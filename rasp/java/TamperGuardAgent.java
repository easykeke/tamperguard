/*
 * TamperGuard RASP probe for the JVM.
 *
 * Load with:
 *   java -Djava.security.manager=allow \
 *        -javaagent:/opt/tamperguard/rasp/java/tg-rasp.jar=socket=/var/lib/tamperguard-agent/rasp.sock \
 *        -jar app.jar
 *
 * The probe installs a SecurityManager and inspects FilePermission checks for
 * write/delete. This covers java.io.FileOutputStream, java.io.File#delete,
 * java.nio.file.Files.write/newOutputStream/delete/move and anything else that
 * goes through the JVM's own permission checks, without bytecode manipulation
 * or external dependencies.
 *
 * Requires JDK 16+ for Unix domain sockets and JDK 17-21 for the SecurityManager
 * (deprecated for removal in later releases). If the SecurityManager cannot be
 * installed the probe logs a warning and does nothing; it never silently
 * pretends to protect.
 */
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class TamperGuardAgent {

    public static void premain(String agentArgs, java.lang.instrument.Instrumentation inst) {
        String socket = System.getenv("TG_RASP_SOCKET");
        if (agentArgs != null) {
            for (String kv : agentArgs.split(",")) {
                if (kv.startsWith("socket=")) {
                    socket = kv.substring("socket=".length());
                }
            }
        }
        if (socket == null || socket.isEmpty()) {
            log("TG_RASP_SOCKET is not set; probe disabled");
            return;
        }
        String app = System.getenv("TG_RASP_APP");
        if (app == null || app.isEmpty()) {
            app = "java";
        }
        Probe probe = new Probe(socket, app);
        probe.start();
        try {
            System.setSecurityManager(new TgSecurityManager(probe));
            log("security manager installed, socket=" + socket);
        } catch (Throwable t) {
            log("cannot install SecurityManager (run with -Djava.security.manager=allow): " + t);
        }
    }

    static void log(String msg) {
        System.err.println("[tamperguard] " + msg);
    }

    /** One policy rule pushed by the agent. */
    static final class Rule {
        final String base;
        final boolean recursive;
        final String mode;

        Rule(String base, boolean recursive, String mode) {
            this.base = base.endsWith("/") && base.length() > 1
                    ? base.substring(0, base.length() - 1)
                    : base;
            this.recursive = recursive;
            this.mode = mode;
        }
    }

    /** Socket client, rule cache and event queue. */
    static final class Probe {
        private final String socketPath;
        private final String app;
        private final int pid = (int) ProcessHandle.current().pid();
        private final LinkedBlockingQueue<String> outbox = new LinkedBlockingQueue<>(1000);
        private volatile List<Rule> rules = List.of();
        private volatile SocketChannel channel;
        private volatile boolean connected;

        Probe(String socketPath, String app) {
            this.socketPath = socketPath;
            this.app = app;
        }

        void start() {
            Thread io = new Thread(this::connectLoop, "tamperguard-probe");
            io.setDaemon(true);
            io.start();
            Thread sender = new Thread(this::senderLoop, "tamperguard-sender");
            sender.setDaemon(true);
            sender.start();
        }

        private void connectLoop() {
            while (true) {
                try {
                    SocketChannel ch = SocketChannel.open(UnixDomainSocketAddress.of(socketPath));
                    ch.configureBlocking(true);
                    channel = ch;
                    connected = true;
                    sendRaw("{\"type\":\"hello\",\"pid\":" + pid + ",\"app\":\"" + escape(app) + "\"}");
                    InputStream in = Channels.newInputStream(ch);
                    BufferedReader reader = new BufferedReader(
                            new InputStreamReader(in, StandardCharsets.UTF_8));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        handleServerLine(line);
                    }
                } catch (Throwable t) {
                    log("probe connection lost: " + t.getMessage());
                } finally {
                    connected = false;
                    channel = null;
                }
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }

        private void senderLoop() {
            while (true) {
                try {
                    String line = outbox.take();
                    if (connected) {
                        sendRaw(line);
                    }
                } catch (InterruptedException ie) {
                    return;
                } catch (Throwable t) {
                    log("send failed: " + t.getMessage());
                }
            }
        }

        private void sendRaw(String line) {
            SocketChannel ch = channel;
            if (ch == null) {
                return;
            }
            try {
                ch.write(java.nio.ByteBuffer.wrap((line + "\n").getBytes(StandardCharsets.UTF_8)));
            } catch (IOException e) {
                connected = false;
            }
        }

        private static final Pattern RULE_PATTERN = Pattern.compile(
                "\\{\"path\":\"((?:[^\"\\\\]|\\\\.)*)\",\"recursive\":(true|false),\"mode\":\"([^\"]*)\"\\}");

        private void handleServerLine(String line) {
            if (!line.contains("\"type\":\"config\"")) {
                return;
            }
            List<Rule> parsed = new ArrayList<>();
            Matcher m = RULE_PATTERN.matcher(line);
            while (m.find()) {
                parsed.add(new Rule(unescape(m.group(1)), Boolean.parseBoolean(m.group(2)), m.group(3)));
            }
            rules = parsed;
            log("rules updated: " + parsed.size());
        }

        /** Returns true when the operation may proceed. */
        boolean check(String path, String op) {
            List<Rule> current = rules;
            if (current.isEmpty() || path == null) {
                return true;
            }
            String abs;
            try {
                abs = new File(path).getAbsolutePath();
            } catch (Throwable t) {
                return true;
            }
            Rule best = null;
            for (Rule r : current) {
                if (abs.equals(r.base) || (r.recursive && abs.startsWith(r.base + "/"))) {
                    if (best == null || r.base.length() > best.base.length()) {
                        best = r;
                    }
                }
            }
            if (best == null) {
                return true;
            }
            boolean enforce = "enforce".equals(best.mode);
            report(path, op, enforce ? "blocked" : "observed");
            return !enforce;
        }

        private void report(String path, String op, String decision) {
            String line = "{\"type\":\"event\",\"pid\":" + pid + ",\"app\":\"" + escape(app)
                    + "\",\"path\":\"" + escape(path) + "\",\"op\":\"" + escape(op)
                    + "\",\"decision\":\"" + decision + "\",\"stack\":\""
                    + escape(stackSummary()) + "\"}";
            outbox.offer(line);
        }

        private static String stackSummary() {
            StringBuilder sb = new StringBuilder();
            StackTraceElement[] st = Thread.currentThread().getStackTrace();
            int n = 0;
            for (StackTraceElement e : st) {
                if (e.getClassName().startsWith("java.base/") || e.getClassName().startsWith("java.")) {
                    continue;
                }
                if (sb.length() > 0) {
                    sb.append(" <- ");
                }
                sb.append(e.getClassName()).append('.').append(e.getMethodName())
                        .append(':').append(e.getLineNumber());
                if (++n >= 8) {
                    break;
                }
            }
            return sb.toString();
        }
    }

    /** Intercepts JVM file permission checks for write/delete. */
    static final class TgSecurityManager extends SecurityManager {
        private final Probe probe;

        TgSecurityManager(Probe probe) {
            this.probe = probe;
        }

        @Override
        public void checkPermission(Permission perm) {
            if (perm instanceof java.io.FilePermission) {
                String actions = perm.getActions();
                if (actions != null && (actions.contains("write") || actions.contains("delete"))) {
                    String name = perm.getName();
                    if (name.endsWith("/*") || name.endsWith("/-")) {
                        name = name.substring(0, name.length() - 2);
                    }
                    String op = actions.contains("delete") ? "unlink" : "write";
                    if (!probe.check(name, op)) {
                        throw new SecurityException(
                                "TamperGuard: " + op + " on " + name + " blocked by the runtime policy");
                    }
                }
            }
        }

        @Override
        public void checkPermission(Permission perm, Object context) {
            checkPermission(perm);
        }
    }

    static String escape(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char n = s.charAt(++i);
            switch (n) {
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u':
                    if (i + 4 < s.length()) {
                        try {
                            sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                            i += 4;
                        } catch (NumberFormatException e) {
                            sb.append(n);
                        }
                    } else {
                        sb.append(n);
                    }
                    break;
                default: sb.append(n);
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        // The jar is an agent, not an application; this only helps `java -jar`.
        System.err.println("tg-rasp is a -javaagent, not a runnable application");
    }
}
