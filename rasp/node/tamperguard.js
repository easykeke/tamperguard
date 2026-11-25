// TamperGuard RASP probe for Node.js.
//
// Load it inside the application process before any application code:
//
//	NODE_OPTIONS="--require /opt/tamperguard/rasp/node/tamperguard.js" node app.js
//
// The probe connects to the local agent's Unix socket, receives the current
// protection rules, and checks every file-writing call. In observe mode it only
// reports; in enforce mode it throws before the write happens. Rules are pushed
// again whenever the policy changes, so no restart is needed.
'use strict';

const fs = require('fs');
const path = require('path');
const net = require('net');

const SOCKET = process.env.TG_RASP_SOCKET || '';
const APP = process.env.TG_RASP_APP || 'node';
const PID = process.pid;

let rules = [];
let socket = null;
let connected = false;
let buffer = '';
let queue = [];

function log(...args) {
  if (process.env.TG_RASP_DEBUG) console.error('[tamperguard]', ...args);
}

function connect() {
  if (!SOCKET) {
    log('TG_RASP_SOCKET is not set; probe disabled');
    return;
  }
  socket = net.connect({ path: SOCKET });
  socket.setEncoding('utf8');
  socket.on('connect', () => {
    connected = true;
    // The probe must not keep the application alive: unref lets Node exit when
    // the app is done while the socket keeps working meanwhile.
    if (typeof socket.unref === 'function') socket.unref();
    send({ type: 'hello', pid: PID, app: APP });
    for (const msg of queue.splice(0)) send(msg);
  });
  socket.on('data', (chunk) => {
    buffer += chunk;
    let idx;
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 1);
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.type === 'config') {
          rules = (msg.rules || []).map((r) => ({
            path: r.path,
            recursive: !!r.recursive,
            mode: r.mode || 'enforce',
          }));
          log('rules updated:', rules.length);
        }
      } catch (e) {
        log('bad message', e.message);
      }
    }
  });
  socket.on('error', () => { connected = false; });
  socket.on('close', () => {
    connected = false;
    setTimeout(connect, 2000).unref?.();
  });
}

function send(msg) {
  if (!connected) {
    if (queue.length < 1000) queue.push(msg);
    return;
  }
  try {
    socket.write(JSON.stringify(msg) + '\n');
  } catch (e) {
    connected = false;
  }
}

// decide returns {allowed, mode, protected}.
function decide(filePath) {
  if (!filePath || typeof filePath !== 'string') return { allowed: true };
  let abs;
  try {
    abs = path.resolve(filePath);
  } catch (e) {
    return { allowed: true };
  }
  let best = null;
  for (const r of rules) {
    const base = path.resolve(r.path);
    const inside = abs === base || (r.recursive && abs.startsWith(base + path.sep));
    if (!inside) continue;
    if (!best || base.length > path.resolve(best.path).length) best = r;
  }
  if (!best) return { allowed: true };
  return { allowed: best.mode !== 'enforce', mode: best.mode, protected: true, path: abs };
}

let stackCache;
function stack() {
  if (stackCache !== undefined) return stackCache;
  const limit = Number(process.env.TG_RASP_STACK_DEPTH || 8);
  const old = Error.stackTraceLimit;
  Error.stackTraceLimit = limit + 1;
  const e = new Error();
  Error.stackTraceLimit = old;
  stackCache = (e.stack || '').split('\n').slice(2).map((s) => s.trim()).join(' <- ');
  return stackCache;
}

function report(filePath, op, decision, mode) {
  send({
    type: 'event',
    pid: PID,
    app: APP,
    path: filePath,
    op,
    decision: decision,
    stack: stack(),
  });
  log(decision, op, filePath, 'mode=' + mode);
}

function check(filePath, op) {
  const d = decide(filePath);
  if (!d.protected) return true;
  if (d.allowed) {
    if (d.mode === 'observe') report(d.path, op, 'observed', d.mode);
    return true;
  }
  report(d.path, op, 'blocked', d.mode);
  return false;
}

function denied(filePath, op) {
  const err = new Error(
    `TamperGuard: ${op} on ${filePath} was blocked by the runtime policy ` +
      '(the process may be compromised or the path is not on the allow list)'
  );
  err.code = 'EPERM';
  err.errno = -1;
  err.syscall = op;
  err.path = filePath;
  return err;
}

// ---------- fs wrappers ----------

function wrapSync(name, op, argIndex) {
  const original = fs[name];
  if (typeof original !== 'function') return;
  fs[name] = function (...args) {
    if (!check(args[argIndex], op)) throw denied(args[argIndex], op);
    return original.apply(this, args);
  };
}

function wrapCallback(name, op, argIndex) {
  const original = fs[name];
  if (typeof original !== 'function') return;
  fs[name] = function (...args) {
    if (!check(args[argIndex], op)) {
      const cb = args[args.length - 1];
      const err = denied(args[argIndex], op);
      if (typeof cb === 'function') return process.nextTick(cb, err);
      throw err;
    }
    return original.apply(this, args);
  };
}

function wrapPromise(name, op, argIndex) {
  const original = fs.promises ? fs.promises[name] : null;
  if (typeof original !== 'function') return;
  fs.promises[name] = function (...args) {
    if (!check(args[argIndex], op)) return Promise.reject(denied(args[argIndex], op));
    return original.apply(this, args);
  };
}

wrapSync('writeFileSync', 'write', 0);
wrapSync('appendFileSync', 'append', 0);
wrapSync('renameSync', 'rename', 1);
wrapSync('copyFileSync', 'copy', 1);
wrapSync('unlinkSync', 'unlink', 0);
wrapSync('rmSync', 'unlink', 0);
wrapSync('rmdirSync', 'unlink', 0);
wrapSync('mkdirSync', 'mkdir', 0);

wrapCallback('writeFile', 'write', 0);
wrapCallback('appendFile', 'append', 0);
wrapCallback('rename', 'rename', 1);
wrapCallback('copyFile', 'copy', 1);
wrapCallback('unlink', 'unlink', 0);
wrapCallback('rm', 'unlink', 0);
wrapCallback('rmdir', 'unlink', 0);
wrapCallback('mkdir', 'mkdir', 0);

wrapPromise('writeFile', 'write', 0);
wrapPromise('appendFile', 'append', 0);
wrapPromise('rename', 'rename', 1);
wrapPromise('copyFile', 'copy', 1);
wrapPromise('unlink', 'unlink', 0);
wrapPromise('rm', 'unlink', 0);
wrapPromise('rmdir', 'unlink', 0);
wrapPromise('mkdir', 'mkdir', 0);

// Streams: check when the stream is created.
const originalCreateWriteStream = fs.createWriteStream;
if (typeof originalCreateWriteStream === 'function') {
  fs.createWriteStream = function (filePath, ...rest) {
    if (!check(filePath, 'write')) throw denied(filePath, 'write');
    return originalCreateWriteStream.call(this, filePath, ...rest);
  };
}

// open() with a write-ish flag: check before handing out a writable fd.
const WRITE_FLAGS = /[wa+]/;
const originalOpen = fs.open;
if (typeof originalOpen === 'function') {
  fs.open = function (filePath, flags, ...rest) {
    if (typeof flags === 'string' && WRITE_FLAGS.test(flags) && !check(filePath, 'open')) {
      const cb = rest[rest.length - 1];
      const err = denied(filePath, 'open');
      if (typeof cb === 'function') return process.nextTick(cb, err);
      throw err;
    }
    return originalOpen.call(this, filePath, flags, ...rest);
  };
}
const originalOpenSync = fs.openSync;
if (typeof originalOpenSync === 'function') {
  fs.openSync = function (filePath, flags, ...rest) {
    if (typeof flags === 'string' && WRITE_FLAGS.test(flags) && !check(filePath, 'open')) {
      throw denied(filePath, 'open');
    }
    return originalOpenSync.call(this, filePath, flags, ...rest);
  };
}

connect();
log('probe loaded, socket=' + SOCKET);
