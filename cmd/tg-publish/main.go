// Command tg-publish is the release agent. It polls the control plane for
// release requests assigned to it, hashes the source tree, obtains a
// manifest-bound token and writes the files.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/agent"
	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/publish"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		if runtime.GOOS == "windows" {
			fmt.Println("\n按回车退出…")
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		if handled, serr := tryServiceMode("TamperGuardPublish", os.Args[2:]); handled {
			err = serr
			break
		}
		err = cmdRun(os.Args[2:])
	case "sync":
		err = cmdSync(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `TamperGuard release agent

  tg-publish run  [--state-dir DIR] [--verity]
  tg-publish sync --node NODE --source DIR --target DIR [--mode full|incremental]
                  [--delivery local|pull] [--note TEXT] [--timeout 5m]
`)
}

// cmdSync triggers one or more console-managed sync tasks. With no arguments it
// lists them for multi-selection, asks for the mode of this run, and executes
// each selected task; paths come from the console unless overridden.
func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultPublishDir, "state directory")
	profileID := fs.String("profile", "", "run one console sync profile by id")
	allFlag := fs.Bool("all", false, "run every console sync profile")
	nodeID := fs.String("node", "", "override target protect node id")
	source := fs.String("source", "", "override source directory on this host")
	target := fs.String("target", "", "override target directory on the protected node")
	mode := fs.String("mode", "", "override mode for this run: full or incremental")
	delivery := fs.String("delivery", "", "override delivery: pull or local")
	note := fs.String("note", "", "release note")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait per task")
	reset := fs.Bool("reset", false, "re-run the local setup wizard")
	verity := fs.Bool("verity", false, "enable fs-verity on locally installed files")
	flagsOnly, positional := splitSyncArgs(args)
	_ = fs.Parse(flagsOnly)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	if state.Role != "publish" {
		return fmt.Errorf("this identity has role %q; enrol with --role publish", state.Role)
	}
	p, err := publish.New(state, logger, *verity)
	if err != nil {
		return err
	}
	posSource := ""
	if len(positional) > 0 {
		posSource = positional[0]
	}
	if len(positional) > 1 {
		return fmt.Errorf("only one source directory may be given")
	}

	explicit := *nodeID != "" || *source != "" || *target != "" || *mode != "" || *delivery != ""
	var tasks []publish.SyncOptions

	if *profileID != "" || *allFlag || !explicit {
		listCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		profiles, perr := p.SyncProfiles(listCtx)
		cancel()
		if perr != nil {
			if *profileID != "" || *allFlag {
				return fmt.Errorf("读取管理端同步配置失败: %w", perr)
			}
			logger.Warn("无法读取管理端同步配置，使用本地设置", "err", perr)
		}
		if len(profiles) > 0 {
			var selected []agent.SyncProfile
			switch {
			case *profileID != "":
				for _, item := range profiles {
					if item.ID == *profileID {
						selected = []agent.SyncProfile{item}
						break
					}
				}
				if len(selected) == 0 {
					return fmt.Errorf("发布端没有 id 为 %s 的同步配置", *profileID)
				}
			case *allFlag:
				selected = profiles
			default:
				fmt.Println("管理端同步配置：")
				for i, item := range profiles {
					last := "未执行"
					if item.LastRunAt > 0 {
						last = item.LastStatus + " @ " + time.Unix(item.LastRunAt, 0).Format("2006-01-02 15:04")
					}
					fmt.Printf("  %d) %s → %s（%s，%s，最近：%s）\n", i+1,
						item.SourceDir, item.TargetDir, modeLabel(item.Mode), deliveryLabel(item.Delivery), last)
				}
				choice, err := ask("选择要执行的同步任务（逗号分隔，回车=全部）", "")
				if err != nil {
					return err
				}
				idx, err := parseSelection(choice, len(profiles))
				if err != nil {
					return err
				}
				for _, i := range idx {
					selected = append(selected, profiles[i])
				}
			}

			modeOverride := *mode
			if !explicit {
				fmt.Println("本次同步模式：1) 全量  2) 增量（默认沿用配置）")
				choice, err := ask("序号", "")
				if err != nil {
					return err
				}
				switch strings.TrimSpace(choice) {
				case "1":
					modeOverride = "full"
				case "2":
					modeOverride = "incremental"
				}
			}
			srcOverride := ""
			if len(selected) == 1 && !explicit && *profileID == "" && !*allFlag {
				v, err := ask("本次源目录（回车使用管理端配置："+selected[0].SourceDir+"）", "")
				if err != nil {
					return err
				}
				srcOverride = v
			}
			for _, item := range selected {
				task := publish.SyncOptions{
					ProfileID: item.ID,
					NodeID:    item.NodeID,
					SourceDir: item.SourceDir,
					TargetDir: item.TargetDir,
					Mode:      item.Mode,
					Delivery:  item.Delivery,
					Note:      *note,
				}
				if modeOverride != "" {
					task.Mode = modeOverride
				}
				if *nodeID != "" {
					task.NodeID = *nodeID
				}
				if *target != "" {
					task.TargetDir = *target
				}
				if *delivery != "" {
					task.Delivery = *delivery
				}
				if *source != "" {
					task.SourceDir = *source
				}
				if posSource != "" {
					task.SourceDir = posSource
				}
				if srcOverride != "" {
					task.SourceDir = srcOverride
				}
				tasks = append(tasks, task)
			}
		} else if *profileID != "" || *allFlag {
			return fmt.Errorf("管理端没有为该发布端配置同步任务")
		}
	}

	if len(tasks) == 0 {
		local, err := publish.LoadProfile(*stateDir)
		if err != nil {
			return err
		}
		cfg := publish.SyncOptions{
			NodeID:    pick(*nodeID, local.NodeID),
			SourceDir: pick(*source, pick(posSource, local.SourceDir)),
			TargetDir: pick(*target, local.TargetDir),
			Mode:      pick(*mode, local.Mode),
			Delivery:  pick(*delivery, local.Delivery),
			Note:      *note,
		}
		if cfg.Mode == "" {
			cfg.Mode = "full"
		}
		if cfg.Delivery == "" {
			cfg.Delivery = "pull"
		}
		if *reset || cfg.NodeID == "" || cfg.SourceDir == "" || cfg.TargetDir == "" {
			if err := runWizard(p, &cfg); err != nil {
				return err
			}
			if err := publish.SaveProfile(*stateDir, &publish.Profile{
				NodeID: cfg.NodeID, SourceDir: cfg.SourceDir, TargetDir: cfg.TargetDir,
				Mode: cfg.Mode, Delivery: cfg.Delivery,
			}); err != nil {
				return fmt.Errorf("save sync profile: %w", err)
			}
			fmt.Println("已保存本地发布配置")
		}
		tasks = append(tasks, cfg)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	failures := 0
	for _, task := range tasks {
		fmt.Printf("同步：%s → %s（节点 %s，%s，%s）\n",
			task.SourceDir, task.TargetDir, task.NodeID, modeLabel(task.Mode), deliveryLabel(task.Delivery))
		req, err := p.TriggerSync(ctx, task, *timeout)
		if err != nil {
			failures++
			fmt.Fprintf(os.Stderr, "任务失败：%v\n", err)
			continue
		}
		if req.VerifiedFiles == 0 {
			fmt.Printf("✓ 校验通过：目标端无变更文件，摘要一致（%s…）\n", shortDigest(req.VerifyDigest))
		} else {
			fmt.Printf("✓ 校验通过：目标端回读 %d 个文件，哈希一致（%s…）\n", req.VerifiedFiles, shortDigest(req.VerifyDigest))
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d 个同步任务失败", failures)
	}
	return nil
}

// splitSyncArgs lets the source directory appear before or after flags.
func splitSyncArgs(args []string) (flags, positional []string) {
	valueFlags := map[string]bool{
		"state-dir": true, "node": true, "source": true, "target": true,
		"mode": true, "delivery": true, "note": true, "timeout": true, "profile": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			continue
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positional
}

func shortDigest(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func pick(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// parseSelection parses "1,3" or "" (all) into zero-based indexes.
func parseSelection(choice string, n int) ([]int, error) {
	choice = strings.TrimSpace(choice)
	if choice == "" {
		out := make([]int, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, i)
		}
		return out, nil
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(choice, ",") {
		var idx int
		if _, err := fmt.Sscanf(strings.TrimSpace(part), "%d", &idx); err != nil || idx < 1 || idx > n {
			return nil, fmt.Errorf("无效的任务序号 %q", part)
		}
		if !seen[idx] {
			seen[idx] = true
			out = append(out, idx-1)
		}
	}
	return out, nil
}

func modeLabel(mode string) string {
	if mode == "incremental" {
		return "增量"
	}
	return "全量"
}

func deliveryLabel(d string) string {
	if d == "local" {
		return "本机写入"
	}
	return "跨机拉取"
}

var stdinReader = bufio.NewReader(os.Stdin)

func ask(label, def string) (string, error) {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("需要输入 %s（或使用命令行参数）", label)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

// runWizard walks a beginner through node, directories, mode and delivery.
func runWizard(p *publish.Publisher, cfg *publish.SyncOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	nodes, err := p.ProtectNodes(ctx)
	if err != nil {
		return fmt.Errorf("获取节点列表失败: %w", err)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("没有可用的被保护节点，请先在管理端注册被防护主机")
	}
	if cfg.NodeID == "" {
		if len(nodes) == 1 {
			cfg.NodeID = nodes[0].ID
			fmt.Printf("目标节点：%s（%s）\n", nodes[0].Hostname, nodes[0].ID)
		} else {
			fmt.Println("请选择目标节点：")
			for i, n := range nodes {
				fmt.Printf("  %d) %s（%s，%s）\n", i+1, n.Hostname, n.ID, n.Status)
			}
			choice, err := ask("序号", "1")
			if err != nil {
				return err
			}
			var idx int
			fmt.Sscanf(strings.TrimSpace(choice), "%d", &idx)
			if idx < 1 || idx > len(nodes) {
				return fmt.Errorf("无效的节点序号 %q", choice)
			}
			cfg.NodeID = nodes[idx-1].ID
		}
	}
	if cfg.SourceDir == "" {
		if cfg.SourceDir, err = ask("发布源目录（本机上的网站文件目录，如 /srv/release）", ""); err != nil {
			return err
		}
	}
	if cfg.TargetDir == "" {
		def := "/var/www/site"
		if cfg.TargetDir, err = ask("目标目录（被保护主机上的路径）", def); err != nil {
			return err
		}
	}
	if cfg.Mode == "" || cfg.Mode == "full" {
		fmt.Println("同步模式：1) 全量  2) 增量（推荐，只传变化的文件）")
		choice, err := ask("序号", "2")
		if err != nil {
			return err
		}
		if strings.TrimSpace(choice) == "1" {
			cfg.Mode = "full"
		} else {
			cfg.Mode = "incremental"
		}
	}
	if cfg.Delivery == "" || cfg.Delivery == "pull" {
		fmt.Println("发布方式：1) 跨机拉取（推荐）  2) 本机写入")
		choice, err := ask("序号", "1")
		if err != nil {
			return err
		}
		if strings.TrimSpace(choice) == "2" {
			cfg.Delivery = "local"
		} else {
			cfg.Delivery = "pull"
		}
	}
	return nil
}

func cmdRun(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return cmdRunContext(args, ctx)
}

func cmdRunContext(args []string, ctx context.Context) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultPublishDir, "state directory")
	verity := fs.Bool("verity", false, "enable fs-verity on the files of every locally installed release")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	state, err := config.LoadAgentState(*stateDir)
	if err != nil {
		return err
	}
	if state.Role != "publish" {
		return fmt.Errorf("this identity has role %q; enrol with --role publish", state.Role)
	}
	p, err := publish.New(state, logger, *verity)
	if err != nil {
		return err
	}
	return p.Run(ctx)
}
