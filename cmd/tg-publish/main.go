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
	"strings"
	"syscall"
	"time"

	"github.com/easykeke/tamperguard/internal/config"
	"github.com/easykeke/tamperguard/internal/publish"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
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

// cmdSync creates a release from the publisher host and waits for it to finish.
// With no arguments it runs an interactive setup once, saves the profile and
// then every later run is just `tg-publish sync`.

// splitSyncArgs separates the optional positional source directory from flags so
// `tg-publish sync /srv/release --state-dir ...` and
// `tg-publish sync --state-dir ... /srv/release` both work.
func splitSyncArgs(args []string) (flags, positional []string) {
	valueFlags := map[string]bool{
		"state-dir": true, "node": true, "source": true, "target": true,
		"mode": true, "delivery": true, "note": true, "timeout": true,
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

func cmdSync(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
	nodeID := fs.String("node", "", "target protect node id")
	source := fs.String("source", "", "source directory on this host")
	target := fs.String("target", "", "target directory on the protected node")
	mode := fs.String("mode", "", "sync mode: full or incremental")
	delivery := fs.String("delivery", "", "delivery: pull (upload) or local (write target directly)")
	note := fs.String("note", "", "release note")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for completion")
	reset := fs.Bool("reset", false, "re-run the interactive setup")
	profileID := fs.String("profile", "", "use a console-managed sync profile by id")
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

	profile, err := publish.LoadProfile(*stateDir)
	if err != nil {
		return err
	}
	// A bare positional argument is the source directory: `tg-publish sync /srv/release`.
	posSource := ""
	if len(positional) > 0 {
		posSource = positional[0]
	}
	if len(positional) > 1 {
		return fmt.Errorf("only one source directory may be given")
	}
	pick := func(flagVal, profileVal string) string {
		if flagVal != "" {
			return flagVal
		}
		return profileVal
	}
	cfg := publish.SyncOptions{
		NodeID:    pick(*nodeID, profile.NodeID),
		SourceDir: pick(*source, pick(posSource, profile.SourceDir)),
		TargetDir: pick(*target, profile.TargetDir),
		Mode:      pick(*mode, profile.Mode),
		Delivery:  pick(*delivery, profile.Delivery),
		Note:      *note,
	}
	if cfg.Mode == "" {
		cfg.Mode = "full"
	}
	if cfg.Delivery == "" {
		cfg.Delivery = "pull"
	}

	explicit := *nodeID != "" || *source != "" || *target != "" || *mode != "" || *delivery != ""
	if *profileID != "" || !explicit {
		listCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		profiles, perr := p.SyncProfiles(listCtx)
		cancel()
		if perr != nil {
			if *profileID != "" {
				return fmt.Errorf("读取管理端同步配置失败: %w", perr)
			}
			logger.Warn("无法读取管理端同步配置，使用本地设置", "err", perr)
		}
		if len(profiles) > 0 {
			chosen := profiles[0]
			if *profileID != "" {
				found := false
				for _, item := range profiles {
					if item.ID == *profileID {
						chosen, found = item, true
						break
					}
				}
				if !found {
					return fmt.Errorf("发布端没有 id 为 %s 的同步配置", *profileID)
				}
			} else if len(profiles) > 1 {
				fmt.Println("请选择管理端同步配置：")
				for i, item := range profiles {
					fmt.Printf("  %d) %s → %s（%s，%s）\n", i+1, item.SourceDir, item.TargetDir, modeLabel(item.Mode), deliveryLabel(item.Delivery))
				}
				choice, err := ask("序号", "1")
				if err != nil {
					return err
				}
				var idx int
				fmt.Sscanf(strings.TrimSpace(choice), "%d", &idx)
				if idx < 1 || idx > len(profiles) {
					return fmt.Errorf("无效的序号 %q", choice)
				}
				chosen = profiles[idx-1]
			}
			cfg.ProfileID = chosen.ID
			cfg.NodeID = chosen.NodeID
			cfg.SourceDir = chosen.SourceDir
			cfg.TargetDir = chosen.TargetDir
			cfg.Mode = chosen.Mode
			cfg.Delivery = chosen.Delivery
			if *source != "" {
				cfg.SourceDir = *source
			}
			if posSource != "" {
				cfg.SourceDir = posSource
			}
			fmt.Printf("使用管理端同步配置 %s\n", chosen.ID)
		} else if *profileID != "" {
			return fmt.Errorf("管理端没有为该发布端配置同步任务")
		}
	}

	needWizard := *reset || (cfg.ProfileID == "" && (cfg.NodeID == "" || cfg.SourceDir == "" || cfg.TargetDir == ""))
	if needWizard {
		if err := runWizard(p, &cfg); err != nil {
			return err
		}
		if err := publish.SaveProfile(*stateDir, &publish.Profile{
			NodeID:    cfg.NodeID,
			SourceDir: cfg.SourceDir,
			TargetDir: cfg.TargetDir,
			Mode:      cfg.Mode,
			Delivery:  cfg.Delivery,
		}); err != nil {
			return fmt.Errorf("save sync profile: %w", err)
		}
		fmt.Println("已保存发布配置，下次直接运行：tg-publish sync")
	}

	fmt.Printf("同步：%s → %s（节点 %s，%s，%s）\n",
		cfg.SourceDir, cfg.TargetDir, cfg.NodeID, modeLabel(cfg.Mode), deliveryLabel(cfg.Delivery))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return p.TriggerSync(ctx, cfg, *timeout)
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
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	stateDir := fs.String("state-dir", config.DefaultDataDir, "state directory")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return p.Run(ctx)
}
