package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
	"github.com/maratbagautdinov/modbus-firewall/internal/generator"
	"github.com/maratbagautdinov/modbus-firewall/internal/logging"
	policypkg "github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/proxy"
	"github.com/maratbagautdinov/modbus-firewall/internal/replay"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
)

// main — точка входа CLI firewall.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка: %v\n", err)
		os.Exit(1)
	}
}

// run маршрутизирует верхнеуровневые подкоманды CLI.
func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("команда обязательна\n\n%s", usage())
	}

	switch args[0] {
	case "run":
		return runCommand(args[1:])
	case "validate-config":
		return validateConfigCommand(args[1:])
	case "generate-policy":
		return generatePolicyCommand(args[1:])
	case "validate-policy":
		return validatePolicyCommand(args[1:])
	case "reset-candidate":
		return resetCandidateCommand(args[1:])
	case "apply-policy":
		return applyPolicyCommand(args[1:])
	case "replay":
		return replayCommand(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage())
		return nil
	default:
		return fmt.Errorf("неизвестная команда %q\n\n%s", args[0], usage())
	}
}

// runCommand поднимает прокси в observe/enforce режиме и включает hot reload.
func runCommand(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", "./configs/config.yaml", "путь к config.yaml")
	modeOverride := fs.String("mode", "", "override режима: observe|enforce")
	policyPath := fs.String("policy", "./configs/policy.yaml", "путь к policy.yaml (используется в режиме enforce)")
	reloadInterval := fs.Duration("reload-interval", time.Second, "интервал hot reload config/policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды run: %v", fs.Args())
	}
	if *reloadInterval <= 0 {
		return fmt.Errorf("reload-interval должен быть > 0")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	if err := cfg.ApplyModeOverride(*modeOverride); err != nil {
		return err
	}

	logger, err := logging.New(cfg.Logging)
	if err != nil {
		return err
	}

	var policyEngine policypkg.Engine
	if cfg.Mode == config.ModeEnforce {
		policyCfg, err := policypkg.Load(*policyPath)
		if err != nil {
			return err
		}

		matcher, err := policypkg.NewMatcher(policyCfg)
		if err != nil {
			return err
		}
		policyEngine = matcher
		logger.Info("policy загружена для enforce режима", "path", *policyPath, "rules", len(policyCfg.Rules))
	}

	eventStore, err := storage.NewSQLiteStore(cfg.Storage.EventsPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := eventStore.Close(); closeErr != nil {
			logger.Warn("не удалось закрыть storage", "error", closeErr.Error())
		}
	}()

	svc := proxy.New(cfg, logger, policyEngine, eventStore, proxy.WithHotReload(*configPath, *policyPath, *reloadInterval))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return svc.Run(ctx)
}

// validateConfigCommand выполняет загрузку и валидацию config.yaml без запуска сервиса.
func validateConfigCommand(args []string) error {
	fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	configPath := fs.String("config", "./configs/config.yaml", "путь к config.yaml")
	modeOverride := fs.String("mode", "", "override режима: observe|enforce")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды validate-config: %v", fs.Args())
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	if err := cfg.ApplyModeOverride(*modeOverride); err != nil {
		return err
	}

	fmt.Println("конфигурация валидна")
	return nil
}

// generatePolicyCommand строит candidate/baseline policy на основе событий из SQLite.
func generatePolicyCommand(args []string) error {
	fs := flag.NewFlagSet("generate-policy", flag.ContinueOnError)
	configPath := fs.String("config", "./configs/config.yaml", "путь к config.yaml")
	outputPath := fs.String("output", "./configs/policy.candidate.yaml", "куда записать candidate policy")
	baselineOutputPath := fs.String("baseline-output", "./configs/policy.generated.yaml", "куда записать baseline generated policy")
	writeThreshold := fs.Int("write-threshold", 2, "порог K для write-операций")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды generate-policy: %v", fs.Args())
	}
	if *writeThreshold <= 0 {
		return fmt.Errorf("write-threshold должен быть > 0")
	}
	if strings.TrimSpace(*outputPath) == "" {
		return fmt.Errorf("output путь обязателен")
	}
	if strings.TrimSpace(*baselineOutputPath) == "" {
		return fmt.Errorf("baseline-output путь обязателен")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	eventStore, err := storage.NewSQLiteStore(cfg.Storage.EventsPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := eventStore.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "ошибка закрытия storage: %v\n", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	generatedPolicy, err := generator.GeneratePolicy(ctx, eventStore, *writeThreshold)
	if err != nil {
		return err
	}

	if err := generator.SavePolicy(*outputPath, generatedPolicy); err != nil {
		return err
	}
	if err := generator.SavePolicy(*baselineOutputPath, generatedPolicy); err != nil {
		return err
	}

	fmt.Printf("policy сгенерирована: candidate=%s baseline=%s (rules=%d)\n", *outputPath, *baselineOutputPath, len(generatedPolicy.Rules))
	return nil
}

// validatePolicyCommand проверяет policy файл через policy.Validate().
func validatePolicyCommand(args []string) error {
	fs := flag.NewFlagSet("validate-policy", flag.ContinueOnError)
	policyPath := fs.String("policy", "./configs/policy.candidate.yaml", "путь к policy (обычно candidate)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды validate-policy: %v", fs.Args())
	}

	validated, err := policypkg.ValidateFile(*policyPath)
	if err != nil {
		return err
	}

	fmt.Printf("policy валидна: %s (rules=%d)\n", *policyPath, len(validated.Rules))
	return nil
}

// applyPolicyCommand атомарно заменяет active policy валидированной candidate версией.
func applyPolicyCommand(args []string) error {
	fs := flag.NewFlagSet("apply-policy", flag.ContinueOnError)
	candidatePath := fs.String("candidate", "./configs/policy.candidate.yaml", "путь к candidate policy")
	activePath := fs.String("active", "./configs/policy.yaml", "путь к active policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды apply-policy: %v", fs.Args())
	}

	applied, err := policypkg.ApplyCandidate(*candidatePath, *activePath)
	if err != nil {
		return err
	}

	fmt.Printf("policy применена атомарно: %s (rules=%d)\n", *activePath, len(applied.Rules))
	return nil
}

// resetCandidateCommand восстанавливает candidate из baseline generated policy.
func resetCandidateCommand(args []string) error {
	fs := flag.NewFlagSet("reset-candidate", flag.ContinueOnError)
	baselinePath := fs.String("baseline", "./configs/policy.generated.yaml", "путь к baseline generated policy")
	candidatePath := fs.String("candidate", "./configs/policy.candidate.yaml", "путь к candidate policy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды reset-candidate: %v", fs.Args())
	}

	resetPolicy, err := policypkg.ResetCandidate(*baselinePath, *candidatePath)
	if err != nil {
		return err
	}

	fmt.Printf("candidate policy восстановлена из baseline: %s (rules=%d)\n", *candidatePath, len(resetPolicy.Rules))
	return nil
}

// replayCommand запускает офлайн-анализ исторических событий и печатает JSON-отчет.
func replayCommand(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	configPath := fs.String("config", "./configs/config.yaml", "путь к config.yaml")
	policyPath := fs.String("policy", "./configs/policy.yaml", "путь к policy.yaml")
	eventsDBPath := fs.String("events-db", "", "путь к sqlite событиям (override, опционально)")
	outputPath := fs.String("output", "", "путь для сохранения replay report в JSON (опционально)")
	timeout := fs.Duration("timeout", 30*time.Second, "таймаут replay анализа")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы для команды replay: %v", fs.Args())
	}

	policyCfg, err := policypkg.Load(*policyPath)
	if err != nil {
		return err
	}
	matcher, err := policypkg.NewMatcher(policyCfg)
	if err != nil {
		return err
	}

	resolvedEventsDBPath := strings.TrimSpace(*eventsDBPath)
	if resolvedEventsDBPath == "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		resolvedEventsDBPath = cfg.Storage.EventsPath
	}
	if strings.TrimSpace(resolvedEventsDBPath) == "" {
		return fmt.Errorf("путь к sqlite событиям обязателен")
	}

	eventStore, err := storage.NewSQLiteReadOnlyStore(resolvedEventsDBPath)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := eventStore.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "ошибка закрытия storage: %v\n", closeErr)
		}
	}()

	ctx, cancel := replay.NewReportContext(*timeout)
	defer cancel()

	report, err := replay.Run(ctx, eventStore, matcher)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать replay report: %w", err)
	}
	fmt.Println(string(data))

	if strings.TrimSpace(*outputPath) != "" {
		if err := replay.SaveReportJSON(*outputPath, report); err != nil {
			return err
		}
		fmt.Printf("replay report сохранен: %s\n", *outputPath)
	}

	return nil
}

// usage возвращает краткую справку по всем командам CLI.
func usage() string {
	return `Использование:
  firewall run --config ./configs/config.yaml [--mode observe|enforce] [--policy ./configs/policy.yaml] [--reload-interval 1s]
  firewall validate-config --config ./configs/config.yaml [--mode observe|enforce]
  firewall generate-policy --config ./configs/config.yaml [--output ./configs/policy.candidate.yaml] [--baseline-output ./configs/policy.generated.yaml] [--write-threshold 2]
  firewall validate-policy --policy ./configs/policy.candidate.yaml
  firewall reset-candidate --baseline ./configs/policy.generated.yaml --candidate ./configs/policy.candidate.yaml
  firewall apply-policy --candidate ./configs/policy.candidate.yaml --active ./configs/policy.yaml
  firewall replay --config ./configs/config.yaml [--policy ./configs/policy.yaml] [--events-db ./data/events.db] [--output ./reports/replay-report.json] [--timeout 30s]
  firewall help
`
}
