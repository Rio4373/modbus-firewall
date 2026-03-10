package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/armsim"
)

// main — точка входа CLI для ARM simulator.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ошибка arm-sim: %v\n", err)
		os.Exit(1)
	}
}

// run читает параметры CLI, формирует сценарий и выполняет его через TCP клиент.
func run(args []string) error {
	fs := flag.NewFlagSet("arm-sim", flag.ContinueOnError)
	target := fs.String("target", "127.0.0.1:1502", "адрес firewall proxy host:port")
	scenarioValue := fs.String("scenario", string(armsim.ScenarioNormalRead), "сценарий: normal-read|repeated-write|rare-write|forbidden-write")
	unitID := fs.Uint("unit-id", 1, "modbus unit id")
	repeat := fs.Int("repeat", 5, "количество повторов для repeated-write")
	timeout := fs.Duration("timeout", 3*time.Second, "таймаут операции")
	listScenarios := fs.Bool("list-scenarios", false, "вывести список поддерживаемых сценариев")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("лишние аргументы: %v", fs.Args())
	}

	if *listScenarios {
		printScenarios()
		return nil
	}

	if *unitID == 0 || *unitID > 255 {
		return fmt.Errorf("unit-id должен быть в диапазоне 1..255")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout должен быть > 0")
	}

	scenario, err := armsim.ParseScenario(*scenarioValue)
	if err != nil {
		return err
	}

	operations, err := armsim.BuildScenarioOperations(scenario, uint8(*unitID), *repeat)
	if err != nil {
		return err
	}

	resolvedTarget := strings.TrimSpace(*target)
	client, err := armsim.NewClient(resolvedTarget, *timeout)
	if err != nil {
		return err
	}

	fmt.Printf("ARM sim старт: target=%s scenario=%s unit-id=%d operations=%d\n", resolvedTarget, scenario, *unitID, len(operations))

	ctx := context.Background()
	results, execErr := client.ExecuteScenario(ctx, operations)
	okCount, exceptionCount, errorCount := printResults(results)

	fmt.Printf("ARM sim итог: ok=%d exceptions=%d errors=%d total=%d\n", okCount, exceptionCount, errorCount, len(results))
	if execErr != nil {
		return execErr
	}

	return nil
}

// printScenarios печатает список поддерживаемых сценариев.
func printScenarios() {
	fmt.Println("Поддерживаемые сценарии:")
	for _, scenario := range armsim.ListScenarios() {
		fmt.Printf("- %s\n", scenario)
	}
}

// printResults выводит человекочитаемую сводку по каждой операции сценария.
func printResults(results []armsim.OperationResult) (int, int, int) {
	okCount := 0
	exceptionCount := 0
	errorCount := 0

	for index, result := range results {
		prefix := fmt.Sprintf("[%d/%d] %s", index+1, len(results), result.Operation.Name)

		if result.Err != nil {
			errorCount++
			fmt.Printf("%s -> ERROR: %v\n", prefix, result.Err)
			continue
		}

		if result.Response.IsException() {
			exceptionCount++
			fmt.Printf(
				"%s -> BLOCKED/EXCEPTION fc=0x%02X code=0x%02X time=%s\n",
				prefix,
				result.Response.FunctionCode,
				result.Response.ExceptionCode(),
				result.Duration.Truncate(time.Millisecond),
			)
			continue
		}

		okCount++
		fmt.Printf(
			"%s -> OK fc=0x%02X addr=%d qty=%d time=%s\n",
			prefix,
			result.Operation.FunctionCode,
			result.Operation.StartAddress,
			result.Operation.Quantity,
			result.Duration.Truncate(time.Millisecond),
		)
	}

	return okCount, exceptionCount, errorCount
}
