package armsim

import (
	"testing"

	"github.com/maratbagautdinov/modbus-firewall/internal/modbus"
)

func TestParseScenarioSuccess(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"normal-read",
		"repeated-write",
		"rare-write",
		"forbidden-write",
	}

	for _, input := range inputs {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()

			parsed, err := ParseScenario(input)
			if err != nil {
				t.Fatalf("ожидали успешный parse для %q, получили ошибку: %v", input, err)
			}
			if string(parsed) != input {
				t.Fatalf("ожидали %q, получили %q", input, parsed)
			}
		})
	}
}

func TestParseScenarioInvalid(t *testing.T) {
	t.Parallel()

	if _, err := ParseScenario("unknown"); err == nil {
		t.Fatal("ожидали ошибку при неподдерживаемом сценарии")
	}
}

func TestBuildScenarioOperationsNormalRead(t *testing.T) {
	t.Parallel()

	ops, err := BuildScenarioOperations(ScenarioNormalRead, 1, 0)
	if err != nil {
		t.Fatalf("не удалось собрать normal-read: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("ожидали 3 операции, получили %d", len(ops))
	}

	expectedAddresses := []uint16{0, 10, 20}
	for i, op := range ops {
		parsed, parseErr := modbus.ParseRequest(op.ADU)
		if parseErr != nil {
			t.Fatalf("операция %d: не удалось распарсить ADU: %v", i+1, parseErr)
		}
		if parsed.TransactionID != uint16(i+1) {
			t.Fatalf("операция %d: ожидали txid=%d, получили %d", i+1, i+1, parsed.TransactionID)
		}
		if parsed.FunctionCode != modbus.FunctionCodeReadHoldingRegisters {
			t.Fatalf("операция %d: ожидали FC03, получили 0x%02X", i+1, uint8(parsed.FunctionCode))
		}
		if parsed.StartAddress != expectedAddresses[i] {
			t.Fatalf("операция %d: ожидали start=%d, получили %d", i+1, expectedAddresses[i], parsed.StartAddress)
		}
		if parsed.Quantity != 2 {
			t.Fatalf("операция %d: ожидали quantity=2, получили %d", i+1, parsed.Quantity)
		}
	}
}

func TestBuildScenarioOperationsRepeatedWrite(t *testing.T) {
	t.Parallel()

	ops, err := BuildScenarioOperations(ScenarioRepeatedWrite, 1, 4)
	if err != nil {
		t.Fatalf("не удалось собрать repeated-write: %v", err)
	}
	if len(ops) != 4 {
		t.Fatalf("ожидали 4 операции, получили %d", len(ops))
	}

	for i, op := range ops {
		parsed, parseErr := modbus.ParseRequest(op.ADU)
		if parseErr != nil {
			t.Fatalf("операция %d: не удалось распарсить ADU: %v", i+1, parseErr)
		}
		if parsed.FunctionCode != modbus.FunctionCodeWriteSingleRegister {
			t.Fatalf("операция %d: ожидали FC06, получили 0x%02X", i+1, uint8(parsed.FunctionCode))
		}
		if parsed.StartAddress != 12 {
			t.Fatalf("операция %d: ожидали start=12, получили %d", i+1, parsed.StartAddress)
		}
		if parsed.Quantity != 1 {
			t.Fatalf("операция %d: ожидали quantity=1, получили %d", i+1, parsed.Quantity)
		}
		if len(parsed.RegisterValues) != 1 {
			t.Fatalf("операция %d: ожидали одно значение регистра", i+1)
		}
		expectedValue := uint16(1234)
		if parsed.RegisterValues[0] != expectedValue {
			t.Fatalf("операция %d: ожидали value=%d, получили %d", i+1, expectedValue, parsed.RegisterValues[0])
		}
	}
}

func TestBuildScenarioOperationsRareWrite(t *testing.T) {
	t.Parallel()

	ops, err := BuildScenarioOperations(ScenarioRareWrite, 1, 0)
	if err != nil {
		t.Fatalf("не удалось собрать rare-write: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("ожидали 1 операцию, получили %d", len(ops))
	}

	parsed, parseErr := modbus.ParseRequest(ops[0].ADU)
	if parseErr != nil {
		t.Fatalf("не удалось распарсить ADU rare-write: %v", parseErr)
	}
	if parsed.FunctionCode != modbus.FunctionCodeWriteMultipleRegs {
		t.Fatalf("ожидали FC16, получили 0x%02X", uint8(parsed.FunctionCode))
	}
	if parsed.StartAddress != 80 || parsed.Quantity != 2 {
		t.Fatalf("ожидали start=80 quantity=2, получили start=%d quantity=%d", parsed.StartAddress, parsed.Quantity)
	}
	if len(parsed.RegisterValues) != 2 || parsed.RegisterValues[0] != 777 || parsed.RegisterValues[1] != 888 {
		t.Fatalf("неожиданные register values: %+v", parsed.RegisterValues)
	}
}

func TestBuildScenarioOperationsForbiddenWrite(t *testing.T) {
	t.Parallel()

	ops, err := BuildScenarioOperations(ScenarioForbiddenWrite, 1, 0)
	if err != nil {
		t.Fatalf("не удалось собрать forbidden-write: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("ожидали 1 операцию, получили %d", len(ops))
	}

	parsed, parseErr := modbus.ParseRequest(ops[0].ADU)
	if parseErr != nil {
		t.Fatalf("не удалось распарсить ADU forbidden-write: %v", parseErr)
	}
	if parsed.FunctionCode != modbus.FunctionCodeWriteSingleRegister {
		t.Fatalf("ожидали FC06, получили 0x%02X", uint8(parsed.FunctionCode))
	}
	if parsed.StartAddress != 1000 {
		t.Fatalf("ожидали start=1000, получили %d", parsed.StartAddress)
	}
}

func TestBuildScenarioOperationsValidation(t *testing.T) {
	t.Parallel()

	if _, err := BuildScenarioOperations(ScenarioRepeatedWrite, 1, 0); err == nil {
		t.Fatal("ожидали ошибку при repeat=0 для repeated-write")
	}
	if _, err := BuildScenarioOperations(ScenarioNormalRead, 0, 0); err == nil {
		t.Fatal("ожидали ошибку при unit-id=0")
	}
}
