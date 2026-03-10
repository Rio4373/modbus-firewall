package generator

import (
	"reflect"
	"testing"

	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
)

func TestMergeAddressRanges(t *testing.T) {
	t.Parallel()

	input := []policy.AddressRange{
		{Start: 10, End: 20},
		{Start: 21, End: 25},
		{Start: 30, End: 40},
		{Start: 35, End: 45},
	}

	got := mergeAddressRanges(input)
	want := []policy.AddressRange{
		{Start: 10, End: 25},
		{Start: 30, End: 45},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ожидали merged ranges %v, получили %v", want, got)
	}
}

func TestFilterWriteRangesByThreshold(t *testing.T) {
	t.Parallel()

	counts := map[policy.AddressRange]int{
		{Start: 100, End: 100}: 3,
		{Start: 101, End: 101}: 1,
		{Start: 102, End: 103}: 2,
	}

	got := filterWriteRangesByThreshold(counts, 2)
	want := []policy.AddressRange{
		{Start: 100, End: 100},
		{Start: 102, End: 103},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ожидали write ranges %v, получили %v", want, got)
	}
}

func TestGeneratePolicyFromEvents(t *testing.T) {
	t.Parallel()

	events := []storage.ModbusEvent{
		{
			SourceIP:      "10.0.0.10",
			DestinationIP: "10.0.0.20",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  10,
			Quantity:      2,
			OperationType: storage.OperationTypeRead,
		},
		{
			SourceIP:      "10.0.0.10",
			DestinationIP: "10.0.0.20",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  12,
			Quantity:      1,
			OperationType: storage.OperationTypeRead,
		},
		{
			SourceIP:      "10.0.0.10",
			DestinationIP: "10.0.0.20",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  30,
			Quantity:      2,
			OperationType: storage.OperationTypeRead,
		},
		{
			SourceIP:      "10.0.0.10",
			DestinationIP: "10.0.0.20",
			UnitID:        1,
			FunctionCode:  6,
			StartAddress:  100,
			Quantity:      1,
			OperationType: storage.OperationTypeWrite,
		},
		{
			SourceIP:      "10.0.0.10",
			DestinationIP: "10.0.0.20",
			UnitID:        1,
			FunctionCode:  6,
			StartAddress:  100,
			Quantity:      1,
			OperationType: storage.OperationTypeWrite,
		},
		{
			SourceIP:      "10.0.0.10",
			DestinationIP: "10.0.0.20",
			UnitID:        1,
			FunctionCode:  6,
			StartAddress:  101,
			Quantity:      1,
			OperationType: storage.OperationTypeWrite,
		},
	}

	generated, err := GeneratePolicyFromEvents(events, 2)
	if err != nil {
		t.Fatalf("не удалось сгенерировать policy: %v", err)
	}

	if generated.DefaultAction != policy.DecisionDeny {
		t.Fatalf("ожидали default_action=deny, получили %q", generated.DefaultAction)
	}
	if len(generated.Rules) != 2 {
		t.Fatalf("ожидали 2 правила, получили %d", len(generated.Rules))
	}

	readRule := generated.Rules[0]
	if readRule.FunctionCodes[0] != 3 {
		t.Fatalf("ожидали read rule для FC=3, получили FC=%d", readRule.FunctionCodes[0])
	}
	readRangesWant := []policy.AddressRange{{Start: 10, End: 12}, {Start: 30, End: 31}}
	if !reflect.DeepEqual(readRule.AddressRanges, readRangesWant) {
		t.Fatalf("ожидали read ranges %v, получили %v", readRangesWant, readRule.AddressRanges)
	}

	writeRule := generated.Rules[1]
	if writeRule.FunctionCodes[0] != 6 {
		t.Fatalf("ожидали write rule для FC=6, получили FC=%d", writeRule.FunctionCodes[0])
	}
	writeRangesWant := []policy.AddressRange{{Start: 100, End: 100}}
	if !reflect.DeepEqual(writeRule.AddressRanges, writeRangesWant) {
		t.Fatalf("ожидали write ranges %v, получили %v", writeRangesWant, writeRule.AddressRanges)
	}
}
