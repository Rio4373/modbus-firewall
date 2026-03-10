package replay

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
)

func TestAnalyzeEventsBuildsReport(t *testing.T) {
	t.Parallel()

	matcher := mustMatcher(t, policy.Policy{
		Version:       1,
		DefaultAction: policy.DecisionDeny,
		Rules: []policy.Rule{
			{
				ID:             "allow-read",
				Action:         policy.DecisionAllow,
				SourceIPs:      []string{"10.0.0.1"},
				DestinationIPs: []string{"10.0.0.2"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []policy.AddressRange{{Start: 10, End: 20}},
			},
		},
	})

	events := []storage.ModbusEvent{
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  12,
			Quantity:      2,
			OperationType: storage.OperationTypeRead,
		},
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  30,
			Quantity:      1,
			OperationType: storage.OperationTypeRead,
		},
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  6,
			StartAddress:  100,
			Quantity:      1,
			OperationType: storage.OperationTypeWrite,
		},
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  6,
			StartAddress:  100,
			Quantity:      1,
			OperationType: storage.OperationTypeWrite,
		},
	}

	report, err := AnalyzeEvents(events, matcher)
	if err != nil {
		t.Fatalf("не удалось выполнить replay анализ: %v", err)
	}

	if report.TotalEvents != 4 {
		t.Fatalf("ожидали total=4, получили %d", report.TotalEvents)
	}
	if report.CoveredEvents != 1 {
		t.Fatalf("ожидали covered=1, получили %d", report.CoveredEvents)
	}
	if report.BlockedEvents != 3 {
		t.Fatalf("ожидали blocked=3, получили %d", report.BlockedEvents)
	}

	if len(report.UncoveredOperations) != 2 {
		t.Fatalf("ожидали 2 uncovered operation, получили %d", len(report.UncoveredOperations))
	}

	if report.UncoveredOperations[0].Count != 2 {
		t.Fatalf("ожидали первую uncovered operation с count=2, получили %d", report.UncoveredOperations[0].Count)
	}

	want := []UncoveredOperation{
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  6,
			StartAddress:  100,
			EndAddress:    100,
			Quantity:      1,
			OperationType: storage.OperationTypeWrite,
			Count:         2,
		},
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  30,
			EndAddress:    30,
			Quantity:      1,
			OperationType: storage.OperationTypeRead,
			Count:         1,
		},
	}
	if !reflect.DeepEqual(report.UncoveredOperations, want) {
		t.Fatalf("unexpected uncovered operations:\nwant=%+v\ngot=%+v", want, report.UncoveredOperations)
	}
}

func TestAnalyzeEventsInvalidEventBecomesBlocked(t *testing.T) {
	t.Parallel()

	matcher := mustMatcher(t, policy.Policy{Version: 1, DefaultAction: policy.DecisionDeny, Rules: nil})
	report, err := AnalyzeEvents([]storage.ModbusEvent{
		{
			SourceIP:      "10.0.0.1",
			DestinationIP: "10.0.0.2",
			UnitID:        1,
			FunctionCode:  3,
			StartAddress:  0,
			Quantity:      0,
			OperationType: storage.OperationTypeRead,
		},
	}, matcher)
	if err != nil {
		t.Fatalf("не ожидали ошибки AnalyzeEvents, получили: %v", err)
	}

	if report.TotalEvents != 1 || report.CoveredEvents != 0 || report.BlockedEvents != 1 {
		t.Fatalf("unexpected totals: %+v", report)
	}
	if len(report.UncoveredOperations) != 1 {
		t.Fatalf("ожидали 1 uncovered operation, получили %d", len(report.UncoveredOperations))
	}
}

func TestRunLoadsEventsFromStore(t *testing.T) {
	t.Parallel()

	matcher := mustMatcher(t, policy.Policy{
		Version:       1,
		DefaultAction: policy.DecisionDeny,
		Rules: []policy.Rule{
			{
				ID:             "allow",
				Action:         policy.DecisionAllow,
				SourceIPs:      []string{"10.0.0.1"},
				DestinationIPs: []string{"10.0.0.2"},
				UnitIDs:        []uint8{1},
				FunctionCodes:  []uint8{3},
				AddressRanges:  []policy.AddressRange{{Start: 0, End: 100}},
			},
		},
	})

	store := &fakeEventStore{events: []storage.ModbusEvent{
		{SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2", UnitID: 1, FunctionCode: 3, StartAddress: 5, Quantity: 1, OperationType: storage.OperationTypeRead},
	}}

	report, err := Run(context.Background(), store, matcher)
	if err != nil {
		t.Fatalf("не удалось выполнить Run: %v", err)
	}
	if report.TotalEvents != 1 || report.CoveredEvents != 1 || report.BlockedEvents != 0 {
		t.Fatalf("unexpected totals: %+v", report)
	}
}

func mustMatcher(t *testing.T, policyCfg policy.Policy) policy.Engine {
	t.Helper()

	matcher, err := policy.NewMatcher(policyCfg)
	if err != nil {
		t.Fatalf("не удалось создать matcher: %v", err)
	}
	return matcher
}

type fakeEventStore struct {
	events []storage.ModbusEvent
}

func (f *fakeEventStore) SaveEvent(context.Context, storage.ModbusEvent) (int64, error) {
	return 0, errors.New("not implemented")
}

func (f *fakeEventStore) ListEvents(_ context.Context, filter storage.EventListFilter) ([]storage.ModbusEvent, error) {
	if filter.Offset >= len(f.events) {
		return []storage.ModbusEvent{}, nil
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = len(f.events)
	}
	end := filter.Offset + limit
	if end > len(f.events) {
		end = len(f.events)
	}

	batch := make([]storage.ModbusEvent, end-filter.Offset)
	copy(batch, f.events[filter.Offset:end])
	return batch, nil
}

func (f *fakeEventStore) ListEventsForReplay(context.Context, int) ([]storage.ModbusEvent, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeEventStore) ListPolicyCandidates(context.Context, int) ([]storage.PolicyCandidate, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeEventStore) Close() error {
	return nil
}
