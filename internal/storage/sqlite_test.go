package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteStoreInitializesSchema(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	var tableName string
	err := store.db.QueryRowContext(
		context.Background(),
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'modbus_events'`,
	).Scan(&tableName)
	if err != nil {
		if err == sql.ErrNoRows {
			t.Fatal("таблица modbus_events не создана")
		}
		t.Fatalf("не удалось проверить наличие таблицы modbus_events: %v", err)
	}

	if tableName != "modbus_events" {
		t.Fatalf("ожидали таблицу modbus_events, получили %q", tableName)
	}
}

func TestSQLiteStoreSaveAndListEvents(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	ctx := context.Background()
	base := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	event1 := ModbusEvent{
		Timestamp:     base,
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  100,
		Quantity:      2,
		OperationType: OperationTypeRead,
	}
	event2 := ModbusEvent{
		Timestamp:     base.Add(2 * time.Second),
		SourceIP:      "10.0.0.3",
		DestinationIP: "10.0.0.4",
		UnitID:        2,
		FunctionCode:  16,
		StartAddress:  200,
		Quantity:      4,
		OperationType: OperationTypeWrite,
	}

	id1, err := store.SaveEvent(ctx, event1)
	if err != nil {
		t.Fatalf("не удалось сохранить первое событие: %v", err)
	}
	if id1 == 0 {
		t.Fatal("ожидали ненулевой id для первого события")
	}

	id2, err := store.SaveEvent(ctx, event2)
	if err != nil {
		t.Fatalf("не удалось сохранить второе событие: %v", err)
	}
	if id2 <= id1 {
		t.Fatalf("ожидали, что id2 > id1, получили id1=%d id2=%d", id1, id2)
	}

	events, err := store.ListEvents(ctx, EventListFilter{Limit: 10})
	if err != nil {
		t.Fatalf("не удалось получить список событий: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("ожидали 2 события, получили %d", len(events))
	}

	if events[0].ID != id1 || events[1].ID != id2 {
		t.Fatalf("ожидали порядок id [%d, %d], получили [%d, %d]", id1, id2, events[0].ID, events[1].ID)
	}
}

func TestSQLiteStoreListEventsFilter(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	ctx := context.Background()
	base := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base,
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  10,
		Quantity:      1,
		OperationType: OperationTypeRead,
	})
	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base.Add(time.Second),
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  16,
		StartAddress:  20,
		Quantity:      2,
		OperationType: OperationTypeWrite,
	})

	fc := uint8(16)
	filtered, err := store.ListEvents(ctx, EventListFilter{
		FunctionCode:  &fc,
		OperationType: OperationTypeWrite,
		Limit:         10,
	})
	if err != nil {
		t.Fatalf("не удалось получить фильтрованный список событий: %v", err)
	}

	if len(filtered) != 1 {
		t.Fatalf("ожидали 1 событие после фильтрации, получили %d", len(filtered))
	}
	if filtered[0].FunctionCode != 16 || filtered[0].OperationType != OperationTypeWrite {
		t.Fatalf("получено неожиданное событие: %+v", filtered[0])
	}
}

func TestSQLiteStoreListEventsForReplay(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	ctx := context.Background()
	base := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base,
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  1,
		Quantity:      1,
		OperationType: OperationTypeRead,
	})
	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base.Add(time.Second),
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  4,
		StartAddress:  2,
		Quantity:      1,
		OperationType: OperationTypeRead,
	})
	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base.Add(2 * time.Second),
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  16,
		StartAddress:  3,
		Quantity:      2,
		OperationType: OperationTypeWrite,
	})

	replayEvents, err := store.ListEventsForReplay(ctx, 2)
	if err != nil {
		t.Fatalf("не удалось получить события для replay: %v", err)
	}

	if len(replayEvents) != 2 {
		t.Fatalf("ожидали 2 события для replay, получили %d", len(replayEvents))
	}

	if replayEvents[0].FunctionCode != 4 || replayEvents[1].FunctionCode != 16 {
		t.Fatalf("ожидали последние 2 события в хронологическом порядке, получили: %+v", replayEvents)
	}
}

func TestSQLiteStoreListPolicyCandidates(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	ctx := context.Background()
	base := time.Date(2026, 3, 9, 10, 0, 0, 0, time.UTC)

	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base,
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  100,
		Quantity:      2,
		OperationType: OperationTypeRead,
	})
	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base.Add(time.Second),
		SourceIP:      "10.0.0.1",
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  100,
		Quantity:      2,
		OperationType: OperationTypeRead,
	})
	mustSaveEvent(t, store, ModbusEvent{
		Timestamp:     base.Add(2 * time.Second),
		SourceIP:      "10.0.0.3",
		DestinationIP: "10.0.0.4",
		UnitID:        2,
		FunctionCode:  16,
		StartAddress:  200,
		Quantity:      4,
		OperationType: OperationTypeWrite,
	})

	candidates, err := store.ListPolicyCandidates(ctx, 10)
	if err != nil {
		t.Fatalf("не удалось получить кандидатов политики: %v", err)
	}

	if len(candidates) != 2 {
		t.Fatalf("ожидали 2 кандидата, получили %d", len(candidates))
	}

	if candidates[0].Hits != 2 {
		t.Fatalf("ожидали, что первый кандидат будет с hits=2, получили %d", candidates[0].Hits)
	}
	if candidates[0].FunctionCode != 3 || candidates[0].OperationType != OperationTypeRead {
		t.Fatalf("первый кандидат не соответствует ожидаемому шаблону: %+v", candidates[0])
	}
}

func TestSQLiteStoreSaveEventValidation(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	_, err := store.SaveEvent(context.Background(), ModbusEvent{
		DestinationIP: "10.0.0.2",
		UnitID:        1,
		FunctionCode:  3,
		StartAddress:  10,
		Quantity:      1,
		OperationType: OperationTypeRead,
	})
	if err == nil {
		t.Fatal("ожидали ошибку валидации при пустом source_ip")
	}
}

func TestSQLiteStoreListEventsValidation(t *testing.T) {
	t.Parallel()

	store := newTestSQLiteStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("не удалось закрыть store: %v", err)
		}
	}()

	_, err := store.ListEvents(context.Background(), EventListFilter{
		OperationType: OperationType("invalid"),
		Limit:         10,
	})
	if err == nil {
		t.Fatal("ожидали ошибку валидации при невалидном operation_type")
	}
}

func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()

	path := filepath.Join(t.TempDir(), "events.db")
	store, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("не удалось создать sqlite store: %v", err)
	}
	return store
}

func mustSaveEvent(t *testing.T, store *SQLiteStore, event ModbusEvent) int64 {
	t.Helper()

	id, err := store.SaveEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("не удалось сохранить событие: %v", err)
	}
	return id
}
