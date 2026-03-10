package generator

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
	"gopkg.in/yaml.v3"
)

// defaultBatchSize определяет размер порции чтения событий из storage.
const defaultBatchSize = 1000

// groupKey группирует события по ключевым признакам доступа.
type groupKey struct {
	SourceIP      string
	DestinationIP string
	UnitID        uint8
	FunctionCode  uint8
}

// groupBucket аккумулирует read-диапазоны и частоты write-диапазонов.
type groupBucket struct {
	readRanges  []policy.AddressRange
	writeCounts map[policy.AddressRange]int
}

// GeneratePolicy загружает события из storage и строит policy.
func GeneratePolicy(ctx context.Context, eventStore storage.EventStore, writeThreshold int) (policy.Policy, error) {
	if eventStore == nil {
		return policy.Policy{}, fmt.Errorf("eventStore обязателен")
	}

	events, err := loadAllEvents(ctx, eventStore, defaultBatchSize)
	if err != nil {
		return policy.Policy{}, err
	}

	return GeneratePolicyFromEvents(events, writeThreshold)
}

// GeneratePolicyFromEvents строит policy из набора событий с учетом порога writeThreshold.
func GeneratePolicyFromEvents(events []storage.ModbusEvent, writeThreshold int) (policy.Policy, error) {
	if writeThreshold <= 0 {
		return policy.Policy{}, fmt.Errorf("writeThreshold должен быть > 0")
	}

	groups := make(map[groupKey]*groupBucket)
	for _, event := range events {
		addressRange, ok := eventToRange(event)
		if !ok {
			continue
		}

		key := groupKey{
			SourceIP:      event.SourceIP,
			DestinationIP: event.DestinationIP,
			UnitID:        event.UnitID,
			FunctionCode:  event.FunctionCode,
		}

		bucket, exists := groups[key]
		if !exists {
			bucket = &groupBucket{writeCounts: make(map[policy.AddressRange]int)}
			groups[key] = bucket
		}

		switch event.OperationType {
		case storage.OperationTypeRead:
			bucket.readRanges = append(bucket.readRanges, addressRange)
		case storage.OperationTypeWrite:
			bucket.writeCounts[addressRange]++
		}
	}

	sortedKeys := sortGroupKeys(groups)
	rules := make([]policy.Rule, 0, len(sortedKeys)*2)
	ruleIndex := 1
	for _, key := range sortedKeys {
		bucket := groups[key]

		if len(bucket.readRanges) > 0 {
			mergedReadRanges := mergeAddressRanges(bucket.readRanges)
			if len(mergedReadRanges) > 0 {
				rules = append(rules, policy.Rule{
					ID:             fmt.Sprintf("gen-read-%03d", ruleIndex),
					Action:         policy.DecisionAllow,
					SourceIPs:      []string{key.SourceIP},
					DestinationIPs: []string{key.DestinationIP},
					UnitIDs:        []uint8{key.UnitID},
					FunctionCodes:  []uint8{key.FunctionCode},
					AddressRanges:  mergedReadRanges,
				})
				ruleIndex++
			}
		}

		writeRanges := filterWriteRangesByThreshold(bucket.writeCounts, writeThreshold)
		if len(writeRanges) > 0 {
			rules = append(rules, policy.Rule{
				ID:             fmt.Sprintf("gen-write-%03d", ruleIndex),
				Action:         policy.DecisionAllow,
				SourceIPs:      []string{key.SourceIP},
				DestinationIPs: []string{key.DestinationIP},
				UnitIDs:        []uint8{key.UnitID},
				FunctionCodes:  []uint8{key.FunctionCode},
				AddressRanges:  writeRanges,
			})
			ruleIndex++
		}
	}

	generatedPolicy := policy.Policy{
		Version:       1,
		DefaultAction: policy.DecisionDeny,
		Rules:         rules,
	}
	if err := generatedPolicy.Validate(); err != nil {
		return policy.Policy{}, fmt.Errorf("сгенерирована невалидная policy: %w", err)
	}

	return generatedPolicy, nil
}

// SavePolicy сериализует policy в YAML и сохраняет на диск.
func SavePolicy(path string, generatedPolicy policy.Policy) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("путь для policy обязателен")
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("не удалось создать директорию для policy %q: %w", dir, err)
		}
	}

	data, err := yaml.Marshal(generatedPolicy)
	if err != nil {
		return fmt.Errorf("не удалось сериализовать policy в YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("не удалось записать policy %q: %w", path, err)
	}

	return nil
}

// loadAllEvents постранично считывает все события из EventStore.
func loadAllEvents(ctx context.Context, eventStore storage.EventStore, batchSize int) ([]storage.ModbusEvent, error) {
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}

	allEvents := make([]storage.ModbusEvent, 0, batchSize)
	offset := 0
	for {
		batch, err := eventStore.ListEvents(ctx, storage.EventListFilter{Limit: batchSize, Offset: offset})
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать события из storage: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		allEvents = append(allEvents, batch...)
		offset += len(batch)
	}

	return allEvents, nil
}

// mergeAddressRanges объединяет пересекающиеся и соседние интервалы read-операций.
func mergeAddressRanges(ranges []policy.AddressRange) []policy.AddressRange {
	if len(ranges) == 0 {
		return nil
	}

	sorted := append([]policy.AddressRange(nil), ranges...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start == sorted[j].Start {
			return sorted[i].End < sorted[j].End
		}
		return sorted[i].Start < sorted[j].Start
	})

	merged := make([]policy.AddressRange, 0, len(sorted))
	current := sorted[0]
	for i := 1; i < len(sorted); i++ {
		next := sorted[i]
		if uint32(next.Start) <= uint32(current.End)+1 {
			if next.End > current.End {
				current.End = next.End
			}
			continue
		}
		merged = append(merged, current)
		current = next
	}
	merged = append(merged, current)

	return merged
}

// filterWriteRangesByThreshold оставляет только write-диапазоны с частотой >= threshold.
func filterWriteRangesByThreshold(writeCounts map[policy.AddressRange]int, threshold int) []policy.AddressRange {
	if threshold <= 0 || len(writeCounts) == 0 {
		return nil
	}

	filtered := make([]policy.AddressRange, 0, len(writeCounts))
	for addressRange, count := range writeCounts {
		if count >= threshold {
			filtered = append(filtered, addressRange)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Start == filtered[j].Start {
			return filtered[i].End < filtered[j].End
		}
		return filtered[i].Start < filtered[j].Start
	})

	return filtered
}

// sortGroupKeys сортирует ключи групп для детерминированной генерации policy.
func sortGroupKeys(groups map[groupKey]*groupBucket) []groupKey {
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}

	sort.Slice(keys, func(i, j int) bool {
		if keys[i].SourceIP != keys[j].SourceIP {
			return keys[i].SourceIP < keys[j].SourceIP
		}
		if keys[i].DestinationIP != keys[j].DestinationIP {
			return keys[i].DestinationIP < keys[j].DestinationIP
		}
		if keys[i].UnitID != keys[j].UnitID {
			return keys[i].UnitID < keys[j].UnitID
		}
		return keys[i].FunctionCode < keys[j].FunctionCode
	})

	return keys
}

// eventToRange переводит событие в адресный диапазон [start, end].
func eventToRange(event storage.ModbusEvent) (policy.AddressRange, bool) {
	if event.Quantity == 0 {
		return policy.AddressRange{}, false
	}

	endAddress := uint32(event.StartAddress) + uint32(event.Quantity) - 1
	if endAddress > 0xFFFF {
		return policy.AddressRange{}, false
	}

	return policy.AddressRange{
		Start: event.StartAddress,
		End:   uint16(endAddress),
	}, true
}
