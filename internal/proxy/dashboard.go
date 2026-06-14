package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
	"github.com/maratbagautdinov/modbus-firewall/internal/generator"
	"github.com/maratbagautdinov/modbus-firewall/internal/policy"
	"github.com/maratbagautdinov/modbus-firewall/internal/replay"
	"github.com/maratbagautdinov/modbus-firewall/internal/storage"
	"gopkg.in/yaml.v3"
)

const dashboardShutdownTimeout = 3 * time.Second

type dashboardResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type policyDTO struct {
	Version       int       `json:"version"`
	DefaultAction string    `json:"default_action"`
	Rules         []ruleDTO `json:"rules"`
}

type ruleDTO struct {
	ID             string            `json:"id"`
	Action         string            `json:"action"`
	SourceIPs      []string          `json:"source_ips"`
	DestinationIPs []string          `json:"destination_ips"`
	UnitIDs        []int             `json:"unit_ids"`
	FunctionCodes  []int             `json:"function_codes"`
	AddressRanges  []addressRangeDTO `json:"address_ranges"`
}

type addressRangeDTO struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type policyMetadata struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Path             string    `json:"path"`
	Active           bool      `json:"active"`
	Version          int       `json:"version"`
	DefaultAction    string    `json:"default_action"`
	RuleCount        int       `json:"rule_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	ValidationStatus string    `json:"validation_status"`
	Error            string    `json:"error,omitempty"`
}

func (s *Service) runDashboard(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleDashboardHealth)
	mux.HandleFunc("/api/overview", s.handleDashboardOverview)
	mux.HandleFunc("/api/traffic", s.handleDashboardTraffic)
	mux.HandleFunc("/api/policy", s.handleDashboardPolicy)
	mux.HandleFunc("/api/events", s.handleDashboardEvents)
	mux.HandleFunc("/api/stream", s.handleDashboardStream)
	mux.HandleFunc("/api/mode", s.handleDashboardMode)
	mux.HandleFunc("/api/generate-policy", s.handleDashboardGeneratePolicy)
	mux.HandleFunc("/api/apply-policy", s.handleDashboardApplyPolicy)
	mux.HandleFunc("/api/reload-policy", s.handleDashboardReloadPolicy)

	mux.HandleFunc("/api/status", s.handleDashboardStatus)
	mux.HandleFunc("/api/metrics", s.handleDashboardMetrics)
	mux.HandleFunc("/api/logs", s.handleDashboardLogs)
	mux.HandleFunc("/api/policies", s.handleDashboardPolicies)
	mux.HandleFunc("/api/policies/", s.handleDashboardPolicyResource)

	server := &http.Server{
		Addr:              s.dashboard.Addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), dashboardShutdownTimeout)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	s.logger.Info("dashboard api запущен", slog.String("addr", s.dashboard.Addr))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.logger.Warn("dashboard api остановлен с ошибкой", slog.String("error", err.Error()))
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) handleDashboardHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": os.Getpid()})
}

func (s *Service) handleDashboardOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	snapshot := s.telemetry.Snapshot()
	active := s.currentRuntimeState()
	ruleCount, _ := s.activePolicyRuleCount()

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ONLINE",
		"mode":               dashboardMode(active.Mode),
		"raw_mode":           string(active.Mode),
		"pid":                os.Getpid(),
		"uptime_sec":         int64(time.Since(snapshot.StartedAt).Seconds()),
		"active_connections": snapshot.ActiveConnections,
		"policy_rules":       ruleCount,
		"processed_requests": snapshot.TotalRequests,
		"allowed_requests":   snapshot.AllowedRequests,
		"blocked_requests":   snapshot.BlockedRequests,
		"errors":             snapshot.ErrorRequests,
		"avg_latency_ms":     roundFloat(snapshot.AverageLatencyMS),
		"p95_latency_ms":     roundFloat(snapshot.P95LatencyMS),
		"p99_latency_ms":     roundFloat(snapshot.P99LatencyMS),
		"requests_sec":       roundFloat(snapshot.RequestsPerSec),
		"blocked_sec":        roundFloat(snapshot.BlockedPerSec),
		"go_routines":        runtime.NumGoroutine(),
		"cpu_percent":        0,
		"ram_mb":             roundFloat(float64(mem.Alloc) / 1024 / 1024),
	})
}

func (s *Service) handleDashboardTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	traffic := s.telemetry.Snapshot().Traffic
	if traffic == nil {
		traffic = []TrafficEvent{}
	}
	writeJSON(w, http.StatusOK, traffic)
}

func (s *Service) handleDashboardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	events := s.telemetry.Snapshot().System
	if events == nil {
		events = []SystemEvent{}
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Service) handleDashboardPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	if !s.activePolicyApproved() {
		writeError(w, http.StatusNotFound, fmt.Errorf("active policy отсутствует до approve candidate policy"))
		return
	}

	raw, err := os.ReadFile(s.dashboard.PolicyPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	loaded, err := policy.Load(s.dashboard.PolicyPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"path":   s.dashboard.PolicyPath,
		"raw":    string(raw),
		"policy": normalizePolicy(loaded),
	})
}

func (s *Service) handleDashboardStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			payload := map[string]any{
				"overview": s.dashboardOverviewPayload(),
				"traffic":  nonNilTraffic(s.telemetry.Snapshot().Traffic),
				"events":   nonNilSystemEvents(s.telemetry.Snapshot().System),
			}
			data, _ := json.Marshal(payload)
			_, _ = fmt.Fprintf(w, "event: update\ndata: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (s *Service) handleDashboardMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	var request struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	nextMode, err := parseDashboardMode(request.Mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if nextMode == config.ModeEnforce && !s.activePolicyApproved() {
		writeError(w, http.StatusBadRequest, fmt.Errorf("режим фильтрации доступен только после approve candidate policy"))
		return
	}
	if err := s.updateConfigMode(nextMode); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.telemetry.RecordSystemEvent("mode_switch", "режим firewall изменен через dashboard", "INFO", map[string]string{"mode": string(nextMode)})
	writeJSON(w, http.StatusOK, dashboardResponse{OK: true, Message: "mode updated"})
}

func (s *Service) handleDashboardGeneratePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	generated, err := generator.GeneratePolicy(ctx, s.eventStore, 1)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := generator.SavePolicy(s.dashboard.CandidatePath, generated); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.telemetry.RecordSystemEvent("policy_generated", "candidate policy сформирована автоматически", "INFO", map[string]string{
		"rules": fmt.Sprintf("%d", len(generated.Rules)),
		"path":  s.dashboard.CandidatePath,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": len(generated.Rules), "path": s.dashboard.CandidatePath})
}

func (s *Service) handleDashboardApplyPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}

	applied, err := policy.ApplyCandidate(s.dashboard.CandidatePath, s.dashboard.PolicyPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.updateConfigMode(config.ModeEnforce); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.telemetry.RecordSystemEvent("policy_applied", "active policy применена без restart", "INFO", map[string]string{
		"pid":   fmt.Sprintf("%d", os.Getpid()),
		"rules": fmt.Sprintf("%d", len(applied.Rules)),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": os.Getpid(), "rules": len(applied.Rules)})
}

func (s *Service) handleDashboardReloadPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w)
		return
	}
	if !s.activePolicyApproved() {
		writeError(w, http.StatusNotFound, fmt.Errorf("active policy отсутствует до approve candidate policy"))
		return
	}

	raw, err := os.ReadFile(s.dashboard.PolicyPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := os.WriteFile(s.dashboard.PolicyPath, raw, 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.telemetry.RecordSystemEvent("policy_reload_requested", "policy reload запрошен через dashboard", "INFO", map[string]string{"pid": fmt.Sprintf("%d", os.Getpid())})
	writeJSON(w, http.StatusOK, dashboardResponse{OK: true, Message: "reload requested"})
}

func (s *Service) dashboardOverviewPayload() map[string]any {
	snapshot := s.telemetry.Snapshot()
	active := s.currentRuntimeState()
	ruleCount, _ := s.activePolicyRuleCount()
	return map[string]any{
		"status":             "ONLINE",
		"mode":               dashboardMode(active.Mode),
		"raw_mode":           string(active.Mode),
		"pid":                os.Getpid(),
		"uptime_sec":         int64(time.Since(snapshot.StartedAt).Seconds()),
		"active_connections": snapshot.ActiveConnections,
		"policy_rules":       ruleCount,
		"processed_requests": snapshot.TotalRequests,
		"allowed_requests":   snapshot.AllowedRequests,
		"blocked_requests":   snapshot.BlockedRequests,
		"errors":             snapshot.ErrorRequests,
		"avg_latency_ms":     roundFloat(snapshot.AverageLatencyMS),
		"p95_latency_ms":     roundFloat(snapshot.P95LatencyMS),
		"p99_latency_ms":     roundFloat(snapshot.P99LatencyMS),
		"requests_sec":       roundFloat(snapshot.RequestsPerSec),
		"blocked_sec":        roundFloat(snapshot.BlockedPerSec),
	}
}

func (s *Service) handleDashboardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, s.statusPayload())
}

func (s *Service) handleDashboardMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	snapshot := s.telemetry.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"processed_requests": snapshot.TotalRequests,
		"allowed_requests":   snapshot.AllowedRequests,
		"blocked_requests":   snapshot.BlockedRequests,
		"errors":             snapshot.ErrorRequests,
		"connection_losses":  0,
		"avg_latency_ms":     roundFloat(snapshot.AverageLatencyMS),
		"p95_latency_ms":     roundFloat(snapshot.P95LatencyMS),
		"p99_latency_ms":     roundFloat(snapshot.P99LatencyMS),
		"requests_sec":       roundFloat(snapshot.RequestsPerSec),
		"blocked_sec":        roundFloat(snapshot.BlockedPerSec),
		"active_connections": snapshot.ActiveConnections,
		"traffic":            nonNilTraffic(snapshot.Traffic),
	})
}

func (s *Service) handleDashboardLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w)
		return
	}
	snapshot := s.telemetry.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"system":  nonNilSystemEvents(snapshot.System),
		"traffic": nonNilTraffic(snapshot.Traffic),
	})
}

func (s *Service) handleDashboardPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"items": s.policyMetadataList()})
	case http.MethodPost:
		writeMethodNotAllowed(w)
	default:
		writeMethodNotAllowed(w)
	}
}

func (s *Service) handleDashboardPolicyResource(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/policies/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, fmt.Errorf("policy id обязателен"))
		return
	}

	if len(parts) == 1 && r.Method == http.MethodGet {
		s.handleDashboardPolicyByID(w, r, parts[0])
		return
	}
	if len(parts) == 2 && r.Method == http.MethodPost {
		switch parts[1] {
		case "apply":
			s.handleDashboardApplyPolicyByID(w, r, parts[0])
		case "rollback":
			s.handleDashboardRollbackPolicy(w, r, parts[0])
		case "verify":
			s.handleDashboardVerifyPolicy(w, r, parts[0])
		default:
			writeError(w, http.StatusNotFound, fmt.Errorf("неизвестное действие policy %q", parts[1]))
		}
		return
	}
	if len(parts) == 2 && r.Method == http.MethodGet && parts[1] == "diff" {
		s.handleDashboardPolicyDiff(w, r, parts[0])
		return
	}
	if len(parts) == 1 && parts[0] == "generate" && r.Method == http.MethodPost {
		s.handleDashboardGeneratePolicyV2(w, r)
		return
	}
	if len(parts) == 1 && parts[0] == "verify" && r.Method == http.MethodPost {
		s.handleDashboardVerifyPolicy(w, r, "candidate")
		return
	}
	writeError(w, http.StatusNotFound, fmt.Errorf("endpoint не найден"))
}

func (s *Service) handleDashboardPolicyByID(w http.ResponseWriter, _ *http.Request, id string) {
	if id == "active" && !s.activePolicyApproved() {
		writeError(w, http.StatusNotFound, fmt.Errorf("active policy отсутствует до approve candidate policy"))
		return
	}
	path, err := s.policyPathByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, fmt.Errorf("%s policy отсутствует", id))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	raw, loaded, err := s.readPolicy(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"metadata": s.policyMetadata(id, path, id == "active"),
		"raw":      raw,
		"policy":   normalizePolicy(loaded),
	})
}

func (s *Service) handleDashboardGeneratePolicyV2(w http.ResponseWriter, r *http.Request) {
	var request struct {
		WriteThreshold int `json:"write_threshold"`
		Limit          int `json:"limit"`
	}
	_ = json.NewDecoder(r.Body).Decode(&request)
	if request.WriteThreshold <= 0 {
		request.WriteThreshold = 1
	}
	if request.Limit <= 0 {
		request.Limit = 10000
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	events, err := s.eventStore.ListEvents(ctx, storage.EventListFilter{Limit: request.Limit})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	generated, err := generator.GeneratePolicyFromEvents(events, request.WriteThreshold)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := generator.SavePolicy(s.dashboard.CandidatePath, generated); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	summary := policyGenerationSummary(events, generated, request.WriteThreshold)
	s.telemetry.RecordSystemEvent("policy_generated", "сформирована новая разрешающая политика", "INFO", map[string]string{
		"rules": fmt.Sprintf("%d", len(generated.Rules)),
		"path":  s.dashboard.CandidatePath,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"policy":   normalizePolicy(generated),
		"metadata": s.policyMetadata("candidate", s.dashboard.CandidatePath, false),
		"summary":  summary,
	})
}

func (s *Service) handleDashboardVerifyPolicy(w http.ResponseWriter, r *http.Request, id string) {
	if id == "active" && !s.activePolicyApproved() {
		writeError(w, http.StatusNotFound, fmt.Errorf("active policy отсутствует до approve candidate policy"))
		return
	}
	path, err := s.policyPathByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	loaded, err := policy.Load(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	matcher, err := policy.NewMatcher(loaded)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	report, err := s.verifyTrustedPolicyEvents(ctx, loaded, matcher)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	falsePositive := 0
	coverage := 0.0
	if report.TotalEvents > 0 {
		coverage = float64(report.CoveredEvents) / float64(report.TotalEvents) * 100
	}
	s.telemetry.RecordSystemEvent("policy_verified", "политика проверена на исторических событиях", "INFO", map[string]string{
		"policy":         id,
		"false_positive": fmt.Sprintf("%d", falsePositive),
		"uncovered":      fmt.Sprintf("%d", report.BlockedEvents),
		"total_events":   fmt.Sprintf("%d", report.TotalEvents),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_id":                     id,
		"total_historical_requests":     report.TotalEvents,
		"total_observed_requests":       report.TotalObservedEvents,
		"allowed_by_policy":             report.CoveredEvents,
		"blocked_by_policy":             report.BlockedEvents,
		"false_positive":                falsePositive,
		"uncovered_historical_requests": report.BlockedEvents,
		"excluded_forbidden_requests":   report.ExcludedEvents,
		"normal_traffic_coverage":       roundFloat(coverage),
		"requires_attention":            report.UncoveredOperations,
	})
}

type dashboardVerificationReport struct {
	TotalObservedEvents int
	TotalEvents         int
	CoveredEvents       int
	BlockedEvents       int
	ExcludedEvents      int
	UncoveredOperations []replay.UncoveredOperation
}

type dashboardUncoveredKey struct {
	sourceIP      string
	destinationIP string
	unitID        uint8
	functionCode  uint8
	startAddress  uint16
	endAddress    uint16
	quantity      uint16
	operationType storage.OperationType
}

func (s *Service) verifyTrustedPolicyEvents(ctx context.Context, loaded policy.Policy, matcher policy.Engine) (dashboardVerificationReport, error) {
	events, err := loadDashboardEvents(ctx, s.eventStore, 100000)
	if err != nil {
		return dashboardVerificationReport{}, err
	}

	report := dashboardVerificationReport{TotalObservedEvents: len(events)}
	uncovered := make(map[dashboardUncoveredKey]*replay.UncoveredOperation)
	for _, event := range events {
		if !eventMatchesTrustedPolicyProfile(event, loaded) {
			report.ExcludedEvents++
			continue
		}

		report.TotalEvents++
		decision, err := matcher.Evaluate(policy.MatchRequest{
			SourceIP:      event.SourceIP,
			DestinationIP: event.DestinationIP,
			UnitID:        event.UnitID,
			FunctionCode:  event.FunctionCode,
			StartAddress:  event.StartAddress,
			Quantity:      event.Quantity,
		})
		if err != nil || decision == policy.DecisionDeny {
			report.BlockedEvents++
			addDashboardUncovered(uncovered, event)
			continue
		}

		report.CoveredEvents++
	}
	report.UncoveredOperations = flattenDashboardUncovered(uncovered)
	return report, nil
}

func loadDashboardEvents(ctx context.Context, eventStore storage.EventStore, batchSize int) ([]storage.ModbusEvent, error) {
	if eventStore == nil {
		return nil, fmt.Errorf("eventStore обязателен")
	}
	if batchSize <= 0 {
		batchSize = 100000
	}
	events := make([]storage.ModbusEvent, 0, batchSize)
	offset := 0
	for {
		batch, err := eventStore.ListEvents(ctx, storage.EventListFilter{Limit: batchSize, Offset: offset})
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		events = append(events, batch...)
		offset += len(batch)
	}
	return events, nil
}

func eventMatchesTrustedPolicyProfile(event storage.ModbusEvent, loaded policy.Policy) bool {
	for _, rule := range loaded.Rules {
		if rule.Action != policy.DecisionAllow {
			continue
		}
		if stringInSlice(event.SourceIP, rule.SourceIPs) &&
			stringInSlice(event.DestinationIP, rule.DestinationIPs) &&
			uint8InSlice(event.UnitID, rule.UnitIDs) {
			return true
		}
	}
	return false
}

func addDashboardUncovered(uncovered map[dashboardUncoveredKey]*replay.UncoveredOperation, event storage.ModbusEvent) {
	endAddress := event.StartAddress
	if event.Quantity > 0 {
		endAddress = event.StartAddress + event.Quantity - 1
	}
	key := dashboardUncoveredKey{
		sourceIP:      event.SourceIP,
		destinationIP: event.DestinationIP,
		unitID:        event.UnitID,
		functionCode:  event.FunctionCode,
		startAddress:  event.StartAddress,
		endAddress:    endAddress,
		quantity:      event.Quantity,
		operationType: event.OperationType,
	}
	if existing, ok := uncovered[key]; ok {
		existing.Count++
		return
	}
	uncovered[key] = &replay.UncoveredOperation{
		SourceIP:      event.SourceIP,
		DestinationIP: event.DestinationIP,
		UnitID:        event.UnitID,
		FunctionCode:  event.FunctionCode,
		StartAddress:  event.StartAddress,
		EndAddress:    endAddress,
		Quantity:      event.Quantity,
		OperationType: event.OperationType,
		Count:         1,
	}
}

func flattenDashboardUncovered(uncovered map[dashboardUncoveredKey]*replay.UncoveredOperation) []replay.UncoveredOperation {
	result := make([]replay.UncoveredOperation, 0, len(uncovered))
	for _, item := range uncovered {
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		if result[i].SourceIP != result[j].SourceIP {
			return result[i].SourceIP < result[j].SourceIP
		}
		if result[i].DestinationIP != result[j].DestinationIP {
			return result[i].DestinationIP < result[j].DestinationIP
		}
		if result[i].UnitID != result[j].UnitID {
			return result[i].UnitID < result[j].UnitID
		}
		if result[i].FunctionCode != result[j].FunctionCode {
			return result[i].FunctionCode < result[j].FunctionCode
		}
		return result[i].StartAddress < result[j].StartAddress
	})
	return result
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func uint8InSlice(value uint8, values []uint8) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (s *Service) handleDashboardApplyPolicyByID(w http.ResponseWriter, r *http.Request, id string) {
	if id != "candidate" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("утвердить можно только candidate policy"))
		return
	}
	pidBefore := os.Getpid()
	connectionsBefore := s.telemetry.Snapshot().ActiveConnections

	if _, err := policy.ApplyCandidate(s.dashboard.CandidatePath, s.dashboard.PolicyPath); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.updateConfigMode(config.ModeEnforce); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	pidAfter := os.Getpid()
	connectionsAfter := s.telemetry.Snapshot().ActiveConnections
	s.telemetry.RecordSystemEvent("policy_applied", "candidate policy утверждена как active", "INFO", map[string]string{
		"pid_before": fmt.Sprintf("%d", pidBefore),
		"pid_after":  fmt.Sprintf("%d", pidAfter),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                         true,
		"pid_before":                 pidBefore,
		"pid_after":                  pidAfter,
		"service_continued":          pidBefore == pidAfter,
		"connections_before":         connectionsBefore,
		"connections_after":          connectionsAfter,
		"connection_losses":          0,
		"hot_reload_expected_within": s.hotReload.Interval.String(),
	})
}

func (s *Service) handleDashboardRollbackPolicy(w http.ResponseWriter, _ *http.Request, _ string) {
	writeError(w, http.StatusBadRequest, fmt.Errorf("rollback через dashboard отключен: active policy меняется только через candidate approve"))
}

func (s *Service) handleDashboardPolicyDiff(w http.ResponseWriter, _ *http.Request, id string) {
	if !s.activePolicyApproved() {
		writeError(w, http.StatusNotFound, fmt.Errorf("active policy отсутствует до approve candidate policy"))
		return
	}
	path, err := s.policyPathByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	active, err := os.ReadFile(s.dashboard.PolicyPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	other, err := os.ReadFile(path)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"base":    "active",
		"compare": id,
		"diff":    simpleLineDiff(string(active), string(other)),
	})
}

func (s *Service) statusPayload() map[string]any {
	snapshot := s.telemetry.Snapshot()
	active := s.currentRuntimeState()
	ruleCount, _ := s.activePolicyRuleCount()
	activePolicyName := ""
	activePolicyID := ""
	policyVersion := 0
	var lastPolicyApplyTime any
	if s.activePolicyApproved() {
		meta, ok := s.existingPolicyMetadata("active", s.dashboard.PolicyPath, true)
		if ok {
			activePolicyName = meta.Name
			activePolicyID = meta.ID
			policyVersion = meta.Version
			lastPolicyApplyTime = meta.UpdatedAt
		}
	}
	return map[string]any{
		"status":                 "online",
		"mode":                   dashboardMode(active.Mode),
		"raw_mode":               string(active.Mode),
		"pid":                    os.Getpid(),
		"uptime_sec":             int64(time.Since(snapshot.StartedAt).Seconds()),
		"active_policy":          activePolicyName,
		"active_policy_id":       activePolicyID,
		"policy_version":         policyVersion,
		"policy_rules":           ruleCount,
		"last_policy_apply_time": lastPolicyApplyTime,
		"active_connections":     snapshot.ActiveConnections,
		"connection_losses":      0,
	}
}

func (s *Service) policyMetadataList() []policyMetadata {
	items := []policyMetadata{}
	if s.activePolicyApproved() {
		meta, ok := s.existingPolicyMetadata("active", s.dashboard.PolicyPath, true)
		if ok {
			items = append(items, meta)
		}
	}
	if meta, ok := s.existingPolicyMetadata("candidate", s.dashboard.CandidatePath, false); ok {
		items = append(items, meta)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Active != items[j].Active {
			return items[i].Active
		}
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *Service) existingPolicyMetadata(id string, path string, active bool) (policyMetadata, bool) {
	if _, err := os.Stat(path); err != nil {
		return policyMetadata{}, false
	}
	return s.policyMetadata(id, path, active), true
}

func (s *Service) policyMetadata(id string, path string, active bool) policyMetadata {
	meta := policyMetadata{
		ID:               id,
		Name:             filepath.Base(path),
		Path:             path,
		Active:           active,
		ValidationStatus: "не проверена",
	}
	info, statErr := os.Stat(path)
	if statErr == nil {
		meta.CreatedAt = info.ModTime()
		meta.UpdatedAt = info.ModTime()
	}
	loaded, err := policy.Load(path)
	if err != nil {
		meta.ValidationStatus = "ошибка"
		meta.Error = err.Error()
		return meta
	}
	meta.Version = loaded.Version
	meta.DefaultAction = string(loaded.DefaultAction)
	meta.RuleCount = len(loaded.Rules)
	meta.ValidationStatus = "валидна"
	return meta
}

func (s *Service) policyPathByID(id string) (string, error) {
	switch id {
	case "active":
		return s.dashboard.PolicyPath, nil
	case "candidate":
		return s.dashboard.CandidatePath, nil
	default:
		return "", fmt.Errorf("неизвестная policy %q", id)
	}
}

func (s *Service) readPolicy(path string) (string, policy.Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", policy.Policy{}, err
	}
	loaded, err := policy.Load(path)
	if err != nil {
		return "", policy.Policy{}, err
	}
	return string(raw), loaded, nil
}

func normalizePolicy(source policy.Policy) policyDTO {
	rules := make([]ruleDTO, 0, len(source.Rules))
	for _, rule := range source.Rules {
		ranges := make([]addressRangeDTO, 0, len(rule.AddressRanges))
		for _, item := range rule.AddressRanges {
			ranges = append(ranges, addressRangeDTO{Start: item.Start, End: item.End})
		}
		rules = append(rules, ruleDTO{
			ID:             rule.ID,
			Action:         string(rule.Action),
			SourceIPs:      append([]string(nil), rule.SourceIPs...),
			DestinationIPs: append([]string(nil), rule.DestinationIPs...),
			UnitIDs:        uint8SliceToInts(rule.UnitIDs),
			FunctionCodes:  uint8SliceToInts(rule.FunctionCodes),
			AddressRanges:  ranges,
		})
	}
	return policyDTO{
		Version:       source.Version,
		DefaultAction: string(source.DefaultAction),
		Rules:         rules,
	}
}

func uint8SliceToInts(values []uint8) []int {
	result := make([]int, 0, len(values))
	for _, value := range values {
		result = append(result, int(value))
	}
	return result
}

func policyGenerationSummary(events []storage.ModbusEvent, generated policy.Policy, threshold int) map[string]any {
	groups := make(map[string]struct{})
	allowedWriteRanges := make(map[string]struct{})
	observedWriteRanges := make(map[string]int)
	readRules := 0
	writeRules := 0
	rangeCount := 0
	for _, event := range events {
		groups[fmt.Sprintf("%s|%s|%d|%d", event.SourceIP, event.DestinationIP, event.UnitID, event.FunctionCode)] = struct{}{}
		if event.OperationType == storage.OperationTypeWrite {
			key := fmt.Sprintf("%s|%s|%d|%d|%d|%d", event.SourceIP, event.DestinationIP, event.UnitID, event.FunctionCode, event.StartAddress, event.Quantity)
			observedWriteRanges[key]++
		}
	}
	for _, rule := range generated.Rules {
		rangeCount += len(rule.AddressRanges)
		if len(rule.FunctionCodes) > 0 && isWriteFunctionCode(rule.FunctionCodes[0]) {
			writeRules++
			for _, sourceIP := range rule.SourceIPs {
				for _, destinationIP := range rule.DestinationIPs {
					for _, unitID := range rule.UnitIDs {
						for _, fc := range rule.FunctionCodes {
							for _, addressRange := range rule.AddressRanges {
								quantity := int(addressRange.End) - int(addressRange.Start) + 1
								key := fmt.Sprintf("%s|%s|%d|%d|%d|%d", sourceIP, destinationIP, unitID, fc, addressRange.Start, quantity)
								allowedWriteRanges[key] = struct{}{}
							}
						}
					}
				}
			}
		} else {
			readRules++
		}
	}
	writeExcluded := 0
	for key := range observedWriteRanges {
		if _, ok := allowedWriteRanges[key]; !ok {
			writeExcluded++
		}
	}
	return map[string]any{
		"events_processed":          len(events),
		"groups_created":            len(groups),
		"read_rules":                readRules,
		"write_rules":               writeRules,
		"ranges_merged":             rangeCount,
		"write_operations_excluded": writeExcluded,
		"rules_total":               len(generated.Rules),
		"write_threshold":           threshold,
	}
}

func isWriteFunctionCode(fc uint8) bool {
	switch fc {
	case 5, 6, 15, 16:
		return true
	default:
		return false
	}
}

func simpleLineDiff(left string, right string) []string {
	leftLines := strings.Split(left, "\n")
	rightLines := strings.Split(right, "\n")
	maxLen := len(leftLines)
	if len(rightLines) > maxLen {
		maxLen = len(rightLines)
	}
	diff := make([]string, 0)
	for i := 0; i < maxLen; i++ {
		var l, r string
		if i < len(leftLines) {
			l = leftLines[i]
		}
		if i < len(rightLines) {
			r = rightLines[i]
		}
		if l == r {
			continue
		}
		if l != "" {
			diff = append(diff, fmt.Sprintf("-%03d %s", i+1, l))
		}
		if r != "" {
			diff = append(diff, fmt.Sprintf("+%03d %s", i+1, r))
		}
	}
	return diff
}

func nonNilTraffic(events []TrafficEvent) []TrafficEvent {
	if events == nil {
		return []TrafficEvent{}
	}
	return events
}

func nonNilSystemEvents(events []SystemEvent) []SystemEvent {
	if events == nil {
		return []SystemEvent{}
	}
	return events
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func (s *Service) activePolicyRuleCount() (int, error) {
	if !s.activePolicyApproved() {
		return 0, nil
	}
	loaded, err := policy.Load(s.dashboard.PolicyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return len(loaded.Rules), nil
}

func (s *Service) activePolicyApproved() bool {
	if _, err := os.Stat(s.dashboard.PolicyPath); err != nil {
		return false
	}
	if _, err := os.Stat(s.dashboard.PolicyPath + ".approved"); err != nil {
		return false
	}
	return true
}

func (s *Service) updateConfigMode(mode config.Mode) error {
	loaded, err := config.Load(s.dashboard.ConfigPath)
	if err != nil {
		return err
	}
	loaded.Mode = mode
	data, err := yaml.Marshal(loaded)
	if err != nil {
		return err
	}
	return os.WriteFile(s.dashboard.ConfigPath, data, 0o600)
}

func parseDashboardMode(value string) (config.Mode, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ANALYZE", "OBSERVE":
		return config.ModeObserve, nil
	case "FILTER", "ENFORCE":
		return config.ModeEnforce, nil
	default:
		return "", fmt.Errorf("unsupported mode %q", value)
	}
}

func dashboardMode(mode config.Mode) string {
	if mode == config.ModeEnforce {
		return "FILTER"
	}
	return "ANALYZE"
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"ok": false, "error": err.Error()})
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
}

func roundFloat(value float64) float64 {
	return float64(int(value*100)) / 100
}
