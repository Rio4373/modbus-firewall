package proxy

import (
	"path/filepath"
	"testing"

	"github.com/maratbagautdinov/modbus-firewall/internal/config"
)

func TestStatusPayloadHasNoPolicyApplyTimeBeforePolicyApproval(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	service := New(
		config.Config{Mode: config.ModeObserve},
		nil,
		nil,
		nil,
		WithDashboard("127.0.0.1:0", "", policyPath, filepath.Join(tmpDir, "candidate.yaml")),
	)

	payload := service.statusPayload()
	if got := payload["last_policy_apply_time"]; got != nil {
		t.Fatalf("last_policy_apply_time до первого применения должен быть nil, получили %#v", got)
	}
}
