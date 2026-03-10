package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateFileSuccess(t *testing.T) {
	t.Parallel()

	path := writePolicyFile(t, `version: 1
default_action: deny
rules: []
`)

	loaded, err := ValidateFile(path)
	if err != nil {
		t.Fatalf("ожидали успешную валидацию policy, получили ошибку: %v", err)
	}

	if loaded.DefaultAction != DecisionDeny {
		t.Fatalf("ожидали default_action=deny, получили %q", loaded.DefaultAction)
	}
}

func TestApplyCandidateReplacesActive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	candidatePath := filepath.Join(dir, "policy.candidate.yaml")
	activePath := filepath.Join(dir, "policy.yaml")

	if err := os.WriteFile(candidatePath, []byte(`version: 1
default_action: deny
rules:
  - id: allow-read
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [3]
    address_ranges:
      - start: 0
        end: 10
`), 0o600); err != nil {
		t.Fatalf("не удалось записать candidate policy: %v", err)
	}

	if err := os.WriteFile(activePath, []byte(`version: 1
default_action: deny
rules: []
`), 0o600); err != nil {
		t.Fatalf("не удалось записать active policy: %v", err)
	}

	applied, err := ApplyCandidate(candidatePath, activePath)
	if err != nil {
		t.Fatalf("не удалось применить candidate policy: %v", err)
	}

	if len(applied.Rules) != 1 {
		t.Fatalf("ожидали 1 правило в примененной policy, получили %d", len(applied.Rules))
	}

	activeData, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatalf("не удалось прочитать active policy: %v", err)
	}
	if !strings.Contains(string(activeData), "allow-read") {
		t.Fatalf("ожидали что active policy содержит allow-read, получили:\n%s", string(activeData))
	}

	candidateData, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatalf("candidate policy должна оставаться доступной, ошибка: %v", err)
	}
	if !strings.Contains(string(candidateData), "allow-read") {
		t.Fatalf("ожидали что candidate policy сохранена без изменений")
	}
}

func TestApplyCandidateInvalidRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	candidatePath := filepath.Join(dir, "policy.candidate.yaml")
	activePath := filepath.Join(dir, "policy.yaml")

	if err := os.WriteFile(candidatePath, []byte(`version: 1
default_action: allow
rules: []
`), 0o600); err != nil {
		t.Fatalf("не удалось записать candidate policy: %v", err)
	}
	if err := os.WriteFile(activePath, []byte(`version: 1
default_action: deny
rules: []
`), 0o600); err != nil {
		t.Fatalf("не удалось записать active policy: %v", err)
	}

	_, err := ApplyCandidate(candidatePath, activePath)
	if err == nil {
		t.Fatal("ожидали ошибку при невалидной candidate policy")
	}

	activeData, readErr := os.ReadFile(activePath)
	if readErr != nil {
		t.Fatalf("не удалось прочитать active policy после ошибки apply: %v", readErr)
	}
	if !strings.Contains(string(activeData), "default_action: deny") {
		t.Fatalf("active policy не должна измениться при ошибке apply")
	}
}

func TestResetCandidateRevertsToBaseline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "policy.generated.yaml")
	candidatePath := filepath.Join(dir, "policy.candidate.yaml")

	if err := os.WriteFile(baselinePath, []byte(`version: 1
default_action: deny
rules:
  - id: baseline-allow
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [3]
    address_ranges:
      - start: 1
        end: 5
`), 0o600); err != nil {
		t.Fatalf("не удалось записать baseline policy: %v", err)
	}

	if err := os.WriteFile(candidatePath, []byte(`version: 1
default_action: deny
rules:
  - id: edited-rule
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [3]
    address_ranges:
      - start: 100
        end: 101
`), 0o600); err != nil {
		t.Fatalf("не удалось записать candidate policy: %v", err)
	}

	resetPolicy, err := ResetCandidate(baselinePath, candidatePath)
	if err != nil {
		t.Fatalf("не удалось сбросить candidate policy к baseline: %v", err)
	}
	if len(resetPolicy.Rules) != 1 || resetPolicy.Rules[0].ID != "baseline-allow" {
		t.Fatalf("ожидали baseline policy после reset, получили: %+v", resetPolicy.Rules)
	}

	candidateData, err := os.ReadFile(candidatePath)
	if err != nil {
		t.Fatalf("не удалось прочитать candidate policy после reset: %v", err)
	}
	if !strings.Contains(string(candidateData), "baseline-allow") {
		t.Fatalf("ожидали что candidate восстановлена из baseline, получили:\n%s", string(candidateData))
	}
	if strings.Contains(string(candidateData), "edited-rule") {
		t.Fatalf("не ожидали что правка edited-rule сохранится после reset")
	}
}

func TestResetCandidateInvalidBaselineRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "policy.generated.yaml")
	candidatePath := filepath.Join(dir, "policy.candidate.yaml")

	if err := os.WriteFile(baselinePath, []byte(`version: 1
default_action: allow
rules: []
`), 0o600); err != nil {
		t.Fatalf("не удалось записать baseline policy: %v", err)
	}
	if err := os.WriteFile(candidatePath, []byte(`version: 1
default_action: deny
rules:
  - id: edited
    action: allow
    source_ips: ["127.0.0.1"]
    destination_ips: ["127.0.0.1"]
    unit_ids: [1]
    function_codes: [3]
    address_ranges:
      - start: 5
        end: 10
`), 0o600); err != nil {
		t.Fatalf("не удалось записать candidate policy: %v", err)
	}

	_, err := ResetCandidate(baselinePath, candidatePath)
	if err == nil {
		t.Fatal("ожидали ошибку при невалидном baseline")
	}

	candidateData, readErr := os.ReadFile(candidatePath)
	if readErr != nil {
		t.Fatalf("не удалось прочитать candidate policy после ошибки reset: %v", readErr)
	}
	if !strings.Contains(string(candidateData), "edited") {
		t.Fatalf("candidate policy не должна измениться при ошибке reset")
	}
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать policy файл: %v", err)
	}
	return path
}
