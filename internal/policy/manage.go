package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateFile выполняет полную проверку policy-файла.
func ValidateFile(path string) (Policy, error) {
	if strings.TrimSpace(path) == "" {
		return Policy{}, fmt.Errorf("путь к policy обязателен")
	}

	policyCfg, err := Load(path)
	if err != nil {
		return Policy{}, err
	}

	return policyCfg, nil
}

// ApplyCandidate атомарно заменяет active policy содержимым candidate и удаляет candidate после успешного approve.
func ApplyCandidate(candidatePath string, activePath string) (Policy, error) {
	if strings.TrimSpace(candidatePath) == "" {
		return Policy{}, fmt.Errorf("путь к candidate policy обязателен")
	}
	if strings.TrimSpace(activePath) == "" {
		return Policy{}, fmt.Errorf("путь к active policy обязателен")
	}

	applied, err := copyPolicyAtomically(candidatePath, activePath, "candidate policy")
	if err != nil {
		return Policy{}, err
	}
	if err := os.WriteFile(approvedMarkerPath(activePath), []byte("approved\n"), 0o600); err != nil {
		return Policy{}, fmt.Errorf("policy применена, но approve marker не записан: %w", err)
	}
	if err := os.Remove(candidatePath); err != nil && !os.IsNotExist(err) {
		return Policy{}, fmt.Errorf("policy применена, но candidate policy не удалена: %w", err)
	}
	return applied, nil
}

func approvedMarkerPath(activePath string) string {
	return activePath + ".approved"
}

// ResetCandidate атомарно восстанавливает candidate из baseline.
func ResetCandidate(baselinePath string, candidatePath string) (Policy, error) {
	if strings.TrimSpace(baselinePath) == "" {
		return Policy{}, fmt.Errorf("путь к baseline policy обязателен")
	}
	if strings.TrimSpace(candidatePath) == "" {
		return Policy{}, fmt.Errorf("путь к candidate policy обязателен")
	}

	return copyPolicyAtomically(baselinePath, candidatePath, "baseline policy")
}

// copyPolicyAtomically валидирует источник и выполняет безопасную замену целевого файла через rename.
func copyPolicyAtomically(sourcePath string, destinationPath string, sourceLabel string) (Policy, error) {
	validatedPolicy, err := ValidateFile(sourcePath)
	if err != nil {
		return Policy{}, fmt.Errorf("%s невалидна: %w", sourceLabel, err)
	}

	policyData, err := os.ReadFile(sourcePath)
	if err != nil {
		return Policy{}, fmt.Errorf("не удалось прочитать %s %q: %w", sourceLabel, sourcePath, err)
	}

	destinationDir := filepath.Dir(destinationPath)
	if destinationDir != "." && destinationDir != "" {
		if err := os.MkdirAll(destinationDir, 0o755); err != nil {
			return Policy{}, fmt.Errorf("не удалось создать директорию %q: %w", destinationDir, err)
		}
	}

	tmpFile, err := os.CreateTemp(destinationDir, filepath.Base(destinationPath)+".tmp.*")
	if err != nil {
		return Policy{}, fmt.Errorf("не удалось создать временный файл для atomic apply: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(policyData); err != nil {
		_ = tmpFile.Close()
		return Policy{}, fmt.Errorf("не удалось записать временный policy файл: %w", err)
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return Policy{}, fmt.Errorf("не удалось выставить права на временный policy файл: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return Policy{}, fmt.Errorf("не удалось закрыть временный policy файл: %w", err)
	}

	if err := os.Rename(tmpPath, destinationPath); err != nil {
		return Policy{}, fmt.Errorf("не удалось атомарно применить policy (%q -> %q): %w", tmpPath, destinationPath, err)
	}

	return validatedPolicy, nil
}
