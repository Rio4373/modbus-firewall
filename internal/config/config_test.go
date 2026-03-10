package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSuccess(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `mode: observe
server:
  listen_addr: "0.0.0.0:1502"
proxy:
  upstream_addr: "plc-sim:502"
  dial_timeout: "2s"
logging:
  level: "info"
  format: "text"
storage:
  events_path: "./data/events.db"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("ожидали валидный конфиг, получили ошибку: %v", err)
	}

	if cfg.Mode != ModeObserve {
		t.Fatalf("ожидали mode=%q, получили %q", ModeObserve, cfg.Mode)
	}

	if cfg.Proxy.UpstreamAddr != "plc-sim:502" {
		t.Fatalf("ожидали upstream plc-sim:502, получили %q", cfg.Proxy.UpstreamAddr)
	}
}

func TestLoadInvalidMode(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `mode: block
server:
  listen_addr: "0.0.0.0:1502"
proxy:
  upstream_addr: "plc-sim:502"
  dial_timeout: "2s"
logging:
  level: "info"
  format: "text"
storage:
  events_path: "./data/events.db"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("ожидали ошибку при невалидном mode")
	}

	if !strings.Contains(err.Error(), "неподдерживаемый mode") {
		t.Fatalf("ожидали ошибку про mode, получили: %v", err)
	}
}

func TestLoadInvalidUpstream(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `mode: observe
server:
  listen_addr: "0.0.0.0:1502"
proxy:
  upstream_addr: ""
  dial_timeout: "2s"
logging:
  level: "info"
  format: "text"
storage:
  events_path: "./data/events.db"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("ожидали ошибку при пустом upstream")
	}

	if !strings.Contains(err.Error(), "proxy.upstream_addr") {
		t.Fatalf("ожидали ошибку про proxy.upstream_addr, получили: %v", err)
	}
}

func TestApplyModeOverride(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `mode: observe
server:
  listen_addr: "0.0.0.0:1502"
proxy:
  upstream_addr: "plc-sim:502"
  dial_timeout: "2s"
logging:
  level: "info"
  format: "text"
storage:
  events_path: "./data/events.db"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("не удалось загрузить конфиг: %v", err)
	}

	if err := cfg.ApplyModeOverride("enforce"); err != nil {
		t.Fatalf("ожидали успешный override mode, получили ошибку: %v", err)
	}

	if cfg.Mode != ModeEnforce {
		t.Fatalf("ожидали mode=%q, получили %q", ModeEnforce, cfg.Mode)
	}
}

func TestLoadInvalidReadTimeout(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `mode: observe
server:
  listen_addr: "0.0.0.0:1502"
proxy:
  upstream_addr: "plc-sim:502"
  dial_timeout: "2s"
  read_timeout: "-1s"
logging:
  level: "info"
  format: "text"
storage:
  events_path: "./data/events.db"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("ожидали ошибку при невалидном read_timeout")
	}

	if !strings.Contains(err.Error(), "proxy.read_timeout") {
		t.Fatalf("ожидали ошибку про proxy.read_timeout, получили: %v", err)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("не удалось записать тестовый конфиг: %v", err)
	}

	return path
}
