package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Mode определяет режим работы firewall.
type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
)

type Config struct {
	Mode    Mode          `yaml:"mode"`
	Server  ServerConfig  `yaml:"server"`
	Proxy   ProxyConfig   `yaml:"proxy"`
	Logging LoggingConfig `yaml:"logging"`
	Storage StorageConfig `yaml:"storage"`
}

type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

type ProxyConfig struct {
	UpstreamAddr string `yaml:"upstream_addr"`
	DialTimeout  string `yaml:"dial_timeout"`
	ReadTimeout  string `yaml:"read_timeout"`
	WriteTimeout string `yaml:"write_timeout"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type StorageConfig struct {
	EventsPath string `yaml:"events_path"`
}

// ParseMode нормализует и валидирует строковое значение режима.
func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case ModeObserve:
		return ModeObserve, nil
	case ModeEnforce:
		return ModeEnforce, nil
	default:
		return "", fmt.Errorf("неподдерживаемый mode: %q", value)
	}
}

// Load читает config.yaml, применяет значения по умолчанию и валидирует итоговую структуру.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("не удалось прочитать конфиг %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("не удалось распарсить YAML %q: %w", path, err)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("невалидный конфиг %q: %w", path, err)
	}

	return cfg, nil
}

// ApplyModeOverride позволяет переопределить режим из CLI поверх YAML-конфига.
func (c *Config) ApplyModeOverride(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	mode, err := ParseMode(value)
	if err != nil {
		return err
	}

	c.Mode = mode
	return c.Validate()
}

// applyDefaults заполняет безопасные дефолты для опциональных полей.
func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeObserve
	}

	if c.Proxy.DialTimeout == "" {
		c.Proxy.DialTimeout = "3s"
	}
	if c.Proxy.ReadTimeout == "" {
		c.Proxy.ReadTimeout = "5s"
	}
	if c.Proxy.WriteTimeout == "" {
		c.Proxy.WriteTimeout = "5s"
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}

	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
}

// Validate выполняет полную семантическую проверку конфига.
func (c Config) Validate() error {
	if _, err := ParseMode(string(c.Mode)); err != nil {
		return err
	}

	if err := validateTCPAddress(c.Server.ListenAddr, "server.listen_addr"); err != nil {
		return err
	}

	if err := validateTCPAddress(c.Proxy.UpstreamAddr, "proxy.upstream_addr"); err != nil {
		return err
	}

	timeout, err := time.ParseDuration(c.Proxy.DialTimeout)
	if err != nil {
		return fmt.Errorf("proxy.dial_timeout: %w", err)
	}
	if timeout <= 0 {
		return fmt.Errorf("proxy.dial_timeout должен быть > 0")
	}

	readTimeout, err := time.ParseDuration(c.Proxy.ReadTimeout)
	if err != nil {
		return fmt.Errorf("proxy.read_timeout: %w", err)
	}
	if readTimeout <= 0 {
		return fmt.Errorf("proxy.read_timeout должен быть > 0")
	}

	writeTimeout, err := time.ParseDuration(c.Proxy.WriteTimeout)
	if err != nil {
		return fmt.Errorf("proxy.write_timeout: %w", err)
	}
	if writeTimeout <= 0 {
		return fmt.Errorf("proxy.write_timeout должен быть > 0")
	}

	if !isSupportedLogLevel(c.Logging.Level) {
		return fmt.Errorf("logging.level должен быть одним из: debug, info, warn, error")
	}

	if !isSupportedLogFormat(c.Logging.Format) {
		return fmt.Errorf("logging.format должен быть одним из: text, json")
	}

	if strings.TrimSpace(c.Storage.EventsPath) == "" {
		return fmt.Errorf("storage.events_path обязателен")
	}

	return nil
}

// validateTCPAddress проверяет корректность host:port и диапазон порта.
func validateTCPAddress(value string, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s обязателен", fieldName)
	}

	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s: %w", fieldName, err)
	}

	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s: host обязателен", fieldName)
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("%s: порт должен быть числом", fieldName)
	}

	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("%s: порт должен быть в диапазоне 1..65535", fieldName)
	}

	return nil
}

// isSupportedLogLevel проверяет допустимые уровни логирования.
func isSupportedLogLevel(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

// isSupportedLogFormat проверяет допустимые форматы логирования.
func isSupportedLogFormat(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "text", "json":
		return true
	default:
		return false
	}
}
