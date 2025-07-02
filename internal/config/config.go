package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	Security     SecurityConfig    `mapstructure:"security" yaml:"security"`
	Performance  PerformanceConfig `mapstructure:"performance" yaml:"performance"`
	Quality      QualityConfig     `mapstructure:"quality" yaml:"quality"`
	Maintenance  MaintenanceConfig `mapstructure:"maintenance" yaml:"maintenance"`
	Workflow     WorkflowConfig    `mapstructure:"workflow" yaml:"workflow"`
	Dependencies DependencyConfig  `mapstructure:"dependencies" yaml:"dependencies"`
}

type SecurityConfig struct {
	SecretPatterns  []string `mapstructure:"secret_patterns" yaml:"secret_patterns"`
	MaxFileSizeMB   int      `mapstructure:"max_file_size_mb" yaml:"max_file_size_mb"`
	SuspiciousFiles []string `mapstructure:"suspicious_files" yaml:"suspicious_files"`
	AllowedSecrets  []string `mapstructure:"allowed_secrets" yaml:"allowed_secrets"`
}

type PerformanceConfig struct {
	MaxRepositorySizeMB int      `mapstructure:"max_repository_size_mb" yaml:"max_repository_size_mb"`
	LargeFileSizeMB     int      `mapstructure:"large_file_size_mb" yaml:"large_file_size_mb"`
	BinaryExtensions    []string `mapstructure:"binary_extensions" yaml:"binary_extensions"`
}

type QualityConfig struct {
	MaxFunctionLines     int     `mapstructure:"max_function_lines" yaml:"max_function_lines"`
	MaxFileLines         int     `mapstructure:"max_file_lines" yaml:"max_file_lines"`
	DuplicationThreshold int     `mapstructure:"duplication_threshold" yaml:"duplication_threshold"`
	ComplexityThreshold  int     `mapstructure:"complexity_threshold" yaml:"complexity_threshold"`
	MinTestCoverage      float64 `mapstructure:"min_test_coverage" yaml:"min_test_coverage"`
}

type MaintenanceConfig struct {
	StaleBranchDays int      `mapstructure:"stale_branch_days" yaml:"stale_branch_days"`
	RequiredFiles   []string `mapstructure:"required_files" yaml:"required_files"`
	CIFiles         []string `mapstructure:"ci_files" yaml:"ci_files"`
}

type WorkflowConfig struct {
	ProtectedBranches          []string `mapstructure:"protected_branches" yaml:"protected_branches"`
	RequireConventionalCommits bool     `mapstructure:"require_conventional_commits" yaml:"require_conventional_commits"`
	MaxCommitMessageLength     int      `mapstructure:"max_commit_message_length" yaml:"max_commit_message_length"`
}

type DependencyConfig struct {
	CheckOutdated        bool     `mapstructure:"check_outdated" yaml:"check_outdated"`
	CheckVulnerabilities bool     `mapstructure:"check_vulnerabilities" yaml:"check_vulnerabilities"`
	MaxDaysOutdated      int      `mapstructure:"max_days_outdated" yaml:"max_days_outdated"`
	AllowedPackages      []string `mapstructure:"allowed_packages" yaml:"allowed_packages"`
	BlockedPackages      []string `mapstructure:"blocked_packages" yaml:"blocked_packages"`
}

func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	v := viper.New()
	v.SetConfigType("yaml")

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName(".healthcheck")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME")
	}

	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, nil
}

func DefaultConfig() *Config {
	return &Config{
		Security: SecurityConfig{
			SecretPatterns: []string{
				`(?i)api[_-]?key[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?`,
				`(?i)password[\s]*[:=][\s]*['"]?[^\s'"]{8,}['"]?`,
				`(?i)secret[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{16,}['"]?`,
				`(?i)token[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?`,
				`(?i)private[_-]?key`,
				`(?i)access[_-]?token[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?`,
				`(?i)auth[_-]?token[\s]*[:=][\s]*['"]?[a-zA-Z0-9]{20,}['"]?`,
				`(?i)database[_-]?url[\s]*[:=][\s]*['"]?[^\s'"]+['"]?`,
				`(?i)connection[_-]?string[\s]*[:=][\s]*['"]?[^\s'"]+['"]?`,
			},
			MaxFileSizeMB: 100,
			SuspiciousFiles: []string{
				"*.pem", "*.key", "*.p12", "*.pfx", "*.jks",
				".env", ".env.*", "*.env",
				"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
				"*.dump", "*.backup", "database.sql", "db_dump.sql",
			},
			AllowedSecrets: []string{},
		},
		Performance: PerformanceConfig{
			MaxRepositorySizeMB: 1000,
			LargeFileSizeMB:     10,
			BinaryExtensions: []string{
				".exe", ".dll", ".so", ".dylib", ".a", ".lib",
				".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
				".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
				".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv",
				".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
			},
		},
		Quality: QualityConfig{
			MaxFunctionLines:     200,  // Increased - focus on complexity instead
			MaxFileLines:         2000, // Increased - focus on file cohesion instead
			DuplicationThreshold: 10,
			ComplexityThreshold:  10, // Cyclomatic complexity threshold
			MinTestCoverage:      80.0,
		},
		Maintenance: MaintenanceConfig{
			StaleBranchDays: 90,
			RequiredFiles: []string{
				".gitignore",
				"go.mod",
			},
			CIFiles: []string{
				".github/workflows/", ".gitlab-ci.yml", ".travis.yml",
				"Jenkinsfile", ".circleci/", "azure-pipelines.yml",
			},
		},
		Workflow: WorkflowConfig{
			ProtectedBranches:          []string{"main", "master", "develop"},
			RequireConventionalCommits: false,
			MaxCommitMessageLength:     72,
		},
		Dependencies: DependencyConfig{
			CheckOutdated:        true,
			CheckVulnerabilities: true,
			MaxDaysOutdated:      90, // 3 months - more reasonable threshold
			AllowedPackages:      []string{},
			BlockedPackages:      []string{},
		},
	}
}

func (c *Config) Validate() error {
	if err := c.validateSecurity(); err != nil {
		return err
	}
	if err := c.validatePerformance(); err != nil {
		return err
	}
	if err := c.validateQuality(); err != nil {
		return err
	}
	if err := c.validateMaintenance(); err != nil {
		return err
	}
	if err := c.validateWorkflow(); err != nil {
		return err
	}
	return c.validateDependencies()
}

func (c *Config) validateSecurity() error {
	if c.Security.MaxFileSizeMB <= 0 {
		return fmt.Errorf("security.max_file_size_mb must be positive")
	}
	return nil
}

func (c *Config) validatePerformance() error {
	if c.Performance.LargeFileSizeMB < 0 {
		return fmt.Errorf("performance.large_file_size_mb must be non-negative")
	}
	return nil
}

func (c *Config) validateQuality() error {
	if c.Quality.MaxFunctionLines <= 0 {
		return fmt.Errorf("quality.max_function_lines must be positive")
	}
	if c.Quality.MaxFileLines <= 0 {
		return fmt.Errorf("quality.max_file_lines must be positive")
	}
	if c.Quality.ComplexityThreshold <= 0 {
		return fmt.Errorf("quality.complexity_threshold must be positive")
	}
	if c.Quality.MinTestCoverage < 0 || c.Quality.MinTestCoverage > 100 {
		return fmt.Errorf("quality.min_test_coverage must be between 0 and 100")
	}
	return nil
}

func (c *Config) validateMaintenance() error {
	if c.Maintenance.StaleBranchDays <= 0 {
		return fmt.Errorf("maintenance.stale_branch_days must be positive")
	}
	return nil
}

func (c *Config) validateWorkflow() error {
	if c.Workflow.MaxCommitMessageLength <= 0 {
		return fmt.Errorf("workflow.max_commit_message_length must be positive")
	}
	return nil
}

func (c *Config) validateDependencies() error {
	if c.Dependencies.MaxDaysOutdated <= 0 {
		return fmt.Errorf("dependencies.max_days_outdated must be positive")
	}
	return nil
}

func (c *Config) Save(path string) error {
	v := viper.New()
	v.SetConfigType("yaml")

	v.Set("security", c.Security)
	v.Set("performance", c.Performance)
	v.Set("quality", c.Quality)
	v.Set("maintenance", c.Maintenance)
	v.Set("workflow", c.Workflow)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := v.WriteConfigAs(path); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
