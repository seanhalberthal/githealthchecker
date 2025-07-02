package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultConfig(t *testing.T) {
	// Test loading default config when no file exists
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	// Verify default values
	if len(cfg.Security.SecretPatterns) == 0 {
		t.Error("Default config should have secret patterns")
	}

	if len(cfg.Security.SuspiciousFiles) == 0 {
		t.Error("Default config should have suspicious file patterns")
	}

	if cfg.Quality.MaxFileLines == 0 {
		t.Error("Default config should have max file lines")
	}

	if cfg.Quality.MaxFunctionLines == 0 {
		t.Error("Default config should have max function lines")
	}

	if len(cfg.Maintenance.RequiredFiles) == 0 {
		t.Error("Default config should have required files")
	}

	if cfg.Performance.LargeFileSizeMB == 0 {
		t.Error("Default config should have large file size threshold")
	}
}

func TestLoad_CustomConfig(t *testing.T) {
	// Create a temporary config file
	tempDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Fatalf("Failed to clean up temp directory %s: %v", path, err)
		}
	}(tempDir)

	configContent := `
security:
  secret_patterns:
    - "custom_pattern_1"
    - "custom_pattern_2"
  suspicious_files:
    - "*.secret"
    - "private.*"
  allowed_secrets:
    - "test_secret"

quality:
  max_file_lines: 500
  max_function_lines: 25

performance:
  large_file_size_mb: 50
  binary_extensions:
    - ".exe"
    - ".dll"

maintenance:
  required_files:
    - "go.mod"
    - "README.md"

workflow:
  require_conventional_commits: true
  max_commit_message_length: 50
  protected_branches:
    - "main"
    - "production"
`

	configPath := filepath.Join(tempDir, ".healthcheck.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Load custom config
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load custom config: %v", err)
	}

	// Verify custom values were loaded
	if len(cfg.Security.SecretPatterns) != 2 {
		t.Errorf("Expected 2 secret patterns, got %d", len(cfg.Security.SecretPatterns))
	}

	if cfg.Security.SecretPatterns[0] != "custom_pattern_1" {
		t.Errorf("Expected first pattern to be 'custom_pattern_1', got '%s'", cfg.Security.SecretPatterns[0])
	}

	if cfg.Quality.MaxFileLines != 500 {
		t.Errorf("Expected max file lines to be 500, got %d", cfg.Quality.MaxFileLines)
	}

	if cfg.Quality.MaxFunctionLines != 25 {
		t.Errorf("Expected max function lines to be 25, got %d", cfg.Quality.MaxFunctionLines)
	}

	if cfg.Performance.LargeFileSizeMB != 50 {
		t.Errorf("Expected large file size to be 50MB, got %d", cfg.Performance.LargeFileSizeMB)
	}

	if !cfg.Workflow.RequireConventionalCommits {
		t.Error("Expected require conventional commits to be true")
	}

	if cfg.Workflow.MaxCommitMessageLength != 50 {
		t.Errorf("Expected max commit message length to be 50, got %d", cfg.Workflow.MaxCommitMessageLength)
	}
}

func getDefaultConfig() *Config {
	return DefaultConfig()
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "valid default config",
			config:  getDefaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid max file lines",
			config: &Config{
				Quality: QualityConfig{
					MaxFileLines:     -1,
					MaxFunctionLines: 50,
				},
				Security:     getDefaultConfig().Security,
				Performance:  getDefaultConfig().Performance,
				Maintenance:  getDefaultConfig().Maintenance,
				Workflow:     getDefaultConfig().Workflow,
				Dependencies: getDefaultConfig().Dependencies,
			},
			wantErr: true,
		},
		{
			name: "invalid max function lines",
			config: &Config{
				Quality: QualityConfig{
					MaxFileLines:     1000,
					MaxFunctionLines: 0,
				},
				Security:     getDefaultConfig().Security,
				Performance:  getDefaultConfig().Performance,
				Maintenance:  getDefaultConfig().Maintenance,
				Workflow:     getDefaultConfig().Workflow,
				Dependencies: getDefaultConfig().Dependencies,
			},
			wantErr: true,
		},
		{
			name: "invalid large file size",
			config: &Config{
				Performance: PerformanceConfig{
					LargeFileSizeMB:  -5,
					BinaryExtensions: []string{".exe"},
				},
				Security:     getDefaultConfig().Security,
				Quality:      getDefaultConfig().Quality,
				Maintenance:  getDefaultConfig().Maintenance,
				Workflow:     getDefaultConfig().Workflow,
				Dependencies: getDefaultConfig().Dependencies,
			},
			wantErr: true,
		},
		{
			name: "invalid commit message length",
			config: &Config{
				Workflow: WorkflowConfig{
					RequireConventionalCommits: true,
					MaxCommitMessageLength:     0,
					ProtectedBranches:          []string{"main"},
				},
				Security:     getDefaultConfig().Security,
				Quality:      getDefaultConfig().Quality,
				Performance:  getDefaultConfig().Performance,
				Maintenance:  getDefaultConfig().Maintenance,
				Dependencies: getDefaultConfig().Dependencies,
			},
			wantErr: true,
		},
		{
			name: "invalid dependency max days outdated",
			config: &Config{
				Dependencies: DependencyConfig{
					CheckOutdated:   true,
					MaxDaysOutdated: -1,
				},
				Security:    getDefaultConfig().Security,
				Quality:     getDefaultConfig().Quality,
				Performance: getDefaultConfig().Performance,
				Maintenance: getDefaultConfig().Maintenance,
				Workflow:    getDefaultConfig().Workflow,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
