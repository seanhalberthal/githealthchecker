# Git Repository Health Checker

A CLI tool for analyzing Go repositories to identify security vulnerabilities, code quality issues, and maintenance problems, with advanced complexity analysis and dependency management.

## Installation

### Homebrew (macOS/Linux)

```bash
# Add the tap
brew tap seanhalberthal/githealthchecker

# Install the tool
brew install githealthchecker

# Upgrade to latest version
brew upgrade githealthchecker
```

### Direct Download

Download the latest release for your platform from the [releases page](https://github.com/seanhalberthal/githealthchecker/releases).

### Build from Source

```bash
git clone https://github.com/seanhalberthal/githealthchecker.git
cd githealthchecker
go build -o git-health-checker .
```

## Usage

#### Ideally you should run this tool from the root of your Git repository

```bash
### Health Check

```bash
# Basic health check
git-health-checker check

# Specific analysis types
git-health-checker check --security
git-health-checker check --quality

# Different output formats
git-health-checker check --format json
git-health-checker check --format markdown --output report.md
```

### Auto-Fix Dependencies

```bash
# Preview what would be fixed
git-health-checker fix --dry-run

# Fix all dependency issues
git-health-checker fix
```

## What it checks

- **Security**: Secrets in your codebase, suspicious files, configuration files
- **Quality**: Cognitive complexity, large files
- **Performance**: Binary files, repository size
- **Dependencies**: Outdated modules, unused dependencies, blocked packages (go.mod)
- **Maintenance**: Missing required files (go.mod, .gitignore, README)
- **Workflow**: Commit conventions, stale branches

## Configuration

Create a `.healthcheck.yaml` file in your repository:

```yaml
security:
  secret_patterns:
    - "(?i)api[_-]?key[\\s]*[:=][\\s]*['\"]?[a-zA-Z0-9]{20,}['\"]?"
  max_file_size_mb: 100

quality:
  complexity_threshold: 10
  max_file_lines: 2000

dependencies:
  check_outdated: true
  max_days_outdated: 180
  blocked_packages:
    - "lodash"
    - "moment"

maintenance:
  required_files:
    - "README.md"
    - ".gitignore"
```

## Examples

```bash
# CI/CD integration
git-health-checker check --fail-on-issues --severity high

# Generate reports
git-health-checker check --format json --output health.json
git-health-checker check --format markdown --output HEALTH.md
```