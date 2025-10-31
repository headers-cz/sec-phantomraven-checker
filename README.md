# PhantomRaven Scanner

**Fast npm malware detector** for PhantomRaven campaign - scans single projects or mass repository batches.

## 🎯 What It Does

Detects **PhantomRaven malware** that steals credentials (npm tokens, GitHub/GitLab, CI/CD secrets):

### ✅ Checks
- **126 known malicious packages** (`unused-imports`, `eslint-comments`, `crowdstrike`, etc.)
- **Remote Dynamic Dependencies** - HTTP/HTTPS URLs in package.json dependencies
- **Lock files** - package-lock.json, yarn.lock, pnpm-lock.yaml for transitive dependencies
- **Malicious domain** - `packages.storeartifact.com`
- **Suspicious install scripts** - curl/wget piping, eval, base64 decoding
- **Suspicious Git URLs** - non-GitHub/GitLab/Bitbucket sources

### 🚨 Attack Method
```json
{
  "dependencies": {
    "malicious": "http://packages.storeartifact.com/npm/package"
  }
}
```

Malicious code downloads during `npm install` via automatic preinstall scripts.

### 💰 What Gets Stolen
- npm tokens (~/.npmrc)
- GitHub/GitLab credentials (~/.gitconfig)
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

# Verbose output
./phantomraven-scan.sh -v ~/my-app
```

## 📖 Usage

```bash
./phantomraven-scan.sh [OPTIONS] [path]

Options:
  -v, --verbose    Show detailed information (install scripts, lock file checks)
  -h, --help       Show help message
  [path]           Directory to scan (default: current directory)

Examples:
  # Scan current directory
  ./phantomraven-scan.sh

  # Scan specific project
  ./phantomraven-scan.sh /path/to/project

  # Verbose mode
  ./phantomraven-scan.sh -v ~/my-app

  # Scan from parent directory (finds all package.json recursively)
  ./phantomraven-scan.sh ~/projects
```

**Note:** The scanner finds all `package.json` files recursively in the target directory (excluding build dirs like `node_modules`, `dist`, `.next`).

## 🔍 Detection Details

### Malicious Packages (126)
Full list includes: `unused-imports`, `eslint-comments`, `transform-react-remove-prop-types`, `crowdstrike`, `mocha-no-only`, `jest-hoist`, `chai-friendly`, `aikido-module`, and 118 more.

### Suspicious Script Patterns
- `curl ... | sh` / `wget ... | sh`
- `eval $(...)` / `base64 -d`
- Scripts in `/tmp` / `chmod +x && ...`

### Whitelisted (Safe)
- `registry.npmjs.org` / `registry.yarnpkg.com`
- GitHub tarball/zipball URLs
- Standard GitHub/GitLab/Bitbucket git URLs

## 📊 Output Example

```
================================================
PhantomRaven Scanner
================================================
Scanning: /home/user/projects/my-app
(Verbose mode)

Found 1 package.json file(s)

[1/1] Checking: /home/user/projects/my-app/package.json
  ✗ Malicious package: unused-imports
  ✗ Remote Dynamic Dependency: http://packages.storeartifact.com/npm/package-1.0.0.tgz
    ⚠ CRITICAL: Known malicious domain!
  → Checking package-lock.json...
    ✗ Malicious domain in package-lock.json: packages.storeartifact.com
    ! Issues found in package-lock.json
  ! Issues found

================================================
✗ WARNING: Malware detected!

Recommended actions:
  1. Remove malicious packages from package.json
  2. Delete node_modules and lock files
  3. Rotate ALL credentials: npm, GitHub, CI/CD tokens
  4. Check ~/.npmrc and ~/.gitconfig
  5. Review CI/CD secrets and environment variables
  6. Reinstall dependencies from clean sources
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
0 2 * * * /path/to/phantomraven-scan.sh ~/projects > /var/log/phantomraven-scan.log 2>&1
```

### Multiple Projects

```bash
# Scan multiple project directories
for project in ~/projects/*/; do
    echo "Scanning: $project"
    ./phantomraven-scan.sh "$project" || echo "INFECTED: $project"
done
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

### Slow scans on large monorepos
The scanner checks all `package.json` files recursively. For large directories:
```bash
# Scan specific subdirectory instead
./phantomraven-scan.sh ~/projects/my-app

# Or scan each project individually
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
