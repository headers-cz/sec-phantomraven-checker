#!/bin/bash

# PhantomRaven Scanner
# Security-focused scanner for PhantomRaven npm malware detection
# Detects PhantomRaven npm malware and Remote Dynamic Dependencies

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
VERBOSE=0

# Known malicious packages (126 packages from PhantomRaven campaign)
MALICIOUS_PACKAGES=(
    "fq-ui" "mocha-no-only" "ft-flow" "ul-inline" "jest-hoist"
    "jfrog-npm-actions-example" "@acme-types/acme-package" "react-web-api"
    "mourner" "unused-imports" "jira-ticket-todo-comment" "polyfill-corejs3"
    "polyfill-regenerator" "@aio-commerce-sdk/config-tsdown"
    "@aio-commerce-sdk/config-typedoc" "@aio-commerce-sdk/config-typescript"
    "@aio-commerce-sdk/config-vitest" "powerbi-visuals-sunburst"
    "@gitlab-lsp/pkg-1" "@gitlab-lsp/pkg-2" "@gitlab-lsp/workflow-api"
    "@gitlab-test/bun-v1" "@gitlab-test/npm-v10" "@gitlab-test/pnpm-v9"
    "@gitlab-test/yarn-v4" "acme-package" "add-module-exports"
    "add-shopify-header" "jsx-a11y" "prefer-object-spread" "preferred-import"
    "durablefunctionsmonitor" "durablefunctionsmonitor-vscodeext"
    "durablefunctionsmonitor.react" "e-voting-libraries-ui-kit"
    "named-asset-import" "chai-friendly" "aikido-module" "airbnb-babel"
    "airbnb-base-hf" "airbnb-base-typescript-prettier" "airbnb-bev"
    "airbnb-calendar" "airbnb-opentracing-javascript" "airbnb-scraper"
    "airbnb-types" "ais-sn-components" "goji-js-org"
    "google-cloud-functions-framework" "chromestatus-openapi" "elemefe"
    "labelbox-custom-ui" "rxjs-angular" "@apache-felix/felix-antora-ui"
    "@apache-netbeans/netbeans-antora-ui" "syntax-dynamic-import"
    "no-floating-promise" "no-only-tests" "@i22-td-smarthome/component-library"
    "vuejs-accessibility" "lfs-ui" "react-async-component-lifecycle-hooks"
    "eslint-comments" "wdr-beam" "lion-based-ui" "lion-based-ui-labs"
    "eslint-disable-next-line" "eslint-github-bot" "eslint-plugin-cli-microsoft365"
    "eslint-plugin-custom-eslint-rules" "@item-shop-data/client"
    "@msdyn365-commerce-marketplace/address-extensions"
    "@msdyn365-commerce-marketplace/tax-registration-numbers"
    "artifactregistry-login" "crowdstrike" "wm-tests-helper" "external-helpers"
    "react-important-stuff" "audio-game" "faltest" "only-warn"
    "op-cli-installer" "react-naming-convention" "skyscanner-with-prettier"
    "xo-form-components" "xo-login-components" "xo-page-components"
    "xo-shipping-change" "xo-shipping-options" "xo-title" "xo-tracking"
    "xo-validation" "badgekit-api-client" "important-stuff"
    "transform-es2015-modules-commonjs" "transform-merge-sibling-variables"
    "transform-react-constant-elements" "transform-react-jsx-source"
    "transform-react-remove-prop-types" "transform-strict-mode" "trezor-rollout"
    "filename-rules" "ing-web-es" "inline-react-svg" "ts-important-stuff"
    "firefly-sdk-js" "firefly-shared-js" "zeus-me-ops-tool"
    "zeus-mex-user-profile" "ts-migrate-example" "ts-react-important-stuff"
    "zohocrm-nodejs-sdk-3.0" "iot-cardboard-js" "pensions-portals-fe"
    "sort-class-members" "sort-keys-fix" "sort-keys-plus" "flowtype-errors"
    "twilio-react" "twilio-ts" "bernie-core" "bernie-plugin-l10n" "spaintest1"
    "typescript-compat" "typescript-sort-keys" "uach-retrofill"
)

# Known malicious infrastructure
MALICIOUS_DOMAIN="packages.storeartifact.com"
MALICIOUS_IP="54.173.15.59"

show_help() {
    cat << EOF
PhantomRaven Scanner - npm Malware Detector

USAGE:
  $0 [OPTIONS] [path]

OPTIONS:
  -v, --verbose         Show detailed information
  -h, --help            Show this help message
  [path]                Path to scan (default: current directory)

WHAT IT CHECKS:
  • 126 known PhantomRaven malicious packages
  • Remote Dynamic Dependencies (HTTP/HTTPS URLs in dependencies)
  • Suspicious URLs in lock files (transitive dependencies)
  • Suspicious Git dependencies (non-standard hosts)
  • Malicious domain: packages.storeartifact.com
  • Suspicious preinstall/postinstall/install scripts
  • All lock files (package-lock.json, yarn.lock, pnpm-lock.yaml)

EXAMPLES:
  # Scan current directory
  $0

  # Scan specific project
  $0 /path/to/project

  # Verbose scan
  $0 -v ~/my-app

EXIT CODES:
  0 - Clean (no issues found)
  1 - Infected (malware detected)
  2 - Errors during scan

MORE INFO:
  https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies

EOF
    exit 0
}

# Validate and sanitize path
validate_path() {
    local path="$1"

    # Resolve to absolute path and remove symlinks
    if ! path=$(realpath "$path" 2>/dev/null); then
        echo -e "${RED}Error: Invalid path${NC}" >&2
        return 1
    fi

    # Check if directory exists
    if [ ! -d "$path" ]; then
        echo -e "${RED}Error: Directory does not exist: $path${NC}" >&2
        return 1
    fi

    # Prevent scanning sensitive system directories
    case "$path" in
        /|/bin|/sbin|/usr|/etc|/var|/sys|/proc|/dev|/boot)
            echo -e "${RED}Error: Cannot scan system directory: $path${NC}" >&2
            return 1
            ;;
    esac

    echo "$path"
}

# Parse arguments
SCAN_TARGET=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            show_help
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            ;;
        *)
            SCAN_TARGET="$1"
            shift
            ;;
    esac
done

# Default scan target
[ -z "$SCAN_TARGET" ] && SCAN_TARGET="."

# Validate path
if ! SCAN_TARGET=$(validate_path "$SCAN_TARGET"); then
    exit 2
fi

# Check malicious packages in file
# Returns 0 if clean, 1 if found issues
check_malicious_packages() {
    local file="$1"
    local label="${2:-}"
    local found=0

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}  ⚠ Warning: jq not installed, using fallback grep method${NC}" >&2
        # Fallback to grep
        for pkg in "${MALICIOUS_PACKAGES[@]}"; do
            if grep -qF "\"$pkg\"" "$file" 2>/dev/null; then
                if [ -n "$label" ]; then
                    echo -e "${RED}  ✗ Malicious package in $label: ${YELLOW}$pkg${NC}"
                else
                    echo -e "${RED}  ✗ Malicious package: ${YELLOW}$pkg${NC}"
                fi
                found=1
            fi
        done
        return $found
    fi

    # Use jq to properly parse JSON and extract all dependency names
    local all_deps
    all_deps=$(jq -r '
        [
            (.dependencies // {} | keys[]),
            (.devDependencies // {} | keys[]),
            (.optionalDependencies // {} | keys[])
        ] | .[]
    ' "$file" 2>/dev/null) || return 0

    # Check each extracted package name against malicious list
    for pkg in "${MALICIOUS_PACKAGES[@]}"; do
        if echo "$all_deps" | grep -qFx "$pkg"; then
            if [ -n "$label" ]; then
                echo -e "${RED}  ✗ Malicious package in $label: ${YELLOW}$pkg${NC}"
            else
                echo -e "${RED}  ✗ Malicious package: ${YELLOW}$pkg${NC}"
            fi
            found=1
        fi
    done

    return $found
}

# Check for Remote Dynamic Dependencies and suspicious git URLs
# Returns 0 if clean, 1 if found issues
check_remote_dependencies() {
    local file="$1"
    local found=0

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}  ⚠ Warning: jq not installed, using fallback grep method${NC}" >&2
        # Fallback to grep with limited capabilities
        while IFS= read -r line; do
            if [[ $line =~ \"(https?://[^\"]+)\" ]]; then
                url="${BASH_REMATCH[1]}"
                echo -e "${RED}  ✗ Remote Dynamic Dependency: ${YELLOW}$url${NC}"
                found=1
                if [[ $url == *"$MALICIOUS_DOMAIN"* ]]; then
                    echo -e "${RED}    ⚠ CRITICAL: Known malicious domain!${NC}"
                fi
            fi
        done < <(grep -A 20 -E "\"dependencies\"|\"devDependencies\"|\"optionalDependencies\"" "$file" 2>/dev/null | grep -E "https?://" || true)
        return $found
    fi

    # Use jq to extract all dependency values from all dependency sections
    local dep_values
    dep_values=$(jq -r '
        [
            (.dependencies // {} | to_entries[] | .value),
            (.devDependencies // {} | to_entries[] | .value),
            (.optionalDependencies // {} | to_entries[] | .value)
        ] | .[]
    ' "$file" 2>/dev/null) || return 0

    # Check each dependency value for HTTP/HTTPS URLs
    while IFS= read -r value; do
        [ -z "$value" ] && continue

        # Check for HTTP/HTTPS URLs (Remote Dynamic Dependencies)
        if [[ $value =~ (https?://[^[:space:]\"]+) ]]; then
            url="${BASH_REMATCH[1]}"

            # Whitelist legitimate sources
            if [[ $url =~ registry\.npmjs\.org ]]; then
                # Official npm registry - safe
                continue
            elif [[ $url =~ github\.com/[^/]+/[^/]+/(tarball|zipball) ]]; then
                # GitHub tarball/zipball - common and safe
                continue
            fi

            echo -e "${RED}  ✗ Remote Dynamic Dependency: ${YELLOW}$url${NC}"
            found=1

            if [[ $url == *"$MALICIOUS_DOMAIN"* ]]; then
                echo -e "${RED}    ⚠ CRITICAL: Known malicious domain!${NC}"
            fi
        fi

        # Check for Git URLs (skip known safe hosts)
        if [[ $value =~ (git(\+https?|\+ssh)?://[^[:space:]\"]+) ]]; then
            url="${BASH_REMATCH[1]}"
            if [[ ! $url =~ (github\.com|gitlab\.com|bitbucket\.org) ]]; then
                echo -e "${YELLOW}  ⚠ Suspicious git dependency: ${CYAN}$url${NC}"
                found=1
            fi
        fi
    done <<< "$dep_values"

    return $found
}

# Check for Remote Dynamic Dependencies in lock files
# Returns 0 if clean, 1 if found issues
check_lock_file_urls() {
    local file="$1"
    local lock_type="$2"
    local found=0

    [ $VERBOSE -eq 1 ] && echo -e "  ${CYAN}Checking URLs in $lock_type...${NC}"

    case "$lock_type" in
        package-lock.json)
            # Parse package-lock.json with jq if available
            if command -v jq >/dev/null 2>&1; then
                local urls
                urls=$(jq -r '
                    .. |
                    objects |
                    select(has("resolved")) |
                    .resolved // empty
                ' "$file" 2>/dev/null) || return 0

                while IFS= read -r url; do
                    [ -z "$url" ] && continue

                    # Skip npm registry and GitHub URLs
                    if [[ $url =~ registry\.npmjs\.org ]] || \
                       [[ $url =~ github\.com/[^/]+/[^/]+/(tarball|zipball) ]]; then
                        continue
                    fi

                    # Check for HTTP/HTTPS URLs (excluding npm registry)
                    if [[ $url =~ ^https?:// ]]; then
                        echo -e "${RED}  ✗ Remote Dynamic Dependency in $lock_type: ${YELLOW}$url${NC}"
                        found=1

                        if [[ $url == *"$MALICIOUS_DOMAIN"* ]]; then
                            echo -e "${RED}    ⚠ CRITICAL: Known malicious domain!${NC}"
                        fi
                    fi
                done <<< "$urls"
            else
                # Fallback to grep
                while IFS= read -r line; do
                    if [[ $line =~ \"resolved\":[[:space:]]*\"(https?://[^\"]+)\" ]]; then
                        url="${BASH_REMATCH[1]}"

                        if [[ ! $url =~ registry\.npmjs\.org ]] && \
                           [[ ! $url =~ github\.com/[^/]+/[^/]+/(tarball|zipball) ]]; then
                            echo -e "${RED}  ✗ Remote Dynamic Dependency in $lock_type: ${YELLOW}$url${NC}"
                            found=1

                            if [[ $url == *"$MALICIOUS_DOMAIN"* ]]; then
                                echo -e "${RED}    ⚠ CRITICAL: Known malicious domain!${NC}"
                            fi
                        fi
                    fi
                done < <(grep -E "\"resolved\":" "$file" 2>/dev/null || true)
            fi
            ;;

        yarn.lock)
            # Parse yarn.lock (format: resolved "https://...")
            while IFS= read -r line; do
                if [[ $line =~ resolved[[:space:]]+\"(https?://[^\"]+)\" ]]; then
                    url="${BASH_REMATCH[1]}"

                    if [[ ! $url =~ registry\.yarnpkg\.com ]] && \
                       [[ ! $url =~ registry\.npmjs\.org ]] && \
                       [[ ! $url =~ github\.com/[^/]+/[^/]+/(tarball|zipball) ]]; then
                        echo -e "${RED}  ✗ Remote Dynamic Dependency in $lock_type: ${YELLOW}$url${NC}"
                        found=1

                        if [[ $url == *"$MALICIOUS_DOMAIN"* ]]; then
                            echo -e "${RED}    ⚠ CRITICAL: Known malicious domain!${NC}"
                        fi
                    fi
                fi
            done < <(grep -E "^[[:space:]]*resolved " "$file" 2>/dev/null || true)
            ;;

        pnpm-lock.yaml)
            # Parse pnpm-lock.yaml (format: tarball: https://... or resolution.tarball)
            while IFS= read -r line; do
                if [[ $line =~ (tarball|resolution):[[:space:]]*(https?://[^,}\][:space:]]+) ]]; then
                    url="${BASH_REMATCH[2]}"

                    if [[ ! $url =~ registry\.npmjs\.org ]] && \
                       [[ ! $url =~ github\.com/[^/]+/[^/]+/(tarball|zipball) ]]; then
                        echo -e "${RED}  ✗ Remote Dynamic Dependency in $lock_type: ${YELLOW}$url${NC}"
                        found=1

                        if [[ $url == *"$MALICIOUS_DOMAIN"* ]]; then
                            echo -e "${RED}    ⚠ CRITICAL: Known malicious domain!${NC}"
                        fi
                    fi
                fi
            done < <(grep -E "(tarball|resolution):" "$file" 2>/dev/null || true)
            ;;
    esac

    return $found
}

# Check for suspicious install scripts
# Returns 0 if clean, 1 if found issues
check_install_scripts() {
    local file="$1"
    local found=0

    local patterns=(
        "curl.*\|.*sh"
        "wget.*\|.*sh"
        "eval.*\$"
        "base64.*-d"
        "/tmp/.*\.sh"
        "chmod.*\+x.*&&"
    )

    # Check if jq is available
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${YELLOW}  ⚠ Warning: jq not installed, using fallback grep method${NC}" >&2
        # Fallback to grep
        for script_type in "preinstall" "postinstall" "install"; do
            if script_content=$(grep -o "\"$script_type\":[[:space:]]*\"[^\"]*\"" "$file" 2>/dev/null); then
                for pattern in "${patterns[@]}"; do
                    if echo "$script_content" | grep -qE "$pattern"; then
                        echo -e "${YELLOW}  ⚠ Suspicious $script_type script: ${CYAN}$script_content${NC}"
                        found=1
                        break
                    fi
                done
                if [ $VERBOSE -eq 1 ] && [ $found -eq 0 ]; then
                    echo -e "${CYAN}  ℹ $script_type: $script_content${NC}"
                fi
            fi
        done
        return $found
    fi

    # Use jq to extract install scripts
    for script_type in "preinstall" "postinstall" "install"; do
        local script_content
        script_content=$(jq -r ".scripts.${script_type} // empty" "$file" 2>/dev/null)

        [ -z "$script_content" ] && continue

        local is_suspicious=0
        for pattern in "${patterns[@]}"; do
            if echo "$script_content" | grep -qE "$pattern"; then
                echo -e "${YELLOW}  ⚠ Suspicious $script_type script: ${CYAN}\"$script_content\"${NC}"
                found=1
                is_suspicious=1
                break
            fi
        done

        if [ $VERBOSE -eq 1 ] && [ $is_suspicious -eq 0 ]; then
            echo -e "${CYAN}  ℹ $script_type: \"$script_content\"${NC}"
        fi
    done

    return $found
}

# Scan a single project
scan_project() {
    local scan_dir="$1"
    local has_issues=0

    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}PhantomRaven Scanner${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo -e "Scanning: ${GREEN}$scan_dir${NC}"
    [ $VERBOSE -eq 1 ] && echo -e "${CYAN}(Verbose mode)${NC}"
    echo ""

    # Find package.json files (exclude build directories)
    local package_files=()
    while IFS= read -r -d '' file; do
        package_files+=("$file")
    done < <(find "$scan_dir" -name "package.json" \
        -not -path "*/node_modules/*" \
        -not -path "*/.next/*" \
        -not -path "*/dist/*" \
        -not -path "*/build/*" \
        -not -path "*/.nuxt/*" \
        -not -path "*/.output/*" \
        -print0 2>/dev/null)

    if [ ${#package_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}No package.json files found${NC}"
        exit 0
    fi

    echo -e "Found ${GREEN}${#package_files[@]}${NC} package.json file(s)"
    echo ""

    local count=0
    for pkg_file in "${package_files[@]}"; do
        count=$((count + 1))
        local project_dir=$(dirname "$pkg_file")
        local project_has_issues=0

        echo -e "${BLUE}[$count/${#package_files[@]}]${NC} Checking: ${GREEN}$pkg_file${NC}"

        # Run checks (functions return 1 if they found issues)
        ! check_malicious_packages "$pkg_file" && project_has_issues=1
        ! check_remote_dependencies "$pkg_file" && project_has_issues=1
        ! check_install_scripts "$pkg_file" && project_has_issues=1

        # Check lock files
        for lock in "package-lock.json" "yarn.lock" "pnpm-lock.yaml"; do
            local lock_file="$project_dir/$lock"
            [ ! -f "$lock_file" ] && continue

            [ $VERBOSE -eq 1 ] && echo -e "  ${CYAN}Checking $lock...${NC}"

            ! check_malicious_packages "$lock_file" "$lock" && project_has_issues=1
            ! check_lock_file_urls "$lock_file" "$lock" && project_has_issues=1

            # Use -F for literal string matching - security fix
            if grep -qF "$MALICIOUS_DOMAIN" "$lock_file" 2>/dev/null; then
                echo -e "${RED}  ✗ Malicious domain in $lock: ${YELLOW}$MALICIOUS_DOMAIN${NC}"
                project_has_issues=1
            fi
        done

        if [ $project_has_issues -eq 0 ]; then
            echo -e "${GREEN}  ✓ Clean${NC}"
        else
            echo -e "${YELLOW}  ! Issues found${NC}"
            has_issues=1
        fi

        echo ""
    done

    # Summary
    echo -e "${BLUE}================================================${NC}"
    if [ $has_issues -eq 0 ]; then
        echo -e "${GREEN}✓ All projects are clean${NC}"
        exit 0
    else
        echo -e "${RED}✗ WARNING: Malware detected!${NC}"
        echo ""
        echo -e "${YELLOW}Recommended actions:${NC}"
        echo -e "  ${RED}1.${NC} Remove malicious packages from package.json"
        echo -e "  ${RED}2.${NC} Delete node_modules and lock files"
        echo -e "  ${RED}3.${NC} Rotate ALL credentials: npm, GitHub, CI/CD tokens"
        echo -e "  ${RED}4.${NC} Check ~/.npmrc and ~/.gitconfig"
        echo -e "  ${RED}5.${NC} Review CI/CD secrets and environment variables"
        echo -e "  ${RED}6.${NC} Reinstall dependencies from clean sources"
        exit 1
    fi
}

# Main
scan_project "$SCAN_TARGET"
