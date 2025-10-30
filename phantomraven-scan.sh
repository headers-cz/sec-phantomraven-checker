#!/bin/bash

# PhantomRaven Scanner
# Universal scanner for single projects or mass repository scanning
# Detects PhantomRaven npm malware and Remote Dynamic Dependencies

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
MODE="single"  # single or batch
WORKERS=4
OUTPUT_FORMAT="text"  # text, json, csv
OUTPUT_FILE=""
VERBOSE=0
SUMMARY_ONLY=0

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
PhantomRaven Scanner - Universal npm Malware Detector

USAGE:
  Single project:  $0 [OPTIONS] [path]
  Batch mode:      $0 --batch [OPTIONS] <repos_dir|repos_list>

MODES:
  Single (default)  Scan one project directory
  Batch (--batch)   Scan multiple repositories in parallel

OPTIONS:
  -v, --verbose         Show detailed information
  -h, --help            Show this help message

  Single mode options:
    [path]              Path to scan (default: current directory)

  Batch mode options:
    -w, --workers N     Number of parallel workers (default: 4)
    -f, --format FMT    Output format: text, json, csv (default: text)
    -o, --output FILE   Save results to file
    --summary-only      Show only final summary

WHAT IT CHECKS:
  • 126 known PhantomRaven malicious packages
  • Remote Dynamic Dependencies (HTTP/HTTPS URLs in dependencies)
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

  # Batch: Scan all repos in directory with 8 workers
  $0 --batch -w 8 ~/projects

  # Batch: Generate JSON report
  $0 --batch -f json -o report.json ~/workspace

  # Batch: Scan from list file
  $0 --batch repos.txt

EXIT CODES:
  0 - Clean (no issues found)
  1 - Infected (malware detected)
  2 - Errors during scan

MORE INFO:
  https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies

EOF
    exit 0
}

# Parse arguments
SCAN_TARGET=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --batch)
            MODE="batch"
            shift
            ;;
        -w|--workers)
            WORKERS="$2"
            shift 2
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --summary-only)
            SUMMARY_ONLY=1
            shift
            ;;
        -h|--help)
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

#############################################################################
# SINGLE PROJECT MODE
#############################################################################

# Check malicious packages in file
# Returns 0 if clean, 1 if found issues
check_malicious_packages() {
    local file="$1"
    local label="${2:-}"
    local found=0

    for pkg in "${MALICIOUS_PACKAGES[@]}"; do
        if grep -q "\"$pkg\"" "$file" 2>/dev/null; then
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

    if grep -qE "\"dependencies\"|\"devDependencies\"|\"optionalDependencies\"" "$file" 2>/dev/null; then
        # Check HTTP/HTTPS URLs
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

        # Check Git URLs (skip known safe hosts)
        while IFS= read -r line; do
            if [[ $line =~ \"(git(\+https?|\+ssh)?://[^\"]+)\" ]]; then
                url="${BASH_REMATCH[1]}"
                if [[ ! $url =~ (github\.com|gitlab\.com|bitbucket\.org) ]]; then
                    echo -e "${YELLOW}  ⚠ Suspicious git dependency: ${CYAN}$url${NC}"
                    found=1
                fi
            fi
        done < <(grep -A 20 -E "\"dependencies\"|\"devDependencies\"|\"optionalDependencies\"" "$file" 2>/dev/null | grep -E "git(\+https?|\+ssh)?://" || true)
    fi

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
}

# Scan a single project
scan_single_project() {
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

            if grep -q "$MALICIOUS_DOMAIN" "$lock_file" 2>/dev/null; then
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

#############################################################################
# BATCH MODE
#############################################################################

# Statistics
TOTAL_REPOS=0
SCANNED_REPOS=0
INFECTED_REPOS=0
CLEAN_REPOS=0
ERROR_REPOS=0
START_TIME=$(date +%s)

INFECTED_LIST=()
CLEAN_LIST=()
ERROR_LIST=()
FINDINGS_FILE=""

# Discover repositories from directory or list file
discover_repos() {
    local input="$1"
    local repos=()

    if [ -f "$input" ]; then
        echo -e "${CYAN}Reading repository list from: $input${NC}" >&2
        while IFS= read -r line; do
            line=$(echo "$line" | xargs)
            [ -z "$line" ] && continue
            [ "${line:0:1}" = "#" ] && continue
            [ -d "$line" ] && repos+=("$line")
        done < "$input"
    elif [ -d "$input" ]; then
        echo -e "${CYAN}Discovering git repositories in: $input${NC}" >&2
        while IFS= read -r -d '' repo; do
            repos+=("$repo")
        done < <(find "$input" -maxdepth 3 -name ".git" -type d -print0 2>/dev/null | xargs -0 -I {} dirname {})
    fi

    # Output repos if any found
    if [ ${#repos[@]} -gt 0 ]; then
        printf '%s\n' "${repos[@]}"
    fi
}

# Scan repository in worker process
scan_repo_worker() {
    local repo="$1"
    local worker_id="$2"
    local temp_dir="$3"

    local status="clean"
    local exit_code=0
    local findings=""

    # Create a temporary script to scan this repo
    if output=$(bash "$0" "$repo" 2>&1); then
        exit_code=$?
        [ $exit_code -ne 0 ] && status="infected"
    else
        exit_code=$?
        status="error"
        findings="Scan failed with exit code $exit_code"
    fi

    # Extract findings from output
    if [ "$status" = "infected" ]; then
        findings=$(echo "$output" | grep -E "✗|⚠" | head -3 | tr '\n' '; ' | sed 's/[|]/_/g')
    fi

    # Write result (escape pipe characters in findings)
    echo "REPO|$repo|$status|$exit_code|$findings" >> "$temp_dir/result_${worker_id}.txt"

    # Show output if verbose
    if [ $VERBOSE -eq 1 ]; then
        echo -e "\n${BLUE}=== $(basename "$repo") ===${NC}"
        echo "$output"
    fi
}

# Process repos in parallel
process_batch() {
    local -a repos=("$@")
    TOTAL_REPOS=${#repos[@]}

    [ $TOTAL_REPOS -eq 0 ] && return

    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}PhantomRaven Batch Scanner${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo -e "Total repositories: ${GREEN}$TOTAL_REPOS${NC}"
    echo -e "Parallel workers: ${CYAN}$WORKERS${NC}"
    echo ""

    [ $SUMMARY_ONLY -eq 1 ] && echo -e "${CYAN}Summary-only mode${NC}\n"

    # Create temp directory
    local temp_dir=$(mktemp -d -t phantomraven.XXXXXX)
    trap "rm -rf $temp_dir" EXIT

    # Create queue
    local queue="$temp_dir/queue.txt"
    printf '%s\n' "${repos[@]}" > "$queue"

    # Launch workers
    local pids=()
    for worker_id in $(seq 1 $WORKERS); do
        (
            while true; do
                repo=$(flock "$queue" sh -c "head -n 1 '$queue'; sed -i.bak '1d' '$queue'" 2>/dev/null)
                [ -z "$repo" ] && break

                scan_repo_worker "$repo" "$worker_id" "$temp_dir"

                if [ $SUMMARY_ONLY -eq 0 ]; then
                    scanned=$(cat "$temp_dir"/result_*.txt 2>/dev/null | wc -l)
                    echo -e "${CYAN}Progress: [$scanned/$TOTAL_REPOS]${NC} $(basename "$repo")"
                fi
            done
        ) &
        pids+=($!)
    done

    # Wait for all workers
    for pid in "${pids[@]}"; do
        wait $pid
    done

    # Aggregate results
    FINDINGS_FILE="$temp_dir/findings.txt"
    > "$FINDINGS_FILE"  # Create empty file

    for result_file in "$temp_dir"/result_*.txt; do
        [ ! -f "$result_file" ] && continue

        while IFS='|' read -r prefix repo status exit_code findings; do
            [ "$prefix" != "REPO" ] && continue

            SCANNED_REPOS=$((SCANNED_REPOS + 1))

            case "$status" in
                clean)
                    CLEAN_REPOS=$((CLEAN_REPOS + 1))
                    CLEAN_LIST+=("$repo")
                    ;;
                infected)
                    INFECTED_REPOS=$((INFECTED_REPOS + 1))
                    INFECTED_LIST+=("$repo")
                    echo "$repo|$findings" >> "$FINDINGS_FILE"
                    ;;
                error)
                    ERROR_REPOS=$((ERROR_REPOS + 1))
                    ERROR_LIST+=("$repo")
                    echo "$repo|$findings" >> "$FINDINGS_FILE"
                    ;;
            esac
        done < "$result_file"
    done
}

# Generate reports
generate_text_report() {
    local duration=$(($(date +%s) - START_TIME))

    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${BLUE}Scan Summary${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo -e "Scanned: ${GREEN}$SCANNED_REPOS${NC} | Clean: ${GREEN}$CLEAN_REPOS${NC} | Infected: ${RED}$INFECTED_REPOS${NC} | Errors: ${YELLOW}$ERROR_REPOS${NC}"
    echo -e "Duration: ${CYAN}${duration}s${NC}\n"

    if [ $INFECTED_REPOS -gt 0 ]; then
        echo -e "${RED}⚠ INFECTED REPOSITORIES:${NC}"
        for repo in "${INFECTED_LIST[@]}"; do
            echo -e "  ${RED}✗${NC} $repo"
            # Look up findings for this repo
            if [ -f "$FINDINGS_FILE" ]; then
                findings=$(grep "^$repo|" "$FINDINGS_FILE" | cut -d'|' -f2-)
                [ -n "$findings" ] && echo -e "    ${YELLOW}$findings${NC}"
            fi
        done
        echo ""
    fi

    [ $ERROR_REPOS -gt 0 ] && echo -e "${YELLOW}Errors: $ERROR_REPOS repositories${NC}\n"

    if [ $INFECTED_REPOS -gt 0 ]; then
        echo -e "${RED}ACTION REQUIRED!${NC}"
        echo -e "Review infected repositories and follow remediation steps"
    else
        echo -e "${GREEN}✓ All repositories are clean!${NC}"
    fi
}

generate_json_report() {
    local json='{'
    json+="\"scan_date\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    json+="\"total\":$SCANNED_REPOS,"
    json+="\"clean\":$CLEAN_REPOS,"
    json+="\"infected\":$INFECTED_REPOS,"
    json+="\"errors\":$ERROR_REPOS,"
    json+="\"duration_seconds\":$(($(date +%s) - START_TIME)),"

    json+="\"infected_repositories\":["
    local first=1
    for repo in "${INFECTED_LIST[@]}"; do
        [ $first -eq 0 ] && json+=","
        first=0
        local findings=""
        [ -f "$FINDINGS_FILE" ] && findings=$(grep "^$repo|" "$FINDINGS_FILE" | cut -d'|' -f2-)
        json+="{\"path\":\"$repo\",\"findings\":\"${findings:-}\"}"
    done
    json+="]"

    json+='}'
    echo "$json"
}

generate_csv_report() {
    echo "Repository,Status,Findings"
    for repo in "${CLEAN_LIST[@]}"; do
        echo "\"$repo\",clean,\"\""
    done
    for repo in "${INFECTED_LIST[@]}"; do
        local findings=""
        [ -f "$FINDINGS_FILE" ] && findings=$(grep "^$repo|" "$FINDINGS_FILE" | cut -d'|' -f2-)
        echo "\"$repo\",infected,\"${findings//\"/\\\"}\""
    done
    for repo in "${ERROR_LIST[@]}"; do
        local error=""
        [ -f "$FINDINGS_FILE" ] && error=$(grep "^$repo|" "$FINDINGS_FILE" | cut -d'|' -f2-)
        echo "\"$repo\",error,\"${error//\"/\\\"}\""
    done
}

#############################################################################
# MAIN
#############################################################################

if [ "$MODE" = "single" ]; then
    scan_single_project "$SCAN_TARGET"
else
    # Batch mode
    REPOS=()
    while IFS= read -r repo; do
        REPOS+=("$repo")
    done < <(discover_repos "$SCAN_TARGET")

    if [ ${#REPOS[@]} -eq 0 ]; then
        echo -e "${YELLOW}No repositories found${NC}"
        exit 0
    fi

    process_batch "${REPOS[@]}"

    # Generate report
    case "$OUTPUT_FORMAT" in
        json) report=$(generate_json_report) ;;
        csv) report=$(generate_csv_report) ;;
        *) report=$(generate_text_report) ;;
    esac

    # Output
    if [ -n "$OUTPUT_FILE" ]; then
        if [ "$OUTPUT_FORMAT" = "text" ]; then
            echo -e "$report" | sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"
        else
            echo "$report" > "$OUTPUT_FILE"
        fi
        echo -e "${GREEN}Report saved: $OUTPUT_FILE${NC}"
    fi

    echo -e "$report"

    [ $INFECTED_REPOS -gt 0 ] && exit 1
    [ $ERROR_REPOS -gt 0 ] && exit 2
    exit 0
fi
