#!/usr/bin/env bash
# pentest-ai tool installation audit
# Reports which underlying CLI tools the agents drive are present on this system
# Output groups tools by agent so a user can see exactly what gaps to fill

set -uo pipefail

# ─── color and symbol setup ─────────────────────────────────────────────
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" == "" ]]; then
    GREEN=$'\033[0;32m'
    RED=$'\033[0;31m'
    YELLOW=$'\033[0;33m'
    DIM=$'\033[0;90m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
    OK="✔"
    MISS="✘"
    OPT="○"
else
    GREEN="" RED="" YELLOW="" DIM="" BOLD="" RESET=""
    OK="[OK]"
    MISS="[MISS]"
    OPT="[OPT]"
fi

# ─── tool catalog ───────────────────────────────────────────────────────
# Format: "<binary>|<agent>|<category>|<install hint>"
# Categories: required (advisory + execution), optional (nice to have), platform (only on certain OS)

TOOLS=(
    # recon-advisor
    "nmap|recon-advisor|required|apt install nmap | brew install nmap"
    "masscan|recon-advisor|optional|apt install masscan"
    "rustscan|recon-advisor|optional|cargo install rustscan"
    "whatweb|recon-advisor|optional|apt install whatweb"
    "dig|recon-advisor|required|apt install dnsutils | brew install bind"
    "whois|recon-advisor|optional|apt install whois"

    # vuln-scanner
    "nuclei|vuln-scanner|required|go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "nikto|vuln-scanner|required|apt install nikto | brew install nikto"
    "rsf.py|vuln-scanner|optional|pipx install routersploit"

    # web-hunter
    "ffuf|web-hunter|required|go install github.com/ffuf/ffuf/v2@latest"
    "gobuster|web-hunter|optional|go install github.com/OJ/gobuster/v3@latest"
    "feroxbuster|web-hunter|optional|cargo install feroxbuster"
    "sqlmap|web-hunter|required|apt install sqlmap | pipx install sqlmap"
    "dalfox|web-hunter|optional|go install github.com/hahwul/dalfox/v2@latest"
    "commix|web-hunter|optional|pipx install commix"
    "subfinder|web-hunter|optional|go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "amass|web-hunter|optional|go install -v github.com/owasp-amass/amass/v4/...@latest"
    "httpx|web-hunter|optional|go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"

    # ad-attacker
    "crackmapexec|ad-attacker|required|pipx install crackmapexec"
    "nxc|ad-attacker|optional|pipx install netexec"
    "impacket-secretsdump|ad-attacker|required|pipx install impacket"
    "bloodhound-python|ad-attacker|optional|pipx install bloodhound"
    "kerbrute|ad-attacker|optional|go install github.com/ropnop/kerbrute@latest"
    "certipy|ad-attacker|optional|pipx install certipy-ad"
    "responder|ad-attacker|optional|apt install responder"
    "ldapsearch|ad-attacker|required|apt install ldap-utils"

    # credential-tester
    "hydra|credential-tester|required|apt install hydra | brew install hydra"
    "hashcat|credential-tester|required|apt install hashcat | brew install hashcat"
    "john|credential-tester|required|apt install john | brew install john"
    "medusa|credential-tester|optional|apt install medusa"
    "cewl|credential-tester|optional|apt install cewl"
    "cupp|credential-tester|optional|apt install cupp | pipx install cupp-py"
    "crunch|credential-tester|optional|apt install crunch"
    "hashid|credential-tester|optional|pipx install hashid"
    "haiti|credential-tester|optional|gem install haiti-hash"

    # payload-crafter
    "msfvenom|payload-crafter|required|apt install metasploit-framework"
    "msfconsole|payload-crafter|required|apt install metasploit-framework"
    "donut|payload-crafter|optional|build from github.com/TheWover/donut"

    # reverse-engineer
    "ghidra|reverse-engineer|required|apt install ghidra | brew install --cask ghidra"
    "r2|reverse-engineer|optional|apt install radare2 | brew install radare2"
    "jadx|reverse-engineer|optional|apt install jadx | brew install jadx"
    "binwalk|reverse-engineer|optional|apt install binwalk | pipx install binwalk"
    "apktool|reverse-engineer|optional|apt install apktool | brew install apktool"
    "objdump|reverse-engineer|optional|apt install binutils"
    "readelf|reverse-engineer|optional|apt install binutils"

    # mobile-pentester
    "frida|mobile-pentester|optional|pipx install frida-tools"
    "objection|mobile-pentester|optional|pipx install objection"
    "adb|mobile-pentester|required|apt install adb | brew install --cask android-platform-tools"

    # wireless-pentester
    "aircrack-ng|wireless-pentester|required|apt install aircrack-ng"
    "hcxdumptool|wireless-pentester|optional|apt install hcxdumptool"
    "hcxtools|wireless-pentester|optional|apt install hcxtools"
    "bettercap|wireless-pentester|optional|apt install bettercap"
    "wifite|wireless-pentester|optional|apt install wifite"

    # phishing-operator
    "dnstwist|phishing-operator|optional|pipx install dnstwist[full]"
    "evilginx|phishing-operator|optional|build from github.com/kgretzky/evilginx2"
    "gophish|phishing-operator|optional|download from github.com/gophish/gophish"

    # cloud-security
    "aws|cloud-security|optional|pipx install awscli"
    "az|cloud-security|optional|see docs.microsoft.com/cli/azure/install"
    "gcloud|cloud-security|optional|see cloud.google.com/sdk/docs/install"
    "trivy|cloud-security|optional|brew install trivy | apt install trivy"
    "prowler|cloud-security|optional|pipx install prowler"
    "scout|cloud-security|optional|pipx install scoutsuite"

    # malware-analyst / forensics-analyst
    "yara|malware-analyst|optional|apt install yara | brew install yara"
    "exiftool|forensics-analyst|optional|apt install libimage-exiftool-perl"
    "vol|forensics-analyst|optional|pipx install volatility3"
    "foremost|forensics-analyst|optional|apt install foremost"

    # ctf-solver / stego
    "zsteg|ctf-solver|optional|gem install zsteg"
    "steghide|ctf-solver|optional|apt install steghide"
    "stegseek|ctf-solver|optional|see github.com/RickdeJager/stegseek"
    "pngcheck|ctf-solver|optional|apt install pngcheck"

    # osint-collector
    "theharvester|osint-collector|optional|pipx install theHarvester"
    "sherlock|osint-collector|optional|pipx install sherlock-project"
    "holehe|osint-collector|optional|pipx install holehe"
    "maigret|osint-collector|optional|pipx install maigret"

    # general utilities
    "curl|core|required|apt install curl"
    "jq|core|required|apt install jq | brew install jq"
    "git|core|required|apt install git"
    "python3|core|required|apt install python3 | brew install python"
    "go|core|optional|apt install golang | brew install go"
    "cargo|core|optional|apt install rustc | brew install rust"
    "pipx|core|optional|apt install pipx | brew install pipx"
)

# ─── option parsing ─────────────────────────────────────────────────────
ONLY_AGENT=""
JSON_OUTPUT=0
QUIET=0
SHOW_HINTS=1

usage() {
    cat <<EOF
Usage: doctor.sh [options]

Audit which underlying CLI tools the pentest-ai agents drive are installed.

Options:
  --agent <name>   Filter to tools used by a specific agent (e.g. ad-attacker)
  --json           Emit JSON instead of human-readable output
  --quiet          Only show missing required tools
  --no-hints       Suppress install hints in human output
  -h, --help       Show this help

Exit codes:
  0  All required tools present
  1  At least one required tool missing
  2  Invalid usage
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent) ONLY_AGENT="$2"; shift 2 ;;
        --json) JSON_OUTPUT=1; shift ;;
        --quiet) QUIET=1; shift ;;
        --no-hints) SHOW_HINTS=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

# ─── audit ──────────────────────────────────────────────────────────────
declare -A AGENT_TOTAL=()
declare -A AGENT_PRESENT=()
declare -A AGENT_REQ_MISSING=()
RESULTS=()
REQ_MISSING_COUNT=0

for entry in "${TOOLS[@]}"; do
    IFS='|' read -r bin agent category hint <<< "$entry"

    if [[ -n "$ONLY_AGENT" ]] && [[ "$agent" != "$ONLY_AGENT" ]]; then
        continue
    fi

    if command -v "$bin" >/dev/null 2>&1; then
        status="present"
    else
        status="missing"
    fi

    AGENT_TOTAL[$agent]=$((${AGENT_TOTAL[$agent]:-0} + 1))
    if [[ "$status" == "present" ]]; then
        AGENT_PRESENT[$agent]=$((${AGENT_PRESENT[$agent]:-0} + 1))
    elif [[ "$category" == "required" ]]; then
        AGENT_REQ_MISSING[$agent]=$((${AGENT_REQ_MISSING[$agent]:-0} + 1))
        REQ_MISSING_COUNT=$((REQ_MISSING_COUNT + 1))
    fi

    RESULTS+=("$bin|$agent|$category|$status|$hint")
done

# ─── output ─────────────────────────────────────────────────────────────
if [[ "$JSON_OUTPUT" == "1" ]]; then
    printf '{\n  "tools": [\n'
    first=1
    for r in "${RESULTS[@]}"; do
        IFS='|' read -r bin agent category status hint <<< "$r"
        [[ $first -eq 1 ]] || printf ',\n'
        first=0
        printf '    {"binary":"%s","agent":"%s","category":"%s","status":"%s"}' \
            "$bin" "$agent" "$category" "$status"
    done
    printf '\n  ],\n  "required_missing": %d\n}\n' "$REQ_MISSING_COUNT"
    [[ $REQ_MISSING_COUNT -gt 0 ]] && exit 1 || exit 0
fi

# Human output
echo "${BOLD}pentest-ai tool audit${RESET}"
echo "${DIM}$(date '+%Y-%m-%d %H:%M:%S')  host: $(hostname)${RESET}"
echo

# Group results by agent
declare -A BY_AGENT=()
for r in "${RESULTS[@]}"; do
    IFS='|' read -r bin agent category status hint <<< "$r"
    BY_AGENT[$agent]="${BY_AGENT[$agent]:-}$r"$'\n'
done

# Stable agent order
AGENT_ORDER=(
    core recon-advisor osint-collector vuln-scanner web-hunter
    ad-attacker credential-tester payload-crafter reverse-engineer
    mobile-pentester wireless-pentester phishing-operator cloud-security
    malware-analyst forensics-analyst ctf-solver
)

for agent in "${AGENT_ORDER[@]}"; do
    [[ -z "${BY_AGENT[$agent]:-}" ]] && continue

    total="${AGENT_TOTAL[$agent]:-0}"
    present="${AGENT_PRESENT[$agent]:-0}"
    req_miss="${AGENT_REQ_MISSING[$agent]:-0}"

    if [[ "$QUIET" == "1" ]] && [[ "$req_miss" == "0" ]]; then
        continue
    fi

    if [[ "$req_miss" -gt 0 ]]; then
        header_color="$RED"
    elif [[ "$present" -lt "$total" ]]; then
        header_color="$YELLOW"
    else
        header_color="$GREEN"
    fi

    printf "${BOLD}${header_color}%s${RESET}  ${DIM}(%d/%d present)${RESET}\n" \
        "$agent" "$present" "$total"

    while IFS= read -r r; do
        [[ -z "$r" ]] && continue
        IFS='|' read -r bin a category status hint <<< "$r"

        if [[ "$status" == "present" ]]; then
            [[ "$QUIET" == "1" ]] && continue
            printf "  ${GREEN}%s${RESET} %-20s ${DIM}%s${RESET}\n" "$OK" "$bin" "$category"
        else
            if [[ "$category" == "required" ]]; then
                sym="$MISS"; col="$RED"
            else
                sym="$OPT"; col="$YELLOW"
            fi
            printf "  ${col}%s${RESET} %-20s ${DIM}%s${RESET}" "$sym" "$bin" "$category"
            if [[ "$SHOW_HINTS" == "1" ]]; then
                printf "\n      ${DIM}↳ %s${RESET}" "$hint"
            fi
            printf "\n"
        fi
    done <<< "${BY_AGENT[$agent]}"
    echo
done

# Summary
echo "${BOLD}Summary${RESET}"
total_tools=${#RESULTS[@]}
present_total=0
for k in "${!AGENT_PRESENT[@]}"; do
    present_total=$((present_total + ${AGENT_PRESENT[$k]}))
done

printf "  ${GREEN}%s${RESET} %d / %d tools detected\n" "$OK" "$present_total" "$total_tools"
if [[ "$REQ_MISSING_COUNT" -gt 0 ]]; then
    printf "  ${RED}%s${RESET} %d required tool%s missing\n" \
        "$MISS" "$REQ_MISSING_COUNT" "$([ "$REQ_MISSING_COUNT" -eq 1 ] && echo "" || echo "s")"
    echo
    echo "Run: ${BOLD}install.sh --tools${RESET}  to install required tools where supported"
    exit 1
else
    printf "  ${GREEN}%s${RESET} all required tools present\n" "$OK"
    exit 0
fi
