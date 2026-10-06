#!/usr/bin/env bash
# pentest-ai installer
# Usage: ./install.sh [--global | --project | --uninstall | --update]

set -euo pipefail

VERSION="3.2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_SRC="${SCRIPT_DIR}/.claude/agents"
GLOBAL_DIR="${HOME}/.claude/agents"
PROJECT_DIR=".claude/agents"
LITE_MODE=false
NO_DB=false

# Advisory-only agents safe to run on Haiku (no Bash tool, no execution risk)
HAIKU_SAFE_AGENTS=(
    "engagement-planner.md"
    "report-generator.md"
    "detection-engineer.md"
    "threat-modeler.md"
    "ctf-solver.md"
    "stig-analyst.md"
    "exploit-guide.md"
    "attack-planner.md"
    "forensics-analyst.md"
    "malware-analyst.md"
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "  ____  _____ _   _ _____ _____ ____ _____        _    ___ "
    echo " |  _ \| ____| \ | |_   _| ____/ ___|_   _|     / \  |_ _|"
    echo " | |_) |  _| |  \| | | | |  _| \___ \ | |_____ / _ \  | | "
    echo " |  __/| |___| |\  | | | | |___ ___) || |_____/ ___ \ | | "
    echo " |_|   |_____|_| \_| |_| |_____|____/ |_|    /_/   \_\___|"
    echo ""
    echo -e "  ${BOLD}v${VERSION}${NC}${CYAN} - AI-Powered Penetration Testing Agents${NC}"
    echo ""
}

count_agents() {
    local dir="$1"
    find "$dir" -maxdepth 1 -name "*.md" ! -name "_*" -type f 2>/dev/null | wc -l
}

is_haiku_safe() {
    local name="$1"
    for safe in "${HAIKU_SAFE_AGENTS[@]}"; do
        if [ "$name" = "$safe" ]; then
            return 0
        fi
    done
    return 1
}

copy_agent() {
    local src="$1"
    local dest="$2"
    local name
    name=$(basename "$src")

    if [ "$LITE_MODE" = true ] && is_haiku_safe "$name"; then
        sed 's/^model: sonnet$/model: haiku/' "$src" > "$dest"
    else
        cp "$src" "$dest"
    fi
}

REPO_URL="https://github.com/0xSteph/pentest-ai-agents.git"

bootstrap_from_curl() {
    # When piped from curl, clone the repo to a temp dir and re-exec the cloned install.sh.
    if ! command -v git &>/dev/null; then
        echo -e "${RED}Error: git is required for the one-line installer.${NC}"
        echo "  Install git first, or clone the repo manually."
        exit 1
    fi
    local tmp
    tmp=$(mktemp -d -t pentest-ai-XXXXXX)
    echo -e "${CYAN}Bootstrapping installer...${NC} (cloning ${REPO_URL})"
    if ! git clone --depth=1 --quiet "$REPO_URL" "$tmp/pentest-ai-agents"; then
        echo -e "${RED}Error: git clone failed.${NC}"
        rm -rf "$tmp"
        exit 1
    fi
    # Default to --global when piped without arguments so curl|bash "just works".
    local args=("$@")
    [ ${#args[@]} -eq 0 ] && args=(--global)
    exec bash "$tmp/pentest-ai-agents/install.sh" "${args[@]}"
}

check_prereqs() {
    if ! command -v claude &>/dev/null; then
        echo -e "${YELLOW}Warning: Claude Code CLI not found in PATH.${NC}"
        echo "  Install it with: npm install -g @anthropic-ai/claude-code"
        echo ""
    fi

    if [ ! -d "$AGENTS_SRC" ]; then
        bootstrap_from_curl "$@"
    fi
}

install_db() {
    if [ "$NO_DB" = true ]; then
        echo -e "  ${YELLOW}Skipped${NC} findings database (--no-db)"
        return
    fi

    local db_src="${SCRIPT_DIR}/db"
    if [ ! -d "$db_src" ]; then
        echo -e "  ${YELLOW}Skipped${NC} findings database (db/ not found)"
        return
    fi

    local db_dest="${HOME}/.pentest-ai/bin"
    mkdir -p "$db_dest"
    mkdir -p "${HOME}/.pentest-ai/bin/lib"

    cp "$db_src/findings.sh" "$db_dest/findings.sh"
    cp "$db_src/handoff.sh" "$db_dest/handoff.sh"
    cp "$db_src/migrate.sh" "$db_dest/migrate.sh"
    cp "$db_src/schema.sql" "$db_dest/schema.sql"
    cp "$db_src/lib/common.sh" "$db_dest/lib/common.sh"
    [ -f "$db_src/doctor.sh" ] && cp "$db_src/doctor.sh" "$db_dest/doctor.sh"
    chmod +x "$db_dest/findings.sh" "$db_dest/handoff.sh" "$db_dest/migrate.sh"
    [ -f "$db_dest/doctor.sh" ] && chmod +x "$db_dest/doctor.sh"

    # Add to PATH if not already there
    local shell_rc=""
    if [ -f "$HOME/.zshrc" ]; then
        shell_rc="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        shell_rc="$HOME/.bashrc"
    fi

    if [ -n "$shell_rc" ]; then
        if ! grep -q "pentest-ai/bin" "$shell_rc" 2>/dev/null; then
            echo "" >> "$shell_rc"
            echo "# pentest-ai findings database" >> "$shell_rc"
            echo "export PATH=\"\$HOME/.pentest-ai/bin:\$PATH\"" >> "$shell_rc"
            echo -e "  ${GREEN}installed${NC} findings database + PATH added to $(basename "$shell_rc")"
        else
            echo -e "  ${GREEN}installed${NC} findings database (PATH already configured)"
        fi
    else
        echo -e "  ${GREEN}installed${NC} findings database"
        echo -e "  ${YELLOW}Note:${NC} Add to your PATH: export PATH=\"\$HOME/.pentest-ai/bin:\$PATH\""
    fi
}

install_global() {
    echo -e "${BOLD}Installing agents globally...${NC}"
    [ "$LITE_MODE" = true ] && echo -e "${CYAN}Lite mode:${NC} advisory agents will use Haiku for lower token cost"
    mkdir -p "$GLOBAL_DIR"

    local installed=0
    local updated=0
    local skipped=0
    local haiku_count=0

    for agent in "${AGENTS_SRC}"/*.md; do
        local name
        name=$(basename "$agent")
        local dest="${GLOBAL_DIR}/${name}"

        if [ -f "$dest" ]; then
            # Build what the new file would look like, then compare
            local tmp
            tmp=$(mktemp)
            copy_agent "$agent" "$tmp"
            if ! diff -q "$tmp" "$dest" &>/dev/null; then
                mv "$tmp" "$dest"
                updated=$((updated + 1))
                if [ "$LITE_MODE" = true ] && is_haiku_safe "$name"; then
                    echo -e "  ${YELLOW}updated${NC}  ${name} ${CYAN}(haiku)${NC}"
                    haiku_count=$((haiku_count + 1))
                else
                    echo -e "  ${YELLOW}updated${NC}  ${name}"
                fi
            else
                rm "$tmp"
                skipped=$((skipped + 1))
            fi
        else
            copy_agent "$agent" "$dest"
            installed=$((installed + 1))
            if [ "$LITE_MODE" = true ] && is_haiku_safe "$name"; then
                echo -e "  ${GREEN}installed${NC} ${name} ${CYAN}(haiku)${NC}"
                haiku_count=$((haiku_count + 1))
            else
                echo -e "  ${GREEN}installed${NC} ${name}"
            fi
        fi
    done

    local total
    total=$(count_agents "$AGENTS_SRC")
    echo ""
    echo -e "${GREEN}Done.${NC} ${total} agents available globally."
    [ $installed -gt 0 ] && echo -e "  ${GREEN}${installed} new${NC}"
    [ $updated -gt 0 ] && echo -e "  ${YELLOW}${updated} updated${NC}"
    [ $skipped -gt 0 ] && echo -e "  ${skipped} unchanged"
    [ "$LITE_MODE" = true ] && echo -e "  ${CYAN}${haiku_count} agents set to Haiku (lite mode)${NC}"
    echo ""
    echo -e "  Location: ${CYAN}${GLOBAL_DIR}${NC}"
    echo "  Agents are available in all Claude Code sessions."

    install_db
}

install_project() {
    echo -e "${BOLD}Installing agents for this project...${NC}"
    [ "$LITE_MODE" = true ] && echo -e "${CYAN}Lite mode:${NC} advisory agents will use Haiku for lower token cost"
    mkdir -p "$PROJECT_DIR"

    local installed=0
    local haiku_count=0
    for agent in "${AGENTS_SRC}"/*.md; do
        local name
        name=$(basename "$agent")
        copy_agent "$agent" "${PROJECT_DIR}/${name}"
        installed=$((installed + 1))
        if [ "$LITE_MODE" = true ] && is_haiku_safe "$name"; then
            echo -e "  ${GREEN}installed${NC} ${name} ${CYAN}(haiku)${NC}"
            haiku_count=$((haiku_count + 1))
        else
            echo -e "  ${GREEN}installed${NC} ${name}"
        fi
    done

    echo ""
    echo -e "${GREEN}Done.${NC} ${installed} agents installed to ${CYAN}${PROJECT_DIR}${NC}"
    [ "$LITE_MODE" = true ] && echo -e "  ${CYAN}${haiku_count} agents set to Haiku (lite mode)${NC}"
    echo "  Agents are available only in this directory."

    install_db
}

detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v brew &>/dev/null; then
        echo "brew"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "none"
    fi
}

install_tools() {
    echo -e "${BOLD}Installing underlying CLI tools used by the agents...${NC}"
    echo ""
    local pm
    pm=$(detect_pkg_manager)

    if [ "$pm" = "none" ]; then
        echo -e "${RED}No supported package manager detected (apt, brew, pacman, dnf, yum).${NC}"
        echo "  Use db/doctor.sh to see what's missing and install per the hints."
        exit 1
    fi

    echo -e "  Package manager: ${CYAN}${pm}${NC}"
    echo ""

    # Tools available via package manager (best-effort, common-denominator set)
    local apt_pkgs=(nmap masscan dnsutils whois nikto sqlmap hydra hashcat john medusa cewl crunch \
                    aircrack-ng hcxdumptool hcxtools bettercap wifite \
                    radare2 binwalk apktool binutils \
                    libimage-exiftool-perl foremost yara steghide pngcheck \
                    ldap-utils responder \
                    curl jq git python3 golang rustc pipx adb)

    local brew_pkgs=(nmap masscan rustscan whatweb bind nikto sqlmap hydra hashcat john \
                     radare2 jadx binwalk \
                     trivy yara exiftool \
                     curl jq git python go rust pipx)

    local pacman_pkgs=(nmap masscan whois nikto sqlmap hydra hashcat john \
                       aircrack-ng radare2 binwalk binutils \
                       perl-image-exiftool yara \
                       curl jq git python go rust python-pipx)

    local pkgs=()
    case "$pm" in
        apt) pkgs=("${apt_pkgs[@]}") ;;
        brew) pkgs=("${brew_pkgs[@]}") ;;
        pacman) pkgs=("${pacman_pkgs[@]}") ;;
        dnf|yum) pkgs=(nmap nikto sqlmap hydra hashcat john curl jq git python3 golang rust) ;;
    esac

    # Filter out already-installed tools to keep the install set small
    local to_install=()
    for pkg in "${pkgs[@]}"; do
        local check="$pkg"
        # Map pkg name to check binary where they differ
        case "$pkg" in
            dnsutils|bind) check="dig" ;;
            libimage-exiftool-perl|perl-image-exiftool) check="exiftool" ;;
            ldap-utils) check="ldapsearch" ;;
            binutils) check="objdump" ;;
            python-pipx) check="pipx" ;;
        esac
        if ! command -v "$check" &>/dev/null; then
            to_install+=("$pkg")
        fi
    done

    if [ ${#to_install[@]} -eq 0 ]; then
        echo -e "  ${GREEN}All package-manager-installable tools already present.${NC}"
    else
        echo "Will install:"
        printf "  %s\n" "${to_install[@]}"
        echo ""
        if [ "${PENTEST_AI_TOOLS_YES:-}" != "1" ]; then
            read -rp "Proceed? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                echo "Aborted."
                exit 0
            fi
        fi

        case "$pm" in
            apt)    sudo apt-get update && sudo apt-get install -y "${to_install[@]}" || true ;;
            brew)   brew install "${to_install[@]}" || true ;;
            pacman) sudo pacman -S --noconfirm "${to_install[@]}" || true ;;
            dnf)    sudo dnf install -y "${to_install[@]}" || true ;;
            yum)    sudo yum install -y "${to_install[@]}" || true ;;
        esac
    fi

    # Tools that need pipx / go / cargo (not in standard repos, or fresher upstream)
    echo ""
    echo -e "${BOLD}Installing language-ecosystem tools...${NC}"

    if command -v pipx &>/dev/null; then
        local pipx_tools=(crackmapexec netexec impacket bloodhound certipy-ad \
                          theHarvester sherlock-project holehe maigret \
                          dnstwist commix volatility3 cupp-py hashid)
        for tool in "${pipx_tools[@]}"; do
            if ! pipx list 2>/dev/null | grep -q "$tool"; then
                echo -e "  ${CYAN}pipx install ${tool}${NC}"
                pipx install "$tool" 2>/dev/null || echo -e "    ${YELLOW}skip${NC} (not found or failed)"
            fi
        done
    else
        echo -e "  ${YELLOW}pipx not available; skipping Python tools.${NC}"
        echo "    Install pipx then re-run: install.sh --tools"
    fi

    if command -v go &>/dev/null; then
        local go_tools=(
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            "github.com/ffuf/ffuf/v2@latest"
            "github.com/OJ/gobuster/v3@latest"
            "github.com/hahwul/dalfox/v2@latest"
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            "github.com/projectdiscovery/httpx/cmd/httpx@latest"
            "github.com/owasp-amass/amass/v4/...@latest"
            "github.com/ropnop/kerbrute@latest"
        )
        for tool in "${go_tools[@]}"; do
            local bin
            bin=$(basename "${tool%%@*}" | sed 's/\.\.\.//')
            if ! command -v "$bin" &>/dev/null; then
                echo -e "  ${CYAN}go install ${tool}${NC}"
                go install -v "$tool" 2>/dev/null || echo -e "    ${YELLOW}skip${NC} (failed)"
            fi
        done
    else
        echo -e "  ${YELLOW}go not available; skipping Go tools.${NC}"
    fi

    if command -v cargo &>/dev/null; then
        if ! command -v feroxbuster &>/dev/null; then
            echo -e "  ${CYAN}cargo install feroxbuster${NC}"
            cargo install feroxbuster 2>/dev/null || true
        fi
        if ! command -v rustscan &>/dev/null; then
            echo -e "  ${CYAN}cargo install rustscan${NC}"
            cargo install rustscan 2>/dev/null || true
        fi
    fi

    echo ""
    echo -e "${GREEN}Done.${NC}"
    echo "  Run ${CYAN}db/doctor.sh${NC} to see the final install audit."
    echo "  Some tools (Ghidra, Metasploit, Evilginx, GoPhish) are too large for this script."
    echo "  See db/doctor.sh hints for those."
}

uninstall() {
    echo -e "${BOLD}Uninstalling pentest-ai agents...${NC}"
    echo ""

    local removed=0

    # Check global
    if [ -d "$GLOBAL_DIR" ]; then
        for agent in "${AGENTS_SRC}"/*.md; do
            local name
            name=$(basename "$agent")
            if [ -f "${GLOBAL_DIR}/${name}" ]; then
                rm "${GLOBAL_DIR}/${name}"
                ((removed++))
                echo -e "  ${RED}removed${NC}  ${GLOBAL_DIR}/${name}"
            fi
        done
    fi

    # Check project-level
    if [ -d "$PROJECT_DIR" ]; then
        for agent in "${AGENTS_SRC}"/*.md; do
            local name
            name=$(basename "$agent")
            if [ -f "${PROJECT_DIR}/${name}" ]; then
                rm "${PROJECT_DIR}/${name}"
                ((removed++))
                echo -e "  ${RED}removed${NC}  ${PROJECT_DIR}/${name}"
            fi
        done
    fi

    if [ $removed -eq 0 ]; then
        echo "  No pentest-ai agents found to remove."
    else
        echo ""
        echo -e "${GREEN}Done.${NC} Removed ${removed} agent files."
    fi
}

show_status() {
    echo -e "${BOLD}Installation Status${NC}"
    echo ""

    local global_count
    global_count=$(count_agents "$GLOBAL_DIR")
    if [ "$global_count" -gt 0 ]; then
        echo -e "  Global: ${GREEN}${global_count} agents${NC} in ${GLOBAL_DIR}"
    else
        echo -e "  Global: ${YELLOW}not installed${NC}"
    fi

    if [ -d "$PROJECT_DIR" ]; then
        local project_count
        project_count=$(count_agents "$PROJECT_DIR")
        if [ "$project_count" -gt 0 ]; then
            echo -e "  Project: ${GREEN}${project_count} agents${NC} in ${PROJECT_DIR}"
        fi
    fi

    local source_count
    source_count=$(count_agents "$AGENTS_SRC")
    echo -e "  Source:  ${CYAN}${source_count} agents${NC} available in repo"
    echo ""
}

usage() {
    echo -e "${BOLD}Usage:${NC} ./install.sh [option] [--lite]"
    echo ""
    echo "Options:"
    echo "  --global      Install agents globally (~/.claude/agents/)"
    echo "  --project     Install agents for current project (.claude/agents/)"
    echo "  --uninstall   Remove all pentest-ai agents"
    echo "  --update      Update existing global install (same as --global)"
    echo "  --status      Show installation status"
    echo "  --tools       Install underlying CLI tools (nmap, nuclei, etc.) via system package manager + pipx/go/cargo"
    echo "  --lite        Use Haiku for advisory agents (lower token cost)"
    echo "  --no-db       Skip findings database installation"
    echo "  --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./install.sh --global              # Standard install (all Sonnet)"
    echo "  ./install.sh --global --lite       # Lite install (advisory on Haiku)"
    echo ""
    echo "One-liner install from GitHub:"
    echo "  git clone https://github.com/0xSteph/pentest-ai.git && cd pentest-ai && ./install.sh --global"
}

interactive() {
    echo "Where do you want to install the agents?"
    echo ""
    echo "  1) Global     - available in all Claude Code sessions"
    echo "  2) Project    - available only in the current directory"
    echo "  3) Uninstall  - remove pentest-ai agents"
    echo "  4) Status     - show current installation"
    echo ""

    if [ "$LITE_MODE" = false ]; then
        read -rp "Use lite mode? (Haiku for advisory agents, lower token cost) [y/N]: " lite_choice
        if [[ "$lite_choice" =~ ^[Yy] ]]; then
            LITE_MODE=true
        fi
        echo ""
    fi

    read -rp "Choice [1-4]: " choice

    case "$choice" in
        1) install_global ;;
        2) install_project ;;
        3) uninstall ;;
        4) show_status ;;
        *) echo "Invalid choice."; exit 1 ;;
    esac
}

# Main
banner
check_prereqs "$@"

# Parse flags from any position
for arg in "$@"; do
    if [ "$arg" = "--lite" ]; then
        LITE_MODE=true
    elif [ "$arg" = "--no-db" ]; then
        NO_DB=true
    fi
done

# Parse primary command (first non-flag argument)
PRIMARY=""
for arg in "$@"; do
    if [ "$arg" != "--lite" ] && [ "$arg" != "--no-db" ]; then
        PRIMARY="$arg"
        break
    fi
done

case "${PRIMARY:-}" in
    --global|--update) install_global ;;
    --project)         install_project ;;
    --uninstall)       uninstall ;;
    --status)          show_status ;;
    --tools)           install_tools ;;
    --help|-h)         usage ;;
    "")                interactive ;;
    *)                 echo -e "${RED}Unknown option: ${PRIMARY}${NC}"; usage; exit 1 ;;
esac
