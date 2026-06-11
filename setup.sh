#!/usr/bin/env bash
# ============================================================================
# VK Scanner (Voight-Kampff) — Automated Setup Script
# Usage: chmod +x setup.sh && ./setup.sh
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                                                         ║"
    echo "║   ██╗   ██╗██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗║"
    echo "║   ██║   ██║██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║║"
    echo "║   ██║   ██║█████╔╝     ███████╗██║     ███████║██╔██╗ ██║║"
    echo "║   ╚██╗ ██╔╝██╔═██╗     ╚════██║██║     ██╔══██║██║╚██╗██║║"
    echo "║    ╚████╔╝ ██║  ██╗    ███████║╚██████╗██║  ██║██║ ╚████║║"
    echo "║     ╚═══╝  ╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝║"
    echo "║                                                         ║"
    echo "║          Voight-Kampff Phishing Detector                ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log_info() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_step() { echo -e "${CYAN}[→]${NC} ${BOLD}$1${NC}"; }

# ── Detect OS ──
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_LIKE=$ID_LIKE
    elif [ -f /etc/debian_version ]; then
        OS="debian"
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    echo "$OS"
}

# ── Check if command exists ──
cmd_exists() {
    command -v "$1" &> /dev/null
}

# ── Install Docker ──
install_docker() {
    log_step "Installing Docker..."

    local os=$(detect_os)

    case "$os" in
        ubuntu|debian|kali|linuxmint|pop)
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                ca-certificates \
                curl \
                gnupg \
                lsb-release > /dev/null 2>&1

            # Add Docker's official GPG key
            sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$os/gpg | \
                sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
            sudo chmod a+r /etc/apt/keyrings/docker.gpg

            # For Kali/other derivatives, use debian repo
            local repo_os=$os
            if [[ "$os" == "kali" ]] || [[ "$os" == "linuxmint" ]] || [[ "$os" == "pop" ]]; then
                repo_os="debian"
            fi

            # Set up the repository
            echo \
                "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
                https://download.docker.com/linux/$repo_os \
                $(. /etc/os-release && echo "$VERSION_CODENAME" 2>/dev/null || echo "bookworm") stable" | \
                sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                docker-ce \
                docker-ce-cli \
                containerd.io \
                docker-buildx-plugin \
                docker-compose-plugin > /dev/null 2>&1
            ;;

        fedora|rhel|centos|rocky|alma)
            sudo dnf -y install dnf-plugins-core > /dev/null 2>&1
            sudo dnf config-manager --add-repo \
                https://download.docker.com/linux/fedora/docker-ce.repo > /dev/null 2>&1
            sudo dnf install -y \
                docker-ce \
                docker-ce-cli \
                containerd.io \
                docker-buildx-plugin \
                docker-compose-plugin > /dev/null 2>&1
            ;;

        arch|manjaro)
            sudo pacman -Sy --noconfirm docker docker-compose > /dev/null 2>&1
            ;;

        macos)
            if cmd_exists brew; then
                brew install --cask docker
            else
                log_error "Install Docker Desktop from: https://docker.com/products/docker-desktop"
                exit 1
            fi
            ;;

        *)
            log_error "Unsupported OS: $os"
            log_error "Please install Docker manually: https://docs.docker.com/get-docker/"
            exit 1
            ;;
    esac

    # Start and enable Docker service
    if [[ "$os" != "macos" ]]; then
        sudo systemctl start docker 2>/dev/null || true
        sudo systemctl enable docker 2>/dev/null || true
    fi

    log_info "Docker installed successfully"
}

# ── Configure Docker permissions ──
setup_docker_permissions() {
    log_step "Configuring Docker permissions..."

    # Add current user to docker group
    if ! groups "$USER" | grep -q docker; then
        sudo groupadd docker 2>/dev/null || true
        sudo usermod -aG docker "$USER"
        log_info "User '$USER' added to docker group"
        log_warn "Permission changes applied. If Docker commands fail, run: newgrp docker"

        # Apply group change for current script
        sg docker -c "true" 2>/dev/null || true
    else
        log_info "User '$USER' already in docker group"
    fi
}

# ── Check Docker Compose ──
get_compose_cmd() {
    if docker compose version &> /dev/null; then
        echo "docker compose"
    elif docker-compose version &> /dev/null; then
        echo "docker-compose"
    else
        echo ""
    fi
}

# ── Main Setup ──
main() {
    print_banner

    echo -e "${PURPLE}Starting automated setup (Suite & CLI Command)...${NC}"
    echo ""

    # Step 1: Check/Install Docker
    log_step "Step 1/6: Checking Docker..."
    if cmd_exists docker; then
        log_info "Docker is already installed: $(docker --version 2>/dev/null | head -1)"
    else
        log_warn "Docker not found. Installing..."
        install_docker
    fi

    # Step 2: Docker permissions
    log_step "Step 2/6: Checking Docker permissions..."
    setup_docker_permissions

    # Step 3: Check Docker Compose
    log_step "Step 3/6: Checking Docker Compose..."
    COMPOSE_CMD=$(get_compose_cmd)
    if [ -z "$COMPOSE_CMD" ]; then
        log_error "Docker Compose not found. Please install it:"
        log_error "  https://docs.docker.com/compose/install/"
        exit 1
    fi
    log_info "Docker Compose available: $COMPOSE_CMD"

    # Step 4: Build and run containers
    log_step "Step 4/6: Building and starting VK Scanner container services..."
    echo ""

    # Stop any existing containers
    $COMPOSE_CMD down 2>/dev/null || sg docker -c "$COMPOSE_CMD down" 2>/dev/null || true

    # Build and start
    if $COMPOSE_CMD up --build -d 2>/dev/null; then
        true
    elif sg docker -c "$COMPOSE_CMD up --build -d" 2>/dev/null; then
        true
    else
        log_warn "Trying with sudo..."
        sudo $COMPOSE_CMD up --build -d
    fi
    log_info "Web services are running successfully!"

    # Step 5: Install Python local dependencies for CLI
    log_step "Step 5/6: Installing local Python host dependencies for CLI..."
    
    # Check if pip is available, install if needed
    if ! cmd_exists pip3 && ! cmd_exists pip; then
        log_warn "Python pip not found on host. Installing system package..."
        local os=$(detect_os)
        case "$os" in
            ubuntu|debian|kali|linuxmint|pop)
                sudo apt-get update -qq && sudo apt-get install -y -qq python3-pip python3-venv > /dev/null 2>&1 || true
                ;;
            fedora|rhel|centos|rocky|alma)
                sudo dnf install -y python3-pip > /dev/null 2>&1 || true
                ;;
            arch|manjaro)
                sudo pacman -Sy --noconfirm python-pip > /dev/null 2>&1 || true
                ;;
        esac
    fi

    # Install python requirements natively on host
    if cmd_exists pip3; then
        log_info "Installing CLI dependencies via pip3 (requests)..."
        pip3 install --user requests || pip3 install requests || true
        log_info "CLI dependencies installed successfully"
    elif cmd_exists pip; then
        log_info "Installing CLI dependencies via pip (requests)..."
        pip install --user requests || pip install requests || true
        log_info "CLI dependencies installed successfully"
    else
        log_error "Could not install CLI dependencies automatically. Please run 'pip install requests' manually."
    fi

    # Step 6: Create system-wide CLI command (vkscanner shebang symlink)
    log_step "Step 6/6: Configuring global 'vkscanner' CLI system command..."
    local script_path="$(pwd)/vkscanner.py"
    chmod +x "$script_path"
    
    local linked=false
    if [ -w /usr/local/bin ]; then
        ln -sf "$script_path" /usr/local/bin/vkscanner
        linked=true
        log_info "Global CLI symlink created at: /usr/local/bin/vkscanner"
    else
        log_warn "Need sudo privileges to write to /usr/local/bin..."
        if sudo ln -sf "$script_path" /usr/local/bin/vkscanner 2>/dev/null; then
            linked=true
            log_info "Global CLI symlink created successfully at: /usr/local/bin/vkscanner"
        else
            # Try user local bin
            mkdir -p "$HOME/.local/bin"
            ln -sf "$script_path" "$HOME/.local/bin/vkscanner"
            linked=true
            log_info "CLI symlink created at: $HOME/.local/bin/vkscanner"
            log_warn "Please ensure '$HOME/.local/bin' is included in your system PATH variable."
        fi
    fi

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                         ║${NC}"
    echo -e "${GREEN}║   ${BOLD}✅ VK Scanner is successfully configured!${NC}${GREEN}              ║${NC}"
    echo -e "${GREEN}║                                                         ║${NC}"
    echo -e "${GREEN}║   🌐 Web Suite: ${CYAN}http://localhost:3000${GREEN}                     ║${NC}"
    echo -e "${GREEN}║   📖 API Docs:  ${CYAN}http://localhost:8000/docs${GREEN}                ║${NC}"
    echo -e "${GREEN}║                                                         ║${NC}"
    if [ "$linked" = true ]; then
        echo -e "${GREEN}║   💻 Global CLI: Run anywhere using: ${YELLOW}vkscanner${GREEN}            ║${NC}"
        echo -e "${GREEN}║   🌐 Web Launch: Open portal using:  ${YELLOW}vkscanner -w${GREEN}         ║${NC}"
    fi
    echo -e "${GREEN}║                                                         ║${NC}"
    echo -e "${GREEN}║   To stop web:  ${YELLOW}docker compose down${GREEN}                       ║${NC}"
    echo -e "${GREEN}║   Web Logs:     ${YELLOW}docker compose logs -f${GREEN}                    ║${NC}"
    echo -e "${GREEN}║                                                         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

main "$@"
