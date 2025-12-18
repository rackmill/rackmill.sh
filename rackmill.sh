#!/usr/bin/env bash
set -eEuo pipefail

# =============================================
# Rackmill Ubuntu/Debian/RHEL Setup Script
# Operators will observe the script as it runs and respond to any errors or prompts during execution.
# Always allow the operator to see what is happening. Allow standard console output to be visible at all times.
# All functions should use `section()` and `step()` for logging, and avoid silent failures. 
# Any irreversible actions (for example, removing user data) must be explicitly called out in the function comments and confirmed interactively by the operator before proceeding.
# Backups should be performed in the function that owns the resource (for example, `apt_sources()` should back up apt files).
# =============================================

# =============================================
# Global utilities and variables
# =============================================
GREEN="\e[32m"
CYAN="\e[36m"
RED="\e[31m"
RESET="\e[0m"

section() {
  echo -e "${CYAN}\n# ===========================================\n# => $1${RESET}\n"
}
step() {
  echo -e "\n${GREEN}-> $1${RESET}"
}
error() {
  echo -e "\n${RED}-> $1${RESET}\n\n"
}

# Prompt for y/n confirmation. Usage: confirm "prompt" || exit 1
confirm() {
  local response
  read -rp "$1 Type 'y' to proceed, anything else to exit: " response
  [[ "$response" == "y" || "$response" == "Y" ]]
}

# Require confirmation or exit with error. Usage: require_confirm "prompt" "error_msg"
require_confirm() {
  confirm "$1" || { error "$2"; exit 1; }
}

# Determine canonical APT source file based on OS type and version.
# Sets: canonical_file (path), is_deb822 (true/false)
get_canonical_file() {
  is_deb822=false
  if [[ "$OS_TYPE" == "debian" ]]; then
    if [[ "${VERSION_MAJOR}" -ge 13 ]]; then
      canonical_file="/etc/apt/sources.list.d/debian.sources"
      is_deb822=true
    else
      canonical_file="/etc/apt/sources.list"
    fi
  else
    # Ubuntu: 23.10+ uses deb822
    if [[ "${VERSION_ID:-}" =~ ^23\.10|^2[4-9]\.|^[3-9][0-9]\. ]]; then
      canonical_file="/etc/apt/sources.list.d/ubuntu.sources"
      is_deb822=true
    else
      canonical_file="/etc/apt/sources.list"
    fi
  fi
}

# Set ERR trap globally so it applies to all functions and subshells
trap 'error "Fatal error on line $LINENO: $BASH_COMMAND"; exit 1' ERR

# Global arrays for tracking state
declare -a BACKUPS=()
declare -a CLEANUP_FILES=()
declare -a CLEANUP_TRUNCATE=()

# OS version information (populated by setup())
OS_TYPE=""          # "ubuntu", "debian", or "rhel"
OS_DISTRO=""        # specific distro: "ubuntu", "debian", "almalinux", "rocky", "ol", "centos", "cloudlinux", "rhel"
VERSION_ID=""
VERSION_MAJOR=""
CODENAME=""
PKG_MGR=""          # "apt" for Debian/Ubuntu, "dnf" for RHEL 8+, "yum" for CentOS 7
HAS_SYSTEMD=true    # false for Ubuntu <15, Debian <8
APT_FLAGS="-y"      # may include --allow-unauthenticated for archived Debian

# Decision flags
APT_SOURCES_CHANGES_REQUIRED=false

# Patterns for files to TRUNCATE during cleanup (contents cleared, file remains)
TRUNCATE_PATTERNS=(
  "/etc/machine-id"
  "/var/lib/dbus/machine-id"
  "/var/lib/systemd/machine-id"
)

# Patterns for files/directories to REMOVE during cleanup
REMOVE_PATTERNS=(
  # System randomness/state
  "/var/lib/systemd/random-seed"

  # SSH host keys - regenerated on first boot
  "/etc/ssh/ssh_host_*"

  # Root-specific files
  "/root/.ssh/authorized_keys"
  "/root/.wget-hsts"
  "/root/.Xauthority"
  "/root/.bash_history"
  "/root/anaconda-ks.cfg"
  "/root/.lesshst"
  "/root/.config"
  "/root/.cache"
  "/root/.nano"
  "/root/snap"
  "/root/.gnupg"
  "/root/.viminfo"

  # Per-user files under /home
  "/home/*/.ssh/authorized_keys"
  "/home/*/.wget-hsts"
  "/home/*/.Xauthority"
  "/home/*/.bash_history"
  "/home/*/.lesshst"
  "/home/*/.config"
  "/home/*/snap"
  "/home/*/.gnupg"
  "/home/*/.viminfo"

  # Temp space
  "/tmp/*"

  # All system logs
  "/var/log/*"

  # All runtime logs
  "/run/log/*"

  # RHEL-specific: DNF/YUM cache and history
  "/var/cache/dnf/*"
  "/var/cache/yum/*"
  "/var/lib/dnf/history*"
  "/var/lib/yum/history*"
  "/var/lib/rpm/__db*"
)

# Output canonical APT sources for detected OS/version. See FUNCTIONS.md for details.
canonical_sources() {
  local codename="${1:-$CODENAME}"
  local os_type="${2:-$OS_TYPE}"
  
  if [[ "$os_type" == "debian" ]]; then
    # Debian sources - check if archived
    local use_archive=false
    if [[ "${VERSION_MAJOR}" -le 10 ]]; then
      use_archive=true
    fi
    
    if $use_archive; then
      # Archived Debian releases (Stretch 9, Buster 10) use archive.debian.org
      # Note: Archive repos don't have signed Release files (expected warnings)
      local components="main contrib non-free"
      cat <<EOF
deb http://archive.debian.org/debian $codename $components
deb http://archive.debian.org/debian ${codename}-backports $components
deb http://archive.debian.org/debian-security ${codename}/updates $components
EOF
    elif [[ "${VERSION_MAJOR}" -ge 12 ]]; then
      # DEB822 format for Debian 12+ (Bookworm and newer)
      local components="main contrib non-free non-free-firmware"
      # Debian 12+ includes non-free-firmware
      cat <<EOF
Types: deb
URIs: http://deb.debian.org/debian
Suites: $codename $codename-updates $codename-backports
Components: $components
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: ${codename}-security
Components: $components
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
    else
      # Classic sources.list format for Debian 11 (Bullseye)
      # Note: Debian 11 (bullseye) backports are no longer available
      local components="main contrib non-free"
      cat <<EOF
deb http://deb.debian.org/debian $codename $components
deb http://deb.debian.org/debian ${codename}-updates $components
deb http://security.debian.org/debian-security ${codename}-security $components
EOF
    fi
  else
    # Ubuntu sources
    if [[ "${VERSION_ID:-}" =~ ^23\.10|^2[4-9]\.|^[3-9][0-9]\. ]]; then
      # DEB822 format for Ubuntu 23.10+
      cat <<EOF
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: $codename $codename-updates $codename-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: $codename-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
    else
      # Classic sources.list format for Ubuntu 23.04 and earlier
      cat <<EOF
deb https://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${codename}-updates main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu ${codename}-backports main restricted universe multiverse
deb https://security.ubuntu.com/ubuntu ${codename}-security main restricted universe multiverse
EOF
    fi
  fi
}

# Verify root, detect OS type/version, set global variables. See FUNCTIONS.md.
setup() {
  section "Initial Setup and Detection"

  # Ensure running as root
  if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root. Exiting."
    exit 1
  fi
  step "Confirmed running as root."

  # Display network interfaces and routes for operator visibility
  step "Displaying network interfaces:"
  if command -v ip &> /dev/null; then
    ip link show
    ip route show
    ip addr show
  else
    # Fallback for older systems (e.g., Ubuntu 14.04) without iproute2
    ifconfig -a 2>/dev/null || true
    route -n 2>/dev/null || true
  fi
  cat /etc/resolv.conf || true
  cat /etc/network/interfaces || true

  # Detect OS version and codename
  section "Detecting OS version ... "
  cat /etc/os-release
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    
    # Detect OS type and distro
    OS_DISTRO="${ID:-}"
    VERSION_ID="${VERSION_ID:-}"
    
    # Map distro to OS type family
    case "$OS_DISTRO" in
      ubuntu)
        OS_TYPE="ubuntu"
        ;;
      debian)
        OS_TYPE="debian"
        ;;
      almalinux|rocky|ol|centos|cloudlinux|rhel)
        OS_TYPE="rhel"
        ;;
      *)
        error "Unsupported OS detected: $OS_DISTRO. This script supports Ubuntu, Debian, and RHEL-family (AlmaLinux, Rocky, Oracle Linux, CentOS Stream, CloudLinux, RHEL 8+). Exiting."
        exit 2
        ;;
    esac
    
    # Extract codename based on OS type
    if [[ "$OS_TYPE" == "ubuntu" ]]; then
      # For older Ubuntu (like 14.04), UBUNTU_CODENAME may not exist.
      # Try to extract codename from VERSION or PRETTY_NAME if UBUNTU_CODENAME is empty.
      CODENAME="${UBUNTU_CODENAME:-}"
      if [[ -z "$CODENAME" ]]; then
        # Try to extract from VERSION or PRETTY_NAME (POSIX-compatible)
        if [[ -n "${VERSION:-}" ]]; then
          CODENAME="$(echo "$VERSION" | sed -n 's/.*[^(]*[[:space:]]\([^)]*\)).*/\1/p' | tr '[:upper:]' '[:lower:]' | awk '{print $1}')"
        elif [[ -n "${PRETTY_NAME:-}" ]]; then
          CODENAME="$(echo "$PRETTY_NAME" | sed -n 's/.*[^(]*[[:space:]]\([^)]*\)).*/\1/p' | tr '[:upper:]' '[:lower:]' | awk '{print $1}')"
        fi
      fi
    elif [[ "$OS_TYPE" == "debian" ]]; then
      # Debian uses VERSION_CODENAME
      CODENAME="${VERSION_CODENAME:-}"
      if [[ -z "$CODENAME" ]]; then
        # Try to extract from VERSION field as fallback (POSIX-compatible)
        if [[ -n "${VERSION:-}" ]]; then
          CODENAME="$(echo "$VERSION" | sed -n 's/.*[^(]*[[:space:]]\([^)]*\)).*/\1/p' | tr '[:upper:]' '[:lower:]' | awk '{print $1}')"
        fi
      fi
    elif [[ "$OS_TYPE" == "rhel" ]]; then
      # RHEL-family uses VERSION_CODENAME if available, otherwise use version number
      CODENAME="${VERSION_CODENAME:-$VERSION_ID}"
    fi
    
    # Validate VERSION_ID is set
    if [[ -z "$VERSION_ID" ]]; then
      error "Failed to detect OS version. Exiting."
      exit 2
    fi
    
    # For Debian/Ubuntu, codename is required
    if [[ "$OS_TYPE" != "rhel" && -z "$CODENAME" ]]; then
      error "Failed to detect OS codename. Exiting."
      exit 2
    fi
    
    VERSION_MAJOR="${VERSION_ID%%.*}"
    
    # Validate supported versions
    if [[ "$OS_TYPE" == "ubuntu" ]]; then
      if [[ "$VERSION_MAJOR" -lt 14 ]]; then
        error "Ubuntu $VERSION_ID is not supported. Minimum version: 14.04 (Trusty). Exiting."
        exit 2
      fi
      step "Detected Ubuntu $VERSION_ID ($CODENAME)."
    elif [[ "$OS_TYPE" == "debian" ]]; then
      if [[ "$VERSION_MAJOR" -lt 9 ]]; then
        error "Debian $VERSION_ID is not supported. Minimum version: 9 (Stretch). Exiting."
        exit 2
      fi
      # Inform operator about archived versions
      if [[ "$VERSION_MAJOR" -le 10 ]]; then
        step "⚠️  Detected Debian $VERSION_ID ($CODENAME) - ARCHIVED RELEASE"
        step "    This version uses archive.debian.org (no security updates)."
        step "    APT will show warnings about missing Release files - this is expected."
      else
        step "Detected Debian $VERSION_ID ($CODENAME)."
      fi
    elif [[ "$OS_TYPE" == "rhel" ]]; then
      # CentOS 7 is minimum for RHEL-family (uses yum); RHEL 8+ uses dnf
      if [[ "$OS_DISTRO" == "centos" && "$VERSION_MAJOR" -eq 7 ]]; then
        PKG_MGR="yum"
        step "⚠️  Detected CentOS $VERSION_ID - END OF LIFE (EOL)"
        step "    CentOS 7 reached EOL on June 30, 2024."
        step "    Repositories have moved to vault.centos.org (no security updates)."
        step "    Consider migrating to AlmaLinux, Rocky Linux, or another supported distribution."
      elif [[ "$VERSION_MAJOR" -lt 8 ]]; then
        error "$OS_DISTRO $VERSION_ID is not supported. Minimum version: 8 (or CentOS 7). Exiting."
        exit 2
      else
        PKG_MGR="dnf"
        step "Detected $OS_DISTRO $VERSION_ID (RHEL-family)."
      fi
    fi
  else
    error "/etc/os-release not found. Unable to detect OS. Exiting."
    exit 2
  fi

  # Set derived flags based on detected OS
  # HAS_SYSTEMD: false for Ubuntu <15 or Debian <8 (Upstart/SysVinit)
  if [[ "$OS_TYPE" == "ubuntu" && "$VERSION_MAJOR" -lt 15 ]]; then
    HAS_SYSTEMD=false
  elif [[ "$OS_TYPE" == "debian" && "$VERSION_MAJOR" -lt 8 ]]; then
    HAS_SYSTEMD=false
  fi
  # APT_FLAGS: archived Debian releases need --allow-unauthenticated
  if [[ "$OS_TYPE" == "debian" && "$VERSION_MAJOR" -le 10 ]]; then
    APT_FLAGS="-y --allow-unauthenticated"
  fi
}


# Audit APT sources, enforce canonical configuration. See FUNCTIONS.md.
apt_sources_prepare() {
  section "Auditing APT Sources"

  # Determine canonical file based on OS type and version
  local canonical_file
  local is_deb822
  get_canonical_file

  # For deb822 systems: if canonical file doesn't exist but sources.list does, offer migration
  if $is_deb822 && [[ ! -f "$canonical_file" ]] && [[ -f /etc/apt/sources.list ]]; then
    if grep -qE '^\s*deb ' /etc/apt/sources.list; then
      step "$canonical_file not found. /etc/apt/sources.list contains deb lines."
      if confirm "Create $canonical_file and backup sources.list?"; then
        step "Creating $canonical_file..."
        canonical_sources > "$canonical_file"
        step "Backing up /etc/apt/sources.list to /etc/apt/sources.list.bak..."
        mv /etc/apt/sources.list /etc/apt/sources.list.bak
        step "Running apt update..."
        apt update
      else
        error "Exiting. Create $canonical_file manually to proceed."
        exit 1
      fi
    fi
  fi

  # Enforce canonical file rules
  if $is_deb822; then
    if [[ -f /etc/apt/sources.list ]]; then
      # /etc/apt/sources.list may exist, but must not contain any deb lines
      if grep -qE '^\s*deb ' /etc/apt/sources.list; then
        error "/etc/apt/sources.list contains deb lines but deb822 sources are in use."
        if confirm "Move /etc/apt/sources.list to /etc/apt/sources.list.bak?"; then
          step "Backing up /etc/apt/sources.list to /etc/apt/sources.list.bak..."
          mv /etc/apt/sources.list /etc/apt/sources.list.bak
          step "Done. Old sources.list backed up."
        else
          error "Please remove or comment out all deb lines in /etc/apt/sources.list."
          exit 1
        fi
      fi
    fi
  else # classic
    # When using classic sources.list, deb822 files should not exist
    if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
      error "/etc/apt/sources.list.d/ubuntu.sources should not exist when using classic sources.list. Please remove it."
      exit 1
    fi
    if [[ -f /etc/apt/sources.list.d/debian.sources ]]; then
      error "/etc/apt/sources.list.d/debian.sources should not exist when using classic sources.list. Please remove it."
      exit 1
    fi
  fi

  # Check to make sure the canonical file exists
  if [[ ! -f "$canonical_file" ]]; then
    error "Canonical APT source file not found: $canonical_file"
    exit 1
  fi

  # Check for non-canonical .list or .sources files in /etc/apt/sources.list.d/
  local offending_files=()
  shopt -s nullglob
  for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    # Only allow the canonical file for this OS
    if $is_deb822; then
      # Allow only the canonical deb822 file for this OS type
      if [[ "$OS_TYPE" == "debian" && "$f" == "/etc/apt/sources.list.d/debian.sources" ]]; then
        continue
      elif [[ "$OS_TYPE" == "ubuntu" && "$f" == "/etc/apt/sources.list.d/ubuntu.sources" ]]; then
        continue
      fi
    fi
    # If we reach here, this file is non-canonical
    offending_files+=("$f")
  done
  shopt -u nullglob
  if [[ ${#offending_files[@]} -gt 0 ]]; then
    error "Non-canonical APT source files found in /etc/apt/sources.list.d/:"
    for f in "${offending_files[@]}"; do
      echo "  - $f"
    done
    step "--------------------------------------------------"
    require_confirm "Review the above files." "Operator did not confirm non-canonical APT sources. Exiting."
  fi

  # For all sources, display file and prompt operator for confirmation
  step "Displaying contents of $canonical_file:\n"
  cat "$canonical_file"
  step "--------------------------------------------------"
  if ! confirm "Is this APT source config correct?"; then
    step "Cool. We'll stop now. Here's the canonical config for $canonical_file:\n"
    canonical_sources
    error "Operator did not confirm deb822 APT sources. Exiting."
    exit 1
  fi

  if ! $is_deb822; then
    # For classic sources.list, compare normalized deb lines to canonical configuration
    local expected_sources
    expected_sources=$(canonical_sources | sed 's/#.*//;s/\\s\\+/ /g' | sort)

    local current_sources
    current_sources=$(grep -E '^\\s*deb ' "$canonical_file" | sed 's/#.*//;s/\\s\\+/ /g' | sort)
    if [[ "$expected_sources" != "$current_sources" ]]; then
      APT_SOURCES_CHANGES_REQUIRED=true
    fi
  fi
}

# Apply approved APT source changes or prompt for manual intervention.
apt_sources_apply() {
  if ! $APT_SOURCES_CHANGES_REQUIRED; then
    step "No changes required to APT sources."
    return 0
  fi

  section "Manual APT Sources Intervention Required"
  error "APT sources do not match the canonical configuration for $OS_TYPE $VERSION_ID ($CODENAME)."

  local canonical_file is_deb822
  get_canonical_file

  # Backup classic sources.list before manual intervention
  if [[ "$canonical_file" == "/etc/apt/sources.list" && -f /etc/apt/sources.list ]]; then
    local backup_file="/etc/apt/sources.list.bak.$(date +%Y%m%d%H%M%S)"
    cp /etc/apt/sources.list "$backup_file"
    BACKUPS+=("$backup_file")
    step "Created backup of /etc/apt/sources.list at $backup_file."
  fi

  step "Double-check to see if you need to manually edit the APT source file.\n"
  echo "Expected canonical contents for $canonical_file:"
  echo
  canonical_sources
  step "--------------------------------------------------"
  require_confirm "Are you sure you want to continue?" "After making the necessary changes, re-run this script. No automatic changes have been made."
}

# Audit RHEL yum/dnf repositories, prompt for confirmation. See FUNCTIONS.md.
rhel_repos_prepare() {
  section "Auditing RHEL Repositories"

  # CentOS 7 EOL: Fix repos to use vault.centos.org
  if [[ "$OS_DISTRO" == "centos" && "$VERSION_MAJOR" -eq 7 ]]; then
    step "CentOS 7 is EOL - checking if vault.centos.org migration is needed ..."
    
    # Check if any repo files point to mirror.centos.org (which no longer works)
    if grep -rlq "mirror.centos.org\|mirrorlist.centos.org" /etc/yum.repos.d/ 2>/dev/null; then
      step "Migrating CentOS 7 repos to vault.centos.org ..."
      
      # Process all .repo files that contain mirror.centos.org references
      for repo_file in /etc/yum.repos.d/*.repo; do
        [[ -f "$repo_file" ]] || continue
        if grep -q "mirror.centos.org\|mirrorlist.centos.org" "$repo_file" 2>/dev/null; then
          sed -i 's/^mirrorlist=/#mirrorlist=/g' "$repo_file"
          sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' "$repo_file"
          step "  Updated: $repo_file"
        fi
      done
      
      step "CentOS 7 repos migrated to vault.centos.org."
    else
      step "CentOS 7 repos already configured for vault or alternate mirror."
    fi
  fi

  step "Listing enabled repositories ..."
  $PKG_MGR repolist enabled

  step "Repository files in /etc/yum.repos.d/:"
  ls -la /etc/yum.repos.d/

  step "--------------------------------------------------"
  require_confirm "Are the enabled repositories correct?" "Operator did not confirm RHEL repositories. Please review /etc/yum.repos.d/ and try again."

  step "RHEL repositories confirmed."
}

# Update package lists and perform system upgrade.
update_packages() {
  section "Updating and Upgrading Packages"

  # Network connectivity check (ICMP first, then HTTP fallback for ICMP-blocked environments)
  step "Checking network connectivity ..."
  local network_ok=false
  
  # Try ICMP ping first
  if ping -c 1 -W 5 1.1.1.1 > /dev/null 2>&1; then
    network_ok=true
  # Fallback: try HTTP HEAD request (works when ICMP is blocked)
  elif command -v curl &> /dev/null && curl -sI --connect-timeout 5 https://deb.debian.org > /dev/null 2>&1; then
    network_ok=true
  elif command -v wget &> /dev/null && wget -q --spider --timeout=5 https://deb.debian.org 2>/dev/null; then
    network_ok=true
  fi
  
  if ! $network_ok; then
    error "Network connectivity check failed (ICMP and HTTP tests failed)."
    error "Please verify network configuration before continuing."
    confirm "Continue anyway?" || exit 1
  else
    step "Network connectivity verified."
  fi

  if [[ "$OS_TYPE" == "rhel" ]]; then
    # RHEL-family: use dnf (RHEL 8+) or yum (CentOS 7)
    step "Cleaning $PKG_MGR cache ..."
    $PKG_MGR clean all

    step "Checking for updates ..."
    # check-update returns 100 if updates are available, 0 if none, 1 on error
    # Must disable both exit-on-error AND the ERR trap (due to set -E inheriting traps)
    set +e
    trap - ERR
    $PKG_MGR check-update
    local check_status=$?
    trap 'error "Fatal error on line $LINENO: $BASH_COMMAND"; exit 1' ERR
    set -e
    if [[ $check_status -eq 1 ]]; then
      error "$PKG_MGR check-update failed."
      exit 1
    elif [[ $check_status -eq 100 ]]; then
      step "Updates are available."
    else
      step "System is up to date."
    fi

    step "Upgrading packages ..."
    if [[ "$PKG_MGR" == "yum" ]]; then
      yum update -y
    else
      dnf upgrade -y
    fi

    step "Removing unused packages ..."
    if [[ "$PKG_MGR" == "yum" ]]; then
      # yum doesn't have autoremove in CentOS 7, use package-cleanup from yum-utils
      if command -v package-cleanup &> /dev/null; then
        package-cleanup --leaves --quiet 2>/dev/null || true
      fi
    else
      dnf autoremove -y
    fi

    step "Package update and upgrade completed successfully."
  else
    # Debian/Ubuntu: use apt-get
    if [[ "$APT_FLAGS" == *"--allow-unauthenticated"* ]]; then
      step "Note: Using --allow-unauthenticated for archived Debian release (expected for archive.debian.org)"
    fi

    apt-get autoremove --purge -y
    apt-get clean
    
    # Clean all apt cache to prevent corruption errors (especially for archived repos)
    step "Cleaning APT cache ..."
    rm -rf /var/lib/apt/lists/*
    mkdir -p /var/lib/apt/lists/partial
    
    # Run apt-get update, retry once if it fails (common with archived repos)
    step "Running apt-get update ..."
    set +e  # Temporarily disable exit-on-error for retry logic
    apt-get update
    local update_status=$?
    set -e  # Re-enable exit-on-error
    
    if [[ $update_status -ne 0 ]]; then
      step "apt-get update failed (exit code: $update_status), cleaning cache and retrying once more ..."
      rm -rf /var/lib/apt/lists/*
      mkdir -p /var/lib/apt/lists/partial
      apt-get clean
      sleep 2  # Brief pause before retry
      apt-get update  # If this fails, the script will exit due to set -e
    fi
    
    apt-get dist-upgrade $APT_FLAGS
    apt-get autoremove --purge $APT_FLAGS
    apt-get autoclean

    step "Package update and upgrade completed successfully."
  fi
}

# Install cloud-init package for template provisioning.
cloud_init_install() {
  section "Installing cloud-init"

  step "Installing cloud-init package ..."
  
  if [[ "$OS_TYPE" == "rhel" ]]; then
    # CentOS 7 requires EPEL for cloud-init
    if [[ "$OS_DISTRO" == "centos" && "$VERSION_MAJOR" -eq 7 ]]; then
      if ! yum repolist enabled | grep -qi epel; then
        step "Enabling EPEL repository for CentOS 7 (required for cloud-init) ..."
        yum install -y epel-release
      fi
    fi
    $PKG_MGR install -y cloud-init
  else
    if [[ "$APT_FLAGS" == *"--allow-unauthenticated"* ]]; then
      step "Note: Using --allow-unauthenticated for archived Debian release"
    fi
    apt-get install $APT_FLAGS cloud-init
  fi

  step "cloud-init installed successfully."
}

# Set system hostname to 'rackmill' and update /etc/hosts.
set_host() {
  step "Setting hostname to 'rackmill' ..."
  if command -v hostnamectl &> /dev/null; then
    hostnamectl set-hostname rackmill
  else
    # Fallback for non-systemd systems (e.g., Ubuntu 14.04 Upstart)
    echo "rackmill" > /etc/hostname
    hostname rackmill
  fi

  step "Updating /etc/hosts to reflect hostname change ..."
  if [[ -f /etc/hosts ]]; then
    # Replace any instance of masterdaweb with rackmill
    sed -i 's/masterdaweb/rackmill/g' /etc/hosts || true
    hostname && getent hosts "$(hostname)"
    step "Displaying contents of /etc/hosts:"
    cat /etc/hosts
    step "--------------------------------------------------"
    require_confirm "Is this /etc/hosts config correct?" "Operator did not confirm /etc/hosts changes. Exiting."
  fi
}

# Set system timezone to Australia/Perth.
set_timezone() {
  step "Setting timezone to Australia/Perth ..."
  if command -v timedatectl &> /dev/null; then
    timedatectl set-timezone Australia/Perth
  else
    ln -sf /usr/share/zoneinfo/Australia/Perth /etc/localtime
    echo "Australia/Perth" > /etc/timezone
  fi
  date
}

# Regenerate SSH host keys and conditionally restart sshd.
regenerate_ssh_keys() {
  step "Regenerating SSH host keys ..."
  rm -f /etc/ssh/ssh_host_*
  ssh-keygen -A
  
  # Restart sshd if systemctl is available and functional
  if command -v systemctl &> /dev/null && systemctl is-system-running &> /dev/null; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  fi
}

# Build cleanup lists and prompt for operator confirmation. See FUNCTIONS.md.
cleanup_prepare() {
  section "Preparing Cleanup Actions"

  step "Scanning filesystem for sensitive data to clean ..."

  # Populate arrays from the defined pattern arrays
  CLEANUP_FILES=("${REMOVE_PATTERNS[@]}")
  CLEANUP_TRUNCATE=("${TRUNCATE_PATTERNS[@]}")

  if [[ ${#CLEANUP_FILES[@]} -gt 0 ]]; then
    step "The following file patterns will be removed:"
    for pattern in "${CLEANUP_FILES[@]}"; do
      echo "  - $pattern"
    done
  fi

  if [[ ${#CLEANUP_TRUNCATE[@]} -gt 0 ]]; then
    step "The following files will be truncated:"
    for pattern in "${CLEANUP_TRUNCATE[@]}"; do
      echo "  - $pattern"
    done
  fi

  # Prompt for confirmation
  step "--------------------------------------------------"
  require_confirm "Do you want to proceed with the cleanup? This is irreversible!" "Cleanup operation cancelled by operator. Exiting."

  step "Operator confirmed cleanup actions."
}

# Apply confirmed cleanup actions.
# Apply confirmed cleanup actions (removes/truncates sensitive files).
cleanup_apply() {
  section "Applying Cleanup Actions"

  # Stop systemd-journald and flush before removing journal files
  # This prevents "Directory not empty" errors from active journal writes
  if command -v systemctl &> /dev/null && systemctl is-active --quiet systemd-journald 2>/dev/null; then
    step "Stopping systemd-journald to allow journal cleanup ..."
    journalctl --rotate 2>/dev/null || true
    journalctl --vacuum-time=1s 2>/dev/null || true
    systemctl stop systemd-journald.socket systemd-journald-dev-log.socket systemd-journald 2>/dev/null || true
    sleep 1
  fi

  # Remove files matching patterns
  if [[ ${#CLEANUP_FILES[@]} -gt 0 ]]; then
    step "Removing files ..."
    for pattern in "${CLEANUP_FILES[@]}"; do
      if compgen -G "$pattern" > /dev/null 2>&1; then
        # shellcheck disable=SC2086
        rm -rf $pattern 2>/dev/null || true
        echo "✅ removed: $pattern"
      else
        echo "🦘 no files found matching $pattern. Skipping."
      fi
    done
  fi

  # Truncate files (clear contents but keep file)
  if [[ ${#CLEANUP_TRUNCATE[@]} -gt 0 ]]; then
    step "Truncating files ..."
    for pattern in "${CLEANUP_TRUNCATE[@]}"; do
      if compgen -G "$pattern" > /dev/null 2>&1; then
        # shellcheck disable=SC2086
        for f in $pattern; do
          if [[ -f "$f" ]]; then
            : > "$f"
            step "Truncated: $f"
          fi
        done
      else
        step "No files found matching $pattern. Skipping."
      fi
    done
  fi

  # Clean cloud-init state for templating
  if command -v cloud-init > /dev/null 2>&1; then
    step "Cleaning cloud-init state ..."
    cloud-init clean --logs
  fi

  step "Cleanup actions completed successfully."
}

# Configure keyboard layout (OS-specific).
configure_keyboard() {
  if [[ "$OS_TYPE" == "rhel" ]]; then
    step "Current keyboard layout:"
    localectl status
    step "Available keyboard layouts can be listed with: localectl list-keymaps"
    read -rp "Enter keyboard layout (e.g., us, uk, de) or press Enter to keep current: " keymap
    if [[ -n "$keymap" ]]; then
      if localectl list-keymaps | grep -qx "$keymap"; then
        localectl set-keymap "$keymap"
        step "Keyboard layout set to $keymap."
      else
        error "Invalid keymap: $keymap. Run 'localectl list-keymaps' to see available options."
        confirm "Continue with current keyboard layout?" || exit 1
        step "Keeping current keyboard layout."
      fi
    else
      step "Keeping current keyboard layout."
    fi
  else
    step "Running keyboard configuration ..."
    dpkg-reconfigure keyboard-configuration
  fi
}

# Configure locale to en_AU.UTF-8 (OS-specific).
configure_locale() {
  step "Setting locale to en_AU.UTF-8 ..."
  if [[ "$OS_TYPE" == "rhel" ]]; then
    if ! locale -a 2>/dev/null | grep -qi "en_AU"; then
      step "Installing Australian English language pack ..."
      if [[ "$PKG_MGR" == "yum" ]]; then
        yum reinstall -y glibc-common || yum install -y glibc-common || true
        localedef -i en_AU -f UTF-8 en_AU.UTF-8 || true
      else
        $PKG_MGR install -y glibc-langpack-en || true
      fi
    fi
    localectl set-locale LANG=en_AU.UTF-8
  else
    if [[ -f /etc/locale.gen ]]; then
      sed -i 's/^# *en_AU.UTF-8/en_AU.UTF-8/' /etc/locale.gen
    fi
    if command -v locale-gen &> /dev/null; then
      locale-gen en_AU.UTF-8
    else
      localedef -i en_AU -f UTF-8 en_AU.UTF-8 || true
    fi
    update-locale LANG=en_AU.UTF-8
  fi
}

# Configure system settings (keyboard, hostname, timezone, locale, SSH keys).
configure_system() {
  section "Configuring System Settings"

  configure_keyboard
  set_host
  set_timezone
  configure_locale
  regenerate_ssh_keys

  step "Configuration complete. Locale changes take effect on next login."
}


# Ensure systemd journal is properly configured (skipped on pre-systemd systems).
journal() {
  section "Ensuring machine-id and systemd journal is properly configured"

  if ! $HAS_SYSTEMD; then
    step "Pre-systemd OS detected. Skipping journal setup."
    return 0
  fi

  step "Setting up machine-id ..."
  systemd-machine-id-setup

  step "Creating journal directories ..."
  mkdir -p /run/log/journal
  mkdir -p /var/log/journal

  step "Restoring permissions with systemd-tmpfiles ..."
  systemd-tmpfiles --create --prefix /var/log/journal
  systemd-tmpfiles --create --prefix /run/log/journal

  step "Verifying journal directories ..."
  ls -ld /var/log/journal
  ls -ld /run/log/journal

  step "Restarting systemd-journald ..."
  systemctl restart systemd-journald

  step "Journal configuration completed."
}

# Display summary of backups created during this run.
report() {
  step "Backups created during this run:"
  if [[ ${#BACKUPS[@]} -eq 0 ]]; then
    echo "  None"
  else
    for backup in "${BACKUPS[@]}"; do
      echo "  - $backup"
    done
  fi
}

# Offer an interactive choice to reboot or shutdown.
post_run_action() {
  section "Nearly done"
  step "Clearing artifacts ..."
  rm -f rackmill.sh .bash_history ~/.bash_history /root/.bash_history /home/*/.bash_history 2>/dev/null || true
  # Prevent bash from saving history on exit
  unset HISTFILE
  export HISTFILE=
  export HISTSIZE=0
  history -c
  sync

  step "Reboot or shutdown"
  read -rp "[r] reboot | [s] shutdown | [*] neither: " choice
  case "$choice" in
    r|R)
      # Use exec to replace the shell process entirely, preventing any history save
      exec reboot
      ;;
    s|S)
      exec shutdown -h now
      ;;
    *)
      echo "Cool."
      ;;
  esac
}

# Main conductor function - orchestrates the full setup flow. See FUNCTIONS.md.
main() {
  setup
  
  # Ensure journal infrastructure is healthy for logging during script execution
  journal

  # OS-specific: repository setup
  if [[ "$OS_TYPE" == "rhel" ]]; then
    rhel_repos_prepare
  else
    apt_sources_prepare
    apt_sources_apply
  fi

  # Common: system configuration
  configure_system

  # Common: package updates and cloud-init
  update_packages
  cloud_init_install

  # Template preparation: wipe SSH keys, logs, machine-id, cloud-init state
  cleanup_prepare
  cleanup_apply
  report
  post_run_action

  # Clear trap on successful completion
  trap - ERR

  step "Rackmill setup completed."
  exit 0
}

# =============================================
# Entry point
# =============================================
main "$@"