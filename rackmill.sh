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

# Set ERR trap globally so it applies to all functions and subshells
trap 'error "Fatal error occurred. Exiting."; exit 1' ERR

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

# Canonical sources generator for this release.
# @see: https://releases.ubuntu.com/ (Ubuntu)
# @see: https://www.debian.org/releases/ (Debian)
# @see: https://archive.debian.org/ (Archived Debian releases)
#
# This function outputs the canonical APT sources for the detected OS and version:
#
# Ubuntu:
#   - For Ubuntu 23.04 and earlier: output classic deb lines (sources.list format)
#   - For Ubuntu 23.10 and newer:  output deb822 format (for /etc/apt/sources.list.d/ubuntu.sources)
#
# Debian:
#   - For Debian 9-10 (archived): uses archive.debian.org (no signed Release files)
#   - For Debian 11: output classic deb lines (sources.list format)
#   - For Debian 12+:  output deb822 format (for /etc/apt/sources.list.d/debian.sources)
#
# Note: Archived Debian releases (9-10) use archive.debian.org which does not have
# signed Release files. APT will show warnings about missing Release files - this is
# expected and normal for archived releases.
#
# The output format must match the canonical file expected by apt_sources_prepare().
#
# Arguments:
#   $1 (optional): OS codename (defaults to $CODENAME)
#   $2 (optional): OS type (defaults to $OS_TYPE)
#
# Outputs:
#   Canonical APT sources in the correct format for the detected OS and version

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
    if [[ "${VERSION_ID:-}" =~ ^23\.10|24\. ]]; then
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

# Ensure preconditions are met and detect OS release.
#
# Verifies the script is running as root, outputs network info, and detects the OS type
# (Ubuntu, Debian, or RHEL-family), version, and codename. Sets global variables OS_TYPE,
# OS_DISTRO, VERSION_ID, VERSION_MAJOR, and CODENAME for use by other functions.
#
# Supported versions:
#   Ubuntu: 14.04+ (Trusty and newer)
#   Debian: 9+ (Stretch and newer)
#   RHEL-family: 8+ (AlmaLinux, Rocky Linux, Oracle Linux, CentOS Stream, CloudLinux, RHEL)
#
# Outputs:
#   Sets OS_TYPE, OS_DISTRO, VERSION_ID, VERSION_MAJOR, CODENAME globals
#   Logs detected OS information via section() and step()
#
# Exit status:
#   0 on success
#   1 if not running as root
#   2 if OS detection fails or unsupported OS/version

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
}


# Audit apt sources to enforce canonical configuration.
#
# This function enforces rules for canonical APT source files for both Ubuntu and Debian:
#
# Ubuntu:
#   - For Ubuntu 23.04 and earlier: /etc/apt/sources.list
#   - For Ubuntu 23.10 and newer:   /etc/apt/sources.list.d/ubuntu.sources (deb822 format)
#
# Debian:
#   - For Debian 9-11: /etc/apt/sources.list
#   - For Debian 12+:  /etc/apt/sources.list.d/debian.sources (deb822 format)
#
# For deb822 format (Ubuntu 23.10+ or Debian 12+):
#   - The canonical source file is /etc/apt/sources.list.d/ubuntu.sources (Ubuntu) or debian.sources (Debian).
#   - /etc/apt/sources.list may exist by default, but should not contain any deb sources.
#   - The script does NOT error if /etc/apt/sources.list exists, but will error if it contains any deb lines.
#   - The script will echo the contents of the canonical file and prompt the operator to review & confirm.
#
# For classic format (Ubuntu 23.04 and earlier, or Debian 9-11):
#   - The canonical source file is /etc/apt/sources.list (classic format).
#   - The script compares the normalized deb lines to the expected canonical configuration.
#
# In all cases:
#   - If any other .list or .sources files are present in /etc/apt/sources.list.d/, 
#       the script will display a list of offending files and prompt the operator 
#       to review & confirm before proceeding. 
#
# Outputs:
#   - For classic sources: sets up canonical sources for comparison and sets APT_SOURCES_CHANGES_REQUIRED=true if the current sources differ from the canonical configuration.
#   - For deb822 sources: displays the file contents and prompts the operator to confirm correctness interactively.
#   - If found, displays a list of offending files and prompt the operator to review & confirm before proceeding.
#   - Logs progress and audit results via step() calls.
#
# Exit status:
#   0 if only the canonical APT source file is present and matches expected configuration, or if no changes are required
#   1 if any non-canonical .list or .sources files are found in /etc/apt/sources.list.d/, or on other audit errors

apt_sources_prepare() {
  section "Auditing APT Sources"

  # Determine canonical file based on OS type and version
  local canonical_file
  local is_deb822=false
  
  if [[ "$OS_TYPE" == "debian" ]]; then
    if [[ "${VERSION_MAJOR}" -ge 12 ]]; then
      canonical_file="/etc/apt/sources.list.d/debian.sources"
      is_deb822=true
    else
      canonical_file="/etc/apt/sources.list"
    fi
  else
    # Ubuntu
    if [[ "${VERSION_ID:-}" =~ ^23\.10|24\. ]]; then
      canonical_file="/etc/apt/sources.list.d/ubuntu.sources"
      is_deb822=true
    else
      canonical_file="/etc/apt/sources.list"
    fi
  fi

  # Enforce canonical file rules
  if $is_deb822; then
    if [[ -f /etc/apt/sources.list ]]; then
      # /etc/apt/sources.list may exist, but must not contain any deb lines
      if grep -qE '^\s*deb ' /etc/apt/sources.list; then
        error "/etc/apt/sources.list contains deb lines but deb822 sources are in use. Please remove or comment out all deb lines."
        exit 1
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
    read -rp "Review the above files. Type 'y' to proceed anyway, anything else to exit: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      error "Operator did not confirm non-canonical APT sources. Exiting."
      exit 1
    fi
  fi

  # For all sources, display file and prompt operator for confirmation
  step "Displaying contents of $canonical_file:\n"
  cat "$canonical_file"
  step "--------------------------------------------------"
  read -rp "Is this APT source config correct? Type 'y' to proceed, anything else to exit: " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then

    step "Cool. We'll stop now. Here's the canonical config for $canonical_file:\n"
    canonical_sources

    error "Operator did not confirm deb822 APT sources. Exiting."
    exit 1
  fi
  APT_SOURCES_CHANGES_REQUIRED=false

  if ! $is_deb822; then
    # For classic sources.list, compare normalized deb lines to canonical configuration
    local expected_sources
    expected_sources=$(canonical_sources | sed 's/#.*//;s/\s\+/ /g' | sort)

    local current_sources
    current_sources=$(grep -E '^\s*deb ' "$canonical_file" | sed 's/#.*//;s/\s\+/ /g' | sort)
    if [[ "$expected_sources" != "$current_sources" ]]; then
      APT_SOURCES_CHANGES_REQUIRED=true
    else
      APT_SOURCES_CHANGES_REQUIRED=false
    fi
  fi
}

# Apply approved changes to apt source files.
#
# If changes to APT sources are required, this function exits after informing
# the operator of the required changes. The operator is expected to manually
# edit the relevant files and re-run the script. No automatic changes are made
# in this case.
#
# If no changes are required, the function continues normally.
#
# Outputs:
#   If changes are required: appends backup paths to BACKUPS array, 
#   prints a message describing the required changes, then exits.
#
# Exit status:
#   0 on success or if no changes required
#   1 if backup creation fails or if changes are required and operator intervention is needed

apt_sources_apply() {
  if $APT_SOURCES_CHANGES_REQUIRED; then
    section "Manual APT Sources Intervention Required"
    error "APT sources do not match the canonical configuration for $OS_TYPE $VERSION_ID ($CODENAME)."
    # Determine canonical file based on OS type and version
    local canonical_file
    if [[ "$OS_TYPE" == "debian" ]]; then
      if [[ "${VERSION_MAJOR}" -ge 12 ]]; then
        canonical_file="/etc/apt/sources.list.d/debian.sources"
      else
        canonical_file="/etc/apt/sources.list"
      fi
    else
      # Ubuntu
      if [[ "${VERSION_ID:-}" =~ ^23\.10|24\. ]]; then
        canonical_file="/etc/apt/sources.list.d/ubuntu.sources"
      else
        canonical_file="/etc/apt/sources.list"
      fi
    fi
    # Always create a backup before requiring manual intervention (only for classic sources.list)
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
    read -rp "Are you sure you want to continue? Type 'y' to proceed, anything else to exit: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      error "After making the necessary changes, re-run this script. No automatic changes have been made."
      exit 1
    fi
  else
    step "No changes required to APT sources."
    return 0
  fi
}

# Audit RHEL-family yum/dnf repositories.
#
# This function displays enabled repositories for RHEL-family systems and prompts
# the operator to confirm they are correct before proceeding.
#
# Supported distributions:
#   - AlmaLinux 8+
#   - Rocky Linux 8+
#   - Oracle Linux 8+
#   - CentOS Stream 8+
#   - CloudLinux 8+
#   - RHEL 8+
#
# Outputs:
#   - Lists all enabled repositories via dnf repolist
#   - Displays repo files in /etc/yum.repos.d/
#   - Prompts operator to confirm repos are correct
#   - Logs progress via step() calls
#
# Exit status:
#   0 if operator confirms repositories are correct
#   1 if operator declines or on error

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
  read -rp "Are the enabled repositories correct? Type 'y' to proceed, anything else to exit: " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    error "Operator did not confirm RHEL repositories. Please review /etc/yum.repos.d/ and try again."
    exit 1
  fi

  step "RHEL repositories confirmed."
}

# Update package lists and perform system upgrade.
#
# For Debian/Ubuntu: Runs apt-get update, dist-upgrade, autoremove, and autoclean.
# For RHEL-family: Runs dnf clean, check-update, upgrade, and autoremove.
#
# For archived Debian releases (9-10), adds --allow-unauthenticated flag
# since archive.debian.org repositories don't have valid GPG signatures.
#
# Outputs:
#   Standard package manager console output
#   Progress messages via section() and step() calls
#
# Exit status:
#   0 on success
#   Non-zero if package operations fail

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
    read -rp "Continue anyway? Type 'y' to proceed, anything else to exit: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      exit 1
    fi
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
    trap 'error "Fatal error occurred. Exiting."; exit 1' ERR
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
    # Determine if we need --allow-unauthenticated for archived releases
    local apt_flags="-y"
    if [[ "$OS_TYPE" == "debian" && "${VERSION_MAJOR}" -le 10 ]]; then
      apt_flags="-y --allow-unauthenticated"
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
    
    apt-get dist-upgrade $apt_flags
    apt-get autoremove --purge $apt_flags
    apt-get autoclean

    step "Package update and upgrade completed successfully."
  fi
}

# Install cloud-init package.
#
# Installs cloud-init on all systems for template provisioning.
# For archived Debian releases (9-10), uses --allow-unauthenticated flag.
# For RHEL-family, uses dnf.
#
# Outputs:
#   Standard package manager console output
#   Progress messages via section() and step() calls
#
# Exit status:
#   0 on success
#   Non-zero if package install fails (script will exit)

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
    # Determine if we need --allow-unauthenticated for archived releases
    local apt_flags="-y"
    if [[ "$OS_TYPE" == "debian" && "${VERSION_MAJOR}" -le 10 ]]; then
      apt_flags="-y --allow-unauthenticated"
      step "Note: Using --allow-unauthenticated for archived Debian release"
    fi
    apt-get install $apt_flags cloud-init
  fi

  step "cloud-init installed successfully."
}

# Set system hostname.
#
# Sets hostname to "rackmill".
# Also updates /etc/hosts to change masterdaweb to rackmill.
# Outputs the contents of /etc/hosts and prompts the operator to confirm it's okay.
#
# Outputs:
#   Configuration changes via step() calls
#
# Exit status:
#   0 on success
#   Non-zero if critical configuration fails

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
    read -rp "Is this /etc/hosts config correct? Type 'y' to proceed, anything else to exit: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      error "Operator did not confirm /etc/hosts changes. Exiting."
      exit 1
    fi
  fi
}

# Build and present cleanup actions for operator review.
#
# Scans the filesystem for sensitive data that should be removed
# from template images (SSH keys, history, machine IDs, etc).
# Presents a dry-run summary and prompts for confirmation.
# IMPORTANT: This function only prepares the cleanup list and
# seeks confirmation. No files are modified or deleted here.
#
# Outputs:
#   Populates CLEANUP_FILES and CLEANUP_TRUNCATE arrays
#   Dry-run summary of files to be removed/truncated
#   Interactive prompt for operator confirmation
#
# Exit status:
#   0 if operator approves cleanup
#   1 if operator declines cleanup

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
  read -rp "Do you want to proceed with the cleanup? This is irreversible! Type 'y' to proceed, anything else to exit: " confirm
  if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    error "Cleanup operation cancelled by operator. Exiting."
    exit 1
  fi

  step "Operator confirmed cleanup actions."
}

# Apply confirmed cleanup actions.
#
# Removes or truncates files identified by cleanup_prepare().
# IRREVERSIBLE: Permanently deletes sensitive data including
# SSH keys, shell history, and user data. Only runs after
# explicit operator confirmation from cleanup_prepare().
#
# Outputs:
#   Progress messages for each cleanup action
#   Verification results via step() calls
#
# Exit status:
#   0 on successful cleanup
#   1 if any cleanup operations fail

cleanup_apply() {
  section "Applying Cleanup Actions"

  # Remove files matching patterns
  if [[ ${#CLEANUP_FILES[@]} -gt 0 ]]; then
    step "Removing files ..."
    for pattern in "${CLEANUP_FILES[@]}"; do
      if compgen -G "$pattern" > /dev/null 2>&1; then
        # shellcheck disable=SC2086
        rm -rf $pattern
        step "Removed: $pattern"
      else
        step "No files found matching $pattern. Skipping."
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

# Configure system locale, timezone, hostname, and keyboard layout.
#
# This function performs the following system configuration steps:
#   - Sets timezone to Australia/Perth
#   - Sets locale to en_AU.UTF-8
#   - Regenerates SSH host keys
#   - Runs keyboard configuration
#
# For Debian/Ubuntu: Uses dpkg-reconfigure for keyboard and openssh-server.
# For RHEL-family: Uses localectl for keyboard and ssh-keygen for host keys.
#
# Note: Changes to hostname, locale, and keyboard may require session restart to take full effect.
#
# Outputs:
#   Configuration changes via step() calls
#   Current locale and timezone status
#   Keyboard configuration prompt
#   Reminder about session restart requirement
#
# Exit status:
#   0 on success
#   Non-zero if critical configuration fails

configure() {
  section "Configuring System Settings"

  if [[ "$OS_TYPE" == "rhel" ]]; then
    # RHEL-family configuration
    step "Current keyboard layout:"
    localectl status
    
    step "Available keyboard layouts can be listed with: localectl list-keymaps"
    read -rp "Enter keyboard layout (e.g., us, uk, de) or press Enter to keep current: " keymap
    if [[ -n "$keymap" ]]; then
      # Validate keymap exists before applying
      if localectl list-keymaps | grep -qx "$keymap"; then
        localectl set-keymap "$keymap"
        step "Keyboard layout set to $keymap."
      else
        error "Invalid keymap: $keymap. Run 'localectl list-keymaps' to see available options."
        read -rp "Continue with current keyboard layout? Type 'y' to continue, anything else to exit: " cont
        if [[ "$cont" != "y" && "$cont" != "Y" ]]; then
          exit 1
        fi
        step "Keeping current keyboard layout."
      fi
    else
      step "Keeping current keyboard layout."
    fi

    # Set hostname
    set_host

    step "Setting timezone to Australia/Perth ..."
    timedatectl set-timezone Australia/Perth
    date

    step "Setting locale to en_AU.UTF-8 ..."
    # Install langpacks if needed
    if ! locale -a 2>/dev/null | grep -qi "en_AU"; then
      step "Installing Australian English language pack ..."
      if [[ "$PKG_MGR" == "yum" ]]; then
        # CentOS 7 uses different locale handling
        yum reinstall -y glibc-common || yum install -y glibc-common || true
        localedef -i en_AU -f UTF-8 en_AU.UTF-8 || true
      else
        $PKG_MGR install -y glibc-langpack-en || true
      fi
    fi
    localectl set-locale LANG=en_AU.UTF-8

    step "Regenerating SSH host keys ..."
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -A
    systemctl restart sshd

  else
    # Debian/Ubuntu configuration
    step "Running keyboard configuration ..."
    dpkg-reconfigure keyboard-configuration

    # Set hostname to "rackmill" and update /etc/hosts
    set_host

    step "Setting timezone to Australia/Perth ..."
    if command -v timedatectl &> /dev/null; then
      timedatectl set-timezone Australia/Perth
    else
      # Fallback for non-systemd systems (e.g., Ubuntu 14.04 Upstart)
      ln -sf /usr/share/zoneinfo/Australia/Perth /etc/localtime
      echo "Australia/Perth" > /etc/timezone
    fi
    date # show current date/time for verification

    step "Setting locale to en_AU.UTF-8 ..."
    # Ensure en_AU.UTF-8 is uncommented in /etc/locale.gen (Debian requirement)
    if [[ -f /etc/locale.gen ]]; then
      sed -i 's/^# *en_AU.UTF-8/en_AU.UTF-8/' /etc/locale.gen
    fi
    if command -v locale-gen &> /dev/null; then
      locale-gen en_AU.UTF-8
    else
      # Fallback for minimal systems without locale-gen
      localedef -i en_AU -f UTF-8 en_AU.UTF-8 || true
    fi
    update-locale LANG=en_AU.UTF-8

    step "Regenerating SSH host keys ..."
    rm -f /etc/ssh/ssh_host_*
    if dpkg -l openssh-server &> /dev/null; then
      dpkg-reconfigure openssh-server
    else
      # Fallback if openssh-server not installed via dpkg (minimal image)
      ssh-keygen -A
    fi
  fi

  step "Configuration changes applied. Locale and hostname won't take effect until the next session restart."
}


# Ensure systemd journal directory exists and is properly configured (systemd-based systems only).
#
# This function runs on systemd-based systems:
#   - Ubuntu 15.04 and newer (systemd-based)
#   - Debian 8 (Jessie) and newer (systemd-based)
#
# It creates /run/log/journal if missing, restores correct permissions using systemd-tmpfiles,
# and restarts systemd-journald. This prevents errors like "Failed to open runtime journal"
# on boot, especially in cloned or templated VMs.
#
# On older versions (Ubuntu 14.04 Upstart-based, or Debian 7 and older), this function is skipped.
#
# Outputs:
#   Logs progress via section() and step() calls
#   Displays any errors encountered
#
# Exit status:
#   0 on success or if skipped due to unsupported version
#   Non-zero if any command fails on supported versions

journal() {
  section "Ensuring machine-id and systemd journal is properly configured"

  # Only run on systemd-based systems
  if [[ -z "$VERSION_ID" || -z "$OS_TYPE" ]]; then
    error "VERSION_ID or OS_TYPE not set. Run setup() first. Skipping journal setup."
    return 0
  fi
  
  local major_version="${VERSION_ID%%.*}"
  local skip_journal=false
  
  if [[ "$OS_TYPE" == "ubuntu" ]]; then
    if [[ "$major_version" -lt 15 ]]; then
      step "Ubuntu $VERSION_ID detected (Upstart-based, no systemd). Skipping journal setup."
      skip_journal=true
    fi
  elif [[ "$OS_TYPE" == "debian" ]]; then
    if [[ "$major_version" -lt 8 ]]; then
      step "Debian $VERSION_ID detected (no systemd). Skipping journal setup."
      skip_journal=true
    fi
  fi
  # RHEL 8+ always has systemd, no skip needed
  
  if $skip_journal; then
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

# Generate final summary and recovery instructions.
#
# Provides a concise summary of all actions performed, lists
# created backups, and suggests post-run verification steps.
# Includes recovery hints if any issues were detected.
#
# Outputs:
#   Summary of backups created (from BACKUPS array)
#
# Exit status:
#   0 always

report() {
  section "Final Report"

  step "Backups created during this run:"
  if [[ ${#BACKUPS[@]} -eq 0 ]]; then
    echo "  None"
  else
    for backup in "${BACKUPS[@]}"; do
      echo "  - $backup"
    done
  fi
}

# Offer an interactive choice to reboot or shutdown after cleaning history.
#
# Note: history -c only works in the current shell, not from a script subshell.
# The only reliable way to clear history is to:
#   1. Delete ~/.bash_history
#   2. Kill the parent shell with SIGKILL (prevents it from writing in-memory history)
#   3. Immediately reboot/shutdown
post_run_action() {
  # Skip if stdin is not a TTY (non-interactive run)
  if [[ ! -t 0 ]]; then
    step "Reminder: Run the following command before finalizing the image:"
    step "(Running the "exec" command prevents in-memory history from being saved.)"
    echo "rm -f rackmill.sh ~/.bash_history; exec reboot"
    return
  fi

  read -rp "Clean up and power off? [r] = Reboot, [s] = Shutdown, anything else = Skip " choice
  case "$choice" in
    r|R)
      step "Clearing artifacts and rebooting ..."
      rm -f rackmill.sh .bash_history ~/.bash_history
      # Running the "exec" command prevents in-memory history from being saved."
      exec reboot
      ;;
    s|S)
      step "Clearing artifacts and shutting down ..."
      rm -f rackmill.sh .bash_history ~/.bash_history
      # Running the "exec" command prevents in-memory history from being saved."
      exec shutdown -h now
      ;;
    *)
      step "Skipped. (The 'exec' command replaces your shell, so history can't be saved.)"
      echo "rm -f rackmill.sh ~/.bash_history; exec reboot"
      echo "rm -f rackmill.sh ~/.bash_history; exec shutdown -h now"
      ;;
  esac
}

# Main conductor function that orchestrates the setup process.
#
# Calls all functions in the prescribed order, manages error
# handling and shell state restoration via traps. Ensures
# predictable flow and clear error messages on failure.
#
# Outputs:
#   All output from called functions
#   Fatal error messages on unexpected failures
#
# Returns:
#   0 on successful completion
#   Non-zero exit code on any fatal error

main() {
  # Trap to catch errors and report
  trap 'error "Fatal error occurred. Exiting." ; exit 1' ERR

  setup
  
  # Route to appropriate package management based on OS type
  if [[ "$OS_TYPE" == "rhel" ]]; then
    rhel_repos_prepare
    update_packages
  else
    apt_sources_prepare
    apt_sources_apply
    update_packages
  fi
  
  cloud_init_install
  cleanup_prepare
  cleanup_apply
  configure
  journal
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