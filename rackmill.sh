#!/usr/bin/env bash
set -eEuo pipefail

# =============================================
# Rackmill Ubuntu/Debian Setup Script
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
OS_TYPE=""          # "ubuntu" or "debian"
VERSION_ID=""
VERSION_MAJOR=""
CODENAME=""

# Decision flags
APT_SOURCES_CHANGES_REQUIRED=false

# File patterns for cleanup (used by cleanup_prepare and cleanup_apply)
PATTERNS=(
  # Machine identifiers - should be cleared in templates
  "/etc/machine-id"                # truncate: ensures unique machine id per clone
  "/var/lib/dbus/machine-id"       # truncate: dbus machine id (may duplicate /etc)
  "/var/lib/systemd/machine-id"    # truncate: systemd machine id (some systems)

  # System randomness/state - clear so guests regenerate
  "/var/lib/systemd/random-seed"   # remove: avoid reusing VM randomness across images

  # SSH host keys - always remove and regenerate on first boot
  "/etc/ssh/ssh_host_*"            # remove files matching host key prefixes

  # Root-specific files
  "/root/.ssh/authorized_keys"     # remove: prevent baked-in root SSH keys
  "/root/.wget-hsts"               # remove: wget HSTS cache
  "/root/.Xauthority"              # remove: X auth tokens for root
  "/root/.bash_history"            # remove: root shell history
  "/root/.cache"                   # remove directory: caches
  "/root/.nano"                    # remove editor state
  "/root/snap"                     # remove: Snap user data for root
  "/root/.gnupg"                   # remove: root GPG keyrings
  "/root/.viminfo"                 # remove: root Vim editor history

  # Per-user files under /home
  "/home/*/.ssh/authorized_keys"   # remove: user SSH authorized keys
  "/home/*/.wget-hsts"             # remove: per-user wget HSTS
  "/home/*/.Xauthority"            # remove: per-user X auth tokens
  "/home/*/.bash_history"          # remove: per-user shell history
  "/home/*/snap"                   # remove: Snap user data for all users
  "/home/*/.gnupg"                 # remove: per-user GPG keyrings
  "/home/*/.viminfo"               # remove: per-user Vim editor history

  # Temp space
  "/tmp/*"                         # remove: user/system temp files (entries under /tmp)

  # All system logs - remove all logs for a clean template
  "/var/log/*"                     # remove: all system logs

  # All runtime logs - remove all runtime logs for a clean template
  "/run/log/*"                     # remove: all runtime logs
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
# (Ubuntu or Debian), version, and codename. Sets global variables OS_TYPE, VERSION_ID,
# VERSION_MAJOR, and CODENAME for use by other functions.
#
# Supported versions:
#   Ubuntu: 14.04+ (Trusty and newer)
#   Debian: 9+ (Stretch and newer)
#
# Outputs:
#   Sets OS_TYPE, VERSION_ID, VERSION_MAJOR, CODENAME globals
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
    # exit 1
  fi
  step "Confirmed running as root."

  # Display network interfaces and routes for operator visibility
  step "Displaying network interfaces:"
  ip link show
  ip route show
  ip addr show
  cat /etc/resolv.conf || true
  cat /etc/network/interfaces || true

  # Detect OS version and codename
  section "Detecting OS version ... "
  cat /etc/os-release
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    
    # Detect OS type
    OS_TYPE="${ID:-}"
    if [[ "$OS_TYPE" != "ubuntu" && "$OS_TYPE" != "debian" ]]; then
      error "Unsupported OS detected: $OS_TYPE. This script supports Ubuntu and Debian only. Exiting."
      exit 2
    fi
    
    VERSION_ID="${VERSION_ID:-}"
    
    # Extract codename based on OS type
    if [[ "$OS_TYPE" == "ubuntu" ]]; then
      # For older Ubuntu (like 14.04), UBUNTU_CODENAME may not exist.
      # Try to extract codename from VERSION or PRETTY_NAME if UBUNTU_CODENAME is empty.
      CODENAME="${UBUNTU_CODENAME:-}"
      if [[ -z "$CODENAME" ]]; then
        # Try to extract from VERSION or PRETTY_NAME
        if [[ -n "${VERSION:-}" ]]; then
          CODENAME="$(echo "$VERSION" | grep -oP '(?<=\()[^)]+' | awk '{print tolower($1)}')"
        elif [[ -n "${PRETTY_NAME:-}" ]]; then
          CODENAME="$(echo "$PRETTY_NAME" | grep -oP '(?<=\()[^)]+' | awk '{print tolower($1)}')"
        fi
      fi
    elif [[ "$OS_TYPE" == "debian" ]]; then
      # Debian uses VERSION_CODENAME
      CODENAME="${VERSION_CODENAME:-}"
      if [[ -z "$CODENAME" ]]; then
        # Try to extract from VERSION field as fallback
        if [[ -n "${VERSION:-}" ]]; then
          CODENAME="$(echo "$VERSION" | grep -oP '(?<=\()[^)]+' | awk '{print tolower($1)}')"
        fi
      fi
    fi
    
    if [[ -z "$VERSION_ID" || -z "$CODENAME" ]]; then
      error "Failed to detect OS version or codename. Exiting."
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
    if [[ "$confirm" != "y" ]]; then
      error "Operator did not confirm non-canonical APT sources. Exiting."
      exit 1
    fi
  fi

  # For all sources, display file and prompt operator for confirmation
  step "Displaying contents of $canonical_file:\n"
  cat "$canonical_file"
  step "--------------------------------------------------"
  read -rp "Is this APT source config correct? Type 'y' to proceed, anything else to exit: " confirm
  if [[ "$confirm" != "y" ]]; then

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
    if [[ "$confirm" != "y" ]]; then
      error "After making the necessary changes, re-run this script. No automatic changes have been made."
      exit 1
    fi
  else
    step "No changes required to APT sources."
    return 0
  fi
}

# Update package lists and perform system upgrade.
#
# Runs apt-get update, dist-upgrade, autoremove, and autoclean.
# Performs basic smoke checks to verify package system health.
# Clears stale indices before updating.
#
# For archived Debian releases (9-10), adds --allow-unauthenticated flag
# since archive.debian.org repositories don't have valid GPG signatures.
#
# Outputs:
#   Standard apt-get console output
#   Progress messages via section() and step() calls
#
# Exit status:
#   0 on success
#   Non-zero if apt operations fail

aptdate() {
  section "Updating and Upgrading Packages"

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
}

# Install cloud-init package.
#
# Installs cloud-init on all Ubuntu and Debian systems for template provisioning.
# For archived Debian releases (9-10), uses --allow-unauthenticated flag.
#
# Outputs:
#   Standard apt-get console output
#   Progress messages via section() and step() calls
#
# Exit status:
#   0 on success
#   Non-zero if apt-get install fails (script will exit)

cloud_init_install() {
  section "Installing cloud-init"

  # Determine if we need --allow-unauthenticated for archived releases
  local apt_flags="-y"
  if [[ "$OS_TYPE" == "debian" && "${VERSION_MAJOR}" -le 10 ]]; then
    apt_flags="-y --allow-unauthenticated"
    step "Note: Using --allow-unauthenticated for archived Debian release"
  fi

  step "Installing cloud-init package ..."
  apt-get install $apt_flags cloud-init

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
  hostnamectl set-hostname rackmill

  step "Updating /etc/hosts to reflect hostname change ..."
  if [[ -f /etc/hosts ]]; then
    # Replace any instance of masterdaweb with rackmill
    sed -i 's/masterdaweb/rackmill/g' /etc/hosts || true
    hostname && getent hosts "$(hostname)"
    step "Displaying contents of /etc/hosts:"
    cat /etc/hosts
    step "--------------------------------------------------"
    read -rp "Is this /etc/hosts config correct? Type 'y' to proceed, anything else to exit: " confirm
    if [[ "$confirm" != "y" ]]; then
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

  # Example logic to populate CLEANUP_FILES and CLEANUP_TRUNCATE
  for pattern in "${PATTERNS[@]}"; do
    if [[ "$pattern" == *"truncate"* ]]; then
      CLEANUP_TRUNCATE+=("${pattern% *}")
    else
      CLEANUP_FILES+=("${pattern% *}")
    fi
  done

  if [[ ${#CLEANUP_FILES[@]} > 0 ]]; then
    step "The following files will be removed:"
    for file in "${CLEANUP_FILES[@]}"; do
      echo "  - $file"
    done
  fi

  if [[ ${#CLEANUP_TRUNCATE[@]} > 0 ]]; then
    step "The following files will be truncated:"
    for file in "${CLEANUP_TRUNCATE[@]}"; do
      echo "  - $file"
    done
  fi

  # Prompt for confirmation
  step "--------------------------------------------------"
  read -rp "Do you want to proceed with the cleanup? This is irreversible! Type 'y' to proceed, anything else to exit: " confirm
  if [[ "$confirm" != "y" ]]; then
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

  # Remove files
  if [[ ${#CLEANUP_FILES[@]} > 0 ]]; then
    step "Removing files ..."
    for file in "${CLEANUP_FILES[@]}"; do
      if compgen -G "$file" > /dev/null; then
        rm -rf $file
      else
        step "No files found matching $file. Skipping."
      fi
    done
  fi

  # Truncate files
  if [[ ${#CLEANUP_TRUNCATE[@]} > 0 ]]; then
    step "Truncating files ..."
    for file in "${CLEANUP_TRUNCATE[@]}"; do
      if compgen -G "$file" > /dev/null; then
        for f in $file; do
          echo " : > \"$f\""
        done
      else
        step "No files found matching $file. Skipping."
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
#   - Runs keyboard configuration (dpkg-reconfigure keyboard-configuration)
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

  step "Running keyboard configuration ..."
  dpkg-reconfigure keyboard-configuration

  # Set hostname to "rackmill" and update /etc/hosts
  set_host

  step "Setting timezone to Australia/Perth ..."
  timedatectl set-timezone Australia/Perth
  date # show current date/time for verification

  step "Setting locale to en_AU.UTF-8 ..."
  # Ensure en_AU.UTF-8 is uncommented in /etc/locale.gen (Debian requirement)
  if [[ -f /etc/locale.gen ]]; then
    sed -i 's/^# *en_AU.UTF-8/en_AU.UTF-8/' /etc/locale.gen
  fi
  locale-gen en_AU.UTF-8
  update-locale LANG=en_AU.UTF-8

  step "Regenerating SSH host keys ..."
  rm -f /etc/ssh/ssh_host_*
  dpkg-reconfigure openssh-server

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

  step "Reminder: For best security, run \`rm rackmill.sh .bash_history; history -c;\` in your interactive shell."
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
  apt_sources_prepare
  apt_sources_apply
  aptdate
  cloud_init_install
  cleanup_prepare
  cleanup_apply
  configure
  journal
  report

  # Clear trap on successful completion
  trap - ERR

  step "Rackmill setup completed."
  exit 0
}

# =============================================
# Entry point
# =============================================
main "$@"