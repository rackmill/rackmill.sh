# Rackmill Script Function Reference

This document contains detailed documentation for all functions in `rackmill.sh`.

## Table of Contents

- [Logging Functions](#logging-functions)
- [OS Detection](#os-detection)
- [APT Sources Management](#apt-sources-management)
- [RHEL Repository Management](#rhel-repository-management)
- [Package Management](#package-management)
- [System Configuration](#system-configuration)
- [Cleanup Functions](#cleanup-functions)
- [Journal Management](#journal-management)
- [Main Orchestration](#main-orchestration)

---

## Logging Functions

### `section()`
Prints a section header in cyan.

### `step()`
Prints a step message in green.

### `error()`
Prints an error message in red.

---

## OS Detection

### `setup()`

Ensures preconditions are met and detects OS release.

Verifies the script is running as root, outputs network info, and detects the OS type (Ubuntu, Debian, or RHEL-family), version, and codename.

**Sets global variables:**
- `OS_TYPE` - "ubuntu", "debian", or "rhel"
- `OS_DISTRO` - specific distro: "ubuntu", "debian", "almalinux", "rocky", "ol", "centos", "cloudlinux", "rhel"
- `VERSION_ID` - full version string
- `VERSION_MAJOR` - major version number
- `CODENAME` - release codename
- `PKG_MGR` - "apt" for Debian/Ubuntu, "dnf" for RHEL 8+, "yum" for CentOS 7

**Supported versions:**
- Ubuntu: 14.04+ (Trusty and newer)
- Debian: 9+ (Stretch and newer)
- RHEL-family: 8+ (AlmaLinux, Rocky Linux, Oracle Linux, CentOS Stream, CloudLinux, RHEL)

**Exit status:**
- 0 on success
- 1 if not running as root
- 2 if OS detection fails or unsupported OS/version

---

## APT Sources Management

### `canonical_sources()`

Outputs the canonical APT sources for the detected OS and version.

**Ubuntu:**
- For Ubuntu 23.04 and earlier: output classic deb lines (sources.list format)
- For Ubuntu 23.10 and newer: output deb822 format (for /etc/apt/sources.list.d/ubuntu.sources)

**Debian:**
- For Debian 9-10 (archived): uses archive.debian.org (no signed Release files)
- For Debian 11: output classic deb lines (sources.list format)
- For Debian 12+: output deb822 format (for /etc/apt/sources.list.d/debian.sources)

**Note:** Archived Debian releases (9-10) use archive.debian.org which does not have signed Release files. APT will show warnings about missing Release files - this is expected and normal for archived releases.

**Arguments:**
- `$1` (optional): OS codename (defaults to `$CODENAME`)
- `$2` (optional): OS type (defaults to `$OS_TYPE`)

**References:**
- https://releases.ubuntu.com/ (Ubuntu)
- https://www.debian.org/releases/ (Debian)
- https://archive.debian.org/ (Archived Debian releases)

### `apt_sources_prepare()`

Audits apt sources to enforce canonical configuration.

**For deb822 format (Ubuntu 23.10+ or Debian 12+):**
- The canonical source file is `/etc/apt/sources.list.d/ubuntu.sources` (Ubuntu) or `debian.sources` (Debian)
- `/etc/apt/sources.list` may exist by default, but should not contain any deb sources
- The script does NOT error if `/etc/apt/sources.list` exists, but will error if it contains any deb lines
- Displays the canonical file contents and prompts the operator to review & confirm

**For classic format (Ubuntu 23.04 and earlier, or Debian 9-11):**
- The canonical source file is `/etc/apt/sources.list`
- Compares the normalized deb lines to the expected canonical configuration

**In all cases:**
- If any other `.list` or `.sources` files are present in `/etc/apt/sources.list.d/`, displays a list of offending files and prompts the operator to review & confirm before proceeding

**Sets:** `APT_SOURCES_CHANGES_REQUIRED=true` if the current sources differ from canonical configuration

**Exit status:**
- 0 if canonical APT source file is present and matches expected configuration
- 1 if any non-canonical files are found or on other audit errors

### `apt_sources_apply()`

Applies approved changes to apt source files.

If changes to APT sources are required, this function exits after informing the operator of the required changes. The operator is expected to manually edit the relevant files and re-run the script. No automatic changes are made in this case.

**Exit status:**
- 0 on success or if no changes required
- 1 if backup creation fails or if changes are required and operator intervention is needed

---

## RHEL Repository Management

### `rhel_repos_prepare()`

Audits RHEL-family yum/dnf repositories.

Displays enabled repositories for RHEL-family systems and prompts the operator to confirm they are correct before proceeding.

**Supported distributions:**
- AlmaLinux 8+
- Rocky Linux 8+
- Oracle Linux 8+
- CentOS Stream 8+
- CloudLinux 8+
- RHEL 8+

**Special handling:**
- CentOS 7 EOL: Automatically migrates repos from mirror.centos.org to vault.centos.org

**Exit status:**
- 0 if operator confirms repositories are correct
- 1 if operator declines or on error

---

## Package Management

### `update_packages()`

Updates package lists and performs system upgrade.

**For Debian/Ubuntu:** Runs `apt-get update`, `dist-upgrade`, `autoremove`, and `autoclean`.

**For RHEL-family:** Runs `dnf clean`, `check-update`, `upgrade`, and `autoremove`.

**Special handling:**
- For archived Debian releases (9-10), adds `--allow-unauthenticated` flag since archive.debian.org repositories don't have valid GPG signatures
- Network connectivity check with ICMP and HTTP fallback

**Exit status:**
- 0 on success
- Non-zero if package operations fail

### `cloud_init_install()`

Installs cloud-init package for template provisioning.

**Special handling:**
- For archived Debian releases (9-10), uses `--allow-unauthenticated` flag
- CentOS 7 requires EPEL for cloud-init

**Exit status:**
- 0 on success
- Non-zero if package install fails

---

## System Configuration

### `set_host()`

Sets system hostname to "rackmill".

Also updates `/etc/hosts` to change masterdaweb to rackmill. Outputs the contents of `/etc/hosts` and prompts the operator to confirm.

### `set_timezone()`

Sets system timezone to Australia/Perth.

Uses `timedatectl` if available, otherwise falls back to symlink method for older systems without systemd.

### `regenerate_ssh_keys()`

Regenerates SSH host keys and restarts sshd.

Removes existing SSH host keys and generates new ones using `ssh-keygen -A`. Attempts to restart sshd if systemctl is available and functional.

### `configure_rhel()`

Configures system settings for RHEL-family systems.

- Keyboard layout configuration via `localectl`
- Hostname and timezone setup
- Locale configuration (en_AU.UTF-8)
- SSH key regeneration

### `configure_debian()`

Configures system settings for Debian/Ubuntu systems.

- Keyboard configuration via `dpkg-reconfigure keyboard-configuration`
- Hostname and timezone setup
- Locale configuration (en_AU.UTF-8)
- SSH key regeneration

---

## Cleanup Functions

### `cleanup_prepare()`

Builds and presents cleanup actions for operator review.

Scans the filesystem for sensitive data that should be removed from template images (SSH keys, history, machine IDs, etc). Presents a dry-run summary and prompts for confirmation.

**IMPORTANT:** This function only prepares the cleanup list and seeks confirmation. No files are modified or deleted here.

**Populates:** `CLEANUP_FILES` and `CLEANUP_TRUNCATE` arrays

**Exit status:**
- 0 if operator approves cleanup
- 1 if operator declines cleanup

### `cleanup_apply()`

Applies confirmed cleanup actions.

**IRREVERSIBLE:** Permanently deletes sensitive data including SSH keys, shell history, and user data. Only runs after explicit operator confirmation from `cleanup_prepare()`.

**Actions:**
- Stops systemd-journald to allow journal cleanup
- Removes files matching patterns in `CLEANUP_FILES`
- Truncates files matching patterns in `CLEANUP_TRUNCATE`
- Cleans cloud-init state

**Exit status:**
- 0 on successful cleanup
- 1 if any cleanup operations fail

---

## Journal Management

### `journal()`

Ensures systemd journal directory exists and is properly configured.

**Runs on systemd-based systems:**
- Ubuntu 15.04 and newer
- Debian 8 (Jessie) and newer
- RHEL 8+

Creates `/run/log/journal` if missing, restores correct permissions using `systemd-tmpfiles`, and restarts systemd-journald. This prevents errors like "Failed to open runtime journal" on boot, especially in cloned or templated VMs.

**Skipped on:**
- Ubuntu 14.04 (Upstart-based)
- Debian 7 and older

---

## Main Orchestration

### `report()`

Generates final summary showing backups created during the run.

### `post_run_action()`

Offers an interactive choice to reboot or shutdown.

Clears artifacts (history files, script itself) and prevents bash from saving history on exit using `exec` to replace the shell process.

### `main()`

Main conductor function that orchestrates the setup process.

**Execution order:**
1. `setup()` - Detect OS type and version
2. `journal()` - Ensure systemd journal is healthy
3. `*_repos_prepare()` - Audit package repositories
4. `configure_rhel/debian()` - Set timezone, locale, hostname, keyboard, regenerate SSH keys
5. `update_packages()` - Update and upgrade system packages
6. `cloud_init_install()` - Install cloud-init for template provisioning
7. `cleanup_prepare/apply()` - Wipe SSH keys, logs, machine-id for clean template
8. `report()` - Show backups created
9. `post_run_action()` - Offer reboot/shutdown

**Returns:**
- 0 on successful completion
- Non-zero exit code on any fatal error
