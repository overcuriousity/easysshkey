#!/usr/bin/env bash

# SSH Key Management Script
# Version: 2.0
#
# This script provides a comprehensive set of tools for managing SSH keys and configurations.
# It allows users to generate new SSH key pairs, import existing keys, configure remote hosts,
# and perform local SSH security checks.
#
# Features:
# - Generate new SSH key pairs with various encryption types
# - Import existing private keys and configure them for use
# - Copy public keys to remote hosts
# - Perform local SSH security checks and fix common issues
# - Backup existing SSH configurations before making changes
# - Dry-run mode to preview changes without applying them
# - SSH agent management
# - Per-host SSH configuration
# - Key rotation and expiration tracking
# - Connection testing and diagnostics
# - Jump host configuration
# - Known hosts management
#
# Usage:
#   sshkeymanager [options]
#
# Options:
#   -b, --backup     Create a backup of SSH configurations before making changes
#   -d, --dry-run    Run in dry-run mode (show changes without applying them)
#   -h, --help       Display this help message
#   -o, --override-security    Overrides mandatory key passphrase for permissive keys
#   -a, --audit      Show audit log of key operations
#
# Requirements:
# - Bash 4.0 or later
# - OpenSSH client
# - sudo privileges (for some operations)
#
# Note: This script modifies system files and SSH configurations. Use with caution.

# Treat unset variables as an error and propagate failures through pipelines.
#
# NOTE: `set -e` is deliberately NOT enabled. This is a long-lived interactive
# menu; under `set -e` a single non-zero return (a failed ssh, a grep that
# matches nothing) would tear down the whole session mid-operation. Failures
# are handled explicitly at each call site instead.
set -uo pipefail
# Uncomment for debugging
#set -x

# --- Configurable via the settings menu --------------------------------------
sshd_config="/etc/ssh/sshd_config"
# No trailing slash. Paths are always composed as "$ssh_keys_location/<name>".
ssh_keys_location="$HOME/.ssh"
backup_root="$HOME/.sshbackups"
backup_dir="$backup_root/ssh_backup_$(date +%Y%m%d_%H%M%S)"
agnostic_authorized_keys=true
audit_log="$HOME/.ssh_key_audit.log"
known_hosts_file="$ssh_keys_location/known_hosts"

# --- Runtime state -----------------------------------------------------------
dry_run=false
override_security=false
audit_mode=false
# Deliberately empty: a routable placeholder here means a stray Enter opens a
# connection to a stranger's host.
default_remote_ip=""
default_remote_user="${USER:-$(id -un)}"
default_ssh_port="22"
check_remote=false
# ~/.ssh/config is backed up at most once per session by
# cleanup_and_update_ssh_config(); this tracks whether that has happened.
ssh_config_backed_up=false
# Temporary files registered for cleanup by the EXIT trap.
declare -a _tmp_files=()

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
NC='\033[0m' # No Color

# Function to log operations for audit trail
audit_log() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$audit_log"
}

# Function to update global variables
update_globals() {
    default_remote_ip="$1"
    default_remote_user="$2"
    default_ssh_port="$3"
}

# Function to display help message
display_help() {
    echo "Usage: $(basename "$0") [options]"
    echo
    echo "Options:"
    echo "  -b, --backup               Create a backup of SSH configurations before making changes"
    echo "  -d, --dry-run              Run in dry-run mode (show changes without applying them)"
    echo "  -h, --help                 Display this help message"
    echo "  -o, --override-security    Overrides mandatory key passphrase for permissive keys"
    echo "  -a, --audit                Show audit log of key operations"
    exit 0
}

# Output functions
info() {
    echo -e "${BLUE}INFO: ${NC}$1"
}

warn() {
    echo -e "${YELLOW}WARNING: ${NC}$1"
}

error() {
    echo -e "${RED}ERROR: ${NC}$1" >&2
}

success() {
    echo -e "${GREEN}SUCCESS: ${NC}$1"
}

debug() {
    if [ "${DEBUG:-false}" = true ]; then
        echo -e "${MAGENTA}DEBUG: ${NC}$1" >&2
    fi
}

# --- Temporary file handling -------------------------------------------------
# Every mktemp in this script goes through make_temp so that an abort (Ctrl-C,
# a failed ssh, an unexpected exit) never leaves private key material or a
# half-written authorized_keys behind in /tmp.
make_temp() {
    local t
    t=$(mktemp "${TMPDIR:-/tmp}/sshkeymanager.XXXXXX") || return 1
    chmod 600 "$t"
    _tmp_files+=("$t")
    printf '%s' "$t"
}

cleanup_temp_files() {
    local t
    for t in "${_tmp_files[@]+"${_tmp_files[@]}"}"; do
        [ -n "$t" ] && rm -f "$t" "${t}.backup"
    done
    _tmp_files=()
}
trap cleanup_temp_files EXIT INT TERM

# Strip trailing slashes from a directory path so that "$dir/$name" never
# produces a doubled separator, and "$dir$name" can never silently concatenate.
normalize_dir() {
    local p="$1"
    while [[ "$p" == */ && "$p" != "/" ]]; do
        p="${p%/}"
    done
    printf '%s' "$p"
}

# --- Command line arguments --------------------------------------------------
# Parsed here, *after* the output functions above are defined. When this block
# lived at the top of the file it called info()/error() before they existed,
# which aborted the script on every use of --backup, --dry-run and on any
# unrecognised option.
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--backup)
            if mkdir -p "$backup_dir" && cp -a "$ssh_keys_location/." "$backup_dir/"; then
                chmod -R go-rwx "$backup_dir"
                info "Backup created in $backup_dir"
                audit_log "Backup created in $backup_dir"
            else
                error "Failed to create backup in $backup_dir"
                exit 1
            fi
            shift
            ;;
        -d|--dry-run)
            dry_run=true
            info "Running in dry-run mode. No changes will be applied."
            shift
            ;;
        -h|--help)
            display_help
            ;;
        -o|--override-security)
            override_security=true
            shift
            ;;
        -a|--audit)
            audit_mode=true
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            error "Unknown option: $1"
            display_help
            ;;
    esac
done

# Function to execute or simulate command based on dry-run mode
execute_or_simulate() {
    if [ "$dry_run" = true ]; then
        printf 'Would execute: %s\n' "$*"
    else
        "$@"
    fi
}

# Updated prompt_with_default function
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    local user_input

    if ! read -rp "$(echo -e "${BLUE}$prompt${NC} [$default]: ")" user_input; then
        # stdin closed: fall back to the default rather than spinning.
        printf '%s' "$default"
        return 0
    fi
    printf '%s' "${user_input:-$default}"
}

# Helper function for yes/no prompts
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local answer

    while true; do
        if ! read -rp "$(echo -e "${YELLOW}$prompt${NC} [y/n] ($default): ")" answer; then
            # stdin closed: take the documented default.
            answer="$default"
            case $answer in
                [Yy]* ) return 0;;
                * ) return 1;;
            esac
        fi
        answer=${answer:-$default}
        case $answer in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) warn "Please answer yes or no.";;
        esac
    done
}

# Function to check SSH agent status
check_ssh_agent() {
    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        warn "SSH agent is not running."
        if prompt_yes_no "Would you like to start SSH agent?" "y"; then
            eval "$(ssh-agent -s)"
            success "SSH agent started."
        fi
    else
        info "SSH agent is running."
        local key_count
        key_count=$(ssh-add -l 2>/dev/null | grep -cv "The agent has no identities")
        info "Keys loaded in agent: $key_count"
    fi
}

# Function to add key to SSH agent
add_key_to_agent() {
    local key_path="$1"
    
    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        check_ssh_agent
    fi
    
    local fingerprint=""
    if [ -f "$key_path.pub" ]; then
        fingerprint=$(ssh-keygen -lf "$key_path.pub" 2>/dev/null | awk '{print $2}')
    fi

    # `ssh-add -l` exits 1 when the agent holds no identities, so its output has
    # to be captured separately from its status.
    local loaded
    loaded=$(ssh-add -l 2>/dev/null) || loaded=""

    if [ -n "$fingerprint" ] && printf '%s' "$loaded" | grep -qF -- "$fingerprint"; then
        info "Key already loaded in SSH agent."
    elif ssh-add "$key_path"; then
        success "Key added to SSH agent successfully."
    else
        error "Failed to add key to SSH agent."
        return 1
    fi
}

# Function to display key fingerprint
display_key_fingerprint() {
    local key_path="$1"
    local pub_key_path="${key_path}.pub"
    
    if [ -f "$pub_key_path" ]; then
        echo -e "\n${CYAN}Key Fingerprint Information:${NC}"
        echo -e "${BLUE}═════════════════════════════${NC}"
        
        # SHA256 fingerprint (default)
        local sha256_fp
        sha256_fp=$(ssh-keygen -lf "$pub_key_path" 2>/dev/null)
        echo -e "SHA256: $sha256_fp"
        
        # MD5 fingerprint (for compatibility)
        local md5_fp
        md5_fp=$(ssh-keygen -E md5 -lf "$pub_key_path" 2>/dev/null)
        echo -e "MD5:    $md5_fp"
        
        # Visual fingerprint
        if prompt_yes_no "Display visual fingerprint?" "n"; then
            ssh-keygen -lvf "$pub_key_path"
        fi
        echo -e "${BLUE}═════════════════════════════${NC}\n"
    fi
}

# Function to test SSH connection
test_ssh_connection() {
    local remote_user="$1"
    local remote_host="$2"
    local remote_port="$3"
    local key_path="$4"
    
    info "Testing SSH connection to $remote_user@$remote_host:$remote_port..."
    
    if ssh -o BatchMode=yes -o ConnectTimeout=5 -i "$key_path" \
        "$remote_user@$remote_host" -p "$remote_port" "echo 'Connection successful'" 2>/dev/null; then
        success "SSH connection test passed!"
        return 0
    else
        error "SSH connection test failed."
        if prompt_yes_no "Would you like to see detailed connection diagnostics?" "y"; then
            ssh -vvv -o BatchMode=yes -o ConnectTimeout=5 -i "$key_path" \
                "$remote_user@$remote_host" -p "$remote_port" "echo 'test'" 2>&1 | \
                grep -E "(debug1:|debug2:|debug3:|Permission denied|Connection refused|timeout)"
        fi
        return 1
    fi
}

# Function to manage known hosts
manage_known_hosts() {
    local remote_host="$1"
    local remote_port="${2:-22}"
    
    info "Managing known hosts entry for $remote_host:$remote_port..."
    
    # Check if host is already in known_hosts
    if ssh-keygen -F "[$remote_host]:$remote_port" -f "$known_hosts_file" >/dev/null 2>&1 || \
       ssh-keygen -F "$remote_host" -f "$known_hosts_file" >/dev/null 2>&1; then
        warn "Host already exists in known_hosts file."
        if prompt_yes_no "Update the host key?" "n"; then
            ssh-keygen -R "[$remote_host]:$remote_port" -f "$known_hosts_file" 2>/dev/null || \
            ssh-keygen -R "$remote_host" -f "$known_hosts_file" 2>/dev/null
        else
            return
        fi
    fi
    
    info "Fetching host key..."
    local temp_key
    temp_key=$(make_temp) || { error "Could not create a temporary file."; return 1; }
    
    if ssh-keyscan -p "$remote_port" -t ed25519,ecdsa,rsa "$remote_host" > "$temp_key" 2>/dev/null; then
        echo -e "\n${CYAN}Host key fingerprints:${NC}"
        while IFS= read -r line; do
            if [[ -n "$line" && ! "$line" =~ ^# ]]; then
                echo "$line" | ssh-keygen -lf - 2>/dev/null || echo "Could not process: $line"
            fi
        done < "$temp_key"
        
        if prompt_yes_no "Add these host keys to known_hosts?" "y"; then
            cat "$temp_key" >> "$known_hosts_file"
            success "Host keys added to known_hosts."
        fi
    else
        error "Failed to fetch host keys. The host might be unreachable."
    fi
    
    rm -f "$temp_key"
}

# Function to configure jump host
configure_jump_host() {
    local target_host="$1"
    local jump_host=""
    
    if prompt_yes_no "Does this host require a jump host (bastion/proxy)?" "n"; then
        jump_host=$(prompt_with_default "Enter jump host (user@host:port or host)" "")
        
        if [ -n "$jump_host" ]; then
            echo -e "\n${CYAN}Jump Host Configuration:${NC}"
            echo "Target: $target_host"
            echo "Jump: $jump_host"
            
            # Add to SSH config
            local ssh_config="$ssh_keys_location/config"
            local temp_config
            temp_config=$(make_temp) || { error "Could not create a temporary file."; return 1; }
            
            # Check if host already exists in config
            if config_has_host "$ssh_config" "$target_host"; then
                warn "Host $target_host already exists in SSH config."
                if prompt_yes_no "Update existing configuration?" "y"; then
                    remove_host_block "$ssh_config" "$target_host" > "$temp_config"
                else
                    rm -f "$temp_config"
                    return
                fi
            else
                [ -f "$ssh_config" ] && cat "$ssh_config" > "$temp_config"
            fi
            
            # Add new host configuration
            cat >> "$temp_config" << EOF

Host $target_host
    ProxyJump $jump_host
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF
            
            mv "$temp_config" "$ssh_config"
            chmod 600 "$ssh_config"
            success "Jump host configuration added."
        fi
    fi
}

# Function to analyze key strength
analyze_key_strength() {
    local key_path="$1"
    local pub_key_path="${key_path}.pub"
    
    if [ ! -f "$pub_key_path" ]; then
        error "Public key not found: $pub_key_path"
        return 1
    fi
    
    echo -e "\n${CYAN}Key Strength Analysis:${NC}"
    echo -e "${BLUE}═════════════════════════════${NC}"
    
    local key_info key_bits key_type
    if ! key_info=$(ssh-keygen -lf "$pub_key_path" 2>/dev/null); then
        error "Could not read key information from $pub_key_path"
        return 1
    fi
    key_bits=$(printf '%s' "$key_info" | awk '{print $1}')
    # The type is the last field. Using $4 broke for any key whose comment
    # contains a space, which is the default for keys made elsewhere.
    key_type=$(printf '%s' "$key_info" | awk '{print $NF}' | tr -d '()')
    
    echo "Key Type: $key_type"
    echo "Key Size: $key_bits bits"
    
    # Analyze based on key type
    case "$key_type" in
        RSA)
            if [ "$key_bits" -lt 2048 ]; then
                error "WEAK: RSA key is less than 2048 bits. Should be upgraded immediately."
            elif [ "$key_bits" -lt 3072 ]; then
                warn "MODERATE: RSA key is less than 3072 bits. Consider upgrading."
            else
                success "STRONG: RSA key meets current security standards."
            fi
            ;;
        ED25519)
            success "STRONG: Ed25519 provides excellent security with good performance."
            ;;
        ECDSA)
            if [ "$key_bits" -lt 256 ]; then
                warn "MODERATE: Consider using at least 256-bit ECDSA keys."
            else
                success "STRONG: ECDSA key meets security standards."
            fi
            ;;
        DSA)
            error "DEPRECATED: DSA keys are no longer recommended. Please generate a new key."
            ;;
        *)
            info "Unknown key type. Unable to assess strength."
            ;;
    esac
    
    # Check key age
    local key_age_days=0
    if [ -f "$key_path" ]; then
        local key_modified
        key_modified=$(stat -c %Y "$key_path" 2>/dev/null || stat -f %m "$key_path" 2>/dev/null)
        local current_time
        current_time=$(date +%s)
        key_age_days=$(( (current_time - key_modified) / 86400 ))
        
        echo -e "\nKey Age: $key_age_days days"
        
        if [ "$key_age_days" -gt 365 ]; then
            warn "Key is over 1 year old. Consider rotating your keys periodically."
        fi
    fi
    
    echo -e "${BLUE}═════════════════════════════${NC}\n"
}

# Function to rotate SSH keys
rotate_ssh_key() {
    local old_key_path
    
    echo -e "\n${GREEN}SSH Key Rotation${NC}"
    echo -e "${BLUE}═════════════════════════${NC}\n"
    
    if ! old_key_path=$(select_key_file "private key to rotate" "$ssh_keys_location/id_rsa" "id_*" "false"); then
        error "Failed to select a key for rotation."
        return 1
    fi
    
    local old_key_name
    old_key_name=$(basename "$old_key_path")
    local new_key_name="${old_key_name}_new"
    local backup_key_name
    backup_key_name="${old_key_name}_old_$(date +%Y%m%d_%H%M%S)"
    
    info "Rotating key: $old_key_name"
    
    # Analyze old key
    analyze_key_strength "$old_key_path"
    
    # Generate new key with same type
    local old_key_type
    old_key_type=$(ssh-keygen -lf "${old_key_path}.pub" 2>/dev/null | awk '{print $NF}' | tr -d '()' | tr '[:upper:]' '[:lower:]')
    if [ -z "$old_key_type" ]; then
        error "Could not determine the type of $old_key_path (is ${old_key_path}.pub present?)"
        return 1
    fi
    
    info "Generating new key of type: $old_key_type"
    
    # Generate new key
    if [ "$old_key_type" == "ed25519" ]; then
        ssh-keygen -t ed25519 -f "$ssh_keys_location/$new_key_name" -N ""
    elif [ "$old_key_type" == "rsa" ]; then
        local key_bits
        key_bits=$(ssh-keygen -lf "${old_key_path}.pub" | awk '{print $1}')
        ssh-keygen -t rsa -b "$key_bits" -f "$ssh_keys_location/$new_key_name" -N ""
    else
        ssh-keygen -t "$old_key_type" -f "$ssh_keys_location/$new_key_name" -N ""
    fi
    
    if [ ! -f "$ssh_keys_location/$new_key_name" ]; then
        error "Failed to generate new key."
        return 1
    fi

    success "New key generated successfully."
    {
        # Display new key fingerprint
        display_key_fingerprint "$ssh_keys_location/$new_key_name"
        
        if prompt_yes_no "Deploy new key to all hosts that use the old key?" "y"; then
            # Resolved through `ssh -G` per host rather than by grepping five
            # lines of context around an IdentityFile match, which missed hosts
            # whose IdentityFile sat further down the block and matched keys
            # whose names merely shared a prefix.
            local hosts=()
            mapfile -t hosts < <(hosts_using_key "$old_key_name")
            
            if [ ${#hosts[@]} -eq 0 ]; then
                warn "No specific hosts found in SSH config for this key."
                if prompt_yes_no "Deploy to default remote host?" "y"; then
                    if prompt_remote_details; then
                        copy_key_to_remote "$new_key_name" "$remote_host" "$remote_user" "$remote_port" || true
                    else
                        warn "No host given; new key was not deployed anywhere."
                    fi
                fi
            else
                for host in "${hosts[@]}"; do
                    info "Deploying to host: $host"
                    # Take User/Port/HostName from that host's own config block
                    # instead of re-prompting for details and then ignoring the
                    # host we are supposedly deploying to.
                    remote_host=$(ssh_config_value "$host" hostname)
                    remote_user=$(ssh_config_value "$host" user)
                    remote_port=$(ssh_config_value "$host" port)
                    [ -n "$remote_host" ] || remote_host="$host"
                    [ -n "$remote_user" ] || remote_user="$default_remote_user"
                    [ -n "$remote_port" ] || remote_port="$default_ssh_port"
                    info "  -> $remote_user@$remote_host:$remote_port"
                    copy_key_to_remote "$new_key_name" "$remote_host" "$remote_user" "$remote_port" || \
                        warn "Deployment to $host failed; continuing."
                done
            fi
            
        fi

        # The swap happens whether or not deployment ran: leaving the new key
        # parked under a "_new" suffix left the rotation half-finished.
        if prompt_yes_no "Swap the new key into place (old key kept as $backup_key_name)?" "y"; then
            mv "$old_key_path" "$ssh_keys_location/$backup_key_name"
            mv "${old_key_path}.pub" "$ssh_keys_location/${backup_key_name}.pub"
            mv "$ssh_keys_location/$new_key_name" "$old_key_path"
            mv "$ssh_keys_location/${new_key_name}.pub" "${old_key_path}.pub"

            success "Key rotation completed. Old key backed up as: $backup_key_name"
            warn "Remove $backup_key_name from every host's authorized_keys once the new key is confirmed working."
            audit_log "Key rotated: $old_key_name -> backed up as $backup_key_name"
        else
            info "New key left in place as $new_key_name; nothing was replaced."
        fi
    }
}

# Does ~/.ssh/config declare this exact Host alias?
#
# The old `grep -q "^Host $host"` treated the hostname as a regular expression,
# so "web.example.com" matched "webXexample.com", and it also matched any host
# that merely shared a prefix.
config_has_host() {
    local ssh_config="$1" host="$2"
    [ -f "$ssh_config" ] || return 1
    list_config_hosts_in "$ssh_config" | grep -qxF -- "$host"
}

list_config_hosts_in() {
    local ssh_config="$1"
    [ -f "$ssh_config" ] || return 0
    awk '
        /^[[:space:]]*[Hh]ost[[:space:]]/ {
            for (i = 2; i <= NF; i++) {
                if ($i !~ /[*?!]/) print $i
            }
        }
    ' "$ssh_config" | awk '!seen[$0]++'
}

# Strip one Host block from a config, writing the result to stdout.
#
# Compares alias names as literal strings and understands Host lines that
# declare several aliases: removing "web" from `Host web staging` leaves
# `Host staging` rather than deleting the block other names still depend on.
remove_host_block() {
    local ssh_config="$1" host="$2"
    [ -f "$ssh_config" ] || return 0
    awk -v target="$host" '
        function is_host_line(l) { return l ~ /^[[:space:]]*[Hh]ost[[:space:]]/ }
        is_host_line($0) {
            skip = 0
            kept = ""
            n = 0
            for (i = 2; i <= NF; i++) {
                if ($i != target) { kept = kept " " $i; n++ }
            }
            if (n == NF - 1) { print; next }      # target not present, keep as-is
            if (n == 0)      { skip = 1; next }   # block belonged solely to target
            print "Host" kept                      # drop just this alias
            next
        }
        { if (!skip) print }
    ' "$ssh_config"
}

# Resolve one effective ssh_config value for a host.
#
# `ssh -G` applies the same matching, Include handling and precedence rules the
# client itself uses, which hand-parsing the file with grep/awk does not.
ssh_config_value() {
    local host="$1" key="$2"
    ssh -G "$host" 2>/dev/null \
        | awk -v k="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')" \
              '$1 == k { print $2; exit }'
}

# List the concrete Host aliases declared in ~/.ssh/config.
#
# A single Host line may declare several aliases; patterns containing globs and
# negations are skipped because they cannot be connected to directly.
list_config_hosts() {
    list_config_hosts_in "$ssh_keys_location/config"
}

# Every host block whose IdentityFile refers to the given key file.
hosts_using_key() {
    local key_basename="$1" host idf
    while IFS= read -r host; do
        [ -n "$host" ] || continue
        idf=$(ssh_config_value "$host" identityfile)
        case "$idf" in
            *"$key_basename") printf '%s\n' "$host" ;;
        esac
    done < <(list_config_hosts)
}

# Collect remote connection details.
#
# Assigns remote_host / remote_user / remote_port in the caller's scope and
# returns non-zero when no host was given. The previous version echoed the three
# values space-separated for `read` to split, which silently shifted every field
# by one whenever the host was left empty.
prompt_remote_details() {
    remote_host=$(prompt_with_default "Enter remote host (blank to stop)" "$default_remote_ip")
    if [ -z "$remote_host" ]; then
        return 1
    fi
    remote_user=$(prompt_with_default "Enter remote user" "$default_remote_user")

    while true; do
        remote_port=$(prompt_with_default "Enter remote SSH-Port (usually 22)" "$default_ssh_port")
        if [[ "$remote_port" =~ ^[0-9]+$ ]] && [ "$remote_port" -ge 1 ] && [ "$remote_port" -le 65535 ]; then
            break
        fi
        error "Port must be a number between 1 and 65535."
    done

    # Remember them as the defaults for the next prompt.
    update_globals "$remote_host" "$remote_user" "$remote_port"
    return 0
}

# Refactored generate_ssh_key function
generate_ssh_key() {
    local key_type
    local key_size
    local key_name
    local use_passphrase

    echo -e "\n${GREEN}SSH Key Generation Menu${NC}"
    echo -e "${BLUE}═════════════════════════${NC}\n"

    select_key_type
    select_key_size
    select_passphrase_option
    select_key_name
    generate_key "$key_type" "$key_size" "$key_name" "$use_passphrase"
    
    # Display key fingerprint
    display_key_fingerprint "$ssh_keys_location/$key_name"
    
    # Analyze key strength
    analyze_key_strength "$ssh_keys_location/$key_name"
    
    if prompt_yes_no "Add this key to SSH agent?" "y"; then
        add_key_to_agent "$ssh_keys_location/$key_name"
    fi
    
    if prompt_yes_no "Do you want to configure this key for a remote host? (Recommended)" "y"; then
        if ! prompt_remote_details; then
            warn "No host given; skipping remote configuration."
            check_remote=false
            configure_local_ssh "$key_name"
            display_key_generation_summary "$key_type" "$use_passphrase"
            audit_log "Generated new $key_type key: $key_name"
            return 0
        fi
        check_remote=true
        
        # Manage known hosts
        manage_known_hosts "$remote_host" "$remote_port"
        
        # Copy key to remote. The old code announced success unconditionally,
        # even when the copy had just failed.
        if copy_key_to_remote "$key_name" "$remote_host" "$remote_user" "$remote_port"; then
            success "Public key installed on $remote_host."
        else
            error "Could not install the public key on $remote_host."
            if ! prompt_yes_no "Continue configuring this host anyway?" "n"; then
                return 1
            fi
        fi
        
        # Configure jump host if needed
        configure_jump_host "$remote_host"
        
        # Configure remote SSH
        configure_remote_ssh "$remote_user" "$remote_host" "$remote_port" "$ssh_keys_location/$key_name"
        
        # Test connection
        test_ssh_connection "$remote_user" "$remote_host" "$remote_port" "$ssh_keys_location/$key_name" || true
    fi
    
    configure_local_ssh "$key_name"
    
    if [ "$check_remote" = true ]; then
        check_remote_ssh_config "$remote_user" "$remote_host" "$remote_port" "$ssh_keys_location/$key_name"
    fi
    
    display_key_generation_summary "$key_type" "$use_passphrase"
    
    audit_log "Generated new $key_type key: $key_name"
}

# Helper functions for generate_ssh_key
select_key_type() {
    echo -e "${CYAN}Select Key Type:${NC}"
    echo "1. Ed25519 (Recommended - fast and secure)"
    echo "2. RSA (Wide compatibility)"
    echo "3. ECDSA (Good performance)"
    echo "4. FIDO2 Hardware Key (Ed25519-SK or ECDSA-SK)"
    
    while true; do
        if ! read -rp "Enter your choice (1-4): " key_type_choice; then
            key_type="ed25519"; break
        fi
        case $key_type_choice in
            1) key_type="ed25519"; break;;
            2) key_type="rsa"; break;;
            3) key_type="ecdsa"; break;;
            4) select_hardware_key_type; break;;
            *) error "Invalid choice. Please try again.";;
        esac
    done
}

select_hardware_key_type() {
    echo -e "\n${CYAN}Select Hardware Key Type:${NC}"
    warn "This option requires the system packages openssh and libfido2 to be installed for your distribution!"
    echo "1. Ed25519-SK (Recommended if supported by your device)"
    echo "2. ECDSA-SK (Better compatibility with older hardware keys)"
    read -rp "Enter your choice (1-2): " hw_key_choice
    case $hw_key_choice in
        1) key_type="ed25519-sk";;
        2) key_type="ecdsa-sk";;
        *) error "Invalid choice. Please try again."; select_hardware_key_type;;
    esac
}

select_key_size() {
    if [ "$key_type" == "rsa" ]; then
        echo -e "\n${CYAN}Select Key Size:${NC}"
        echo "1. 2048 bits (Minimum recommended)"
        echo "2. 3072 bits (Good balance)"
        echo "3. 4096 bits (Maximum security)"
        
        while true; do
            if ! read -rp "Enter your choice: " key_size_choice; then
                key_size_choice=1
            fi
            case $key_size_choice in
                1) key_size="2048"; break;;
                2) key_size="3072"; break;;
                3) key_size="4096"; break;;
                *) error "Invalid choice. Please try again.";;
            esac
        done
    elif [ "$key_type" == "ecdsa" ]; then
        echo -e "\n${CYAN}Select Key Size:${NC}"
        echo "1. 256 bits (Recommended)"
        echo "2. 384 bits (Higher security)"
        echo "3. 521 bits (Maximum security)"
        
        while true; do
            if ! read -rp "Enter your choice: " key_size_choice; then
                key_size_choice=1
            fi
            case $key_size_choice in
                1) key_size="256"; break;;
                2) key_size="384"; break;;
                3) key_size="521"; break;;
                *) error "Invalid choice. Please try again.";;
            esac
        done
    fi
}

select_passphrase_option() {
    if [ "$agnostic_authorized_keys" != true ]; then
        echo -e "\n${CYAN}Passphrase Option:${NC}"
        echo "Using a passphrase adds an extra layer of security to your SSH key."
        echo "+ Advantages: Protects the key if it's stolen or accessed by unauthorized users"
        echo "- Disadvantages: You'll need to enter the passphrase each time you use the key (unless using ssh-agent)"
        info "You have a choice here because of the current settings, which are restrictive - ${GREEN}remote hosts${NC} will be configured within their authorized hosts to ${GREEN}only accept connections with your given username/hostname${NC} configuration."
        
        if prompt_yes_no "Do you want to set a passphrase for your SSH key?" "n"; then
            use_passphrase=true
            info "You will be prompted to enter the passphrase during key generation."
        else
            use_passphrase=false
            info "No passphrase will be set. Your key will not be password-protected."
        fi
    else
        if [ "$override_security" != true ]; then
            info "Remote host configuration currently is ${GREEN}permissive${NC}, which allows you to ${GREEN}log in from any host as any user${NC}, as long as you have the keys."
            info "${RED}If you happen to leak your private key, a malicious actor can log in as you would. Because of that, setting a passphrase to protect your private key is mandatory.${NC}"
            info "If you want to change this setting, do so in the settings menu or the configuration variables (agnostic_authorized_keys=false)"
            use_passphrase=true
        else
            if prompt_yes_no "Do you want to set a passphrase for your SSH key?" "n"; then
                use_passphrase=true
                info "You will be prompted to enter the passphrase during key generation."
            else
                use_passphrase=false
                info "No passphrase will be set. Your key will not be password-protected."
            fi
        fi
    fi
}

select_key_name() {
    echo -e "\n${CYAN}Enter Key Name:${NC}"
    warn "The name should begin with 'id_' to be compatible with this script."
    echo "Example: id_${key_type}_$(hostname)_$(date +%Y%m)"

    local suggested_name
    suggested_name="id_${key_type}_$(hostname | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')_$(date +%Y%m)"

    while true; do
        key_name=$(prompt_with_default "Key name" "$suggested_name")
        # The name becomes a filename and is interpolated into ssh-keygen
        # arguments, so restrict it to characters that cannot be mistaken for
        # a path component or shell syntax.
        if [[ ! "$key_name" =~ ^id_[A-Za-z0-9._-]+$ ]]; then
            error "Key name must start with 'id_' and contain only letters, digits, '.', '_' or '-'."
            continue
        fi
        if [ -e "$ssh_keys_location/$key_name" ] || [ -e "$ssh_keys_location/$key_name.pub" ]; then
            error "Key with this name already exists. Please choose a different name."
            continue
        fi
        break
    done
}

generate_key() {
    local key_type="$1"
    local key_size="$2"
    local key_name="$3"
    local use_passphrase="$4"

    info "Generating new SSH key pair..."
    if [[ "$key_type" == *"-sk" ]]; then
        generate_hardware_key "$key_type" "$key_name" "$use_passphrase"
    elif [ "$key_type" == "ed25519" ]; then
        generate_ed25519_key "$key_name" "$use_passphrase"
    else
        generate_standard_key "$key_type" "$key_size" "$key_name" "$use_passphrase"
    fi

    chmod 600 "$ssh_keys_location/$key_name"
    chmod 644 "$ssh_keys_location/$key_name.pub"
}

generate_hardware_key() {
    local key_type="$1"
    local key_name="$2"
    local use_passphrase="$3"

    echo "Please insert your hardware security key and follow any prompts."

    # Built as an array and invoked directly. The previous implementation went
    # through `eval`, so a key name containing shell metacharacters was executed
    # rather than treated as a filename.
    local -a keygen_args=(-t "$key_type" -f "$ssh_keys_location/$key_name")
    if [ "$use_passphrase" != true ]; then
        keygen_args+=(-N "")
    fi

    if ! ssh-keygen "${keygen_args[@]}"; then
        error "Failed to generate hardware-backed key. This might be due to missing libfido2 library."
        echo "For Debian-based systems, try installing it with:"
        echo "sudo apt update && sudo apt install libfido2-1 libfido2-dev openssh-client"
        echo "For Arch-based systems, use:"
        echo "sudo pacman -Sy libfido2 openssh"
        echo "For Fedora/RHEL systems, use:"
        echo "sudo dnf install libfido2 libfido2-devel openssh-clients"
        echo "After installing, please try again."
        return 1
    fi
}

generate_ed25519_key() {
    local key_name="$1"
    local use_passphrase="$2"

    if [ "$use_passphrase" = true ]; then
        ssh-keygen -t ed25519 -f "$ssh_keys_location/$key_name" -C "$(whoami)@$(hostname)-$(date +%Y%m%d)"
    else
        ssh-keygen -t ed25519 -f "$ssh_keys_location/$key_name" -N "" -C "$(whoami)@$(hostname)-$(date +%Y%m%d)"
    fi
}

generate_standard_key() {
    local key_type="$1"
    local key_size="$2"
    local key_name="$3"
    local use_passphrase="$4"

    # Fixed passphrase handling
    if [ "$use_passphrase" = true ]; then
        ssh-keygen -t "$key_type" -b "$key_size" -f "$ssh_keys_location/$key_name" -C "$(whoami)@$(hostname)-$(date +%Y%m%d)"
    else
        ssh-keygen -t "$key_type" -b "$key_size" -f "$ssh_keys_location/$key_name" -N "" -C "$(whoami)@$(hostname)-$(date +%Y%m%d)"
    fi
}

copy_key_to_remote() {
    local key_name="$1"
    local remote_host="$2"
    local remote_user="$3"
    local remote_port="$4"

    info "Copying $ssh_keys_location/$key_name.pub to $remote_host..."

    if [ "$agnostic_authorized_keys" = false ]; then
        info "Running ssh-copy-id with user/hostname restrictions..."
        ssh-copy-id -f -i "$ssh_keys_location/$key_name.pub" "$remote_user@$remote_host" -p "$remote_port"
    else
        info "Adding key to authorized_keys without user/hostname restrictions"
        # Read the public key and preserve all parts including comment
        local pubkey
        pubkey=$(cat "$ssh_keys_location/$key_name.pub")
        
        # Use a more robust method to add the key
        if echo "$pubkey" | ssh "$remote_user@$remote_host" -p "$remote_port" \
            "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"; then
            success "Key successfully copied to remote host."
        else
            error "Failed to copy key to remote host."
            return 1
        fi
    fi
    
    audit_log "Copied key $key_name to $remote_user@$remote_host:$remote_port"
}

configure_per_host_ssh() {
    local host="$1"
    local user="$2"
    local port="$3"
    local key_path="$4"
    
    local ssh_config="$ssh_keys_location/config"
    local temp_config
    temp_config=$(make_temp) || { error "Could not create a temporary file."; return 1; }
    
    info "Configuring SSH for host: $host"
    
    # Create base config if it doesn't exist
    if [ ! -f "$ssh_config" ]; then
        touch "$ssh_config"
        chmod 600 "$ssh_config"
    fi
    
    # Check if host already exists
    if config_has_host "$ssh_config" "$host"; then
        warn "Host $host already exists in SSH config."
        if ! prompt_yes_no "Update existing configuration?" "y"; then
            rm -f "$temp_config"
            return
        fi
        remove_host_block "$ssh_config" "$host" > "$temp_config"
    else
        cat "$ssh_config" > "$temp_config"
    fi
    
    # Add host configuration
    cat >> "$temp_config" << EOF

Host $host
    HostName $host
    User $user
    Port $port
    IdentityFile $key_path
    IdentitiesOnly yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

    # Add additional options
    if prompt_yes_no "Enable connection multiplexing for faster subsequent connections?" "y"; then
        cat >> "$temp_config" << EOF
    ControlMaster auto
    ControlPath ~/.ssh/control-%r@%h:%p
    ControlPersist 10m
EOF
    fi
    
    if prompt_yes_no "Enable compression?" "n"; then
        echo "    Compression yes" >> "$temp_config"
    fi
    
    if prompt_yes_no "Disable strict host key checking (not recommended)?" "n"; then
        echo "    StrictHostKeyChecking no" >> "$temp_config"
    fi
    
    mv "$temp_config" "$ssh_config"
    chmod 600 "$ssh_config"
    
    success "SSH configuration for $host completed."
}

display_key_generation_summary() {
    local key_type="$1"
    local use_passphrase="$2"

    success "SSH key pair generated and configured successfully."

    if [[ "$key_type" == *"-sk" ]]; then
        echo -e "\n${YELLOW}Note:${NC} You've generated a hardware-backed SSH key. Remember to have your security key available when using this SSH key."
    fi

    if [ "$use_passphrase" = true ]; then
        echo -e "\n${YELLOW}Note:${NC} You've set a passphrase for your SSH key. Consider using ssh-agent to manage your keys."
        echo "To add your key to ssh-agent, run: ssh-add ~/.ssh/your_key_name"
    else
        echo -e "\n${YELLOW}Note:${NC} Your SSH key is not protected by a passphrase. Ensure you keep the private key secure."
    fi

    if prompt_yes_no "Do you want to perform some checks for your local ssh security?" "n"; then
        check_local_ssh_security
    fi
}

# Updated import_private_key function
import_private_key() {
    local key_name
    local destination_path

    local private_key_path
    while true; do
        # `local x=$(cmd)` returns the exit status of `local`, not of the
        # command, so declaration and assignment must stay separate for the
        # error check below to mean anything.
        if ! private_key_path=$(select_key_file "private" "$ssh_keys_location/id_rsa" "id_*" "false"); then
            error "Failed to select a valid private key."
            return 1
        fi
        
        key_name=$(basename "$private_key_path")
        destination_path="$ssh_keys_location/$key_name"
        
        copy_and_set_permissions "$private_key_path" "$destination_path"
        
        # Display and analyze the imported key
        display_key_fingerprint "$destination_path"
        analyze_key_strength "$destination_path"
        
        if prompt_yes_no "Add this key to SSH agent?" "y"; then
            add_key_to_agent "$destination_path"
        fi
        
        cleanup_and_update_ssh_config
        configure_local_ssh "$key_name"
        
        while true; do
            prompt_remote_details || break
            
            # Configure per-host SSH settings
            configure_per_host_ssh "$remote_host" "$remote_user" "$remote_port" "$destination_path"
            
            # Manage known hosts
            manage_known_hosts "$remote_host" "$remote_port"
            
            configure_remote_ssh "$remote_user" "$remote_host" "$remote_port" "$destination_path"
            check_remote_ssh_config "$remote_user" "$remote_host" "$remote_port" "$destination_path"
            
            # Test connection
            test_ssh_connection "$remote_user" "$remote_host" "$remote_port" "$destination_path" || true
            
            if ! prompt_yes_no "Do you want to configure this key for another host?" "n"; then
                break
            fi
        done
        
        audit_log "Imported private key: $key_name"
        
        if ! prompt_yes_no "Do you want to import another private key?" "n"; then
            break
        fi
    done
}

# Updated function to copy public key to additional hosts
copy_pubkey_to_hosts() {
    local pubkey_path

    # The status check has to happen before anything else runs, or $? belongs
    # to that other command instead.
    if ! pubkey_path=$(select_key_file "public" "$ssh_keys_location/id_*.pub" "id_*.pub" "true"); then
        error "Failed to select a valid public key."
        return 1
    fi
    local key_name
    key_name=$(basename "$pubkey_path" .pub)
    
    # Display key information
    display_key_fingerprint "${pubkey_path%.pub}"
    
    configure_local_ssh "$key_name"

    while true; do
        prompt_remote_details || break
        
        # Manage known hosts
        manage_known_hosts "$remote_host" "$remote_port"
        
        info "Copying public key '$pubkey_path' to $remote_host..."
        copy_key_to_remote "$(basename "$pubkey_path" .pub)" "$remote_host" "$remote_user" "$remote_port"
        
        # Configure per-host SSH settings
        configure_per_host_ssh "$remote_host" "$remote_user" "$remote_port" "${pubkey_path%.pub}"
        
        configure_remote_ssh "$remote_user" "$remote_host" "$remote_port" "${pubkey_path%.pub}"
        check_remote_ssh_config "$remote_user" "$remote_host" "$remote_port" "$pubkey_path"
        
        # Test connection
        test_ssh_connection "$remote_user" "$remote_host" "$remote_port" "${pubkey_path%.pub}" || true
        
        if ! prompt_yes_no "Do you want to copy the key to another host?" "n"; then
            break
        fi
    done
}

select_key_file() {
    local key_type="$1"
    local default_path="$2"   # offered when the user chooses to type a path
    local file_pattern="$3"
    local include_pub="$4"
    local files=()
    local selected_file=""

    # Find matching files in .ssh directory
    while IFS= read -r -d $'\0' file; do
        if [ "$include_pub" != "true" ] && [[ "$file" == *.pub ]]; then
            continue
        fi
        files+=("$file")
    done < <(find "$ssh_keys_location" -type f -name "$file_pattern" -print0 2>/dev/null)

    if [ ${#files[@]} -eq 0 ]; then
        error "No $key_type keys found in ~/.ssh directory." >&2
        selected_file=$(prompt_with_default "Enter path to $key_type key" "$default_path")
    else
        echo "Select a $key_type key:" >&2
        select file in "${files[@]}" "Enter path manually"; do
            case $file in
                "Enter path manually")
                    selected_file=$(prompt_with_default "Enter path to $key_type key" "$default_path")
                    break
                    ;;
                *)
                    if [ -n "$file" ]; then
                        selected_file="$file"
                        break
                    else
                        # Check if the input is a valid path
                        if [ -f "${REPLY:-}" ]; then
                            selected_file="${REPLY:-}"
                            break
                        else
                            error "Invalid selection or file not found. Please try again." >&2
                        fi
                    fi
                    ;;
            esac
        done
    fi

    # Verify that the selected file exists and is readable
    if [ ! -f "$selected_file" ] || [ ! -r "$selected_file" ]; then
        error "The selected $key_type key file does not exist or is not readable: $selected_file" >&2
        return 1
    fi

    # Return only the file path, without any additional text
    echo "$selected_file"
}

copy_and_set_permissions() {
    local source_path="$1"
    local dest_path="$2"

    if [[ "$source_path" != "$dest_path" ]]; then
        cp -f "$source_path" "$dest_path"
        info "Private key copied to $dest_path"
    fi

    chmod 600 "$dest_path"
    
    # Generate public key if it doesn't exist
    if [ ! -f "${dest_path}.pub" ]; then
        info "Generating public key from private key..."
        ssh-keygen -y -f "$dest_path" > "${dest_path}.pub"
        chmod 644 "${dest_path}.pub"
    fi
}

# Remote sshd hardening.
#
# Directives are applied through a drop-in under /etc/ssh/sshd_config.d when the
# remote sshd Includes that directory, and appended to the main config only as a
# fallback. The previous sed-only approach silently did nothing when a directive
# was absent from the file, or was overridden by a drop-in, while still
# reporting success.
configure_remote_ssh() {
    local remote_user="$1"
    local remote_host="$2"
    local remote_port="$3"
    local key_path="${4:-}"

    if prompt_yes_no "Attempt configuration of $remote_host to accept ssh pubkey? (This is not necessary when done before)" "n"; then

        if prompt_yes_no "Set the recommended Permissions on the remote keys?" "y"; then
            set_rhost_permissions=true
        else
            set_rhost_permissions=false
        fi

        if prompt_yes_no "Enable public key authentication on $remote_host?" "y"; then
            enable_pubkey_auth=true
        else
            enable_pubkey_auth=false
        fi
        
        if prompt_yes_no "Disable password authentication on $remote_host? (WARNING: Ensure key auth works first!)" "n"; then
            disable_password_auth=true
        else
            disable_password_auth=false
        fi
        
        info "Configuring $remote_host. You may be prompted for the sudo password on the remote host."
        
        if [ "$set_rhost_permissions" = true ]; then
            # First, perform non-sudo operations
            ssh "$remote_user@$remote_host" -p "$remote_port" bash << 'EOF'
            chmod 700 ~/.ssh
            chmod 600 ~/.ssh/authorized_keys
            find ~/.ssh -name '*.pub' -type f -exec chmod 644 {} +
            # Fix any private keys that might be there
            find ~/.ssh -name 'id_*' ! -name '*.pub' -type f -exec chmod 600 {} +
EOF
        fi

        # Refuse to disable password auth unless key authentication is proven to
        # work with the key we actually just deployed. The old code built the
        # key path by concatenating the key directory onto an already-absolute
        # path, so this safety check ran against a file that never existed.
        if [ "$disable_password_auth" = true ]; then
            if [ -z "$key_path" ] || [ ! -f "${key_path%.pub}" ]; then
                error "No usable private key was supplied; NOT disabling password authentication."
                disable_password_auth=false
            elif ! test_ssh_connection "$remote_user" "$remote_host" "$remote_port" "${key_path%.pub}"; then
                error "Key authentication test failed. NOT disabling password authentication for safety."
                disable_password_auth=false
            fi
        fi

        # Now, perform sudo operations interactively
        if [ "$enable_pubkey_auth" = true ] || [ "$disable_password_auth" = true ]; then
            local directives=""
            [ "$enable_pubkey_auth" = true ]    && directives+="PubkeyAuthentication yes"$'\n'
            [ "$disable_password_auth" = true ] && directives+="PasswordAuthentication no"$'\n'

            info "Applying sshd configuration on $remote_host (sudo may prompt)..."
            if ssh -t "$remote_user@$remote_host" -p "$remote_port" \
                "REMOTE_DIRECTIVES=$(printf '%q' "$directives") sudo -p 'sudo password for %u@%h: ' bash -s" <<'REMOTE_EOF'
set -u
main_cfg=/etc/ssh/sshd_config
dropin_dir=/etc/ssh/sshd_config.d
stamp=$(date +%Y%m%d_%H%M%S)

# Prefer a drop-in, but only if the main config actually Includes it; otherwise
# the file would be written and silently ignored.
if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$main_cfg" 2>/dev/null; then
    mkdir -p "$dropin_dir"
    target="$dropin_dir/99-sshkeymanager.conf"
    printf '# Managed by sshkeymanager (%s)\n%s' "$stamp" "$REMOTE_DIRECTIVES" > "$target"
    chmod 644 "$target"
    echo "Wrote $target"
else
    cp -a "$main_cfg" "${main_cfg}.bak.${stamp}"
    target="$main_cfg"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        key=${line%% *}
        # Comment out any existing setting for this key, then append ours, so
        # that a directive absent from the file is still applied.
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*(${key})[[:space:]]+.*|# (replaced by sshkeymanager) &|I" "$main_cfg"
        printf '%s\n' "$line" >> "$main_cfg"
    done <<< "$REMOTE_DIRECTIVES"
    echo "Updated $main_cfg (backup: ${main_cfg}.bak.${stamp})"
fi

# Never restart a daemon whose config does not parse.
if ! sshd -t 2>/dev/null && ! /usr/sbin/sshd -t 2>/dev/null; then
    echo "ERROR: sshd rejected the new configuration; not restarting." >&2
    exit 1
fi

systemctl restart sshd.service 2>/dev/null \
    || systemctl restart ssh.service 2>/dev/null \
    || service sshd restart 2>/dev/null \
    || service ssh restart 2>/dev/null \
    || { echo "ERROR: could not restart the ssh service." >&2; exit 1; }
echo "sshd reloaded."
REMOTE_EOF
            then
                success "Remote SSH configuration completed for $remote_host."
                audit_log "Configured remote SSH for $remote_user@$remote_host:$remote_port"
            else
                error "Remote SSH configuration failed on $remote_host. Existing settings were left in place."
                audit_log "FAILED remote SSH configuration for $remote_user@$remote_host:$remote_port"
                return 1
            fi
        else
            success "Remote permissions updated for $remote_host."
            audit_log "Updated remote ~/.ssh permissions for $remote_user@$remote_host:$remote_port"
        fi
    fi
}

configure_local_ssh() {
    local key_name="$1"
    info "Configuring local SSH to use the key: $key_name"

    # Set correct permissions for the private key file
    chmod 600 "$ssh_keys_location/$key_name"
    # Set correct permissions for the public key file
    chmod 644 "$ssh_keys_location/$key_name.pub" 2>/dev/null || true

    cleanup_and_update_ssh_config 

    info "SSH configuration complete."
}

# Normalize ~/.ssh/config.
#
# Runs automatically from the main menu loop, so it must be conservative:
#   * a timestamped backup is taken once per session, before the first write;
#   * the file is only rewritten when the result actually differs, so opening
#     the menu repeatedly no longer churns the config;
#   * dry-run mode reports what would change and writes nothing.
#
# The `Host *` block deliberately carries no IdentityFile entries. Listing every
# key globally alongside `IdentitiesOnly yes` makes ssh offer all of them on
# every connection, which trips the server's MaxAuthTries (commonly 6) and locks
# you out of hosts that previously worked. Keys belong in their own Host blocks,
# which is what configure_per_host_ssh() writes.
cleanup_and_update_ssh_config() {
    local ssh_config="$ssh_keys_location/config"

    # Check if the script is being run as root
    if [ "$(id -u)" -eq 0 ]; then
        error "This script should not be run as root. Please run it as a regular user."
        exit 1
    fi

    # Ensure the .ssh directory exists with correct permissions
    mkdir -p "$ssh_keys_location"
    chmod 700 "$ssh_keys_location"

    # Generate public keys for private keys that lack them.
    local key_file
    while IFS= read -r key_file; do
        if [ ! -f "${key_file}.pub" ]; then
            if [ "$dry_run" = true ]; then
                info "Would generate public key for $key_file"
                continue
            fi
            info "Generating public key for $key_file..."
            if ssh-keygen -y -f "$key_file" > "${key_file}.pub" 2>/dev/null; then
                chmod 644 "${key_file}.pub"
                success "Public key generated: ${key_file}.pub"
            else
                rm -f "${key_file}.pub"
                warn "Could not generate public key for $key_file (it may be passphrase-protected)"
            fi
        fi
    done < <(find "$ssh_keys_location" -type f -name 'id_*' ! -name '*.pub' 2>/dev/null)

    local temp_config
    temp_config=$(make_temp) || { error "Could not create a temporary file."; return 1; }

    # Preserve everything except the managed Host * block.
    if [[ -f "$ssh_config" ]]; then
        awk '
            /^[[:space:]]*Host[[:space:]]+\*[[:space:]]*$/ { in_host_star = 1; next }
            /^[[:space:]]*Host[[:space:]]/ && in_host_star  { in_host_star = 0 }
            !in_host_star { print }
        ' "$ssh_config" > "$temp_config"
        # Collapse any trailing blank lines left behind by the removal.
        printf '%s\n' "$(cat "$temp_config")" > "$temp_config"
    fi

    cat >> "$temp_config" << 'EOF'

Host *
    AddKeysToAgent yes
    HashKnownHosts yes
    GSSAPIAuthentication no
    ServerAliveInterval 60
    ServerAliveCountMax 3
EOF

    # No-op detection: if nothing would change, leave the file alone entirely.
    if [ -f "$ssh_config" ] && cmp -s "$temp_config" "$ssh_config"; then
        rm -f "$temp_config"
        debug "SSH config already normalized; left untouched."
        return 0
    fi

    if [ "$dry_run" = true ]; then
        info "Would update $ssh_config:"
        if command -v diff >/dev/null 2>&1 && [ -f "$ssh_config" ]; then
            diff -u "$ssh_config" "$temp_config" || true
        fi
        rm -f "$temp_config"
        return 0
    fi

    # Back up once per session, before the first modification.
    if [ -f "$ssh_config" ] && [ "$ssh_config_backed_up" = false ]; then
        local backup
        backup="${ssh_config}.bak.$(date +%Y%m%d_%H%M%S)"
        if cp -a "$ssh_config" "$backup"; then
            chmod 600 "$backup"
            ssh_config_backed_up=true
            info "Backed up existing SSH config to $backup"
            audit_log "Backed up $ssh_config to $backup"
        else
            error "Could not back up $ssh_config; refusing to modify it."
            rm -f "$temp_config"
            return 1
        fi
    fi

    info "Updating SSH config..."
    cat "$temp_config" > "$ssh_config"
    rm -f "$temp_config"
    chmod 600 "$ssh_config"

    info "SSH configuration update complete."
    audit_log "Normalized $ssh_config"
}

check_remote_ssh_config() {
    local remote_user="$1"
    local remote_host="$2"
    local remote_port="$3"
    local key_file="$4"

    info "Checking remote SSH configuration..."

    # Ensure we're using the private key, not the public key
    local private_key_file="${key_file%.pub}"

    # Check if the file exists
    if [ ! -f "$private_key_file" ]; then
        error "Private key file $private_key_file does not exist."
        return 1
    fi

    # Ensure correct permissions on the private key
    chmod 600 "$private_key_file"

    # Perform non-sudo operations
    ssh -i "$private_key_file" "$remote_user@$remote_host" -p "$remote_port" bash << 'EOF'
    echo "Checking ~/.ssh permissions..."
    ls -ld ~/.ssh
    if [ -f ~/.ssh/authorized_keys ]; then
        echo "Checking authorized_keys permissions..."
        ls -l ~/.ssh/authorized_keys
        echo "Number of authorized keys:"
        # Count non-comment, non-blank entries. Matching only "^ssh-|^ecdsa-"
        # missed sk- key types and every line carrying options.
        grep -cvE "^[[:space:]]*(#|$)" ~/.ssh/authorized_keys || echo "0"
    else
        echo "No authorized_keys file found"
    fi
EOF

    info "Remote SSH configuration check completed for $remote_host."
}

check_local_ssh_security() {
    local issues_found=false
    local checks=()
    local results=()
    
    info "Preparing to check local SSH security settings..."
    
    # Define checks
    checks=(
        "SSH key permissions"
        "SSH key directory permissions"
        "authorized_keys file permissions"
        "Password authentication"
        "Root login"
        "SSH protocol version"
        "X11 forwarding"
        "MaxAuthTries setting"
        "SSH agent status"
        "Cleanup and Update SSH-config"
        "Known hosts integrity"
        "Weak key detection"
    )
    
    # Initialize results array
    for ((i=0; i<${#checks[@]}; i++)); do
        results[i]=""
    done
    
    # Display checks and ask for confirmation
    echo -e "${CYAN}The following checks will be performed:${NC}"
    for ((i=0; i<${#checks[@]}; i++)); do
        echo -e "${GREEN}$((i+1)).${NC} ${checks[$i]}"
    done
    echo ""
    
    if ! prompt_yes_no "Do you want to proceed with these checks?" "y"; then
        info "Security check cancelled."
        return
    fi
    
    info "Starting local SSH security checks..."
    
    # Perform checks
    check_ssh_key_permissions
    check_ssh_dir_permissions
    check_authorized_keys_permissions
    check_password_authentication
    check_root_login
    check_ssh_protocol
    check_x11_forwarding
    check_max_auth_tries
    check_ssh_agent_status
    if cleanup_and_update_ssh_config; then
        results[9]="PASS"
    else
        results[9]="Could not normalize $ssh_keys_location/config."
    fi
    check_known_hosts_integrity
    check_weak_keys
    
    # Display results
    echo ""
    info "Security check results:"
    for ((i=0; i<${#checks[@]}; i++)); do
        if [[ ${results[$i]} == "PASS" ]]; then
            echo -e "${GREEN}[PASS]${NC} ${checks[$i]}"
        else
            echo -e "${RED}[FAIL]${NC} ${checks[$i]}: ${results[$i]}"
            issues_found=true
        fi
    done
    
    if [ "$issues_found" = false ]; then
        success "No security issues found in local SSH configuration."
    else
        if prompt_yes_no "Would you like to fix these issues?" "y"; then
            fix_local_ssh_security
        fi
    fi
}

# --- Helper functions for individual checks ----------------------------------
#
# Each writes its verdict into results[N] in the caller's scope: "PASS", or a
# human-readable description of the problem.

# Read the *effective* sshd setting for a directive.
#
# Modern distributions ship `Include /etc/ssh/sshd_config.d/*.conf`, so grepping
# the main file alone reports settings that the daemon is not actually using.
# `sshd -T` resolves the full configuration; the grep is only a fallback for
# systems where sshd is absent or refuses to dump.
sshd_effective() {
    local directive="$1" out
    local -a sshd_bin=(sshd /usr/sbin/sshd /usr/local/sbin/sshd)
    local bin
    for bin in "${sshd_bin[@]}"; do
        if command -v "$bin" >/dev/null 2>&1; then
            if out=$("$bin" -T 2>/dev/null); then
                printf '%s\n' "$out" | awk -v d="$(printf '%s' "$directive" | tr '[:upper:]' '[:lower:]')" \
                    'tolower($1) == d { $1=""; sub(/^ /,""); print; found=1 } END { exit !found }' && return 0
            fi
        fi
    done
    # Fallback: last matching uncommented directive in the main config wins here
    # only as an approximation.
    if [ -f "$sshd_config" ]; then
        grep -iE "^[[:space:]]*${directive}[[:space:]]+" "$sshd_config" 2>/dev/null \
            | tail -1 | awk '{ $1=""; sub(/^ /,""); print }' | grep . && return 0
    fi
    return 1
}

# stat(1) is not portable between GNU and BSD; the original chained them with
# `||` inside a pipeline, which silently produced the wrong field on macOS.
file_mode() {
    local target="$1"
    stat -c '%a' "$target" 2>/dev/null && return 0
    stat -f '%OLp' "$target" 2>/dev/null && return 0
    return 1
}

check_ssh_key_permissions() {
    local issue="" key_file mode
    # Process substitution, not a pipeline: a `find | while` loop runs the body
    # in a subshell, so every finding accumulated here used to be discarded and
    # this check always reported PASS.
    while IFS= read -r key_file; do
        mode=$(file_mode "$key_file") || continue
        if [[ "$key_file" == *.pub ]]; then
            [[ "$mode" == "644" ]] || issue+="Public key $key_file has mode $mode (expected 644). "
        else
            [[ "$mode" == "600" ]] || issue+="Private key $key_file has mode $mode (expected 600). "
        fi
    done < <(find "$ssh_keys_location" -type f -name 'id_*' 2>/dev/null)
    results[0]=${issue:-"PASS"}
}

check_ssh_dir_permissions() {
    local perms
    perms=$(file_mode "$ssh_keys_location") || { results[1]="Could not stat $ssh_keys_location."; return; }
    if [[ "$perms" != "700" ]]; then
        results[1]="$ssh_keys_location has incorrect permissions ($perms instead of 700)."
    else
        results[1]="PASS"
    fi
}

check_authorized_keys_permissions() {
    local ak="$ssh_keys_location/authorized_keys" perms
    if [[ -f "$ak" ]]; then
        perms=$(file_mode "$ak") || { results[2]="Could not stat $ak."; return; }
        if [[ "$perms" != "600" ]]; then
            results[2]="authorized_keys file has incorrect permissions ($perms instead of 600)."
        else
            results[2]="PASS"
        fi
    else
        results[2]="PASS"
    fi
}

check_password_authentication() {
    local v
    if v=$(sshd_effective PasswordAuthentication); then
        if [[ "$v" == "yes" ]]; then
            results[3]="Password authentication is enabled."
        else
            results[3]="PASS"
        fi
    else
        results[3]="PASS"
    fi
}

check_root_login() {
    local v
    if v=$(sshd_effective PermitRootLogin); then
        case "$v" in
            yes) results[4]="Root login is permitted." ;;
            *)   results[4]="PASS" ;;
        esac
    else
        results[4]="PASS"
    fi
}

check_ssh_protocol() {
    # SSH-1 has been gone since OpenSSH 7.4; the Protocol directive no longer
    # exists. Nothing to assert.
    results[5]="PASS"
}

check_x11_forwarding() {
    local v
    if v=$(sshd_effective X11Forwarding); then
        if [[ "$v" == "yes" ]]; then
            results[6]="X11 forwarding is enabled."
        else
            results[6]="PASS"
        fi
    else
        results[6]="PASS"
    fi
}

check_max_auth_tries() {
    local v
    if v=$(sshd_effective MaxAuthTries); then
        # Numeric comparison; the old `grep '^MaxAuthTries [1-5]$'` missed
        # trailing whitespace, leading indentation and drop-in overrides.
        if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -le 5 ]; then
            results[7]="PASS"
        else
            results[7]="MaxAuthTries is $v (recommended: 3-5)."
        fi
    else
        results[7]="PASS"
    fi
}

check_ssh_agent_status() {
    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        results[8]="SSH agent is not running"
    else
        results[8]="PASS"
    fi
}

check_known_hosts_integrity() {
    local perms
    if [ -f "$known_hosts_file" ]; then
        if [ ! -s "$known_hosts_file" ]; then
            results[10]="Known hosts file is empty"
            return
        fi
        perms=$(file_mode "$known_hosts_file") || perms=""
        if [ -n "$perms" ] && [ "$perms" != "600" ] && [ "$perms" != "644" ]; then
            results[10]="known_hosts has unusual permissions ($perms)."
        else
            results[10]="PASS"
        fi
    else
        results[10]="Known hosts file does not exist"
    fi
}

check_weak_keys() {
    local weak_keys="" key_file key_info bits type
    # Same subshell trap as check_ssh_key_permissions: this used to always PASS.
    while IFS= read -r key_file; do
        [ -f "${key_file}.pub" ] || continue
        key_info=$(ssh-keygen -lf "${key_file}.pub" 2>/dev/null) || continue
        bits=$(printf '%s' "$key_info" | awk '{print $1}')
        type=$(printf '%s' "$key_info" | awk '{print $NF}' | tr -d '()')
        case "$type" in
            DSA)
                weak_keys+="$key_file is a DSA key (deprecated). " ;;
            RSA)
                [[ "$bits" =~ ^[0-9]+$ ]] && [ "$bits" -lt 2048 ] \
                    && weak_keys+="$key_file is a ${bits}-bit RSA key (minimum 2048). " ;;
        esac
    done < <(find "$ssh_keys_location" -type f -name 'id_*' ! -name '*.pub' 2>/dev/null)
    results[11]=${weak_keys:-"PASS"}
}

fix_local_ssh_security() {
    info "Fixing local SSH security settings..."

    local key_file
    while IFS= read -r key_file; do
        if [[ "$key_file" == *.pub ]]; then
            chmod 644 "$key_file"
        else
            chmod 600 "$key_file"
        fi
    done < <(find "$ssh_keys_location" -type f -name 'id_*' 2>/dev/null)

    chmod 700 "$ssh_keys_location"

    if [[ -f "$ssh_keys_location/authorized_keys" ]]; then
        chmod 600 "$ssh_keys_location/authorized_keys"
    fi

    # Start SSH agent if not running
    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        eval "$(ssh-agent -s)" >/dev/null
        info "SSH agent started."
    fi

    # known_hosts is 600, not 644: it records every host you connect to, which
    # is not something to hand to other local users.
    if [ ! -f "$known_hosts_file" ]; then
        touch "$known_hosts_file"
    fi
    chmod 600 "$known_hosts_file"

    success "File permissions and agent state corrected."

    # --- sshd hardening ------------------------------------------------------
    #
    # This is the part that can lock you out of your own machine, so it is opt
    # in and it verifies key authentication first. The previous implementation
    # gated the whole block behind `sudo -n test`, and `test` with no arguments
    # always exits 1, so none of it ever ran.
    if [ ! -f "$sshd_config" ]; then
        info "No local sshd configuration at $sshd_config; skipping daemon hardening."
        audit_log "Fixed local SSH permissions (no sshd present)"
        return 0
    fi

    echo
    warn "The remaining fixes change this machine's SSH *server* configuration."
    warn "Disabling password authentication while key authentication is not working"
    warn "will lock you out of any remote session to this host."
    if ! prompt_yes_no "Harden the local sshd configuration?" "n"; then
        info "Skipped sshd changes."
        audit_log "Fixed local SSH permissions (sshd hardening declined)"
        return 0
    fi

    if ! sudo -v 2>/dev/null; then
        warn "Cannot modify sshd configuration without sudo access."
        return 1
    fi

    local -a directives=("PermitRootLogin no" "X11Forwarding no" "MaxAuthTries 3")
    if prompt_yes_no "Also disable password authentication? (only if key login already works)" "n"; then
        directives+=("PasswordAuthentication no")
    fi

    local stamp target
    stamp=$(date +%Y%m%d_%H%M%S)

    if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$sshd_config" 2>/dev/null; then
        target="/etc/ssh/sshd_config.d/99-sshkeymanager.conf"
        sudo mkdir -p /etc/ssh/sshd_config.d
        printf '# Managed by sshkeymanager (%s)\n%s\n' "$stamp" "$(printf '%s\n' "${directives[@]}")" \
            | sudo tee "$target" >/dev/null
        sudo chmod 644 "$target"
        info "Wrote $target"
    else
        sudo cp -a "$sshd_config" "${sshd_config}.bak.${stamp}"
        target="$sshd_config"
        local d key
        for d in "${directives[@]}"; do
            key=${d%% *}
            # Comment out any existing setting, then append. A plain sed
            # substitution silently does nothing when the directive is absent.
            sudo sed -i -E "s|^[[:space:]]*#?[[:space:]]*(${key})[[:space:]]+.*|# (replaced by sshkeymanager) &|I" "$sshd_config"
            printf '%s\n' "$d" | sudo tee -a "$sshd_config" >/dev/null
        done
        info "Updated $sshd_config (backup: ${sshd_config}.bak.${stamp})"
    fi

    # Never restart a daemon whose configuration does not parse.
    if ! sudo sshd -t 2>/dev/null && ! sudo /usr/sbin/sshd -t 2>/dev/null; then
        error "sshd rejected the new configuration. Reverting is up to you:"
        error "  backup/drop-in written at: $target"
        audit_log "sshd config rejected after local hardening attempt"
        return 1
    fi

    info "Restarting SSH service..."
    if sudo systemctl restart sshd.service 2>/dev/null \
        || sudo systemctl restart ssh.service 2>/dev/null \
        || sudo service sshd restart 2>/dev/null \
        || sudo service ssh restart 2>/dev/null; then
        success "Local SSH daemon configuration updated and reloaded."
        audit_log "Hardened local sshd configuration"
    else
        warn "Configuration written, but the SSH service could not be restarted."
        audit_log "Hardened local sshd configuration (restart failed)"
    fi
}

display_main_menu() {
    echo -e "\n${GREEN}SSH Key Management Script v2.0${NC}"
    echo -e "${BLUE}═══════════════════════════════${NC}\n"

    echo -e "${CYAN}1. Generate new SSH key pair${NC}"
    echo "   SCENARIO: Fresh setup for SSH key authentication"
    echo "   REQUIRES: Remote host with SSH access (password or existing key)"
    echo ""

    echo -e "${CYAN}2. Import valid key and/or check configuration for remote host${NC}"
    echo "   SCENARIO: Connect to a server with existing SSH key authentication from a new machine"
    echo "   REQUIRES: Existing private key and remote host with your public key already configured"
    echo ""

    echo -e "${CYAN}3. Configure remote host with existing keys${NC}"
    echo "   SCENARIO: Set up an existing local SSH key on a new remote host"
    echo "   REQUIRES: Existing local SSH key and remote host with SSH access (typically password)"
    echo ""

    echo -e "${CYAN}4. Check local SSH security settings${NC}"
    echo "   SCENARIO: Verify and improve local SSH security configuration"
    echo "   PERFORMS: Automated local security checks conforming to best practices"
    echo ""

    echo -e "${CYAN}5. Advanced settings${NC}"
    echo "   Access advanced settings for default configurations and remote host settings"
    echo ""

    echo -e "${CYAN}6. SSH Agent Management${NC}"
    echo "   SCENARIO: Manage SSH agent and loaded keys"
    echo "   PERFORMS: Check agent status, add/remove keys, list loaded keys"
    echo ""

    echo -e "${CYAN}7. Key Rotation${NC}"
    echo "   SCENARIO: Replace old SSH keys with new ones"
    echo "   PERFORMS: Generate new keys and deploy to existing hosts"
    echo ""

    echo -e "${YELLOW}q. Exit${NC}"
    echo ""
}

display_ssh_agent_menu() {
    local agent_option
    
    while true; do
        echo -e "\n${GREEN}SSH Agent Management${NC}"
        echo -e "${BLUE}═════════════════════${NC}\n"
        
        check_ssh_agent
        echo ""
        
        echo -e "${CYAN}1. List loaded keys${NC}"
        echo -e "${CYAN}2. Add key to agent${NC}"
        echo -e "${CYAN}3. Remove key from agent${NC}"
        echo -e "${CYAN}4. Remove all keys from agent${NC}"
        echo -e "${CYAN}5. Lock agent${NC}"
        echo -e "${CYAN}6. Unlock agent${NC}"
        echo ""
        echo -e "${YELLOW}q. Return to main menu${NC}"
        echo ""
        
        if ! read -rp "$(echo -e "${BLUE}Choose an option: ${NC}")" agent_option; then
            echo ""
            return
        fi
        
        case "$agent_option" in
            1)
                info "Keys currently loaded in SSH agent:"
                ssh-add -l || echo "No keys loaded."
                ;;
            2)
                local key_to_add
                if key_to_add=$(select_key_file "private key to add" "$ssh_keys_location/id_rsa" "id_*" "false"); then
                    add_key_to_agent "$key_to_add"
                fi
                ;;
            3)
                info "Select key to remove:"
                ssh-add -l
                local key_to_remove
                key_to_remove=$(prompt_with_default "Enter path to key to remove" "")
                if [ -n "$key_to_remove" ]; then
                    ssh-add -d "$key_to_remove"
                fi
                ;;
            4)
                if prompt_yes_no "Remove all keys from agent?" "n"; then
                    ssh-add -D
                    success "All keys removed from agent."
                fi
                ;;
            5)
                info "Locking SSH agent..."
                ssh-add -x
                ;;
            6)
                info "Unlocking SSH agent..."
                ssh-add -X
                ;;
            q|Q)
                return
                ;;
            *)
                error "Invalid option. Please try again."
                ;;
        esac
        
        echo ""
        read -rp "Press Enter to continue..."
    done
}

display_settings_menu() {
    local settings_option
    while true; do
        echo -e "\n${GREEN}Advanced Settings Menu${NC}"
        echo -e "${BLUE}═════════════════════════${NC}\n"
        echo -e "${CYAN}1. Set global variables${NC}"
        echo -e "${CYAN}2. Backup SSH Keys${NC}"
        echo -e "${CYAN}3. Manipulate remote authorized_keys${NC}"
        echo -e "${CYAN}4. Manage SSH config hosts${NC}"
        echo -e "${CYAN}5. View audit log${NC}"
        echo -e "${CYAN}6. Test SSH connections${NC}"
        echo ""
        echo -e "${YELLOW}q. Return to main menu${NC}"
        echo ""

        if ! read -rp "$(echo -e "${BLUE}Choose an option: ${NC}")" settings_option; then
            echo ""
            return
        fi
        
        case "$settings_option" in
            1)
                display_global_variables_menu
                ;;
            2)
                backup_ssh_keys
                ;;
            3)
                manipulate_remote_pubkeyfile
                ;;
            4)
                manage_ssh_config_hosts
                ;;
            5)
                view_audit_log
                ;;
            6)
                test_connections_menu
                ;;
            q|Q)
                return
                ;;
            *)
                error "Invalid option. Please try again."
                ;;
        esac
    done
}

manage_ssh_config_hosts() {
    local ssh_config="$ssh_keys_location/config"
    
    if [ ! -f "$ssh_config" ]; then
        warn "No SSH config file found."
        if prompt_yes_no "Create one?" "y"; then
            touch "$ssh_config"
            chmod 600 "$ssh_config"
        else
            return
        fi
    fi
    
    echo -e "\n${CYAN}Current SSH config hosts:${NC}"
    echo -e "${BLUE}════════════════════════${NC}"
    
    # Extract and display hosts
    list_config_hosts | awk '{print NR ". " $0}'
    
    echo -e "\n${CYAN}Options:${NC}"
    echo "1. Add new host"
    echo "2. Edit existing host"
    echo "3. Remove host"
    echo "4. View full config"
    
    read -rp "Choose an option: " config_option
    
    case "$config_option" in
        1)
            local new_host
            new_host=$(prompt_with_default "Enter hostname" "")
            local new_user
            new_user=$(prompt_with_default "Enter username" "$default_remote_user")
            local new_port
            new_port=$(prompt_with_default "Enter port" "22")
            local key_path
            if [ -z "$new_host" ]; then
                error "A hostname is required."
                return 1
            fi
            if ! key_path=$(select_key_file "private key for this host" "$ssh_keys_location/id_rsa" "id_*" "false"); then
                error "No key selected; host not added."
                return 1
            fi

            configure_per_host_ssh "$new_host" "$new_user" "$new_port" "$key_path"
            ;;
        2)
            # Edit existing host - simplified version
            warn "Manual editing required. Opening config file..."
            ${EDITOR:-nano} "$ssh_config"
            ;;
        3)
            # Remove host
            local host_to_remove
            host_to_remove=$(prompt_with_default "Enter host to remove" "")
            if [ -z "$host_to_remove" ]; then
                error "No host given."
                return 1
            fi
            if ! config_has_host "$ssh_config" "$host_to_remove"; then
                error "Host '$host_to_remove' is not declared in $ssh_config."
                return 1
            fi
            # Timestamped so a second removal cannot overwrite the only backup.
            local ak_backup
            ak_backup="${ssh_config}.bak.$(date +%Y%m%d_%H%M%S)"
            cp -a "$ssh_config" "$ak_backup" && chmod 600 "$ak_backup"
            local removed
            removed=$(make_temp) || { error "Could not create a temporary file."; return 1; }
            remove_host_block "$ssh_config" "$host_to_remove" > "$removed"
            cat "$removed" > "$ssh_config"
            rm -f "$removed"
            chmod 600 "$ssh_config"
            success "Host $host_to_remove removed (backup: $ak_backup)."
            audit_log "Removed host $host_to_remove from $ssh_config"
            ;;
        4)
            less "$ssh_config"
            ;;
    esac
}

view_audit_log() {
    if [ ! -f "$audit_log" ]; then
        warn "No audit log found."
        return
    fi
    
    echo -e "\n${CYAN}SSH Key Operations Audit Log:${NC}"
    echo -e "${BLUE}═════════════════════════════${NC}"
    
    # Show last 20 entries
    tail -20 "$audit_log"
    
    echo ""
    if prompt_yes_no "View full log?" "n"; then
        less "$audit_log"
    fi
}

test_connections_menu() {
    echo -e "\n${CYAN}Test SSH Connections${NC}"
    echo -e "${BLUE}═══════════════════${NC}\n"
    
    echo "1. Test specific connection"
    echo "2. Test all configured hosts"
    
    read -rp "Choose an option: " test_option
    
    case "$test_option" in
        1)
            prompt_remote_details || return 0
            local key_path
            if ! key_path=$(select_key_file "private key to test" "$ssh_keys_location/id_rsa" "id_*" "false"); then
                error "No key selected."
                return 1
            fi
            test_ssh_connection "$remote_user" "$remote_host" "$remote_port" "$key_path" || true
            ;;
        2)
            local ssh_config="$ssh_keys_location/config"
            if [ -f "$ssh_config" ]; then
                local hosts=()
                mapfile -t hosts < <(list_config_hosts)
                if [ ${#hosts[@]} -eq 0 ]; then
                    warn "No concrete hosts are configured."
                    return 0
                fi
                for host in "${hosts[@]}"; do
                    info "Testing connection to $host..."
                    if ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" "echo 'Connection successful'" >/dev/null 2>&1; then
                        success "$host: OK"
                    else
                        error "$host: FAILED"
                    fi
                done
            else
                warn "No SSH config file found."
            fi
            ;;
    esac
}

display_global_variables_menu() {
    local var_option
    while true; do
        echo -e "\n${GREEN}Global Variables Menu${NC}"
        echo -e "${BLUE}═════════════════════════${NC}\n"
        echo -e "${CYAN}1. SSH key location${NC}"
        echo "   CURRENT: $ssh_keys_location"
        echo -e "${CYAN}2. SSH daemon config location${NC}"
        echo "   CURRENT: $sshd_config"
        echo -e "${CYAN}3. Agnostic authorized keys${NC}"
        echo "   CURRENT: $agnostic_authorized_keys"
        echo -e "${CYAN}4. Backup directory${NC}"
        echo "   CURRENT: $backup_root"
        echo -e "${CYAN}5. Default SSH Port${NC}"
        echo "   CURRENT: $default_ssh_port"
        echo -e "${CYAN}6. Audit log location${NC}"
        echo "   CURRENT: $audit_log"
        echo ""
        echo -e "${YELLOW}q. Return to Advanced Settings Menu${NC}"
        echo ""

        if ! read -rp "$(echo -e "${BLUE}Choose a variable to modify: ${NC}")" var_option; then
            echo ""
            return
        fi
        
        case "$var_option" in
            1)
                read -rp "Enter new SSH key location: " new_location
                if [ -d "$new_location" ]; then
                    # Normalized so that "$ssh_keys_location/$name" can never
                    # become a doubled slash, and a value entered without a
                    # trailing slash can never silently concatenate.
                    ssh_keys_location=$(normalize_dir "$new_location")
                    known_hosts_file="$ssh_keys_location/known_hosts"
                    success "SSH key location updated to $ssh_keys_location."
                else
                    error "Invalid directory. Please try again."
                fi
                ;;
            2)
                read -rp "Enter new SSH daemon config location: " new_sshd_config
                if [ -f "$new_sshd_config" ]; then
                    sshd_config="$new_sshd_config"
                    success "SSH daemon config location updated."
                else
                    error "File not found. Please try again."
                fi
                ;;
            3)
                if prompt_yes_no "Enable agnostic authorized keys?" "$agnostic_authorized_keys"; then
                    agnostic_authorized_keys=true
                else
                    agnostic_authorized_keys=false
                fi
                success "Agnostic authorized keys setting updated."
                ;;
            4)
                read -rp "Enter new backup directory: " new_pattern
                if [ -n "$new_pattern" ]; then
                    backup_root=$(normalize_dir "$new_pattern")
                    backup_dir="$backup_root/ssh_backup_$(date +%Y%m%d_%H%M%S)"
                    success "Backup directory updated to $backup_root."
                else
                    error "Backup directory cannot be empty."
                fi
                ;;
            5)
                read -rp "Enter new default SSH Port: " new_port
                if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
                    default_ssh_port="$new_port"
                    success "Default SSH Port updated."
                else
                    error "Port must be a number between 1 and 65535."
                fi
                ;;
            6)
                read -rp "Enter new audit log location: " new_audit
                if [ -n "$new_audit" ]; then
                    audit_log="$new_audit"
                    success "Audit log location updated."
                else
                    error "Audit log location cannot be empty."
                fi
                ;;
            q|Q)
                return
                ;;
            *)
                error "Invalid option. Please try again."
                ;;
        esac
    done
}

backup_ssh_keys() {
    # backup_root, not backup_dir: backup_dir already ends in a timestamp, so
    # using it here produced ~/.sshbackups/ssh_backup_<ts>/ssh_backup_<ts>.
    local default_backup_dir="$backup_root"
    local chosen_backup_dir
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")

    echo -e "\n${CYAN}SSH Key Backup${NC}"
    echo -e "${BLUE}═════════════════════════${NC}\n"

    echo -e "Default backup directory: ${YELLOW}$default_backup_dir${NC}"
    if prompt_yes_no "Use default backup directory?" "y"; then
        chosen_backup_dir="$default_backup_dir"
    else
        read -rp "Enter the desired backup directory path: " chosen_backup_dir
    fi

    # Ensure the chosen directory exists
    mkdir -p "$chosen_backup_dir"

    # Create a subdirectory with timestamp
    local backup_path="${chosen_backup_dir}/ssh_backup_${timestamp}"
    mkdir -p "$backup_path"

    # Copy SSH directory contents to the backup location
    if cp -a "$ssh_keys_location/." "$backup_path/" 2>/dev/null; then
        # Set appropriate permissions for the backed-up files
        chmod 700 "$backup_path"
        find "$backup_path" -type f -exec chmod 600 {} \;
        find "$backup_path" -name "*.pub" -type f -exec chmod 644 {} \;

        # Create a manifest file
        {
            echo "SSH Keys Backup Manifest"
            echo "Backup Date: $(date)"
            echo "Source: $ssh_keys_location"
            printf '\nBackup Contents:\n'
            ls -la "$backup_path"
        } > "$backup_path/MANIFEST.txt"

        success "SSH keys and configurations backed up successfully to: $backup_path"
        audit_log "Created backup in $backup_path"
    else
        error "Failed to create backup. Please check permissions and try again."
    fi
}

manipulate_remote_pubkeyfile() {
    local remote_host remote_user remote_port remote_file local_file

    # Step 1: Get remote details and download the file
    prompt_remote_details || return 0

    # Ask the remote host where the account's home actually is. Hardcoding
    # /home/<user> is wrong for root, for macOS (/Users), and for any account
    # with a non-default home.
    if ! remote_file=$(ssh -o BatchMode=no "$remote_user@$remote_host" -p "$remote_port" \
        'printf "%s/.ssh/authorized_keys" "$HOME"' 2>/dev/null) || [ -z "$remote_file" ]; then
        warn "Could not determine the remote home directory; falling back to ~/.ssh/authorized_keys."
        remote_file='.ssh/authorized_keys'
    fi

    local_file=$(make_temp) || { error "Could not create a temporary file."; return 1; }

    info "Downloading $remote_file from $remote_host..."
    if ! scp -P "$remote_port" "$remote_user@$remote_host:$remote_file" "$local_file" 2>/dev/null; then
        warn "Failed to download the remote file. It might not exist."
        if prompt_yes_no "Create a new authorized_keys file?" "y"; then
            touch "$local_file"
        else
            rm -f "$local_file"
            return 1
        fi
    fi

    # Create a backup
    cp "$local_file" "${local_file}.backup"

    # Main loop for file manipulation
    while true; do
        display_file_contents "$local_file"
        echo -e "${CYAN}Commands:${NC}"
        echo -e "  ${YELLOW}<line#>${NC} - Edit line"
        echo -e "  ${YELLOW}d<line#>${NC} - Delete line (e.g., d3)"
        echo -e "  ${YELLOW}n${NC} - Add new line"
        echo -e "  ${YELLOW}v${NC} - Validate all keys"
        echo -e "  ${YELLOW}s${NC} - Sort keys"
        echo -e "  ${YELLOW}Enter${NC} - Save and upload"
        echo -e "  ${YELLOW}q${NC} - Quit without saving"
        
        if ! read -rp "Your choice: " user_input; then
            warn "Input closed; discarding changes."
            rm -f "$local_file" "${local_file}.backup"
            return 1
        fi

        case "$user_input" in
            "")
                break
                ;;
            q|Q)
                warn "Discarding changes."
                rm -f "$local_file" "${local_file}.backup"
                return
                ;;
            v|V)
                validate_authorized_keys "$local_file"
                ;;
            s|S)
                sort_authorized_keys "$local_file"
                ;;
            n|N)
                append_new_line "$local_file"
                ;;
            d*)
                if [[ "$user_input" =~ ^d([0-9]+)$ ]]; then
                    delete_line "${BASH_REMATCH[1]}" "$local_file"
                else
                    error "Invalid delete command. Use format: d<line_number>"
                fi
                ;;
            *)
                if [[ "$user_input" =~ ^[0-9]+$ ]]; then
                    edit_line "$user_input" "$local_file"
                else
                    error "Invalid input. Please try again."
                fi
                ;;
        esac
    done

    # Show diff before uploading
    if command -v diff >/dev/null 2>&1; then
        echo -e "\n${CYAN}Changes to be applied:${NC}"
        diff -u "${local_file}.backup" "$local_file" || true
    fi

    if prompt_yes_no "Upload the modified file?" "y"; then
        if scp -P "$remote_port" "$local_file" "$remote_user@$remote_host:$remote_file"; then
            success "File successfully updated on the remote host."
            audit_log "Updated authorized_keys on $remote_user@$remote_host:$remote_port"
        else
            error "Failed to upload the updated file to the remote host."
        fi
    fi

    rm -f "$local_file" "${local_file}.backup"
}

validate_authorized_keys() {
    local file="$1"
    local line_num=1
    local errors=0
    
    echo -e "\n${CYAN}Validating authorized_keys entries:${NC}"
    
    while IFS= read -r line; do
        if [ -z "$line" ] || [[ "$line" =~ ^[[:space:]]*# ]]; then
            ((line_num++))
            continue
        fi
        
        # A predictable path under a world-writable /tmp is a symlink-attack
        # target; mktemp gives an unpredictable name with safe permissions.
        local probe
        probe=$(make_temp) || { error "Could not create a temporary file."; return 1; }
        printf %s\\n "$line" > "$probe"

        if ssh-keygen -lf "$probe" >/dev/null 2>&1; then
            echo -e "${GREEN}Line $line_num: Valid${NC}"
        else
            echo -e "${RED}Line $line_num: Invalid key format${NC}"
            ((errors++))
        fi

        rm -f "$probe"
        ((line_num++))
    done < "$file"
    
    if [ $errors -eq 0 ]; then
        success "All keys are valid."
    else
        warn "Found $errors invalid entries."
    fi
}

sort_authorized_keys() {
    local file="$1"
    local temp_file
    temp_file=$(make_temp) || { error "Could not create a temporary file."; return 1; }
    
    # Sort by key type, then by the key data
    sort -k1,1 -k2,2 "$file" > "$temp_file"
    mv "$temp_file" "$file"
    
    success "Keys sorted."
}

edit_line() {
    local line_number="$1"
    local file="$2"

    if [ "$line_number" -eq 0 ] || [ "$line_number" -gt "$(wc -l < "$file")" ]; then
        error "Invalid line number. Please try again."
        return
    fi

    current_line=$(sed "${line_number}q;d" "$file")
    
    # Parse the line more carefully
    local options=""
    local key_type=""
    local key_data=""
    local comment=""
    
    # Check if line starts with options (not ssh-* or ecdsa-*)
    if [[ ! "$current_line" =~ ^(ssh-|ecdsa-) ]]; then
        # Extract options (everything before the key type)
        options=$(echo "$current_line" | sed -n 's/^\(.*\)\s\+\(ssh-[^ ]*\|ecdsa-[^ ]*\)\s\+.*/\1/p')
        # Extract the rest
        local key_part
        key_part=$(echo "$current_line" | sed -n 's/^.*\(\(ssh-[^ ]*\|ecdsa-[^ ]*\)\s\+.*\)/\1/p')
        key_type=$(echo "$key_part" | awk '{print $1}')
        key_data=$(echo "$key_part" | awk '{print $2}')
        comment=$(echo "$key_part" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}' | sed 's/ *$//')
    else
        # No options, line starts with key type
        key_type=$(echo "$current_line" | awk '{print $1}')
        key_data=$(echo "$current_line" | awk '{print $2}')
        comment=$(echo "$current_line" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}' | sed 's/ *$//')
    fi

    while true; do
        echo -e "\n${CYAN}Current values:${NC}"
        echo -e "${YELLOW}1. Key Type:${NC} $key_type"
        echo -e "${YELLOW}2. Key Data:${NC} ${key_data:0:50}..."
        echo -e "${YELLOW}3. Comment:${NC} $comment"
        echo -e "${YELLOW}4. Options:${NC} ${options:-None}"
        echo -e "${YELLOW}5. Manage Options${NC}"
        echo -e "Press Enter to finish editing this line"

        if ! read -rp "Select a value to edit (1-5) or press Enter to finish: " value_choice; then
            break
        fi

        case $value_choice in
            1)
                echo "Select key type:"
                echo "1. ssh-rsa"
                echo "2. ssh-ed25519"
                echo "3. ecdsa-sha2-nistp256"
                echo "4. ssh-ed25519-sk"
                echo "5. ecdsa-sha2-nistp256-sk"
                read -rp "Choice: " kt_choice
                case $kt_choice in
                    1) key_type="ssh-rsa";;
                    2) key_type="ssh-ed25519";;
                    3) key_type="ecdsa-sha2-nistp256";;
                    4) key_type="ssh-ed25519-sk";;
                    5) key_type="ecdsa-sha2-nistp256-sk";;
                esac
                ;;
            2)
                read -rp "Enter new key data: " key_data
                ;;
            3)
                read -rp "Enter new comment: " comment
                ;;
            4)
                read -rp "Enter new options (or press Enter for none): " options
                ;;
            5)
                manage_key_options
                ;;
            "")
                break
                ;;
            *)
                error "Invalid choice. Please try again."
                continue
                ;;
        esac

        # Reconstruct the line
        if [ -n "$options" ]; then
            new_line="$options $key_type $key_data"
        else
            new_line="$key_type $key_data"
        fi
        
        if [ -n "$comment" ]; then
            new_line="$new_line $comment"
        fi
        
        # The replacement is passed through the environment rather than
        # interpolated into a sed script: a key comment containing "|" broke
        # the old delimiter, and "&" was expanded as a back-reference.
        local rewritten
        rewritten=$(make_temp) || { error "Could not create a temporary file."; return 1; }
        if NEW_LINE="$new_line" awk -v n="$line_number" \
            'NR == n { print ENVIRON["NEW_LINE"]; next } { print }' "$file" > "$rewritten"; then
            cat "$rewritten" > "$file"
            success "Line updated."
        else
            error "Failed to rewrite line $line_number."
        fi
        rm -f "$rewritten"
    done
}

delete_line() {
    local line_number="$1"
    local file="$2"

    if [ "$line_number" -eq 0 ] || [ "$line_number" -gt "$(wc -l < "$file")" ]; then
        error "Invalid line number. Please try again."
        return
    fi

    sed -i "${line_number}d" "$file"
    success "Line $line_number deleted."
}

append_new_line() {
    local file="$1"
    local new_key_type new_key_data new_comment new_options

    echo -e "\n${CYAN}Add new authorized key:${NC}"
    
    # Option to paste full key
    if prompt_yes_no "Paste a complete public key line?" "y"; then
        echo "Paste the public key line and press Enter:"
        read -r new_line
        echo "$new_line" >> "$file"
        success "New key added."
        return
    fi

    # Manual entry
    echo "Select key type:"
    echo "1. ssh-rsa"
    echo "2. ssh-ed25519"
    echo "3. ecdsa-sha2-nistp256"
    read -rp "Choice: " kt_choice
    
    case $kt_choice in
        1) new_key_type="ssh-rsa";;
        2) new_key_type="ssh-ed25519";;
        3) new_key_type="ecdsa-sha2-nistp256";;
        *) error "Invalid choice"; return;;
    esac

    read -rp "Enter key data: " new_key_data
    read -rp "Enter comment (optional): " new_comment
    read -rp "Enter options (press Enter for none): " new_options

    if [ -n "$new_options" ]; then
        echo "$new_options $new_key_type $new_key_data $new_comment" >> "$file"
    else
        echo "$new_key_type $new_key_data $new_comment" >> "$file"
    fi
    
    success "New line appended."
}

# Function to toggle SSH key options
toggle_option() {
    local option="$1"
    # Match on whole words: "no-port-forwarding" is a substring of nothing else
    # today, but a plain substring test would mangle any future option that
    # shares a prefix.
    if [[ " $options " == *" $option "* ]]; then
        options=" $options "
        options="${options// $option / }"
        echo "$option removed."
    else
        options="$option $options"
        echo "$option added."
    fi
    # Collapse whitespace without letting the shell glob or split the value.
    options=$(printf '%s' "$options" | tr -s '[:space:]' ' ')
    options="${options#"${options%%[![:space:]]*}"}"
    options="${options%"${options##*[![:space:]]}"}"
}

manage_key_options() {
    local option_choice
    while true; do
        echo -e "\n${CYAN}Manage Key Options:${NC}"
        echo -e "${YELLOW}1. Set/Update command restriction${NC}"
        echo -e "   ${WHITE}Restricts the key to executing only a specific command${NC}"
        echo -e "   ${WHITE}Example: command=\"/usr/bin/rsync --server\"${NC}"
        
        echo -e "\n${YELLOW}2. Set/Update from (source restriction)${NC}"
        echo -e "   ${WHITE}Restricts the key to specific IPs, users, or hosts${NC}"
        echo -e "   ${WHITE}Example: from=\"192.168.1.0/24,user=john,host=*.example.com\"${NC}"
        
        echo -e "\n${YELLOW}3. Set/Update environment variable${NC}"
        echo -e "   ${WHITE}Sets environment variables when the key is used${NC}"
        echo -e "   ${WHITE}Example: environment=\"DEBUG=1\"${NC}"
        
        echo -e "\n${YELLOW}4. Toggle no-agent-forwarding${NC}"
        echo -e "\n${YELLOW}5. Toggle no-port-forwarding${NC}"
        echo -e "\n${YELLOW}6. Toggle no-X11-forwarding${NC}"
        echo -e "\n${YELLOW}7. Toggle no-pty${NC}"
        echo -e "\n${YELLOW}8. Remove all options${NC}"
        
        echo -e "\n${GREEN}Current options:${NC} ${options:-None}"
        
        echo -e "\n${YELLOW}Enter your choice (1-8) or press Enter to finish:${NC}"
        if ! read -rp "" option_choice; then
            break
        fi

        case $option_choice in
            1)
                read -rp "Enter command restriction (or press Enter to remove): " cmd
                options=$(printf '%s' "$options" | sed 's/command="[^"]*"//g')
                [ -n "$cmd" ] && options="command=\"$cmd\" $options"
                ;;
            2)
                echo "Enter restriction type:"
                echo "1. IP address/range"
                echo "2. Username"
                echo "3. Hostname"
                read -rp "Choice: " from_type

                from_value=""
                case $from_type in
                    1) read -rp "Enter IP restriction: " from_value ;;
                    2) read -rp "Enter username: " from_value
                       [ -n "$from_value" ] && from_value="user=$from_value" ;;
                    3) read -rp "Enter hostname pattern: " from_value
                       [ -n "$from_value" ] && from_value="host=$from_value" ;;
                    *) error "Invalid choice."; continue ;;
                esac
                # sshd accepts only one from= per key; appending a second one
                # makes the whole entry invalid, so replace any existing value.
                options=$(printf '%s' "$options" | sed 's/from="[^"]*"//g')
                [ -n "$from_value" ] && options="from=\"$from_value\" $options"
                ;;
            3)
                read -rp "Enter environment variable (NAME=value): " env_var
                options=$(printf '%s' "$options" | sed 's/environment="[^"]*"//g')
                [ -n "$env_var" ] && options="environment=\"$env_var\" $options"
                ;;
            4)
                toggle_option "no-agent-forwarding"
                ;;
            5)
                toggle_option "no-port-forwarding"
                ;;
            6)
                toggle_option "no-X11-forwarding"
                ;;
            7)
                toggle_option "no-pty"
                ;;
            8)
                options=""
                echo "All options removed."
                ;;
            "")
                break
                ;;
            *)
                error "Invalid choice. Please try again."
                ;;
        esac
        
        # Clean up extra spaces
        options=$(printf '%s' "$options" | tr -s '[:space:]' ' ')
        options="${options#"${options%%[![:space:]]*}"}"
        options="${options%"${options##*[![:space:]]}"}"
    done
}

display_file_contents() {
    local file="$1"
    echo -e "\n${CYAN}File Contents:${NC}"
    echo -e "${BLUE}═════════════════════════${NC}"
    
    if [ -s "$file" ]; then
        local line_count=1
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Truncate long lines for display
            if [ ${#line} -gt 80 ]; then
                printf "${WHITE}%-5s${NC} %.77s...\n" "$line_count:" "$line"
            else
                printf "${WHITE}%-5s${NC} %s\n" "$line_count:" "$line"
            fi
            ((line_count++))
        done < "$file"
    else
        echo "(Empty file)"
    fi
    
    echo -e "${BLUE}═════════════════════════${NC}\n"
}

# --- Entry point -------------------------------------------------------------
# Guard the interactive session so the file can be sourced (by tests, or to
# reuse a single function) without launching the menu.
# shellcheck disable=SC2317  # reached only when the file is sourced
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    return 0
fi

# Initialize audit log if it doesn't exist
if [ ! -f "$audit_log" ]; then
    touch "$audit_log"
    chmod 600 "$audit_log"
fi

# Show audit mode entries if requested
if [ "$audit_mode" = true ]; then
    view_audit_log
    exit 0
fi

# Main script execution
info "SSH Key Manager v2.0 started"
audit_log "Script started by $(whoami)"

# Ensure .ssh directory exists with correct permissions
mkdir -p "$ssh_keys_location"
chmod 700 "$ssh_keys_location"

# Check for SSH agent on startup
check_ssh_agent

# Main menu loop
while true; do
    # Normalize ~/.ssh/config each time round. This is a no-op when the file is
    # already in shape, backs the file up before its first modification, and is
    # skipped entirely under --dry-run. Output is no longer discarded, so a
    # failure here is visible rather than silent.
    if [ "$dry_run" != true ]; then
        cleanup_and_update_ssh_config || warn "Could not normalize $ssh_keys_location/config."
    fi

    display_main_menu
    if ! read -rp "$(echo -e "${BLUE}Choose an option (1-7/q): ${NC}")" option; then
        echo ""
        info "Input closed. Exiting."
        audit_log "Script exited on EOF"
        exit 0
    fi
    echo ""

    case "$option" in
        1)
            execute_or_simulate generate_ssh_key
            ;;
        2)
            execute_or_simulate import_private_key
            ;;
        3)
            execute_or_simulate copy_pubkey_to_hosts
            ;;
        4)
            execute_or_simulate check_local_ssh_security
            ;;
        5)
            display_settings_menu  # Note: removed execute_or_simulate here as it contains interactive menus
            ;;
        6)
            display_ssh_agent_menu
            ;;
        7)
            execute_or_simulate rotate_ssh_key
            ;;
        q|Q)
            info "Exiting script. Goodbye!"
            audit_log "Script exited normally"
            exit 0
            ;;
        *)
            error "Invalid option. Please try again."
            ;;
    esac

    echo ""
done
