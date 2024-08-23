#!/usr/bin/env bash

# SSH Key Management Script
# Version: 1.1
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
#
# Usage:
#   ./ssh_key_manager.sh [options]
#
# Options:
#   -b, --backup     Create a backup of SSH configurations before making changes
#   -d, --dry-run    Run in dry-run mode (show changes without applying them)
#   -h, --help       Display this help message
#
# Requirements:
# - Bash 4.0 or later
# - OpenSSH client
# - sudo privileges (for some operations)
#
# Note: This script modifies system files and SSH configurations. Use with caution.

# Exit on error
set -e
# debug
#set -x

# Configurable via menu globals
sshd_config="/etc/ssh/sshd_config"
ssh_keys_location="$HOME/.ssh/"
backup_dir="$HOME/.ssh/backups/.ssh_backup_$(date +%Y%m%d_%H%M%S)"
agnostic_authorized_keys=true

# Global variables
dry_run=false
override_security=false

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display help message
display_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -b, --backup               Create a backup of SSH configurations before making changes"
    echo "  -d, --dry-run              Run in dry-run mode (show changes without applying them)"
    echo "  -h, --help                 Display this help message"
    echo "  -o. --override-security    Overrides mandatory key passphrase for permissive keys"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--backup)
            mkdir -p "$backup_dir"
            cp -r "$ssh_keys_location" "$backup_dir"
            info "Backup created in $backup_dir"
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
            ;;
        *)
            error "Unknown option: $1"
            display_help
            ;;
    esac
done

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

# Function to execute or simulate command based on dry-run mode
execute_or_simulate() {
    if [ "$dry_run" = true ]; then
        echo "Would execute: $@"
    else
        "$@"
    fi
}


# Function to prompt user with a default value
prompt_with_default() {
    local prompt="$1"
    local default="$2"
    read -p "$(echo -e "${BLUE}$prompt${NC} [$default]: ")" value
    echo "${value:-$default}"
}

# Helper function for yes/no prompts
prompt_yes_no() {
    local prompt="$1"
    local default="$2"
    local answer

    while true; do
        read -p "$(echo -e "${YELLOW}$prompt${NC} [y/n] ($default): ")" answer
        answer=${answer:-$default}
        case $answer in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) warn "Please answer yes or no.";;
        esac
    done
}

# New shared function for prompting remote host and user
prompt_remote_details() {
    local remote_host=$(prompt_with_default "Enter remote host" "1.2.3.4")
    local remote_user=$(prompt_with_default "Enter remote user" "$USER")
    echo "$remote_host $remote_user"
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
    
    if prompt_yes_no "Do you want to configure this key for a remote host? (Recommended)" "y"; then
        check_remote=true
        read remote_host remote_user <<< $(prompt_remote_details)
        copy_key_to_remote "$key_name" "$remote_host" "$remote_user"
        success "Initial SSH login via password successful!"
        configure_remote_ssh "$remote_user" "$remote_host"
    fi
    configure_local_ssh "$key_name"
    if [ "$check_remote" = true ]; then
        check_remote_ssh_config "$remote_user" "$remote_host" "$ssh_keys_location$key_name"
    fi
    display_key_generation_summary "$key_type" "$use_passphrase"
}

# Helper functions for generate_ssh_key
select_key_type() {
    echo -e "${CYAN}Select Key Type:${NC}"
    echo "1. Ed25519 (Recommended)"
    echo "2. RSA"
    echo "3. ECDSA"
    echo "4. FIDO2 Hardware Key (Ed25519-SK or ECDSA-SK)"
    
    while true; do
        read -p "Enter your choice (1-4): " key_type_choice
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
    read -p "Enter your choice (1-2): " hw_key_choice
    case $hw_key_choice in
        1) key_type="ed25519-sk";;
        2) key_type="ecdsa-sk";;
        *) error "Invalid choice. Please try again."; select_hardware_key_type;;
    esac
}

select_key_size() {
    if [ "$key_type" == "rsa" ] || [ "$key_type" == "ecdsa" ]; then
        echo -e "\n${CYAN}Select Key Size:${NC}"
        if [ "$key_type" == "rsa" ]; then
            echo "1. 2048 bits (Minimum recommended)"
            echo "2. 4096 bits (More secure, but slower)"
        else  # ECDSA
            echo "1. 256 bits (Recommended)"
            echo "2. 384 bits (More secure, but slower)"
            echo "3. 521 bits (Most secure, slowest)"
        fi
        
        while true; do
            read -p "Enter your choice: " key_size_choice
            case $key_size_choice in
                1) key_size=$([ "$key_type" == "rsa" ] && echo "2048" || echo "256"); break;;
                2) key_size=$([ "$key_type" == "rsa" ] && echo "4096" || echo "384"); break;;
                3) [ "$key_type" == "ecdsa" ] && { key_size="521"; break; } || error "Invalid choice for RSA. Please try again.";;
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
            info "No passphrase will be set. Your key will not be password-protected - this is not a problem if you don't lose your key."
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
                info "No passphrase will be set. Your key will not be password-protected - this is not a problem if you don't lose your key."
            fi
        fi
    fi
}

select_key_name() {
    echo -e "\n${CYAN}Enter Key Name:${NC}"
    warn "The name should begin with 'id_' to be compatible with this script."
    echo "Example: id_${key_type}_username"
    while true; do
        read -p "Key name: " key_name
        if [[ $key_name == id_* ]]; then
            break
        else
            error "Key name must start with 'id_'. Please try again."
        fi
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

    chmod 600 "$ssh_keys_location$key_name"
    chmod 644 "$ssh_keys_location$key_name.pub"
}

generate_hardware_key() {
    local key_type="$1"
    local key_name="$2"
    local use_passphrase="$3"

    echo "Please insert your hardware security key and follow any prompts."
    if ! ssh-keygen -t $key_type -f "$ssh_keys_location$key_name" ${use_passphrase:+-N ""}; then
        error "Failed to generate hardware-backed key. This might be due to missing libfido2 library."
        echo "For Debian-based systems, try installing it with:"
        echo "sudo apt update && sudo apt install libfido2-1"
        echo "For Arch-based systems, use:"
        echo "sudo pacman -Sy libfido2"
        echo "After installing, please try again."
        return 1
    fi
}

generate_ed25519_key() {
    local key_name="$1"
    local use_passphrase="$2"

    if [ "$use_passphrase" = true ]; then
        ssh-keygen -t ed25519 -f "$ssh_keys_location$key_name"
    else
        ssh-keygen -t ed25519 -f "$ssh_keys_location$key_name" -N ""
    fi
}

generate_standard_key() {
    local key_type="$1"
    local key_size="$2"
    local key_name="$3"
    local use_passphrase="$4"

    ssh-keygen -t $key_type -b $key_size -f "$ssh_keys_location$key_name" ${use_passphrase:+-N ""}
}

copy_key_to_remote() {
    local key_name="$1"
    local remote_host="$2"
    local remote_user="$3"

    info "Copying $ssh_keys_location$key_name.pub to $remote_host..."

    if [ "$agnostic_authorized_keys" = false ]; then
        info "Running ssh-copy-id -f -i \"$ssh_keys_location$key_name.pub\" \"$remote_user@$remote_host\""
        ssh-copy-id -f -i "$ssh_keys_location$key_name.pub" "$remote_user@$remote_host"
    else
        info "Adding key to authorized_keys without user/hostname restrictions"
        # Read the public key
        local pubkey=$(cat "$ssh_keys_location$key_name.pub")
        # Append the key to the remote authorized_keys file
        ssh "$remote_user@$remote_host" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '$pubkey' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    fi     
}

display_key_generation_summary() {
    local key_type="$1"
    local use_passphrase="$2"

    success "SSH key pair generated and configured successfully."

    if [[ "$key_type" == *"-sk" ]]; then
        echo -e "\n${YELLOW}Note:${NC} You've generated a hardware-backed SSH key. Remember to have your security key available when using this SSH key."
    fi

    if [ "$use_passphrase" = true ]; then
        echo -e "\n${YELLOW}Note:${NC} You've set a passphrase for your SSH key. Remember to enter this passphrase when using the key, or consider using ssh-agent to manage your keys."
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

    local private_key_path=$(select_key_file "private" "$ssh_keys_location/id_rsa" "id_*" "false")
    if [ $? -ne 0 ]; then
        error "Failed to select a valid private key. Exiting."
        return 1
    fi
    
    key_name=$(basename "$private_key_path")
    destination_path="$ssh_keys_location$key_name"
    
    copy_and_set_permissions "$private_key_path" "$destination_path"
    
    cleanup_and_update_ssh_config
    configure_local_ssh "$key_name"
    
    while true; do
        read remote_host remote_user <<< $(prompt_remote_details)
        
        if [ -z "$remote_host" ]; then
            break
        fi
        
        configure_remote_ssh "$remote_user" "$remote_host"
        check_remote_ssh_config "$remote_user" "$remote_host" "$destination_path"
        
        if ! prompt_yes_no "Do you want to configure this key for another host?" "n"; then
            break
        fi
    done
    if prompt_yes_no "Do you want to perform some checks for your local ssh security?" "n"; then
                check_local_ssh_security
    fi
}

# Updated function to copy public key to additional hosts
copy_pubkey_to_hosts() {
    local pubkey_path

    pubkey_path=$(select_key_file "public" "$ssh_keys_location/id_*.pub" "id_*.pub" "true")
    key_name=$(basename "$pubkey_path" .pub)
    if [ $? -ne 0 ]; then
        error "Failed to select a valid public key. Exiting."
        return 1
    fi
    configure_local_ssh "$key_name"

    while true; do
        read remote_host remote_user <<< $(prompt_remote_details)
        
        if [ -z "$remote_host" ]; then
            break
        fi
        
        info "Copying public key '$pubkey_path' to $remote_host..."
        copy_key_to_remote "$(basename "$pubkey_path" .pub)" "$remote_host" "$remote_user"
        
        configure_remote_ssh "$remote_user" "$remote_host"
        check_remote_ssh_config "$remote_user" "$remote_host" "$pubkey_path"
        if prompt_yes_no "Do you want to perform some checks for your local ssh security?" "n"; then
            check_local_ssh_security
        fi
        
        if ! prompt_yes_no "Do you want to copy the key to another host?" "n"; then
            break
        fi
    done
}

select_key_file() {
    local key_type="$1"
    local default_path="$2"
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
    done < <(find "$ssh_keys_location" -type f -name "$file_pattern" -print0)

    if [ ${#files[@]} -eq 0 ]; then
        error "No $key_type keys found in ~/.ssh directory." >&2
        selected_file=$(prompt_with_default "Enter path to $key_type key" "")
    else
        echo "Select a $key_type key:" >&2
        select file in "${files[@]}" "Enter path manually"; do
            case $file in
                "Enter path manually")
                    selected_file=$(prompt_with_default "Enter path to $key_type key" "")
                    break
                    ;;
                *)
                    if [ -n "$file" ]; then
                        selected_file="$file"
                        break
                    else
                        # Check if the input is a valid path
                        if [ -f "$REPLY" ]; then
                            selected_file="$REPLY"
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
}

configure_multiple_hosts() {
    local key_name="$1"
    local key_path="$2"
    local hosts=()

    while true; do
        local host=$(prompt_with_default "Enter host (or press Enter to finish)" "")
        [ -z "$host" ] && break
        hosts+=("$host")
    done
    
    for host in "${hosts[@]}"; do
        read remote_host remote_user <<< $(prompt_remote_details)
        
        configure_remote_ssh "$remote_user" "$host"
        check_remote_ssh_config "$remote_user" "$host" "$key_path"
        if prompt_yes_no "Do you want to perform some checks for your local ssh security?" "n"; then
            check_local_ssh_security
        fi
    done

    configure_local_ssh "$key_name"
}

configure_remote_ssh() {
    local remote_user="$1"
    local remote_host="$2"

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
        
        if prompt_yes_no "Disable password authentication on $remote_host?" "y"; then
            disable_password_auth=true
        else
            disable_password_auth=false
        fi
        
        info "Configuring $remote_host. You will be prompted approx. 7 times times for the sudo password on the remote host."
        
        if [ "$set_rhost_permissions" = true ]; then
            # First, perform non-sudo operations
            ssh "$remote_user@$remote_host" bash << EOF
            chmod 700 ~/.ssh
            chmod 600 ~/.ssh/authorized_keys
            find ~/.ssh -name '*.pub' -type f -exec chmod 644 {} +
EOF
        fi

        # Now, perform sudo operations interactively
        if [ "$enable_pubkey_auth" = true ] || [ "$disable_password_auth" = true ]; then
            
            if [ "$enable_pubkey_auth" = true ]; then
                ssh -t "$remote_user@$remote_host" "sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config"
            fi
            
            if [ "$disable_password_auth" = true ]; then
                ssh -t "$remote_user@$remote_host" "sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
            fi
            
            ssh -t "$remote_user@$remote_host" "sudo systemctl restart sshd.service"
        fi

        success "Remote SSH configuration completed for $remote_host."
    fi
}

configure_local_ssh() {
    local key_name="$1"
    info "Configuring local SSH to use the new key..."

    # Set correct permissions for the private key file
    chmod 600 "$ssh_keys_location$key_name"
    # Set correct permissions for the public key file
    chmod 644 "$ssh_keys_location$key_name.pub"

    cleanup_and_update_ssh_config 

    info "SSH configuration complete."
}

cleanup_and_update_ssh_config() {
    local ssh_config="$ssh_keys_location/config"

    # Check if the script is being run as root
    if [ "$(id -u)" -eq 0 ]; then
        error "This script should not be run as root. Please run it as a regular user."
        exit 1
    fi

    info "Updating SSH config..."

    # Ensure the .ssh directory exists
    mkdir -p "$ssh_keys_location"

    # Generate public keys for all private keys
    find "$ssh_keys_location" -type f -name 'id_*' ! -name '*.pub' | while read -r key_file; do
        #info "Generating public key for $key_file..."
        ssh-keygen -y -f "$key_file" > "${key_file}.pub"
        #success "Public key generated/updated: ${key_file}.pub"
        chmod 644 "${key_file}.pub"
    done

    # Create a temporary file
    local temp_config=$(mktemp)

    # Write the Host * block
    echo "Host *" > "$temp_config"

    # Array to store unique IdentityFile entries
    declare -A identity_files

    # Add all private key files as IdentityFile entries
    find "$ssh_keys_location" -type f -name 'id_*' ! -name '*.pub' | while read -r key_file; do
        if [[ ! ${identity_files[$key_file]} ]]; then
            echo "    IdentityFile $key_file" >> "$temp_config"
            identity_files[$key_file]=1
        fi
    done

    # If the config file already exists, process its content
    if [[ -f "$ssh_config" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" =~ ^[[:space:]]*IdentityFile[[:space:]]+(.*) ]]; then
                # Check if the IdentityFile exists and hasn't been added yet
                if [[ -f "${BASH_REMATCH[1]}" && ! ${identity_files[${BASH_REMATCH[1]}]} ]]; then
                    echo "$line" >> "$temp_config"
                    identity_files[${BASH_REMATCH[1]}]=1
                fi
            elif [[ "$line" != "Host *" ]]; then
                # Keep all other lines except "Host *"
                echo "$line" >> "$temp_config"
            fi
        done < "$ssh_config"
    fi

    # Replace the original file with the updated version
    mv "$temp_config" "$ssh_config"
    chmod 600 "$ssh_config"

    info "SSH configuration update complete."
    results[9]="PASS"
}

check_remote_ssh_config() {
    local remote_user="$1"
    local remote_host="$2"
    local key_file="$3"

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
    ssh -i "$private_key_file" "$remote_user@$remote_host" bash << EOF
    echo "Checking ~/.ssh permissions..."
    ls -ld ~/.ssh
    ls -l ~/.ssh/authorized_keys
    echo "Checking authorized_keys content..."
    tail -n 5 ~/.ssh/authorized_keys
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
        "~/.ssh directory permissions"
        "authorized_keys file permissions"
        "Password authentication"
        "Root login"
        "SSH protocol version"
        "X11 forwarding"
        "MaxAuthTries setting"
        "Privilege separation"
        "Cleanup and Update SSH-config"
    )
    
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
    check_privilege_separation
    cleanup_and_update_ssh_config
    
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

# Helper functions for individual checks
check_ssh_key_permissions() {
    local issue=""
    find "$ssh_keys_location" -type f -name 'id_*' | while read key_file; do
        if [[ "$key_file" == *.pub ]]; then
            if [[ $(stat -c %a "$key_file") != "644" ]]; then
                issue+="Public key file $key_file has incorrect permissions. "
            fi
        else
            if [[ $(stat -c %a "$key_file") != "600" ]]; then
                issue+="Private key file $key_file has incorrect permissions. "
            fi
        fi
    done
    results[0]=${issue:-"PASS"}
}

check_ssh_dir_permissions() {
    if [[ $(stat -c %a "$ssh_keys_location") != "700" ]]; then
        results[1]="~/.ssh directory has incorrect permissions."
    else
        results[1]="PASS"
    fi
}

check_authorized_keys_permissions() {
    if [[ -f "$ssh_keys_location/authorized_keys" && $(stat -c %a "$ssh_keys_location/authorized_keys") != "600" ]]; then
        results[2]="authorized_keys file has incorrect permissions."
    else
        results[2]="PASS"
    fi
}

check_password_authentication() {
    if grep -q "^PasswordAuthentication yes" "$sshd_config"; then
        results[3]="Password authentication is enabled."
    else
        results[3]="PASS"
    fi
}

check_root_login() {
    if grep -q "^PermitRootLogin yes" "$sshd_config"; then
        results[4]="Root login is permitted."
    else
        results[4]="PASS"
    fi
}

check_ssh_protocol() {
    if ! grep -q "^Protocol 2" "$sshd_config"; then
        results[5]="SSH protocol version 2 is not explicitly set."
    else
        results[5]="PASS"
    fi
}

check_x11_forwarding() {
    if grep -q "^X11Forwarding yes" "$sshd_config"; then
        results[6]="X11 forwarding is enabled."
    else
        results[6]="PASS"
    fi
}

check_max_auth_tries() {
    if ! grep -q "^MaxAuthTries [1-5]$" "$sshd_config"; then
        results[7]="MaxAuthTries is not set to a low value (recommended: 3-5)."
    else
        results[7]="PASS"
    fi
}

check_privilege_separation() {
    if grep -q "^UsePrivilegeSeparation no" "$sshd_config"; then
        results[8]="Privilege separation is disabled."
    else
        results[8]="PASS"
    fi
}

fix_local_ssh_security() {
    info "Fixing local SSH security settings..."
    
    find "$ssh_keys_location" -type f -name 'id_*' | while read key_file; do
        if [[ "$key_file" == *.pub ]]; then
            chmod 644 "$key_file"
        else
            chmod 600 "$key_file"
        fi
    done

    chmod 700 "$ssh_keys_location"

    if [[ -f "$ssh_keys_location/authorized_keys" ]]; then
        chmod 600 "$ssh_keys_location/authorized_keys"
    fi
    
    sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_config"
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
    sudo sed -i 's/^#*Protocol.*/Protocol 2/' "$sshd_config"
    if ! grep -q "^Protocol 2" "$sshd_config"; then
        echo "Protocol 2" | sudo tee -a "$sshd_config" > /dev/null
    fi
    sudo sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$sshd_config"
    sudo sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 5/' "$sshd_config"
    sudo sed -i 's/^#*UsePrivilegeSeparation.*/UsePrivilegeSeparation yes/' "$sshd_config"
    
    success "Local SSH security settings have been updated."
    info "Restarting SSH service..."
    sudo systemctl restart sshd.service
}

# Add this new function
display_main_menu() {
    echo -e "\n${GREEN}SSH Key Setup Script Menu${NC}"
    echo -e "${BLUE}═════════════════════════${NC}\n"

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

    echo -e "${YELLOW}q. Exit${NC}"
    echo ""
}

# Main script
while true; do
    cleanup_and_update_ssh_config
    display_main_menu
    read -p "$(echo -e "${BLUE}Choose an option (1/2/3/4/q): ${NC}")" option
    echo ""

    case "$option" in
        1) execute_or_simulate generate_ssh_key ;;
        2) execute_or_simulate import_private_key ;;
        3) execute_or_simulate copy_pubkey_to_hosts ;;
        4) execute_or_simulate check_local_ssh_security ;;
        q|Q) info "Exiting script. Goodbye!"; exit 0 ;;
        *) error "Invalid option. Please try again." ;;
    esac

    echo ""
    read -p "Press Enter to return to the main menu..."
done