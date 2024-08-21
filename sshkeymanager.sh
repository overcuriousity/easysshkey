#!/usr/bin/env bash
sshd_config="/etc/ssh/sshd_config"
ssh_keys_location="$HOME/.ssh/"

set -e


# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

# Function to generate SSH key
generate_ssh_key() {
    local remote_host=$(prompt_with_default "Enter remote host" "1.2.3.4")
    local remote_user=$(prompt_with_default "Enter remote user" "$USER")
    local key_algo=$(prompt_with_default "Enter key algorithm" "ed25519")
    warn "The name you select for the key should begin with "id_*" to be compatible with this script!"
    local key_name=$(prompt_with_default "Enter key name" "id_${key_algo}_$USER")
    
    info "Generating new SSH key pair..."
    ssh-keygen -t "$key_algo" -f "$ssh_keys_location$key_name" -N ""
    chmod 600 "$ssh_keys_location$key_name"
    chmod 644 "$ssh_keys_location$key_name.pub"
    
    info "Copying $ssh_keys_location$key_name.pub to $remote_host..."
    echo "Running ssh-copy-id -f -i "$ssh_keys_location$key_name.pub" "$remote_user@$remote_host""
    ssh-copy-id -f -i "$ssh_keys_location$key_name.pub" "$remote_user@$remote_host"
    
    configure_remote_ssh "$remote_user" "$remote_host"
    configure_local_ssh "$key_name" "$remote_host" "$remote_user"
    check_remote_ssh_config "$remote_user" "$remote_host" "$ssh_keys_location$key_name"
    
    success "SSH key pair generated and configured successfully."
}

# Function to import private key
import_private_key() {
    local private_key_path=$(select_key_file "private" "$ssh_keys_location/id_rsa" "id_*" "false")
    local remote_host=$(prompt_with_default "Enter remote host" "example.com")
    local remote_user=$(prompt_with_default "Enter remote user" "$USER")
    
    local key_name=$(basename "$private_key_path")
    local destination_path="$ssh_keys_location$key_name"

    if [[ "$private_key_path" != "$destination_path" ]]; then
        cp -f "$private_key_path" "$destination_path"
        echo "Private key copied to $destination_path"
    fi

    chmod 600 "$destination_path"
    
    if [ ! -f "${destination_path}.pub" ]; then
        echo "Public key not found. Generating from private key..."
        ssh-keygen -y -f "$destination_path" > "${destination_path}.pub"
        echo "Public key generated: ${destination_path}.pub"
    fi

    configure_remote_ssh "$remote_user" "$remote_host"
    configure_local_ssh "$key_name" "$remote_host" "$remote_user"
    check_remote_ssh_config "$remote_user" "$remote_host" "$destination_path"
}

select_key_file() {
    local key_type="$1"
    local default_path="$2"
    local file_pattern="$3"
    local include_pub="$4"  # New parameter to determine whether to include .pub files
    local files=()
    local selected_file=""

    # Find matching files in .ssh directory
    while IFS= read -r -d $'\0' file; do
        # Skip .pub files if include_pub is false
        if [ "$include_pub" != "true" ] && [[ "$file" == *.pub ]]; then
            continue
        fi
        files+=("$file")
    done < <(find "$ssh_keys_location" -type f -name "$file_pattern" -print0)

    if [ ${#files[@]} -eq 0 ]; then
        echo "No $key_type keys found in ~/.ssh directory." >&2
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
                        echo "Invalid selection. Please try again." >&2
                    fi
                    ;;
            esac
        done
    fi

    # Verify that the selected file exists
    if [ ! -f "$selected_file" ]; then
        echo "Error: The selected $key_type key file does not exist: $selected_file" >&2
        return 1
    fi

    # Return only the file path, without any additional text
    echo "$selected_file"
}

# Updated function to copy public key to additional hosts
copy_pubkey_to_hosts() {
    local hosts=()
    local pubkey_path


    #echo "Need to set Permissions correctly for all local ssh-pubkeys. You might be prompted for the local sudo password."
    #find $ssh_keys_location -name '*.pub' -type f -exec chmod 644 {} \;

    pubkey_path=$(select_key_file "public" "$ssh_keys_location/id_*.pub" "id_*.pub" "true")
    if [ $? -ne 0 ]; then
        echo "Failed to select a valid public key. Exiting."
        return 1
    fi


    while true; do
        local host=$(prompt_with_default "Enter host (or press Enter to finish)" "")
        if [ -z "$host" ]; then
            break
        fi
        hosts+=("$host")
    done

    for host in "${hosts[@]}"; do
        local remote_user=$(prompt_with_default "Enter remote user for $host" "$USER")
        
        echo "Copying public key '$pubkey_path' to $host..."
        ssh-copy-id -i "$pubkey_path" "$remote_user@$host"
        
        configure_remote_ssh "$remote_user" "$host"
        configure_local_ssh "$(basename "$pubkey_path" .pub)" "$host" "$remote_user"
        check_remote_ssh_config "$remote_user" "$host" "$pubkey_path"
    done
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

        echo "Remote SSH configuration completed for $remote_host."
    fi
}

configure_local_ssh() {
    local key_name="$1"
    local remote_host="$2"
    local remote_user="$3"
    echo "Configuring local SSH to use the new key..."

    #if prompt_yes_no "Would you like to update your SSH config to use this key for $remote_host? (Recommended)" "y"; then
    #    cleanup_and_update_ssh_config "$key_name" "$remote_host" "$remote_user"
    #fi

    # Set correct permissions for the private key file
    chmod 600 "$ssh_keys_location$key_name"
    # Set correct permissions for the public key file
    chmod 644 "$ssh_keys_location$key_name.pub"

    echo "SSH configuration complete."
}

cleanup_and_update_ssh_config() {
    local new_key_name="$1"
    local remote_host="$2"
    local remote_user="$3"
    local ssh_config="$ssh_keys_location/config"
    local wildcard_id="/id*"

    echo "Updating SSH config..."
    #echo "Before modification:"
    #cat "$ssh_config"

    # Create a temporary file
    local temp_config=$(mktemp)

    # Process the config file
    {
        # Variable to track if we've seen the target host
        local seen_target_host=false

        # Read the existing config file line by line
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Write the line to the new config
            echo "$line"

            # Check if this is the start of a Host block
            if [[ "$line" =~ ^Host[[:space:]] ]]; then
                # Extract the hostname
                local current_host=$(echo "$line" | awk '{print $2}')

                # If this is our target host, update the seen_target_host flag
                if [[ "$current_host" == "$remote_host" ]]; then
                    seen_target_host=true
                    # Add or update the User and IdentityFile entries
                    echo "    User $remote_user"
                    echo "    IdentityFile $ssh_keys_location$wildcard_id"
                fi
            fi
        done < "$ssh_config"

        # If we haven't seen the target host, append it to the config
        if ! $seen_target_host; then
            echo ""
            echo "Host $remote_host"
            echo "    User $remote_user"
            echo "    IdentityFile $ssh_keys_location$wildcard_id"
        fi
    } > "$temp_config"

    # Replace the original file with the updated version
    mv "$temp_config" "$ssh_config"
    chmod 600 "$ssh_config"

    #echo "After modification:"
    #cat "$ssh_config"
    echo "SSH configuration update complete."
}

check_remote_ssh_config() {
    local remote_user="$1"
    local remote_host="$2"
    local key_file="$3"

    echo "Checking remote SSH configuration..."

    # Ensure we're using the private key, not the public key
    local private_key_file="${key_file%.pub}"

    # Check if the file exists
    if [ ! -f "$private_key_file" ]; then
        echo "Error: Private key file $private_key_file does not exist."
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

    echo "Remote SSH configuration check completed for $remote_host."
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

# Main script
while true; do
    # Display menu
    echo -e "\n${GREEN}SSH Key Setup Script Menu${NC}"
    echo -e "${BLUE}═════════════════════════${NC}\n"

    echo -e "${CYAN}1. Generate new SSH key pair${NC}"
    echo "   SCENARIO: Fresh setup for SSH key authentication"
    echo "   REQUIRES: Remote host with SSH access (password or existing key)"
    echo ""

    echo -e "${CYAN}2. Import existing key for remote host${NC}"
    echo "   SCENARIO: Connect to a server with existing SSH key authentication from a new machine"
    echo "   REQUIRES: Existing private key and remote host with your public key already configured"
    echo ""

    echo -e "${CYAN}3. Configure remote host with existing keys${NC}"
    echo "   SCENARIO: Set up an existing local SSH key on a new remote host"
    echo "   REQUIRES: Existing local SSH key and remote host with SSH access (typically password)"
    echo ""

    echo -e "${CYAN}4. Check local SSH security settings${NC}"
    echo "   SCENARIO: Verify and improve local SSH security configuration"
    echo "   PERFORMS: Automated local security checks against best practices"
    echo ""

    echo -e "${YELLOW}q. Exit${NC}"
    echo ""

    # Get user input
    read -p "$(echo -e "${BLUE}Choose an option (1/2/3/4/q): ${NC}")" option
    echo ""

    # Process user input
    case "$option" in
        1)
            generate_ssh_key
            ;;
        2)
            import_private_key
            ;;
        3)
            copy_pubkey_to_hosts
            ;;
        4) 
            check_local_ssh_security
            ;;
        q|Q)
            info "Exiting script. Goodbye!"
            exit 0
            ;;
        *)
            error "Invalid option. Please try again."
            ;;
    esac

    # Add a pause after each action
    echo ""
    read -p "Press Enter to return to the main menu..."
done

echo -e "${GREEN}Script execution completed.${NC}"