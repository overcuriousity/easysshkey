# SSH Key Manager

## Overview

SSH Key Manager is a bash script designed to simplify the process of generating, importing, and managing SSH keys across multiple hosts. It provides an interactive interface for common SSH key operations and includes security checks to ensure best practices are followed.

## Features

- Generate new SSH key pairs
- Import existing private keys
- Configure remote hosts with existing keys
- Perform local SSH security checks
- Interactive menu-driven interface
- Colorized output for better readability

## Requirements

- Bash shell (version 4.0 or later recommended)
- OpenSSH client tools (ssh, ssh-keygen, ssh-copy-id)
- sudo privileges for some operations

## Installation

1. Clone this repository or download the `sshkeymanager.sh` script.
2. Make the script executable:
   ```
   chmod +x sshkeymanager.sh
   ```

## Usage

Run the script with:

```
./sshkeymanager.sh
```

Follow the on-screen prompts to perform various SSH key management tasks.

### Menu Options

1. **Generate new SSH key pair**: Creates a new SSH key pair and configures it for use with a remote host.
2. **Import existing key for remote host**: Imports an existing private key and configures it for use with a remote host.
3. **Configure remote host with existing keys**: Copies an existing public key to one or more remote hosts.
4. **Check local SSH security settings**: Performs a series of checks on your local SSH configuration and offers to fix any issues found.

## Security Considerations

- This script modifies SSH configurations and key files. Always review the changes and ensure they align with your security policies.
- Backup your existing SSH configurations and keys before using this script.
- The script may require sudo privileges for some operations. Review the code to understand what elevated actions it performs.

## Compatibility

This script is primarily designed for Linux systems using systemd. It has been tested on various distributions, including Ubuntu and Arch Linux. While it should work on most POSIX-compliant shells, it's primarily intended for use with bash.

## Customization

You can modify the following variables at the beginning of the script to customize its behavior:

- `sshd_config`: Location of the SSH daemon configuration file
- `ssh_keys_location`: Directory where SSH keys are stored

## Contributing

Contributions to improve SSH Key Manager are welcome. Please feel free to submit issues or pull requests through the project's Git repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This script is provided as-is, without any warranty. Always review and understand any script that modifies system configurations before running it, especially with elevated privileges.