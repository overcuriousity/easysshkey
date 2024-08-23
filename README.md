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

## Future Features

- Hardware Key Support
- Password-Protected Keys
- possibly Implementation in Python (with more Features) and publishing in AUR

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

- There is only one occasion where the script asks for your sudo password (fixing your local ssh security)
- The script is deliberately unrestricted and allows maximum user freedom while providing hints for best-practices. Always consider your threat model.

## Compatibility

This script is primarily designed for Linux systems using systemd. It has been tested on various distributions, including Ubuntu and Arch Linux. While it should work on most POSIX-compliant shells, it's primarily intended for use with bash.

## Customization

You can modify the following variables at the beginning of the script to customize its behavior:

- `sshd_config`: Location of the SSH daemon configuration file
- `ssh_keys_location`: Directory where SSH keys are stored
- `backup_dir`: Default destination  when making backups
- `agnostic_authorized_keys`: By default, the script will configure remote hosts with a permissive `authorized_keys`file which will allow you to log in from everywhere with your private key. This can be changed.

## Contributing

Contributions to improve SSH Key Manager are welcome. Please feel free to submit issues or pull requests through the project's Git repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This script is provided as-is, without any warranty. Always review and understand any script that modifies system configurations before running it, especially with elevated privileges.
