# SSH Key Manager

## Overview

SSH Key Manager is a bash script designed to simplify the process of generating, importing, and managing SSH keys across multiple hosts. It provides an interactive interface for common SSH key operations and includes security checks to ensure best practices are followed.

## Features

- Generate new SSH key pairs (Ed25519, RSA, ECDSA)
- FIDO2 hardware-backed keys (Ed25519-SK / ECDSA-SK)
- Passphrase-protected keys, mandatory for permissive `authorized_keys` setups
- Import existing private keys
- Configure remote hosts with existing keys
- Key rotation, with deployment to the hosts that already use the old key
- SSH agent management
- Per-host SSH configuration, including jump hosts
- Remote `authorized_keys` editing, with per-key option management
- Local SSH security checks, with optional fixes
- Backups before anything is modified
- Dry-run mode
- Audit log of key operations
- Interactive menu-driven interface with colorized output

## Future Features

- Possibly a Python implementation (with more features) and an AUR package

## Requirements

- Bash shell (version 4.0 or later recommended)
- OpenSSH client tools (ssh, ssh-keygen, ssh-copy-id)
- sudo privileges for some operations

## Installation

### Quick install (recommended)

```
curl -fsSL https://raw.githubusercontent.com/overcuriousity/easysshkey/main/install.sh | bash
```

This installs the script as `sshkeymanager` into `~/.local/bin` (or `/usr/local/bin` when run
as root) and tells you how to add that directory to your `PATH` if it isn't there already.

The installer verifies the download is a syntactically valid bash script before making it
executable, and never touches your existing keys or `~/.ssh`.

Options:

```
# install somewhere else
curl -fsSL .../install.sh | INSTALL_DIR=/usr/local/bin bash

# install a specific tag or branch
curl -fsSL .../install.sh | REF=v1.2 bash

# remove it again
curl -fsSL .../install.sh | bash -s -- --uninstall
```

If you would rather read the installer before running it — which is a reasonable habit for
anything piped into a shell — download it first:

```
curl -fsSLO https://raw.githubusercontent.com/overcuriousity/easysshkey/main/install.sh
less install.sh
bash install.sh
```

### Manual install

1. Clone this repository or download the `sshkeymanager.sh` script.
2. Make the script executable:
   ```
   chmod +x sshkeymanager.sh
   ```

## Usage

If you used the quick install:

```
sshkeymanager
```

Otherwise run it from the repository:

```
./sshkeymanager.sh
```

Follow the on-screen prompts to perform various SSH key management tasks.

### Command line options

| Option | Effect |
| --- | --- |
| `-b`, `--backup` | Back up SSH configuration before making changes |
| `-d`, `--dry-run` | Show what would change without applying it |
| `-o`, `--override-security` | Allow keys without a passphrase in permissive mode |
| `-a`, `--audit` | Print the audit log and exit |
| `-h`, `--help` | Show usage |

### Menu Options

1. **Generate new SSH key pair**: Creates a new SSH key pair and configures it for use with a remote host.
2. **Import valid key and/or check configuration for remote host**: Imports an existing private key and configures it for use with a remote host.
3. **Configure remote host with existing keys**: Copies an existing public key to one or more remote hosts.
4. **Check local SSH security settings**: Performs a series of checks on your local SSH configuration and offers to fix any issues found.
5. **Advanced settings**: Default values, backups, remote `authorized_keys` editing, SSH config host management, audit log, connection tests.
6. **SSH Agent Management**: Check agent status, list/add/remove keys, lock and unlock the agent.
7. **Key Rotation**: Generate a replacement for an existing key and deploy it to the hosts that use it.

### How `~/.ssh/config` is handled

The script keeps a managed `Host *` block at the end of `~/.ssh/config` holding
safe defaults (`AddKeysToAgent`, `HashKnownHosts`, `ServerAlive*`). Everything
else in the file — your comments, your own host blocks — is left alone.

Before the first modification in a session the existing file is copied to
`~/.ssh/config.bak.<timestamp>`, and when normalization would produce no change
the file is not touched at all.

Keys are bound to hosts in their own `Host` blocks rather than being listed
globally, so ssh does not offer every key on every connection.

## Security Considerations

- The script may require sudo privileges for some operations. Review the code to
  understand what elevated actions it performs.
- Changes to `sshd_config` are written to `/etc/ssh/sshd_config.d/99-sshkeymanager.conf`
  where the daemon includes that directory, and appended to the main file
  otherwise. The configuration is validated with `sshd -t` before the service is
  restarted.
- Disabling password authentication is opt-in and only proceeds after key
  authentication has been shown to work against the host in question.
- Backups contain private keys in plaintext. They are created mode 600 under a
  directory you choose; treat them like the keys themselves.

## Compatibility

This script is primarily designed for Linux systems using systemd. It has been tested on various distributions, including Ubuntu and Arch Linux. While it should work on most POSIX-compliant shells, it's primarily intended for use with bash.

## Customization

You can modify the following variables at the beginning of the script to customize its behavior:

- `sshd_config`: Location of the SSH daemon configuration file
- `ssh_keys_location`: Directory where SSH keys are stored (no trailing slash)
- `backup_root`: Parent directory for backups
- `agnostic_authorized_keys`: `true` installs keys without `from=` restrictions
  and makes a passphrase mandatory; `false` restricts by user/host via `ssh-copy-id`
- `audit_log`: Location of the operation log

All of these are also editable at runtime under *Advanced settings → Set global
variables*.

## Development

The script is checked with [ShellCheck](https://www.shellcheck.net/) in CI:

```
shellcheck -S style sshkeymanager.sh install.sh
```

Sourcing the script does not start the menu, so individual functions can be
exercised directly:

```
source ./sshkeymanager.sh
declare -a results
check_weak_keys
echo "${results[11]}"
```

## Contributing

Contributions to improve SSH Key Manager are welcome. Please feel free to submit issues or pull requests through the project's Git repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This script is provided as-is, without any warranty. Always review and understand any script that modifies system configurations before running it, especially with elevated privileges.