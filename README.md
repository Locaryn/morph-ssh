# Locaryn Plugin: Remote SSH Connector (`plugin-ssh`)

Official Locaryn extension allowing AI agents to connect to remote Linux/macOS servers and execute deployment, inspection, and maintenance commands over SSH.

## Features
- **Strict Approval Gating**: Commands default to requiring user confirmation.
- **TOFU Fingerprint Verification**: Protects against MITM attacks.
- **Agent Integration**: Exposes `ssh_exec` tool to the agent runtime.

## Installation
```bash
locaryn plugin install Locaryn/plugin-ssh
```

## Tools Provided
- `ssh_exec`: Executes a bash/shell command on a configured remote SSH host.
