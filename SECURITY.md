# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Safety Architecture (7 Layers)

CyberSim6 implements a **7-layer safety framework** to ensure all simulations remain within the sandbox:

| Layer | Mechanism              | Implementation                                    |
|-------|------------------------|---------------------------------------------------|
| 1     | **IP Validation**      | Only `127.0.0.1`, `localhost`, `::1` allowed      |
| 2     | **Sandbox Marker**     | `.cybersim_sandbox` file required in target dir    |
| 3     | **Anti-Path Traversal**| `Path.resolve()` + prefix verification             |
| 4     | **File Limits**        | MAX_FILES=50, MAX_SIZE=10MB, extension whitelist   |
| 5     | **Interactive Confirm**| User must type `YES` before ransomware encryption  |
| 6     | **Non-Destructive**    | Original files preserved by default                |
| 7     | **Blocked Directories**| Home, C:\, Windows, Program Files are hardcoded blocked |

## Reporting a Vulnerability

If you discover a safety issue that could allow CyberSim6 to affect systems outside the sandbox:

1. **DO NOT** open a public issue
2. Email: **omarbabba27@gmail.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
4. You will receive a response within **48 hours**

## Scope

This project is **strictly educational**. All attack simulations are designed to run exclusively against `localhost` in a sandboxed environment. Any use against unauthorized systems is **illegal** and violates the terms of this project.

## Approved Use Cases

- Academic research and coursework
- Cybersecurity training and demonstrations
- Understanding attack vectors for defensive purposes
- Testing detection and response mechanisms

## Prohibited Use Cases

- Targeting any system without explicit written authorization
- Bypassing or disabling safety mechanisms
- Using attack modules outside the sandbox environment
- Distributing modified versions without safety controls
