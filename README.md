# WIP: Rust Key Logger

A Windows keylogger implementation written in Rust for educational and security research purposes.

## ⚠️ Disclaimer

This project is intended for **educational purposes only** and should only be used on systems you own or have explicit permission to monitor. Unauthorized keylogging is illegal and unethical.

## Project Overview

This keylogger demonstrates low-level Windows API integration with Rust, focusing on:

- **System-level programming**: Direct Windows API calls using Rust
- **Security research**: Understanding keystroke capture mechanisms
- **Evasion techniques**: Modern approaches to avoid detection
- **Data protection**: Encryption and secure storage methods

## Features

### ✅ Implemented
- Basic project structure

### 🚧 In Progress
- Core keylogger functionality

### 📋 Todo List

#### Phase 1: Core Functionality
- [ ] **Keystroke Hooking Module**
    - [ ] Low-level keyboard hook via WinAPI
    - [ ] System-wide keystroke capture
    - [ ] Special key handling (SHIFT, CTRL, ENTER, etc.)
    - [ ] Timestamp logging

- [ ] **Context Awareness Module**
    - [ ] Active application identification
    - [ ] Window title capture
    - [ ] Credential form detection
    - [ ] PII and financial data form detection

- [ ] **Secure Storage Module**
    - [ ] Background process persistence
    - [ ] Log encryption (AES-GCM/ChaCha20-Poly1305)
    - [ ] String obfuscation
    - [ ] Dynamic API loading

#### Phase 2: Advanced Features
- [ ] **Data Exfiltration Module**
    - [ ] Scheduled log transmission
    - [ ] Remote server communication
    - [ ] Local log cleanup

- [ ] **Masquerading Module**
    - [ ] Legitimate application wrapper
    - [ ] Multi-threaded operation

## Dependencies

- `windows-sys` - Windows API bindings
- `chrono` - Timestamp management
- `aes-gcm` or `chacha20poly1305` - Encryption
- `reqwest` - HTTP requests (future)

## Legal Notice

Use responsibly and in accordance with local laws and regulations.
