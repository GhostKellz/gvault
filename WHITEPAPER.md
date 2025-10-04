# GVault Whitepaper
**Terminal Keychain Manager for the Modern Age**

*Version 0.1.0-alpha*
*Last Updated: 2025-10-04*

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Introduction](#introduction)
3. [Architecture Overview](#architecture-overview)
4. [Security Model](#security-model)
5. [Core Features](#core-features)
6. [Ghostshell Integration](#ghostshell-integration)
7. [Technical Implementation](#technical-implementation)
8. [Comparison with Termius](#comparison-with-termius)
9. [Roadmap](#roadmap)
10. [Conclusion](#conclusion)

---

## Executive Summary

**GVault** is a next-generation, Zig-native credential management library designed specifically for terminal emulators and power users. Built to integrate seamlessly with Ghostshell (a Ghostty fork optimized for NVIDIA/Wayland), GVault provides enterprise-grade security with offline-first architecture, post-quantum cryptography readiness, and zero cloud dependencies.

### Key Differentiators

- **🔒 Post-Quantum Ready**: zqlite-backed storage with quantum-resistant encryption
- **⚡ Native Performance**: Pure Zig implementation, zero Electron overhead
- **🎯 Terminal-First**: Deep integration with terminal emulators, SSH agent protocol
- **🔐 Hardware Security**: FIDO2, YubiKey, TPM 2.0 support
- **🌐 Offline-First**: No mandatory cloud sync, full local control
- **🔑 Multi-Algorithm**: Argon2id, SHA-2/3 support for legacy compatibility

---

## Introduction

### The Problem

Modern developers and sysadmins manage hundreds of credentials across multiple environments. Existing solutions are either:
- **Cloud-dependent** (security/privacy concerns)
- **Feature-limited** (basic password managers)
- **Platform-locked** (vendor lock-in)
- **Performance-heavy** (Electron-based bloat)

### The Solution

GVault provides a **terminal-native, Zig-powered credential vault** that:
- Stores SSH keys, GPG keys, API tokens, passwords, certificates
- Integrates directly into your terminal workflow
- Uses battle-tested cryptography with post-quantum extensions
- Works completely offline with optional encrypted sync
- Provides biometric and hardware key authentication

### Target Users

- **DevOps Engineers**: Managing fleet infrastructure
- **Security Professionals**: Requiring audit trails and compliance
- **Power Users**: Demanding performance and customization
- **Home Lab Enthusiasts**: Self-hosting without cloud dependencies

---

## Architecture Overview

### System Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Ghostshell Terminal Emulator               │
│   (Ghostty fork - Wayland native, NVIDIA optimized)    │
└──────────────────────────┬──────────────────────────────┘
                           │
                  ┌────────▼─────────┐
                  │  GVault Library  │
                  │  (Zig Native)    │
                  └────────┬─────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼─────┐      ┌────▼─────┐      ┌────▼──────┐
   │  zqlite  │      │ zcrypto  │      │   zssh    │
   │ Database │      │  Crypto  │      │ SSH Impl  │
   └──────────┘      └──────────┘      └───────────┘
        │                  │                  │
   ┌────▼─────┐      ┌────▼─────┐      ┌────▼──────┐
   │ Post-    │      │ Argon2id │      │ ED25519   │
   │ Quantum  │      │ ChaCha20 │      │ RSA-4096  │
   │ Secure   │      │ Poly1305 │      │ ECDSA     │
   └──────────┘      └──────────┘      └───────────┘
```

### Data Flow

1. **Vault Initialization**: Generate salt, create vault structure
2. **Unlock**: User provides passphrase → KDF derives master key
3. **Encryption**: ChaCha20-Poly1305 AEAD encryption
4. **Storage**: Persistent storage via zqlite with PQ encryption
5. **Retrieval**: Decrypt credentials on-demand
6. **Lock**: Zero sensitive memory, invalidate keys

---

## Security Model

### Encryption Architecture

#### 1. Personal Vault Encryption

```
Passphrase
    ↓
Argon2id KDF (64MB, t=3, p=4) + Salt
    ↓
Master Key (32 bytes)
    ↓
ChaCha20-Poly1305 AEAD
    ↓
Encrypted Credential Data
    ↓
zqlite Storage (Post-Quantum Layer)
```

**Security Properties:**
- **End-to-End Encryption**: Zero-knowledge architecture
- **Password Never Transmitted**: Local-only KDF
- **Memory Hardening**: mlock() on sensitive data
- **Secure Erasure**: Explicit memory zeroing

#### 2. Shared Vault Encryption (Hybrid Model)

```
User A                          Vault Owner
  │                                  │
  │ Generate X25519 Keypair          │ Generate Vault Encryption Key
  │        ↓                          │        ↓
  │  Personal Vault                  │  Encrypt with each member's pubkey
  │  (Private Key)                   │        ↓
  │        ↓                          │  Distribute encrypted vault keys
  │  Sync Public Key ─────────────────→     (via cloud or direct)
  │                                   │
  │  ←──────────────── Encrypted Vault Key + MAC (owner signature)
  │
  │  Decrypt with Private Key
  │  Verify MAC with Owner's Public Key
  │        ↓
  │  Access Shared Vault
```

**Team Security Features:**
- **Role-Based Access Control (RBAC)**: Owner, Edit, View-only
- **Selective Sharing**: Choose which credentials to share
- **Audit Trail**: All access logged with timestamps
- **Revocation**: Change encryption password to revoke all access

#### 3. Key Derivation Algorithms

GVault supports multiple KDF algorithms for compatibility:

| Algorithm | Use Case | Security Level | Performance |
|-----------|----------|----------------|-------------|
| **Argon2id** | Default (Recommended) | ⭐⭐⭐⭐⭐ | Medium |
| **SHA3-256** | Modern alternative | ⭐⭐⭐⭐ | Fast |
| **SHA3-512** | High security | ⭐⭐⭐⭐⭐ | Fast |
| **SHA-256** | Legacy compatibility | ⭐⭐⭐ | Very Fast |
| **SHA-512** | Legacy high security | ⭐⭐⭐⭐ | Very Fast |

### Authentication Protocols

#### SRP6a Protocol (Zero-Knowledge Proof)

For optional cloud sync, GVault implements modified SRP6a:

```
Client                                Server
  │                                      │
  │  Email ────────────────────────────→│
  │                                      │
  │  ←──────── Server Random Data, Salt │
  │                                      │
  │  Compute Argon2id(password, salt)    │
  │  Generate Client Proof               │
  │                                      │
  │  Client Proof ────────────────────→ │
  │                                      │
  │                   Server verifies    │
  │                   Generates proof    │
  │                                      │
  │  ←───── Server Proof, Encrypted API Key, Salt
  │                                      │
  │  Validate & Decrypt API Key          │
```

**Security Guarantees:**
- Password never transmitted over network
- Server cannot reconstruct password from stored data
- Mutual authentication (both parties prove knowledge)
- Resistant to replay and MITM attacks

### Hardware Security Integration

#### FIDO2 & YubiKey Support

```zig
pub const FIDO2Auth = struct {
    pub fn generateKey(device: Device, pin: []const u8) !KeyPair {
        // Key generation on hardware, private key never leaves device
        // ECDSA/EdDSA key generation
    }

    pub fn signChallenge(device: Device, challenge: []const u8) ![]u8 {
        // Challenge-response authentication
        // Touch confirmation required
    }
};
```

**Hardware Security Features:**
- Private keys isolated on hardware module
- Touch confirmation for critical operations
- PIN protection with brute-force resistance
- Works with YubiKey, Nitrokey, SoloKey

#### TPM 2.0 Integration (Linux)

```zig
pub const TPMSecureEnclave = struct {
    pub fn sealKey(key: []const u8, pcr_state: []const u8) !void {
        // Seal key to TPM with PCR values
        // Key only accessible with matching system state
    }

    pub fn unsealKey(pcr_state: []const u8) ![]u8 {
        // Retrieve key if PCR values match
        // Ensures boot integrity
    }
};
```

---

## Core Features

### 1. Credential Management

#### Supported Credential Types

```zig
pub const CredentialType = enum {
    ssh_key,        // ED25519, RSA-4096, ECDSA
    gpg_key,        // EdDSA, RSA-4096
    api_token,      // OAuth, JWT, API keys
    password,       // Secure password storage
    certificate,    // X.509 certificates
    server_config,  // Connection configurations
};
```

#### CRUD Operations

- **Create**: Add credentials with metadata (tags, auto-load rules)
- **Read**: Retrieve and decrypt on-demand
- **Update**: Modify credentials, track last-used timestamp
- **Delete**: Secure deletion with memory zeroing
- **Search**: Pattern matching, filtering by type/tags

### 2. SSH Key Management

#### Key Generation

```zig
pub const SSHKeyGenerator = struct {
    pub fn generate(
        key_type: SSHKeyType,
        options: SSHKeyOptions,
    ) !SSHKeyPair {
        // ED25519: Default, fast, secure (256-bit)
        // RSA-4096: Legacy compatibility
        // ECDSA P-256/P-384: NIST curves
    }
};

pub const SSHKeyOptions = struct {
    comment: ?[]const u8,
    passphrase: ?[]const u8,
    key_size: ?usize,  // For RSA
};
```

#### SSH Agent Protocol (RFC 4251/4252)

GVault implements a drop-in replacement for `ssh-agent`:

```zig
pub const SSHAgent = struct {
    socket_path: []const u8,  // ~/.gvault/ssh-agent.sock
    vault: *Vault,

    pub fn listen(self: *SSHAgent) !void {
        // Unix socket server
        // Set SSH_AUTH_SOCK environment variable
    }

    pub fn handleRequest(self: *SSHAgent, request: SSHAgentMessage) ![]u8 {
        // SSH_AGENTC_REQUEST_IDENTITIES
        // SSH_AGENTC_SIGN_REQUEST
        // SSH_AGENTC_ADD_IDENTITY
        // SSH_AGENTC_REMOVE_IDENTITY
    }
};
```

**Features:**
- Auto-load keys based on server patterns
- Key constraints (lifetime, confirm-on-use)
- Agent forwarding support
- Integration with OpenSSH, PuTTY, WinSCP

#### Server Pattern Matching

```zig
pub const ServerPattern = struct {
    pattern: []const u8,           // "*.prod.example.com"
    credential_id: CredentialId,
    auto_load: bool,
    jump_host: ?[]const u8,

    pub fn matches(self: *ServerPattern, hostname: []const u8) bool {
        // Wildcard: *.example.com
        // Regex: ^db[0-9]+\.prod\..*$
        // Exact: server.example.com
    }
};
```

### 3. GPG Key Management

#### Key Generation & Management

```zig
pub const GPGKeyGenerator = struct {
    pub fn generate(
        key_type: GPGKeyType,
        identity: GPGIdentity,
        options: GPGKeyOptions,
    ) !GPGKeyPair {
        // EdDSA (Ed25519): Default
        // RSA-4096: Legacy
        // ECC (Curve25519): Modern alternative
    }
};

pub const GPGIdentity = struct {
    name: []const u8,
    email: []const u8,
    comment: ?[]const u8,
};
```

#### Git Integration

```zig
pub const GitSigning = struct {
    pub fn enableSigningForRepo(repo_path: []const u8, gpg_key: CredentialId) !void {
        // Configure git config user.signingkey
        // Set commit.gpgsign = true
    }

    pub fn signCommit(message: []const u8, key: GPGKey) ![]u8 {
        // Sign commit with GPG key
        // Return detached signature
    }
};
```

### 4. Biometric Authentication (Linux/macOS)

#### Linux PAM Integration

```zig
pub const BiometricAuth = struct {
    pub fn unlockWithFingerprint(vault: *Vault) !void {
        // Use fprintd D-Bus interface
        // Verify fingerprint via PAM
        // Retrieve key from TPM on success
    }
};
```

#### Platform Support

| Platform | Biometric Method | Implementation |
|----------|------------------|----------------|
| **Linux** | Fingerprint | fprintd + PAM |
| **macOS** | Touch ID | Security Framework (future) |
| **Windows** | Windows Hello | DPAPI (future) |

---

## Ghostshell Integration

### Terminal Plugin Architecture

```zig
pub const GhostshellPlugin = struct {
    vault: *Vault,
    terminal: *Terminal,

    pub fn init(config: PluginConfig) !GhostshellPlugin {
        // Register keyboard shortcuts
        // Hook into terminal events
    }

    pub fn registerHotkeys(self: *GhostshellPlugin) !void {
        // Ctrl+Shift+K: Quick SSH key picker
        // Ctrl+Shift+V: Unlock vault
        // Ctrl+Shift+P: Password generator
    }
};
```

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+V` | Unlock/Lock vault |
| `Ctrl+Shift+K` | SSH key picker (fuzzy search) |
| `Ctrl+Shift+G` | GPG key picker |
| `Ctrl+Shift+P` | Generate secure password |
| `Ctrl+Shift+S` | Quick snippet insertion |

### Session Recording with Sanitization

```zig
pub const SessionRecorder = struct {
    pub fn startRecording(sanitize_credentials: bool) !void {
        // Record terminal session
        // Filter out passwords/keys if sanitize=true
    }
};
```

### Snippet Management

```zig
pub const Snippet = struct {
    name: []const u8,
    command: []const u8,
    tags: [][]const u8,

    pub fn execute(self: *Snippet, variables: VariableMap) !void {
        // Template expansion: {{variable}}
        // Inject into terminal
    }
};
```

**Example Snippets:**
```bash
# Docker cleanup
docker system prune -af && docker volume prune -f

# Git force push protection
git push --force-with-lease origin {{branch}}

# SSH tunnel with auto key selection
ssh -L 5432:localhost:5432 -N {{server}}
```

---

## Technical Implementation

### Storage Layer: zqlite Integration

```zig
const zqlite = @import("zqlite");

pub fn saveCredentials(self: *Vault) !void {
    const db = try zqlite.open(self.vault_path, .{
        .encryption = .post_quantum,  // zqlite PQ encryption layer
        .journal_mode = .wal,          // Write-Ahead Logging
    });
    defer db.close();

    // Vault metadata
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS vault_metadata (
        \\  id INTEGER PRIMARY KEY,
        \\  salt BLOB NOT NULL,
        \\  kdf_algorithm TEXT NOT NULL,
        \\  version INTEGER NOT NULL,
        \\  created_at INTEGER NOT NULL,
        \\  updated_at INTEGER NOT NULL
        \\)
    );

    // Credentials storage
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS credentials (
        \\  id BLOB PRIMARY KEY,
        \\  name TEXT NOT NULL,
        \\  type TEXT NOT NULL,
        \\  encrypted_data BLOB NOT NULL,
        \\  metadata TEXT NOT NULL,
        \\  created_at INTEGER NOT NULL,
        \\  updated_at INTEGER NOT NULL,
        \\  last_used INTEGER
        \\)
    );

    // Server patterns for auto-loading
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS server_patterns (
        \\  id INTEGER PRIMARY KEY,
        \\  pattern TEXT NOT NULL,
        \\  credential_id BLOB NOT NULL,
        \\  auto_load INTEGER NOT NULL,
        \\  priority INTEGER DEFAULT 0,
        \\  FOREIGN KEY (credential_id) REFERENCES credentials(id)
        \\)
    );

    // Audit log
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS audit_log (
        \\  id INTEGER PRIMARY KEY,
        \\  timestamp INTEGER NOT NULL,
        \\  action TEXT NOT NULL,
        \\  credential_id BLOB,
        \\  success INTEGER NOT NULL,
        \\  details TEXT
        \\)
    );
}
```

**Storage Advantages:**
- **Post-Quantum Security**: zqlite's PQ encryption layer
- **ACID Compliance**: SQLite guarantees
- **Efficient Queries**: Indexed searches
- **Version Control**: Schema migrations
- **Atomic Operations**: Write-Ahead Logging

### Cryptographic Primitives

#### zcrypto Integration

```zig
const zcrypto = @import("zcrypto");

// Argon2id for KDF
pub fn deriveKey(password: []const u8, salt: []const u8) !Key {
    return try zcrypto.kdf.argon2id(
        allocator,
        password,
        salt,
        32,  // key length
    );
}

// ChaCha20-Poly1305 for AEAD encryption
pub fn encryptCredential(plaintext: []const u8, key: Key) !EncryptedData {
    var nonce: [12]u8 = undefined;
    zcrypto.random.bytes(&nonce);

    return try zcrypto.sym.chacha20poly1305.encrypt(
        allocator,
        plaintext,
        key,
        nonce,
        null,  // additional data
    );
}
```

### Memory Security

```zig
pub const SecureMemory = struct {
    pub fn lock(ptr: [*]u8, len: usize) !void {
        // mlock() - prevent swapping to disk
        const result = std.os.linux.mlock(ptr, len);
        if (result != 0) return error.MemoryLockFailed;
    }

    pub fn zero(ptr: [*]u8, len: usize) void {
        // Secure memory zeroing (compiler can't optimize away)
        @memset(ptr[0..len], 0);
        std.mem.doNotOptimizeAway(ptr);
    }

    pub fn unlock(ptr: [*]u8, len: usize) void {
        zero(ptr, len);
        _ = std.os.linux.munlock(ptr, len);
    }
};
```

---

## Comparison with Termius

| Feature | Termius | GVault |
|---------|---------|--------|
| **Architecture** | Electron (C++/Node.js) | Pure Zig (native) |
| **Encryption** | Libsodium (XSalsa20-Poly1305) | zcrypto (ChaCha20-Poly1305) |
| **KDF** | Argon2id (fixed) | Argon2id + SHA-2/3 (flexible) |
| **Storage** | AWS Cloud (mandatory for sync) | zqlite (local + optional sync) |
| **Post-Quantum** | ❌ No | ✅ Yes (via zqlite) |
| **Offline Mode** | Limited | Full functionality |
| **Platform** | Cross-platform GUI | Terminal-native (Linux primary) |
| **SSH Agent** | Built-in | RFC-compliant implementation |
| **Hardware Keys** | FIDO2 | FIDO2 + YubiKey + TPM 2.0 |
| **Biometrics** | Touch ID, Face ID | Fingerprint (PAM), future Touch ID |
| **Team Vaults** | ✅ Yes (Business plan) | ✅ Yes (included) |
| **RBAC** | Owner/Member | Owner/Edit/View |
| **Open Source** | ❌ Proprietary | ✅ Open Source |
| **License** | Subscription | MIT License |
| **Performance** | ~150MB RAM | ~10MB RAM (projected) |
| **Binary Size** | ~200MB (Electron) | ~5MB (native) |

### Advantages Over Termius

1. **No Cloud Lock-In**: Fully functional offline, optional sync
2. **Post-Quantum Security**: Future-proof cryptography via zqlite
3. **Native Performance**: 10x smaller memory footprint
4. **Terminal Integration**: Deep Ghostshell/Ghostty integration
5. **Hardware Security**: TPM 2.0 support for Linux
6. **Open Source**: Auditable, community-driven
7. **Zero Telemetry**: Complete privacy by design

---

## Roadmap

### MVP (Current State) ✅

- [x] Core vault structure with locking/unlocking
- [x] ChaCha20-Poly1305 encryption
- [x] Argon2id + SHA-2/3 KDF support
- [x] Multiple credential types
- [x] CRUD operations
- [x] Search and filtering
- [x] Flash CLI framework integration
- [x] Basic tests

### Alpha (v0.1.0-alpha) - *2 Weeks*

- [ ] zqlite persistent storage
- [ ] Atomic file operations
- [ ] File integrity verification (HMAC)
- [ ] Memory locking (mlock)
- [ ] Audit logging
- [ ] SSH key generation (ED25519, RSA-4096)
- [ ] Basic SSH agent protocol

### Beta (v0.1.0-beta) - *4 Weeks*

- [ ] Complete SSH agent implementation
- [ ] Server pattern matching
- [ ] Auto-key loading
- [ ] GPG key generation
- [ ] Git commit signing
- [ ] Snippet management
- [ ] TUI with Phantom framework

### Theta (v0.1.0-theta) - *6 Weeks*

- [ ] FIDO2 hardware key support
- [ ] YubiKey integration
- [ ] Biometric auth (Linux PAM)
- [ ] Shared vault implementation
- [ ] RBAC system
- [ ] WebRTC terminal sharing
- [ ] Advanced security audit

### Release Candidates

**RC1** - *Week 7*
- [ ] Performance optimization
- [ ] Security audit (external)
- [ ] Documentation completion
- [ ] Integration testing
- [ ] Bug fixes

**RC2** - *Week 8*
- [ ] User acceptance testing
- [ ] Edge case handling
- [ ] Platform compatibility testing
- [ ] Final security review

**RC3** - *Week 9*
- [ ] Release preparation
- [ ] Package creation
- [ ] Distribution setup
- [ ] Marketing materials

### Release v0.1.0 - *Week 10*

- [ ] Official release
- [ ] AUR package (Arch Linux)
- [ ] Homebrew formula (macOS/Linux)
- [ ] GitHub release with binaries
- [ ] Documentation site
- [ ] Community launch

---

## Conclusion

GVault represents the next evolution of credential management for terminal users. By combining:

- **Zig's memory safety and performance**
- **Post-quantum cryptography readiness**
- **Deep terminal integration**
- **Offline-first architecture**
- **Hardware security module support**

We're building a tool that surpasses proprietary solutions while remaining **open source, privacy-respecting, and community-driven**.

### Call to Action

GVault is positioned to become the **de-facto credential manager for Ghostshell/Ghostty** and the broader terminal emulator ecosystem. With planned integration into:

- Ghostshell (primary target)
- Alacritty, Kitty, WezTerm (future plugins)
- Neovim, VSCode (editor integrations)

We're creating a universal, secure, and performant solution for the modern developer.

---

## Technical Specifications

### Supported Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux (Wayland)** | ✅ Primary | Full feature support |
| **Linux (X11)** | ✅ Secondary | Clipboard limitations |
| **macOS** | 🔄 Planned | v0.2.0 target |
| **Windows** | 🔄 Future | v0.3.0 target |

### Dependencies

```zig
.dependencies = .{
    .flash = .{ .url = "...", .hash = "..." },      // CLI framework
    .zcrypto = .{ .url = "...", .hash = "..." },    // Cryptography
    .zssh = .{ .url = "...", .hash = "..." },       // SSH implementation
    .zqlite = .{ .url = "...", .hash = "..." },     // Post-quantum database
    .phantom = .{ .url = "...", .hash = "..." },    // TUI framework
};
```

### Performance Targets

- **Unlock Time**: < 100ms (Argon2id with 1000 credentials)
- **Search**: < 10ms (pattern matching across vault)
- **Key Generation**: < 1s (RSA-4096)
- **Memory Usage**: < 10MB (1000 credentials loaded)
- **Binary Size**: < 5MB (optimized release build)

### Security Certifications (Planned)

- [ ] SOC 2 Type II compliance
- [ ] OWASP Security Audit
- [ ] Penetration testing report
- [ ] CVE monitoring program
- [ ] Bug bounty program

---

## Contact & Contributing

**Project Repository**: https://github.com/ghostkellz/gvault
**Documentation**: https://gvault.ghostkellz.sh
**Security Issues**: security@ghostkellz.sh
**Community**: Discord / Matrix

**License**: MIT
**Maintainer**: Christopher Kelley (@ghostkellz)

---

*GVault: Your keys, your control, your terminal.*
