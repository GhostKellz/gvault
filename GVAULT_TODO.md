# GVAULT_TODO.md - Terminal Keychain Manager Development Roadmap

🔐 **Mission: Build the most secure, efficient keychain manager optimized for terminal emulators and home lab workflows**

## Overview

gvault is a secure credential management library designed specifically for terminal emulators. Unlike general-purpose password managers or crypto wallets, gvault focuses on SSH keys, GPG keys, API tokens, and server credentials that power users and home lab enthusiasts need every day.

## Direct Impact on Ghostshell

### Immediate Terminal Enhancements
```bash
# Instead of managing keys manually
ssh-add ~/.ssh/id_rsa
ssh user@server

# Ghostshell with gvault integration
ghostshell connect production-server  # Auto-loads correct key
ghostshell ssh-keygen --vault-store  # Generate and store automatically
ghostshell vault list                # View all credentials
```

## Core Requirements

### 🎯 Phase 1: Foundation (Week 1-2)

#### 1. Secure Storage Backend
```zig
pub const Vault = struct {
    path: []const u8,
    master_key: [32]u8,
    cipher: zcrypto.ChaCha20Poly1305,

    pub fn init(path: []const u8, passphrase: []const u8) !Vault;
    pub fn unlock(self: *Vault, passphrase: []const u8) !void;
    pub fn lock(self: *Vault) void;

    // Auto-lock after inactivity
    pub fn setAutoLock(self: *Vault, timeout_seconds: u32) void;
};
```

#### 2. Credential Types
```zig
pub const CredentialType = enum {
    ssh_key,
    gpg_key,
    api_token,
    password,
    certificate,
    server_config, // Host, port, username combo
};

pub const Credential = struct {
    id: Uuid,
    name: []const u8,
    type: CredentialType,
    data: []const u8, // Encrypted
    metadata: Metadata,

    pub const Metadata = struct {
        created: i64,
        last_used: ?i64,
        auto_load: bool,
        tags: [][]const u8,
        server_patterns: ?[][]const u8, // Auto-match servers
    };
};
```

#### 3. Basic CRUD Operations
```zig
pub fn add(self: *Vault, cred: Credential) !Uuid;
pub fn get(self: *Vault, id: Uuid) !Credential;
pub fn update(self: *Vault, id: Uuid, cred: Credential) !void;
pub fn delete(self: *Vault, id: Uuid) !void;
pub fn list(self: *Vault, filter: ?Filter) ![]Credential;
```

### 🚀 Phase 2: SSH Integration (Week 3-4)

#### 1. SSH Key Management
```zig
pub const SshKey = struct {
    private_key: []const u8,
    public_key: []const u8,
    type: SshKeyType,
    passphrase: ?[]const u8,

    pub const SshKeyType = enum {
        rsa_2048,
        rsa_4096,
        ed25519,
        ecdsa_256,
        ecdsa_384,
        ecdsa_521,
    };
};

// SSH key operations
pub fn generateSshKey(self: *Vault, options: SshKeyOptions) !Uuid;
pub fn importSshKey(self: *Vault, path: []const u8) !Uuid;
pub fn exportSshKey(self: *Vault, id: Uuid, path: []const u8) !void;
```

#### 2. SSH Agent Protocol
```zig
pub const SshAgent = struct {
    vault: *Vault,
    socket_path: []const u8,

    // Act as SSH agent
    pub fn start(self: *SshAgent) !void;
    pub fn addKey(self: *SshAgent, id: Uuid) !void;
    pub fn removeKey(self: *SshAgent, id: Uuid) void;
    pub fn listKeys(self: *SshAgent) ![]PublicKey;

    // Handle agent requests
    pub fn handleSignRequest(self: *SshAgent, data: []const u8, key_id: Uuid) ![]const u8;
};
```

#### 3. Auto-loading for Connections
```zig
pub const AutoLoader = struct {
    pub fn matchServer(self: *Vault, hostname: []const u8) ?Uuid;
    pub fn loadForSession(self: *Vault, hostname: []const u8) !void;

    // Pattern matching
    pub fn addPattern(self: *Vault, key_id: Uuid, pattern: []const u8) !void;
};
```

### 🔐 Phase 3: GPG Integration (Week 5-6)

#### 1. GPG Key Support
```zig
pub const GpgKey = struct {
    key_id: []const u8,
    private_key: []const u8,
    public_key: []const u8,
    subkeys: []SubKey,
    identities: []Identity,
};

pub fn generateGpgKey(self: *Vault, identity: Identity) !Uuid;
pub fn importGpgKey(self: *Vault, armored: []const u8) !Uuid;
pub fn signData(self: *Vault, key_id: Uuid, data: []const u8) ![]const u8;
pub fn encryptData(self: *Vault, recipient: Uuid, data: []const u8) ![]const u8;
```

#### 2. Git Commit Signing
```zig
pub fn setupGitSigning(self: *Vault, key_id: Uuid) !void;
pub fn signGitCommit(self: *Vault, commit_data: []const u8) ![]const u8;
```

### ⚡ Phase 4: Terminal Integration (Week 7-8)

#### 1. Ghostshell-Specific Features
```zig
pub const GhostshellIntegration = struct {
    vault: *Vault,

    // Quick access shortcuts
    pub fn registerHotkey(self: *GhostshellIntegration, key: Hotkey, action: Action) !void;

    // Terminal UI
    pub fn showPicker(self: *GhostshellIntegration) !?Uuid; // TUI credential picker
    pub fn showStatus(self: *GhostshellIntegration) void;    // Status bar integration

    // Session management
    pub fn attachToSession(self: *GhostshellIntegration, session_id: []const u8) !void;
    pub fn detachFromSession(self: *GhostshellIntegration) void;
};
```

#### 2. Clipboard Integration
```zig
pub const ClipboardManager = struct {
    // Secure clipboard operations
    pub fn copyPassword(self: *Vault, id: Uuid, timeout_seconds: u32) !void;
    pub fn copyPublicKey(self: *Vault, id: Uuid) !void;

    // Auto-clear sensitive data
    pub fn startAutoClear(self: *ClipboardManager) void;
};
```

#### 3. Server Profile Management
```zig
pub const ServerProfile = struct {
    name: []const u8,
    hostname: []const u8,
    port: u16,
    username: []const u8,
    key_id: Uuid,
    jump_hosts: ?[]JumpHost,
    environment: ?[]EnvVar,
    startup_commands: ?[][]const u8,
};

pub fn saveProfile(self: *Vault, profile: ServerProfile) !Uuid;
pub fn connectProfile(self: *Vault, profile_id: Uuid) !SshSession;
```

### 🔒 Phase 5: Security Features (Week 9-10)

#### 1. Hardware Security Module Support
```zig
pub const HsmBackend = struct {
    // YubiKey, TPM, etc.
    pub fn detectHardware() ![]HsmDevice;
    pub fn storeInHsm(self: *Vault, key_id: Uuid, device: HsmDevice) !void;
    pub fn signWithHsm(self: *Vault, device: HsmDevice, data: []const u8) ![]const u8;
};
```

#### 2. Audit Logging
```zig
pub const AuditLog = struct {
    pub const Event = struct {
        timestamp: i64,
        action: Action,
        credential_id: ?Uuid,
        source: []const u8, // Terminal session, API, etc.
        success: bool,
    };

    pub fn log(self: *AuditLog, event: Event) !void;
    pub fn query(self: *AuditLog, filter: Filter) ![]Event;
};
```

#### 3. Key Rotation
```zig
pub fn rotateKey(self: *Vault, id: Uuid) !Uuid;
pub fn scheduleRotation(self: *Vault, id: Uuid, interval_days: u32) !void;
pub fn checkExpiredKeys(self: *Vault) ![]Uuid;
```

## API Examples

### Basic Usage
```zig
const gvault = @import("gvault");

// Initialize vault
var vault = try gvault.Vault.init("/home/user/.config/ghostshell/vault", "master_pass");
defer vault.lock();

// Generate new SSH key
const key_id = try vault.generateSshKey(.{
    .type = .ed25519,
    .name = "production-server",
    .auto_load = true,
    .server_patterns = &.{"*.prod.example.com"},
});

// Use in terminal
const cred = try vault.get(key_id);
try ssh_client.authenticate(cred);
```

### Ghostshell Integration
```zig
// In Ghostshell's SSH command handler
pub fn handleSshCommand(self: *Terminal, args: [][]const u8) !void {
    const hostname = args[1];

    // Auto-load matching key from vault
    if (self.vault.matchServer(hostname)) |key_id| {
        try self.vault.loadForSession(hostname);
    }

    // Continue with SSH connection
    try self.ssh_client.connect(hostname);
}
```

### Server Profiles
```zig
// Save frequently used server
const profile = ServerProfile{
    .name = "Production DB",
    .hostname = "db.prod.example.com",
    .port = 22,
    .username = "admin",
    .key_id = key_id,
    .jump_hosts = &.{JumpHost{ .host = "bastion.example.com" }},
    .startup_commands = &.{"tmux attach || tmux new"},
};

const profile_id = try vault.saveProfile(profile);

// Quick connect later
ghostshell connect "Production DB"
```

## Security Considerations

### Encryption
- **Master key derivation**: Argon2id with proper parameters
- **Storage encryption**: ChaCha20-Poly1305 or AES-256-GCM
- **Memory protection**: mlock() sensitive data, zero on free
- **Key isolation**: Each credential encrypted with unique key

### Access Control
- **Session binding**: Keys only available to specific terminal session
- **Time limits**: Auto-lock after inactivity
- **Rate limiting**: Prevent brute force attempts
- **Audit trail**: Log all access attempts

### Platform Security
- **Linux**: Use kernel keyring when available
- **macOS**: Integrate with Keychain Services
- **Windows**: Use Windows Credential Manager
- **Wayland**: Secure clipboard through wzl

## Performance Targets

- **Unlock speed**: < 100ms for 1000 credentials
- **Search**: < 10ms for pattern matching
- **Key generation**: < 1s for RSA-4096
- **Memory usage**: < 10MB for 1000 credentials
- **Zero allocations**: During normal operations

## Integration with Ghostshell Ecosystem

### With zsync
```zig
// Async key operations
const task = zsync.spawn(async {
    const key = await vault.generateSshKeyAsync(.{ .type = .ed25519 });
    await vault.uploadToServer(key);
});
```

### With wzl (Wayland)
```zig
// Secure clipboard operations
const clipboard = wzl.Clipboard.init();
try vault.copyToClipboard(key_id, clipboard);
```

### With ghostnet
```zig
// Distributed vault sync
const sync = ghostnet.Sync.init(vault);
try sync.replicateToBackup("backup.example.com");
```

## Success Metrics

- ✅ Replace ssh-agent completely
- ✅ 10x faster than gnome-keyring
- ✅ Zero password prompts for configured servers
- ✅ Seamless Ghostshell integration
- ✅ < 5000 lines of core code
- ✅ Support 90% of SSH key operations

## Killer Features for Home Lab Users

### 1. **Multi-Server Management**
```bash
# Connect to any of 50+ servers instantly
ghostshell connect prod-db  # Auto-loads correct key, jump hosts, etc.
```

### 2. **Bulk Key Operations**
```bash
# Generate keys for entire infrastructure
ghostshell vault generate-fleet --servers=servers.txt
```

### 3. **Session Recording**
```bash
# Record SSH sessions with credentials safely stripped
ghostshell record production-debug --vault-sanitize
```

### 4. **Team Sharing** (Future)
```bash
# Share credentials securely with team
ghostshell vault share --key=staging --team=devops
```

## Development Phases Summary

- **Week 1-2**: Core vault storage and encryption
- **Week 3-4**: SSH key management and agent
- **Week 5-6**: GPG support
- **Week 7-8**: Ghostshell terminal integration
- **Week 9-10**: Security hardening and polish

---

**🔐 Let's build the ultimate terminal keychain manager that makes SSH feel magical!**