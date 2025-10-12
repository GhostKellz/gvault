# 🔐 GVault Wishlist for GShell Integration

<div align="center">
  <strong>What GShell needs from GVault to become the ultimate terminal keychain</strong>
</div>

---

## 📋 Current Status

✅ **Already Have:**
- Architecture designed with ChaCha20-Poly1305 + Argon2id
- SSH key management and generation planned
- GPG integration in roadmap
- Pattern matching for auto-loading keys
- Session isolation and auto-lock

⏳ **In Progress:**
- Phase 1: Secure storage backend (Week 1-2)
- Phase 2: SSH integration (Week 3-4)
- Phase 3: GPG integration (Week 5-6)

---

## 🎯 What GShell Needs

### **P0: Critical Path** (Needed for GShell v0.2.0 - Next 4 weeks)

#### 1. **Shell API Module** (`shell_api.zig`)

A simple, synchronous API that GShell can call without complex async handling:

```zig
const gvault = @import("gvault");

// Shell needs simple credential retrieval
pub fn getCredentialForHost(allocator: std.mem.Allocator, hostname: []const u8) !?Credential {
    var vault = try gvault.Vault.initSession(allocator);
    defer vault.unlock();

    return try vault.findBestMatch(hostname);
}

// List all credentials for tab completion
pub fn listAllCredentials(allocator: std.mem.Allocator) ![]const CredentialInfo {
    // Return simplified credential list for shell autocomplete
    // No sensitive data, just names and hostnames
}

// Add credential from shell command
pub fn addCredential(allocator: std.mem.Allocator, cred: CredentialInput) !void {
    // gshell > vault add --name "prod-server" --type ssh --host "*.prod.example.com"
}
```

**Use Case:**
```bash
# In GShell
$ ssh prod-db
# GShell calls getCredentialForHost("prod-db")
# GVault auto-loads correct SSH key
# Connection succeeds without manual key selection

$ vault list
# Shows all stored credentials for quick reference

$ vault add --name "staging" --host "*.staging.company.com"
# Adds new credential pattern
```

#### 2. **Pattern Matching for Hostnames**

GShell needs intelligent matching for SSH hosts:

```zig
// Patterns to support:
// 1. Exact match: "prod-db.example.com"
// 2. Wildcard: "*.prod.example.com"
// 3. Regex: "^prod-.*\\.example\\.com$"
// 4. IP ranges: "192.168.1.*"
// 5. Jump host chains: "bastion -> prod-db"

pub const HostPattern = union(enum) {
    exact: []const u8,
    wildcard: []const u8,
    regex: []const u8,
    ip_range: []const u8,
};

pub fn matchesPattern(hostname: []const u8, pattern: HostPattern) bool {
    // Fast pattern matching for shell operations
}
```

**Use Case:**
```bash
$ vault add --name "production-fleet" --pattern "*.prod.example.com" --key ~/.ssh/prod_rsa
# Now all prod-* hosts use this key automatically

$ ssh prod-web-01.prod.example.com  # Matches!
$ ssh prod-db-02.prod.example.com   # Matches!
$ ssh staging-web.staging.example.com  # Doesn't match (different pattern)
```

#### 3. **Async Unlock with Timeout**

GShell REPL cannot block on user input during normal operations:

```zig
pub const UnlockOptions = struct {
    timeout_ms: u64 = 5000,  // 5 second timeout
    prompt: []const u8 = "🔐 Vault password: ",
    allow_cached: bool = true,  // Use cached session if available
};

pub fn unlockVault(allocator: std.mem.Allocator, options: UnlockOptions) !VaultSession {
    // Try cached session first
    if (options.allow_cached) {
        if (getCachedSession()) |session| return session;
    }

    // Otherwise, prompt with timeout
    // Must be non-blocking for shell REPL
    const password = try promptWithTimeout(options.prompt, options.timeout_ms);
    return try Vault.init(allocator, password);
}
```

**Use Case:**
```bash
$ ssh prod-db
🔐 Vault password: ********
# User has 5 seconds to enter password
# If timeout, falls back to default SSH behavior
# Session stays unlocked for duration of GShell session

$ ssh prod-web  # Same session, no re-prompt
$ ssh staging-db  # Same session, no re-prompt
```

---

### **P1: Important** (Needed for GShell v0.3.0 - 4-8 weeks)

#### 4. **GPG Key Management for Git Signing**

GShell wants to auto-sign git commits using stored GPG keys:

```zig
pub fn getGpgKeyForEmail(allocator: std.mem.Allocator, email: []const u8) !?GpgKey {
    // Match GPG key by email address
    // Used for git commit signing
}

pub fn signData(data: []const u8, key_id: []const u8) ![]const u8 {
    // Sign arbitrary data with stored GPG key
    // Used by built-in git commands
}
```

**Use Case:**
```bash
$ git config --global commit.gpgsign true
$ git config --global user.signingkey "$(vault gpg-key chris@ghost.dev)"
# GShell integrates with GVault to sign commits automatically

$ git commit -m "feat: add new feature"
🔐 Sign commit with GPG key chris@ghost.dev? [Y/n]: y
# GVault signs commit, no need for gpg-agent
```

#### 5. **API Token Storage for Cloud CLIs**

Store AWS, GCP, Docker Hub tokens securely:

```zig
pub const ApiToken = struct {
    name: []const u8,
    token: []const u8,  // Encrypted at rest
    service: []const u8,  // "aws", "gcp", "docker", etc.
    expires_at: ?i64,
};

pub fn getApiToken(allocator: std.mem.Allocator, service: []const u8) !?ApiToken {
    // Retrieve API token for cloud service
}

pub fn setApiToken(allocator: std.mem.Allocator, token: ApiToken) !void {
    // Store encrypted API token
}
```

**Use Case:**
```bash
$ vault token add aws --token "AKIAIOSFODNN7EXAMPLE"
$ vault token add gcp --token "ya29.a0AfH6SMB..."
$ vault token add docker --token "dckr_pat_..."

# GShell can now auto-inject tokens into commands
$ aws s3 ls  # GShell injects AWS credentials from vault
$ gcloud projects list  # GShell injects GCP credentials
```

#### 6. **SSH Agent Integration**

GShell should act as an SSH agent using GVault keys:

```zig
pub fn startSshAgent(allocator: std.mem.Allocator) !SshAgent {
    // Start SSH agent using GVault as backend
    // Set SSH_AUTH_SOCK for child processes
}

pub fn addKeyToAgent(agent: *SshAgent, key_name: []const u8) !void {
    // Add key from vault to running agent
}
```

**Use Case:**
```bash
$ gshell  # Starts shell with integrated SSH agent
SSH_AUTH_SOCK=/tmp/gshell-agent-12345

$ vault agent start  # Start SSH agent backed by GVault
$ vault agent add prod-key  # Load key into agent

$ ssh prod-db  # Uses agent, no password prompt
$ git push origin main  # Uses agent for git SSH
```

---

### **P2: Nice to Have** (Needed for GShell v0.4.0+ - 8+ weeks)

#### 7. **Jump Host / Bastion Support**

Complex SSH setups with bastion hosts:

```zig
pub const JumpHost = struct {
    hostname: []const u8,
    credential: []const u8,
    port: u16 = 22,
};

pub const SshConnection = struct {
    target: []const u8,
    credential: []const u8,
    jump_hosts: []const JumpHost,
};

pub fn resolveConnection(hostname: []const u8) !SshConnection {
    // Resolve full connection path including jumps
}
```

**Use Case:**
```bash
$ vault connection add prod-db \
    --target "prod-db.internal" \
    --via "bastion.example.com" \
    --key prod-key

$ ssh prod-db
# GShell automatically: ssh bastion -> ssh prod-db
# Using correct keys for each hop
```

#### 8. **Credential Health Monitoring**

Alert when credentials are about to expire:

```zig
pub fn checkCredentialHealth(allocator: std.mem.Allocator) ![]HealthReport {
    // Return list of expiring/expired credentials
}

pub const HealthReport = struct {
    credential_name: []const u8,
    status: enum { healthy, expiring_soon, expired },
    expires_in_days: ?i64,
};
```

**Use Case:**
```bash
$ gshell  # On startup
⚠️  Warning: 3 credentials expiring soon:
  - prod-api-token (expires in 7 days)
  - staging-cert (expires in 2 days)
  - docker-hub-token (expired 1 day ago)

$ vault health
Credential Health Report:
  ✅ prod-ssh-key (valid for 365 days)
  ⚠️  prod-api-token (expires in 7 days)
  ⚠️  staging-cert (expires in 2 days)
  ❌ docker-hub-token (expired 1 day ago)
```

#### 9. **Backup and Sync**

Securely backup vault to git repository:

```zig
pub fn exportVault(allocator: std.mem.Allocator, path: []const u8) !void {
    // Export encrypted vault to file
    // Safe to commit to private git repo
}

pub fn importVault(allocator: std.mem.Allocator, path: []const u8) !void {
    // Import vault from backup
}
```

**Use Case:**
```bash
$ vault backup ~/dotfiles/vault/gvault.enc
$ cd ~/dotfiles
$ git add vault/gvault.enc
$ git commit -m "chore: backup vault"
$ git push origin main

# On new machine:
$ cd ~/dotfiles && git pull
$ vault restore ~/dotfiles/vault/gvault.enc
🔐 Enter vault password: ********
✅ Vault restored with 42 credentials
```

---

### **P3: Future Vision** (Nice to have, no timeline)

#### 10. **Hardware Security Module Support**

YubiKey and TPM integration:

```zig
pub fn setupHsm(allocator: std.mem.Allocator, device: HsmDevice) !void {
    // Use YubiKey/TPM for key derivation
}
```

#### 11. **Team Credential Sharing**

Encrypted credential sharing for team environments:

```zig
pub fn shareCredential(cred_name: []const u8, team_members: []const []const u8) !void {
    // Encrypt credential for multiple recipients
}
```

---

## 🔧 API Design Preferences

### **What GShell Prefers:**

1. **Synchronous APIs**: GShell REPL is synchronous, async complicates integration
2. **Error Types**: Clear error enums, not generic errors
3. **Allocator Patterns**: Accept allocator parameter, let caller manage memory
4. **Session Management**: Long-lived sessions, not per-call authentication
5. **Zero Dependencies**: Don't require GShell to link extra libraries

### **Example Perfect API:**

```zig
// Simple, synchronous, allocator-based, clear errors
pub fn getCredential(allocator: std.mem.Allocator, hostname: []const u8) !?Credential {
    var vault = try Vault.getSession(allocator);
    return try vault.find(hostname);
}

pub const VaultError = error{
    VaultLocked,
    CredentialNotFound,
    InvalidPassword,
    PatternSyntaxError,
    StorageCorrupted,
};
```

---

## 📊 Integration Success Metrics

When GVault integration is complete, GShell users should be able to:

- ✅ `ssh prod-db` without manual key selection (auto-loads correct key)
- ✅ `vault list` shows all credentials
- ✅ `vault add` stores new credentials
- ✅ `git commit -S` auto-signs with GPG key from vault
- ✅ `aws s3 ls` uses API token from vault
- ✅ `gshell` starts with SSH agent backed by vault
- ✅ Vault stays unlocked for shell session duration
- ✅ No password re-prompts during normal usage

---

## 🤝 Collaboration

GShell is happy to:
- Test GVault features as they're built
- Provide real-world use cases and feedback
- Contribute PRs for shell-specific APIs
- Write integration tests

GVault can prioritize:
- P0 features for immediate GShell integration (next 4 weeks)
- P1 features for power user workflows (4-8 weeks)
- P2 features as nice-to-haves (8+ weeks)

**Let's build the most seamless terminal keychain experience ever!** 🚀

---

## 📞 Contact

For questions or coordination:
- Open an issue in GShell repo: [ghostkellz/gshell](https://github.com/ghostkellz/gshell)
- Reference this wishlist in GVault issues/PRs
- Coordinate timelines in DRAFT_DISCOVERY.md

**Thank you for building GVault!** 🔐
