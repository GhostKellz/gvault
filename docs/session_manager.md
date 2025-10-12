# Session Manager Design

## Goals

- Provide a reusable unlocking subsystem that the CLI and GShell/Ghostshell integrations can share without bespoke plumbing.
- Guarantee that master keys stay resident only in locked memory and are wiped deterministically when no longer needed.
- Allow synchronous callers to obtain a vault session quickly, reusing cached unlock state when possible.
- Support configurable inactivity timeouts with auto-lock and event notification hooks for future UI feedback.
- Keep the implementation allocator-friendly and deterministic for testing.

## Components

### `SessionManager`

A singleton-style coordinator responsible for tracking the active `Vault` instance and its lifecycle.  Intent is to expose:

```zig
pub const SessionManager = struct {
    pub fn init(config: SessionConfig) !void;
    pub fn deinit() void;

    pub fn acquire(allocator: std.mem.Allocator) !*VaultSession;
    pub fn release(session: *VaultSession) void;

    pub fn lock() void;               // force lock
    pub fn status() SessionStatus;    // for CLI/status command
};
```

### `VaultSession`

A lightweight handle that wraps a pointer to the unlocked `root.Vault`, guarded by a refcount.  Provides convenience helpers (`encrypt`, `decrypt`, credential lookup) that delegate to `root.Vault` while ensuring session validity.

### `SessionConfig`

```zig
pub const SessionConfig = struct {
    vault_path: []const u8,
    unlock_timeout_ms: u64 = 5_000,
    inactivity_ttl_ns: ?u64 = std.time.ns_per_min * 15, // auto-lock after 15 min by default
    allow_cached_unlock: bool = true,
    prompt_fn: PromptFn = defaultPrompt,
    clock: Clock = .auto,
};
```

- `prompt_fn`: callback invoked when interactive unlock is required. Allows swapping in REPL-friendly prompt w/ timeout.
- `clock`: interface so tests can mock time and verify TTL behaviour.

### `UnlockCache`

Keeps the encrypted master key material in secure memory between unlocks so that password prompting is skipped inside the TTL.

```zig
const UnlockCache = struct {
    sealed_key: ?[]u8, // ChaCha20 sealed master key using random nonce
    expires_at_ns: ?u64,
    secure_buf: secure_mem.SecureBuffer,
};
```

- When `SessionManager.acquire` is called and no active session exists, we check the cache.
- If cache valid, decrypt sealed key and hydrate `Vault` without prompting.
- On timeout or explicit `lock`, secure wipe the sealed blob and release buffer.

## Control Flow

1. **Initialization**
   - CLI/startup calls `SessionManager.init(config)` exactly once.
   - Manager loads metadata via `root.Vault.init` but leaves it locked until first `acquire`.
   - Secure buffer reserved up front for master key + sealed copy.

2. **Acquire Session**
   - Increment refcount to guard concurrent users.
   - If vault already unlocked, return current session handle.
   - Otherwise attempt cache restore.
   - If cache miss/expired, invoke `prompt_fn` with timeout. Prompt returns passphrase or `error.Timeout`.
   - Derive master key through `Vault.unlock`, update cache (seal derived key with random nonce), set `expires_at_ns` if TTL configured.
   - Start inactivity timer; store `last_used_ns` on session.

3. **Release Session**
   - Decrement refcount; update `last_used_ns` for TTL.
   - If refcount drops to 0, schedule auto-lock check.  Timer compares `current_time - last_used_ns` against TTL; if exceeded, call `Vault.lock()` and scrub key material.

4. **Forced Lock**
   - Exposed via CLI `vault lock` or when TTL hits.
   - Cancels timers, clears cache, zeroes master key using `secure_mem.secureZero`.

5. **Shutdown**
   - `deinit` locks vault, frees secure buffers, ensures storage handles closed cleanly.

## Error Handling

- `SessionError` enum supplements `root.GVaultError` with:
  - `UnlockTimedOut`
  - `PromptUnavailable`
  - `SessionBusy`
  - `AlreadyInitialized`
- `SessionManager.acquire` returns `error` wrapping either `SessionError` or underlying vault errors.
- Timeout from prompt propagates as `error.UnlockTimedOut` so shell can fall back gracefully.

## Thread Safety & Concurrency

- Manager protects shared state with `std.Thread.Mutex` (or spinlock when Zig gains userspace mutex in std).
- Refcount stored in atomic `u32` to prevent double free.
- Prompt call occurs outside of lock to avoid blocking other status queries; we use a simple state machine to prevent double prompts.

## Secure Memory Strategy

- `secure_mem.lockMemory` applied to:
  - Master key inside `root.Vault`
  - Sealed key buffer in cache
  - Temporary passphrase buffer returned by prompt (via `SecureBuffer` helper that zeroizes on drop)
- On UNIX we rely on `mlock` / `munlock`; on systems where unsupported we log warning but continue.
- All passphrases erased immediately after deriving master key.

## CLI / API Touchpoints

- `vault unlock` → `SessionManager.acquire`; on success prints status; release immediately afterwards.
- `vault lock` → `SessionManager.lock`.
- `vault status` → `SessionManager.status` (reports locked/unlocked, expires in).
- Shell API functions call `SessionManager.acquire` internally, hold handle for duration of operation, then release.

## Testing Plan

1. **Unit Tests**
   - Mock prompt returning deterministic passphrase; verify unlock + cache reuse.
   - Simulate timeout by returning `error.Timeout`; ensure error surfaces and vault remains locked.
   - Inject fake clock to test TTL auto-lock.
   - Ensure reference counting prevents early lock while multi commands active.

2. **Integration Tests**
   - Use temp directory for vault storage; run `unlock → add credential → release → reacquire`.
   - Confirm master key buffer is zeroed after lock via pointer inspection (feature gated for debug).

3. **Fuzz Hooks**
   - Later: harness around prompt state machine to guard against race conditions.

## Next Steps

- Implement `docs/secure_prompt.md` describing prompt contract and how GShell supplies its UI.
- Wire `SessionManager` into `src/root.zig` or new `session.zig` module.
- Update CLI commands to adopt manager once implementation lands.
