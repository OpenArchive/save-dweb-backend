# Bug Report Analysis

## Executive Summary

This analysis identifies **5 critical issues** and **2 architectural concerns** in the save-dweb-backend system based on the bug report. The primary issue is a **race condition during initialization** where group creation can happen before Veilid Iroh Blobs API is fully initialized.

---

## 1. Critical Bug: Group Creation Before Initialization

### Symptoms
```
POST /api/groups
AppError occurred: Veilid Iroh Blobs API not initialized
500 Internal Server Error
```

### Root Cause
**Location**: `src/backend.rs:343-345`

The `create_group()` method calls `inner.iroh_blobs()` which checks if `iroh_blobs` is `None`:

```rust
pub async fn create_group(&self) -> Result<Group> {
    let mut inner = self.inner.lock().await;
    let iroh_blobs = inner.iroh_blobs()?;  // Line 345 - fails if None
    // ...
}
```

**Problem**: The `start()` method is async and initializes `iroh_blobs` at line 243, but there's no guard preventing `create_group()` from being called before `start()` completes or if initialization fails.

### Expected vs Broken
- **Expected**: `create_group()` should wait for initialization or return a clear error.
- **Broken**: No synchronization between `start()` and `create_group()`.

### Fix Strategy
1. Add an initialization state flag to `BackendInner`.
2. Make `create_group()` wait for initialization or check initialization state.
3. Add initialization timeout handling.

---

## 2. DHT Lookup Failures

### Symptoms
```
Error getting repo hash from DHT: Unable to get DHT value for repo root hash
```

### Root Cause
**Location**: `src/repo.rs:134-139`

The `get_hash_from_dht()` method fails when:
1. The DHT value hasn't been set yet (new repo without uploads).
2. DHT network isn't ready.
3. The repo owner hasn't published the hash.

```rust
pub async fn get_hash_from_dht(&self) -> Result<Hash> {
    let value = self
        .routing_context
        .get_dht_value(self.dht_record.key().clone(), HASH_SUBKEY, true)
        .await?
        .ok_or_else(|| anyhow!("Unable to get DHT value for repo root hash"))?;
    // ...
}
```

### Expected vs Broken
- **Expected**: Gracefully handle missing DHT values for new/empty repos.
- **Broken**: Hard error prevents listing files even when repo exists locally.

### Fix Strategy
- Check if repo is writable and has local collection before DHT lookup.
- Return empty file list if DHT lookup fails for read-only repos (this is partially implemented in `list_files()` but not consistently).

---

## 3. Peer Download Failures

### Symptoms
```
Error downloading collection: Unable to download from any peer
Error downloading file: Unable to download from any peer
```

### Root Cause
**Location**: `src/rpc.rs:641-670` and `src/group.rs:122-148`

The download logic iterates through repos but:
1. Doesn't retry with exponential backoff.
2. Doesn't wait for network readiness.
3. May try downloading before peers have advertised their route IDs.

```rust
async fn download(group: &Group, hash: &Hash) -> Result<()> {
    // ... tries each repo sequentially
    for repo_key in repo_keys.iter() {
        let repo = group.get_repo(&repo_key).await?;
        if let Ok(route_id_blob) = repo.get_route_id_blob().await {
            // ...
            if result.is_ok() {
                return Ok(());
            }
        }
    }
    Err(anyhow!("Unable to download from any peer"))
}
```

### Expected vs Broken
- **Expected**: Retry logic, peer availability checks, timeout handling.
- **Broken**: Single-pass attempt with no retry mechanism.

### Fix Strategy
- Add retry logic with exponential backoff.
- Check peer availability before attempting download.
- Add timeouts for DHT lookups and downloads.

---

## 4. Group Member Visibility Issue

### Symptoms
> "Group owner cannot see members until: app force stop, server restart"

### Root Cause
**Location**: Likely in DHT record subscription/listening logic.

The issue suggests that:
1. DHT updates aren't being subscribed to properly.
2. Member additions aren't triggering refresh events.
3. Cache invalidation isn't happening when members join.

### Expected vs Broken
- **Expected**: Real-time updates when members join groups.
- **Broken**: Manual refresh required to see new members.

### Fix Strategy
- Implement DHT record watchers/subscribers.
- Add event notifications for member additions.
- Invalidate caches on DHT updates.

---

## 5. Refresh Returns Files from Multiple Groups

### Symptoms
> "Refresh returns files from **multiple groups** in one repo response."

### Root Cause
**Location**: Likely in the refresh endpoint handler (not in this repo, but in Android app or HTTP wrapper).

However, the issue may stem from:
- Shared `VeilidIrohBlobs` instance across groups.
- Collection hash collision or name collision.
- Incorrect filtering when listing repos.

### Expected vs Broken
- **Expected**: Refresh should return files only from the specified group.
- **Broken**: Files from other groups leak into the response.

### Fix Strategy
- Ensure repo filtering by group ID.
- Verify collection naming doesn't collide between groups.
- Add group ID validation in refresh handlers.

---

## 6. Android 16.1 Initialization Failure

### Symptoms
> "Android 16.1 prevents Rust code from initializing."

### Root Cause
Unknown - likely related to:
- File permissions in Android sandbox.
- Veilid network initialization on Android.
- Threading/tokio runtime issues on Android.

### Expected vs Broken
- **Expected**: Veilid should initialize on Android 16.1.
- **Broken**: Initialization fails completely.

### Fix Strategy
- Add more detailed logging around initialization.
- Check Android-specific file permissions.
- Investigate Veilid compatibility with Android 16.1.

---

## 7. Architecture Concern: Initialization Order

### Problem
The `Backend` has two initialization paths:
1. `new()` + `start()` - sets up Veilid and Iroh from scratch.
2. `from_dependencies()` - takes pre-initialized Veilid API.

Both paths initialize `iroh_blobs` differently, and there's no guarantee of completion before use.

### Recommendation
- Add explicit initialization state tracking.
- Implement a readiness check API.
- Ensure all public methods check initialization state.

---

## 8. Architecture Concern: Error Handling

### Problem
Many async operations return generic errors without context:
- DHT failures don't distinguish between "not ready" vs "not found".
- Network errors don't distinguish between "peer unavailable" vs "route dead".

### Recommendation
- Create error types that distinguish failure modes.
- Add structured logging with context.
- Implement retry strategies based on error type.

---

## Priority Recommendations

### Immediate (P0)
1. **Fix initialization race**: Add state tracking to prevent `create_group()` before `start()` completes.
2. **Improve DHT error handling**: Make `get_hash_from_dht()` handle missing values gracefully.

### Short-term (P1)
3. **Add retry logic**: Implement retries for peer downloads with backoff.
4. **Fix member visibility**: Implement DHT record watchers for real-time updates.

### Medium-term (P2)
5. **Fix multi-group file leak**: Investigate and fix refresh endpoint filtering.
6. **Android compatibility**: Debug Android 16.1 initialization issues.

---

## Minimal Logging Recommendations

To disambiguate DHT vs peer vs local state issues, add logging at:

1. **Initialization lifecycle**:
   - `backend.rs:243` - Log when `iroh_blobs` is initialized.
   - `backend.rs:345` - Log when `create_group()` is called before init.

2. **DHT operations**:
   - `repo.rs:137` - Log DHT lookup attempts with subkey and record key.
   - `repo.rs:240` - Log when DHT lookup fails but local collection exists.

3. **Peer operations**:
   - `group.rs:136` - Log each peer download attempt with peer ID.
   - `rpc.rs:650` - Log route ID blob retrieval failures per repo.

4. **State transitions**:
   - `backend.rs:193` - Log when Veilid network becomes ready.
   - `group.rs:334` - Log when repos are loaded from DHT.

---

## Mapping to Veilid/Iroh Lifecycle

### Expected Flow
1. **Backend.start()** → Initialize Veilid API → Wait for network ready → Initialize Iroh Blobs
2. **Group creation** → Requires initialized Iroh Blobs → Creates DHT record → Stores keys
3. **Repo operations** → Require initialized Iroh Blobs → Use DHT for discovery → Use Iroh for storage

### Current Issues
- Step 1 and Step 2 can race (P0 bug).
- Step 3 doesn't handle DHT unavailability gracefully (P1 bug).
- Peer discovery (implicit in Step 3) has no retry logic (P1 bug).

---

## Testing Recommendations

1. **Race condition test**: Call `create_group()` immediately after `start()` in a tight loop.
2. **DHT unavailability test**: Simulate DHT failures and verify graceful degradation.
3. **Peer unavailability test**: Test download behavior when no peers are available.
4. **Network partition test**: Test behavior when network connectivity is intermittent.

