# Architecture: Zero-Config Local P2P File Transfer (TigerStyle Compliant)

This document outlines the architecture for a local peer-to-peer file transfer system, strictly adhering to **TigerStyle Principles**: safety via static verification, performance via mechanical sympathy, and zero dynamic allocation.

## 1. Core Constraint & Style Guide
All implementation must verify against these rules:
-   **Memory**: No dynamic allocation (`malloc`, `free`) after initialization phase. Use `static` pools or stack.
-   **Loops**: All loops must have a statically provable upper bound. High-assurance.
-   **Data**: No serialization/deserialization. In-memory structs **are** the wire format.
-   **Alignment**: Structs cache-line aligned (64 bytes). Members aligned to largest field.
-   **Naming**: Snake case (`peer_connect`), big-endian naming (`system_state_init`, `system_state_free`), no abbreviations.
-   **Pointers**: Max 1 level of dereference. No function pointers.
-   **Control**: Simple control flow. No recursion.

## 2. Memory Model
We avoid heap fragmentation and allocation overhead by using fixed-size static arenas.

### Global State (`ctx_main`)
A single, statically allocated global context holds all application state.
```c
// Aligned to cache line (64 bytes)
typedef struct alignas(64) ctx_main {
    // Discovery State
    peer_list       peers_known;
    
    // Transfer State
    transfer_job    jobs_active[JOBS_MAX]; // Fixed upper bound
    
    // System Resources
    u8             work_buffer[BUFFER_SIZE_LARGE]; // 4MB or similar for batching
} ctx_main_t;
```

## 3. Wire Protocol & Data Structures
**Principle:** "Don't serialize or deserialize data".
We define structs that map directly to the network bytes. All fields are fixed-width (e.g., `u32`, `u64`), little-endian (standard on x86/ARM, convert if needed but prefer native), and padded for alignment.

### Packet Header
```c
typedef struct alignas(8) packet_header {
    u32 magic;          // 0x544F5953 "TOYS"
    u32 type;           // packet_type_e
    u64 body_length;    // Length of following data
    u64 checksum;       // BLAKE3 hash of body
} packet_header_t;
```

### Peer Discovery (mDNS equivalent)
Instead of a complex mDNS library with callbacks (function pointers forbidden), we use a fixed-bound polling loop on a UDP socket.
-   **Advert**: Broadcast strict struct `peer_advert_t` every N seconds.
-   **Listen**: Read into fixed buffer, cast to `peer_advert_t`, validate magic/checksum.

```c
typedef struct alignas(32) peer_advert {
    u8  public_key[32]; // X25519
    u32 ip_address;
    u16 port;
    u16 padding;        // maintain alignment
} peer_advert_t;
```

## 4. Connection & Transfer
**Principle:** "Separate control plane from data plane". "Use bigger block sizes".

### Connection Type: Direct TCP
-   **Control Plane**: Handshake, File Offer, Accept/Reject, Resume Bitfield. Small messages.
-   **Data Plane**: Bulk data transfer. Zero-copy.

### Zero-Copy Data Path
1.  **Read**: `read()` from socket into a large, pinned "sprint buffer" (e.g., 2MB).
2.  **Hash**: BLAKE3 process the buffer in-place.
3.  **Write**: `write()` / `TransmitFile` directly to disk.
*No intermediate user-space copies.*

### Encryption (Monocypher)
-   **Key Exchange**: X25519 (static) + ephemeral keys.
-   **Transport**: ChaCha20-Poly1305.
-   **Design Note**: Encrypting in-place in the sprint buffer before sending/after receiving to avoid extra copies.

## 5. Resumability & Reliability
**Principle:** "All loops have fixed upper bound".
We use a fixed-size bitmap to track block completion.

-   **File Chunk**: Fixed size (e.g., 1MB).
-   **Bitmap**: `u64 bitmap[FILE_MAX_BLOCKS / 64]`.
-   **Constraint**: Maximum file size is strictly bounded by the bitmap size in the protocol version 1.0 (e.g., 1MB * 64k blocks = 64GB limit, or utilize a sparse acknowledgement range struct).

### Resume Logic
1.  Receiver sends `transfer_state_t` (contains bitmap).
2.  Sender iterates `for (u32 i = 0; i < total_blocks; ++i)` finding missing bits.
3.  Sender "sprints" contiguous missing ranges.

## 6. Implementation Strategy (The "Steel" Approach)

### Phase 1: The Skeleton (Compile-Time Verify)
-   Define `types.h` with all `struct` definitions, `_Static_assert` for sizes and offsets.
-   Ensure clang-format enforces structure.

### Phase 2: The Engine (No IO)
-   Implement `state_update()` function.
-   Input: `ctx_main`, `event`. Output: `ctx_main` mutation.
-   Pure logic, easily fuzzable.

### Phase 3: The Shell (Platform IO)
-   `main.c`: simple loop.
    -   `platform_net_poll()` -> events
    -   `engine_step(events)`
    -   `platform_net_flush()`

## 7. Cross-Platform Low-Level
**Principle:** "Restricted pointers", "Direct way".
Do not create a heavy abstraction layer.
-   **Windows**: Use `WSASocket`, `Overlapped IO` (if fixed bound wait is possible) or blocking with non-blocking polling.
-   **POSIX**: `socket`, `poll` (fixed array of `pollfd`).

## 8. Directory Structure
```
/src
  /core
    types.h       // The rigid data definitions
    state.c       // The deterministic state machine
    crypto.c      // Monocypher wrapper
  /platform
    win32_main.c  // Windows entry point & loop
    posix_main.c  // Linux/macOS entry point & loop
```