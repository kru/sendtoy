To create a local, peer-to-peer file transfer system in C, optimized for cross-platform compatibility (initially iPhone to Windows) with zero configuration and no internet dependency, we need to address several core technical areas. The design emphasizes efficiency, security, and minimal overhead.

Here's a breakdown of how to satisfy the outlined principles and requirements:

### 1. Core Principles & Requirements Summary

The goal is a "Taildrop-like" experience for local Wi-Fi, without internet, accounts, or QR codes. Key aspects include:
*   **Zero-configuration & Zero-internet:** Instant discovery and operation on isolated Wi-Fi, even with captive portals or airplane mode + Wi-Fi.
*   **Direct P2P:** Prioritize UDP hole-punching, with TCP fallback, and mDNS relay as a last resort (local, peer-based).
*   **Encryption:** End-to-end with Noise_NK_25519 (WireGuard-like).
*   **Efficiency:** Binary, allocation-free protocol with BLAKE3 hashing, 256 KiB blocks, and run-length bitmap for resumability.
*   **Minimal Dependencies:** Static linking where possible, targeting a single shared library (`.dylib/.dll`) with a C ABI.
*   **Cross-platform:** Linux, Android, macOS, iPhone, Windows, implemented in C.

### 2. How to Satisfy the Requirements

#### a. Discovery Mechanism: Instant, Zero-Configuration

To achieve "Works the second both devices are on the same Wi-Fi" without internet or accounts, we'll combine two local discovery techniques:

*   **mDNS (Multicast DNS):** This is the primary method for instant service discovery on local networks.
    *   **Service Advertisement:** Each device, upon starting, will register a custom mDNS service (e.g., `_p2pfiletransfer._tcp.local.`) advertising its local IP addresses (IPv4 and IPv6) and the UDP/TCP ports it's listening on. This is handled via system APIs:
        *   **iOS/macOS:** Utilize `dns_sd.h` (Bonjour/mDNSResponder) in C for service registration and browsing.
        *   **Windows:** Leverage the Bonjour SDK for Windows or implement mDNS parsing/announcing directly, though integrating with the OS service is generally more robust.
        *   **Linux/Android:** Use Avahi's C API.
    *   **Service Discovery:** Devices will browse for instances of this `_p2pfiletransfer._tcp.local.` service. When a new instance is found, its IP address and port information are extracted, providing a list of potential peers.
*   **UDP Broadcast:** As a complementary or fallback mechanism, devices can periodically send small UDP broadcast packets to a well-known port on the local subnet. These packets would announce the sender's presence and possibly their primary listening port. Other devices listening on that port would receive the broadcast and become aware of the sender. This can be quicker for initial discovery on some simpler networks but is less feature-rich than mDNS.

#### b. Connection Establishment: Direct P2P with Local NAT Traversal

The multi-tiered approach ensures robust local connectivity:

*   **Tier 1: Direct UDP Hole-Punching:**
    *   Once peers discover each other (via mDNS/broadcast), they exchange their local IP addresses and designated UDP ports.
    *   Each peer attempts to send a "hello" UDP packet directly to the other's reported IP and port.
    *   For most home routers, when an internal device initiates an outbound UDP connection to another internal device, the router's local NAT (if any) allows the return traffic for that "session" through. This creates a "hole" in the local firewall/NAT, enabling direct UDP communication.
    *   Success is determined by receiving an authenticated Noise handshake packet in response.
*   **Tier 2: TCP Fallback:**
    *   If UDP direct connection fails after several attempts (e.g., due to strict local firewalls or unusual network configurations that block internal UDP P2P), peers fall back to TCP.
    *   The mDNS service advertisement will also include a TCP port. One peer initiates a standard TCP connection to the other's advertised TCP port.
    *   TCP connections are generally more reliable for traversing local network obstacles as routers and firewalls are typically configured to allow internal TCP connections.
*   **Tier 3: Local Relay (mDNS Relay) - Last Resort:**
    *   This tier addresses rare scenarios where direct UDP and TCP connections between two specific peers (A and B) on the *same Wi-Fi* fail, but a third peer (C) on the same network *can* connect to both A and B.
    *   **Mechanism:** If A cannot connect to B directly, it might discover (via mDNS) that peer C is also available. A could then send a request to C to act as a relay to B. If C agrees and can connect to both, C would forward encrypted data packets between A and B.
    *   **Implications:** This adds significant complexity for routing, session management, and resource utilization on the relaying peer (C). It must be carefully designed to remain "local" and "peer-to-peer," avoiding any external servers. This is a very advanced fallback, and its practical implementation for a first version might be deferred unless absolutely necessary. The system needs to intelligently determine if a relay is needed and if a suitable relay peer is available and willing.

**No Coordination Server, No STUN, No DERP:** This principle is strictly adhered to by relying solely on local network protocols (mDNS, UDP/TCP sockets) and a peer-driven relay mechanism if Tier 3 is implemented.

#### c. End-to-End Encryption: Noise_NK_25519

*   **Noise Protocol Framework:** This will be implemented directly in C, focusing on the `Noise_NK_25519_ChaChaPoly_BLAKE3` handshake and transport.
    *   `NK` Handshake Pattern: The initiator (A) knows the responder's (B's) static public key, but B does not necessarily know A's initially. This is suitable for a "first contact" scenario where a device's public key is advertised via mDNS.
        1.  **Key Generation:** Each device generates a long-term static Curve25519 key pair. The public key is advertised via mDNS.
        2.  **Handshake:**
            *   Initiator A sends `e` (its ephemeral public key) and `p_B` (an encrypted payload containing an authentication tag for B's static public key) to Responder B.
            *   Responder B receives `e`, verifies `p_B` using its static private key, and sends `e` (its own ephemeral public key) and `p_A` (an encrypted payload containing an authentication tag for A's static public key) back to A.
        3.  **Session Key Derivation:** Both A and B derive a shared secret key from their static and ephemeral keys. This key is used to generate session keys for ChaCha20-Poly1305 authenticated encryption.
    *   **Forward Secrecy:** Achieved through the use of ephemeral keys in each handshake.
    *   **Authentication:** Achieved by deriving session keys that incorporate both static keys, ensuring only trusted peers can establish a secure channel.
    *   **Implementation:** A lightweight C implementation of Noise (like the one found in WireGuard's codebase) or a similar minimal crypto library that provides `Curve25519`, `ChaCha20-Poly1305`, and `BLAKE3` will be used. The "minimal dependencies, 0 dependency" goal means these cryptographic primitives should either be implemented from scratch (highly complex and error-prone for crypto) or integrated from extremely lean, statical-linkable C libraries.

#### d. File Transfer Protocol (Binary, Allocation-Free)

This custom protocol ensures efficiency and resumability:

*   **Message Structure:** All protocol messages (control, data, acknowledgments) will be defined as compact binary structures, avoiding dynamic memory allocations during critical path processing.
*   **BLAKE3 Hashing:**
    *   The entire file will be pre-hashed with BLAKE3.
    *   Each 256 KiB block will also have its individual BLAKE3 hash.
    *   The receiver verifies the integrity of each received block using its hash.
    *   The overall file hash is used for final verification.
*   **256 KiB Blocks:** Files are segmented into fixed-size blocks. This allows for parallel transfer, efficient retransmissions, and simple resumability.
*   **Run-Length Bitmap for Resumability:**
    *   The sender maintains a bitmap of all blocks in the file (e.g., one bit per block).
    *   The receiver also maintains such a bitmap, initially empty.
    *   When a block is successfully received and verified, the corresponding bit in the receiver's bitmap is set.
    *   To request missing blocks (for initial transfer or resumption), the receiver can send its bitmap (or a run-length encoded version) to the sender. Run-length encoding (RLE) compresses sequences of identical bits (e.g., "100 blocks received," "50 blocks missing"), making the bitmap transmission efficient, especially for large files or mid-transfer resumptions.
    *   The sender then transmits only the blocks indicated as missing by the receiver.
*   **Flow Control & Acknowledgments:** A simple window-based flow control mechanism will be implemented over UDP (or TCP) to manage outstanding blocks and ensure reliable delivery and congestion avoidance. Each block sent requires an acknowledgment.

#### e. Minimal Dependencies & Static Linking

*   **Pure C Implementation:** The entire core logic will be in C.
*   **No C++ Runtimes/STL:** Avoid C++ to keep dependencies minimal and consistent across platforms.
*   **System APIs:** Network (sockets), file I/O, and mDNS interaction will use the native C APIs provided by each operating system (e.g., Winsock on Windows, POSIX sockets on Unix-like systems, `dns_sd.h` for Apple, Avahi for Linux). These are typically part of the OS and do not count as external *library* dependencies in the build chain.
*   **Cryptography:** Implement `Curve25519`, `ChaCha20-Poly1305`, and `BLAKE3` directly or integrate their C reference implementations as source code, compiling them directly into the library. This avoids linking against external crypto libraries like OpenSSL or Libsodium, which might add dynamic link dependencies.
*   **Static Linking:** The C code, including any integrated crypto primitives, will be compiled into a single static library (`.lib` on Windows, `.a` on Unix-like) and then linked into the final shared library (`.dll` on Windows, `.dylib` on macOS/iOS, `.so` on Linux/Android). This ensures the shared library is self-contained.

#### f. Cross-Platform & C ABI

*   **Platform Abstraction Layer:** The C codebase will include a thin platform abstraction layer that defines generic interfaces for:
    *   **Networking:** Socket creation, binding, sending, receiving, multicast.
    *   **Threading:** Thread creation, mutexes, condition variables.
    *   **File I/O:** Opening, reading, writing, seeking, closing files.
    *   **Time:** High-resolution timers.
    *   This layer would then implement these interfaces using platform-specific APIs (e.g., `CreateThread` vs. `pthread_create`, `socket` vs. `WSASocket`, `ReadFile` vs. `read`).
*   **Single Shared Library:**
    *   The entire core logic, including the platform abstraction and crypto, will be compiled into a single shared library for each target platform:
        *   `p2ptransfer.dll` for Windows
        *   `libp2ptransfer.dylib` for macOS/iOS
        *   `libp2ptransfer.so` for Linux/Android
*   **C ABI Export:**
    *   The shared library will export a well-defined set of C functions (e.g., `p2ptransfer_init()`, `p2ptransfer_start_discovery()`, `p2ptransfer_send_file()`, `p2ptransfer_receive_file()`, `p2ptransfer_set_callback()`).
    *   These functions will use standard C types (pointers, `int`, `char*`, `void*`).
    *   **Swift Integration (iOS/macOS):** Swift can directly call C functions exported via a C ABI. A bridging header would declare the C functions, making them callable from Swift code.
    *   **C# Integration (Windows):** C# uses `P/Invoke` (Platform Invoke) to call functions from unmanaged DLLs. A C# wrapper class would declare the C functions with `[DllImport("p2ptransfer.dll")]` attributes.

This comprehensive approach leverages native capabilities for discovery, builds a secure and efficient custom protocol in C, and ensures a clean, minimal-dependency shared library for cross-platform integration.