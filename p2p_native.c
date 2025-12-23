#define _CRT_SECURE_NO_WARNINGS
#include "p2p_native.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// --- Platform Layer (Windows/POSIX) ---
#if defined(_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    typedef int socklen_t;
    #define P2P_INVALID_SOCKET INVALID_SOCKET
    #define P2P_CLOSE_SOCKET closesocket
    #define P2P_SLEEP_MS(x) Sleep(x)

    // Thread wrapper
    typedef HANDLE p2p_thread_t;
    #define THREAD_FUNC unsigned __stdcall
    void p2p_create_thread(p2p_thread_t* t, THREAD_FUNC(*func)(void*), void* arg) {
        *t = (HANDLE)_beginthreadex(NULL, 0, func, arg, 0, NULL);
    }
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <pthread.h>
    #include <errno.h>
    typedef int socket_t;
    #define P2P_INVALID_SOCKET -1
    #define P2P_CLOSE_SOCKET close
    #define P2P_SLEEP_MS(x) usleep((x)*1000)

    // Thread wrapper
    typedef pthread_t p2p_thread_t;
    #define THREAD_FUNC void*
    void p2p_create_thread(p2p_thread_t* t, THREAD_FUNC(*func)(void*), void* arg) {
        pthread_create(t, NULL, func, arg);
    }
#endif

// --- Crypto Constants (NOISE_NK_25519_ChaChaPoly_BLAKE3) ---
// Note: In a real deploy, link Monocypher or Libsodium here.
// These are placeholders to satisfy the architecture.
void crypto_gen_keypair(u8 pk[32], u8 sk[32]) {
    // TODO: Call crypto_library_keygen()
}
// Encrypt using ChaCha20-Poly1305
void crypto_encrypt(u8* cipher, const u8* plain, size_t len, u8* key, u64 nonce) {
    // TODO: Real encryption. For demo, just memcpy
    memcpy(cipher, plain, len);
}
// Decrypt
bool crypto_decrypt(u8* plain, const u8* cipher, size_t len, u8* key, u64 nonce) {
    // TODO: Real decryption.
    memcpy(plain, cipher, len);
    return true;
}

// --- Protocol Structures ---
#pragma pack(push, 1)

typedef enum {
    MSG_DISCOVERY = 0x01,
    MSG_HANDSHAKE_INIT = 0x02,
    MSG_HANDSHAKE_RESP = 0x03,
    MSG_FILE_START = 0x04,
    MSG_FILE_DATA = 0x05,
    MSG_ACK = 0x06
} msg_type_t;

typedef struct {
    u64 magic;
    u8 type;
    u64 session_id; // 0 for discovery
    u16 payload_len;
} packet_header_t;

typedef struct {
    char device_name[64];
    u8 static_pubkey[32];
} discovery_payload_t;

typedef struct {
    u64 file_size;
    u32 block_count;
    char filename[128];
} file_start_payload_t;

typedef struct {
    u32 block_index;
    u32 data_len;
    // Data follows immediately
} file_data_header_t;

#pragma pack(pop)

// --- Internal State ---
static struct {
    socket_t sock;
    p2p_callback_t cb;
    bool running;
    p2p_thread_t listener_thread;
    p2p_thread_t broadcaster_thread;

    // Identity
    u8 my_static_pk[32];
    u8 my_static_sk[32];
    char device_name[64];

} g_ctx;

// --- Helper Functions ---

void log_debug(const char* msg) {
    printf("[P2P_NATIVE] %s\n", msg);
}

// Create a UDP socket bound to the port (dual stack if possible, here IPv4 for simplicity)
socket_t create_socket() {
    socket_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == P2P_INVALID_SOCKET) return P2P_INVALID_SOCKET;

    // Enable Broadcast
    int broadcast = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char*)&broadcast, sizeof(broadcast));

    // Bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(P2P_PORT);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        P2P_CLOSE_SOCKET(s);
        return P2P_INVALID_SOCKET;
    }
    return s;
}

// --- Threads ---

// 1. Broadcaster: Sends UDP beacons
THREAD_FUNC broadcaster_loop(void* arg) {
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(P2P_PORT);
    broadcast_addr.sin_addr.s_addr = 0xFFFFFFFF; // 255.255.255.255

    packet_header_t header;
    header.magic = P2P_MAGIC;
    header.type = MSG_DISCOVERY;
    header.session_id = 0;
    header.payload_len = sizeof(discovery_payload_t);

    discovery_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    strncpy(payload.device_name, g_ctx.device_name, 63);
    memcpy(payload.static_pubkey, g_ctx.my_static_pk, 32);

    u8 packet[sizeof(header) + sizeof(payload)];
    memcpy(packet, &header, sizeof(header));
    memcpy(packet + sizeof(header), &payload, sizeof(payload));

    while (g_ctx.running) {
        sendto(g_ctx.sock, (const char*)packet, sizeof(packet), 0,
               (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        P2P_SLEEP_MS(2000); // Beacon every 2 seconds
    }
    return 0;
}

// 2. Listener: Handles Incoming Packets
THREAD_FUNC listener_loop(void* arg) {
    u8 buffer[P2P_BLOCK_SIZE + 1024]; // Large buffer
    struct sockaddr_in sender_addr;
    socklen_t sender_len = sizeof(sender_addr);

    while (g_ctx.running) {
        int len = recvfrom(g_ctx.sock, (char*)buffer, sizeof(buffer), 0,
                           (struct sockaddr*)&sender_addr, &sender_len);

        if (len < sizeof(packet_header_t)) continue;

        packet_header_t* hdr = (packet_header_t*)buffer;
        if (hdr->magic != P2P_MAGIC) continue;

        // Process Packet Type
        if (hdr->type == MSG_DISCOVERY) {
             // Avoid discovering self
             // In real app, check UUID. Here we just rely on IP loopback filtering usually
             // For this demo, we just parse and notify
             if (len >= sizeof(packet_header_t) + sizeof(discovery_payload_t)) {
                 discovery_payload_t* p = (discovery_payload_t*)(buffer + sizeof(packet_header_t));

                 p2p_event_t evt;
                 evt.type = P2P_EVENT_PEER_FOUND;
                 inet_ntop(AF_INET, &sender_addr.sin_addr, evt.data.peer.ip, 46);
                 evt.data.peer.port = ntohs(sender_addr.sin_port);
                 memcpy(evt.data.peer.public_key, p->static_pubkey, 32);

                 if (g_ctx.cb) g_ctx.cb(evt);
             }
        }
        else if (hdr->type == MSG_FILE_START) {
            // Handle file offer...
            log_debug("Received File Offer");
        }
        // ... Handle Handshake and Data ...
    }
    return 0;
}

// --- Public API Implementation ---

int p2p_init(p2p_callback_t cb) {
#if defined(_WIN32)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return -1;
#endif

    memset(&g_ctx, 0, sizeof(g_ctx));
    g_ctx.cb = cb;

    // Generate Identity
    crypto_gen_keypair(g_ctx.my_static_pk, g_ctx.my_static_sk);

    g_ctx.sock = create_socket();
    if (g_ctx.sock == P2P_INVALID_SOCKET) return -2;

    g_ctx.running = true;
    return 0;
}

int p2p_start_discovery(const char* device_name) {
    strncpy(g_ctx.device_name, device_name, 63);

    // Start Threads
    p2p_create_thread(&g_ctx.listener_thread, listener_loop, NULL);
    p2p_create_thread(&g_ctx.broadcaster_thread, broadcaster_loop, NULL);

    return 0;
}

int p2p_send_file(const char* peer_ip, const char* file_path) {
    FILE* f = fopen(file_path, "rb");
    if (!f) return -1;

    // Get file size
    fseek(f, 0, SEEK_END);
    u64 fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Prepare target address
    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(P2P_PORT);
    inet_pton(AF_INET, peer_ip, &target.sin_addr);

    // 1. Send FILE_START (Simplified: Skipping Handshake for code brevity)
    packet_header_t hdr;
    hdr.magic = P2P_MAGIC;
    hdr.type = MSG_FILE_START;
    hdr.session_id = 12345; // Random session ID
    hdr.payload_len = sizeof(file_start_payload_t);

    file_start_payload_t start;
    start.file_size = fsize;
    start.block_count = (fsize + P2P_BLOCK_SIZE - 1) / P2P_BLOCK_SIZE;
    // Extract filename from path
    const char* fname = strrchr(file_path, '/');
    if (!fname) fname = strrchr(file_path, '\\');
    if (!fname) fname = file_path; else fname++;
    strncpy(start.filename, fname, 127);

    u8 buffer[1500]; // MTU safe
    memcpy(buffer, &hdr, sizeof(hdr));
    memcpy(buffer + sizeof(hdr), &start, sizeof(start));

    sendto(g_ctx.sock, (const char*)buffer, sizeof(hdr) + sizeof(start), 0,
           (struct sockaddr*)&target, sizeof(target));

    // 2. Send Data Blocks (UDP Blind send for demo - Real needs ACK/Window)
    u8* block_buf = (u8*)malloc(P2P_BLOCK_SIZE + sizeof(packet_header_t) + sizeof(file_data_header_t));
    u8* file_read_buf = (u8*)malloc(P2P_BLOCK_SIZE);

    u32 blk_idx = 0;
    size_t read_bytes;
    while ((read_bytes = fread(file_read_buf, 1, P2P_BLOCK_SIZE, f)) > 0) {

        // Construct Packet
        packet_header_t* dhdr = (packet_header_t*)block_buf;
        dhdr->magic = P2P_MAGIC;
        dhdr->type = MSG_FILE_DATA;
        dhdr->session_id = 12345;
        dhdr->payload_len = sizeof(file_data_header_t) + read_bytes;

        file_data_header_t* dmeta = (file_data_header_t*)(block_buf + sizeof(packet_header_t));
        dmeta->block_index = blk_idx++;
        dmeta->data_len = read_bytes;

        // Encrypt payload (file_read_buf) -> block_buf data area
        // Mock encryption:
        memcpy(block_buf + sizeof(packet_header_t) + sizeof(file_data_header_t), file_read_buf, read_bytes);

        // Send
        sendto(g_ctx.sock, (const char*)block_buf, sizeof(packet_header_t) + dhdr->payload_len, 0,
               (struct sockaddr*)&target, sizeof(target));

        // Pacing (essential for UDP without congestion control)
        P2P_SLEEP_MS(5);

        // Progress Callback
        p2p_event_t evt;
        evt.type = P2P_EVENT_PROGRESS;
        evt.data.transfer.current = blk_idx * P2P_BLOCK_SIZE; // Approx
        evt.data.transfer.total = fsize;
        if (g_ctx.cb) g_ctx.cb(evt);
    }

    free(block_buf);
    free(file_read_buf);
    fclose(f);
    return 0;
}

void p2p_shutdown() {
    g_ctx.running = false;
    P2P_CLOSE_SOCKET(g_ctx.sock);
#if defined(_WIN32)
    WSACleanup();
#endif
}