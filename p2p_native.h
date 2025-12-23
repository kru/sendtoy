#ifndef P2P_NATIVE_H
#define P2P_NATIVE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- configuration ---
#define P2P_PORT 43424
#define P2P_BLOCK_SIZE (256 * 1024) // 256 KiB
#define P2P_MAGIC 0x53454E44544F59 // "SENDTOY" ASCII

// --- types abbreviation ---
#define u16 uint16_t
#define u8 	uint8_t
#define u32 uint32_t
#define u64 uint64_t

// --- Public Types ---
typedef enum {
	P2P_EVENT_PEER_FOUND,
	P2P_EVENT_TRANSFER_START,
	P2P_EVENT_PROGRESS,
	P2P_EVENT_COMPLETE,
	P2P_EVENT_ERROR,
} p2p_event_type_t;

typedef struct {
	char ip[46];
	u16 port;
	u8 public_key[32];
} p2p_peer_t;

typedef struct {
    p2p_event_type_t type;
    union {
        p2p_peer_t peer;
        struct {
            const char* filename;
            u64 current;
            u64 total;
        } transfer;
        const char* error_msg;
    } data;
} p2p_event_t;

// Callback function pointer
typedef void (*p2p_callback_t)(p2p_event_t event);

// --- Public API ---

// Initialize library (Network startup, Crypto init)
int p2p_init(p2p_callback_t cb);

// Start announcing presence and listening for peers
int p2p_start_discovery(const char* device_name);

// Send a file to a specific peer IP
int p2p_send_file(const char* peer_ip, const char* file_path);

// Cleanup
void p2p_shutdown();

#ifdef __cplusplus
}
#endif

#endif // end P2P_NATIVE_H