#ifndef SENDTOY_CORE_TYPES_H
#define SENDTOY_CORE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _MSC_VER
#define TIGER_ALIGN(n) __declspec(align(n))
#else
#define TIGER_ALIGN(n) __attribute__((aligned(n)))
#endif

// TigerStyle: Fixed types
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

// TigerStyle: Constants & Limits
#define JOBS_MAX 16
#define PEERS_MAX 64
#define BUFFER_SIZE_LARGE (4 * 1024 * 1024) // 4MB
#define FILE_CHUNK_SIZE (1024 * 1024)       // 1MB
#define FILE_MAX_BLOCKS                                                        \
  (64 * 1024)                 // 64k blocks -> 64GB max file (Protocol 1.0)
#define MAGIC_TOYS 0x544F5953 // "TOYS"

// TigerStyle: Helper Macros
#define PRECISE_ASSERT(cond) _Static_assert(cond, #cond)

// --- Wire Protocol Structs ---
// Principle: "In-memory structs are the wire format"

typedef enum {
  PACKET_TYPE_ADVERT = 1,
  PACKET_TYPE_HELLO = 2,
  PACKET_TYPE_OFFER = 3,
  PACKET_TYPE_ACCEPT = 4,
  PACKET_TYPE_CHUNK_REQ = 5,
  PACKET_TYPE_CHUNK_DATA = 6,
  PACKET_TYPE_ACK = 7
} packet_type_e;

typedef struct TIGER_ALIGN(8) packet_header {
  u32 magic;       // 0x544F5953 "TOYS"
  u32 type;        // packet_type_e
  u64 body_length; // Length of following data
  u64 checksum;    // BLAKE3 hash of body
} packet_header_t;

PRECISE_ASSERT(sizeof(packet_header_t) == 24);

typedef struct TIGER_ALIGN(8) peer_advert {
  u8 public_key[32]; // X25519
  u32 ip_address;    // Network byte order
  u16 port;          // Network byte order
  u16 padding;       // maintain alignment
} peer_advert_t;

PRECISE_ASSERT(sizeof(peer_advert_t) == 40); // 32 + 4 + 2 + 2

typedef struct TIGER_ALIGN(8) msg_offer {
    u64 file_size;
    u64 file_hash_low; // First 64 bits of hash for verification
    u32 job_id;        // Sender's Job ID
    u32 timestamp;
    u32 name_len;
    char name[256]; // Fixed buffer for simplicity
    u32 padding;    // Align to 8 bytes (Total 288)
} msg_offer_t;

typedef struct TIGER_ALIGN(8) msg_request {
    u32 job_id; // Sender's Job ID
    u32 len;    
    u64 offset;
} msg_request_t;

typedef struct TIGER_ALIGN(8) msg_data {
    u32 job_id;
    u64 offset;
    // Data follows immediately after struct in the packet body
} msg_data_t;

// --- Internal State Structs ---

typedef enum {
  JOB_STATE_FREE = 0,
  JOB_STATE_OFFER_SENT = 1,
  JOB_STATE_TRANSFERRING = 2,
  JOB_STATE_COMPLETED = 3,
  JOB_STATE_FAILED = 4
} job_state_e;

// Bitmap for tracking blocks. 64k blocks / 64 bits per u64 = 1024 u64s.
#define BITMAP_SIZE_U64 (FILE_MAX_BLOCKS / 64)

typedef struct TIGER_ALIGN(64) transfer_job {
  u8 peer_key[32];
  u8 file_hash[32]; // BLAKE3
  u64 file_size;
  u64 bytes_transferred;
  u64 start_time;
  u32 state; // job_state_e
  u32 id;
  u32 peer_job_id;
  
  // Filename for Platform IO
  char filename[256];

  // Bitmap of completed blocks (1 = complete, 0 = missing)
  u64 block_bitmap[BITMAP_SIZE_U64];

  // Keep alignment to 64 bytes
  // Current size: 32+32+8+8+8+4+4 (96) + 4 (peer_id) = 100 + 256 + 8192 = 8548.
  // 8548 % 64 = 36. Need 28 bytes padding.
  u8 padding[28];
} transfer_job_t;

PRECISE_ASSERT(sizeof(transfer_job_t) % 64 == 0);

typedef struct TIGER_ALIGN(64) peer_entry {
  u8 public_key[32];
  u32 ip_address;
  u16 port;
  u16 padding;
  u64 last_seen_time;
} peer_entry_t;

// --- IO Interface (State -> Platform) ---
typedef enum {
    IO_NONE = 0,
    IO_READ_CHUNK = 1,
    IO_WRITE_CHUNK = 2
} io_req_type_e;

// --- Global Context ---

typedef struct TIGER_ALIGN(64) ctx_main {
  // Identity
  u8 my_public_key[32];
  u8 my_private_key[32];

  // Configuration
  u16 config_listen_port;
  u16 config_target_port;
  bool debug_enabled;
  u8 _padding_config[3];

  // IO Request (Platform reads this after state_update)
  u32 io_req_type;      // io_req_type_e
  u32 io_req_job_id;
  u64 io_req_offset;
  u32 io_req_len;
  u32 io_peer_ip;       // For sending data after read
  u16 io_peer_port;
  u32 _padding_io;
  u8* io_data_ptr;      // Pointer to data for Write (Zero Copy from packet)

  // Discovery
  peer_entry_t peers_known[PEERS_MAX];
  u32 peers_count;
  u32 _padding1;
  u64 next_advert_time; // TigerStyle: Explicit timing state

  // Output (Side Effects)
  // The state machine writes here, platform layer reads and sends.
  u8 outbox[1500]; // MTU sized buffer
  u32 outbox_len;
  u32 _padding2;

  // Transfer
  transfer_job_t jobs_active[JOBS_MAX];

  // System Resources
  // Large buffer for batching IO or crypto work
  TIGER_ALIGN(64) u8 work_buffer[BUFFER_SIZE_LARGE];
} ctx_main_t;

PRECISE_ASSERT(sizeof(ctx_main_t) % 64 == 0);

// --- Crypto API ---

// Initialize random seed (platform dependent)
void crypto_init(const u8 *entropy, u32 len);

// Key Exchange (X25519)
void crypto_keypair(u8 public_key[32], u8 private_key[32]);
void crypto_shared_secret(u8 shared_secret[32], const u8 my_private_key[32],
                          const u8 their_public_key[32]);

// Authenticated Encryption (ChaCha20-Poly1305)
void crypto_encrypt(u8 *dst, const u8 *src, u32 len, const u8 key[32],
                    const u8 nonce[24]);
bool crypto_decrypt(u8 *dst, const u8 *src, u32 len, const u8 key[32],
                    const u8 nonce[24]);

// Hashing (BLAKE3)
void crypto_hash(u8 out[32], const u8 *in, u32 len);

// --- State API ---

typedef enum {
  EVENT_INIT,
  EVENT_TICK_100MS,
  EVENT_NET_PACKET_RECEIVED,
  EVENT_USER_COMMAND,
} event_type_e;

typedef struct {
  event_type_e type;
  union {
    struct {
      u8 *data;
      u32 len;
      u32 from_ip;
      u16 from_port;
    } packet;
    // User Command Data
    struct {
        u32 target_ip;
        u64 file_size;
        u64 file_hash_low;
        char filename[256];
    } cmd_send;
  };
} state_event_t;

// Pure function: ctx + event -> ctx'
// Returns true if state changed (optimization hint)
bool state_update(ctx_main_t *ctx, const state_event_t *event);

// Helper to init default state
void state_init(ctx_main_t *ctx);

#endif // SENDTOY_CORE_TYPES_H
