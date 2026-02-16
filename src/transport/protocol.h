#ifndef SENDTOY_PROTOCOL_H
#define SENDTOY_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

// Forward declaration
typedef struct Connection Connection;

// Magic bytes to identify the protocol: 'S', 'T', 'O', 'Y'
#define PROTO_MAGIC 0x594F5453 

// Version 1
#define PROTO_VERSION 1

// Standard block size for transfer (256 KiB)
#define PROTO_BLOCK_SIZE (256 * 1024)

// BLAKE3 Hash Length
#define PROTO_HASH_LEN 32

// Message Types
typedef enum {
    MSG_HELLO       = 0x01, // Handshake / Version check
    MSG_FILE_OFFER  = 0x02, // Sender offers a file (metadata)
    MSG_FILE_ACCEPT = 0x03, // Receiver accepts offer
    MSG_FILE_REJECT = 0x04, // Receiver rejects offer
    MSG_CHUNK_DATA  = 0x05, // File data chunk
    MSG_CHUNK_ACK   = 0x06, // Acknowledge chunk receipt
    MSG_RESUME_REQ  = 0x07, // Request missing chunks (ranges)
    MSG_FINISH      = 0x08, // Sender indicates end of transmission
    MSG_ERROR       = 0xFF  // Error condition
} MsgType;

// Ensure 1-byte packing for network structures
#pragma pack(push, 1)

// Common Header (12 bytes)
typedef struct {
    uint32_t magic;     // PROTO_MAGIC
    uint8_t  version;   // PROTO_VERSION
    uint8_t  type;      // MsgType
    uint16_t flags;     // Reserved
    uint32_t length;    // Payload length following this header
} ProtoHeader;

// Payload for MSG_FILE_OFFER
typedef struct {
    uint64_t file_size;
    uint64_t total_chunks;
    uint8_t  content_hash[PROTO_HASH_LEN]; // BLAKE3 root hash (if available) or zero
    uint16_t name_len;
    // Variable length filename string follows (not null-terminated in struct)
    // char filename[name_len]; 
} ProtoFileOffer;

// Payload for MSG_CHUNK_DATA
typedef struct {
    uint64_t chunk_index;
    // Variable length data follows (up to PROTO_BLOCK_SIZE)
    // uint8_t data[];
} ProtoChunkData;

// Payload for MSG_CHUNK_ACK
typedef struct {
    uint64_t chunk_index;
} ProtoChunkAck;

// Payload for MSG_RESUME_REQ
// Represents a request for a range of blocks [start_index, start_index + count)
typedef struct {
    uint64_t start_index;
    uint32_t count; 
} ProtoResumeReq;

// Payload for MSG_ERROR
typedef struct {
    int32_t code;
    uint16_t msg_len;
    // char message[msg_len];
} ProtoError;

#pragma pack(pop)

// Send a packet with header and payload
bool protocol_send_packet(Connection *conn, uint8_t type, const void *payload, uint32_t length);

// Receive packet header
bool protocol_recv_header(Connection *conn, uint8_t *out_type, uint32_t *out_len);

// Receive payload
bool protocol_recv_payload(Connection *conn, void *buffer, uint32_t length);

#endif // SENDTOY_PROTOCOL_H