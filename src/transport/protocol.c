#include "protocol.h"
#include "connection.h"
#include <string.h>
#include <stdio.h>

// --- Endianness Helpers ---

static int is_big_endian(void) {
    union {
        uint32_t i;
        char c[4];
    } bint = {0x01020304};
    return bint.c[0] == 1;
}

static uint16_t swap_uint16(uint16_t val) {
    return (val << 8) | (val >> 8);
}

static uint32_t swap_uint32(uint32_t val) {
    return ((val << 24) & 0xff000000) |
           ((val << 8)  & 0x00ff0000) |
           ((val >> 8)  & 0x0000ff00) |
           ((val >> 24) & 0x000000ff);
}

// Convert Host to Network (Big Endian)
static uint16_t h2n16(uint16_t host) {
    if (is_big_endian()) return host;
    return swap_uint16(host);
}

static uint32_t h2n32(uint32_t host) {
    if (is_big_endian()) return host;
    return swap_uint32(host);
}

// Convert Network to Host
static uint16_t n2h16(uint16_t net) {
    if (is_big_endian()) return net;
    return swap_uint16(net);
}

static uint32_t n2h32(uint32_t net) {
    if (is_big_endian()) return net;
    return swap_uint32(net);
}

// --- Implementation ---

bool protocol_send_header(Connection *conn, uint8_t type, uint32_t length) {
    ProtoHeader header;
    header.magic = h2n32(PROTO_MAGIC);
    header.version = PROTO_VERSION;
    header.type = type;
    header.flags = 0;
    header.length = h2n32(length);

    return connection_send_all(conn, &header, sizeof(header));
}

bool protocol_send_packet(Connection *conn, uint8_t type, const void *payload, uint32_t length) {
    if (!protocol_send_header(conn, type, length)) {
        return false;
    }
    
    if (length > 0 && payload) {
        return connection_send_all(conn, payload, length);
    }
    
    return true;
}

// Reads header from connection.
// Returns true if valid header received.
bool protocol_recv_header(Connection *conn, uint8_t *out_type, uint32_t *out_len) {
    ProtoHeader header;
    if (!connection_recv_all(conn, &header, sizeof(ProtoHeader))) {
        return false;
    }

    // Convert fields to host byte order
    header.magic = n2h32(header.magic);
    header.length = n2h32(header.length);
    header.flags = n2h16(header.flags);

    // Validate Magic
    if (header.magic != PROTO_MAGIC) {
        printf("[Protocol] Error: Invalid magic 0x%08X (expected 0x%08X)\n", 
               header.magic, PROTO_MAGIC);
        return false;
    }

    // Validate Version
    if (header.version != PROTO_VERSION) {
        printf("[Protocol] Error: Version mismatch %d (expected %d)\n", 
               header.version, PROTO_VERSION);
        return false;
    }
    
    *out_type = header.type;
    *out_len = header.length;

    return true;
}

bool protocol_recv_payload(Connection *conn, void *buffer, uint32_t length) {
    if (length == 0) return true;
    return connection_recv_all(conn, buffer, length);
}

bool protocol_recv_payload(Connection *conn, void *buffer, uint32_t length) {
    if (length == 0) return true;
    return connection_recv_all(conn, buffer, length);
}