#include "platform/platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "connection.h"

typedef enum {
    CONN_TYPE_TCP,
    CONN_TYPE_UDP
} ConnectionType;

typedef struct {
    char ip[46];
    uint16_t port;
} PeerAddress;

struct Connection {
    PlatformSocket socket;
    ConnectionType type;
    PeerAddress peer_addr;
    bool is_connected;
};

int transport_init(void) {
    return platform_init();
}

void transport_cleanup(void) {
    platform_cleanup();
}

Connection* connection_create(void) {
    Connection *conn = (Connection*)malloc(sizeof(Connection));
    if (conn) {
        memset(conn, 0, sizeof(Connection));
        conn->socket = PLATFORM_INVALID_SOCKET;
        conn->is_connected = false;
    }
    return conn;
}

void connection_destroy(Connection *conn) {
    if (conn) {
        if (conn->socket != PLATFORM_INVALID_SOCKET) {
            platform_close_socket(conn->socket);
        }
        free(conn);
    }
}

bool connection_connect(Connection *conn, const char *ip, uint16_t port) {
    if (!conn) return false;
    if (conn->socket != PLATFORM_INVALID_SOCKET) {
        platform_close_socket(conn->socket);
        conn->socket = PLATFORM_INVALID_SOCKET;
    }

    conn->socket = platform_tcp_connect(ip, port);
    if (conn->socket == PLATFORM_INVALID_SOCKET) return false;

    conn->type = CONN_TYPE_TCP;
    conn->is_connected = true;
    strncpy(conn->peer_addr.ip, ip, sizeof(conn->peer_addr.ip) - 1);
    conn->peer_addr.ip[sizeof(conn->peer_addr.ip) - 1] = '\0';
    conn->peer_addr.port = port;
    return true;
}

bool connection_send_all(Connection *conn, const void *data, size_t len) {
    if (!conn || !conn->is_connected) return false;
    if (platform_tcp_send_exact(conn->socket, data, len) < 0) {
        conn->is_connected = false;
        return false;
    }
    return true;
}

int connection_receive(Connection *conn, void *buf, size_t len) {
    if (!conn || !conn->is_connected) return -1;
    int received = platform_tcp_recv(conn->socket, buf, len);
    if (received <= 0) {
        conn->is_connected = false;
    }
    return received;
}

bool connection_send_file(Connection *conn, const char *filepath, uint64_t offset, uint64_t length) {
    if (!conn || !conn->is_connected) return false;
    PlatformFile file = platform_file_open_read(filepath);
    if (file == PLATFORM_INVALID_FILE) return false;

    bool result = true;
    uint64_t remaining = length;
    uint64_t current_offset = offset;

    while (remaining > 0) {
        uint64_t chunk = remaining > (1024*1024*1024) ? (1024*1024*1024) : remaining;
        int64_t sent = platform_sendfile(conn->socket, file, current_offset, chunk);
        if (sent < 0) {
            result = false;
            conn->is_connected = false;
            break;
        }
        remaining -= sent;
        current_offset += sent;
    }
    platform_file_close(file);
    return result;
}