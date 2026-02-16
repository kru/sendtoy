#ifndef _WIN32

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <pthread.h> // POSIX threads

#include "../core/types.h"

// --- Platform Interface & Implementation (POSIX) ---

// TigerStyle: Assert macros
#define TIGER_ASSERT(cond) if (!(cond)) { fprintf(stderr, "ASSERT FAILED: %s:%d\n", __FILE__, __LINE__); abort(); }

// Types
typedef int PlatformSocket;
#define PLATFORM_INVALID_SOCKET (-1)

typedef int PlatformFile;
#define PLATFORM_INVALID_FILE (-1)

// Aligned storage for opaque types
typedef struct {
    _Alignas(8) uint8_t data[64];
} PlatformMutex;

typedef struct {
    _Alignas(8) uint8_t data[64]; // Increased size just in case
} PlatformThread;

// --- Implementation ---

int platform_init(void) {
    // POSIX doesn't usually need global init for sockets
    return 0;
}

void platform_cleanup(void) {
    // No-op
}

void platform_sleep_ms(uint32_t ms) {
    usleep(ms * 1000);
}

uint64_t platform_get_time_ms(void) {
    // Monotonic clock if available
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)(ts.tv_sec) * 1000 + (ts.tv_nsec / 1000000);
    }
    // Fallback
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)(tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
}

// Networking

PlatformSocket platform_udp_bind(uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return PLATFORM_INVALID_SOCKET;
    }

    // Reuse address to allow quick restart/testing
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
#ifdef SO_REUSEPORT
    // Useful for local testing on macOS/Linux if we ran multiple instances on same port
    // But architecture says 2 computers, so maybe not strictly needed.
    // However, it doesn't hurt.
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);

    if (bind(s, (struct sockaddr*)&local, sizeof(local)) < 0) {
        close(s);
        return PLATFORM_INVALID_SOCKET;
    }

    // Set non-blocking (optional, but good for poll)
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    return s;
}

int platform_udp_enable_broadcast(PlatformSocket sock) {
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt)) < 0) {
        return -1;
    }
    return 0;
}

int platform_udp_sendto(PlatformSocket sock, const void *data, size_t len, const char *ip, uint16_t port) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &dest.sin_addr) != 1) {
        return -1;
    }
    dest.sin_port = htons(port);

    int sent = sendto(sock, data, len, 0, (struct sockaddr*)&dest, sizeof(dest));
    return sent;
}

int platform_udp_recvfrom(PlatformSocket sock, void *buf, size_t len, char *ip_out, size_t ip_len, uint16_t *port_out) {
    struct sockaddr_in sender;
    socklen_t senderLen = sizeof(sender);

    int received = recvfrom(sock, buf, len, 0, (struct sockaddr*)&sender, &senderLen);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0; 
        }
        return -1;
    }

    if (ip_out && ip_len > 0) {
        inet_ntop(AF_INET, &sender.sin_addr, ip_out, ip_len);
    }
    if (port_out) {
        *port_out = ntohs(sender.sin_port);
    }

    return received;
}

void platform_close_socket(PlatformSocket sock) {
    close(sock);
}

// Threading (Pthreads)

typedef struct {
    pthread_t thread;
    void (*func)(void*);
    void *arg;
} PosixThread;

_Static_assert(sizeof(PosixThread) <= sizeof(PlatformThread), "PlatformThread struct too small");

static void* thread_wrapper(void *arg) {
    PosixThread *pt = (PosixThread*)arg;
    if (pt->func) {
        pt->func(pt->arg);
    }
    return NULL;
}

void platform_thread_start(PlatformThread *thread, void (*func)(void*), void *arg) {
    PosixThread *pt = (PosixThread*)thread->data;
    pt->func = func;
    pt->arg = arg;
    
    if (pthread_create(&pt->thread, NULL, thread_wrapper, pt) != 0) {
        // Handle error?
        fprintf(stderr, "Failed to create thread\n");
    }
}

void platform_thread_join(PlatformThread *thread) {
    PosixThread *pt = (PosixThread*)thread->data;
    pthread_join(pt->thread, NULL);
}

// --- Main ---

// Global Context (Statically allocated)
static ctx_main_t g_ctx;
// Network Buffers (Statically allocated)
static u8 g_net_rx_buffer[1500];

int main(int argc, char **argv) {
    printf("[TigerStyle] SendToy Starting (POSIX)...\n");

    const char* target_ip = "255.255.255.255";
    if (argc > 1) {
        target_ip = argv[1];
        printf("[TigerStyle] Targeting Peer IP: %s\n", target_ip);
    }

    if (platform_init() != 0) {
        fprintf(stderr, "Failed to init platform\n");
        return 1;
    }

    state_init(&g_ctx);
    
    // TigerStyle: Init Random Identity (Temporary until Crypto)
    srand((unsigned int)(time(NULL) ^ getpid()));
    for (int i = 0; i < 32; ++i) {
        g_ctx.my_public_key[i] = (u8)rand();
    }
    
    // Configuration Defaults
    g_ctx.config_listen_port = 44444;
    g_ctx.config_target_port = 44444;

    PlatformSocket udp_sock = platform_udp_bind(g_ctx.config_listen_port);
    if (udp_sock == PLATFORM_INVALID_SOCKET) {
        fprintf(stderr, "Failed to bind UDP socket on %d\n", g_ctx.config_listen_port);
        return 1;
    }

    if (platform_udp_enable_broadcast(udp_sock) != 0) {
        fprintf(stderr, "Failed to enable broadcast\n");
    }

    printf("[TigerStyle] Listening on port %d...\n", g_ctx.config_listen_port);

    u64 last_tick = platform_get_time_ms();

    while (1) {
        u64 now = platform_get_time_ms();

        // 4a. Tick Event
        if (now - last_tick >= 100) {
            state_event_t tick_ev;
            tick_ev.type = EVENT_TICK_100MS;
            state_update(&g_ctx, &tick_ev);
            last_tick = now;
            
            // TigerStyle Output: Flush Outbox
            if (g_ctx.outbox_len > 0) {
                 printf("DEBUG: Sending %d bytes to %s\n", g_ctx.outbox_len, target_ip);
                 platform_udp_sendto(udp_sock, g_ctx.outbox, g_ctx.outbox_len, target_ip, g_ctx.config_target_port);
                 g_ctx.outbox_len = 0;
            }
        }

        // 4b. Network Poll (poll)
        struct pollfd fds[1];
        fds[0].fd = udp_sock;
        fds[0].events = POLLIN;
        
        // Timeout 10ms
        int ret = poll(fds, 1, 10);
        
        if (ret > 0) {
            if (fds[0].revents & POLLIN) {
                char ip_str[64];
                u16 port;
                int bytes = platform_udp_recvfrom(udp_sock, g_net_rx_buffer, sizeof(g_net_rx_buffer), ip_str, sizeof(ip_str), &port);
                
                if (bytes > 0) {
                    printf("DEBUG: UDP Recv %d bytes from %s:%d\n", bytes, ip_str, port);
                    state_event_t net_ev;
                    net_ev.type = EVENT_NET_PACKET_RECEIVED;
                    net_ev.packet.data = g_net_rx_buffer;
                    net_ev.packet.len = (u32)bytes;
                    net_ev.packet.from_port = port;
                    struct in_addr addr;
                    
                    if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                         net_ev.packet.from_ip = addr.s_addr;
                    } else {
                         net_ev.packet.from_ip = 0;
                    }

                    state_update(&g_ctx, &net_ev);
                }
            }
        }
    }

    return 0;
}

#endif // !_WIN32
