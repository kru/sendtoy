#ifdef _WIN32

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <process.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "../core/types.h"

// --- Platform Interface & Implementation (Merged) ---

// TigerStyle: Assert macros
#define TIGER_ASSERT(cond) if (!(cond)) { fprintf(stderr, "ASSERT FAILED: %s:%d\n", __FILE__, __LINE__); abort(); }

// Types
typedef uint64_t PlatformSocket;
#define PLATFORM_INVALID_SOCKET ((PlatformSocket)(~0))

typedef uintptr_t PlatformFile;
#define PLATFORM_INVALID_FILE ((PlatformFile)(~0))

typedef struct {
#ifdef _MSC_VER
    __declspec(align(8)) uint8_t data[64];
#else
    _Alignas(8) uint8_t data[64];
#endif
} PlatformMutex;

typedef struct {
#ifdef _MSC_VER
    __declspec(align(8)) uint8_t data[32];
#else
    _Alignas(8) uint8_t data[32];
#endif
} PlatformThread;


// --- Implementation ---

int platform_init(void) {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return 1;
    }
    return 0;
}

void platform_cleanup(void) {
    WSACleanup();
}

void platform_sleep_ms(uint32_t ms) {
    Sleep(ms);
}

uint64_t platform_get_time_ms(void) {
    return GetTickCount64();
}

// Networking

PlatformSocket platform_udp_bind(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        return PLATFORM_INVALID_SOCKET;
    }

    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(port);

    if (bind(s, (SOCKADDR*)&local, sizeof(local)) == SOCKET_ERROR) {
        closesocket(s);
        return PLATFORM_INVALID_SOCKET;
    }

    return (PlatformSocket)s;
}

int platform_udp_enable_broadcast(PlatformSocket sock) {
    SOCKET s = (SOCKET)sock;
    BOOL bOptVal = TRUE;
    int bOptLen = sizeof(BOOL);
    if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char*)&bOptVal, bOptLen) == SOCKET_ERROR) {
        return -1;
    }
    return 0;
}

int platform_udp_sendto(PlatformSocket sock, const void *data, size_t len, const char *ip, uint16_t port) {
    SOCKET s = (SOCKET)sock;
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &dest.sin_addr);
    dest.sin_port = htons(port);

    int sent = sendto(s, (const char*)data, (int)len, 0, (SOCKADDR*)&dest, sizeof(dest));
    if (sent == SOCKET_ERROR) {
        return -1;
    }
    return sent;
}

int platform_udp_recvfrom(PlatformSocket sock, void *buf, size_t len, char *ip_out, size_t ip_len, uint16_t *port_out) {
    SOCKET s = (SOCKET)sock;
    struct sockaddr_in sender;
    int senderLen = sizeof(sender);

    int received = recvfrom(s, (char*)buf, (int)len, 0, (SOCKADDR*)&sender, &senderLen);
    if (received == SOCKET_ERROR) {
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
    closesocket((SOCKET)sock);
}

// Threading

typedef struct {
    HANDLE handle;
    void (*func)(void*);
    void *arg;
} Win32Thread;

_Static_assert(sizeof(Win32Thread) <= sizeof(PlatformThread), "PlatformThread struct too small");

static unsigned __stdcall thread_wrapper(void *arg) {
    Win32Thread *pt = (Win32Thread*)arg;
    if (pt->func) {
        pt->func(pt->arg);
    }
    return 0;
}

void platform_thread_start(PlatformThread *thread, void (*func)(void*), void *arg) {
    Win32Thread *pt = (Win32Thread*)thread->data;
    pt->func = func;
    pt->arg = arg;
    uintptr_t handle = _beginthreadex(NULL, 0, thread_wrapper, pt, 0, NULL);
    if (handle == 0) {
        pt->handle = NULL;
        return;
    }
    pt->handle = (HANDLE)handle;
}

void platform_thread_join(PlatformThread *thread) {
    Win32Thread *pt = (Win32Thread*)thread->data;
    if (pt->handle) {
        WaitForSingleObject(pt->handle, INFINITE);
        CloseHandle(pt->handle);
        pt->handle = NULL;
    }
}

// --- Main ---

// Global Context (Statically allocated)
static ctx_main_t g_ctx;

// Network Buffers (Statically allocated)
static u8 g_net_rx_buffer[1500]; // Standard MTU

int main(void) {
    printf("[TigerStyle] SendToy Starting...\n");

    // 1. Platform Init
    if (platform_init() != 0) {
        fprintf(stderr, "Failed to init platform\n");
        return 1;
    }

    // 2. Core Init
    state_init(&g_ctx);
    
    // TigerStyle: Init Random Identity (Temporary until Crypto)
    srand((unsigned int)(time(NULL) ^ GetCurrentProcessId()));
    for (int i = 0; i < 32; ++i) {
        g_ctx.my_public_key[i] = (u8)rand();
    }
    
    // Configuration Defaults
    g_ctx.config_listen_port = 44444;
    g_ctx.config_target_port = 44444;

    // 3. Network Setup (Discovery)
    PlatformSocket udp_sock = platform_udp_bind(g_ctx.config_listen_port); 
    if (udp_sock == PLATFORM_INVALID_SOCKET) {
        fprintf(stderr, "Failed to bind UDP socket on port %d\n", g_ctx.config_listen_port);
        return 1;
    }
    
    if (platform_udp_enable_broadcast(udp_sock) != 0) {
        fprintf(stderr, "Failed to enable broadcast\n");
    }

    printf("[TigerStyle] Listening on port %d...\n", g_ctx.config_listen_port);

    // 4. Main Loop
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
                 printf("DEBUG: UDP Broadcast %d bytes\n", g_ctx.outbox_len);
                 platform_udp_sendto(udp_sock, g_ctx.outbox, g_ctx.outbox_len, "255.255.255.255", g_ctx.config_target_port);
                 g_ctx.outbox_len = 0;
            }
        }

        // 4b. Network Poll
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET((SOCKET)udp_sock, &readfds);

        struct timeval tv = { 0, 10000 }; // 10ms timeout

        int activity = select(0, &readfds, NULL, NULL, &tv);

        if (activity > 0 && FD_ISSET((SOCKET)udp_sock, &readfds)) {
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

    return 0;
}

#endif // _WIN32
