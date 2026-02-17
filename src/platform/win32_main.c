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

// Helper to get Downloads path (Simple version using env var)
static void get_downloads_path(char* out_buf, size_t size) {
    const char* user_profile = getenv("USERPROFILE");
    if (user_profile) {
        snprintf(out_buf, size, "%s\\Downloads", user_profile);
    } else {
        strncpy(out_buf, ".", size);
    }
}

// TigerStyle: Handle IO Requests from State Machine
static void handle_io_request(PlatformSocket sock) {
    if (g_ctx.io_req_type == IO_NONE) return;

    if (g_ctx.io_req_type == IO_READ_CHUNK) {
        // Find filename
        char* fname = NULL;
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (g_ctx.jobs_active[i].state != JOB_STATE_FREE && 
                 g_ctx.jobs_active[i].id == g_ctx.io_req_job_id) { // Sender Job logic? 
                 // Wait, receiver sends REQ with sender's job ID (if negotiated) or receiver's?
                 // Current state.c uses 0 for MVP or random.
                 // Let's assume for MVP: single active transfer, or linear search.
                 fname = g_ctx.jobs_active[i].filename;
                 break;
             }
        }
        
        // Fallback for MVP: If we can't match ID (because state.c logic for ID isn't fully robust yet), usage scan.
        // Actually, state.c's `handle_command` sets a random ID. The REQ should carry it.
        // But for the very first REQ from receiver, does receiver know the ID?
        // Receiver sent REQ with job_id=0 in `handle_packet_offer`.
        // Sender needs to handle job_id=0? Or lookup by filename?
        // Sender `EVENT_USER_COMMAND` set a random ID.
        // Receiver `OFFER` handler didn't know sender's ID, so it sent 0.
        // Sender `REQ` handler needs to handle 0?
        if (!fname) {
             // Try to find ANY sender job
             for (int i = 0; i < JOBS_MAX; ++i) {
                 if (g_ctx.jobs_active[i].state == JOB_STATE_OFFER_SENT || 
                     g_ctx.jobs_active[i].state == JOB_STATE_TRANSFERRING) {
                     fname = g_ctx.jobs_active[i].filename;
                     break;
                 }
             }
        }

        if (fname) {
            FILE* f = fopen(fname, "rb");
            if (f) {
                fseek(f, (long)g_ctx.io_req_offset, SEEK_SET);
                
                packet_header_t header = {0};
                header.magic = MAGIC_TOYS;
                header.type = PACKET_TYPE_CHUNK_DATA;
                
                msg_data_t data_msg = {0};
                data_msg.offset = g_ctx.io_req_offset;
                data_msg.job_id = 0; // Sender ID?
                
                size_t headers_size = sizeof(packet_header_t) + sizeof(msg_data_t);
                u8* ptr = g_ctx.outbox;
                
                // Read directly into outbox after headers
                size_t read = fread(ptr + headers_size, 1, g_ctx.io_req_len, f);
                fclose(f);
                
                if (read > 0) {
                    header.body_length = sizeof(msg_data_t) + read;
                    memcpy(ptr, &header, sizeof(packet_header_t));
                    memcpy(ptr + sizeof(packet_header_t), &data_msg, sizeof(msg_data_t));
                    
                    int sent = platform_udp_sendto(sock, g_ctx.outbox, headers_size + read, 
                                        "255.255.255.255", // TODO: Use io_peer_ip
                                        g_ctx.io_peer_port);
                    // Hack for IP string
                    char ip_str[64];
                    struct in_addr addr;
                    addr.s_addr = g_ctx.io_peer_ip;
                    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                    platform_udp_sendto(sock, g_ctx.outbox, headers_size + read, ip_str, g_ctx.io_peer_port);
                    
                    if (g_ctx.debug_enabled) printf("DEBUG: Sent DATA Offset %llu Len %llu to %s\n", g_ctx.io_req_offset, read, ip_str);
                }
            } else {
                printf("Error: Read IO failed for %s\n", fname);
            }
        }
    } 
    else if (g_ctx.io_req_type == IO_WRITE_CHUNK) {
        // Find filename (Receiver Job)
        // Similar lookup...
        char* fname = NULL;
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (g_ctx.jobs_active[i].state == JOB_STATE_TRANSFERRING) {
                 fname = g_ctx.jobs_active[i].filename;
                 break;
             }
        }
        
        if (fname) {
            // Construct full path to Downloads
            char full_path[512];
            char down_path[256];
            get_downloads_path(down_path, sizeof(down_path));
            
            // Ensure dir exists
            CreateDirectoryA(down_path, NULL);
            
            snprintf(full_path, sizeof(full_path), "%s\\%s", down_path, fname);
            
            FILE* f = fopen(full_path, "r+b");
            if (!f) f = fopen(full_path, "wb"); 
            
            if (f) {
                fseek(f, (long)g_ctx.io_req_offset, SEEK_SET);
                fwrite(g_ctx.io_data_ptr, 1, g_ctx.io_req_len, f);
                fclose(f);
                if (g_ctx.debug_enabled) printf("DEBUG: Wrote Chunks %llu to %s\n", g_ctx.io_req_offset, full_path);
            } else {
                printf("Error: Write IO failed for %s\n", full_path);
            }
        }
    }

    g_ctx.io_req_type = IO_NONE; // Clear
}

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

    // Command Line Args: Target IP
    const char* target_ip = "255.255.255.255";
    if (__argc > 1) {
        target_ip = __argv[1];
        printf("[TigerStyle] Targeting Peer IP: %s\n", target_ip);
    }

    // 4. Main Loop
    u64 last_tick = platform_get_time_ms();
    
    // Console Input Buffer
    char input_buf[256];
    int input_pos = 0;

    // Set Console Mode for non-blocking check?
    // We'll use polling with kbhit-style logic or PeekConsoleInput
    HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);

    while (1) {
        u64 now = platform_get_time_ms();

        // 4a. Console Input (Simple Poll)
        DWORD events = 0;
        GetNumberOfConsoleInputEvents(hStdIn, &events);
        if (events > 0) {
            INPUT_RECORD record;
            DWORD read;
            if (PeekConsoleInputA(hStdIn, &record, 1, &read) && read > 0) {
                if (record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown) {
                    ReadConsoleInputA(hStdIn, &record, 1, &read); // Consume
                    char c = record.Event.KeyEvent.uChar.AsciiChar;
                    if (c == '\r' || c == '\n') {
                        if (input_pos > 0) {
                            input_buf[input_pos] = 0;
                            printf("\nCMD: %s\n", input_buf);
                            
                            // Parse "send <IP> <File>" manually to handle quotes/spaces
                            char cmd[16] = {0};
                            char ip_str[64] = {0};
                            char fname[256] = {0};
                            
                            char* s = input_buf;
                            
                            // 1. Skip leading whitespace
                            while (*s && *s <= 32) s++;
                            
                            // 2. Parse Command
                            int i = 0;
                            while (*s && *s > 32 && i < 15) cmd[i++] = *s++;
                            cmd[i] = 0;
                            
                            // 3. Skip whitespace
                            while (*s && *s <= 32) s++;
                            
                            // 4. Parse IP
                            i = 0;
                            while (*s && *s > 32 && i < 63) ip_str[i++] = *s++;
                            ip_str[i] = 0;
                            
                            // 5. Skip whitespace
                            while (*s && *s <= 32) s++;
                            
                            // 6. Parse Filename (Handle Quotes)
                            if (*s == '\"') {
                                s++; // Skip open quote
                                i = 0;
                                while (*s && *s != '\"' && i < 255) fname[i++] = *s++;
                                if (*s == '\"') s++; // Skip close quote
                            } else {
                                i = 0;
                                while (*s && *s >= 32 && i < 255) fname[i++] = *s++; // Take rest of line
                                // Trim trailing whitespace?
                                while (i > 0 && fname[i-1] <= 32) i--;
                            }
                            fname[i] = 0;

                            if (cmd[0]) {
                                if (strcmp(cmd, "send") == 0) {
                                    if (ip_str[0] && fname[0]) {
                                        state_event_t ev;
                                        ev.type = EVENT_USER_COMMAND;
                                        
                                        struct in_addr addr;
                                        if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                                            ev.cmd_send.target_ip = addr.s_addr;
                                            
                                            // Get File Size/Hash (Platform Job)
                                            FILE* f = fopen(fname, "rb");
                                            if (f) {
                                                fseek(f, 0, SEEK_END);
                                                ev.cmd_send.file_size = _ftelli64(f);
                                                fclose(f);
                                                strncpy(ev.cmd_send.filename, fname, 255);
                                                ev.cmd_send.file_hash_low = 0xCAFEBABE; // Todo: Real Hash
                                                
                                                state_update(&g_ctx, &ev);
                                            } else {
                                                printf("Error: File not found: %s\n", fname);
                                            }
                                        } else {
                                            printf("Error: Invalid IP\n");
                                        }
                                    } else {
                                        printf("Usage: send <IP> <File>\n");
                                    }
                                } else if (strcmp(cmd, "debug") == 0) {
                                    if (strcmp(ip_str, "on") == 0 || strcmp(ip_str, "1") == 0) {
                                        g_ctx.debug_enabled = true;
                                        printf("Debug Mode: ON\n");
                                    } else if (strcmp(ip_str, "off") == 0 || strcmp(ip_str, "0") == 0) {
                                        g_ctx.debug_enabled = false;
                                        printf("Debug Mode: OFF\n");
                                    } else {
                                        printf("Usage: debug <on|off>\n");
                                    }
                                }
                            }
                            input_pos = 0;
                        }
                        printf("> ");
                    } else if (c >= 32 && c <= 126 && input_pos < sizeof(input_buf) - 1) {
                        input_buf[input_pos++] = c;
                        printf("%c", c);
                    } else if (c == 8 && input_pos > 0) { // Backspace
                        input_pos--;
                        printf("\b \b");
                    }
                } else {
                     // Consume non-key events or key-up
                     ReadConsoleInputA(hStdIn, &record, 1, &read);
                }
            }
        }

// TigerStyle: Handle IO Requests from State Machine


// ... Main Loop ...
        // 4a. Tick Event
        if (now - last_tick >= 100) {
            state_event_t tick_ev;
            tick_ev.type = EVENT_TICK_100MS;
            state_update(&g_ctx, &tick_ev);
            handle_io_request(udp_sock); // Handle IO
            last_tick = now;
            
            // TigerStyle Output: Flush Outbox (Discovery packets)
            if (g_ctx.outbox_len > 0) {
                 // ...

                 if (g_ctx.debug_enabled) printf("DEBUG: Sending %d bytes to %s\n", g_ctx.outbox_len, target_ip);
                 platform_udp_sendto(udp_sock, g_ctx.outbox, g_ctx.outbox_len, target_ip, g_ctx.config_target_port);
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
                if (g_ctx.debug_enabled) printf("DEBUG: UDP Recv %d bytes from %s:%d\n", bytes, ip_str, port);
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
