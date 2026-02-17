#ifndef _WIN32

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
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

// TCP Helpers
PlatformSocket platform_tcp_bind(uint16_t port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return PLATFORM_INVALID_SOCKET;
    
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    
    if (bind(s, (struct sockaddr*)&local, sizeof(local)) < 0) {
        close(s);
        return PLATFORM_INVALID_SOCKET;
    }
    
    if (listen(s, 128) < 0) { // SOMAXCONN often 128 on POSIX
        close(s);
        return PLATFORM_INVALID_SOCKET;
    }
    
    // Set Non-Blocking
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    
    return s;
}

PlatformSocket platform_tcp_connect(const char* ip, uint16_t port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return PLATFORM_INVALID_SOCKET;
    
    // Set Non-Blocking
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &dest.sin_addr) != 1) {
        close(s);
        return PLATFORM_INVALID_SOCKET;
    }
    dest.sin_port = htons(port);
    
    int res = connect(s, (struct sockaddr*)&dest, sizeof(dest));
    if (res < 0) {
        if (errno != EINPROGRESS) {
            printf("DEBUG: connect failed with error %d (%s)\n", errno, strerror(errno));
            close(s);
            return PLATFORM_INVALID_SOCKET;
        }
    }
    
    return s;
}

int platform_tcp_send(PlatformSocket sock, const void* data, size_t len) {
    // MSG_NOSIGNAL to prevent SIGPIPE on broken pipe
    ssize_t sent = send(sock, data, len, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return (int)sent;
}

int platform_tcp_recv(PlatformSocket sock, void* buf, size_t len) {
    ssize_t received = recv(sock, buf, len, 0);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    // 0 means clean close
    return (int)received;
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
static u8 g_net_rx_buffer[65536];

// TigerStyle: TCP Stream Reassembly Buffers
typedef struct {
    u8 buffer[65536 + 4096]; 
    u32 len;
} JobRxBuffer;

static JobRxBuffer g_job_rx[JOBS_MAX];

// Helper to get Downloads path
static void get_downloads_path(char* out_buf, size_t size) {
    const char* home_dir = getenv("HOME");
    if (home_dir) {
        snprintf(out_buf, size, "%s/Downloads", home_dir);
    } else {
        strncpy(out_buf, ".", size);
    }
}

// TigerStyle: Handle IO Requests from State Machine
static void handle_io_request(PlatformSocket sock) {
    if (g_ctx.io_req_type == IO_NONE) return;

    if (g_ctx.io_req_type == IO_READ_CHUNK) {
        // Find filename and Job
        char* fname = NULL;
        transfer_job_t* job = NULL;

        for (int i = 0; i < JOBS_MAX; ++i) {
             if (g_ctx.jobs_active[i].state != JOB_STATE_FREE && 
                 g_ctx.jobs_active[i].id == g_ctx.io_req_job_id) { 
                 fname = g_ctx.jobs_active[i].filename;
                 job = &g_ctx.jobs_active[i];
                 break;
             }
        }
        
        // Fallback for MVP
        if (!fname) {
             for (int i = 0; i < JOBS_MAX; ++i) {
                 if (g_ctx.jobs_active[i].state == JOB_STATE_OFFER_SENT || 
                     g_ctx.jobs_active[i].state == JOB_STATE_TRANSFERRING) {
                     fname = g_ctx.jobs_active[i].filename;
                     job = &g_ctx.jobs_active[i];
                     if (g_ctx.debug_enabled) printf("DEBUG: IO Read Fallback to Job %d File '%s'\n", i, fname);
                     break;
                 }
             }
        }

        if (fname) {
            FILE* f = fopen(fname, "rb");
            if (f) {
                fseeko(f, (off_t)g_ctx.io_req_offset, SEEK_SET);
                
                size_t read_len = g_ctx.io_req_len;
                if (read_len > sizeof(g_ctx.work_buffer)) read_len = sizeof(g_ctx.work_buffer);
                
                size_t read = fread(g_ctx.work_buffer, 1, read_len, f);
                fclose(f);
                
                if (read > 0) {
                    if (job && job->tcp_socket != 0 && job->tcp_socket != PLATFORM_INVALID_SOCKET) {
                        // ** TCP Fast Path **
                        // Segment into 64KB chunks to fit in our RX buffers
                        const size_t TCP_CHUNK_SIZE = 65536 - sizeof(packet_header_t) - sizeof(msg_data_t) - 128; // Safe margin
                        size_t offset = 0;
                        PlatformSocket s = (PlatformSocket)job->tcp_socket;

                        while (offset < read) {
                            size_t chunk_len = read - offset;
                            if (chunk_len > TCP_CHUNK_SIZE) chunk_len = TCP_CHUNK_SIZE;
                            
                            packet_header_t header = {0};
                            header.magic = MAGIC_TOYS;
                            header.type = PACKET_TYPE_CHUNK_DATA;
                            
                            msg_data_t data_msg = {0};
                            data_msg.offset = g_ctx.io_req_offset + offset;
                            data_msg.job_id = job->id; 
                            
                            header.body_length = sizeof(msg_data_t) + chunk_len;
                            
                            u8* ptr = g_ctx.outbox;
                            memcpy(ptr, &header, sizeof(packet_header_t));
                            memcpy(ptr + sizeof(packet_header_t), &data_msg, sizeof(msg_data_t));
                            memcpy(ptr + sizeof(packet_header_t) + sizeof(msg_data_t), 
                                   g_ctx.work_buffer + offset, chunk_len);
                                   
                            size_t packet_len = sizeof(packet_header_t) + sizeof(msg_data_t) + chunk_len;
                            
                            int res = platform_tcp_send(s, ptr, packet_len);
                            if (res < 0) {
                                printf("Error: TCP Send Failed during chunk xfer. Closing.\n");
                                break;
                            }
                            
                            offset += chunk_len;
                            // NO SLEEP!
                        }
                        if (g_ctx.debug_enabled) printf("DEBUG: TCP Stream Sent %zu bytes\n", read);

                    } else {
                        // ** UDP Fallback Path **
                        const size_t CHUNK_MTU = 1400;
                        size_t offset = 0;
                        
                        char ip_str[64];
                        struct in_addr addr;
                        addr.s_addr = g_ctx.io_peer_ip;
                        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
                        
                        while (offset < read) {
                            size_t chunk_len = read - offset;
                            if (chunk_len > CHUNK_MTU) chunk_len = CHUNK_MTU;
                            
                            packet_header_t header = {0};
                            header.magic = MAGIC_TOYS;
                            header.type = PACKET_TYPE_CHUNK_DATA;
                            
                            msg_data_t data_msg = {0};
                            data_msg.offset = g_ctx.io_req_offset + offset;
                            data_msg.job_id = 0; 
                            
                            header.body_length = sizeof(msg_data_t) + chunk_len;
                            
                            u8* ptr = g_ctx.outbox;
                            memcpy(ptr, &header, sizeof(packet_header_t));
                            memcpy(ptr + sizeof(packet_header_t), &data_msg, sizeof(msg_data_t));
                            memcpy(ptr + sizeof(packet_header_t) + sizeof(msg_data_t), 
                                   g_ctx.work_buffer + offset, chunk_len);
                                   
                            size_t packet_len = sizeof(packet_header_t) + sizeof(msg_data_t) + chunk_len;
                            
                            platform_udp_sendto(sock, g_ctx.outbox, packet_len, ip_str, g_ctx.io_peer_port);
                            
                            offset += chunk_len;
                            
                            // Pacing: Sleep 1ms every 32 packets
                            if ((offset / chunk_len) % 32 == 0) {
                                usleep(1000); 
                            }
                        }
                        if (g_ctx.debug_enabled) printf("DEBUG: UDP Burst Sent %zu bytes to %s\n", read, ip_str);
                    }
                }
            } else {
                printf("Error: Read IO failed for '%s'\n", fname);
            }
        } else {
             if (g_ctx.debug_enabled) printf("DEBUG: IO Read - No Active Job Found for ID %d\n", g_ctx.io_req_job_id);
        }
    } 
    else if (g_ctx.io_req_type == IO_WRITE_CHUNK) {
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
            struct stat st = {0};
            if (stat(down_path, &st) == -1) {
                mkdir(down_path, 0755);
            }
            
            snprintf(full_path, sizeof(full_path), "%s/%s", down_path, fname);
            
            FILE* f = fopen(full_path, "r+b");
            if (!f) f = fopen(full_path, "wb"); 
            
            if (f) {
                fseeko(f, (off_t)g_ctx.io_req_offset, SEEK_SET);
                fwrite(g_ctx.io_data_ptr, 1, g_ctx.io_req_len, f);
                fclose(f);
                if (g_ctx.debug_enabled) printf("DEBUG: Wrote Chunks %llu to %s\n", g_ctx.io_req_offset, full_path);

                // Trigger Next Request
                state_event_t ev;
                ev.type = EVENT_CHUNK_WRITTEN;
                ev.tcp.socket = (u64)g_ctx.io_req_job_id; 
                ev.tcp.success = true;
                state_update(&g_ctx, &ev, platform_get_time_ms());
                
                // Recursively handle the resulting IO request (REQ Send)
                handle_io_request(sock);

            } else {
                printf("Error: Write IO failed for %s\n", full_path);
            }
        }
    }

    } else if (g_ctx.io_req_type == IO_TCP_CONNECT) {
        char ip_str[64];
        struct in_addr addr;
        addr.s_addr = g_ctx.io_peer_ip;
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));
        
        PlatformSocket sock = platform_tcp_connect(ip_str, g_ctx.io_peer_port);
        if (sock != PLATFORM_INVALID_SOCKET) {
             for (int i=0; i<JOBS_MAX; ++i) {
                 if (g_ctx.jobs_active[i].id == g_ctx.io_req_job_id) {
                     g_ctx.jobs_active[i].tcp_socket = (u64)sock;
                     break;
                 }
             }
        } else {
             printf("Error: TCP Connect failed to %s\n", ip_str);
             state_event_t ev;
             ev.type = EVENT_TCP_CONNECTED;
             ev.tcp.socket = 0;
             ev.tcp.success = false;
             state_update(&g_ctx, &ev, platform_get_time_ms());
        }
    } else if (g_ctx.io_req_type == IO_TCP_SEND) {
        PlatformSocket sock = PLATFORM_INVALID_SOCKET;
         for (int i=0; i<JOBS_MAX; ++i) {
             if (g_ctx.jobs_active[i].id == g_ctx.io_req_job_id) {
                 sock = (PlatformSocket)g_ctx.jobs_active[i].tcp_socket;
                 break;
             }
         }
         
         if (sock != PLATFORM_INVALID_SOCKET) {
             int result = platform_tcp_send(sock, g_ctx.io_data_ptr, g_ctx.io_req_len);
             if (result < 0) {
                 printf("Error: TCP Send Failed\n");
             } else {
                 if (g_ctx.debug_enabled) printf("DEBUG: TCP Sent %d bytes\n", result);
             }
         }
    } else if (g_ctx.io_req_type == IO_TCP_CLOSE) {
         // Close logic
    }

    g_ctx.io_req_type = IO_NONE; // Clear
}

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

    // 3b. TCP Listener
    PlatformSocket tcp_listener = platform_tcp_bind(g_ctx.config_listen_port);
    if (tcp_listener == PLATFORM_INVALID_SOCKET) {
        fprintf(stderr, "Failed to bind TCP listener on port %d\n", g_ctx.config_listen_port);
    } else {
        printf("[TigerStyle] TCP Listening on port %d...\n", g_ctx.config_listen_port);
    }

    u64 last_tick = platform_get_time_ms();

    while (1) {
        u64 now = platform_get_time_ms();

// TigerStyle: Handle IO Requests from State Machine


    // Console Input Buffer
    char input_buf[256];
    int input_pos = 0;

    // ... loop ...
        // 4a. Tick Event
        if (now - last_tick >= 100) {
            state_event_t tick_ev;
            tick_ev.type = EVENT_TICK_100MS;
            state_update(&g_ctx, &tick_ev, now);
            handle_io_request(udp_sock);
            last_tick = now;
            
            // TigerStyle Output: Flush Outbox
            if (g_ctx.outbox_len > 0) {
                 char ip_str[64] = "255.255.255.255";
                 u16 target_port = g_ctx.config_target_port;
                 
                 if (g_ctx.outbox_target_ip != 0) {
                      struct in_addr addr;
                      addr.s_addr = g_ctx.outbox_target_ip;
                      if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str))) {
                          // Success
                      }
                      target_port = g_ctx.outbox_target_port;
                 } else {
                      // Broadcast (Default) for 0
                      target_port = g_ctx.config_target_port; 
                      if (g_ctx.outbox_target_port != 0) target_port = g_ctx.outbox_target_port;
                 }

                 if (g_ctx.debug_enabled) printf("DEBUG: Sending %u bytes to %s:%u\n", g_ctx.outbox_len, ip_str, target_port);
                 platform_udp_sendto(udp_sock, g_ctx.outbox, g_ctx.outbox_len, ip_str, target_port);
                 g_ctx.outbox_len = 0;
                 g_ctx.outbox_target_ip = 0; // Reset
                 g_ctx.outbox_target_port = 0;
            }
        }

        // 4b. Network Poll (poll) + Stdin Poll
        // UDP(0) + Stdin(1) + TCP_Listen(2) + Max_Jobs(JOBS_MAX)
        #define MAX_POLL_FDS (3 + JOBS_MAX)
        struct pollfd fds[MAX_POLL_FDS];
        int nfds = 0;
        
        // 0. UDP
        fds[nfds].fd = udp_sock;
        fds[nfds].events = POLLIN;
        nfds++;
        
        // 1. Stdin
        fds[nfds].fd = STDIN_FILENO;
        fds[nfds].events = POLLIN;
        nfds++;
        
        // 2. TCP Listener
        if (tcp_listener != PLATFORM_INVALID_SOCKET) {
            fds[nfds].fd = tcp_listener;
            fds[nfds].events = POLLIN;
            nfds++;
        }
        
        // 3... TCP Connections
        for (int i=0; i<JOBS_MAX; ++i) {
            PlatformSocket s = (PlatformSocket)g_ctx.jobs_active[i].tcp_socket;
            if (s != 0 && s != PLATFORM_INVALID_SOCKET) {
                fds[nfds].fd = s;
                fds[nfds].events = POLLIN;
                // If connecting, wait for POLLOUT
                if (g_ctx.jobs_active[i].state == JOB_STATE_CONNECTING) {
                    fds[nfds].events |= POLLOUT;
                }
                nfds++;
            }
        }
        
        // Timeout 10ms
        int ret = poll(fds, nfds, 10);


        
        if (ret > 0) {
            // 1. Network Scan
            for (int i=0; i<nfds; ++i) {
                if (fds[i].revents == 0) continue;
                
                if (fds[i].fd == udp_sock && (fds[i].revents & POLLIN)) {
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
                         state_update(&g_ctx, &net_ev, platform_get_time_ms());
                         handle_io_request(udp_sock);
                     }
                }
                else if (tcp_listener != PLATFORM_INVALID_SOCKET && fds[i].fd == tcp_listener && (fds[i].revents & POLLIN)) {
                    // TCP Accept
                    struct sockaddr_in client_addr;
                    socklen_t addrlen = sizeof(client_addr);
                    int client = accept(tcp_listener, (struct sockaddr*)&client_addr, &addrlen);
                    if (client >= 0) {
                        int flags = fcntl(client, F_GETFL, 0);
                        fcntl(client, F_SETFL, flags | O_NONBLOCK);
                        
                        char client_ip[64];
                        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
                        printf("DEBUG: Accepted TCP Connection from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
                        
                        state_event_t ev;
                        ev.type = EVENT_TCP_CONNECTED;
                        ev.tcp.socket = (u64)client;
                        ev.tcp.success = true;
                        state_update(&g_ctx, &ev, platform_get_time_ms());
                        handle_io_request(udp_sock);
                    }
                }
                else if (fds[i].fd == STDIN_FILENO && (fds[i].revents & POLLIN)) {
                    // Stdin handled below to keep structure... or handle here?
                    // Let's handle it here to simplify the loop
                    continue; // Skip, detailed below
                }
                else {
                    // Must be a Job Socket
                    for (int j=0; j<JOBS_MAX; ++j) {
                        PlatformSocket s = (PlatformSocket)g_ctx.jobs_active[j].tcp_socket;
                        if (s == fds[i].fd) {
                            // Check Connect
                            if (g_ctx.jobs_active[j].state == JOB_STATE_CONNECTING && (fds[i].revents & POLLOUT)) {
                                int err = 0;
                                socklen_t len = sizeof(err);
                                getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
                                
                                if (err == 0) {
                                     state_event_t ev;
                                     ev.type = EVENT_TCP_CONNECTED;
                                     ev.tcp.socket = (u64)s;
                                     ev.tcp.success = true;
                                     state_update(&g_ctx, &ev, platform_get_time_ms());
                                     handle_io_request(udp_sock);
                                } else {
                                     printf("DEBUG: TCP Connect Async Failed error %d\n", err);
                                     state_event_t ev;
                                     ev.type = EVENT_TCP_CONNECTED;
                                     ev.tcp.socket = (u64)s;
                                     ev.tcp.success = false;
                                     state_update(&g_ctx, &ev, platform_get_time_ms());
                                     close(s);
                                     g_ctx.jobs_active[j].tcp_socket = 0;
                                }
                            }
                            // Check Data
                            else if (fds[i].revents & POLLIN) {
                                JobRxBuffer* rx = &g_job_rx[j];
                                int space = sizeof(rx->buffer) - rx->len;
                                if (space > 0) {
                                    int n = platform_tcp_recv(s, rx->buffer + rx->len, space);
                                    if (n > 0) {
                                        rx->len += n;
                                        
                                        // Framing Loop
                                        while (rx->len >= sizeof(packet_header_t)) {
                                            packet_header_t* head = (packet_header_t*)rx->buffer;
                                            if (head->magic != MAGIC_TOYS) {
                                                printf("DEBUG: TCP Magic Mismatch! Closing.\n");
                                                state_event_t ev;
                                                ev.type = EVENT_TCP_CLOSED;
                                                ev.tcp.socket = (u64)s;
                                                state_update(&g_ctx, &ev, platform_get_time_ms());
                                                close(s);
                                                g_ctx.jobs_active[j].tcp_socket = 0;
                                                rx->len = 0;
                                                break;
                                            }
                                            
                                            u32 packet_len = sizeof(packet_header_t) + (u32)head->body_length;
                                            if (rx->len >= packet_len) {
                                                state_event_t ev;
                                                ev.type = EVENT_TCP_DATA;
                                                ev.tcp.socket = (u64)s;
                                                ev.tcp.data = rx->buffer;
                                                ev.tcp.len = packet_len;
                                                state_update(&g_ctx, &ev, platform_get_time_ms());
                                                handle_io_request(udp_sock);
                                                
                                                u32 remaining = rx->len - packet_len;
                                                if (remaining > 0) {
                                                    memmove(rx->buffer, rx->buffer + packet_len, remaining);
                                                }
                                                rx->len = remaining;
                                            } else {
                                                break;
                                            }
                                        }
                                    } else if (n == 0) {
                                        // Close
                                        state_event_t ev;
                                        ev.type = EVENT_TCP_CLOSED;
                                        ev.tcp.socket = (u64)s;
                                        state_update(&g_ctx, &ev, platform_get_time_ms());
                                        close(s);
                                        g_ctx.jobs_active[j].tcp_socket = 0;
                                        rx->len = 0;
                                    } else {
                                        // Error
                                        state_event_t ev;
                                        ev.type = EVENT_TCP_CLOSED;
                                        ev.tcp.socket = (u64)s;
                                        state_update(&g_ctx, &ev, platform_get_time_ms());
                                        close(s);
                                        g_ctx.jobs_active[j].tcp_socket = 0;
                                        rx->len = 0;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            
            // 2. Console Input (Find index for Stdin)
            int stdin_idx = -1;
            for(int i=0; i<nfds; ++i) if(fds[i].fd == STDIN_FILENO) stdin_idx = i;
            
            if (stdin_idx != -1 && (fds[stdin_idx].revents & POLLIN)) {
                char c;
                if (read(STDIN_FILENO, &c, 1) > 0) {
                     if (c == '\n') {
                        if (input_pos > 0) {
                            input_buf[input_pos] = 0;
                            printf("CMD: %s\n", input_buf);
                            
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
                                            
                                            // Get File Size/Hash
                                            FILE* f = fopen(fname, "rb");
                                            if (f) {
                                                fseeko(f, 0, SEEK_END);
                                                ev.cmd_send.file_size = (u64)ftello(f); // ftello for large files?
                                                fclose(f);
                                                strncpy(ev.cmd_send.filename, fname, 255);
                                                ev.cmd_send.file_hash_low = 0xCAFEBABE; 
                                                
                                                state_update(&g_ctx, &ev, platform_get_time_ms());
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
                        fflush(stdout);
                     } else if (c >= 32 && c <= 126 && input_pos < sizeof(input_buf) - 1) {
                        input_buf[input_pos++] = c;
                        // printf("%c", c); // Local echo? Depends on terminal mode. 
                        // Usually local echo is on, so we don't print.
                     }
                }
            }
        }
    }

    return 0;
}

#endif // !_WIN32
