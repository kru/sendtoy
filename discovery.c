#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winerror.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>
    #include <process.h>
    #include <netioapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    typedef SOCKET socket_t;
    #define CLOSE_SOCKET closesocket
    #define SLEEP_SECONDS(sec) Sleep((sec) * 1000)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    typedef int socket_t;
    #define CLOSE_SOCKET close
    #define SLEEP_SECONDS(sec) sleep(sec)
#endif

#define PORT 50000
#define BUFFER_SIZE 1024
#define SEND_INTERVAL 5  // seconds

// Dynamic array implentation from 
// https://github.com/tsoding/nob.h/blob/main/nob.h
#define SND_DA_INIT_CAP 256

#define SND_REALLOC realloc

#ifdef __cplusplus
#define SND_DECLTYPE_CAST(T) (decltype(T))
#else
#define SND_DECLTYPE_CAST(T)
#endif // __cplusplus

#define ARRAY_SIZE(x) ( sizeof(x)/sizeof(x[0]) )

#define snd_da_reserve(da, expected_capacity)               \
    do {                                                    \
        if ((expected_capacity) > (da)->capacity) {         \
            if ((da)->capacity == 0) {                      \
                (da)->capacity = SND_DA_INIT_CAP;           \
            }                                               \
            while((expected_capacity) > (da)->capacity) {   \
                (da)->capacity *= 2;                        \
            }                                               \
            (da)->items = SND_DECLTYPE_CAST((da)->items)SND_REALLOC((da)->items, (da)->capacity * sizeof(*(da)->items)); \
        }                                                   \
    } while(0)

#define snd_da_append(da, item)                 \
    do {                                        \
        snd_da_reserve((da), (da)->count + 1);  \
        (da)->items[(da)->count++] = (item);    \
    } while(0)

// Append several items to a dynamic array
#define snd_da_append_many(da, new_items, new_items_count)                                      \
    do {                                                                                        \
        snd_da_reserve((da), (da)->count + (new_items_count));                                  \
        memcpy((da)->items + (da)->count, (new_items), (new_items_count)*sizeof(*(da)->items)); \
        (da)->count += (new_items_count);                                                       \
    } while (0)

#define snd_da_free(da) free((da).items)

typedef struct {
    char *items;
    size_t count;
    size_t capacity;
} Snd_String_Builder;

// Append a NULL-terminated string to a string builder
#define snd_sb_append_cstr(sb, cstr)  \
    do {                              \
        const char *s = (cstr);       \
        size_t n = strlen(s);         \
        snd_da_append_many(sb, s, n); \
    } while (0)

char LOCAL_IP[INET_ADDRSTRLEN]  = "127.0.0.1";
char BROADCAST_IP[INET_ADDRSTRLEN]  = "255.255.255.255";

/**
 * We can have several broadcast address -> put inside array
 * We can have several local ip -> put inside array
 * Broadcast to addresses
 * Listener later update this valid addresses(the one that broadcast the same packet)
 * Let's make above initial discovery work first
**/

typedef struct {
    char        *items;
    size_t      count;
    size_t      capacity;
} IP_Addrs;

IP_Addrs brd_addrs = {0};
IP_Addrs ip_addrs = {0};

void die(const char *msg) {
    perror(msg);
#ifdef _WIN32
    WSACleanup();
#endif
    exit(1);
}

// TODO(kris): better detection for daily use
// now we rely on 192.168.x.x
int is_non_local_subnet(uint32_t addr) {
    // Common private/VPN ranges to exclude
    if ((addr & htonl(0xFF000000)) == htonl(0x0A000000)) return 1;  // 10.0.0.0/8
    if ((addr & htonl(0xFFF00000)) == htonl(0xAC100000)) return 1;  // 172.16.0.0/12
    // if ((addr & htonl(0xFFFF0000)) == htonl(0xC0A80000)) return 1;  // 192.168.0.0/16
    return 0;
}

void compute_local_and_broadcast() {
#ifdef _WIN32
    PIP_ADAPTER_ADDRESSES adapters = NULL;
    ULONG buf_size = 16384;
    adapters = (PIP_ADAPTER_ADDRESSES)malloc(buf_size);
    if (adapters == NULL) return;

    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, adapters, &buf_size) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
            // printf("sa_family: %lu, status: %d, name: %ls \n", 
            // adapter->IfType, adapter->OperStatus, adapter->FriendlyName);

            if (adapter->OperStatus != IfOperStatusUp 
                || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK 
                || adapter->IfType == IF_TYPE_TUNNEL) continue;

            // we have 3 OperStatus:1 (active) and 3 addresses
            // 10.77.0.5 -> wireguard
            // 169.254.83.107 -> tailscale 
            // 192.168.1.76 -> WLAN

            // to detect if and IP attached to physical interface
            // use adapter->PhysicalAddress.PhysicalAddressLength
            if (adapter->PhysicalAddressLength != 0) {
                for (PIP_ADAPTER_UNICAST_ADDRESS u = adapter->FirstUnicastAddress; u; u = u->Next) {
                    if (u->Address.lpSockaddr->sa_family != AF_INET) continue;

                    struct sockaddr_in *sin = (struct sockaddr_in *)u->Address.lpSockaddr;
                    uint32_t addr = sin->sin_addr.s_addr;

                    int is_local = is_non_local_subnet(addr) == 1;
                    printf("is_local: %d\n", is_local);
                    if (is_local) continue;

                    inet_ntop(AF_INET, &sin->sin_addr, LOCAL_IP, INET_ADDRSTRLEN);
                    printf("unicast IP addr: %s\n", LOCAL_IP);
                    snd_da_append_many(&ip_addrs, LOCAL_IP, INET_ADDRSTRLEN);
                    snd_da_append_many(&ip_addrs, "\n", 1);


                    // Obtain the prefix length (CIDR notation, e.g., 24)
                    ULONG prefixLength = u->OnLinkPrefixLength;
                    // Convert prefix length to subnet mask (network byte order)
                    ULONG mask_network = 0;
                    if (ConvertLengthToIpv4Mask(prefixLength, &mask_network) != NO_ERROR) {
                        printf("Failed to convert prefix length %lu to mask\n", prefixLength);
                        continue;
                    }
                    uint32_t bcast_val = (addr & mask_network) | (~mask_network);

                    struct in_addr bcast_addr = { .s_addr = bcast_val };

                    inet_ntop(AF_INET, &bcast_addr, BROADCAST_IP, INET_ADDRSTRLEN);
                    snd_da_append_many(&brd_addrs, BROADCAST_IP, INET_ADDRSTRLEN);
                    snd_da_append_many(&brd_addrs, "\n", 1);
                    printf("unicast broadcast: %s, val: %lu\n", BROADCAST_IP, mask_network);
                }
            }
        }
    } // end GetAdaptersAddresses
    free(adapters);
    if (ip_addrs.count == 0) {
        printf("Windows: No suitable physical interface found; using fallback limited broadcast\n");
    }
#else
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0) return;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        uint32_t ip = addr->sin_addr.s_addr;

        struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
        if (!mask) continue;

        inet_ntop(AF_INET, &addr->sin_addr, LOCAL_IP, INET_ADDRSTRLEN);

        uint32_t net = addr->sin_addr.s_addr & mask->sin_addr.s_addr;
        uint32_t bcast_val = net | ~mask->sin_addr.s_addr;
        struct in_addr bcast_addr = { .s_addr = bcast_val };
        inet_ntop(AF_INET, &bcast_addr, BROADCAST_IP, INET_ADDRSTRLEN);

        printf("macOS: Selected physical interface - Local IP %s, broadcast %s (interface %s)\n",
            LOCAL_IP, BROADCAST_IP, ifa->ifa_name);
        break;
    }
    freeifaddrs(ifap);
#endif
}

#ifdef _WIN32
DWORD WINAPI listener_thread(LPVOID arg) {
#else
void *listener_thread(void *arg) {
#endif
    socket_t sock = *(socket_t *)arg;
    struct sockaddr_in sender_addr;
    socklen_t addr_len = sizeof(sender_addr);
    char buffer[BUFFER_SIZE];

    printf("Listening for broadcasts on port %d...\n", PORT);

    while (1) {
        int recv_len = recvfrom(
            sock, buffer, BUFFER_SIZE - 1, 0,(struct sockaddr *)&sender_addr, &addr_len);

        if (recv_len < 0) {
#ifdef _WIN32
            printf("recvfrom failed: %d\n", WSAGetLastError());
#else
            perror("recvfrom failed");
#endif
            continue;
        }
        buffer[recv_len] = '\0';

        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);

        if (strcmp(sender_ip, LOCAL_IP) == 0) {
            continue;  // Ignore self-sent
        }

        printf("Received from %s:%d: %s\n", sender_ip, ntohs(sender_addr.sin_port), buffer);
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

void sender_loop(socket_t sock) {
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(PORT);

    // for (int i = 0; i < brd_addrs.count;)
    inet_pton(AF_INET, BROADCAST_IP, &broadcast_addr.sin_addr);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "DISCOVERY: Hello from %s (PID: %ld)", hostname, (long)getpid());

    printf("Sending broadcasts every %d seconds to %s...\n", SEND_INTERVAL, BROADCAST_IP);

    while (1) {
        int sent = sendto(sock, 
            message, strlen(message), 0,(struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)); 
        if (sent < 0) {
#ifdef _WIN32
            printf("sendto failed: %d\n", WSAGetLastError());
#else
            perror("sendto failed");
#endif
        } else {
            printf("Sent: %s\n", message);
        }
        SLEEP_SECONDS(SEND_INTERVAL);
    }
}

int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        die("WSAStartup failed");
    }
#endif

    compute_local_and_broadcast();

    socket_t send_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sock < 0) die("socket creation failed (sender)");

    int broadcast_enable = 1;
    if (setsockopt(send_sock, SOL_SOCKET, SO_BROADCAST, 
        (const char *)&broadcast_enable, sizeof(broadcast_enable)) < 0) {
        die("setsockopt SO_BROADCAST failed");
    }

    socket_t listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_sock < 0) die("socket creation failed (listener)");

    int reuse = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0) {
        die("setsockopt SO_REUSEADDR failed");
    }
#ifndef _WIN32
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEPORT failed (non-fatal)");
    }
#endif

    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(PORT);
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        die("bind failed");
    }

#ifdef _WIN32
    HANDLE thread = CreateThread(NULL, 0, listener_thread, &listen_sock, 0, NULL);
    if (thread == NULL) die("CreateThread failed");
#else
    pthread_t thread;
    if (pthread_create(&thread, NULL, listener_thread, &listen_sock) != 0) {
        die("pthread_create failed");
    }
#endif

    sender_loop(send_sock);

    CLOSE_SOCKET(send_sock);
    CLOSE_SOCKET(listen_sock);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}