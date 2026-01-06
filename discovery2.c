#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <process.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>
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

char BROADCAST_IP[INET_ADDRSTRLEN] = "255.255.255.255";  // Fallback
char LOCAL_IP[INET_ADDRSTRLEN] = "127.0.0.1";            // Fallback

void die(const char *msg) {
    perror(msg);
#ifdef _WIN32
    WSACleanup();
#endif
    exit(1);
}

void compute_local_and_broadcast() {
#ifdef _WIN32
    PIP_ADAPTER_ADDRESSES adapters = NULL;
    ULONG bufferSize = 16384;
    adapters = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    if (GetAdaptersAddresses(AF_INET, 0, NULL, adapters, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
            printf("LOCAL_IP: %s \n", LOCAL_IP);

            if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            for (PIP_ADAPTER_UNICAST_ADDRESS addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
                if (addr->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in *sa = (struct sockaddr_in *)addr->Address.lpSockaddr;
                    inet_ntop(AF_INET, &sa->sin_addr, LOCAL_IP, INET_ADDRSTRLEN);

                    PIP_ADAPTER_PREFIX prefix = adapter->FirstPrefix;
                    if (prefix) {
                        uint32_t mask = ((struct sockaddr_in *)prefix->Address.lpSockaddr)->sin_addr.s_addr;
                        uint32_t net = sa->sin_addr.s_addr & mask;
                        uint32_t bcast = net | ~mask;
                        struct in_addr bcast_addr;
                        bcast_addr.s_addr = bcast;
                        inet_ntop(AF_INET, &bcast_addr, BROADCAST_IP, INET_ADDRSTRLEN);
                        printf("Windows: Using local IP: %s, directed broadcast: %s\n", LOCAL_IP, BROADCAST_IP);
                        free(adapters);
                        return;
                    }
                }
            }
        }
    }
    free(adapters);
    printf("Windows: Failed to compute broadcast; using fallback\n");
#else
    struct ifaddrs *ifap, *ifa;
    if (getifaddrs(&ifap) != 0) {
        printf("getifaddrs failed; using fallback\n");
        return;
    }

    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
        if (mask == NULL) continue;

        inet_ntop(AF_INET, &addr->sin_addr, LOCAL_IP, INET_ADDRSTRLEN);

        uint32_t net = addr->sin_addr.s_addr & mask->sin_addr.s_addr;
        uint32_t bcast = net | ~mask->sin_addr.s_addr;

        inet_ntop(AF_INET, &bcast, BROADCAST_IP, INET_ADDRSTRLEN);
        printf("macOS: Using local IP: %s, directed broadcast: %s (interface %s)\n", LOCAL_IP, BROADCAST_IP, ifa->ifa_name);
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
            sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&sender_addr, &addr_len
        );
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
    inet_pton(AF_INET, BROADCAST_IP, &broadcast_addr.sin_addr);

    char hostname[256];
    gethostname(hostname, sizeof(hostname));

    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "DISCOVERY: Hello from %s (PID: %ld)", hostname, (long)getpid());

    printf("Sending broadcasts every %d seconds to %s...\n", SEND_INTERVAL, BROADCAST_IP);

    while (1) {
        if (sendto(sock, message, strlen(message), 0,
                   (struct sockaddr *)&broadcast_addr, sizeof(broadcast_addr)) < 0) {
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
    if (setsockopt(send_sock, SOL_SOCKET, SO_BROADCAST, (const char *)&broadcast_enable, sizeof(broadcast_enable)) < 0) {
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