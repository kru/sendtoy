#include "p2p_native.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

void on_p2p_event(p2p_event_t evt) {
	switch(evt.type) {
		case P2P_EVENT_PEER_FOUND:
			printf("[+] Peer found: %s:%d (Has Key? %s)\n",
				evt.data.peer.ip, evt.data.peer.port, "Yes");
			break;
		case P2P_EVENT_PROGRESS:
			printf("\r--> Transferring... %llu / %llu",
				evt.data.transfer.current, evt.data.transfer.total);
			break;
		case P2P_EVENT_ERROR:
			printf("[-] Error: %s\n", evt.data.error_msg);
			break;
        case P2P_EVENT_TRANSFER_START:
        case P2P_EVENT_COMPLETE:
        	break;
    }
}

int main(int argc, char** argv) {
	printf("Initializing P2P Node...\n");

	if (p2p_init(on_p2p_event) != 0) {
		printf("Failed to init socket.\n");
		return 1;
	}

	char name[32];
	sprintf(name, "Node-%d", (int)time(NULL) % 1000);
	p2p_start_discovery(name);

	printf("Listening for peers... (Press 's' to send file, 'q' to quit)\n");

    while (1) {
        char c = getchar();
        if (c == 'q') break;
        if (c == 's') {
            char ip[64];
            char path[256];
            printf("Enter IP: ");
            scanf("%s", ip);
            printf("Enter File Path: ");
            scanf("%s", path);
            printf("Sending...\n");
            p2p_send_file(ip, path);
            printf("\nDone.\n");
        }
    }

	p2p_shutdown();
	return 0;
}