#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

// Mock Platform functions needed by state.c (since we include it)
// state.c might use random...
// state.c uses printf...

// Include the unit under test
// Note: We need to define types and such first? No, state.c includes types.h
// We need to make sure include path finds types.h in core/
#include "core/state.c"

// Helpers
#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAILED at line %d: %s\n", __LINE__, #cond); \
        fflush(stdout); \
        exit(1); \
    } \
} while(0)

// Static context to avoid stack overflow
static ctx_main_t ctx; // Zero initialized

void print_test_header(const char* name) {
    printf("\n=== TEST: %s ===\n", name);
    fflush(stdout);
}

void test_get_basename() {
    print_test_header("get_basename");
    
    // 1. Simple file
    TEST_ASSERT(strcmp(get_basename("file.txt"), "file.txt") == 0);
    
    // 2. Windows Path
    TEST_ASSERT(strcmp(get_basename("C:\\Users\\User\\Downloads\\doc.pdf"), "doc.pdf") == 0);
    
    // 3. Unix Path
    TEST_ASSERT(strcmp(get_basename("/home/user/img.png"), "img.png") == 0);
    
    // 4. Mixed
    TEST_ASSERT(strcmp(get_basename("C:/Projects/Src\\main.c"), "main.c") == 0);
    
    // 5. No extension
    TEST_ASSERT(strcmp(get_basename("README"), "README") == 0);
    
    printf("PASS\n");
}

void test_discovery() {
    print_test_header("Peer Discovery");

    memset(&ctx, 0, sizeof(ctx));
    state_init(&ctx);
    ctx.config_listen_port = 9000;
    
    // 1. Tick should queue ADVERT
    state_event_t evt_tick = {0};
    evt_tick.type = EVENT_TICK_100MS;
    
    state_update(&ctx, &evt_tick, 0);
    
    // Verify Outbox has ADVERT
    TEST_ASSERT(ctx.outbox_len > 0);
    packet_header_t* head = (packet_header_t*)ctx.outbox;
    TEST_ASSERT(head->magic == MAGIC_TOYS);
    TEST_ASSERT(head->type == PACKET_TYPE_ADVERT);
    TEST_ASSERT(ctx.outbox_target_ip == 0); // Broadcast
    
    // 2. Receive ADVERT
    // Construct an advert packet from "another peer"
    u8 sim_packet[1024];
    packet_header_t* rx_head = (packet_header_t*)sim_packet;
    rx_head->magic = MAGIC_TOYS;
    rx_head->type = PACKET_TYPE_ADVERT;
    rx_head->body_length = sizeof(peer_advert_t);
    
    peer_advert_t* rx_adv = (peer_advert_t*)(sim_packet + sizeof(packet_header_t));
    memset(rx_adv->public_key, 0xAA, 32); // Different key
    rx_adv->port = 9001;
    
    state_event_t evt_net = {0};
    evt_net.type = EVENT_NET_PACKET_RECEIVED;
    evt_net.packet.data = sim_packet;
    evt_net.packet.len = sizeof(packet_header_t) + sizeof(peer_advert_t);
    evt_net.packet.from_ip = 0x01020304; // 1.2.3.4
    evt_net.packet.from_port = 9001;
    
    state_update(&ctx, &evt_net, 0);
    
    // Verify Peer Added
    TEST_ASSERT(ctx.peers_count == 1);
    TEST_ASSERT(ctx.peers_known[0].ip_address == 0x01020304);
    TEST_ASSERT(ctx.peers_known[0].port == 9001);
    
    printf("PASS\n");
    fflush(stdout);
}

void test_transfer_sender() {
    print_test_header("Transfer (Sender State TCP)");
    
    memset(&ctx, 0, sizeof(ctx));
    state_init(&ctx);
    // Init Dummy Keys
    memset(ctx.my_public_key, 0x11, 32);
    memset(ctx.my_private_key, 0x22, 32);
    
    // User commands SEND
    state_event_t evt = {0};
    evt.type = EVENT_USER_COMMAND;
    strcpy(evt.cmd_send.filename, "C:\\Test\\data.bin");
    evt.cmd_send.file_size = 5000;
    evt.cmd_send.target_ip = 0x0A000001;
    
    state_update(&ctx, &evt, 0);
    
    // 1. Verify Job Created & Connecting
    int job_idx = -1;
    for(int i=0; i<JOBS_MAX; ++i) {
        if (ctx.jobs_active[i].state == JOB_STATE_CONNECTING) {
            job_idx = i;
            break;
        }
    }
    TEST_ASSERT(job_idx != -1);
    TEST_ASSERT(ctx.io_req_type == IO_TCP_CONNECT);
    TEST_ASSERT(ctx.io_peer_ip == 0x0A000001);
    
    // 2. Mock TCP Connect Success
    state_event_t ev_conn = {0};
    ev_conn.type = EVENT_TCP_CONNECTED;
    ev_conn.tcp.socket = 1234;
    ev_conn.tcp.success = true;
    
    state_update(&ctx, &ev_conn, 0);
    
    TEST_ASSERT(ctx.jobs_active[job_idx].state == JOB_STATE_HANDSHAKE);
    TEST_ASSERT(ctx.io_req_type == IO_TCP_SEND); // Should send HELLO
    TEST_ASSERT(ctx.io_req_len == sizeof(packet_header_t) + 32);
    
    // 3. Mock Recv HELLO from Peer
    packet_header_t hello = { .magic = MAGIC_TOYS, .type = PACKET_TYPE_HELLO, .body_length = 32 };
    u8 buf[sizeof(packet_header_t) + 32];
    memcpy(buf, &hello, sizeof(hello));
    memset(buf + sizeof(hello), 0x33, 32); // Peer Key
    
    state_event_t ev_data = {0};
    ev_data.type = EVENT_TCP_DATA;
    ev_data.tcp.socket = 1234;
    ev_data.tcp.data = buf;
    ev_data.tcp.len = sizeof(buf);
    
    state_update(&ctx, &ev_data, 0);
    
    // Should now send OFFER
    TEST_ASSERT(ctx.jobs_active[job_idx].state == JOB_STATE_TRANSFERRING);
    TEST_ASSERT(ctx.io_req_type == IO_TCP_SEND);
    packet_header_t* head = (packet_header_t*)ctx.io_data_ptr;
    TEST_ASSERT(head->type == PACKET_TYPE_OFFER);
    
    printf("PASS\n");
}

void test_transfer_receiver() {
    print_test_header("Transfer (Receiver State TCP)");
    
    memset(&ctx, 0, sizeof(ctx));
    state_init(&ctx);
    memset(ctx.my_public_key, 0x11, 32);
    memset(ctx.my_private_key, 0x22, 32);
    
    // 1. Mock Incoming TCP Connection
    state_event_t ev_conn = {0};
    ev_conn.type = EVENT_TCP_CONNECTED;
    ev_conn.tcp.socket = 5678;
    ev_conn.tcp.success = true;
    
    state_update(&ctx, &ev_conn, 0);
    
    int job_idx = -1;
    for(int i=0; i<JOBS_MAX; ++i) {
        if (ctx.jobs_active[i].state == JOB_STATE_HANDSHAKE) {
            job_idx = i;
            break;
        }
    }
    TEST_ASSERT(job_idx != -1);
    TEST_ASSERT(ctx.jobs_active[job_idx].tcp_socket == 5678);
    // Receiver waits for HELLO (Client speaks first)
    TEST_ASSERT(ctx.io_req_type == IO_NONE); 
    
    // 2. Mock Recv HELLO from Sender
    packet_header_t hello = { .magic = MAGIC_TOYS, .type = PACKET_TYPE_HELLO, .body_length = 32 };
    u8 buf[sizeof(packet_header_t) + 32];
    memcpy(buf, &hello, sizeof(hello));
    memset(buf + sizeof(hello), 0x44, 32); // Sender Key
    
    state_event_t ev_data = {0};
    ev_data.type = EVENT_TCP_DATA;
    ev_data.tcp.socket = 5678;
    ev_data.tcp.data = buf;
    ev_data.tcp.len = sizeof(buf);
    
    state_update(&ctx, &ev_data, 0);
    
    // Should respond with HELLO
    TEST_ASSERT(ctx.io_req_type == IO_TCP_SEND);
    packet_header_t* head = (packet_header_t*)ctx.io_data_ptr;
    TEST_ASSERT(head->type == PACKET_TYPE_HELLO);
    TEST_ASSERT(ctx.jobs_active[job_idx].state == JOB_STATE_TRANSFERRING); // Ready for OFFER
    
    // 3. Mock Recv OFFER
    msg_offer_t offer = { .file_size = 9000, .name_len = 8, .job_id = 100 };
    strcpy(offer.name, "recv.bin");
    packet_header_t opkt = { .magic = MAGIC_TOYS, .type = PACKET_TYPE_OFFER, .body_length = sizeof(offer) };
    
    u8 obuf[sizeof(packet_header_t) + sizeof(msg_offer_t)];
    memcpy(obuf, &opkt, sizeof(opkt));
    memcpy(obuf + sizeof(opkt), &offer, sizeof(offer));
    
    ev_data.tcp.data = obuf;
    ev_data.tcp.len = sizeof(obuf);
    
    state_update(&ctx, &ev_data, 0);
    
    // Should Send REQ
    TEST_ASSERT(ctx.io_req_type == IO_TCP_SEND);
    head = (packet_header_t*)ctx.io_data_ptr;
    TEST_ASSERT(head->type == PACKET_TYPE_CHUNK_REQ);
    msg_request_t* req = (msg_request_t*)(ctx.io_data_ptr + sizeof(packet_header_t));
    TEST_ASSERT(req->offset == 0);
    
    printf("PASS\n");
}

int main() {
    printf("Running SendToy Core Tests...\n");
    
    test_get_basename();
    test_discovery();
    test_transfer_sender();
    test_transfer_receiver();
    
    printf("\nALL TESTS PASSED.\n");
    return 0;
}
