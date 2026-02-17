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
    
    state_update(&ctx, &evt_tick);
    
    // Verify Outbox has ADVERT
    TEST_ASSERT(ctx.outbox_len > 0);
    packet_header_t* head = (packet_header_t*)ctx.outbox;
    TEST_ASSERT(head->magic == MAGIC_TOYS);
    TEST_ASSERT(head->type == PACKET_TYPE_ADVERT);
    
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
    
    state_update(&ctx, &evt_net);
    
    // Verify Peer Added
    TEST_ASSERT(ctx.peers_count == 1);
    TEST_ASSERT(ctx.peers_known[0].ip_address == 0x01020304);
    TEST_ASSERT(ctx.peers_known[0].port == 9001);
    
    printf("PASS\n");
    fflush(stdout);
}

void test_transfer_sender() {
    print_test_header("Transfer (Sender State)");
    
    memset(&ctx, 0, sizeof(ctx));
    state_init(&ctx);
    
    // User commands SEND
    state_event_t evt = {0};
    evt.type = EVENT_USER_COMMAND;
    strcpy(evt.cmd_send.filename, "C:\\Test\\data.bin");
    evt.cmd_send.file_size = 5000; // 5KB
    evt.cmd_send.target_ip = 0x0A000001;
    
    state_update(&ctx, &evt);
    
    // 1. Verify Job Created
    int job_idx = -1;
    for(int i=0; i<JOBS_MAX; ++i) {
        if (ctx.jobs_active[i].state == JOB_STATE_OFFER_SENT) {
            job_idx = i;
            break;
        }
    }
    TEST_ASSERT(job_idx != -1);
    TEST_ASSERT(strcmp(ctx.jobs_active[job_idx].filename, "C:\\Test\\data.bin") == 0); // Sender keeps full path
    
    // 2. Verify OFFER Packet (Basename only)
    TEST_ASSERT(ctx.outbox_len > 0);
    packet_header_t* head = (packet_header_t*)ctx.outbox;
    TEST_ASSERT(head->type == PACKET_TYPE_OFFER);
    
    msg_offer_t* offer = (msg_offer_t*)(ctx.outbox + sizeof(packet_header_t));
    printf("DEBUG Check: Offer Name '%s' JobID %u\n", offer->name, offer->job_id);
    fflush(stdout);
    TEST_ASSERT(strcmp(offer->name, "data.bin") == 0);
    TEST_ASSERT(offer->job_id == ctx.jobs_active[job_idx].id);
    
    printf("PASS\n");
    fflush(stdout);
}

void test_transfer_receiver() {
    print_test_header("Transfer (Receiver State)");
    
    memset(&ctx, 0, sizeof(ctx));
    state_init(&ctx);
    
    // Simulate Receiving OFFER
    u8 sim_packet[1024];
    packet_header_t* head = (packet_header_t*)sim_packet;
    head->magic = MAGIC_TOYS;
    head->type = PACKET_TYPE_OFFER;
    head->body_length = sizeof(msg_offer_t); // Includes padding now!
    
    msg_offer_t* offer = (msg_offer_t*)(sim_packet + sizeof(packet_header_t));
    offer->file_size = 5000;
    offer->job_id = 999; // Sender's ID
    strcpy(offer->name, "recv.bin");
    offer->name_len = (u32)strlen("recv.bin");
    
    state_event_t evt = {0};
    evt.type = EVENT_NET_PACKET_RECEIVED;
    evt.packet.data = sim_packet;
    evt.packet.len = sizeof(packet_header_t) + sizeof(msg_offer_t);
    evt.packet.from_ip = 0x0B000002;
    
    state_update(&ctx, &evt);
    
    // 1. Verify Job Created
    int job_idx = -1;
    for(int i=0; i<JOBS_MAX; ++i) {
        if (ctx.jobs_active[i].state == JOB_STATE_TRANSFERRING) {
            job_idx = i;
            break;
        }
    }
    TEST_ASSERT(job_idx != -1);
    TEST_ASSERT(strcmp(ctx.jobs_active[job_idx].filename, "recv.bin") == 0);
    TEST_ASSERT(ctx.jobs_active[job_idx].peer_job_id == 999); // Vital check!
    
    // 2. Verify CHUNK_REQ Sent with correct ID
    TEST_ASSERT(ctx.outbox_len > 0);
    packet_header_t* out_head = (packet_header_t*)ctx.outbox;
    TEST_ASSERT(out_head->type == PACKET_TYPE_CHUNK_REQ);
    
    msg_request_t* req = (msg_request_t*)(ctx.outbox + sizeof(packet_header_t));
    TEST_ASSERT(req->job_id == 999);
    TEST_ASSERT(req->offset == 0);
    
    printf("PASS\n");
    fflush(stdout);
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
