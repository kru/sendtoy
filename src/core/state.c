#include "types.h"
#include <string.h> // for memcmp, memcpy
#include <stdio.h> // Debug

// ... (rest of file)

static void handle_tick(ctx_main_t* ctx) {
    if (ctx->next_advert_time == 0) {
        // Init or timer fired
        printf("DEBUG: Tick - Queueing Advert\n");
        
        // 1. Build Advert
        peer_advert_t advert = {0};
        // memcpy(advert.public_key, ctx->my_public_key, 32); // TODO: Init keys
        advert.ip_address = 0; // Filled by platform if 0
        advert.port = ctx->config_listen_port;
        
        // 2. Build Packet
        packet_header_t header = {0};
        header.magic = MAGIC_TOYS;
        header.type = PACKET_TYPE_ADVERT;
        header.body_length = sizeof(peer_advert_t);
        
        if (sizeof(packet_header_t) + sizeof(peer_advert_t) <= sizeof(ctx->outbox)) {
            memcpy(ctx->outbox, &header, sizeof(packet_header_t));
            memcpy(ctx->outbox + sizeof(packet_header_t), &advert, sizeof(peer_advert_t));
            ctx->outbox_len = sizeof(packet_header_t) + sizeof(peer_advert_t);
        }
        
        ctx->next_advert_time = 10; // 10 ticks = 1 second
    } else {
        ctx->next_advert_time--;
    }
}

static void handle_packet(ctx_main_t* ctx, const state_event_t* event) {
    if (event->packet.len < sizeof(packet_header_t)) {
        printf("DEBUG: Packet too short: %u\n", event->packet.len);
        return; 
    }
    
    const packet_header_t* header = (const packet_header_t*)event->packet.data;
    if (header->magic != MAGIC_TOYS) {
        printf("DEBUG: Invalid Magic: %08X\n", header->magic);
        return; 
    }

    const u8* body = event->packet.data + sizeof(packet_header_t);
    u32 body_len = event->packet.len - sizeof(packet_header_t);

    if (header->type == PACKET_TYPE_ADVERT) {
        // printf("DEBUG: Recv ADVERT from IP: %08X\n", event->packet.from_ip);
        if (body_len < sizeof(peer_advert_t)) {
             printf("DEBUG: Advert body too short\n");
             return;
        }
        
        const peer_advert_t* advert = (const peer_advert_t*)body;
        
        bool found = false;
        for (u32 i = 0; i < ctx->peers_count; ++i) {
            if (ctx->peers_known[i].ip_address == event->packet.from_ip && 
                ctx->peers_known[i].port == advert->port) { 
                
                ctx->peers_known[i].last_seen_time = 1; 
                found = true;
                printf("DEBUG: Updated peer %d\n", i);
                break;
            }
        }
        
        if (!found && ctx->peers_count < PEERS_MAX) {
            peer_entry_t* p = &ctx->peers_known[ctx->peers_count];
            printf("DEBUG: New Peer Discovered! IP: %u\n", event->packet.from_ip);
            p->ip_address = event->packet.from_ip; 
            p->port = advert->port;
            p->last_seen_time = 1;
            ctx->peers_count++;
        }
    } else {
        printf("DEBUG: Unknown packet type: %u\n", header->type);
    }
}
static void handle_tick(ctx_main_t* ctx);
static void handle_packet(ctx_main_t* ctx, const state_event_t* event);
static void handle_advert(ctx_main_t* ctx, const peer_advert_t* advert);

void state_init(ctx_main_t* ctx) {
    // Zero out the entire context for safety
    // In a real scenario, we might use a secure zero function
    for (u32 i = 0; i < sizeof(ctx_main_t); ++i) {
        ((u8*)ctx)[i] = 0;
    }
    
    // Initialize defaults if any (e.g., random keys generation should happen here or be passed in)
}

bool state_update(ctx_main_t* ctx, const state_event_t* event) {
    bool changed = false;

    switch (event->type) {
        case EVENT_INIT:
            state_init(ctx);
            changed = true;
            break;
            
        case EVENT_TICK_100MS:
            handle_tick(ctx);
            changed = true; // Assume tick always potentially changes time-based state
            break;
            
        case EVENT_NET_PACKET_RECEIVED:
            handle_packet(ctx, event);
            changed = true;
            break;
            
        case EVENT_USER_COMMAND:
            // TODO: Handle user commands
            break;
    }

    return changed;
}


