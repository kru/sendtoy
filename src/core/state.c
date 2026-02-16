#include "types.h"
#include <string.h> // for memcmp, memcpy

// Forward declarations of internal helpers (static)
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

static void handle_tick(ctx_main_t* ctx) {
    // Current time is roughly monotonically increasing tick count for now
    // In real system, we'd pass current time in event. 
    // For now, assume this is called every 100ms and use a counter or just simplified logic.
    // Ideally state_update should receive u64 timestamp_ms.
    // Let's assume the event struct has it, or we add it. 
    // Wait, the event struct doesn't have time. 
    // TigerStyle: Add timestamp to event? 
    // For MVP, since we don't have time in event, we will just assume we tick.
    // But we need to know WHEN to send.
    // Let's rely on `next_advert_time` being a counter decremented by 100ms ticks?
    // OR BETTER: Add `u64 timestamp_ms` to `state_event_t`.
    
    // Modification: We will assume the caller puts a timestamp in the event if needed, 
    // but looking at `state.h/types.h`, `state_event_t` doesn't have it.
    // Let's use a static counter in ctx for now to approximate 1 sec (10 ticks).
    
    if (ctx->next_advert_time == 0) {
        // Init or timer fired
        
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
        // header.checksum = ...; // Todo
        
        // 3. Write to Outbox
        // TigerStyle: Bounds check
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
        return; // Too short
    }
    
    // TigerStyle: Check alignment? 
    // We assume the buffer passed in is aligned to 8 bytes at least.
    
    // Validate Magic
    const packet_header_t* header = (const packet_header_t*)event->packet.data;
    if (header->magic != MAGIC_TOYS) {
        return; 
    }

    const u8* body = event->packet.data + sizeof(packet_header_t);
    u32 body_len = event->packet.len - sizeof(packet_header_t);

    if (header->type == PACKET_TYPE_ADVERT) {
        if (body_len < sizeof(peer_advert_t)) return;
        
        const peer_advert_t* advert = (const peer_advert_t*)body;
        
        // Update Peer List
        bool found = false;
        for (u32 i = 0; i < ctx->peers_count; ++i) {
            if (ctx->peers_known[i].ip_address == event->packet.from_ip && // Use source IP from packet event, NO trust payload IP
                ctx->peers_known[i].port == advert->port) { // Trust payload port? Or source port? 
                                                            // Usually discovery payload contains listening TCP port, which might differ from UDP source port.
                                                            // So we use advert->port for TCP connection.
                
                // Update
                // printf("Upd peer\n");
                ctx->peers_known[i].last_seen_time = 1; // Todo: timestamp
                found = true;
                break;
            }
        }
        
        if (!found && ctx->peers_count < PEERS_MAX) {
            peer_entry_t* p = &ctx->peers_known[ctx->peers_count];
            // printf("New peer: %08X\n", event->packet.from_ip);
            p->ip_address = event->packet.from_ip; // Store network order
            p->port = advert->port;
            // memcpy(p->public_key, advert->public_key, 32);
            p->last_seen_time = 1;
            ctx->peers_count++;
        }
    }
}

// Forward declare if used before definition
static void handle_tick(ctx_main_t* ctx);
