#include "types.h"
#include <string.h> // for memcmp, memcpy
#include <stdlib.h> // for rand
#include <stdio.h> // Debug

// ... (rest of file)

static void handle_tick(ctx_main_t* ctx) {
    if (ctx->next_advert_time == 0) {
        // Init or timer fired
        if (ctx->debug_enabled) printf("DEBUG: Tick - Queueing Advert\n");
        
        // 1. Build Advert
        peer_advert_t advert = {0};
        memcpy(advert.public_key, ctx->my_public_key, 32); 
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
        if (ctx->debug_enabled) printf("DEBUG: Packet too short: %u\n", event->packet.len);
        return; 
    }
    
    const packet_header_t* header = (const packet_header_t*)event->packet.data;
    if (header->magic != MAGIC_TOYS) {
        if (ctx->debug_enabled) printf("DEBUG: Invalid Magic: %08X\n", header->magic);
        return; 
    }

    const u8* body = event->packet.data + sizeof(packet_header_t);
    u32 body_len = event->packet.len - sizeof(packet_header_t);

    if (header->type == PACKET_TYPE_ADVERT) {
        if (ctx->debug_enabled) printf("DEBUG: Recv ADVERT from IP: %08X\n", event->packet.from_ip);
        if (body_len < sizeof(peer_advert_t)) {
             if (ctx->debug_enabled) printf("DEBUG: Advert body too short\n");
             return;
        }
        
        const peer_advert_t* advert = (const peer_advert_t*)body;

        // TigerStyle: Ignore self
        if (memcmp(advert->public_key, ctx->my_public_key, 32) == 0) {
            // if (ctx->debug_enabled) printf("DEBUG: Ignored own packet\n");
            return;
        }
        
        bool found = false;
        for (u32 i = 0; i < ctx->peers_count; ++i) {
            if (ctx->peers_known[i].ip_address == event->packet.from_ip && 
                ctx->peers_known[i].port == advert->port) { 
                
                ctx->peers_known[i].last_seen_time = 1; 
                memcpy(ctx->peers_known[i].public_key, advert->public_key, 32);
                found = true;
                // printf("DEBUG: Updated peer %d\n", i);
                break;
            }
        }
        
        if (!found && ctx->peers_count < PEERS_MAX) {
            peer_entry_t* p = &ctx->peers_known[ctx->peers_count];
            if (ctx->debug_enabled) printf("DEBUG: New Peer Discovered! IP: %u\n", event->packet.from_ip);
            p->ip_address = event->packet.from_ip; 
            p->port = advert->port;
            p->last_seen_time = 1;
            ctx->peers_count++;
        }
    } else if (header->type == PACKET_TYPE_OFFER) {
        if (body_len < sizeof(msg_offer_t)) return;
        const msg_offer_t* offer = (const msg_offer_t*)body;
        
        if (ctx->debug_enabled) printf("DEBUG: Recv OFFER File: %s Size: %llu\n", offer->name, offer->file_size);
        
        // Find free job for Receiver
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (ctx->jobs_active[i].state == JOB_STATE_FREE) {
                 transfer_job_t* job = &ctx->jobs_active[i];
                 job->state = JOB_STATE_TRANSFERRING;
                 // receiver job? we need to distinguish sender/receiver in job struct?
                 // For now, implicit: if we have file_size but bytes_transferred < size, we are working.
                 // But wait, sender also has these.
                 // Let's assume OFFER reception implies we are Sink.
                 job->file_size = offer->file_size;
                 job->file_hash[0] = (u8)offer->file_hash_low;
                 job->bytes_transferred = 0;
                 
                 // Store Filename
                 u32 fname_len = offer->name_len;
                 if (fname_len > 255) fname_len = 255;
                 memcpy(job->filename, offer->name, fname_len);
                 job->filename[fname_len] = 0;
                 
                 // Immediately Request First Chunk (Offset 0)
                 msg_request_t req = {0};
                 req.job_id = 0; // TODO: Negotiation
                 req.len = 1024; // 1KB chunks for MVP
                 req.offset = 0;
                 
                 packet_header_t req_header = {0};
                 req_header.magic = MAGIC_TOYS;
                 req_header.type = PACKET_TYPE_CHUNK_REQ;
                 req_header.body_length = sizeof(msg_request_t);
                 
                 if (sizeof(packet_header_t) + sizeof(msg_request_t) <= sizeof(ctx->outbox)) {
                    memcpy(ctx->outbox, &req_header, sizeof(packet_header_t));
                    memcpy(ctx->outbox + sizeof(packet_header_t), &req, sizeof(msg_request_t));
                    ctx->outbox_len = sizeof(packet_header_t) + sizeof(msg_request_t);
                    
                    // Respond to sender
                    ctx->io_peer_ip = event->packet.from_ip;
                    ctx->io_peer_port = event->packet.from_port; // Or configured target port?
                    // Usually respond to sender's port if UDP hole punching, but here we use fixed config port for simplicity
                    ctx->io_peer_port = ctx->config_target_port;
                 }
                 break;
             }
        }
    } else if (header->type == PACKET_TYPE_CHUNK_REQ) {
        if (body_len < sizeof(msg_request_t)) return;
        const msg_request_t* req = (const msg_request_t*)body;
        
        // Ensure we are in Sender Mode (Job ID check? For MVP just check state)
        // Find Job (Sender)
        // For MVP, simplistic: assume request is valid for the file we are sending.
        
        // TigerStyle: Validate Input
        // if (ctx->jobs_active[req->job_id].state != JOB_STATE_OFFER_SENT) return;
        
        // Signal Platform to Read & Send
        ctx->io_req_type = IO_READ_CHUNK;
        ctx->io_req_offset = req->offset;
        ctx->io_req_len = req->len;
        if (ctx->io_req_len > 1024) ctx->io_req_len = 1024; // Clamp
        
        ctx->io_peer_ip = event->packet.from_ip;
        ctx->io_peer_port = ctx->config_target_port; // Or from packet
        
        if (ctx->debug_enabled) printf("DEBUG: Recv REQ Offset %llu Len %u\n", req->offset, req->len);
        
    } else if (header->type == PACKET_TYPE_CHUNK_DATA) {
        if (body_len < sizeof(msg_data_t)) return;
        const msg_data_t* data_msg = (const msg_data_t*)body;
        
        u32 data_len = body_len - sizeof(msg_data_t);
        
        // Signal Platform to Write
        ctx->io_req_type = IO_WRITE_CHUNK;
        ctx->io_req_offset = data_msg->offset;
        ctx->io_req_len = data_len;
        ctx->io_data_ptr = (u8*)(body + sizeof(msg_data_t));
        
        if (ctx->debug_enabled) printf("DEBUG: Recv DATA Offset %llu Len %u\n", data_msg->offset, data_len);
        
        // Update Job Progress
        // Find Job (Receiver)
        // For MVP, look for first transferring job
        transfer_job_t* job = NULL;
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (ctx->jobs_active[i].state == JOB_STATE_TRANSFERRING) {
                 job = &ctx->jobs_active[i];
                 break;
             }
        }
        
        if (job) {
             job->bytes_transferred += data_len;
             
             // Request Next Chunk immediately if not done
             if (job->bytes_transferred < job->file_size) {
                 msg_request_t req = {0};
                 req.job_id = job->id;
                 req.len = 1024;
                 req.offset = data_msg->offset + data_len;
                 
                 packet_header_t req_header = {0};
                 req_header.magic = MAGIC_TOYS;
                 req_header.type = PACKET_TYPE_CHUNK_REQ;
                 req_header.body_length = sizeof(msg_request_t);
                 
                 if (sizeof(packet_header_t) + sizeof(msg_request_t) <= sizeof(ctx->outbox)) {
                    memcpy(ctx->outbox, &req_header, sizeof(packet_header_t));
                    memcpy(ctx->outbox + sizeof(packet_header_t), &req, sizeof(msg_request_t));
                    ctx->outbox_len = sizeof(packet_header_t) + sizeof(msg_request_t);
                    
                    ctx->io_peer_ip = event->packet.from_ip; 
                    ctx->io_peer_port = ctx->config_target_port;
                 }
             } else {
                 if (ctx->debug_enabled) printf("DEBUG: Transfer Complete!\n");
                 job->state = JOB_STATE_COMPLETED;
             }
        }
    } else {
        if (ctx->debug_enabled) printf("DEBUG: Unknown packet type: %u\n", header->type);
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
    ctx->debug_enabled = true;
}

// Helper to extract filename from path (handles / and \)
static const char* get_basename(const char* path) {
    const char* base = path;
    for (const char* p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            base = p + 1;
        }
    }
    return base;
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
            // Find free job
            for (int i = 0; i < JOBS_MAX; ++i) {
                if (ctx->jobs_active[i].state == JOB_STATE_FREE) {
                    transfer_job_t* job = &ctx->jobs_active[i];
                    job->state = JOB_STATE_OFFER_SENT;
                    job->id = (u32)rand(); // Simple ID for now
                    job->file_size = event->cmd_send.file_size;
                    job->file_hash[0] = (u8)event->cmd_send.file_hash_low; // Partial hash store
                    
                    // Store Filename
                    u32 fname_len = (u32)strlen(event->cmd_send.filename);
                    if (fname_len > 255) fname_len = 255;
                    memcpy(job->filename, event->cmd_send.filename, fname_len);
                    job->filename[fname_len] = 0; // Null terminate
                    
                    // Build OFFER Packet
                    msg_offer_t offer = {0};
                    offer.file_size = event->cmd_send.file_size;
                    offer.file_hash_low = event->cmd_send.file_hash_low;
                    
                    const char* base_name = get_basename(event->cmd_send.filename);
                    offer.name_len = (u32)strlen(base_name);
                    
                    if (offer.name_len > 255) offer.name_len = 255;
                    memcpy(offer.name, base_name, offer.name_len);
                    
                    packet_header_t header = {0};
                    header.magic = MAGIC_TOYS;
                    header.type = PACKET_TYPE_OFFER;
                    header.body_length = sizeof(msg_offer_t);
                    
                    if (sizeof(packet_header_t) + sizeof(msg_offer_t) <= sizeof(ctx->outbox)) {
                        memcpy(ctx->outbox, &header, sizeof(packet_header_t));
                        memcpy(ctx->outbox + sizeof(packet_header_t), &offer, sizeof(msg_offer_t));
                        ctx->outbox_len = sizeof(packet_header_t) + sizeof(msg_offer_t);
                        
                        // Set IO target for the immediate send
                        ctx->io_peer_ip = event->cmd_send.target_ip;
                        ctx->io_peer_port = ctx->config_target_port;
                    }
                    
                    if (ctx->debug_enabled) printf("DEBUG: Started Job %d (Offer Sent)\n", i);
                    changed = true;
                    break;
                }
            }
            break;
    }

    return changed;
}


