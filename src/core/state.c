#include "types.h"
#include <string.h> // for memcmp, memcpy
#include <stdlib.h> // for rand
#include <stdio.h> // Debug

// ... (rest of file)

static void handle_tick(ctx_main_t* ctx, u64 now) {
    // 3. Reliability Check (Retransmission)
    // Iterate active jobs (Receivers)
    // We using a simple tick counter for time (1 tick = 100ms)
    // Let's increment a global tick counter in context if we had one, 
    // or just rely on 'now' passed in. 
    // For now, let's assume 'now' is a monotonic tick counter from platform.
    
    for (int i = 0; i < JOBS_MAX; ++i) {
        if (ctx->jobs_active[i].state == JOB_STATE_TRANSFERRING) {
             transfer_job_t* job = &ctx->jobs_active[i];
             
             // Check if stalled
             if (job->bytes_transferred < job->requested_offset) {
                 if (now - job->last_activity_time > 5) { // 0.5 second timeout (assuming 100ms ticks)
                     if (ctx->debug_enabled) printf("DEBUG: Job %d Stalled. Re-requesting offset %llu\n", i, job->bytes_transferred);
                     
                     msg_request_t req = {0};
                     req.job_id = job->peer_job_id;
                     
                     u64 remaining = job->file_size - job->bytes_transferred;
                     u64 req_len = FILE_CHUNK_SIZE; 
                     if (req_len > remaining) req_len = remaining;
                     
                     // We re-request from current position up to window size (or less)
                     // Actually, if we just re-send the original request for the block:
                     // The clamp in 'handle_packet' will handle it.
                     // But we should request 'bytes_transferred' (the missing piece).
                     
                     req.offset = job->bytes_transferred;
                     
                     // Calculate length up to the NEXT block boundary or requested_offset
                     // For simplicity, just request 'req_len' (1MB) from current position.
                     // This might overlap or extend the window, which is fine.
                     req.len = (u32)req_len; 
                     
                     job->requested_offset = req.offset + req_len; // Extend window if needed
                     job->last_activity_time = now;
                     
                     packet_header_t req_header = {0};
                     req_header.magic = MAGIC_TOYS;
                     req_header.type = PACKET_TYPE_CHUNK_REQ;
                     req_header.body_length = sizeof(msg_request_t);
                     
                     if (sizeof(packet_header_t) + sizeof(msg_request_t) <= sizeof(ctx->outbox)) {
                        memcpy(ctx->outbox, &req_header, sizeof(packet_header_t));
                        memcpy(ctx->outbox + sizeof(packet_header_t), &req, sizeof(msg_request_t));
                        ctx->outbox_len = sizeof(packet_header_t) + sizeof(msg_request_t);
                        
                        // Set Target
                        ctx->outbox_target_ip = job->peer_ip;
                        ctx->outbox_target_port = ctx->config_target_port;
                     }
                 }
             }
        }
    }

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
            ctx->outbox_target_ip = 0; // Broadcast
            ctx->outbox_target_port = ctx->config_listen_port; // Adverts go to listen port usually? Or 9000?
            // Adverts are usually broadcast to local subnet on 'config_listen_port' or specific discovery port?
            // Existing logic relies on platform to broadcast.
        }
        
        ctx->next_advert_time = 10; // 1 second
    } else {
        ctx->next_advert_time--;
    }
}

static void handle_packet(ctx_main_t* ctx, const state_event_t* event, u64 now) {
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
        
        // Check if this is a reflection of our own Offer
        bool is_reflection = false;
        for (int i = 0; i < JOBS_MAX; ++i) {
            if (ctx->jobs_active[i].state == JOB_STATE_OFFER_SENT && 
                ctx->jobs_active[i].id == offer->job_id) {
                is_reflection = true;
                break;
            }
        }
        
        if (is_reflection) {
             if (ctx->debug_enabled) printf("DEBUG: Ignored own OFFER reflection\n");
             return;
        }

        // Find free job for Receiver
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (ctx->jobs_active[i].state == JOB_STATE_FREE) {
                  transfer_job_t* job = &ctx->jobs_active[i];
                  job->state = JOB_STATE_TRANSFERRING;
                  // receiver job? we need to distinguish sender/receiver in job struct?
                  // For now, implicit: if we have file_size but bytes_transferred < size, we are working.
                  // Let's assume OFFER reception implies we are Sink.
                  job->file_size = offer->file_size;
                  job->file_hash[0] = (u8)offer->file_hash_low;
                  job->bytes_transferred = 0;
                  job->peer_job_id = offer->job_id;
                  job->peer_ip = event->packet.from_ip; // Store IP
                  
                  // Store Filename
                  u32 fname_len = offer->name_len;
                  if (fname_len > 255) fname_len = 255;
                  memcpy(job->filename, offer->name, fname_len);
                  job->filename[fname_len] = 0;
                  
                  // Request First Chunk (Batched)
                  msg_request_t req = {0};
                  req.job_id = job->peer_job_id;
                  
                  u64 req_len = FILE_CHUNK_SIZE;
                  if (req_len > job->file_size) req_len = job->file_size;
                  req.len = (u32)req_len;
                  req.offset = 0;
                  
                  job->requested_offset = req_len;
                  job->last_activity_time = 0; // Reset
                  
                  packet_header_t req_header = {0};
                  req_header.magic = MAGIC_TOYS;
                  req_header.type = PACKET_TYPE_CHUNK_REQ;
                  req_header.body_length = sizeof(msg_request_t);
                  
                  if (sizeof(packet_header_t) + sizeof(msg_request_t) <= sizeof(ctx->outbox)) {
                     memcpy(ctx->outbox, &req_header, sizeof(packet_header_t));
                     memcpy(ctx->outbox + sizeof(packet_header_t), &req, sizeof(msg_request_t));
                     ctx->outbox_len = sizeof(packet_header_t) + sizeof(msg_request_t);
                     
                     // Respond to sender
                     ctx->outbox_target_ip = event->packet.from_ip;
                     ctx->outbox_target_port = ctx->config_target_port;
                  }
                  break;
              }
         }
    } else if (header->type == PACKET_TYPE_CHUNK_REQ) {
        if (body_len < sizeof(msg_request_t)) return;
        const msg_request_t* req = (const msg_request_t*)body;
        
        // Ensure we are in Sender Mode
        // Lookup job by ID from request
        transfer_job_t* job = NULL;
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (ctx->jobs_active[i].state == JOB_STATE_OFFER_SENT && 
                 ctx->jobs_active[i].id == req->job_id) {
                 job = &ctx->jobs_active[i];
                 break;
             }
        }
        
        if (!job) {
             if (ctx->debug_enabled) printf("DEBUG: Ignored REQ for unknown Job ID %u\n", req->job_id);
             return;
        }

        // Signal Platform to Read & Send
        ctx->io_req_type = IO_READ_CHUNK;
        ctx->io_req_job_id = job->id;
        ctx->io_req_offset = req->offset;
        ctx->io_req_len = req->len;
        if (ctx->io_req_len > FILE_CHUNK_SIZE) ctx->io_req_len = FILE_CHUNK_SIZE; // Clamp to 1MB
        
        ctx->io_peer_ip = event->packet.from_ip;
        ctx->io_peer_port = ctx->config_target_port; // Or from packet
        
        if (ctx->debug_enabled) printf("DEBUG: Recv REQ Offset %llu Len %u Job %u\n", req->offset, req->len, req->job_id);
        
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
             // Reliability: Enforce Ordering
             // If we receive data out of order (offset != bytes_transferred), drop it.
             // This forces a re-request of the missing piece and ensures we don't have gaps.
             if (data_msg->offset != job->bytes_transferred) {
                 // if (ctx->debug_enabled) printf("DEBUG: Drop OoO Data. Want %llu Got %llu\n", job->bytes_transferred, data_msg->offset);
                 return;
             }

             job->bytes_transferred += data_len;
             job->last_activity_time = now;
             
             // Request Next Chunk ONLY if we completed the current window
             // Or if we are done
             
             if (job->bytes_transferred < job->file_size) {
                 if (job->bytes_transferred >= job->requested_offset) {
                     // Window finished, request next batch
                     msg_request_t req = {0};
                     req.job_id = job->peer_job_id;
                     
                     u64 remaining = job->file_size - job->bytes_transferred;
                     u64 req_len = FILE_CHUNK_SIZE;
                     if (req_len > remaining) req_len = remaining;
                     
                     req.len = (u32)req_len;
                     req.offset = job->bytes_transferred;
                     
                     job->requested_offset = job->bytes_transferred + req_len;
                     
                     packet_header_t req_header = {0};
                     req_header.magic = MAGIC_TOYS;
                     req_header.type = PACKET_TYPE_CHUNK_REQ;
                     req_header.body_length = sizeof(msg_request_t);
                     
                     if (sizeof(packet_header_t) + sizeof(msg_request_t) <= sizeof(ctx->outbox)) {
                        memcpy(ctx->outbox, &req_header, sizeof(packet_header_t));
                        memcpy(ctx->outbox + sizeof(packet_header_t), &req, sizeof(msg_request_t));
                        ctx->outbox_len = sizeof(packet_header_t) + sizeof(msg_request_t);
                        
                        ctx->outbox_target_ip = event->packet.from_ip; 
                        ctx->outbox_target_port = ctx->config_target_port;
                     }
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
static void handle_tick(ctx_main_t* ctx, u64 now);
static void handle_packet(ctx_main_t* ctx, const state_event_t* event, u64 now);
static void handle_advert(ctx_main_t* ctx, const peer_advert_t* advert);
static const char* get_basename(const char* path);

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
// --- TCP Handlers ---

static void handle_tcp_connected(ctx_main_t* ctx, u64 socket, bool success) {
    transfer_job_t* job = NULL;
    // Find Sender Job (Connecting)
    for (int i = 0; i < JOBS_MAX; ++i) {
        if (ctx->jobs_active[i].state == JOB_STATE_CONNECTING) {
            job = &ctx->jobs_active[i];
            break;
        }
    }
    
    if (!success) {
        if (job) {
             job->state = JOB_STATE_FAILED;
             if (ctx->debug_enabled) printf("DEBUG: TCP Connect Failed for Job %d\n", job->id);
        }
        return;
    }
    
    if (job) {
        // Outgoing Connection Established (Sender)
        job->state = JOB_STATE_HANDSHAKE;
        job->tcp_socket = socket;
        if (ctx->debug_enabled) printf("DEBUG: TCP Connected (Sender). Sending HELLO.\n");
        
        // Send HELLO (Handshake)
        packet_header_t head = {
            .magic = MAGIC_TOYS,
            .type = PACKET_TYPE_HELLO,
            .body_length = 32, // Public Key
            .checksum = 0 // TODO
        };
        
        memcpy(ctx->work_buffer, &head, sizeof(head));
        memcpy(ctx->work_buffer + sizeof(head), ctx->my_public_key, 32);
        
        ctx->io_req_type = IO_TCP_SEND;
        ctx->io_req_job_id = job->id;
        ctx->io_req_len = sizeof(head) + 32;
        ctx->io_data_ptr = ctx->work_buffer;
    } else {
        // Incoming Connection (Receiver)
        // Create new Job
        for (int i = 0; i < JOBS_MAX; ++i) {
             if (ctx->jobs_active[i].state == JOB_STATE_FREE) {
                 job = &ctx->jobs_active[i];
                 memset(job, 0, sizeof(transfer_job_t));
                 job->id = (u32)(i + 1 + (ctx->next_advert_time & 0xFFFF)); // Random-ish ID
                 job->state = JOB_STATE_HANDSHAKE;
                 job->tcp_socket = socket;
                 job->start_time = ctx->next_advert_time; // Approx
                 if (ctx->debug_enabled) printf("DEBUG: TCP Inbound (Receiver) Job %d\n", job->id);
                 break;
             }
        }
        
        if (!job) {
            if (ctx->debug_enabled) printf("DEBUG: No free jobs for incoming TCP\n");
            // IO_TCP_CLOSE (Not Implemented yet in this snippet, but platform should close if we return nothing?)
            // We should explicit close.
            // ctx->io_req_type = IO_TCP_CLOSE;
            return;
        }
    }
}

static void handle_tcp_closed(ctx_main_t* ctx, u64 socket) {
     for (int i = 0; i < JOBS_MAX; ++i) {
        if (ctx->jobs_active[i].tcp_socket == socket && ctx->jobs_active[i].state != JOB_STATE_FREE) {
            if (ctx->debug_enabled) printf("DEBUG: TCP Closed for Job %d\n", ctx->jobs_active[i].id);
            ctx->jobs_active[i].state = JOB_STATE_FAILED;
            ctx->jobs_active[i].tcp_socket = 0;
        }
    }
}

static void handle_tcp_data(ctx_main_t* ctx, u64 socket, u8* data, u32 len) {
    transfer_job_t* job = NULL;
    for (int i = 0; i < JOBS_MAX; ++i) {
        if (ctx->jobs_active[i].tcp_socket == socket) {
            job = &ctx->jobs_active[i];
            break;
        }
    }
    
    if (!job) return;
    
    if (job->state == JOB_STATE_HANDSHAKE) {
        if (len < sizeof(packet_header_t) + 32) return;
        
        packet_header_t* head = (packet_header_t*)data;
        if (head->magic != MAGIC_TOYS || head->type != PACKET_TYPE_HELLO) {
             if (ctx->debug_enabled) printf("DEBUG: Invalid Handshake\n");
             return;
        }
        
        u8* peer_pub = data + sizeof(packet_header_t);
        memcpy(job->peer_key, peer_pub, 32);
        
        // Derive Shared Secret (Static-Static or Static-Eph depending on impl)
        // Using MyPrivate + PeerPublic (from handshake)
        crypto_shared_secret(job->shared_key, ctx->my_private_key, peer_pub);
        if (ctx->debug_enabled) printf("DEBUG: Handshake Complete.\n");
        
        if (job->peer_ip == 0) {
             // Receiver: Respond with HELLO
             packet_header_t resp = {
                .magic = MAGIC_TOYS,
                .type = PACKET_TYPE_HELLO,
                .body_length = 32
             };
             memcpy(ctx->work_buffer, &resp, sizeof(resp));
             memcpy(ctx->work_buffer + sizeof(resp), ctx->my_public_key, 32);
             
             ctx->io_req_type = IO_TCP_SEND;
             ctx->io_req_job_id = job->id;
             ctx->io_req_len = sizeof(resp) + 32;
             ctx->io_data_ptr = ctx->work_buffer;
             
             job->state = JOB_STATE_TRANSFERRING; // Ready for OFFER
        } else {
             // Sender: Send OFFER
             msg_offer_t offer = {0};
             offer.file_size = job->file_size;
             offer.job_id = job->id;
             const char* base_name = get_basename(job->filename);
             u32 name_len = (u32)strlen(base_name);
             if (name_len > 255) name_len = 255;
             memcpy(offer.name, base_name, name_len);
             offer.name_len = name_len;
             
             packet_header_t opkt = {
                 .magic = MAGIC_TOYS,
                 .type = PACKET_TYPE_OFFER,
                 .body_length = sizeof(msg_offer_t)
             };
             
             memcpy(ctx->work_buffer, &opkt, sizeof(opkt));
             memcpy(ctx->work_buffer + sizeof(opkt), &offer, sizeof(offer));
             
             ctx->io_req_type = IO_TCP_SEND;
             ctx->io_req_job_id = job->id;
             ctx->io_req_len = sizeof(opkt) + sizeof(offer);
             ctx->io_data_ptr = ctx->work_buffer;
             
             job->state = JOB_STATE_TRANSFERRING;
        }
    } else if (job->state == JOB_STATE_TRANSFERRING) {
        packet_header_t* head = (packet_header_t*)data;
        if (head->magic != MAGIC_TOYS) return;
        
        if (head->type == PACKET_TYPE_OFFER) {
             msg_offer_t* offer = (msg_offer_t*)(data + sizeof(packet_header_t));
             if (ctx->debug_enabled) printf("DEBUG: Recv OFFER (TCP) '%s' size %llu\n", offer->name, offer->file_size);
             
             job->file_size = offer->file_size;
             job->peer_job_id = offer->job_id;
             memcpy(job->filename, offer->name, offer->name_len);
             job->filename[offer->name_len] = 0;
             
             // Send REQ (Offset 0, Len Max to start stream)
             msg_request_t req = { .job_id = offer->job_id, .offset = 0, .len = 0xFFFFFFFF };
             packet_header_t rpkt = { .magic = MAGIC_TOYS, .type = PACKET_TYPE_CHUNK_REQ, .body_length = sizeof(req) };
             
             memcpy(ctx->work_buffer, &rpkt, sizeof(rpkt));
             memcpy(ctx->work_buffer + sizeof(rpkt), &req, sizeof(req));
             
             ctx->io_req_type = IO_TCP_SEND;
             ctx->io_req_job_id = job->id;
             ctx->io_req_len = sizeof(rpkt) + sizeof(req);
             ctx->io_data_ptr = ctx->work_buffer;
             
        } else if (head->type == PACKET_TYPE_CHUNK_REQ) {
             msg_request_t* req = (msg_request_t*)(data + sizeof(packet_header_t));
             if (ctx->debug_enabled) printf("DEBUG: Recv REQ (TCP) Offset %llu\n", req->offset);
             
             // Start Stream (Read first chunk)
             // We reuse IO_READ_CHUNK, but Platform needs to know to Send via TCP.
             // We can check job->tcp_socket in Platform.
             ctx->io_req_type = IO_READ_CHUNK;
             ctx->io_req_job_id = job->id;
             ctx->io_req_offset = req->offset;
             ctx->io_req_len = FILE_CHUNK_SIZE;
             
             if (ctx->io_req_len > job->file_size - req->offset) {
                 ctx->io_req_len = (u32)(job->file_size - req->offset);
             }
        } else if (head->type == PACKET_TYPE_CHUNK_DATA) {
             // Receiver got Data
             // Write to disk
             // ... This requires implementation. UDP used IO_WRITE_CHUNK.
             // TCP data comes in `data` buffer.
             // But Wait! `handle_tcp_data` gets `data` buffer.
             // We can just trigger `IO_WRITE_CHUNK` with this pointer.
             
             // Problem: `data` contains Header + Body.
             // We need to point to Body.
             // Also we need `msg_data_t`?
             // Actually, for TCP Stream, do we need `msg_data_t` (Offset)? 
             // Yes, for validation/seek?
             // Or can we stream raw bytes?
             // "Zero-Copy Data Path... 2. Hash... 3. Write".
             // If we send `PACKET_TYPE_CHUNK_DATA` wrapping the chunk:
             // [Header][msg_data_t][Raw Bytes...]
             
             // So:
             if (len < sizeof(packet_header_t) + sizeof(msg_data_t)) return;
             msg_data_t* data_msg = (msg_data_t*)(data + sizeof(packet_header_t));
             u8* raw_bytes = data + sizeof(packet_header_t) + sizeof(msg_data_t);
             u32 raw_len = len - (sizeof(packet_header_t) + sizeof(msg_data_t));
             
             ctx->io_req_type = IO_WRITE_CHUNK;
             ctx->io_req_offset = data_msg->offset;
             ctx->io_req_len = raw_len;
             ctx->io_data_ptr = raw_bytes;
             
             job->bytes_transferred += raw_len;
             
             if (ctx->debug_enabled) printf("DEBUG: Recv TCP Data %u bytes. Total %llu\n", raw_len, job->bytes_transferred);
        }
    }
}

static const char* get_basename(const char* path) {
    const char* base = path;
    for (const char* p = path; *p; p++) {
        if (*p == '/' || *p == '\\') {
            base = p + 1;
        }
    }
    return base;
}

bool state_update(ctx_main_t* ctx, const state_event_t* event, u64 now) {
    bool changed = false;

    switch (event->type) {
        case EVENT_INIT:
            state_init(ctx);
            changed = true;
            break;
            
        case EVENT_TICK_100MS:
            handle_tick(ctx, now);
            changed = true; // Assume tick always potentially changes time-based state
            break;
            
        case EVENT_NET_PACKET_RECEIVED:
            handle_packet(ctx, event, now);
            changed = true;
            break;
            changed = true;
            break;
            
        case EVENT_TCP_CONNECTED:
            handle_tcp_connected(ctx, event->tcp.socket, event->tcp.success);
            changed = true;
            break;
            
        case EVENT_TCP_DATA:
            handle_tcp_data(ctx, event->tcp.socket, event->tcp.data, event->tcp.len);
            changed = true;
            break;
            
        case EVENT_TCP_CLOSED:
            handle_tcp_closed(ctx, event->tcp.socket);
            changed = true;
            break;

        case EVENT_USER_COMMAND:
            // Find free job for Sender
            for (int i = 0; i < JOBS_MAX; ++i) {
                if (ctx->jobs_active[i].state == JOB_STATE_FREE) {
                    transfer_job_t* job = &ctx->jobs_active[i];
                    memset(job, 0, sizeof(transfer_job_t));
                    job->state = JOB_STATE_CONNECTING;
                    job->id = (u32)rand();
                    job->file_size = event->cmd_send.file_size;
                    
                    u32 fname_len = (u32)strlen(event->cmd_send.filename);
                    if (fname_len > 255) fname_len = 255;
                    memcpy(job->filename, event->cmd_send.filename, fname_len);
                    job->filename[fname_len] = 0;
                    job->peer_ip = event->cmd_send.target_ip;
                    
                    // Trigger TCP Connect
                    ctx->io_req_type = IO_TCP_CONNECT;
                    ctx->io_peer_ip = job->peer_ip;
                    ctx->io_peer_port = ctx->config_target_port;
                    ctx->io_req_job_id = job->id;
                    
                    if (ctx->debug_enabled) printf("DEBUG: Job %d Connecting to %u...\n", job->id, job->peer_ip);
                    changed = true;
                    break;
                }
            }
            break;
    }

    return changed;
}
