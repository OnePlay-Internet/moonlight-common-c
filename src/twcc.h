#pragma once
#include <stdint.h>
#include <stddef.h>
#include "PlatformThreads.h"
#include "glib/GQueue.h"

typedef struct ListNode ListNode;

typedef struct {
    uint16_t seq;
    int64_t  arrival_us;
    int      received;
} twcc_packet_t;

typedef struct {
    uint32_t transport_wide_cc_cycles;
    uint32_t transport_wide_cc_last_seq_num;

    ListNode *transport_wide_received_seq_nums;

    uint32_t transport_wide_cc_feedback_count;
    uint32_t transport_wide_cc_last_feedback_seq_num;

    PLT_MUTEX mutex;

    /*Stats*/
    uint32_t video_Bps; //Video Bytes Per Second
    uint32_t audio_Bps; //Video Bytes Per Second
} twcc_context_t;

void twcc_init(
    twcc_context_t *ctx,
    uint32_t sender_ssrc,
    uint32_t media_ssrc
    );

void twcc_destry(twcc_context_t* ctx);

void twcc_add_packet(
    twcc_context_t *ctx,
    uint16_t transport_seq,
    uint64_t arrival_time_us
    );

int twcc_build_rtcp(
    twcc_context_t *ctx,
    Queue* packets,
    uint32_t packets_len,
    char* rtcpbuf,
    size_t size
    );

Queue* twcc_create_packets_queue(twcc_context_t *ctx);
