#pragma once
#include <stdint.h>
#include <stddef.h>

#define TWCC_MAX_PACKETS 2048

typedef struct {
    uint16_t seq;
    int64_t  arrival_us;
    int      received;
} twcc_packet_t;

typedef struct {
    uint32_t sender_ssrc;
    uint32_t media_ssrc;

    twcc_packet_t packets[TWCC_MAX_PACKETS];
    uint16_t base_seq;
    uint16_t count;

    int initialized;
} twcc_context_t;

void twcc_init(
    twcc_context_t *ctx,
    uint32_t sender_ssrc,
    uint32_t media_ssrc
    );

void twcc_add_packet(
    twcc_context_t *ctx,
    uint16_t transport_seq,
    int64_t arrival_time_us
    );

size_t twcc_build_rtcp(
    twcc_context_t *ctx,
    uint8_t *out,
    size_t out_size,
    uint8_t fb_pkt_count
    );

void twcc_reset(twcc_context_t *ctx);
