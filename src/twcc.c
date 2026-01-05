#include "twcc.h"
#include <string.h>
#include "Limelight-internal.h"

#define RTCP_VERSION 2
#define RTCP_PT_RTPFB 205
#define RTCP_FMT_TWCC 15

#define TWCC_STATUS_NOT_RECEIVED 0
#define TWCC_STATUS_SMALL_DELTA  1
#define TWCC_STATUS_LARGE_DELTA  2

static inline uint32_t rtcp_header(uint8_t fmt, uint8_t pt, uint16_t len)
{
    return htonl((RTCP_VERSION << 30) | (fmt << 24) | (pt << 16) | len);
}

void twcc_init(twcc_context_t *ctx, uint32_t sender_ssrc, uint32_t media_ssrc)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->sender_ssrc = sender_ssrc;
    ctx->media_ssrc  = media_ssrc;
}

void twcc_add_packet(twcc_context_t *ctx, uint16_t seq, int64_t arrival_us)
{
    if (!ctx->initialized) {
        ctx->base_seq = seq;
        ctx->initialized = 1;
    }

    if (ctx->count >= TWCC_MAX_PACKETS)
        return;

    ctx->packets[ctx->count++] = (twcc_packet_t){
        .seq = seq,
        .arrival_us = arrival_us,
        .received = 1
    };
}

static uint16_t encode_run_length(uint8_t status, uint16_t run)
{
    return (0 << 15) | ((status & 0x3) << 13) | (run & 0x1FFF);
}

static uint16_t encode_vector(uint8_t *s, int n)
{
    uint16_t v = (1 << 15);
    for (int i = 0; i < n; i++)
        v |= (s[i] & 0x3) << (14 - i * 2);
    return v;
}

size_t twcc_build_rtcp(
    twcc_context_t *ctx,
    uint8_t *out,
    size_t out_size,
    uint8_t fb_pkt_count
    ) {
    if (ctx->count == 0 || out_size < 64)
        return 0;

    uint8_t *p = out;
    uint32_t *hdr = (uint32_t *)p;
    p += 4;

    *(uint32_t *)p = htonl(ctx->sender_ssrc); p += 4;
    *(uint32_t *)p = htonl(ctx->media_ssrc);  p += 4;

    *(uint16_t *)p = htons(ctx->base_seq); p += 2;
    *(uint16_t *)p = htons(ctx->count);    p += 2;

    int64_t ref_us = ctx->packets[0].arrival_us;
    uint32_t ref_time = (ref_us / 64000) & 0xFFFFFF;

    *p++ = (ref_time >> 16) & 0xFF;
    *p++ = (ref_time >> 8)  & 0xFF;
    *p++ = ref_time & 0xFF;
    *p++ = fb_pkt_count;

    uint8_t status[TWCC_MAX_PACKETS];
    int64_t delta_us[TWCC_MAX_PACKETS];

    for (int i = 0; i < ctx->count; i++) {
        delta_us[i] = ctx->packets[i].arrival_us - ref_us;
        int d = delta_us[i] / 250;
        status[i] = (d >= -128 && d <= 127) ?
                        TWCC_STATUS_SMALL_DELTA : TWCC_STATUS_LARGE_DELTA;
    }

    for (int i = 0; i < ctx->count; ) {
        int run = 1;
        while (i + run < ctx->count && status[i] == status[i + run] && run < 0x1FFF)
            run++;

        if (run >= 7) {
            *(uint16_t *)p = htons(encode_run_length(status[i], run));
            p += 2;
            i += run;
        } else {
            uint8_t vec[7];
            int n = 0;
            while (n < 7 && i < ctx->count)
                vec[n++] = status[i++];
            *(uint16_t *)p = htons(encode_vector(vec, n));
            p += 2;
        }
    }

    for (int i = 0; i < ctx->count; i++) {
        int d = delta_us[i] / 250;
        if (status[i] == TWCC_STATUS_SMALL_DELTA) {
            *p++ = (int8_t)d;
        } else {
            *(int16_t *)p = htons(d);
            p += 2;
        }
    }

    while ((p - out) & 3)
        *p++ = 0;

    uint16_t len_words = ((p - out) / 4) - 1;
    *hdr = rtcp_header(RTCP_FMT_TWCC, RTCP_PT_RTPFB, len_words);

    return p - out;
}

void twcc_reset(twcc_context_t *ctx)
{
    ctx->count = 0;
    ctx->initialized = 0;
}
