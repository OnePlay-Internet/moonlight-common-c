#include "twcc.h"
#include <string.h>
#include "Limelight-internal.h"

#include "glib/gtypes.h"
#include "glib/GSList.h"
#include "glib/GQueue.h"

/* Bit manipulation (mostly for TWCC) */
inline guint32 oneplay_push_bits(guint32 word, size_t num, guint32 val) {
    if(num == 0)
        return word;
    return (word << num) | (val & (0xFFFFFFFF>>(32-num)));
}

inline void oneplay_set1(guint8 *data,size_t i,guint8 val) {
    data[i] = val;
}

inline void oneplay_set2(guint8 *data,size_t i,guint32 val) {
    data[i+1] = (guint8)(val);
    data[i]   = (guint8)(val>>8);
}

inline void oneplay_set3(guint8 *data,size_t i,guint32 val) {
    data[i+2] = (guint8)(val);
    data[i+1] = (guint8)(val>>8);
    data[i]   = (guint8)(val>>16);
}

inline void oneplay_set4(guint8 *data,size_t i,guint32 val) {
    data[i+3] = (guint8)(val);
    data[i+2] = (guint8)(val>>8);
    data[i+1] = (guint8)(val>>16);
    data[i]   = (guint8)(val>>24);
}

void twcc_destry(twcc_context_t* ctx){
    PltDeleteMutex(&ctx->mutex);
}

void twcc_init(twcc_context_t *ctx, uint32_t sender_ssrc, uint32_t media_ssrc)
{
    ctx->transport_wide_cc_cycles = 0;
    ctx->transport_wide_cc_last_seq_num = 0;
    ctx->transport_wide_cc_feedback_count = 0;
    ctx->transport_wide_cc_last_feedback_seq_num = 0;

    PltCreateMutex(&ctx->mutex);
}

/*! \brief Stores transport wide packet reception statistics */
typedef struct rtcp_transport_wide_cc_stats
{
    /*! \brief Transwport wide sequence number */
    uint32_t transport_seq_num;
    /*! \brief Reception time */
    uint64_t timestamp;
} rtcp_transport_wide_cc_stats;
typedef rtcp_transport_wide_cc_stats oneplay_rtcp_transport_wide_cc_stats;

static int twcc_stats_cmp(const void *a, const void *b) {
    const rtcp_transport_wide_cc_stats *s1 = (rtcp_transport_wide_cc_stats*)a;
    const rtcp_transport_wide_cc_stats *s2 = (rtcp_transport_wide_cc_stats*)b;

    if (s1->transport_seq_num < s2->transport_seq_num)
        return -1;
    if (s1->transport_seq_num > s2->transport_seq_num)
        return 1;
    return 0;
}

/*! \brief oneplay plugin RTCP packet */
struct oneplay_plugin_rtcp {
    /*! \brief Index of the stream (relative to the SDP)
     * @note On outgoing packets you can set this to -1, to let the oneplay
     * core find the first audio/video (depending on the \c video property)
     * to send this on; notice that this tweak is only there for convenience,
     * and to make it easier for plugins not dealing with multistream, but
     * this shouldn't be relied upon too much as it may go away soon. */
    int mindex;
    /*! \brief Whether this is an audio or video RTCP packet */
    bool video;
    /*! \brief The packet data */
    char *buffer;
    /*! \brief The packet length */
    uint16_t length;
};
/*! \brief RTCP message exchanged with the core */
typedef struct oneplay_plugin_rtcp oneplay_plugin_rtcp;

/*! \brief RTCP Header (http://tools.ietf.org/html/rfc3550#section-6.1) */
typedef struct rtcp_header
{
    // #if __BYTE_ORDER == __BIG_ENDIAN
    //     uint16_t version:2;
    //     uint16_t padding:1;
    //     uint16_t rc:5;
    //     uint16_t type:8;
    // #elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rc:5;
    uint16_t padding:1;
    uint16_t version:2;
    uint16_t type:8;
    // #endif
    uint16_t length:16;
} rtcp_header;

/*! \brief RTCP Packet Types (http://www.networksorcery.com/enp/protocol/rtcp.htm) */
typedef enum {
    RTCP_FIR = 192,
    RTCP_SR = 200,
    RTCP_RR = 201,
    RTCP_SDES = 202,
    RTCP_BYE = 203,
    RTCP_APP = 204,
    RTCP_RTPFB = 205,
    RTCP_PSFB = 206,
    RTCP_XR = 207,
} rtcp_type;
typedef rtcp_type oneplay_rtcp_type;

/*! \brief RTCP-FB (http://tools.ietf.org/html/rfc4585) */
typedef struct rtcp_fb
{
    /*! \brief Common header */
    rtcp_header header;
    /*! \brief Sender SSRC */
    uint32_t ssrc;
    /*! \brief Media source */
    uint32_t media;
    /*! \brief Feedback Control Information */
    char fci[1];
} rtcp_fb;
typedef rtcp_fb oneplay_rtcp_fb;

typedef rtcp_header oneplay_rtcp_header;

typedef enum oneplay_rtp_packet_status {
    oneplay_rtp_packet_status_notreceived = 0,
    oneplay_rtp_packet_status_smalldelta = 1,
    oneplay_rtp_packet_status_largeornegativedelta = 2,
    oneplay_rtp_packet_status_reserved = 3
} oneplay_rtp_packet_status;

int oneplay_rtcp_transport_wide_cc_feedback(char* packet, size_t size, uint32_t ssrc,
                                          uint32_t media, uint8_t feedback_packet_count, Queue* transport_wide_cc_stats) {
    if(packet == NULL || size < sizeof(oneplay_rtcp_header) || transport_wide_cc_stats == NULL || g_queue_is_empty(transport_wide_cc_stats))
        return -1;

    memset(packet, 0, size);
    oneplay_rtcp_header *rtcp = (oneplay_rtcp_header *)packet;
    /* Set header */
    rtcp->version = 2;
    rtcp->type = RTCP_RTPFB;
    rtcp->rc = 15;
    /* Now set FB stuff */
    oneplay_rtcp_fb *rtcpfb = (oneplay_rtcp_fb *)rtcp;
    rtcpfb->ssrc = htonl(ssrc);
    rtcpfb->media = htonl(media);

    /* Get first packet */
    oneplay_rtcp_transport_wide_cc_stats *stat = (oneplay_rtcp_transport_wide_cc_stats *) g_queue_pop_head (transport_wide_cc_stats);
    /* Calculate temporal info */
    uint16_t base_seq_num = stat->transport_seq_num;
    bool first_received	= FALSE;
    uint64_t reference_time = 0;
    uint32_t packet_status_count = (int)g_queue_get_length(transport_wide_cc_stats) + 1;

    /*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |      base sequence number     |      packet status count      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                 reference time                | fb pkt. count |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    /* The packet as unsigned */
    uint8_t *data = (uint8_t *)packet;
    /* The start of the feedback data */
    size_t len = sizeof(oneplay_rtcp_header) + 8;

    /* Set header data */
    oneplay_set2(data, len, base_seq_num);
    oneplay_set2(data, len+2, packet_status_count);
    /* Set3 referenceTime when first received */
    size_t reference_time_pos = len + 4;
    oneplay_set1(data, len+7, feedback_packet_count);

    /* Next byte */
    len += 8;

    /* Initial time in us */
    guint64 timestamp = 0;
    /* Store delta array */
    Queue *deltas = queue_new();
    Queue *statuses = queue_new();
    oneplay_rtp_packet_status last_status = oneplay_rtp_packet_status_reserved;
    oneplay_rtp_packet_status max_status = oneplay_rtp_packet_status_notreceived;
    bool all_same = TRUE;

    /* For each packet  */
    while (stat != NULL) {
        oneplay_rtp_packet_status status = oneplay_rtp_packet_status_notreceived;

        /* If got packet */
        if (stat->timestamp) {
            int delta = 0;
            /* If first received */
            if (!first_received) {
                /* Got it  */
                first_received = TRUE;
                /* Set it */
                reference_time = stat->timestamp / 64000;
                /* Get initial time */
                timestamp = reference_time * 64000;
                /* also in buffer */
                /* (use only 23 bits of reference_time) */
                oneplay_set3(data, reference_time_pos, (reference_time & 0x007FFFFF));
            }

            /* Get delta */
            if (stat->timestamp>timestamp)
                delta = (int)((stat->timestamp-timestamp)/250);
            else
                delta = -(int)((timestamp-stat->timestamp)/250);
            /* If it is negative or too big */
            if (delta<0 || delta> 255) {
                /* Big one */
                status = oneplay_rtp_packet_status_largeornegativedelta;
            } else {
                /* Small */
                status = oneplay_rtp_packet_status_smalldelta;
            }
            /* Store delta */
            /* Overflows are possible here */
            g_queue_push_tail(deltas, GINT_TO_POINTER(delta));
            /* Set last time */
            timestamp = stat->timestamp;
        }

        /* Check if all previoues ones were equal and this one the first different */
        if (all_same && last_status!=oneplay_rtp_packet_status_reserved && status!=last_status) {
            /* How big was the same run */
            if (g_queue_get_length(statuses)>7) {
                guint32 word = 0;
                /* Write run! */
                /*
                    0                   1
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |T| S |       Run Length        |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    T = 0
                 */
                word = oneplay_push_bits(word, 1, 0);
                word = oneplay_push_bits(word, 2, last_status);
                word = oneplay_push_bits(word, 13, (guint32)g_queue_get_length(statuses));
                /* Write word */
                oneplay_set2(data, len, word);
                len += 2;
                /* Remove all statuses */
                g_queue_clear(statuses);
                /* Reset status */
                last_status = oneplay_rtp_packet_status_reserved;
                max_status = oneplay_rtp_packet_status_notreceived;
                all_same = TRUE;
            } else {
                /* Not same */
                all_same = FALSE;
            }
        }

        /* Push back statuses, it will be handled later */
        g_queue_push_tail(statuses, GUINT_TO_POINTER(status));

        /* If it is bigger */
        if (status>max_status) {
            /* Store it */
            max_status = status;
        }
        /* Store las status */
        last_status = status;

        /* Check if we can still be enqueuing for a run */
        if (!all_same) {
            /* Check  */
            if (!all_same && max_status==oneplay_rtp_packet_status_largeornegativedelta && g_queue_get_length(statuses)>6) {
                guint32 word = 0;
                /*
                    0                   1
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |T|S|        Symbols            |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    T = 1
                    S = 1
                 */
                word = oneplay_push_bits(word, 1, 1);
                word = oneplay_push_bits(word, 1, 1);
                /* Set next 7 */
                size_t i = 0;
                for (i=0;i<7;++i) {
                    /* Get status */
                    oneplay_rtp_packet_status status = (oneplay_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
                    /* Write */
                    word = oneplay_push_bits(word, 2, (guint8)status);
                }
                /* Write word */
                oneplay_set2(data, len, word);
                len += 2;
                /* Reset */
                last_status = oneplay_rtp_packet_status_reserved;
                max_status = oneplay_rtp_packet_status_notreceived;
                all_same = TRUE;

                /* We need to restore the values, as there may be more elements on the buffer */
                for (i=0; i<g_queue_get_length(statuses); ++i) {
                    /* Get status */
                    status = (oneplay_rtp_packet_status) GPOINTER_TO_UINT(g_queue_peek_nth(statuses, i));
                    /* If it is bigger */
                    if (status>max_status) {
                        /* Store it */
                        max_status = status;
                    }
                    //Check if it is the same */
                    if (all_same && last_status!=oneplay_rtp_packet_status_reserved && status!=last_status) {
                        /* Not the same */
                        all_same = FALSE;
                    }
                    /* Store las status */
                    last_status = status;
                }
            } else if (!all_same && g_queue_get_length(statuses)>13) {
                guint32 word = 0;
                /*
                    0                   1
                    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |T|S|       symbol list         |
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    T = 1
                    S = 0
                 */
                word = oneplay_push_bits(word, 1, 1);
                word = oneplay_push_bits(word, 1, 0);
                /* Set next 7 */
                guint32 i = 0;
                for (i=0;i<14;++i) {
                    /* Get status */
                    oneplay_rtp_packet_status status = (oneplay_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
                    /* Write */
                    word = oneplay_push_bits(word, 1, (guint8)status);
                }
                /* Write word */
                oneplay_set2(data, len, word);
                len += 2;
                /* Reset */
                last_status = oneplay_rtp_packet_status_reserved;
                max_status = oneplay_rtp_packet_status_notreceived;
                all_same = TRUE;
            }
        }
        /* Free mem */
        free(stat);

        /* Get next packet stat */
        stat = (oneplay_rtcp_transport_wide_cc_stats *) g_queue_pop_head (transport_wide_cc_stats);
    }

    /* Get status len */
    size_t statuses_len = g_queue_get_length(statuses);
    /* If not finished yet */
    if (statuses_len>0) {
        /* How big was the same run */
        if (all_same) {
            guint32 word = 0;
            /* Write run! */
            word = oneplay_push_bits(word, 1, 0);
            word = oneplay_push_bits(word, 2, last_status);
            word = oneplay_push_bits(word, 13, (int)statuses_len);
            /* Write word */
            oneplay_set2(data, len, word);
            len += 2;
        } else if (max_status == oneplay_rtp_packet_status_largeornegativedelta) {
            guint32 word = 0;
            /* Write chunk */
            word = oneplay_push_bits(word, 1, 1);
            word = oneplay_push_bits(word, 1, 1);
            /* Write all the statuses */
            unsigned int i = 0;
            for (i=0;i<statuses_len;i++) {
                /* Get each status */
                oneplay_rtp_packet_status status = (oneplay_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
                /* Write */
                word = oneplay_push_bits(word, 2, (guint8)status);
            }
            /* Write pending */
            word = oneplay_push_bits(word, 14-statuses_len*2, 0);
            /* Write word */
            oneplay_set2(data , len, word);
            len += 2;
        } else {
            guint32 word = 0;
            /* Write chunk */
            word = oneplay_push_bits(word, 1, 1);
            word = oneplay_push_bits(word, 1, 0);
            /* Write all the statuses */
            unsigned int i = 0;
            for (i=0;i<statuses_len;i++) {
                /* Get each status */
                oneplay_rtp_packet_status status = (oneplay_rtp_packet_status) GPOINTER_TO_UINT(g_queue_pop_head (statuses));
                /* Write */
                word = oneplay_push_bits(word, 1, (guint8)status);
            }
            /* Write pending */
            word = oneplay_push_bits(word, 14-statuses_len, 0);
            /* Write word */
            oneplay_set2(data, len, word);
            len += 2;
        }
    }

    /* Write now the deltas */
    while (!g_queue_is_empty(deltas)) {
        /* Get next delta */
        gint delta = GPOINTER_TO_INT(g_queue_pop_head (deltas));
        /* Check size */
        if (delta<0 || delta>255) {
            short reported_delta = (short)delta;
            /* Overflow */
            if (reported_delta != delta) {
                reported_delta = delta > 0 ? SHRT_MAX : SHRT_MIN;
                printf("Delta value (%d) too large, reporting it as %d\n", delta, reported_delta);
            }
            /* 2 bytes */
            oneplay_set2(data, len, reported_delta);
            /* Inc */
            len += 2;
        } else {
            /* 1 byte */
            oneplay_set1(data, len, (guint8)delta);
            /* Inc */
            len ++;
        }
    }
    /* Clean mem */
    g_queue_free(statuses);
    g_queue_free(deltas);

    /* Add zero padding */
    while (len%4) {
        /* Add padding */
        oneplay_set1(data, len++, 0);
    }

    /* Set RTCP Len */
    rtcp->length = (uint16_t)htons(((int)len/4)-1);

    /* Done */
    return (int)len;
}

void twcc_build_rtcp(
    twcc_context_t *ctx,
    void (*callback)(char *rtcpbuf, size_t size, void* data),
    void* data
    ) {

    /* Create a transport wide feedback message */
    size_t size = 1300;
    char rtcpbuf[1300];

    //Lock Mutex cause we share transport_wide_received_seq_nums with twcc_add_packet which is called from VideoReceiveThreadProc
    PltLockMutex(&ctx->mutex);

    /* Order packet list */
    ctx->transport_wide_received_seq_nums =
        list_sort(ctx->transport_wide_received_seq_nums, twcc_stats_cmp);

    /* Create full stats queue */
    Queue* packets = queue_new();

    /* For all packets */
    ListNode *it = NULL;
    for(it = ctx->transport_wide_received_seq_nums; it; it = it->next) {
        /* Get stat */
        oneplay_rtcp_transport_wide_cc_stats *stats = it->data;
        /* Get transport seq */
        uint32_t transport_seq_num = stats->transport_seq_num;
        /* Check if it is an out of order  */
        if(transport_seq_num < ctx->transport_wide_cc_last_feedback_seq_num) {
            /* Skip, it was already reported as lost */
            free(stats);
            continue;
        }

        /* If not first */
        if(ctx->transport_wide_cc_last_feedback_seq_num) {
            /* For each lost */
            uint32_t i = 0;
            for(i = ctx->transport_wide_cc_last_feedback_seq_num+1; i<transport_seq_num; ++i) {
                /* Create new stat */
                oneplay_rtcp_transport_wide_cc_stats *missing = malloc(sizeof(oneplay_rtcp_transport_wide_cc_stats));
                /* Add missing packet */
                missing->transport_seq_num = i;
                missing->timestamp = 0;
                /* Add it */
                g_queue_push_tail(packets, missing);
            }
        }
        /* Store last */
        ctx->transport_wide_cc_last_feedback_seq_num = transport_seq_num;
        /* Add this one */
        g_queue_push_tail(packets, stats);
    }
    /* Free and reset stats list */
    list_free(ctx->transport_wide_received_seq_nums);
    ctx->transport_wide_received_seq_nums = NULL;

    //Unlock the Mutex
    PltUnlockMutex(&ctx->mutex);

    /* Create and enqueue RTCP packets */
    uint32_t packets_len = 0;

    uint16_t len;
    while((packets_len = (int)g_queue_get_length(packets)) > 0) {
        Queue *packets_to_process;
        /* If we have more than 400 packets to acknowledge, let's send more than one message */
        if(packets_len > 400) {
            QueueNode *new_head = g_queue_peek_nth(packets, 400);
            QueueNode *new_tail = new_head->prev;
            new_head->prev = NULL;
            new_tail->next = NULL;
            packets_to_process = queue_new();
            packets_to_process->head = packets->head;
            packets_to_process->tail = new_tail;
            packets_to_process->length = 400;
            packets->head = new_head;
            /* packets->tail is unchanged */
            packets->length = packets_len - 400;
        }else {
            packets_to_process = packets;
        }
        /* Get feedback packet count and increase it for next one */
        uint8_t feedback_packet_count = ctx->transport_wide_cc_feedback_count++;
        /* Create RTCP packet */
        len = oneplay_rtcp_transport_wide_cc_feedback(rtcpbuf, size,
                                                             456, 456, feedback_packet_count, packets_to_process);

        /* We send the packet using the callback */
        if(len > 0) {
            callback(rtcpbuf, len, data);
        }
        if(packets_to_process != packets) {
            g_queue_free(packets_to_process);
        }
    }
    /* Free mem */
    g_queue_free(packets);
}

void twcc_add_packet(twcc_context_t *ctx, uint16_t transport_seq_num, uint64_t arrival_us)
{
    /* Create <seq num, time> pair */
    oneplay_rtcp_transport_wide_cc_stats *stats = malloc(sizeof(oneplay_rtcp_transport_wide_cc_stats));

    if(transport_seq_num<0x0FFF && (ctx->transport_wide_cc_last_seq_num&0xFFFF)>0xF000) {
        /* Increase cycles */
        ctx->transport_wide_cc_cycles++;
    }

    /* Get extended value */
    uint32_t transport_ext_seq_num = ctx->transport_wide_cc_cycles<<16 | transport_seq_num;
    /* Store last received transport seq num */
    ctx->transport_wide_cc_last_seq_num = transport_seq_num;
    /* Set stats values */
    stats->transport_seq_num = transport_ext_seq_num;
    stats->timestamp = arrival_us;

    PltLockMutex(&ctx->mutex);
    ctx->transport_wide_received_seq_nums = list_prepend(ctx->transport_wide_received_seq_nums, stats);
    PltUnlockMutex(&ctx->mutex);
}
