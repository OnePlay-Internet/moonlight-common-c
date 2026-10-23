// OnePlay adaptive bitrate: the client's half.
//
// The host runs the controller; the client measures what only it can see and reports it
// every ABR_REPORT_INTERVAL_MS on the control stream (SS_ABR_REPORT_PTYPE, 72 bytes,
// little-endian, cumulative counters so a lost report costs resolution, not information):
//
//  - Transport: the LI_VIDEO_NETWORK_STATS counters, plus frames delivered and bytes
//    received, so the host can compare what arrived against what it sent.
//  - Queueing delay: each frame's first packet is stamped on arrival and compared with the
//    frame's RTP timestamp. The difference has an arbitrary offset (the clocks are not
//    synchronised) but its excess over the recent minimum is the time the frame spent
//    queued on the path - the earliest sign of congestion, before anything is lost.
//  - Decoder health, from the application (LiReportDecoderStats).
//
// The host answers with its status (SS_ABR_STATUS_PTYPE), kept for LiGetAbrStatus().
//
// Wire layouts must match the host's src/abr_protocol.h.

#include "Limelight-internal.h"

// Requested by the application for the next connection.
static bool abrWanted;
static int abrWantedMinKbps;

// This connection negotiated it: we asked and the host advertised SS_FF_ONEPLAY_ABR.
bool AbrNegotiated;

uint32_t VideoStatFramesDelivered;
uint64_t VideoStatBytesReceived;

static PLT_MUTEX abrMutex;
static bool abrMutexCreated;

// Queueing delay. The path floor is the minimum transit over the last
// OWD_BUCKETS * OWD_BUCKET_MS, kept as per-second minimums so it can follow a route change.
#define OWD_BUCKET_MS 1000
#define OWD_BUCKETS 10
static int64_t owdBucketMin[OWD_BUCKETS];
static bool owdBucketUsed[OWD_BUCKETS];
static uint64_t owdBucketEpoch;
static bool owdStarted;
static uint32_t lastRtpTimestamp;
static int64_t extendedRtpTimestamp;
static uint64_t owdSum;
static uint32_t owdCount;
static uint32_t owdMax;

// RFC 3550 interarrival jitter over frames, in milliseconds.
static double arrivalJitterMs;
static int64_t lastTransitMs;
static bool haveTransit;

// Decoder health since the last report.
static bool decoderStatsValid;
static uint32_t decoderQueueDepthMax;
static uint64_t decodeTimeSumUs;
static uint32_t decodeTimeCount;
static uint32_t decoderDroppedTotal;

// Report bookkeeping.
static uint16_t reportSequence;
static uint64_t lastReportMs;

// Host status.
static LI_ABR_STATUS hostStatus;
static bool hostStatusValid;

void LiSetAdaptiveBitrate(bool enabled, int minBitrateKbps) {
    abrWanted = enabled;
    abrWantedMinKbps = minBitrateKbps > 0 ? minBitrateKbps : 0;
}

bool abrWantedForConnection(int* minBitrateKbps) {
    *minBitrateKbps = abrWantedMinKbps;
    return abrWanted;
}

void abrInitialize(void) {
    if (!abrMutexCreated) {
        if (PltCreateMutex(&abrMutex) == 0) {
            abrMutexCreated = true;
        }
    }

    // AbrNegotiated is decided during the RTSP handshake, before this runs.
    VideoStatFramesDelivered = 0;
    VideoStatBytesReceived = 0;

    memset(owdBucketMin, 0, sizeof(owdBucketMin));
    memset(owdBucketUsed, 0, sizeof(owdBucketUsed));
    owdBucketEpoch = 0;
    owdStarted = false;
    lastRtpTimestamp = 0;
    extendedRtpTimestamp = 0;
    owdSum = 0;
    owdCount = 0;
    owdMax = 0;
    arrivalJitterMs = 0;
    lastTransitMs = 0;
    haveTransit = false;

    decoderStatsValid = false;
    decoderQueueDepthMax = 0;
    decodeTimeSumUs = 0;
    decodeTimeCount = 0;
    decoderDroppedTotal = 0;

    reportSequence = 0;
    lastReportMs = 0;

    memset(&hostStatus, 0, sizeof(hostStatus));
    hostStatusValid = false;
}

static void abrLock(void) {
    if (abrMutexCreated) {
        PltLockMutex(&abrMutex);
    }
}

static void abrUnlock(void) {
    if (abrMutexCreated) {
        PltUnlockMutex(&abrMutex);
    }
}

// Called by the RTP queue for the first packet of each frame.
void abrOnFrameStart(uint32_t rtpTimestamp, uint64_t receiveTimeMs) {
    int64_t transitMs;
    int64_t floorMs;
    int i;
    uint64_t bucket;

    if (!AbrNegotiated) {
        return;
    }

    abrLock();

    // Extend the 90 kHz timestamp across wraparound; a signed difference also absorbs a
    // frame that arrives slightly out of order.
    if (!owdStarted) {
        extendedRtpTimestamp = rtpTimestamp;
        owdBucketEpoch = receiveTimeMs / OWD_BUCKET_MS;
        owdStarted = true;
    }
    else {
        extendedRtpTimestamp += (int32_t)(rtpTimestamp - lastRtpTimestamp);
    }
    lastRtpTimestamp = rtpTimestamp;

    transitMs = (int64_t)receiveTimeMs - extendedRtpTimestamp / 90;

    // Retire buckets older than the window, then record this sample.
    bucket = receiveTimeMs / OWD_BUCKET_MS;
    while (owdBucketEpoch < bucket) {
        owdBucketEpoch++;
        owdBucketUsed[owdBucketEpoch % OWD_BUCKETS] = false;
    }
    i = (int)(bucket % OWD_BUCKETS);
    if (!owdBucketUsed[i] || transitMs < owdBucketMin[i]) {
        owdBucketMin[i] = transitMs;
        owdBucketUsed[i] = true;
    }

    floorMs = transitMs;
    for (i = 0; i < OWD_BUCKETS; i++) {
        if (owdBucketUsed[i] && owdBucketMin[i] < floorMs) {
            floorMs = owdBucketMin[i];
        }
    }

    {
        uint32_t excess = (uint32_t)(transitMs - floorMs);
        owdSum += excess;
        owdCount++;
        if (excess > owdMax) {
            owdMax = excess;
        }
    }

    if (haveTransit) {
        int64_t d = transitMs - lastTransitMs;
        if (d < 0) {
            d = -d;
        }
        arrivalJitterMs += ((double)d - arrivalJitterMs) / 16.0;
    }
    lastTransitMs = transitMs;
    haveTransit = true;

    abrUnlock();
}

void LiReportDecoderStats(uint32_t queueDepth, uint32_t decodeTimeUs, uint32_t droppedFramesTotal) {
    abrLock();
    decoderStatsValid = true;
    if (queueDepth > decoderQueueDepthMax) {
        decoderQueueDepthMax = queueDepth;
    }
    if (decodeTimeUs > 0) {
        decodeTimeSumUs += decodeTimeUs;
        decodeTimeCount++;
    }
    decoderDroppedTotal = droppedFramesTotal;
    abrUnlock();
}

static uint16_t clamp16(uint64_t v) {
    return v > 0xFFFF ? 0xFFFF : (uint16_t)v;
}

// Builds the next report into buffer (at least ABR_REPORT_SIZE bytes). Returns its size,
// or 0 when it is not yet time for one.
int abrBuildReport(char* buffer, int bufferSize, uint64_t nowMs) {
    BYTE_BUFFER bb;
    uint8_t flags = 0;
    uint32_t intervalMs;
    uint16_t owdAvg, owdMaxValue, jitter, depth;
    uint32_t decodeUs, dropped;

    if (!AbrNegotiated || bufferSize < ABR_REPORT_SIZE) {
        return 0;
    }
    if (lastReportMs != 0 && nowMs - lastReportMs < ABR_REPORT_INTERVAL_MS) {
        return 0;
    }
    intervalMs = lastReportMs == 0 ? ABR_REPORT_INTERVAL_MS : (uint32_t)(nowMs - lastReportMs);
    lastReportMs = nowMs;

    abrLock();
    if (owdCount > 0) {
        flags |= 0x01;
        owdAvg = clamp16(owdSum / owdCount);
        owdMaxValue = clamp16(owdMax);
    }
    else {
        owdAvg = 0;
        owdMaxValue = 0;
    }
    jitter = clamp16((uint64_t)(arrivalJitterMs + 0.5));
    owdSum = 0;
    owdCount = 0;
    owdMax = 0;

    if (decoderStatsValid) {
        flags |= 0x02;
    }
    depth = clamp16(decoderQueueDepthMax);
    decodeUs = decodeTimeCount > 0 ? (uint32_t)(decodeTimeSumUs / decodeTimeCount) : 0;
    dropped = decoderDroppedTotal;
    decoderQueueDepthMax = 0;
    decodeTimeSumUs = 0;
    decodeTimeCount = 0;
    abrUnlock();

    BbInitializeWrappedBuffer(&bb, buffer, 0, ABR_REPORT_SIZE, BYTE_ORDER_LITTLE);
    BbPut8(&bb, 1); // version
    BbPut8(&bb, flags);
    BbPut16(&bb, reportSequence++);
    BbPut32(&bb, intervalMs);
    BbPut32(&bb, VideoStatTotalDataPackets);
    BbPut32(&bb, VideoStatReceivedDataPackets);
    BbPut32(&bb, VideoStatTotalParityPackets);
    BbPut32(&bb, VideoStatReceivedParityPackets);
    BbPut32(&bb, VideoStatSentParityPackets);
    BbPut32(&bb, VideoStatFramesDelivered);
    BbPut32(&bb, VideoStatFramesRecovered);
    BbPut32(&bb, VideoStatFramesLost);
    BbPut32(&bb, VideoStatIdrRequests);
    BbPut32(&bb, VideoStatRfiRequests);
    BbPut64(&bb, VideoStatBytesReceived);
    BbPut16(&bb, owdAvg);
    BbPut16(&bb, owdMaxValue);
    BbPut16(&bb, jitter);
    BbPut16(&bb, depth);
    BbPut32(&bb, decodeUs);
    BbPut32(&bb, dropped);

    return ABR_REPORT_SIZE;
}

// Payload of SS_ABR_STATUS_PTYPE, after the control header.
void abrHandleHostStatus(const char* payload, int length) {
    BYTE_BUFFER bb;
    LI_ABR_STATUS status;
    uint8_t version;

    if (length < ABR_STATUS_SIZE) {
        Limelog("Discarding short ABR status message: %d bytes\n", length);
        return;
    }

    memset(&status, 0, sizeof(status));
    BbInitializeWrappedBuffer(&bb, (char*)payload, 0, length, BYTE_ORDER_LITTLE);
    BbGet8(&bb, &version);
    if (version == 0) {
        return;
    }
    BbGet8(&bb, &status.state);
    BbGet8(&bb, &status.reason);
    BbGet8(&bb, &status.encoderControl);
    BbGet32(&bb, &status.targetKbps);
    BbGet32(&bb, &status.ceilingKbps);
    BbGet32(&bb, &status.floorKbps);
    BbGet32(&bb, &status.budgetKbps);
    BbGet16(&bb, &status.fecPercent);
    BbGet16(&bb, &status.rttMs);
    BbGet16(&bb, &status.queueDelayMs);
    BbGet16(&bb, &status.lossBasisPoints);
    BbGet32(&bb, &status.decreases);
    BbGet32(&bb, &status.increases);
    BbGet32(&bb, &status.sequence);
    status.receivedAtMs = PltGetMillis();

    abrLock();
    hostStatus = status;
    hostStatusValid = true;
    abrUnlock();
}

bool LiGetAbrStatus(PLI_ABR_STATUS status) {
    bool valid;

    if (status == NULL) {
        return false;
    }

    abrLock();
    valid = hostStatusValid;
    if (valid) {
        *status = hostStatus;
    }
    else {
        memset(status, 0, sizeof(*status));
    }
    abrUnlock();

    return valid;
}

bool LiIsAdaptiveBitrateNegotiated(void) {
    return AbrNegotiated;
}

const char* LiGetAbrStateName(uint8_t state) {
    switch (state) {
    case 0: return "disabled";
    case 1: return "startup";
    case 2: return "stable";
    case 3: return "backoff";
    case 4: return "probing";
    case 5: return "blackout";
    case 6: return "fixed";
    default: return "unknown";
    }
}

const char* LiGetAbrReasonName(uint8_t reason) {
    switch (reason) {
    case 0: return "none";
    case 1: return "loss";
    case 2: return "FEC pressure";
    case 3: return "queue delay";
    case 4: return "keyframe request";
    case 5: return "decoder backlog";
    case 6: return "link capacity";
    case 7: return "recovery";
    case 8: return "FEC budget";
    default: return "unknown";
    }
}
