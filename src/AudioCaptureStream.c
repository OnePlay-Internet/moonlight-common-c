#include "Limelight-internal.h"
#include <opus_defines.h>
#include <WinSock2.h>
#include <opus.h>
#include <stdbool.h>

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
#include <time.h>
#endif

static bool captureThreadStarted;
static PLT_THREAD captureThread;

static PPLT_CRYPTO_CONTEXT audioEncryptionCtx;

#ifdef DEBUG_AUDIO_ENCRYPTION
static PPLT_CRYPTO_CONTEXT audioDecryptionCtx;
#endif

static bool initialized;
static uint32_t avRiKeyId;
// static unsigned char currentAesIv[16];

#define AUDIO_CAPTURE_FRAME_DURATION 10

#define BITRATE_MS_126 15750 / 1000
#define MAX_PAYLOAD_SIZE BITRATE_MS_126 *AUDIO_CAPTURE_FRAME_DURATION

#define FREQ 48000
#define FRAME_SAMPLE_COUNT AUDIO_CAPTURE_FRAME_DURATION *(FREQ / 1000)

typedef struct _RAW_FRAME_HOLDER
{
    LINKED_BLOCKING_QUEUE_ENTRY entry;

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    LARGE_INTEGER timeStamp;
#endif

    uint16_t frame[FRAME_SAMPLE_COUNT];
} RAW_FRAME_HOLDER, *PRAW_FRAME_HOLDER;

typedef struct _ENCODED_AUDIO_PAYLOAD_HEADER
{
    LINKED_BLOCKING_QUEUE_ENTRY lentry;

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    LARGE_INTEGER timeStamp;
#endif

    int size;
} ENCODED_AUDIO_PAYLOAD_HEADER, *PENCODED_AUDIO_PAYLOAD_HEADER;

typedef struct _ENCODED_AUDIO_PAYLOAD
{
    ENCODED_AUDIO_PAYLOAD_HEADER header;
    uint16_t data[MAX_PAYLOAD_SIZE];
} ENCODED_AUDIO_PAYLOAD_HOLDER, *PENCODED_AUDIO_PAYLOAD_HOLDER;

// TODO: use modified RTPQueue instead for better use with FEC
typedef struct _AUDIO_PACKET
{
    RTP_PACKET rtp;
    uint16_t payload[MAX_PAYLOAD_SIZE]; // TODO: shouldn't this be bytes
} AUDIO_PACKET, *PAUDIO_PACKET;

typedef struct _AUDIO_PACKET_HOLDER_HEADER
{
    LINKED_BLOCKING_QUEUE_ENTRY lentry;
    int EncodedPayloadSize;
} AUDIO_PACKET_HOLDER_HEADER, *PAUDIO_PACKET_HOLDER_HEADER;

typedef struct _AUDIO_PACKET_HOLDER
{
    AUDIO_PACKET_HOLDER_HEADER header;
    AUDIO_PACKET data;
} AUDIO_PACKET_HOLDER, *PAUDIO_PACKET_HOLDER;

// TODO: keep them in the holder header
static uint32_t rtpTimestamp = 0;
static uint16_t seqNumber = 0;

// *********FEC related*********

#define MAX_BLOCK_SIZE ROUND_TO_PKCS7_PADDED_LEN(2048)

typedef struct _AUDIO_FEC_PACKET
{
    RTP_PACKET rtp;
    AUDIO_FEC_HEADER fecHeader;
    uint8_t payload[MAX_BLOCK_SIZE];
} AUDIO_FEC_PACKET, *PAUDIO_FEC_PACKET;

static uint8_t *shards;
static uint8_t *shards_p[RTPA_TOTAL_SHARDS];
static PAUDIO_FEC_PACKET fec_packet;
static int audioQosType; // TODO: manage QOS

static reed_solomon *rs;

// *********FEC related End*********

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
static LARGE_INTEGER frequency;
static double audioLatency;
static double avgLatency;
#endif

// #define RTP_DEBUG 1

#ifdef RTP_DEBUG
FILE *rtpFile;
FILE *sizeFile;
void InitPacketDebug()
{
    rtpFile = fopen("rtp.bin", "ab");
    sizeFile = fopen("packetsize.txt", "w");
}

void DeinitPacketDebug()
{
    fclose(rtpFile);
    fclose(sizeFile);
}

void appendToRTPFile(PAUDIO_PACKET_HOLDER data)
{
    fwrite(&data->data, sizeof(RTP_PACKET) + data->header.EncodedPayloadSize, 1, rtpFile);
}

void appendpacketSizeToFile(int32_t size)
{
    fprintf(sizeFile, "%d \n", size);
}

#endif

static bool isMicToggled = false;
static CRITICAL_SECTION cs;
static CONDITION_VARIABLE cond;

int initializeAudioCaptureStream(void)
{

#ifdef RTP_DEBUG
    InitPacketDebug();
#endif

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    QueryPerformanceFrequency(&frequency);
#endif

    // Encryption
    audioEncryptionCtx = PltCreateCryptoContext();
    memcpy(&avRiKeyId, StreamConfig.remoteInputAesIv, sizeof(avRiKeyId));
    avRiKeyId = BE32(avRiKeyId);

    // FEC related
    rs = reed_solomon_new(RTPA_DATA_SHARDS, RTPA_FEC_SHARDS);
    fec_packet = malloc(sizeof(AUDIO_FEC_PACKET));
    if (shards == NULL)
    {
        Limelog("FEC PACKET: malloc() failed\n");
    }

    fec_packet->rtp.header = 0x80;
    fec_packet->rtp.packetType = 127;
    fec_packet->rtp.timestamp = 0;
    fec_packet->rtp.ssrc = 0;
    fec_packet->fecHeader.payloadType = 101;
    fec_packet->fecHeader.ssrc = 0;

    shards = malloc(RTPA_TOTAL_SHARDS * MAX_BLOCK_SIZE);
    if (shards == NULL)
    {
        Limelog("FEC Shards: malloc() failed\n");
    }

    for (int x = 0; x < RTPA_TOTAL_SHARDS; ++x)
    {
        shards_p[x] = (uint8_t *)&shards[x * MAX_BLOCK_SIZE];
    }

#ifdef DEBUG_AUDIO_ENCRYPTION
    audioDecryptionCtx = PltCreateCryptoContext();
#endif
    return 0;
}

int notifyAudioCapturePortNegotiationComplete(void)
{
    // TODO: setup the udp ports here
    return 0;
}

static void *allocateHolder(int extraLength, PLINKED_BLOCKING_QUEUE queue, size_t PacketHolderSize)
{
    void *holder;
    int err;

    if (extraLength > 0)
    {
        return malloc(PacketHolderSize + extraLength);
    }

    // Grab an entry from the free list (if available)
    err = LbqPollQueueElement(queue, &holder);
    if (err == LBQ_SUCCESS)
    {
        return holder;
    }
    else if (err == LBQ_INTERRUPTED)
    {
        // We're shutting down. Don't bother allocating.
        return NULL;
    }
    else
    {
        LC_ASSERT(err == LBQ_NO_ELEMENT);

        // Otherwise we'll have to allocate
        return malloc(PacketHolderSize);
    }
}

// return bytes written on success or return -1 on error
static inline int encryptAudio(unsigned char *inData, int inDataLen,
                               unsigned char *outEncryptedData, int *outEncryptedDataLen)
{
    unsigned char iv[16] = {0};
    uint32_t ivSeq = BE32(avRiKeyId + seqNumber);
    memcpy(iv, &ivSeq, sizeof(ivSeq));

    int ret = 0;
    unsigned char paddedData[ROUND_TO_PKCS7_PADDED_LEN(MAX_PAYLOAD_SIZE)];

    memcpy(paddedData, inData, inDataLen);

    ret = PltEncryptMessage(
              audioEncryptionCtx, ALGORITHM_AES_CBC, CIPHER_FLAG_RESET_IV | CIPHER_FLAG_FINISH,
              (unsigned char *)StreamConfig.remoteInputAesKey,
              sizeof(StreamConfig.remoteInputAesKey), iv,
              sizeof(iv), NULL, 0, paddedData, inDataLen,
              outEncryptedData, outEncryptedDataLen)
              ? 0
              : -1;

#ifdef DEBUG_AUDIO_ENCRYPTION
    unsigned char decryptedAudio[ROUND_TO_PKCS7_PADDED_LEN(MAX_PAYLOAD_SIZE)];
    int32_t decryptedLen;

    PltDecryptMessage(audioDecryptionCtx, ALGORITHM_AES_CBC,
                      CIPHER_FLAG_RESET_IV | CIPHER_FLAG_FINISH,
                      (unsigned char *)StreamConfig.remoteInputAesKey,
                      sizeof(StreamConfig.remoteInputAesKey), iv,
                      sizeof(iv), NULL, 0, outEncryptedData,
                      *outEncryptedDataLen, decryptedAudio, &decryptedLen);

    if (decryptedLen != inDataLen)
    {
        Limelog("Mic Decryption Error: Decrypted audio size mismatch.");
    }

    for (int i = 0; i < inDataLen; i++)
    {
        if (paddedData[i] != decryptedAudio[i])
        {
            Limelog("Mic Decryption test Failed");
        }
    }

#endif

    return ret;
}

extern struct sockaddr_storage RemoteAddr;
extern uint16_t AudioPortNumber;
int rtpSocket;

void audioCaptureThreadProc(void *context)
{
    Limelog("Audio Capture Thread Started");

    OPUS_ENCODER_CONFIGURATION chosenConfig;
    chosenConfig.sampleRate = 48000;
    chosenConfig.channelCount = 1;
    chosenConfig.samplesPerFrame = (chosenConfig.sampleRate / 1000) * AUDIO_CAPTURE_FRAME_DURATION;
    chosenConfig.Application = OPUS_APPLICATION_VOIP; // TODO: check quality

    AudioCaptureCallbacks.init(0, &chosenConfig, context, 0);

    isMicToggled = true;
    uint16_t CapturedFrame[FRAME_SAMPLE_COUNT * 100];
    uint32_t len = 0;

    unsigned char outFrame[1024];
    int encoded_len = 0;
    LC_SOCKADDR saddr;

    LC_ASSERT(AudioPortNumber != 0);

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, AudioPortNumber);

    while (!PltIsThreadInterrupted(&captureThread))
    {
        EnterCriticalSection(&cs);
        if(!isMicToggled){
            SleepConditionVariableCS(&cond, &cs, INFINITE);
        }
        LeaveCriticalSection(&cs);

        if (len < FRAME_SAMPLE_COUNT * 2)
        {
            // SDL_LOG_INFO(0, "Waiting for capturing next frame\n");
            PltSleepMs(AUDIO_CAPTURE_FRAME_DURATION);
        }
        if (!AudioCaptureCallbacks.captureMic((void *)&CapturedFrame, &len))
            continue;

        len -= FRAME_SAMPLE_COUNT * 2;
        AudioCaptureCallbacks.encode((void *)CapturedFrame, FRAME_SAMPLE_COUNT, &outFrame, &encoded_len);

        if (encoded_len < 0)
        {
            Limelog("Encoding error: &d", encoded_len);
            continue;
        }

        sendto(rtpSocket, (char *)&outFrame, encoded_len, 0, (struct sockaddr *)&saddr, AddrLen);
    }
}

void destroyAudioCaptureStream(void)
{
    DeleteCriticalSection(&cs);
#ifdef RTP_DEBUG
    DeinitPacketDebug();
#endif
    PltDestroyCryptoContext(audioEncryptionCtx);

#ifdef DEBUG_AUDIO_ENCRYPTION
    PltDestroyCryptoContext(audioDecryptionCtx);
#endif
}

int startAudioCaptureStream(void *audioCaptureContext, int rtpsocket)
{

    InitializeCriticalSection(&cs);
    InitializeConditionVariable(&cond);

    int err;
    OPUS_ENCODER_CONFIGURATION chosenConfig;
    chosenConfig.sampleRate = FREQ;
    chosenConfig.channelCount = 1;
    chosenConfig.samplesPerFrame = FRAME_SAMPLE_COUNT;
    chosenConfig.Application = OPUS_APPLICATION_VOIP; // TODO: check quality

    err = AudioCaptureCallbacks.init(StreamConfig.audioConfiguration, &chosenConfig, audioCaptureContext, 0);
    if (err != 0)
    {
        return err;
    }

    // Owais: This doesn't do anything be we will keep it just in case
    AudioCaptureCallbacks.start();

    rtpSocket = rtpsocket;
    err = PltCreateThread("AudioCapSend", audioCaptureThreadProc, NULL, &captureThread);
    if (err != 0)
    {
        // AudioCaptureCallbacks.stop();
        AudioCaptureCallbacks.cleanup();
        return err;
    }
    captureThreadStarted = true;

    return 0;
}

void stopAudioCaptureStream(void)
{
    // AudioCaptureCallbacks.stop();
    AudioCaptureCallbacks.cleanup();

    if (captureThreadStarted)
    {
        PltInterruptThread(&captureThread);
        PltJoinThread(&captureThread);
        captureThreadStarted = false;
    }
    else
    {
        Limelog("Called stopAudioCaptureStream but capture thread already not running.");
    }

    initialized = false;
}

int LiSendMicToggleEvent(bool isMuted)
{
    char *data = isMuted ? "Mute" : "UnMute";

    if (sendMicStatusPacketOnControlStream((unsigned char *)data, strlen(data)) == -1)
    {
        Limelog("Error sending Mic Status on Control Stream.");
        return -1;
    }

    EnterCriticalSection(&cs);
    isMicToggled = !isMuted;
    if(isMicToggled){
        WakeConditionVariable(&cond);
    }
    LeaveCriticalSection(&cs);
    return 0;
}
// int LiGetPendingAudioFrames(void){}

// int LiGetPendingAudioDuration(void){}

// TODO: Expose required functions to c++
