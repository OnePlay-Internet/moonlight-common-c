#include "Limelight-internal.h"
#include <opus_defines.h>
#include <WinSock2.h>
#include <opus.h>

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
#include <time.h>
#endif

//TODO: add socks send function to the platform functions
SOCKET sockMic;
struct sockaddr_in serverAddrMic;

static LINKED_BLOCKING_QUEUE rawFrameQueue;
static LINKED_BLOCKING_QUEUE rawFreeFrameList;
static LINKED_BLOCKING_QUEUE encodedFrameQueue;
static LINKED_BLOCKING_QUEUE encodedFreeFrameList;
static LINKED_BLOCKING_QUEUE rtpPacketQueue;
static LINKED_BLOCKING_QUEUE rtpFreePacketList;

//TODO: setup rtp_queue for FEC and encryption
//static RTP_AUDIO_QUEUE rtpAudioQueue;// the rtppackets will be queued here by encoder thread for sender thread

static PLT_THREAD senderThread;
static PLT_THREAD encoderThread;
static PLT_THREAD captureThread;
static PLT_MUTEX frameQMutex;
static PLT_MUTEX rtpQMutex;

static PPLT_CRYPTO_CONTEXT audioEncryptionCtx;
static bool initialized;
static bool encryptedControlStream;
static unsigned char currentAesIv[16];
static uint32_t avRiKeyId;// initialization vector

#define MAX_QUEUED_AUDIO_FRAMES 30

#define RTP_SEND_BUFFER (64 * 1024)//TBD size in frames

#define AUDIO_CAPTURE_FRAME_DURATION 10

#define FRAME_DURATION 10//ms
#define BITRATE_MS_126 15750/1000
#define MAX_PAYLOAD_SIZE BITRATE_MS_126 * FRAME_DURATION

#define FRAME_SAMPLE_COUNT FRAME_DURATION * 16

typedef struct _RAW_FRAME_HOLDER {
    LINKED_BLOCKING_QUEUE_ENTRY entry;

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    LARGE_INTEGER timeStamp;
#endif

    uint16_t frame[FRAME_SAMPLE_COUNT];
} RAW_FRAME_HOLDER, *PRAW_FRAME_HOLDER;

typedef struct _ENCODED_AUDIO_PAYLOAD_HEADER {
    LINKED_BLOCKING_QUEUE_ENTRY lentry;

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    LARGE_INTEGER timeStamp;
#endif

    int size;
} ENCODED_AUDIO_PAYLOAD_HEADER, *PENCODED_AUDIO_PAYLOAD_HEADER;

typedef struct _ENCODED_AUDIO_PAYLOAD {
    ENCODED_AUDIO_PAYLOAD_HEADER header;
    uint16_t data[MAX_PAYLOAD_SIZE];
} ENCODED_AUDIO_PAYLOAD_HOLDER, *PENCODED_AUDIO_PAYLOAD_HOLDER;

//TODO: use modified RTPQueue instead for better use with FEC
typedef struct _AUDIO_PACKET {
    RTP_PACKET rtp;
    uint16_t payload[MAX_PAYLOAD_SIZE];
} AUDIO_PACKET, *PAUDIO_PACKET;

typedef struct _AUDIO_PACKET_HOLDER_HEADER{
    LINKED_BLOCKING_QUEUE_ENTRY lentry;
    int EncodedPayloadSize;
} AUDIO_PACKET_HOLDER_HEADER, *PAUDIO_PACKET_HOLDER_HEADER;

typedef struct _AUDIO_PACKET_HOLDER{
    AUDIO_PACKET_HOLDER_HEADER header;
    AUDIO_PACKET data;
} AUDIO_PACKET_HOLDER, *PAUDIO_PACKET_HOLDER;

static int rtpTimestamp = 0;
static int seqNumber = 0;

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
static LARGE_INTEGER frequency;
static double audioLatency;
static double avgLatency;
#endif

//#define RTP_DEBUG 1

#ifdef RTP_DEBUG
FILE* rtpFile;
FILE* sizeFile;
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

int initializeAudioCaptureStream(void) {

#ifdef RTP_DEBUG
    InitPacketDebug();
#endif

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    QueryPerformanceFrequency(&frequency);
#endif

    LbqInitializeLinkedBlockingQueue(&rawFrameQueue, MAX_QUEUED_AUDIO_FRAMES);
    LbqInitializeLinkedBlockingQueue(&rawFreeFrameList, MAX_QUEUED_AUDIO_FRAMES);

    LbqInitializeLinkedBlockingQueue(&encodedFrameQueue, MAX_QUEUED_AUDIO_FRAMES);
    LbqInitializeLinkedBlockingQueue(&encodedFreeFrameList, MAX_QUEUED_AUDIO_FRAMES);

    LbqInitializeLinkedBlockingQueue(&rtpPacketQueue, MAX_QUEUED_AUDIO_FRAMES);
    LbqInitializeLinkedBlockingQueue(&rtpFreePacketList, MAX_QUEUED_AUDIO_FRAMES);

    //RtpaInitializeQueue(&rtpAudioQueue);

    PltCreateMutex(&frameQMutex);
    PltCreateMutex(&rtpQMutex);



    //-- Init Sock --
    WSADATA wsaData;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Create socket
    sockMic = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockMic == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set server address
    memset(&serverAddrMic, 0, sizeof(serverAddrMic));
    serverAddrMic.sin_family = AF_INET;
    serverAddrMic.sin_port = htons(48002); //TODO: get for server
    serverAddrMic.sin_addr.s_addr = inet_addr(RemoteAddrString);

    return 0;
}

int notifyAudioCapturePortNegotiationComplete(void) {
    // TODO: setup the udp ports here
    return 0;
}

//TODO: try to club into single function
static void freeRawFrameHolder(PRAW_FRAME_HOLDER holder) {
    if (LbqOfferQueueItem(&rawFreeFrameList, holder, &holder->entry) != LBQ_SUCCESS) {
        free(holder);
    }
}

static void freeEncodeFrameHolder(PENCODED_AUDIO_PAYLOAD_HOLDER holder) {
    LC_ASSERT(holder->header.size != 0);

    if (holder->header.size > (int)sizeof(*holder) || LbqOfferQueueItem(&encodedFreeFrameList, holder, &holder->header.lentry) != LBQ_SUCCESS) {
        free(holder);
    }
}

static void freePacketHolder(PAUDIO_PACKET_HOLDER holder) {
    LC_ASSERT(holder->header.EncodedPayloadSize != 0);

    // Place the packet holder back into the free list if it's a standard size entry
    if (holder->header.EncodedPayloadSize > (int)sizeof(*holder) || LbqOfferQueueItem(&rtpFreePacketList, holder, &holder->header.lentry) != LBQ_SUCCESS) {
        free(holder);
    }
}

static void* allocateHolder(int extraLength, PLINKED_BLOCKING_QUEUE queue, size_t PacketHolderSize){
    void* holder;
    int err;

     if (extraLength > 0) {
         return malloc(PacketHolderSize + extraLength);
    }

    // Grab an entry from the free list (if available)
    err = LbqPollQueueElement(queue, &holder);
    if (err == LBQ_SUCCESS) {
        return holder;
    }
    else if (err == LBQ_INTERRUPTED) {
        // We're shutting down. Don't bother allocating.
        return NULL;
    }
    else {
        LC_ASSERT(err == LBQ_NO_ELEMENT);

        // Otherwise we'll have to allocate
        return malloc(PacketHolderSize);
    }
}

void encodeInputData(uint16_t* packet){


}

int encryptData(unsigned char* plaintext, int plaintextLen,
                       unsigned char* ciphertext, int* ciphertextLen){

    return 0;
}


bool sendInputPacket(PAUDIO_PACKET_HOLDER holder, PENCODED_AUDIO_PAYLOAD_HOLDER payload){

    holder->data.rtp.header = 0x80;
    holder->data.rtp.packetType = 101;
    holder->data.rtp.ssrc = 0;
    holder->data.rtp.timestamp = BE32(rtpTimestamp);
    holder->data.rtp.sequenceNumber = BE16(seqNumber);

    rtpTimestamp += 160*3;//frame *3(clocked at 48khz for opus) * //2 channel of opus encoder (TBD if one channel)
    seqNumber++;

    memcpy_s(&holder->data.payload[0], 2000, &payload->data[0], payload->header.size );

    if(seqNumber % 200 == 0){
        Limelog("Encode Len: %d", payload->header.size);
    }

    int sent_bytes = sendto(sockMic, (const char*)&holder->data, sizeof(RTP_PACKET)+payload->header.size, 0, (struct sockaddr *) &serverAddrMic, sizeof(serverAddrMic));

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    audioLatency = (double)(end.QuadPart - payload->header.timeStamp.QuadPart) / frequency.QuadPart;
    avgLatency += audioLatency;
    Limelog("Audio Latency for packet number: %d is %f ms | avg latency: %f ms"
            , seqNumber
            , audioLatency*1000
            , (avgLatency/seqNumber) * 1000);

#endif

    if (sent_bytes == SOCKET_ERROR) {
        Limelog("Failed to send message: %d\n", WSAGetLastError());
        closesocket(sockMic);
        WSACleanup();
        return false;
    }

#ifdef RTP_DEBUG
    // saving 10 sec of rtp packet to file for sunshine test
    if(seqNumber<=1000)
    {
        appendToRTPFile(holder);
        appendpacketSizeToFile((int32_t)(sizeof(RTP_PACKET)+ holder->header.EncodedPayloadSize));
    } else
    {
        DeinitPacketDebug();
    }
#endif

    //PltSleepMs(1);

    return true;
}

void audioCaptureThreadProc(void* context){
    int err = 0;
    PRAW_FRAME_HOLDER holder;

    while (!PltIsThreadInterrupted(&senderThread))
    {
        holder = allocateHolder(0, &rawFreeFrameList, sizeof(RAW_FRAME_HOLDER));
        if(holder == NULL){
            Limelog("Null holder in capture thread: %d", err);
            return;
        }

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
        QueryPerformanceCounter(&holder->timeStamp);
#endif

        AudioCaptureCallbacks.captureMic(holder->frame);

        err = LbqOfferQueueItem(&rawFrameQueue, holder, &holder->entry);
        if (err != LBQ_SUCCESS) {
            LC_ASSERT(err == LBQ_BOUND_EXCEEDED);
            Limelog("Input queue reached maximum size limit\n");
            freeRawFrameHolder(holder);
        }
    }
}

void audioEncodeThreadProc(void* context){
    int err = 0;
    int outPayloadSize = 0;
    PRAW_FRAME_HOLDER rawFrameHolder;
    PENCODED_AUDIO_PAYLOAD_HOLDER encodedFrameHolder;

    while(!PltIsThreadInterrupted(&encoderThread))
    {
        err = LbqWaitForQueueElement(&rawFrameQueue, (void**)&rawFrameHolder);
        if (err != LBQ_SUCCESS) {
            Limelog("Queue Error in Audio Encode Thread: %d", err);
            //return;
        }

        encodedFrameHolder = allocateHolder(0, &encodedFreeFrameList, sizeof(*encodedFrameHolder));
        if(encodedFrameHolder == NULL){
            Limelog("Null holder in audio encode thread: %d", err);
            //return;
        }

        AudioCaptureCallbacks.encode(rawFrameHolder->frame, MAX_PAYLOAD_SIZE, &encodedFrameHolder->data[0], &outPayloadSize);

        if (outPayloadSize < 0) {
            Limelog("Encode Error: %d", outPayloadSize);
            //return;
        }

        encodedFrameHolder->header.size = outPayloadSize;

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
        encodedFrameHolder->header.timeStamp = rawFrameHolder->timeStamp;
#endif
        err = LbqOfferQueueItem(&encodedFrameQueue, encodedFrameHolder, &encodedFrameHolder->header.lentry);
        if (err != LBQ_SUCCESS) {
            LC_ASSERT(err == LBQ_BOUND_EXCEEDED);
            Limelog("Input queue reached maximum size limit\n");
            freeEncodeFrameHolder(encodedFrameHolder);
        }

        freeRawFrameHolder(rawFrameHolder);
        //PltSleepMs(1);
    }
}

void audioSenderThreadProc(void* context) {
    int err = 0;
    PENCODED_AUDIO_PAYLOAD_HOLDER encodedFrameHolder;
    PAUDIO_PACKET_HOLDER audioPacket;

    while(!PltIsThreadInterrupted(&senderThread)){
        err = LbqWaitForQueueElement(&encodedFrameQueue, (void**)&encodedFrameHolder);
        if (err != LBQ_SUCCESS) {
            Limelog("Queue Error in Audio Sender Thread: %d", err);
            //return;
        }

        audioPacket = allocateHolder(0, &rtpFreePacketList, sizeof(*audioPacket));
        if(encodedFrameHolder == NULL){
            Limelog("Null holder in audio senser thread: %d", err);
            //return;
        }

        audioPacket->header.EncodedPayloadSize = encodedFrameHolder->header.size;

        if(!sendInputPacket(audioPacket, encodedFrameHolder)){
            Limelog("sockMic send Error!");
        }

        freeEncodeFrameHolder(encodedFrameHolder);
        freePacketHolder(audioPacket);
    }
}

void freePacketList(PLINKED_BLOCKING_QUEUE_ENTRY entry)
{
    PLINKED_BLOCKING_QUEUE_ENTRY nextEntry;

    while (entry != NULL) {
        nextEntry = entry->flink;

        // The entry is stored within the data allocation
        free(entry->data);

        entry = nextEntry;
    }
}

void destroyAudioCaptureStream(void){

#ifdef RTP_DEBUG
    DeinitPacketDebug();
#endif

    if (sockMic != INVALID_SOCKET) {
        closeSocket(sockMic);
        sockMic = INVALID_SOCKET;
    }

    freePacketList(LbqDestroyLinkedBlockingQueue(&rawFrameQueue));
    freePacketList(LbqDestroyLinkedBlockingQueue(&rawFreeFrameList));

    freePacketList(LbqDestroyLinkedBlockingQueue(&encodedFrameQueue));
    freePacketList(LbqDestroyLinkedBlockingQueue(&encodedFreeFrameList));

    freePacketList(LbqDestroyLinkedBlockingQueue(&rtpPacketQueue));
    freePacketList(LbqDestroyLinkedBlockingQueue(&rtpFreePacketList));

    // RtpaCleanupQueue(&rtpAudioQueue);

    PltDeleteMutex(&frameQMutex);
    PltDeleteMutex(&rtpQMutex);
}

int startAudioCaptureStream(void* audioCaptureContext, int arFlags)
{
    int err;
    OPUS_ENCODER_CONFIGURATION chosenConfig;
    chosenConfig.sampleRate = 16000;
    chosenConfig.channelCount = 1;
    chosenConfig.samplesPerFrame = (chosenConfig.sampleRate/1000) * AUDIO_CAPTURE_FRAME_DURATION;
    chosenConfig.Application = OPUS_APPLICATION_VOIP;//TODO: check quality

    err = AudioCaptureCallbacks.init(StreamConfig.audioConfiguration, &chosenConfig, audioCaptureContext, arFlags);
    if (err != 0) {
        return err;
    }

    AudioCaptureCallbacks.start();

    err = PltCreateThread("AudioCapSend", audioCaptureThreadProc, NULL, &captureThread);
    if (err != 0) {
        AudioCaptureCallbacks.stop();
        closeSocket(sockMic);
        AudioCaptureCallbacks.cleanup();
        return err;
    }

    err = PltCreateThread("AudioEnc", audioEncodeThreadProc , NULL, &encoderThread);
    if (err != 0) {
        AudioCaptureCallbacks.stop();
        PltInterruptThread(&captureThread);
        PltJoinThread(&captureThread);
        PltCloseThread(&captureThread);
        closeSocket(sockMic);
        AudioCallbacks.cleanup();
        return err;
    }

    // TODO: set and check capabilities before creating threads.
    err = PltCreateThread("AudioSender", audioSenderThreadProc, NULL, &senderThread);
    if (err != 0) {
        AudioCaptureCallbacks.stop();
        PltInterruptThread(&captureThread);
        PltJoinThread(&captureThread);
        PltCloseThread(&captureThread);
        PltInterruptThread(&encoderThread);
        PltJoinThread(&encoderThread);
        PltCloseThread(&encoderThread);
        closeSocket(sockMic);
        AudioCallbacks.cleanup();
        return err;
    }
    return 0;
}

void stopAudioCaptureStream(void)
{
    AudioCaptureCallbacks.stop();

    PltInterruptThread(&senderThread);
    if ((AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        // Signal threads waiting on the LBQ
        //TODO: Capabilities setup base on thread count
        LbqSignalQueueShutdown(&encodedFrameQueue);
        LbqSignalQueueShutdown(&rtpPacketQueue);
        PltInterruptThread(&encoderThread);
    }

    PltJoinThread(&senderThread);
    if ((AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltJoinThread(&encoderThread);
    }

    PltCloseThread(&senderThread);
    if ((AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltCloseThread(&encoderThread);
    }

    AudioCaptureCallbacks.cleanup();

    initialized = false;
    LbqSignalQueueShutdown(&rawFreeFrameList);
    LbqSignalQueueShutdown(&encodedFreeFrameList);
    LbqSignalQueueShutdown(&rtpFreePacketList);

    LbqSignalQueueDrain(&rawFrameQueue);
    LbqSignalQueueDrain(&rawFreeFrameList);

    LbqSignalQueueDrain(&encodedFrameQueue);
    LbqSignalQueueDrain(&encodedFreeFrameList);

    LbqSignalQueueDrain(&rtpPacketQueue);
    LbqSignalQueueDrain(&rtpFreePacketList);
}

// int LiGetPendingAudioFrames(void){}

// int LiGetPendingAudioDuration(void){}

// TODO: Expose required functions to c++
