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

static PLT_THREAD senderThread;
static PLT_THREAD encoderThread;
static PLT_THREAD captureThread;

static PPLT_CRYPTO_CONTEXT audioEncryptionCtx;

#ifdef DEBUG_AUDIO_ENCRYPTION
static PPLT_CRYPTO_CONTEXT audioDecryptionCtx;
#endif

static bool initialized;
static uint32_t avRiKeyId;
//static unsigned char currentAesIv[16];

#define MAX_QUEUED_AUDIO_FRAMES 30

#define RTP_SEND_BUFFER (64 * 1024)//TBD size in frames

#define AUDIO_CAPTURE_FRAME_DURATION 5

#define BITRATE_MS_126 15750/1000
#define MAX_PAYLOAD_SIZE BITRATE_MS_126 * AUDIO_CAPTURE_FRAME_DURATION

#define FRAME_SAMPLE_COUNT AUDIO_CAPTURE_FRAME_DURATION * 16

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
    uint16_t payload[MAX_PAYLOAD_SIZE];//TODO: shouldn't this be bytes
} AUDIO_PACKET, *PAUDIO_PACKET;

typedef struct _AUDIO_PACKET_HOLDER_HEADER{
    LINKED_BLOCKING_QUEUE_ENTRY lentry;
    int EncodedPayloadSize;
} AUDIO_PACKET_HOLDER_HEADER, *PAUDIO_PACKET_HOLDER_HEADER;

typedef struct _AUDIO_PACKET_HOLDER{
    AUDIO_PACKET_HOLDER_HEADER header;
    AUDIO_PACKET data;
} AUDIO_PACKET_HOLDER, *PAUDIO_PACKET_HOLDER;

//TODO: keep them in the holder header
static uint32_t rtpTimestamp = 0;
static uint16_t seqNumber = 0;
static bool isMicToggled = false;

// *********FEC related*********

#define MAX_BLOCK_SIZE ROUND_TO_PKCS7_PADDED_LEN(2048)

typedef struct _AUDIO_FEC_PACKET {
  RTP_PACKET rtp;
  AUDIO_FEC_HEADER fecHeader;
  uint8_t payload[MAX_BLOCK_SIZE];
} AUDIO_FEC_PACKET, *PAUDIO_FEC_PACKET;

static uint8_t* shards;
static uint8_t* shards_p[RTPA_TOTAL_SHARDS];
static PAUDIO_FEC_PACKET fec_packet;
static int audioQosType;// TODO: manage QOS

static reed_solomon* rs;

// *********FEC related End*********

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

    //Encryption
    audioEncryptionCtx = PltCreateCryptoContext();
    memcpy(&avRiKeyId, StreamConfig.remoteInputAesIv, sizeof(avRiKeyId));
    avRiKeyId = BE32(avRiKeyId);

    // FEC related
    rs = reed_solomon_new(RTPA_DATA_SHARDS, RTPA_FEC_SHARDS);
    fec_packet = malloc(sizeof(AUDIO_FEC_PACKET));
    if (shards == NULL) {
        Limelog("FEC PACKET: malloc() failed\n");
    }

    fec_packet->rtp.header = 0x80;
    fec_packet->rtp.packetType = 127;
    fec_packet->rtp.timestamp = 0;
    fec_packet->rtp.ssrc = 0;
    fec_packet->fecHeader.payloadType = 101;
    fec_packet->fecHeader.ssrc = 0;

    shards = malloc(RTPA_TOTAL_SHARDS * MAX_BLOCK_SIZE);
    if (shards == NULL) {
        Limelog("FEC Shards: malloc() failed\n");
    }

    for (int x = 0; x < RTPA_TOTAL_SHARDS; ++x) {
        shards_p[x] = (uint8_t *) &shards[x * MAX_BLOCK_SIZE];
    }


#ifdef DEBUG_AUDIO_ENCRYPTION
    audioDecryptionCtx = PltCreateCryptoContext();
#endif

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
    serverAddrMic.sin_port = htons(48002); //TODO: get from server
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

// return bytes written on success or return -1 on error
static inline int encryptAudio(unsigned char *inData, int inDataLen,
                                unsigned char *outEncryptedData, int *outEncryptedDataLen) {
    unsigned char iv[16] = { 0 };
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

    if(decryptedLen != inDataLen)
    {
        Limelog("Mic Decryption Error: Decrypted audio size mismatch.");
    }

    for(int i = 0; i < inDataLen; i++)
    {
        if(paddedData[i] != decryptedAudio[i])
        {
            Limelog("Mic Decryption test Failed");
        }
    }

#endif

    return ret;
}

bool sendRtpMicPacket(PAUDIO_PACKET_HOLDER holder, PENCODED_AUDIO_PAYLOAD_HOLDER payload){

    int sentBytes = 0;

    holder->data.rtp.header = 0x80;
    holder->data.rtp.packetType = 101;
    holder->data.rtp.ssrc = 0;
    holder->data.rtp.timestamp = BE32(rtpTimestamp);
    holder->data.rtp.sequenceNumber = BE16(seqNumber);

#ifdef MIC_DEBUG
    Limelog("Sequence Number: %d", seqNumber);
    Limelog("Encoded data Size: %d", payload->header.size);
#endif

// #ifndef DISABLE_MIC_ENCRYPTION

//     if(AudioEncryptionEnabled)
//     {
//       // TODO: encrypt based on conf file
//       int err = encryptAudio(
//           (unsigned char *)(&payload->data[0]), payload->header.size,
//           (unsigned char *)(&payload->data[0]), &payload->header.size);

//       if (err == -1) {
//         Limelog("Mic Audio Encryption Failed : %d", err);
//       }
//     }
// #endif

    memcpy_s(&holder->data.payload[0], 2000, &payload->data[0], payload->header.size );

#ifdef FEC_DEBUG_DROP_CHECK
    if ((/*seqNumber % 2 == 0 ||*/ seqNumber % 3 == 0) && seqNumber % 10 != 0) {
      Limelog("FEC_DEBUG_DROP_CHECK: Dropping :: %d", seqNumber);
    } else {
      sentBytes =
          sendto(sockMic, (const char *)&holder->data,
                 sizeof(RTP_PACKET) + payload->header.size, 0,
                 (struct sockaddr *)&serverAddrMic, sizeof(serverAddrMic));
    }
#else
    sentBytes = sendto(sockMic
                            , (const char*)&holder->data
                            , sizeof(RTP_PACKET)+payload->header.size
                            , 0
                            , (struct sockaddr *) &serverAddrMic
                            , sizeof(serverAddrMic)
                            );
#endif

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

    if (sentBytes == SOCKET_ERROR) {
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

    memcpy_s(&holder->data.payload[0], MAX_PAYLOAD_SIZE, shards_p[seqNumber % RTPA_DATA_SHARDS], payload->header.size);

    if (seqNumber % RTPA_DATA_SHARDS == 0) {
        fec_packet->fecHeader.baseSequenceNumber = BE16(seqNumber);
        fec_packet->fecHeader.baseTimestamp = BE32(rtpTimestamp);
    }

    if ((seqNumber + 1) % RTPA_DATA_SHARDS == 0) {
        // TODO: check what will happen when the blocksize are different like 32 and 16
        reed_solomon_encode(rs, shards_p, RTPA_TOTAL_SHARDS, payload->header.size);

        for (int x = 0; x < RTPA_FEC_SHARDS; ++x) {
            fec_packet->rtp.sequenceNumber = (seqNumber + x + 1);
            fec_packet->fecHeader.fecShardIndex = x;
            memcpy(&fec_packet->payload[0], shards_p[RTPA_DATA_SHARDS + x], payload->header.size);

            //FEC
#ifdef FEC_DEBUG_FECDROP_CHECK
// Randomly introduce drops in the packets and check if they are correctly
// detected and corrected at sunshine side.

            if(fec_packet->fecHeader.fecShardIndex == 0){
                Limelog("FEC_DEBUG: Dropping fec packet itself at seqNumber: %d | IndexNumber %d", seqNumber);
            }
            else{
                sentBytes = sendto(sockMic
                                   , (const char*)fec_packet
                                   , sizeof(AUDIO_FEC_PACKET)+payload->header.size - MAX_BLOCK_SIZE
                                   , 0
                                   , (struct sockaddr *) &serverAddrMic
                                   , sizeof(serverAddrMic)
                                   );
            }
#else

            sentBytes = sendto(sockMic
                                    , (const char*)fec_packet
                                    , sizeof(AUDIO_FEC_PACKET)+payload->header.size - MAX_BLOCK_SIZE
                                    , 0
                                    , (struct sockaddr *) &serverAddrMic
                                    , sizeof(serverAddrMic)
                                    );
#endif

#ifdef FEC_DEBUG
            //}
            Limelog("Audio FEC [%d] :: %d :: send...", (seqNumber & ~(RTPA_DATA_SHARDS - 1)) ,x );
            Limelog("Audio Packet type:: %d | FEC Type:: %d", fec_packet->rtp.packetType, fec_packet->fecHeader.payloadType );
#endif

            if (sentBytes == SOCKET_ERROR) {
                Limelog("Failed to send FEC: %d\n", WSAGetLastError());
                closesocket(sockMic);
                WSACleanup();
                return false;
            }
        }
    }

    //frame *3(clocked at 48khz for opus)
    rtpTimestamp += 80*3; // 80 = 16000/1000 * Frame Duration(5) TODO: dont hardcode
    seqNumber++;

    return true;
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
void audioCaptureThreadProc(void* context){
    int err = 0;
    PRAW_FRAME_HOLDER holder;
    isMicToggled = false;

    while (!PltIsThreadInterrupted(&captureThread))
    {
        bool isMicMuted = AudioCaptureCallbacks.isMuted();
        if(isMicMuted)
        {
            PltSleepMs(1500);
            continue;
        }
        else{
            holder = allocateHolder(0, &rawFreeFrameList, sizeof(RAW_FRAME_HOLDER));
            if(holder == NULL){
                Limelog("Null holder in capture thread: %d", err);
                return;
            }

#ifdef ENABLE_AUDIO_LATENCY_MONITOR
            QueryPerformanceCounter(&holder->timeStamp);
#endif
            if(AudioCaptureCallbacks.captureMic(holder->frame)){
                err = LbqOfferQueueItem(&rawFrameQueue, holder, &holder->entry);

                if (err != LBQ_SUCCESS) {
                    if(err == LBQ_BOUND_EXCEEDED){
                        Limelog("Mic capture queue reached maximum size limit\n");
                        // The packet queue is full, so free all existing items
                        freePacketList(LbqFlushQueueItems(&rawFrameQueue));
                    }
                    freeRawFrameHolder(holder);
                }
            }
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
        if(AudioCaptureCallbacks.isMuted())
        {
            PltSleepMs(1500);
            continue;
        }

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
            Limelog("Mic encode queue reached maximum size limit\n");
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

        if(AudioCaptureCallbacks.isMuted())
        {
            // Better to sleep the thread rather than recreating it.
            PltSleepMs(1500);
            continue;
        }

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

        if(!sendRtpMicPacket(audioPacket, encodedFrameHolder)){
            Limelog("sockMic send Error!");
        }

        freeEncodeFrameHolder(encodedFrameHolder);
        freePacketHolder(audioPacket);
    }

    if(fec_packet != NULL)
    {
        free(fec_packet);
    }

    if(shards != NULL)
    {
        free(shards);
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

    PltDestroyCryptoContext(audioEncryptionCtx);

#ifdef DEBUG_AUDIO_ENCRYPTION
    PltDestroyCryptoContext(audioDecryptionCtx);
#endif
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
        //PltCloseThread(&captureThread);
        closeSocket(sockMic);
        AudioCaptureCallbacks.cleanup();
        return err;
    }

    // TODO: set and check capabilities before creating threads.
    err = PltCreateThread("AudioSender", audioSenderThreadProc, NULL, &senderThread);
    if (err != 0) {
        AudioCaptureCallbacks.stop();
        PltInterruptThread(&captureThread);
        PltJoinThread(&captureThread);
        //PltCloseThread(&captureThread);
        PltInterruptThread(&encoderThread);
        PltJoinThread(&encoderThread);
        //PltCloseThread(&encoderThread);
        closeSocket(sockMic);
        AudioCaptureCallbacks.cleanup();
        return err;
    }
    return 0;
}

void stopAudioCaptureStream(void)
{
    AudioCaptureCallbacks.stop();

    PltInterruptThread(&senderThread);
    if ((AudioCaptureCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        // Signal threads waiting on the LBQ
        //TODO: Capabilities setup base on thread count
        LbqSignalQueueShutdown(&rawFrameQueue);
        LbqSignalQueueShutdown(&encodedFrameQueue);
        LbqSignalQueueShutdown(&rtpPacketQueue);
        PltInterruptThread(&captureThread);
        PltInterruptThread(&encoderThread);
    }

    PltJoinThread(&senderThread);
    if ((AudioCaptureCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
        PltJoinThread(&captureThread);
        PltJoinThread(&encoderThread);
    }

    //PltCloseThread(&senderThread);
    // if ((AudioCaptureCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
    //   PltCloseThread(&captureThread);
    //   PltCloseThread(&encoderThread);
    // }

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

int LiSendMicToggleEvent(bool isMuted){
    char* data = isMuted? "Muted" : "Not Muted";

    if(sendMicStatusPacketOnControlStream((unsigned char*)data, strlen(data)) == -1)
    {
        Limelog("Error sending Mic Status on Control Stream.");
    }

    return 0;
}
// int LiGetPendingAudioFrames(void){}

// int LiGetPendingAudioDuration(void){}

// TODO: Expose required functions to c++
