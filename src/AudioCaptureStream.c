#include "Limelight-internal.h"
#include <opus_defines.h>
#include <WinSock2.h>
#include <math.h>

SOCKET sockMic;
struct sockaddr_in serverAddrMic;
//static ENetHost* client;
//static ENetPeer* peer;
static PLT_MUTEX enetMutex;

static LINKED_BLOCKING_QUEUE packetQueue;//tbd
static LINKED_BLOCKING_QUEUE packetHolderFreeList;
static RTP_AUDIO_QUEUE rtpAudioQueue;//tbd

static PLT_THREAD senderThread;
static PLT_THREAD encoderThread;


static PPLT_CRYPTO_CONTEXT audioEncryptionCtx;
static bool initialized;
static bool encryptedControlStream;
static unsigned char currentAesIv[16];
static uint32_t avRiKeyId;// initialization vector

#ifdef LC_DEBUG
#define INVALID_OPUS_HEADER 0x00
static uint8_t opusHeaderByte;
#endif

#define MAX_PACKET_SIZE 1400

#define INPUT_STREAM_TIMEOUT_SEC 10

#define MAX_QUEUED_INPUT_PACKETS 30 //tbd

#define PAYLOAD_SIZE(x) BE32((x)->packet.header.size)
#define PACKET_SIZE(x) (PAYLOAD_SIZE(x) + sizeof(uint32_t))


// This is much larger than we should typically have buffered, but
// it needs to be. We need a cushion in case our thread gets blocked
// for longer than normal.
#define RTP_RECV_BUFFER (64 * 1024)

// TBD: decide right value for it
int AudioCaptureFrameDuration = 10;//ms

//TODO: check how to handle these header at sunshine side
typedef struct _QUEUE_AUDIO_PACKET_HEADER {
    LINKED_BLOCKING_QUEUE_ENTRY lentry;
    int size;
} QUEUED_AUDIO_PACKET_HEADER, *PQUEUED_AUDIO_PACKET_HEADER;

typedef struct _QUEUED_AUDIO_PACKET {
    QUEUED_AUDIO_PACKET_HEADER header;
    char data[MAX_PACKET_SIZE];
} QUEUED_AUDIO_PACKET, *PQUEUED_AUDIO_PACKET;

// replace with some other shit
// Contains input stream packets
typedef struct _PACKET_HOLDER {
    LINKED_BLOCKING_QUEUE_ENTRY entry;
    uint32_t enetPacketFlags;
    uint8_t channelId;

    // The union must be the last member since we abuse the NV_UNICODE_PACKET
    // text field to store variable length data which gets split before being
    // sent to the host.
    union {
        NV_INPUT_HEADER header;
        NV_KEYBOARD_PACKET keyboard;
        NV_REL_MOUSE_MOVE_PACKET mouseMoveRel;
        NV_ABS_MOUSE_MOVE_PACKET mouseMoveAbs;
        NV_MOUSE_BUTTON_PACKET mouseButton;
        NV_CONTROLLER_PACKET controller;
        NV_MULTI_CONTROLLER_PACKET multiController;
        NV_SCROLL_PACKET scroll;
        SS_HSCROLL_PACKET hscroll;
        NV_HAPTICS_PACKET haptics;
        SS_TOUCH_PACKET touch;
        SS_PEN_PACKET pen;
        SS_CONTROLLER_ARRIVAL_PACKET controllerArrival;
        SS_CONTROLLER_TOUCH_PACKET controllerTouch;
        SS_CONTROLLER_MOTION_PACKET controllerMotion;
        SS_CONTROLLER_BATTERY_PACKET controllerBattery;
        NV_UNICODE_PACKET unicode;
    } packet;
} PACKET_HOLDER, *PPACKET_HOLDER;

typedef struct _AUDIO_PACKET_RAW {
    RTP_PACKET rtp;
    uint16_t payload[320];
} AUDIO_PACKET_RAW;

AUDIO_PACKET_RAW micRtpPacket;

int initializeAudioCaptureStream(void) {

    // TODO: Setup Queue and Crypto stuff for encryption
    // TODO: Multithread: init mutex if needed
    // TODO: enet

    ENetAddress address;
    ENetEvent event;

    enet_address_set_address(&address, (struct sockaddr *)&RemoteAddr, AddrLen);

    //TODO: micport setup
    //enet_address_set_port(&address, MicPortNumber);
    enet_address_set_port(&address, 48002);

    // Create a client
    ENetHost* client = enet_host_create( RemoteAddr.ss_family, NULL, 1, 1, 0, 0);
    if (client == NULL) {
        return -1;
    }

    // Connect to the host
    ENetPeer* peer = enet_host_connect(client, &address, 1, 0);
    if (peer == NULL) {
        enet_host_destroy(client);
        client = NULL;
        return -1;
    }

#define FLAG_EXTENSION 0x10

    //rtp test

    // TODO: change the buffer size
    //micRtpPacket.payload = malloc(sizeof(uint8_t)*2000);
    //memset(micRtpPacket.payload,5,sizeof(uint8_t)*80);

    micRtpPacket.rtp.header = 0x80;
    micRtpPacket.rtp.packetType = 101;
    micRtpPacket.rtp.ssrc = 0;
    micRtpPacket.rtp.sequenceNumber = BE16(0);
    micRtpPacket.rtp.timestamp = BE32(0);

    //send random rtp packets for 5 secs
    // for(int i =0; i<1000; ++i)
    // {
    //     ENetPacket * packet = enet_packet_create (&testPacket,
    //                                             sizeof(RTP_PACKET)+sizeof(uint8_t)*80,
    //                                             ENET_PACKET_FLAG_UNRELIABLE_FRAGMENT);
    //     int ret = enet_peer_send(peer, 0, packet);


    //     testPacket.rtp.timestamp+=80;
    //     testPacket.rtp.sequenceNumber++;
    // }

    // // Wait for the connect to complete
    // if (serviceEnetHost(client, &event, RTSP_CONNECT_TIMEOUT_SEC * 1000) <= 0 ||
    //     event.type != ENET_EVENT_TYPE_CONNECT) {
    //     Limelog("RTSP: Failed to connect to UDP port %u\n", RtspPortNumber);
    //     enet_peer_reset(peer);
    //     peer = NULL;
    //     enet_host_destroy(client);
    //     client = NULL;
    //     return -1;
    // }

    // Ensure the connect verify ACK is sent immediately
    enet_host_flush(client);


    //init socks

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
    serverAddrMic.sin_port = htons(48002);
    serverAddrMic.sin_addr.s_addr = inet_addr(RemoteAddrString);

    // Send message
    // for(int i =0; i<1000;i++)
    // {
    //     int sent_bytes = sendto(sockfd, (const char*)&testPacket, sizeof(RTP_PACKET)+sizeof(uint8_t)*80, 0, (struct sockaddr *) &server_addr, sizeof(server_addr));
    //     if (sent_bytes == SOCKET_ERROR) {
    //         printf("Failed to send message: %d\n", WSAGetLastError());
    //         closesocket(sockfd);
    //         WSACleanup();
    //         return 1;
    //     }
    //     testPacket.rtp.timestamp = BE32(testPacket.rtp.timestamp + 80);
    //     testPacket.rtp.sequenceNumber = BE32(testPacket.rtp.sequenceNumber + 1);
    // }

    // TODO: Close socket
    // closesocket(sockfd);
    // WSACleanup();


    return 0;
}

int notifyAudioCapturePortNegotiationComplete(void) {
    //TODO: Setup udp port here rather than during init
    //TODO: Check if SDP required during rtsp handshake for announcing audio stream?

    //TODO: Use ENet instead of platsocks
    // rtpSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen, 0);
    // if (rtpSocket == INVALID_SOCKET) {
    //     return LastSocketFail();
    // }

    return 0;
}


static PPACKET_HOLDER allocatePacketHolder(int extraLength){}

static void freePacketList(PLINKED_BLOCKING_QUEUE_ENTRY entry){}

static bool queuePacketToLbq(PQUEUED_AUDIO_PACKET* packet){}

void encodeInputData(char* packet){
    //     // If the packet size is zero, this is a placeholder for a missing
    //     // packet. Trigger packet loss concealment logic in libopus by
    //     // invoking the decoder with a NULL buffer.
    //     if (packet->header.size == 0) {
    //         AudioCallbacks.decodeAndPlaySample(NULL, 0);
    //         return;
    //     }

    //     PRTP_PACKET rtp = (PRTP_PACKET)&packet->data[0];
    //     if (lastSeq != 0 && (unsigned short)(lastSeq + 1) != rtp->sequenceNumber) {
    //         Limelog("Network dropped audio data (expected %d, but received %d)\n", lastSeq + 1, rtp->sequenceNumber);
    //     }

    //     lastSeq = rtp->sequenceNumber;

    //     if (AudioEncryptionEnabled) {
    //         // We must have room for the AES padding which may be written to the buffer
    //         unsigned char decryptedOpusData[ROUND_TO_PKCS7_PADDED_LEN(MAX_PACKET_SIZE)];
    //         unsigned char iv[16] = { 0 };
    //         int dataLength = packet->header.size - sizeof(*rtp);

    //         LC_ASSERT(dataLength <= MAX_PACKET_SIZE);

    //         // The IV is the avkeyid (equivalent to the rikeyid) +
    //         // the RTP sequence number, in big endian.
    //         uint32_t ivSeq = BE32(avRiKeyId + rtp->sequenceNumber);

    //         memcpy(iv, &ivSeq, sizeof(ivSeq));

    //         if (!PltDecryptMessage(audioDecryptionCtx, ALGORITHM_AES_CBC, CIPHER_FLAG_RESET_IV | CIPHER_FLAG_FINISH,
    //                                (unsigned char*)StreamConfig.remoteInputAesKey, sizeof(StreamConfig.remoteInputAesKey),
    //                                iv, sizeof(iv),
    //                                NULL, 0,
    //                                (unsigned char*)(rtp + 1), dataLength,
    //                                decryptedOpusData, &dataLength)) {
    //             Limelog("Failed to decrypt audio packet (sequence number: %u)\n", rtp->sequenceNumber);
    //             LC_ASSERT_VT(false);
    //             return;
    //         }

    // #ifdef LC_DEBUG
    //         if (opusHeaderByte == INVALID_OPUS_HEADER) {
    //             opusHeaderByte = decryptedOpusData[0];
    //             LC_ASSERT_VT(opusHeaderByte != INVALID_OPUS_HEADER);
    //         }
    //         else {
    //             // Opus header should stay constant for the entire stream.
    //             // If it doesn't, it may indicate that the RtpAudioQueue
    //             // incorrectly recovered a data shard or the decryption
    //             // of the audio packet failed. Sunshine violates this for
    //             // surround sound in some cases, so just ignore it.
    //             LC_ASSERT_VT(decryptedOpusData[0] == opusHeaderByte || IS_SUNSHINE());
    //         }
    // #endif

    //         AudioCallbacks.decodeAndPlaySample((char*)decryptedOpusData, dataLength);
    //     }
    //     else {
    // #ifdef LC_DEBUG
    //         if (opusHeaderByte == INVALID_OPUS_HEADER) {
    //             opusHeaderByte = ((uint8_t*)(rtp + 1))[0];
    //             LC_ASSERT_VT(opusHeaderByte != INVALID_OPUS_HEADER);
    //         }
    //         else {
    //             // Opus header should stay constant for the entire stream.
    //             // If it doesn't, it may indicate that the RtpAudioQueue
    //             // incorrectly recovered a data shard.
    //             LC_ASSERT_VT(((uint8_t*)(rtp + 1))[0] == opusHeaderByte);
    //         }
    // #endif

    //         AudioCallbacks.decodeAndPlaySample((char*)(rtp + 1), packet->header.size - sizeof(*rtp));
    //     }

}

static int encryptData(unsigned char* plaintext, int plaintextLen,
                       unsigned char* ciphertext, int* ciphertextLen){}


void generate_sine_wave(int16_t *buffer, int num_samples, double frequency) {
    for (int i = 0; i < num_samples; i++) {
        buffer[i] = (int16_t)(32767 * sin(2 * 3.141 * frequency * i / 16000));
    }
}


// Function to convert a 16-bit integer to big endian
uint16_t toBigEndian16(uint16_t value) {
    return (value >> 8) | (value << 8);
}
void convert_to_big_endian(uint32_t *buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        uint32_t value = buffer[i];
        buffer[i] = ((value & 0x000000FF) << 24) |
                    ((value & 0x0000FF00) << 8) |
                    ((value & 0x00FF0000) >> 8) |
                    ((value & 0xFF000000) >> 24);
    }
}

// Function to convert a whole buffer of 16-bit integers to big endian
void convertBufferToBigEndian(uint16_t* buffer, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        buffer[i] = toBigEndian16(buffer[i]);
    }
}

int timestamp = 0;
int seqNumber = 0;
static bool sendInputPacket(void* payload, int len){

    //convertBufferToBigEndian(payload, len);

    //convert_to_big_endian(payload, len);
    memcpy_s(&micRtpPacket.payload[0], 2000, payload, len );



    if(seqNumber % 200 == 0){
        Limelog("Encode Len: %d", len);
    }
    //TODO: setup right timestamps
    //micRtpPacket.rtp.timestamp += (160/(1000/90));
    //micRtpPacket.rtp.timestamp /= (1000/90);
    timestamp +=320*3;//framesize *3 * number of channel(2)
    seqNumber++;
    micRtpPacket.rtp.timestamp = BE32(timestamp);
    //micRtpPacket.rtp.timestamp = hto
    micRtpPacket.rtp.sequenceNumber = BE16(seqNumber);

    int sent_bytes = sendto(sockMic, (const char*)&micRtpPacket, sizeof(RTP_PACKET)+len, 0, (struct sockaddr *) &serverAddrMic, sizeof(serverAddrMic));
    //int sent_bytes = sendto(sockMic, payload,len,  0, (struct sockaddr *) &serverAddrMic, sizeof(serverAddrMic));
    if (sent_bytes == SOCKET_ERROR) {
        Limelog("Failed to send message: %d\n", WSAGetLastError());
        closesocket(sockMic);
        WSACleanup();
        return false;
    }

    //PltSleepMs(1);

    return true;
}

//this is static? tbd
// static void floatToNetfloat(float in, netfloat out){
//     if (IS_LITTLE_ENDIAN()) {
//         memcpy(out, &in, sizeof(in));
//     }
//     else {
//         uint8_t* inb = (uint8_t*)&in;
//         out[0] = inb[3];
//         out[1] = inb[2];
//         out[2] = inb[1];
//         out[3] = inb[0];
//     }
// }


void audioCaptureSendThreadProc(){

    while (!PltIsThreadInterrupted(&senderThread))
    {
        void* data = NULL;
        int len = 0;
        data = AudioCaptureCallbacks.getEncodedMicData(&len);

        if(data == NULL)
        {
            Limelog("Empty data from mic.");
            continue;
        }

        //decode test:

        //AudioCallbacks.decodeAndPlaySample(data, len);

        //Todo: check enet
        sendInputPacket(data, len);
    }


}

void audioEncodeThreadProc(){

    int i = 0;
    while(true)
    {
        PltSleepMs(2000);
        Limelog("AudioEncodeThread: %d", i);
        ++i;
    }
    // int err;
    // PQUEUED_AUDIO_PACKET packet;

    // while (!PltIsThreadInterrupted(&decoderThread)) {
    //     err = LbqWaitForQueueElement(&packetQueue, (void**)&packet);
    //     if (err != LBQ_SUCCESS) {
    //         // An exit signal was received
    //         return;
    //     }

    //     decodeInputData(packet);

    //     free(packet);
    // }
}


void destroyAudioCaptureStream(void){
    // if (rtpSocket != INVALID_SOCKET) {
    //     if (pingThreadStarted) {
    //         PltInterruptThread(&udpPingThread);
    //         PltJoinThread(&udpPingThread);
    //         PltCloseThread(&udpPingThread);
    //     }

    //     closeSocket(rtpSocket);
    //     rtpSocket = INVALID_SOCKET;
    // }

    // PltDestroyCryptoContext(audioDecryptionCtx);
    // freePacketList(LbqDestroyLinkedBlockingQueue(&packetQueue));
    // RtpaCleanupQueue(&rtpAudioQueue);
    // return;

    // PLINKED_BLOCKING_QUEUE_ENTRY entry, nextEntry;

    // PltDestroyCryptoContext(cryptoContext);

    // entry = LbqDestroyLinkedBlockingQueue(&packetQueue);

    // while (entry != NULL) {
    //     nextEntry = entry->flink;

    //     // The entry is stored in the data buffer
    //     free(entry->data);

    //     entry = nextEntry;
    // }

    // entry = LbqDestroyLinkedBlockingQueue(&packetHolderFreeList);

    // while (entry != NULL) {
    //     nextEntry = entry->flink;

    //     // The entry is stored in the data buffer
    //     free(entry->data);

    //     entry = nextEntry;
    // }

    // PltDeleteMutex(&batchedInputMutex);
}

int startAudioCaptureStream(void* audioCaptureContext, int arFlags)
{
    //AudioCaptureFrameDuration = 10;
    int err;
    OPUS_ENCODER_CONFIGURATION chosenConfig;
    chosenConfig.sampleRate = 16000;
    chosenConfig.channelCount = 1;
    chosenConfig.samplesPerFrame = (chosenConfig.sampleRate/1000) * AudioCaptureFrameDuration;
    chosenConfig.Application = OPUS_APPLICATION_VOIP;//TODO: check quality

    err = AudioCaptureCallbacks.init(StreamConfig.audioConfiguration, &chosenConfig, audioCaptureContext, arFlags);
    if (err != 0) {
        return err;
    }

    AudioCaptureCallbacks.start();

    err = PltCreateThread("AudioCapSend", audioCaptureSendThreadProc, NULL, &senderThread);
    if (err != 0) {
        AudioCaptureCallbacks.stop();
        //closeSocket(rtpSocket);
        AudioCaptureCallbacks.cleanup();
        return err;
    }


    // //TODO: Decode in seperate thread
    // if ((AudioCaptureCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
    //     err = PltCreateThread("AudioDec", audiodecodeThreadProc, NULL, &encoderThread);
    //     if (err != 0) {
    //         AudioCaptureCallbacks.stop();
    //         PltInterruptThread(&senderThread);
    //         PltJoinThread(&senderThread);
    //         PltCloseThread(&senderThread);
    //         closeSocket(rtpSocket);
    //         AudioCallbacks.cleanup();
    //         return err;
    //     }
    // }

    return 0;
}

void stopAudioCaptureStream(void)
{
    // if (!receivedDataFromPeer) {
    //     Limelog("No audio traffic was ever received from the host!\n");
    // }

    // AudioCallbacks.stop();

    // PltInterruptThread(&receiveThread);
    // if ((AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
    //     // Signal threads waiting on the LBQ
    //     LbqSignalQueueShutdown(&packetQueue);
    //     PltInterruptThread(&decoderThread);
    // }

    // PltJoinThread(&receiveThread);
    // if ((AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
    //     PltJoinThread(&decoderThread);
    // }

    // PltCloseThread(&receiveThread);
    // if ((AudioCallbacks.capabilities & CAPABILITY_DIRECT_SUBMIT) == 0) {
    //     PltCloseThread(&decoderThread);
    // }

    // AudioCallbacks.cleanup();
    // return;

    // // No more packets should be queued now
    // initialized = false;
    // LbqSignalQueueShutdown(&packetHolderFreeList);

    // // Signal the input send thread to drain all pending
    // // input packets before shutting down.
    // LbqSignalQueueDrain(&packetQueue);
    // PltJoinThread(&inputSendThread);
    // PltCloseThread(&inputSendThread);

    // if (inputSock != INVALID_SOCKET) {
    //     shutdownTcpSocket(inputSock);
    // }

    // if (inputSock != INVALID_SOCKET) {
    //     closeSocket(inputSock);
    //     inputSock = INVALID_SOCKET;
    // }

    return;
}




// int LiGetPendingAudioFrames(void){}

// int LiGetPendingAudioDuration(void){}

// TODO: Expose required function to c++
