#include "Limelight-internal.h"
#include <opus_defines.h>
#include <opus.h>
#include <stdbool.h>

#define AUDIO_CAPTURE_FRAME_DURATION 10

#define FREQ 48000
#define FRAME_SAMPLE_COUNT AUDIO_CAPTURE_FRAME_DURATION *(FREQ / 1000)
#define m_FrameSize FRAME_SAMPLE_COUNT * sizeof(short);

static bool isMicToggled = false;

int initializeAudioCaptureStream(void)
{
    return 0;
}

int notifyAudioCapturePortNegotiationComplete(void)
{
    // TODO: setup the udp ports here
    return 0;
}

static bool IsAudioCaptureStarted;
extern struct sockaddr_storage RemoteAddr;
extern uint16_t AudioPortNumber;
static int rtpSocket = 0;
static unsigned char outFrame[1024];
LC_SOCKADDR saddr;

void PushAudio(uint16_t* CapturedFrame, int len){
    if(!IsAudioCaptureStarted){
        Limelog("Error: Audio Capture not Started!");
        return;
    }
    int outLen = opus_encode(m_OpusEncoder,
                          (opus_int16*)CapturedFrame,
                          FRAME_SAMPLE_COUNT, // TBD: less than 10 ms will disable LPC or hybrid modes
                          (unsigned char*)outFrame,
                          FRAME_SAMPLE_COUNT //adjust this to set upper limit on bitrate
                          );

        if (outLen < 0)
        {
            Limelog("Encoding error: &d", outLen);
        }

        if(rtpSocket == 0) return;
        sendto(rtpSocket, (char *)&outFrame, outLen, 0, (struct sockaddr *)&saddr, AddrLen);
}

void destroyAudioCaptureStream(void)
{

}

void SetAudioCaptureStreamSocket(int rtpsocket){
    rtpSocket = rtpsocket;
}

OpusEncoder* m_OpusEncoder;
int startAudioCaptureStream(void *audioCaptureContext, int rtpsocket)
{
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

    m_OpusEncoder = opus_encoder_create(
         chosenConfig.sampleRate,
         chosenConfig.channelCount,
         chosenConfig.Application,
        &err);

    if(m_OpusEncoder == NULL){
        Limelog("Failed to create MIC encoder: %d", err);
        return err;
    }

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, AudioPortNumber);

    IsAudioCaptureStarted = true;

    // Prepare to start capturing here
    AudioCaptureCallbacks.start();

    return 0;
}

void stopAudioCaptureStream(void)
{
    AudioCaptureCallbacks.stop();

    if(m_OpusEncoder != NULL){
        opus_encoder_destroy(m_OpusEncoder);
        m_OpusEncoder = NULL;
    }
    
    AudioCaptureCallbacks.cleanup();
    IsAudioCaptureStarted = false;
}

int LiSendMicToggleEvent(bool isMuted)
{
    char *data = isMuted ? "Mute" : "UnMute";

    if (sendMicStatusPacketOnControlStream((unsigned char *)data, strlen(data)) == -1)
    {
        Limelog("Error sending Mic Status on Control Stream.");
        return -1;
    }

    return 0;
}