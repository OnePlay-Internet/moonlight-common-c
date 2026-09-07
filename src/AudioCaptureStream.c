#include "Limelight-internal.h"
#include <opus_defines.h>
#include <opus.h>
#include <stdbool.h>

static bool captureThreadStarted;
static PLT_THREAD captureThread;

#define AUDIO_CAPTURE_FRAME_DURATION 10

#define FREQ 48000
#define FRAME_SAMPLE_COUNT AUDIO_CAPTURE_FRAME_DURATION *(FREQ / 1000)

static bool isMicToggled = false;
static PLT_MUTEX isMicToggled_MTX;
static PLT_COND isMicToggled_MTX_COND;

int initializeAudioCaptureStream(void)
{
    PltCreateMutex(&isMicToggled_MTX);
    PltCreateConditionVariable(&isMicToggled_MTX_COND, &isMicToggled_MTX);

    return 0;
}

int notifyAudioCapturePortNegotiationComplete(void)
{
    // TODO: setup the udp ports here
    return 0;
}

extern struct sockaddr_storage RemoteAddr;
extern uint16_t AudioPortNumber;
static int rtpSocket = 0;

void audioCaptureThreadProc(void *context)
{
    Limelog("Audio Capture Thread Started");

    isMicToggled = true;
    uint16_t CapturedFrame[FRAME_SAMPLE_COUNT * 100];
    uint32_t len = 0;

    unsigned char outFrame[1024];
    int encoded_len = 0;
    LC_SOCKADDR saddr;

    LC_ASSERT(AudioPortNumber != 0);

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, AudioPortNumber);

    PltLockMutex(&isMicToggled_MTX);
    if(rtpSocket == 0){
        PltWaitForConditionVariable(&isMicToggled_MTX_COND, &isMicToggled_MTX);
    }
    PltUnlockMutex(&isMicToggled_MTX);

    while (!PltIsThreadInterrupted(&captureThread))
    {
        PltLockMutex(&isMicToggled_MTX);
        if(!isMicToggled){
            PltWaitForConditionVariable(&isMicToggled_MTX_COND, &isMicToggled_MTX);
        }
        PltUnlockMutex(&isMicToggled_MTX);

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

        if(rtpSocket == 0) break;
        sendto(rtpSocket, (char *)&outFrame, encoded_len, 0, (struct sockaddr *)&saddr, AddrLen);
    }
}

void destroyAudioCaptureStream(void)
{
    PltDeleteMutex(&isMicToggled_MTX);
    PltDeleteConditionVariable(&isMicToggled_MTX_COND);
}

void SetAudioCaptureStreamSocket(int rtpsocket){
    if(rtpsocket == 0){
        rtpSocket = rtpsocket;
    }else{
        rtpSocket = rtpsocket;
    }
}

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

    // Owais: This doesn't do anything but we will keep it just in case
    AudioCaptureCallbacks.start();

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
    AudioCaptureCallbacks.stop();

    PltLockMutex(&isMicToggled_MTX);
    if(!isMicToggled){
        PltSignalConditionVariable(&isMicToggled_MTX_COND);
    }
    PltUnlockMutex(&isMicToggled_MTX);

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

    AudioCaptureCallbacks.cleanup();
}

int LiSendMicToggleEvent(bool isMuted)
{
    char *data = isMuted ? "Mute" : "UnMute";

    if (sendMicStatusPacketOnControlStream((unsigned char *)data, strlen(data)) == -1)
    {
        Limelog("Error sending Mic Status on Control Stream.");
        return -1;
    }

    PltLockMutex(&isMicToggled_MTX);
    isMicToggled = !isMuted;
    if(isMicToggled){
        PltSignalConditionVariable(&isMicToggled_MTX_COND);
    }
    PltUnlockMutex(&isMicToggled_MTX);
    return 0;
}
// int LiGetPendingAudioFrames(void){}

// int LiGetPendingAudioDuration(void){}

// TODO: Expose required functions to c++
