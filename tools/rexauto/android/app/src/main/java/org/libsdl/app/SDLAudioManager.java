package org.libsdl.app;

import android.content.Context;
import android.media.AudioDeviceCallback;
import android.media.AudioDeviceInfo;
import android.media.AudioManager;
import android.os.Build;
import android.util.Log;

import java.util.Arrays;
import java.util.ArrayList;

class SDLAudioManager {
    protected static final String TAG = "SDLAudio";

    protected static Context mContext;

    private static AudioDeviceCallback mAudioDeviceCallback;

    static void initialize() {
        mAudioDeviceCallback = null;

        if(Build.VERSION.SDK_INT >= 24 /* Android 7.0 (N) */)
        {
            mAudioDeviceCallback = new AudioDeviceCallback() {
                @Override
                public void onAudioDevicesAdded(AudioDeviceInfo[] addedDevices) {
                    for (AudioDeviceInfo deviceInfo : addedDevices) {
                        nativeAddAudioDevice(deviceInfo.isSink(), productName(deviceInfo), deviceInfo.getId());
                    }
                }

                @Override
                public void onAudioDevicesRemoved(AudioDeviceInfo[] removedDevices) {
                    for (AudioDeviceInfo deviceInfo : removedDevices) {
                        nativeRemoveAudioDevice(deviceInfo.isSink(), deviceInfo.getId());
                    }
                }
            };
        }
    }

    static void setContext(Context context) {
        mContext = context;
    }

    static void release(Context context) {
        // no-op atm
    }

    // Audio

    // (Hunt v1.4.6 ronda 12, A4-R12-02.) getProductName() is nullable:
    // the HAL reports no product name for some devices, and the old code
    // called .toString() on it at all three nativeAddAudioDevice sites
    // below — NPE on the main thread (the AudioDeviceCallback runs on the
    // main looper: registered with a null Handler) when such a device was
    // enumerated or hot-plugged. The native side only uses the name for
    // display, so "" is a safe stand-in. Upstream SDL3 has the same
    // unguarded calls; this is a local divergence.
    private static String productName(AudioDeviceInfo deviceInfo) {
        CharSequence name = deviceInfo.getProductName();
        return name == null ? "" : name.toString();
    }

    private static AudioDeviceInfo getInputAudioDeviceInfo(int deviceId) {
        if (Build.VERSION.SDK_INT >= 24 /* Android 7.0 (N) */) {
            AudioManager audioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            for (AudioDeviceInfo deviceInfo : audioManager.getDevices(AudioManager.GET_DEVICES_INPUTS)) {
                if (deviceInfo.getId() == deviceId) {
                    return deviceInfo;
                }
            }
        }
        return null;
    }

    private static AudioDeviceInfo getPlaybackAudioDeviceInfo(int deviceId) {
        if (Build.VERSION.SDK_INT >= 24 /* Android 7.0 (N) */) {
            AudioManager audioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            for (AudioDeviceInfo deviceInfo : audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
                if (deviceInfo.getId() == deviceId) {
                    return deviceInfo;
                }
            }
        }
        return null;
    }

    static void registerAudioDeviceCallback() {
        if (Build.VERSION.SDK_INT >= 24 /* Android 7.0 (N) */) {
            AudioManager audioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            // get an initial list now, before hotplug callbacks fire.
            for (AudioDeviceInfo dev : audioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS)) {
                if (dev.getType() == AudioDeviceInfo.TYPE_TELEPHONY) {
                    continue;  // Device cannot be opened
                }
                nativeAddAudioDevice(dev.isSink(), productName(dev), dev.getId());
            }
            for (AudioDeviceInfo dev : audioManager.getDevices(AudioManager.GET_DEVICES_INPUTS)) {
                nativeAddAudioDevice(dev.isSink(), productName(dev), dev.getId());
            }
            audioManager.registerAudioDeviceCallback(mAudioDeviceCallback, null);
        }
    }

    static void unregisterAudioDeviceCallback() {
        if (Build.VERSION.SDK_INT >= 24 /* Android 7.0 (N) */) {
            AudioManager audioManager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
            audioManager.unregisterAudioDeviceCallback(mAudioDeviceCallback);
        }
    }

    /** This method is called by SDL using JNI. */
    static void audioSetThreadPriority(boolean recording, int device_id) {
        try {

            /* Set thread name */
            if (recording) {
                Thread.currentThread().setName("SDLAudioC" + device_id);
            } else {
                Thread.currentThread().setName("SDLAudioP" + device_id);
            }

            /* Set thread priority */
            android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_AUDIO);

        } catch (Exception e) {
            Log.v(TAG, "modify thread properties failed " + e.toString());
        }
    }

    static native void nativeSetupJNI();

    static native void nativeRemoveAudioDevice(boolean recording, int deviceId);

    static native void nativeAddAudioDevice(boolean recording, String name, int deviceId);

}
