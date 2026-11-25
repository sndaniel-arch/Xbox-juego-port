package org.libsdl.app;

import android.content.Context;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothGattService;
import android.hardware.usb.UsbDevice;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.os.*;

//import com.android.internal.util.HexDump;

import java.lang.Runnable;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.LinkedList;
import java.util.UUID;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

class HIDDeviceBLESteamController extends BluetoothGattCallback implements HIDDevice {

    private static final String TAG = "hidapi";
    private HIDDeviceManager mManager;
    private BluetoothDevice mDevice;
    private int mDeviceId;
    private BluetoothGatt mGatt;
    private boolean mIsRegistered = false;
    private boolean mIsConnected = false;
    private boolean mIsChromebook = false;
    private boolean mIsReconnecting = false;
    private boolean mFrozen = false;
    private LinkedList<GattOperation> mOperations;
    GattOperation mCurrentOperation = null;
    private Handler mHandler;
    private int mProductId = -1;
    // (Hunt v1.4.6 ronda 9, A4-R9-05.) Consecutive failed service
    // discoveries on the current connection. Reset on connect and on any
    // successful discovery, so a later failure starts fresh.
    private int mServiceDiscoveryAttempts = 0;
    // (Hunt v1.4.6 ronda 9, A4-R9-04.) A D0G Valve-mode write issued
    // directly from onDescriptorWrite is outstanding. Its completion
    // arrives at onCharacteristicWrite too, but it is not a queued op (it
    // is the trigger that registers a D0G controller). Set only when the
    // write was actually issued (writeCharacteristic returned true);
    // cleared by its completion, on disconnect, and on shutdown.
    private boolean mDirectWritePending = false;

    private static final int D0G_BLE2_PID = 0x1106;
    private static final int TRITON_BLE_PID = 0x1303;


    private static final int TRANSPORT_AUTO = 0;
    private static final int TRANSPORT_BREDR = 1;
    private static final int TRANSPORT_LE = 2;

    private static final int CHROMEBOOK_CONNECTION_CHECK_INTERVAL = 10000;

    // (Hunt v1.4.6 ronda 9, A4-R9-04.) A GATT op is attempted at most this
    // many times in total; after that it is dropped so one dead op can
    // never wedge the queue. The old code re-enqueued a failed op at the
    // front with no limit -- and, worse, only from the GATT callbacks, so
    // a synchronously failing op never completed at all.
    private static final int MAX_GATT_OPERATION_ATTEMPTS = 3;

    // (Hunt v1.4.6 ronda 9, A4-R9-05.) Service-discovery retries on
    // status != 0 (the classic GATT 133, common on reconnects after a
    // Bluetooth toggle), with linear backoff; after the last attempt the
    // connection is dropped and re-established.
    private static final int MAX_SERVICE_DISCOVERY_ATTEMPTS = 3;
    private static final int SERVICE_DISCOVERY_RETRY_DELAY_MS = 500;

    static final UUID steamControllerService = UUID.fromString("100F6C32-1735-4313-B402-38567131E5F3");
    static final UUID inputCharacteristicD0G = UUID.fromString("100F6C33-1735-4313-B402-38567131E5F3");
    static final UUID inputCharacteristicTriton = UUID.fromString("100F6C7A-1735-4313-B402-38567131E5F3");
    static final UUID reportCharacteristic = UUID.fromString("100F6C34-1735-4313-B402-38567131E5F3");
    static private final byte[] enterValveMode = new byte[] { (byte)0xC0, (byte)0x87, 0x03, 0x08, 0x07, 0x00 };

    // (Hunt v1.4.6 ronda 20, A4-R20-03.) ConcurrentHashMap, not HashMap:
    // probeService() put()s into this map from the binder thread
    // (onServicesDiscovered) and the main thread
    // (checkConnectionForChromebookIssue), while writeReport() get()s from
    // the SDL thread -- a plain HashMap is not safe for concurrent
    // put/get. Only put/get are used (no iteration), so the swap is
    // behavior-identical apart from the thread safety.
    private ConcurrentHashMap<Integer, BluetoothGattCharacteristic> mOutputReportChars = new ConcurrentHashMap<Integer, BluetoothGattCharacteristic>();

    static class GattOperation {
        private enum Operation {
            CHR_READ,
            CHR_WRITE,
            ENABLE_NOTIFICATION
        }

        Operation mOp;
        UUID mUuid;
        byte[] mValue;
        BluetoothGatt mGatt;
        boolean mResult = true;
        // (Hunt v1.4.6 ronda 9, A4-R9-04.) Attempts spent on this op, counted
        // in run(): the queue drops an op after MAX_GATT_OPERATION_ATTEMPTS
        // tries instead of re-enqueueing it at the front forever.
        int mAttempts = 0;

        private GattOperation(BluetoothGatt gatt, GattOperation.Operation operation, UUID uuid) {
            mGatt = gatt;
            mOp = operation;
            mUuid = uuid;
        }

        private GattOperation(BluetoothGatt gatt, GattOperation.Operation operation, UUID uuid, byte[] value) {
            mGatt = gatt;
            mOp = operation;
            mUuid = uuid;
            mValue = value;
        }

        public void run() {
            // This is executed in main thread
            BluetoothGattCharacteristic chr;
            mAttempts++;

            switch (mOp) {
                case CHR_READ:
                    chr = getCharacteristic(mUuid);
                    //Log.v(TAG, "Reading characteristic " + chr.getUuid());
                    if (chr == null) {
                        // (Hunt v1.4.6 ronda 9, A4-R9-03.) The service may
                        // not be discovered yet on a fresh GATT after
                        // reconnect(): fail the op instead of passing null
                        // to readCharacteristic() -- no callback ever
                        // arrives for it (see A4-R9-04), so a null here
                        // used to wedge the whole queue.
                        Log.e(TAG, "Unable to read characteristic " + mUuid.toString() + ": service not discovered");
                        mResult = false;
                        break;
                    }
                    if (!mGatt.readCharacteristic(chr)) {
                        Log.e(TAG, "Unable to read characteristic " + mUuid.toString());
                        mResult = false;
                        break;
                    }
                    mResult = true;
                    break;
                case CHR_WRITE:
                    chr = getCharacteristic(mUuid);
                    //Log.v(TAG, "Writing characteristic " + chr.getUuid() + " value=" + HexDump.toHexString(value));
                    if (chr == null) {
                        // (Hunt v1.4.6 ronda 9, A4-R9-03.) As CHR_READ: a
                        // null characteristic here used to NPE in
                        // chr.setValue() on the main thread (and
                        // writeCharacteristic(null) throws
                        // IllegalArgumentException per the Android docs).
                        Log.e(TAG, "Unable to write characteristic " + mUuid.toString() + ": service not discovered");
                        mResult = false;
                        break;
                    }
                    chr.setValue(mValue);
                    if (!mGatt.writeCharacteristic(chr)) {
                        Log.e(TAG, "Unable to write characteristic " + mUuid.toString());
                        mResult = false;
                        break;
                    }
                    mResult = true;
                    break;
                case ENABLE_NOTIFICATION:
                    chr = getCharacteristic(mUuid);
                    //Log.v(TAG, "Writing descriptor of " + chr.getUuid());
                    if (chr != null) {
                        BluetoothGattDescriptor cccd = chr.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"));
                        if (cccd != null) {
                            int properties = chr.getProperties();
                            byte[] value;
                            if ((properties & BluetoothGattCharacteristic.PROPERTY_NOTIFY) == BluetoothGattCharacteristic.PROPERTY_NOTIFY) {
                                value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE;
                            } else if ((properties & BluetoothGattCharacteristic.PROPERTY_INDICATE) == BluetoothGattCharacteristic.PROPERTY_INDICATE) {
                                value = BluetoothGattDescriptor.ENABLE_INDICATION_VALUE;
                            } else {
                                Log.e(TAG, "Unable to start notifications on input characteristic");
                                mResult = false;
                                return;
                            }

                            mGatt.setCharacteristicNotification(chr, true);
                            cccd.setValue(value);
                            if (!mGatt.writeDescriptor(cccd)) {
                                Log.e(TAG, "Unable to write descriptor " + mUuid.toString());
                                mResult = false;
                                return;
                            }
                            mResult = true;
                        } else {
                            // (Hunt v1.4.6 ronda 9, A4-R9-03/04.) No CCCD,
                            // no descriptor write, no callback: the op must
                            // fail here or the queue wedges waiting for a
                            // callback that never arrives.
                            Log.e(TAG, "Unable to start notifications on " + mUuid.toString() + ": no CCCD");
                            mResult = false;
                        }
                    } else {
                        // (Hunt v1.4.6 ronda 9, A4-R9-03/04.) As CHR_READ:
                        // the service may not be discovered yet on a fresh
                        // GATT after reconnect(). This branch used to fall
                        // through with mResult still true and no callback.
                        Log.e(TAG, "Unable to start notifications on " + mUuid.toString() + ": service not discovered");
                        mResult = false;
                    }
            }
        }

        public boolean finish() {
            return mResult;
        }

        private BluetoothGattCharacteristic getCharacteristic(UUID uuid) {
            BluetoothGattService valveService = mGatt.getService(steamControllerService);
            if (valveService == null)
                return null;
            return valveService.getCharacteristic(uuid);
        }

        static public GattOperation readCharacteristic(BluetoothGatt gatt, UUID uuid) {
            return new GattOperation(gatt, Operation.CHR_READ, uuid);
        }

        static public GattOperation writeCharacteristic(BluetoothGatt gatt, UUID uuid, byte[] value) {
            return new GattOperation(gatt, Operation.CHR_WRITE, uuid, value);
        }

        static public GattOperation enableNotification(BluetoothGatt gatt, UUID uuid) {
            return new GattOperation(gatt, Operation.ENABLE_NOTIFICATION, uuid);
        }
    }

    HIDDeviceBLESteamController(HIDDeviceManager manager, BluetoothDevice device) {
        mManager = manager;
        mDevice = device;
        mDeviceId = mManager.getDeviceIDForIdentifier(getIdentifier());
        mIsRegistered = false;
        mIsChromebook = SDLActivity.isChromebook();
        mOperations = new LinkedList<GattOperation>();
        mHandler = new Handler(Looper.getMainLooper());

        mGatt = connectGatt();
        // (Hunt v1.4.6 ronda 19, A4-R19-04.) Same dead loop as the
        // manager's chromebookConnectionHandler: the initial post was
        // commented out, so checkConnectionForChromebookIssue (which only
        // re-arms itself) never ran -- on a Chromebook a controller whose
        // GATT connects without callbacks is never recovered. Re-enable
        // it for Chromebooks only; shutdown() already cancels all Handler
        // work (removeCallbacksAndMessages), so the loop stops when the
        // device is shut down.
        if (mIsChromebook) {
            final HIDDeviceBLESteamController finalThis = this;
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    finalThis.checkConnectionForChromebookIssue();
                }
            }, CHROMEBOOK_CONNECTION_CHECK_INTERVAL);
        }
    }

    String getIdentifier() {
        return String.format("SteamController.%s", mDevice.getAddress());
    }

    BluetoothGatt getGatt() {
        return mGatt;
    }

    // Because on Chromebooks we show up as a dual-mode device, it will attempt to connect TRANSPORT_AUTO, which will use TRANSPORT_BREDR instead
    // of TRANSPORT_LE.  Let's force ourselves to connect low energy.
    private BluetoothGatt connectGatt(boolean managed) {
        if (Build.VERSION.SDK_INT >= 23 /* Android 6.0 (M) */) {
            try {
                return mDevice.connectGatt(mManager.getContext(), managed, this, TRANSPORT_LE);
            } catch (Exception e) {
                return mDevice.connectGatt(mManager.getContext(), managed, this);
            }
        } else {
            return mDevice.connectGatt(mManager.getContext(), managed, this);
        }
    }

    private BluetoothGatt connectGatt() {
        return connectGatt(false);
    }

    protected int getConnectionState() {

        Context context = mManager.getContext();
        if (context == null) {
            // We are lacking any context to get our Bluetooth information.  We'll just assume disconnected.
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        BluetoothManager btManager = (BluetoothManager)context.getSystemService(Context.BLUETOOTH_SERVICE);
        if (btManager == null) {
            // This device doesn't support Bluetooth.  We should never be here, because how did
            // we instantiate a device to start with?
            return BluetoothProfile.STATE_DISCONNECTED;
        }

        return btManager.getConnectionState(mDevice, BluetoothProfile.GATT);
    }

    // (Hunt v1.4.6 ronda 13, A4-R13-02.) Retire the current GATT before
    // replacing it: disconnect() alone does NOT release the client
    // interface -- every connectGatt() needs a matching close(), and the
    // pool is ~30 for the whole phone (GATT_MAX_APPS 32, two used
    // internally). The old code disconnected the old GATT and dropped the
    // reference, leaking one clientIf per reconnect; after ~30 the stack
    // refuses new connections with GATT 133, phone-wide, until Bluetooth
    // restarts. Closing the old GATT also suppresses its disconnect
    // callback, so the state reset that callback used to do (clear the
    // registered/connected flags, drop the in-flight op) is done here:
    // without it the new GATT would inherit a stale "registered" state
    // and probeService() would skip re-registering it.
    private void replaceGatt() {
        BluetoothGatt old = mGatt;
        mIsRegistered = false;
        mIsConnected = false;
        mDirectWritePending = false;
        dropCurrentGattOperation();
        if (old != null) {
            old.disconnect();
            old.close();
        }
        mGatt = connectGatt(false);
    }

    void reconnect() {

        if (getConnectionState() != BluetoothProfile.STATE_CONNECTED) {
            // (Hunt v1.4.6 ronda 13, A4-R13-01.) connectGatt() can return
            // null (AOSP: IBluetoothGatt null, or RemoteException): the
            // constructor stores it unchecked, so a null first connect
            // NPE'd on the mGatt.disconnect() below the next time this
            // ran for the same device (ACL_CONNECTED after the service
            // came back). Re-attempt the connect instead of disconnecting
            // a null GATT; if it is still null there is nothing to
            // disconnect and the next ACL_CONNECTED retries.
            if (mGatt == null) {
                mGatt = connectGatt();
                return;
            }
            replaceGatt();
        }

    }

    protected void checkConnectionForChromebookIssue() {
        if (!mIsChromebook) {
            // We only do this on Chromebooks, because otherwise it's really annoying to just attempt
            // over and over.
            return;
        }

        // (Hunt v1.4.6 ronda 19, A4-R19-04.) connectGatt() can return null
        // (A4-R13-01): every branch below dereferences mGatt. Without a
        // GATT there is nothing to check, but keep the loop alive -- a
        // reconnect may have one by the next tick.
        if (mGatt == null) {
            rearmChromebookCheck();
            return;
        }

        int connectionState = getConnectionState();

        switch (connectionState) {
            case BluetoothProfile.STATE_CONNECTED:
                if (!mIsConnected) {
                    // We are in the Bad Chromebook Place.  We can force a disconnect
                    // to try to recover.
                    Log.v(TAG, "Chromebook: We are in a very bad state; the controller shows as connected in the underlying Bluetooth layer, but we never received a callback.  Forcing a reconnect.");
                    mIsReconnecting = true;
                    // (Hunt v1.4.6 ronda 20, A4-R20-02.) replaceGatt()
                    // disconnects AND closes: the bare disconnect +
                    // connectGatt here leaked a GATT clientIf per tick.
                    replaceGatt();
                    break;
                }
                else if (!isRegistered()) {
                    if (mGatt.getServices().size() > 0) {
                        Log.v(TAG, "Chromebook: We are connected to a controller, but never got our registration.  Trying to recover.");
                        probeService(this);
                    }
                    else {
                        Log.v(TAG, "Chromebook: We are connected to a controller, but never discovered services.  Trying to recover.");
                        mIsReconnecting = true;
                        // (Hunt v1.4.6 ronda 20, A4-R20-02.) replaceGatt()
                        // disconnects AND closes: the bare disconnect +
                        // connectGatt here leaked a GATT clientIf per tick.
                        replaceGatt();
                        break;
                    }
                }
                else {
                    Log.v(TAG, "Chromebook: We are connected, and registered.  Everything's good!");
                    return;
                }
                break;

            case BluetoothProfile.STATE_DISCONNECTED:
                Log.v(TAG, "Chromebook: We have either been disconnected, or the Chromebook BtGatt.ContextMap bug has bitten us.  Attempting a disconnect/reconnect, but we may not be able to recover.");

                mIsReconnecting = true;
                // (Hunt v1.4.6 ronda 20, A4-R20-02.) replaceGatt()
                // disconnects AND closes: the bare disconnect +
                // connectGatt here leaked a GATT clientIf per tick.
                replaceGatt();
                break;

            case BluetoothProfile.STATE_CONNECTING:
                Log.v(TAG, "Chromebook: We're still trying to connect.  Waiting a bit longer.");
                break;
        }

        rearmChromebookCheck();
    }

    // (Hunt v1.4.6 ronda 19, A4-R19-04.) One re-arm point for the
    // Chromebook loop, so the null-GATT path above and the normal path
    // schedule the same next tick. shutdown() cancels all Handler work,
    // so the loop stops when the device is shut down.
    private void rearmChromebookCheck() {
        // (Hunt v1.4.6 ronda 19, A4-R19-04b, PADRE.) mManager solo lo nullea
        // shutdown() (los callbacks lo usan ya como señal de apagado):
        // un tick en vuelo cuando shutdown() corre rearmaria el loop
        // DESPUES de que shutdown() cancelara el trabajo del Handler, y
        // el camino mGatt == null lo seguiria rearmando cada 10 s para
        // siempre (mGatt queda en null; nada reconecta un dispositivo
        // apagado). Misma clase que la guarda del manager en A4-R19-04
        // (mHandler null); el lado BLE no nullea mHandler, asi que la
        // señal de apagado aqui es mManager == null.
        if (mManager == null) {
            return;
        }
        final HIDDeviceBLESteamController finalThis = this;
        mHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                finalThis.checkConnectionForChromebookIssue();
            }
        }, CHROMEBOOK_CONNECTION_CHECK_INTERVAL);
    }

    private boolean isRegistered() {
        return mIsRegistered;
    }

    private void setRegistered() {
        mIsRegistered = true;
    }

    private boolean probeService(HIDDeviceBLESteamController controller) {

        if (isRegistered()) {
            return true;
        }

        if (!mIsConnected) {
            return false;
        }

        // (Hunt v1.4.6 ronda 19, A4-R19-05.) Capture the GATT: shutdown()
        // (main thread) nulls mGatt while this runs on a binder thread
        // (onServicesDiscovered) or the SDL thread (writeReport), and the
        // mManager == null guard in the callbacks is not atomic with this
        // use -- a shutdown in between NPE'd on mGatt.getServices(). A
        // stale-but-non-null local can at worst probe a closed GATT
        // (getServices() is empty there); registration itself is still
        // guarded by the mManager == null checks in the callbacks.
        BluetoothGatt gatt = mGatt;
        if (gatt == null) {
            return false;
        }

        Log.v(TAG, "probeService controller=" + controller);

        for (BluetoothGattService service : gatt.getServices()) {
            if (service.getUuid().equals(steamControllerService)) {
                Log.v(TAG, "Found Valve steam controller service " + service.getUuid());

                for (BluetoothGattCharacteristic chr : service.getCharacteristics()) {
                    boolean bShouldStartNotifications = false;

                    if (chr.getUuid().equals(inputCharacteristicTriton)) {
                        Log.v(TAG, "Found Triton input characteristic");
                        mProductId = TRITON_BLE_PID;
                        bShouldStartNotifications = true;
                    } else if (chr.getUuid().equals(inputCharacteristicD0G)) {
                        Log.v(TAG, "Found D0G input characteristic");
                        mProductId = D0G_BLE2_PID;
                        bShouldStartNotifications = true;
                    } else {
                        Pattern reportPattern = Pattern.compile("100F6C([0-9A-Z]{2})", Pattern.CASE_INSENSITIVE);
                        Matcher matcher = reportPattern.matcher(chr.getUuid().toString());

                        if (matcher.find()) {
                            try {
                                int reportId = Integer.parseInt(matcher.group(1), 16);

                                reportId -= 0x35;
                                if (reportId >= 0x80) {
                                    // This is a Triton output report characteristic that we need to care about.
                                    Log.v(TAG, "Found Triton output report 0x" + Integer.toString(reportId, 16));
                                    mOutputReportChars.put(reportId, chr);
                                }
                            }
                            catch (NumberFormatException nfe) {
                                Log.w(TAG, "Could not parse report characteristic " + chr.getUuid().toString() + ": " + nfe.toString());
                            }
                        }
                    }

                    if (bShouldStartNotifications) {
                        // Start notifications
                        BluetoothGattDescriptor cccd = chr.getDescriptor(UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"));
                        if (cccd != null) {
                            enableNotification(chr.getUuid());
                        }
                    }
                }
                return true;
            }
        }

        if ((gatt.getServices().size() == 0) && mIsChromebook && !mIsReconnecting) {
            Log.e(TAG, "Chromebook: Discovered services were empty; this almost certainly means the BtGatt.ContextMap bug has bitten us.");
            mIsConnected = false;
            mIsReconnecting = true;
            // (Hunt v1.4.6 ronda 13, A4-R13-02.) Same replaceGatt() as
            // reconnect()/onServicesDiscovered: the old disconnect() +
            // connectGatt() here abandoned the old GATT without close().
            replaceGatt();
        }

        return false;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * Marks the in-flight op failed: a GATT callback arrived with
     * status != 0, so the op did NOT complete. Its finish() then reports
     * the failure to finishCurrentGattOperation(), which retries it
     * (bounded) or drops it. (Hunt v1.4.6 ronda 9, A4-R9-04.)
     */
    private void markCurrentGattOperationFailed() {
        synchronized (mOperations) {
            if (mCurrentOperation != null) {
                mCurrentOperation.mResult = false;
            }
        }
    }

    /**
     * Drops the in-flight op without retry: its GATT is gone (disconnect),
     * so no callback will ever arrive for it and re-running it is pointless.
     * The queued ops are left to drain through the normal path (each fails
     * synchronously against the dead GATT and is dropped by the bounded
     * retry). (Hunt v1.4.6 ronda 9, A4-R9-04.)
     */
    private void dropCurrentGattOperation() {
        synchronized (mOperations) {
            mCurrentOperation = null;
        }
        executeNextGattOperation();
    }

    private void finishCurrentGattOperation() {
        GattOperation op = null;
        synchronized (mOperations) {
            if (mCurrentOperation != null) {
                op = mCurrentOperation;
                mCurrentOperation = null;
            }
        }
        if (op != null) {
            // (Hunt v1.4.6 ronda 9, A4-R9-04.) A failed op is retried at
            // most MAX_GATT_OPERATION_ATTEMPTS times in total, then
            // dropped: the old code re-enqueued at the front with no
            // limit. A successful op is never re-enqueued. (The re-enqueue
            // used to run outside the lock; it is under the lock now.)
            if (!op.finish() && op.mAttempts < MAX_GATT_OPERATION_ATTEMPTS) {
                synchronized (mOperations) {
                    mOperations.addFirst(op);
                }
            }
        }
        executeNextGattOperation();
    }

    private void executeNextGattOperation() {
        synchronized (mOperations) {
            if (mCurrentOperation != null)
                return;

            if (mOperations.isEmpty())
                return;

            mCurrentOperation = mOperations.removeFirst();
        }

        // Run in main thread
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                GattOperation op;
                synchronized (mOperations) {
                    op = mCurrentOperation;
                    if (op == null) {
                        Log.e(TAG, "Current operation null in executor?");
                        return;
                    }
                }

                op.run();
                // (Hunt v1.4.6 ronda 9, A4-R9-04.) If run() failed
                // synchronously (read/writeCharacteristic returned false,
                // or the characteristic was not discovered yet), no GATT
                // callback will ever arrive for this op: complete it here
                // or mCurrentOperation stays set forever and the whole
                // queue starves. A successful run() is completed by its
                // callback instead. (The lock is not held across run()
                // anymore, so completing here cannot deadlock with a
                // callback finishing the same op.)
                // (Corrección del coordinador, segundo barrido.) Only
                // finish if this op is STILL current: a disconnect in
                // the window between the read above and run() drops
                // this op (dropCurrentGattOperation) and advances
                // mCurrentOperation to the next op, and an unconditional
                // finishCurrentGattOperation() here would finish --
                // and silently drop -- that next op, which never ran.
                // If op is no longer current it was already dropped
                // by the disconnect path, and the next op is already
                // scheduled, so there is nothing to do here.
                if (!op.finish()) {
                    boolean stillCurrent;
                    synchronized (mOperations) {
                        stillCurrent = (mCurrentOperation == op);
                    }
                    if (stillCurrent) {
                        finishCurrentGattOperation();
                    }
                }
            }
        });
    }

    private void queueGattOperation(GattOperation op) {
        synchronized (mOperations) {
            mOperations.add(op);
        }
        executeNextGattOperation();
    }

    private void enableNotification(UUID chrUuid) {
        GattOperation op = HIDDeviceBLESteamController.GattOperation.enableNotification(mGatt, chrUuid);
        queueGattOperation(op);
    }

    void writeCharacteristic(UUID uuid, byte[] value) {
        GattOperation op = HIDDeviceBLESteamController.GattOperation.writeCharacteristic(mGatt, uuid, value);
        queueGattOperation(op);
    }

    void readCharacteristic(UUID uuid) {
        GattOperation op = HIDDeviceBLESteamController.GattOperation.readCharacteristic(mGatt, uuid);
        queueGattOperation(op);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //////////////  BluetoothGattCallback overridden methods
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
        //Log.v(TAG, "onConnectionStateChange status=" + status + " newState=" + newState);
        mIsReconnecting = false;
        if (newState == 2) {
            mIsConnected = true;
            mServiceDiscoveryAttempts = 0;
            // Run directly, without GattOperation
            if (!isRegistered()) {
                // (Hunt v1.4.6 ronda 12, A4-R12-01.) Capture the GATT this
                // callback arrived for: the old code read the mGatt field
                // when the Runnable ran, so a reconnect in between sent
                // discoverServices() to the NEW (not yet connected) GATT,
                // and a shutdown() in between NPE'd on the nulled field.
                // The R9-05 discovery-retry Runnable already captures its
                // GATT the same way (retryGatt).
                final BluetoothGatt connectedGatt = g;
                mHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        connectedGatt.discoverServices();
                    }
                });
            }
        }
        else if (newState == 0) {
            mIsConnected = false;
            // (Hunt v1.4.6 ronda 9, A4-R9-03.) The GATT that reconnect()
            // builds is a NEW object with undiscovered services: a stale
            // mIsRegistered=true would skip discovery and probeService
            // after the reconnect, leaving the pad connected but never
            // registered (and letting writeReport enqueue ops whose
            // characteristic is null). Clear it here; the reconnect path
            // re-registers through onServicesDiscovered -> probeService.
            mIsRegistered = false;
            // A disconnect also abandons any outstanding direct write
            // (A4-R9-04): its completion will never arrive, so the flag
            // must not swallow a later queued write's completion.
            mDirectWritePending = false;
            // An op issued to the old GATT will never get its callback
            // after a disconnect: drop it so the queue is not wedged
            // behind a stale mCurrentOperation when the reconnect
            // enqueues its enableNotification (A4-R9-04).
            dropCurrentGattOperation();
        }

        // Disconnection is handled in SteamLink using the ACTION_ACL_DISCONNECTED Intent.
    }

    @Override
    public void onServicesDiscovered(BluetoothGatt gatt, int status) {
        //Log.v(TAG, "onServicesDiscovered status=" + status);
        // (Hunt v1.4.6 ronda 13, A4-R13-04.) GATT callbacks run on binder
        // threads while shutdown() (main thread) nulls mManager: a callback
        // dispatched before close() but running after it NPE'd below (see
        // onCharacteristicRead/Write, onCharacteristicChanged,
        // onDescriptorWrite for the same guard). The manager is only ever
        // nulled by shutdown(), so a null manager means this device is
        // dead; drop the callback.
        if (mManager == null) {
            return;
        }
        if (status == 0) {
            mServiceDiscoveryAttempts = 0;
            if (gatt.getServices().size() == 0) {
                Log.v(TAG, "onServicesDiscovered returned zero services; something has gone horribly wrong down in Android's Bluetooth stack.");
                mIsReconnecting = true;
                mIsConnected = false;
                // (Hunt v1.4.6 ronda 13, A4-R13-02.) Same replaceGatt()
                // as reconnect(): the old disconnect() + connectGatt()
                // here abandoned the old GATT without close().
                replaceGatt();
            } else {
                if (getProductId() == TRITON_BLE_PID) {
                    // Android will not properly play well with Data Length Extensions without manually requesting a large MTU,
                    // and Triton controllers require DLE support.
                    //
                    // 517 is basically a "magic number" as far as Android's bluetooth code is concerned, so do not change
                    // this value. It is functionally "please enable data length extensions" on some Android builds.
                    // (Hunt v1.4.6 ronda 13, A4-R13-04.) The callback's
                    // own GATT, not the field: the field may already have
                    // been replaced (or nulled by shutdown()) by the time
                    // this runs, and the MTU request belongs to the GATT
                    // that just discovered its services.
                    gatt.requestMtu(517);
                }

                probeService(this);
            }
        } else {
            // (Hunt v1.4.6 ronda 9, A4-R9-05.) A failed discovery used to
            // be swallowed: the GATT stayed connected, mIsRegistered stayed
            // false, probeService never ran and SDL never saw the pad. Retry
            // discoverServices() a bounded number of times with backoff
            // (the classic GATT 133 often clears on retry); if it still
            // fails, drop the connection and start over so the normal
            // connect -> discover path runs again. This mirrors the
            // zero-services path above: one disconnect + one connectGatt,
            // never a second concurrent connection.
            if (++mServiceDiscoveryAttempts <= MAX_SERVICE_DISCOVERY_ATTEMPTS) {
                Log.w(TAG, "onServicesDiscovered failed, status=" + status + "; retrying discoverServices (" + mServiceDiscoveryAttempts + "/" + MAX_SERVICE_DISCOVERY_ATTEMPTS + ")");
                final BluetoothGatt retryGatt = gatt;
                final int attempt = mServiceDiscoveryAttempts;
                mHandler.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        // Only retry while this is still the live GATT and
                        // the link is up: a disconnect in the meantime (or
                        // a give-up reconnect) owns recovery from there.
                        if (retryGatt == mGatt && mIsConnected) {
                            retryGatt.discoverServices();
                        }
                    }
                }, (long) SERVICE_DISCOVERY_RETRY_DELAY_MS * attempt);
            } else {
                Log.e(TAG, "onServicesDiscovered failed, status=" + status + " after " + MAX_SERVICE_DISCOVERY_ATTEMPTS + " attempts; reconnecting");
                mServiceDiscoveryAttempts = 0;
                mIsReconnecting = true;
                mIsConnected = false;
                // (Hunt v1.4.6 ronda 13, A4-R13-02.) Same replaceGatt()
                // as reconnect(): the old disconnect() + connectGatt()
                // here abandoned the old GATT without close().
                replaceGatt();
            }
        }
    }

    @Override
    public void onCharacteristicRead(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
        //Log.v(TAG, "onCharacteristicRead status=" + status + " uuid=" + characteristic.getUuid());
        // (Hunt v1.4.6 ronda 13, A4-R13-04.) Same shutdown race as
        // onServicesDiscovered above: this callback runs on a binder
        // thread, mManager is only nulled by shutdown(), and the
        // dereference below NPEs if shutdown() already ran.
        if (mManager == null) {
            return;
        }

        // (Hunt v1.4.6 ronda 9, A4-R9-04.) A callback with status != 0
        // means the op did NOT complete, and the value is undefined: do not
        // report a stale value, and mark the op failed so the bounded
        // retry (or drop) applies instead of treating it as success.
        if (status == BluetoothGatt.GATT_SUCCESS
                && characteristic.getUuid().equals(reportCharacteristic) && !mFrozen) {
            mManager.HIDDeviceReportResponse(getId(), characteristic.getValue());
        }
        if (status != BluetoothGatt.GATT_SUCCESS) {
            markCurrentGattOperationFailed();
        }

        finishCurrentGattOperation();
    }

    @Override
    public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
        //Log.v(TAG, "onCharacteristicWrite status=" + status + " uuid=" + characteristic.getUuid());
        // (Hunt v1.4.6 ronda 13, A4-R13-04.) Same shutdown race as
        // onServicesDiscovered above: this callback runs on a binder
        // thread, mManager is only nulled by shutdown(), and the
        // dereferences below NPE if shutdown() already ran.
        if (mManager == null) {
            return;
        }

        // (Hunt v1.4.6 ronda 9, A4-R9-04.) The D0G Valve-mode write issued
        // directly from onDescriptorWrite bypasses the op queue, but its
        // completion arrives here too. It is the trigger that registers a
        // D0G controller, so it runs the registration below -- but it is
        // not a queued op: it must neither mark nor finish one. (Before
        // this fix its completion finished whatever op happened to be
        // current, early.)
        final boolean directWrite = mDirectWritePending
                && characteristic.getUuid().equals(reportCharacteristic);
        if (directWrite) {
            mDirectWritePending = false;
        } else if (status != BluetoothGatt.GATT_SUCCESS) {
            // A callback with status != 0 means the queued op did NOT
            // complete: mark it failed so the bounded retry (or drop)
            // applies instead of treating it as success.
            markCurrentGattOperationFailed();
        }

        if (status == BluetoothGatt.GATT_SUCCESS
                && characteristic.getUuid().equals(reportCharacteristic)) {
            // Only register controller with the native side once it has been fully configured
            if (!isRegistered()) {
                Log.v(TAG, "Registering Steam Controller with ID: " + getId());
                mManager.HIDDeviceConnected(getId(), getIdentifier(), getVendorId(), getProductId(), getSerialNumber(), getVersion(), getManufacturerName(), getProductName(), 0, 0, 0, 0, true);
                setRegistered();
            }
        }

        if (!directWrite) {
            finishCurrentGattOperation();
        }
    }

    @Override
    public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
    // Enable this for verbose logging of controller input reports
        //Log.v(TAG, "onCharacteristicChanged uuid=" + characteristic.getUuid() + " data=" + HexDump.dumpHexString(characteristic.getValue()));
        // (Hunt v1.4.6 ronda 13, A4-R13-04.) Same shutdown race as
        // onServicesDiscovered above: this callback runs on a binder
        // thread, mManager is only nulled by shutdown(), and the
        // dereference below NPEs if shutdown() already ran.
        if (mManager == null) {
            return;
        }

        if (characteristic.getUuid().equals(getInputCharacteristic()) && !mFrozen) {
            mManager.HIDDeviceInputReport(getId(), characteristic.getValue());
        }
    }

    @Override
    public void onDescriptorRead(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
        //Log.v(TAG, "onDescriptorRead status=" + status);
    }

    @Override
    public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
        BluetoothGattCharacteristic chr = descriptor.getCharacteristic();
        //Log.v(TAG, "onDescriptorWrite status=" + status + " uuid=" + chr.getUuid() + " descriptor=" + descriptor.getUuid());
        // (Hunt v1.4.6 ronda 13, A4-R13-04.) Same shutdown race as
        // onServicesDiscovered above: this callback runs on a binder
        // thread, mManager is only nulled by shutdown(), and the
        // dereference below NPEs if shutdown() already ran.
        if (mManager == null) {
            return;
        }

        // (Hunt v1.4.6 ronda 9, A4-R9-04.) A callback with status != 0
        // means the op did NOT complete: do not register on it and do not
        // send the Valve-mode command on it; mark the op failed so the
        // bounded retry (or drop) applies instead of treating it as success.
        if (status != BluetoothGatt.GATT_SUCCESS) {
            markCurrentGattOperationFailed();
        }

        if (status == BluetoothGatt.GATT_SUCCESS
                && chr.getUuid().equals(getInputCharacteristic())) {
            boolean hasWrittenInputDescriptor = true;
            BluetoothGattCharacteristic reportChr = chr.getService().getCharacteristic(reportCharacteristic);
            if (reportChr != null) {
                if (getProductId() == TRITON_BLE_PID) {
                    // For Triton we just mark things registered.
                    Log.v(TAG, "Registering Triton Steam Controller with ID: " + getId());
                    mManager.HIDDeviceConnected(getId(), getIdentifier(), getVendorId(), getProductId(), getSerialNumber(), getVersion(), getManufacturerName(), getProductName(), 0, 0, 0, 0, true);
                    setRegistered();
                } else {
                    // For the original controller, we need to manually enter Valve mode.
                    Log.v(TAG, "Writing report characteristic to enter valve mode");
                    reportChr.setValue(enterValveMode);
                    // (Ronda 9, A4-R9-04.) This write bypasses the op
                    // queue; remember it is outstanding so its completion
                    // in onCharacteristicWrite is not mistaken for the
                    // queued op's. Only set when the write was issued --
                    // a false return means no callback will ever arrive.
                    if (gatt.writeCharacteristic(reportChr)) {
                        mDirectWritePending = true;
                    }
                }
            }
        }

        finishCurrentGattOperation();
    }

    @Override
    public void onReliableWriteCompleted(BluetoothGatt gatt, int status) {
        //Log.v(TAG, "onReliableWriteCompleted status=" + status);
    }

    @Override
    public void onReadRemoteRssi(BluetoothGatt gatt, int rssi, int status) {
        //Log.v(TAG, "onReadRemoteRssi status=" + status);
    }

    @Override
    public void onMtuChanged(BluetoothGatt gatt, int mtu, int status) {
        //Log.v(TAG, "onMtuChanged status=" + status);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //////// Public API
    //////////////////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public int getId() {
        return mDeviceId;
    }

    @Override
    public int getVendorId() {
        // Valve Corporation
        final int VALVE_USB_VID = 0x28DE;
        return VALVE_USB_VID;
    }

    @Override
    public int getProductId() {
        if (mProductId > 0) {
            // We've already set a product ID.
            return mProductId;
        }

        // (Hunt v1.4.6 ronda 9, A4-R9-06.) BluetoothDevice.getName() may
        // return null (documented); the null-check in
        // HIDDeviceManager.isSteamController only covers scan time, and
        // the name cache can clear between then and this GATT-callback
        // call. A null name takes the D0G default, as in the else today.
        String name = mDevice.getName();
        if (name != null && name.startsWith("Steam Ctrl")) {
            // We're a newer Triton device
            mProductId = TRITON_BLE_PID;
        } else {
            // We're an OG Steam Controller
            mProductId = D0G_BLE2_PID;
        }

        return mProductId;
    }

    private UUID getInputCharacteristic() {
        if (getProductId() == TRITON_BLE_PID) {
            return inputCharacteristicTriton;
        } else {
            return inputCharacteristicD0G;
        }
    }

    @Override
    public String getSerialNumber() {
        // This will be read later via feature report by Steam
        return "12345";
    }

    @Override
    public int getVersion() {
        return 0;
    }

    @Override
    public String getManufacturerName() {
        return "Valve Corporation";
    }

    @Override
    public String getProductName() {
        return "Steam Controller";
    }

    @Override
    public UsbDevice getDevice() {
        return null;
    }

    @Override
    public boolean open() {
        return true;
    }

    @Override
    public int writeReport(byte[] report, boolean feature) {
        if (!isRegistered()) {
            Log.e(TAG, "Attempted writeReport before Steam Controller is registered!");
            if (mIsConnected) {
                probeService(this);
            }
            return -1;
        }

        // (Hunt v1.4.6 ronda 19, A4-R19-06.) A null buffer NPEs below
        // (report.length); the copyOfRange calls in the feature and
        // Triton branches throw IllegalArgumentException for a 0- or
        // 1-byte report (from > to, per the Arrays docs). The native side
        // passes the buffer straight through, so guard here instead of
        // letting it explode on the SDL thread.
        if (report == null) {
            Log.w(TAG, "writeReport with a null report; dropping");
            return -1;
        }

        if (feature) {
            if (report.length < 2) {
                Log.w(TAG, "writeReport with a " + report.length + "-byte feature report; dropping");
                return -1;
            }
            // We need to skip the first byte, as that doesn't go over the air
            byte[] actual_report = Arrays.copyOfRange(report, 1, report.length - 1);
            //Log.v(TAG, "writeFeatureReport " + HexDump.dumpHexString(actual_report));
            writeCharacteristic(reportCharacteristic, actual_report);
            return report.length;
        } else {
            // If we're an original-recipe Steam Controller we just write to the characteristic directly.
            if (getProductId() == D0G_BLE2_PID) {
                //Log.v(TAG, "writeOutputReport " + HexDump.dumpHexString(report));
                writeCharacteristic(reportCharacteristic, report);
                return report.length;                
            }

            // If we're a Triton, we need to find the correct report characteristic.
            if (report.length >= 2) {
                int reportId = report[0];
                BluetoothGattCharacteristic targetedReportCharacteristic = mOutputReportChars.get(reportId);
                if (targetedReportCharacteristic != null) {
                    byte[] actual_report = Arrays.copyOfRange(report, 1, report.length - 1);
                    //Log.v(TAG, "writeOutputReport 0x" + Integer.toString(reportId, 16) + " " + HexDump.dumpHexString(report));
                    writeCharacteristic(targetedReportCharacteristic.getUuid(), actual_report);
                    return report.length;
                } else {
                    Log.w(TAG, "Got report write request for unknown report type 0x" + Integer.toString(reportId, 16));
                }
            } else {
                Log.w(TAG, "Got report write request for a " + report.length + "-byte Triton report; dropping");
            }
        }

        return -1;
    }

    @Override
    public boolean readReport(byte[] report, boolean feature) {
        if (!isRegistered()) {
            Log.e(TAG, "Attempted readReport before Steam Controller is registered!");
            if (mIsConnected) {
                probeService(this);
            }
            return false;
        }

        if (feature) {
            readCharacteristic(reportCharacteristic);
            return true;
        } else {
            // Not implemented
            return false;
        }
    }

    @Override
    public void close() {
    }

    @Override
    public void setFrozen(boolean frozen) {
        mFrozen = frozen;
    }

    @Override
    public void shutdown() {
        close();

        BluetoothGatt g = mGatt;
        if (g != null) {
            g.disconnect();
            g.close();
            mGatt = null;
        }
        mManager = null;
        mIsRegistered = false;
        mIsConnected = false;
        mDirectWritePending = false;
        // (Hunt v1.4.6 ronda 12, A4-R12-01.) Cancel the Handler work posted
        // by onConnectionStateChange (discoverServices) and by
        // executeNextGattOperation (the op executor): both dereference
        // mGatt when they run — discoverServices() on the field, the
        // executor through op.run() -> getCharacteristic() -> mGatt.getService()
        // — and both still fire after this method nulls it, NPEing on the
        // main thread when the disconnect/destroy lands before the looper
        // runs them. The Handler is private to this instance, so dropping
        // all its pending work is safe (the discovery-retry Runnable
        // already guards itself with retryGatt == mGatt and needs
        // nothing). Drop the in-flight op under the same lock the queue
        // uses everywhere else — shutdown() used to clear() the queue
        // without it, racing the synchronized queue methods.
        mHandler.removeCallbacksAndMessages(null);
        synchronized (mOperations) {
            mCurrentOperation = null;
            mOperations.clear();
        }
    }

}

