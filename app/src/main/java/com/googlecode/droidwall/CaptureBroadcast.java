package com.googlecode.droidwall;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;
import android.widget.Toast;

import static com.googlecode.droidwall.Api.PREFS_NAME;
import static com.googlecode.droidwall.Api.PREF_CAP_UIDS;
import static com.googlecode.droidwall.Api.setCapForSpecApp;

/**
 * Created by zhuyuhui on 2017/6/12.
 */

public class CaptureBroadcast extends BroadcastReceiver {
    private static final String TAG = "CaptureBroadcast";
    public static final String ACTION_AUTO_START = "cn.cpuboom.capture.action.AUTO_START";
    public static final String ACTION_AUTO_STOP = "cn.cpuboom.capture.action.AUTO_STOP";
    public static final String ACTION_AUTO_SET = "cn.cpuboom.capture.action.AUTO_SET";
    public static final String ACTION_AUTO_UNSET = "cn.cpuboom.capture.action.AUTO_UNSET";
    public static final String ACTION_AUTO_UNSET_ALL = "cn.cpuboom.capture.action.AUTO_UNSET_ALL";
    @Override
    public void onReceive(final Context context, Intent intent) {
        boolean autoCapStatus = false;
        String action = intent.getAction();
        autoCapStatus = Api.getAutoCapStatus(context);
        Log.d(TAG, "onReceive: Action - " + action);
        Log.d(TAG, "onReceive: Capture status in pref = " + autoCapStatus);
        Toast.makeText(context, "onReceive: Action - " + action, Toast.LENGTH_LONG).show();
        if (action.equals(ACTION_AUTO_START)){
            Log.d(TAG, "onReceive: Capture Start");
            Api.setAutoCapStatus(context, true);
            autoCapStatus = true;
        } else if (action.equals(ACTION_AUTO_STOP)){
            Log.d(TAG, "onReceive: Capture Stop");
            Api.setAutoCapStatus(context, false);
            autoCapStatus = false;
        } else if (autoCapStatus) {
            Log.d(TAG, "onReceive: aaaa");
            if (action.equals(ACTION_AUTO_SET)) {
                final String pkgName = intent.getExtras().getCharSequence("PKG_NAME").toString();
                final String ports;
                CharSequence ports_cs = intent.getExtras().getCharSequence("PORTS");
                if (ports_cs != null)
                    ports = ports_cs.toString();
                else
                    ports = Api.DEF_SSL_PORT;
                new Thread(){
                    @Override
                    public void run() {
                        setCapForSpecApp(context, pkgName, ports);
                        super.run();
                    }
                }.run();
            } else if (action.equals(ACTION_AUTO_UNSET)){

            } else if (action.equals(ACTION_AUTO_UNSET_ALL)){
                new Thread(){
                    @Override
                    public void run() {
                        Api.unsetAllCap(context);
                        super.run();
                    }
                }.run();
            }
        } else {
            Log.d(TAG, "onReceive: Trying to set capture before setting preference???");
        }


    }
}
