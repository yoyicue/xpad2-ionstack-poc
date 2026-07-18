// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

package com.ionstack.trigger;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

public final class MainActivity extends Activity {
    static {
        System.loadLibrary("ionstack_trigger");
    }

    static native int runProbe(String[] args, String logPath);
    static native int smokeAshmem(String logPath);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent service = new Intent(this, TriggerService.class);
        Intent launch = getIntent();
        if (launch != null && launch.getExtras() != null) {
            service.putExtras(launch.getExtras());
        }
        if (Build.VERSION.SDK_INT >= 26) {
            startForegroundService(service);
        } else {
            startService(service);
        }
        finishAndRemoveTask();
    }
}
