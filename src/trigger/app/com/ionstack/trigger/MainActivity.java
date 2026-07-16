// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

package com.ionstack.trigger;

import android.app.Activity;
import android.os.Bundle;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    static {
        System.loadLibrary("ionstack_trigger");
    }

    private static native int runProbe(String[] args, String logPath);
    private static native int smokeAshmem(String logPath);

    private static String extra(Activity activity, String name) {
        String value = activity.getIntent().getStringExtra(name);
        return value == null ? "" : value;
    }

    private void writeDone(File done, int result) {
        try (FileOutputStream output = new FileOutputStream(done, false)) {
            output.write((Integer.toString(result) + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (Exception ignored) {
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final File log = new File(getFilesDir(), "probe.log");
        final File done = new File(getFilesDir(), "probe.done");
        final boolean smoke = getIntent().getBooleanExtra("smoke", false);
        final String tree = extra(this, "tree_arg");
        final String task = extra(this, "task_arg");
        final String lock = extra(this, "lock_arg");
        log.delete();
        done.delete();

        new Thread(new Runnable() {
            @Override
            public void run() {
                int result;
                if (smoke) {
                    result = smokeAshmem(log.getAbsolutePath());
                } else {
                    String[] args = {
                        "--stage-edeadlk-idle",
                        "--i-understand-this-may-panic",
                        "--waiter-post-return=pselect-ashmem-name",
                        tree,
                        task,
                        lock,
                        "--watchdog-sec=20",
                        "--hold-ms=5000",
                        "--ashmem-prio=130",
                        "--waiter-adjust-pi-after-post-return",
                        "--adjust-pi-repeats=1",
                        "--waiter-isolated-hold=busy",
                        "--adjust-pi-start-isolated-hold",
                        "--idle-ms=100"
                    };
                    result = runProbe(args, log.getAbsolutePath());
                }
                writeDone(done, result);
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        finishAndRemoveTask();
                    }
                });
            }
        }, "ionstack-trigger").start();
    }
}
