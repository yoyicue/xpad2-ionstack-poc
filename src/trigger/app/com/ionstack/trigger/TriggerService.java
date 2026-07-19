// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

package com.ionstack.trigger.v2;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

public final class TriggerService extends Service {
    private static final String CHANNEL_ID = "ionstack_probe";
    private static final int NOTIFICATION_ID = 43499;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private static String extra(Intent intent, String name) {
        String value = intent == null ? null : intent.getStringExtra(name);
        return value == null ? "" : value;
    }

    private static void writeDone(File done, int result) {
        try (FileOutputStream output = new FileOutputStream(done, false)) {
            output.write((Integer.toString(result) + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (Exception ignored) {
        }
    }

    private void enterForeground() {
        NotificationManager manager =
                (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID, "Ionstack probe",
                    NotificationManager.IMPORTANCE_LOW);
            manager.createNotificationChannel(channel);
        }

        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        Notification notification = builder
                .setContentTitle("Ionstack probe")
                .setContentText("Xpad3S validation is running")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setOngoing(true)
                .build();
        startForeground(NOTIFICATION_ID, notification);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        enterForeground();
    }

    @Override
    public int onStartCommand(final Intent intent, int flags,
                              final int startId) {
        if (!running.compareAndSet(false, true)) {
            return START_NOT_STICKY;
        }

        final File log = new File(getFilesDir(), "probe.log");
        final File done = new File(getFilesDir(), "probe.done");
        final boolean smoke = intent != null &&
                intent.getBooleanExtra("smoke", false);
        final boolean calibrate = intent != null &&
                intent.getBooleanExtra("calibrate", false);
        final boolean safeHandoff = intent != null &&
                intent.getBooleanExtra("safe_handoff", false);
        final String tree = extra(intent, "tree_arg");
        final String task = extra(intent, "task_arg");
        final String lock = extra(intent, "lock_arg");
        log.delete();
        done.delete();

        new Thread(new Runnable() {
            @Override
            public void run() {
                int result;
                if (smoke) {
                    result = MainActivity.smokeAshmem(log.getAbsolutePath());
                } else if (calibrate) {
                    String[] args = {
                        "--stage-pselect-epoll-lock-calibrate",
                        tree,
                        task,
                        lock,
                        "--ashmem-prio=130"
                    };
                    result = MainActivity.runProbe(args, log.getAbsolutePath());
                } else if (safeHandoff) {
                    String[] args = {
                        "--stage-edeadlk-idle",
                        "--i-understand-this-may-panic",
                        "--waiter-post-return=futex64-pselect-epoll-lock",
                        tree,
                        task,
                        lock,
                        "--watchdog-sec=20",
                        "--hold-ms=5000",
                        "--ashmem-prio=130",
                        "--waiter-isolated-hold=busy",
                        "--idle-ms=100"
                    };
                    result = MainActivity.runProbe(args, log.getAbsolutePath());
                } else {
                    String[] args = {
                        "--stage-edeadlk-idle",
                        "--i-understand-this-may-panic",
                        "--waiter-post-return=futex64-pselect-epoll-lock",
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
                    result = MainActivity.runProbe(args, log.getAbsolutePath());
                }
                writeDone(done, result);
                running.set(false);
                stopForeground(true);
                stopSelf(startId);
            }
        }, "ionstack-trigger").start();
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
