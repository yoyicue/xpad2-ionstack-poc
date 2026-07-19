// SPDX-License-Identifier: GPL-3.0-or-later

#include <jni.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int ionstack_probe_main(int argc, char **argv);

static int redirect_output(JNIEnv *env, jstring log_path) {
  const char *path = (*env)->GetStringUTFChars(env, log_path, NULL);
  if (!path) {
    return -1;
  }
  int fd = open(path,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_DSYNC,
                0600);
  int saved_errno = errno;
  (*env)->ReleaseStringUTFChars(env, log_path, path);
  if (fd < 0) {
    errno = saved_errno;
    return -1;
  }
  if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  close(fd);
  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);
  return 0;
}

JNIEXPORT jint JNICALL
Java_com_ionstack_trigger_v2_MainActivity_smokeAshmem(JNIEnv *env,
                                                       jclass clazz,
                                                       jstring log_path) {
  (void)clazz;
  if (redirect_output(env, log_path) != 0) {
    return errno ? errno : 125;
  }
  char context[256] = "unknown";
  int context_fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
  if (context_fd >= 0) {
    ssize_t got = read(context_fd, context, sizeof(context) - 1);
    if (got > 0) {
      context[got] = '\0';
    }
    close(context_fd);
  }
  errno = 0;
  int ashmem_fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
  int open_errno = errno;
  printf("[app-smoke] pid=%d uid=%d context=%s ashmem_fd=%d errno=%d (%s)\n",
         getpid(), getuid(), context, ashmem_fd, open_errno,
         strerror(open_errno));
  if (ashmem_fd >= 0) {
    close(ashmem_fd);
    return 0;
  }
  return open_errno ? open_errno : 125;
}

JNIEXPORT jint JNICALL
Java_com_ionstack_trigger_v2_MainActivity_runProbe(JNIEnv *env, jclass clazz,
                                                    jobjectArray java_args,
                                                    jstring log_path) {
  (void)clazz;
  if (redirect_output(env, log_path) != 0) {
    return errno ? errno : 125;
  }

  jsize count = (*env)->GetArrayLength(env, java_args);
  char **argv = calloc((size_t)count + 2, sizeof(*argv));
  if (!argv) {
    return 125;
  }
  argv[0] = strdup("cve43499_app_probe");
  if (!argv[0]) {
    free(argv);
    return 125;
  }
  int argc = 1;
  for (jsize i = 0; i < count; ++i) {
    jstring value = (jstring)(*env)->GetObjectArrayElement(env, java_args, i);
    const char *utf = value ? (*env)->GetStringUTFChars(env, value, NULL) : NULL;
    if (!utf) {
      if (value) {
        (*env)->DeleteLocalRef(env, value);
      }
      break;
    }
    argv[argc] = strdup(utf);
    (*env)->ReleaseStringUTFChars(env, value, utf);
    (*env)->DeleteLocalRef(env, value);
    if (!argv[argc]) {
      break;
    }
    argc++;
  }
  if (argc != count + 1) {
    for (int i = 0; i < argc; ++i) {
      free(argv[i]);
    }
    free(argv);
    return 125;
  }

  int result = 125;
  pid_t child = fork();
  if (child == 0) {
    int child_result = ionstack_probe_main(argc, argv);
    fflush(stdout);
    fflush(stderr);
    _exit(child_result & 0xff);
  }
  if (child > 0) {
    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited == child && WIFEXITED(status)) {
      result = WEXITSTATUS(status);
    } else if (waited == child && WIFSIGNALED(status)) {
      result = 128 + WTERMSIG(status);
    }
  }
  fflush(stdout);
  fflush(stderr);
  for (int i = 0; i < argc; ++i) {
    free(argv[i]);
  }
  free(argv);
  return result;
}
