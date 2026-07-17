// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 yoyicue

#ifndef IONSTACK_STATE_MACHINE_H
#define IONSTACK_STATE_MACHINE_H

enum ionstack_state {
  IONSTACK_STATE_INIT = 0,
  IONSTACK_STATE_PREFLIGHT,
  IONSTACK_STATE_PROFILE,
  IONSTACK_STATE_LEAK,
  IONSTACK_STATE_HOLDER,
  IONSTACK_STATE_WRITE_ARMED,
  IONSTACK_STATE_CAPTURE,
  IONSTACK_STATE_ROOT_VERIFY,
  IONSTACK_STATE_COMPLETE,
  IONSTACK_STATE_FAILED,
};

struct ionstack_state_machine {
  enum ionstack_state state;
  unsigned sequence;
};

static const char *ionstack_state_name(enum ionstack_state state) {
  switch (state) {
    case IONSTACK_STATE_INIT:
      return "init";
    case IONSTACK_STATE_PREFLIGHT:
      return "preflight";
    case IONSTACK_STATE_PROFILE:
      return "profile";
    case IONSTACK_STATE_LEAK:
      return "leak";
    case IONSTACK_STATE_HOLDER:
      return "holder";
    case IONSTACK_STATE_WRITE_ARMED:
      return "write-armed";
    case IONSTACK_STATE_CAPTURE:
      return "capture";
    case IONSTACK_STATE_ROOT_VERIFY:
      return "root-verify";
    case IONSTACK_STATE_COMPLETE:
      return "complete";
    case IONSTACK_STATE_FAILED:
      return "failed";
  }
  return "invalid";
}

static int ionstack_state_is_terminal(enum ionstack_state state) {
  return state == IONSTACK_STATE_COMPLETE || state == IONSTACK_STATE_FAILED;
}

static int ionstack_state_can_transition(enum ionstack_state from,
                                         enum ionstack_state to) {
  if (ionstack_state_is_terminal(from)) {
    return 0;
  }
  if (to == IONSTACK_STATE_FAILED) {
    return 1;
  }
  switch (from) {
    case IONSTACK_STATE_INIT:
      return to == IONSTACK_STATE_PREFLIGHT ||
             to == IONSTACK_STATE_COMPLETE;
    case IONSTACK_STATE_PREFLIGHT:
      return to == IONSTACK_STATE_PROFILE;
    case IONSTACK_STATE_PROFILE:
      return to == IONSTACK_STATE_LEAK || to == IONSTACK_STATE_COMPLETE;
    case IONSTACK_STATE_LEAK:
      return to == IONSTACK_STATE_HOLDER;
    case IONSTACK_STATE_HOLDER:
      return to == IONSTACK_STATE_WRITE_ARMED ||
             to == IONSTACK_STATE_COMPLETE;
    case IONSTACK_STATE_WRITE_ARMED:
      return to == IONSTACK_STATE_CAPTURE;
    case IONSTACK_STATE_CAPTURE:
      return to == IONSTACK_STATE_ROOT_VERIFY;
    case IONSTACK_STATE_ROOT_VERIFY:
      return to == IONSTACK_STATE_COMPLETE;
    case IONSTACK_STATE_COMPLETE:
    case IONSTACK_STATE_FAILED:
      return 0;
  }
  return 0;
}

static int ionstack_state_transition(struct ionstack_state_machine *machine,
                                     enum ionstack_state next) {
  if (!machine || !ionstack_state_can_transition(machine->state, next)) {
    return 0;
  }
  machine->state = next;
  machine->sequence++;
  return 1;
}

#endif
