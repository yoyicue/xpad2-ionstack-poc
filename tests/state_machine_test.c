// SPDX-License-Identifier: GPL-3.0-or-later

#include <assert.h>
#include <stdio.h>

#include "../src/state_machine.h"

static void test_full_success_path(void) {
  struct ionstack_state_machine machine = {
      .state = IONSTACK_STATE_INIT,
      .sequence = 0,
  };
  const enum ionstack_state path[] = {
      IONSTACK_STATE_PREFLIGHT, IONSTACK_STATE_PROFILE,
      IONSTACK_STATE_LEAK, IONSTACK_STATE_HOLDER,
      IONSTACK_STATE_WRITE_ARMED, IONSTACK_STATE_CAPTURE,
      IONSTACK_STATE_ROOT_VERIFY, IONSTACK_STATE_COMPLETE,
  };
  for (unsigned i = 0; i < sizeof(path) / sizeof(path[0]); ++i) {
    assert(ionstack_state_transition(&machine, path[i]));
    assert(machine.sequence == i + 1);
  }
  assert(machine.state == IONSTACK_STATE_COMPLETE);
  assert(!ionstack_state_transition(&machine, IONSTACK_STATE_FAILED));
}

static void test_safe_early_exits(void) {
  struct ionstack_state_machine existing = {IONSTACK_STATE_INIT, 0};
  assert(ionstack_state_transition(&existing, IONSTACK_STATE_COMPLETE));

  struct ionstack_state_machine preflight = {IONSTACK_STATE_INIT, 0};
  assert(ionstack_state_transition(&preflight, IONSTACK_STATE_PREFLIGHT));
  assert(ionstack_state_transition(&preflight, IONSTACK_STATE_PROFILE));
  assert(ionstack_state_transition(&preflight, IONSTACK_STATE_COMPLETE));

  struct ionstack_state_machine validation = {IONSTACK_STATE_HOLDER, 4};
  assert(ionstack_state_transition(&validation, IONSTACK_STATE_COMPLETE));
}

static void test_failure_and_invalid_jumps(void) {
  for (int state = IONSTACK_STATE_INIT; state < IONSTACK_STATE_COMPLETE;
       ++state) {
    struct ionstack_state_machine machine = {(enum ionstack_state)state, 7};
    assert(ionstack_state_transition(&machine, IONSTACK_STATE_FAILED));
    assert(machine.sequence == 8);
    assert(!ionstack_state_transition(&machine, IONSTACK_STATE_INIT));
  }

  struct ionstack_state_machine machine = {IONSTACK_STATE_INIT, 0};
  assert(!ionstack_state_transition(&machine, IONSTACK_STATE_CAPTURE));
  assert(machine.state == IONSTACK_STATE_INIT);
  assert(machine.sequence == 0);
  assert(!ionstack_state_can_transition(IONSTACK_STATE_FAILED,
                                        IONSTACK_STATE_COMPLETE));
  assert(!ionstack_state_can_transition(IONSTACK_STATE_COMPLETE,
                                        IONSTACK_STATE_FAILED));
}

int main(void) {
  test_full_success_path();
  test_safe_early_exits();
  test_failure_and_invalid_jumps();
  assert(ionstack_state_name(IONSTACK_STATE_WRITE_ARMED)[0] == 'w');
  puts("state_machine_test: ok");
  return 0;
}
