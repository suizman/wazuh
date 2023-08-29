/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the wm_exec functions
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include "shared.h"
#include "../../wazuh_modules/wmodules.h"

#include "../../wrappers/wazuh/shared/list_op_wrappers.h"

static void setup_modules(void ** state) {
    *state = NULL;
    wm_children_pool_init();
}

static void teardown_modules(void ** state) {
    wm_children_pool_destroy();
}

#ifndef TEST_WINAGENT
static void test_wm_append_sid_fail(void ** state) {

    pid_t sid = 10;

    will_return(__wrap_OSList_AddData, NULL);

    expect_string(__wrap__merror, formatted_msg, "Child process sid 10 could not be registered.");

    wm_append_sid(sid);    
}

static void test_wm_append_sid_success(void ** state) {

    pid_t sid = 10;
    OSListNode *node;
    test_mode = true;

    will_return(__wrap_OSList_AddData, node);
    
    wm_append_sid(sid);
    test_mode = false;
}

static void test_wm_remove_sid_null_list(void ** state) {
    pid_t sid = 10;

    expect_string(__wrap__merror, formatted_msg, "Child process 10 not found.");

    wm_append_sid(sid);
}

static void test_wm_remove_sid_not_found(void ** state) {
    pid_t sid = 10;

    will_return(__wrap_OSList_GetFirstNode, NULL);
    expect_string(__wrap__merror, formatted_msg, "Child process 10 not found.");

    wm_append_sid(sid);
}

#else
static void test_wm_append_handle(void ** state) {

}

static void test_wm_remove_handle(void ** state) {

}

static void test_wm_kill_children_win(void ** state) {

}
#endif

 int main() {
    const struct CMUnitTest tests[] = {
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup_teardown(test_wm_append_sid_fail, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_append_sid_success, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_null_list, NULL, NULL),
        cmocka_unit_test_setup_teardown(test_wm_remove_sid_not_found, setup_modules, teardown_modules),
#else
        cmocka_unit_test_setup_teardown(test_wm_append_handle, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_remove_handle, setup_modules, teardown_modules),
        cmocka_unit_test_setup_teardown(test_wm_kill_children_win, setup_modules, teardown_modules)
#endif
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}