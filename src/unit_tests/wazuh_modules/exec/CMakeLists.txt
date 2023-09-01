# Copyright (C) 2023, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND wmexec_tests_names "test_wm_exec")
list(APPEND wmexec_tests_flags "-Wl,--wrap,OSList_AddData -Wl,--wrap,merror -Wl,--wrap,OSList_DeleteThisNode \
                                -Wl,--wrap,OSList_GetFirstNode ${DEBUG_OP_WRAPPERS}")

# Add extra compiling flags
add_compile_options(-Wall)

# Compilig tests
list(LENGTH wmexec_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wmexec_tests_names ${counter} test_name)
    list(GET wmexec_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
