# Copyright (C) 2023, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND wmexec_tests_names "test_wm_exec")
set(WM_EXEC_BASE_FLAGS "-Wl,--wrap,OSList_AddData -Wl,--wrap,merror \
                        -Wl,--wrap,OSList_DeleteThisNode -Wl,--wrap,OSList_GetFirstNode \
                        -Wl,--wrap,fork -Wl,--wrap,kill -Wl,--wrap,exit \
                        -Wl,--wrap,OSList_Destroy -Wl,--wrap,mdebug1 \
                        -Wl,--wrap,sleep ${DEBUG_OP_WRAPPERS}")

if(${TARGET} STREQUAL "winagent")
    list(APPEND tests_flags "${WM_EXEC_BASE_FLAGS} -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=is_fim_shutdown")
else()
    list(APPEND tests_flags "${WM_EXEC_BASE_FLAGS}")
endif()

# Add extra compiling flags
add_compile_options(-Wall)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Compilig tests
list(LENGTH wmexec_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wmexec_tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    if(${TARGET} STREQUAL "server")
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            -lcmocka
            -ldl
            -fprofile-arcs
            -ftest-coverage
        )
    else()
        target_link_libraries(
            ${test_name}
            ${TEST_DEPS}
        )
        if(${TARGET} STREQUAL "winagent")
          target_link_libraries(${test_name} fimdb)
        endif(${TARGET} STREQUAL "winagent")
    endif()

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
