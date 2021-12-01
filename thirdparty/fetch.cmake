

# if VERBOSE_FETCH is defined, then we print the output of the command.
option(VERBOSE_FETCH "verbose fetch" OFF)

if(DEFINED LOG_FILE AND NOT VERBOSE_FETCH)
    set(LOG_SETTING OUTPUT_FILE ${LOG_FILE} ERROR_FILE ${LOG_FILE} ${OUTPUT_QUIET})
else()
    unset(LOG_SETTING)
endif()

function(RUN)
    cmake_parse_arguments(
        PARSED_ARGS # prefix of parameters
        "" # list of names of the boolean arguments (only defined ones will be true)
        "WD" # list of names of mono-valued arguments
        "CMD;NAME" # list of names of multi-valued arguments (output variables are lists)
        ${ARGN} # arguments of the function to parse, here we take the all original ones
    )
    message("${PARSED_ARGS_NAME}")
    file(APPEND ${LOG_FILE}
        "vvvvvvvvvvvvv RUN ${PARSED_ARGS_NAME} vvvvvvvvvvvv\n"
        "${PARSED_ARGS_CMD}\n"
        "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
    )

    execute_process(
        COMMAND ${PARSED_ARGS_CMD}
        WORKING_DIRECTORY ${PARSED_ARGS_WD}
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
        ${LOG_SETTING}
    )
    if(RESULT)
        if(NOT VERBOSE_FETCH)
            file(READ ${LOG_FILE} LOG_STRING)
            message(FATAL_ERROR "${PARSED_ARGS_NAME} failed (${RESULT}).\nLOG:\n" ${LOG_STRING})
        endif()
    endif()
endfunction()



if(NOT MSVC AND SUDO_FETCH)
    set(SUDO "sudo ")
endif()

if(NOT DEFINED PARALLEL_FETCH)
    include(ProcessorCount)
    ProcessorCount(NUM_PROCESSORS)
    if(NOT NUM_PROCESSORS EQUAL 0)
        set(PARALLEL_FETCH ${NUM_PROCESSORS})
    else()
        set(PARALLEL_FETCH 1)
    endif()
endif()