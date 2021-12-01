set(DEP_NAME            sparsehash-c11)
set(GIT_REPOSITORY      https://github.com/sparsehash/sparsehash-c11.git)
set(GIT_TAG             "edd6f1180156e76facc1c0449da245208ab39503" )

set(CLONE_DIR "${CMAKE_CURRENT_LIST_DIR}/${DEP_NAME}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-${DEP_NAME}.txt")


# defines the run(...) function.
include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

# only download if we haven't already found sparsehash
if(NOT EXISTS ${CLONE_DIR} OR NOT SPARSEHASH_FOUND)

    # find git
    find_program(GIT git REQUIRED)

    # download the source and check out the right commit.
    set(DOWNLOAD_CMD  ${GIT} clone ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    
    # run the commands.
    message("============= Building ${DEP_NAME} =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY}" CMD ${DOWNLOAD_CMD} WD ${CMAKE_CURRENT_LIST_DIR})
    endif()
    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})

    # install the headers into our local install directory LIBPSI_THIRDPARTY_DIR.
    # If the user calls cmake install, we will also install it to the requested location.
    # see below for the code that does this.
    file(COPY ${CLONE_DIR}/sparsehash DESTINATION ${LIBPSI_THIRDPARTY_DIR}/include/)

    message("log ${LOG_FILE}\n==========================================")
else()
    # dont download and install sparsehash if its already found.
    message("${DEP_NAME} already fetched.")
endif()

# this command gets run when the user calls cmake install. This will install sparsehash.
install(
    DIRECTORY "${CLONE_DIR}/sparsehash"
    DESTINATION "include")

