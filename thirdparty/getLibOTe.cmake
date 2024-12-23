
set(DEP_NAME            libOTe)          
set(GIT_REPOSITORY      "https://github.com/osu-crypto/libOTe.git")
set(GIT_TAG             "f47217d924ceef9b65e04a9ae680b65a79a4425a")

set(OUT_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/")
set(CLONE_DIR "${OUT_DIR}/${DEP_NAME}")
set(BUILD_DIR "${CLONE_DIR}/out/build/${LIBPSI_CONFIG}")
set(LOG_FILE  "${CMAKE_CURRENT_LIST_DIR}/log-${DEP_NAME}.txt")

# defines the run(...) function.
include("${CMAKE_CURRENT_LIST_DIR}/fetch.cmake")

# an extra option to always build libOTe. useful if your also editing the subproject
option(LIBOTE_DEV "always build libOTe" OFF)

# only download if we haven't already found libOTe
if(NOT EXISTS ${BUILD_DIR} OR NOT ${DEP_NAME}_FOUND OR LIBOTE_DEV)

    # find git
    find_program(GIT git REQUIRED)

    # define the commands we need to run: download, checkout, submodule update, cmake config, build, local install
    set(DOWNLOAD_CMD  ${GIT} clone --recursive ${GIT_REPOSITORY})
    set(CHECKOUT_CMD  ${GIT} checkout ${GIT_TAG})
    set(SUBMODULE_CMD   ${GIT} submodule update --recursive)
    set(CONFIGURE_CMD ${CMAKE_COMMAND} -S ${CLONE_DIR} -B ${BUILD_DIR} -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
                       -DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE} 
                       -DFETCH_AUTO=ON 
                       -DLIBOTE_STD_VER=${LIBPSI_STD_VER}
                       -DVERBOSE_FETCH=${VERBOSE_FETCH}
                       -DENABLE_ALL_OT=ON
                       -DENABLE_RELIC=${ENABLE_RELIC}
                       -DENABLE_SODIUM=${ENABLE_SODIUM}
                       -DENABLE_BOOST=ON
                       )
    set(BUILD_CMD     ${CMAKE_COMMAND} --build ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE})

    # when we fetch a project, we install it into the local folder LIBPSI_THIRDPARTY_DIR
    # if the user later calls "cmake install", then we will install it to their requested
    # location too. See below for this.
    set(INSTALL_CMD   ${CMAKE_COMMAND} --install ${BUILD_DIR} --config ${CMAKE_BUILD_TYPE} --prefix ${LIBPSI_THIRDPARTY_DIR})

    # execute the fetch commands.
    message("============= Building ${DEP_NAME} =============")
    if(NOT EXISTS ${CLONE_DIR})
        run(NAME "Cloning ${GIT_REPOSITORY} into ${OUT_DIR}" CMD ${DOWNLOAD_CMD} WD ${OUT_DIR})
    endif()

    run(NAME "Checkout ${GIT_TAG} " CMD ${CHECKOUT_CMD}  WD ${CLONE_DIR})
    run(NAME "submodule"       CMD ${SUBMODULE_CMD} WD ${CLONE_DIR})
    run(NAME "Configure"       CMD ${CONFIGURE_CMD} WD ${CLONE_DIR})
    run(NAME "Build"           CMD ${BUILD_CMD}     WD ${CLONE_DIR})
    run(NAME "Install"         CMD ${INSTALL_CMD}   WD ${CLONE_DIR})

    message("log ${LOG_FILE}\n==========================================")
else()

    # if we already found libOTe, then just print that.
    message("${DEP_NAME} already fetched.")
endif()

# this command gets run when the user calls cmake install. This will install libOTe.
install(CODE "
    execute_process(
        COMMAND ${SUDO} \${CMAKE_COMMAND} --install \"${BUILD_DIR}\"  --config ${CMAKE_BUILD_TYPE} --prefix \${CMAKE_INSTALL_PREFIX}
        WORKING_DIRECTORY \"${CLONE_DIR}\"
        RESULT_VARIABLE RESULT
        COMMAND_ECHO STDOUT
    )
")
