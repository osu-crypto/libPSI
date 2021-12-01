

if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################
	if(MSVC)
	else()
		set(COMMON_FLAGS "-Wall -Wfatal-errors")

		if(NOT DEFINED NO_ARCH_NATIVE)
			set(COMMON_FLAGS "${COMMON_FLAGS} -march=native")
		endif()
		SET(CMAKE_CXX_FLAGS_RELEASE "-O3  -DNDEBUG")
		SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb")
		SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb")		
	endif()



	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON_FLAGS}")
	

	############################################
	#           Build mode checks              #
	############################################

	# Set a default build type for single-configuration
	# CMake generators if no build type is set.
	if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	   SET(CMAKE_BUILD_TYPE Release)
	endif()

	if(    NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Release"
       AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug"
       AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo" )

        message(WARNING ": Unknown build type - \${CMAKE_BUILD_TYPE}=${CMAKE_BUILD_TYPE}.  Please use one of Debug, Release, or RelWithDebInfo. e.g. call\n\tcmake . -DCMAKE_BUILD_TYPE=Release\n" )
	endif()
endif()

if(MSVC)
    set(LIBPSI_CONFIG_NAME "${CMAKE_BUILD_TYPE}")
    if("${LIBPSI_CONFIG_NAME}" STREQUAL "RelWithDebInfo" OR "${LIBPSI_CONFIG_NAME}" STREQUAL "")
        set(LIBPSI_CONFIG_NAME "Release")
	endif()
    set(LIBPSI_CONFIG "x64-${LIBPSI_CONFIG_NAME}")
elseif(APPLE)
    set(LIBPSI_CONFIG "osx")
else()
    set(LIBPSI_CONFIG "linux")
endif()

if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/install.cmake)
	set(LIBPSI_IN_BUILD_TREE ON)
else()
	set(LIBPSI_IN_BUILD_TREE OFF)
endif()

if(LIBPSI_IN_BUILD_TREE)

    # we currenty are in the vole psi source tree, vole-psi/cmake
	if(NOT DEFINED LIBPSI_BUILD_DIR)
		set(LIBPSI_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/build/${LIBPSI_CONFIG}")
		get_filename_component(LIBPSI_BUILD_DIR ${LIBPSI_BUILD_DIR} ABSOLUTE)
	endif()

	if(NOT (${CMAKE_BINARY_DIR} STREQUAL ${LIBPSI_BUILD_DIR}))
		message(WARNING "incorrect build directory. \n\tCMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}\nbut expect\n\tLIBPSI_BUILD_DIR=${LIBPSI_BUILD_DIR}")
	endif()

	if(NOT DEFINED LIBPSI_THIRDPARTY_DIR)
		set(LIBPSI_THIRDPARTY_DIR "${CMAKE_CURRENT_LIST_DIR}/../out/install/${LIBPSI_CONFIG}")
		get_filename_component(LIBPSI_THIRDPARTY_DIR ${LIBPSI_THIRDPARTY_DIR} ABSOLUTE)
	endif()
else()
    # we currenty are in install tree, <install-prefix>/lib/cmake/vole-psi
	if(NOT DEFINED LIBPSI_THIRDPARTY_DIR)
		set(LIBPSI_THIRDPARTY_DIR "${CMAKE_CURRENT_LIST_DIR}/../../..")
		get_filename_component(LIBPSI_THIRDPARTY_DIR ${LIBPSI_THIRDPARTY_DIR} ABSOLUTE)
	endif()
endif()

