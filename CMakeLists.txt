cmake_minimum_required (VERSION 2.8)

project("libPSI")


if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")

	############################################
	#          If top level cmake              #
	############################################
	if(${CMAKE_VERSION} VERSION_LESS "3.12.0") 
		message("Please consider updating CMake to 3.12+")
	endif()

	set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/bin)
	set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)
	set( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_HOME_DIRECTORY}/lib)

	############################################
	#           Flag and #defines              #
	############################################
	set(CMAKE_C_FLAGS "-march=native -Wall  -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread -fPIC -no-pie -Wno-ignored-attributes -Wno-parentheses")
	set(CMAKE_CXX_FLAGS  "${CMAKE_C_FLAGS}  -std=c++14")
	
	# Select flags.
	SET(CMAKE_CXX_FLAGS_RELEASE "-O3  -DNDEBUG") 
	SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO " -O2 -g -ggdb -rdynamic")
	SET(CMAKE_CXX_FLAGS_DEBUG  "-O0 -g -ggdb -rdynamic")
	

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
		  
        message(FATAL_ERROR ": Unknown build type - \${CMAKE_BUILD_TYPE}=${CMAKE_BUILD_TYPE}.  Please use one of Debug, Release, or RelWithDebInfo. e.g. call\n\tcmake . -DCMAKE_BUILD_TYPE=Release\n" )        
	endif()
endif()

add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")


#############################################
#       Library/includes locations          #
#############################################

include_directories("${CMAKE_SOURCE_DIR}")

# default location for libOTe
set(libOTe_Dirs "${CMAKE_SOURCE_DIR}/../libOTe/")
include_directories("${libOTe_Dirs}/") 
include_directories("${libOTe_Dirs}/cryptoTools") 

# default location for miracl
set(Miracl_Dirs "${libOTe_Dirs}/cryptoTools/thirdparty/linux/miracl/")
include_directories("${Miracl_Dirs}") 

# default location for NTL
#set(NTL_Dirs "${CMAKE_SOURCE_DIR}/thirdparty/linux/ntl/")
#include_directories("${NTL_Dirs}/include/")

# default location for Boost
set(BOOST_ROOT "${libOTe_Dirs}/cryptoTools/thirdparty/linux/boost/")


#############################################
#                CONFIGURE                  #
#############################################


if(DEFINED ENABLE_ALL_PSI)
	set(ENABLE_DCW_PSI   ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_DKT_PSI   ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_GRR_PSI   ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_RR16_PSI  ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_RR17_PSI  ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_RR17B_PSI ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_KKRT_PSI  ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_ECDH_PSI  ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	set(ENABLE_DRRN_PSI  ${ENABLE_ALL_PSI} CACHE BOOL "" FORCE)
	unset(ENABLE_ALL_PSI CACHE)
endif()

option(ENABLE_DCW_PSI      "Build the DCW PSI protocol" OFF)
option(ENABLE_DKT_PSI      "Build the DKR PSI protocol" OFF)
option(ENABLE_GRR_PSI      "Build the GRR PSI protocol" OFF)
option(ENABLE_RR16_PSI     "Build the RR16 PSI protocol" OFF)
option(ENABLE_RR17_PSI     "Build the RR17 PSI protocol" OFF)
option(ENABLE_RR17B_PSI    "Build the RR17B PSI protocol" OFF)
option(ENABLE_KKRT_PSI     "Build the KKRT PSI protocol" OFF)
option(ENABLE_ECDH_PSI     "Build the EC DH PSI protocol" OFF)
option(ENABLE_DRRN_PSI     "Build the DRRN PSI protocol" OFF)

option(ENABLE_MIRACL     "use the miracl library" OFF)
option(ENABLE_RELIC      "use the relic library" OFF)
option(ENABLE_SIMPLESTOT "use the simplest OT library" OFF)
option(ENABLE_MR_KYBER   "use the kyber OT library" OFF)

message(STATUS "General Options\n=======================================================")
message(STATUS "Option: CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}\n\tRelease\n\tDebug\n\tRELWITHDEBINFO")
message(STATUS "Option: ENABLE_ALL_PSI         = ON/OFF\n\n")

message(STATUS "PSI protocols\n=======================================================")
message(STATUS "Option: ENABLE_DCW_PSI    = ${ENABLE_DCW_PSI}")
message(STATUS "Option: ENABLE_DKT_PSI    = ${ENABLE_DKT_PSI}")
message(STATUS "Option: ENABLE_GRR_PSI    = ${ENABLE_GRR_PSI}")
message(STATUS "Option: ENABLE_RR16_PSI   = ${ENABLE_RR16_PSI}")
message(STATUS "Option: ENABLE_RR17_PSI   = ${ENABLE_RR17_PSI}")
message(STATUS "Option: ENABLE_RR17B_PSI  = ${ENABLE_RR17B_PSI}")
message(STATUS "Option: ENABLE_KKRT_PSI   = ${ENABLE_KKRT_PSI}")
message(STATUS "Option: ENABLE_ECDH_PSI   = ${ENABLE_ECDH_PSI}")
message(STATUS "Option: ENABLE_DRRN_PSI   = ${ENABLE_DRRN_PSI}\n")


message(STATUS "libOTe & cryptoTools options\n=======================================================")
message(STATUS "Option: ENABLE_MIRACL     = ${ENABLE_MIRACL}")
message(STATUS "Option: ENABLE_RELIC      = ${ENABLE_RELIC}")
message(STATUS "Option: ENABLE_SIMPLESTOT = ${ENABLE_SIMPLESTOT}")
message(STATUS "Option: ENABLE_MR_KYBER   = ${ENABLE_MR_KYBER}\n\n")

configure_file(libPSI/config.h.in libPSI/config.h)

#############################################
#               Build libPSI                 #
#############################################
add_subdirectory(libPSI)
include_directories(libPSI)


#############################################
#           Build libPSI Tests              #
#############################################
add_subdirectory(libPSI_Tests)
include_directories(libPSI_Tests)


#############################################
#              Build Frontend               #
#############################################
add_subdirectory(frontend)


