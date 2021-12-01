#helper macro to assign a boolean variable 
macro(SET_BOOL var)
     if(${ARGN})
         set(${var} ON)
     else()
         set(${var} OFF)
     endif()
endmacro()

option(FETCH_AUTO      "automaticly download and build dependancies" OFF)

# here we have to do some special logic to determine if we should
# automaticly download sparsehash. This is done if we used  
#
# does not define FETCH_SPARSEHASH and define FETCH_AUTO 
# or
# define FETCH_SPARSEHASH as True/ON
SET_BOOL(FETCH_SPARSEHASH_AUTO 
	(DEFINED FETCH_SPARSEHASH AND FETCH_SPARSEHASH) OR
	((NOT DEFINED FETCH_SPARSEHASH) AND (FETCH_AUTO)))
    
# here we have to do some special logic to determine if we should
# automaticly download sparsehash. This is done if we used  
#
# does not define FETCH_LIBOTE and define FETCH_AUTO 
# or
# define FETCH_LIBOTE as True/ON
SET_BOOL(FETCH_LIBOTE_AUTO 
	(DEFINED FETCH_LIBOTE AND FETCH_LIBOTE) OR
	((NOT DEFINED FETCH_LIBOTE) AND (FETCH_AUTO)))


message(STATUS "fetch options\n=======================================================")

message(STATUS "Option: FETCH_AUTO            = ${FETCH_AUTO}")
message(STATUS "Option: FETCH_SPARSEHASH      = ${FETCH_SPARSEHASH}")
message(STATUS "Option: FETCH_LIBOTE          = ${FETCH_LIBOTE}\n")


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
option(ENABLE_DKT_PSI      "Build the DKT PSI protocol" OFF)
option(ENABLE_GRR_PSI      "Build the GRR PSI protocol" OFF)
option(ENABLE_RR16_PSI     "Build the RR16 PSI protocol" OFF)
option(ENABLE_RR17_PSI     "Build the RR17 PSI protocol" OFF)
option(ENABLE_RR17B_PSI    "Build the RR17B PSI protocol" OFF)
option(ENABLE_KKRT_PSI     "Build the KKRT PSI protocol" OFF)
option(ENABLE_ECDH_PSI     "Build the EC DH PSI protocol" OFF)
option(ENABLE_DRRN_PSI     "Build the DRRN PSI protocol" OFF)
option(ENABLE_PRTY_PSI     "Build the PRTY PSI protocol" OFF)


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


configure_file(libPSI/config.h.in libPSI/config.h)


