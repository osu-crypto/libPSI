
	
#############################################
#              Build libPSI                 #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 

add_library(libPSI ${SRCS})




#############################################
#                 Link libOTe               #
#############################################


find_library(
    libOTe_LIB
    NAMES libOTe
    HINTS "${libOTe_Dirs}/lib/")
	
find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${libOTe_Dirs}/lib/")


target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty/linux/sparsehash/src/) 
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/libPSI) 
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/libPSI) 

target_link_libraries(libPSI ${libOTe_LIB} ${cryptoTools_LIB})




if(${ENABLE_SIMPLESTOT})

	find_library(
	    SimplestOT_LIB
	    NAMES SimplestOT
	    HINTS "${libOTe_Dirs}/lib/")

    if(NOT SimplestOT_LIB)
      	message(FATAL_ERROR "Failed to find libSimplestOT.a at: ${libOTe_Dirs}/lib/")
  	else()
      	message(STATUS "Found libSimplestOT.a at: ${libOTe_Dirs}/lib/")  	
    endif()

	target_link_libraries(libPSI ${SimplestOT_LIB})

endif()



if(${ENABLE_MR_KYBER})

	find_library(
	    KyberOT_LIB
	    NAMES KyberOT
	    HINTS "${libOTe_Dirs}/lib/")

    if(NOT KyberOT_LIB)
      	message(FATAL_ERROR "Failed to find libKyberOT.a at: ${libOTe_Dirs}/lib/")
  	else()
      	message(STATUS "Found libKyberOT.a at: ${libOTe_Dirs}/lib/")  	
    endif()

	target_link_libraries(libPSI ${KyberOT_LIB})

endif()


#############################################
#                 Link Boost                #
#############################################


set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost  COMPONENTS system thread)

if(Boost_FOUND)
  message( "Found Boost at ${Boost_LIBRARIES}")
else()
   message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()

 
target_include_directories(libPSI PUBLIC ${Boost_INCLUDE_DIR}) 
target_link_libraries(libPSI ${Boost_LIBRARIES})

#############################################
#                 Link Miracl               #
#############################################


if (ENABLE_MIRACL)

    find_library(
      MIRACL_LIB 
      NAMES miracl  
      HINTS "${Miracl_Dirs}/miracl/source/")
  
    # if we cant fint it, throw an error
    if(NOT MIRACL_LIB)
      Message(${MIRACL_LIB})
      message(FATAL_ERROR "Failed to find miracl at " ${Miracl_Dirs})
    else()
      message("Miracl at  ${MIRACL_LIB}")
    endif()
    
    target_link_libraries(libPSI  ${MIRACL_LIB} )

endif()


    


## Relic
###########################################################################


if (ENABLE_RELIC)
  find_package(Relic REQUIRED)

  if (NOT Relic_FOUND)
    message(FATAL_ERROR "Failed to find Relic")
  endif (NOT Relic_FOUND)

  message(STATUS "Relic_LIB:  ${RELIC_LIBRARIES}")

  target_include_directories(libPSI PUBLIC ${RELIC_INCLUDE_DIR}) 
  target_link_libraries(libPSI ${RELIC_LIBRARIES})

endif (ENABLE_RELIC)

## WolfSSL
###########################################################################

if(ENABLE_WOLFSSL)

    if(NOT DEFINED WolfSSL_DIR)
        set(WolfSSL_DIR "/usr/local/")
    endif()


    find_library(WOLFSSL_LIB NAMES wolfssl  HINTS "${WolfSSL_DIR}")
    set(WOLFSSL_LIB_INCLUDE_DIRS "${WolfSSL_DIR}include/")

    # if we cant fint it, throw an error
    if(NOT WOLFSSL_LIB)
        message(FATAL_ERROR "Failed to find WolfSSL at " ${WolfSSL_DIR})
    endif()

    message(STATUS "WOLFSSL_LIB:  ${WOLFSSL_LIB}")
    message(STATUS "WOLFSSL_INC:  ${WOLFSSL_LIB_INCLUDE_DIRS}\n")

    target_include_directories(libPSI PUBLIC "${WOLFSSL_LIB_INCLUDE_DIRS}")
    target_link_libraries(libPSI ${WOLFSSL_LIB})

endif(ENABLE_WOLFSSL)
