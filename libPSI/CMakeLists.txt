
	
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
    SimplestOT_LIB
    NAMES SimplestOT
    HINTS "${libOTe_Dirs}/lib/")

find_library(
    cryptoTools_LIB
    NAMES cryptoTools
    HINTS "${libOTe_Dirs}/lib/")


target_include_directories(libPSI PUBLIC ${Boost_INCLUDE_DIR}) 
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty/linux/sparsehash/src/) 
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/libPSI) 
target_include_directories(libPSI PUBLIC ${CMAKE_SOURCE_DIR}/libPSI) 

target_link_libraries(libPSI ${libOTe_LIB} ${SimplestOT_LIB} ${cryptoTools_LIB})




option(ENABLE_MIRACL "use the miracl library" OFF)
option(ENABLE_RELIC "use the relic library" OFF)

message(STATUS "Option: ENABLE_MIRACL     = ${ENABLE_MIRACL}")
message(STATUS "Option: ENABLE_RELIC      = ${ENABLE_RELIC}")

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

