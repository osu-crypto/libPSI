
#project(libPSI)


#############################################
#                 Link NTL                  #
#############################################
if(USE_NTL)
	set(NTL_Lib_Dirs "${NTL_Dirs}src/")
	set(NTL_Include_Dirs "${NTL_Dirs}/include/")

	# default location for NTL
	#set(NTL_LIB "${NTL_Lib_Dirs}nnnnlibntl.a")


	#if(NOT EXISTS "${NTL_LIB}")
	  # we failed to find it, try using find_library
	  find_library(
		NTL_LIB 
		NAMES ntl libntl.a  
		PATHS "${NTL_Lib_Dirs}")
  
	  # if we still cant fint it, throw an error
	  if(NOT NTL_LIB) 
		if(EXISTS "${NTL_Lib_Dirs}libntl.a")
			set(NTL_LIB "${NTL_Lib_Dirs}libntl.a")
		else()
		   Message(${NTL_LIB})
			message(FATAL_ERROR "Failed to find NTL at ${NTL_Lib_Dirs} or at system locations." )
		endif()
	  endif()
	#endif()
	message(STATUS "NTL  ${NTL_LIB}")
	message(STATUS "NTL  ${NTL_Include_Dirs}")
	message(STATUS "NTL  ${NTL_Lib_Dirs}")
else()
	Message(STATUS "not using NTL.")
endif()


#############################################
#                 Link Boost                #
#############################################


set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME     ON)

find_package(Boost  COMPONENTS system thread)

if(Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIR}) 
  message( "Found Boost at ${Boost_LIBRARIES}")
else()
   message(FATAL_ERROR "Failed to find boost at " ${Boost_Lib_Dirs} " Need system thread")
endif()

 
#############################################
#                 Link Miracl               #
#############################################
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


#############################################
#              Build libPSI                 #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 
include_directories(${CMAKE_SOURCE_DIR}/libPSI)

add_library(libPSI ${SRCS})

target_link_libraries(libPSI ${libOTe_LIB} ${cryptoTools_LIB} ${MIRACL_LIB} ${NTL_LIB} ${Boost_LIBRARIES})

