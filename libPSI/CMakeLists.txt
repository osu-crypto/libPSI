
	
#############################################
#              Build libPSI                 #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 

add_library(libPSI ${SRCS})

#############################################
#                 Link libOTe               #
#############################################

target_link_libraries(libPSI oc::libOTe sparsehash)

target_include_directories(libPSI PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/..>
                    $<INSTALL_INTERFACE:>) 
target_include_directories(libPSI PUBLIC 
                    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
                    $<INSTALL_INTERFACE:>) 

