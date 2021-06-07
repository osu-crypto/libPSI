
	
#############################################
#              Build libPSI                 #
#############################################

file(GLOB_RECURSE SRCS *.cpp)
 

add_library(libPSI ${SRCS})

#############################################
#                 Link libOTe               #
#############################################

target_link_libraries(libPSI oc::libOTe)

target_include_directories(libPSI PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/..;${CMAKE_CURRENT_SOURCE_DIR}/..;${CMAKE_CURRENT_SOURCE_DIR}/../thirdparty/linux/sparsehash/src") 


