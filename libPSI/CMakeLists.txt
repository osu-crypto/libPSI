
	
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

                     
if(MSVC)
    target_compile_options(libPSI PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBPSI_STD_VER}>)
    #target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(libPSI PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBPSI_STD_VER}>)

endif()