
#project(libPSI_Tests)


 

#############################################
#               Build libPSI_Tests            #
#############################################

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR}/libPSI_Tests)


add_library(libPSI_Tests ${SRCS})

target_link_libraries(libPSI_Tests libPSI)

if(MSVC)
    target_compile_options(libPSI_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBPSI_STD_VER}>)
    #target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(libPSI_Tests PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBPSI_STD_VER}>)

endif()