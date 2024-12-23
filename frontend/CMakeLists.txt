
#project(fronend)


 

#############################################
#               Build fronend.exe           #
#############################################

file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/frontend/*.cpp)
include_directories(${CMAKE_SOURCE_DIR}/frontend/)

add_executable(frontend.exe ${SRC_FRONTEND})


#############################################
#            Link our libraries             #
#############################################



#############################################
#                 Link libOTe               #
#############################################

target_link_libraries(frontend.exe PUBLIC libPSI libPSI_Tests oc::libOTe_Tests oc::tests_cryptoTools)


if(MSVC)
    target_compile_options(frontend.exe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/std:c++${LIBPSI_STD_VER}>)
    #target_compile_options(libOTe PRIVATE -openmp:experimental)
else()
    target_compile_options(frontend.exe PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++${LIBPSI_STD_VER}>)

endif()