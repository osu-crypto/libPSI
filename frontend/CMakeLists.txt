
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


find_library(
    libOTe_Tests_LIB
    NAMES libOTe_Tests
    HINTS "${libOTe_Dirs}/lib/")

find_library(
    cryptoTools_Tests_LIB
    NAMES tests_cryptoTools
    HINTS "${libOTe_Dirs}/lib/")

target_link_libraries(frontend.exe libPSI_Tests libPSI ${libOTe_Tests_LIB} ${cryptoTools_Tests_LIB})
