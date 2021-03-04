
#project(libPSI_Tests)


 

#############################################
#               Build libPSI_Tests            #
#############################################

file(GLOB_RECURSE SRCS *.cpp)

include_directories(${CMAKE_SOURCE_DIR}/libPSI_Tests)


add_library(libPSI_Tests ${SRCS} "Paxos_Tests.cpp")

target_link_libraries(libPSI_Tests libPSI)
