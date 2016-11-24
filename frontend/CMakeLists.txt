
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
target_link_libraries(frontend.exe libPSI_Tests)
target_link_libraries(frontend.exe libPSI)