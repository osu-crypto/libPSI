cmake_minimum_required (VERSION 3.18)

project("libPSI" VERSION 1.0.0)

# sets some variables
include(cmake/preamble.cmake)

# sets build option
include(cmake/buildOptions.cmake)

# find all the dependancies.
include(cmake/findDependancies.cmake)

add_definitions(-DSOLUTION_DIR=\"${CMAKE_SOURCE_DIR}\")

#############################################
#               Build libPSI                 #
#############################################

add_subdirectory(libPSI)
add_subdirectory(libPSI_Tests)
add_subdirectory(frontend)



# setup the install
include(cmake/install.cmake)