

#############################################
#            Install                        #
#############################################

# we have to install these scripts since the we required 
# find our depandancies wheneven someone want to include 
# this project. 
configure_file("${CMAKE_CURRENT_LIST_DIR}/findDependancies.cmake" "findDependancies.cmake" COPYONLY)
configure_file("${CMAKE_CURRENT_LIST_DIR}/preamble.cmake" "preamble.cmake" COPYONLY)

# make cache variables for install destinations
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# generate the config file that is includes the exports
configure_package_config_file(
  "${CMAKE_CURRENT_LIST_DIR}/Config.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/libPSIConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libPSI
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

if(NOT DEFINED libPSI_VERSION_MAJOR)
    message("\n\n\n\n warning, libPSI_VERSION_MAJOR not defined ${libPSI_VERSION_MAJOR}")
endif()

set_property(TARGET libPSI PROPERTY VERSION ${libPSI_VERSION})

# generate the version file for the config file
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/libPSIConfigVersion.cmake"
  VERSION "${libPSI_VERSION_MAJOR}.${libPSI_VERSION_MINOR}.${libPSI_VERSION_PATCH}"
  COMPATIBILITY AnyNewerVersion
)

# install the configuration file
install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/libPSIConfig.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/libPSIConfigVersion.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/findDependancies.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/preamble.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libPSI
)

# install library
install(
    TARGETS libPSI
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    EXPORT libPSITargets)

# install headers
install(
    DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../libPSI"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/"
    FILES_MATCHING PATTERN "*.h")

# install config and use the "namespace" of oc::
install(EXPORT libPSITargets
  FILE libPSITargets.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libPSI
       NAMESPACE oc::
)
 export(EXPORT libPSITargets
       FILE "${CMAKE_CURRENT_BINARY_DIR}/libPSITargets.cmake"
       NAMESPACE oc::
)