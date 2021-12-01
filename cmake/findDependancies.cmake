include(${CMAKE_CURRENT_LIST_DIR}/preamble.cmake)


# here we find out depandancies. This happens when we build our project and
# when someone includes our project via find_project(LIBPSI). As such,
# we also have to make sure this also works when we are installed. 


message(STATUS "LIBPSI_THIRDPARTY_DIR=${LIBPSI_THIRDPARTY_DIR}")

# cmake will look for out depandancies at the paths in CMAKE_PREFIX_PATH
# if LIBPSI_THIRDPARTY_DIR is defined, we want this to be the first place
# that is looked at. To make sure only our libraries are looked for here,
# we will resort CMAKE_PREFIX_PATH to its old value at the end if the file.
set(PUSHED_CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH})
set(CMAKE_PREFIX_PATH "${LIBPSI_THIRDPARTY_DIR};${CMAKE_PREFIX_PATH}")


#######################################
# sparsehash


# here we will look for sparsehash and download it if requested. 
# sparsehash doesnt supports find_package so we look for it manually.

# first we will define a macro because we might look for it more than once.
macro(FIND_SPARSEHASH)
    # assign any macro arguemnts to the ARGS variable. 
    set(ARGS ${ARGN})

    # If the user explicitly asked to fetch libOTe, then we dont want to 
    # look for libOTe at any location other than LIBPSI_THIRDPARTY_DIR.
    # this is done with including NO_DEFAULT_PATH as an argument and 
    # specifying where we want to look using PATHS
    if(FETCH_SPARSEHASH)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${LIBPSI_THIRDPARTY_DIR})
    endif()
    
    # next we need to look for the sparsehash headers. One such header is dense_hash_map.
    # we expect this header to be at <some_path>/include/sparsehash/dense_hash_map. We 
    # will have cmake look for this file. cmake will look at system locations and paths
    # specified in the CMAKE_PREFIX_PATH variable. 
    find_path(SPARSEHASH_INCLUDE_DIRS "sparsehash/dense_hash_map" PATH_SUFFIXES "include" ${ARGS}
        DOC "Use -DFETCH_AUTO=ON to automaticly download dependancies")

    # if you are linking a library you will also need to find that via find_library(...)

    # check if we found sparse hash.
    if(EXISTS ${SPARSEHASH_INCLUDE_DIRS})
        set(SPARSEHASH_FOUND ON)
    else()
        set(SPARSEHASH_FOUND OFF)
    endif()
endmacro()


# FETCH_SPARSEHASH_AUTO is set if we should download sparsehash. If we should,
# then we first check if we already have it via the FIND_SPARSEHASH(QUIET)
# call. Then we call the getSparsehash.cmake script to download sparsehash if
# we dont already have it.
if(FETCH_SPARSEHASH_AUTO)
    FIND_SPARSEHASH(QUIET)
    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getSparsehash.cmake)
endif()

FIND_SPARSEHASH(REQUIRED)
message("SPARSEHASH_INCLUDE_DIRS=${SPARSEHASH_INCLUDE_DIRS}")

# If the sparse ahsh target has not been previously defined, lets define it.
if(NOT TARGET sparsehash)

    # since we didnt build sparse, we declare it as an IMPORTED target.
    # moreover, sparsehash is header only so we declare it as INTERFACE.
    add_library(sparsehash INTERFACE IMPORTED)

    #if sparsehash had an associated static library which we previously found, then
    # we could declare it as:
    #
    #  add_library(sparsehash STATIC IMPORTED)
    #  set_property(TARGET sparsehash PROPERTY IMPORTED_LOCATION ${SPARSEHASH_LIB})

    # in either case, we set the header directory as 
    target_include_directories(sparsehash INTERFACE 
                    $<BUILD_INTERFACE:${SPARSEHASH_INCLUDE_DIRS}>
                    $<INSTALL_INTERFACE:>)
endif()



#######################################
# libOTe


# here we will look for libOTe and download it if requested. 
# libOTe supports find_package so its pretty easy. 

# first we will define a macro because we might look for it more than once.
macro(FIND_LIBOTE)

    # assign any macro arguemnts to the ARGS variable. 
    set(ARGS ${ARGN})

    # If the user explicitly asked to fetch libOTe, then we dont want to 
    # look for libOTe at any location other than LIBPSI_THIRDPARTY_DIR.
    # this is done with including NO_DEFAULT_PATH as an argument and 
    # specifying where we want to look using PATHS
    if(FETCH_LIBOTE)
        list(APPEND ARGS NO_DEFAULT_PATH PATHS ${LIBPSI_THIRDPARTY_DIR})
    endif()
    
    # look for libOTe. cmake will look at system locations and paths
    # specified in the CMAKE_PREFIX_PATH variable. 
    # 
    # libOTeConfig.cmake
    #
    # CMAKE_PREFIX_PATH/lib/cmake/libOTe/libOTeConfig.cmake
    # CMAKE_PREFIX_PATH/libOTe/cmake/libOTeConfig.cmake
    find_package(libOTe ${ARGS})

    # check if we found it. 
    if(TARGET oc::libOTe)
        set(libOTe_FOUND ON)
    else()
        set(libOTe_FOUND  OFF)
    endif()
endmacro()

# FETCH_LIBOTE_AUTO is set if we should download libOTe. If we should,
# then we first check if we already have it via the FIND_LIBOTE(QUIET)
# call. Then we call the getLibOTe.cmake script to download libOTe if
# we dont already have it. 
if(FETCH_LIBOTE_AUTO)
    FIND_LIBOTE(QUIET)
    include(${CMAKE_CURRENT_LIST_DIR}/../thirdparty/getLibOTe.cmake)
endif()

# finally, we make sure we have found libOTe.
FIND_LIBOTE(REQUIRED)


# resort the previous prefix path
set(CMAKE_PREFIX_PATH ${PUSHED_CMAKE_PREFIX_PATH})
