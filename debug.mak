BINARYDIR := Debug

#Toolchain
CXX := g++
LD := $(CXX)
AR := ar
OBJCOPY := objcopy

#Additional flags
PREPROCESSOR_MACROS := NDEBUG RELEASE
INCLUDE_DIRS := ./PSI ./PSITests ./thirdparty/linux/boost/includes
LIBRARY_DIRS := ./thirdparty/linux/boost/stage/lib ./thirdparty/linux/cryptopp ./thirdparty/linux/Miracl/source ./thirdparty/linux/mpir/.libs ./Debug ./thirdparty/linux/ntl/src/
LIBRARY_NAMES := PSI PSITests boost_system boost_filesystem boost_thread mpir miracl cryptopp pthread rt ntl
ADDITIONAL_LINKER_INPUTS := 
MACOS_FRAMEWORKS := 
LINUX_PACKAGES := 


CXXFLAGS := -ggdb -ffunction-sections -O0 -Wall -std=c++11 -maes -msse2 -msse4.1 -mpclmul -Wfatal-errors -pthread
LDFLAGS := -Wl,-gc-sections
COMMONFLAGS := 

START_GROUP := -Wl,--start-group
END_GROUP := -Wl,--end-group

