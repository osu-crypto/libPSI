#pragma once

#include <cryptoTools/Common/Version.h>


static_assert(CRYPTO_TOOLS_VERSION >= 10303, "please update libOTe and cryptoTools.");

#define LIB_PSI_VERSION_MAJOR 1
#define LIB_PSI_VERSION_MINOR 0
#define LIB_PSI_VERSION_PATCH 0
#define LIB_PSI_VERSION (LIB_PSI_VERSION_MAJOR * 10000 + LIB_PSI_VERSION_MINOR * 100 + LIB_PSI_VERSION_PATCH)