#pragma once

#include <cryptoTools/Common/Version.h>
#include <libOTe/config.h>

static_assert(CRYPTO_TOOLS_VERSION >= 10500, "please update libOTe and cryptoTools.");
static_assert(LIBOTE_VERSION >= 10000, "please update libOTe and cryptoTools.");

#define LIB_PSI_VERSION_MAJOR 1
#define LIB_PSI_VERSION_MINOR 1
#define LIB_PSI_VERSION_PATCH 0
#define LIB_PSI_VERSION (LIB_PSI_VERSION_MAJOR * 10000 + LIB_PSI_VERSION_MINOR * 100 + LIB_PSI_VERSION_PATCH)