#pragma once
#include <cryptoTools/Common/config.h>
#include <libOTe/config.h>

#if LIBOTE_VERSION < 10000
Config ERROR : libOTe is too old.
#endif

#define ON 1


#if ENABLE_RELIC !=  ON
Config ERROR: ENABLE_RELIC flag does not match with libOTe
#endif

#if ENABLE_MIRACL !=  OFF
Config ERROR: ENABLE_MIRACL flag does not match with libOTe
#endif

#if !defined(_MSC_VER) &&  (ENABLE_SIMPLESTOT !=  ON)
Config ERROR: ENABLE_SIMPLESTOT flag does not match with libOTe
#endif

#if !defined(_MSC_VER) && (ENABLE_MR_KYBER !=  ON)
Config ERROR: ENABLE_MR_KYBER flag does not match with libOTe
#endif



// build the library with DCW PSI enabled
#define ENABLE_DCW_PSI  ON

// build the library with DKT PSI enabled
#define ENABLE_DKT_PSI  ON

// build the library with GRR PSI enabled
#define ENABLE_GRR_PSI  ON

// build the library with RR16 PSI enabled
#define ENABLE_RR16_PSI  ON

// build the library with RR17 PSI enabled
#define ENABLE_RR17_PSI  ON

// build the library with RR17 PSI enabled
/* #undef ENABLE_RR17B_PSI */

// build the library with KKRT PSI enabled
#define ENABLE_KKRT_PSI  ON

// build the library with ECDH PSI enabled
#define ENABLE_ECDH_PSI  ON

// build the library with DRRN PSI enabled
#define ENABLE_DRRN_PSI  ON


#undef ON
