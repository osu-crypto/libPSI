#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_GRR_PSI

#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <cryptoTools/Crypto/PRNG.h>
#include "libPSI/Tools/SimpleHasher.h"

namespace osuCrypto
{

    extern bool mGrr18PrintWarning;

    u64 computeLoads(
        std::vector<u8>& loads,
        PRNG & prng,
        u64 binStart,
        bool oneSided,
        bool lapPlusBuffer,
        u64 n,
        SimpleHasher& bins,
        double eps,
        i64 cwThreshold = -1,
        bool print = false);

}
#endif