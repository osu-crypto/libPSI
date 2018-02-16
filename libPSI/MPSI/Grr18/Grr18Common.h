#pragma once
#include <cryptoTools/Common/Defines.h>
#include <vector>
#include <cryptoTools/Crypto/PRNG.h>
#include "libPSI/Tools/SimpleHasher.h"

namespace osuCrypto
{


    u64 computeLoads(
        std::vector<u8>& loads,
        PRNG & prng,
        u64 binStart,
        bool oneSized,
        u64 n,
        SimpleHasher& bins,
        double eps,
        bool print = false);

}