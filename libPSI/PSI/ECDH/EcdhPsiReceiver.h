#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_ECDH_PSI

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"

namespace osuCrypto
{

    class EcdhPsiReceiver
    {
    public:
        EcdhPsiReceiver();
        ~EcdhPsiReceiver();

        u64 mN, mSecParam;
        PRNG mPrng;

        std::vector<u64> mIntersection;

        void init(u64 n, u64 secParam, block seed);

        void sendInput(span<block> inputs, span<Channel> chl0);

    };

}

#endif