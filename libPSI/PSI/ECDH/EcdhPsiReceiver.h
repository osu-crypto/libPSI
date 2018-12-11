#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"



#if defined ENABLE_RELIC 
#define ENABLE_ECDH_PSI_R

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