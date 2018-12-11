#pragma once

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"


#if defined ENABLE_RELIC  || defined ENABLE_MIRACL
#define ENABLE_ECDH_PSI

namespace osuCrypto
{
    class EcdhPsiSender
    {
    public:
        EcdhPsiSender();
        ~EcdhPsiSender();


        u64 mN, mSecParam;
        PRNG mPrng;

        void init(u64 n, u64 secParam, block seed);
        //void init(u64 n, u64 statSecParam);


        void sendInput(std::vector<block>& inputs, span<Channel> chl);
        //void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };

}

#endif