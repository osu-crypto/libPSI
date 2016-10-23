#pragma once

#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Crypto/PRNG.h"

namespace osuCrypto
{
    class DktMPsiSender
    {
    public:
        DktMPsiSender();
        ~DktMPsiSender();


        u64 mN, mSecParam;
        PRNG mPrng;

        void init(u64 n, u64 secParam, block seed);
        //void init(u64 n, u64 statSecParam);


        void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
        //void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };

}