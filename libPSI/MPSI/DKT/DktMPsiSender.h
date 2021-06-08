#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_DKT_PSI

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"

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


        void sendInput(std::vector<block>& inputs, span<Channel> chl);
        //void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };


}
#endif