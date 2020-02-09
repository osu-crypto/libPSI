#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_DCW_PSI

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"

namespace osuCrypto {

    

    class DcwRBfPsiSender
    {
    public:

        u64 mN, mBfBitCount, mNumHashFunctions;

        std::vector<std::array<block, 2>> mSendOtMessages;
        block mSeed, mHashSeed;

        void init(u64 n, u64 statSecParam, OtExtSender& otExt, Channel& chl, block seed);
        void init(u64 n, u64 statSecParam, OtExtSender& otExt, span<Channel> chl, block seed);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chl);
    };

}


#endif