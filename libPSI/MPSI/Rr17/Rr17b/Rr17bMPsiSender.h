#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libPSI/tools/SimpleHasher.h"

namespace osuCrypto
{


    class Rr17bMPsiSender
    {
    public:


        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        Rr17bMPsiSender();
        ~Rr17bMPsiSender();

        bool mHashToSmallerDomain;
        u64 mN, mStatSecParam;
        block mHashingSeed;
        SimpleHasher mBins;
        PRNG mPrng;

        std::vector<std::unique_ptr<NcoOtExtSender>> mOtSends;

        void init(u64 n, u64 statSecParam,
			ArrayView<Channel> chls,
            NcoOtExtSender& ots, 
            block seed,
            double binScaler = 1.0,
            u64 inputBitSize = -1);

        void init(u64 n, u64 statSecParam,
            Channel & chl0, 
            NcoOtExtSender& ots,
            block seed,
            double binScaler = 1.0,
            u64 inputBitSize = -1);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, ArrayView<Channel> chls);

    };

}