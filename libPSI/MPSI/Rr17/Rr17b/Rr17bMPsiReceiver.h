#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libPSI/tools/SimpleHasher.h"

namespace osuCrypto
{

    class Rr17bMPsiReceiver
    {
    public:
        Rr17bMPsiReceiver();
        ~Rr17bMPsiReceiver();
        
        bool mHashToSmallerDomain;
        u64 mN, mStatSecParam;
        block mHashingSeed;
        std::vector<u64> mIntersection;


        std::vector<std::unique_ptr<NcoOtExtReceiver>> mOtRecvs;

        SimpleHasher mBins;
        PRNG mPrng;

        void init(u64 n, u64 statSecParam, Channel& chl0, NcoOtExtReceiver& otRecv, block seed,
            double binScaler = 1.0, u64 inputBitSize = -1);
        void init(u64 n, u64 statSecParam, ArrayView<Channel> chls, NcoOtExtReceiver& ots, block seed,
            double binScaler = 1.0, u64 inputBitSize = -1);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, ArrayView<Channel> chls);

    };




}
