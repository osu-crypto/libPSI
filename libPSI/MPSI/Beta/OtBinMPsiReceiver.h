#pragma once

#include "Common/Defines.h"
#include "Network/Channel.h"
#include "OT/NChooseOne/NcoOtExt.h"
#include "MPSI/Beta/SimpleHasher.h"

namespace osuCrypto
{

    class OtBinMPsiReceiver
    {
    public:
        OtBinMPsiReceiver();
        ~OtBinMPsiReceiver();
        
        static const u64 CodeWordSize = 7;
        static const u64 hasherStepSize = 128;

        u64 mN,mStatSecParam;
        block mHashingSeed;
        std::vector<u64> mIntersection;

        NcoOtExtSender* mOtSend;
        NcoOtExtReceiver* mOtRecv;

        std::vector<block> mSendOtMessages;
        std::vector<std::array<block, 2>> mRecvOtMessages;
        SimpleHasher mBins;
        PRNG mPrng;

        void init(u64 n, u64 statSecParam, u64 inputBitSize, Channel& chl0, NcoOtExtReceiver& otRecv, NcoOtExtSender& otSend, block seed);
        void init(u64 n, u64 statSecParam, u64 inputBitSize, const std::vector<Channel*>& chls, NcoOtExtReceiver& ots, NcoOtExtSender& otSend, block seed);
        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);

    };




}
