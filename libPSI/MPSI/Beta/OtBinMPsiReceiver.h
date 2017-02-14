#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "MPSI/Beta/SimpleHasher.h"

namespace osuCrypto
{

    class OtBinMPsiReceiver
    {
    public:
        OtBinMPsiReceiver();
        ~OtBinMPsiReceiver();
        
        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        bool mHashToSmallerDomain;
        u64 mN, mStatSecParam, mNcoInputBlkSize;// , mOtMsgBlkSize;
        block mHashingSeed;
        std::vector<u64> mIntersection;


        std::vector<std::unique_ptr<NcoOtExtSender>> mOtSends;
        std::vector<std::unique_ptr<NcoOtExtReceiver>> mOtRecvs;

        SimpleHasher mBins;
        PRNG mPrng;

        void init(u64 n, u64 statSecParam, Channel& chl0, NcoOtExtReceiver& otRecv, NcoOtExtSender& otSend, block seed, u64 inputBitSize = -1);
        void init(u64 n, u64 statSecParam, const std::vector<Channel*>& chls, NcoOtExtReceiver& ots, NcoOtExtSender& otSend, block seed, u64 inputBitSize = -1);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);

    };




}
