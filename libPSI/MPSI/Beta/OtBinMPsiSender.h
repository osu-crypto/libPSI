#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "NChooseOne/NcoOtExt.h"
#include "MPSI/Beta/SimpleHasher.h"

namespace osuCrypto
{


    class OtBinMPsiSender
    {
    public:


        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        OtBinMPsiSender();
        ~OtBinMPsiSender();

        u64 mN, mStatSecParam, mNcoInputBlkSize,  mOtMsgBlkSize;
        block mHashingSeed;
        SimpleHasher mBins;
        PRNG mPrng;

        std::vector<std::unique_ptr<NcoOtExtSender>> mOtSends;
        std::vector<std::unique_ptr<NcoOtExtReceiver>> mOtRecvs;

        void init(u64 n, u64 statSecParam, u64 inputBitSize, 
            const std::vector<Channel*>& chls, 
            NcoOtExtSender& ots, 
            NcoOtExtReceiver& otRecv, 
            block seed);

        void init(u64 n, u64 statSecParam, u64 inputBitSize, 
            Channel & chl0, 
            NcoOtExtSender& ots,
            NcoOtExtReceiver& otRecv,
            block seed);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs,const std::vector<Channel*>& chls);

    };

}