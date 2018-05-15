#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libPSI/Tools/SimpleHasher.h"

namespace osuCrypto
{


    class Grr18MPsiSender : public TimerAdapter
    {
    public:


        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        Grr18MPsiSender();
        ~Grr18MPsiSender();

        bool mHashToSmallerDomain, mOneSided = true;
        double mEps = 1.0;
        u64 mN, mStatSecParam, mOtMsgBlkSize;//, mNumOTsUpperBound;
        block mHashingSeed;
        SimpleHasher mBins;
        PRNG mPrng;

        std::vector<std::unique_ptr<OosNcoOtSender>> mOtSends;
        std::vector<std::unique_ptr<OosNcoOtReceiver>> mOtRecvs;

        void init(u64 n, u64 statSecParam,
            span<Channel> chls,
            OosNcoOtSender& ots,
            OosNcoOtReceiver& otRecv,
            block seed,
            double binScaler = 4.0,
            u64 inputBitSize = -1);

        void init(u64 n, u64 statSecParam,
            Channel & chl0, 
            OosNcoOtSender& ots,
            OosNcoOtReceiver& otRecv,
            block seed,
            double binScaler = 4.0,
            u64 inputBitSize = -1);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chls);



    };

}