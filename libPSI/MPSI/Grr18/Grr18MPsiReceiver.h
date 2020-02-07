#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_GRR_PSI
#ifndef ENABLE_OOS
#pragma error("ENABLE_OOS must be defined in libOTe")
#endif

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include <libPSI/Tools/SimpleHasher.h>

namespace osuCrypto
{

    class Grr18MPsiReceiver : public TimerAdapter
    {
    public:
        Grr18MPsiReceiver();
        ~Grr18MPsiReceiver();
        
        //static const u64 CodeWordSize = 7;
        //static const u64 hasherStepSize;

        bool mHashToSmallerDomain, mOneSided = false, mLapPlusBuff = false;
        double mEpsBins = 0.9, mEpsMasks= 0.1;
        u64 mN, mStatSecParam;// , mNumOTsUpperBound;// , mOtMsgBlkSize;
        block mHashingSeed;
        std::vector<u64> mIntersection;
        std::unique_ptr<std::atomic<u64>> mTotalLoad;

        std::vector<OosNcoOtSender> mOtSends;
        std::vector<OosNcoOtReceiver> mOtRecvs;

        SimpleHasher mBins;
        PRNG mPrng;

        void init(u64 n, u64 statSecParam, Channel& chl0, OosNcoOtReceiver& otRecv, OosNcoOtSender& otSend, block seed,
            double binScaler = 4.0, u64 inputBitSize = -1);
        void init(u64 n, u64 statSecParam, span<Channel> chls, OosNcoOtReceiver& ots, OosNcoOtSender& otSend, block seed,
            double binScaler = 4.0, u64 inputBitSize = -1);

        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chls);

    };




}
#endif