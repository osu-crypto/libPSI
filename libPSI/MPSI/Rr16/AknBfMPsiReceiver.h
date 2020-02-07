#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_RR16_PSI

#ifndef ENABLE_AKN
#pragma error("ENABLE_AKN must be defined in libOTe")
#endif

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseK/AknOtReceiver.h"


namespace osuCrypto
{

    void computeAknBfParams(u64 n, u64 statSecParam, u64& totalOtCount, u64& totalOnesCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);


    class AknBfMPsiReceiver : public TimerAdapter
    {
    public:
        typedef u32 LogOtCount_t;

        
        AknBfMPsiReceiver();
        ~AknBfMPsiReceiver();

        AknOtReceiver mAknOt;
        //SHA1 mHash;
        u64 mMyInputSize, mTheirInputSize, mBfBitCount, mStatSecParam, mTotalOtCount, mNumHashFunctions;
        block mHashingSeed, mSeed;
        std::vector<u64> mIntersection;

        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel& chl0, block seed);
        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, span<Channel> chl0, block seed);
        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chl0);
    };

}

#endif