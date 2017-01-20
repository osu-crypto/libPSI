#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseK/AknOtReceiver.h"


namespace osuCrypto
{

    void computeAknBfParams(u64 n, u64 statSecParam, u64& totalOtCount, u64& totalOnesCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);


    class AknBfMPsiReceiver
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
        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, std::vector<Channel*>& chl0, block seed);
        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl0);
    };

}
