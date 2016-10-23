#pragma once
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Crypto/sha1.h"
#include "OT/NChooseK/AknOtSender.h"

namespace osuCrypto {

    extern void computeAknBfParams(u64 n, u64 statSecParam, u64& totalOtCount, u64& totalOnesCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);
    

    class AknBfMPsiSender
    {
    public:
        typedef u32 LogOtCount_t;


        AknBfMPsiSender();
        ~AknBfMPsiSender();

        //void computeParameters(u64 n, u64 statSecParam, u64& totalOtCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);

        u64 mN, mStatSecParam, mBfBitCount;
        AknOtSender mAknOt;
        block mHashingSeed, mSeed;
        std::vector<SHA1> mHashs;

        void init(u64 n, u64 statSecParam, OtExtSender& otExt, Channel& chl, block seed);
        void init(u64 n, u64 statSecParam, OtExtSender& otExt, std::vector<Channel*>& chl, block seed);


        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, std::vector<Channel*>& chl);
    };

}
