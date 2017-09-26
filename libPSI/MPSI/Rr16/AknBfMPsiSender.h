#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/sha1.h"
#include "libOTe/NChooseK/AknOtSender.h"

namespace osuCrypto {

    extern void computeAknBfParams(u64 n, u64 statSecParam, u64& totalOtCount, u64& totalOnesCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);
    

    class AknBfMPsiSender
    {
    public:
        typedef u32 LogOtCount_t;


        AknBfMPsiSender();
        ~AknBfMPsiSender();

        //void computeParameters(u64 n, u64 statSecParam, u64& totalOtCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);

        u64 mN, mStatSecParam, mBfBitCount, mNumHashFunctions;
        AknOtSender mAknOt;
        block mHashingSeed, mSeed;
        //std::vector<SHA1> mHashs;

        void init(u64 n, u64 statSecParam, OtExtSender& otExt, Channel& chl, block seed);
        void init(u64 n, u64 statSecParam, OtExtSender& otExt, span<Channel>chl, block seed);


        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chl);
    };

}
