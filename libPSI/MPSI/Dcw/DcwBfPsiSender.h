#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/sha1.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"

namespace osuCrypto {

    

    class DcwBfPsiSender
    {
    public:
        DcwBfPsiSender();
        ~DcwBfPsiSender();

        //void computeParameters(u64 n, u64 statSecParam, u64& totalOtCount, u64& cncOnesThreshold, double& cncProb, u64& numHashFunctions, u64& bfBitCount);

        u64 mN, mStatSecParam, mBfBitCount;
        //DcwOtSender mDcwOt;
        block mHashingSeed;
        std::vector<SHA1> mHashs;

        std::vector<std::array<block, 2>> mSendOtMessages;
        block computeSecureSharing(span<block> shares);
        block mEncSeed, mSeed;

        std::vector<block>mShares;
        block mSharesPrime;
        void init(u64 n, u64 statSecParam, OtExtSender& otExt, Channel& chl, block seed);
        void init(u64 n, u64 statSecParam, OtExtSender& otExt, span<Channel> chl, block seed);


        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel>chl);
    };

}
