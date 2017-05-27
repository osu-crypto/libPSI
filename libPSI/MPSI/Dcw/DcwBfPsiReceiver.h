#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Common/BitVector.h"
#include <vector>
#include "libOTe/TwoChooseOne/OTExtInterface.h"
namespace osuCrypto
{



    class DcwBfPsiReceiver
    {
    public:
    
        
        DcwBfPsiReceiver();
        ~DcwBfPsiReceiver();

        //DcwOtReceiver mDcwOt;
        std::vector<SHA1> mHashs;
        u64 mMyInputSize, mTheirInputSize, mBfBitCount, mStatSecParam;
        block mHashingSeed;
        std::vector<u64> mIntersection;
        std::vector<block> mMessages;
        BitVector mRandChoices;
        block mEncSeed, mSeed;

        block interpolate(block prime, std::vector<block>& msgs, std::vector<u8>& choices);

        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel& chl0, block seed);
        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, span<Channel> chl0, block seed);
        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chl0);
    };

}
