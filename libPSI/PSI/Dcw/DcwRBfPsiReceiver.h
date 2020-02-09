#pragma once
#include "libPSI/config.h"
#ifdef ENABLE_DCW_PSI
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"

#include "cryptoTools/Common/BitVector.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"
namespace osuCrypto
{



    class DcwRBfPsiReceiver
    {
    public:
    
        u64 mMyInputSize, mTheirInputSize, mBfBitCount, mNumHashFunctions;
        block mHashingSeed;
        std::vector<u64> mIntersection;
        std::vector<block> mMessages;
        BitVector mRandChoices;
        block mSeed;

        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel& chl0, block seed);
        void init(u64 n, u64 statSecParam, OtExtReceiver& otExt, span<Channel> chl0, block seed);
        void sendInput(std::vector<block>& inputs, Channel& chl);
        void sendInput(std::vector<block>& inputs, span<Channel> chl0);
    };

}


#endif