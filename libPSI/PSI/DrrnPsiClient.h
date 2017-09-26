#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>
#include <libPSI/PSI/KkrtPsiReceiver.h>
#include <unordered_set>
#include <libPSI/Tools/SimpleIndex.h>


namespace osuCrypto
{

    class DrrnPsiClient
    {
    public:

        void init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed,u64 numHash = 2, double binScaler = 1, u64 cuckooSsp = 20);

        void recv(Channel s0, Channel s1, span<block> inputs);

        PRNG mPrng;
        CuckooParam mCuckooParams;

        //Matr
        //SimpleIndex mSimpleIndex;

        KkrtPsiReceiver mPsi;

        u64 mClientSetSize, mServerSetSize, mNumSimpleBins, mBinSize;
		std::unordered_set<u64> mIntersection;
        KkrtNcoOtReceiver otRecv;
        block mHashingSeed;
    };

}
