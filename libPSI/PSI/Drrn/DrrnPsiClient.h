#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#ifndef ENABLE_KKRT_PSI
#pragma error("ENABLE_KKRT_PSI must be defined.");
#endif

#ifndef ENABLE_KKRT
#pragma error("ENABLE_KKRT must be defined in libOTe.");
#endif

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>
#include <libPSI/PSI/Kkrt/KkrtPsiReceiver.h>
#include <unordered_set>
#include <libPSI/Tools/SimpleIndex.h>


namespace osuCrypto
{

    class DrrnPsiClient
    {
    public:

        void init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed,
			u64 numHash = 2,
			double binScaler = 1, 
			u64 cuckooSsp = 20,
			u64 bigBlockSize = 8);

        void recv(Channel s0, Channel s1, span<block> inputs);

        PRNG mPrng;
        CuckooParam mCuckooParams;

        //Matr
        //SimpleIndex mSimpleIndex;

        KkrtPsiReceiver mPsi;

        u64 mClientSetSize, mServerSetSize, mNumSimpleBins, mBinSize, mBigBlockSize;
		std::unordered_set<u64> mIntersection;
        KkrtNcoOtReceiver otRecv;
        block mHashingSeed;
    };

}
#endif