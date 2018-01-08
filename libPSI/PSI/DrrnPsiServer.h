#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Network/Channel.h>
#include <libPSI/PSI/KkrtPsiSender.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>

namespace osuCrypto
{

    class DrrnPsiServer
    {
    public:
		DrrnPsiServer()
			: mUseSingleDataPass(true)
			, mNiave(false)
		{}

        void init(u8 serverId, Channel chan, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed, double binScaler = 1, u64 bigBlockSize = 8);

		//void setCuckooParam(osuCrypto::u64 &serverSetSize, int ssp);

		void setInputs(span<block> inputs, u64 numThreads = 2, u64 ssp = 20);

        void send(Channel clientChl, Channel srvChl, u64 numThreads = 1);

		std::vector<block> mCuckooData, mPiS1, mPi1SigmaRS;

        //CuckooParam mCuckooParams;
        CuckooIndex<NotThreadSafe> mIndex;

		bool mUseSingleDataPass, mNiave;
        KkrtNcoOtSender otSend;
        PRNG mPrng;
        KkrtPsiSender mPsi;

		u64 mClientSetSize, mServerSetSize;

		// The number of regions that the server's cuckoo table is divided into. 
		u64 mNumSimpleBins;
		
		// The number of queries that are made to any given bin (cuckoo table resions).
		u64 mBinSize;
		
		// The number of cuckoo table items that any given DPF point corresponds to. 
		u64 mBigBlockSize;


        u8 mServerId;
        block mHashingSeed;
    };

}
