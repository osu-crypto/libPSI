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

		void init(u8 serverId, Channel chan, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed, double binScaler = 1);
		void init(u8 serverId, span<Channel> chan, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed, double binScaler = 1);

		//void setCuckooParam(osuCrypto::u64 &serverSetSize, int ssp);

		void setInputs(span<block> inputs, u64 numThreads = 2, u64 ssp = 20, u64 byteSize = 16);

		void send(Channel clientChl, Channel srvChl, u64 numThreads = 1);
		void send(span<Channel> clientChl, Channel srvChl, u64 numThreads = 1);

//#define ITEM_SIZE 128
#if  ITEM_SIZE == 128
		std::vector<block> mCuckooData;
#elif ITEM_SIZE == 64
		std::vector<u64> mCuckooData;
#else
		Matrix<u8> mCuckooData;
#endif
        //CuckooParam mCuckooParams;
        CuckooIndex<NotThreadSafe> mIndex;

        PRNG mPrng;
        std::vector<KkrtNcoOtSender> otSend;
		std::vector<KkrtPsiSender> mPsi;

        u64 mClientSetSize, mServerSetSize, mNumSimpleBins, mBinSize, mByteSize;
        u8 mServerId;
        block mHashingSeed;
    };

}
