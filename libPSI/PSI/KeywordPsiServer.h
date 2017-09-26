#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libPSI/PIR/BgiPirServer.h>

namespace osuCrypto
{

	class KeywordPsiServer
	{
	public:
		void init(u8 serverId, Channel chan, u64 databaseSize, u64 clientSetSize, block seed);
		void send(Channel clientCh, span<block> inputs);

		PRNG mPrng;
		u64 mClientSetSize, mServerSetSize;
		u8 mServerId;
	};
}
