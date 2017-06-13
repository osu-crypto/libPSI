#pragma once

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <libPSI/PIR/BgiPirClient.h>

namespace osuCrypto
{
	class KeywordPsiClient
	{
	public:
		void init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed);
		void recv(Channel s0, Channel s1, span<block> inputs);

		PRNG mPrng;
		u64 mClientSetSize, mServerSetSize;
		std::vector<u64> mIntersection;
	};
}
