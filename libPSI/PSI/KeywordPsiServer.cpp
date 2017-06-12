#include "KeywordPsiServer.h"

namespace osuCrypto
{
	void KeywordPsiServer::init(u8 serverId, Channel clientChl, u64 databaseSize, u64 clientSetSize, block seed)
	{
		mPrng.SetSeed(seed);
		mClientSetSize = clientSetSize;
		mServerSetSize = databaseSize;
		mServerId = serverId;
	}

	void KeywordPsiServer::send(Channel clientChl, span<block> inputs)
	{
		if (inputs.size() != mServerSetSize) {
			throw std::runtime_error(LOCATION);
		}

		u64 numLeafBlocks = (mServerSetSize + 127) / 128;
		u64 gDepth = 2;
		u64 kDepth = log2floor(numLeafBlocks) - gDepth;
		u64 groupSize = (numLeafBlocks + (1 << kDepth)) / (1 << kDepth);
		if (groupSize > 8) throw std::runtime_error(LOCATION);

		
		BgiPirServer pir;
		pir.init(kDepth, groupSize);

		std::vector<block> k(kDepth + 1 + groupSize);

		u64 numQueries = mClientSetSize;

		for (u64 i = 0; i < numQueries; ++i)
		{
			clientChl.recv(k.data(), k.size() * sizeof(block));
			span<block> kk(k.data(), kDepth + 1);
			span<block> g(k.data() + kDepth + 1, groupSize);
			
			u8 sum = 0;

			for (u64 j = 0; j < inputs.size(); ++j)
			{
			   sum = sum ^ BgiPirServer::evalOne(inputs[i].m128i_u64[0], kk, g); //TODO: change to full block, once evalOne can handle that
			}

			clientChl.send(&sum, sizeof(u8));
		}
	}
}
