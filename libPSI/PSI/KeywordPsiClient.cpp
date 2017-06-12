#include "KeywordPsiClient.h"

namespace osuCrypto
{
	void KeywordPsiClient::init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed)
	{
		mPrng.SetSeed(seed);
		mServerSetSize = serverSetSize;
		mClientSetSize = clientSetSize;
	}

	void KeywordPsiClient::recv(Channel s0, Channel s1, span<block> inputs)
	{
		if (inputs.size() != mClientSetSize) {
			throw std::runtime_error(LOCATION);
		}

		// power of 2
		u64 numLeafBlocks = (mServerSetSize + 127) / 128;
		u64 gDepth = 2;
		u64 kDepth = log2floor(sizeof(block)) - gDepth;
		u64 groupSize = (numLeafBlocks + (1 << kDepth)) / (1 << kDepth);
		if (groupSize > 8) {
			throw std::runtime_error(LOCATION);
		}

		BgiPirClient pir;

		u64 numQueries = mClientSetSize;
		u8 s0r, s1r;


		for (u64 i = 0; i < mClientSetSize; ++i)
		{
			std::vector<block> k0(kDepth + 1 + groupSize), k1(kDepth + 1 + groupSize);

			span<block>
				kk0(k0.data(), kDepth + 1),
				g0(k0.data() + kDepth + 1, groupSize),
				kk1(k1.data(), kDepth + 1),
				g1(k1.data() + kDepth + 1, groupSize);

			pir.keyGen(i, mPrng.get<block>(), kk0, g0, kk1, g1);

			s0.asyncSend(std::move(k0));
			s1.asyncSend(std::move(k1));

			s0.recv(&s0r, sizeof(u8));
			s1.recv(&s1r, sizeof(u8));

			if (s1r ^ s0r) {
				mIntersection.push_back(i);
				std::cout << i << " \n";
			}
		}
	}
}
