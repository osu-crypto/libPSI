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
        block hashingSeed = ZeroBlock;
		//u64 numLeafBlocksPerBin = ((1 << ((sizeof(block)*8) - 1)) + 127) / 128;
		//    u64 gDepth = 2;
		//    u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocksPerBin)) - gDepth;
		//    u64 groupSize = (numLeafBlocksPerBin + (1 << kDepth) - 1) / (1 << kDepth);
		//    if (groupSize > 8) throw     std::runtime_error(LOCATION);
		//    std::vector<block> pirData((1 << kDepth) * groupSize * 128);

		//	std::cout << kDepth << " " << groupSize << std::endl;
        auto ssp(40);
        u64 inputByteCount = (ssp + log2ceil(mClientSetSize * mServerSetSize) + 7) / 8;
        AES hasher(hashingSeed);
        std::vector<block> hashes(inputs.size());
        hasher.ecbEncBlocks(inputs.data(), inputs.size(), hashes.data());
        for (u64 i = 0; i < inputs.size(); ++i) hashes[i] = hashes[i] ^ inputs[i];

		u64 groupSize = 5;
		u64 kDepth = (inputByteCount  * 8) - log2floor(128 * groupSize);

		BgiPirServer pir;
		pir.init(kDepth, groupSize);

		std::vector<block> k(kDepth + 1 + groupSize);

		u64 numQueries = mClientSetSize;

        BitVector results(numQueries);
		for (u64 i = 0; i < numQueries; ++i)
		{
			clientChl.recv(k.data(), k.size() * sizeof(block));
			span<block> kk(k.data(), kDepth + 1);
			span<block> g(k.data() + kDepth + 1, groupSize);
			
			u8 sum = 0;
			for (u64 j = 0; j < inputs.size(); ++j)
			{
				span<u8> ss((u8*)&hashes[j], inputByteCount);
                auto bit = BgiPirServer::evalOne(ss, kk, g);

				sum = sum ^ bit;
			}
            results[i] = sum;
		}

        clientChl.asyncSend(std::move(results));
	}
}
