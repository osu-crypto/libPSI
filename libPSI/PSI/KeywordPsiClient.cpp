#include "KeywordPsiClient.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Matrix.h>
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

        block hashingSeed = ZeroBlock;
        // power of 2
        //u64 numLeafBlocks = (mCuckooParams.numBins() + 127) / 128;
        //u64 gDepth = 2;
        //u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocks)) - gDepth;
        //u64 groupSize = (numLeafBlocks + (1 << kDepth) - 1) / (1 << kDepth);
        //if (groupSize > 8) throw     std::runtime_error(LOCATION);

        //std::cout << kDepth << " " << groupSize << std::endl;

        //std::vector<
        auto ssp(40);
        u64 inputByteCount = (ssp + log2ceil(mClientSetSize * mServerSetSize) + 7)/ 8;
        AES hasher(hashingSeed);
        std::vector<block> hashes(inputs.size());
        hasher.ecbEncBlocks(inputs.data(), inputs.size(), hashes.data());
        for (u64 i = 0; i < inputs.size(); ++i) hashes[i] = hashes[i] ^ inputs[i];


        u64 groupSize = 5;
        u64 kDepth = (inputByteCount * 8) - log2floor(128 * groupSize);

        BgiPirClient pir;

        u64 numQueries = mClientSetSize;
        u8 s0r = 0, s1r = 0;

        for (u64 i = 0; i < mClientSetSize; ++i)
        {
            std::vector<block> k0(kDepth + 1 + groupSize), k1(kDepth + 1 + groupSize);

            span<block>
                kk0(k0.data(), kDepth + 1),
                g0(k0.data() + kDepth + 1, groupSize),
                kk1(k1.data(), kDepth + 1),
                g1(k1.data() + kDepth + 1, groupSize);


            span<u8> idx((u8*)&hashes[i], inputByteCount);
            pir.keyGen(idx, mPrng.get<block>(), kk0, g0, kk1, g1);

            s0.asyncSend(std::move(k0));
            s1.asyncSend(std::move(k1));

        }

        BitVector r0(numQueries), r1(numQueries);
        s0.recv(r0);
        s1.recv(r1);

        auto results = r0 ^ r1;
        for (u64 i = 0; i < numQueries; ++i)
        {
            if (results[i]) mIntersection.push_back(i);
        }
    }
}
