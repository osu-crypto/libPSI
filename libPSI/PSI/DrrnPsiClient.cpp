#include "DrrnPsiClient.h"

#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>
#include <libPSI/PIR/BgiPirClient.h>

namespace osuCrypto
{
    void DrrnPsiClient::init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed)
    {

        mPrng.SetSeed(seed);
        KkrtNcoOtReceiver otRecv;
        mServerSetSize = serverSetSize;
        mClientSetSize = clientSetSize;
        mHashingSeed = ZeroBlock;

        mCuckooParams = CuckooIndex::selectParams(serverSetSize, 40, true);

        // i think these are the right set sizes for the final PSI
        auto serverPsiInputSize = clientSetSize * mCuckooParams.mNumHashes;
        auto clientPsiInputSize = clientSetSize * mCuckooParams.mNumHashes;
        mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, s0, otRecv, mPrng.get<block>());
    }

    void DrrnPsiClient::recv(Channel s0, Channel s1, span<block> inputs)
    {
        if (inputs.size() != mServerSetSize) throw std::runtime_error(LOCATION);

        //mIndex.insert(inputs, mHashingSeed);
        std::vector<block> hashs(inputs.size());
        std::array<u64, 16> idxs;
        AES hasher(mHashingSeed);

        for (u64 i = 0; i < inputs.size(); i += hashs.size())
        {
            auto min = std::min<u64>(inputs.size() - i, hashs.size());

            hasher.ecbEncBlocks(inputs.data() + i, min, hashs.data());

            for (u64 j = 0, jj = i; j < min; ++j, ++jj)
            {
                idxs[j] = jj;
                hashs[j] = hashs[j] ^ inputs[jj];
            }
        }


        u64 numBins = mCuckooParams.numBins();
        // power of 2
        u64 depth = log2floor(mCuckooParams.numBins() / 4);
        u64 treeLeaves = (1 << depth);
        u64 groupSize = (mCuckooParams.numBins() + treeLeaves - 1) / treeLeaves;
        assert(groupSize <= 8);

        BgiPirClient pir;
        pir.init(depth, groupSize);


        std::vector<block> k(depth + 1 + groupSize);

        u64 numQueries = mClientSetSize * mCuckooParams.mNumHashes;

        block rSeed = mPrng.get<block>();
        AES rGen(rSeed);
        std::vector<block> shares(numQueries);
        rGen.ecbEncCounterMode(0, numQueries, shares.data());
        auto shareIter = shares.begin();

        for (u64 i = 0; i < mClientSetSize; ++i)
        {

            for (u64 j = 0; j < mCuckooParams.mNumHashes; ++j)
            {
                std::vector<block> k0(depth + 1 + groupSize), k1(depth + 1 + groupSize);

                span<block>
                    kk0(k0.data(), depth + 1),
                    g0(k0.data() + depth + 1, groupSize),
                    kk1(k1.data(), depth + 1),
                    g1(k1.data() + depth + 1, groupSize);


                u64 idx = CuckooIndex::getHash(hashs[i], j, numBins);

                pir.keyGen(idx, mPrng.get<block>(), kk0, g0, kk1, g1);

                s0.asyncSend(std::move(k0));
                s1.asyncSend(std::move(k1));

                *shareIter = *shareIter ^ inputs[i];
            }
        }


        s0.asyncSend(&rSeed, sizeof(block));


        mPsi.sendInput(shares, s1);
    }
}
