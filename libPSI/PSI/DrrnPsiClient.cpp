#include "DrrnPsiClient.h"

#include <libPSI/PIR/BgiPirClient.h>

namespace osuCrypto
{
    void DrrnPsiClient::init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed)
    {

        mPrng.SetSeed(seed);
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
        if (inputs.size() != mClientSetSize)
            throw std::runtime_error(LOCATION);

        //mIndex.insert(inputs, mHashingSeed);

        // Simple hashing with a PRP
        std::vector<block> hashs(inputs.size());
        AES hasher(mHashingSeed);
        u64 numBins = mCuckooParams.numBins();

        for (u64 i = 0; i < inputs.size();)
        {
            auto min = std::min<u64>(inputs.size() - i, 8);
            auto end = i + min;

            hasher.ecbEncBlocks(inputs.data() + i, min, hashs.data() + i);

            for (; i < end; ++i)
            {
                hashs[i] = hashs[i] ^ inputs[i];
                //std::cout << IoStream::lock << "cinput[" << i << "] = " << inputs[i] << " -> " << hashs[i] << " ("
                //    << CuckooIndex::getHash(hashs[i], 0, numBins) << ", "
                //    << CuckooIndex::getHash(hashs[i], 1, numBins) << ", "
                //    << CuckooIndex::getHash(hashs[i], 2, numBins) << ")"
                //    << std::endl << IoStream::unlock;
            }
        }





        // power of 2
        u64 numLeafBlocks = (mCuckooParams.numBins() + 127) / 128;
        u64 gDepth = 2;
        u64 kDepth = log2floor(numLeafBlocks) - gDepth;
        u64 groupSize = (numLeafBlocks + (1 << kDepth)) / (1 << kDepth);
        if (groupSize > 8) throw     std::runtime_error(LOCATION);

        BgiPirClient pir;

        u64 numQueries = mClientSetSize * mCuckooParams.mNumHashes;

        // mask generation
        block rSeed = mPrng.get<block>();
        AES rGen(rSeed);
        std::vector<block> shares(numQueries);
        rGen.ecbEncCounterMode(0, numQueries, shares.data());
        auto shareIter = shares.begin();

        for (u64 i = 0; i < mClientSetSize; ++i)
        {

            for (u64 j = 0; j < mCuckooParams.mNumHashes; ++j)
            {
                std::vector<block> k0(kDepth + 1 + groupSize), k1(kDepth + 1 + groupSize);

                span<block>
                    kk0(k0.data(), kDepth + 1),
                    g0(k0.data() + kDepth + 1, groupSize),
                    kk1(k1.data(), kDepth + 1),
                    g1(k1.data() + kDepth + 1, groupSize);

                // derive cuckoo index from encrypted block
                u64 idx = CuckooIndex::getHash(hashs[i], j, numBins);

                //if (i == 0)
                //{
                //    std::cout << "hashs[" << i << "][" << j << "] = " << hashs[i]  << " -> "<< idx << std::endl;
                //}


                pir.keyGen(idx, mPrng.get<block>(), kk0, g0, kk1, g1);

                s0.asyncSend(std::move(k0));
                s1.asyncSend(std::move(k1));

                // add input to masks
                *shareIter = /*shareIter ^*/ inputs[i];

                if (j) *shareIter = mPrng.get<block>();

                shareIter++;


                //s1.send(&idx, sizeof(u64));
            }
        }

        //for (u64 i = 0; i < shares.size(); ++i)
        //{
        //    std::cout << "cshare[" << i << "] = " << shares[i] << std::endl;
        //}

        s1.asyncSend(&rSeed, sizeof(block));

        mPsi.sendInput(shares, s0);

        // indices into the shares array; needs to be diviced by numHashFunctions
        if (mPsi.mIntersection.size())
            std::cout << mPsi.mIntersection[0] << std::endl;
        else std::cout << " no intersection" << std::endl;
    }
}
