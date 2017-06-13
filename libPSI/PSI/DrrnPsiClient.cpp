#include "DrrnPsiClient.h"

#include <libPSI/PIR/BgiPirClient.h>
namespace osuCrypto
{
    void DrrnPsiClient::init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed, double binScaler)
    {
        auto ssp(40);
        mNumSimpleBins = (clientSetSize / std::log2(clientSetSize)) * binScaler;
        mPrng.SetSeed(seed);
        mServerSetSize = serverSetSize;
        mClientSetSize = clientSetSize;
        mHashingSeed = ZeroBlock;

        mCuckooParams = CuckooIndex::selectParams(serverSetSize, ssp, true);



        u64 numBalls = clientSetSize * mCuckooParams.mNumHashes;
        mNumSimpleBins = (numBalls / std::log2(numBalls)) * binScaler;
        mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);

        // i think these are the right set sizes for the final PSI
        auto serverPsiInputSize = mBinSize * mNumSimpleBins;
        auto clientPsiInputSize = clientSetSize * mCuckooParams.mNumHashes;
        mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, s0, otRecv, mPrng.get<block>());
    }

    void DrrnPsiClient::recv(Channel s0, Channel s1, span<block> inputs)
    {
        if (inputs.size() != mClientSetSize)
            throw std::runtime_error(LOCATION);

        Matrix<u64> bins(mNumSimpleBins, mBinSize);
        std::vector<u64> binSizes(mNumSimpleBins);
        u64 cuckooSlotsPerBin = (mCuckooParams.numBins() + mNumSimpleBins) / mNumSimpleBins;


        // Simple hashing with a PRP
        std::vector<block> hashs(inputs.size());
        AES hasher(mHashingSeed);
        u64 numCuckooBins = mCuckooParams.numBins();
        for (u64 i = 0; i < inputs.size();)
        {
            auto min = std::min<u64>(inputs.size() - i, 8);
            auto end = i + min;
            hasher.ecbEncBlocks(inputs.data() + i, min, hashs.data() + i);
            for (; i < end; ++i)
            {
                hashs[i] = hashs[i] ^ inputs[i];
                for (u64 j = 0; j < mCuckooParams.mNumHashes; ++j)
                {
                    u64 idx = CuckooIndex::getHash(hashs[i], j, numCuckooBins) / cuckooSlotsPerBin;

                    // insert this item in this bin. pack together the hash index and input index
                    bins(idx, binSizes[idx]++) = (j << 56) | i;
                }

                //std::cout << IoStream::lock << "cinput[" << i << "] = " << inputs[i] << " -> " << hashs[i] << " ("
                //    << CuckooIndex::getHash(hashs[i], 0,numCuckooBins) << ", "
                //    << CuckooIndex::getHash(hashs[i], 1,numCuckooBins) << ", "
                //    << CuckooIndex::getHash(hashs[i], 2,numCuckooBins) << ")"
                //    << std::endl << IoStream::unlock;
            }
        }



        // power of 2
        u64 numLeafBlocks = (cuckooSlotsPerBin + 127) / 128;
        u64 gDepth = 2;
        u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocks)) - gDepth;
        u64 groupSize = (numLeafBlocks + (1 << kDepth) - 1) / (1 << kDepth);
        if (groupSize > 8) throw std::runtime_error(LOCATION);

        BgiPirClient pir;

        u64 numQueries = mClientSetSize * mCuckooParams.mNumHashes;

        // mask generation
        block rSeed = mPrng.get<block>();
        AES rGen(rSeed);
        std::vector<block> shares(numQueries), enc(mNumSimpleBins * mBinSize);
        rGen.ecbEncCounterMode(0, enc.size(), enc.data());
        auto encIter = enc.begin();
        auto shareIter = shares.begin();
        u64 queryIdx = 0;

        std::unordered_map<u64, u64> inputMap;
        inputMap.reserve(numQueries);


        u64 mask = (u64(1) << 56) - 1;
        auto binIter = bins.begin();
        for (u64 bIdx = 0; bIdx < mNumSimpleBins; ++bIdx)
        {
            u64 i = 0;
            for (; i < binSizes[bIdx]; ++i)
            {
                std::vector<block> k0(kDepth + 1 + groupSize), k1(kDepth + 1 + groupSize);
                span<block>
                    kk0(k0.data(), kDepth + 1),
                    g0(k0.data() + kDepth + 1, groupSize),
                    kk1(k1.data(), kDepth + 1),
                    g1(k1.data() + kDepth + 1, groupSize);


                u8 hashIdx = *binIter >> 56;
                u64 itemIdx = *binIter & mask;
                u64 cuckooIdx = CuckooIndex::getHash(hashs[itemIdx], hashIdx, numCuckooBins) - bIdx * cuckooSlotsPerBin;
                ++binIter;

                pir.keyGen(cuckooIdx, mPrng.get<block>(), kk0, g0, kk1, g1);
                s0.asyncSend(std::move(k0));
                s1.asyncSend(std::move(k1));

                // add input to masks
                *shareIter = *encIter ^  inputs[itemIdx];
                inputMap.insert({ queryIdx, itemIdx });

                //*encIter = _mm_set1_epi64x(queryIdx);
                //std::cout << "cq mask " << queryIdx << " " << *enc
                ++shareIter;
                ++encIter;
                ++queryIdx;
            }

            for (; i < mBinSize; ++i)
            {
                // dummy query
                std::vector<block> k0(kDepth + 1 + groupSize), k1(kDepth + 1 + groupSize);
                mPrng.get<block>(k0.data(), k0.size());
                mPrng.get<block>(k1.data(), k1.size());

                s0.asyncSend(std::move(k0));
                s1.asyncSend(std::move(k1));
                ++binIter;
                ++encIter;
            }
        }

        s1.asyncSend(&rSeed, sizeof(block));

        //rGen.ecbEncBlocks(enc.data(), enc.size(), enc.data());
        //for (u64 i = 0; i < shares.size(); ++i)
        //{
        //    std::cout << "c " << i << " " << shares[i] << std::endl;
        //}
        mPsi.sendInput(shares, s0);

        mIntersection.reserve(mPsi.mIntersection.size());
        for (u64 i = 0; i < mPsi.mIntersection.size(); ++i) {
            // divide index by #hashes			
            mIntersection.emplace(inputMap[mPsi.mIntersection[i]]);
        }

    }
}
