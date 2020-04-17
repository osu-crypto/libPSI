
#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#include "DrrnPsiClient.h"
#include <unordered_map>
#include <libPSI/PIR/BgiPirClient.h>

namespace osuCrypto
{
    void DrrnPsiClient::init(
        Channel s0,
        Channel s1,
        u64 serverSetSize,
        u64 clientSetSize,
        block seed,
        u64 numHash,
        double binScaler,
        u64 cuckooSsp,
        u64 bigBlockSize)
    {
        auto ssp(40);
        mPrng.SetSeed(seed);
        mServerSetSize = serverSetSize;
        mClientSetSize = clientSetSize;
        mHashingSeed = ZeroBlock;
        mBigBlockSize = bigBlockSize;

        mCuckooParams = CuckooIndex<>::selectParams(mServerSetSize, cuckooSsp, 0, numHash);



        u64 numBalls = clientSetSize * mCuckooParams.mNumHashes;
        mNumSimpleBins = std::max<u64>(1, (numBalls / log2floor(numBalls)) * binScaler);
        mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);

        // i think these are the right set sizes for the final PSI
        auto serverPsiInputSize = mBinSize * mNumSimpleBins * mBigBlockSize;
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
        for (u64 i = 0; i < u64(inputs.size());)
        {
            auto min = std::min<u64>(inputs.size() - i, 8);
            auto end = i + min;
            hasher.ecbEncBlocks(inputs.data() + i, min, hashs.data() + i);
            for (; i < end; ++i)
            {
                hashs[i] = hashs[i] ^ inputs[i];
                for (u64 j = 0; j < mCuckooParams.mNumHashes; ++j)
                {
                    u64 idx = CuckooIndex<>::getHash(hashs[i], j, numCuckooBins) * mNumSimpleBins / mCuckooParams.numBins();

                    // insert this item in this bin. pack together the hash index and input index
                    bins(idx, binSizes[idx]++) = (j << 56) | i;
                }

                //if (!i)
                //{
                //    ostreamLock(std::cout) << "cinput[" << i << "] = " << inputs[i] << " -> " << hashs[i] << " ("
                //        << CuckooIndex<>::getHash(hashs[i], 0, numCuckooBins) << ", "
                //        << CuckooIndex<>::getHash(hashs[i], 1, numCuckooBins) << ", "
                //        << CuckooIndex<>::getHash(hashs[i], 2, numCuckooBins) << ")"
                //        << std::endl;
                //}
            }
        }



        // power of 2
        u64 numLeafBlocks = (cuckooSlotsPerBin + mBigBlockSize * 128 - 1) / (mBigBlockSize * 128);
        u64 gDepth = 2;
        u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocks)) - gDepth;
        u64 groupSize = (numLeafBlocks + (u64(1) << kDepth) - 1) / (u64(1) << kDepth);
        if (groupSize > 8) throw std::runtime_error(LOCATION);

        //std::cout << "kDepth:   " << kDepth << std::endl;
        //std::cout << "mBinSize: " << mBinSize << std::endl;

        u64 numQueries = mNumSimpleBins * mBinSize;
        auto permSize = numQueries * mBigBlockSize;

        // mask generation
        block rSeed = CCBlock;// mPrng.get<block>();
        AES rGen(rSeed);


        std::vector<block> shares(mClientSetSize * mCuckooParams.mNumHashes), r(permSize), piS1(permSize), s(permSize);
        //std::vector<u32> rIdxs(numQueries);
        //std::vector<u64> sharesIdx(shares.size());

        //TODO("use real masks");
        //memset(r.data(), 0, r.size() * sizeof(block));
        rGen.ecbEncCounterMode(r.size() * 0, r.size(), r.data());
        rGen.ecbEncCounterMode(r.size() * 1, r.size(), piS1.data());
        rGen.ecbEncCounterMode(r.size() * 2, r.size(), s.data());

        //auto encIter = enc.begin();
        auto shareIter = shares.begin();
        //auto shareIdxIter = sharesIdx.begin();
        u64 queryIdx = 0, dummyPermIdx = mClientSetSize * mCuckooParams.mNumHashes;

        std::unordered_map<u64, u64> inputMap;
        inputMap.reserve(mClientSetSize * mCuckooParams.mNumHashes);

        std::vector<u32> pi(permSize);
        auto piIter = pi.begin();


        u64 keySize = kDepth + 1 + groupSize;
        u64 mask = (u64(1) << 56) - 1;
        auto binIter = bins.begin();
        for (u64 bIdx = 0; bIdx < mNumSimpleBins; ++bIdx)
        {
            u64 i = 0;

            auto binOffset = (bIdx * numCuckooBins + mNumSimpleBins - 1) / mNumSimpleBins;

            std::vector<block> k0(keySize * mBinSize), k1(keySize * mBinSize);
            //std::vector<u64> idx0(mBinSize), idx1(mBinSize);
            auto k0Iter = k0.data(), k1Iter = k1.data();
            //auto idx0Iter = idx0.data(), idx1Iter = idx1.data();

            for (; i < binSizes[bIdx]; ++i)
            {
                span<block>
                    kk0(k0Iter, kDepth + 1),
                    g0(k0Iter + kDepth + 1, groupSize),
                    kk1(k1Iter, kDepth + 1),
                    g1(k1Iter + kDepth + 1, groupSize);

                k0Iter += keySize;
                k1Iter += keySize;

                u8 hashIdx = *binIter >> 56;
                u64 itemIdx = *binIter & mask;
                u64 cuckooIdx = CuckooIndex<>::getHash(hashs[itemIdx], hashIdx, numCuckooBins) - binOffset;
                ++binIter;

                auto bigBlockoffset = cuckooIdx % mBigBlockSize;
                auto bigBlockIdx = cuckooIdx / mBigBlockSize;

                BgiPirClient::keyGen(bigBlockIdx, mPrng.get<block>(), kk0, g0, kk1, g1);



                // the index of the mask that will mask this item
                auto rIdx = *piIter = itemIdx * mCuckooParams.mNumHashes + hashIdx * mBigBlockSize + bigBlockoffset;

                // the masked value that will be inputted into the PSI
                *shareIter = r[rIdx] ^ inputs[itemIdx];
                //*shareIter = inputs[itemIdx];

                //if (itemIdx == 0)
                //    ostreamLock(std::cout)
                //    << "item[" << i << "]    bin " << bIdx
                //    << " block " << bigBlockIdx 
                //    << " offset " << bigBlockoffset 
                //    << " psi " << *shareIter << std::endl;

                // This will be used to map itemed items in the intersection back to their input item
                inputMap.insert({ queryIdx, itemIdx });

                ++shareIter;
                ++piIter;
                ++queryIdx;
            }

            u64 rem = mBinSize - i;


            binIter += rem;
            for (u64 i = 0; i < rem; ++i)
            {
                *piIter++ = dummyPermIdx++;
            }

            //s0.asyncSendCopy(k0);
            //s0.asyncSendCopy(k1);
            //s1.asyncSendCopy(k1);
            //s1.asyncSendCopy(k0);

            s0.asyncSend(std::move(k0));
            s1.asyncSend(std::move(k1));

        }

        std::vector<u32> pi1(permSize), pi0(permSize), pi1Inv(permSize);
        for (u32 i = 0; i < pi1.size(); ++i) pi1[i] = i;
        PRNG prng(rSeed ^ OneBlock);
        std::random_shuffle(pi1.begin(), pi1.end(), prng);


        //std::vector<block> pi1RS(pi.size());
        for (u64 i = 0; i < permSize; ++i)
        {
            //auto pi1i = pi1[i];
            //pi1RS[i] = r[pi1i] ^ s[pi1i];

            pi1Inv[pi1[i]] = i;
            //std::cout << "pi1(r + s)[" << i << "] " << pi1RS[i] << std::endl;
        }
        std::vector<block> piS0(r.size());
        for (u64 i = 0; i < permSize; ++i)
        {
            //std::cout << "r[" << i << "] " << r[i] << std::endl;
            //std::cout << "pi(r + s)[" << i << "]=" << (r[pi[i]] ^ s[pi[i]]) << std::endl;


            pi0[i] = pi1Inv[pi[i]];
            piS0[i] = piS1[i] ^ s[pi[i]];
            //std::cout << "pi (r + s)[" << i << "] = " << (r[pi[i]] ^ s[pi[i]]) << " = " << r[pi[i]] << " ^ " << s[pi[i]] << " c " << pi[i] << std::endl;
            //std::cout << "pi`(r + s)[" << i << "] = " << pi1RS[pi0[i]]  <<" c " << pi0[pi1[i]] << std::endl;
        }

        s0.asyncSend(std::move(pi0));
        s0.asyncSend(std::move(piS0));
        //rGen.ecbEncBlocks(r.data(), r.size(), r.data());
        //for (u64 i = 0; i < shares.size(); ++i)
        //{
        //    std::cout << IoStream::lock << "cshares[" << i << "] " << shares[i] << " input[" << sharesIdx[i]<<"]" << std::endl << IoStream::unlock;
        //}
        mPsi.sendInput(shares, s0);

        mIntersection.reserve(mPsi.mIntersection.size());
        for (u64 i = 0; i < mPsi.mIntersection.size(); ++i) {
            // divide index by #hashes
            mIntersection.emplace(inputMap[mPsi.mIntersection[i]]);
        }

    }
}
#endif