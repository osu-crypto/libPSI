#include "DrrnPsiServer.h"
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libPSI/PIR/BgiPirServer.h>
#include <libPSI/Tools/SimpleIndex.h>
namespace osuCrypto
{
    void DrrnPsiServer::init(u8 serverId, Channel clientChl, Channel srvChl, u64 databaseSize, u64 clientSetSize, block seed, double binScaler)
    {
        if (mServerId == 0) gTimer.setTimePoint("DrrnSrv init start");
        auto ssp(40);
        mPrng.SetSeed(seed);
        mClientSetSize = clientSetSize;
        mServerSetSize = databaseSize;
        mServerId = serverId;

        mCuckooParams = CuckooIndex<>::selectParams(mServerSetSize, ssp, true);

        u64 numBalls = clientSetSize * mIndex.mParams.mNumHashes;
        mNumSimpleBins = static_cast<u64>((numBalls / log2floor(numBalls)) * binScaler);

        if (mServerId == 0) gTimer.setTimePoint("DrrnSrv balls_bins start");
        mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);


        if (serverId == 0)
        {
            // i think these are the right set sizes for the final PSI        
            auto serverPsiInputSize = mBinSize * mNumSimpleBins;
            auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, clientChl, otSend, mPrng.get<block>());
        }
        if (mServerId == 0) gTimer.setTimePoint("DrrnSrv init end");

    }

    void DrrnPsiServer::setInputs(span<block> inputs, u64 numThreads)
    {
        //if (numThreads == 0) numThreads = std::thread::hardware_concurrency();
        //if (inputs.size() != mServerSetSize)
        //    throw std::runtime_error(LOCATION);
        //auto routine = [&](u64 tIdx)
        //{
        //	auto startIdx = tIdx * inputs.size() / numThreads;
        //	span<block> region(
        //		inputs.begin() + startIdx,
        //		inputs.begin() + (tIdx + 1)* inputs.size() / numThreads);

        mHashingSeed = ZeroBlock; // todo, make random;
        mIndex.init(inputs.size(), 40, true);
        mIndex.insert(inputs, mHashingSeed);
        //};

        //std::vector<std::thread> thrds(numThreads - 1);
        //for (u64 i = 1; i < numThreads; ++i)
        //	thrds[i - 1] = std::thread([i, &routine]() { routine(i); });

        //routine(0);

        //for (u64 i = 1; i < numThreads; ++i)
        //	thrds[i - 1].join();

        mInputs = inputs;

#ifndef NDEBUG
        //mIndex.validate(inputs, mHashingSeed);
#endif
    }


    void DrrnPsiServer::send(Channel clientChl, Channel srvChl, u64 numThreads)
    {
        //numThreads = 1;
        if (numThreads == 0) numThreads = std::thread::hardware_concurrency();
        if (mInputs.size() != mServerSetSize ||
            mInputs.size() != mCuckooParams.mN ||
            mInputs.size() != mIndex.mParams.mN)
        {
            std::cout << " failed " << std::endl;
            throw std::runtime_error(LOCATION);
        }


        u64 cuckooSlotsPerBin = (mIndex.mBins.size() + mNumSimpleBins) / mNumSimpleBins;

        if (mServerId == 0) gTimer.setTimePoint("DrrnSrv send start");

        // power of 2
        u64 numLeafBlocksPerBin = (cuckooSlotsPerBin + 127) / 128;
        u64 gDepth = 2;
        u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocksPerBin)) - gDepth;
        u64 groupSize = (numLeafBlocksPerBin + (u64(1) << kDepth) - 1) / (u64(1) << kDepth);
        if (groupSize > 8) throw     std::runtime_error(LOCATION);
        std::vector<block> shares(mNumSimpleBins * mBinSize);

        u64 keySize = kDepth + 1 + groupSize;
        std::vector<std::future<u64>> futrs(mNumSimpleBins);
        Matrix<block> k(mNumSimpleBins * mBinSize, keySize);
        //std::vector<u64> idxs(mNumSimpleBins * mBinSize);
        for (u64 bIdx = 0; bIdx < futrs.size(); ++bIdx)
        {
            futrs[bIdx] = clientChl.asyncRecv(k.data() + keySize * bIdx * mBinSize, k.stride() * sizeof(block) * mBinSize);
            //futrs[bIdx] = clientChl.asyncRecv(idxs.data() + bIdx * mBinSize, sizeof(u64) * mBinSize);
        }
        //auto fIter = futrs.begin();


        //u64 cuckooIdx = 0;
        auto routine = [this, numThreads, kDepth, keySize, groupSize, &futrs, &k, &shares](u64 tIdx)
        {
            std::vector<block> pirData((u64(1) << kDepth) * groupSize * 128);

            for (u64 binIdx = tIdx; binIdx < mNumSimpleBins; binIdx += numThreads)
            {
                auto shareIter = shares.begin() + binIdx * mBinSize;

                //u64 idx = cuckooIdx * mNumSimpleBins / mIndex.mBins.size();

                auto cuckooIdx = (binIdx * mIndex.mBins.size()       + mNumSimpleBins - 1) / mNumSimpleBins;
                auto cuckooEnd = ((binIdx + 1) * mIndex.mBins.size() + mNumSimpleBins - 1) / mNumSimpleBins;
                //auto curSize = std::min<u64>(cuckooSlotsPerBin, mIndex.mBins.size() - cuckooIdx);

                for (u64 i = 0; cuckooIdx < cuckooEnd; ++i, ++cuckooIdx)
                {
                    auto& item = mIndex.mBins[cuckooIdx];
                    auto empty = item.isEmpty();
                    if (empty == false)
                    {
                        auto idx = item.idx();
                        pirData[i] = mInputs[idx];

                        //{
                        //    auto hash = mIndex.mHashes[idx];
                        //    std::cout << IoStream::lock << "sinput[" << idx << "] = " << mInputs[idx] << " -> pir["<< i << "], hash= "  << hash << " ("
                        //        << CuckooIndex<>::getHash(hash, 0, mIndex.mBins.size()) << ", "
                        //        << CuckooIndex<>::getHash(hash, 1, mIndex.mBins.size()) << ", "
                        //        << CuckooIndex<>::getHash(hash, 2, mIndex.mBins.size()) << ") " << mIndex.mBins[cuckooIdx].hashIdx()
                        //        << std::endl << IoStream::unlock;
                        //}
                    }
                }


                futrs[binIdx].get();
                auto kIter = k.data() + keySize * binIdx * mBinSize;
                //auto idxIter = idxs.data() + binIdx * mBinSize;
                for (u64 i = 0; i < mBinSize; ++i)
                {

                    span<block> kk(kIter, kDepth + 1);
                    span<block> g(kIter + kDepth + 1, groupSize);
                    *shareIter = BgiPirServer::fullDomain(pirData, kk, g);
                    //if (neq(kIter[keySize - 1], ZeroBlock))
                    //{
                    //    std::cout << IoStream::lock << "bIdx " << binIdx << " " << i << " key " << kIter[keySize - 1] << "   shareIdx=" << (shareIter - shares.begin()) << " pir["<< *idxIter <<"] " << pirData[*idxIter]<< std::endl << IoStream::unlock;
                    //}
                    ++shareIter;
                    kIter += keySize;
                    //++idxIter;
                }
            }
        };
        if (mServerId == 0) gTimer.setTimePoint("DrrnSrv PSI start");

        std::vector<std::thread> thrds(numThreads - 1);
        for (u64 i = 1; i < numThreads; ++i)
            thrds[i - 1] = std::thread([i, &routine]() { routine(i); });

        routine(0);

        for (u64 i = 1; i < numThreads; ++i)
            thrds[i - 1].join();

        if (mServerId)
        {
            block rSeed;
            clientChl.recv(&rSeed, sizeof(block));
            AES rGen(rSeed);


            std::array<block, 8> buff;
            u64 j = 0, end = shares.size() - 7;
            for (; j < end; j += 8)
            {
                rGen.ecbEncCounterMode(j, 8, buff.data());

                shares[j + 0] = shares[j + 0] ^ buff[0];
                shares[j + 1] = shares[j + 1] ^ buff[1];
                shares[j + 2] = shares[j + 2] ^ buff[2];
                shares[j + 3] = shares[j + 3] ^ buff[3];
                shares[j + 4] = shares[j + 4] ^ buff[4];
                shares[j + 5] = shares[j + 5] ^ buff[5];
                shares[j + 6] = shares[j + 6] ^ buff[6];
                shares[j + 7] = shares[j + 7] ^ buff[7];
            }
            rGen.ecbEncCounterMode(j, shares.size() - j, buff.data());
            for (u64 i = 0; j < shares.size(); ++j, ++i)
            {
                shares[j] = shares[j] ^ buff[i];
            }

            srvChl.asyncSend(std::move(shares));
        }
        else
        {

            std::vector<block> otherShare(shares.size());
            srvChl.recv(otherShare.data(), otherShare.size() * sizeof(block));

            u64  j = 0, end = shares.size() - 7;
            for (; j < end; j += 8)
            {
                shares[j + 0] = shares[j + 0] ^ otherShare[j + 0];
                shares[j + 1] = shares[j + 1] ^ otherShare[j + 1];
                shares[j + 2] = shares[j + 2] ^ otherShare[j + 2];
                shares[j + 3] = shares[j + 3] ^ otherShare[j + 3];
                shares[j + 4] = shares[j + 4] ^ otherShare[j + 4];
                shares[j + 5] = shares[j + 5] ^ otherShare[j + 5];
                shares[j + 6] = shares[j + 6] ^ otherShare[j + 6];
                shares[j + 7] = shares[j + 7] ^ otherShare[j + 7];
            }
            for (; j < shares.size(); ++j)
            {
                shares[j] = shares[j] ^ otherShare[j];
            }

            //for (u64 i = 0; i < shares.size(); ++i)
            //{
            //    std::cout << IoStream::lock << "sshare[" << i << "] = " << shares[i] << std::endl << IoStream::unlock;
            //}
            mPsi.sendInput(shares, clientChl);
        }

        if (mServerId == 0) gTimer.setTimePoint("DrrnSrv send Done");

    }
}
