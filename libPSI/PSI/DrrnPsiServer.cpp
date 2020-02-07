
#include "libPSI/config.h"
#ifdef ENABLE_DRRN_PSI

#include "DrrnPsiServer.h"
#include <libOTe/TwoChooseOne/IknpOtExtReceiver.h>
#include <libPSI/PIR/BgiPirServer.h>
#include <libPSI/Tools/SimpleIndex.h>

#include <cryptoTools/Common/Timer.h>
#include <algorithm>
namespace osuCrypto
{
    void DrrnPsiServer::init(u8 serverId, Channel clientChl, Channel srvChl, u64 serverSetSize, u64 clientSetSize, block seed, double binScaler, u64 bigBlockSize)
    {
        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.init.start");
        auto ssp(40);
        mPrng.SetSeed(seed);
        mClientSetSize = clientSetSize;
        mServerSetSize = serverSetSize;
        mServerId = serverId;
        mBigBlockSize = bigBlockSize;

        if (mIndex.mParams.mN != serverSetSize)
            throw std::runtime_error(LOCATION);

        //setCuckooParam(serverSetSize, ssp);


        u64 numBalls = clientSetSize * mIndex.mParams.mNumHashes;
        mNumSimpleBins = std::max<u64>(1, static_cast<u64>((numBalls / log2floor(numBalls)) * binScaler));

        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv balls_bins start");
        mBinSize = SimpleIndex::get_bin_size(mNumSimpleBins, numBalls, ssp);

        if (mNumSimpleBins == 1 && mBinSize != numBalls)
            throw std::runtime_error(LOCATION);

        auto serverPsiInputSize = mBinSize * mNumSimpleBins * mBigBlockSize;
        if (serverId == 0)
        {
            // i think these are the right set sizes for the final PSI
            auto clientPsiInputSize = clientSetSize * mIndex.mParams.mNumHashes;
            //std::cout << "|ss| "<< serverPsiInputSize << std::endl;
            mPsi.init(serverPsiInputSize, clientPsiInputSize, 40, clientChl, otSend, mPrng.get<block>());

            srvChl.recv(mPi1SigmaRS);
        }
        else
        {
            block rSeed = CCBlock;
            //clientChl.recv((u8*)&rSeed, sizeof(block));

            PRNG prng(rSeed ^ OneBlock);

            std::vector<u32> pi1(serverPsiInputSize), sigma(mIndex.mParams.mNumHashes);
            for (u32 i = 0; i < sigma.size(); ++i) sigma[i] = i;
            for (u32 i = 0; i < pi1.size(); ++i) pi1[i] = i;
            std::random_shuffle(pi1.begin(), pi1.end(), prng);

            std::vector<block>
                r(serverPsiInputSize),
                s(serverPsiInputSize),
                //piS1(serverPsiInputSize),
                pi1SigmaRS(serverPsiInputSize);

            mPiS1.resize(serverPsiInputSize);

            AES rGen(rSeed);
            //memset(r.data(), 0, r.size() * sizeof(block));
            rGen.ecbEncCounterMode(serverPsiInputSize * 0, serverPsiInputSize, r.data());
            rGen.ecbEncCounterMode(serverPsiInputSize * 1, serverPsiInputSize, mPiS1.data());
            rGen.ecbEncCounterMode(serverPsiInputSize * 2, serverPsiInputSize, s.data());

            auto rIter = r.begin();
            for (u64 i = 0; i < mClientSetSize; ++i)
            {
                std::random_shuffle(sigma.begin(), sigma.end(), prng);
                for (u64 j = 1; j < sigma.size(); ++j)
                {
                    std::swap(rIter[j], rIter[sigma[j]]);
                }
                rIter += sigma.size();
            }

            for (u64 i = 0; i < pi1SigmaRS.size(); ++i)
            {
                auto pi1i = pi1[i];
                pi1SigmaRS[i] = r[pi1i] ^ s[pi1i];
                //std::cout << "pi1(r + s)[" << i << "] " << pi1SigmaRS[i] << " = " << r[pi1i]<<" ^ "<<s[pi1i] << std::endl;
            }
            srvChl.asyncSend(std::move(pi1SigmaRS));
        }

        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.init.end");

    }

    //void DrrnPsiServer::setCuckooParam(osuCrypto::u64 &serverSetSize, int ssp)
    //{
    //	u64 h = 2;
    //	mIndex.init(CuckooIndex<>::selectParams(serverSetSize, ssp, true, h));
    //}

    void DrrnPsiServer::setInputs(span<block> inputs, u64 numHash, u64 ssp)
    {
        if (numHash != 2 && numHash != 3)
        {
            std::cout << "#hash must be in {2,3}. Provided h=" << numHash << std::endl;
            throw std::runtime_error(LOCATION);
        }


        mHashingSeed = ZeroBlock; // todo, make random;
        if (mIndex.mBins.size()) throw std::runtime_error(LOCATION);
        mIndex.init(CuckooIndex<>::selectParams(inputs.size(), ssp, 0, numHash));
        //std::cout << mIndex.mParams.mN << " " << mIndex.mParams.mBinScaler << std::endl;

        mCuckooDataPtr.reset(new Item[inputs.size()]);
        mCuckooData = span<Item>(mCuckooDataPtr.get(), inputs.size());




        mIndex.insert(inputs, mHashingSeed);

        //mInputs = inputs;

        auto iter = mCuckooData.begin();
        for (u64 i = 0; i < mIndex.mBins.size(); ++i)
        {
            auto& item = mIndex.mBins[i];
            auto empty = item.isEmpty();
            if (empty == false)
            {
                auto idx = item.idx();
                iter->mCuckooIdx = static_cast<u32>(i);
                iter->mVal = inputs[idx];
                ++iter;
            }
        }

        //#ifndef NDEBUG
        //        mIndex.validate(inputs, mHashingSeed);
        //#endif

    }

    inline u64 divCeil(u64 n, u64 d)
    {
        return (n + d - 1) / d;
    }

    struct DrrnBin
    {

        std::future<void> mRecvFutr;
        u32 mKDepth, mGroupSize, mBinIdx, mBlockSize, mServerId;
        Matrix<block> mKeys;// , mKeys2;

        inline u32 keySize() const
        {
            return mKDepth + 1 + mGroupSize;
        }

        inline u32 getBinSize() const
        {
            return static_cast<u32>(mKeys.rows());
        }

        void init(u32 binSize, u32 kDepth, u32 groupSize, u32 binIdx, u32 bigBlockSize, u32 serverId)
        {
            mKDepth = kDepth;
            mGroupSize = groupSize;
            mBinIdx = binIdx;
            mBlockSize = bigBlockSize;
            mServerId = serverId;

            mKeys.resize(binSize, keySize());
            //mKeys2.resize(binSize, keySize());
        }

        void asyncRecv(Channel& chl)
        {
            mRecvFutr = chl.asyncRecv(mKeys);
            // mRecvFutr = chl.asyncRecv(mKeys2);
        }

        void eval(span<DrrnPsiServer::Item> items, span<block> output, u32 tableSize)
        {
            if (tableSize % mBlockSize != 0)
                throw std::runtime_error(LOCATION);

            mRecvFutr.get();

            if (items.size())
            {

                BgiPirServer::MultiKey mk;
                mk.init(getBinSize(), mKDepth + 1, mGroupSize);
                mk.setKeys(mKeys);


                //BgiPirServer::MultiKey mk2;
                //mk2.init(getBinSize(), mKDepth + 1, mGroupSize);
                //mk2.setKeys(mKeys2);

                auto numBlocks = divCeil(tableSize, mBlockSize);
                std::vector<block> expandedBits(getBinSize());

                const u32 binSize = getBinSize();
                const u32 numSteps = binSize / 8;
                const u32 rem = binSize % 8;

                auto inIter = items.begin();

                //std::vector<std::vector<std::pair<u64, std::vector<u64>>>> hits(binSize);

                auto endIdx = inIter->mCuckooIdx + mBlockSize;

                for (u32 i = 0; i < numBlocks; i++)
                {

                    // get the bits for this big block.
                    {
                        auto bits = mk.yeild();
                        auto bitsIter = bits.data();

                        auto expandedBitsIter = expandedBits.data();
                        for (u32 j = 0; j < numSteps; ++j)
                        {
                            expandedBitsIter[0] = zeroAndAllOne[bitsIter[0]];
                            expandedBitsIter[1] = zeroAndAllOne[bitsIter[1]];
                            expandedBitsIter[2] = zeroAndAllOne[bitsIter[2]];
                            expandedBitsIter[3] = zeroAndAllOne[bitsIter[3]];
                            expandedBitsIter[4] = zeroAndAllOne[bitsIter[4]];
                            expandedBitsIter[5] = zeroAndAllOne[bitsIter[5]];
                            expandedBitsIter[6] = zeroAndAllOne[bitsIter[6]];
                            expandedBitsIter[7] = zeroAndAllOne[bitsIter[7]];
                            expandedBitsIter += 8;
                            bitsIter += 8;
                        }

                        for (u32 j = 0; j < rem; ++j)
                        {
                            expandedBitsIter[j] = zeroAndAllOne[bitsIter[j]];
                        }


                        //auto bits2 = mk2.yeild();
                        //for (u32 j = 0; j < binSize; ++j)
                        //{
                        //    if (bits[j] ^ bits2[j])
                        //    {
                        //        std::vector<u64> items;
                        //        for (u32 k = 0; k < mBlockSize; ++k)
                        //        {
                        //            if (cIter[k].isEmpty() == false)
                        //                items.push_back(cIter[k].idx());
                        //        }
                        //        hits[j].push_back({ i, items });
                        //    }
                        //}
                    }


                    // for this big block, 

                    auto shareIter = output.data();

                    //for (u32 i = 0; i < mBlockSize; ++i)
                    while (
                        inIter != items.end() &&
                        inIter->mCuckooIdx < endIdx)
                    {
                        block& pirData_i = inIter->mVal;
                        ++inIter;
                        auto expandedBitsIter = expandedBits.data();

                        for (u32 j = 0; j < numSteps; ++j)
                        {

                            auto select0 = expandedBitsIter[0] & pirData_i;
                            auto select1 = expandedBitsIter[1] & pirData_i;
                            auto select2 = expandedBitsIter[2] & pirData_i;
                            auto select3 = expandedBitsIter[3] & pirData_i;
                            auto select4 = expandedBitsIter[4] & pirData_i;
                            auto select5 = expandedBitsIter[5] & pirData_i;
                            auto select6 = expandedBitsIter[6] & pirData_i;
                            auto select7 = expandedBitsIter[7] & pirData_i;

                            shareIter[0] = shareIter[0] ^ select0;
                            shareIter[1] = shareIter[1] ^ select1;
                            shareIter[2] = shareIter[2] ^ select2;
                            shareIter[3] = shareIter[3] ^ select3;
                            shareIter[4] = shareIter[4] ^ select4;
                            shareIter[5] = shareIter[5] ^ select5;
                            shareIter[6] = shareIter[6] ^ select6;
                            shareIter[7] = shareIter[7] ^ select7;

                            shareIter += 8;
                            expandedBitsIter += 8;
                        }

                        for (u32 j = 0; j < rem; ++j)
                        {
                            auto select = expandedBitsIter[j] & pirData_i;
                            shareIter[j] = shareIter[j] ^ select;
                        }
                    }

                    endIdx += mBlockSize;
                }


                //if (mServerId == 0 && mBinIdx)
                //{
                //    ostreamLock oo(std::cout);
                //    oo << "bin " << mBinIdx << std::endl;
                //    for (u32 q = 0; q < binSize; ++q)
                //    {
                //        if (hits[q].size() == 1)
                //        {
                //            oo << "   query= " << q << " -> ";
                //            oo << hits[q][0].first << " {";
                //            for (auto& h : hits[q][0].second)
                //                oo << " " << h;
                //            oo << " }" << std::endl;
                //        }
                //        //else
                //        //    oo << " bad (" << hits[q].size() << " hits)" << std::endl;
                //    }
                //}
            }
        }

    };

    void DrrnPsiServer::send(Channel clientChl, Channel srvChl, u64 numThreads)
    {
        //numThreads = 1;
        if (numThreads == 0) numThreads = std::thread::hardware_concurrency();


        u64 cuckooSlotsPerBin = (mIndex.mBins.size() + mNumSimpleBins) / mNumSimpleBins;

        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.send.start");

        // power of 2
        u64 numLeafBlocksPerBin = (cuckooSlotsPerBin + mBigBlockSize * 128 - 1) / (mBigBlockSize * 128);
        u64 gDepth = 2;
        u64 kDepth = std::max<u64>(gDepth, log2floor(numLeafBlocksPerBin)) - gDepth;
        u64 groupSize = (numLeafBlocksPerBin + (u64(1) << kDepth) - 1) / (u64(1) << kDepth);
        if (groupSize > 8) throw std::runtime_error(LOCATION);


        std::vector<block> shares(mNumSimpleBins * mBinSize * mBigBlockSize);
        std::vector<DrrnBin> bins(mNumSimpleBins);

        for (u64 i = 0; i < bins.size(); ++i)
        {
            bins[i].init(
                static_cast<u32>(mBinSize), 
                static_cast<u32>(kDepth), 
                static_cast<u32>(groupSize), 
                static_cast<u32>(i), 
                static_cast<u32>(mBigBlockSize), 
                static_cast<u32>(mServerId));

            bins[i].asyncRecv(clientChl);
        }

        auto routine = [this, numThreads, &bins, &shares](u64 tIdx)
        {
            for (u64 binIdx = tIdx; binIdx < mNumSimpleBins; binIdx += numThreads)
            {
                auto cuckooIdx = roundUpTo(divCeil((binIdx + 0) * mIndex.mBins.size(), mNumSimpleBins), mBigBlockSize);
                auto cuckooEnd = roundUpTo(divCeil((binIdx + 1) * mIndex.mBins.size(), mNumSimpleBins), mBigBlockSize);

                auto itemIdx = find(cuckooIdx);
                auto itemEnd = find(cuckooEnd);


                //if (itemIdx == itemEnd)
                //{

                //    if(mCuckooData[itemIdx].mCuckooIdx )
                //}

                span<Item> items(mCuckooData.begin() + itemIdx, mCuckooData.begin() + itemEnd);

                auto shareIdx = (binIdx + 0) * mBinSize * mBigBlockSize;
                auto shareEnd = (binIdx + 1) * mBinSize * mBigBlockSize;
                span<block> dest(shares.begin() + shareIdx, shares.begin() + shareEnd);
                mIndex.mBins[cuckooIdx];

                bins[binIdx].eval(items, dest, static_cast<u32>(cuckooEnd - cuckooIdx));
            }
        };



        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.query");

        std::vector<std::thread> thrds(numThreads - 1);
        for (u64 i = 1; i < numThreads; ++i)
            thrds[i - 1] = std::thread([i, &routine]() { routine(i); });

        routine(0);

        for (u64 i = 1; i < numThreads; ++i)
            thrds[i - 1].join();

        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.psi");


        if (mServerId)
        {

            auto piSIter = mPiS1.begin();
            for (u64 j = 0; piSIter != mPiS1.end(); ++piSIter, ++j)
            {
                shares[j] = shares[j] ^ *piSIter;
            }

            srvChl.asyncSend(std::move(shares));
            //srvChl.asyncSend(std::move(piS1));
        }
        else
        {
            std::vector<u32> pi0(shares.size());
            std::vector<block> piS0(shares.size()), piSigmaR0(shares.size());
            clientChl.recv((u8*)pi0.data(), pi0.size() * sizeof(u32));
            clientChl.recv(piS0);
            gTimer.setTimePoint("Drrn_Srv.recv_client_perm");
            //srvChl.recv((u8*)pi1SigmaRS.data(), pi1SigmaRS.size() * sizeof(block));

            for (u64 i = 0; i < shares.size(); ++i)
            {
                //std::cout << "pi(r + s)[" << i << "]=" << pi1SigmaRS[pi0[i]] << std::endl;
                piSigmaR0[i] = mPi1SigmaRS[pi0[i]] ^ piS0[i];
            }

            // reuse the memory
            auto& piSigmaRV1 = mPi1SigmaRS;
            srvChl.recv(piSigmaRV1);
            //srvChl.recv(piS1);
            gTimer.setTimePoint("Drrn_Srv.recv_server_perm");


            for (u64 i = 0; i < shares.size(); ++i)
            {

                shares[i] = shares[i] ^ piSigmaR0[i] ^ piSigmaRV1[i];

                //oo << "share[" << i << "] " << shares[i] << " =  " << a << " ^ " << b << std::endl;

            }

            mPsi.sendInput(shares, clientChl);
        }

        if (mServerId == 0) gTimer.setTimePoint("Drrn_Srv.send_done");

    }
    u64 DrrnPsiServer::find(u64 cuckooIdx)
    {
        i64 left = 0, right = mCuckooData.size() - 1;
        u64 ret = -1;
        while (left <= right)
        {
            auto m = (left + right) / 2;

            if (m >= mCuckooData.size())
                throw std::runtime_error(LOCATION);

            if (m < 0)
                throw std::runtime_error(LOCATION);

            if (mCuckooData[m].mCuckooIdx < cuckooIdx)
            {
                left = m + 1;
            }
            else if (mCuckooData[m].mCuckooIdx > cuckooIdx)
            {
                right = m - 1;
            }
            else
            {
                ret = m;
                break;
            }
        }

        if (ret == -1)
            ret = left;


        if (ret)
            Expects(mCuckooData[ret - 1].mCuckooIdx < cuckooIdx);

        if (ret != mCuckooData.size())
            Expects(mCuckooData[ret].mCuckooIdx >= cuckooIdx);

        return ret;
    }
}
#endif