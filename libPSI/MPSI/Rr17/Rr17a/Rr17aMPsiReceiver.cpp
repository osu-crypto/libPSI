#include "Rr17aMPsiReceiver.h"
#include <future>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>

#include <libPSI/Tools/SimpleHasher.h>
#include <cryptoTools/Common/Log.h>
#include <libOTe/Base/naor-pinkas.h>
#include <unordered_map>

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include <libPSI/MPSI/Rr17/Rr17MPsiDefines.h>
#include <libPSI/Tools/CuckooHasher.h>

namespace osuCrypto
{


    inline block shiftRight(block v, u8 n)
    {
        auto v1 = _mm_srli_epi64(v, n);
        auto v2 = _mm_srli_si128(v, 8);
        v2 = _mm_slli_epi64(v2, 64 - (n));
        return _mm_or_si128(v1, v2);
    }

    Rr17aMPsiReceiver::Rr17aMPsiReceiver()
    {
    }

    Rr17aMPsiReceiver::~Rr17aMPsiReceiver()
    {
    }

    void Rr17aMPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        Channel & chl0,
        NcoOtExtReceiver& ots,
        NcoOtExtSender& otSend,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        std::vector<Channel> c{ chl0 };
        init(n, statSecParam, c, ots, otSend, seed, binScaler, inputBitSize);
    }

    void Rr17aMPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        span<Channel> chls,
        NcoOtExtReceiver& otRecv,
        NcoOtExtSender& otSend,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {

        // this is the offline function for doing binning and then performing the OtPsi* between the bins.


        mStatSecParam = statSecParam;
        mN = n;


        // hash to smaller domain size?
        if (inputBitSize == -1)
        {
            inputBitSize = statSecParam + log2ceil(n) - 1;
            mHashToSmallerDomain = true;
        }
        else
        {
            inputBitSize -= log2ceil(n);
            mHashToSmallerDomain = false;
        }

        otSend.configure(true, statSecParam, inputBitSize);
        otRecv.configure(true, statSecParam, inputBitSize); 
        u64 baseOtCount = otSend.getBaseOTCount();

        //mOtMsgBlkSize = (baseOtCount + 127) / 128;


        gTimer.setTimePoint("Init.recv.start");
        mPrng.SetSeed(seed);
        auto& prng = mPrng;

        auto myHashSeed = prng.get<block>();

        auto& chl0 = chls[0];

        // we need a random hash function, so we will both commit to a seed and then later decommit. 
        //This is the commitments phase
        Commit comm(myHashSeed), theirComm;
        chl0.asyncSend(comm.data(), comm.size());
        chl0.recv(theirComm.data(), theirComm.size());

        // ok, now decommit to the seed.
        chl0.asyncSend(&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl0.recv(&theirHashingSeed, sizeof(block));

        gTimer.setTimePoint("Init.recv.hashSeed");

        // compute the hashing seed as the xor of both of ours seeds.
        mHashingSeed = myHashSeed ^ theirHashingSeed;


        // this SimpleHasher class knows how to hash things into bins. But first we need 
        // to compute how many bins we need, the max size of bins, etc.
        mBins.init(n, inputBitSize, mHashingSeed, statSecParam, binScaler);

        gTimer.setTimePoint("Init.recv.baseStart");
        // since we are doing mmlicious PSI, we need OTs going in both directions. 
        // This will hold the send OTs

        if (otRecv.hasBaseOts() == false ||
            otSend.hasBaseOts() == false)
        {
            // first do 128 public key OTs (expensive)
            std::array<block, gOtExtBaseOtCount> kosSendBase;
            BitVector choices(gOtExtBaseOtCount); choices.randomize(prng);
            NaorPinkas base;
            base.receive(choices, kosSendBase, prng, chl0, 2);


            KosOtExtSender kosSend;
            kosSend.setBaseOts(kosSendBase, choices);
            std::vector<std::array<block, 2>> sendBaseMsg(baseOtCount + gOtExtBaseOtCount);
            kosSend.send(sendBaseMsg, prng, chl0);


            // Divide these OT mssages between the Kco and Kos protocols
            span<std::array<block, 2>> kcoRecvBase(
                sendBaseMsg.begin(),
                sendBaseMsg.begin() + baseOtCount);
            span<std::array<block, 2>> kosRecvBase(
                sendBaseMsg.begin() + baseOtCount,
                sendBaseMsg.end());

            BitVector recvChoice(baseOtCount); recvChoice.randomize(prng);
            std::vector<block> kcoSendBase(baseOtCount);
            KosOtExtReceiver kos;
            kos.setBaseOts(kosRecvBase);
            kos.receive(recvChoice, kcoSendBase, prng, chl0);

            // now set these ~800 OTs as the base of our N choose 1 OTs.
            otSend.setBaseOts(kcoSendBase, recvChoice);

            // now set these ~800 OTs as the base of our N choose 1 OTs.
            otRecv.setBaseOts(kcoRecvBase);
        }


        gTimer.setTimePoint("Init.recv.ExtStart");




        auto sendOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtSender& ots, Channel& chl, PRNG& prng)
        {
            auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;
            //std::cout << IoStream::unlock << "rs " << tIdx << " " << (end - start) << std::endl << IoStream::unlock;

            ots.init(end - start, prng, chl);
        };

        auto recvOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtReceiver& ots, Channel& chl, PRNG& prng)
        {
            auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;
            //std::cout << IoStream::unlock << "rr " << tIdx << " " << (end - start) << std::endl << IoStream::unlock;

            ots.init(end - start, prng, chl);
        };




        // compute how amny threads we want to do for each direction.
        // the current thread will do one of the OT receives so -1 for that.
        u64 numThreads = chls.size() - 1;

        // where we will store the threads that are doing the extension
        std::vector<std::thread> thrds(numThreads);

        // some iters to help giving out resources.
        auto thrdIter = thrds.begin();
        auto chlIter = chls.begin() + 1;

        mOtRecvs.resize(chls.size());
        mOtSends.resize(chls.size());
        std::vector<PRNG> prngs(chls.size() - 1);

        // now make the threads that will to the extension
        for (u64 i = 0; i < numThreads; ++i)
        {
            prngs[i].SetSeed(prng.get<block>());

            mOtRecvs[i] = std::move(otRecv.split());
            mOtSends[i] = std::move(otSend.split());

            // spawn the thread and call the routine.
            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                recvOtRoutine(i, chls.size(), *mOtRecvs[i], *chlIter, prngs[i]);
                sendOtRoutine(i, chls.size(), *mOtSends[i], *chlIter, prngs[i]);
            });

            ++chlIter;
        }


        // now use this thread to do a recv routine.
        mOtRecvs.back() = std::move(otRecv.split());
        mOtSends.back() = std::move(otSend.split());
        recvOtRoutine(chls.size() - 1, chls.size(), *mOtRecvs.back(), chl0, prng);
        sendOtRoutine(chls.size() - 1, chls.size(), *mOtSends.back(), chl0, prng);

        // join any threads that we created.
        for (auto& thrd : thrds)
            thrd.join();

        gTimer.setTimePoint("Init.recv.done");



        //std::cout << IoStream::lock;
        //for(u64 j =0; j < )

        //for (u64 i = 0; i < ->mKos.mGens.size(); ++i)
        //{
        //    std::cout << "rr " << i << "  "
        //        << dynamic_cast<Rr17NcoOtReceiver*>(&otRecv)->mKos.mGens[i][0].getSeed() << " "
        //        << dynamic_cast<Rr17NcoOtReceiver*>(&otRecv)->mKos.mGens[i][1].getSeed() << std::endl;
        //}
        //for (u64 i = 0; i < dynamic_cast<Rr17NcoOtSender*>(&otSend)->mKos.mGens.size(); ++i)
        //{
        //    std::cout << "rs " << i << "  "
        //        << dynamic_cast<Rr17NcoOtSender*>(&otSend)->mKos.mGens[i].getSeed() << std::endl;
        //}
        //std::cout << IoStream::unlock;

    }


    void Rr17aMPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> c{ chl };
        sendInput(inputs, c);
    }

    void Rr17aMPsiReceiver::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        // this is the online phase.
        gTimer.setTimePoint("online.recv.start");

        // check that the number of inputs is as expected.
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);



        std::vector<block> recvMasks(mN);
        u64 maskSize = roundUpTo(mStatSecParam + 2 * std::log(mN * mBins.mMaxBinSize) - 1, 8) / 8;

        if (maskSize > sizeof(block))
            throw std::runtime_error("masked are stored in blocks, so they can exceed that size");


        std::vector<std::thread>  thrds(chls.size());
        //std::vector<std::thread>  thrds(1);

        // since we are going to do this in parallel, these objects will
        // be used for synchronization. specifically, when all threads are 
        // done inserting items into the bins, the future will be fulfilled 
        // and all threads will advance to performing the base OtPsi's
        std::atomic<u32>
            insertRemaining(u32(thrds.size())),
            commonRemaining(u32(thrds.size()));

        std::promise<void> insertProm, maskMergeProm;
        std::shared_future<void>
            insertFuture(insertProm.get_future()),
            maskMergeFuture(maskMergeProm.get_future());



        std::promise<void> maskProm;
        std::shared_future<void> maskFuture(maskProm.get_future());
        ByteStream maskBuffer;


        CuckooHasher maskMap;
        maskMap.init(mN * mBins.mMaxBinSize, mStatSecParam, chls.size() > 1);


        // this mutex is used to guard inserting things into the intersection vector.
        std::mutex mInsertMtx;

        std::vector<block> hashToSmallerDomainBuff( mHashToSmallerDomain ? mN : 0);
        span<block> ncoInputBuff(mHashToSmallerDomain ? hashToSmallerDomainBuff : inputs);

        //std::cout << ncoInputBuff.data() << "  " << ncoInputBuff[0].data() << std::endl;

        // fr each thread, spawn it.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]()
            {

                if (tIdx == 0) gTimer.setTimePoint("online.recv.thrdStart");

                auto& otRecv = *mOtRecvs[tIdx];
                auto& otSend = *mOtSends[tIdx];


                auto& chl = chls[tIdx];

                auto startIdx = tIdx     * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();


                AES ncoInputHasher(mHashingSeed);

                u64 phaseShift = log2ceil(mN);
                //if (phaseShift > 3)
                    //throw std::runtime_error(LOCATION);

                for (u64 i = startIdx; i < endIdx; i += 128)
                {
                    auto currentStepSize = std::min(u64(128), endIdx - i);


                    if (mHashToSmallerDomain)
                    {

                            ncoInputHasher.ecbEncBlocks(
                                inputs.data() + i,
                                currentStepSize,
                                ncoInputBuff.data() + i);

                    }
                    else
                    {
                        // simple hack to skip hashing to smaller domain.
                        //memcpy(ncoInputBuff[0].data() + i, inputs.data() + i, currentStepSize * sizeof(block));
                    }
                    // since we are using random codes, lets just use the first part of the code 
                    // as where each item should be hashed.
                    for (u64 j = 0; j < currentStepSize; ++j)
                    {
                        block& item = ncoInputBuff[i + j];
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        // implements phasing. Note that we are doing very course phasing. 
                        // At the byte level. This is good enough for use. Since we just 
                        // need things to be smaller than 76 bits for OOS16.


                        item = shiftRight(item, phaseShift);
                        //switch (phaseShift)
                        //{
                        //case 1:
                        //    ncoInputBuff[0][i + j] = _mm_srli_si128(item, 1);
                        //    break;
                        //case 2:
                        //    ncoInputBuff[0][i + j] = _mm_srli_si128(item, 2);
                        //    break;
                        //case 3:
                        //    ncoInputBuff[0][i + j] = _mm_srli_si128(item, 3);
                        //    break;
                        //default:
                        //    break;
                        //}

                        std::lock_guard<std::mutex> lock(mBins.mMtx[addr]);
                        mBins.mBins[addr].emplace_back(i + j);
                    }
                }

                // block until all items have been inserted. the last to finish will set the promise...
                if (--insertRemaining)
                    insertFuture.get();
                else
                    insertProm.set_value();

                if (tIdx == 0) gTimer.setTimePoint("online.recv.insertDone");

                // get the region of the base OTs that this thread should do.
                auto binStart = tIdx       * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

                PRNG prng(seed);


                std::vector<u16> perm(mBins.mMaxBinSize);
                for (size_t i = 0; i < perm.size(); i++)
                    perm[i] = i;


                //const u64 stepSize = 128;


                u64 otIdx = 0;


                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {

                        auto& bin = mBins.mBins[bIdx];

                        for (u64 i = 0; i < bin.size(); ++i)
                        {
                            u64 inputIdx = bin[i];
                            u16 swapIdx = (prng.get<u16>() % (mBins.mMaxBinSize - i)) + i;
                            std::swap(perm[i], perm[swapIdx]);


                            otRecv.encode(
                                otIdx + perm[i],         // input
                                &ncoInputBuff[inputIdx], // input
                                &recvMasks[inputIdx]);   // output

                            //std::cout << "input[" << inputIdx << "] = " << ncoInputBuff[inputIdx] << " -> " << recvMasks[inputIdx] << " r" << (otIdx + perm[i]) << std::endl;
                        }

                        for (u64 i = bin.size(); i < mBins.mMaxBinSize; ++i)
                        {
                            otRecv.zeroEncode(otIdx + perm[i]);
                        }



                        otIdx += mBins.mMaxBinSize;

                    }

                    otRecv.sendCorrection(chl, currentStepSize * mBins.mMaxBinSize);
                }


                if (tIdx == 0) gTimer.setTimePoint("online.recv.recvMask");

                otIdx = 0;
                //std::cout << IoStream::lock;

                std::vector<block> tempMaskBuff(32);
                std::vector<u64> tempIdxBuff(tempMaskBuff.size());
                CuckooHasher::Workspace w(tempMaskBuff.size());
                u64 tempMaskIdx = 0;
                //std::cout << IoStream::lock << "bidx[" << tIdx << "] = " << binStart << " ~ " << binEnd << "  (" << mBins.mBinCount << ")" << std::endl << IoStream::unlock;
                for (u64 bIdx = binStart; bIdx < binEnd;)
                {

                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    //std::cout << "recver recv " << (currentStepSize * mBins.mMaxBinSize) << std::endl;

                    otSend.recvCorrection(chl, currentStepSize * mBins.mMaxBinSize);



                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto& bin = mBins.mBins[bIdx];

                        for (u64 i = 0; i < bin.size(); ++i)
                        {

                            u64 inputIdx = bin[i];
                            //if (inputIdx > ncoInputBuff[0].size())
                            //    throw std::runtime_error(LOCATION);

                            //std::cout << IoStream::lock << bIdx <<" "<< inputIdx << std::endl << IoStream::unlock;

                            u64 innerOtIdx = otIdx;


                            for (u64 l = 0; l < mBins.mMaxBinSize; ++l)
                            {
                                block sendMask;

                                otSend.encode(
                                    innerOtIdx,
                                    &ncoInputBuff[inputIdx],
                                    &sendMask);

                                //if (inputIdx == 11 )
                                //{
                                //    std::cout  << IoStream::lock
                                //        << "r " << inputIdx << " " 
                                //        << inputs[inputIdx] << " " << l << ": "
                                //        << (sendMask ^ recvMasks[inputIdx]) << " = " 
                                //        << sendMask << " ^ " << recvMasks[inputIdx] 
                                //        << " sendOtIdx " << innerOtIdx << std::endl << IoStream::unlock;
                                //}

                                sendMask = sendMask ^ recvMasks[inputIdx];


                                tempIdxBuff[tempMaskIdx] = inputIdx * mBins.mMaxBinSize + l;


                                tempMaskBuff[tempMaskIdx] = ZeroBlock;
                                memcpy(&tempMaskBuff[tempMaskIdx], &sendMask, maskSize);
                                ++tempMaskIdx;

                                if (tempMaskIdx == tempMaskBuff.size())
                                {

                                    // use aes as a hash function. A weak invertable one. but security doesnt matter here.
                                    mAesFixedKey.ecbEncBlocks(tempMaskBuff.data(), tempMaskIdx, tempMaskBuff.data());
                                    MatrixView<u64> hashes((u64*)tempMaskBuff.data(), tempMaskIdx, 2);

                                    maskMap.insertBatch(tempIdxBuff, hashes, w);

                                    tempMaskIdx = 0;
                                }


                                ++innerOtIdx;
                            }
                        }

                        otIdx += mBins.mMaxBinSize;
                    }

                }
                //std::cout << IoStream::unlock;


                otSend.check(chl, prng.get<block>());
                otRecv.check(chl, prng.get<block>());

                // use aes as a hash function. A weak invertable one. but security doesnt matter here.
                mAesFixedKey.ecbEncBlocks(tempMaskBuff.data(), tempMaskIdx, tempMaskBuff.data());
                std::vector<u64> idxs(tempIdxBuff.begin(), tempIdxBuff.begin() + tempMaskIdx);
                MatrixView<u64> hashes((u64*)tempMaskBuff.data(), tempMaskIdx, 2);
                maskMap.insertBatch(idxs, hashes, w);


                if (tIdx == 0) gTimer.setTimePoint("online.recv.sendMask");

                // all masks have been merged


                // this is the intersection that will be computed by this thread,
                // this will be merged into the overall list at the end.
                std::vector<u64> localIntersection;
                localIntersection.reserve(mBins.mMaxBinSize);


                if (--commonRemaining)
                    maskFuture.get();
                else
                    maskProm.set_value();

                //MatrixView<u8> maskView;
                //if (tIdx == 0)
                //{

                //    static const u64 chunkSize = 1 << 20;

                //    u64 numMasks = mN * mBins.mMaxBinSize;

                //    // make a buffer for the pseudo-code we need to send
                //    maskBuffer.res
                //    
                //    chl.recv(maskBuffer);
                //    maskView = maskBuffer.getMatrixView<u8>(maskSize);

                //    //if (maskView.size()[0] != numMasks)
                //    //    throw std::runtime_error("size not expedted");

                //    maskProm.set_value(maskView);
                //}
                //else
                //{
                //    maskView = maskFuture.get();
                //}

                u64 numMasks = mN * mBins.mMaxBinSize;
                u64 chunkSize = std::min<u64>(1 << 20, (numMasks + chls.size() - 1) / chls.size());
                u64 numChunks = numMasks / chunkSize;

                
                Buff buff(chunkSize * maskSize);

                for (u64 kk = tIdx; kk < numChunks; kk += chls.size())
                {
                    auto curSize = std::min(chunkSize, numMasks - kk * chunkSize) * maskSize;



                    chl.recv(buff.data(), curSize);

                    auto maskView = buff.getMatrixView<u8>(maskSize);

                    for (u64 i = 0; i < maskView.bounds()[0]; )
                    {
                        u64 curStepSize = std::min(tempMaskBuff.size(), maskView.bounds()[0] - i);

                        for (u64 j = 0; j < curStepSize; ++j, ++i)
                        {
                            auto mask = maskView[i];
                            tempMaskBuff[j] = ZeroBlock;
                            memcpy(&tempMaskBuff[j], mask.data(), maskSize);


                            //std::cout << tempMaskBuff[j] << "    " <<kk <<"  "<< (i) << std::endl;
                        }

                        mAesFixedKey.ecbEncBlocks(tempMaskBuff.data(), curStepSize, tempMaskBuff.data());

                        MatrixView<u64> hashes((u64*)tempMaskBuff.data(), curStepSize, 2);
                        maskMap.findBatch(hashes, tempIdxBuff, w);

                        for (u64 j = 0; j < curStepSize; ++j)
                        {
                            //u64 idx = maskMap.find(span<u64>((u64*)&tempMaskBuff[j], 2));
                            if (tempIdxBuff[j] != u64(-1))
                            {
                                auto idx = tempIdxBuff[j] / mBins.mMaxBinSize;
                                //auto offset = tempIdxBuff[j] % mBins.mMaxBinSize;
                                //std::cout << IoStream::lock << "match on " << idx << " " << offset << "  " << hashes[j][0] << std::endl << IoStream::unlock;

                                localIntersection.push_back(idx);
                            }
                        }
                    }

                }

                if (localIntersection.size())
                {
                    std::lock_guard<std::mutex> lock(mInsertMtx);
                    if (mIntersection.size())
                    {
                        mIntersection.insert(
                            mIntersection.end(),
                            localIntersection.begin(),
                            localIntersection.end());
                    }
                    else
                    {
                        mIntersection = std::move(localIntersection);
                    }
                }
                if (tIdx == 0) gTimer.setTimePoint("online.recv.done");


                //if (!tIdx)
                //    gTimer.setTimePoint("sendInput.done");
            });
        }

        // join the threads.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
            thrds[tIdx].join();

        //std::cout << IoStream::lock << "exit" << std::endl << IoStream::unlock;

        gTimer.setTimePoint("online.recv.exit");

        //std::cout << gTimer;
    }
}