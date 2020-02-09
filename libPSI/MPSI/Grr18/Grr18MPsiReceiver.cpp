#include "libPSI/config.h"
#ifdef ENABLE_GRR_PSI

#include "Grr18MPsiReceiver.h"
#include <future>
#include <unordered_map>
#include <random>

#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/Commit.h>

#include <libPSI/Tools/SimpleHasher.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <libOTe/Base/naor-pinkas.h>

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include <libPSI/MPSI/Rr17/Rr17MPsiDefines.h>
#include <libPSI/Tools/CuckooHasher.h>
#include "Grr18Common.h"
#include <sparsehash/dense_hash_map>

namespace osuCrypto
{

    namespace {
        template<typename T>
        struct NoHash
        {
            inline size_t operator()(const T& v) const
            {
                return v;
            }
        };
    }


    inline block shiftRight(block v, u8 n)
    {
        auto v1 = _mm_srli_epi64(v, n);
        auto v2 = _mm_srli_si128(v, 8);
        v2 = _mm_slli_epi64(v2, 64 - (n));
        return _mm_or_si128(v1, v2);
    }

    Grr18MPsiReceiver::Grr18MPsiReceiver()
    {
    }

    Grr18MPsiReceiver::~Grr18MPsiReceiver()
    {
    }

    void Grr18MPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        Channel & chl0,
        OosNcoOtReceiver& ots,
        OosNcoOtSender& otSend,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        std::vector<Channel> c{ chl0 };
        init(n, statSecParam, c, ots, otSend, seed, binScaler, inputBitSize);
    }

    void Grr18MPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        span<Channel> chls,
        OosNcoOtReceiver& otRecv,
        OosNcoOtSender& otSend,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {

        // this is the offline function for doing binning and then performing the OtPsi* between the bins.

        mTotalLoad.reset(new std::atomic<u64>(0));
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

        otSend.configure(true, 40, inputBitSize);
        otRecv.configure(true, 40, inputBitSize);
        u64 baseOtCount = otSend.getBaseOTCount();

        //mOtMsgBlkSize = (baseOtCount + 127) / 128;


        setTimePoint("grr.recv.Init.start");
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
        chl0.asyncSend((u8*)&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl0.recv((u8*)&theirHashingSeed, sizeof(block));

        setTimePoint("grr.recv.Init.hashSeed");

        // compute the hashing seed as the xor of both of ours seeds.
        mHashingSeed = myHashSeed ^ theirHashingSeed;


        // this SimpleHasher class knows how to hash things into bins. But first we need
        // to compute how many bins we need, the max size of bins, etc.
        mBins.init(n, inputBitSize, mHashingSeed, statSecParam, binScaler);

        setTimePoint("grr.recv.Init.baseStart");
        // since we are doing mmlicious PSI, we need OTs going in both directions.
        // This will hold the send OTs

        if (otRecv.hasBaseOts() == false ||
            otSend.hasBaseOts() == false)
        {
#ifdef LIBOTE_HAS_BASE_OT

            // first do 128 public key OTs (expensive)
            std::array<block, gOtExtBaseOtCount> kosSendBase;
            BitVector choices(gOtExtBaseOtCount); choices.randomize(prng);
            DefaultBaseOT base;
            base.receive(choices, kosSendBase, prng, chl0, 2);


            KosOtExtSender kosSend;
            kosSend.setBaseOts(kosSendBase, choices, chl0);
            std::vector<std::array<block, 2>> sendBaseMsg(baseOtCount + gOtExtBaseOtCount);
            kosSend.send(sendBaseMsg, prng, chl0);


            // Divide these OT mssages between the Kco and Kos protocols
            span<std::array<block, 2>> kcoRecvBase(
                sendBaseMsg.begin(),
                sendBaseMsg.begin() + baseOtCount);
            span<std::array<block, 2>> kosRecvBase(
                sendBaseMsg.begin() + baseOtCount,
                sendBaseMsg.end());

            // now set these ~800 OTs as the base of our N choose 1 OTs.
            otRecv.setBaseOts(kcoRecvBase, mPrng, chl0);

            BitVector recvChoice(baseOtCount); recvChoice.randomize(prng);
            std::vector<block> kcoSendBase(baseOtCount);
            KosOtExtReceiver kos;
            kos.setBaseOts(kosRecvBase, mPrng, chl0);
            kos.receive(recvChoice, kcoSendBase, prng, chl0); 

            // now set these ~800 OTs as the base of our N choose 1 OTs.
            otSend.setBaseOts(kcoSendBase, recvChoice, chl0);

#else
            throw std::runtime_error("base OTs must be set. " LOCATION);
#endif
        }


        setTimePoint("grr.recv.Init.ExtStart");


        mOtRecvs.resize(chls.size());
        mOtSends.resize(chls.size());

        // now make the threads that will to the extension
        for (u64 i = 0; i < chls.size(); ++i)
        {
            mOtRecvs[i] = std::move(otRecv.splitBase());
            mOtSends[i] = std::move(otSend.splitBase());
        }

        setTimePoint("grr.recv.Init.done");
    }


    void Grr18MPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> c{ chl };
        sendInput(inputs, c);
    }

    void Grr18MPsiReceiver::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        // this is the online phase.
        setTimePoint("grr.recv.online.start");

        // check that the number of inputs is as expected.
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);


        std::vector<block> recvMasks(mN);
        u64 maskSize = roundUpTo(u64(mStatSecParam + 2 * std::log(mN * mBins.mMaxBinSize) - 1), 8) / 8;

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

        //std::vector<block> sendMasks(mN * mBins.mMaxBinSize);
        //CuckooHasher maskMap;
        //maskMap.init(mN * mBins.mMaxBinSize, 40, chls.size() > 1);

        // this mutex is used to guard inserting things into the intersection vector.
        std::mutex mInsertMtx;

        std::vector<block> hashToSmallerDomainBuff(mHashToSmallerDomain ? mN : 0);
        span<block> ncoInputBuff(mHashToSmallerDomain ? hashToSmallerDomainBuff : inputs);

        Matrix<u8> masks(mN, mBins.mMaxBinSize * maskSize);
        google::dense_hash_map<u64, u64, NoHash<u64>> maskMap(mN * mBins.mMaxBinSize);
        maskMap.set_empty_key(0);

        //std::cout << ncoInputBuff.data() << "  " << ncoInputBuff[0].data() << std::endl;

        // fr each thread, spawn it.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]()
            {
                setThreadName("recv_thrd_" + std::to_string(tIdx));

                if (tIdx == 0) setTimePoint("grr.recv.online.thrdStart");

                auto& otRecv = mOtRecvs[tIdx];
                auto& otSend = mOtSends[tIdx];


                auto startIdx = tIdx * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();

                // get the region of the base OTs that this thread should do.
                auto binStart = tIdx * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

                const auto multiThreaded = chls.size() > 1;
                auto& chl = chls[tIdx];

                std::vector<u8> loads(binEnd - binStart), theirLoads;
                u64 theirTotalLoad;
                auto theirTotalLoadFut = chl.asyncRecv(theirTotalLoad);
                auto theirLoadsFut = chl.asyncRecv(theirLoads);

                AES ncoInputHasher(mHashingSeed);

                u8 phaseShift = u8(log2ceil(mN));
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

                    // since we are using random codes, lets just use the first part of the code
                    // as where each item should be hashed.
                    for (u64 j = 0; j < currentStepSize; ++j)
                    {
                        block& item = ncoInputBuff[i + j];
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        //ostreamLock(std::cout) << "r[" << i + j << "] = " << ncoInputBuff[i + j] << " -> bin " << addr << std::endl;

                        // implements phasing. Note that we are doing very course phasing.
                        // At the byte level. This is good enough for use. Since we just
                        // need things to be smaller than 76 bits for OOS16.

                        item = shiftRight(item, phaseShift);


                        mBins.push(addr, i + j);
                        //if (multiThreaded)
                        //{
                        //    std::lock_guard<std::mutex> lock(mBins.mMtx[addr]);
                        //    mBins.mBins[addr].emplace_back(i + j);
                        //}
                        //else
                        //{
                        //    mBins.mBins[addr].emplace_back(i + j);
                        //}
                    }
                }

                // block until all items have been inserted. the last to finish will set the promise...
                if (--insertRemaining)
                    insertFuture.get();
                else
                    insertProm.set_value();

                if (tIdx == 0) setTimePoint("grr.recv.online.insertDone");


                PRNG prng(seed);
                computeLoads(loads, prng, binStart, mOneSided, mLapPlusBuff, mN, mBins, mEpsBins);

                theirLoadsFut.get();
                u64  totalLoad = 0;
                for (u64 i = 0; i < loads.size(); ++i)
                {
                    loads[i] = std::max(loads[i], theirLoads[i]);
                    totalLoad += loads[i];
                }

                chl.asyncSend(totalLoad);
                chl.asyncSend(loads.data(), loads.size());


                Channel throwIfUsed;
                otRecv.init(totalLoad, prng, throwIfUsed);
                *mTotalLoad += totalLoad;

                std::vector<u16> permutation(mBins.mMaxBinSize);



                u64 otIdx = 0;


                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
                    auto otStart = otIdx;



                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {

                        auto bin = mBins.getBin(bIdx);
                        auto load = loads[bIdx - binStart];


                        permutation.resize(load);
                        for (size_t i = 0; i < permutation.size(); i++)
                            permutation[i] = (u16)i;
                        std::random_shuffle(permutation.begin(), permutation.end(), prng);

                        for (u64 i = 0; i < permutation.size(); ++i)
                        {
                            if (permutation[i] < bin.size())
                            {
                                u64 inputIdx = bin[permutation[i]];


                                otRecv.encode(
                                    otIdx,                   //  input
                                    &ncoInputBuff[inputIdx], //  input
                                    &recvMasks[inputIdx]);   // output
                                //ostreamLock(std::cout) << "r[" << inputIdx << "] encoded under " << i << " -> " << recvMasks[inputIdx] << std::endl;
                            }
                            else
                            {
                                otRecv.zeroEncode(otIdx);
                            }

                            otIdx++;
                        }
                    }

                    otRecv.sendCorrection(chl, otIdx - otStart);
                }


                if (tIdx == 0) setTimePoint("grr.recv.online.recvMask");




                otIdx = 0;
                theirTotalLoadFut.get();

                otSend.init(theirTotalLoad, prng, throwIfUsed);

                std::vector<std::future<void>> correctionFutrs((binEnd - binStart + stepSize - 1) / stepSize);

                for (u64 bIdx = binStart, i = 0; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
                    auto numCorrections = 0ull;

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        numCorrections += theirLoads[bIdx - binStart];
                    }
                    correctionFutrs[i++] = otSend.asyncRecvCorrection(chl, numCorrections);
                }



                std::vector<std::pair<u64, u64>> insertBuffer(mBins.mMaxBinSize * 4096);
                auto insertIter = insertBuffer.data();
                auto insertEnd = insertBuffer.data() + insertBuffer.size();


                u64 keyMask = (maskSize >= 8) ? ~0ull : ~(~0ull << (maskSize * 8));

                Expects(keyMask);

                //std::unordered_map<u64, std::pair<i64, block>> maskMap; maskMap.reserve(mN * mBins.mMaxBinSize);

                for (u64 bIdx = binStart, i = 0; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
                    correctionFutrs[i++].get();

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto bin = mBins.getBin(bIdx);
                        auto binLoad = theirLoads[bIdx - binStart];


                        for (u64 i = 0; i < bin.size(); ++i)
                        {
                            u64 inputIdx = bin[i];
                            u64 innerOtIdx = otIdx;
                            auto inBlock = recvMasks[inputIdx];
                            //ostreamLock oo(std::cout);
                            //oo << "r[" << inputIdx << "] encodes " << std::endl;

                            if (insertIter + binLoad > insertEnd)
                            {
                                auto size = insertIter - insertBuffer.data();
                                insertIter = insertBuffer.data();
                                if (multiThreaded)
                                {
                                    std::lock_guard<std::mutex> lock(mInsertMtx);
                                    maskMap.insert(insertBuffer.begin(), insertBuffer.begin() + size);
                                }
                                else
                                    maskMap.insert(insertBuffer.begin(), insertBuffer.begin() + size);
                            }


                            for (u64 l = 0; l < binLoad; ++l)
                            {
                                block sendMask;
                                u64& key = insertIter->first;
                                insertIter->second = inputIdx * mBins.mMaxBinSize + l;
                                ++insertIter;


                                otSend.encode(
                                    innerOtIdx,
                                    &ncoInputBuff[inputIdx],
                                    &sendMask);

                                //oo << "   " << sendMask << " ^ " << recvMasks[inputIdx];
                                sendMask = sendMask ^ inBlock;
                                key = (*(u64*)&sendMask) & keyMask;
                                //oo << " -> " << sendMask << "   ~  " << key << "  ~ " << innerOtIdx << std::endl;


                                memcpy(masks.data(inputIdx) + l * maskSize, &sendMask, maskSize);
                                ++innerOtIdx;
                            }


                        }

                        otIdx += binLoad;
                    }

                }

                u64 totalMaskCount;
                auto totalMaskCountFutr = chl.asyncRecv(totalMaskCount);



                otRecv.sendFinalization(chl, prng.get<block>()); // sends
                otSend.recvFinalization(chl);       // recvs

                otSend.sendChallenge(chl, prng.get<block>());
                otRecv.recvChallenge(chl);

                otRecv.computeProof();
                otRecv.sendProof(chl);

                otSend.computeProof();

                {
                    auto size = insertIter - insertBuffer.data();
                    std::lock_guard<std::mutex> lock(mInsertMtx);
                    maskMap.insert(insertBuffer.begin(), insertBuffer.begin() + size);
                }


                if (tIdx == 0) setTimePoint("grr.recv.online.sendMask");

                // all masks have been merged


                // this is the intersection that will be computed by this thread,
                // this will be merged into the overall list at the end.
                std::vector<u64> localIntersection;
                localIntersection.reserve(mBins.mMaxBinSize);


                if (--commonRemaining)
                    maskFuture.get();
                else
                    maskProm.set_value();

                totalMaskCountFutr.get();

                //if (tIdx == 0)
                //{
                //    ostreamLock oo(std::cout);

                //    for (auto m : maskMap)
                //    {

                //        auto idx = m.second / mBins.mMaxBinSize;
                //        auto offset = m.second % mBins.mMaxBinSize;

                //        oo << "idx " << idx << " " << offset << " " << m.first << std::endl;
                //    }
                //}


                u64 maxSendSize = 1ull << log2ceil(mN);
                auto curRow = totalMaskCount * tIdx / chls.size();
                auto endRow = totalMaskCount * (tIdx + 1) / chls.size();

                Matrix<u8> theirMasks(endRow - curRow, maskSize, AllocType::Uninitialized);
                auto theirMasksIter = theirMasks.data();
                std::vector<std::future<void>> maskFutrs((endRow - curRow + maxSendSize - 1) / maxSendSize);
                auto futrIter = maskFutrs.begin();

                {
                    int i = 0;
                    //ostreamLock oo(std::cout);
                    //oo << "r " << curRow << " -> " << endRow << std::endl;
                    while (curRow != endRow)
                    {
                        auto step = std::min(maxSendSize, endRow - curRow);
                        //oo << "r step " << step << " " << i++ << std::endl;

                        if (theirMasksIter + step * maskSize > theirMasks.data() + theirMasks.size())
                            throw std::runtime_error(LOCATION);

                        *futrIter++ = chl.asyncRecv(theirMasksIter, step * maskSize);
                        theirMasksIter += step * maskSize;
                        curRow += step;
                    }
                }

                curRow = totalMaskCount * tIdx / chls.size();
                endRow = totalMaskCount * (tIdx + 1) / chls.size();
                theirMasksIter = theirMasks.data();

                futrIter = maskFutrs.begin();
                int i = 0;
                while (curRow != endRow)
                {
                    auto step = std::min(maxSendSize, endRow - curRow);
                    curRow += step;

                    //std::cout << i++ << std::endl;
                    futrIter++->get();

                    //std::cout << "#rows " << rows << std::endl;
                    for (u64 i = 0; i < step; ++i)
                    {
                        auto key = *(u64*)theirMasksIter & keyMask;
                        //if (key == 0)
                        //    throw std::runtime_error(LOCATION);
                        auto ll = maskMap.find(key);

                        if (ll != maskMap.end())
                        {
                            auto idx = ll->second / mBins.mMaxBinSize;
                            auto offset = ll->second % mBins.mMaxBinSize;
                            auto localMask = masks.data(idx) + offset * maskSize;

                            //ostreamLock o(std::cout);
                            //o << "match " << idx << " " << offset << " " << key << std::endl;
                            if (memcmp(theirMasksIter, localMask, maskSize) == 0)
                            {
                                //o << "full " << idx << " " << offset << std::endl;

                                localIntersection.push_back(idx);
                            }
                        }
                        //else
                        //{
                        //    ostreamLock o(std::cout);
                        //    o << "miss " << key << std::endl;
                        //}

                        theirMasksIter += maskSize;
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
                if (tIdx == 0) setTimePoint("grr.recv.online.done");


                otSend.recvProof(chl);
                //otSend.check(chl, prng.get<block>());

            });
        }

        // join the threads.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
            thrds[tIdx].join();

        //std::cout << IoStream::lock << "exit" << std::endl << IoStream::unlock;

        setTimePoint("grr.recv.online.exit");

        //std::cout << gTimer;
    }
}
#endif