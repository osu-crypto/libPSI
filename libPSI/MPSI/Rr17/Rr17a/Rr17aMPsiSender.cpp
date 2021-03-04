#include "libPSI/config.h"
#ifdef ENABLE_RR17_PSI

#include "Rr17aMPsiSender.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libPSI/MPSI/Rr17/Rr17MPsiDefines.h"
#include <atomic>

namespace osuCrypto
{

    inline block shiftRight(block v, u8 n)
    {
        auto v1 = _mm_srli_epi64(v, n);
        auto v2 = _mm_srli_si128(v, 8);
        v2 = _mm_slli_epi64(v2, 64 - (n));
        return _mm_or_si128(v1, v2);
    }

    Rr17aMPsiSender::Rr17aMPsiSender()
    {
    }
    //const u64 Rr17aMPsiSender::hasherStepSize(128);


    Rr17aMPsiSender::~Rr17aMPsiSender()
    {
    }

    void Rr17aMPsiSender::init(u64 n, u64 statSec,
        Channel & chl0,
        NcoOtExtSender&  ots,
        NcoOtExtReceiver& otRecv,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        std::vector<Channel> c{ chl0 };
        init(n, statSec, c, ots, otRecv, seed, binScaler, inputBitSize);
    }

    void Rr17aMPsiSender::init(u64 n, u64 statSecParam,
        span<Channel> chls,
        NcoOtExtSender& otSend,
        NcoOtExtReceiver& otRecv,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        mStatSecParam = statSecParam;
        mN = n;
        setTimePoint("rr17a.init.send.start");


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


        mOtMsgBlkSize = (baseOtCount + 127) / 128;


        mPrng.SetSeed(seed);
        auto myHashSeed = mPrng.get<block>();
        auto& chl0 = chls[0];


        Commit comm(myHashSeed), theirComm;
        chl0.asyncSend(comm.data(), comm.size());
        chl0.recv(theirComm.data(), theirComm.size());


        chl0.asyncSend((u8*)&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl0.recv((u8*)&theirHashingSeed, sizeof(block));

        mHashingSeed = myHashSeed ^ theirHashingSeed;

        setTimePoint("rr17a.init.send.hashSeed");


        mBins.init(n, inputBitSize, mHashingSeed, statSecParam, binScaler);
        
        //std::cout << "max bin size: " << mBins.mMaxBinSize << " #masks " << mN * mBins.mMaxBinSize<< std::endl;
        //mPsis.resize(mBins.mBinCount);

        setTimePoint("rr17a.init.send.baseStart");

        if (otSend.hasBaseOts() == false ||
            otRecv.hasBaseOts() == false)
        {
#if defined(LIBOTE_HAS_BASE_OT) && defined(ENABLE_KOS)

            // first do 128 public key OTs (expensive)
            std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;
            DefaultBaseOT base;
            base.send(baseMsg, mPrng, chl0, 2);


            // now extend these to enough recv OTs to seed the send Kco and the send Kos ot extension
            BitVector recvChoice(baseOtCount + gOtExtBaseOtCount); recvChoice.randomize(mPrng);
            std::vector<block> recvBaseMsg(baseOtCount + gOtExtBaseOtCount);
            KosOtExtReceiver kosRecv;
            kosRecv.setBaseOts(baseMsg, mPrng, chl0);
            kosRecv.receive(recvChoice, recvBaseMsg, mPrng, chl0);


            // we now have a bunch of recv OTs, lets seed the NcoOtExtSender
            BitVector kcoSendBaseChoice;
            kcoSendBaseChoice.copy(recvChoice, 0, baseOtCount);
            span<block> kcoSendBase(
                recvBaseMsg.begin(),
                recvBaseMsg.begin() + baseOtCount);

            otSend.setBaseOts(kcoSendBase, kcoSendBaseChoice, chl0);


            // now lets extend these recv OTs in the other direction
            BitVector kosSendBaseChoice;
            kosSendBaseChoice.copy(recvChoice, baseOtCount, gOtExtBaseOtCount);
            span<block> kosSendBase(
                recvBaseMsg.begin() + baseOtCount,
                recvBaseMsg.end());
            KosOtExtSender kos;
            kos.setBaseOts(kosSendBase, kosSendBaseChoice, chl0);

            // these send OTs will be stored here
            std::vector<std::array<block, 2>> sendBaseMsg(baseOtCount);
            kos.send(sendBaseMsg, mPrng, chl0);

            // now set these ~800 OTs as the base of our N choose 1 OTs NcoOtExtReceiver
            otRecv.setBaseOts(sendBaseMsg, mPrng, chl0);
#else
            throw std::runtime_error("base OTs must be set or enable base OTs and KOS in libOTe. " LOCATION);
#endif
        }

        setTimePoint("rr17a.init.send.extStart");

        mOtSends.resize(chls.size());
        mOtRecvs.resize(chls.size());


        auto sendOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtSender& ots, Channel& chl, PRNG& prng)
        {
            auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;

            //std::cout << IoStream::unlock << "ss " << tIdx << " " << (end - start) << std::endl<<IoStream::unlock;

            ots.init(end - start, prng, chl);
        };

        auto recvOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtReceiver& ots, Channel& chl, PRNG& prng)
        {
            auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;

            //std::cout << IoStream::unlock << "sr " << tIdx << " " << (end - start) << std::endl << IoStream::unlock;
            ots.init(end - start, prng, chl);
        };

        u64 numThreads = chls.size() - 1;

        //std::cout << IoStream::lock;
        //for (u64 i = 0; i < dynamic_cast<Rr17NcoOtReceiver*>(&otRecv)->mKos.mGens.size(); ++i)
        //{
        //    std::cout << "sr " << i << "  "
        //        << dynamic_cast<Rr17NcoOtReceiver*>(&otRecv)->mKos.mGens[i][0].getSeed() << " "
        //        << dynamic_cast<Rr17NcoOtReceiver*>(&otRecv)->mKos.mGens[i][1].getSeed() << std::endl;
        //}
        //for (u64 i = 0; i < dynamic_cast<Rr17NcoOtSender*>(&otSend)->mKos.mGens.size(); ++i)
        //{
        //    std::cout << "ss " << i << "  "
        //        << dynamic_cast<Rr17NcoOtSender*>(&otSend)->mKos.mGens[i].getSeed() << std::endl;
        //}
        //std::cout << IoStream::unlock;

        std::vector<std::thread> thrds(numThreads);
        auto thrdIter = thrds.begin();
        auto chlIter = chls.begin() + 1;

        std::vector<PRNG> prngs(chls.size() - 1);

        for (u64 i = 0; i < numThreads; ++i)
        {
            prngs[i].SetSeed(mPrng.get<block>());

            mOtSends[i] = std::move(otSend.split());
            mOtRecvs[i] = std::move(otRecv.split());

            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                sendOtRoutine(i, chls.size(), *mOtSends[i], *chlIter, prngs[i]);
                recvOtRoutine(i, chls.size(), *mOtRecvs[i], *chlIter, prngs[i]);
            });
            ++chlIter;
        }

        mOtSends.back() = std::move(otSend.split());
        mOtRecvs.back() = std::move(otRecv.split());

        sendOtRoutine(chls.size() - 1, chls.size(), *mOtSends.back(), chl0, mPrng);
        recvOtRoutine(chls.size() - 1, chls.size(), *mOtRecvs.back(), chl0, mPrng);

        for (auto& thrd : thrds)
            thrd.join();

        setTimePoint("rr17a.init.send.done");

    }


    void Rr17aMPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> c{ chl };
        sendInput(inputs, c);
    }

    void Rr17aMPsiSender::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);

        u64 maskSize = roundUpTo(u64(mStatSecParam + 2 * std::log(mN * mBins.mMaxBinSize) - 1), 8) / 8;

        if (maskSize > sizeof(block))
            throw std::runtime_error("masked are stored in blocks, so they can exceed that size");


        std::vector<std::thread>  thrds(chls.size());
        //std::vector<std::thread>  thrds(1);

        std::atomic<u32> remaining((u32)thrds.size()), remainingMasks((u32)thrds.size());
        std::promise<void> doneProm, maskProm;
        std::shared_future<void>
            doneFuture(doneProm.get_future()),
            maskFuture(maskProm.get_future());

        std::mutex mtx;

        std::vector<block> hashToSmallerDomainBuff(mHashToSmallerDomain ? mN : 0);
        span<block> ncoInputBuff(mHashToSmallerDomain ? hashToSmallerDomainBuff : inputs);
        std::vector<block> recvMasks(mN);

        //for (u64 hashIdx = 0; hashIdx < ncoInputBuff.size(); ++hashIdx)
        //    ncoInputBuff[hashIdx].resize(inputs.size());
        //for (u64 i = 0; i < mN; ++i)
        //{
        //    ostreamLock(std::cout) << "s[" << i << "] " << inputs[i] << std::endl;
        //}

        std::vector<u64> maskPerm(mN);

        auto permSeed = mPrng.get<block>();

        std::promise<void> permProm;
        std::shared_future<void> permDone(permProm.get_future());

        auto permThrd = std::thread([&]() {
            PRNG prng(permSeed);
            for (u64 i = 0; i < maskPerm.size(); ++i)
                maskPerm[i] = i;

            std::random_shuffle(maskPerm.begin(), maskPerm.end(), prng);
            //u64 l, u32Max = (u32(-1));
            //for (l = maskPerm.size(); l > u32Max; --l)
            //{
            //    u64 d = prng.get<u64>() % l;

            //    u64 pi = maskPerm[l];
            //    maskPerm[l] = maskPerm[d];
            //    maskPerm[d] = pi;
            //}
            //for (l = maskPerm.size(); l > 1; --l)
            //{

            //    u32 d = prng.get<u32>() % l;

            //    u64 pi = maskPerm[l];
            //    maskPerm[l] = maskPerm[d];
            //    maskPerm[d] = pi;
            //}
            permProm.set_value();
        });

        std::atomic<u64> maskIdx(0);// , inserts(0);
        //std::shared_ptr<Buff> sendMaskBuff(new Buff);
        std::vector<u8>* sendMaskBuff(new std::vector<u8>);
        auto numMasks = maskPerm.size() * mBins.mMaxBinSize;
        sendMaskBuff->resize(numMasks * maskSize);
        auto maskView = MatrixView<u8>(sendMaskBuff->begin(), sendMaskBuff->end(), maskSize);

        u64 masksPer = std::min<u64>(1 << 20, (numMasks + chls.size() - 1) / chls.size());
        u64 numChunks = (numMasks + (masksPer - 1)) / masksPer;
        auto sendMaskBuffFreeCounter = new std::atomic<u32>;
        *sendMaskBuffFreeCounter = u32(numChunks);

        setTimePoint("rr17a.online.send.spaw");

        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]() {

                PRNG prng(seed);

                if (tIdx == 0) setTimePoint("rr17a.online.send.thrdStart");

                auto& otRecv = *mOtRecvs[tIdx];
                auto& otSend = *mOtSends[tIdx];

                auto& chl = chls[tIdx];
                auto startIdx = tIdx * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();

                // compute the region of inputs this thread should insert.
                //span<block> itemRange(
                //    inputs.begin() + startIdx,
                //    inputs.begin() + endIdx);

                AES ncoInputHasher(mHashingSeed);// (mNcoInputBlkSize);
                //for (u64 i = 0; i < ncoInputHasher.size(); ++i)
                    //ncoInputHasher[i].setKey(_mm_set1_epi64x(i) ^ mHashingSeed);

                u8 phaseShift = u8(log2ceil(mN));// / 8;

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
                        //memcpy(ncoInputBuff.data() + i, inputs.data() + i, currentStepSize * sizeof(block));
                    }

                    // since we are using random codes, lets just use the first part of the code
                    // as where each item should be hashed.
                    for (u64 j = 0; j < currentStepSize; ++j)
                    {
                        block& item = ncoInputBuff[i + j];
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        // implements phase. Note that we are doing very course phasing.
                        // At the byte level. This is good enough for use. Since we just
                        // need things tp be smaller than 76 bits.

                        item = shiftRight(item, phaseShift);

                        mBins.push(addr, i + j);
                    }

                    //if (tIdx == 0) std::cout << "\r" << std::setw(8) << i << " / " << endIdx << " a" << std::flush;
                }
                //<< IoStream::lock << "Sender"<< std::endl;
                //mBins.insertItemsWithPhasing(range, mStatSecParam, inputs.size());


                // block until all items have been inserted. the last to finish will set the promise...
                if (--remaining)
                    doneFuture.get();
                else
                    doneProm.set_value();

                if (tIdx == 0) setTimePoint("rr17a.online.send.insert");

                //if (!tIdx)
                {
                    u64 max = 0;
                    for(u64 i =0; i < mBins.mBinCount; ++i)
                    {
                        max = std::max<u64>(max, mBins.getBinSize(i));
                    }

                    //std::cout << " true max: " << max << std::endl;
                }

                //const u64 stepSize = 128;

                auto binStart = tIdx * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

                std::vector<u16> permutation(mBins.mMaxBinSize);
                for (size_t i = 0; i < permutation.size(); i++)
                    permutation[i] = (u16)i;

                u64 otIdx = 0;
                //u64 maskIdx = binStart;

                //std::vector<block> ncoInput(mNcoInputBlkSize);

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {

                        auto bin = mBins.getBin(bIdx);
                        std::random_shuffle(permutation.begin(), permutation.end(), prng);

                        for (u64 i = 0; i < permutation.size(); ++i)
                        {

                            if (permutation[i] < bin.size())
                            {
                                u64 inputIdx = bin[permutation[i]];
                                // ncoInput

                                otRecv.encode(
                                    otIdx,                   //  input
                                    &ncoInputBuff[inputIdx], //  input
                                    &recvMasks[inputIdx]);   // output

                            }
                            else
                            {

                                otRecv.zeroEncode(otIdx);
                            }

                            otIdx++;
                        }
                    }
                    //std::cout << "sender send " << (currentStepSize * mBins.mMaxBinSize) << std::endl;

                    otRecv.sendCorrection(chl, currentStepSize * mBins.mMaxBinSize);


                    //if (tIdx == 0) std::cout << "\r" << std::setw(8) << bIdx << " / " << binEnd << " b" << std::flush;

                }



                std::vector<u8> buff;
                otIdx = 0;

                if (tIdx == 0) setTimePoint("rr17a.online.send.recvMask");
                permDone.get();
                if (tIdx == 0) setTimePoint("rr17a.online.send.permPromDone");

                //std::cout << IoStream::lock;

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {

                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    otSend.recvCorrection(chl, currentStepSize * mBins.mMaxBinSize);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto bin = mBins.getBin(bIdx);
                        auto mm = maskIdx.fetch_add(bin.size(), std::memory_order::memory_order_relaxed);


                        for (u64 i = 0; i < bin.size(); ++i)
                        {

                            u64 inputIdx = bin[i];

                            u64 baseMaskIdx = maskPerm[mm + i] * mBins.mMaxBinSize;

                            u64 innerOtIdx = otIdx;

                            for (u64 l = 0; l < mBins.mMaxBinSize; ++l)
                            {

                                //for (u64 j = 0; j < mNcoInputBlkSize; ++j)
                                //{
                                //    ncoInput[j] = ncoInputBuff[inputIdx];
                                //}

                                block sendMask;

                                otSend.encode(
                                    innerOtIdx,
                                    &ncoInputBuff[inputIdx],
                                    &sendMask);

                                //std::cout << "input[" << inputIdx << "] = " << ncoInputBuff[inputIdx] << " -> " << recvMasks[inputIdx] << " r" << (innerOtIdx) << std::endl;

                                //if (inputIdx == 1)
                                //{
                                //ostreamLock(std::cout)
                                //    << "s " << inputIdx << " "
                                //    << inputs[inputIdx] << " " << l << ": "
                                //    << (sendMask ^ recvMasks[inputIdx]) << " = "
                                //    << sendMask << " ^ " << recvMasks[inputIdx] << "     " << (baseMaskIdx + l) << " sendOtIdx " << innerOtIdx << std::endl;
                                //}

                                sendMask = sendMask ^ recvMasks[inputIdx];

                                // truncate the block size mask down to "maskSize" bytes
                                // and store it in the maskView matrix at row maskIdx
                                memcpy(
                                    maskView[baseMaskIdx + l].data(),
                                    (u8*)&sendMask,
                                    maskSize);
                                //if (inputIdx == 2)
                                //{

                                //    std::cout << IoStream::lock
                                //        << "s 2 " << inputs[inputIdx] << " " << l << ": "
                                //        << (sendMask ^ recvMasks[inputIdx]) << " = "
                                //        << sendMask << " ^ " << recvMasks[inputIdx] << std::endl << IoStream::unlock;
                                //}

                                ++innerOtIdx;
                            }

                        }

                        //++maskIdx;
                        otIdx += mBins.mMaxBinSize;
                    }
                    //if (tIdx == 0) std::cout << "\r" << std::setw(8) << bIdx << " / " << binEnd << " c" << std::flush;

                }
                if (tIdx == 0)
                {
                    setTimePoint("rr17a.online.send.sendMask");
                    //std::cout << " start->mid  " << std::chrono::duration_cast<std::chrono::milliseconds>(midTime - startTime).count() << std::endl;

                }
                //std::cout << IoStream::unlock;

                otRecv.check(chl, prng.get<block>());
                otSend.check(chl, prng.get<block>());

                // block until all masks are computed. the last to finish will set the promise...
                if (--remainingMasks)
                {
                    maskFuture.get();
                }
                else
                {
                    maskProm.set_value();
                }

                //if (tIdx == 0)
                {


                    for (u64 i = tIdx; i < numChunks; i += chls.size())
                    {
                        auto curSize = std::min(masksPer, numMasks - i * masksPer) * maskSize;
                        auto chunk = span<u8>(sendMaskBuff->data() + i * masksPer * maskSize, curSize);
                        chl.asyncSend(std::move(chunk), [=]()
                        {
                            // no op, just make sure it lives this long.
                            //sendMaskBuff.get();
                            if (--*sendMaskBuffFreeCounter == 0)
                            {
                                delete sendMaskBuff;
                                delete sendMaskBuffFreeCounter;
                            }
                        });
                    }

                }

                if (tIdx == 0) setTimePoint("rr17a.online.send.finalMask");

            });
        }

        for (auto& thrd : thrds)
            thrd.join();

        permThrd.join();

    }

}


#endif