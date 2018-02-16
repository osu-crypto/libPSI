#include "Grr18MPsiSender.h"

#include <cryptoTools/Crypto/Commit.h>
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Matrix.h>
#include <cryptoTools/Common/Timer.h>
#include "libOTe/Base/naor-pinkas.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"
#include "libPSI/MPSI/Rr17/Rr17MPsiDefines.h"
#include <atomic>
#include <random>
#include "libPSI/Tools/RandomShuffle.h"
#include "Grr18Common.h"

namespace osuCrypto
{

    inline block shiftRight(block v, u8 n)
    {
        auto v1 = _mm_srli_epi64(v, n);
        auto v2 = _mm_srli_si128(v, 8);
        v2 = _mm_slli_epi64(v2, 64 - (n));
        return _mm_or_si128(v1, v2);
    }

    Grr18MPsiSender::Grr18MPsiSender()
    {
    }
    //const u64 Grr18MPsiSender::hasherStepSize(128);


    Grr18MPsiSender::~Grr18MPsiSender()
    {
    }

    void Grr18MPsiSender::init(u64 n, u64 statSec,
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

    void Grr18MPsiSender::init(u64 n, u64 statSecParam,
        span<Channel> chls,
        NcoOtExtSender& otSend,
        NcoOtExtReceiver& otRecv,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        mStatSecParam = statSecParam;
        mN = n;
        gTimer.setTimePoint("init.send.start");


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

        gTimer.setTimePoint("init.send.hashSeed");


        mBins.init(n, inputBitSize, mHashingSeed, statSecParam, binScaler);

        //std::cout << "max bin size: " << mBins.mMaxBinSize 
        //    << " (" << double(mBins.mMaxBinSize) / (double(mBins.mN) / mBins.mBins.size()) <<") " << statSecParam << std::endl;
        //mPsis.resize(mBins.mBinCount);

        gTimer.setTimePoint("init.send.baseStart");

        if (otSend.hasBaseOts() == false ||
            otRecv.hasBaseOts() == false)
        {
            // first do 128 public key OTs (expensive)
            std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;
            NaorPinkas base;
            base.send(baseMsg, mPrng, chl0, 2);


            // now extend these to enough recv OTs to seed the send Kco and the send Kos ot extension
            BitVector recvChoice(baseOtCount + gOtExtBaseOtCount); recvChoice.randomize(mPrng);
            std::vector<block> recvBaseMsg(baseOtCount + gOtExtBaseOtCount);
            KosOtExtReceiver kosRecv;
            kosRecv.setBaseOts(baseMsg);
            kosRecv.receive(recvChoice, recvBaseMsg, mPrng, chl0);


            // we now have a bunch of recv OTs, lets seed the NcoOtExtSender
            BitVector kcoSendBaseChoice;
            kcoSendBaseChoice.copy(recvChoice, 0, baseOtCount);
            span<block> kcoSendBase(
                recvBaseMsg.begin(),
                recvBaseMsg.begin() + baseOtCount);

            otSend.setBaseOts(kcoSendBase, kcoSendBaseChoice);


            // now lets extend these recv OTs in the other direction
            BitVector kosSendBaseChoice;
            kosSendBaseChoice.copy(recvChoice, baseOtCount, gOtExtBaseOtCount);
            span<block> kosSendBase(
                recvBaseMsg.begin() + baseOtCount,
                recvBaseMsg.end());
            KosOtExtSender kos;
            kos.setBaseOts(kosSendBase, kosSendBaseChoice);

            // these send OTs will be stored here
            std::vector<std::array<block, 2>> sendBaseMsg(baseOtCount);
            kos.send(sendBaseMsg, mPrng, chl0);

            // now set these ~800 OTs as the base of our N choose 1 OTs NcoOtExtReceiver
            otRecv.setBaseOts(sendBaseMsg);
        }

        gTimer.setTimePoint("init.send.extStart");

        mOneSided = false;
        mOtSends.resize(chls.size());
        mOtRecvs.resize(chls.size());

        for (u64 i = 0; i < chls.size(); ++i)
        {
            mOtSends[i] = std::move(otSend.split());
            mOtRecvs[i] = std::move(otRecv.split());
        }

        gTimer.setTimePoint("init.send.done");

    }


    void Grr18MPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> c{ chl };
        sendInput(inputs, c);
    }

    void Grr18MPsiSender::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);

        u64 maskSize = roundUpTo(u64(mStatSecParam + 2 * std::log(mN * mBins.mMaxBinSize) - 1), 8) / 8;

        if (maskSize > sizeof(block))
            throw std::runtime_error("masked are stored in blocks, so they can exceed that size");


        std::vector<std::thread>  thrds(chls.size());
        //std::vector<std::thread>  thrds(1);

        std::atomic<u32> remaining((u32)thrds.size()), remainingMasks((u32)thrds.size()), remainingNumMaskCounts((u32)thrds.size());
        std::promise<void> doneProm, maskProm, numMaskProm;
        std::shared_future<void>
            doneFuture(doneProm.get_future()),
            maskFuture(maskProm.get_future()),
            numMaskFuture(numMaskProm.get_future());


        std::vector<block> hashToSmallerDomainBuff(mHashToSmallerDomain ? mN : 0);
        span<block> ncoInputBuff(mHashToSmallerDomain ? hashToSmallerDomainBuff : inputs);
        std::vector<block> recvMasks(mN);

        std::atomic<u64> maskIdx(0), totalMaskCount_atomic(0);
        std::vector<u8> theirLoadsMaster(mBins.mBins.size());


        auto expectedBinLoad = mN / mBins.mBinCount + 1.0 / mEps;
        //std::vector<u64> maskPerm(mNumOTsUpperBound * expectedBinLoad);
        //auto permSeed = mPrng.get<block>();
        //std::promise<void> permProm;
        //std::shared_future<void> permDone(permProm.get_future());
        //auto permThrd = std::thread([&]() {
        //    PRNG prng(permSeed);
        //    for (u64 i = 0; i < maskPerm.size(); ++i)
        //        maskPerm[i] = i;

        //    std::random_shuffle(maskPerm.begin(), maskPerm.end(), prng);
        //    permProm.set_value();
        //});

        Matrix<u8> masks;



        gTimer.setTimePoint("online.send.spaw");

        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]() {

                PRNG prng(seed);

                if (tIdx == 0) gTimer.setTimePoint("online.send.thrdStart");

                auto& otRecv = *mOtRecvs[tIdx];
                auto& otSend = *mOtSends[tIdx];

                auto& chl = chls[tIdx];
                auto startIdx = tIdx * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();
                auto binStart = tIdx * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

                span<u8> theirLoads(theirLoadsMaster.begin() + binStart, theirLoadsMaster.begin() + binEnd);
               
                u64 theirTotalLoad;
                auto theirTotalLoadFut = chl.asyncRecv(theirTotalLoad);
                auto theirLoadsFut = chl.asyncRecv(theirLoads);


                AES ncoInputHasher(mHashingSeed);

                u8 phaseShift = u8(log2ceil(mN));

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

                        // implements phase. Note that we are doing very course phasing.
                        // At the byte level. This is good enough for use. Since we just
                        // need things tp be smaller than 76 bits.

                        item = shiftRight(item, phaseShift);



                        std::lock_guard<std::mutex> lock(mBins.mMtx[addr]);
                        mBins.mBins[addr].emplace_back(i + j);
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

                if (tIdx == 0) gTimer.setTimePoint("online.send.insert");


                //const u64 stepSize = 128;

                std::vector<u8> loads(binEnd - binStart);

                auto totalLoad = computeLoads(loads, prng, binStart, mOneSided, mN, mBins, mEps);
                chl.asyncSend(totalLoad);
                chl.asyncSend(loads.data(), loads.size());


                Channel throwIfUsed;
                otRecv.init(totalLoad, prng, throwIfUsed);





                std::vector<u16> permutation(mBins.mMaxBinSize);


                u64 otIdx = 0, numItems = 0;

                //std::vector<block> ncoInput(mNcoInputBlkSize);


                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
                    auto otStart = otIdx;

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {

                        auto& bin = mBins.mBins[bIdx];
                        numItems += bin.size();

                        permutation.resize(loads[bIdx]);
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
                            }
                            else
                            {
                                otRecv.zeroEncode(otIdx);
                            }

                            otIdx++;
                        }
                    }
                    //std::cout << "sender send " << (currentStepSize * mBins.mMaxBinSize) << std::endl;


                    otRecv.sendCorrection(chl, otIdx - otStart);
                }

                theirTotalLoadFut.get();
                otSend.init(theirTotalLoad, prng, throwIfUsed);

                theirLoadsFut.get();

                if (tIdx == 0) gTimer.setTimePoint("online.send.recvMask");


                u64 numLocalMasks = 0;
                for (u64 bIdx = binStart; bIdx < binEnd; ++bIdx)
                    numLocalMasks += mBins.mBins[bIdx].size() * theirLoadsMaster[bIdx];

                totalMaskCount_atomic += numLocalMasks;

                if (--remainingNumMaskCounts)
                    numMaskFuture.get();
                else
                {
                    masks.resize(totalMaskCount_atomic, maskSize);
                    std::cout << "#masks: " << totalMaskCount_atomic << std::endl;
                    numMaskProm.set_value();
                }

                //if (totalMaskCount_atomic > maskPerm.size())
                //    throw std::runtime_error(LOCATION);



                std::vector<u8> buff;
                otIdx = 0;

                //permDone.get();
                if (tIdx == 0) gTimer.setTimePoint("online.send.permPromDone");




                auto maskPermIdx = maskIdx.fetch_add(numLocalMasks, std::memory_order::memory_order_relaxed);
                //auto maskPermEnd = maskPermIdx + numLocalMasks;

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);
                    auto numCorrections = otSend.recvCorrection(chl);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto& bin = mBins.mBins[bIdx];
                        auto binLoad = theirLoads[bIdx - binStart];
                        numCorrections -= binLoad;


                        for (u64 i = 0; i < bin.size(); ++i)
                        {
                            u64 inputIdx = bin[i];
                            u64 innerOtIdx = otIdx;

                            for (u64 l = 0; l < binLoad; ++l)
                            {
                                block sendMask;
                                otSend.encode(
                                    innerOtIdx,
                                    &ncoInputBuff[inputIdx],
                                    &sendMask);

                                sendMask = sendMask ^ recvMasks[inputIdx];

                                //auto offset = maskPerm[maskIdx++];
                                //while (offset >= masks.rows())
                                //    offset = maskPerm[maskIdx++];

                                auto dest = masks.data() + maskPermIdx++ * maskSize;

                                // truncate the block size mask down to "maskSize" bytes
                                // and store it in the maskView matrix at row 
                                memcpy(
                                    dest,
                                    (u8*)&sendMask,
                                    maskSize);

                                ++innerOtIdx;
                            }
                        }

                        otIdx += binLoad;
                    }

                    if (numCorrections) throw std::runtime_error(LOCATION);
                }


                if (tIdx == 0) gTimer.setTimePoint("online.send.sendMask");


                otRecv.check(chl, prng.get<block>());
                otSend.check(chl, prng.get<block>());

                // block until all masks are computed. the last to finish will set the promise...
                if (--remainingMasks)
                    maskFuture.get();
                else
                    maskProm.set_value();


                u64 maxSendSize = 1ull << 18;
                auto curRow = masks.rows() * tIdx / masks.rows();
                auto endRow = masks.rows() * (tIdx + 1) / masks.rows();
                while (curRow != endRow)
                {
                    auto numRows = std::min(maxSendSize, endRow - curRow);
                    chl.asyncSend(masks.data() + curRow * maskSize, numRows * maskSize);
                    curRow += numRows;
                }

                char ccc = 0;
                chl.send(ccc);

                if (tIdx == 0) gTimer.setTimePoint("online.send.finalMask");

            });
        }

        for (auto& thrd : thrds)
            thrd.join();

        //permThrd.join();

    }


}


