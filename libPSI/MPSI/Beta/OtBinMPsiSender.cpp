#include "OtBinMPsiSender.h"

#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/naor-pinkas.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "OtBinMPsiDefines.h"
namespace osuCrypto
{

    OtBinMPsiSender::OtBinMPsiSender()
    {
    }
    //const u64 OtBinMPsiSender::hasherStepSize(128);


    OtBinMPsiSender::~OtBinMPsiSender()
    {
    }

    void OtBinMPsiSender::init(u64 n, u64 statSec, u64 inputBitSize,
        Channel & chl0,
        NcoOtExtSender&  ots,
        NcoOtExtReceiver& otRecv,
        block seed)
    {
        init(n, statSec, inputBitSize, { &chl0 }, ots, otRecv, seed);
    }

    void OtBinMPsiSender::init(u64 n, u64 statSec, u64 inputBitSize,
        const std::vector<Channel*>& chls,
        NcoOtExtSender& otSend,
        NcoOtExtReceiver& otRecv,
        block seed)
    {
        mStatSecParam = statSec;
        mN = n;
        gTimer.setTimePoint("init.send.start");

        // must be a multiple of 128...
        u64 baseOtCount;// = 128 * CodeWordSize;
        //u64 plaintextBlkSize;

        u64 compSecParam = 128;

        otSend.getParams(
            true, // input, is malicious
            compSecParam, statSec, inputBitSize, mN, //  input
            mNcoInputBlkSize, baseOtCount); // output

        mOtMsgBlkSize = (baseOtCount + 127) / 128;


        mPrng.SetSeed(seed);
        auto myHashSeed = mPrng.get<block>();
        auto& chl0 = *chls[0];


        Commit comm(myHashSeed), theirComm;
        chl0.asyncSend(comm.data(), comm.size());
        chl0.recv(theirComm.data(), theirComm.size());


        chl0.asyncSend(&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl0.recv(&theirHashingSeed, sizeof(block));

        mHashingSeed = myHashSeed ^ theirHashingSeed;

        gTimer.setTimePoint("init.send.hashSeed");


        mBins.init(n, inputBitSize, mHashingSeed, statSec);

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
            ArrayView<block> kcoSendBase(
                recvBaseMsg.begin(),
                recvBaseMsg.begin() + baseOtCount);
           
            otSend.setBaseOts(kcoSendBase, kcoSendBaseChoice);


            // now lets extend these recv OTs in the other direction
            BitVector kosSendBaseChoice;
            kosSendBaseChoice.copy(recvChoice, baseOtCount, gOtExtBaseOtCount);
            ArrayView<block> kosSendBase(
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

        mOtSends.resize(chls.size());
        mOtRecvs.resize(chls.size());


        auto sendOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtSender& ots, Channel& chl)
        {
            auto start = (  tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto end =   ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;

            ots.init(end - start);
        };

        auto recvOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtReceiver& ots, Channel& chl)
        {
            auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;

            ots.init(end - start);
        };

        u64 numThreads = chls.size() - 1;


        std::vector<std::thread> thrds(numThreads);
        auto thrdIter = thrds.begin();
        auto chlIter = chls.begin() + 1;


        for (u64 i = 0; i < numThreads; ++i)
        {
            mOtSends[i] = std::move(otSend.split());
            mOtRecvs[i] = std::move(otRecv.split());

            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                sendOtRoutine(i, chls.size(), *mOtSends[i], **chlIter);
                recvOtRoutine(i, chls.size(), *mOtRecvs[i], **chlIter);
            });
            ++chlIter;
        }

        mOtSends.back() = std::move(otSend.split());
        mOtRecvs.back() = std::move(otRecv.split());

        sendOtRoutine(chls.size() - 1, chls.size(), *mOtSends.back(), chl0);
        recvOtRoutine(chls.size() - 1, chls.size(), *mOtRecvs.back(), chl0);


        for (auto& thrd : thrds)
            thrd.join();

        gTimer.setTimePoint("init.send.done");

    }


    void OtBinMPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        sendInput(inputs, { &chl });
    }

    void OtBinMPsiSender::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls)
    {
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);



        u64 maskSize = roundUpTo(mStatSecParam + 2 * std::log(mN * mBins.mMaxBinSize) - 1, 8) / 8;

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

        std::vector<std::vector<block>> ncoInputBuff(mNcoInputBlkSize);
        std::vector<block> recvMasks(mN);

        for (u64 hashIdx = 0; hashIdx < ncoInputBuff.size(); ++hashIdx)
            ncoInputBuff[hashIdx].resize(inputs.size());


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

        std::atomic<u64> maskIdx(0);
        uPtr<Buff> sendMaskBuff(new Buff);
        sendMaskBuff->resize(maskPerm.size() * mBins.mMaxBinSize * maskSize);
        auto maskView = sendMaskBuff->getMatrixView<u8>(maskSize);
        
        gTimer.setTimePoint("online.send.spaw");

        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]() {

                PRNG prng(seed);

                if (tIdx == 0) gTimer.setTimePoint("online.send.thrdStart");

                auto& otRecv = *mOtRecvs[tIdx];
                auto& otSend = *mOtSends[tIdx];

                auto& chl = *chls[tIdx];
                auto startIdx = tIdx       * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();

                // compute the region of inputs this thread should insert.
                //ArrayView<block> itemRange(
                //    inputs.begin() + startIdx,
                //    inputs.begin() + endIdx);

                std::vector<AES> ncoInputHasher(mNcoInputBlkSize);
                for (u64 i = 0; i < ncoInputHasher.size(); ++i)
                    ncoInputHasher[i].setKey(_mm_set1_epi64x(i) ^ mHashingSeed);

                u64 phaseShift = log2ceil(mN) / 8;

                for (u64 i = startIdx; i < endIdx; i += 128)
                {
                    auto currentStepSize = std::min(u64(128), inputs.size() - i);

                    for (u64 hashIdx = 0; hashIdx < ncoInputHasher.size(); ++hashIdx)
                    {
                        ncoInputHasher[hashIdx].ecbEncBlocks(
                            inputs.data() + i,
                            currentStepSize,
                            ncoInputBuff[hashIdx].data() + i);
                    }

                    // since we are using random codes, lets just use the first part of the code 
                    // as where each item should be hashed.
                    for (u64 j = 0; j < currentStepSize; ++j)
                    {
                        block& item = ncoInputBuff[0][i + j];
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        // implements phase. Note that we are doing very course phasing. 
                        // At the byte level. This is good enough for use. Since we just 
                        // need things tp be smaller than 76 bits.
                        if(phaseShift == 3)
                            ncoInputBuff[0][i + j] = _mm_srli_si128(item, 3);
                        else// if (phaseShift <= 2)
                            ncoInputBuff[0][i + j] = _mm_srli_si128(item, 2);

                        std::lock_guard<std::mutex> lock(mBins.mMtx[addr]);
                        mBins.mBins[addr].emplace_back(i + j);
                    }
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

                auto binStart = tIdx       * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

                std::vector<u16> permutation(mBins.mMaxBinSize);
                for (size_t i = 0; i < permutation.size(); i++)
                    permutation[i] = (u16)i;

                u64 otIdx = 0;
                //u64 maskIdx = binStart;

                std::vector<block> ncoInput(mNcoInputBlkSize);

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {

                        auto& bin = mBins.mBins[bIdx];
                        std::random_shuffle(permutation.begin(), permutation.end(), prng);

                        for (u64 i = 0; i < permutation.size(); ++i)
                        {

                            if (permutation[i] < bin.size())
                            {
                                u64 inputIdx = bin[permutation[i]];
                                // ncoInput

                                for (u64 j = 0; j < ncoInput.size(); ++j)
                                {
                                    ncoInput[j] = ncoInputBuff[j][inputIdx];
                                }

                                otRecv.encode(
                                    otIdx,                //  input
                                    ncoInput,             //  input
                                    recvMasks[inputIdx]); // output

                            }
                            else
                            {

                                otRecv.zeroEncode(otIdx);
                            }

                            otIdx++;
                        }
                    }

                    otRecv.sendCorrection(chl, currentStepSize * mBins.mMaxBinSize);
                }



                Buff buff;
                otIdx = 0;

                if (tIdx == 0) gTimer.setTimePoint("online.send.recvMask");
                permDone.get();
                if (tIdx == 0) gTimer.setTimePoint("online.send.permPromDone");

                //std::cout << IoStream::lock;

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {

                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    otSend.recvCorrection(chl, currentStepSize * mBins.mMaxBinSize);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto& bin = mBins.mBins[bIdx];
                        

                        for (u64 i = 0; i < bin.size(); ++i)
                        {

                            u64 inputIdx = bin[i];
                            u64 baseMaskIdx = maskPerm[maskIdx++] * mBins.mMaxBinSize;

                            u64 innerOtIdx = otIdx;

                            for (u64 l = 0; l < mBins.mMaxBinSize; ++l)
                            {

                                for (u64 j = 0; j < mNcoInputBlkSize; ++j)
                                {
                                    ncoInput[j] = ncoInputBuff[j][inputIdx];
                                }

                                block sendMask;

                                otSend.encode(
                                    innerOtIdx,
                                    ncoInput,
                                    sendMask);

                                //if (inputIdx == 2)
                                //{
                                //    std::cout 
                                //        << "s "<<inputIdx<<" " << inputs[inputIdx] << " " << l << ": "
                                //        << (sendMask ^ recvMasks[inputIdx]) << " = "
                                //        << sendMask << " ^ " << recvMasks[inputIdx] << "     " << (baseMaskIdx + l) << std::endl ;
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

                }
                if (tIdx == 0) gTimer.setTimePoint("online.send.sendMask");

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

                if (tIdx == 0)
                    chl.asyncSend(std::move(sendMaskBuff));

                if (tIdx == 0) gTimer.setTimePoint("online.send.finalMask");



            });
        }

        for (auto& thrd : thrds)
            thrd.join();

        permThrd.join();

    }

}


