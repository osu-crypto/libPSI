#include "OtBinMPsiReceiver.h"
#include <future>

#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"

#include "MPSI/Beta/SimpleHasher.h"
#include "Common/Log.h"
#include "OT/Base/naor-pinkas.h"
#include <unordered_map>

#include "OT/TwoChooseOne/KosOtExtReceiver.h"
#include "OT/TwoChooseOne/KosOtExtSender.h"
namespace osuCrypto
{
    OtBinMPsiReceiver::OtBinMPsiReceiver()
    {
    }


    OtBinMPsiReceiver::~OtBinMPsiReceiver()
    {
    }

    void OtBinMPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        u64 inputBitSize,
        Channel & chl0,
        NcoOtExtReceiver& ots,
        NcoOtExtSender& otSend,
        block seed)
    {
        init(n, statSecParam, inputBitSize, { &chl0 }, ots, otSend, seed);
    }

    void OtBinMPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        u64 inputBitSize,
        const std::vector<Channel*>& chls,
        NcoOtExtReceiver& otRecv,
        NcoOtExtSender& otSend,
        block seed)
    {

        // this is the offline function for doing binning and then performing the OtPsi* between the bins.


        mStatSecParam = statSecParam;
        mN = n;

        // must be a multiple of 128...
        u64 baseOtCount = 128 * CodeWordSize;

        mOtSend = &otSend;
        mOtRecv = &otRecv;


        gTimer.setTimePoint("Init.start");
        mPrng.SetSeed(seed);
        auto& prng = mPrng;

        auto myHashSeed = prng.get<block>();

        auto& chl0 = *chls[0];

        // we need a random hash function, so we will both commit to a seed and then later decommit. 
        //This is the commitments phase
        Commit comm(myHashSeed), theirComm;
        chl0.asyncSend(comm.data(), comm.size());
        chl0.recv(theirComm.data(), theirComm.size());

        // ok, now decommit to the seed.
        chl0.asyncSend(&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl0.recv(&theirHashingSeed, sizeof(block));

        gTimer.setTimePoint("Init.hashSeed");

        // compute the hashing seed as the xor of both of ours seeds.
        mHashingSeed = myHashSeed ^ theirHashingSeed;
        //Log::out << "recv's hash seed " << mHashingSeed << Log::endl;


        // this SimpleHasher class knows how to hash things into bins. But first we need 
        // to compute how many bins we need, the max size of bins, etc.
        mBins.init(n, inputBitSize, mHashingSeed, statSecParam);

        // makes base OTPsi's for each bins
        //mPsis.resize(mBins.mBinCount);


        //Log::out << "n=" << n << "  m=" << mBins.mBinCount << "    binSize="<< mBins.mMaxBinSize << "   sigma=" << inputBitSize << "   repSize=" << mBins.mRepSize << Log::endl;

        // figure out how many OTs we need in total.
        u64 perBinOtCount = mBins.mMaxBinSize;// mPsis[0].PsiOTCount(mBins.mMaxBinSize, mBins.mRepSize);
        u64 otCount = perBinOtCount * mBins.mBinCount;

        // this will hold the receive messages.
        //std::vector<block> recvMessages(otCount);mRecvOtMessages

        // since we are doing mmlicious PSI, we need OTs going in both directions. 
        // This will hold the send OTs
        mRecvOtMessages.resize(otCount* CodeWordSize);
        mSendOtMessages.resize(otCount* CodeWordSize);


        // compute the base if needed


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
            ArrayView<std::array<block, 2>> kcoRecvBase(
                sendBaseMsg.begin(),
                sendBaseMsg.begin() + baseOtCount);
            ArrayView<std::array<block, 2>> kosRecvBase(
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
        

        gTimer.setTimePoint("Init.ExtStart");

        // this is a lambda function that does part of the OT extension where i am the sender. Again
        // malicious PSI does OTs in both directions.
        auto sendOtRountine = [&](u64 i, u64 total, NcoOtExtSender& ots, block seed, Channel& chl)
        {
            // round up to the next 128 to make sure we aren't wasting OTs in the extension...
            u64 start = std::min(roundUpTo(i *     otCount / total, 128), otCount);
            u64 end = std::min(roundUpTo((i + 1) * otCount / total, 128), otCount);

            // get the range of rows starting at start and ending at end
            MatrixView<block> range(
                mSendOtMessages.begin() + (start * CodeWordSize),
                mSendOtMessages.begin() + (end *CodeWordSize),
                CodeWordSize);

            ots.init(range);
        };

        // this is a lambda function that does part of the OT extension where i am the receiver.
        auto recvOtRountine = [&](u64 i, u64 total, NcoOtExtReceiver& ots, block seed, Channel& chl)
        {
            u64 start = std::min(roundUpTo(i *     otCount / total, 128), otCount);
            u64 end = std::min(roundUpTo((i + 1) * otCount / total, 128), otCount);

            // get the range of rows starting at start and ending at end
            MatrixView<std::array<block, 2>> range(
                mRecvOtMessages.begin() + (start * CodeWordSize),
                mRecvOtMessages.begin() + (end *CodeWordSize),
                CodeWordSize);


            PRNG prng(seed);
            ots.init(range);
        };

        // compute how amny threads we want to do for each direction.
        // the current thread will do one of the OT receives so -1 for that.
        u64 numThreads = chls.size() - 1;
        u64 numRecvThreads = numThreads / 2;
        u64 numSendThreads = numThreads - numRecvThreads;

        // create locals for doing the extension in parallel.
        std::vector<std::unique_ptr<NcoOtExtReceiver>> recvOts(numRecvThreads);
        std::vector<std::unique_ptr<NcoOtExtSender>> sendOts(numSendThreads);

        // where we will store the threads that are doing the extension
        std::vector<std::thread> thrds(numThreads);

        // some iters to help giving out resources.
        auto thrdIter = thrds.begin();
        auto chlIter = chls.begin() + 1;

        // now make the threads that will to the extension
        for (u64 i = 0; i < numRecvThreads; ++i)
        {
            // each need a seed.
            auto seed = prng.get<block>();

            // the split function allows us to create a new extension that has
            // more or less the same base. This allows us to do only 128 base OTs
            recvOts[i] = std::move(otRecv.split());

            // spawn the thread and call the routine.
            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                //Log::out<< Log::lock << "r recvOt " <<i << "  "<< (**chlIter).getName() << Log::endl << Log::unlock;
                recvOtRountine(i + 1, numRecvThreads + 1, *recvOts[i].get(), seed, **chlIter);
            });

            ++chlIter;
        }

        // do the same thing but for the send OT extensions
        for (u64 i = 0; i < numSendThreads; ++i)
        {
            auto seed = prng.get<block>();
            sendOts[i] = std::move(otSend.split());

            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                //Log::out << Log::lock << "r sendOt " << i << "  " << (**chlIter).getName() << Log::endl << Log::unlock;
                sendOtRountine(i, numSendThreads, *sendOts[i].get(), seed, **chlIter);
            });

            ++chlIter;
        }

        // now use this thread to do a recv routine.
        seed = prng.get<block>();
        recvOtRountine(0, numRecvThreads + 1, otRecv, seed, chl0);

        // if the caller doesnt want to do things in parallel
        // the we will need to do the send OT Ext now...
        if (numSendThreads == 0)
        {
            seed = prng.get<block>();
            sendOtRountine(0, 1, otSend, seed, chl0);
        }

        // join any threads that we created.
        for (auto& thrd : thrds)
            thrd.join();

        gTimer.setTimePoint("Init.extFinished");

    }


    void OtBinMPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        sendInput(inputs, { &chl });
    }
    void OtBinMPsiReceiver::sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls)
    {
        // this is the online phase.

        // check that the number of inputs is as expected.
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);

        std::vector<block> recvMasks(mN);

        //gTimer.setTimePoint("sendInput.start");

        TODO("actually compute the required mask size!!!!!!!!!!!!!!!!!!!!!!");
        u64 maskSize = 16;

        if (maskSize > sizeof(block))
            throw std::runtime_error("masked are stored in blocks, so they can exceed that size");


        std::vector<std::thread>  thrds(chls.size());
        //std::vector<std::thread>  thrds(1);

        // since we are going to do this in parallel, these objects will
        // be used for synchronization. specifically, when all threads are 
        // done inserting items into the bins, the future will be fulfilled 
        // and all threads will advance to performing the base OtPsi's
        std::atomic<u32>
            insertRemaining((u32)thrds.size());

        std::promise<void> insertProm, maskMergeProm;
        std::shared_future<void>
            insertFuture(insertProm.get_future()),
            maskMergeFuture(maskMergeProm.get_future());

        std::promise<MatrixView<u8>> maskProm;
        std::shared_future<MatrixView<u8>> maskFuture(maskProm.get_future());
        ByteStream maskBuffer;


        typedef std::unordered_map<u64, std::pair<block, u64>> MaskMap;
        MaskMap sharedMasks;

        std::vector<std::promise<MaskMap*>> localMaskMapsProms(chls.size() - 1);
        std::vector<std::future<MaskMap*>> localMaskMapsFutures(chls.size() - 1);
        for (u64 i = 0; i < localMaskMapsProms.size(); ++i)
            localMaskMapsFutures[i] = localMaskMapsProms[i].get_future();


        // this mutex is used to guard inserting things into the intersection vector.
        std::mutex mInsertMtx;

        std::array<std::vector<block>, CodeWordSize> codewordBuff;

        for (u64 hashIdx = 0; hashIdx < CodeWordSize; ++hashIdx)
            codewordBuff[hashIdx].resize(inputs.size());


        // fr each thread, spawn it.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]()
            {
                auto& chl = *chls[tIdx];

                auto startIdx = tIdx       * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();

                // compute the region of inputs this thread should insert.
                //ArrayView<block> itemRange(
                //    inputs.begin() + startIdx,
                //    inputs.begin() + endIdx);

                std::array<AES, CodeWordSize> codewordHasher;
                for (u64 i = 0; i < codewordHasher.size(); ++i)
                    codewordHasher[i].setKey(_mm_set1_epi64x(i) ^ mHashingSeed);


                for (u64 i = startIdx; i < endIdx; i += hasherStepSize)
                {
                    auto currentStepSize = std::min(hasherStepSize, inputs.size() - i);

                    for (u64 hashIdx = 0; hashIdx < CodeWordSize; ++hashIdx)
                    {
                        codewordHasher[hashIdx].ecbEncBlocks(
                            inputs.data() + i,
                            currentStepSize,
                            codewordBuff[hashIdx].data() + i);
                    }

                    // since we are using random codes, lets just use the first part of the code 
                    // as where each item should be hashed.
                    for (u64 j = 0; j < currentStepSize; ++j)
                    {
                        block& item = codewordBuff[0][i + j];
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        std::lock_guard<std::mutex> lock(mBins.mMtx[addr]);
                        mBins.mBins[addr].emplace_back(i + j);
                    }
                }

                // block until all items have been inserted. the last to finish will set the promise...
                if (--insertRemaining)
                    insertFuture.get();
                else
                    insertProm.set_value();

                // get the region of the base OTs that this thread should do.
                auto binStart = tIdx       * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();
                auto otStart = binStart * mBins.mMaxBinSize;
                auto otEnd = binEnd * mBins.mMaxBinSize;

                PRNG prng(seed);

                u8 hashBuff[SHA1::HashSize];
                //if (!tIdx)
                    //gTimer.setTimePoint("sendInput.PSI");

                std::vector<u16> permutation(mBins.mMaxBinSize);
                for (size_t i = 0; i < permutation.size(); i++)
                    permutation[i] = i;


                const u64 stepSize = 16;

                MaskMap* localMasks = nullptr;
                if (tIdx)
                    localMasks = new MaskMap();
                else
                    localMasks = &sharedMasks;

                MatrixView<std::array<block, 2>> correlatedRecvOts(
                    mRecvOtMessages.begin() + (otStart * CodeWordSize),
                    mRecvOtMessages.begin() + (otEnd * CodeWordSize),
                    CodeWordSize);

                MatrixView<block> correlatedSendOts(
                    mSendOtMessages.begin() + (otStart * CodeWordSize),
                    mSendOtMessages.begin() + (otEnd * CodeWordSize),
                    CodeWordSize);


                u64 otIdx = 0;

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    // make a buffer for the pseudo-code we need to send
                    std::unique_ptr<ByteStream> buff(new ByteStream());
                    buff->resize(sizeof(block) * CodeWordSize * currentStepSize * mBins.mMaxBinSize);

                    auto otCorrectionView = buff->getMatrixView<block>(CodeWordSize);
                    auto otCorrectionIdx = 0;

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        MultiBlock<CodeWordSize> codeword;

                        auto& bin = mBins.mBins[bIdx];
                        std::random_shuffle(permutation.begin(), permutation.end(), prng);

                        for(u64 i =0; i < permutation.size(); ++i)
                        {

                            if (permutation[i] < bin.size())
                            {
                                u64 inputIdx = bin[permutation[i]];
                                //codeword

                                for (u64 j = 0; j < CodeWordSize; ++j)
                                {
                                    codeword[j] = codewordBuff[j][inputIdx];
                                }

                                auto otMsg = correlatedRecvOts[otIdx];
                                auto correction = otCorrectionView[otCorrectionIdx];


                                mOtRecv->encode(
                                    otMsg,                  // input
                                    codeword,               // input
                                    correction,             // output
                                    recvMasks[inputIdx]);   // output

                                
                            }
                            else
                            {
                                // fill with random correction value.
                                prng.get((u8*)otCorrectionView[otCorrectionIdx].data(),
                                    CodeWordSize * sizeof(block));
                                
 
                            }

                            otCorrectionIdx++;
                            otIdx++;
                        }
                    }

                    chl.asyncSend(std::move(buff));
                }


                Buff buff;
                otIdx = 0;

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {

                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    chl.recv(buff);
                    if (buff.size() != CodeWordSize * sizeof(block) * mBins.mMaxBinSize * currentStepSize)
                        throw std::runtime_error("not expected size");

                    auto otCorrectionBuff = buff.getMatrixView<block>(CodeWordSize);
                    u64 otCorrectionIdx = 0;



                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto& bin = mBins.mBins[bIdx];
                        MultiBlock<CodeWordSize> codeword;

                        for (u64 i = 0; i < bin.size(); ++i)
                        {

                            u64 inputIdx = bin[i];

                            u64 innerOtIdx = otIdx;
                            u64 innerOtCorrectionIdx = otCorrectionIdx;

                            for (u64 i = 0; i < mBins.mMaxBinSize; ++i)
                            {
                                for (u64 j = 0; j < CodeWordSize; ++j)
                                {
                                    codeword[j] = codewordBuff[j][inputIdx];
                                }

                                block sendMask;

                                auto otMsg = correlatedSendOts[innerOtIdx];
                                auto correction = otCorrectionBuff[innerOtCorrectionIdx];

                                mOtSend->encode(
                                    otMsg,
                                    codeword,
                                    correction,
                                    sendMask);

                                sendMask = sendMask ^ recvMasks[inputIdx];


                                u64 part = 0;

                                memcpy(&part, &sendMask, std::min(sizeof(u64), maskSize));

                                TODO("encode this mask with our sender OTs");

                                //store my mask into corresponding buff at the permuted position
                                localMasks->emplace(part, std::pair<block, u64>(sendMask, inputIdx));

                                ++innerOtIdx;
                                ++innerOtCorrectionIdx;
                            }
                        }

                        otIdx += mBins.mMaxBinSize;
                        otCorrectionIdx += mBins.mMaxBinSize;
                    }

                }

                if (tIdx)
                {
                    localMaskMapsProms[tIdx - 1].set_value(localMasks);

                    maskMergeFuture.get();
                }
                else
                {

                    for (u64 i = 0; i < localMaskMapsFutures.size(); ++i)
                    {
                        MaskMap* otherMasks = localMaskMapsFutures[i].get();

                        sharedMasks.insert(otherMasks->begin(), otherMasks->end());

                        delete otherMasks;
                    }


                    maskMergeProm.set_value();
                }
                
                // all masks have been merged


                // this is the intersection that will be computed by this thread,
                // this will be merged into the overall list at the end.
                std::vector<u64> localIntersection;
                localIntersection.reserve(mBins.mMaxBinSize);

                MatrixView<u8> maskView;
                if (tIdx == 0)
                {

                    u64 numMasks = mN * mBins.mMaxBinSize;

                    // make a buffer for the pseudo-code we need to send
                    chl.recv(maskBuffer);
                    maskView = maskBuffer.getMatrixView<u8>(maskSize);

                    if (maskView.size()[0] != numMasks)
                        throw std::runtime_error("size not expedted");

                    maskProm.set_value(maskView);
                }
                else
                {
                    maskView = maskFuture.get();
                }

                auto maskStart = tIdx     * maskView.size()[0] / thrds.size();
                auto maskEnd = (tIdx + 1) * maskView.size()[0] / thrds.size();

                for (u64 i = maskStart; i < maskEnd; ++i)
                {
                    auto mask = maskView[i];


                    u64 part = 0;
                    memcpy(&part, mask.data(), std::min(sizeof(u64), mask.size()));

                    auto match = sharedMasks.find(part);

                    if (match != sharedMasks.end() && memcmp(mask.data(), (u8*)&match->second.first, maskSize) == 0)
                    {
                        localIntersection.push_back(match->second.second);
                    }
                }



                if (localIntersection.size())
                {
                    std::lock_guard<std::mutex> lock(mInsertMtx);

                    for (auto idx : localIntersection)
                    {
                        mIntersection.push_back(idx);
                    }
                }
                //if (!tIdx)
                //    gTimer.setTimePoint("sendInput.done");
            });
        }

        // join the threads.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
            thrds[tIdx].join();

        //gTimer.setTimePoint("sendInput.exit");

        //Log::out << gTimer;
    }
}