#include "libPSI/config.h"
#ifdef ENABLE_RR17B_PSI

#include "Rr17bMPsiSender.h"

#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"
#include "libPSI/MPSI/Rr17/Rr17MPsiDefines.h"
#include <atomic>
#include "cryptoTools/Common/ThreadBarrier.h"

namespace osuCrypto
{


    inline block shiftRight(block v, u8 n)
    {
        auto v1 = _mm_srli_epi64(v, n);
        auto v2 = _mm_srli_si128(v, 8);
        v2 = _mm_slli_epi64(v2, 64 - (n));
        return _mm_or_si128(v1, v2);
    }

    Rr17bMPsiSender::Rr17bMPsiSender()
    {
    }
    //const u64 Rr17bMPsiSender::hasherStepSize(128);


    Rr17bMPsiSender::~Rr17bMPsiSender()
    {
    }

    void Rr17bMPsiSender::init(u64 n, u64 statSec,
        Channel & chl0,
        NcoOtExtSender&  ots,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        init(n, statSec, { &chl0, 1 }, ots, seed, binScaler, inputBitSize);
    }

    void Rr17bMPsiSender::init(u64 n, u64 statSecParam,
        span<Channel> chls,
        NcoOtExtSender& otSend,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        mStatSecParam = statSecParam;
        mN = n;
        setTimePoint("rr17b.init.send.start");

        // must be a multiple of 128...
        // = 128 * CodeWordSize;
        //u64 plaintextBlkSize;
        //
        //u64 compSecParam = 128;



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


        otSend.configure(
            true, // input, is malicious
            statSecParam, inputBitSize);
        u64 baseOtCount = otSend.getBaseOTCount();


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

        setTimePoint("rr17b.init.send.hashSeed");


        mBins.init(n, inputBitSize, mHashingSeed, statSecParam, binScaler);
		//std::cout << "binSize " << mBins.mMaxBinSize << " vs " << n << " (" << double(mBins.mMaxBinSize) / n << ")" << std::endl;
        //mPsis.resize(mBins.mBinCount);

        setTimePoint("rr17b.init.send.baseStart");

        if (otSend.hasBaseOts() == false)
        {
#ifdef LIBOTE_HAS_BASE_OT
            // first do 128 public key OTs (expensive)
            std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;
            DefaultBaseOT base;
            base.send(baseMsg, mPrng, chl0, 2);


            // now extend these to enough recv OTs to seed the send Kco and the send Kos ot extension
            BitVector recvChoice(baseOtCount); recvChoice.randomize(mPrng);
            std::vector<block> recvBaseMsg(baseOtCount);
            KosOtExtReceiver kosRecv;
            kosRecv.setBaseOts(baseMsg, mPrng, chl0);
            kosRecv.receive(recvChoice, recvBaseMsg, mPrng, chl0);



            otSend.setBaseOts(recvBaseMsg, recvChoice, chl0);
#else
            throw std::runtime_error("base OTs must be set. " LOCATION);
#endif
        }

        setTimePoint("rr17b.init.send.extStart");

        mOtSends.resize(chls.size());


        auto sendOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtSender& ots, Channel& chl, PRNG& prng)
        {
            //auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            //auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;
            auto binsPerThread = (mBins.mBinCount + total - 1) / total;

            //std::cout << IoStream::unlock << "ss " << tIdx << " " << (end - start) << std::endl<<IoStream::unlock;

            ots.init(binsPerThread * mBins.mMaxBinSize, prng, chl);
        };

        u64 numThreads = chls.size() - 1;
        std::vector<std::thread> thrds(numThreads);
        auto thrdIter = thrds.begin();
        auto chlIter = chls.begin() + 1;

        std::vector<PRNG> prngs(chls.size() - 1);

        for (u64 i = 0; i < numThreads; ++i)
        {
            prngs[i].SetSeed(mPrng.get<block>());

            mOtSends[i] = std::move(otSend.split());

            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                sendOtRoutine(i, chls.size(), *mOtSends[i], *chlIter, prngs[i]);
            });
            ++chlIter;
        }

        mOtSends.back() = std::move(otSend.split());

        sendOtRoutine(chls.size() - 1, chls.size(), *mOtSends.back(), chl0, mPrng);

        for (auto& thrd : thrds)
            thrd.join();

        setTimePoint("rr17b.init.send.done");

    }


    void Rr17bMPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> c{ chl };
        sendInput(inputs, c);
    }

    void Rr17bMPsiSender::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);

        // tags help the receiver identify protential commitments that should be
        // trial decommitted. Small tags will result in excress work by the receiver
        // while large tags results in more communication (but less computation).
        //static const u64 tagSize = 4;// std::log(mN * mBins.mMaxBinSize);

        // we will use these threads to perform the work.
        std::vector<std::thread>  thrds(chls.size());

        // some barriers that will be used to ensure all threads have
        // made it to some point before proceedding.
        ThreadBarrier
            itemsInsertedBarrier(thrds.size()),
            encodingsComputedBarrier(thrds.size());


        // This buffer will hold { H( inputs[0] ), ..., H( inputs[mN - 1] ) } and will be used as the location
        // which an item is inserted at in the hash table. Additionaly, if we perform the hash to smaller domain
        // operation, then this will also be the input value to the OT-encoding functionality.
        std::vector<block> hashedInputBuffer(mHashToSmallerDomain ? inputs.size() : 0);

        // Use this view to indicate which of the two buffers should be the OT-OT-encoding input values.
        span<block> otInputs(mHashToSmallerDomain ? hashedInputBuffer : inputs);

        // next we will create a random permutation that the sender will use when
        // sending over their commitments/decommitments. This permutation is over
        // the input order. The std::future permDone will be fulfilled when maskPerm
        // contains a random permutation of [0,1, ..., mN - 1].
        std::vector<u64> itemPermutation(mN);
        auto permSeed = mPrng.get<block>();
        std::promise<void> permProm;
        std::shared_future<void> permDone(permProm.get_future());
        auto permThrd = std::thread([&]() {
            PRNG prng(permSeed);
            for (u64 i = 0; i < itemPermutation.size(); ++i)
                itemPermutation[i] = i;
            std::random_shuffle(itemPermutation.begin(), itemPermutation.end(), prng);
            permProm.set_value();
        });



        //std::atomic<u64> maskIdx(0);

        const auto pairSize = RandomOracle::HashSize;// tagSize + sizeof(block);
        const auto encodingSetSize = pairSize * mBins.mMaxBinSize + sizeof(Commit);
        std::vector<u8>* sendMaskBuff(new std::vector<u8>(mN * encodingSetSize));

        //u64 itemsPerChunk = std::min<u64>(1 << 14, (mN + chls.size() - 1) / chls.size());
        //u64 numChunks = (mN + itemsPerChunk - 1) / itemsPerChunk;
        //auto remainingChunks = new std::atomic<u32>(numChunks);
        auto outstandingSendCount = new std::atomic<u32>(0);

        // This denotes the number of bins that each thread gets. The last thread may get fewer.
        auto binsPerThread = (mBins.mBinCount + thrds.size() - 1) / thrds.size();


        setTimePoint("rr17b.online.send.spaw");

        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]() {

                // timing information
                if (tIdx == 0) setTimePoint("rr17b.online.send.thrdStart");

                // local randomness generator
                PRNG prng(seed);

                // rename these guys for convienience
                auto& otSend = *mOtSends[tIdx];
                auto& chl = chls[tIdx];

                // we will phase off this many bits.
                u8 phaseShift = u8(log2ceil(mN));

                // the start/end index of the item that we shoudl insert into the hash table
                auto startIdx = tIdx       * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();

                // These idxs denote the start and end index for the bins that this thread will process.
                auto binStart = tIdx     * binsPerThread;
                auto binEnd = std::min((tIdx + 1) * binsPerThread, mBins.mBinCount);

                //auto myItemCountByThread = itemCountByThread[tIdx];

                // iterate over the input within this thread's range and perform hashing and phasing
                // We process the input in steps of 128 items to gain efficientcy
                if (mHashToSmallerDomain)
                {
                    for (u64 i = startIdx; i < endIdx; ++i)
                    {
                        // hash to smaller domain using the RO
                        RandomOracle sha(sizeof(block));
                        sha.Update(mHashingSeed);
                        sha.Update(inputs[i]);
                        sha.Final(hashedInputBuffer[i]);

                        block& item = hashedInputBuffer[i];

                        // compute the bin index as the low bits mod #bins
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        // phase the item by removing log( #bin ) low bits. High bits just get ignored.
                        item = shiftRight(item, phaseShift);

                        // insert this item into its bin.
                        mBins.push(addr, i);
                    }
                }
                else
                {
                    // We key the AES with the hashingSeed. We then hash items to bins as AES(item) % #bins.
                    // This should be near uniform.
                    AES inputHasher(mHashingSeed);

                    for (u64 i = startIdx; i < endIdx; ++i)
                    {
                        // In the case where we do not hash to smaller domain, we dont need to use the OR
                        // Instead, we will use a random key AES.
                        block item = inputHasher.ecbEncBlock(inputs[i]);

                        // compute the bin index as the low bits mod #bins
                        u64 addr = *(u64*)&item % mBins.mBinCount;

                        // phase the item by removing log( #bin ) low bits. High bits just get ignored.
                        item = shiftRight(item, phaseShift);

                        // insert this item into its bin.
                        mBins.push(addr, i);
                    }
                }

                // block until all items have been inserted. the last to finish will set the promise...
                itemsInsertedBarrier.decrementWait();


                if (tIdx == 0) setTimePoint("rr17b.online.send.insert");

                // This will index the OT that we should use for the current bin.
                // Each item used mBin.mMaxBinSize OT, where they are reused on items
                // in the same bin.
                u64 otIdx = 0;// binStart * mBins.mMaxBinSize;


                // Block until the permutation over the order of the input items has been computed.
                permDone.get();
                if (tIdx == 0) setTimePoint("rr17b.online.send.permPromDone");

                // OK, now we will compute the common OT-encodings,  mBin.mMaxBinSize of them for each of our items.
                // Will will first commit to our item and then use these common OT-encodings to decommit to our item.
                // If the receiver has the same items, they will be able to verify this decommitment :)
                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    // Instead of doing things bin by bin, we will process "stepSize" worht of bins
                    // at a time. currentStepSize denotes the size of our current step since the last
                    // one mine be a partial step
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    // To compute the common OT-encodings, we need to receive correction values for these OT.
                    // These values tells just how to encode our items, as OT sender...
                    otSend.recvCorrection(chl, currentStepSize * mBins.mMaxBinSize);

                    // We are now ready to encode the next currentStepSize worth of bins.
                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {
                        auto bin = mBins.getBin(bIdx);

                        // For the current bin, loop over the items that are in it.
                        for (u64 i = 0; i < bin.size(); ++i)
                        {
                            // bin[i] denotes the index if them input item that is stored at that location.
                            u64 inputIdx = bin[i];

                            // First we compute the commitment to our value. Each of the common OT-encodings that we
                            // generate for this items will be used to encrypt the decommitment value.
                            RandomOracle sha;

                            // sample a random decommitment value
                            auto itemDecomm = prng.get<block>();

                            //std::cout << "r[" << inputIdx << "] = " << itemDecomm << std::endl;

                            // iter is the local in the shared sendMaskBuff that we should write this
                            // item's data. For each item x, we write as:
                            //
                            //     Comm(x; r),
                            //     [[ x ]]_1  + ( 0000 || r )
                            //     ...
                            //     [[ x ]]_m  + ( 0000 || r )
                            //
                            // Where [[ x ]]_i denotes the i'th OT-encoding. ( 0000 || r ) denote 4 bytes of zero followed by the
                            // the decommitment value r. The leading zeros help the receiver identify x if they already know [[ x ]]_i
                            // which in turn allows them to efficiently check Comm(x; r)
                            auto iter = sendMaskBuff->data() + itemPermutation[inputIdx] * encodingSetSize;

                            // Compute  Comm(x; r)
                            sha.Update(inputs[inputIdx]);
                            sha.Update(itemDecomm);
                            sha.Final(iter);
                            iter += RandomOracle::HashSize;

                            // Compute the i'th
                            for (u64 l = 0, innerOtIdx = otIdx; l < mBins.mMaxBinSize; ++l)
                            {

                                otSend.encode(
                                    innerOtIdx,
                                    &otInputs[inputIdx],
                                    iter,
                                    RandomOracle::HashSize);

                                //std::cout << "inp[" << inputs[inputIdx] << "] " << innerOtIdx << "  " << otInputs[inputIdx] << std::endl;
                                //std::cout << "tag[" << inputs[inputIdx] << "] " << innerOtIdx << "  " << *(u32*)iter << std::endl;
                                iter += 4;

                                //std::cout << "enc[" << inputs[inputIdx] << "] " << innerOtIdx << "  "
                                //    << (*(block*)iter ^ itemDecomm) << " = " << *(block*)iter << " ^ " << itemDecomm << std::endl;

                                //block c;
                                auto enc = toBlock(iter) ^ itemDecomm;
                                auto encPtr = (u8*)(&enc);
                                //*iter = 0;
                                //memcpy(&c, ByteArray(enc), sizeof(block));
                                memcpy(iter, encPtr, sizeof(block));

                                iter += sizeof(block);

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
                    setTimePoint("rr17b.online.send.sendMask");
                    //std::cout << " start->mid  " << std::chrono::duration_cast<std::chrono::milliseconds>(midTime - startTime).count() << std::endl;

                }
                //std::cout << IoStream::unlock;

                otSend.check(chl, prng.get<block>());

                if (tIdx == 0)
                {
                    setTimePoint("rr17b.online.send.check");
                }

                // block until all masks are computed. the last to finish will set the promise...
                encodingsComputedBarrier.decrementWait();


                auto itemsPerThread = (mN + thrds.size() - 1) / thrds.size();
                auto startSendIdx = itemsPerThread * tIdx;
                auto endSendIdx = std::min<u64>(itemsPerThread * (tIdx + 1), mN);
                static const u64 sendSize = 1 << 14;

                for (u64 i = startSendIdx; i < endSendIdx; i += sendSize)
                {
                    auto curSize = std::min(sendSize, endSendIdx - i) * encodingSetSize;

                    ++*outstandingSendCount;
                    auto chunk = span<u8>(sendMaskBuff->data() + i * encodingSetSize, curSize);
                    chl.asyncSend(std::move(chunk), [=]()
                    {
                        // when outstandingSendCount hits zero, all messages have completed and we should
                        // clean up the data.
                        if (--*outstandingSendCount == 0)
                        {
                            delete sendMaskBuff;
                            delete outstandingSendCount;
                        }
                    });
                }


                if (tIdx == 0) setTimePoint("rr17b.online.send.finalMask");

            });
        }

        for (auto& thrd : thrds)
            thrd.join();

        permThrd.join();

    }

}

#endif