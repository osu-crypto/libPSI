
#include "libPSI/config.h"
#ifdef ENABLE_RR17B_PSI
#include "Rr17bMPsiReceiver.h"
#include <future>

#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"

#include "libPSI/Tools/SimpleHasher.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
#include <unordered_map>

#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include "libPSI/MPSI/Rr17/Rr17MPsiDefines.h"
#include "libPSI/Tools/CuckooHasher.h"
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

    Rr17bMPsiReceiver::Rr17bMPsiReceiver()
    {
    }

    Rr17bMPsiReceiver::~Rr17bMPsiReceiver()
    {
    }

    void Rr17bMPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        Channel & chl0,
        NcoOtExtReceiver& ots,
        block seed,
        double binScaler,
        u64 inputBitSize)
    {
        std::vector<Channel> c{ chl0 };
        init(n, statSecParam, c, ots, seed, binScaler, inputBitSize);
    }

    void Rr17bMPsiReceiver::init(
        u64 n,
        u64 statSecParam,
        span<Channel> chls,
        NcoOtExtReceiver& otRecv,
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
            //std::cout << " inputBitSize = 128*" << std::endl;
            inputBitSize = statSecParam + log2ceil(n) - 1;
            mHashToSmallerDomain = true;
        }
        else
        {
            //std::cout << " inputBitSize = " << inputBitSize << std::endl;
            inputBitSize -= log2ceil(n);
            mHashToSmallerDomain = false;
        }



        otRecv.configure( true, statSecParam, inputBitSize);
        u64 baseOtCount = otRecv.getBaseOTCount();

        //mOtMsgBlkSize = (baseOtCount + 127) / 128;


        setTimePoint("rr17b.Init.recv.start");
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

        setTimePoint("rr17b.Init.recv.hashSeed");

        // compute the hashing seed as the xor of both of ours seeds.
        mHashingSeed = myHashSeed ^ theirHashingSeed;


        // this SimpleHasher class knows how to hash things into bins. But first we need
        // to compute how many bins we need, the max size of bins, etc.
        mBins.init(n, inputBitSize, mHashingSeed, statSecParam, binScaler);

        setTimePoint("rr17b.Init.recv.baseStart");
        // since we are doing mmlicious PSI, we need OTs going in both directions.
        // This will hold the send OTs

        if (otRecv.hasBaseOts() == false)
        {
#ifdef LIBOTE_HAS_BASE_OT

            // first do 128 public key OTs (expensive)
            std::array<block, gOtExtBaseOtCount> kosSendBase;
            BitVector choices(gOtExtBaseOtCount); choices.randomize(prng);
            DefaultBaseOT base;
            base.receive(choices, kosSendBase, prng, chl0, 2);


            KosOtExtSender kosSend;
            kosSend.setBaseOts(kosSendBase, choices, chl0);
            std::vector<std::array<block, 2>> sendBaseMsg(baseOtCount);
            kosSend.send(sendBaseMsg, prng, chl0);


            // now set these ~800 OTs as the base of our N choose 1 OTs.
            otRecv.setBaseOts(sendBaseMsg, prng, chl0);
      
#else
            throw std::runtime_error("base OTs must be set. " LOCATION);
#endif
        }


        setTimePoint("rr17b.Init.recv.ExtStart");



        auto recvOtRoutine = [&](u64 tIdx, u64 total, NcoOtExtReceiver& ots, Channel& chl, PRNG& prng)
        {
            //auto start = (tIdx     * mBins.mBinCount / total) * mBins.mMaxBinSize;
            //auto end = ((tIdx + 1) * mBins.mBinCount / total) * mBins.mMaxBinSize;
            //std::cout << IoStream::unlock << "rr " << tIdx << " " << (end - start) << std::endl << IoStream::unlock;
            auto binsPerThread = (mBins.mBinCount + total - 1) / total;

            ots.init(binsPerThread * mBins.mMaxBinSize, prng, chl);
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
        std::vector<PRNG> prngs(chls.size() - 1);

        // now make the threads that will to the extension
        for (u64 i = 0; i < numThreads; ++i)
        {
            prngs[i].SetSeed(prng.get<block>());

            mOtRecvs[i] = std::move(otRecv.split());

            // spawn the thread and call the routine.
            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                recvOtRoutine(i, chls.size(), *mOtRecvs[i], *chlIter, prngs[i]);
            });

            ++chlIter;
        }


        // now use this thread to do a recv routine.
        mOtRecvs.back() = std::move(otRecv.split());
        recvOtRoutine(chls.size() - 1, chls.size(), *mOtRecvs.back(), chl0, prng);

        // join any threads that we created.
        for (auto& thrd : thrds)
            thrd.join();

        setTimePoint("rr17b.Init.recv.done");

    }


    void Rr17bMPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> c{ chl };
        sendInput(inputs, c);
    }

    void Rr17bMPsiReceiver::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        // this is the online phase.
        setTimePoint("rr17b.online.recv.start");

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
        ThreadBarrier
            itemsInsertedBarrier(thrds.size());

        std::vector<block> recvEncodings(mN);



        // This maps tags -> (input position, OT-encoding).
        std::unordered_multimap<u32, std::pair<u64, block>> tagMap(mN);
        std::mutex tagMapMtx;

        // this mutex is used to guard inserting things into the intersection vector.
        std::mutex mInsertMtx;

        // This buffer will hold { H( inputs[0] ), ..., H( inputs[mN - 1] ) } and will be used as the location
        // which an item is inserted at in the hash table. Additionaly, if we perform the hash to smaller domain
        // operation, then this will also be the input value to the OT-encoding functionality.
        std::vector<block> hashedInputBuffer(mHashToSmallerDomain ? inputs.size() : 0);

        // Use this view to indicate which of the two buffers should be the OT-OT-encoding input values.
        span<block> otInputs(mHashToSmallerDomain ? hashedInputBuffer : inputs);




        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
        {
            auto seed = mPrng.get<block>();
            thrds[tIdx] = std::thread([&, tIdx, seed]()
            {

                if (tIdx == 0) setTimePoint("rr17b.online.recv.thrdStart");

                auto& otRecv = *mOtRecvs[tIdx];
                auto& chl = chls[tIdx];

                auto startIdx = tIdx     * mN / thrds.size();
                auto endIdx = (tIdx + 1) * mN / thrds.size();


                u8 phaseShift = u8(log2ceil(mN));




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

                if (tIdx == 0) setTimePoint("rr17b.online.recv.insertDone");

                // get the region of the base OTs that this thread should do.
                auto binStart = tIdx       * mBins.mBinCount / thrds.size();
                auto binEnd = (tIdx + 1) * mBins.mBinCount / thrds.size();

                PRNG prng(seed);


                std::vector<u16> perm(mBins.mMaxBinSize);
                for (size_t i = 0; i < perm.size(); i++)
                    perm[i] = u16(i);


                u64 otIdx = 0;// binStart * mBins.mMaxBinSize;

                for (u64 bIdx = binStart; bIdx < binEnd;)
                {
                    u64 currentStepSize = std::min(stepSize, binEnd - bIdx);

                    for (u64 stepIdx = 0; stepIdx < currentStepSize; ++bIdx, ++stepIdx)
                    {

                        auto bin = mBins.getBin(bIdx);

                        for (u64 i = 0; i < bin.size(); ++i)
                        {
                            u64 inputIdx = bin[i];
                            u16 swapIdx = u16((prng.get<u16>() % (mBins.mMaxBinSize - i)) + i);
                            std::swap(perm[i], perm[swapIdx]);


                            std::array<u8, RandomOracle::HashSize> buff;

                            //block encoding;
                            otRecv.encode(
                                otIdx + perm[i],      // input
                                &otInputs[inputIdx],         // input
                                buff.data(),
                                buff.size());              // output


                            u32 tag = *(u32*)buff.data();
                            block key = toBlock(buff.data() + sizeof(u32));


                            //std::cout << "inp[" << inputs[inputIdx] << "] " << (otIdx + perm[i]) << "  " << otInputs[i] << std::endl;
                            //std::cout << "tag[" << inputs[inputIdx] << "] " << (otIdx + perm[i]) << "  " << tag << std::endl;
                            //std::cout << "val[" << inputs[inputIdx] << "] " << (otIdx + perm[i]) << "  " << key << std::endl;


                            std::lock_guard<std::mutex> lock(tagMapMtx);
                            tagMap.insert(std::make_pair(tag, std::make_pair(inputIdx, key)));
                        }

                        for (u64 i = bin.size(); i < mBins.mMaxBinSize; ++i)
                        {
                            otRecv.zeroEncode(otIdx + perm[i]);
                        }



                        otIdx += mBins.mMaxBinSize;

                    }

                    otRecv.sendCorrection(chl, currentStepSize * mBins.mMaxBinSize);
                }


                if (tIdx == 0) setTimePoint("rr17b.online.recv.recvMask");


                otRecv.check(chl, prng.get<block>());


                if (tIdx == 0) setTimePoint("rr17b.online.recv.checkdone");


                // this is the intersection that will be computed by this thread,
                // this will be merged into the overall list at the end.
                std::vector<u64> localIntersection;
                localIntersection.reserve(mBins.mMaxBinSize);


                const auto encodingSetSize = RandomOracle::HashSize * mBins.mMaxBinSize + sizeof(Commit);
                const auto itemsPerThread = (mN + thrds.size() - 1) / thrds.size();
                const auto startSendIdx = itemsPerThread * tIdx;
                const auto endSendIdx = std::min<u64>(itemsPerThread * (tIdx + 1), mN);
                static const u64 sendSize = 1 << 14;

                std::vector<u8> buff;
                for (u64 i = startSendIdx; i < endSendIdx; i += sendSize)
                {
                    auto curSize = std::min(sendSize, endSendIdx - i);


                    buff.resize(curSize * encodingSetSize);
                    chl.recv(buff.data(), buff.size());
                    auto iter = buff.data();

                    for (u64 j = 0; j < curSize; ++j)
                    {
                        auto& comm = *(std::array<u8, RandomOracle::HashSize>*)iter;
                        iter += RandomOracle::HashSize;

                        //span<std::pair<u32, block>> decomms((std::pair<u32, block>*) iter, mBins.mMaxBinSize);
                        //iter += RandomOracle::HashSize * mBins.mMaxBinSize;


                        //if (iter > buff.data() + buff.size())
                        //    throw std::runtime_error(LOCATION);

                        for (u64 k = 0; k < mBins.mMaxBinSize; ++k)
                        {
                            auto tag = *(u32*)iter; iter += sizeof(u32);
                            auto enc = toBlock(iter); iter += sizeof(block);

                            if (iter > buff.data() + buff.size())
                                throw std::runtime_error(LOCATION);

                            auto tagIter = tagMap.find(tag);

                            //std::cout << "tag check " << tag << "  " << (tagIter != tagMap.end()) << std::endl;

                            while (tagIter != tagMap.end() && tagIter->first == tag)
                            {
                                // we have found a potential match, lets try and decommit with it.
                                auto inputIdx = tagIter->second.first;
                                auto decommitmentKey = tagIter->second.second ^ enc;

                                std::array<u8, RandomOracle::HashSize> hash;

                                RandomOracle sha;
                                sha.Update(inputs[inputIdx]);
                                sha.Update(decommitmentKey);
                                sha.Final(hash.data());

                                if (comm == hash)
                                {
                                    //std::cout << "tag[" << inputs[inputIdx] << "] match " << tag << std::endl;

                                    localIntersection.push_back(inputIdx);


                                    iter += (mBins.mMaxBinSize - k - 1) * RandomOracle::HashSize;

                                    k = mBins.mMaxBinSize;

                                    break;
                                }
                                ++tagIter;
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
                if (tIdx == 0) setTimePoint("rr17b.online.recv.done");


                //if (!tIdx)
                //    setTimePoint("rr17b.sendInput.done");
            });
        }

        // join the threads.
        for (u64 tIdx = 0; tIdx < thrds.size(); ++tIdx)
            thrds[tIdx].join();

        //std::cout << IoStream::lock << "exit" << std::endl << IoStream::unlock;

        setTimePoint("rr17b.online.recv.exit");

        //std::cout << gTimer;
    }
}
#endif