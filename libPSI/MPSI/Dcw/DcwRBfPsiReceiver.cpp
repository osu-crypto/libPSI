#include "DcwRBfPsiReceiver.h"
#include "Crypto/PRNG.h"
#include "Crypto/Commit.h"
#include "OT/TwoChooseOne/KosOtExtReceiver.h"
#include "Common/Log.h"
#include <unordered_map>
#include "Common/Timer.h"
#include "Crypto/ShamirSSScheme.h"
#include "OT/Base/naor-pinkas.h"
#include <unordered_map>

namespace osuCrypto
{

    DcwRBfPsiReceiver::DcwRBfPsiReceiver()
    {


    }


    DcwRBfPsiReceiver::~DcwRBfPsiReceiver()
    {
    }


    block DcwRBfPsiReceiver::interpolate(block prime, std::vector<block>& msgs, std::vector<u8>& choices)
    {

        //ss.reconstruct()

        std::vector<u32> idxs(msgs.size() / 2);
        std::vector<block> shares(idxs.size());



        //Log::out << Log::lock;
        for (u32 i = 0, j = 0; i < choices.size() && j < idxs.size(); ++i)
        {
            if (choices[i] == 0)
            {
                idxs[j] = i;
                shares[j] = msgs[i] ^ mMessages[i];


                //mEncSeed = msgs[i] ^ mMessages[i]; 
                //Log::out << "enc " << i << "  " << shares[j] <<  " = " << msgs[i] << " ^ " << mMessages[i]  << "  " << (u32)(mRandChoices[i] ^ choices[i]) << "   but really " << mRandChoices[i] << Log::endl;


                ++j;

                //return;
            }
        }


            //Log::out << "interp " << shares.size() << Log::endl;

            ShamirSSScheme ss;
            NTL::GF2XFromBytes(ss.mPrime, (u8*)&prime, sizeof(block));
            //Log::out << "recv Prime  " << ss.mPrime << Log::endl;

            return ss.reconstruct(idxs, shares);

        //Log::out << Log::unlock;

    }

    void DcwRBfPsiReceiver::init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel & chl, block seed)
    {
        std::vector<Channel*> cc{ &chl };

        init(n, statSecParam, otExt, cc, seed);
    }


    void DcwRBfPsiReceiver::init(u64 n, u64 statSecParam, OtExtReceiver& otExt, std::vector<Channel*> & chls, block seed)
    {

        //Timer timer;
        gTimer.setTimePoint("Init.start");
        mMyInputSize = n;
        mTheirInputSize = n;
        mStatSecParam = statSecParam;
        //auto logn = std::log2(n);
        //mNumBins = (n + logn - 1) / logn;
        //mBinSize = logn * std::log2(logn);

        PRNG prng(seed);
        mSeed = prng.get<block>();
        auto myHashSeed = prng.get<block>();


        auto & chl = *chls[0];
        Commit comm(myHashSeed), theirComm;
        chl.asyncSend(comm.data(), comm.size());
        auto theirCommFutre = chl.asyncRecv(theirComm.data(), theirComm.size());


        theirCommFutre.get();
        chl.asyncSend(&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl.recv(&theirHashingSeed, sizeof(block));

        u64 numHashFunctions;
        gTimer.setTimePoint("Init.params");

        numHashFunctions = 128;
        mBfBitCount = numHashFunctions * 2 * n;

        mHashs.resize(numHashFunctions);

        mRandChoices.resize(mBfBitCount);
        mRandChoices.randomize(prng);
        mMessages.resize(mBfBitCount);



        if (otExt.hasBaseOts() == false)
        {
            std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;

            NaorPinkas base;
            base.send(baseMsg, prng, chl, 2);
            otExt.setBaseOts(baseMsg);
        }


        // this is a lambda function that does part of the OT extension where i am the receiver.
        auto recvOtRountine = [this](u64 i, u64 total, OtExtReceiver& ots, block seed, Channel& chl)
        {
            // compute the region of the OTs im going to do
            u64 start = std::min(roundUpTo(i *     mMessages.size() / total, 128), mMessages.size());
            u64 end = std::min(roundUpTo((i + 1) * mMessages.size() / total, 128), mMessages.size());
            //Log::out << Log::lock << "recv Chl " << chl.getName() << " get " << start << " - " << end << Log::endl << Log::unlock;

            if (end - start)
            {

                // copy the bits that this regeion will use. We should find a way to avoid this copy
                BitVector choices;
                choices.copy(mRandChoices, start, end - start);
                //TODO("avoid this copy. need BitView...");

                // compute the region of the OTs im going to do
                ArrayView<block> range(
                    mMessages.begin() + start,
                    mMessages.begin() + end);
                PRNG prng(seed);

                // do the extension
                ots.receive(choices, range, prng, chl);
            }

        };


        // compute how amny threads we want to do for each direction.
        // the current thread will do one of the OT receives so -1 for that.
        u64 numRecvThreads = chls.size() - 1;

        // create locals for doing the extension in parallel.
        std::vector<std::unique_ptr<OtExtReceiver>> recvOts(numRecvThreads);

        // where we will store the threads that are doing the extension
        std::vector<std::thread> thrds(numRecvThreads);

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
            recvOts[i] = std::move(otExt.split());

            // spawn the thread and call the routine.
            *thrdIter++ = std::thread([&, i, chlIter]()
            {
                //Log::out<< Log::lock << "r recvOt " <<i << "  "<< (**chlIter).getName() << Log::endl << Log::unlock;
                recvOtRountine(i + 1, numRecvThreads + 1, *recvOts[i].get(), seed, **chlIter);
            });

            ++chlIter;
        }


        // now use this thread to do a recv routine.
        seed = prng.get<block>();
        recvOtRountine(0, numRecvThreads + 1, otExt, seed, chl);


        mHashingSeed = myHashSeed ^ theirHashingSeed;
        PRNG hashSeedGen(mHashingSeed);

        for (u64 i = 0; i < mHashs.size(); ++i)
        {
            mHashs[i].Update(hashSeedGen.get<block>());
        }


        // join any threads that we created.
        for (auto& thrd : thrds)
            thrd.join();

        gTimer.setTimePoint("Init.done");
        //Log::out << timer;
    }


    void DcwRBfPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel*> cc{ &chl };

        sendInput(inputs, cc);
    }

    void DcwRBfPsiReceiver::sendInput(std::vector<block>& inputs, std::vector<Channel*>& chls)
    {
        if (inputs.size() != mMyInputSize)
            throw std::runtime_error(LOCATION);
        //Timer timer;
        gTimer.setTimePoint("online.start");
        u64 numBits = 32;

        if (chls.size() > 1)
            throw std::runtime_error("not impl");

        //TODO("need real seed");
        PRNG prng(mSeed);

        std::vector<u8> bf(mBfBitCount, 0);

        std::promise<void> hashingsDoneProm, mergeDoneProm, decryptDoneProm;
        std::shared_future<void>
            hashingsDoneFuture(hashingsDoneProm.get_future()),
            mergeDoneFuture(mergeDoneProm.get_future()),
            decryptDoneFuture(decryptDoneProm.get_future());

        std::atomic<u32> hashingsRemaing((u32)chls.size());
        std::atomic<i32> firstDone(-1);

        std::unordered_map<u64, std::pair<block, u64>> masks;
        masks.reserve(inputs.size());

        std::vector<std::promise<std::unordered_map<u64, std::pair<block, u64>>>> masksProms(chls.size() - 1);
        std::vector<std::shared_future<std::unordered_map<u64, std::pair<block, u64>>>> masksFutures;


        for (u64 i = 0; i < chls.size() - 1; ++i)masksFutures.push_back(masksProms[i].get_future());

        std::mutex finalMtx;
        std::vector<block> theirMasks(mTheirInputSize);
        std::vector<block> shares(mBfBitCount);

        std::unordered_map<u64, block> masksMap;
        masks.reserve(mTheirInputSize);

        auto routine = [&](u64 t)
        {
            auto & chl = *chls[t];
            auto start = inputs.size() * t / chls.size();
            auto end = inputs.size() * (t + 1) / chls.size();


            std::vector<u64> idxs((end - start)* mHashs.size());
            auto idxIter = idxs.begin();
            u8 hashOut[SHA1::HashSize];

            for (u64 i = start; i < end; ++i)
            {
                auto& item = inputs[i];

                for (u64 j = 0; j < mHashs.size(); ++j)
                {
                    // copy the hash since its stateful and has the seed in it
                    auto hash = mHashs[j];

                    hash.Update((u8*)&item, sizeof(block));
                    hash.Final(hashOut);

                    *idxIter = *(u64*)hashOut% mBfBitCount;

                    bf[*idxIter++] = 1;

                }

            }

            if (--hashingsRemaing == 0)
                hashingsDoneProm.set_value();
            else
                hashingsDoneFuture.get();

            // all hashing is done now.

            if (t == 0)
            {
                gTimer.setTimePoint("online.BF_computed");

                // if we are the main thread, then convert the bloom filter into a permutation
                //TODO("make perm item size smaller");
                std::unique_ptr<BitVector> otCorrection(new BitVector(mBfBitCount));

                auto& perm = *otCorrection;

                //std::array<u64, 2> permIdxs{ 0,0 };


                u64 i = 0;
                for (; i < mBfBitCount; ++i)
                {
                    perm[i] = bf[i] ^ mRandChoices[i];
                }


                chl.asyncSend(std::move(otCorrection));
                gTimer.setTimePoint("online.Bf_permuite_sent");

                block prime;
                chl.recv(&prime, sizeof(block));
                chl.recv((u8*)shares.data(), shares.size() * sizeof(block));
                auto recvDone = chl.asyncRecv((u8*)theirMasks.data(), theirMasks.size() * sizeof(block));

                gTimer.setTimePoint("online.sharesRecved");

                mEncSeed = interpolate(prime, shares, bf);

                gTimer.setTimePoint("online.sharesInterpolated");




                //Log::out << "recv seed " << mEncSeed << Log::endl;

                const u64 stepSize = 128;
                AES enc(mEncSeed);
                std::vector<block> encBuff(stepSize);

                for (u64 i = 0; i < mMessages.size(); i += stepSize)
                {
                    auto s = std::min(stepSize, mMessages.size() - i);

                    for (u64 j = 0, ii = i; j < s; ++j, ++ii)
                    {
                        encBuff[j] = _mm_set1_epi64x(ii);
                    }

                    enc.ecbEncBlocks(encBuff.data(), encBuff.size(), encBuff.data());

                    for (u64 j = 0, ii = i; j < s; ++j, ++ii)
                    {
                        auto blkEnc = mMessages[ii] ^ encBuff[j];

                        //if (bf[ii])
                        //    Log::out << "recver " << ii << "  " << blkEnc << " <- " << mMessages[ii] << Log::endl;
                        //else
                        //    Log::out << Log::endl;

                        mMessages[ii] = blkEnc;

                    }
                }
                gTimer.setTimePoint("online.masks_decrypted");

                recvDone.get();


                for (u64 i = 0; i < theirMasks.size(); ++i)
                {
                    masksMap.emplace(*(u64*)&theirMasks[i], theirMasks[i]);
                }




                decryptDoneProm.set_value();


            }
            else
            {
                decryptDoneFuture.get();
            }

            // now lets generate the masks. we have the computed indices in the permIdxs vector.
            idxIter = idxs.begin();

            std::vector<u64> localIntersection;


            //Log::out << Log::lock;
            for (u64 i = start; i < end; ++i)
            {
                block mask(ZeroBlock);
                for (u64 j = 0; j < mHashs.size(); ++j)
                {
                    mask = mask ^ mMessages[*idxIter];

                    //Log::out << "recver " << i << " " << j << "   " << gbf << "   " << *idxIter << Log::endl;


                    ++idxIter;
                }
                
                
                //Log::out << "recver " << i << " " << mask << " <-  " << inputs[i] << Log::endl;

                auto match = masksMap.find(*(u64*)&mask);

                if (match != masksMap.end() && eq(match->second, mask))
                    mIntersection.push_back(i);


            }

            if (t > 0)
                throw std::runtime_error("not impl");


            //{
            //    std::lock_guard<std::mutex> lock(finalMtx);
            //    if (mIntersection.capacity() == 0)
            //    {
            //        // if it appears that we are first here, lets estimate the size of the intersection and reserve the memory
            //        mIntersection.reserve(localIntersection.size() * chls.size() * 1.2);
            //    }

            //    mIntersection.insert(mIntersection.end(), localIntersection.begin(), localIntersection.end());
            //}

        };


        // launch the threads to do the routine
        std::vector<std::thread> thrds(chls.size() - 1);

        for (u64 i = 0; i < thrds.size(); ++i)
        {
            //compute the thread idx t
            u64 t = i + 1;

            // go!
            thrds[i] = std::thread([&, t]() {routine(t); });
        }
        routine(0);



        // join any threads we may have spawned.
        for (auto& thrd : thrds)
            thrd.join();

        gTimer.setTimePoint("online.done");

        //Log::out << timer;
    }
}