#include "DcwRBfPsiReceiver.h"
#ifdef ENABLE_DCW_PSI
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "cryptoTools/Common/Log.h"
#include <unordered_map>
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
//#include <unordered_map>
#include <sparsehash/dense_hash_map>
#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"

namespace osuCrypto
{

    void DcwRBfPsiReceiver::init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel& chl, block seed)
    {
        std::vector<Channel> cc{ chl };

        init(n, statSecParam, otExt, cc, seed);
    }


    void DcwRBfPsiReceiver::init(u64 n, u64 statSecParam, OtExtReceiver& otExt, span<Channel> chls, block seed)
    {
        gTimer.setTimePoint("Init.start");
        mMyInputSize = n;
        mTheirInputSize = n;

        PRNG prng(seed);
        mSeed = prng.get<block>();
        auto myHashSeed = prng.get<block>();

        auto& chl = chls[0];

        chl.asyncSendCopy(myHashSeed);
        block theirHashingSeed;
        chl.recv(theirHashingSeed);
        mHashingSeed = myHashSeed ^ theirHashingSeed;

        gTimer.setTimePoint("Init.params");

        mNumHashFunctions = 128;
        mBfBitCount = mNumHashFunctions * 1.5 * n;

        mRandChoices.resize(mBfBitCount);
        mMessages.resize(mBfBitCount);




        if (dynamic_cast<SilentOtExtReceiver*>(&otExt))
        {
            auto& ot = dynamic_cast<SilentOtExtReceiver&>(otExt);
            ot.silentReceive(mRandChoices, mMessages, prng, chls);

            char c;
            chls[0].send(c);
            chls[0].recv(c);
        }
        else
        {

            mRandChoices.randomize(prng);

            if (otExt.hasBaseOts() == false)
            {
                otExt.genBaseOts(prng, chl);
            }

            // this is a lambda function that does part of the OT extension where i am the receiver.
            auto recvOtRountine = [this](u64 i, u64 total, OtExtReceiver& ots, block seed, Channel& chl)
            {
                // compute the region of the OTs im going to do
                u64 start = std::min(roundUpTo(i * mMessages.size() / total, 128), mMessages.size());
                u64 end = std::min(roundUpTo((i + 1) * mMessages.size() / total, 128), mMessages.size());
                //std::cout << IoStream::lock << "recv Chl " << chl.getName() << " get " << start << " - " << end << std::endl << IoStream::unlock;

                if (end - start)
                {

                    // copy the bits that this regeion will use. We should find a way to avoid this copy
                    BitVector choices;
                    choices.copy(mRandChoices, start, end - start);
                    //TODO("avoid this copy. need BitView...");

                    // compute the region of the OTs im going to do
                    span<block> range(
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
                        //std::cout<< IoStream::lock << "r recvOt " <<i << "  "<< (**chlIter).getName() << std::endl << IoStream::unlock;
                        recvOtRountine(i + 1, numRecvThreads + 1, *recvOts[i].get(), seed, *chlIter);
                    });

                ++chlIter;
            }


            // now use this thread to do a recv routine.
            seed = prng.get<block>();
            recvOtRountine(0, numRecvThreads + 1, otExt, seed, chl);




            // join any threads that we created.
            for (auto& thrd : thrds)
                thrd.join();

            //std::cout << timer;
        }
        gTimer.setTimePoint("Init.done");

    }


    void DcwRBfPsiReceiver::sendInput(std::vector<block>& inputs, Channel& chl)
    {
        std::vector<Channel> cc{ chl };

        sendInput(inputs, cc);
    }

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

    void DcwRBfPsiReceiver::sendInput(std::vector<block>& inputs, span<Channel>chls)
    {
        if (inputs.size() != mMyInputSize)
            throw std::runtime_error(LOCATION);
        gTimer.setTimePoint("online.start");

        auto& chl = chls[0];
        PRNG prng(mSeed);
        BitVector bf(mBfBitCount);

        google::dense_hash_map<u64, u64, NoHash<u64>> maskMap(inputs.size());
        maskMap.set_empty_key(0);
        std::vector<block> theirMasks(mTheirInputSize), myMasks(mMyInputSize);
        std::vector<AES> mHasher(mNumHashFunctions / 2);

        PRNG hashSeedGen(mHashingSeed);
        for (u64 i = 0; i < mHasher.size(); ++i)
            mHasher[i].setKey(hashSeedGen.get<block>());

        for (u64 i = 0; i < inputs.size(); ++i)
        {
            auto& item = inputs[i];
            block encoding = ZeroBlock;

            for (u64 j = 0; j < mHasher.size(); ++j)
            {
                auto hashOut = mHasher[j].ecbEncBlock(inputs[i]) ^ inputs[i];
                auto idx = (std::array<u64, 2>&)hashOut;
                idx[0] %= mBfBitCount;
                idx[1] %= mBfBitCount;

                bf[idx[0]] = 1;
                bf[idx[1]] = 1;

                encoding = encoding ^ mMessages[idx[0]];
                encoding = encoding ^ mMessages[idx[1]];
            }

            auto res = maskMap.insert(std::make_pair((u64&)encoding, i));
            if (res.second == false)
                throw std::runtime_error("correctness error, collision on the 64-bit hash within my set");
            myMasks[i] = encoding;
        }

        gTimer.setTimePoint("online.BF_computed");

        bf ^= mRandChoices;
        chl.asyncSend(std::move(bf));
        gTimer.setTimePoint("online.Bf_permuite_sent");
        chl.recv(theirMasks.data(), theirMasks.size());

        for (u64 i = 0; i < mTheirInputSize; ++i)
        {
            auto match = maskMap.find(*(u64*)&theirMasks[i]);
            if (match != maskMap.end() && eq(myMasks[match->second], theirMasks[i]))
                mIntersection.push_back(match->second);
        }

        gTimer.setTimePoint("online.done");
    }
}
#endif