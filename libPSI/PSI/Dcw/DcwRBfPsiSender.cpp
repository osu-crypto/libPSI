#include "DcwRBfPsiSender.h"
#ifdef ENABLE_DCW_PSI
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h" 
//#include "cryptoTools/Crypto/ShamirSSScheme2.h"  
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"


namespace osuCrypto {

    void DcwRBfPsiSender::init(u64 n, u64 statSecParam, OtExtSender& otExt, Channel& chl, block seed)
    {
        init(n, statSecParam, otExt, { &chl, 1 }, seed);
    }

    void DcwRBfPsiSender::init(u64 n, u64 statSecParam, OtExtSender& otExt, span<Channel> chls, block seed)
    {

        gTimer.setTimePoint("init.start");

        mN = n;
        PRNG prng(seed);
        mSeed = prng.get<block>();
        auto myHashSeed = prng.get<block>();
        auto& chl0 = chls[0];

        mNumHashFunctions = 128;
        mBfBitCount = n * mNumHashFunctions * 1.5;

        mSendOtMessages.resize(mBfBitCount);

        chl0.asyncSendCopy(myHashSeed);
        block theirHashingSeed;
        chl0.recv(theirHashingSeed);
        gTimer.setTimePoint("init.commitDone");

        mHashSeed = myHashSeed ^ theirHashingSeed;

        if (dynamic_cast<SilentOtExtSender*>(&otExt))
        {
            auto rBefore = chls[0].getTotalDataRecv();
            auto sBefore = chls[0].getTotalDataSent();

            //std::cout << "silent" << std::endl;
            auto& ot = dynamic_cast<SilentOtExtSender&>(otExt);
            ot.silentSend(mSendOtMessages, prng, chls);

            char c;
            chls[0].send(c);
            chls[0].recv(c);

            auto rAfter = chls[0].getTotalDataRecv();
            auto sAfter = chls[0].getTotalDataSent();

            std::cout << "1 before sent " << sBefore << std::endl;
            std::cout << "1 before recv " << rBefore << std::endl;

            std::cout << "1 after sent " << sAfter << std::endl;
            std::cout << "1 after recv " << rAfter << std::endl;
        }
        else
        {

            if (otExt.hasBaseOts() == false)
            {
                otExt.genBaseOts(prng, chl0);
            }

            // this is a lambda function that does part of the OT extension where i am the sender. Again
            // malicious PSI does OTs in both directions.
            auto sendOtRountine = [this](u64 i, u64 total, OtExtSender& ots, block seed, Channel& chl)
            {
                // compute the region of the OTs im going to do
                u64 start = std::min(roundUpTo(i * mSendOtMessages.size() / total, 128), mSendOtMessages.size());
                u64 end = std::min(roundUpTo((i + 1) * mSendOtMessages.size() / total, 128), mSendOtMessages.size());

                //std::cout << IoStream::lock << "send Chl " << chl.getName() <<" "<< i << "/"<< total << " get " << start << " - " << end << std::endl << IoStream::unlock;

                if (end - start)
                {

                    // get a view of where the messages should be stored.
                    span<std::array<block, 2>> range(
                        mSendOtMessages.begin() + start,
                        mSendOtMessages.begin() + end);
                    PRNG prng(seed);

                    // do the extension.
                    ots.send(range, prng, chl);
                }

            };


            // compute how many threads we want to do for each direction.
            // the current thread will do one of the OT receives so -1 for that.
            u64 numSendThreads = chls.size() - 1;

            std::vector<std::unique_ptr<OtExtSender>> sendOts(numSendThreads);

            // where we will store the threads that are doing the extension
            std::vector<std::thread> thrds(numSendThreads);

            // some iters to help giving out resources.
            auto thrdIter = thrds.begin();
            auto chlIter = chls.begin() + 1;


            // do the same thing but for the send OT extensions
            for (u64 i = 0; i < numSendThreads; ++i)
            {
                auto seed = prng.get<block>();
                sendOts[i] = std::move(otExt.split());

                *thrdIter++ = std::thread([&, i, chlIter]()
                    {
                        //std::cout << IoStream::lock << "r sendOt " << i << "  " << (**chlIter).getName() << std::endl << IoStream::unlock;
                        sendOtRountine(i + 1, numSendThreads + 1, *sendOts[i].get(), seed, *chlIter);
                    });

                ++chlIter;
            }

            seed = prng.get<block>();
            sendOtRountine(0, numSendThreads + 1, otExt, seed, chl0);


            gTimer.setTimePoint("init.OtExtDone");

            for (auto& thrd : thrds)
                thrd.join();
        }

        gTimer.setTimePoint("init.Done");

    }


    void DcwRBfPsiSender::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> cc{ chl };

        sendInput(inputs, cc);
    }

    void DcwRBfPsiSender::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {

        if (inputs.size() != mN)
            throw std::runtime_error(LOCATION);

        gTimer.setTimePoint("online.start");
        PRNG prng(mSeed);
        auto & chl = chls[0];

        BitVector otCorrection(mBfBitCount);
        chl.recv(otCorrection);

        gTimer.setTimePoint("online.otCorrectionRecv");

        auto start = 0;
        auto end = inputs.size();

        PRNG hashSeedGen(mHashSeed);
        std::vector<AES> mHashs(mNumHashFunctions / 2);

        for (u64 i = 0; i < mHashs.size(); ++i)
        {
            mHashs[i].setKey(hashSeedGen.get<block>());
        }

        std::vector<block> myMasks(inputs.size());

        for (u64 i = start, k = 0; i < end; ++i, ++k)
        {
            myMasks[i] = ZeroBlock;

            for (u64 j = 0; j < mHashs.size(); ++j)
            {
                auto hashOut = mHashs[j].ecbEncBlock(inputs[i]) ^ inputs[i];
                auto idx = (std::array<u64,2>&)hashOut;
                idx[0] %= mBfBitCount;
                idx[1] %= mBfBitCount;

                myMasks[i] = myMasks[i] ^ mSendOtMessages[idx[0]][otCorrection[idx[0]] ^ 1];
                myMasks[i] = myMasks[i] ^ mSendOtMessages[idx[1]][otCorrection[idx[1]] ^ 1];
            }
        }

        chl.asyncSend(std::move(myMasks));
        gTimer.setTimePoint("online.masksSent");
    }
}
#endif