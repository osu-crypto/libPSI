#ifdef ENABLE_DCW
#include "DcwRBfPsiSender.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h" 
//#include "cryptoTools/Crypto/ShamirSSScheme2.h"  
#include "libOTe/Base/naor-pinkas.h"
#include "ShamirSSScheme.h"  


namespace osuCrypto {

    DcwRBfPsiSender::DcwRBfPsiSender()
    {
    }


    DcwRBfPsiSender::~DcwRBfPsiSender()
    {
    }


    block DcwRBfPsiSender::computeSecureSharing(span<block> shares)
    {

        //std::cout << "# shares = " << shares.size() << "   (" << shares.size() * shares.size() / 2 << ")" << std::endl;


            ShamirSSScheme ss;

            auto ret = ss.init(shares.size(), shares.size() / 2);
            ss.computeShares(shares);


            NTL::BytesFromGF2X((u8*)&mSharesPrime, ss.mPrime, sizeof(block));

            //std::cout << "send Prime  " << ss.mPrime << std::endl;

            return ret;
        

    }

    void DcwRBfPsiSender::init(u64 n, u64 statSecParam, OtExtSender& otExt, span<Channel> chls, block seed)
    {

        gTimer.setTimePoint("init.start");
        mN = n;
        mStatSecParam = statSecParam;

        PRNG prng(seed);
        mSeed = prng.get<block>();
        auto myHashSeed = prng.get<block>();

        Commit comm(myHashSeed), theirComm;

        auto& chl0 = chls[0];
        chl0.asyncSend(comm.data(), comm.size());
        auto theirCommFutre = chl0.asyncRecv(theirComm.data(), theirComm.size());

        //u64 statSecParam(40);
        u64  numHashFunctions = 128;


        mHashs.resize(numHashFunctions);
        mBfBitCount = n * numHashFunctions * 2;

        mSendOtMessages.resize(mBfBitCount);

        //mDcwOt.init(m, mBinSize * mHashs.size(), mNumBins, mHashs.size(), otExt, chl, prng);

        theirCommFutre.get();
        chl0.asyncSend(&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl0.recv(&theirHashingSeed, sizeof(block));
        gTimer.setTimePoint("init.commitDone");

        if (otExt.hasBaseOts() == false)
        {
            //Timer gTimer;
            //gTimer.setTimePoint("base start");
            //PvwBaseOT base(chl0, OTRole::Receiver);
            //base.exec_base(prng);
            //std::array<std::array<block, 2>, gOtExtBaseOtCount> baseMsg;
            std::array<block, gOtExtBaseOtCount> baseMsg;
            BitVector choices(gOtExtBaseOtCount);
            choices.randomize(prng);

            //crypto crpto(128, prng.get<block>());
            NaorPinkas base;
            base.receive(choices, baseMsg, prng, chl0, 2);

            otExt.setBaseOts(baseMsg, choices);

            //gTimer.setTimePoint("baseDone");
            //std::cout << gTimer;
        }



        // this is a lambda function that does part of the OT extension where i am the sender. Again
        // malicious PSI does OTs in both directions.
        auto sendOtRountine = [this](u64 i, u64 total, OtExtSender& ots, block seed, Channel& chl)
        {
            // compute the region of the OTs im going to do
            u64 start = std::min(roundUpTo(i *     mSendOtMessages.size() / total, 128), mSendOtMessages.size());
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




        mHashingSeed = myHashSeed ^ theirHashingSeed;
        PRNG hashSeedGen(mHashingSeed);

        for (u64 i = 0; i < mHashs.size(); ++i)
        {
            mHashs[i].Update(hashSeedGen.get<block>());
        }

        gTimer.setTimePoint("init.OtExtDone");


        mShares.resize(mBfBitCount);
        mEncSeed = computeSecureSharing(mShares);

        gTimer.setTimePoint("init.ComputedShares " + std::to_string(mBfBitCount));


        // join any threads that we created.
        for (auto& thrd : thrds)
            thrd.join();

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
        auto t = 0;
        auto & chl = chls[t];

        BitVector otCorrection(mBfBitCount);
        chl.recv(otCorrection);

        gTimer.setTimePoint("online.otCorrectionRecv");



        //auto routine = [&](u64 t)
        //{
        auto start = 0;// chls.size();
        auto end = inputs.size();// chls.size();



        std::unique_ptr<ByteStream> myMasksBuff(new ByteStream((mBfBitCount)* sizeof(block)));
        myMasksBuff->setp(myMasksBuff->capacity());
        auto zeroMessages = myMasksBuff->getSpan<block>();
        u8 hashOut[SHA1::HashSize];
        //std::cout << IoStream::lock;

        for (u64 i = 0, k = 0; i < mBfBitCount; ++i, ++k)
        {

            zeroMessages[i] = mShares[i] ^ mSendOtMessages[i][otCorrection[i]];

            //std::cout << "enc' " << i << "  " << mShares[i] << " = " << zeroMessages[i] << " ^ " << mSendOtMessages[i][otCorrection[i]]
                //<< "  " << otCorrection[i] << "   " << mSendOtMessages[i][otCorrection[i] ^ 1] << std::endl;
        }

        //std::unique_ptr<ByteStream> primeBuff(new ByteStream(sizeof(block)));
        //NTL::BytesFromZZ(primeBuff->data(),, primeBuff->size());

        chl.asyncSendCopy(&mSharesPrime, sizeof(block));
        chl.asyncSend(std::move(myMasksBuff));
        gTimer.setTimePoint("online.sharesSent");

        myMasksBuff.reset(new ByteStream(inputs.size()* sizeof(block)));
        myMasksBuff->setp(myMasksBuff->capacity());
        auto myMasks = myMasksBuff->getSpan<block>();

        const u64 stepSize = 128;
        std::vector<block> encBuff(stepSize);
        AES enc(mEncSeed);

        //std::cout << "send seed " << mEncSeed << std::endl;ss.mPrime

        for (u64 i = 0; i < mSendOtMessages.size(); i += stepSize)
        {
            auto s = std::min(stepSize, mSendOtMessages.size() - i);

            for (u64 j = 0, ii = i; j < s; ++j, ++ii)
            {
                encBuff[j] = _mm_set1_epi64x(ii);
            }

            enc.ecbEncBlocks(encBuff.data(), encBuff.size(), encBuff.data());

            for (u64 j = 0, idx = i; j < s; ++j, ++idx)
            {

                auto blkEnc = mSendOtMessages[idx][otCorrection[idx] ^ 1] ^ encBuff[j];


                //std::cout << "sender " << idx << "  " << blkEnc << " <- " << mSendOtMessages[idx][otCorrection[idx] ^ 1] << std::endl;

                mSendOtMessages[idx][otCorrection[idx] ^ 1] = blkEnc;

            }
        }
        gTimer.setTimePoint("online.masksEncrypted");



        for (u64 i = start, k = 0; i < end; ++i, ++k)
        {
            myMasks[i] = ZeroBlock;

            for (u64 j = 0; j < mHashs.size(); ++j)
            {
                // copy the hash since its stateful
                auto hash = mHashs[j];

                hash.Update(inputs[i]);
                hash.Final(hashOut);
                u64& idx = *(u64*)hashOut;

                idx %= mBfBitCount;

                myMasks[i] = myMasks[i] ^ mSendOtMessages[idx][otCorrection[idx] ^ 1];

            }
            //std::cout << "sender "<< i << " " << myMasks[i] << "  <-  " << inputs[i] << std::endl;
        }


        //std::cout << IoStream::unlock;

        chl.asyncSend(std::move(myMasksBuff));
        gTimer.setTimePoint("online.masksSent");
        //if (result)
        //    chl.asyncSend(std::move(myMasksBuff));
        //};
    //

        //std::vector< std::thread> thrds(chls.size());
        //for (u64 i = 0; i < chls.size(); ++i)
        //{
        //    thrds[i] = std::thread([&, i]()
        //    {
        //        routine(i);
        //    });

        //}

        //BitVector& usedBits = mDcwOt.mSampled;
        //for (u64 i = 0; i < mBfBitCount; ++i)
        //{
        //    if (usedBits[permutes[i]])
        //    {
        //        isValidPerm.set_value(false);
        //        break;
        //    }

        //    usedBits[permutes[i]] = 1;
        //}

        //isValidPerm.set_value(true);

        //for (auto& thrd : thrds)
        //    thrd.join();

        //    //std::cout << IoStream::lock << "s" << std::endl;;
        //    for (u64 i = 0; i < inputs.size(); ++i)
        //    {
        //        myMasks[i] = ZeroBlock;
        //        for (u64 j = 0; j < mHashs.size(); ++j)
        //        {
        //            // copy the hash since its stateful
        //            auto hash = mHashs[j];

        //            hash.Update(inputs[i]);
        //            hash.Final(hashOut);
        //            u64& idx = *(u64*)hashOut;

        //            idx %= mBfBitCount;

        //            auto pIdx = permutes[idx];

        //            myMasks[i] = myMasks[i] ^ mDcwOt.mMessages[pIdx][1];

        //            //if (i == 0)
        //            //{
        //            //    std::cout << mDcwOt.mMessages[pIdx][1] << "  " << pIdx << "  " << mDcwOt.mMessages[pIdx][0] << "  " << std::endl;
        //            //}

        //        }

        //        //if (i == 0)
        //        //{
        //        //    std::cout << myMasks[i] << std::endl;
        //        //}
        //    }
        //    //std::cout << IoStream::unlock;

        //    chl.asyncSend(std::move(myMasksBuff));
        //}
    }
}
#endif