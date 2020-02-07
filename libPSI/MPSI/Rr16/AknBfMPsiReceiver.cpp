#include "libPSI/config.h"
#ifdef ENABLE_RR16_PSI

#include "AknBfMPsiReceiver.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "cryptoTools/Common/Log.h"
#include <unordered_map>
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/RandomOracle.h"

namespace osuCrypto
{

    AknBfMPsiReceiver::AknBfMPsiReceiver()
    {


    }


    AknBfMPsiReceiver::~AknBfMPsiReceiver()
    {
    }


    void AknBfMPsiReceiver::init(u64 n, u64 statSecParam, OtExtReceiver& otExt, Channel & chl, block seed)
    {
        std::vector<Channel> cc{ chl };

        init(n, statSecParam, otExt, cc, seed);
    }


    void AknBfMPsiReceiver::init(u64 n, u64 statSecParam, OtExtReceiver& otExt, span<Channel>  chls, block seed)
    {

        //Timer timer;
        setTimePoint("AknPSI.recv.Init.start");
        mMyInputSize = n;
        mTheirInputSize = n;
        mStatSecParam = statSecParam;
        //auto logn = std::log2(n);
        //mNumBins = (n + logn - 1) / logn;
        //mBinSize = logn * std::log2(logn);

        PRNG prng(seed);
        mSeed = prng.get<block>();
        auto myHashSeed = prng.get<block>();


        auto & chl = chls[0];
        Commit comm(myHashSeed), theirComm;
        chl.asyncSend(comm.data(), comm.size());
        auto theirCommFutre = chl.asyncRecv(theirComm.data(), theirComm.size());

        //u64 statSecParam(40);
        u64 totalOnesCount,  cncThreshold;
        double cncProb;
        setTimePoint("AknPSI.recv.Init.params");

        computeAknBfParams(mMyInputSize, statSecParam, mTotalOtCount, totalOnesCount, cncThreshold, cncProb, mNumHashFunctions, mBfBitCount);




        setTimePoint("AknPSI.recv.Init.aknOTstart");
        mAknOt.init(mTotalOtCount, totalOnesCount, cncProb, otExt, chls, prng);

        setTimePoint("AknPSI.recv.Init.aknFinish");

        if (mBfBitCount > mAknOt.mMessages.size())
            throw std::runtime_error(LOCATION);

        //std::random_shuffle(mAknOt.mZeros.begin(), mAknOt.mZeros.end(), prng);
        //std::random_shuffle(mAknOt.mOnes.begin(), mAknOt.mOnes.end(), prng);

        theirCommFutre.get();
        chl.asyncSend((u8*)&myHashSeed, sizeof(block));
        block theirHashingSeed;
        chl.recv((u8*)&theirHashingSeed, sizeof(block));

        mHashingSeed = myHashSeed ^ theirHashingSeed;

        setTimePoint("AknPSI.recv.Init.done");
        //std::cout << timer;
    }


    void AknBfMPsiReceiver::sendInput(std::vector<block>& inputs, Channel & chl)
    {
        std::vector<Channel> cc{ chl };

        sendInput(inputs, cc);
    }

    void AknBfMPsiReceiver::sendInput(std::vector<block>& inputs, span<Channel> chls)
    {
        if (inputs.size() != mMyInputSize)
            throw std::runtime_error(LOCATION);
        //Timer timer;
        setTimePoint("AknPSI.recv.online.start");

        PRNG prng(mSeed);

        std::vector<u8> bf(mBfBitCount, 0);

        std::promise<void> hashingsDoneProm, mergeDoneProm, permuteDoneProm;
        std::shared_future<void>
            hashingsDoneFuture(hashingsDoneProm.get_future()),
            mergeDoneFuture(mergeDoneProm.get_future()),
            permuteDoneFuture(permuteDoneProm.get_future());

        std::atomic<u32> hashingsRemaing((u32)chls.size());
        std::atomic<i32> firstDone(-1);

        std::unordered_map<u64, std::pair<block, u64>> masks;
        masks.reserve(inputs.size());

        std::vector<std::promise<std::unordered_map<u64, std::pair<block, u64>>>> masksProms(chls.size() - 1);
        std::vector<std::shared_future<std::unordered_map<u64, std::pair<block, u64>>>> masksFutures;


        for (u64 i = 0; i < u64(chls.size()) - 1; ++i)masksFutures.push_back(masksProms[i].get_future());

        std::mutex finalMtx;


        if (sizeof(LogOtCount_t) * 8 < std::ceil(std::log2(mTotalOtCount)))
            throw std::runtime_error(LOCATION);

        std::vector<LogOtCount_t> permute(mBfBitCount);
        //std::cout << "size  " << permuteBuff.size() << " = " <<mBfBitCount << " * " << permByteSize  << std::endl;

        std::vector<block>bv((mNumHashFunctions + 1) / 2);
        auto routine = [&](u64 t)
        {
            auto & chl = chls[t];
            auto start = inputs.size() * t / chls.size();
            auto end = inputs.size() * (t + 1) / chls.size();
            RandomOracle hash;


            std::vector<u64> idxs((end - start)* mNumHashFunctions);
            auto idxIter = idxs.begin();
            u8 hashOut[RandomOracle::HashSize];

            //std::cout << IoStream::lock;

            for (u64 i = start; i < end; ++i)
            {
                hash.Reset();


                hash.Update(mHashingSeed);
                hash.Update(inputs[i]);
                hash.Final(hashOut);

                //std::cout << "r " << (u64)hashOut << std::endl;

                auto key = toBlock(hashOut);
                AES hasher(key);

                hasher.ecbEncCounterMode(0, bv.size(), bv.data());
                span<u64>iv((u64*)bv.data(), mNumHashFunctions);


                //std::cout << "R inputs[" << i << "] " << inputs[i]  << " h -> "
                //    << toBlock(hashOut) << " = H(" << mHashingSeed << " || " << inputs[i] << ")" << std::endl;
                //<< toBlock(hashOut) << std::endl;

                for (u64 j = 0; j < mNumHashFunctions; ++j)
                {
                    // copy the hash since its stateful


                    //auto idx = hasher.get<u64>() % mBfBitCount;

                    *idxIter = iv[j] % mBfBitCount;
                    //std::cout << "R send " << i << "  " << j << "  bf[" << *idxIter<< "] = 1  "<< std::endl;

                    bf[*idxIter++] = 1;

                    //auto pIdx = permutes[idx];

                    //myMasks[k] = myMasks[k] ^ mAknOt.mMessages[pIdx][1];
                }
                //for (u64 j = 0; j < mNumHashFunctions; ++j)
                //{
                //    // copy the hash since its stateful and has the seed in it
                //    auto hash = mHashs[j];

                //    hash.Update((u8*)&item, sizeof(block));
                //    hash.Final(hashOut);


                //}

            }
            //std::cout << IoStream::unlock;


            if (--hashingsRemaing == 0)
                hashingsDoneProm.set_value();
            else
                hashingsDoneFuture.get();

            // all hashing is done now.

            if (t == 0)
            {
                setTimePoint("AknPSI.recv.online.BF_computed");

                // if we are the main thread, then convert the bloom filter into a permutation
                //TODO("make perm item size smaller");
                auto& vv = permute;

                std::array<std::vector<u64>::iterator, 2> idxIters{ mAknOt.mZeros.begin(), mAknOt.mOnes.begin() };

                u64 i = 0;
                for (; i < mBfBitCount && idxIters[0] != mAknOt.mZeros.end(); ++i)
                {
                    auto& idx = *idxIters[bf[i]]++;
                    vv[i] = (LogOtCount_t)idx;
                    //memcpy(iter, &idx, permByteSize);
                    //iter += permByteSize;
                }

                for (; i < mBfBitCount; ++i)
                {
                    auto& idx = *idxIters[1]++;
                    vv[i] = (LogOtCount_t)idx;

                    //memcpy(iter, &idx, permByteSize);
                    //iter += permByteSize;
                }


                //TODO("Split this send into several");
                //u8 dummy[1];
                //chl.asyncSendCopy(dummy, 1);
                //std::cout << "size  " << permuteBuff.size() << std::endl;
                chl.asyncSend(permute);
                //u64 blockSize = 4096 * 128 * 20;
                //std::cout << "blockSize " << blockSize << std::endl;

                //for (i64 i = 0; i < (i64)permuteBuff.size(); i += blockSize)
                //{
                //    auto ss = std::min(blockSize, permuteBuff.size() - i);

                //    chl.asyncSend(permuteBuff.data() + i, ss);
                //}

                permuteDoneProm.set_value();

                setTimePoint("AknPSI.recv.online.perm_computed");

            }
            else
            {
                permuteDoneFuture.get();
            }


            // now lets generate the masks. we have the computed indices in the idxs vector.
            idxIter = idxs.begin();


            //TODO("make masks smaller");
            //u64 maskSize = (mStatSecParam + log2ceil(inputs.size()) + 7) / 8;


            // store all masks in the local hash table. will be merged together in a bit.
            std::unordered_map<u64, std::pair<block, u64>> localMasks;
            localMasks.reserve(end - start);


            //std::cout << IoStream::lock;
            for (u64 i = start; i < end; ++i)
            {
                block mask(ZeroBlock);
                //std::cout << "inputs[" << i << "] " << inputs[i] << std::endl;
                const u64 stepSize = 2;
                u64 stepCount = mNumHashFunctions / stepSize;

                for (u64 j = 0; j < stepCount; ++j)
                {
                    std::array<u64, stepSize> idxs;
                    idxs[0] = *idxIter++;
                    idxs[1] = *idxIter++;
                    //idxs[2] = *idxIter++;
                    //idxs[3] = *idxIter++;
                    //idxs[4] = *idxIter++;
                    //idxs[5] = *idxIter++;
                    //idxs[6] = *idxIter++;
                    //idxs[7] = *idxIter++;

                    //auto idx = *idxIter++;
                    idxs[0] = permute[idxs[0]];
                    idxs[1] = permute[idxs[1]];
                    //idxs[2] = permute[idxs[2]];
                    //idxs[3] = permute[idxs[3]];
                    //idxs[4] = permute[idxs[4]];
                    //idxs[5] = permute[idxs[5]];
                    //idxs[6] = permute[idxs[6]];
                    //idxs[7] = permute[idxs[7]];

                    //std::cout << "recv " << i << "  " << j << "  " << pIdx << "  ("<<idx<< ")" << std::endl;

                    mask = mask
                        ^ mAknOt.mMessages[idxs[0]]
                        ^ mAknOt.mMessages[idxs[1]]
                        //^ mAknOt.mMessages[idxs[2]]
                        //^ mAknOt.mMessages[idxs[3]]
                        //^ mAknOt.mMessages[idxs[4]]
                        //^ mAknOt.mMessages[idxs[5]]
                        //^ mAknOt.mMessages[idxs[6]]
                        //^ mAknOt.mMessages[idxs[7]]
                        ;
                }
                for (u64 j = stepSize * stepCount; j < mNumHashFunctions; ++j)
                {
                    auto idx = *idxIter++;
                    auto pIdx = permute[idx];

                    //std::cout << "recv " << i << "  " << j << "  " << pIdx << "  ("<<idx<< ")" << std::endl;

                    mask = mask ^ mAknOt.mMessages[pIdx];
                }

                localMasks.emplace(*(u64*)&mask, std::pair<block, u64>(mask, i));
            }
            //std::cout << IoStream::unlock;


            // ok we have computed out masks. Lets have the thread that is first
            // done start merging them into a bit hash table that can be queried.
            auto idx = firstDone++;
            if (idx == -1)
            {
                setTimePoint("AknPSI.recv.online.maskSet1_done");

                // first done. Lets do the merge of the masks and insert ours first
                masks.insert(localMasks.begin(), localMasks.end());


                // get the other threads masks. They pass them here in the else branch below
                for (auto& otherMasksFuture : masksFutures)
                {
                    std::unordered_map<u64, std::pair<block, u64>> moreMasks(std::move(otherMasksFuture.get()));
                    masks.insert(moreMasks.begin(), moreMasks.end());
                }

                // signal the other threads that the merge is done.
                mergeDoneProm.set_value();

                setTimePoint("AknPSI.recv.online.masks_merged");

            }
            else
            {
                // ok, we weren't first done, lets move out masks into the
                //  promise which the first threads will get in the code above.
                masksProms[idx].set_value(std::move(localMasks));

                // ok. now the merge is done.
                mergeDoneFuture.get();
            }

            std::vector<block> theirMasks;
            chl.recv(theirMasks);

            if (t == 0)
                setTimePoint("AknPSI.recv.online.recvMasked");

            //u64 numMasks = theirMasksBuff.size() / maskSize;
            std::vector<u64> localIntersection;

            for (u64 i = 0; i < u64(theirMasks.size()); ++i)
            {
                auto& kk = *(u64*)&theirMasks[i];

                auto match = masks.find(kk);
                if (match != masks.end())
                {
                    localIntersection.push_back(match->second.second);
                }
            }

            {
                std::lock_guard<std::mutex> lock(finalMtx);
                if (mIntersection.capacity() == 0)
                {
                    // if it appears that we are first here, lets estimate the size of the intersection and reserve the memory
                    mIntersection.reserve((u64)(localIntersection.size() * chls.size() * 1.2));
                }

                mIntersection.insert(mIntersection.end(), localIntersection.begin(), localIntersection.end());
            }
        };


        // launch the threads to do the routine
        std::vector<std::thread> thrds(chls.size() - 1);

        for (u64 i = 0; i < thrds.size(); ++i)
        {
            //compute the thread idk t
            u64 t = i + 1;

            // go!
            thrds[i] = std::thread([&, t]() {routine(t); });
        }
        routine(0);



        // join any threads we may have spawned.
        for (auto& thrd : thrds)
            thrd.join();

        setTimePoint("AknPSI.recv.online.done");

        //std::cout << timer;
    }




    u64 computeMa(double p, u64 t, u64 k)
    {

        auto ma = (p*k + p*t + std::sqrt(k*k*p*p + 2 * k*p*p*t)) / (p*p);
        return (u64)ma;
    }

    u64 computeTau(u64 mh, double p, u64 k)
    {
        auto tau = p * mh + (k + std::sqrt(k * k + 8 * k * p * mh)) / 2;
        return (u64)tau;
    }

    u64 computeMh(u64 minOnes, double p, u64 k)
    {
        auto dem = std::sqrt(k) * std::sqrt(k + p * p + 2 * k * p + k - 8 * minOnes * p * p + 8 * minOnes * p)
            + k * p + k - 2 * minOnes * p + 2 * minOnes;

        auto num = 2 * (p * p - 2 * p + 1);

        auto mh = dem / num;

        return (u64)mh;
    }

    double computeMaxOnes(u64 ma, double p, u64 k)
    {
        return (1 - p) *ma + std::sqrt(2 * k * (p*ma));
    }


    double compute(double p, u64 kappa, u64 minOnes, u64& mh, u64 & tau)
    {
        mh = computeMh(minOnes, p, kappa);
        tau = computeTau(mh, p, kappa);
        auto ma = computeMa(p, tau, kappa);
        auto maxOnes = computeMaxOnes(ma, p, kappa);
        return maxOnes;
    }

    void computeAknBfParams(
        u64 n,
        u64 kappa,
        u64 & totalOtCount,
        u64 & totalOnesCount,
        u64 & cncOnesThreshold,
        double & cncProb,
        u64 & numHashFunctions,
        u64 & bfBitCount)
    {

        if (kappa == 40)
        {
            switch (n)
            {
            case 1:
            case 4:
                totalOtCount = 8295;
                totalOnesCount = 517;
                cncOnesThreshold = 138;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 7196;
                return;
            case 8:
                totalOtCount = 10663;
                totalOnesCount = 959;
                cncOnesThreshold = 204;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 9296;
                return;
            case 16:
                totalOtCount = 14715;
                totalOnesCount = 1829;
                cncOnesThreshold = 323;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 12896;
                return;
            case 32:
                totalOtCount = 21762;
                totalOnesCount = 3549;
                cncOnesThreshold = 540;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 19172;
                return;
            case 64:
                totalOtCount = 34286;
                totalOnesCount = 6961;
                cncOnesThreshold = 944;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 30350;
                return;
            case 128:
                totalOtCount = 57068;
                totalOnesCount = 13743;
                cncOnesThreshold = 1711;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 50726;
                return;
            case 256:
                totalOtCount = 99372;
                totalOnesCount = 27246;
                cncOnesThreshold = 3182;
                cncProb = 0.099;
                numHashFunctions = 94;
                bfBitCount = 88627;
                return;
            case 512:
                totalOtCount = 179281;
                totalOnesCount = 54101;
                cncOnesThreshold = 5973;
                cncProb = 0.098;
                numHashFunctions = 94;
                bfBitCount = 160506;
                return;
            case 1024:
                totalOtCount = 331450;
                totalOnesCount = 105905;
                cncOnesThreshold = 9648;
                cncProb = 0.083;
                numHashFunctions = 94;
                bfBitCount = 302436;
                return;
            case 2048:
                totalOtCount = 623180;
                totalOnesCount = 207952;
                cncOnesThreshold = 15440;
                cncProb = 0.069;
                numHashFunctions = 94;
                bfBitCount = 578306;
                return;
            case 4096:
                totalOtCount = 1187141;
                totalOnesCount = 407982;
                cncOnesThreshold = 22958;
                cncProb = 0.053;
                numHashFunctions = 94;
                bfBitCount = 1121959;
                return;
            case 8192:
                totalOtCount = 2285265;
                totalOnesCount = 790117;
                cncOnesThreshold = 36452;
                cncProb = 0.044;
                numHashFunctions = 92;
                bfBitCount = 2181857;
                return;
            case 16384:
                totalOtCount = 4434188;
                totalOnesCount = 1582849;
                cncOnesThreshold = 59137;
                cncProb = 0.036;
                numHashFunctions = 93;
                bfBitCount = 4270964;
                return;
            case 32768:
                totalOtCount = 8658560;
                totalOnesCount = 3073716;
                cncOnesThreshold = 91828;
                cncProb = 0.029;
                numHashFunctions = 91;
                bfBitCount = 8402960;
                return;
            case 65536:
                totalOtCount = 16992857;
                totalOnesCount = 6113957;
                cncOnesThreshold = 150181;
                cncProb = 0.024;
                numHashFunctions = 91;
                bfBitCount = 16579297;
                return;
            case 131072:
                totalOtCount = 33479820;
                totalOnesCount = 12162968;
                cncOnesThreshold = 235416;
                cncProb = 0.019;
                numHashFunctions = 91;
                bfBitCount = 32836550;
                return;
            case 262144:
                totalOtCount = 66165163;
                totalOnesCount = 23957707;
                cncOnesThreshold = 364747;
                cncProb = 0.015;
                numHashFunctions = 90;
                bfBitCount = 65163755;
                return;
            case 524288:
                totalOtCount = 131108816;
                totalOnesCount = 47283348;
                cncOnesThreshold = 621716;
                cncProb = 0.013;
                numHashFunctions = 89;
                bfBitCount = 129392705;
                return;
            case 1048576:
                totalOtCount = 260252093;
                totalOnesCount = 95333932;
                cncOnesThreshold = 962092;
                cncProb = 0.01;
                numHashFunctions = 90;
                bfBitCount = 257635123;
                return;
            case 2097152:
                totalOtCount = 517435654;
                totalOnesCount = 188162824;
                cncOnesThreshold = 1516296;
                cncProb = 0.008;
                numHashFunctions = 89;
                bfBitCount = 513277951;
                return;
            case 4194304:
                totalOtCount = 1030082690;
                totalOnesCount = 371340163;
                cncOnesThreshold = 2241411;
                cncProb = 0.006;
                numHashFunctions = 88;
                bfBitCount = 1023879938;
                return;
            case 8388608:
                totalOtCount = 2052497778;
                totalOnesCount = 758786092;
                cncOnesThreshold = 3811372;
                cncProb = 0.005;
                numHashFunctions = 90;
                bfBitCount = 2042206617;
                return;
            default:
                break;
            }
        }



        double pStep = 0.001;
        double cStep = 0.001;

        double best = 9999999999999999999999999999.0;
        double pBest(-1), cBest(0);
        u64 mh1Best(0), thresholdBest(0), hBest(0);

        for (u64 h = 80; h < 100; ++h)
        {

            double p = .001;
            u64 minOnes = n * h;

            while (p < .1)
            {

                double c;
                double cPrime = 0;
                double sec = 0;
                u64 mh(-1), threshold(-1);

                c = 2.4;
                sec = 0;

                double maxOnes = compute(p, kappa, minOnes, mh, threshold);

                while (sec < 128 && c < 120)
                {
                    c += cStep;

                    cPrime = (n*h * c) / maxOnes;

                    sec = log2(std::pow(cPrime, h));
                }

                auto total = n * h * c / (1 - p);



                if (total < best && sec >= 128.0)
                {
                    best = total;
                    pBest = p;
                    cBest = c;
                    hBest = h;
                    mh1Best = mh;
                    thresholdBest = threshold;
                }

                p += pStep;
            }
        }

        if (pBest < 0)
        {
            throw std::runtime_error("n is too small for kappa bit security");
        }

        bfBitCount = (u64)(n * hBest * cBest);
        totalOnesCount = mh1Best;
        totalOtCount = (u64)computeMh(bfBitCount, pBest, kappa);
        //totalOtCount2 = computeMh(bfBitCount, pBest, kappa);
        //totalOnesCount = computeMh()
        cncOnesThreshold = (u64)thresholdBest;
        cncProb = pBest;
        numHashFunctions = (u64)hBest;
    }






}
#endif