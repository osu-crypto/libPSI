
#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI
#include "KkrtPsiSender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include <cryptoTools/Common/Matrix.h>
#include "cryptoTools/Common/CuckooIndex.h"
//#include <unordered_map>
#include "libPSI/Tools/SimpleIndex.h"


namespace osuCrypto
{

    KkrtPsiSender::KkrtPsiSender()
    {
    }

    KkrtPsiSender::~KkrtPsiSender()
    {
    }
    //extern std::string hexString(u8* data, u64 length);

    void KkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, Channel & chl0, NcoOtExtSender& ots, block seed)
    {
        std::array<Channel, 1> c{ chl0 };
        init(senderSize, recverSize, statSec, c, ots, seed);
    }

    void KkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, span<Channel> chls, NcoOtExtSender& otSend, block seed)
    {
        mStatSecParam = statSec;
        mSenderSize = senderSize;
        mRecverSize = recverSize;

        // we need a random hash function, so both commit to a seed and then decommit later
        mPrng.SetSeed(seed);
        block myHashSeeds;
        myHashSeeds = mPrng.get<block>();
        auto& chl = chls[0];
        chl.asyncSend((u8*)&myHashSeeds, sizeof(block));
        //std::cout <<IoStream::lock << "send: sending PSI seed " << myHashSeeds << std::endl << IoStream::unlock;


        block theirHashingSeeds;
        auto fu = chl.asyncRecv((u8*)&theirHashingSeeds, sizeof(block));

        // init Simple hash
        mParams = CuckooIndex<>::selectParams(mRecverSize, statSec, 0,3);
        if (mParams.mNumHashes != 3) throw std::runtime_error(LOCATION);

        otSend.configure(false, 40, 128);

        //mIndex.init(cuckoo.mBins.size(), mSenderSize, statSec, cuckoo.mParams.mNumHashes);

        //do base OT
        if (otSend.hasBaseOts() == false)
        {
#if defined(LIBOTE_HAS_BASE_OT) && defined(ENABLE_IKNP)
            DefaultBaseOT baseBase;
            std::array<std::array<block, 2>, 128> baseBaseOT;
            baseBase.send(baseBaseOT, mPrng, chl);

            IknpOtExtReceiver base;
            BitVector baseChoice(otSend.getBaseOTCount());
            baseChoice.randomize(mPrng);
            std::vector<block> baseOT(otSend.getBaseOTCount());
            base.setBaseOts(baseBaseOT, mPrng, chl);
            base.receive(baseChoice, baseOT, mPrng, chl);

            otSend.setBaseOts(baseOT, baseChoice, chl);
#else
            throw std::runtime_error("base OTs must be set or enable base OTs and IKNP in libOTe. " LOCATION);
#endif
        }

        fu.get();
        //std::cout << IoStream::lock << "send: recved PSI seed " << theirHashingSeeds << std::endl << IoStream::unlock;

        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        otSend.init(mParams.numBins() + mParams.mStashSize, mPrng, chl);

        mOtSender = &otSend;
        //setTimePoint("kkrt.s InitS.extFinished");

        setTimePoint("kkrt.S offline.perm start");
        mPermute.resize(mSenderSize);
        for (u64 i = 0; i < mSenderSize; ++i) mPermute[i] = i;

        //mPermute position
        std::shuffle(mPermute.begin(), mPermute.end(), mPrng);

        setTimePoint("kkrt.S offline.perm done");

    }


    void KkrtPsiSender::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs, chls);
    }








    void hashItems(
        span<block> items,
        MatrixView<u64> mItemToBinMap,
        block hashingSeed,
        u64 numBins,
        PRNG& prng,
        MatrixView<u8> masks,
        span<u64> perm)
    {

        std::array<block, 8> hashs;
        AES hasher(hashingSeed);

        auto mNumHashFunctions = mItemToBinMap.stride();
        auto mainSteps = items.size() / hashs.size();
        auto remSteps = items.size() % hashs.size();
        u64 itemIdx = 0;

        if (mNumHashFunctions == 3)
        {

            std::array<PRNG, 8> prngs;
            for (u64 i = 0; i < 8; ++i)
                prngs[i].SetSeed(prng.get<block>());

            for (u64 i = 0; i < mainSteps; ++i, itemIdx += 8)
            {
                hasher.ecbEncBlocks(items.data() + itemIdx, 8, hashs.data());

                auto itemIdx0 = itemIdx + 0;
                auto itemIdx1 = itemIdx + 1;
                auto itemIdx2 = itemIdx + 2;
                auto itemIdx3 = itemIdx + 3;
                auto itemIdx4 = itemIdx + 4;
                auto itemIdx5 = itemIdx + 5;
                auto itemIdx6 = itemIdx + 6;
                auto itemIdx7 = itemIdx + 7;

                // compute the hash as  H(x) = AES(x) + x
                hashs[0] = hashs[0] ^ items[itemIdx0];
                hashs[1] = hashs[1] ^ items[itemIdx1];
                hashs[2] = hashs[2] ^ items[itemIdx2];
                hashs[3] = hashs[3] ^ items[itemIdx3];
                hashs[4] = hashs[4] ^ items[itemIdx4];
                hashs[5] = hashs[5] ^ items[itemIdx5];
                hashs[6] = hashs[6] ^ items[itemIdx6];
                hashs[7] = hashs[7] ^ items[itemIdx7];

                // Get the first bin that each of the items maps to
                auto bIdx00 = CuckooIndex<>::getHash(hashs[0], 0, numBins);
                auto bIdx10 = CuckooIndex<>::getHash(hashs[1], 0, numBins);
                auto bIdx20 = CuckooIndex<>::getHash(hashs[2], 0, numBins);
                auto bIdx30 = CuckooIndex<>::getHash(hashs[3], 0, numBins);
                auto bIdx40 = CuckooIndex<>::getHash(hashs[4], 0, numBins);
                auto bIdx50 = CuckooIndex<>::getHash(hashs[5], 0, numBins);
                auto bIdx60 = CuckooIndex<>::getHash(hashs[6], 0, numBins);
                auto bIdx70 = CuckooIndex<>::getHash(hashs[7], 0, numBins);

                // update the map with these bin indexs
                mItemToBinMap(itemIdx0, 0) = bIdx00;
                mItemToBinMap(itemIdx1, 0) = bIdx10;
                mItemToBinMap(itemIdx2, 0) = bIdx20;
                mItemToBinMap(itemIdx3, 0) = bIdx30;
                mItemToBinMap(itemIdx4, 0) = bIdx40;
                mItemToBinMap(itemIdx5, 0) = bIdx50;
                mItemToBinMap(itemIdx6, 0) = bIdx60;
                mItemToBinMap(itemIdx7, 0) = bIdx70;

                // get the second bin index
                auto bIdx01 = CuckooIndex<>::getHash(hashs[0], 1, numBins);
                auto bIdx11 = CuckooIndex<>::getHash(hashs[1], 1, numBins);
                auto bIdx21 = CuckooIndex<>::getHash(hashs[2], 1, numBins);
                auto bIdx31 = CuckooIndex<>::getHash(hashs[3], 1, numBins);
                auto bIdx41 = CuckooIndex<>::getHash(hashs[4], 1, numBins);
                auto bIdx51 = CuckooIndex<>::getHash(hashs[5], 1, numBins);
                auto bIdx61 = CuckooIndex<>::getHash(hashs[6], 1, numBins);
                auto bIdx71 = CuckooIndex<>::getHash(hashs[7], 1, numBins);

                // check if we get a collision with the first bin index
                u8 c01 = 1 & (bIdx00 == bIdx01);
                u8 c11 = 1 & (bIdx10 == bIdx11);
                u8 c21 = 1 & (bIdx20 == bIdx21);
                u8 c31 = 1 & (bIdx30 == bIdx31);
                u8 c41 = 1 & (bIdx40 == bIdx41);
                u8 c51 = 1 & (bIdx50 == bIdx51);
                u8 c61 = 1 & (bIdx60 == bIdx61);
                u8 c71 = 1 & (bIdx70 == bIdx71);

                // If we didnt get a collision, set the new bin index and otherwise set it to -1
                mItemToBinMap(itemIdx0, 1) = bIdx01 | (c01 * u64(-1));
                mItemToBinMap(itemIdx1, 1) = bIdx11 | (c11 * u64(-1));
                mItemToBinMap(itemIdx2, 1) = bIdx21 | (c21 * u64(-1));
                mItemToBinMap(itemIdx3, 1) = bIdx31 | (c31 * u64(-1));
                mItemToBinMap(itemIdx4, 1) = bIdx41 | (c41 * u64(-1));
                mItemToBinMap(itemIdx5, 1) = bIdx51 | (c51 * u64(-1));
                mItemToBinMap(itemIdx6, 1) = bIdx61 | (c61 * u64(-1));
                mItemToBinMap(itemIdx7, 1) = bIdx71 | (c71 * u64(-1));

                // if we got a collision, then fill the final mask locations with junk data
                prngs[0].get(masks.data() + (perm[itemIdx0] * mNumHashFunctions + 1) * masks.stride(), c01 * masks.stride());
                prngs[1].get(masks.data() + (perm[itemIdx1] * mNumHashFunctions + 1) * masks.stride(), c11 * masks.stride());
                prngs[2].get(masks.data() + (perm[itemIdx2] * mNumHashFunctions + 1) * masks.stride(), c21 * masks.stride());
                prngs[3].get(masks.data() + (perm[itemIdx3] * mNumHashFunctions + 1) * masks.stride(), c31 * masks.stride());
                prngs[4].get(masks.data() + (perm[itemIdx4] * mNumHashFunctions + 1) * masks.stride(), c41 * masks.stride());
                prngs[5].get(masks.data() + (perm[itemIdx5] * mNumHashFunctions + 1) * masks.stride(), c51 * masks.stride());
                prngs[6].get(masks.data() + (perm[itemIdx6] * mNumHashFunctions + 1) * masks.stride(), c61 * masks.stride());
                prngs[7].get(masks.data() + (perm[itemIdx7] * mNumHashFunctions + 1) * masks.stride(), c71 * masks.stride());


                // repeat the process with the last hash function
                auto bIdx02 = CuckooIndex<>::getHash(hashs[0], 2, numBins);
                auto bIdx12 = CuckooIndex<>::getHash(hashs[1], 2, numBins);
                auto bIdx22 = CuckooIndex<>::getHash(hashs[2], 2, numBins);
                auto bIdx32 = CuckooIndex<>::getHash(hashs[3], 2, numBins);
                auto bIdx42 = CuckooIndex<>::getHash(hashs[4], 2, numBins);
                auto bIdx52 = CuckooIndex<>::getHash(hashs[5], 2, numBins);
                auto bIdx62 = CuckooIndex<>::getHash(hashs[6], 2, numBins);
                auto bIdx72 = CuckooIndex<>::getHash(hashs[7], 2, numBins);


                u8 c02 = 1 & (bIdx00 == bIdx02 || bIdx01 == bIdx02);
                u8 c12 = 1 & (bIdx10 == bIdx12 || bIdx11 == bIdx12);
                u8 c22 = 1 & (bIdx20 == bIdx22 || bIdx21 == bIdx22);
                u8 c32 = 1 & (bIdx30 == bIdx32 || bIdx31 == bIdx32);
                u8 c42 = 1 & (bIdx40 == bIdx42 || bIdx41 == bIdx42);
                u8 c52 = 1 & (bIdx50 == bIdx52 || bIdx51 == bIdx52);
                u8 c62 = 1 & (bIdx60 == bIdx62 || bIdx61 == bIdx62);
                u8 c72 = 1 & (bIdx70 == bIdx72 || bIdx71 == bIdx72);


                mItemToBinMap(itemIdx0, 2) = bIdx02 | (c02 * u64(-1));
                mItemToBinMap(itemIdx1, 2) = bIdx12 | (c12 * u64(-1));
                mItemToBinMap(itemIdx2, 2) = bIdx22 | (c22 * u64(-1));
                mItemToBinMap(itemIdx3, 2) = bIdx32 | (c32 * u64(-1));
                mItemToBinMap(itemIdx4, 2) = bIdx42 | (c42 * u64(-1));
                mItemToBinMap(itemIdx5, 2) = bIdx52 | (c52 * u64(-1));
                mItemToBinMap(itemIdx6, 2) = bIdx62 | (c62 * u64(-1));
                mItemToBinMap(itemIdx7, 2) = bIdx72 | (c72 * u64(-1));

                prngs[0].get(masks.data() + (perm[itemIdx0] * mNumHashFunctions + 2) * masks.stride(), c01 * masks.stride());
                prngs[1].get(masks.data() + (perm[itemIdx1] * mNumHashFunctions + 2) * masks.stride(), c11 * masks.stride());
                prngs[2].get(masks.data() + (perm[itemIdx2] * mNumHashFunctions + 2) * masks.stride(), c21 * masks.stride());
                prngs[3].get(masks.data() + (perm[itemIdx3] * mNumHashFunctions + 2) * masks.stride(), c31 * masks.stride());
                prngs[4].get(masks.data() + (perm[itemIdx4] * mNumHashFunctions + 2) * masks.stride(), c41 * masks.stride());
                prngs[5].get(masks.data() + (perm[itemIdx5] * mNumHashFunctions + 2) * masks.stride(), c51 * masks.stride());
                prngs[6].get(masks.data() + (perm[itemIdx6] * mNumHashFunctions + 2) * masks.stride(), c61 * masks.stride());
                prngs[7].get(masks.data() + (perm[itemIdx7] * mNumHashFunctions + 2) * masks.stride(), c71 * masks.stride());
            }

            // in case the input does not divide evenly by 8, handle the last few items.
            hasher.ecbEncBlocks(items.data() + itemIdx, remSteps, hashs.data());
            for (u64 i = 0; i < remSteps; ++i, ++itemIdx)
            {
                hashs[i] = hashs[i] ^ items[itemIdx];

                std::vector<u64> bIdxs(mNumHashFunctions);
                for (u64 h = 0; h < mNumHashFunctions; ++h)
                {
                    auto bIdx = CuckooIndex<>::getHash(hashs[i], h, numBins);
                    bool collision = false;

                    bIdxs[h] = bIdx;
                    for (u64 hh = 0; hh < h; ++hh)
                        collision |= (bIdxs[hh] == bIdx);

                    u8 c = ((u8)collision & 1);
                    mItemToBinMap(itemIdx, h) = bIdx | c * u64(-1);
                    prng.get(masks.data() + (perm[itemIdx] * mNumHashFunctions + h) * masks.stride(), c * masks.stride());
                }
            }
        }
        else
        {
            // general proceedure for when numHashes != 3
            std::vector<u64> bIdxs(mNumHashFunctions);
            for (u64 i = 0; i < items.size(); i += hashs.size())
            {
                auto min = std::min<u64>(items.size() - i, hashs.size());

                hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

                for (u64 j = 0, itemIdx = i; j < min; ++j, ++itemIdx)
                {
                    hashs[j] = hashs[j] ^ items[itemIdx];

                    for (u64 h = 0; h < mNumHashFunctions; ++h)
                    {
                        auto bIdx = CuckooIndex<>::getHash(hashs[j], h, numBins);
                        bool collision = false;

                        bIdxs[h] = bIdx;
                        for (u64 hh = 0; hh < h; ++hh)
                            collision |= (bIdxs[hh] == bIdx);
                        u8 c = ((u8)collision & 1);
                        mItemToBinMap(itemIdx, h) = bIdx | c * u64(-1);
                        prng.get(masks.data() + (perm[itemIdx] * mNumHashFunctions + h) * masks.stride(), c * masks.stride());

                    }
                }
            }
        }
    }











    void KkrtPsiSender::sendInput(span<block> inputs, span<Channel> chls)
    {
        if (inputs.size() != mSenderSize)
            throw std::runtime_error("rt error at " LOCATION);

        setTimePoint("kkrt.S Online.online start");



        auto& chl = chls[0];
        u64 maskSize = u64(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8; //by byte
        auto numBins = mParams.numBins();


        // the buffer that we will write the masks to. There are
        // mParams.mNumHashes * mSenderSize rows, where the input at index
        // i will have its mParams.mNumHashes encodings written to locations
        // { i * mParams.mNumHashes + 0,
        //   i * mParams.mNumHashes + 1,
        //   ...
        //   i * mParams.mNumHashes + mParams.mNumHashes - 1 }
        Matrix<u8> myMaskBuff(mSenderSize * mParams.mNumHashes, maskSize);



        // we will process data in chucks of this size.
        u64 stepSize = 1 << 10;

        // set of some inter thread communication objects that will
        // allow this thread to know when the OT correction values have
        // been received.
        std::atomic<u64> recvedIdx(0);


        // spin off anothe thread that will schedule the corrections to be received.
        // This thread does not actually do any work and could be removed somehow.
        auto thrd = std::thread([&]() {

            // while there are more corrections for be recieved
            while (recvedIdx < numBins)
            {
                // compute the  size of the current step and the end index
                auto currentStepSize = std::min(stepSize, numBins - recvedIdx);

                // receive the corrections.
                mOtSender->recvCorrection(chl, currentStepSize);


                // notify the other thread that the corrections have arrived
                recvedIdx.fetch_add(currentStepSize, std::memory_order::memory_order_release);
            }
        });


        setTimePoint("kkrt.S Online.hashing start");

        // hash the items to bins. Instead of inserting items into bins,
        // we will just keep track of a map mapping input index to bin indexs
        //
        // e.g.   binIdxs[i] -> { h0(input[i]), h1(input[i]), h2(input[i]) }
        //
        Matrix<u64> binIdxs(inputs.size(), mParams.mNumHashes);
        hashItems(inputs, binIdxs, mHashingSeed, numBins, mPrng, myMaskBuff, mPermute);

        setTimePoint("kkrt.S Online.computeBucketMask start");

        // Now we will look over the inputs and try to encode them. Not that not all
        // of the corrections have beed received. In the case that the current item
        // is mapped to a bin where we do not have the correction, we will simply
        // skip this item for now. Once all corrections have been received, we
        // will make a second pass over the inputs and enocde them all.

        // the current input index
        u64 i = 0;

        // the index of the corrections that have been received in the other thread.
        u64 r = 0;

        // while not all the corrections have been recieved, try to encode any that we can
        while (r != numBins)
        {
            // process things in steps
            for (u64 j = 0; j < stepSize; ++j)
            {
                // lets check a random item to see if it can be encoded. If so,
                // we will write this item's encodings in the myMaskBuff at position i.
                auto inputIdx = mPermute[i];

                // for each hash function, try to encode the item.
                for (u64 h = 0; h < mParams.mNumHashes; ++h)
                {
                    auto& bIdx = binIdxs(inputIdx, h);

                    // if the bin index is less than r, then we have recieved
                    // the correction and can encode it
                    if (bIdx < r)
                    {
                        // write the encoding into myMaskBuff at position  i, h
                        auto encoding = myMaskBuff.data() + (i * mParams.mNumHashes + h) * myMaskBuff.stride();
                        mOtSender->encode(bIdx, &inputs[inputIdx], encoding, myMaskBuff.stride());

                        // make this location as already been encoded
                        bIdx = -1;
                    }
                }

                // wrap around the input looking for items that we can encode
                i = (i + 1) % inputs.size();
            }

            // after stepSize attempts to encode items, lets see if more
            // corrections have arrived.
            r = recvedIdx.load(std::memory_order::memory_order_acquire);
        }


        setTimePoint("kkrt.S Online.linear start");
        auto encoding = myMaskBuff.data();

        // OK, all corrections have been recieved. It is now safe to start sending
        // masks to the reciever. We will send them in permuted order
        //     mPermute[0],
        //     mPermute[1],
        //        ...
        //     mPermute[mSenderSize]
        //
        // Also note that we can start sending them before all have been
        // encoded. This will allow us to start communicating data back to the
        // reciever almost right after all the corrections have been recieved.
        for (u64 i = 0; i < inputs.size();)
        {
            auto start = i;
            auto currentStepSize = std::min(stepSize, inputs.size() - i);

            for (u64 j = 0; j < currentStepSize; ++j, ++i)
            {

                // get the next input that we should encode
                auto inputIdx = mPermute[i];

                for (u64 h = 0; h < mParams.mNumHashes; ++h)
                {

                    auto bIdx = binIdxs(inputIdx, h);

                    // see if we have alreadt encoded this items
                    if (bIdx != -1)
                    {
                        mOtSender->encode(bIdx, &inputs[inputIdx], encoding, myMaskBuff.stride());
                    }
                    encoding += myMaskBuff.stride();
                }
            }

            // send over next currentStepSize * * mParams.mNumHashes masks
            auto data = myMaskBuff.data() + myMaskBuff.stride() * start * mParams.mNumHashes;
            auto size = myMaskBuff.stride() * currentStepSize * mParams.mNumHashes;
            chl.asyncSend(data, size);
        }
        setTimePoint("kkrt.S Online.done start");

        // send one byte to make sure that we dont leave this scope before the masks
        // have all been sent.
        // TODO: fix this.
        u8 dummy[1];
        chl.send(dummy, 1);


        thrd.join();
    }
}


#endif