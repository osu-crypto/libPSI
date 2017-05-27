#include "KkrtPsiSender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/naor-pinkas.h"
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
        chl.asyncSend(&myHashSeeds, sizeof(block));
        //std::cout <<IoStream::lock << "send: sending PSI seed " << myHashSeeds << std::endl << IoStream::unlock;


        block theirHashingSeeds;
        auto fu = chl.asyncRecv(&theirHashingSeeds, sizeof(block));

        // init Simple hash
        mCuckooParams = CuckooIndex::selectParams(mRecverSize, statSec, true);
        if (mCuckooParams.mNumHashes != 3) throw std::runtime_error(LOCATION);

        otSend.configure(false, 40, 128);

        //mIndex.init(cuckoo.mBins.size(), mSenderSize, statSec, cuckoo.mParams.mNumHashes);

        //do base OT
        if (otSend.hasBaseOts() == false)
        {
            NaorPinkas baseBase;
            std::array<std::array<block, 2>, 128> baseBaseOT;
            baseBase.send(baseBaseOT, mPrng, chl);

            IknpOtExtReceiver base;
            BitVector baseChoice(otSend.getBaseOTCount());
            baseChoice.randomize(mPrng);
            std::vector<block> baseOT(otSend.getBaseOTCount());
            base.setBaseOts(baseBaseOT);
            base.receive(baseChoice, baseOT, mPrng, chl);

            otSend.setBaseOts(baseOT, baseChoice);
        }

        fu.get();
        //std::cout << IoStream::lock << "send: recved PSI seed " << theirHashingSeeds << std::endl << IoStream::unlock;

        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        otSend.init(mCuckooParams.numBins() + mCuckooParams.mStashSize, mPrng, chl);

        mOtSender = &otSend;
        //gTimer.setTimePoint("s InitS.extFinished");
    }


    void KkrtPsiSender::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs, chls);
    }

    void KkrtPsiSender::sendInput(span<block> inputs, span<Channel> chls)
    {
        if (inputs.size() != mSenderSize)
            throw std::runtime_error("rt error at " LOCATION);


        auto& chl = chls[0];
        u64 maskSize = (mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8; //by byte


        //======================Bucket BINs (not stash)==========================

        AES hasher(mHashingSeed);

        gTimer.setTimePoint("S Online.perm start");
        auto binCount = mCuckooParams.numBins();
        //u64 cntMask = mBins.mN;
        Matrix<u8> myMaskBuff(mSenderSize * 3, maskSize);

        //std::vector<std::unordered_map<u64, u8>> bins(mCuckooParams.numBins());
        //for (u64 i = 0; i < bins.size(); ++i)
        //    bins[i].reserve(mSenderSize / bins.size() * 1.2);
        SimpleIndex mIndex;

        mIndex.init(binCount, mSenderSize, mStatSecParam, mCuckooParams.mNumHashes);
        mIndex.insertItems(inputs, mHashingSeed);
        //create permute array to add my mask in the permuted positions
        std::vector<u64>permute(mSenderSize);
        for (u64 i = 0; i < mSenderSize; ++i) permute[i] = i;

        //permute position
        std::shuffle(permute.begin(), permute.end(), mPrng);


        gTimer.setTimePoint("S Online.perm done");

        //std::array<block, 16> buff;
        //for (u64 i = 0; i < mSenderSize; )
        //{
        //    auto min = std::min<u64>(mSenderSize - i, buff.size());

        //    hasher.ecbEncBlocks(inputs.data() + i, min, buff.data());

        //    for (u64 j = 0; j < min; ++i, ++j)
        //    {
        //        buff[j] = buff[j] ^ inputs[i];

        //        // make sure that we only save the smallest h for when two h map an item to the same bin.
        //        for (u64 h = 0; h < mCuckooParams.mNumHashes; ++h)
        //        {
        //            auto bIdx = CuckooIndex::getHash(buff[j], h, binCount);
        //            auto ret = bins[bIdx].emplace(i,h);

        //            // failed to insert due to collision, fill mask with junk.
        //            if (ret.second == false)
        //            {
        //                auto pos = permute[i] * 3 + h;
        //                mPrng.get(myMaskBuff[pos].data(), maskSize);

        //                block ss =ZeroBlock;
        //                memcpy(&ss, myMaskBuff[pos].data(), maskSize);
        //                //std::cout << " h collision at input[" << i << "] = " << inputs[i] << "  h = " << (int)h << "  -> " << ss  << "  " << *(u64*)&ss << std::endl;
        //            }
        //        }
        //    }
        //}



        //pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
        TODO("run in parallel");
        auto binStart = 0;
        auto binEnd = mCuckooParams.numBins();

        u64 stepSize = 1 << 10;

        gTimer.setTimePoint("S Online.computeBucketMask start");

        //for each batch
        for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
        {
            // compute the  size of the current step and the end index
            auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
            auto stepEnd = stepIdx + currentStepSize;


            mOtSender->recvCorrection(chl, currentStepSize);


            // loop all the bins in this step.
            for (u64 bIdx = stepIdx, j = 0; bIdx < stepEnd; ++bIdx, ++j)
            {
                // current bin.
                auto itemIter = mIndex.mBins.data() + bIdx * mIndex.mBins.stride();
                auto itemEnd = itemIter + mIndex.mBinSizes[bIdx];

                // for each item, hash it, encode then hash it again. 
                //for (u64 i = 0; i < mBins.mBinSizes[bIdx]; ++i)
                while (itemIter != itemEnd)
                {
                    auto idx = itemIter->idx();
                    auto h = itemIter->hashIdx();

                    auto pos = permute[idx] * 3 + h;
                    if (itemIter->isCollision() == false)
                    {
                        mOtSender->encode(bIdx, &inputs[idx], myMaskBuff.data() + pos * myMaskBuff.stride(), maskSize);
                    }
                    else
                    {
                        mPrng.get(myMaskBuff.data() + pos * myMaskBuff.stride(), maskSize);
                    }

                    block encoding = ZeroBlock;
                    memcpy(&encoding, myMaskBuff[pos].data(), maskSize);
                    //std::cout << "s input[" << idx << "] = " << inputs[idx] << " h = " << (int)h << " bIdx = " << bIdx << " -> " << encoding << "  " << *(u64*)&encoding  << "  collision " << itemIter->isCollision() << std::endl;

                    ++itemIter;
                }
            }
        }

        gTimer.setTimePoint("S Online.computeBucketMask done");
        chl.asyncSend(std::move(myMaskBuff));


        //======================STASH BIN==========================

        //receive theirStashCorrOTMasksBuff
        //ByteStream theirStashCorrOTMasksBuff;
        //chl.recv(theirStashCorrOTMasksBuff);
        //auto theirStashCorrOT = theirStashCorrOTMasksBuff.getSpan<blockBop>();
        //if (theirStashCorrOT.size() != mNumStash)
        //    throw std::runtime_error("rt error at " LOCATION);

        //// now compute mask for each of the stash elements
        //for (u64 stashIdx = 0, otIdx = mBins.mBinCount; stashIdx < mNumStash; ++stashIdx, ++otIdx)
        //{
        //    std::unique_ptr<ByteStream> myStashMasksBuff(new ByteStream());
        //    myStashMasksBuff->resize(mSenderSize* maskSize);

        //    //cntMask = mSenderSize;
        //    std::vector<u64> stashPermute(mSenderSize);
        //    int idxStashDone = 0;
        //    for (u64 i = 0; i < mSenderSize; i++)
        //        stashPermute[i] = i;

        //    //permute position
        //    std::shuffle(stashPermute.begin(), stashPermute.end(), prng);

        //    //compute mask
        //    for (u64 i = 0; i < inputs.size(); ++i)
        //    {
        //        codeWord.elem[0] = aesHashBuffs[0][i];
        //        codeWord.elem[1] = aesHashBuffs[1][i];
        //        codeWord.elem[2] = aesHashBuffs[2][i];
        //        codeWord.elem[3] = aesHashBuffs[3][i];

        //        codeWord = mPsiRecvSSOtMessages[stashIdx] ^ ((theirStashCorrOT[stashIdx] ^ codeWord) & blk448Choice);


        //        sha1.Reset();
        //        sha1.Update((u8*)&codeWord, codeWordSize);
        //        sha1.Final(hashBuff);

        //        // copy mask into the buffer in permuted pos
        //        memcpy(myStashMasksBuff->data() + stashPermute[idxStashDone++] * maskSize, hashBuff, maskSize);
        //    }

        //    //check the size of mask
        //    if (mSenderSize != myStashMasksBuff->size() / maskSize)
        //    {
        //        Log::out << "myMaskByteIter != myMaskBuff->data() + myMaskBuff->size()" << Log::endl;
        //        throw std::runtime_error("rt error at " LOCATION);
        //    }
        //    chl.asyncSend(std::move(myStashMasksBuff));
        //}
    }
}


