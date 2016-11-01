#include "KkrtNcoOtSender.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "KkrtDefines.h"

namespace osuCrypto
{
    //#define OTEXT_DEBUG
    //#define    PRINT_OTEXT_DEBUG
    using namespace std;

    void KkrtNcoOtSender::setBaseOts(
        ArrayView<block> baseRecvOts,
        const BitVector & choices)
    {
        if (choices.size() != baseRecvOts.size())
            throw std::runtime_error("size mismatch");

        if (choices.size() % (sizeof(block) * 8) != 0)
            throw std::runtime_error("only multiples of 128 are supported");


        mBaseChoiceBits = choices;
        mGens.resize(choices.size());

        for (int i = 0; i < baseRecvOts.size(); i++)
        {
            mGens[i].SetSeed(baseRecvOts[i]);
        }

        mChoiceBlks.resize(choices.size() / (sizeof(block) * 8));
        for (u64 i = 0; i < mChoiceBlks.size(); ++i)
        {
            mChoiceBlks[i] = toBlock(mBaseChoiceBits.data() + (i * sizeof(block)));
        }
    }

    std::unique_ptr<NcoOtExtSender> KkrtNcoOtSender::split()
    {
        auto* raw = new KkrtNcoOtSender();
        
        std::vector<block> base(mGens.size());

        for (u64 i = 0; i < base.size();++i)
        {
            base[i] = mGens[i].get<block>();
        }
        raw->setBaseOts(base, mBaseChoiceBits);

        return std::unique_ptr<NcoOtExtSender>(raw);
    }

    void KkrtNcoOtSender::init(
        MatrixView<block> correlatedMsgs)
    {
        const u8 superBlkSize(8);

        // round up
        u64 numOTExt = ((correlatedMsgs.size()[0] + 127) / 128) * 128;

        // we are going to process SSOTs in blocks of 128 messages.
        u64 numBlocks = numOTExt / 128;
        u64 numSuperBlocks = (numBlocks + superBlkSize - 1) / superBlkSize;

        u64 doneIdx = 0;

        std::array<std::array<block,superBlkSize>, 128> q;

        u64 numCols = mGens.size();

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. For each of the
        //   numCol columns that we have, we generate 128 bits/rows of data.
        //   This results in a matrix with 128 rows and numCol columns. 
        //   Transposing each 128 * 128 sub-matrix will then give us the
        //   next 128 rows, i.e. the transpose of the original.
        //for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
        //{
        //    // compute at what row does the user want use to stop.
        //    // the code will still compute the transpose for these
        //    // extra rows, but it is thrown away.
        //    u32 stopIdx
        //        = doneIdx
        //        + std::min(u64(128), correlatedMsgs.size()[0] - doneIdx);

        //    for (u64 i = 0; i < numCols / 128; ++i)
        //    {
        //        // for each segment of 128 rows, 
        //        // generate and transpose them
        //        for (u64 qIdx = 0, colIdx = 128 * i; qIdx < 128; ++qIdx, ++colIdx)
        //        {
        //            q[qIdx] = mGens[colIdx].get<block>();
        //        }

        //        sse_transpose128(q);

        //        for (u64 rowIdx = doneIdx, qIdx = 0; rowIdx < stopIdx; ++rowIdx, ++qIdx)
        //        {
        //            correlatedMsgs[rowIdx][i] = q[qIdx];
        //        }
        //    }

        //    doneIdx = stopIdx;
        //}

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want use to stop.
            // the code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u32 stopIdx
                = doneIdx
                + std::min(u64(128) * superBlkSize, correlatedMsgs.size()[0] - doneIdx);

            for (u64 i = 0; i < numCols / 128; ++i)
            {

                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, q[tIdx].data());

                    mGens[colIdx].mBlockIdx += superBlkSize;

                    // use the base key from the base OTs to 
                    // extend the i'th column of t0 and t1    
                    //t0[tIdx] = mGens[colIdx][0].get<block>();
                    //t1[tIdx] = mGens[colIdx][1].get<block>();

                    //for (u64 j = 0; j < superBlkSize; ++j)
                    //{
                    //    q[tIdx][j] = mGens[colIdx].get<block>();
                    //}

                }


                sse_transpose128x1024(q);


                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        correlatedMsgs[rowIdx][i] = q[k][j];
                    }
                }

            }

            doneIdx = stopIdx;
        }
    }

    void KkrtNcoOtSender::encode(
        const ArrayView<block> correlatedMgs,
        const ArrayView<block> codeword,
        const ArrayView<block> otCorrectionMessage,
        block& val)
    {

#ifndef NDEBUG
        u64 expectedSize = mGens.size() / (sizeof(block) * 8);

        if (otCorrectionMessage.size() != expectedSize ||
            correlatedMgs.size() != expectedSize ||
            codeword.size() != expectedSize)
            throw std::invalid_argument("");
#endif // !NDEBUG

#ifdef AES_HASH
        std::array<block,10> sums, hashOut;

        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            sums[i] = correlatedMgs[i] ^
                (otCorrectionMessage[i] ^ codeword[i]) & mChoiceBlks[i];
        }
        // compute the AES hash H(x) = AES(x_1) + x_1 + ... + AES(x_n) + x_n 
        mAesFixedKey.ecbEncBlocks(sums.data(), correlatedMgs.size(), hashOut.data());

        val = ZeroBlock;
        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            val = val ^ sums[i] ^ hashOut[i];
        }
#else
        SHA1  sha1;
        block sum;
        u8 hashBuff[SHA1::HashSize];

        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            sum = correlatedMgs[i] ^
                (otCorrectionMessage[i] ^ codeword[i]) & mChoiceBlks[i];

            sha1.Update((u8*)&sum,  sizeof(block));
        }

        sha1.Final(hashBuff);
        val = toBlock(hashBuff);

#endif // AES_HASH

    }

    void KkrtNcoOtSender::getParams(
        u64 compSecParm, 
        u64 statSecParam,
        u64 inputBitCount, 
        u64 inputCount, 
        u64 & inputBlkSize, 
        u64 & baseOtCount)
    {
        baseOtCount =roundUpTo(compSecParm * 7, 128);
        inputBlkSize = baseOtCount / 128;
    }


}
