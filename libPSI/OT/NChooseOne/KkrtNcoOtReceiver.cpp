#include "OT/Base/naor-pinkas.h"
#include "KkrtNcoOtReceiver.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include  <mmintrin.h>
#include "KkrtDefines.h"
using namespace std;

namespace osuCrypto
{
    void KkrtNcoOtReceiver::setBaseOts(
        ArrayView<std::array<block, 2>> baseRecvOts)
    {


        if (baseRecvOts.size() % 128 != 0)
            throw std::runtime_error("rt error at " LOCATION);

        mGens.resize(baseRecvOts.size());

        for (int i = 0; i < mGens.size(); i++)
        {
            mGens[i][0].SetSeed(baseRecvOts[i][0]);
            mGens[i][1].SetSeed(baseRecvOts[i][1]);
        }
        mHasBase = true;
    }


    void KkrtNcoOtReceiver::init(
        MatrixView<std::array<block, 2>> correlatedMsgs)
    {
        u64 doneIdx = 0;
        if (mHasBase == false)
            throw std::runtime_error("rt error at " LOCATION);

        const u8 superBlkSize(8);

        u64 numBlocks = (correlatedMsgs.size()[0] + 127) / 128;
        u64 numSuperBlocks = (numBlocks + superBlkSize - 1) / superBlkSize;

        std::array<std::array<block, superBlkSize>, 128> t0;
        std::array<std::array<block, superBlkSize>, 128> t1;

        //std::array<block, 128> t00;


        u64 numCols = mGens.size();

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. For each of the
        //   numCol columns that we have, we generate 128 bits/rows of data.
        //   This results in a matrix with 128 rows and numCol columns. 
        //   Transposing each 128 * 128 sub-matrix will then give us the
        //   next 128 rows, i.e. the transpose of the original.
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
                    mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, superBlkSize, t0[tIdx].data());
                    mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, superBlkSize, t1[tIdx].data());

                    mGens[colIdx][0].mBlockIdx += superBlkSize;
                    mGens[colIdx][1].mBlockIdx += superBlkSize;

                    // use the base key from the base OTs to 
                    // extend the i'th column of t0 and t1    
                    //t0[tIdx] = mGens[colIdx][0].get<block>();
                    //t1[tIdx] = mGens[colIdx][1].get<block>();

                    //for (u64 j = 0; j < superBlkSize; ++j)
                    //{
                    //    t0[tIdx][j] = mGens[colIdx][0].get<block>();
                    //    t1[tIdx][j] = mGens[colIdx][1].get<block>();
                    //}

                    //t00[tIdx] = t0[tIdx][0];
                }


                // transpose t0 in place
                sse_transpose128x1024(t0);
                sse_transpose128x1024(t1);

                //sse_transpose128(t00);

                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        correlatedMsgs[rowIdx][i][0] = t0[k][j];
                        correlatedMsgs[rowIdx][i][1] = t1[k][j];

                        //if (j == 0)
                        //{
                        //    if (neq(correlatedMsgs[rowIdx][i][0], t00[k]))
                        //    {
                        //        throw std::runtime_error("");
                        //    }
                        //}
                    }
                }

            }

            doneIdx = stopIdx;
        }
    }
    std::unique_ptr<NcoOtExtReceiver> KkrtNcoOtReceiver::split()
    {
        auto* raw = new KkrtNcoOtReceiver();

        std::vector<std::array<block, 2>> base(mGens.size());

        for (u64 i = 0; i < base.size(); ++i)
        {
            base[i][0] = mGens[i][0].get<block>();
            base[i][1] = mGens[i][1].get<block>();
        }
        raw->setBaseOts(base);

        return std::unique_ptr<NcoOtExtReceiver>(raw);
    }

    void KkrtNcoOtReceiver::encode(
        // the output of the init function. The two correlated OT messages that
        // the receiver gets from the base OTs
        const ArrayView<std::array<block, 2>> correlatedMgs,
        // The random code word that should be encoded
        const ArrayView<block> codeword,
        // Output: the message that should be sent to the sender
        ArrayView<block> otCorrectionMessage,
        // Output: the encoding of the codeword
        block & val)
    {
#ifndef NDEBUG
        u64 expectedSize = mGens.size() / (sizeof(block) * 8);

        if (otCorrectionMessage.size() != expectedSize ||
            correlatedMgs.size() != expectedSize ||
            codeword.size() != expectedSize)
            throw std::invalid_argument("");
#endif // !NDEBUG

#ifdef AES_HASH
        std::array<block, 10> correlatedZero, hashOut;
        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            otCorrectionMessage[i]
                = codeword[i]
                ^ correlatedMgs[i][0]
                ^ correlatedMgs[i][1];

            correlatedZero[i] = correlatedMgs[i][0];
        }

        // compute the AES hash H(x) = AES(x_1) + x_1 + ... + AES(x_n) + x_n 
        mAesFixedKey.ecbEncBlocks(correlatedZero.data(), correlatedMgs.size(), hashOut.data());

        val = ZeroBlock;
        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            val = val ^ correlatedZero[i] ^ hashOut[i];
}
#else
        SHA1  sha1;
        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            otCorrectionMessage[i]
                = codeword[i]
                ^ correlatedMgs[i][0]
                ^ correlatedMgs[i][1];

            sha1.Update((u8*)&correlatedMgs[i][0], sizeof(block));
        }

        u8 hashBuff[SHA1::HashSize];
        sha1.Final(hashBuff);
        val = toBlock(hashBuff);
#endif

}

    void KkrtNcoOtReceiver::getParams(
        u64 compSecParm,
        u64 statSecParam,
        u64 inputBitCount,
        u64 inputCount,
        u64 & inputBlkSize,
        u64 & baseOtCount)
    {
        baseOtCount = roundUpTo(compSecParm * 7, 128);
        inputBlkSize = baseOtCount / 128;
    }

}
