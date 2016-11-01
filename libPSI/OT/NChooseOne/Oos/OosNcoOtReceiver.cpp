#include "OT/Base/naor-pinkas.h"
#include "OosNcoOtReceiver.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include  <mmintrin.h>
#include "OosDefines.h"
using namespace std;

namespace osuCrypto
{

    //void OosNcoOtReceiver::setBaseOts(
    //    ArrayView<std::array<block, 2>> baseRecvOts)
    //{


    //    if (baseRecvOts.size() % 128 != 0)
    //        throw std::runtime_error("rt error at " LOCATION);

    //    mGens.resize(baseRecvOts.size());

    //    for (int i = 0; i < mGens.size(); i++)
    //    {
    //        mGens[i][0].SetSeed(baseRecvOts[i][0]);
    //        mGens[i][1].SetSeed(baseRecvOts[i][1]);
    //    }
    //    mHasBase = true;
    //}


    //void OosNcoOtReceiver::init(
    //    MatrixView<std::array<block, 2>> correlatedMsgs)
    //{
    //    u64 doneIdx = 0;
    //    if (mHasBase == false)
    //        throw std::runtime_error("rt error at " LOCATION);

    //    auto numOTExt = ((correlatedMsgs.size()[0] + 127) / 128) * 128;

    //    // we are going to process SSOTs in blocks of 128 messages.
    //    u64 numBlocks = numOTExt / 128;

    //    std::array<block, 128> t0;
    //    std::array<block, 128> t1;

    //    u64 numCols = mGens.size();

    //    // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
    //    //   Instead we break it down into smaller chunks. For each of the
    //    //   numCol columns that we have, we generate 128 bits/rows of data.
    //    //   This results in a matrix with 128 rows and numCol columns. 
    //    //   Transposing each 128 * 128 sub-matrix will then give us the
    //    //   next 128 rows, i.e. the transpose of the original.
    //    for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
    //    {
    //        // compute at what row does the user want use to stop.
    //        // the code will still compute the transpose for these
    //        // extra rows, but it is thrown away.
    //        u32 stopIdx
    //            = doneIdx
    //            + std::min(u64(128), correlatedMsgs.size()[0] - doneIdx);

    //        for (u64 i = 0; i < numCols / 128; ++i)
    //        {

    //            for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
    //            {
    //                // use the base key from the base OTs to 
    //                // extend the i'th column of t0 and t1    
    //                t0[tIdx] = mGens[colIdx][0].get<block>();
    //                t1[tIdx] = mGens[colIdx][1].get<block>();
    //            }


    //            // transpose t0 in place
    //            sse_transpose128(t0);
    //            sse_transpose128(t1);

    //            for (u64 rowIdx = doneIdx, tIdx = 0; rowIdx < stopIdx; ++rowIdx, ++tIdx)
    //            {
    //                correlatedMsgs[rowIdx][i][0] = t0[tIdx];
    //                correlatedMsgs[rowIdx][i][1] = t1[tIdx];
    //            }

    //        }

    //        doneIdx = stopIdx;
    //    }
    //}
    //std::unique_ptr<NcoOtExtReceiver> OosNcoOtReceiver::split()
    //{
    //    auto* raw = new OosNcoOtReceiver(mCode);

    //    std::vector<std::array<block,2>> base(mGens.size());

    //    for (u64 i = 0; i < base.size(); ++i)
    //    {
    //        base[i][0] = mGens[i][0].get<block>();
    //        base[i][1] = mGens[i][1].get<block>();
    //    }
    //    raw->setBaseOts(base);

    //    return std::unique_ptr<NcoOtExtReceiver>(raw);
    //}

    void OosNcoOtReceiver::encode(
        // the output of the init function. The two correlated OT messages that
        // the receiver gets from the base OTs
        const ArrayView<std::array<block, 2>> correlatedMgs,
        // The random code word that should be encoded
        const ArrayView<block> plaintxt,
        // Output: the message that should be sent to the sender
        ArrayView<block> otCorrectionMessage,
        // Output: the encoding of the plaintxt
        block & val)
    {
#ifndef NDEBUG
        u64 expectedSize = mCode.codewordBlkSize();

        if (otCorrectionMessage.size() != expectedSize ||
            correlatedMgs.size() != expectedSize ||
            plaintxt.size() != mCode.plaintextBlkSize())
            throw std::invalid_argument(LOCATION);

        if (expectedSize > 10)
            throw std::runtime_error("increase the block array size (below)." LOCATION);
#endif // !NDEBUG

        // use this for two thing, to store the code word and 
        // to store the zero message from base OT matrix transposed.
        std::array<block, 10> codeword;

        mCode.encode(plaintxt, codeword);


         
#ifdef AES_HASH
        std::array<block, 10>  hashOut;
        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            otCorrectionMessage[i]
                = codeword[i]
                ^ correlatedMgs[i][0]
                ^ correlatedMgs[i][1];

            // reuse the codeword buffer as where we will store the hash preimage
            codeword[i] = correlatedMgs[i][0];
        }

        // compute the AES hash H(x) = AES(x_1) + x_1 + ... + AES(x_n) + x_n 
        mAesFixedKey.ecbEncBlocks(codeword.data(), correlatedMgs.size(), hashOut.data());

        val = ZeroBlock;
        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            val = val ^ codeword[i] ^ hashOut[i];
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


    void OosNcoOtReceiver::getParams(
        u64 compSecParm,
        u64 statSecParam,
        u64 inputBitCount,
        u64 inputCount,
        u64 & inputBlkSize,
        u64 & baseOtCount)
    {

        auto ncoPlainBitCount = mCode.plaintextBitSize();
        auto logn = std::ceil(std::log2(inputCount));

        // we assume that the sender will hash their items first. That mean
        // we need the hash output (input to the OT/code) to be the statistical 
        // security parameter + log_2(n) bits, e.g. 40 + log_2(2^20) = 60.
        if (statSecParam + logn > ncoPlainBitCount)
            throw std::runtime_error("");

        inputBlkSize = mCode.plaintextBlkSize();

        TODO("check to see if things still work if we dont have a multiple of 128...");
        baseOtCount = mCode.codewordBlkSize() * 128;
    }
}
