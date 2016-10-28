#include "OosNcoOtSender.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "OosDefines.h"

namespace osuCrypto
{
    //#define OTEXT_DEBUG
    //#define    PRINT_OTEXT_DEBUG
    using namespace std;

    void OosNcoOtSender::setBaseOts(
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

    std::unique_ptr<NcoOtExtSender> OosNcoOtSender::split()
    {
        auto* raw = new OosNcoOtSender(mCode);
        
        std::vector<block> base(mGens.size());

        for (u64 i = 0; i < base.size();++i)
        {
            base[i] = mGens[i].get<block>();
        }
        raw->setBaseOts(base, mBaseChoiceBits);

        return std::unique_ptr<NcoOtExtSender>(raw);
    }

    void OosNcoOtSender::init(
        MatrixView<block> correlatedMsgs)
    {
        // round up
        u64 numOTExt = ((correlatedMsgs.size()[0] + 127) / 128) * 128;

        // we are going to process SSOTs in blocks of 128 messages.
        u64 numBlocks = numOTExt / 128;

        u64 doneIdx = 0;

        std::array<block, 128> q;

        u64 numCols = mGens.size();

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. For each of the
        //   numCol columns that we have, we generate 128 bits/rows of data.
        //   This results in a matrix with 128 rows and numCol columns. 
        //   Transposing each 128 * 128 sub-matrix will then give us the
        //   next 128 rows, i.e. the transpose of the original.
        for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
        {
            // compute at what row does the user want use to stop.
            // the code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u32 stopIdx
                = doneIdx
                + std::min(u64(128), correlatedMsgs.size()[0] - doneIdx);

            for (u64 i = 0; i < numCols / 128; ++i)
            {
                // for each segment of 128 rows, 
                // generate and transpose them
                for (u64 qIdx = 0, colIdx = 128 * i; qIdx < 128; ++qIdx, ++colIdx)
                {
                    q[qIdx] = mGens[colIdx].get<block>();
                }

                sse_transpose128(q);

                for (u64 rowIdx = doneIdx, qIdx = 0; rowIdx < stopIdx; ++rowIdx, ++qIdx)
                {
                    correlatedMsgs[rowIdx][i] = q[qIdx];
                }
            }

            doneIdx = stopIdx;
        }
    } 

    void OosNcoOtSender::encode(
        const ArrayView<block> correlatedMgs,
        const ArrayView<block> plaintext,
        const ArrayView<block> otCorrectionMessage,
        block& val)
    {

#ifndef NDEBUG
        u64 expectedSize = mGens.size() / (sizeof(block) * 8);

        if (otCorrectionMessage.size() != expectedSize ||
            correlatedMgs.size() != expectedSize ||
            plaintext.size() != mCode.plaintextBlkSize())
            throw std::invalid_argument("");
#endif // !NDEBUG
        std::array<block, 10> codeword;
        mCode.encode(plaintext, codeword);

#ifdef AES_HASH
        std::array<block,10> hashOut;

        for (u64 i = 0; i < correlatedMgs.size(); ++i)
        {
            // use this codeword buffer for two things, the codeword
            // itself and as a hash input buffer.
            codeword[i] = correlatedMgs[i] ^
                (otCorrectionMessage[i] ^ codeword[i]) & mChoiceBlks[i];
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

    void OosNcoOtSender::getParams(
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
