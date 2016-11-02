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

        for (u64 i = 0; i < base.size(); ++i)
        {
            base[i] = mGens[i].get<block>();
        }
        raw->setBaseOts(base, mBaseChoiceBits);

        return std::unique_ptr<NcoOtExtSender>(raw);
    }





    void OosNcoOtSender::init(
        u64 numOTExt)
    {
        const u8 superBlkSize(8);

        u64 statSecParm = 40;

        // round up
        numOTExt = ((numOTExt + 127 + statSecParm) / 128) * 128;

        mCorrectionVals = std::move(MatrixView<block>(numOTExt, mGens.size() / 128));
        mT = std::move(MatrixView<block>(numOTExt, mGens.size() / 128));
        mCorrectionIdx = 0;

        // we are going to process SSOTs in blocks of 128 messages.
        u64 numBlocks = numOTExt / 128;
        u64 numSuperBlocks = (numBlocks + superBlkSize - 1) / superBlkSize;

        u64 doneIdx = 0;

        std::array<std::array<block, superBlkSize>, 128> t;

        u64 numCols = mGens.size();


        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want use to stop.
            // the code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min(u64(128) * superBlkSize, mT.size()[0] - doneIdx);

            for (u64 i = 0; i < numCols / 128; ++i)
            {

                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    mGens[colIdx].mAes.ecbEncCounterMode(mGens[colIdx].mBlockIdx, superBlkSize, t[tIdx].data());
                    mGens[colIdx].mBlockIdx += superBlkSize;
                }

                sse_transpose128x1024(t);

                for (u64 rowIdx = doneIdx, j = 0; rowIdx < stopIdx; ++j)
                {
                    for (u64 k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        mT[rowIdx][i] = t[k][j];
                    }
                }

            }

            doneIdx = stopIdx;
        }
    }


    void OosNcoOtSender::encode(
        u64 otIdx,
        const ArrayView<block> plaintext,
        block& val)
    {

#ifndef NDEBUG
        u64 expectedSize = mGens.size() / (sizeof(block) * 8);

        if (plaintext.size() != mCode.plaintextBlkSize())
            throw std::invalid_argument("");
#endif // !NDEBUG
        std::array<block, 10> codeword;
        mCode.encode(plaintext, codeword);

#ifdef AES_HASH
        std::array<block,10> hashOut;

        for (u64 i = 0; i < mT.size(); ++i)
        {
            // use this codeword buffer for two things, the codeword
            // itself and as a hash input buffer.
            codeword[i] = mT[i] ^
                (otCorrectionMessage[i] ^ codeword[i]) & mChoiceBlks[i];
        }

        // compute the AES hash H(x) = AES(x_1) + x_1 + ... + AES(x_n) + x_n 
        mAesFixedKey.ecbEncBlocks(codeword.data(), mT.size(), hashOut.data());

        val = ZeroBlock;
        for (u64 i = 0; i < mT.size(); ++i)
        {
            val = val ^ codeword[i] ^ hashOut[i];
        }
#else
        SHA1  sha1;
        u8 hashBuff[SHA1::HashSize];

        for (u64 i = 0; i < mT.size()[1]; ++i)
        {
            codeword[i] 
                = mT[otIdx][i] 
                ^ (mCorrectionVals[otIdx][i] ^ codeword[i]) & mChoiceBlks[i];
        }

        sha1.Update((u8*)codeword.data(),  sizeof(block) * mT.size()[1]);
        sha1.Final(hashBuff);
        val = toBlock(hashBuff);

#endif // AES_HASH

    }

    void OosNcoOtSender::getParams(
        bool maliciousSecure,
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

        baseOtCount = mCode.codewordBlkSize() * 128;
    }

    void OosNcoOtSender::recvCorrection(Channel & chl, u64 recvCount)
    {

#ifndef NDEBUG
        if (recvCount > mCorrectionVals.size()[0] - mCorrectionIdx)
            throw std::runtime_error("bad reciever, will overwrite the end of our buffer" LOCATION);

#endif // !NDEBUG        


        auto* dest = mCorrectionVals.begin() + (mCorrectionIdx * mCorrectionVals.size()[1]);
        chl.recv(dest,
            recvCount * sizeof(block) * mCorrectionVals.size()[1]);

        mCorrectionIdx += recvCount;
    }

    void OosNcoOtSender::check(Channel & chl)
    {
    }


}
