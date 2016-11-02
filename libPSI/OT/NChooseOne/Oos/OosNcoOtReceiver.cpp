#include "OT/Base/naor-pinkas.h"
#include "OosNcoOtReceiver.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include  <mmintrin.h>
#include "OosDefines.h"
using namespace std;

namespace osuCrypto
{
    void OosNcoOtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseRecvOts)
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
    void OosNcoOtReceiver::init(u64 numOtExt)
    {
        u64 doneIdx = 0;
        if (mHasBase == false)
            throw std::runtime_error("rt error at " LOCATION);


        const u8 superBlkSize(8);

        TODO("Make the statistical sec param a parameter");
        u64 statSecParam = 40;

        numOtExt = roundUpTo(numOtExt + statSecParam, 128);

        u64 numBlocks = numOtExt / 128;

        u64 numSuperBlocks = (numBlocks + superBlkSize - 1) / superBlkSize;

        std::array<std::array<block, superBlkSize>, 128> t0;
        std::array<std::array<block, superBlkSize>, 128> t1;

        u64 numCols = mGens.size();
        u64 extraDoneIdx = 0;

        mW = std::move(MatrixView<block>(numOtExt, mCode.plaintextBlkSize()));
        mT0 = std::move(MatrixView<block>(numOtExt, numCols / 128));
        mT1 = std::move(MatrixView<block>(numOtExt, numCols / 128));

        // NOTE: We do not transpose a bit-matrix of size numCol * numCol.
        //   Instead we break it down into smaller chunks. We do 128 columns 
        //   times 8 * 128 rows at a time, where 8 = superBlkSize. This is done for  
        //   performance reasons. The reason for 8 is that most CPUs have 8 AES vector  
        //   lanes, and so its more efficient to encrypt (aka prng) 8 blocks at a time.
        //   So thats what we do. 
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // compute at what row does the user want us to stop.
            // The code will still compute the transpose for these
            // extra rows, but it is thrown away.
            u64 stopIdx
                = doneIdx
                + std::min(u64(128) * superBlkSize, numOtExt - doneIdx);

            // This is the stop index for the extra rows.  
            u64 extraStopIdx = std::min((stopIdx - doneIdx) - u64(128) * superBlkSize, statSecParam - extraDoneIdx);

            for (u64 i = 0; i < numCols / 128; ++i)
            {

                for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
                {
                    // generate the column indexed by colIdx. This is done with
                    // AES in counter mode acting as a PRNG. We dont use the normal
                    // PRNG interface because that would result in a data copy when 
                    // we mode it into the T0,T1 matrices. Instead we do it directly.
                    mGens[colIdx][0].mAes.ecbEncCounterMode(mGens[colIdx][0].mBlockIdx, superBlkSize, t0[tIdx].data());
                    mGens[colIdx][1].mAes.ecbEncCounterMode(mGens[colIdx][1].mBlockIdx, superBlkSize, t1[tIdx].data());

                    // increment the counter mode idx.
                    mGens[colIdx][0].mBlockIdx += superBlkSize;
                    mGens[colIdx][1].mBlockIdx += superBlkSize;
                }


                // transpose t0, t1 in place
                sse_transpose128x1024(t0);
                sse_transpose128x1024(t1);

                // Now copy the transposed data into the correct spot.
                u64 j = 0, k = 0;
                for (u64 rowIdx = doneIdx; rowIdx < stopIdx; ++j)
                {
                    for (k = 0; rowIdx < stopIdx && k < 128; ++rowIdx, ++k)
                    {
                        mT0[rowIdx][i] = t0[k][j];
                        mT1[rowIdx][i] = t1[k][j];
                    }
                }
            }

            // If we wanted streaming OTs, aka you already know your 
            // choices, do the encode here.... 
            extraDoneIdx = extraStopIdx;
            doneIdx = stopIdx;
        }

    }


    std::unique_ptr<NcoOtExtReceiver> OosNcoOtReceiver::split()
    {
        auto* raw = new OosNcoOtReceiver(mCode);

        std::vector<std::array<block, 2>> base(mGens.size());

        for (u64 i = 0; i < base.size(); ++i)
        {
            base[i][0] = mGens[i][0].get<block>();
            base[i][1] = mGens[i][1].get<block>();
        }
        raw->setBaseOts(base);

        return std::unique_ptr<NcoOtExtReceiver>(raw);
    }

    void OosNcoOtReceiver::encode(
        u64 otIdx,
        // The random code word that should be encoded
        const ArrayView<block> choice,
        // Output: the encoding of the plaintxt
        block & val)
    {
#ifndef NDEBUG
        if (choice.size() != mT0.size()[1])
            throw std::invalid_argument("");

        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extenion");
#endif // !NDEBUG

        // use this for two thing, to store the code word and 
        // to store the zero message from base OT matrix transposed.
        std::array<block, 10> codeword;

        mCode.encode(choice, codeword);

        for (u64 i = 0; i < mW.size()[1]; ++i)
        {
            mW[otIdx][i] = choice[i];
        }

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
        for (u64 i = 0; i < mT0.size()[1]; ++i)
        {
            // reuse mT1 as the place we store the correlated value. 
            // this will later get sent to the sender.
            mT1[otIdx][i]
                = codeword[i]
                ^ mT0[otIdx][i]
                ^ mT1[otIdx][i];
        }

        sha1.Update((u8*)mT0[otIdx].data(), mT0[otIdx].size() * sizeof(block));

        u8 hashBuff[SHA1::HashSize];
        sha1.Final(hashBuff);
        val = toBlock(hashBuff);
#endif

    }

    void OosNcoOtReceiver::zeroEncode(u64 otIdx)
    {
#ifndef NDEBUG
        if (eq(mT0[otIdx][0], ZeroBlock))
            throw std::runtime_error("uninitialized OT extenion");
#endif // !NDEBUG

        for (u64 i = 0; i < mT0.size()[1]; ++i)
        {
            // encode the zero message. We assume the zero message is a valie codeword.
            // Also, reuse mT1 as the place we store the correlated value. 
            // this will later get sent to the sender.
            mT1[otIdx][i]
                = mT0[otIdx][i]
                ^ mT1[otIdx][i];
        }
    }


    void OosNcoOtReceiver::getParams(
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

        TODO("check to see if things still work if we dont have a multiple of 128...");
        baseOtCount = mCode.codewordBlkSize() * 128;
    }
    void OosNcoOtReceiver::sendCorrection(Channel & chl, u64 sendCount)
    {

        // this is potentially dangerous. We dont have a guarantee that mT1 will still exist when 
        // the network gets around to sending this. Oh well.
        TODO("Make this memory safe");
        chl.asyncSend(mT1.data() + (mCorrectionIdx * mT1.size()[1]), mT1.size()[1] * sendCount * sizeof(block));

        mCorrectionIdx += sendCount;
    }
    void OosNcoOtReceiver::check(Channel & chl)
    {
    }
}
