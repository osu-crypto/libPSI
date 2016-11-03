#include "OosNcoOtSender.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include "OosDefines.h"
#include "Common/ByteStream.h"
namespace osuCrypto
{
    //#define OTEXT_DEBUG
    //#define    PRINT_OTEXT_DEBUG
    using namespace std;

    OosNcoOtSender::~OosNcoOtSender()
    {
        //Log::out << "destruct" << Log::endl;
    }

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

        SHA1  sha1;
        u8 hashBuff[SHA1::HashSize];

        auto* corVal = mCorrectionVals.data() + otIdx * mCorrectionVals.size()[1];
        auto* tVal = mT.data() + otIdx * mT.size()[1];

        for (u64 i = 0; i < mT.size()[1]; ++i)
        {
            block t0 = corVal[i] ^ codeword[i];
            block t1 = t0 & mChoiceBlks[i];

            codeword[i]
                = tVal[i]
                ^ t1;
        }

        sha1.Update((u8*)codeword.data(), sizeof(block) * mT.size()[1]);
        sha1.Final(hashBuff);
        val = toBlock(hashBuff);


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


        auto dest = mCorrectionVals.begin() + (mCorrectionIdx * mCorrectionVals.size()[1]);
        chl.recv(dest,
            recvCount * sizeof(block) * mCorrectionVals.size()[1]);

        mCorrectionIdx += recvCount;
    }

    void OosNcoOtSender::check(Channel & chl)
    {

        block seed = ZeroBlock;
        u64 statSecParam(40);

        if (statSecParam % 8) throw std::runtime_error("Must be a multiple of 8. " LOCATION);

        recvCorrection(chl, statSecParam);
        chl.asyncSend(&seed, sizeof(block));
        AES aes(seed);
        u64 aesIdx(0);
        u64 k = 0;

        std::vector<block> qSum(statSecParam * mT.size()[1]);

        for (u64 i = 0; i < statSecParam; ++i)
        {
            for (u64 j = 0; j < mT.size()[1]; ++j)
            {
                qSum[i * mT.size()[1] + j]
                    = (mCorrectionVals[mCorrectionIdx - statSecParam + i][j]
                        & mChoiceBlks[j])
                    ^ mT[mCorrectionIdx - statSecParam + i][j];
            }
        }


#ifdef OOS_CHECK_DEBUG
        Buff mT0Buff, mWBuff;
        chl.recv(mT0Buff);
        chl.recv(mWBuff);

        auto mT0 = mT0Buff.getMatrixView<block>(mCode.codewordBlkSize());
        auto mW = mWBuff.getMatrixView<block>(mCode.plaintextBlkSize());
#endif

        u64 codeSize = mT.size()[1];
        std::array<std::array<block, 8>, 2> zeroAndQ;
        if (codeSize < zeroAndQ.size()) throw std::runtime_error("Make this bigger. " LOCATION);
        memset(zeroAndQ.data(), 0, zeroAndQ.size() * 2 * sizeof(block));



        std::vector<block> challengeBuff(statSecParam);
        std::vector<block> expandedBuff(statSecParam * 8);
        block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
        u8* byteView = (u8*)expandedBuff.data();



        auto corIter = mCorrectionVals.data();
        auto tIter = mT.data();


        u64 lStop = (mCorrectionIdx - statSecParam + 127) / 128;
        for (u64 l = 0; l < lStop; ++l)
        {

            aes.ecbEncCounterMode(aesIdx, statSecParam, challengeBuff.data());
            aesIdx += statSecParam;
            for (u64 i = 0; i < statSecParam; ++i)
            {
                expandedBuff[i * 8 + 0] = mask & _mm_srai_epi16(challengeBuff[i], 0);
                expandedBuff[i * 8 + 1] = mask & _mm_srai_epi16(challengeBuff[i], 1);
                expandedBuff[i * 8 + 2] = mask & _mm_srai_epi16(challengeBuff[i], 2);
                expandedBuff[i * 8 + 3] = mask & _mm_srai_epi16(challengeBuff[i], 3);
                expandedBuff[i * 8 + 4] = mask & _mm_srai_epi16(challengeBuff[i], 4);
                expandedBuff[i * 8 + 5] = mask & _mm_srai_epi16(challengeBuff[i], 5);
                expandedBuff[i * 8 + 6] = mask & _mm_srai_epi16(challengeBuff[i], 6);
                expandedBuff[i * 8 + 7] = mask & _mm_srai_epi16(challengeBuff[i], 7);
            }

            u64 kk = k;
            u64 stopIdx = std::min(mCorrectionIdx - statSecParam - k, u64(128));
            k += 128;
            u8* byteIter = byteView;

            if (mT.size()[1] == 4)
            {
                //  vvvvvvvvvvvv   OPTIMIZED for codeword size 4   vvvvvvvvvvvv

                for (u64 i = 0; i < stopIdx; ++i, ++kk, corIter += 4, tIter += 4)
                {
                    auto q0 = (corIter[0] & mChoiceBlks[0]);
                    auto q1 = (corIter[1] & mChoiceBlks[1]);
                    auto q2 = (corIter[2] & mChoiceBlks[2]);
                    auto q3 = (corIter[3] & mChoiceBlks[3]);

                    zeroAndQ[1][0] = q0 ^ tIter[0];
                    zeroAndQ[1][1] = q1 ^ tIter[1];
                    zeroAndQ[1][2] = q2 ^ tIter[2];
                    zeroAndQ[1][3] = q3 ^ tIter[3];

#ifdef OOS_CHECK_DEBUG
                    std::vector<block> cw(mCode.codewordBlkSize());
                    mCode.encode(mW[kk], cw);

                    for (u64 j = 0; j < 4; ++j)
                    {
                        block tq = mT0[kk][j] ^ zeroAndQ[j][1];
                        block cb = cw[j] & mChoiceBlks[j];

                        if (neq(tq, cb))
                        {
                            throw std::runtime_error("");
                        }
                    }
#endif

                    auto qSumIter = qSum.data();

                    for (u64 j = 0; j < statSecParam / 2; ++j, qSumIter += 8)
                    {
                        u8 x0 = *byteIter++;
                        u8 x1 = *byteIter++;

                        block* mask0 = zeroAndQ[x0].data();
                        block* mask1 = zeroAndQ[x1].data();

                        qSumIter[0] = qSumIter[0] ^ mask0[0];
                        qSumIter[1] = qSumIter[1] ^ mask0[1];
                        qSumIter[2] = qSumIter[2] ^ mask0[2];
                        qSumIter[3] = qSumIter[3] ^ mask0[3];
                        qSumIter[4] = qSumIter[4] ^ mask1[0];
                        qSumIter[5] = qSumIter[5] ^ mask1[1];
                        qSumIter[6] = qSumIter[6] ^ mask1[2];
                        qSumIter[7] = qSumIter[7] ^ mask1[3];
                    }
                }

                //  ^^^^^^^^^^^^^   OPTIMIZED for codeword size 4   ^^^^^^^^^^^^^
            }
            else
            {
                //  vvvvvvvvvvvv       general codeword size        vvvvvvvvvvvv

                for (u64 i = 0; i < stopIdx; ++i, ++kk, corIter += codeSize, tIter += codeSize)
                {
                    for (u64 m = 0; m < codeSize; ++m)
                    {
                        zeroAndQ[1][m] = (corIter[m] & mChoiceBlks[m]) ^ tIter[m];
                    }

#ifdef OOS_CHECK_DEBUG
                    std::vector<block> cw(mCode.codewordBlkSize());
                    mCode.encode(mW[kk], cw);

                    for (u64 j = 0; j < codeSize; ++j)
                    {
                        block tq = mT0[kk][j] ^ zeroAndQ[j][1];
                        block cb = cw[j] & mChoiceBlks[j];

                        if (neq(tq, cb))
                        {
                            throw std::runtime_error("");
                        }
                    }
#endif
                    auto qSumIter = qSum.data();

                    for (u64 j = 0; j < statSecParam; ++j, qSumIter += codeSize)
                    {
                        block* mask0 = zeroAndQ[*byteIter++].data();
                        for (u64 m = 0; m < codeSize; ++m)
                        {
                            qSumIter[m] = qSumIter[m] ^ mask0[m];
                        }
                    }
                }

                //  ^^^^^^^^^^^^^      general codeword size        ^^^^^^^^^^^^^
            }
        }
         

        std::vector<block> tSum(statSecParam * mT.size()[1]);
        std::vector<block> wSum(statSecParam * mCode.plaintextBlkSize());

        chl.recv(tSum.data(), tSum.size() * sizeof(block));
        chl.recv(wSum.data(), wSum.size() * sizeof(block));

        std::vector<block> cw(mCode.codewordBlkSize());

        for (u64 i = 0; i < statSecParam; ++i)
        {
            ArrayView<block> word(
                wSum.begin() + i * mCode.plaintextBlkSize(),
                wSum.begin() + (i + 1) * mCode.plaintextBlkSize());

            mCode.encode(word, cw);

            for (u64 j = 0; j < cw.size(); ++j)
            {
                block tq = tSum[i * cw.size() + j] ^ qSum[i * cw.size() + j];
                block cb = cw[j] & mChoiceBlks[j];

                if (neq(tq, cb))
                {
                    //Log::out << "bad OOS16 OT check. " << i << "m " << j << Log::endl;
                    //return;
                    throw std::runtime_error("bad OOS16 OT check. " LOCATION);
                }
            }

        }

    }


}
