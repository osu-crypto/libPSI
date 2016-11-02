#include "BchCode.h"
#include <fstream>
#include "Common/BitVector.h"
#include "Common/Log.h"
#define BITSET
#include <bitset>

#include "Common/MatrixView.h"
namespace osuCrypto
{

    BchCode::BchCode()
    {
    }

    BchCode::~BchCode()
    {
    }

    void BchCode::loadTxtFile(const std::string & fileName)
    {
        std::ifstream in;
        in.open(fileName, std::ios::in);

        if (in.is_open() == false)
        {
            Log::out << "failed to open:\n     " << fileName << Log::endl;
            throw std::runtime_error("");
        }

        loadTxtFile(in);
    }

    void BchCode::loadTxtFile(std::istream & in)
    {
        u64 numRows, numCols;
        in >> numRows >> numCols;
        mCodewordBitSize = numCols;

        mG.resize(numRows * ((numCols + 127) / 128));
        //mG1.resize(numRows * ((numCols + 127) / 128));
        
        auto iter = mG.begin();
        //auto iter1 = mG1.begin();

        BitVector buff;
        buff.reserve(roundUpTo(numCols, 128));
        buff.resize(numCols);

        //u32 v;
        std::string line;
        std::getline(in, line);

        for (u64 i = 0; i < numRows; ++i)
        {
            memset(buff.data(), 0, buff.sizeBytes());
            std::getline(in, line);

#ifndef NDEBUG
            if (line.size() != 2 * numCols - 1)
                throw std::runtime_error("");
#endif
            for (u64 j = 0; j < numCols; ++j)
            {

#ifndef NDEBUG
                if (line[j * 2] - '0' > 1)
                    throw std::runtime_error("");
#endif
                buff[j] = line[j * 2] - '0';;
            }

            block* blkView = (block*)buff.data();
            for (u64 j = 0, k = 0; j < numCols; j += 128, ++k)
            {
                *iter++ = blkView[k];
            }
        }
    }
    void BchCode::loadBinFile(const std::string & fileName)
    {
        std::fstream out;
        out.open(fileName, std::ios::in | std::ios::binary);

        loadBinFile(out);

    }
    void BchCode::loadBinFile(std::istream & out)
    {

        u64 size =0;

        out.read((char *)&size, sizeof(u64));
        out.read((char *)&mCodewordBitSize, sizeof(u64));

        if (mCodewordBitSize == 0)
        {
            Log::out << "bad code " << Log::endl;
            throw std::runtime_error(LOCATION);
        }

        mG.resize(size);
        //mG1.resize(size);
        //mG2.resize(size / 2);
        mG8.resize(roundUpTo((size + 7 )/ 8, 8));

        out.read((char *)mG.data(), mG.size() * sizeof(block));

        generateMod8Table();
        //for (u64 i = 0; i < size; ++i)
        //{
        //    mG1[i][0] = ZeroBlock;
        //    mG1[i][1] = mG[i];
        //}
        //for (u64 i = 0; i < size / 2; ++i)
        //{
        //    mG2[i][0] = ZeroBlock;
        //    mG2[i][1] = mG[i];
        //}

    }

    void BchCode::writeBinFile(const std::string & fileName)
    {
        std::fstream out;
        out.open(fileName, std::ios::out | std::ios::binary | std::ios::trunc);

        writeBinFile(out);

    }
    void BchCode::writeBinFile(std::ostream & out)
    {
        u64 size = mG.size();
        out.write((const char *)&size, sizeof(u64));
        out.write((const char *)&mCodewordBitSize, sizeof(u64));

        out.write((const char *)mG.data(), mG.size() * sizeof(block));
    }

    void BchCode::generateMod8Table()
    {

        memset(mG8.data(), 0, mG8.size() * sizeof(std::array<block, 256>));

        MatrixView<block> g(mG.begin(), mG.end(), codewordBlkSize());
        MatrixView<std::array<block, 256>> g8(mG8.begin(), mG8.end(), codewordBlkSize());


        for (u64 i = 0; i < g8.size()[0]; ++i)
        {
            //std::array<std::vector<u64>, 256> counts;

            for (u64 gRow = 0; gRow < 8; ++gRow)
            {
                u64 g8Row = (1 << gRow);
                u64 stride = g8Row;

                while (g8Row < 256)
                {
                    do
                    {
                        if (i * 8 + gRow < g.size()[0])
                        {

                            //counts[g8Row].push_back(gRow);

                            for (u64 wordIdx = 0; wordIdx < codewordBlkSize(); ++wordIdx)
                            {
                                g8[i][wordIdx][g8Row] 
                                    = g8[i][wordIdx][g8Row]  
                                    ^ g[i * 8 + gRow][wordIdx];
                            }
                        }

                        ++g8Row;
                    } while (g8Row % stride);

                    g8Row += stride;
                }
            }


            //block exp = ZeroBlock;// = g[i * 8 + 0][0] ^ g[i * 8 + 1][0];
            //for (u64 j = 0; j < 8; ++j)
            //{
            //    if(i * 8 + j < g.size()[0])
            //        exp = exp ^ g[i * 8 + j][0];
            //}

            //if (neq(exp, g8[i][0][255]))
            //{
            //    Log::out << "failed " << i << Log::endl;
            //    Log::out << g8[i][0][255] << "  " << g8[i][0][0] << Log::endl;
            //    Log::out <<exp << "  " << ZeroBlock << Log::endl;
            //}

            //if (i == 0)
            //{

            //    for (u64 j = 0; j < 256; ++j)
            //    {
            //        Log::out << j << ":  ";

            //        u64 k = 0, b = 0;
            //        while (k < counts[j].size())
            //        {
            //            if (b == counts[j][k])
            //            {
            //                Log::out << "1";
            //                ++k;
            //            }
            //            else
            //            {
            //                Log::out << "0";
            //            }
            //            ++b;
            //        }
            //        //for (u64 k = 0; k < counts[j].size(); ++k)
            //        //{
            //        //    if (k) Log::out << ",";
            //        //    Log::out << " " << counts[j][k];
            //        //}
            //        Log::out << Log::endl;
            //    }
            //    Log::out << Log::endl;
            //}
        }
    }

    u64 BchCode::plaintextBlkSize() const
    {
        return (plaintextBitSize() + 127) / 128;
    }

    u64 BchCode::plaintextBitSize() const
    {
        return mG.size() / codewordBlkSize();
    }

    u64 BchCode::codewordBlkSize() const
    {
        return (codewordBitSize() + 127) / 128;
    }

    u64 BchCode::codewordBitSize() const
    {
        return mCodewordBitSize;
    }


    static std::array<block, 2> sBlockMasks{ { ZeroBlock, AllOneBlock } };

    void BchCode::encode(
        ArrayView<block> plaintxt,
        ArrayView<block> codeword)
    {
#ifndef NDEBUG
        if (plaintxt.size() != plaintextBlkSize() ||
            codeword.size() < codewordBlkSize())
            throw std::runtime_error("");
#endif

        BitIterator bitIter((u8*)plaintxt.data(), 0);

        u64 cnt = plaintextBitSize();

        // use an outer swich to speed up the inner loop;
        switch (codewordBlkSize())
        {
        case 1:
            codeword[0] = ZeroBlock;

            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                // sBlock works as an if statment, but its faster...
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 2:
            codeword[0] = ZeroBlock;
            codeword[1] = ZeroBlock;

            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 3:
            codeword[0] = ZeroBlock;
            codeword[1] = ZeroBlock;
            codeword[2] = ZeroBlock;

            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
                codeword[2] = codeword[2] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 4:

        {

#define G8
#ifdef G8

            std::array<block, 8>
                c{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock };

                u8* byteView = (u8*)plaintxt.data();
                u64 byteCount = roundUpTo(cnt, 8) / 8,
                    kStop = (mG8.size() / 8) * 8,
                    k = 0, 
                    i = 0;

                for (; k < kStop; i += 2, k += 8)
                {
                    c[0] = c[0] ^ mG8[k + 0][byteView[i]];
                    c[1] = c[1] ^ mG8[k + 1][byteView[i]];
                    c[2] = c[2] ^ mG8[k + 2][byteView[i]];
                    c[3] = c[3] ^ mG8[k + 3][byteView[i]];

                    c[4] = c[4] ^ mG8[k + 4][byteView[i + 1]];
                    c[5] = c[5] ^ mG8[k + 5][byteView[i + 1]];
                    c[6] = c[6] ^ mG8[k + 6][byteView[i + 1]];
                    c[7] = c[7] ^ mG8[k + 7][byteView[i + 1]];
                }

                codeword[0] = c[0] ^ c[4];
                codeword[1] = c[1] ^ c[5];
                codeword[2] = c[2] ^ c[6];
                codeword[3] = c[3] ^ c[7];
#else
            std::array<block, 8>
                b, b2,
                t{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock },
                c{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock };

            std::array<u8, 128>& bb = *(std::array<u8, 128>*)&b;

            block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);


            if (cnt != 76)
                throw std::runtime_error(LOCATION);
            //for (u64 i = 0, k = 0; i < plaintxt.size(); ++i)
            {
                //const std::bitset<128> b((u8*)&plaintxt[i],16);
                static const u64 stop = 76;// std::min(u64(128), cnt - (i * 128));
                static const u64 i = 0;

                // b[i] holds 16 bytes \in {0,1}. the g8Row'th byte of b, b[i][g8Row] 
                //    holds the (i + g8Row * 8)'th bit of plaintext[i]. That is,
                //    if we view plaintext[i] as 16 bytes, the b[i] holds the 
                //    i'th bit of each byte. 
                //    Viewing b as a long array of bytes called bb, then 
                //    bb[(g8Row / 8) + (g8Row % 8) * 16] is the g8Row'th bit of plaintext[i].
                //    Also, _mm_srai_epi16(p,i) is just  p >> i. At least for us it is.
                b[0] = mask & plaintxt[i];
                b[1] = mask & _mm_srai_epi16(plaintxt[i], 1);
                b[2] = mask & _mm_srai_epi16(plaintxt[i], 2);
                b[3] = mask & _mm_srai_epi16(plaintxt[i], 3);
                b[4] = mask & _mm_srai_epi16(plaintxt[i], 4);
                b[5] = mask & _mm_srai_epi16(plaintxt[i], 5);
                b[6] = mask & _mm_srai_epi16(plaintxt[i], 6);
                b[7] = mask & _mm_srai_epi16(plaintxt[i], 7);

                // we now iterate throw the bits of plaintext[i]. But keep in mind 
                // they are out of order now. 
                for (u64 row = 0, k = 0; row < stop; )
                {
                    auto
                        *j0 = bb.data() + row / 8,
                        *j1 = bb.data() + row / 8 + 16;

                    for (u64 l = 0; l < 4 && row < stop; ++l, k += 8, row += 2, j0 += 32, j1 += 32)
                    {
                        t[0] = (mG[k] & sBlockMasks[*j0]);
                        t[1] = (mG[k + 1] & sBlockMasks[*j0]);
                        t[2] = (mG[k + 2] & sBlockMasks[*j0]);
                        t[3] = (mG[k + 3] & sBlockMasks[*j0]);
                        t[4] = (mG[k + 4] & sBlockMasks[*j1]);
                        t[5] = (mG[k + 5] & sBlockMasks[*j1]);
                        t[6] = (mG[k + 6] & sBlockMasks[*j1]);
                        t[7] = (mG[k + 7] & sBlockMasks[*j1]);

                        c[0] = c[0] ^ t[0];
                        c[1] = c[1] ^ t[1];
                        c[2] = c[2] ^ t[2];
                        c[3] = c[3] ^ t[3];
                        c[4] = c[4] ^ t[4];
                        c[5] = c[5] ^ t[5];
                        c[6] = c[6] ^ t[6];
                        c[7] = c[7] ^ t[7];
                    }
                }

                codeword[0] = c[0] ^ c[4];
                codeword[1] = c[1] ^ c[5];
                codeword[2] = c[2] ^ c[6];
                codeword[3] = c[3] ^ c[7];
            }
#endif // G8

            break;
            }
        case 5:
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
                codeword[2] = codeword[2] ^ (mG[k++] & sBlockMasks[b]);
                codeword[3] = codeword[3] ^ (mG[k++] & sBlockMasks[b]);
                codeword[4] = codeword[4] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 6:
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
                codeword[2] = codeword[2] ^ (mG[k++] & sBlockMasks[b]);
                codeword[3] = codeword[3] ^ (mG[k++] & sBlockMasks[b]);
                codeword[4] = codeword[4] ^ (mG[k++] & sBlockMasks[b]);
                codeword[5] = codeword[5] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        default:

            // just to use a general for loop, slower...
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                for (u64 j = 0; j < codeword.size(); ++j, ++k)
                {
                    // sBlock works as an if statment, but its faster...
                    codeword[j] = codeword[j] ^ (mG[k] & sBlockMasks[*bitIter++]);
                }
            }
            break;
        }
        }



    }
