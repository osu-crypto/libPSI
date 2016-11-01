#include "BchCode.h"
#include <fstream>
#include "Common/BitVector.h"
#include "Common/Log.h"
#define BITSET
#include <bitset>


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
        auto iter = mG.begin();

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

        u64 size = mG.size();
        out.read((char *)&size, sizeof(u64));
        out.read((char *)&mCodewordBitSize, sizeof(u64));

        mG.resize(size);
        out.read((char *)mG.data(), mG.size() * sizeof(block));
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
        for (u64 j = 0; j < codeword.size(); ++j)
            codeword[j] = ZeroBlock;

        // use an outer swich to speed up the inner loop;
        switch (codewordBlkSize())
        {
        case 1:
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                // sBlock works as an if statment, but its faster...
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 2:
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 3:
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
                codeword[2] = codeword[2] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 4:
            //for (u64 i = 0, k = 0; i < cnt; ++i)
            //{
            //    u8 b = *bitIter++;
            //    codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
            //    codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
            //    codeword[2] = codeword[2] ^ (mG[k++] & sBlockMasks[b]);
            //    codeword[3] = codeword[4] ^ (mG[k++] & sBlockMasks[b]);
            //}
            //break;
        {
            std::array<block, 8> 
                b, 
                t{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock}, 
                c{ ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock};

            std::array<u8, 128>& bb = *(std::array<u8, 128>*)&b;

            block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

            if (cnt != 76)
                throw std::runtime_error(LOCATION);

            //for (u64 i = 0, k = 0; i < plaintxt.size(); ++i)
            {
                //const std::bitset<128> b((u8*)&plaintxt[i],16);
                static const u64 stop = 76;// std::min(u64(128), cnt - (i * 128));
                static const u64 i = 0;


                // b[i] holds 16 bytes \in {0,1}. the j'th byte of b, b[i][j] 
                //    holds the (i + j * 8)'th bit of plaintext[i]. That is,
                //    if we view plaintext[i] as 16 bytes, the b[i] holds the 
                //    i'th bit of each byte. 
                //    Viewing b as a long array of bytes called bb, then 
                //    bb[(j / 8) + (j % 8) * 16] is the j'th bit of plaintext[i].
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

                    for(u64 l =0; l < 4 && row < stop; ++l, k += 8, row += 2, j0 += 32, j1 += 32)
                    {

                        t[0 ] = (mG[k     ] & sBlockMasks[*j0]);
                        t[1 ] = (mG[k + 1 ] & sBlockMasks[*j0]);
                        t[2 ] = (mG[k + 2 ] & sBlockMasks[*j0]);
                        t[3 ] = (mG[k + 3 ] & sBlockMasks[*j0]);
                        t[4 ] = (mG[k + 4 ] & sBlockMasks[*j1]);
                        t[5 ] = (mG[k + 5 ] & sBlockMasks[*j1]);
                        t[6 ] = (mG[k + 6 ] & sBlockMasks[*j1]);
                        t[7 ] = (mG[k + 7 ] & sBlockMasks[*j1]);

                        c[0 ] = c[0 ] ^ t[0 ];
                        c[1 ] = c[1 ] ^ t[1 ];
                        c[2 ] = c[2 ] ^ t[2 ];
                        c[3 ] = c[3 ] ^ t[3 ];
                        c[4 ] = c[4 ] ^ t[4 ];
                        c[5 ] = c[5 ] ^ t[5 ];
                        c[6 ] = c[6 ] ^ t[6 ];
                        c[7 ] = c[7 ] ^ t[7 ];
                    }
                }

                codeword[0] = c[0] ^ c[4];
                codeword[1] = c[1] ^ c[5];
                codeword[2] = c[2] ^ c[6];
                codeword[3] = c[3] ^ c[7];
            }

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
