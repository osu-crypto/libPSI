#include "BchCode.h"
#include <fstream>
#include "Common/BitVector.h"
#include "Common/Log.h"

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
                // sBlock works as an if statment, but its faster...
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[*bitIter++]);
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
                codeword[3] = codeword[3] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
        case 4:
            for (u64 i = 0, k = 0; i < cnt; ++i)
            {
                u8 b = *bitIter++;
                codeword[0] = codeword[0] ^ (mG[k++] & sBlockMasks[b]);
                codeword[1] = codeword[1] ^ (mG[k++] & sBlockMasks[b]);
                codeword[2] = codeword[2] ^ (mG[k++] & sBlockMasks[b]);
                codeword[3] = codeword[3] ^ (mG[k++] & sBlockMasks[b]);
            }
            break;
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
