#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/ArrayView.h"

namespace osuCrypto
{
    //// a list of {{set size, bit size}}
    //std::vector<std::array<u64, 2>> binSizes
    //{
    //    {1<<12, 18},
    //    {1<<16, 19},
    //    {1<<20, 20},
    //    {1<<24, 21}
    //};


    class SimpleHasher
    {
    public:
        SimpleHasher();
        ~SimpleHasher();

        typedef std::vector<u64> MtBin;
        //typedef std::vector<std::pair<u64, block>> MtBin;

        u64 mBinCount , mMaxBinSize/*, mRepSize, mInputBitSize*/, mN;

        std::unique_ptr<std::mutex[]> mMtx;
        std::vector<MtBin> mBins;
        block mHashSeed;

        void print() const;

        void init(u64 n, u64 numBits, block hashSeed, u64 secParam, double binScaler);

        //void preHashedInsertItems(ArrayView<block> items, u64 itemIdx);
        //void insertItemsWithPhasing(ArrayView<block> items, u64 itemIdx);
    };

}
