#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"


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

        //typedef std::vector<u64> MtBin;
        //typedef std::vector<std::pair<u64, block>> MtBin;

        u64 mBinCount , mMaxBinSize, mN;

        Matrix<u64> mBins_;
        std::unique_ptr<std::atomic<u8>[]> mBinSizes;
        block mHashSeed;

        inline void push(u64 binIdx, u64 value)
        {
            auto pos = mBinSizes[binIdx].fetch_add(1,std::memory_order::memory_order_relaxed);
            mBins_(binIdx, pos) = value;
        }

        inline span<u64> getBin(u64 binIdx)
        {
            return { mBins_.data(binIdx), getBinSize(binIdx) };
        }

        inline u8 getBinSize(u64 binIdx)
        {
            return mBinSizes[binIdx].load(std::memory_order::memory_order_relaxed);
        }

        void print() const;

        void init(u64 n, u64 numBits, block hashSeed, u64 secParam, double binScaler);

        //void preHashedInsertItems(ArrayView<block> items, u64 itemIdx);
        //void insertItemsWithPhasing(ArrayView<block> items, u64 itemIdx);
    };

}
