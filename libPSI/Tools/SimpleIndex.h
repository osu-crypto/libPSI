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
    /*{
        return mVal == u64(-1);
    }

    u64 CuckooIndex::Bin::idx() const
    {
        return mVal  & (u64(-1) >> 8);
    }

    u64 CuckooIndex::Bin::hashIdx() const
    {
        return mVal >> 56;*/

    class SimpleIndex
    {
    public:


        struct Item
        {
            Item() :mVal(-1) {}

            bool isEmpty() const { return mVal == -1; }
            u64 idx() const { return mVal  & (u64(-1) >> 8); }
            u64 hashIdx() const { return ((u8*)&mVal)[7] & 127; }
            bool isCollision() const { return  ((u8*)&mVal)[7] >> 7; }

            void set(u64 idx, u8 hashIdx, bool collision)
            {
                mVal = idx;
                ((u8*)&mVal)[7] = hashIdx | ((collision & 1) << 7);
            }
#ifdef THREAD_SAFE_SIMPLE_INDEX
            Item(const Item& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            Item(Item&& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            std::atomic<u64> mVal;
#else
            Item(const Item& b) : mVal(b.mVal) {}
            Item(Item&& b) : mVal(b.mVal) {}
            u64 mVal;
#endif
        };



        u64 mMaxBinSize, mNumHashFunctions;
        Matrix<Item> mBins;
        std::vector<u64> mBinSizes;
        block mHashSeed;
        void print() ;


        void init(u64 numBins, u64 simpleSize, u64 statSecParam = 40, u64 numHashFunction = 3);
        void insertItems(span<block> items, block hashingSeed);
    };

}
