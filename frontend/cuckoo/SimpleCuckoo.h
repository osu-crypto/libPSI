#pragma once
#include "Common/Defines.h"
#include "Common/Log.h"
#include "Common/BitVector.h"
#include "Common/ArrayView.h"
#include "Common/MatrixView.h"
//#include <mutex>
#include <atomic>
#include "MPSI/Beta/CuckooHasher.h"
//#define THREAD_SAFE_CUCKOO

namespace osuCrypto
{

    class SimpleCuckoo
    {
    public:
        SimpleCuckoo();
        ~SimpleCuckoo();

        struct Bin
        {
            Bin() :mVal(-1) {}
            Bin(u64 idx, u64 hashIdx) : mVal(idx | (hashIdx << 56)) {}

            bool isEmpty() const;
            u64 idx() const;
            u64 hashIdx() const;

            void swap(u64& idx, u64& hashIdx);
#ifdef THREAD_SAFE_CUCKOO
            Bin(const Bin& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            Bin(Bin&& b) : mVal(b.mVal.load(std::memory_order_relaxed)) {}
            std::atomic<u64> mVal;
#else
            Bin(const Bin& b) : mVal(b.mVal) {}
            Bin(Bin&& b) : mVal(b.mVal) {}
            u64 mVal;
#endif
        };
        struct Workspace
        {
            Workspace(u64 n, u64 h)
                : curAddrs(n)
                , curHashIdxs(n)
                , oldVals(n)
                , findVal(n, h)
            {}

            std::vector<u64>
                curAddrs,   
                curHashIdxs,
                oldVals;    

            MatrixView<u64>   findVal;
        };



        u64 mTotalTries;

        bool operator==(const SimpleCuckoo& cmp)const;
        bool operator!=(const SimpleCuckoo& cmp)const;

        //std::mutex mStashx;

        CuckooParam mParams;

        void print() const;
        void init(u64 n, u64 statSecParam, bool multiThreaded);

        void insertBatch(ArrayView<u64> itemIdxs, MatrixView<u64> hashs, Workspace& workspace);

        u64 findBatch(MatrixView<u64> hashes, 
            ArrayView<u64> idxs,
            Workspace& wordkspace);


        u64 stashUtilization();
    private:

        std::vector<u64> mHashes;
        MatrixView<u64> mHashesView;

        std::vector<Bin> mBins;
        std::vector<Bin> mStash;

        //std::vector<Bin> mBins;
        //std::vector<Bin> mStash;


        //void insertItems(std::array<std::vector<block>,4>& hashs);
    };

}
