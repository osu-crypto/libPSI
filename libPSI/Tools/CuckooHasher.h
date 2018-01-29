#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"

#include "cryptoTools/Common/MatrixView.h"
//#include <mutex>
#include <atomic>

#include <cryptoTools/Common/CuckooIndex.h>

#define THREAD_SAFE_CUCKOO_HASHER

namespace osuCrypto
{
    //struct CuckooParam
    //{
    //    u64 mStashSize;
    //    double mBinScaler;
    //    u64 mNumHashes, mN;// , mSenderBinSize;
    //};



    class CuckooHasher
    {
    public:
        CuckooHasher();
        ~CuckooHasher();

        struct Bin
        {
            Bin() :mVal(-1) {}
            Bin(u64 idx, u64 hashIdx) : mVal(idx | (hashIdx << 56)) {}

            bool isEmpty() const;
            u64 idx() const;
            u64 hashIdx() const;

            void swap(u64& idx, u64& hashIdx);
#ifdef THREAD_SAFE_CUCKOO_HASHER
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
            Workspace(u64 n)
                : curAddrs(n)
                , curHashIdxs(n)
                , oldVals(n)
                //, findAddr(n)
                , findVal(n)
            {}

            std::vector<u64>
                curAddrs,// (inputIdxs.size(), 0),
                curHashIdxs,// (inputIdxs.size(), 0),
                oldVals;// (inputIdxs.size());

            std::vector<std::array<u64, 2>> /*findAddr,*/ findVal;
        };


        bool mPrint = true;
        u64 mTotalTries;

        bool operator==(const CuckooHasher& cmp)const;
        bool operator!=(const CuckooHasher& cmp)const;

        //std::mutex mStashx;

        CuckooParam mParams;

        void print() const;
        void init(u64 n, u64 statSecParam, bool multiThreaded);
        void insert(u64 IdxItem, span<u64> hashes);
        void insertHelper(u64 IdxItem, u64 hashIdx, u64 numTries);

        void insertBatch(span<u64> itemIdxs, MatrixView<u64> hashs, Workspace& workspace);

        u64 find(span<u64> hashes);
        u64 findBatch(MatrixView<u64> hashes,
            span<u64> idxs,
            Workspace& wordkspace);

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
