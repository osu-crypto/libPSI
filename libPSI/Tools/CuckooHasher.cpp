#include "CuckooHasher.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include <numeric>
#include "cryptoTools/Common/CuckooIndex.h"
namespace osuCrypto
{
     
    //// parameters for k=2 hash functions, 2^n items, and statistical security 40
    //CuckooParam k2n32s40CuckooParam
    //{ 4, 2.4, 2, u64(1) << 32 };
    //CuckooParam k2n30s40CuckooParam
    //{ 4, 2.4, 2, u64(1) << 30 };
    //CuckooParam k2n28s40CuckooParam
    //{ 2, 2.4, 2, u64(1) << 28 };
    //CuckooParam k2n24s40CuckooParam
    //{ 2, 2.4, 2, u64(1) << 24 };
    //CuckooParam k2n20s40CuckooParam
    //{ 2, 2.4, 2, u64(1) << 20 };
    //CuckooParam k2n16s40CuckooParam
    //{ 3, 2.4, 2, u64(1) << 16 };
    //CuckooParam k2n12s40CuckooParam
    //{ 5, 2.4, 2, u64(1) << 12 };
    //CuckooParam k2n08s40CuckooParam
    //{ 8, 2.4, 2, u64(1) << 8 };

    //// not sure if this needs a stash of 40, but should be safe enough.
    //CuckooParam k2n07s40CuckooParam
    //{ 40, 2.4, 2, 1 << 7 };


    CuckooHasher::CuckooHasher()
        :mTotalTries(0)
    { }

    CuckooHasher::~CuckooHasher()
    {
    }

    bool CuckooHasher::operator==(const CuckooHasher & cmp) const
    {
        if (mBins.size() != cmp.mBins.size())
            throw std::runtime_error("");

        if (mStash.size() != cmp.mStash.size())
            throw std::runtime_error("");



        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].mVal != cmp.mBins[i].mVal)
            {
                return false;
            }
        }

        for (u64 i = 0; i < mStash.size(); ++i)
        {
            if (mStash[i].mVal != cmp.mStash[i].mVal)
            {
                return false;
            }
        }

        return true;
    }

    bool CuckooHasher::operator!=(const CuckooHasher & cmp) const
    {
        return !(*this == cmp);
    }

    void CuckooHasher::print() const
    {

        std::cout << "Cuckoo Hasher  " << std::endl;


        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "Bin #" << i;

            if (mBins[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mBins[i].idx() << "  hIdx=" << mBins[i].hashIdx() << std::endl;

            }

        }
        for (u64 i = 0; i < mStash.size() && mStash[i].isEmpty() == false; ++i)
        {
            std::cout << "Bin #" << i;

            if (mStash[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mStash[i].idx() << "  hIdx=" << mStash[i].hashIdx() << std::endl;

            }

        }
        std::cout << std::endl;

    }

    void CuckooHasher::init(u64 n, u64 statSecParam, bool multiThreaded)
    {

        //mParams = CuckooIndex<>::selectParams(n, statSecParam, 0, 2);
        //
        if (statSecParam != 40) throw std::runtime_error("not implemented");

        ////std::cout << "Params: " << n << " " << std::log2(n) << std::endl;

        if (n <= 1 << 7)
            mParams = k2n07s40CuckooParam;
        else if (n <= u64(1) << 8)
            mParams = k2n08s40CuckooParam;
        else if (n <= u64(1) << 12)
            mParams = k2n12s40CuckooParam;
        else if (n <= u64(1) << 16)
            mParams = k2n16s40CuckooParam;
        else if (n <= u64(1) << 20)
            mParams = k2n20s40CuckooParam;
        else if (n <= u64(1) << 24)
            mParams = k2n24s40CuckooParam;
        else if (n <= u64(1) << 28)
            mParams = k2n28s40CuckooParam;
        else if (n <= u64(1) << 30)
            mParams = k2n30s40CuckooParam;
        else if (n <= u64(1) << 32)
            mParams = k2n32s40CuckooParam;
        else
        {
            std::cout << "Failed to find cuckoo parameters large enough  "<< n << " " << std::log2(n) << "\n" LOCATION << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            throw std::runtime_error("not implemented " LOCATION);
        }


        mHashes.resize(n * mParams.mNumHashes, u64(-1));


        mHashesView = MatrixView<u64>(mHashes.begin(), mHashes.end(), mParams.mNumHashes);

        u64 binCount = u64(mParams.mBinScaler * mParams.mN);

        mBins.resize(binCount);
        mStash.resize(mParams.mStashSize);
    }

    void CuckooHasher::insert(u64 inputIdx, span<u64> hashs)
    {
        if (mHashesView[inputIdx][0] != u64(-1))
        {
            throw std::runtime_error("");
        }

        memcpy(mHashesView[inputIdx].data(), hashs.data(), sizeof(u64) * mParams.mNumHashes);

        insertHelper(inputIdx, 0, 0);
    }

    void CuckooHasher::insertBatch(
        span<u64> inputIdxs,
        MatrixView<u64> hashs,
        Workspace& w)
    {

        u64 width = mHashesView.bounds()[1];
        u64 remaining = inputIdxs.size();
        u64 tryCount = 0;

#ifndef  NDEBUG
        if (hashs.bounds()[1] != width)
            throw std::runtime_error("" LOCATION);
#endif // ! NDEBUG


        for (u64 i = 0; i < inputIdxs.size(); ++i)
        {
            for (u64 j = 0; j < mParams.mNumHashes; ++j)
            {
#ifndef  NDEBUG
                if ((mHashesView.data() + inputIdxs[i] * width)[j] != u64(-1))
                {
                    std::cout << IoStream::lock << "cuckoo index " << inputIdxs[i] << " already inserted" << std::endl << IoStream::unlock;
                    throw std::runtime_error(LOCATION);
                }
#endif // ! NDEBUG
                (mHashesView.data() + inputIdxs[i] * width)[j] = (hashs.data() + i * width)[j];

            }
            w.curHashIdxs[i] = 0;
        }


        while (remaining && tryCount++ < 100)
        {

            // this data fetch can be slow (after the first loop). 
            // As such, lets do several fetches in parallel.
            for (u64 i = 0; i < remaining; ++i)
            {
                //w.curAddrs[i] = mHashesView[inputIdxs[i]][w.curHashIdxs[i]] % mBins.size();
                w.curAddrs[i] = (mHashesView.data() + inputIdxs[i] * width)[w.curHashIdxs[i]] % mBins.size();
            }

            // same thing here, this fetch is slow. Do them in parallel.
            for (u64 i = 0; i < remaining; ++i)
            {
                u64 newVal = inputIdxs[i] | (w.curHashIdxs[i] << 56);
#ifdef THREAD_SAFE_CUCKOO_HASHER
                w.oldVals[i] = mBins[w.curAddrs[i]].mVal.exchange(newVal, std::memory_order_relaxed);
#else
                w.oldVals[i] = mBins[w.curAddrs[i]].mVal;
                mBins[w.curAddrs[i]].mVal = newVal;
#endif
//#ifndef  NDEBUG
                //if (newVal == w.oldVals[i])
                //    throw std::runtime_error(LOCATION);
//#endif // ! NDEBUG

            }

            // this loop will update the items that were just evicted. The main
            // idea of that our array looks like
            //     |XW__Y____Z __|
            // For X and W, which failed to be placed, lets write over them
            // with the vaues that they evicted.
            u64 putIdx = 0, getIdx = 0;
            while (putIdx < remaining && w.oldVals[putIdx] != u64(-1))
            {
                inputIdxs[putIdx] = w.oldVals[putIdx] & (u64(-1) >> 8);
                w.curHashIdxs[putIdx] = (1 + (w.oldVals[putIdx] >> 56)) % mParams.mNumHashes;
                ++putIdx;
            }

            getIdx = putIdx + 1;

            // Now we want an array that looks like 
            //  |ABCD___________| but currently have 
            //  |AB__Y_____Z____| so lets move them 
            // forward and replace Y, Z with the values
            // they evicted.
            while (getIdx < remaining)
            {
                while (getIdx < remaining &&
                    w.oldVals[getIdx] == u64(-1))
                    ++getIdx;

                if (getIdx >= remaining) break;

                inputIdxs[putIdx] = w.oldVals[getIdx] & (u64(-1) >> 8);
                w.curHashIdxs[putIdx] = (1 + (w.oldVals[getIdx] >> 56)) % mParams.mNumHashes;

                // not needed. debug only
                std::swap(w.oldVals[putIdx], w.oldVals[getIdx]);

                ++putIdx;
                ++getIdx;
            }

            remaining = putIdx;
        }

        // put any that remain in the stash.
        for (u64 i = 0, j = 0; i < remaining; ++j)
        {
            if (j >= mStash.size())
            {
                if (mPrint)std::cout << "stash overflow " << std::endl;
                throw std::runtime_error(LOCATION);
            }

            mStash[j].swap(inputIdxs[i], w.curHashIdxs[i]);

            if (inputIdxs[i] == u64(-1))
                ++i;
        }

    }



    void CuckooHasher::insertHelper(u64 inputIdx, u64 hashIdx, u64 numTries)
    {
        //++mTotalTries;

        u64 xrHashVal = mHashesView[inputIdx][hashIdx];

        auto addr = (xrHashVal) % mBins.size();

        // replaces whatever was in this bin with our new item
        //mBins[addr].swap(inputIdx, hashIdx);
        {

            u64 newVal = inputIdx | (hashIdx << 56);
#ifdef THREAD_SAFE_CUCKOO_HASHER
            u64 oldVal = mBins[addr].mVal.exchange(newVal, std::memory_order_relaxed);
#else
            u64 oldVal = mBins[addr].mVal;
            mBins[addr].mVal = newVal;
#endif

            if (oldVal == u64(-1))
            {
                inputIdx = u64(-1);
            }
            else
            {
                inputIdx = oldVal & (u64(-1) >> 8);
                hashIdx = oldVal >> 56;
            }
        }

        if (inputIdx != u64(-1))
        {

            // if idxItem is anything but -1, then we just exicted something. 
            if (numTries < 100)
            {
                // lets try to insert it into its next location
                insertHelper(inputIdx, (hashIdx + 1) % mParams.mNumHashes, numTries + 1);
            }
            else
            {
                // put in stash
                for (u64 i = 0; inputIdx != u64(-1); ++i)
                {
                    mStash[i].swap(inputIdx, hashIdx);
                }

            }
        }

    }



    u64 CuckooHasher::find(span<u64> hashes)
    {
        if (mParams.mNumHashes == 2)
        {
            std::array<u64, 2>  addr{
                (hashes[0]) % mBins.size(),
                (hashes[1]) % mBins.size() };

#ifdef THREAD_SAFE_CUCKOO_HASHER
            std::array<u64, 2> val{
                mBins[addr[0]].mVal.load(std::memory_order::memory_order_relaxed),
                mBins[addr[1]].mVal.load(std::memory_order::memory_order_relaxed) };
#else
            std::array<u64, 2> val{
                mBins[addr[0]].mVal,
                mBins[addr[1]].mVal };
#endif

            if (val[0] != u64(-1))
            {
                u64 itemIdx = val[0] & (u64(-1) >> 8);

                bool match =
                    (mHashesView[itemIdx][0] == hashes[0]) &&
                    (mHashesView[itemIdx][1] == hashes[1]);

                if (match) return itemIdx;
            }

            if (val[1] != u64(-1))
            {
                u64 itemIdx = val[1] & (u64(-1) >> 8);

                bool match =
                    (mHashesView[itemIdx][0] == hashes[0]) &&
                    (mHashesView[itemIdx][1] == hashes[1]);

                if (match) return itemIdx;
            }


            // stash

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
#ifdef THREAD_SAFE_CUCKOO_HASHER
                u64 val = mStash[i].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mStash[i].mVal;
#endif
                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match =
                        (mHashesView[itemIdx][0] == hashes[0]) &&
                        (mHashesView[itemIdx][1] == hashes[1]);

                    if (match)
                    {
                        return itemIdx;
                    }
                }

                ++i;
            }

        }
        else
        {

            for (u64 i = 0; i < mParams.mNumHashes; ++i)
            {
                u64 xrHashVal = hashes[i];
                auto addr = (xrHashVal) % mBins.size();


#ifdef THREAD_SAFE_CUCKOO_HASHER
                u64 val = mBins[addr].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mBins[addr].mVal;
#endif

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = true;
                    for (u64 j = 0; j < mParams.mNumHashes; ++j)
                    {
                        match &= (mHashesView[itemIdx][j] == hashes[j]);
                    }

                    if (match)
                    {
                        return itemIdx;
                    }
                }
            }

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
#ifdef THREAD_SAFE_CUCKOO_HASHER
                u64 val = mStash[i].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mStash[i].mVal;
#endif

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = true;
                    for (u64 j = 0; j < mParams.mNumHashes; ++j)
                    {
                        match &= (mHashesView[itemIdx][j] == hashes[j]);
                    }

                    if (match)
                    {
                        return itemIdx;
                    }
                }

                ++i;
            }
        }
        //}

        return u64(-1);
    }




    u64 CuckooHasher::findBatch(
        MatrixView<u64> hashes,
        span<u64> idxs,
        Workspace& w)
    {

        if (mParams.mNumHashes == 2)
        {
            std::array<u64, 2>  addr;

            for (u64 i = 0; i < hashes.bounds()[0]; ++i)
            {
                idxs[i] = -1;

                addr[0] = (hashes[i][0]) % mBins.size();
                addr[1] = (hashes[i][1]) % mBins.size();

#ifdef THREAD_SAFE_CUCKOO_HASHER
                w.findVal[i][0] = mBins[addr[0]].mVal.load(std::memory_order::memory_order_relaxed);
                w.findVal[i][1] = mBins[addr[1]].mVal.load(std::memory_order::memory_order_relaxed);
#else
                w.findVal[i][0] = mBins[addr[0]].mVal;
                w.findVal[i][1] = mBins[addr[1]].mVal;
#endif
            }

            for (u64 i = 0; i < hashes.bounds()[0]; ++i)
            {
                if (w.findVal[i][0] != u64(-1))
                {
                    u64 itemIdx = w.findVal[i][0] & (u64(-1) >> 8);

                    bool match =
                        (mHashesView[itemIdx][0] == hashes[i][0]) &&
                        (mHashesView[itemIdx][1] == hashes[i][1]);

                    if (match) idxs[i] = itemIdx;
                }

                if (w.findVal[i][1] != u64(-1))
                {
                    u64 itemIdx = w.findVal[i][1] & (u64(-1) >> 8);

                    bool match =
                        (mHashesView[itemIdx][0] == hashes[i][0]) &&
                        (mHashesView[itemIdx][1] == hashes[i][1]);

                    if (match) idxs[i] = itemIdx;
                }
            }

            // stash

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
#ifdef THREAD_SAFE_CUCKOO_HASHER
                u64 val = mStash[i].mVal.load(std::memory_order::memory_order_relaxed);
#else
                u64 val = mStash[i].mVal;
#endif
                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    for (u64 j = 0; j < hashes.bounds()[0]; ++j)
                    {

                        bool match =
                            (mHashesView[itemIdx][0] == hashes[j][0]) &&
                            (mHashesView[itemIdx][1] == hashes[j][1]);

                        if (match)
                        {
                            idxs[j] = itemIdx;
                        }
                    }
                }

                ++i;
            }

        }
        else
        {
            throw std::runtime_error("not implemented");
        }
        return u64(-1);
    }




    bool CuckooHasher::Bin::isEmpty() const
    {
        return mVal == u64(-1);
    }

    u64 CuckooHasher::Bin::idx() const
    {
        return mVal  & (u64(-1) >> 8);
    }

    u64 CuckooHasher::Bin::hashIdx() const
    {
        return mVal >> 56;
    }

    void CuckooHasher::Bin::swap(u64 & idx, u64 & hashIdx)
    {
        u64 newVal = idx | (hashIdx << 56);
#ifdef THREAD_SAFE_CUCKOO_HASHER
        u64 oldVal = mVal.exchange(newVal, std::memory_order_relaxed);
#else
        u64 oldVal = mVal;
        mVal = newVal;
#endif
        if (oldVal == u64(-1))
        {
            idx = hashIdx = u64(-1);
        }
        else
        {
            idx = oldVal & (u64(-1) >> 8);
            hashIdx = oldVal >> 56;
        }
    }
}
