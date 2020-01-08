#include "SimpleCuckoo.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include <numeric>

namespace osuCrypto
{


    SimpleCuckoo::SimpleCuckoo()
        :mTotalTries(0)
    {
    }

    SimpleCuckoo::~SimpleCuckoo()
    {

        mHashes = std::vector<u64>();
        mHashesView   = MatrixView<u64>();

        mBins = std::vector<Bin>();
        mStash = std::vector<Bin>();

    }

    bool SimpleCuckoo::operator==(const SimpleCuckoo & cmp) const
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

    bool SimpleCuckoo::operator!=(const SimpleCuckoo & cmp) const
    {
        return !(*this == cmp);
    }

    void SimpleCuckoo::print() const
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

    void SimpleCuckoo::init()
    {

        mHashes.resize(mParams.mN * mParams.mNumHashes, 0);


        mHashesView = MatrixView<u64>(mHashes.begin(), mHashes.end(), mParams.mNumHashes);

        u64 binCount = u64(mParams.mBinScaler * mParams.mN);

        mBins.resize(binCount);
        //mStash.resize(mParams.mStashSize);
    }


    void SimpleCuckoo::insertBatch(
        span<u64> inputIdxs,
        MatrixView<u64> hashs,
        Workspace& w)
    {

        u64 width = mHashesView.bounds()[1];
        u64 remaining = inputIdxs.size();
        u64 tryCount = 0;
        //u64 evists = 0;

#ifndef  NDEBUG
        if (hashs.bounds()[1] != width)
            throw std::runtime_error("" LOCATION);
#endif // ! NDEBUG


        for (u64 i = 0; i < inputIdxs.size(); ++i)
        {
            //std::cout << inputIdxs[i] << " hs ";

            for (u64 j = 0; j < mParams.mNumHashes; ++j)
            {
#ifndef  NDEBUG
                mHashesView[inputIdxs[i]][j] = hashs[i][j];
#else
                (mHashesView.data() + inputIdxs[i] * width)[j] = (hashs.data() + i * width)[j];
#endif // ! NDEBUG

                //std::cout << hashs[i][j] << "   ";

            }

            //std::cout << std::endl;

            w.curHashIdxs[i] = 0;
        }


        while (remaining && tryCount++ < 100)
        {

            // this data fetch can be slow (after the first loop).
            // As such, lets do several fetches in parallel.
            for (u64 i = 0; i < remaining; ++i)
            {
#ifndef  NDEBUG
                w.curAddrs[i] = mHashesView[inputIdxs[i]][w.curHashIdxs[i]] % mBins.size();
#else
                w.curAddrs[i] = (mHashesView.data() + inputIdxs[i] * width)[w.curHashIdxs[i]] % mBins.size();
#endif
                //if(inputIdxs[i]  == 8)
				//std::cout <<  i << "   idx " << inputIdxs[i]  <<  "  addr "<< w.curAddrs[i] << std::endl;
            }
            //std::cout << std::endl;

            // same thing here, this fetch is slow. Do them in parallel.
            for (u64 i = 0; i < remaining; ++i)
            {
                u64 newVal = inputIdxs[i] | (w.curHashIdxs[i] << 56);
#ifdef THREAD_SAFE_CUCKOO
                w.oldVals[i] = mBins[w.curAddrs[i]].mVal.exchange(newVal, std::memory_order_relaxed);
#else
                w.oldVals[i] = mBins[w.curAddrs[i]].mVal;
                mBins[w.curAddrs[i]].mVal = newVal;
#endif
				//if (inputIdxs[i] == 8)
				//{

				//	u64 oldIdx = w.oldVals[i] & (u64(-1) >> 8);
				//	u64 oldHash = (w.oldVals[i] >> 56);
				//	std::cout
				//	    << i << "   bin[" << w.curAddrs[i] << "]  "
				//	    << " gets (" << inputIdxs[i] << ", "<< w.curHashIdxs[i]<< "),"
				//	    << " evicts ("<< oldIdx << ", "<< oldHash<< ")" << std::endl;
				//}
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
                //std::swap(w.oldVals[putIdx], w.oldVals[getIdx]);

                ++putIdx;
                ++getIdx;
            }

            remaining = putIdx;
            //evists += remaining;

            //std::cout << std::endl;
            //for (u64 i = 0; i < remaining; ++i)
            //    std::cout<< "evicted[" << i << "]'  " << inputIdxs[i] << "  " << w.curHashIdxs[i] << std::endl;
            //std::cout << std::endl;

        }

        // put any that remain in the stash.
        for (u64 i = 0; i < remaining; ++i)
        {
            mStash.push_back(Bin(inputIdxs[i], w.curHashIdxs[i]));
            //mStash[j].swap(inputIdxs[i], w.curHashIdxs[i]);

            //if (inputIdxs[i] == u64(-1))
            //    ++i;
        }

        //std::cout << "total evicts "<< evists << std::endl;
    }



    u64 SimpleCuckoo::findBatch(
        MatrixView<u64> hashes,
        span<u64> idxs,
        Workspace& w)
    {

        if (mParams.mNumHashes == 2)
        {
            std::array<u64, 2>  addr;

            for (u64 i = 0; i < hashes.bounds()[0]; ++i)
            {
                idxs[i] = u64(-1);

                addr[0] = (hashes[i][0]) % mBins.size();
                addr[1] = (hashes[i][1]) % mBins.size();

#ifdef THREAD_SAFE_CUCKOO
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

                // stash
                if (idxs[i] == u64(-1))
                {
                    u64 j = 0;
                    while (j < mStash.size() && mStash[j].isEmpty() == false)
                    {
#ifdef THREAD_SAFE_CUCKOO
                        u64 val = mStash[j].mVal.load(std::memory_order::memory_order_relaxed);
#else
                        u64 val = mStash[j].mVal;
#endif
                        if (val != u64(-1))
                        {
                            u64 itemIdx = val & (u64(-1) >> 8);


                            bool match =
                                (mHashesView[itemIdx][0] == hashes[i][0]) &&
                                (mHashesView[itemIdx][1] == hashes[i][1]);

                            if (match)
                            {
                                idxs[i] = itemIdx;
                            }

                        }

                        ++j;
                    }
                }

            }


        }
        else
        {
            std::vector<u64> addr(hashes.bounds()[1]);

            for (u64 i = 0; i < hashes.bounds()[0]; ++i)
            {
                idxs[i] = u64(-1);

                for(u64 j =0; j < hashes.bounds()[1]; ++j)
                    addr[j] = hashes[i][j] % mBins.size();

#ifdef THREAD_SAFE_CUCKOO
                for (u64 j = 0; j < hashes.bounds()[1]; ++j)
                    w.findVal[i][j] = mBins[addr[j]].mVal.load(std::memory_order::memory_order_relaxed);
#else
                for (u64 j = 0; j < hashes.stride(); ++j)
                    w.findVal[i][j] = mBins[addr[j]].mVal;
#endif
            }

            for (u64 i = 0; i < hashes.bounds()[0]; ++i)
            {
                for (u64 j = 0; j < hashes.bounds()[1] && idxs[i] == u64(-1); ++j)
                {

                    if (w.findVal[i][j] != u64(-1))
                    {
                        u64 itemIdx = w.findVal[i][j] & (u64(-1) >> 8);

                        bool match = true;

                        for (u64 k = 0; k < hashes.bounds()[1]; ++k)
                        {
                            match &= (mHashesView[itemIdx][k] == hashes[i][k]);
                        }

                        if (match) idxs[i] = itemIdx;
                    }
                }

                // stash
                if (idxs[i] == u64(-1))
                {
                    u64 j = 0;
                    while (j < mStash.size() && mStash[j].isEmpty() == false)
                    {
#ifdef THREAD_SAFE_CUCKOO
                        u64 val = mStash[j].mVal.load(std::memory_order::memory_order_relaxed);
#else
                        u64 val = mStash[j].mVal;
#endif
                        if (val != u64(-1))
                        {
                            u64 itemIdx = val & (u64(-1) >> 8);
                            bool match = true;

                            for (u64 k = 0; k < hashes.bounds()[1]; ++k)
                            {
                                match &= (mHashesView[itemIdx][k] == hashes[i][k]);
                            }

                            if (match) idxs[i] = itemIdx;

                        }

                        ++j;
                    }
                }


            }

        }
        return u64(-1);
    }

    u64 SimpleCuckoo::stashUtilization()
    {

        u64 i = 0;
        while (i < mStash.size() && mStash[i].isEmpty() == false)
        {
            ++i;
        }

        return i;
    }




    bool SimpleCuckoo::Bin::isEmpty() const
    {
        return mVal == u64(-1);
    }

    u64 SimpleCuckoo::Bin::idx() const
    {
        return mVal  & (u64(-1) >> 8);
    }

    u64 SimpleCuckoo::Bin::hashIdx() const
    {
        return mVal >> 56;
    }

    void SimpleCuckoo::Bin::swap(u64 & idx, u64 & hashIdx)
    {
        u64 newVal = idx | (hashIdx << 56);
#ifdef THREAD_SAFE_CUCKOO
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