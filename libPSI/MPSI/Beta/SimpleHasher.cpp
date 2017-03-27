#include "SimpleHasher.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include <numeric>

namespace osuCrypto
{


    SimpleHasher::SimpleHasher()
    {
    }


    SimpleHasher::~SimpleHasher()
    {
    }

    void SimpleHasher::print() const
    {

        //std::cout << IoStream::lock;
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "Bin #" << i << std::endl;

            std::cout << " contains " << mBins[i].size() << " elements" << std::endl;

            for (u64 j = 0; j < mBins[i].size(); ++j)
            {
                std::cout
                    << "    " << mBins[i][j]
                    /*<< "  " << mBins[i][j].second */ << std::endl;
            }

            std::cout << std::endl;
        }

        std::cout << std::endl;// << IoStream::unlock;
    }

    double maxprob(u64 balls, u64 bins, u64 k)
    {
        return std::log(bins * std::pow(balls * exp(1) / (bins * k), k)) / std::log(2);
    }

    double binomial(double n, double k)
    {
        double sum = 0;
        for (u64 i = 1; i <= k; ++i)
        {
            sum += (n + 1 - i) / i;
        }

        return sum;
    }


    void SimpleHasher::init(u64 n, u64 numBits, block hashSeed, u64 secParam, double binScaler)
    {
#ifdef OLD_SIMPLE_HASH_PARAM
        mHashSeed = hashSeed;
        mN = n;
        mInputBitSize = numBits;

        double best = (999999999999999.0);

        for (u64 maxBin = 15; maxBin < 40; maxBin++)
        {
            u64 binsHigh = n * 2;
            u64 binsLow = 1;
            // finds the min number of bins needed to get max occ. to be maxBin

            if (-maxprob(n, binsHigh, maxBin) < secParam)
            {
                // maxBins is too small, skip it.
                continue;
            }


            while (binsHigh != binsLow && binsHigh - 1 != binsLow)
            {
                auto mid = (binsHigh + binsLow) / 2;

                if (-maxprob(n, mid, maxBin) < secParam)
                {
                    binsLow = mid;
                }
                else
                {
                    binsHigh = mid;
                }
            }

            u64 bins = binsHigh;

            u64 logBinCount = (u64)std::log2(bins);

            double total = bins*(double)maxBin * (double)maxBin * ((double)mInputBitSize - logBinCount);

            if (total < best)
            {
                best = total;
                mBinCount = bins;
                mMaxBinSize = maxBin;
                //std::cout << "##########################################################" << std::endl;
                //std::cout << n << "  " << bins << "   " << maxBin << "    " << logBinCount << "     " << total << std::endl;
                //std::cout << "##########################################################" << std::endl;

            }
        }

        mMtx.reset(new std::mutex[mBinCount]);
        mBins.resize(mBinCount);
        mRepSize = mInputBitSize - (u32)std::log2(mBinCount);
#else
        //u64 scale = 2;
        mBinCount = n / binScaler;
        mN = n;
        mMtx.reset(new std::mutex[mBinCount]);
        mBins.resize(mBinCount);

        if (secParam != 40)
            throw std::runtime_error(LOCATION);

        if (binScaler == 1.0)
        {
            // bins = items
            switch (n)
            {
			case (4):
			case (8):
			case (16):
			case (128):
                mMaxBinSize = 16;
                break;
            case (1 << 8):
                mMaxBinSize = 16;
                break;
            case (1 << 12):
                mMaxBinSize = 17;
                break;
            case (1 << 16):
                mMaxBinSize = 18;
                break;
            case (1 << 20):
                mMaxBinSize = 19;
                break;
            case (1 << 24):
                mMaxBinSize = 20;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }

        }
        else if (binScaler == 2.0)
        {

            // bins = items/2
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 20;
                break;
            case (1 << 12):
                mMaxBinSize = 22;
                break;
            case (1 << 16):
                mMaxBinSize = 23;
                break;
            case (1 << 20):
                mMaxBinSize = 24;
                break;
            case (1 << 24):
                mMaxBinSize = 25;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }

        }
        else if (binScaler == 3.0)
        {

            // bins = items/2
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 24;
                break;
            case (1 << 12):
                mMaxBinSize = 25;
                break;
            case (1 << 16):
                mMaxBinSize = 26;
                break;
            case (1 << 20):
                mMaxBinSize = 28;
                break;
            case (1 << 24):
                mMaxBinSize = 29;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }

        }
        else if (binScaler == 4.0)
        {
            // bins = items / 4
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 26;
                break;
            case (1 << 12):
                mMaxBinSize = 28;
                break;
            case (1 << 16):
                mMaxBinSize = 30;
                break;
            case (1 << 20):
                mMaxBinSize = 31;
                break;
            case (1 << 24):
                mMaxBinSize = 32;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 5.0)
        {
            // bins = items / 4
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 29;
                break;
            case (1 << 12):
                mMaxBinSize = 31;
                break;
            case (1 << 16):
                mMaxBinSize = 33;
                break;
            case (1 << 20):
                mMaxBinSize = 34;
                break;
            case (1 << 24):
                mMaxBinSize = 36;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 6.0)
        {
            // bins = items / 4
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 32;
                break;
            case (1 << 12):
                mMaxBinSize = 34;
                break;
            case (1 << 16):
                mMaxBinSize = 35;
                break;
            case (1 << 20):
                mMaxBinSize = 37;
                break;
            case (1 << 24):
                mMaxBinSize = 38;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 8.0)
        {
            // bins = items / 8
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 36;
                break;
            case (1 << 12):
                mMaxBinSize = 39;
                break;
            case (1 << 16):
                mMaxBinSize = 41;
                break;
            case (1 << 20):
                mMaxBinSize = 42;
                break;
            case (1 << 24):
                mMaxBinSize = 44;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 10.0)
        {
            // bins = items / 8
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 40;
                break;
            case (1 << 12):
                mMaxBinSize = 43;
                break;
            case (1 << 16):
                mMaxBinSize = 45;
                break;
            case (1 << 20):
                mMaxBinSize = 47;
                break;
            case (1 << 24):
                mMaxBinSize = 49;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 12.0)
        {
            // bins = items / 12
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 44;
                break;
            case (1 << 12):
                mMaxBinSize = 48;
                break;
            case (1 << 16):
                mMaxBinSize = 50;
                break;
            case (1 << 20):
                mMaxBinSize = 52;
                break;
            case (1 << 24):
                mMaxBinSize = 53;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 16.0)
        {
            // bins = items / 12
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 51;
                break;
            case (1 << 12):
                mMaxBinSize = 56;
                break;
            case (1 << 16):
                mMaxBinSize = 58;
                break;
            case (1 << 20):
                mMaxBinSize = 60;
                break;
            case (1 << 24):
                mMaxBinSize = 62;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 20.0)
        {
            // bins = items / 20
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 58;
                break;
            case (1 << 12):
                mMaxBinSize = 63;
                break;
            case (1 << 16):
                mMaxBinSize = 66;
                break;
            case (1 << 20):
                mMaxBinSize = 68;
                break;
            case (1 << 24):
                mMaxBinSize = 70;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 24.0)
        {
            // bins = items / 24
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 64;
                break;
            case (1 << 12):
                mMaxBinSize = 70;
                break;
            case (1 << 16):
                mMaxBinSize = 73;
                break;
            case (1 << 20):
                mMaxBinSize = 76;
                break;
            case (1 << 24):
                mMaxBinSize = 78;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 32.0)
        {
            // bins = items / 24
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 76;
                break;
            case (1 << 12):
                mMaxBinSize = 84;
                break;
            case (1 << 16):
                mMaxBinSize = 87;
                break;
            case (1 << 20):
                mMaxBinSize = 90;
                break;
            case (1 << 24):
                mMaxBinSize = 92;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 48.0)
        {
            // bins = items / 24
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 98;
                break;
            case (1 << 12):
                mMaxBinSize = 109;
                break;
            case (1 << 16):
                mMaxBinSize = 113;
                break;
            case (1 << 20):
                mMaxBinSize = 116;
                break;
            case (1 << 24):
                mMaxBinSize = 119;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else if (binScaler == 64.0)
        {
            // bins = items / 24
            switch (n)
            {
            case (1 << 8):
                mMaxBinSize = 117;
                break;
            case (1 << 12):
                mMaxBinSize = 133;
                break;
            case (1 << 16):
                mMaxBinSize = 137;
                break;
            case (1 << 20):
                mMaxBinSize = 141;
                break;
            case (1 << 24):
                mMaxBinSize = 144;
                break;
            default:
                throw std::runtime_error(LOCATION);
                break;
            }
        }
        else
        {
            throw std::runtime_error(LOCATION);
        }






        //std::cout << IoStream::lock;
        //double k = 1;
        //mMaxBinSize = 10;
        //while (k > -double(secParam))
        //{
        //    ++mMaxBinSize;
        //    double sum = 0, sum2 = 1;

        //    u64 i = mMaxBinSize;
        //    while (sum != sum2 && i < mN)
        //    {
        //        sum2 = sum;

        //        sum += mBinCount * binomial(mN, i) * std::pow(1.0 / mBinCount, i) * std::pow(1 - 1.0 / mBinCount, mN - i);


        //        ++i;
        //        std::cout << "sec = " << std::log2(sum) << std::endl;
        //    }
        //    // cite: Scalable Private Set Intersection Based on OT Extension - Pinkas, et. al
        //    //k = double(mBinCount) * std::pow(mN * 2.6 / mBinCount / mMaxBinSize, mMaxBinSize);


        //    k = std::log2(sum);
        //}
        ////--mMaxBinSize;
        //std::cout << IoStream::unlock;

#endif
    }

    //void SimpleHasher::preHashedInsertItems(ArrayView<block> mySet, u64 itemIdx)
    //{
    //    for (u64 i = 0; i < mySet.size(); ++i, ++itemIdx)
    //    {
    //        auto& item = mySet[i];


    //        u64 addr = *(u64*)&item % mBinCount;

    //        std::lock_guard<std::mutex> lock(mMtx[addr]);
    //        mBins[addr].emplace_back();
    //        mBins[addr].back() = itemIdx;
    //    }
    //}

    ////void SimpleHasher::insertItemsWithPhasing(
    //    ArrayView<block> mySet,  
    //    u64 itemIdx)
    //{
    //    u64 addressbitSize = mInputBitSize - mRepSize;
    //    throw std::runtime_error("not impl");

    //    //SHA1 fSeed;
    //    //fSeed.Update(mHashSeed);
    //    //std::cout << "hash seed     " << mHashSeed << std::endl;
    //    //std::cout << "mInputBitSize " << mInputBitSize << std::endl;
    //    //std::cout << "mRepSize      " << mRepSize << std::endl;
    //    //std::cout << "totalRepSize  " << totalRepSize << std::endl << std::endl;

    //    u8 xrHash[SHA1::HashSize];

    //    SHA1 f;

    //    //for (u64 i = 0; i < mySet.size(); ++i)
    //    //{
    //    //    auto& item = mySet[i];
    //    //    //std::cout << "  item[" << i << "] " << item << std::endl;

    //    //    //u64 xr(0),xl(0);

    //    //    //memccpy(&xr, &item, )

    //    //    //BitVector xr;
    //    //    //xr.append((u8*)&item, mRepSize);

    //    //    //BitVector xl;
    //    //    //xl.append((u8*)&item, addressbitSize, xr.size());
    //    //    auto xr = item / mBinCount;
    //    //    auto xl = item % mBinCount;

    //    //    //auto f = fSeed;

    //    //    f.Reset();
    //    //    f.Update(mHashSeed);
    //    //    f.Update((u8*)&xr, sizeof(u64));
    //    //    f.Final(xrHash);

    //    //    //u64 xlVal = 0;
    //    //    //memcpy(&xlVal, xl.data(), xl.sizeBytes());

    //    //    u64 xrHashVal = *(u64*)xrHash % mBinCount;

    //    //    auto addr = (xl + xrHashVal) % mBinCount;

    //    //    //std::cout << "     xr   " << xr << std::endl;
    //    //    //std::cout << "     xl   " << xl << std::endl;
    //    //    //std::cout << "     addr " << addr <<  std::endl;

    //    //    BitVector val(mRepSize);
    //    //    memcpy(val.data(), &xr, std::min(sizeof(xr), val.sizeBytes()));

    //    //    std::lock_guard<std::mutex> lock(mMtx[addr]);
    //    //    mBins[addr].first.push_back(i);
    //    //    mBins[addr].second.emplace_back(std::move(val));

    //    //    //if (i == 0)
    //    //    //{
    //    //    //    std::cout << IoStream::lock << item << "  -> addr = " << addr << "  val = " << xr << "  (" << mBins[addr].second.back() << ")" << std::endl << IoStream::unlock;
    //    //    //}
    //    //}
    //}
}
