#include "SimpleHasher.h"
//#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include <numeric>
#include "SimpleIndex.h"
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

        ////std::cout << IoStream::lock;
        //for (u64 i = 0; i < mBinCount; ++i)
        //{
        //    std::cout << "Bin #" << i << std::endl;

        //    std::cout << " contains " << getBinSize(i) << " elements" << std::endl;

        //    for (u64 j = 0; j < mBins[i].size(); ++j)
        //    {
        //        std::cout
        //            << "    " << mBins[i][j]
        //            /*<< "  " << mBins[i][j].second */ << std::endl;
        //    }

        //    std::cout << std::endl;
        //}

        //std::cout << std::endl;// << IoStream::unlock;
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
        mBinCount = std::max<u64>(1, n / binScaler);
        mN = n;
        mBinSizes.reset( new std::atomic<u8>[mBinCount]());


        for (u64 i = 0; i < mBinCount; ++i)
        {
            mBinSizes[i].store(0, std::memory_order::memory_order_relaxed);
        }

        if (secParam == 40)
        {

            if (binScaler == 1.0)
            {
                // bins = items
                switch (n)
                {
                case (1):
                case (2):
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
                    break;
                }
            }
        }
        

        mMaxBinSize = SimpleIndex::get_bin_size(mBinCount, mN, secParam);
        mBins_.resize(mBinCount, mMaxBinSize);


        if (mMaxBinSize > 255)
            throw std::runtime_error("mBinSizes only holds u8's " LOCATION);
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
