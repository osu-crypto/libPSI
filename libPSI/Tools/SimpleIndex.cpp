#include "SimpleIndex.h"
#include "cryptoTools/Crypto/sha1.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <random>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include <numeric>
#include <boost/math/special_functions/binomial.hpp>
#include <boost/multiprecision/cpp_bin_float.hpp>

namespace osuCrypto
{


    void SimpleIndex::print()
    {

        for (u64 i = 0; i < mBins.size(); ++i)
            //	for (u64 i = 0; i <1; ++i)
        {
            std::cout << "Bin #" << i << std::endl;

            std::cout << " contains " << mBinSizes[i] << " elements" << std::endl;

            for (u64 j = 0; j < mBinSizes[i]; ++j)
            {
                std::cout << "    idx=" << mBins(i, j).idx() << "  hIdx=" << mBins(i, j).hashIdx() << std::endl;
                //	std::cout << "    " << mBins[i].first[j] << "  " << mBins[i].second[j] << std::endl;

            }

            std::cout << std::endl;
        }

        std::cout << std::endl;
    }


    //template<unsigned int N = 16>
    double getBinOverflowProb(u64 numBins, u64 numBalls, u64 binSize, double epsilon = 0.0001)
    {
        if (numBalls <= binSize)
            return std::numeric_limits<double>::max();

        if (numBalls > unsigned(-1))
        {
            auto msg = ("boost::math::binomial_coefficient(...) only supports " + std::to_string(sizeof(unsigned) * 8) + " bit inputs which was exceeded." LOCATION);
            std::cout << msg << std::endl;
            throw std::runtime_error(msg);
        }

        //std::cout << numBalls << " " << numBins << " " << binSize << std::endl;
        typedef boost::multiprecision::number<boost::multiprecision::backends::cpp_bin_float<16>> T;
        T sum = 0.0;
        T sec = 0.0;// minSec + 1;
        T diff = 1;
        u64 i = binSize + 1;


        while (diff > T(epsilon) && numBalls >= i /*&& sec > minSec*/)
        {
            sum += numBins * boost::math::binomial_coefficient<T>(numBalls, i)
                * boost::multiprecision::pow(T(1.0) / numBins, i) * boost::multiprecision::pow(1 - T(1.0) / numBins, numBalls - i);

            //std::cout << "sum[" << i << "] " << sum << std::endl;

            T sec2 = boost::multiprecision::log2(sum);
            diff = boost::multiprecision::abs(sec - sec2);
            //std::cout << diff << std::endl;
            sec = sec2;

            i++;
        }

        return std::max<double>(0, (double)-sec);
    }

    u64 get_bin_size(u64 numBins, u64 numBalls, u64 statSecParam)
    {

        auto B = std::max<u64>(1, numBalls / numBins);

        double currentProb = 0;
        u64 step = 1;

        bool doubling = true;

        while (currentProb < statSecParam || step > 1)
        {
            if (!step)
                throw std::runtime_error(LOCATION);


            if (statSecParam > currentProb)
            {
                if (doubling) step = std::max<u64>(1, step * 2);
                else          step = std::max<u64>(1, step / 2);

                B += step;
            }
            else
            {
                doubling = false;
                step = std::max<u64>(1, step / 2);
                B -= step;
            }
            currentProb = getBinOverflowProb(numBins, numBalls, B);
        }

        return B;
    }


    void SimpleIndex::init(u64 numBins, u64 simpleSize, u64 statSecParam, u64 numHashFunction)
    {
        mNumHashFunctions = numHashFunction;
        mMaxBinSize = get_bin_size(numBins, simpleSize * numHashFunction, statSecParam);
        mBins.resize(numBins, mMaxBinSize);
        mBinSizes.resize(numBins, 0);
    }


    void SimpleIndex::insertItems(span<block> items, block hashingSeed)
    {

        std::array<block, 8> hashs;
        AES hasher(hashingSeed);
        auto numBins = mBins.bounds()[0];

        auto mainSteps = items.size() / hashs.size();
        auto remSteps = items.size() % hashs.size();
        u64 itemIdx = 0;
        if (mNumHashFunctions == 3 )
        {
            for (u64 i = 0; i < mainSteps; ++i, itemIdx += 8)
            {
                auto min = std::min<u64>(items.size() - itemIdx, hashs.size());

                hasher.ecbEncBlocks(items.data() + itemIdx, min, hashs.data());

                auto itemIdx0 = itemIdx + 0;
                auto itemIdx1 = itemIdx + 1;
                auto itemIdx2 = itemIdx + 2;
                auto itemIdx3 = itemIdx + 3;
                auto itemIdx4 = itemIdx + 4;
                auto itemIdx5 = itemIdx + 5;
                auto itemIdx6 = itemIdx + 6;
                auto itemIdx7 = itemIdx + 7;



                hashs[0] = hashs[0] ^ items[itemIdx0];
                hashs[1] = hashs[1] ^ items[itemIdx1];
                hashs[2] = hashs[2] ^ items[itemIdx2];
                hashs[3] = hashs[3] ^ items[itemIdx3];
                hashs[4] = hashs[4] ^ items[itemIdx4];
                hashs[5] = hashs[5] ^ items[itemIdx5];
                hashs[6] = hashs[6] ^ items[itemIdx6];
                hashs[7] = hashs[7] ^ items[itemIdx7];

                auto bIdx00 = CuckooIndex::getHash(hashs[0], 0, numBins);
                auto bIdx10 = CuckooIndex::getHash(hashs[1], 0, numBins);
                auto bIdx20 = CuckooIndex::getHash(hashs[2], 0, numBins);
                auto bIdx30 = CuckooIndex::getHash(hashs[3], 0, numBins);
                auto bIdx40 = CuckooIndex::getHash(hashs[4], 0, numBins);
                auto bIdx50 = CuckooIndex::getHash(hashs[5], 0, numBins);
                auto bIdx60 = CuckooIndex::getHash(hashs[6], 0, numBins);
                auto bIdx70 = CuckooIndex::getHash(hashs[7], 0, numBins);

                mBins(bIdx00, mBinSizes[bIdx00]++).set(itemIdx0, 0, false);
                mBins(bIdx10, mBinSizes[bIdx10]++).set(itemIdx1, 0, false);
                mBins(bIdx20, mBinSizes[bIdx20]++).set(itemIdx2, 0, false);
                mBins(bIdx30, mBinSizes[bIdx30]++).set(itemIdx3, 0, false);
                mBins(bIdx40, mBinSizes[bIdx40]++).set(itemIdx4, 0, false);
                mBins(bIdx50, mBinSizes[bIdx50]++).set(itemIdx5, 0, false);
                mBins(bIdx60, mBinSizes[bIdx60]++).set(itemIdx6, 0, false);
                mBins(bIdx70, mBinSizes[bIdx70]++).set(itemIdx7, 0, false);

                auto bIdx01 = CuckooIndex::getHash(hashs[0], 1, numBins);
                auto bIdx11 = CuckooIndex::getHash(hashs[1], 1, numBins);
                auto bIdx21 = CuckooIndex::getHash(hashs[2], 1, numBins);
                auto bIdx31 = CuckooIndex::getHash(hashs[3], 1, numBins);
                auto bIdx41 = CuckooIndex::getHash(hashs[4], 1, numBins);
                auto bIdx51 = CuckooIndex::getHash(hashs[5], 1, numBins);
                auto bIdx61 = CuckooIndex::getHash(hashs[6], 1, numBins);
                auto bIdx71 = CuckooIndex::getHash(hashs[7], 1, numBins);

                bool collision01 = bIdx00 == bIdx01;
                bool collision11 = bIdx10 == bIdx11;
                bool collision21 = bIdx20 == bIdx21;
                bool collision31 = bIdx30 == bIdx31;
                bool collision41 = bIdx40 == bIdx41;
                bool collision51 = bIdx50 == bIdx51;
                bool collision61 = bIdx60 == bIdx61;
                bool collision71 = bIdx70 == bIdx71;

                mBins(bIdx01, mBinSizes[bIdx01]++).set(itemIdx0, 1, collision01);
                mBins(bIdx11, mBinSizes[bIdx11]++).set(itemIdx1, 1, collision11);
                mBins(bIdx21, mBinSizes[bIdx21]++).set(itemIdx2, 1, collision21);
                mBins(bIdx31, mBinSizes[bIdx31]++).set(itemIdx3, 1, collision31);
                mBins(bIdx41, mBinSizes[bIdx41]++).set(itemIdx4, 1, collision41);
                mBins(bIdx51, mBinSizes[bIdx51]++).set(itemIdx5, 1, collision51);
                mBins(bIdx61, mBinSizes[bIdx61]++).set(itemIdx6, 1, collision61);
                mBins(bIdx71, mBinSizes[bIdx71]++).set(itemIdx7, 1, collision71);


                auto bIdx02 = CuckooIndex::getHash(hashs[0], 2, numBins);
                auto bIdx12 = CuckooIndex::getHash(hashs[1], 2, numBins);
                auto bIdx22 = CuckooIndex::getHash(hashs[2], 2, numBins);
                auto bIdx32 = CuckooIndex::getHash(hashs[3], 2, numBins);
                auto bIdx42 = CuckooIndex::getHash(hashs[4], 2, numBins);
                auto bIdx52 = CuckooIndex::getHash(hashs[5], 2, numBins);
                auto bIdx62 = CuckooIndex::getHash(hashs[6], 2, numBins);
                auto bIdx72 = CuckooIndex::getHash(hashs[7], 2, numBins);


                bool collision02 = bIdx00 == bIdx02 || bIdx01 == bIdx02;
                bool collision12 = bIdx10 == bIdx12 || bIdx11 == bIdx12;
                bool collision22 = bIdx20 == bIdx22 || bIdx21 == bIdx22;
                bool collision32 = bIdx30 == bIdx32 || bIdx31 == bIdx32;
                bool collision42 = bIdx40 == bIdx42 || bIdx41 == bIdx42;
                bool collision52 = bIdx50 == bIdx52 || bIdx51 == bIdx52;
                bool collision62 = bIdx60 == bIdx62 || bIdx61 == bIdx62;
                bool collision72 = bIdx70 == bIdx72 || bIdx71 == bIdx72;


                mBins(bIdx02, mBinSizes[bIdx02]++).set(itemIdx0, 2, collision02);
                mBins(bIdx12, mBinSizes[bIdx12]++).set(itemIdx1, 2, collision12);
                mBins(bIdx22, mBinSizes[bIdx22]++).set(itemIdx2, 2, collision22);
                mBins(bIdx32, mBinSizes[bIdx32]++).set(itemIdx3, 2, collision32);
                mBins(bIdx42, mBinSizes[bIdx42]++).set(itemIdx4, 2, collision42);
                mBins(bIdx52, mBinSizes[bIdx52]++).set(itemIdx5, 2, collision52);
                mBins(bIdx62, mBinSizes[bIdx62]++).set(itemIdx6, 2, collision62);
                mBins(bIdx72, mBinSizes[bIdx72]++).set(itemIdx7, 2, collision72);


            }

            hasher.ecbEncBlocks(items.data() + itemIdx, remSteps, hashs.data());
            for (u64 i = 0; i < remSteps; i += hashs.size())
            {
                hashs[i] = hashs[i] ^ items[itemIdx + i];

                std::vector<u64> bIdxs(mNumHashFunctions);
                for (u64 h = 0; h < mNumHashFunctions; ++h)
                {
                    auto bIdx = CuckooIndex::getHash(hashs[i], h, numBins);
                    bool collision = false;

                    bIdxs[h] = bIdx;
                    for (u64 hh = 0; hh < h; ++hh)
                        collision |= (bIdxs[hh] == bIdx);

                    mBins(bIdx, mBinSizes[bIdx]++).set(itemIdx, h, collision);
                }
            }
        }
        else
        {
            std::vector<u64> bIdxs(mNumHashFunctions);
            for (u64 i = 0; i < items.size(); i += hashs.size())
            {
                auto min = std::min<u64>(items.size() - i, hashs.size());

                hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

                for (u64 j = 0, itemIdx = i; j < min; ++j, ++itemIdx)
                {
                    hashs[j] = hashs[j] ^ items[itemIdx];

                    for (u64 h = 0; h < mNumHashFunctions; ++h)
                    {
                        auto bIdx = CuckooIndex::getHash(hashs[j], h, mBins.bounds()[0]);
                        bool collision = false;

                        bIdxs[h] = bIdx;
                        for (u64 hh = 0; hh < h; ++hh)
                            collision |= (bIdxs[hh] == bIdx);

                        mBins(bIdx, mBinSizes[bIdx]++).set(itemIdx, h, collision);


                    }
                }
            }
        }
    }

}
