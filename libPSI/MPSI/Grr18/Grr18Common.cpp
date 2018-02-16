#include "Grr18Common.h"
#include <random>

namespace osuCrypto
{



    u64 computeLoads(
        std::vector<u8>& loads, 
        PRNG & prng, 
        u64 binStart, 
        bool oneSized,
        u64 n,
        SimpleHasher& bins,
        double eps,
        bool print)
    {
        auto totalLoad = 0ull;

        if (oneSized)
        {
            std::exponential_distribution<double> exp(1.0 / eps);

            auto  avg = 0.0;
            for (u64 i = 0; i < loads.size(); ++i)
            {
                auto noise = exp(prng);
                auto ss = std::min<u64>(bins.mBins[binStart + i].size() + noise, bins.mMaxBinSize);
                if (ss > 255)
                    throw std::runtime_error(LOCATION);
                
                avg += ss - bins.mBins[binStart + i].size();

                loads[i] = ss;

                totalLoad += loads[i];
            }

            if (print)
            {
                auto expectedBinLoad = n / bins.mBinCount + 1.0 / eps;
                std::cout << "avg:" << avg / loads.size() << " " << 1.0 / eps << " actual load: " << totalLoad / loads.size() << " vs exp " << expectedBinLoad << " vs max " << bins.mMaxBinSize << std::endl;
            }
        }
        else
        {
            std::vector<u8> lookup;

            if (bins.mBinCount == n / 4)
            {
                if(n == 1<< 16)
                   lookup = { 20, 20, 20, 21, 21, 21, 22, 22, 23, 24, 24, 25, 25, 26, 27, 27, 28, 29, 29, 30 };
                if (n == 1 << 20)
                    lookup = { 21, 21, 21, 22, 22, 22, 23, 23, 24, 25, 25, 26, 26, 27, 28, 28, 29, 30, 30, 31 };
            }


            if(lookup.size() == 0)
            {
                throw std::runtime_error(LOCATION);
            }

            std::exponential_distribution<double> exp(1.0 / eps);

            for (u64 i = 0; i < loads.size(); ++i)
            {
                auto noise = exp(prng) * (prng.getBit() * 2 - 1);
                auto estimate =
                    std::max<i32>(
                        std::min<i32>(lookup.size() - 1, bins.mBins[binStart + i].size() + noise)
                        , 0);

                loads[i] = lookup[estimate];


                totalLoad += loads[i];
            }
        }


        return totalLoad;
    }

}