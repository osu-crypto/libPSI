#include "RandomShuffle.h"
#include <random>
#include <algorithm>
#include<future>
#include <cryptoTools/Common/Timer.h>
namespace osuCrypto
{
    RandomShuffle::RandomShuffle(u64 numTHreads)
    {
    }
    void RandomShuffle::shuffle(span<u64> vals, PRNG& prng)
    {
        std::random_shuffle(vals.begin(), vals.end(), prng);
    }

    void RandomShuffle::parallelShuffle(span<u64> vals, u64 t, u64 nt)
    {
        auto start = vals.size() * t / nt;
        auto end = vals.size() * t / nt;
        PRNG prng(toBlock(t));
        //std::vector<u64> dest(vals.size());
        mergeShuffle({ vals.data() + start, vals.data() + end }, prng);



        //memcpy(vals.data(), dest.data(), sizeof(u64) * vals.size());
    }

    void RandomShuffle::mergeShuffle(span<u64> src, PRNG & prng)
    {
        //Expects(src.size() == dest.size());

        u64 k = 1ull << 20;

        //std::array<block, 4> base{ ZeroBlock, toBlock(0ull,~0ull), toBlock(~0ull,0ull),  AllOneBlock };
        //std::array<block, 8> masks;

        //std::array<u64, 2> u64Masks{ 0ull, ~0ull };

        if (src.size() < k)
        {
            shuffle(src, prng);
        }
        else
        {
            block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
            std::array<block, 8> expended;
            auto bytes = (u8*)expended.data();
        
            PRNG prng2( prng.get<block>(), 256);
            auto low = src.begin();
            auto mid = src.begin() + src.size() / 2;
            auto end = src.end();

            auto g = std::async([&]() {
            mergeShuffle({ low, mid }, prng2);
            //gTimer.setTimePoint("s1");
            });
            mergeShuffle({ mid, end }, prng);
            //gTimer.setTimePoint("s1");
            g.get();



            while (low != mid && mid != end)
            {
                //u64 rand = prng.get<u64>();
                auto min = std::min<u64>(128ll, std::min<u64>(mid - low, end - mid));
                auto blk = prng.get<block>();
                expended[0] = mask & _mm_srai_epi16(blk, 0);
                expended[1] = mask & _mm_srai_epi16(blk, 1);
                expended[2] = mask & _mm_srai_epi16(blk, 2);
                expended[3] = mask & _mm_srai_epi16(blk, 3);
                expended[4] = mask & _mm_srai_epi16(blk, 4);
                expended[5] = mask & _mm_srai_epi16(blk, 5);
                expended[6] = mask & _mm_srai_epi16(blk, 6);
                expended[7] = mask & _mm_srai_epi16(blk, 7);

                for (u64 i = 0; i < min; ++i)
                {
                    if (bytes[i]) std::swap(*low, *mid);
                    mid += bytes[i];
                    ++low;
                }
            }

            //gTimer.setTimePoint("merge");

            shuffle({ low, end }, prng);

            //gTimer.setTimePoint("final");

            //mergeShuffle({ auxBegin,auxEnd }, prng);
        }

    }
}
