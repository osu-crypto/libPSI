#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
namespace osuCrypto
{


    class RandomShuffle
    {

    public:

        RandomShuffle(u64 numTHreads = 1);


        void shuffle(span<u64> vals, PRNG& prng);
        void parallelShuffle(span<u64> vals, u64 threadIndex, u64 numThreads);

        //void randomPermutation(span<u64> dest, u64 threadIndex);

        void mergeShuffle(span<u64> vals, PRNG& prng);


    };

}