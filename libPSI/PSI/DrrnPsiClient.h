#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Network/Channel.h>
#include <libPSI/PSI/KkrtPsiReceiver.h>
namespace osuCrypto
{

    class DrrnPsiClient
    {
    public:

        void init(Channel s0, Channel s1, u64 serverSetSize, u64 clientSetSize, block seed);

        void recv(Channel s0, Channel s1, span<block> inputs);

        PRNG mPrng;
        CuckooParam mCuckooParams;
        
        KkrtPsiReceiver mPsi;

        u64 mClientSetSize, mServerSetSize;
        block mHashingSeed;
    };

}
