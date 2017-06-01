#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>

namespace osuCrypto
{
    class BgiPirClient
    {
    public:
        u64 mDatasetSize;
        u64 mKDepth, mGroupBlkSize;

        void init(u64 dataSetSize, u64 groupByteSize);
        block query(u64 idx, Channel srv0, Channel Srv1, block seed);

        static void keyGen(u64 idx, block seed, span<block> k0, span<block> g0, span<block> k1, span<block> g1);
    };

}