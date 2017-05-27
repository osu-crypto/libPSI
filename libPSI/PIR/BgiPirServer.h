#pragma once
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Common/ArrayView.h>
namespace osuCrypto
{

class BgiPirServer
{
public:
    u64 mDepth;

    void init(u64 depth);

    void serve(Channel chan, span<block> data);

    static block evalOne(u64 idx, u64 depth, const std::vector<osuCrypto::block> &k);


};

}
