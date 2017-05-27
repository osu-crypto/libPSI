#include "BgiPirServer.h"
#include <cryptoTools/Crypto/PRNG.h>

namespace osuCrypto
{
extern std::string ss(block b);
extern std::string t1(block b);
extern std::string t2(block b);
extern std::string stt(block b);

void BgiPirServer::init(u64 depth)
{
    mDepth = depth;
}

void BgiPirServer::serve(Channel chan, span<block> data)
{
    static const std::array<block, 2> zeroAndAllOne{ZeroBlock, AllOneBlock};

    std::vector<block> k(mDepth + 2);
    chan.recv(k.data(), k.size() * sizeof(block));

    block sum = ZeroBlock;
    for (u32 idx = 0; idx < data.size(); ++idx)
    {
        auto b = evalOne(idx, mDepth, k);
        auto add = (data[idx] & zeroAndAllOne[*(u8 *)&b & 1]);
        //std::cout << "add " << idx << " " << add << " " << (*(u8*)&b & 1) << std::endl;
        //chan.send(&b, 16);
        sum = sum ^ add;
    }
    //std::cout << std::endl;
    chan.send(&sum, sizeof(block));
}

block BgiPirServer::evalOne(u64 idx, u64 depth, const std::vector<osuCrypto::block> &k)
{
    // static const std::array<block, 2> zeroOne{ZeroBlock, OneBlock};
    static const std::array<block, 2> zeroAndAllOne{ZeroBlock, AllOneBlock};
    static const block notOneBlock = OneBlock ^ AllOneBlock;
    static const block notThreeBlock = notOneBlock << 1;

    block s = k[0];
    //std::cout << "s         " << stt(s) << std::endl;

    //std::vector<block> ret(depth);

    static AES aes0(ZeroBlock);
    static AES aes1(OneBlock);

    std::array<block, 2> tau, stcw;

    for (u64 i = 0; i < depth; ++i)
    {
        const u8 keep = (idx >> i) & 1;
        ////std::cout << "keep " << (int)keep << std::endl;

        //AES(s & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), tau.data());

        aes0.ecbEncBlock(s & notThreeBlock, *tau.data());
        aes1.ecbEncBlock(s & notThreeBlock, *(tau.data() + 1));
        // TODO: we should probably do more than 1 block at once

        //std::cout << "g[" << i << "][0]   " << stt(tau[0]) << std::endl;
        //std::cout << "g[" << i << "][1]   " << stt(tau[1]) << std::endl;

        const auto &cw = k[i + 1];
        //std::cout << "cw[" << i << "]     " << stt(cw) << std::endl;

        const auto scw = (cw & notThreeBlock);
        const auto mask = zeroAndAllOne[*(u8 *)&s & 1];

        //std::cout << "scw[" << i << "]    " << stt(scw) << std::endl;

        auto d0 = ((cw >> 1) & OneBlock);
        auto d1 = (cw & OneBlock);
        auto c0 = ((scw ^ d0) & mask);
        auto c1 = ((scw ^ d1) & mask);

        stcw[0] = c0 ^ tau[0];
        stcw[1] = c1 ^ tau[1];

        //std::cout << "tau[" << i << "][0] " << stt(stcw[0]) << " = " << stt(c0) << " + " << stt(tau[0]) << " "<< d0 << std::endl;
        //std::cout << "tau[" << i << "][1] " << stt(stcw[1]) << " = " << stt(c1) << " + " << stt(tau[1]) << " "<< d1 << std::endl;

        s = stcw[keep];
        //std::cout << "s[" << (i + 1) << "]      " << stt(s) << std::endl << std::endl;

        //stcw[0] = ZeroBlock;
        //stcw[1] = k.back();
        //ret[i] = (s  ^ stcw[*(u8*)&s & 1]) >> 2;
    }

    stcw[0] = ZeroBlock;
    stcw[1] = k.back();
    return (s ^ stcw[*(u8 *)&s & 1]) >> 2;
    //return ret;
}
}
