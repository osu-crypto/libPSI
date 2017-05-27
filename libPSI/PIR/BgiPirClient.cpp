#include "BgiPirClient.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>
namespace osuCrypto
{
std::string ss(block b)
{
    std::stringstream ss;

    b = b >> 2;
    ss << b;
    return ss.str();
}
std::string t1(block b)
{
    std::stringstream ss;
    ss << (int)((*(u8 *)&b) & 1);
    return ss.str();
}
std::string t2(block b)
{
    std::stringstream ss;
    ss << ((int)((*(u8 *)&b) & 2) >> 1);
    return ss.str();
}
std::string stt(block b)
{
    return ss(b) + " " + t2(b) + " " + t1(b);
}

void BgiPirClient::init(u64 depth)
{
    mDatasetSize = 1 << depth;
    mDepth = depth;
}

block BgiPirClient::query(u64 idx, Channel srv0, Channel srv1, block seed)
{
    std::vector<block> k0(mDepth + 2), k1(mDepth + 2);

    keyGen(idx, mDepth, seed, k0, k1);
    srv0.asyncSend(std::move(k0));
    srv1.asyncSend(std::move(k1));

    block blk0, blk1;

    srv0.recv(&blk0, sizeof(block));
    srv1.recv(&blk1, sizeof(block));

    return blk0 ^ blk1;
}

void BgiPirClient::keyGen(u64 idx, u64 depth, block seed, std::vector<block> &k0, std::vector<block> &k1)
{

    // static const std::array<block, 2> zeroOne{ZeroBlock, OneBlock};
    static const std::array<block, 2> zeroAndAllOne{ZeroBlock, AllOneBlock};
    static const block notOneBlock = OneBlock ^ AllOneBlock;
    static const block notThreeBlock = notOneBlock << 1;

    std::array<std::array<block, 2>, 2> si;
    std::vector<std::array<block, 2>> s(depth + 1);
    s[0] = PRNG(seed).get<std::array<block, 2>>();

    // make sure that s[0][0]'s bottom bit is the opposite of s[0][1]
    // This bottom bit will prepresent the t values
    s[0][0] = (s[0][0] & notOneBlock)               // take the bits [127,1] bits of  s[0][0]
              ^ ((s[0][1] & OneBlock) ^ OneBlock); // take the bits [0  ,0] bots of ~s[0][1]

    //std::cout << "s0[0] " << stt(s[0][0]) << "\ns1[0] " << stt(s[0][1]) << std::endl;

    k0.resize(depth + 2);
    k1.resize(depth + 2);
    k0[0] = s[0][0];
    k1[0] = s[0][1];

    static AES aes0(ZeroBlock);
    static AES aes1(OneBlock);

    for (u64 i = 0; i < depth; ++i)
    {
        const u8 keep = (idx >> i) & 1;
        auto a = toBlock(keep);

        //std::cout << "keep[" << i << "]   " << (int)keep << std::endl;

        // AES(s[i][0] & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), si[0].data());
        // AES(s[i][1] & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), si[1].data());

        aes0.ecbEncBlock(s[i][0] & notThreeBlock, *si[0].data());
        aes1.ecbEncBlock(s[i][0] & notThreeBlock, *(si[0].data() + 1));

        aes0.ecbEncBlock(s[i][1] & notThreeBlock, *si[1].data());
        aes1.ecbEncBlock(s[i][1] & notThreeBlock, *(si[1].data() + 1));

        std::array<block, 2> siXOR{si[0][0] ^ si[1][0], si[0][1] ^ si[1][1]};

        //std::cout << "s0*[" << i << "]    " << stt(si[0][0]) << " " << stt(si[0][1]) << std::endl;
        //std::cout << "s1*[" << i << "]    " << stt(si[1][0]) << " " << stt(si[1][1]) << std::endl;

        // get the left and right t_CW bits
        std::array<block, 2> t{
            (OneBlock & siXOR[0]) ^ a ^ OneBlock,
            (OneBlock & siXOR[1]) ^ a};

        // take scw to be the bits [127, 2] as scw = s0_loss ^ s1_loss
        auto scw = siXOR[keep ^ 1] & notThreeBlock;

        //std::cout << "scw[" << i << "]    " << stt(scw) << std::endl;
        //std::cout << "tL[" << i << "]     " << t1(t[0]) << std::endl;
        //std::cout << "tR[" << i << "]     " << t1(t[1]) << std::endl;

        k0[i + 1] = k1[i + 1] = scw              // set bits [127, 2] as scw = s0_loss ^ s1_loss
                                ^ (t[0] << 1) // set bit 1 as tL
                                ^ t[1];          // set bit 0 as tR

        //std::cout << "CW[" << i << "]     " << stt(k0[i + 1]) << std::endl;

        // get the the conditional XOR bits t^L_CW, t^R_CW
        auto ti0 = *(u8 *)&s[i][0] & 1;
        auto ti1 = *(u8 *)&s[i][1] & 1;

        auto si0Keep = si[0][keep];
        auto si1Keep = si[1][keep];

        // extract the t^Keep_CW bit
        auto TKeep = t[keep];

        // set the next level of s,t
        s[i + 1][0] = si0Keep ^ (zeroAndAllOne[ti0] & (scw ^ TKeep));
        s[i + 1][1] = si1Keep ^ (zeroAndAllOne[ti1] & (scw ^ TKeep));

        //std::cout << "s0[" << i + 1 << "]     " << stt(s[i + 1][0]) << " = "  << stt(si0Keep) << " ^ "<< (int)ti0 << " * (" << stt(scw) << " ^ " << stt(TKeep) << ")" << std::endl;
        //std::cout << "s1[" << i + 1 << "]     " << stt(s[i + 1][1]) << " = "  << stt(si1Keep) << " ^ "<< (int)ti1 << " * (" << stt(scw) << " ^ " << stt(TKeep) << ")" << std::endl << std::endl;
    }

    k1.back() = k0.back() = (OneBlock << 2) ^ s.back()[0] ^ s.back()[1];

    //std::cout << "CW'       " << stt(k0.back()) << std::endl << std::endl;
}
}
