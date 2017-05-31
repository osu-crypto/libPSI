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

    void BgiPirClient::init(u64 depth, u64 groupByteSize)
    {

        mDatasetSize = 1 << depth;
        mKDepth = depth;
        mGroupSize = groupByteSize;
    }

    block BgiPirClient::query(u64 idx, Channel srv0, Channel srv1, block seed)
    {
        std::vector<block> k0(mKDepth + 1), k1(mKDepth + 1);
        std::vector<u8> g0(mGroupSize), g1(mGroupSize);

        keyGen(idx, seed, k0, g0, k1, g1);
        srv0.asyncSend(std::move(k0));
        srv0.asyncSend(std::move(g0));
        srv1.asyncSend(std::move(k1));
        srv1.asyncSend(std::move(g1));

        block blk0, blk1;

        srv0.recv(&blk0, sizeof(block));
        srv1.recv(&blk1, sizeof(block));

        return blk0 ^ blk1;
    }

    void BgiPirClient::keyGen(u64 idx, block seed, span<block> k0, span<u8> g0, span<block> k1, span<u8> g1)
    {

        // static const std::array<block, 2> zeroOne{ZeroBlock, OneBlock};
        static const std::array<block, 2> zeroAndAllOne{ ZeroBlock, AllOneBlock };
        static const block notOneBlock = OneBlock ^ AllOneBlock;
        static const block notThreeBlock = notOneBlock << 1;

        u64 groupSize = g0.size();
        u64 kIdx = idx / (groupSize * 8);
        u64 gIdx = idx % (groupSize * 8);

        u64 kDepth = k0.size() - 1;
        std::array<std::array<block, 2>, 2> si;
        std::array<block, 2> s = PRNG(seed).get<std::array<block, 2>>();

        // make sure that s[0]'s bottom bit is the opposite of s[1]
        // This bottom bit will prepresent the t values
        s[0] = (s[0] & notOneBlock)           // take the bits [127,1] bits of  s[0]
            ^ ((s[1] & OneBlock) ^ OneBlock); // take the bits [0  ,0] bots of ~s[1]

        k0[0] = s[0];
        k1[0] = s[1];

        static AES aes0(ZeroBlock);
        static AES aes1(OneBlock);

        for (u64 i = 0, shift = kDepth - 1; i < kDepth; ++i, -- shift)
        {
            const u8 keep = (kIdx >> shift) & 1;
            auto a = toBlock(keep);

            //std::cout << "keep[" << i << "]   " << (int)keep << std::endl;

            // AES(s[i][0] & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), si[0].data());
            // AES(s[i][1] & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), si[1].data());

            auto ss0 = s[0] & notThreeBlock;
            auto ss1 = s[1] & notThreeBlock;

            aes0.ecbEncBlock(ss0, si[0][0]);
            aes1.ecbEncBlock(ss0, si[0][1]);
            aes0.ecbEncBlock(ss1, si[1][0]);
            aes1.ecbEncBlock(ss1, si[1][1]);
            si[0][0] = si[0][0] ^ ss0;
            si[0][1] = si[0][1] ^ ss0;
            si[1][0] = si[1][0] ^ ss1;
            si[1][1] = si[1][1] ^ ss1;



            std::array<block, 2> siXOR{ si[0][0] ^ si[1][0], si[0][1] ^ si[1][1] };

            //std::cout << "s0*[" << i << "]    " << stt(si[0][0]) << " " << stt(si[0][1]) << std::endl;
            //std::cout << "s1*[" << i << "]    " << stt(si[1][0]) << " " << stt(si[1][1]) << std::endl;

            // get the left and right t_CW bits
            std::array<block, 2> t{
                (OneBlock & siXOR[0]) ^ a ^ OneBlock,
                (OneBlock & siXOR[1]) ^ a };

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
            auto ti0 = *(u8 *)&s[0] & 1;
            auto ti1 = *(u8 *)&s[1] & 1;

            auto si0Keep = si[0][keep];
            auto si1Keep = si[1][keep];

            // extract the t^Keep_CW bit
            auto TKeep = t[keep];

            // set the next level of s,t
            s[0] = si0Keep ^ (zeroAndAllOne[ti0] & (scw ^ TKeep));
            s[1] = si1Keep ^ (zeroAndAllOne[ti1] & (scw ^ TKeep));

            //std::cout << "s0[" << i + 1 << "]     " << stt(s[0]) << std::endl;
            //std::cout << "s1[" << i + 1 << "]     " << stt(s[1]) << std::endl;
        }

        auto blkSize = (g0.size() + 15) / 16;
        std::vector<block> convertS0(blkSize);
        std::vector<block> convertS1(blkSize);

        //AES(s[0] & notThreeBlock).ecbEncCounterMode(0, blkSize, convertS0.data());
        //AES(s[1] & notThreeBlock).ecbEncCounterMode(0, blkSize, convertS1.data());

        std::array<block, 2> ss{ s[0] & notThreeBlock, s[1] & notThreeBlock };
            


        aes0.ecbEncBlock(ss[0], convertS0[0]);
        aes0.ecbEncBlock(ss[1], convertS1[0]);
        convertS0[0] = convertS0[0] ^ ss[0];
        convertS1[0] = convertS1[0] ^ ss[1];

        //std::cout << "s0 " << stt(s[0] & notThreeBlock) << " -> " << convertS0[0] << std::endl;
        //std::cout << "s1 " << stt(s[1] & notThreeBlock) << " -> " << convertS1[0] << std::endl;

        for (u64 i = 0; i < blkSize; ++i)
        {
            convertS0[i] = convertS0[i] ^ convertS1[i];
        }

        u64 byteIdx = gIdx % 16;
        u64 bitIdx = gIdx / 16;
        if (blkSize != 1) throw std::runtime_error("fix^^^^^ " LOCATION);

        auto u8View = ((u8*)convertS0.data());

        u8View[byteIdx] = u8View[byteIdx] ^ (u8(1) << bitIdx);

        //std::cout << "view[" << byteIdx << "] = " << (int)u8View[byteIdx] << " = " << (int)ss << " ^ (u8(1) << " << bitIdx << ")" << std::endl;

        memcpy(g0.data(), u8View, g0.size());
        memcpy(g1.data(), u8View, g1.size());
    }
}
