#include "BgiPirServer.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Matrix.h>

namespace osuCrypto
{
    extern std::string ss(block b);
    extern std::string t1(block b);
    extern std::string t2(block b);
    extern std::string stt(block b);

    inline u8 lsb(const block& b)
    {
        return *(u8 *)&b & 1;
    }

    void BgiPirServer::init(u64 depth, u64 groupByteSize)
    {
        auto logGroup = log2floor(groupByteSize * 8);
        if (1 << logGroup != groupByteSize * 8)
            throw std::runtime_error("group size should be a power of 2, e.g. 1,2,4,... ");


        mKDepth = depth;
        mGroupSize = groupByteSize;
    }

    void BgiPirServer::serve(Channel chan, span<block> data)
    {
        static const std::array<block, 2> zeroAndAllOne{ ZeroBlock, AllOneBlock };

        std::vector<block> k(mKDepth + 2);
        std::vector<u8> groupWord(mGroupSize);
        chan.recv(k.data(), k.size() * sizeof(block));

        block sum = ZeroBlock;
        for (u32 idx = 0; idx < data.size(); ++idx)
        {
            auto b = evalOne(idx, k, groupWord);
            auto add = (data[idx] & zeroAndAllOne[b & 1]);
            //std::cout << "add " << idx << " " << add << " " << (*(u8*)&b & 1) << std::endl;
            //chan.send(&b, 16);
            sum = sum ^ add;
        }
        //std::cout << std::endl;
        chan.send(&sum, sizeof(block));
    }

    static AES aes0(ZeroBlock);
    static AES aes1(OneBlock);
    static const std::array<block, 2> zeroAndAllOne{ ZeroBlock, AllOneBlock };
    static const block notThreeBlock = (OneBlock ^ AllOneBlock) << 1;

    u8 BgiPirServer::evalOne(u64 idx, span<block> k, span<u8> g, block* bb, block* ss, u8* tt)
    {
        // static const std::array<block, 2> zeroOne{ZeroBlock, OneBlock};
        u64 kDepth = k.size() - 1;
        u64 kIdx = idx / (g.size() * 8);
        u64 gIdx = idx % (g.size() * 8);
        //std::cout << "s         " << stt(s) << std::endl;

        //std::vector<block> ret(kDepth);


        auto s = traversePath(kDepth, kIdx, k);


        auto blkSize = (g.size() + 15) / 16;
        //u64 byteIdx = remIdx / 8;
        //u64 bitIdx = remIdx % 8;
        u64 byteIdx = gIdx % 16;
        u64 bitIdx = gIdx / 16;
        if (blkSize != 1) throw std::runtime_error("fix^^^^^ " LOCATION);

        std::vector<block> convertS(blkSize);


        block sss = s & notThreeBlock;
        aes0.ecbEncBlock(sss, convertS[0]);
        convertS[0] = convertS[0] ^ sss;
        //AES(s & notThreeBlock).ecbEncCounterMode(0, blkSize, convertS.data());
        //std::cout << "*s " << (s & notThreeBlock) << " -> " << convertS[0] << std::endl;


        u8 t = lsb(s);


        auto view = (u8*)convertS.data();

        u8 word = (view[byteIdx] ^ (g[byteIdx] * t)) >> (bitIdx);
        //std::cout << "word = " << (int)word << " = " << (int)view[byteIdx] << " ^ (" << (int)g[byteIdx] << " * " << (int)t_cw << ")" << std::endl;

        if (ss) *ss = (convertS[0]);
        if (bb) *bb = (convertS[0] ^ (zeroAndAllOne[t] & *(block*)g.data()));
        if (tt) *tt = t;

        return word & 1;
        //return ret;
    }

    block BgiPirServer::traversePath(u64 depth, u64 idx, span<block> k)
    {
        block s = k[0];

        for (u64 i = 0, shift = depth - 1; i < depth; ++i, --shift)
        {
            const u8 keep = (idx >> shift) & 1;
            ////std::cout << "keep " << (int)keep << std::endl;

            //AES(s & notThreeBlock).ecbEncTwoBlocks(zeroOne.data(), tau.data());
            s = traverseOne(s, k[i + 1], keep);
            //std::cout << "s[" << (i + 1) << "]      " << stt(s) << std::endl << std::endl;
        }
        return s;
    }

    block BgiPirServer::traverseOne(const block& s, const block& cw, const u8 &keep, bool print)
    {

        std::array<block, 2> tau, stcw;

        auto ss = s & notThreeBlock;
        aes0.ecbEncBlock(ss, tau[0]);
        aes1.ecbEncBlock(ss, tau[1]);
        tau[0] = tau[0] ^ ss;
        tau[1] = tau[1] ^ ss;


        // TODO: we should probably do more than 1 block at once

        //std::cout << "g[" << i << "][0]   " << stt(tau[0]) << std::endl;
        //std::cout << "g[" << i << "][1]   " << stt(tau[1]) << std::endl;

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

        if (print)
        {
            std::cout << "tau[0] " << stt(stcw[0]) << " = " << stt(c0) << " + " << stt(tau[0]) << " " << d0 << std::endl;
            std::cout << "tau[1] " << stt(stcw[1]) << " = " << stt(c1) << " + " << stt(tau[1]) << " " << d1 << std::endl;
        }

        return stcw[keep];
    }

    block BgiPirServer::fullDomain(span<block> data, span<block> k, span<u8> g)
    {
        static const std::array<block, 2> zeroAndAllOne{ ZeroBlock, AllOneBlock };
        static const block notOneBlock = OneBlock ^ AllOneBlock;
        static const block notThreeBlock = notOneBlock << 1;
        u64 kDepth = k.size() - 1;


        // since we don't want to do bit shifting, this larger array
        // will be used to hold each bit of challengeBuff as a whole
        // byte. See below for how we do this efficiently.
        std::array<block, 64> expandedS;

        // This will be used to compute expandedS
        block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

        std::array<AES, 2> aes;
        aes[0].setKey(ZeroBlock);
        aes[1].setKey(OneBlock);

        std::vector<std::array<block, 8>> ss(kDepth - 2);

        // create 8 subtrees each with starting seed ss[0]
        ss[0][0] = traversePath(3, 0, k);
        ss[0][1] = traversePath(3, 1, k);
        ss[0][2] = traversePath(3, 2, k);
        ss[0][3] = traversePath(3, 3, k);
        ss[0][4] = traversePath(3, 4, k);
        ss[0][5] = traversePath(3, 5, k);
        ss[0][6] = traversePath(3, 6, k);
        ss[0][7] = traversePath(3, 7, k);


        //std::cout << "s(0, 3) " << stt(ss[0][0]) << std::endl;

        std::array<block, 8> tau, s, stcw, sums = { ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock ,ZeroBlock };

        //MultiKeyAES<8> H(stcw1);

        u64 idx = 0;
        u64 d = 0;
        auto dEnd = std::max<u64>(kDepth, 3) - 3;
        u64 end = u64(1) << dEnd;


        auto kk = k.data() + 4;
        // extract the correction bits t_cw^L_CW, t_cw^R_CW
        std::vector<std::array<block, 2>> t_cw(dEnd);
        for (u64 i = 0; i < dEnd; ++i)
        {
            t_cw[i][0] = (kk[i] >> 1) & OneBlock;
            t_cw[i][1] = kk[i] & OneBlock;
        }


        while (idx != end)
        {
            while (d != dEnd)
            {
                auto pIdx = (idx >> (dEnd - 1 - d));
                u8 keep = pIdx & 1;

                auto& G = aes[keep];
                u8 t0 = lsb(ss[d][0]);
                u8 t1 = lsb(ss[d][1]);
                u8 t2 = lsb(ss[d][2]);
                u8 t3 = lsb(ss[d][3]);
                u8 t4 = lsb(ss[d][4]);
                u8 t5 = lsb(ss[d][5]);
                u8 t6 = lsb(ss[d][6]);
                u8 t7 = lsb(ss[d][7]);

                s[0] = ss[d][0] & notThreeBlock;
                s[1] = ss[d][1] & notThreeBlock;
                s[2] = ss[d][2] & notThreeBlock;
                s[3] = ss[d][3] & notThreeBlock;
                s[4] = ss[d][4] & notThreeBlock;
                s[5] = ss[d][5] & notThreeBlock;
                s[6] = ss[d][6] & notThreeBlock;
                s[7] = ss[d][7] & notThreeBlock;

                // compute G(s) = AES_{x_i}(s) + s
                G.ecbEncBlocks(s.data(), 8, tau.data());
                tau[0] = s[0] ^ tau[0];
                tau[1] = s[1] ^ tau[1];
                tau[2] = s[2] ^ tau[2];
                tau[3] = s[3] ^ tau[3];
                tau[4] = s[4] ^ tau[4];
                tau[5] = s[5] ^ tau[5];
                tau[6] = s[6] ^ tau[6];
                tau[7] = s[7] ^ tau[7];


                block cw = t_cw[d][keep] ^ (kk[d] & notThreeBlock);

                stcw[0] = cw & zeroAndAllOne[t0];
                stcw[1] = cw & zeroAndAllOne[t1];
                stcw[2] = cw & zeroAndAllOne[t2];
                stcw[3] = cw & zeroAndAllOne[t3];
                stcw[4] = cw & zeroAndAllOne[t4];
                stcw[5] = cw & zeroAndAllOne[t5];
                stcw[6] = cw & zeroAndAllOne[t6];
                stcw[7] = cw & zeroAndAllOne[t7];

                ss[d + 1][0] = stcw[0] ^ tau[0];
                ss[d + 1][1] = stcw[1] ^ tau[1];
                ss[d + 1][2] = stcw[2] ^ tau[2];
                ss[d + 1][3] = stcw[3] ^ tau[3];
                ss[d + 1][4] = stcw[4] ^ tau[4];
                ss[d + 1][5] = stcw[5] ^ tau[5];
                ss[d + 1][6] = stcw[6] ^ tau[6];
                ss[d + 1][7] = stcw[7] ^ tau[7];

                //auto s0 = traversePath(d + 4, (0 << (d+1)) + pIdx, k);
                //auto s1 = traversePath(d + 4, (1 << (d+1)) + pIdx, k);
                //auto s2 = traversePath(d + 4, (2 << (d+1)) + pIdx, k);
                //auto s3 = traversePath(d + 4, (3 << (d+1)) + pIdx, k);
                //auto s4 = traversePath(d + 4, (4 << (d+1)) + pIdx, k);
                //auto s5 = traversePath(d + 4, (5 << (d+1)) + pIdx, k);
                //auto s6 = traversePath(d + 4, (6 << (d+1)) + pIdx, k);
                //auto s7 = traversePath(d + 4, (7 << (d+1)) + pIdx, k);

                //if (neq(s0, ss[d + 1][0])) { std::cout << pIdx << " 0 " << stt(stcw[0]) << " ^ " << stt(tau[0]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s1, ss[d + 1][1])) { std::cout << pIdx << " 1 " << stt(stcw[1]) << " ^ " << stt(tau[1]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s2, ss[d + 1][2])) { std::cout << pIdx << " 2 " << stt(stcw[2]) << " ^ " << stt(tau[2]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s3, ss[d + 1][3])) { std::cout << pIdx << " 3 " << stt(stcw[3]) << " ^ " << stt(tau[3]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s4, ss[d + 1][4])) { std::cout << pIdx << " 4 " << stt(stcw[4]) << " ^ " << stt(tau[4]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s5, ss[d + 1][5])) { std::cout << pIdx << " 5 " << stt(stcw[5]) << " ^ " << stt(tau[5]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s6, ss[d + 1][6])) { std::cout << pIdx << " 6 " << stt(stcw[6]) << " ^ " << stt(tau[6]) << std::endl; throw std::runtime_error(LOCATION); }
                //if (neq(s7, ss[d + 1][7])) { std::cout << pIdx << " 7 " << stt(stcw[7]) << " ^ " << stt(tau[7]) << std::endl; throw std::runtime_error(LOCATION); }

                ++d;
            }




            auto blkSize = (g.size() + 15) / 16;
            //std::vector<block> convertS(blkSize);
            if (blkSize != 1) throw std::runtime_error(LOCATION);

            std::array<u8, 8> t;
            t[0] = lsb(ss[d][0]);
            t[1] = lsb(ss[d][1]);
            t[2] = lsb(ss[d][2]);
            t[3] = lsb(ss[d][3]);
            t[4] = lsb(ss[d][4]);
            t[5] = lsb(ss[d][5]);
            t[6] = lsb(ss[d][6]);
            t[7] = lsb(ss[d][7]);


            s[0] = ss[d][0] & notThreeBlock;
            s[1] = ss[d][1] & notThreeBlock;
            s[2] = ss[d][2] & notThreeBlock;
            s[3] = ss[d][3] & notThreeBlock;
            s[4] = ss[d][4] & notThreeBlock;
            s[5] = ss[d][5] & notThreeBlock;
            s[6] = ss[d][6] & notThreeBlock;
            s[7] = ss[d][7] & notThreeBlock;


            // compute G(s) = AES_{x_i}(s) + s
            aes[0].ecbEncBlocks(s.data(), 8, tau.data());
            
            s[0] = s[0] ^ tau[0];
            s[1] = s[1] ^ tau[1];
            s[2] = s[2] ^ tau[2];
            s[3] = s[3] ^ tau[3];
            s[4] = s[4] ^ tau[4];
            s[5] = s[5] ^ tau[5];
            s[6] = s[6] ^ tau[6];
            s[7] = s[7] ^ tau[7];

            tau[0] = s[0] ^ (*(block*)g.data() & zeroAndAllOne[t[0]]);
            tau[1] = s[1] ^ (*(block*)g.data() & zeroAndAllOne[t[1]]);
            tau[2] = s[2] ^ (*(block*)g.data() & zeroAndAllOne[t[2]]);
            tau[3] = s[3] ^ (*(block*)g.data() & zeroAndAllOne[t[3]]);
            tau[4] = s[4] ^ (*(block*)g.data() & zeroAndAllOne[t[4]]);
            tau[5] = s[5] ^ (*(block*)g.data() & zeroAndAllOne[t[5]]);
            tau[6] = s[6] ^ (*(block*)g.data() & zeroAndAllOne[t[6]]);
            tau[7] = s[7] ^ (*(block*)g.data() & zeroAndAllOne[t[7]]);

            for (u64 i = 0; i < 8; ++i)
            {
                //block sss = ss.back()[i];
                //block convert_;
                //AES(sss & notThreeBlock).ecbEncCounterMode(0, blkSize, &convert_);

                ////if()
                //converts[i] = convert_ ^ (*(block*)g.data() & zeroAndAllOne[lsb(sss)]);


                std::cout << idx << " s" << i << " " << stt(ss[d][i]) << " -> " << tau[i] << " = " << s[i] << " ^ (" << *(block*)g.data() << " * " << int(t[i]) << ")" << std::endl;


                expandedS[i * 8 + 0] = mask & _mm_srai_epi16(tau[i], 0);
                expandedS[i * 8 + 1] = mask & _mm_srai_epi16(tau[i], 1);
                expandedS[i * 8 + 2] = mask & _mm_srai_epi16(tau[i], 2);
                expandedS[i * 8 + 3] = mask & _mm_srai_epi16(tau[i], 3);
                expandedS[i * 8 + 4] = mask & _mm_srai_epi16(tau[i], 4);
                expandedS[i * 8 + 5] = mask & _mm_srai_epi16(tau[i], 5);
                expandedS[i * 8 + 6] = mask & _mm_srai_epi16(tau[i], 6);
                expandedS[i * 8 + 7] = mask & _mm_srai_epi16(tau[i], 7);
            }

            u8* byteView = (u8*)expandedS.data();
            //std::cout << (u64)k.data() << std::endl;
            //for (u64 i = 0; i < 128; ++i)
            //{
            //    std::cout << (int)byteView[128 * 0 + i] ;
            //}
            //std::cout << std::endl;

            auto inputIter = data.data() + (idx << 3) * 128;

            for (u64 i = 0; i < 128; ++i)
            {
                //std::cout << ((idx << 3) + 128 * 0 + i) << " " << int(byteView[128 * 0 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 1 + i) << " " << int(byteView[128 * 1 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 2 + i) << " " << int(byteView[128 * 2 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 3 + i) << " " << int(byteView[128 * 3 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 4 + i) << " " << int(byteView[128 * 4 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 5 + i) << " " << int(byteView[128 * 5 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 6 + i) << " " << int(byteView[128 * 6 + i]) << std::endl;
                //std::cout << ((idx << 3) + 128 * 7 + i) << " " << int(byteView[128 * 7 + i]) << std::endl;
                //bv[(idx << 3) + 128 * 0 + i] = byteView[128 * 0 + i];
                block bb, ss;
                u8 tt;
                u64 ii = idx * 128 + i;
                u8 bit = evalOne(ii, k, g, &bb, &ss, &tt);

                if (byteView[128 * 0 + i] != bit)
                {
                    std::cout << (ii) << " * " << tau[0] << " " << bb << " = " << ss << "( _____ * " << int(tt) << ")  " << int(byteView[128 * 0 + i]) << " != " << int(bit) << std::endl;
                    throw std::runtime_error(LOCATION);
                }
                else
                {
                    //std::cout <<(ii) << " * "<< converts[0] << " " << bb << "  " << int(tt) << "  " << int(byteView[128 * 0 + i])<<" == " <<int(bit )<< std::endl;

                }
                //if (byteView[128 * 1 + i] != (bool)evalOne((idx << 3) + 128 * 1 + i, k, g)) throw std::runtime_error(LOCATION);
                //if (byteView[128 * 2 + i] != (bool)evalOne((idx << 3) + 128 * 2 + i, k, g)) throw std::runtime_error(LOCATION);
                //if (byteView[128 * 3 + i] != (bool)evalOne((idx << 3) + 128 * 3 + i, k, g)) throw std::runtime_error(LOCATION);
                //if (byteView[128 * 4 + i] != (bool)evalOne((idx << 3) + 128 * 4 + i, k, g)) throw std::runtime_error(LOCATION);
                //if (byteView[128 * 5 + i] != (bool)evalOne((idx << 3) + 128 * 5 + i, k, g)) throw std::runtime_error(LOCATION);
                //if (byteView[128 * 6 + i] != (bool)evalOne((idx << 3) + 128 * 6 + i, k, g)) throw std::runtime_error(LOCATION);
                //if (byteView[128 * 7 + i] != (bool)evalOne((idx << 3) + 128 * 7 + i, k, g)) throw std::runtime_error(LOCATION);

                sums[0] = sums[0] ^ (inputIter[128 * 0 + i] & zeroAndAllOne[byteView[128 * 0 + i]]);
                sums[1] = sums[1] ^ (inputIter[128 * 1 + i] & zeroAndAllOne[byteView[128 * 1 + i]]);
                sums[2] = sums[2] ^ (inputIter[128 * 2 + i] & zeroAndAllOne[byteView[128 * 2 + i]]);
                sums[3] = sums[3] ^ (inputIter[128 * 3 + i] & zeroAndAllOne[byteView[128 * 3 + i]]);
                sums[4] = sums[4] ^ (inputIter[128 * 4 + i] & zeroAndAllOne[byteView[128 * 4 + i]]);
                sums[5] = sums[5] ^ (inputIter[128 * 5 + i] & zeroAndAllOne[byteView[128 * 5 + i]]);
                sums[6] = sums[6] ^ (inputIter[128 * 6 + i] & zeroAndAllOne[byteView[128 * 6 + i]]);
                sums[7] = sums[7] ^ (inputIter[128 * 7 + i] & zeroAndAllOne[byteView[128 * 7 + i]]);
            }

            //std::cout << "s(" << ((idx << 3) + 0) << ", " << d << ") = " << stt(ss.back()[0]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 1) << ", " << d << ") = " << stt(ss.back()[1]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 2) << ", " << d << ") = " << stt(ss.back()[2]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 3) << ", " << d << ") = " << stt(ss.back()[3]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 4) << ", " << d << ") = " << stt(ss.back()[4]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 5) << ", " << d << ") = " << stt(ss.back()[5]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 6) << ", " << d << ") = " << stt(ss.back()[6]) << std::endl;
            //std::cout << "s(" << ((idx << 3) + 7) << ", " << d << ") = " << stt(ss.back()[7]) << std::endl;



            u64 shift = (idx + 1) ^ idx;
            d -= log2floor(shift) + 1;
            ++idx;
        }

        //std::cout << std::endl;

        return sums[0]
            ^ sums[1]
            ^ sums[2]
            ^ sums[3]
            ^ sums[4]
            ^ sums[5]
            ^ sums[6]
            ^ sums[7];
    }
}
