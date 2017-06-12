#include "BgiPirServer.h"
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Matrix.h>
#include <libPSI/PIR/BgiPirClient.h>
namespace osuCrypto
{

    static AES aes0(toBlock(u64(0)));
    static AES aes1(toBlock(1));
    static const block notThreeBlock = toBlock(~0, ~3);


    //BitVector BgiPirServer::BgiPirServer_bv;
    extern std::string ss(block b);
    extern std::string t1(block b);
    extern std::string t2(block b);
    extern std::string stt(block b);

    inline u8 lsb(const block& b)
    {
        return  _mm_cvtsi128_si64x(b) & 1;
    }

    void BgiPirServer::init(u64 depth, u64 groupBlkSize)
    {
        mKDepth = depth;
        mGroupBlkSize = groupBlkSize;
    }

    void BgiPirServer::serve(Channel chan, span<block> data)
    {

        std::vector<block> k(mKDepth + 1);
        std::vector<block> groupWord(mGroupBlkSize);
        chan.recv(k.data(), k.size() * sizeof(block));
        chan.recv(groupWord.data(), groupWord.size() * sizeof(block));

        auto sum = fullDomain(data, k, groupWord);
        //block sum = ZeroBlock;
        //for (u32 idx = 0; idx < data.size(); ++idx)
        //{
        //    auto b = evalOne(idx, k, groupWord);
        //    auto add = (data[idx] & zeroAndAllOne[b & 1]);
        //    //std::cout << "add " << idx << " " << add << " " << (*(u8*)&b & 1) << std::endl;
        //    //chan.send(&b, 16);
        //    sum = sum ^ add;
        //}
        //std::cout << std::endl;
        chan.send(&sum, sizeof(block));
    }

    u8 BgiPirServer::evalOne(span<u8> idx, span<block> k, span<block> g, block* bb, block* ss, u8* tt)
    {
        return  evalOne(BgiPirClient::bytesToUint128_t(idx), k, g, bb, ss, tt);
    }

    u8 BgiPirServer::evalOne(uint128_t idx, span<block> k, span<block> g, block* bb, block* ss, u8* tt)
    {

        // static const std::array<block, 2> zeroOne{ZeroBlock, OneBlock};
        u64 kDepth = k.size() - 1;
        auto kIdx = idx / (g.size() * 128);
        u64 gIdx = static_cast<u64>(idx % (g.size() * 128));
        u64 byteIdx = gIdx % 16 + 16 * (gIdx / 128);
        u64 bitIdx = (gIdx % 128) / 16;
        //std::cout << "s         " << stt(s) << std::endl;

        //std::vector<block> ret(kDepth);

        //assert(lsb(OneBlock) == 1);
        auto s = traversePath(kDepth, kIdx, k);

        //if (idx > 255)
        //{
        //    std::cout << "s " << s << " " << kDepth << " " << kIdx << " " << gIdx << " " << int(lsb(s)) << std::endl;
        //    std::cout << "  " << zeroAndAllOne[0] << " " << zeroAndAllOne[1] << " " << AllOneBlock << std::endl;
        //}


        std::vector<block> temp(g.size() * 2);
        auto gs = temp.data();
        auto l = temp.data() + g.size();

        block sss = s & notThreeBlock;

        for (u64 i = 0; i < g.size(); ++i)
        {
            l[i] = sss ^ toBlock(i);
        }


        aes0.ecbEncBlocks(l, g.size(), gs);
        for (u64 i = 0; i < g.size(); ++i)
        {
            gs[i] = gs[i] ^ l[i];
        }

        u8 t = lsb(s);
        //if (idx == 2306)
        //{
        //    std::cout << " byte " << byteIdx << " bit " << bitIdx << std::endl;
        //    std::cout << idx << " " << gs[0] << " " << gs[1] << " = G(" << l[0] << " " << l[1] << ")" << std::endl;
        //    std::cout << "gc + cw* t = " << (gs[0] ^ (zeroAndAllOne[t] & g[0])) <<" " << (gs[1] ^ (zeroAndAllOne[t] & g[1])) << " = " << gs[0] << "  " << gs[1] << " ^ (" << g[0] << " " << g[1] << " * " << int(t) << ")" << std::endl;;

        //}

        auto gBytes = (u8*)g.data();
        auto view = (u8*)gs;

        u8 word = (view[byteIdx] ^ (gBytes[byteIdx] * t)) >> (bitIdx);
        //std::cout << "word = " << (int)word << " = " << (int)view[byteIdx] << " ^ (" << int(gBytes[byteIdx]) << " * " << (int)t << ")  byte " << byteIdx << " bit " << bitIdx << " k " << kIdx << std::endl;

        if (ss) *ss = (gs[(gIdx / 128)]);
        if (bb) *bb = (gs[(gIdx / 128)] ^ (zeroAndAllOne[t] & g[(gIdx / 128)]));
        if (tt) *tt = t;

        return word & 1;
        //return ret;
    }

    block BgiPirServer::traversePath(u64 depth, uint128_t idx, span<block> k)
    {
        block s = k[0];

        for (u64 i = 0, shift = depth - 1; i < depth; ++i, --shift)
        {
            const u8 keep = static_cast<u8>(idx >> shift) & 1;
            s = traverseOne(s, k[i + 1], keep);

            //if(idx == 2)std::cout << "i = " << i << " -> " << s << std::endl;
        }
        return s;
    }

    block BgiPirServer::traverseOne(const block& s, const block& cw, const u8 &keep, bool print)
    {

        std::array<block, 2> tau, stcw;
        //std::cout << "notTHree" << notThreeBlock << std::endl;
        auto ss = s & notThreeBlock;
        aes0.ecbEncBlock(ss, tau[0]);
        aes1.ecbEncBlock(ss, tau[1]);
        tau[0] = tau[0] ^ ss;
        tau[1] = tau[1] ^ ss;


        const auto scw = (cw & notThreeBlock);
        const auto mask = zeroAndAllOne[lsb(s)];

        auto d0 = ((cw >> 1) & OneBlock);
        auto d1 = (cw & OneBlock);
        auto c0 = ((scw ^ d0) & mask);
        auto c1 = ((scw ^ d1) & mask);

        //std::cout << "s  " << s << std::endl;
        //std::cout << "c0 " << c0 << std::endl;
        //std::cout << "c1 " << c1 << std::endl;

        stcw[0] = c0 ^ tau[0];
        stcw[1] = c1 ^ tau[1];

        //if (print)
        //{
        //    std::cout << "tau[0] " << stt(stcw[0]) << " = " << stt(c0) << " + " << stt(tau[0]) << " " << d0 << std::endl;
        //    std::cout << "tau[1] " << stt(stcw[1]) << " = " << stt(c1) << " + " << stt(tau[1]) << " " << d1 << std::endl;
        //}

        return stcw[keep];
    }
    block BgiPirServer::fullDomain(span<block> data, span<block> k, span<block> g)
    {
        u64 kDepth = k.size() - 1;
        static const block mask = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);

        if (data.size() != (1 << (k.size() - 1)) * g.size() * 128)
            throw std::runtime_error(LOCATION);

        std::vector<block> prev{ k[0] }, next;
        for (u64 i = 0; i < std::min<u64>(3, kDepth); ++i)
        {
            next.resize(1 << (i + 1));
            for (u64 j = 0; j < prev.size(); ++j)
            {
                next[j * 2 + 0] = traverseOne(prev[j], k[i + 1], 0);
                next[j * 2 + 1] = traverseOne(prev[j], k[i + 1], 1);
            }

            std::swap(prev, next);
        }

        //if (neq(traversePath(kDepth, 0, k), prev[0]))
        //    throw std::runtime_error(LOCATION);
        //if (neq(traversePath(kDepth, 1, k), prev[1]))
        //    throw std::runtime_error(LOCATION);

        if (kDepth < 3)
        {
            block sum = ZeroBlock;
            auto dataIter = data.begin();

            std::array<block, 8> expandedS;
            auto byteView = (u8*)expandedS.data();
            std::vector<block> l(g.size()), gs(g.size());
            for (u64 kIdx = 0; kIdx < prev.size(); ++kIdx)
            {
                u8 t = lsb(prev[kIdx]);

                for (u64 i = 0; i < g.size(); ++i) l[i] = (prev[kIdx] & notThreeBlock) ^ toBlock(i);
                aes0.ecbEncBlocks(l.data(), g.size(), gs.data());
                for (u64 i = 0; i < g.size(); ++i) gs[i] = gs[i] ^ l[i] ^ (g[i] & zeroAndAllOne[t]);


                //std::cout << "k " << kIdx << "  " << gs[0] << std::endl;

                for (u64 gIdx = 0; gIdx < g.size(); ++gIdx)
                {
                    expandedS[0] = mask & _mm_srai_epi16(gs[gIdx], 0);
                    expandedS[1] = mask & _mm_srai_epi16(gs[gIdx], 1);
                    expandedS[2] = mask & _mm_srai_epi16(gs[gIdx], 2);
                    expandedS[3] = mask & _mm_srai_epi16(gs[gIdx], 3);
                    expandedS[4] = mask & _mm_srai_epi16(gs[gIdx], 4);
                    expandedS[5] = mask & _mm_srai_epi16(gs[gIdx], 5);
                    expandedS[6] = mask & _mm_srai_epi16(gs[gIdx], 6);
                    expandedS[7] = mask & _mm_srai_epi16(gs[gIdx], 7);

                    for (u64 bIdx = 0; bIdx < 128; ++bIdx)
                    {
                        sum = sum ^ (*dataIter++ & zeroAndAllOne[byteView[bIdx]]);
                        //#ifndef NDEBUG
                        //                        u64 byteIdx = bIdx % 16 + 16 * gIdx;
                        //                        u64 bitIdx = (bIdx) / 16;
                        //                        auto bit = BitIterator((u8*)gs.data() + byteIdx, bitIdx);
                        //                        if (*bit != byteView[bIdx])
                        //                            throw std::runtime_error(LOCATION);
                        //
                        //                        auto idx = dataIter - data.begin() - 1;
                        //
                        //                        u8 ttt;
                        //                        block bbb, sss;
                        //                        u8 bb = evalOne(idx, k, g,&bbb,&sss,&ttt );
                        //
                        //                        if (bb != byteView[bIdx])
                        //                        {
                        //                            std::cout << "failed at " << idx << std::endl;
                        //                            //return sum;
                        //                            //throw std::runtime_error(LOCATION);
                        //                        }
                        //#endif
                    }

                }
            }
            return sum;
        }
        else
        {
            // since we don't want to do bit shifting, this larger array
            // will be used to hold each bit of challengeBuff as a whole
            // byte. See below for how we do this efficiently.
            std::vector<block> expandedS(64 * g.size());

            // This will be used to compute expandedS

            std::array<AES, 2> aes;
            aes[0].setKey(ZeroBlock);
            aes[1].setKey(OneBlock);

            std::vector<std::array<block, 8>> ss(kDepth - 2);
            std::vector<std::array<block, 8>> temp(g.size()), enc(g.size());

            // create 8 subtrees each with starting seed ss[0]
            ss[0][0] = prev[0];
            ss[0][1] = prev[1];
            ss[0][2] = prev[2];
            ss[0][3] = prev[3];
            ss[0][4] = prev[4];
            ss[0][5] = prev[5];
            ss[0][6] = prev[6];
            ss[0][7] = prev[7];
            //ss[0][0] = traversePath(3, 0, k);
            //ss[0][1] = traversePath(3, 1, k);
            //ss[0][2] = traversePath(3, 2, k);
            //ss[0][3] = traversePath(3, 3, k);
            //ss[0][4] = traversePath(3, 4, k);
            //ss[0][5] = traversePath(3, 5, k);
            //ss[0][6] = traversePath(3, 6, k);
            //ss[0][7] = traversePath(3, 7, k);


            //std::cout << "s(0, 0) " << stt(ss[0][0]) << std::endl;

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
            //BgiPirServer_bv.resize(((1 << kDepth) + g.size()) * 128);

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




                //auto blkSize = (g.size() + 15) / 16;
                ////std::vector<block> convertS(blkSize);
                //if (blkSize != 1) throw std::runtime_error(LOCATION);

                std::array<u8, 8> t;
                t[0] = lsb(ss[d][0]);
                t[1] = lsb(ss[d][1]);
                t[2] = lsb(ss[d][2]);
                t[3] = lsb(ss[d][3]);
                t[4] = lsb(ss[d][4]);
                t[5] = lsb(ss[d][5]);
                t[6] = lsb(ss[d][6]);
                t[7] = lsb(ss[d][7]);

                for (u64 i = 0; i < g.size(); ++i)
                {
                    temp[i][0] = (ss[d][0] & notThreeBlock) ^ toBlock(i);
                    temp[i][1] = (ss[d][1] & notThreeBlock) ^ toBlock(i);
                    temp[i][2] = (ss[d][2] & notThreeBlock) ^ toBlock(i);
                    temp[i][3] = (ss[d][3] & notThreeBlock) ^ toBlock(i);
                    temp[i][4] = (ss[d][4] & notThreeBlock) ^ toBlock(i);
                    temp[i][5] = (ss[d][5] & notThreeBlock) ^ toBlock(i);
                    temp[i][6] = (ss[d][6] & notThreeBlock) ^ toBlock(i);
                    temp[i][7] = (ss[d][7] & notThreeBlock) ^ toBlock(i);
                }

                // compute G(s) = AES_{x_i}(s) + s
                aes[0].ecbEncBlocks(temp[0].data(), 8 * g.size(), enc[0].data());

                for (u64 i = 0; i < g.size(); ++i)
                {
                    block b = temp[i][0];

                    temp[i][0] = temp[i][0] ^ enc[i][0];
                    temp[i][1] = temp[i][1] ^ enc[i][1];
                    temp[i][2] = temp[i][2] ^ enc[i][2];
                    temp[i][3] = temp[i][3] ^ enc[i][3];
                    temp[i][4] = temp[i][4] ^ enc[i][4];
                    temp[i][5] = temp[i][5] ^ enc[i][5];
                    temp[i][6] = temp[i][6] ^ enc[i][6];
                    temp[i][7] = temp[i][7] ^ enc[i][7];

                    //block bb = temp[i][0];

                    temp[i][0] = temp[i][0] ^ (g[i] & zeroAndAllOne[t[0]]);
                    temp[i][1] = temp[i][1] ^ (g[i] & zeroAndAllOne[t[1]]);
                    temp[i][2] = temp[i][2] ^ (g[i] & zeroAndAllOne[t[2]]);
                    temp[i][3] = temp[i][3] ^ (g[i] & zeroAndAllOne[t[3]]);
                    temp[i][4] = temp[i][4] ^ (g[i] & zeroAndAllOne[t[4]]);
                    temp[i][5] = temp[i][5] ^ (g[i] & zeroAndAllOne[t[5]]);
                    temp[i][6] = temp[i][6] ^ (g[i] & zeroAndAllOne[t[6]]);
                    temp[i][7] = temp[i][7] ^ (g[i] & zeroAndAllOne[t[7]]);

                    //std::cout << "  s[" << i << "][0]  = " << b << std::endl;
                    //std::cout << "G(s[" << i << "][0]) = " << bb  << std::endl;

                    //std::cout << "gs+cw*t = " << temp[i][0] << " = " << bb << " + " << g[i] << " * " << int(t[0]) << std::endl;;
                }


                auto dest = expandedS.data();

                for (u64 j = 0; j < 8; ++j)
                {
                    for (u64 i = 0; i < g.size(); ++i)
                    {
                        //block sss = ss.back()[i];
                        //block convert_;
                        //AES(sss & notThreeBlock).ecbEncCounterMode(0, blkSize, &convert_);

                        ////if()
                        //converts[i] = convert_ ^ (*(block*)g.data() & zeroAndAllOne[lsb(sss)]);


                        //std::cout << idx << " s" << i << " " << stt(ss[d][i]) << " -> " << tau[i] << " = " << s[i] << " ^ (" << *(block*)g.data() << " * " << int(t[i]) << ")" << std::endl;


                        dest[0] = mask & _mm_srai_epi16(temp[i][j], 0);
                        dest[1] = mask & _mm_srai_epi16(temp[i][j], 1);
                        dest[2] = mask & _mm_srai_epi16(temp[i][j], 2);
                        dest[3] = mask & _mm_srai_epi16(temp[i][j], 3);
                        dest[4] = mask & _mm_srai_epi16(temp[i][j], 4);
                        dest[5] = mask & _mm_srai_epi16(temp[i][j], 5);
                        dest[6] = mask & _mm_srai_epi16(temp[i][j], 6);
                        dest[7] = mask & _mm_srai_epi16(temp[i][j], 7);

                        dest += 8;
                    }
                }

                u8* byteView0 = (u8*)expandedS.data() + g.size() * 128 * 0;
                u8* byteView1 = (u8*)expandedS.data() + g.size() * 128 * 1;
                u8* byteView2 = (u8*)expandedS.data() + g.size() * 128 * 2;
                u8* byteView3 = (u8*)expandedS.data() + g.size() * 128 * 3;
                u8* byteView4 = (u8*)expandedS.data() + g.size() * 128 * 4;
                u8* byteView5 = (u8*)expandedS.data() + g.size() * 128 * 5;
                u8* byteView6 = (u8*)expandedS.data() + g.size() * 128 * 6;
                u8* byteView7 = (u8*)expandedS.data() + g.size() * 128 * 7;
                //std::cout << (u64)k.data() << std::endl;
                //for (u64 i = 0; i < 128; ++i)
                //{
                //    std::cout << (int)byteView[128 * 0 + i] ;
                //}
                //std::cout << std::endl;

                auto inputIter0 = data.data() + ((0 << d) + idx) * g.size() * 128;
                auto inputIter1 = data.data() + ((1 << d) + idx) * g.size() * 128;
                auto inputIter2 = data.data() + ((2 << d) + idx) * g.size() * 128;
                auto inputIter3 = data.data() + ((3 << d) + idx) * g.size() * 128;
                auto inputIter4 = data.data() + ((4 << d) + idx) * g.size() * 128;
                auto inputIter5 = data.data() + ((5 << d) + idx) * g.size() * 128;
                auto inputIter6 = data.data() + ((6 << d) + idx) * g.size() * 128;
                auto inputIter7 = data.data() + ((7 << d) + idx) * g.size() * 128;

                for (u64 i = 0; i < 128 * g.size(); ++i)
                {

                    //for (u64 j = 0; j < 8; ++j)
                    //{

                    //    u64 ii = ((j << d) + idx) * g.size() * 128 + i;
                    //    BgiPirServer_bv[ii] = byteView0[g.size() * 128 * j + i];

                    //    //sums[0] = sums[0] ^ (data[((0 << d) + idx) * g.size() * 128 + i] & zeroAndAllOne[byteView0[g.size() * 128 * 0 + i]]);
                    //    //sums[0] = sums[0] ^ (data[ii] & zeroAndAllOne[byteView0[g.size() * 128 * j + i]]);
                    //    //    block bb, ss;
                    //    //    u8 tt;
                    //    //    u8 bit = evalOne(ii, k, g, &bb, &ss, &tt);

                    //    //    if (byteView[g.size() * 128 * j + i] != bit)
                    //    //    {
                    //    //        std::cout << (ii) << " "<< j <<"   " << temp[i / 128][j] << "    ";
                    //    //        std::cout << "       " << bb << " = " << ss << "( _____ * " << int(tt) << ")  " << int(byteView[g.size() * 128 * j + i]) << " != " << int(bit) << std::endl;
                    //    //        throw std::runtime_error(LOCATION);
                    //    //    }
                    //}

                    auto mask0 = zeroAndAllOne[byteView0[i]];
                    auto mask1 = zeroAndAllOne[byteView1[i]];
                    auto mask2 = zeroAndAllOne[byteView2[i]];
                    auto mask3 = zeroAndAllOne[byteView3[i]];
                    auto mask4 = zeroAndAllOne[byteView4[i]];
                    auto mask5 = zeroAndAllOne[byteView5[i]];
                    auto mask6 = zeroAndAllOne[byteView6[i]];
                    auto mask7 = zeroAndAllOne[byteView7[i]];

                    auto input0 = inputIter0[i] & mask0;
                    auto input1 = inputIter1[i] & mask1;
                    auto input2 = inputIter2[i] & mask2;
                    auto input3 = inputIter3[i] & mask3;
                    auto input4 = inputIter4[i] & mask4;
                    auto input5 = inputIter5[i] & mask5;
                    auto input6 = inputIter6[i] & mask6;
                    auto input7 = inputIter7[i] & mask7;

                    sums[0] = sums[0] ^ input0;
                    sums[1] = sums[1] ^ input1;
                    sums[2] = sums[2] ^ input2;
                    sums[3] = sums[3] ^ input3;
                    sums[4] = sums[4] ^ input4;
                    sums[5] = sums[5] ^ input5;
                    sums[6] = sums[6] ^ input6;
                    sums[7] = sums[7] ^ input7;
                }

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
}
