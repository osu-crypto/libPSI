#include "BgiPirTests.h"
#include "libPSI/PIR/BgiPirClient.h"
#include "libPSI/PIR/BgiPirServer.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/BitVector.h>

using namespace osuCrypto;

void BgiPir_keyGen_test()
{
    std::vector<block> vv{ CCBlock, OneBlock, AllOneBlock, AllOneBlock };

    u64 depth = 5;
    u64 groupBlkSize = 1;
    u64 domain = (1 << depth) *  groupBlkSize * 128;
    PRNG prng(ZeroBlock);
    for (u64 seed = 0; seed < 4; ++seed)
    {

        for (u64 ii = 0; ii < 10; ++ii)
        {
            auto i = 128;// prng.get<u64>() % domain;
            std::vector<block> k0(depth + 1), k1(depth + 1);
            std::vector<block> g0(groupBlkSize), g1(groupBlkSize);

            BgiPirClient::keyGen(i, toBlock(seed), k0, g0, k1, g1);

            for (u64 j = 0; j < domain; ++j)
            {

                auto b0 = BgiPirServer::evalOne(j, k0, g0);
                auto b1 = BgiPirServer::evalOne(j, k1, g1);

                //std::cout << i << (i == j ? "*" : " ") << " " << (b0 ^ b1) << std::endl;

                if (i == j)
                {
                    if ((b0 ^ b1) != 1)
                    {
                        std::cout << "\n\n ======================= try " << ii << " target " << i << " cur " << j << " " << (int)b0 << " ^ " << (int)b1 << " = " << (b0 ^ b1) << " != 1 ====================================\n\n\n";
                        throw std::runtime_error(LOCATION);
                    }
                }
                else
                {
                    if ((b0 ^ b1) != 0)
                    {
                        std::cout << "\n\n ======================= try " << ii << " target " << i << " cur " << j << " " << (int)b0 << " ^ " << (int)b1 << " = " << (b0 ^ b1) << " != 0 ====================================\n\n\n";
                        throw std::runtime_error(LOCATION);
                    }
                }
            }
        }
    }
}

void BgiPir_PIR_test()
{

    BgiPirClient client;
    BgiPirServer s0, s1;
    u64 depth = 7, groupSize = 1;
    auto domain = (1 << depth) * groupSize * 128;
    std::vector<block> vv(domain);

    // fill "database" with increasind block numbers up to 2^depth
    for (u64 i = 0; i < vv.size(); ++i)
    {
        vv[i] = toBlock(i);
    }

    client.init(depth, groupSize);
    s0.init(depth, groupSize);
    s1.init(depth, groupSize);

    IOService ios;

    auto thrd = std::thread([&]() {

        Endpoint srv0Ep(ios, "localhost", EpMode::Client, "srv0");
        Endpoint srv1Ep(ios, "localhost", EpMode::Client, "srv1");
        auto chan0 = srv0Ep.addChannel("chan");
        auto chan1 = srv1Ep.addChannel("chan");

        for (u64 i = 0; i < vv.size(); ++i)
        {
            s0.serve(chan0, vv);
            s1.serve(chan1, vv);
        }

    });

    Endpoint srv0Ep(ios, "localhost", EpMode::Server, "srv0");
    Endpoint srv1Ep(ios, "localhost", EpMode::Server, "srv1");
    auto chan0 = srv0Ep.addChannel("chan");
    auto chan1 = srv1Ep.addChannel("chan");

    std::vector<block> rets(vv.size());
    for (u64 i = 0; i < vv.size(); ++i)
    {
        rets[i] = client.query(i, chan0, chan1, toBlock(i));
    }

    thrd.join();

    for (u64 i = 0; i < vv.size(); ++i)
    {
        if (neq(rets[i], vv[i]))
        {
            std::cout << i << "  " << rets[i] << std::endl;
            throw std::runtime_error(LOCATION);
        }
    }
}
void BgiPir_FullDomain_test()
{
    u64 depth = 16, groupBlkSize = 8;
    u64 domain = (1 << depth) * groupBlkSize * 128;

    std::cout << domain << std::endl;

    std::vector<block> data(domain);
    for (u64 i = 0; i < data.size(); ++i)
        data[i] = toBlock(i);



    std::vector<block> k0(depth + 1), k1(depth + 1);
    std::vector<block> g0(groupBlkSize), g1(groupBlkSize);

    PRNG prng(ZeroBlock);
    for (u64 i = 0; i < std::min<u64>(10, domain); ++i)
    {
        //i = 1024;

        for (u64 j = 0; j < 2; ++j)
        {
            auto idx = (i + j * prng.get<int>()) % domain;
            BgiPirClient::keyGen(idx, toBlock(idx), k0, g0, k1, g1);

            //std::cout << "---------------------------------------------------" << std::endl;
            //for (u64 j = 0; j < data.size(); ++j)
            //{
            //    std::cout << int(BgiPirServer::evalOne(j, k0, g0) & 1);
            //}
            //std::cout << std::endl;
            //for (u64 j = 0; j < data.size(); ++j)
            //{
            //    std::cout << int(BgiPirServer::evalOne(j, k1, g1) & 1);
            //}
            //std::cout << std::endl;
            //std::cout << "---------------------------------------------------" << std::endl;


            auto b0 = BgiPirServer::fullDomain(data, k0, g0);

            //BitVector bv0 = BgiPirServer::BgiPirServer_bv;
            auto b1 = BgiPirServer::fullDomain(data, k1, g1);
            //BitVector bv1 = BgiPirServer::BgiPirServer_bv;

            if (neq(b0 ^ b1, data[idx]))
            {
                //auto vv = bv0 ^ bv1;
                std::cout << "target " << data[idx] << " " << idx <<
                    "\n  " << (b0^b1) << "\n = " << b0 << " ^ " << b1 <<
                    //"\n   weight " << vv.hammingWeight() <<
                    //"\n vv[target] = " << vv[idx] << 
                    std::endl;
                throw std::runtime_error(LOCATION);
            }

        }

        //return;

    }
}

