#include "BgiPirTests.h"
#include "libPSI/PIR/BgiPirClient.h"
#include "libPSI/PIR/BgiPirServer.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>

using namespace osuCrypto;

void BgiPir_keyGen_test()
{
    std::vector<block> vv{ CCBlock, OneBlock, AllOneBlock, AllOneBlock };

    u64 depth = 4;
    u64 groupSize = 16;
    u64 domain = (1 << depth) *  groupSize * 8;
    PRNG prng(ZeroBlock);
    for (u64 seed = 0; seed < 4; ++seed)
    {

        for (u64 ii = 0; ii < 10; ++ii)
        {
            auto i = prng.get<u64>() % domain;
            std::vector<block> k0(depth + 1), k1(depth + 1);
            std::vector<u8> g0(groupSize), g1(groupSize);

            BgiPirClient::keyGen(i, toBlock(seed), k0, g0, k1, g1);

            for (u64 j = 0; j <domain; ++j)
            {

                auto b0 = BgiPirServer::evalOne(j, k0, g0);
                auto b1 = BgiPirServer::evalOne(j, k1, g1);

                //std::cout << i << (i == j ? "*" : " ") << " " << (b0 ^ b1) << std::endl;

                if (i == j)
                {
                    if ((b0 ^ b1) != 1)
                    {
                        std::cout << "\n\n ======================= "<<i<< " " << j << " " << (int)b0 << " ^ " << (int)b1 << " = " << (b0 ^ b1) << " != 1 ====================================\n\n\n";
                        throw std::runtime_error(LOCATION);
                    }
                }
                else
                {
                    if ((b0 ^ b1) != 0)
                    {
                        std::cout << "\n\n ======================= " << i << " " << j << " " << (int)b0 << " ^ " << (int)b1 << " = " << (b0 ^ b1) << " != 0 ====================================\n\n\n";
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
    u64 depth = 7;
    std::vector<block> vv(1 << depth);

    // fill "database" with increasind block numbers up to 2^depth
    for (u64 i = 0; i < vv.size(); ++i)
    {
        vv[i] = toBlock(i);
    }

    client.init(depth, 16);
    s0.init(depth, 16);
    s1.init(depth, 16);

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
    u64 depth = 10, groupSize = 16;
    u64 domain = (1 << depth) * groupSize * 8;

    //std::cout << domain << std::endl;

    std::vector<block> data(domain);
    for (u64 i = 0; i < data.size(); ++i)
        data[i] = toBlock(i);



    std::vector<block> k0(depth + 1), k1(depth + 1);
    std::vector<u8> g0(groupSize), g1(groupSize);


    for (u64 i = 0; i < domain; ++i)
    {
        //i = 1024;
        BgiPirClient::keyGen(i, toBlock(i), k0, g0, k1, g1);

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
        auto b1 = BgiPirServer::fullDomain(data, k1, g1);

        if (neq(b0 ^ b1, data[i]))
        {
            std::cout << i << "  " << (b0^b1) <<" = "<<b0<<" ^ "<<b1 << std::endl;
            throw std::runtime_error(LOCATION);
        }


        return;

    }
}

