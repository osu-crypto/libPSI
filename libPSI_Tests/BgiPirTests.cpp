#include "BgiPirTests.h"
#include "libPSI/PIR/BgiPirClient.h"
#include "libPSI/PIR/BgiPirServer.h"
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Crypto/PRNG.h>

using namespace osuCrypto;

void BgiPir_keyGen_test()
{
	std::vector<block> vv{ CCBlock, OneBlock, AllOneBlock,AllOneBlock };

	u64 depth = 5;
	for (u64 seed = 0; seed < 10; ++seed)
	{


		for (u64 i = 0; i < (1 << depth); ++i)
		{


			std::vector<block> k0, k1;

			BgiPirClient::keyGen(i, depth, toBlock(seed), k0, k1);

			for (u64 j = 0; j < (1 << depth); ++j)
			{

				auto b0 = BgiPirServer::evalOne(j, depth, k0);
				auto b1 = BgiPirServer::evalOne(j, depth, k1);

				//std::cout << i << (i == j ? "*" : " ") << " " << (b0 ^ b1) << std::endl;


				if (i == j)
				{
					if (neq(b0^b1, OneBlock))
					{
						std::cout << "\n\n ===========================================================\n\n\n";
						throw std::runtime_error(LOCATION);
					}
				}
				else
				{
					if (neq(b0^b1, ZeroBlock))
					{
						std::cout << "\n\n -----------------------------------------------------------\n\n\n";
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
	u64 depth = 5;
	std::vector<block> vv(1 << depth);

	for (u64 i = 0; i < vv.size(); ++i) vv[i] = toBlock(i);


	client.init(depth);
	s0.init(depth);
	s1.init(depth);


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


	std::vector<block>rets(vv.size());
	for (u64 i = 0; i < vv.size(); ++i)
	{
		rets[i] = client.query(i, chan0, chan1, toBlock(2));
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
