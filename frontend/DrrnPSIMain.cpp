#include "bloomFilterMain.h"
#include "cryptoTools/Network/Endpoint.h"

#include "libPSI/PSI/DrrnPsiClient.h"
#include "libPSI/PSI/DrrnPsiServer.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>
#include "cuckoo/SimpleCuckoo.h"

void Drrn17Send(
	LaunchParams& params)
{
	setThreadName("CP_Test_Thread");
	u8 dummy[1];

	PRNG prng(_mm_set_epi32(4253465, 434565, 234435, 23987045));


	for (auto clientSetSize : params.mNumItems)
	{

		for (auto serverSetSize : params.mNumItems2)
		{
			for (auto numThreads : params.mNumThreads)
			{
				std::vector<Channel> clientChls = params.getChannels(1);
				std::vector<Channel> serverChls = params.getChannels2(1);

				for (auto ss : params.mBinScaler)
				{
					for (u64 jj = 0; jj < params.mTrials; jj++)
					{
						std::vector<block> set(serverSetSize);
						prng.get(set.data(), set.size());
						DrrnPsiServer srv;
						//{
						//	auto param = CuckooIndex<>::selectParams(set.size(), 20, true, 2);
						//	//SimpleCuckoo cc;
						//	//cc.mParams = param;
						//	//cc.init();
						//	//cc.insert(set, ZeroBlock);

						//	CuckooIndex<NotThreadSafe> mm;
						//	mm.init(param);
						//	mm.insert(set, ZeroBlock);
						//}

                        srv.setInputs(set, params.mNumHash, 10);

						clientChls[0].asyncSend(dummy, 1);
						clientChls[0].recv(dummy, 1);

						if (params.mIdx < 1 || params.mIdx > 2) throw std::runtime_error("server index must be 1 or 2");


						srv.init(u8(params.mIdx - 1), clientChls[0], serverChls[0], serverSetSize, clientSetSize, ZeroBlock, ss);
						srv.send(clientChls[0], serverChls[0], numThreads);
					}
				}
			}
		}
	}
}

void Drrn17Recv(
	LaunchParams& params)
{
	setThreadName("CP_Test_Thread");
    u8 dummy[1];


	PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


	if (params.mVerbose) std::cout << "\n";

	for (auto clientSetSize : params.mNumItems)
	{

		for (auto serverSetSize : params.mNumItems2)
		{
			for (auto numThreads : params.mNumThreads)
			{
				auto s0 = params.getChannels(1);
				auto s1 = params.getChannels2(1);

				for (auto ss : params.mBinScaler)
				{
					for (u64 jj = 0; jj < params.mTrials; jj++)
					{
						std::string tag("Drrn ");

						std::vector<block> recvSet(clientSetSize);
						prng.get(recvSet.data(), recvSet.size());
                        s0[0].asyncSend(dummy, 1);
                        s1[0].asyncSend(dummy, 1);
                        s0[0].recv(dummy, 1);
                        s1[0].recv(dummy, 1);


                        gTimer.reset();
						Timer timer;
						auto start = timer.setTimePoint("start");
						DrrnPsiClient client;
						client.init(s0[0], s1[0], serverSetSize, clientSetSize, ZeroBlock, params.mNumHash, ss, 10);

						auto mid = timer.setTimePoint("online");

						client.recv(s0[0], s1[0], recvSet);
						auto end = timer.setTimePoint("done");

						auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
						auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

						//auto byteSent = chls[0]->getTotalDataSent() *chls.size();

						printTimings(tag, s0, offlineTime, onlineTime, params, clientSetSize, numThreads, ss, &s1, serverSetSize);
					}
				}
			}
		}
	}
}

