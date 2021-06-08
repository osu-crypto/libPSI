#include "bloomFilterMain.h"
#include "cryptoTools/Network/Endpoint.h"

#include "libPSI/PSI/Drrn/DrrnPsiClient.h"
#include "libPSI/PSI/Drrn/DrrnPsiServer.h"

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
#ifdef ENABLE_DRRN_PSI
    setThreadName("CP_Test_Thread");
    u8 dummy[1];

    PRNG prng(_mm_set_epi32(4253465, 434565, 234435, 23987045));



    for (auto serverSetSize : params.mNumItems2)
    {
        std::unique_ptr<block[]> setPtr(new block[serverSetSize]);
        span<block> set(setPtr.get(), serverSetSize);
        prng.get(set.data(), set.size());


        for (auto clientSetSize : params.mNumItems)
        {
            for (auto numThreads : params.mNumThreads)
            {
                std::vector<Channel> clientChls = params.getChannels(1);
                std::vector<Channel> serverChls = params.getChannels2(1);

                for (auto ss : params.mBinScaler)
                {
                    for (u64 jj = 0; jj < params.mTrials; jj++)
                    {
                        DrrnPsiServer srv;
                        srv.mUseSingleDataPass = params.mCmd->isSet("multiDP") == false;
                        srv.mNiave = params.mCmd->isSet("niave");
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
                        Timer tt;
                        auto s = tt.setTimePoint("s");
                        srv.setInputs(set, params.mNumHash, 10);
                        auto e = tt.setTimePoint("e");

                        std::this_thread::sleep_for(std::chrono::seconds(1));

                        if (params.mCmd->isSet("cuckooTime") && params.mIdx == 1)
                            std::cout << "ch:" << std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count() << "ms " << std::flush;

                        clientChls[0].asyncSend(dummy, 1);
                        clientChls[0].recv(dummy, 1);

                        if (params.mIdx < 1 || params.mIdx > 2) throw std::runtime_error("server index must be 1 or 2");


                        srv.init(u8(params.mIdx - 1), clientChls[0], serverChls[0], serverSetSize, clientSetSize, ZeroBlock, ss, params.mCmd->get<int>("bigBlock"));
                        srv.send(clientChls[0], serverChls[0], numThreads);
                    }
                }
            }
        }
    }
#else
    std::cout << Color::Red << "DRRN is not enabled " << std::endl << Color::Default;
#endif
}

void Drrn17Recv(
    LaunchParams& params)
{
#ifdef ENABLE_DRRN_PSI
    setThreadName("CP_Test_Thread");
    u8 dummy[1];


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";


    for (auto serverSetSize : params.mNumItems2)
    {
        for (auto clientSetSize : params.mNumItems)
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
                        client.init(s0[0], s1[0], serverSetSize, clientSetSize, ZeroBlock, params.mNumHash, ss, 10, params.mCmd->get<int>("bigBlock"));

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
#else
    std::cout << Color::Red << "DRRN is not enabled " << std::endl << Color::Default;
#endif
}

