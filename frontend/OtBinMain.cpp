#include "bloomFilterMain.h"
#include "cryptoTools/Network/Endpoint.h" 

#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiSender.h"
#include "libPSI/MPSI/Rr17/Rr17b/Rr17bMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17b/Rr17bMPsiSender.h"

#include "libPSI/PSI/KkrtPsiReceiver.h"
#include "libPSI/PSI/KkrtPsiSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>
u8 dummy[1];

#define OOS

void rr17aSend(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

#ifdef OOS
                    OosNcoOtReceiver otRecv;
                    OosNcoOtSender   otSend;
#else
                    KkrtNcoOtReceiver otRecv;
                    KkrtNcoOtSender otSend;
#endif
                    Rr17aMPsiSender sendPSIs;

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, otRecv, prng.get<block>(), ss, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();
                }
            }
        }
    }
}

void rr17aRecv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);


            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17a");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }


#ifdef OOS
                    OosNcoOtReceiver otRecv;
                    OosNcoOtSender   otSend;
#else
                    KkrtNcoOtReceiver otRecv;
                    KkrtNcoOtSender otSend;
#endif
                    Rr17aMPsiReceiver recvPSIs;


                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, otSend, prng.get<block>(), ss, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads, ss);
                }
            }
        }
    }
}


void rr17aSend_StandardModel(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

                    Rr17NcoOtReceiver otRecv;
                    Rr17NcoOtSender otSend;

                    Rr17aMPsiSender sendPSIs;

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, otRecv, prng.get<block>(), ss, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();
                }
            }
        }
    }
}

void rr17aRecv_StandardModel(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");



    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17a-sm");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }


                    Rr17NcoOtReceiver otRecv;
                    Rr17NcoOtSender otSend;

                    Rr17aMPsiReceiver recvPSIs;


                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, otSend, prng.get<block>(), ss, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);
                }
            }
        }
    }
}




void rr17bSend(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

                    OosNcoOtSender   otSend;

                    Rr17bMPsiSender sendPSIs;

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);
                    gTimer.reset();

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, prng.get<block>(), ss, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();


                    if (params.mVerbose > 1) std::cout << gTimer << std::endl;
                }
            }
        }
    }
}

void rr17bRecv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    LinearCode code;
    code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);


            for (auto ss : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17b");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }


                    OosNcoOtReceiver otRecv;// (code, 40);
                    Rr17bMPsiReceiver recvPSIs;


                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, prng.get<block>(), ss, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads, ss);
                }
            }
        }
    }
}





void rr17bSend_StandardModel(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (auto binScaler : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::vector<block> set(setSize);
                    prng.get(set.data(), set.size());

                    Rr17NcoOtSender otSend;

                    Rr17bMPsiSender sendPSIs;

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.init(setSize, params.mStatSecParam, sendChls, otSend, prng.get<block>(), binScaler, params.mBitSize);

                    sendChls[0].asyncSend(dummy, 1);
                    sendChls[0].recv(dummy, 1);

                    sendPSIs.sendInput(set, sendChls);

                    u64 dataSent = 0;
                    for (u64 g = 0; g < sendChls.size(); ++g)
                    {
                        dataSent += sendChls[g].getTotalDataSent();
                    }

                    for (u64 g = 0; g < sendChls.size(); ++g)
                        sendChls[g].resetStats();
                }
            }
        }
    }
}

void rr17bRecv_StandardModel(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);


            for (auto binScaler : params.mBinScaler)
            {
                for (u64 jj = 0; jj < params.mTrials; jj++)
                {
                    std::string tag("RR17b");

                    std::vector<block> sendSet(setSize), recvSet(setSize);
                    for (u64 i = 0; i < setSize; ++i)
                    {
                        sendSet[i] = recvSet[i] = prng.get<block>();
                    }

                    Rr17NcoOtReceiver otRecv;

                    Rr17bMPsiReceiver recvPSIs;


                    chls[0].recv(dummy, 1);
                    gTimer.reset();
                    chls[0].asyncSend(dummy, 1);



                    Timer timer;

                    auto start = timer.setTimePoint("start");

                    recvPSIs.init(setSize, params.mStatSecParam, chls, otRecv, prng.get<block>(), binScaler, params.mBitSize);

                    chls[0].asyncSend(dummy, 1);
                    chls[0].recv(dummy, 1);
                    auto mid = timer.setTimePoint("init");


                    recvPSIs.sendInput(recvSet, chls);


                    auto end = timer.setTimePoint("done");

                    auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                    auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                    //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                    printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads, binScaler);
                }
            }
        }
    }
}





void kkrtSend(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);
                prng.get(set.data(), set.size());

                KkrtNcoOtSender otSend;

                KkrtPsiSender sendPSIs;

                sendChls[0].asyncSend(dummy, 1);
                sendChls[0].recv(dummy, 1);

                sendPSIs.init(setSize, setSize, params.mStatSecParam, sendChls, otSend, prng.get<block>());

                //sendChls[0].asyncSend(dummy, 1);
                //sendChls[0].recv(dummy, 1);

                sendPSIs.sendInput(set, sendChls);

                u64 dataSent = 0;
                for (u64 g = 0; g < sendChls.size(); ++g)
                {
                    dataSent += sendChls[g].getTotalDataSent();
                }

                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g].resetStats();
            }
        }
    }
}

void kkrtRecv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 746587658, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);


            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::string tag("RR17b");

                std::vector<block> sendSet(setSize), recvSet(setSize);
                for (u64 i = 0; i < setSize; ++i)
                {
                    sendSet[i] = recvSet[i] = prng.get<block>();
                }

                KkrtNcoOtReceiver otRecv;

                KkrtPsiReceiver recvPSIs;


                chls[0].recv(dummy, 1);
                gTimer.reset();
                chls[0].asyncSend(dummy, 1);



                Timer timer;

                auto start = timer.setTimePoint("start");

                recvPSIs.init(setSize, setSize, params.mStatSecParam, chls, otRecv, prng.get<block>());

                //chls[0].asyncSend(dummy, 1);
                //chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(recvSet, chls);


                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);
            }
        }
    }
}
