
#ifdef ENABLE_DCW

#include "dcwMain.h"

#include "cryptoTools/Network/Endpoint.h" 


#include "libPSI/MPSI/Dcw/DcwBfPsiReceiver.h"
#include "libPSI/MPSI/Dcw/DcwBfPsiSender.h"
#include "libPSI/MPSI/Dcw/DcwRBfPsiReceiver.h"
#include "libPSI/MPSI/Dcw/DcwRBfPsiSender.h"



#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <fstream>
#include <algorithm>
#include "boost/format.hpp"
extern u8 dummy[];

using namespace osuCrypto;
//using namespace std; //Don't if you're in a header-file
void DcwSend(
    LaunchParams& params)
{

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
    for (auto setSize : params.mNumItems)
    {
        for (auto tt : params.mNumThreads)
        {
            if (tt != 1)
            {
                continue;
            }

            auto chls = params.getChannels(tt);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> sendSet(setSize);
                for (u64 i = 0; i < setSize; ++i)
                    sendSet[i] = prng.get<block>();

                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
                DcwBfPsiSender sendPSIs;

                gTimer.reset();

                sendPSIs.init(setSize, params.mStatSecParam, otSend, chls, prng.get<block>());
                chls[0].asyncSend(dummy, 1);
                sendPSIs.sendInput(sendSet, chls);
            }
        }
    }
}

void DcwRecv(
    LaunchParams& params)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            if (numThreads != 1)
            {
                std::cout << "dcw n = " << setSize << " t = " << numThreads << " skipped, t > 1 (multi-thread) not implemented." << std::endl;
                continue;
            }

            auto chls = params.getChannels(numThreads);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);
                for (u64 i = 0; i < setSize; ++i)
                    set[i] =  prng.get<block>();

                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
                DcwBfPsiReceiver recvPSIs;


                gTimer.reset();
                Timer timer;
                auto start = timer.setTimePoint("start");

                recvPSIs.init(setSize, params.mStatSecParam, otRecv, chls, ZeroBlock);

                chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(set, chls);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();


                std::string tag("DCW");

                printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);
            }
        }
    }
}





void DcwRSend(
    LaunchParams& params)
{

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (auto tt : params.mNumThreads)
        {
            if (tt != 1)
            {
                continue;
            }

            auto chls = params.getChannels(tt);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);

                for (u64 i = 0; i < setSize; ++i)
                    set[i] = prng.get<block>();


                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
                DcwRBfPsiSender sendPSIs;

                gTimer.reset();
                sendPSIs.init(setSize, params.mStatSecParam, otSend, chls, prng.get<block>());
                chls[0].asyncSend(dummy, 1);
                sendPSIs.sendInput(set, chls);
            }
        }
    }
}

void DcwRRecv(
    LaunchParams& params)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (u64 numThreads : params.mNumThreads)
        {
            if (numThreads != 1)
            {
                std::cout << "dcwr n = " << setSize << " t = " << numThreads << " skipped, t > 1 (multi-thread) not implemented." << std::endl;
                continue;
            }

            auto chls = params.getChannels(numThreads);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);
                for (u64 i = 0; i < setSize; ++i)
                    set[i] =prng.get<block>();

                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
                DcwRBfPsiReceiver recvPSIs;



                gTimer.reset();
                Timer timer;
                auto start = timer.setTimePoint("start");

                recvPSIs.init(setSize, params.mStatSecParam, otRecv, chls, ZeroBlock);

                chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");



                recvPSIs.sendInput(set, chls);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();
                
                
                //std::cout << setSize << "  " << offlineTime << "  " << online << std::endl;

                std::string tag("DCWR");

                printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);

            }
        }
    }
}

#endif