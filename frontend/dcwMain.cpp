#include "dcwMain.h"

#include "cryptoTools/Network/BtEndpoint.h" 


#include "MPSI/Dcw/DcwBfPsiReceiver.h"
#include "MPSI/Dcw/DcwBfPsiSender.h"
#include "MPSI/Dcw/DcwRBfPsiReceiver.h"
#include "MPSI/Dcw/DcwRBfPsiSender.h"



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

extern u8 dummy[];

using namespace osuCrypto;

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
                chls[0]->asyncSend(dummy, 1);
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
        for (auto tt : params.mNumThreads)
        {
            if (tt != 1)
            {
                std::cout << "dcw n = " << setSize << " t = " << tt << " skipped, t > 1 (multi-thread) not implemented." << std::endl;
                continue;
            }

            auto chls = params.getChannels(tt);

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

                chls[0]->recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(set, chls);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                u64 dataSent = 0;
                for (u64 g = 0; g < chls.size(); ++g)
                {
                    dataSent += chls[g]->getTotalDataSent();
                    chls[g]->resetStats();
                }



                double time = offlineTime + onlineTime;
                time /= 1000;
                auto Mbps = dataSent * 8 / time / (1 << 20);

                std::string tag("RR16");
                if (params.mVerbose)
                {
                    std::cout << tag << " n = " << setSize << "  threads = " << tt << "\n"
                        << "      Total Time = " << time << " ms\n"
                        << "         Offline = " << offlineTime << " ms\n"
                        << "          Online = " << onlineTime << " ms\n"
                        << "      Total Comm = " << (dataSent / std::pow(2.0, 20)) << " MB\n"
                        << "       Bandwidth = " << Mbps << " Mbps\n" << std::endl;


                    if (params.mVerbose > 1)
                        std::cout << gTimer << std::endl;
                }
                else
                {
                    std::cout << tag
                        << "   n=" << std::setw(6) << setSize
                        << "   t=" << std::setw(3) << tt
                        << "   offline=" << std::setw(6) << offlineTime << " ms"
                        << "   online=" << std::setw(6) << onlineTime << "       "
                        << "    Comm=" << std::setw(6) << (dataSent / std::pow(2.0, 20)) << " MB ("
                        << std::setw(6) << Mbps << " Mbps)" << std::endl;
                }
                //std::cout << setSize << "  " << offlineTime << "  " << online << std::endl;
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
                chls[0]->asyncSend(dummy, 1);
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
        for (u64 tt : params.mNumThreads)
        {
            if (tt != 1)
            {
                std::cout << "dcwr n = " << setSize << " t = " << tt << " skipped, t > 1 (multi-thread) not implemented." << std::endl;
                continue;
            }

            auto chls = params.getChannels(tt);

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

                chls[0]->recv(dummy, 1);
                auto mid = timer.setTimePoint("init");



                recvPSIs.sendInput(set, chls);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();
                
                
                //std::cout << setSize << "  " << offlineTime << "  " << online << std::endl;

                u64 dataSent = 0;
                for (u64 g = 0; g < chls.size(); ++g)
                {
                    dataSent += chls[g]->getTotalDataSent();
                    chls[g]->resetStats();
                }



                double time = offlineTime + onlineTime;
                time /= 1000;
                auto Mbps = dataSent * 8 / time / (1 << 20);

                std::string tag("RR16");
                if (params.mVerbose)
                {
                    std::cout << tag << " n = " << setSize << "  threads = " << tt << "\n"
                        << "      Total Time = " << time << " ms\n"
                        << "         Offline = " << offlineTime << " ms\n"
                        << "          Online = " << onlineTime << " ms\n"
                        << "      Total Comm = " << (dataSent / std::pow(2.0, 20)) << " MB\n"
                        << "       Bandwidth = " << Mbps << " Mbps\n" << std::endl;


                    if (params.mVerbose > 1)
                        std::cout << gTimer << std::endl;
                }
                else
                {
                    std::cout << tag
                        << "   n=" << std::setw(6) << setSize
                        << "   t=" << std::setw(3) << tt
                        << "   offline=" << std::setw(6) << offlineTime << " ms"
                        << "   online=" << std::setw(6) << onlineTime << "       "
                        << "    Comm=" << std::setw(6) << (dataSent / std::pow(2.0, 20)) << " MB ("
                        << std::setw(6) << Mbps << " Mbps)" << std::endl;
                }

            }
        }
    }
}

