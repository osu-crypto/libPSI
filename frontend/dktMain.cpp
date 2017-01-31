#include "dcwMain.h"

#include "cryptoTools/Network/BtEndpoint.h" 

#include "MPSI/DKT/DktMPsiReceiver.h"
#include "MPSI/DKT/DktMPsiSender.h"



#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <fstream>

using namespace osuCrypto;

extern u8 dummy[];

void DktSend(LaunchParams& params)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto sendChls = params.getChannels(numThreads);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);
                prng.get(set.data(), set.size());


                DktMPsiSender sendPSIs;

                gTimer.reset();
                Timer timer;

                sendPSIs.init(setSize, params.mStatSecParam, prng.get<block>());
                sendChls[0]->asyncSend(dummy, 1);

                sendPSIs.sendInput(set, sendChls);

                u64 dataSent = 0;
                for (u64 g = 0; g < sendChls.size(); ++g)
                {
                    dataSent += sendChls[g]->getTotalDataSent();
                }

                std::cout << setSize << "    " << dataSent / std::pow(2, 20) << " byte  " << std::endl;
                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g]->resetStats();
            }
        }
    }
}


void DktRecv(LaunchParams& params)
{

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {

                std::vector<block> set(setSize);
                prng.get(set.data(), set.size());

                DktMPsiReceiver recvPSIs;

                gTimer.reset();

                Timer timer;
                auto start = timer.setTimePoint("start");
                recvPSIs.init(setSize, params.mStatSecParam, ZeroBlock);

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

                std::string tag("DKT11");
                if (params.mVerbose)
                {
                    std::cout << tag << " n = " << setSize << "  threads = " << numThreads << "\n"
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
                        << "   t=" << std::setw(3) << numThreads
                        << "   offline=" << std::setw(6) << offlineTime << " ms"
                        << "   online=" << std::setw(6) << onlineTime << "       "
                        << "    Comm=" << std::setw(6) << (dataSent / std::pow(2.0, 20)) << " MB ("
                        << std::setw(6) << Mbps << " Mbps)" << std::endl;
                }

            }
        }
    }
}



