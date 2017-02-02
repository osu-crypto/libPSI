#include "dcwMain.h"

#include "cryptoTools/Network/BtEndpoint.h" 

#include "MPSI/DKT/DktMPsiReceiver.h"
#include "MPSI/DKT/DktMPsiSender.h"



#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <fstream>
#include "dktMain.h"

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

                //std::cout << setSize << "    " << dataSent / std::pow(2, 20) << " byte  " << std::endl;
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


                std::string tag("DKT11");
                printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);

            }
        }
    }
}



