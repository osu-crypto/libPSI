#include "bloomFilterMain.h"
#include "cryptoTools/Network/Endpoint.h" 

#include "libPSI/MPSI/Rr16/AknBfMPsiReceiver.h"
#include "libPSI/MPSI/Rr16/AknBfMPsiSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

//#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
//#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>

extern u8 dummy[];
//#define LAZY_OT

void bfSend(LaunchParams& params)
{
#ifdef ENABLE_RR16_PSI
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            auto chls = params.getChannels(cc);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);
                for (u64 i = 0; i < setSize; ++i)
                    set[i] = prng.get<block>();

#ifdef LAZY_OT
                LzKosOtExtReceiver otRecv;
                LzKosOtExtSender otSend;
#else
                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
#endif // LAZY_OT


                AknBfMPsiSender sendPSIs;

                sendPSIs.init(setSize, params.mStatSecParam, otSend, chls, prng.get<block>());


                chls[0].asyncSend(dummy, 1);
                chls[0].recv(dummy, 1);

                sendPSIs.sendInput(set, chls);
            }
        }
    }

#else
    std::cout << Color::Red << "RR16 PSI is not enabled" << std::endl << Color::Default;
#endif
}


void bfRecv(LaunchParams& params)
{
#ifdef ENABLE_RR16_PSI
    for (u64 g = 0; g < params.mChls.size(); ++g)
        params.mChls[g].resetStats();


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

#ifdef LAZY_OT
                LzKosOtExtReceiver otRecv;
                LzKosOtExtSender otSend;
#else
                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
#endif // LAZY_OT


                AknBfMPsiReceiver recvPSIs;


                Timer timer;
                auto start = timer.setTimePoint("start");
                recvPSIs.init(setSize, params.mStatSecParam, otRecv, chls, ZeroBlock);



                chls[0].asyncSend(dummy, 1);
                chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("init");

                 
                recvPSIs.sendInput(set, chls);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                std::string tag("RR16");               
                printTimings(tag, chls, offlineTime, onlineTime, params, setSize, numThreads);

            }
        }
    }

#else
    std::cout << Color::Red << "RR16 PSI is not enabled" << std::endl << Color::Default;
#endif
}


