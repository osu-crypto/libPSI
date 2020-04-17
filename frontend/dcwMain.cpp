

#include "dcwMain.h"

#include "cryptoTools/Network/Endpoint.h" 


#include "libPSI/PSI/Dcw/DcwRBfPsiReceiver.h"
#include "libPSI/PSI/Dcw/DcwRBfPsiSender.h"



#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "libOTe/TwoChooseOne/SilentOtExtReceiver.h"
#include "libOTe/TwoChooseOne/SilentOtExtSender.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <fstream>
#include <algorithm>
#include "boost/format.hpp"
extern u8 dummy[];

using namespace osuCrypto;


void DcwRSend(
    LaunchParams& params)
{
#ifdef ENABLE_DCW_PSI
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

                SilentOtExtReceiver sRecv;
                SilentOtExtSender sSend;
                IknpOtExtReceiver iRecv;
                IknpOtExtSender iSend;
                bool silent = params.mCmd->isSet("silent");
                OtExtReceiver& otRecv = silent ? (OtExtReceiver&)sRecv : iRecv;
                OtExtSender& otSend = silent ? (OtExtSender&)sSend : iSend;
                DcwRBfPsiSender sendPSIs;

                gTimer.reset();
                sendPSIs.init(setSize, params.mStatSecParam, otSend, chls, prng.get<block>());
                chls[0].asyncSend(dummy, 1);
                sendPSIs.sendInput(set, chls);
            }
        }
    }

#else
    std::cout << Color::Red << "DCW PSI is not enabled" << std::endl << Color::Default;
#endif
}

void DcwRRecv(
    LaunchParams& params)
{
#ifdef ENABLE_DCW_PSI
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

                SilentOtExtReceiver sRecv;
                SilentOtExtSender sSend;
                IknpOtExtReceiver iRecv;
                IknpOtExtSender iSend;
                bool silent = params.mCmd->isSet("silent");
                OtExtReceiver& otRecv = silent ? (OtExtReceiver&)sRecv : iRecv;
                OtExtSender& otSend = silent ? (OtExtSender&)sSend : iSend;
                DcwRBfPsiReceiver recvPSIs;



                gTimer.reset();
                Timer timer;
                auto start = timer.setTimePoint("start");

                recvPSIs.init(setSize, params.mStatSecParam, otRecv, chls, sysRandomSeed());

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
#else
    std::cout << Color::Red << "DCW PSI is not enabled" << std::endl << Color::Default;
#endif
}
