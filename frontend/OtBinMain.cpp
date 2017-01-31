#include "bloomFilterMain.h"
#include "cryptoTools/Network/BtEndpoint.h" 

#include "MPSI/Beta/OtBinMPsiReceiver.h"
#include "MPSI/Beta/OtBinMPsiSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"
#include "libOTe/NChooseOne/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/KkrtNcoOtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>
u8 dummy[1];

#define OOS

void otBinSend(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");


    LinearCode code;
    code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel*> sendChls  =params.getChannels(cc);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::vector<block> set(setSize);
                prng.get(set.data(), set.size());

#ifdef OOS
                OosNcoOtReceiver otRecv(code, 40);
                OosNcoOtSender otSend(code, 40);
#else
                KkrtNcoOtReceiver otRecv;
                KkrtNcoOtSender otSend;
#endif
                OtBinMPsiSender sendPSIs;

                sendChls[0]->asyncSend(dummy, 1);
                sendChls[0]->recv(dummy, 1);

                sendPSIs.init(setSize, params.mStatSecParam, 128, sendChls, otSend, otRecv, prng.get<block>());

                sendChls[0]->asyncSend(dummy, 1);
                sendChls[0]->recv(dummy, 1);

                sendPSIs.sendInput(set, sendChls);

                u64 dataSent = 0;
                for (u64 g = 0; g < sendChls.size(); ++g)
                {
                    dataSent += sendChls[g]->getTotalDataSent();
                }

                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g]->resetStats();
            }
        }
    }
}

void otBinRecv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    LinearCode code;
    code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            auto chls = params.getChannels(cc);

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {

                std::vector<block> sendSet(setSize), recvSet(setSize);
                for (u64 i = 0; i < setSize; ++i)
                {
                    sendSet[i] = recvSet[i] = prng.get<block>();
                }


#ifdef OOS
                OosNcoOtReceiver otRecv(code, 40);
                OosNcoOtSender otSend(code, 40);
#else
                KkrtNcoOtReceiver otRecv;
                KkrtNcoOtSender otSend;
#endif
                OtBinMPsiReceiver recvPSIs;


                chls[0]->recv(dummy, 1);
                gTimer.reset();
                chls[0]->asyncSend(dummy, 1);



                Timer timer;
                
                auto start = timer.setTimePoint("start");
                
                recvPSIs.init(setSize, params.mStatSecParam, 128, chls, otRecv, otSend, prng.get<block>());

                chls[0]->asyncSend(dummy, 1);
                chls[0]->recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(recvSet, chls);


                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                u64 dataSent = 0;
                for (u64 g = 0; g < chls.size(); ++g)
                {
                    dataSent += chls[g]->getTotalDataSent();
                    chls[g]->resetStats();
                }


                double time = offlineTime + onlineTime;
                time /= 1000;
                auto Mbps = dataSent * 8 / time / (1 << 20);

                std::string tag("RR17");
                if (params.mVerbose)
                {
                    std::cout << tag << " n = " << setSize << "  threads = " << cc << "\n"
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
                        << "   n="<<std::setw(6) << setSize 
                        << "   t=" << std::setw(3) << cc 
                        << "   offline=" << std::setw(6) << offlineTime << " ms"
                        << "   online=" << std::setw(6) << onlineTime << "       "
                        <<"    Comm=" << std::setw(6) << (dataSent / std::pow(2.0, 20)) << " MB ("
                        << std::setw(6) << Mbps << " Mbps)" << std::endl;
                }
            }
        }
    }
}

