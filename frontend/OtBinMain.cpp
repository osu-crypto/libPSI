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

#define OOS
#define pows  { 16/*8,12,,20*/ }
#define threadss {1/*1,4,16,64*/}

void otBinSend()
{


    setThreadName("CP_Test_Thread");
    u64 numThreads(64);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(2);


    std::cout << "role  = sender (" << numThreads << ") otBin" << std::endl;

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint sendEP(ios, "localhost", 1213, true, name);

    std::vector<Channel*> sendChls_(numThreads);

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls_[i] = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    u8 dummy[1];

    senderGetLatency(*sendChls_[0]);
    sendChls_[0]->resetStats();

    LinearCode code;
    code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");

    //for (auto pow : {/* 8,12,*/ 16/*, 20 */ })
    for (auto pow : pows)
    {

        for (auto cc : threadss)
        {
            std::vector<Channel*> sendChls;

            if (pow == 8)
                cc = std::min(8, cc);

            //std::cout << "numTHreads = " << cc << std::endl;

            sendChls.insert(sendChls.begin(), sendChls_.begin(), sendChls_.begin() + cc);

            u64 offlineTimeTot(0);
            u64 onlineTimeTot(0);
            //for (u64 numThreads = 1; numThreads < 129; numThreads *= 2)
            for (u64 jj = 0; jj < numTrial; jj++)
            {

                //u64 repeatCount = 1;
                u64 setSize = (1 << pow), psiSecParam = 40;
                PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


                std::vector<block> sendSet;
                sendSet.resize(setSize);

                for (u64 i = 0; i < setSize; ++i)
                {
                    sendSet[i] = prng.get<block>();
                }

#ifdef OOS
                OosNcoOtReceiver otRecv(code, 40);
                OosNcoOtSender otSend(code, 40);
#else
                KkrtNcoOtReceiver otRecv;
                KkrtNcoOtSender otSend;
#endif
                OtBinMPsiSender sendPSIs;

                //gTimer.reset();

                sendChls[0]->asyncSend(dummy, 1);
                sendChls[0]->recv(dummy, 1);
                u64 otIdx = 0;
                //std::cout << "sender init" << std::endl;
                sendPSIs.init(setSize, psiSecParam,128, sendChls,otSend, otRecv, prng.get<block>());

                //return;
                sendChls[0]->asyncSend(dummy, 1);
                sendChls[0]->recv(dummy, 1);
                //std::cout << "sender init done" << std::endl;

                sendPSIs.sendInput(sendSet, sendChls);

                u64 dataSent = 0;
                for (u64 g = 0; g < sendChls.size(); ++g)
                {
                    dataSent += sendChls[g]->getTotalDataSent();
                }

                //std::accumulate(sendChls[0]->getTotalDataSent())

                //std::cout << setSize << "    " << dataSent / std::pow(2, 20) << " byte  " << std::endl;
                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g]->resetStats();

                //std::cout << gTimer << std::endl;
            }

        }


    }
    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls_[i]->close();// = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    //sendChl.close();
    //recvChl.close();

    sendEP.stop();

    ios.stop();
}

void otBinRecv()
{

    setThreadName("CP_Test_Thread");
    u64 numThreads(64);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(2);

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint recvEP(ios, "localhost", 1213, false, name);

    LinearCode code; 

    code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");

    std::vector<Channel*> recvChls_(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls_[i] = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    std::cout << "role  = recv(" << numThreads << ") otBin" << std::endl;
    u8 dummy[1];
    recverGetLatency(*recvChls_[0]);

    //for (auto pow : {/* 8,12,*/16/*,20*/ })
    for (auto pow : pows)
    {
        for (auto cc : threadss)
        {
            std::vector<Channel*> recvChls;

            if (pow == 8)
                cc = std::min(8, cc);

            u64 setSize = (1 << pow), psiSecParam = 40;

            std::cout << "numTHreads = " << cc << "  n=" << setSize << std::endl;

            recvChls.insert(recvChls.begin(), recvChls_.begin(), recvChls_.begin() + cc);

            u64 offlineTimeTot(0);
            u64 onlineTimeTot(0);
            //for (u64 numThreads = 1; numThreads < 129; numThreads *= 2)
            for (u64 jj = 0; jj < numTrial; jj++)
            {

                //u64 repeatCount = 1;
                PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


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


                recvChls[0]->recv(dummy, 1);
                gTimer.reset();
                recvChls[0]->asyncSend(dummy, 1);

                u64 otIdx = 0;


                Timer timer;
                auto start = timer.setTimePoint("start");
                recvPSIs.init(setSize, psiSecParam,128,  recvChls, otRecv, otSend, ZeroBlock);
                //return;


                //std::vector<u64> sss(recvChls.size());
                //for (u64 g = 0; g < recvChls.size(); ++g)
                //{
                //    sss[g] =  recvChls[g]->getTotalDataSent();
                //}

                recvChls[0]->asyncSend(dummy, 1);
                recvChls[0]->recv(dummy, 1);
                auto mid = timer.setTimePoint("init");


                recvPSIs.sendInput(recvSet, recvChls);
                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();


                offlineTimeTot += offlineTime;
                onlineTimeTot += onlineTime;
                //auto byteSent = recvChls[0]->getTotalDataSent() *recvChls.size();

                u64 dataSent = 0;
                for (u64 g = 0; g < recvChls.size(); ++g)
                {
                    dataSent += recvChls[g]->getTotalDataSent();
                    //std::cout << "chl[" << g << "] " << recvChls[g]->getTotalDataSent() << "   " << sss[g] << std::endl;
                }

                double time = offlineTime + onlineTime;
                time /= 1000;
                auto Mbps = dataSent * 8 / time / (1 << 20);

                std::cout << setSize << "  " << offlineTime << "  " << onlineTime << "        " << Mbps << " Mbps      " << (dataSent / std::pow(2.0, 20)) << " MB" << std::endl;

                for (u64 g = 0; g < recvChls.size(); ++g)
                    recvChls[g]->resetStats();

                //std::cout << "threads =  " << numThreads << std::endl << timer << std::endl << std::endl << std::endl;


                //std::cout << numThreads << std::endl;
                //std::cout << timer << std::endl;

                std::cout << gTimer << std::endl;

                //if (recv.mIntersection.size() != setSize)
                //    throw std::runtime_error("");







            }



            online << onlineTimeTot / numTrial << "-";
            offline << offlineTimeTot / numTrial << "-";

        }
    }

    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls_[i]->close();// = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    //sendChl.close();
    //recvChl.close();

    recvEP.stop();

    ios.stop();
}

