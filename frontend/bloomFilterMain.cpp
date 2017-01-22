#include "bloomFilterMain.h"
#include "cryptoTools/Network/BtEndpoint.h" 

#include "MPSI/Rr16/AknBfMPsiReceiver.h"
#include "MPSI/Rr16/AknBfMPsiSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"

#include "libOTe/TwoChooseOne/LzKosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/LzKosOtExtSender.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>

#define LAZY_OT

#define pows  { 8,12,16/*,20*/ }
#define threadss {1,4/*1,4,16,64*/}


void bfSend()
{


    setThreadName("CP_Test_Thread");
    u64 numThreads(64);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(1);


    std::cout << "role  = sender (" << numThreads << ") akn" << std::endl;

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint sendEP(ios, "localhost", 1212, true, name);

    std::vector<Channel*> sendChls_(numThreads);

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls_[i] = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    u8 dummy[1];

    senderGetLatency(*sendChls_[0]);
    sendChls_[0]->resetStats();

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


#ifdef LAZY_OT
                LzKosOtExtReceiver otRecv;
                LzKosOtExtSender otSend;
#else
                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
#endif // LAZY_OT



                AknBfMPsiSender sendPSIs;

                gTimer.reset();

                //std::cout << "sender init" << std::endl;
                sendPSIs.init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());

                //return;
                sendChls[0]->asyncSend(dummy, 1);
                sendChls[0]->recv(dummy, 1);
                //std::cout << "sender init done" << std::endl;

                sendPSIs.sendInput(sendSet, sendChls);

                u64 dataSent = 0;
                for(u64 g = 0; g < sendChls.size(); ++g)
                {
                    dataSent += sendChls[g]->getTotalDataSent();
                }

                //std::accumulate(sendChls[0]->getTotalDataSent())

                std::cout << setSize << "    " << dataSent / std::pow(2,20) << " byte  " << std::endl;
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

void bfRecv()
{

    setThreadName("CP_Test_Thread");
    u64 numThreads(64);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(1);

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint recvEP(ios, "localhost", 1212, false, name);

    std::vector<Channel*> recvChls_(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls_[i] = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    std::cout << "role  = recv(" << numThreads << ") akn" << std::endl;
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





#define LAZY_OT
#ifdef LAZY_OT
                LzKosOtExtReceiver otRecv;
                LzKosOtExtSender otSend;
#else
                KosOtExtReceiver otRecv;
                KosOtExtSender otSend;
#endif // LAZY_OT


                AknBfMPsiReceiver recvPSIs;

                gTimer.reset();



                Timer timer;
                auto start = timer.setTimePoint("start");
                recvPSIs.init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);
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

                std::cout << setSize << "  " << offlineTime << "  " << onlineTime << "        " << Mbps << " Mbps      " << (dataSent / std::pow(2.0, 20)) << " MB"  << std::endl;

                for (u64 g = 0; g < recvChls.size(); ++g)
                    recvChls[g]->resetStats();

                //std::cout << "threads =  " << numThreads << std::endl << timer << std::endl << std::endl << std::endl;


                //std::cout << numThreads << std::endl;
                //std::cout << timer << std::endl;

                //std::cout << gTimer << std::endl;

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








void bf(int role)
{

    setThreadName("CP_Test_Thread");
    u64 numThreads(64);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(8);


    std::cout << "role  = " << role << std::endl;

    for (auto pow : pows)
    {

        u64 offlineTimeTot(0);
        u64 onlineTimeTot(0);
        //for (u64 numThreads = 1; numThreads < 129; numThreads *= 2)
        for (u64 jj = 0; jj < numTrial; jj++)
        {

            //u64 repeatCount = 1;
            u64 setSize = (1 << pow), psiSecParam = 40;
            PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


            std::vector<block> sendSet(setSize), recvSet(setSize);




            for (u64 i = 0; i < setSize; ++i)
            {
                sendSet[i] = recvSet[i] = prng.get<block>();
            }


            std::shuffle(sendSet.begin(), sendSet.end(), prng);


            std::string name("psi");

            BtIOService ios(0);
            BtEndpoint recvEP(ios, "localhost", 1212, false, name);
            BtEndpoint sendEP(ios, "localhost", 1212, true, name);

            std::vector<Channel*> sendChls, recvChls;
            sendChls.resize(numThreads);
            recvChls.resize(numThreads);
            for (u64 i = 0; i < numThreads; ++i)
            {
                recvChls[i] = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
                sendChls[i] = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
            }

#define LAZY_OT
#ifdef LAZY_OT
            LzKosOtExtReceiver otRecv;
            LzKosOtExtSender otSend;
#else
            KosOtExtReceiver otRecv;
            KosOtExtSender otSend;
#endif // LAZY_OT


            std::thread thrd;

            AknBfMPsiSender sendPSIs;
            AknBfMPsiReceiver recvPSIs;
            thrd = std::thread([&]() {



                sendPSIs.init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());
                sendPSIs.sendInput(sendSet, sendChls);

            });

            gTimer.reset();



            Timer timer;
            auto start = timer.setTimePoint("start");
            recvPSIs.init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);
            auto mid = timer.setTimePoint("init");


            AknBfMPsiReceiver& recv = recvPSIs;

            recv.sendInput(recvSet, recvChls);
            auto end = timer.setTimePoint("done");

            auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
            auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();


            offlineTimeTot += offlineTime;
            onlineTimeTot += onlineTime;
            std::cout << setSize << "  " << offlineTime << "  " << onlineTime << std::endl;


            //std::cout << "threads =  " << numThreads << std::endl << timer << std::endl << std::endl << std::endl;


            //std::cout << numThreads << std::endl;
            //std::cout << timer << std::endl;

            //std::cout << gTimer << std::endl;

            //if (recv.mIntersection.size() != setSize)
            //    throw std::runtime_error("");



            thrd.join();

            for (u64 i = 0; i < numThreads; ++i)
            {
                sendChls[i]->close();// = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
                recvChls[i]->close();// = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
            }
            //sendChl.close();
            //recvChl.close();

            recvEP.stop();
            sendEP.stop();

            ios.stop();


        }



        online << onlineTimeTot / numTrial << "-";
        offline << offlineTimeTot / numTrial << "-";
    }
}
