#include "dcwMain.h"



#include "MPSI/Dcw/DcwBfPsiReceiver.h"
#include "MPSI/Dcw/DcwBfPsiSender.h"
#include "MPSI/Dcw/DcwRBfPsiReceiver.h"
#include "MPSI/Dcw/DcwRBfPsiSender.h"



#include "Common/Defines.h"
#include "Network/BtEndpoint.h" 
#include "OT/TwoChooseOne/KosOtExtReceiver.h"
#include "OT/TwoChooseOne/KosOtExtSender.h"

#include "OT/TwoChooseOne/LzKosOtExtReceiver.h"
#include "OT/TwoChooseOne/LzKosOtExtSender.h"
#include "Common/Log.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <fstream>

using namespace osuCrypto;

void DcwSend()
{


    Log::setThreadName("CP_Test_Thread");
    u64 numThreads(1);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(8);


    Log::out << "role  = sender (" << numThreads << ") Dcw" << Log::endl;

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint sendEP(ios, "localhost", 1212, true, name);

    std::vector<Channel*> sendChls(numThreads);

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i] = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    u8 dummy[1];

    for (auto pow : { 8,12, 16, 20 })
    {

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


            KosOtExtReceiver otRecv;
            KosOtExtSender otSend;



            DcwBfPsiSender sendPSIs;

            gTimer.reset();
            Timer timer;

            //auto start = timer.setTimePoint("sender.Start");
            sendPSIs.init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());
            //auto mid = timer.setTimePoint("sender.InitDOne");
            sendChls[0]->asyncSend(dummy, 1);



            sendPSIs.sendInput(sendSet, sendChls);
            //auto end = timer.setTimePoint("sender.Done");


            //auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
            //auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

            //Log::out << setSize << "  " << offlineTime << "  " << Log::endl;


        }

    }


    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i]->close();// = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    //sendChl.close();
    //recvChl.close();

    sendEP.stop();

    ios.stop();
}

void DcwRecv()
{
    u8 dummy[1];

    Log::setThreadName("CP_Test_Thread");
    u64 numThreads(1);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(8);

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint recvEP(ios, "localhost", 1212, false, name);

    std::vector<Channel*> recvChls;
    recvChls.resize(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls[i] = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    Log::out << "role  = recv(" << numThreads << ")" << Log::endl;

    for (auto pow : { 8,12,16,20 })
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



            KosOtExtReceiver otRecv;
            KosOtExtSender otSend;


            DcwBfPsiReceiver recvPSIs;



            gTimer.reset();

            u64 otIdx = 0;


            Timer timer;
            auto start = timer.setTimePoint("start");
            recvPSIs.init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);

            recvChls[0]->recv(dummy, 1);
            auto mid = timer.setTimePoint("init");



            recvPSIs.sendInput(recvSet, recvChls);
            auto end = timer.setTimePoint("done");

            auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
            auto online = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();


            offlineTimeTot += offlineTime;
            onlineTimeTot += online;
            Log::out << setSize << "  " << offlineTime << "  " << online << Log::endl;

        }

        online << onlineTimeTot / numTrial << "-";
        offline << offlineTimeTot / numTrial << "-";
    }

    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls[i]->close();
    }

    recvEP.stop();

    ios.stop();
}





void DcwRSend()
{


    Log::setThreadName("CP_Test_Thread");
    u64 numThreads(1);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(8);


    Log::out << "role  = sender (" << numThreads << ") Dcw" << Log::endl;

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint sendEP(ios, "localhost", 1212, true, name);

    std::vector<Channel*> sendChls(numThreads);

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i] = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    u8 dummy[1];

    for (auto pow : { 8,12, 16, 20 })
    {

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


            KosOtExtReceiver otRecv;
            KosOtExtSender otSend;



            DcwRBfPsiSender sendPSIs;

            gTimer.reset();
            Timer timer;

            //auto start = timer.setTimePoint("sender.Start");
            sendPSIs.init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());
            //auto mid = timer.setTimePoint("sender.InitDOne");
            sendChls[0]->asyncSend(dummy, 1);



            sendPSIs.sendInput(sendSet, sendChls);
            //auto end = timer.setTimePoint("sender.Done");


            //auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
            //auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

            //Log::out << setSize << "  " << offlineTime << "  " << Log::endl;


        }

    }


    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i]->close();// = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    //sendChl.close();
    //recvChl.close();

    sendEP.stop();

    ios.stop();
}

void DcwRRecv()
{
    u8 dummy[1];

    Log::setThreadName("CP_Test_Thread");
    u64 numThreads(1);

    std::fstream online, offline;
    online.open("./online.txt", online.trunc | online.out);
    offline.open("./offline.txt", offline.trunc | offline.out);
    u64 numTrial(8);

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint recvEP(ios, "localhost", 1212, false, name);

    std::vector<Channel*> recvChls;
    recvChls.resize(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls[i] = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    Log::out << "role  = recv(" << numThreads << ")" << Log::endl;

    for (auto pow : { 8,12,16,20 })
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



            KosOtExtReceiver otRecv;
            KosOtExtSender otSend;


            DcwRBfPsiReceiver recvPSIs;



            gTimer.reset();

            u64 otIdx = 0;


            Timer timer;
            auto start = timer.setTimePoint("start");
            recvPSIs.init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);

            recvChls[0]->recv(dummy, 1);
            auto mid = timer.setTimePoint("init");



            recvPSIs.sendInput(recvSet, recvChls);
            auto end = timer.setTimePoint("done");

            auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
            auto online = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();


            offlineTimeTot += offlineTime;
            onlineTimeTot += online;
            Log::out << setSize << "  " << offlineTime << "  " << online << Log::endl;

        }

        online << onlineTimeTot / numTrial << "-";
        offline << offlineTimeTot / numTrial << "-";
    }

    for (u64 i = 0; i < numThreads; ++i)
    {
        recvChls[i]->close();
    }

    recvEP.stop();

    ios.stop();
}

