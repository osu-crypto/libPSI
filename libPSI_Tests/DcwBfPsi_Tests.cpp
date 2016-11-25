#include "DcwBfPsi_Tests.h"

#include "Common.h"
#include "Network/BtEndpoint.h"
#include "Common/Defines.h"
#include "MPSI/Dcw/DcwBfPsiReceiver.h"
#include "MPSI/Dcw/DcwBfPsiSender.h"
#include "MPSI/Dcw/DcwRBfPsiReceiver.h"
#include "MPSI/Dcw/DcwRBfPsiSender.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
#include "Common/Log.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>

using namespace osuCrypto;



void DcwBfPsi_EmptrySet_Test_Impl()
{
    u64 repeatCount = 1;
    u64 setSize = 8, psiSecParam = 40;
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = prng.get<block>();
        recvSet[i] = prng.get<block>();
    }

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    std::vector<Channel*> recvChl{ &ep1.addChannel(name, name) };
    std::vector<Channel*> sendChl{ &ep0.addChannel(name, name) };


    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



    std::vector<DcwBfPsiSender> sendPSIs(repeatCount);
    std::vector<DcwBfPsiReceiver> recvPSIs(repeatCount);
    std::thread thrd([&]() {

        for (u64 j = 0; j < repeatCount; ++j)
        {
            u64 otIdx = 0;
            sendPSIs[j].init(setSize, psiSecParam, otSend, sendChl, prng.get<block>());
        }
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
        u64 otIdx = 0;
        recvPSIs[j].init(setSize, psiSecParam, otRecv, *recvChl[0], ZeroBlock);
    }

    thrd.join();


    auto sendThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            DcwBfPsiSender& sender = sendPSIs[j];

            sender.sendInput(sendSet, *sendChl[0]);
        }
    });

    auto recvThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            DcwBfPsiReceiver& recv = recvPSIs[j];

            recv.sendInput(recvSet, *recvChl[0]);

            if (recv.mIntersection.size())
                throw UnitTestFail();
        }
    });
    sendThrd.join();
    recvThrd.join();


    sendChl[0]->close();
    recvChl[0]->close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}


void DcwBfPsi_FullSet_Test_Impl()
{
    setThreadName("CP_Test_Thread");
    u64 setSize = 8, psiSecParam = 40, numThreads(1);
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = recvSet[i] = prng.get<block>();
    }

    std::shuffle(sendSet.begin(), sendSet.end(), prng);


    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    std::vector<Channel*> sendChls(numThreads), recvChls(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i] = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i] = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



    DcwBfPsiSender sendPSI;
    DcwBfPsiReceiver recvPSI;
    std::thread thrd([&]() {

        sendPSI.init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());
        sendPSI.sendInput(sendSet, sendChls);
    });
    recvPSI.init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);
    recvPSI.sendInput(recvSet, recvChls);


    thrd.join();

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i]->close();// = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i]->close();// = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    ep0.stop();
    ep1.stop();
    ios.stop();

    if (recvPSI.mIntersection.size() != setSize)
        throw UnitTestFail("Bad intersection size");


}

void DcwBfPsi_SingltonSet_Test_Impl()
{
    setThreadName("Sender");
    //InitDebugPrinting("..//test.out");
    u64 setSize = 5, psiSecParam = 30;

    PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = prng.get<block>();
        recvSet[i] = prng.get<block>();
    }

    sendSet[0] = recvSet[0];

    std::string name("psi");
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    Channel& recvChl = ep1.addChannel(name, name);
    Channel& sendChl = ep0.addChannel(name, name);


    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



    DcwBfPsiSender sendPSI;
    DcwBfPsiReceiver recvPSI;
    std::thread thrd([&]() {
        std::vector<Channel*> cc{ &sendChl };
        sendPSI.init(setSize, psiSecParam, otSend, cc, prng.get<block>());
        sendPSI.sendInput(sendSet, sendChl);
    });

    recvPSI.init(setSize, psiSecParam, otRecv, recvChl, ZeroBlock);


    recvPSI.sendInput(recvSet, recvChl);


    thrd.join();

    sendChl.close();
    recvChl.close();

    ep0.stop();
    ep1.stop();
    ios.stop();


    if (recvPSI.mIntersection.size() != 1 ||
        recvPSI.mIntersection[0] != 0)
        throw UnitTestFail();
}



void DcwRBfPsi_EmptrySet_Test_Impl()
{
    u64 repeatCount = 1;
    u64 setSize = 8, psiSecParam = 40;
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = prng.get<block>();
        recvSet[i] = prng.get<block>();
    }

    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    std::vector<Channel*> recvChl{ &ep1.addChannel(name, name) };
    std::vector<Channel*> sendChl{ &ep0.addChannel(name, name) };


    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



    std::vector<DcwRBfPsiSender> sendPSIs(repeatCount);
    std::vector<DcwRBfPsiReceiver> recvPSIs(repeatCount);
    std::thread thrd([&]() {

        for (u64 j = 0; j < repeatCount; ++j)
        {
            u64 otIdx = 0;
            sendPSIs[j].init(setSize, psiSecParam, otSend, sendChl, prng.get<block>());
        }
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
        u64 otIdx = 0;
        recvPSIs[j].init(setSize, psiSecParam, otRecv, *recvChl[0], ZeroBlock);
    }

    thrd.join();


    auto sendThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            DcwRBfPsiSender& sender = sendPSIs[j];

            sender.sendInput(sendSet, *sendChl[0]);
        }
    });

    auto recvThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            DcwRBfPsiReceiver& recv = recvPSIs[j];

            recv.sendInput(recvSet, *recvChl[0]);

            if (recv.mIntersection.size())
                throw UnitTestFail();
        }
    });
    sendThrd.join();
    recvThrd.join();


    sendChl[0]->close();
    recvChl[0]->close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}


void DcwRBfPsi_FullSet_Test_Impl()
{
    setThreadName("CP_Test_Thread");
    u64 repeatCount = 1;
    u64 setSize = 8, psiSecParam = 40, numThreads(1);
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = recvSet[i] = prng.get<block>();
    }

    std::shuffle(sendSet.begin(), sendSet.end(), prng);


    std::string name("psi");

    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    std::vector<Channel*> sendChls(numThreads), recvChls(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i] = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i] = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



    std::vector<DcwRBfPsiSender> sendPSIs(repeatCount);
    std::vector<DcwRBfPsiReceiver> recvPSIs(repeatCount);
    std::thread thrd([&]() {

        for (u64 j = 0; j < repeatCount; ++j)
        {
            u64 otIdx = 0;

            sendPSIs[j].init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());
            sendPSIs[j].sendInput(sendSet, sendChls);
        }
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
        u64 otIdx = 0;
        recvPSIs[j].init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);

        DcwRBfPsiReceiver& recv = recvPSIs[j];

        recv.sendInput(recvSet, recvChls);

        if (recv.mIntersection.size() != setSize)
            throw UnitTestFail();
    }



    thrd.join();

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i]->close();// = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i]->close();// = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    ep0.stop();
    ep1.stop();
    ios.stop();

}

void DcwRBfPsi_SingltonSet_Test_Impl()
{
    setThreadName("Sender");
    //InitDebugPrinting("..//test.out");
    u64 repeatCount = 1;
    u64 setSize = 20, psiSecParam = 30;

    PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = prng.get<block>();
        recvSet[i] = prng.get<block>();
    }

    sendSet[0] = recvSet[0];

    std::string name("psi");
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    Channel& recvChl = ep1.addChannel(name, name);
    Channel& sendChl = ep0.addChannel(name, name);


    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



    std::vector<DcwRBfPsiSender> sendPSIs(repeatCount);
    std::vector<DcwRBfPsiReceiver> recvPSIs(repeatCount);
    std::thread thrd([&]() {

        for (u64 j = 0; j < repeatCount; ++j)
        {
            u64 otIdx = 0;

            std::vector<Channel*> cc{ &sendChl };
            sendPSIs[j].init(setSize, psiSecParam, otSend, cc, prng.get<block>());
        }
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
        u64 otIdx = 0;
        recvPSIs[j].init(setSize, psiSecParam, otRecv, recvChl, ZeroBlock);
    }

    thrd.join();

    auto sendThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            DcwRBfPsiSender& sender = sendPSIs[j];

            sender.sendInput(sendSet, sendChl);
        }
    });

    auto recvThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            DcwRBfPsiReceiver& recv = recvPSIs[j];

            recv.sendInput(recvSet, recvChl);

            if (recv.mIntersection.size() != 1 ||
                recv.mIntersection[0] != 0)
                throw UnitTestFail();
        }
    });
    sendThrd.join();
    recvThrd.join();

    sendChl.close();
    recvChl.close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}