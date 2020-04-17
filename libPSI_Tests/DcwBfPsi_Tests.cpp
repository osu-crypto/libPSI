#include "DcwBfPsi_Tests.h"

#include "Common.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Common/Defines.h"
#include "libPSI/PSI/Dcw/DcwRBfPsiReceiver.h"
#include "libPSI/PSI/Dcw/DcwRBfPsiSender.h"
#include "cryptoTools/Common/Log.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include "cryptoTools/Common/TestCollection.h"
#include <array>

using namespace osuCrypto;


#ifdef ENABLE_DCW_PSI


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

    IOService ios;
    Endpoint ep0(ios, "localhost:1212", EpMode::Client);
    Endpoint ep1(ios, "localhost:1212", EpMode::Server);

    std::vector<Channel> recvChl{ ep1.addChannel() };
    std::vector<Channel> sendChl{ ep0.addChannel() };

    IknpOtExtReceiver otRecv;
    IknpOtExtSender otSend;


    std::vector<DcwRBfPsiSender> sendPSIs(repeatCount);
    std::vector<DcwRBfPsiReceiver> recvPSIs(repeatCount);
    std::thread thrd([&]() {

        for (u64 j = 0; j < repeatCount; ++j)
        {
            sendPSIs[j].init(setSize, psiSecParam, otSend, sendChl, prng.get<block>());
        }
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
        recvPSIs[j].init(setSize, psiSecParam, otRecv, recvChl[0], ZeroBlock);
    }

    thrd.join();


    auto sendThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            auto& sender = sendPSIs[j];

            sender.sendInput(sendSet, sendChl[0]);
        }
    });

    auto recvThrd = std::thread([&]() {
        for (u64 j = 0; j < repeatCount; ++j)
        {
            auto& recv = recvPSIs[j];

            recv.sendInput(recvSet, recvChl[0]);

            if (recv.mIntersection.size())
                throw UnitTestFail();
        }
    });
    sendThrd.join();
    recvThrd.join();


    sendChl[0].close();
    recvChl[0].close();

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

    IOService ios;
    Endpoint ep0(ios, "localhost:1212", EpMode::Client);
    Endpoint ep1(ios, "localhost:1212", EpMode::Server);


    std::vector<Channel> recvChls{ ep1.addChannel() };
    std::vector<Channel> sendChls{ ep0.addChannel() };


    IknpOtExtReceiver otRecv;
    IknpOtExtSender otSend;



    DcwRBfPsiSender sendPSIs;
    DcwRBfPsiReceiver recvPSIs;
    std::thread thrd([&]() {


            sendPSIs.init(setSize, psiSecParam, otSend, sendChls[0], prng.get<block>());
            sendPSIs.sendInput(sendSet, sendChls);
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
        recvPSIs.init(setSize, psiSecParam, otRecv, recvChls[0], ZeroBlock);
        recvPSIs.sendInput(recvSet, recvChls);
    }

    thrd.join();

    if (recvPSIs.mIntersection.size() != setSize)
    {
        
        throw UnitTestFail("bad size, expected:" + std::to_string(setSize) +
            ", actual:" +std::to_string(recvPSIs.mIntersection.size()));
    }
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

    IOService ios;
    Endpoint ep0(ios, "localhost:1212", EpMode::Client);
    Endpoint ep1(ios, "localhost:1212", EpMode::Server);


    std::vector<Channel> recvChl{ ep1.addChannel() };
    std::vector<Channel> sendChl{ ep0.addChannel() };


    IknpOtExtReceiver otRecv;
    IknpOtExtSender otSend;



    std::vector<DcwRBfPsiSender> sendPSIs(repeatCount);
    std::vector<DcwRBfPsiReceiver> recvPSIs(repeatCount);
    std::thread thrd([&]() {

        for (u64 j = 0; j < repeatCount; ++j)
        {

            std::vector<Channel> cc{ sendChl };
            sendPSIs[j].init(setSize, psiSecParam, otSend, cc, prng.get<block>());
        }
    });

    for (u64 j = 0; j < repeatCount; ++j)
    {
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

}
#else


void DcwRBfPsi_EmptrySet_Test_Impl() { throw oc::UnitTestSkipped("ENABLE_DCW_PSI not defined"); }
void DcwRBfPsi_FullSet_Test_Impl() { throw oc::UnitTestSkipped("ENABLE_DCW_PSI not defined"); }
void DcwRBfPsi_SingltonSet_Test_Impl() { throw oc::UnitTestSkipped("ENABLE_DCW_PSI not defined"); }

#endif 