#include "AknBfPsi_Tests.h"

#include "cryptoTools/Network/Endpoint.h"
#include <cryptoTools/Network/IOService.h>
#include "Common.h"
#include "cryptoTools/Common/Defines.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include "libPSI/MPSI/Rr16/AknBfMPsiReceiver.h"
#include "libPSI/MPSI/Rr16/AknBfMPsiSender.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/TestCollection.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>

using namespace osuCrypto;



void AknBfPsi_EmptrySet_Test_Impl()
{
#ifdef ENABLE_RR16_PSI

    u64 setSize = 8, psiSecParam = 40;
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = prng.get<block>();
        recvSet[i] = prng.get<block>();
    }

    std::string name("psi");

    IOService ios(0);
    Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
    Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);


    std::vector<Channel> recvChl{ ep1.addChannel(name, name) };
    std::vector<Channel> sendChl{ ep0.addChannel(name, name) };


    
    KosOtExtReceiver otRecv;
    KosOtExtSender otSend;

    auto async = std::async([&]() {PRNG prng(ZeroBlock); otRecv.genBaseOts(prng, recvChl[0]); });
    otSend.genBaseOts(prng, sendChl[0]);
    async.get();

    AknBfMPsiSender send;
    AknBfMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, otSend, sendChl, prng.get<block>());
        send.sendInput(sendSet, sendChl[0]);
    });

    recv.init(setSize, psiSecParam, otRecv, recvChl[0], ZeroBlock);
    recv.sendInput(recvSet, recvChl[0]);

    thrd.join();

    sendChl[0].close();
    recvChl[0].close();

    ep0.stop();
    ep1.stop();
    ios.stop();
#else
    throw UnitTestSkipped("Not enabled");
#endif
}


void AknBfPsi_FullSet_Test_Impl()
{
#ifdef ENABLE_RR16_PSI

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

    IOService ios(0);
    Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
    Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);


    std::vector<Channel> sendChls(numThreads), recvChls(numThreads);
    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i] = ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i] = ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }
    KosOtExtReceiver otRecv;
    KosOtExtSender otSend;

    auto async = std::async([&]() {PRNG prng(ZeroBlock); otRecv.genBaseOts(prng, recvChls[0]); });
    otSend.genBaseOts(prng, sendChls[0]);
    async.get();

    AknBfMPsiSender send;
    AknBfMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, otSend, sendChls, prng.get<block>());
        send.sendInput(sendSet, sendChls);
    });

    recv.init(setSize, psiSecParam, otRecv, recvChls, ZeroBlock);
    recv.sendInput(recvSet, recvChls);
    thrd.join();




    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i].close();// = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i].close();// = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    ep0.stop();
    ep1.stop();
    ios.stop();


    if (recv.mIntersection.size() != setSize)
        throw UnitTestFail("Bad intersection size.");

#else
throw UnitTestSkipped("Not enabled");
#endif
}

void AknBfPsi_SingltonSet_Test_Impl()
{
#ifdef ENABLE_RR16_PSI
    //Timer& t = gTimer;

    setThreadName("Sender");
    u64 setSize = 1, psiSecParam = 40;

    PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));

    std::vector<block> sendSet(setSize), recvSet(setSize);
    for (u64 i = 0; i < setSize; ++i)
    {
        sendSet[i] = prng.get<block>();
        recvSet[i] = prng.get<block>();
    }

    sendSet[0] = recvSet[0];

    std::string name("psi");
    IOService ios(0);
    Endpoint ep0(ios, "localhost", 1212, EpMode::Client, name);
    Endpoint ep1(ios, "localhost", 1212, EpMode::Server, name);


    Channel recvChl = ep1.addChannel(name, name);
    Channel sendChl = ep0.addChannel(name, name);


    KosOtExtReceiver otRecv;
    KosOtExtSender otSend;

    auto async = std::async([&]() {PRNG prng(ZeroBlock); otRecv.genBaseOts(prng, recvChl); });
    otSend.genBaseOts(prng, sendChl);
    async.get();

    AknBfMPsiSender send;
    AknBfMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, otSend, sendChl, prng.get<block>());
        send.sendInput(sendSet, sendChl);
    });

    recv.init(setSize, psiSecParam, otRecv, recvChl, ZeroBlock);
    recv.sendInput(recvSet, recvChl);

    thrd.join();

    //std::cout << gTimer << std::endl;

    sendChl.close();
    recvChl.close();

    ep0.stop();
    ep1.stop();
    ios.stop();

    if (recv.mIntersection.size() != 1 ||
        recv.mIntersection[0] != 0)
        throw UnitTestFail("Bad intersection size");

#else
throw UnitTestSkipped("Not enabled");
#endif
}