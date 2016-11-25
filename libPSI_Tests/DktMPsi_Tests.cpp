#include "DktMPsi_Tests.h"

#include "Network/BtEndpoint.h"
#include "Common.h"
#include "Common/Defines.h"
#include "MPSI/DKT/DktMPsiReceiver.h"
#include "MPSI/DKT/DktMPsiSender.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
#include "Common/Log.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>

using namespace osuCrypto;



void DktMPsi_EmptrySet_Test_Impl()
{
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



    DktMPsiSender send;
    DktMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, prng.get<block>());
        send.sendInput(sendSet, sendChl);
    });

    recv.init(setSize, psiSecParam, ZeroBlock);
    recv.sendInput(recvSet, recvChl);

    thrd.join();

    sendChl[0]->close();
    recvChl[0]->close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}

void DktMPsi_FullSet_Test_Impl()
{
    setThreadName("CP_Test_Thread");
    u64 setSize = 40, psiSecParam = 40, numThreads(2);
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



    DktMPsiSender send;
    DktMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, prng.get<block>());
        send.sendInput(sendSet, sendChls);
    });

    recv.init(setSize, psiSecParam, ZeroBlock);
    recv.sendInput(recvSet, recvChls);

    if (recv.mIntersection.size() != setSize)
        throw UnitTestFail();

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

void DktMPsi_SingltonSet_Test_Impl()
{
    setThreadName("Sender");
    u64 setSize = 40, psiSecParam = 40;

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


    std::vector<Channel*> recvChl = {&ep1.addChannel(name, name)};
    std::vector<Channel*> sendChl = {&ep0.addChannel(name, name)};



    DktMPsiSender send;
    DktMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, prng.get<block>());
        send.sendInput(sendSet, sendChl);
    });

    recv.init(setSize, psiSecParam, ZeroBlock);
    recv.sendInput(recvSet, recvChl);

    thrd.join();

    for (u64 i = 0; i < sendChl.size(); ++i)
    {
        sendChl[0]->close();
        recvChl[0]->close();
    }

    ep0.stop();
    ep1.stop();
    ios.stop();

    if (recv.mIntersection.size() != 1 ||
        recv.mIntersection[0] != 0)
    {

        throw UnitTestFail();
    }

}