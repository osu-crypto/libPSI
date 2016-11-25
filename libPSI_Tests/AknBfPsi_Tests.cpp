#include "AknBfPsi_Tests.h"

#include "Network/BtEndpoint.h"
#include "Common.h"
#include "Common/Defines.h"
#include "MPSI/Rr16/AknBfMPsiReceiver.h"
#include "MPSI/Rr16/AknBfMPsiSender.h"
#include "OTOracleReceiver.h"
#include "OTOracleSender.h"
#include "Common/Log.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>

using namespace osuCrypto;



void AknBfPsi_EmptrySet_Test_Impl()
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



    AknBfMPsiSender send;
    AknBfMPsiReceiver recv;
    std::thread thrd([&]() {

        send.init(setSize, psiSecParam, otSend, sendChl, prng.get<block>());
        send.sendInput(sendSet, *sendChl[0]);
    });

    recv.init(setSize, psiSecParam, otRecv, *recvChl[0], ZeroBlock);
    recv.sendInput(recvSet, *recvChl[0]);

    thrd.join();

    sendChl[0]->close();
    recvChl[0]->close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}


void AknBfPsi_FullSet_Test_Impl()
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
        sendChls[i]->close();// = &ep1.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
        recvChls[i]->close();// = &ep0.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
    }

    ep0.stop();
    ep1.stop();
    ios.stop();


    if (recv.mIntersection.size() != setSize)
        throw UnitTestFail("Bad intersection size.");

}

void AknBfPsi_SingltonSet_Test_Impl()
{
    Timer& t = gTimer;

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
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, true, name);
    BtEndpoint ep1(ios, "localhost", 1212, false, name);


    Channel& recvChl = ep1.addChannel(name, name);
    Channel& sendChl = ep0.addChannel(name, name);


    OTOracleReceiver otRecv(ZeroBlock);
    OTOracleSender otSend(ZeroBlock);



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

}