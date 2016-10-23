#include "BinOtPsi_Tests.h"

#include "Common.h"
#include "Common/Defines.h"
#include "MPSI/Beta/OtBinMPsiReceiver.h"
#include "MPSI/Beta/OtBinMPsiSender.h"
#include "Network/BtEndpoint.h"
#include "Common/Log.h"

#include "OT/NChooseOne/KkrtNcoOtReceiver.h"
#include "OT/NChooseOne/KkrtNcoOtSender.h"
//
//#include "cryptopp/aes.h"
//#include "cryptopp/modes.h"
//#include "MyAssert.h"
#include <array>

using namespace osuCrypto;



void OtBinPsi_EmptrySet_Test_Impl()
{
    u64 setSize = 8, psiSecParam = 40, bitSize= 128;
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

    KkrtNcoOtReceiver otRecv0, otRecv1;
    KkrtNcoOtSender otSend0, otSend1;


    u64 baseCount = 128 * 7;
    std::vector<std::array<block, 2>> sendBlks(baseCount);
    std::vector<block> recvBlks(baseCount);
    BitVector choices(baseCount);
    choices.randomize(prng);

    for (u64 i = 0; i < baseCount; ++i)
    {
        sendBlks[i][0] = prng.get<block>();
        sendBlks[i][1] = prng.get<block>();
        recvBlks[i] = sendBlks[i][choices[i]];
    }

    otRecv0.setBaseOts(sendBlks);
    otSend0.setBaseOts(recvBlks, choices);

    for (u64 i = 0; i < baseCount; ++i)
    {
        sendBlks[i][0] = prng.get<block>();
        sendBlks[i][1] = prng.get<block>();
        recvBlks[i] = sendBlks[i][choices[i]];
    }

    otRecv1.setBaseOts(sendBlks);
    otSend1.setBaseOts(recvBlks, choices);

    OtBinMPsiSender send;
    OtBinMPsiReceiver recv;
    std::thread thrd([&]() {


        send.init(setSize, psiSecParam,bitSize, sendChl, otSend0, otRecv0, prng.get<block>());
        send.sendInput(sendSet, sendChl);
    });

    recv.init(setSize, psiSecParam, bitSize, recvChl, otRecv1, otSend1, ZeroBlock);
    recv.sendInput(recvSet, recvChl);

    thrd.join();

    sendChl[0]->close();
    recvChl[0]->close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}


void OtBinPsi_FullSet_Test_Impl()
{
    Log::setThreadName("CP_Test_Thread");
    u64 setSize = 8, psiSecParam = 40, numThreads(1), bitSize = 128;
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


    KkrtNcoOtReceiver otRecv0, otRecv1;
    KkrtNcoOtSender otSend0, otSend1;

    OtBinMPsiSender send;
    OtBinMPsiReceiver recv;
    std::thread thrd([&]() {


        send.init(setSize, psiSecParam, bitSize, sendChls, otSend0, otRecv0, prng.get<block>());
        send.sendInput(sendSet, sendChls);
    });

    recv.init(setSize, psiSecParam, bitSize, recvChls, otRecv1, otSend1, ZeroBlock);
    recv.sendInput(recvSet, recvChls);


    if (recv.mIntersection.size() != setSize)
        throw UnitTestFail();

    thrd.join();

    for (u64 i = 0; i < numThreads; ++i)
    {
        sendChls[i]->close();
        recvChls[i]->close();
    }

    ep0.stop();
    ep1.stop();
    ios.stop();

}

void OtBinPsi_SingltonSet_Test_Impl()
{
    Log::setThreadName("Sender");
    u64 setSize = 128*128, psiSecParam = 40, bitSize= 128;

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

    KkrtNcoOtReceiver otRecv0, otRecv1;
    KkrtNcoOtSender otSend0, otSend1;

    OtBinMPsiSender send;
    OtBinMPsiReceiver recv;
    std::thread thrd([&]() {


        send.init(setSize, psiSecParam, bitSize, sendChl, otSend0, otRecv0, prng.get<block>());
        send.sendInput(sendSet, sendChl);
    });

    recv.init(setSize, psiSecParam, bitSize, recvChl, otRecv1, otSend1, ZeroBlock);
    recv.sendInput(recvSet, recvChl);

    thrd.join();

    if (recv.mIntersection.size() != 1 ||
        recv.mIntersection[0] != 0)
        throw UnitTestFail();


    //Log::out << gTimer << Log::endl;

    sendChl.close();
    recvChl.close();

    ep0.stop();
    ep1.stop();
    ios.stop();
}