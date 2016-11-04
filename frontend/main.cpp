#include <iostream>

using namespace std;
#include "UnitTests.h" 
#include "Common/Defines.h"
using namespace osuCrypto;

#include "bloomFilterMain.h"
#include "dcwMain.h"
#include "dktMain.h"
#include "OtBinMain.h"

#include "OT/TwoChooseOne/KosOtExtReceiver.h"
#include "OT/TwoChooseOne/KosOtExtSender.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"
#include <numeric>
#include "Common/Log.h"
int miraclTestMain();

#include "OT/Tools/BchCode.h"
#include "OT/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "OT/NChooseOne/Oos/OosNcoOtSender.h"

void test(int i)
{
    Log::setThreadName("Sender");

    PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    u64 step = 1024;
    u64 numOTs = 1 << 23;
    u64 numThreads = 16;

    u64 otsPer = numOTs / numThreads;

    std::string name = "n";
    BtIOService ios(0);
    BtEndpoint ep0(ios, "localhost", 1212, i, name);
    std::vector<Channel*> chls(numThreads);
    
    for (u64 k = 0; k < numThreads; ++k)
        chls[k] = &ep0.addChannel(name + ToString(k), name + ToString(k));


    BchCode code;
    code.loadBinFile(std::string(SOLUTION_DIR) + "/libPSI/OT/Tools/bch511.bin");




    u64 ncoinputBlkSize = 1, baseCount = 4 * 128;
    //sender.getParams(true, 128, 40, 128, numOTs, ncoinputBlkSize, baseCount);
    u64 codeSize = (baseCount + 127) / 128;

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }



    std::vector<block> choice(ncoinputBlkSize), correction(codeSize);
    prng0.get((u8*)choice.data(), ncoinputBlkSize * sizeof(block));

    std::vector< thread> thds(numThreads);


    //for (u64 k = 0; k < numThreads; ++k)
    //{
    //    sender.emplace_back(code);
    //    recv.emplace_back(code);
    //    sender.back().setBaseOts(baseRecv, baseChoice);
    //    recv.back().setBaseOts(baseSend);
    //}

    //for (u64 k = 0; k < 1; ++k)
    {


        if (i == 0)
        {
            
            for (u64 k= 0; k < numThreads; ++k)
            {
                thds[k] = std::thread(
                    [&,k]()
                {
                    OosNcoOtReceiver r(code);
                    r.setBaseOts(baseSend);
                    auto& chl = *chls[k];

                    r.init(otsPer);
                    block encoding1, encoding2;
                    for (u64 i = 0; i < otsPer; i += step)
                    {
                        for (u64 j = 0; j < step; ++j)
                        {
                            r.encode(i + j, choice, encoding1);
                        }

                        r.sendCorrection(chl, step);
                    }
                    r.check(chl);
                });
            }
            for (u64 k = 0; k < numThreads; ++k)
                thds[k].join();
        }
        else
        {
            Timer time;
            time.setTimePoint("start");
            block encoding1, encoding2;

            for (u64 k = 0; k < numThreads; ++k)
            {
                thds[k] = std::thread(
                    [&, k]()
                {
                    OosNcoOtSender s(code);// = sender[k];
                    s.setBaseOts(baseRecv, baseChoice);
                    auto& chl = *chls[k];

                    s.init(otsPer);
                    for (u64 i = 0; i < otsPer; i += step)
                    {

                        s.recvCorrection(chl, step);

                        for (u64 j = 0; j < step; ++j)
                        {
                            s.encode(i + j, choice, encoding2);
                        }
                    }
                    s.check(chl);
                });
            }


            for (u64 k = 0; k < numThreads; ++k)
                thds[k].join();

            time.setTimePoint("finish");
            Log::out << time << Log::endl;
        }


    }

    for (u64 k = 0; k < numThreads; ++k)
        chls[k]->close();

    ep0.stop();
    ios.stop();
}



int main(int argc, char** argv)
{

    //test();
    //return 0;

    //BchCode code;
    //code.loadBinFile(SOLUTION_DIR "/libPSI/OT/Tools/bch511.bin");
    //std::vector<block> in(code.plaintextBlkSize()), out(code.codewordBlkSize());

    //Timer t;
    //t.setTimePoint("");
    //for (u64 j = 0; j < 1000000; ++j)
    //{
    //    code.encode(in, out);
    //}
    //t.setTimePoint("done");
    //Log::out << t << Log::endl;

    //run_all();
    //return 0;
    //Ecc2mNumber_Test();
    //return 0;
    //miraclTestMain();
    //return 0;

    //test2();
    //return 0;
    //kpPSI();
    //return 0 ;
    //sim(); 
    //return 0;
    if (argc == 2)
    {
        //DktSend();
        //DcwSend();
        //DcwRSend();
        //test(0);
        //otBinSend();
        //bfSend();
    }
    else if (argc == 3)
    {
        //DktRecv();
        //DcwRecv();
        //DcwRRecv();
        test(1);
        //otBinRecv();
        //bfRecv();
    }
    else
    {
        auto thrd = std::thread([]() {

            //DktRecv();
            otBinRecv();
            //test(0);
            //bfRecv();
        });

        //DktSend();
        otBinSend();
        //test(1);
        //bfSend();

        thrd.join();
        //blogb();
        //otBin();

        //params();
        //bf(3);
        //KosTest();
        //run_all();
    }

    return 0;
}