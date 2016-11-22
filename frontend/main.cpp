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
#include "cuckoo/cuckooTests.h"

int main(int argc, char** argv)
{

    simpleTest(argc, argv);
    return 0;

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
        //test(1);
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