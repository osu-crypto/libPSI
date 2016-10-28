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
//#include "OT/TwoChooseOne/KosOtExtReceiver2.h"
#include "OT/TwoChooseOne/KosOtExtSender.h"
//#include "OT/TwoChooseOne/KosOtExtSender2.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"
#include <numeric>
#include "Common/Log.h"
int miraclTestMain();

int main(int argc, char** argv)
{

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
        otBinSend();
        //bfSend();
    }
    else if (argc == 3)
    {
        //DktRecv();
        //DcwRecv();
        //DcwRRecv();
        otBinRecv();
        //bfRecv();
    }
    else
    {
        auto thrd = std::thread([]() {

            //DktRecv();
            otBinRecv();
            //bfRecv();
        });

        //DktSend();
        otBinSend();
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