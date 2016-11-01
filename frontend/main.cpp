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
#include "OT/Tools/temp/ecc.h"

#include "OT/Tools/BchCode.h"

void codes()
{

	ECC code;

	if (code.bch_control == nullptr)
	{
		Log::out << "bad init" << Log::endl;
	}

	u8 data[10];
	u8 dest[16 * 4];



	BchCode code2;
	code2.loadBinFile(SOLUTION_DIR "/libPSI/OT/Tools/bch511.bin");

	block b;
	ArrayView<block> ss(&b, 1);
	ArrayView<block> c(4);

	Timer t; 
	t.setTimePoint("start");

	for(u64 i =0; i < 10000; ++i)
		code.Encode(data, dest);


	t.setTimePoint("lin");

	for (u64 i = 0; i < 10000; ++i)
	{
		code2.encode(ss, c);
	}
	t.setTimePoint("mine");
	Log::out << t << Log::endl;

}

int main(int argc, char** argv)
{
	codes();
	return 0;
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