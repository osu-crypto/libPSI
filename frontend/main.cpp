#include <iostream>

using namespace std;
#include "UnitTests.h" 
#include "Common/Defines.h"
using namespace libPSI;

#include "bloomFilterMain.h"
#include "dcwMain.h"
#include "dktMain.h"

#include "OT/KosOtExtReceiver.h"
//#include "OT/KosOtExtReceiver2.h"
#include "OT/KosOtExtSender.h"
//#include "OT/KosOtExtSender2.h"
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
		DktSend();
		//bfSend();
		//DcwSend();
		//DcwRSend();
		//otBinSend();
	}
	else if (argc == 3)
	{
		DktRecv();
		//bfRecv();
		//DcwRecv();
		//DcwRRecv();
		//otBinRecv();
	}
	else
	{
		auto thrd = std::thread([]() {

			DktRecv();
		});

		DktSend();
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