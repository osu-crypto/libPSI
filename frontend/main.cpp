#include <iostream>

using namespace std;
#include "UnitTests.h" 
#include "Common/Defines.h"
using namespace libPSI;

#include "bloomFilterMain.h"
#include "dcwMain.h"


#include "OT/KosOtExtReceiver.h"
//#include "OT/KosOtExtReceiver2.h"
#include "OT/KosOtExtSender.h"
//#include "OT/KosOtExtSender2.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"
#include "Common/Log.h"
//
//void KosTest()
//{
//
//
//
//	BtIOService ios(0);
//	BtEndpoint ep0(ios, "127.0.0.1", 1212, true, "ep");
//	BtEndpoint ep1(ios, "127.0.0.1", 1212, false, "ep");
//	Channel& senderChannel = ep1.addChannel("chl", "chl");
//	Channel& recvChannel = ep0.addChannel("chl", "chl");
//
//	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
//	PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));
//
//	u64 numOTs =  1024 * 1024 * 16;
//
//	std::vector<block> recvMsg(numOTs), baseRecv(128);
//	std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
//	BitVector choices(numOTs), baseChoice(128);
//	choices.randomize(prng0);
//	baseChoice.randomize(prng0);
//
//
//	for (u64 i = 0; i < 128; ++i)
//	{
//		baseSend[i][0] = prng0.get_block();
//		baseSend[i][1] = prng0.get_block();
//		baseRecv[i] = baseSend[i][baseChoice[i]];
//	}
//	for (int i = 0; i < 3;++i)
//	{
//		KosOtExtSender2 sender;
//		KosOtExtReceiver2 recv;
//
//		std::thread thrd = std::thread([&]() {
//			Log::setThreadName("receiver");
//			recv.setBaseOts(baseSend);
//			recv.Extend(choices, recvMsg, prng0, recvChannel);
//		});
//
//
//		sender.setBaseOts(baseRecv, baseChoice);
//
//		Timer tt;
//		tt.setTimePoint("start2");
//		sender.Extend(sendMsg, prng1, senderChannel);
//		thrd.join();
//		tt.setTimePoint("end2");
//
//
//		Log::out << tt;
//
//	}
//	
//	
//	for (int i = 0; i < 3; ++i)
//	{
//		KosOtExtSender sender;
//		KosOtExtReceiver recv;
//
//		std::thread thrd = std::thread([&]() {
//			Log::setThreadName("receiver");
//			recv.setBaseOts(baseSend);
//			recv.Extend(choices, recvMsg, prng0, recvChannel);
//		});
//
//
//		sender.setBaseOts(baseRecv, baseChoice);
//
//		Timer tt;
//		tt.setTimePoint("start");
//		sender.Extend(sendMsg, prng1, senderChannel);
//		thrd.join();
//		tt.setTimePoint("end");
//
//
//		Log::out << tt;
//
//	}
//
//	senderChannel.close();
//	recvChannel.close();
//
//
//	ep1.stop();
//	ep0.stop();
//
//	ios.stop();
//
//
//}


int main(int argc, char** argv)
{
	//kpPSI();
	//return 0 ;

	//sim();
	//return 0;
	if (argc == 2)
	{
		bfSend();
		//DcwSend();
		//DcwRSend();
		//otBinSend();
	}
	else if (argc == 3)
	{
		bfRecv();
		//DcwRecv();
		//DcwRRecv();
		//otBinRecv();
	}
	else
	{

		//blogb();
		//otBin();

		//params();
		//bf(3);
		//KosTest();
		run_all();
	}

	return 0;
}