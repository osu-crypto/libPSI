#include "dcwMain.h"


#include "MPSI/DKT/DktMPsiReceiver.h"
#include "MPSI/DKT/DktMPsiSender.h"



#include "Common/Defines.h"
#include "Network/BtEndpoint.h" 
#include "Common/Log.h"
#include "Common/Timer.h"
#include "Crypto/PRNG.h"
#include <fstream>

using namespace libPSI;
std::vector<u32> numThreadss{/*1, 4,16,*/ 64 };
u64 numTrial(1);
std::vector<u32> pows{ 8,12,16,20 };

void DktSend()
{

		Log::out << "role  = sender Dkt" << Log::endl;

	Log::setThreadName("CP_Test_Thread");

	std::fstream online, offline;
	online.open("./online.txt", online.trunc | online.out);
	offline.open("./offline.txt", offline.trunc | offline.out);



	std::string name("psi");

	for (auto numThreads : numThreadss)
	{

		BtIOService ios(0);
		BtEndpoint sendEP(ios, "localhost", 1212, true, name);
		std::vector<Channel*> sendChls(numThreads);

		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i] = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		}

		u8 dummy[1];


		for (auto pow : pows)
		{

			u64 offlineTimeTot(0);
			u64 onlineTimeTot(0);
			//for (u64 numThreads = 1; numThreads < 129; numThreads *= 2)
			for (u64 jj = 0; jj < numTrial; jj++)
			{

				//u64 repeatCount = 1;
				u64 setSize = (1 << pow), psiSecParam = 40;
				PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


				std::vector<block> sendSet;
				sendSet.resize(setSize);

				for (u64 i = 0; i < setSize; ++i)
				{
					sendSet[i] = prng.get_block();
				}





				DktMPsiSender sendPSIs;

				gTimer.reset();
				Timer timer;

				//auto start = timer.setTimePoint("sender.Start");
				sendPSIs.init(setSize, psiSecParam, prng.get_block());
				//auto mid = timer.setTimePoint("sender.InitDOne");
				sendChls[0]->asyncSend(dummy, 1);

				sendPSIs.sendInput(sendSet, sendChls);
				//auto end = timer.setTimePoint("sender.Done");

				u64 dataSent = 0;
				for (u64 g = 0; g < sendChls.size(); ++g)
				{
					dataSent += sendChls[g]->getTotalDataSent();
				}

				//std::accumulate(sendChls[0]->getTotalDataSent())

				Log::out << setSize << "    " << dataSent / std::pow(2,20) << " byte  " << Log::endl;
				for (u64 g = 0; g < sendChls.size(); ++g)
					sendChls[g]->resetStats();


				//auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
				//auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

				//Log::out << setSize << "  " << offlineTime << "  " << Log::endl;


			}

		}


		for (u64 i = 0; i < numThreads; ++i)
		{
			sendChls[i]->close();// = &sendEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		}
		sendEP.stop();
		ios.stop();
	}
	//sendChl.close();
	//recvChl.close();


}

void DktRecv()
{
	u8 dummy[1];

	Log::setThreadName("CP_Test_Thread");

	std::fstream online, offline;
	online.open("./online.txt", online.trunc | online.out);
	offline.open("./offline.txt", offline.trunc | offline.out);

	std::string name("psi");


	for (auto numThreads : numThreadss)
	{
		BtIOService ios(0);
		BtEndpoint recvEP(ios, "localhost", 1212, false, name);
		std::vector<Channel*> recvChls;
		recvChls.resize(numThreads);
		for (u64 i = 0; i < numThreads; ++i)
		{
			recvChls[i] = &recvEP.addChannel("chl" + std::to_string(i), "chl" + std::to_string(i));
		}

		Log::out << "role  = recv(" << numThreads << ") Dkt" << Log::endl;

		for (auto pow : pows)
		{

			u64 offlineTimeTot(0);
			u64 onlineTimeTot(0);
			//for (u64 numThreads = 1; numThreads < 129; numThreads *= 2)
			for (u64 jj = 0; jj < numTrial; jj++)
			{

				//u64 repeatCount = 1;
				u64 setSize = (1 << pow), psiSecParam = 40;
				PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


				std::vector<block> sendSet(setSize), recvSet(setSize);




				for (u64 i = 0; i < setSize; ++i)
				{
					sendSet[i] = recvSet[i] = prng.get_block();
				}



				DktMPsiReceiver recvPSIs;



				gTimer.reset();

				u64 otIdx = 0;


				Timer timer;
				auto start = timer.setTimePoint("start");
				recvPSIs.init(setSize, psiSecParam, ZeroBlock);

				recvChls[0]->recv(dummy, 1);
				auto mid = timer.setTimePoint("init");



				recvPSIs.sendInput(recvSet, recvChls);
				auto end = timer.setTimePoint("done");

				auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
				auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();


				offlineTimeTot += offlineTime;
				onlineTimeTot += onlineTime;
				Log::out << setSize << "  " << offlineTime << "  " << onlineTime << Log::endl;



				u64 dataSent = 0;
				for (u64 g = 0; g < recvChls.size(); ++g)
				{
					dataSent += recvChls[g]->getTotalDataSent();
					

					//Log::out << "chl[" << g << "] " << recvChls[g]->getTotalDataSent() << "   " << sss[g] << Log::endl;
				}

				double time = offlineTime + onlineTime;
				time /= 1000;
				auto Mbps = dataSent * 8 / time / (1 << 20);

				Log::out << setSize << "  " << offlineTime << "  " << onlineTime << "        " << Mbps << " Mbps      " << (dataSent / std::pow(2.0, 20)) << " MB" << Log::endl;

				for (u64 g = 0; g < recvChls.size(); ++g)
					recvChls[g]->resetStats();

			}

			online << onlineTimeTot / numTrial << "-";
			offline << offlineTimeTot / numTrial << "-";
		}

		for (u64 i = 0; i < numThreads; ++i)
		{
			recvChls[i]->close();
		}
		recvEP.stop();	
		ios.stop();
	}

}



