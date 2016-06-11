#include "util.h"

using namespace libPSI;
#include "Common/Log.h"

void senderGetLatency(Channel& chl)
{

	u8 dummy[1];

	chl.asyncSend(dummy, 1);



	chl.recv(dummy, 1);
	chl.asyncSend(dummy, 1);

}

void recverGetLatency(Channel& chl)
{

	u8 dummy[1];
	chl.recv(dummy, 1);
	Timer timer;
	auto start = timer.setTimePoint("");
	chl.asyncSend(dummy, 1);


	chl.recv(dummy, 1);
	auto end = timer.setTimePoint("");


	Log::out << "latency: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << " ms" << Log::endl;

}
