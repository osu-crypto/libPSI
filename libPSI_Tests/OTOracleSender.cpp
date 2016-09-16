#include <unordered_map>
#include "Common/Defines.h"
#include "OTOracleSender.h"
#include "Common/Log.h"
#include <mutex>
#include "Network/Channel.h"


using namespace libPSI;

OTOracleSender::OTOracleSender(const block& seed)
	:mPrng(seed)
{
}

OTOracleSender::~OTOracleSender()
{
}




void OTOracleSender::send(
	ArrayView<std::array<block,2>> messages,
	PRNG& prng,
	Channel& chl)
{
	block test = mPrng.get_block();
	chl.asyncSendCopy((u8*)&test, sizeof(block));

	u64 doneIdx = 0;

	for (doneIdx = 0; doneIdx < messages.size(); ++doneIdx)
	{
		messages[doneIdx][0] = mPrng.get_block();
		messages[doneIdx][1] = mPrng.get_block(); 

		//Log::out << " idx  " << doneIdx << "   " << messages[doneIdx][0] << "   " << messages[doneIdx][1] << Log::endl;

	}
}

