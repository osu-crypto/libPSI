#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/NcoOtExt.h>
#include "libPSI/Tools/SimpleHasher.h"
//#include "OT/SSOTReceiver.h"
//#include "OT/SSOTSender.h"


namespace osuCrypto
{


	class KkrtPsiSender
	{
	public:
		KkrtPsiSender();
		~KkrtPsiSender();

		u64 mSenderSize, mRecverSize, mStatSecParam;
		
		//std::vector<SSOtPsiSender> mPsis;

		//std::vector<blockBop> mPsiRecvSSOtMessages;



		SimpleHasher mBins;
		BitVector mSSOtChoice;

		block mHashingSeed;

		u64 mNumStash;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, ArrayView<Channel> chls, NcoOtExtSender& otSender, block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, NcoOtExtSender& otSender, block seed);

		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);


	};

}