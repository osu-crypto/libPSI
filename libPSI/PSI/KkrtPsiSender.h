#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/NcoOtExt.h>
//#include "PSI/SimpleHasher.h"
//#include "OT/SSOTReceiver.h"
//#include "OT/SSOTSender.h"


namespace osuCrypto
{


	class BopPsiSender
	{
	public:
		BopPsiSender();
		~BopPsiSender();

		u64 mSenderSize, mRecverSize, mStatSecParam;
		
		//std::vector<SSOtPsiSender> mPsis;

		std::vector<blockBop> mPsiRecvSSOtMessages;



		SimpleHasher mBins;
		BitVector mSSOtChoice;

		block mHashingSeed;

		u64 mNumStash;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, const std::vector<Channel*>& chls, SSOtExtSender& otSender, block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, SSOtExtSender& otSender, block seed);

		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);


	};

}