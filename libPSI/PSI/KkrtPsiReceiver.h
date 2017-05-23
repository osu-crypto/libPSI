#pragma once

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libPSI/Tools/CuckooHasher.h"
#include "cryptoTools/Common/CuckooIndex.h"

namespace osuCrypto
{

	class KkrtPsiReceiver
	{
	public:
		KkrtPsiReceiver();
		~KkrtPsiReceiver();

		u64 mRecverSize,mSenderSize,mStatSecParam;
		std::vector<u64> mIntersection;
		CuckooIndex mIndex;

		block mHashingSeed;
		

		u64 mNumStash;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel chl0, NcoOtExtReceiver& otRecv,  block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, ArrayView<Channel> chls, NcoOtExtReceiver& otRecv,  block seed);
		void sendInput(std::vector<block>& inputs, Channel& chl);
		void sendInput(std::vector<block>& inputs, const std::vector<Channel*>& chls);

	};




}
