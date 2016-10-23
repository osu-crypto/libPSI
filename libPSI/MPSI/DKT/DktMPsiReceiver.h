#pragma once
#include "Common/ArrayView.h"
#include "Common/Defines.h"
#include "Network/Channel.h"
#include "Crypto/PRNG.h"

namespace osuCrypto
{

	class DktMPsiReceiver
	{
	public:
		DktMPsiReceiver();
		~DktMPsiReceiver();


		u64 mN, mSecParam;
		PRNG mPrng;

		std::vector<u64> mIntersection;

		void init(u64 n, u64 secParam, block seed);


		void sendInput(ArrayView<block> inputs, std::vector<Channel*>& chl0);

	};

}