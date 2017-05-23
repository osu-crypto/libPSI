#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>

namespace osuCrypto
{
	class BgiPirClient
	{
	public:
		u64 mDatasetSize;
		u64 mDepth;

		void init(u64 dataSetSize);
		block query(u64 idx, Channel srv0, Channel Srv1, block seed);

		static void keyGen(u64 idx, u64 depth, block seed, std::vector<block>& k0 , std::vector<block>& k1);
	};

}