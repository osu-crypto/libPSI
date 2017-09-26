#include "binningExp.h"

#include "cryptoTools/Common/Defines.h"
#include "libPSI/Tools/SimpleIndex.h"
using namespace oc;

void binningExp()
{
	auto N = 1ull << 24;
	auto h = 3;
	//auto scaler = 16;

	for (double scaler = 0.125; scaler < 32; scaler *= 2)

	{

		for (u64 pow : {20})
		{
			auto numBalls = (1ull << pow) * h;
			u64 numBins = numBalls / log2(numBalls) * scaler;

			auto bLen = N / numBins;
			auto qSize = log2ceil(bLen);

			std::vector<u64> secs{ 10,40 };
			std::vector<u64> numQueries(secs.size());

			numQueries[0] = SimpleIndex::get_bin_size(numBins, numBalls, secs[0]);

			auto curNumBins = numBins;
			auto curBinLen = bLen;
			u64 comp = numQueries[0] * curBinLen * curNumBins;
			u64 comm = numQueries[0] * qSize * curNumBins;

			auto dd = SimpleIndex::get_bin_size(numBins, numBalls, secs.back());
			u64 comp0 = dd * curBinLen * curNumBins;
			u64 comm0 = dd * qSize * curNumBins;

			for (i64 i = 1; i < secs.size(); ++i)
			{
				curBinLen *= 2;
				curNumBins /= 2;
				qSize += 1;

				//auto n1 = numQueries[i];
				auto n2 = SimpleIndex::get_bin_size(curNumBins, numBalls, secs[i - 1]);
				auto n3 = SimpleIndex::get_bin_size(curNumBins, numBalls, secs[i]);

				numQueries[i] = n3 - n2;

				comp += numQueries[i] * curBinLen * curNumBins;
				comm += numQueries[i] * qSize * curNumBins;
			}

			comp /= 1000000;
			comm /= 1000;

			comp0 /= 1000000;
			comm0 /= 1000;

			std::cout << "p=" << pow << " scale="<<scaler<< std::endl
				<< "     comp=" << comp << "  comm=" << comm << std::endl
				<< "     comp=" << comp0 << "  comm=" << comm0 << std::endl;

			for (i64 i = 0; i < secs.size(); ++i)
				std::cout << "  " << numQueries[i];
			std::cout << std::endl << "   " << dd << std::endl;
		}

	}
}
