#include "OT/Base/naor-pinkas.h"
#include "KkrtNcoOTReceiver.h"
#include "OT/Tools/Tools.h"
#include "Common/Log.h"
#include  <mmintrin.h>

using namespace std;

namespace osuCrypto
{
	void KkrtNcoOtReceiver::setBaseOts(
		ArrayView<std::array<block, 2>> baseRecvOts)
	{


		if (baseRecvOts.size() % 128 != 0)
			throw std::runtime_error("rt error at " LOCATION);

		mGens.resize(baseRecvOts.size());

		for (int i = 0; i < mGens.size(); i++)
		{
			mGens[i][0].SetSeed(baseRecvOts[i][0]);
			mGens[i][1].SetSeed(baseRecvOts[i][1]);
		}
		mHasBase = true;
	}


	void KkrtNcoOtReceiver::init(
		MatrixView<std::array<block, 2>> correlatedMsgs)
	{
		u64 doneIdx = 0;
		if (mHasBase == false)
			throw std::runtime_error("rt error at " LOCATION);

		auto numOTExt = ((correlatedMsgs.size()[0] + 127) / 128) * 128;

		// we are going to process SSOTs in blocks of 128 messages.
		u64 numBlocks = numOTExt / 128;

		// PRC length is around 4k
		std::array<block, 128> t0;
		std::array<block, 128> t1;

		u64 numCols = mGens.size();

		// NOTE: We do not transpose a bit-matrix of size numCol * numCol.
		//   Instead we break it down into smaller chunks. For each of the
		//   numCol columns that we have, we generate 128 bits/rows of data.
		//   This results in a matrix with 128 rows and numCol columns. 
		//   Transposing each 128 * 128 sub-matrix will then give us the
		//   next 128 rows, i.e. the transpose of the original.
		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
		{
			// compute at what row does the user want use to stop.
			// the code will still compute the transpose for these
			// extra rows, but it is thrown away.
			u32 stopIdx
				= doneIdx
				+ std::min(u64(128), correlatedMsgs.size()[0] - doneIdx);

			for (u64 i = 0; i < numCols / 128; ++i)
			{

				for (u64 tIdx = 0, colIdx = i * 128; tIdx < 128; ++tIdx, ++colIdx)
				{
					// use the base key from the base OTs to 
					// extend the i'th column of t0 and t1	
					t0[tIdx] = mGens[colIdx][0].get<block>();
					t1[tIdx] = mGens[colIdx][1].get<block>();
				}


				// transpose t0 in place
				sse_transpose128(t0);
				sse_transpose128(t1);

				for (u64 rowIdx = doneIdx, tIdx = 0; rowIdx < stopIdx; ++rowIdx, ++tIdx)
				{
					correlatedMsgs[rowIdx][i][0] = t0[tIdx];
					correlatedMsgs[rowIdx][i][1] = t1[tIdx];
				}

			}

			doneIdx = stopIdx;
		}
	}
	std::unique_ptr<NcoOtExtReceiver> KkrtNcoOtReceiver::split()
	{
		auto* raw = new KkrtNcoOtReceiver();

		std::vector<std::array<block,2>> base(mGens.size());

		for (u64 i = 0; i < base.size(); ++i)
		{
			base[i][0] = mGens[i][0].get<block>();
			base[i][1] = mGens[i][1].get<block>();
		}
		raw->setBaseOts(base);

		return std::unique_ptr<NcoOtExtReceiver>(raw);
	}

	void KkrtNcoOtReceiver::encode(
		// the output of the init function. The two correlated OT messages that
		// the receiver gets from the base OTs
		const ArrayView<std::array<block, 2>> correlatedMgs,
		// The random code word that should be encoded
		const ArrayView<block> codeword,
		// Output: the message that should be sent to the sender
		ArrayView<block> otCorrectionMessage,
		// Output: the encoding of the codeword
		block & val)
	{
#ifndef NDEBUG
		u64 expectedSize = mGens.size() / (sizeof(block) * 8);

		if (otCorrectionMessage.size() != expectedSize ||
			correlatedMgs.size() != expectedSize ||
			codeword.size() != expectedSize)
			throw std::invalid_argument("");
#endif // !NDEBUG

		SHA1  sha1;
		u8 hashBuff[SHA1::HashSize];

		for (u64 i = 0; i < correlatedMgs.size(); ++i)
		{
			otCorrectionMessage[i]
				= codeword[i]
				^ correlatedMgs[i][0]
				^ correlatedMgs[i][1];
			
			sha1.Update((u8*)&correlatedMgs[i][0], sizeof(block));
		}


		sha1.Final(hashBuff);
		val = toBlock(hashBuff);
	}
}
