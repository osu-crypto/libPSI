#include "OT/Base/PvwBaseOT.h"
#include "LzKosOtExtReceiver.h"
#include "OT/Base/Tools.h"
#include "Common/Log.h"

using namespace std;

namespace libPSI
{
	void LzKosOtExtReceiver::setBaseOts(ArrayView<std::array<block, 2>> baseOTs)
	{
		if (baseOTs.size() != BASE_OT_COUNT)
			throw std::runtime_error(LOCATION);

		for (int i = 0; i < BASE_OT_COUNT; i++)
		{
			mGens[i][0].SetSeed(baseOTs[i][0]);
			mGens[i][1].SetSeed(baseOTs[i][1]);
		}


		mHasBase = true;
	}
	std::unique_ptr<OtExtReceiver> LzKosOtExtReceiver::split()
	{
		std::array<std::array<block, 2>, BASE_OT_COUNT>baseRecvOts;

		for (u64 i = 0; i < mGens.size(); ++i)
		{
			baseRecvOts[i][0] = mGens[i][0].get_block();
			baseRecvOts[i][1] = mGens[i][1].get_block();
		}

		std::unique_ptr<OtExtReceiver> ret(new LzKosOtExtReceiver());

		ret->setBaseOts(baseRecvOts);

		return std::move(ret);
	}


	void LzKosOtExtReceiver::Extend(
		const BitVector& choices,
		ArrayView<block> messages,
		PRNG& prng,
		Channel& chl/*,
		std::atomic<u64>& doneIdx*/)
	{
		if (choices.size() == 0) return;

		if (mHasBase == false || choices.size() != messages.size())
			throw std::runtime_error(LOCATION);

		// round up
		auto numOTExt = ((choices.size() + 127) / 128) * 128;

				// we are going to process OTs in blocks of 128 messages.
		u64 numBlocks = numOTExt / BASE_OT_COUNT + 1;

		// column vector form of t0, the receivers primary masking matrix
		// We only ever have 128 of them in memory at a time. Since we only
		// use it once and dont need to keep it around.
		std::array<block, BASE_OT_COUNT> t0;


		SHA1 sha;
		u8 hashBuff[SHA1::HashSize];

		// For the malicious secure OTs, we need a random PRNG that is chosen random 
		// for both parties. So that is what this is. 
		PRNG G;
		block seed;
		random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get_block());
		G.SetSeed(seed);

		// this buffer will be sent to the other party to prove we used the 
		// same value of r in all of the column vectors...
		std::unique_ptr<ByteStream> correlationData(new ByteStream(3 * sizeof(block)));
		correlationData->setp(correlationData->capacity());
		block& x = correlationData->getArrayView<block>()[0];
		block& t = correlationData->getArrayView<block>()[1];
		block& t2 = correlationData->getArrayView<block>()[2];
		x = t = t2 = ZeroBlock;
		block chij, ti, ti2;

		// turn the choice vbitVector into an array of blocks. 
		BitVector choices2(numBlocks * 128);
		choices2 = choices;
		choices2.resize(numBlocks * 128);
		auto choiceBlocks = choices2.getArrayView<block>();

#ifdef OTEXT_DEBUG
		ByteStream debugBuff;
		chl.recv(debugBuff);
		block debugDelta; debugBuff.consume(debugDelta);

		Log::out << "delta" << Log::endl << debugDelta << Log::endl;
#endif 

		u64 dIdx(0), doneIdx(0);
		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
		{
			// this will store the next 128 rows of the matrix u
			std::unique_ptr<ByteStream> uBuff(new ByteStream(BASE_OT_COUNT * sizeof(block)));
			uBuff->setp(BASE_OT_COUNT * sizeof(block));

			// get an array of blocks that we will fill. 
			auto u = uBuff->getArrayView<block>();

			for (u64 colIdx = 0; colIdx < BASE_OT_COUNT; colIdx++)
			{
				// use the base key material from the base OTs to 
				// extend the i'th column of t0 and t1	
				t0[colIdx] = mGens[colIdx][0].get_block();

				// This is t1[colIdx]
				block t1i = mGens[colIdx][1].get_block();

				// compute the next column of u (within this block) as this ha
				u[colIdx] = t1i ^ (t0[colIdx] ^ choiceBlocks[blkIdx]);

				//Log::out << "Receiver sent u[" << colIdx << "]=" << u[colIdx] <<" = " << t1i <<" + " << t0[colIdx] << " + " << choiceBlocks[blkIdx] << Log::endl;
			}

			// send over u buffer
			chl.asyncSend(std::move(uBuff));

			// transpose t0 in place
			eklundh_transpose128(t0);

#ifdef OTEXT_DEBUG 
			chl.recv(debugBuff); assert(debugBuff.size() == sizeof(t0));
			block* q = (block*)debugBuff.data();
#endif
			// now finalize and compute the correlation value for this block that we just processes
			u32 blkRowIdx;
			u32 stopIdx = (u32) std::min(u64(BASE_OT_COUNT), messages.size() - doneIdx);
			for (blkRowIdx = 0; blkRowIdx < stopIdx; ++blkRowIdx, ++dIdx)
			{
#ifdef OTEXT_DEBUG
				u8 choice = mChoiceBits[dIdx];
				block expected = choice ? (q[blkRowIdx] ^ debugDelta) : q[blkRowIdx];
				Log::out << (int)choice << " " << expected << Log::endl;

				if (t0[blkRowIdx] != expected)
				{
					Log::out << "- " << t0[blkRowIdx] << Log::endl;
					throw std::runtime_error(LOCATION);
				}
#endif

				// hash it
				//sha.Reset();
				//sha.Update((u8*)&t0[blkRowIdx], sizeof(block));
				//sha.Final(hashBuff);
				//messages[dIdx] = t0[blkRowIdx];// *(block*)hashBuff;

				// and check for correlation
				chij = G.get_block();
				if (choices2[dIdx])
				{
					x = x ^ chij;
					sha.Reset();
					sha.Update((u8*)&t0[blkRowIdx], sizeof(block));
					sha.Final(hashBuff);
					messages[dIdx] =  *(block*)hashBuff;

				}
				else
				{
					messages[dIdx] = t0[blkRowIdx];// *(block*)hashBuff;
				}
				// multiply over polynomial ring to avoid reduction
				mul128(t0[blkRowIdx], chij, &ti, &ti2);

				t = t ^ ti;
				t2 = t2 ^ ti2;
			}
			 
			for (; blkRowIdx < BASE_OT_COUNT; ++blkRowIdx, ++dIdx)
			{
				// and check for correlation
				chij = G.get_block();
				if (choices2[dIdx]) x = x ^ chij;

				// multiply over polynomial ring to avoid reduction
				mul128(t0[blkRowIdx], chij, &ti, &ti2);

				t = t ^ ti;
				t2 = t2 ^ ti2;
			}

			doneIdx = std::min((u64)dIdx, messages.size());
		}
		chl.asyncSend(std::move(correlationData));

		static_assert(BASE_OT_COUNT == 128, "expecting 128");
	}

}
