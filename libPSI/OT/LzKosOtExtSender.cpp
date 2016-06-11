#include "LzKosOtExtSender.h"

#include "OT/Base/PvwBaseOT.h"
#include "OT/Base/Tools.h"
#include "Common/Log.h"

namespace libPSI
{
//#define OTEXT_DEBUG

	using namespace std;




	std::unique_ptr<OtExtSender> LzKosOtExtSender::split()
	{

		std::unique_ptr<OtExtSender> ret(new LzKosOtExtSender());
		
		std::array<block, BASE_OT_COUNT> baseRecvOts;

		for (u64 i = 0; i < mGens.size(); ++i)
		{
			baseRecvOts[i] = mGens[i].get_block();
		}

		ret->setBaseOts(baseRecvOts, mBaseChoiceBits);

		return std::move(ret);
	}

	void LzKosOtExtSender::setBaseOts(ArrayView<block> baseRecvOts, const BitVector & choices)
	{
		if (baseRecvOts.size() != BASE_OT_COUNT || choices.size() != BASE_OT_COUNT)
			throw std::runtime_error("not supported/implemented");


		mBaseChoiceBits = choices;
		for (int i = 0; i < BASE_OT_COUNT; i++)
		{
			mGens[i].SetSeed(baseRecvOts[i]);
		}
	}

	void LzKosOtExtSender::Extend(
		ArrayView<std::array<block, 2>> messages,
		PRNG& prng,
		Channel& chl/*,
		std::atomic<u64>& doneIdx*/)
	{
		if (messages.size() == 0) return;

		if (mBaseChoiceBits.size() != BASE_OT_COUNT)
			throw std::runtime_error("must set base first");

		// round up
		u64 numOTExt = ((messages.size() + 127) / 128) * 128;

		block seed;
		random_seed_commit(ByteArray(seed), chl, SEED_SIZE, prng.get_block());
		PRNG commonPrng(seed);

		block  chii, qi, qi2;
		block q2 = ZeroBlock;
		block q1 = ZeroBlock;
		block delta = *(block*)mBaseChoiceBits.data();

		SHA1 sha;
		u8 hashBuff[SHA1::HashSize];


		u64 doneIdx = 0;
		std::array<block, BASE_OT_COUNT> q;
		ByteStream buff;
#ifdef OTEXT_DEBUG
		Log::out << "sender delta " << delta << Log::endl;
		buff.append(delta);
		chl.AsyncSendCopy(buff);
#endif

		// add one for the extra 128 OTs used for the correlation check
		u64 numBlocks = numOTExt / BASE_OT_COUNT + 1;
		for (u64 blkIdx = 0; blkIdx < numBlocks; ++blkIdx)
		{

			chl.recv(buff);
			assert(buff.size() == sizeof(block) * BASE_OT_COUNT);

			// u = t0 + t1 + x 
			auto u = buff.getArrayView<block>(); 

			for (int colIdx = 0; colIdx < BASE_OT_COUNT; colIdx++)
			{
				// a column vector sent by the receiver that hold the correction mask.
				q[colIdx] = mGens[colIdx].get_block();
			
				if (mBaseChoiceBits[colIdx])
				{
					// now q[i] = t0[i] + Delta[i] * x
					q[colIdx] = q[colIdx] ^ u[colIdx];
				}
			}

			eklundh_transpose128(q);

#ifdef OTEXT_DEBUG
			buff.setp(0);
			buff.append((u8*)&q, sizeof(q));
			chl.AsyncSendCopy(buff);
#endif
			u32 blkRowIdx = 0;
			u32 stopIdx = (u32)std::min(u64(BASE_OT_COUNT), messages.size() - doneIdx);
			for (; blkRowIdx < stopIdx; ++blkRowIdx, ++doneIdx)
			{
				messages[doneIdx][0] = q[blkRowIdx];
				block msg1 = q[blkRowIdx] ^ delta;

				// hash the message without delta
				//sha.Reset();
				//sha.Update((u8*)&msg0, sizeof(block));
				//sha.Final(hashBuff);
				//messages[doneIdx][0] = *(block*)hashBuff;

				// hash the message with delta
				sha.Reset();
				sha.Update((u8*)&msg1, sizeof(block)); 
				sha.Final(hashBuff);
			    messages[doneIdx][1] = *(block*)hashBuff;


				chii = commonPrng.get_block();

				mul128(q[blkRowIdx], chii, &qi, &qi2);
				q1 = q1  ^ qi;
				q2 = q2 ^ qi2;
			}

			for (; blkRowIdx < BASE_OT_COUNT; ++blkRowIdx)
			{
				auto& msg0 = q[blkRowIdx];
				chii = commonPrng.get_block();
				mul128(msg0, chii, &qi, &qi2);
				q1 = q1  ^ qi;
				q2 = q2 ^ qi2;
			}
		}

		block t1, t2;
		std::vector<char> data(sizeof(block) * 3);

		chl.recv(data.data(), data.size());

		block& received_x = ((block*)data.data())[0];
		block& received_t = ((block*)data.data())[1];
		block& received_t2 = ((block*)data.data())[2];

		// check t = x * Delta + q 
		mul128(received_x, delta, &t1, &t2);
		t1 = t1 ^ q1;
		t2 = t2 ^ q2;

		if (eq(t1, received_t) && eq(t2, received_t2))
		{
			//Log::out << "\tCheck passed\n";
		}
		else
		{
			Log::out << "OT Ext Failed Correlation check failed" << Log::endl;
			Log::out << "rec t = " << (received_t) << Log::endl;
			Log::out << "tmp1  = " << (t1) << Log::endl;
			Log::out << "q  = " << (q1) << Log::endl;
			//throw std::runtime_error("Exit");;
		}

		static_assert(BASE_OT_COUNT == 128, "expecting 128");
	}


}
