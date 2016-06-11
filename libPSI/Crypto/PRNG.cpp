#include "PRNG.h"
#include <algorithm>
#include <cstring>
#include <Common/Log.h>

namespace libPSI {

#define DEFAULT_BUFF_SIZE 64
	PRNG::PRNG() : mBytesIdx(0), mBlockIdx(0),
		mBuffer(DEFAULT_BUFF_SIZE),
		mIndexArray(DEFAULT_BUFF_SIZE, ZeroBlock),
		mBufferByteCapacity(sizeof(block) * DEFAULT_BUFF_SIZE)
	{
	}


	PRNG::PRNG(const block& seed)
		: 
		mBytesIdx(0), 
		mBlockIdx(0),
		mBuffer(DEFAULT_BUFF_SIZE),
		mIndexArray(DEFAULT_BUFF_SIZE, ZeroBlock),
		mBufferByteCapacity(sizeof(block) * DEFAULT_BUFF_SIZE)
	{
		mSeed = seed;
		mAes.setKey(seed);

		refillBuffer();
	}


	//PRNG::~PRNG()
	//{
	//}


	void PRNG::SetSeed(const block& seed)
	{
		mSeed = seed;
		mAes.setKey(seed);
		mBlockIdx = 0;

		if (mBuffer.size() == 0)
		{
			mBuffer.resize(DEFAULT_BUFF_SIZE);
			mIndexArray.resize(DEFAULT_BUFF_SIZE);
			mBufferByteCapacity = (sizeof(block) * DEFAULT_BUFF_SIZE);
		}


		refillBuffer();
	}
	//const block & PRNG::get_seed() const
	//{
	//	return mSeed;
	//}
	//void PRNG::setBufferSize(u64 size)
	//{
	//	u64 rem = mBytesIdx % sizeof(block);
	//	mBlockIdx = mBlockIdx - mBuffer.size() + (mBytesIdx / 16);

	//	mBuffer.resize(0);
	//	mBuffer.resize(size);

	//	mIndexArray.resize(0);
	//	mIndexArray.resize(size, ZeroBlock);
	//	mBufferByteCapacity = size * sizeof(block);

	//	refillBuffer();

	//	mBytesIdx = rem;
	//}
	//u64 PRNG::getBufferSize()
	//{
	//	return mBuffer.size();
	//}
	//u8 PRNG::get_bit()
	//{
	//	u8 data;
	//	get_u8s((u8*)&data, 1);
	//	return data & 1;
	//}
	double PRNG::get_double()
	{
		double data;
		get_u8s((u8*)&data,sizeof(double));
		return data;
	}
	u8 PRNG::get_uchar()
	{
		u8 data;
		get_u8s((u8*)&data, 1);
		return data;
	}
	u32 PRNG::get_u32()
	{
		u32 data;
		get_u8s((u8*)&data, 4);
		return data;
	}
	//u64 PRNG::get_u64()
	//{
	//	u64 data;
	//	get_u8s((u8*)&data, 8);

	//	return data;
	//}
	block PRNG::get_block()
	{
		block data;
		get_u8s((u8*)&data, 16);
		return data;
	}
	blockRIOT PRNG::get_block512(u64 length)
	{
		blockRIOT data;
		get_u8s((u8*)&data, length);
		return data;
	}
	void PRNG::get_u8s(u8 * dest, u64 length)
	{
		//TODO("REMOVE THIS");
		//memset(dest, 0xcc, length);
		//return;

		u8* destu8 = (u8*)dest;
		while (length)
		{
			u64 step = std::min(length, mBufferByteCapacity - mBytesIdx);

			memcpy(destu8, ((u8*)mBuffer.data()) + mBytesIdx, step);

			//for (u64 i = 0; i < step; ++i)
			//	if(((u8*)mBuffer.data())[mBytesIdx + i])
			//		destu8[i] = ((u8*)mBuffer.data())[mBytesIdx + i];

			destu8 += step;
			length -= step;
			mBytesIdx += step;

			if (mBytesIdx == mBufferByteCapacity)
				refillBuffer();
		}
	}


	void PRNG::refillBuffer()
	{
		//if (mIndexArray.size() != mBuffer.size())
		//	throw std::runtime_error("rt error at " LOCATION);

		for (u64 i = 0; i < mBuffer.size(); ++i)
		{
			//reinterpret_cast<u64*>(&mIndexArray[i])[0] = mBlockIdx++;
			//reinterpret_cast<u64*>(&mIndexArray[i])[1] = 0;

			//mIndexArray[i] = _mm_set_epi64x(mBlockIdx++, 0);
			((u64*)&mIndexArray[i])[0] = mBlockIdx++;
			((u64*)&mIndexArray[i])[1] = 0;

			//Log::out << mIndexArray[i] << " ";
		}
		//Log::out << Log::endl;

		//memset(mBuffer.data(), 0xcc, mBuffer.size() * sizeof(block));
		mAes.ecbEncBlocks(mIndexArray.data(), mBuffer.size(), mBuffer.data());

		//for (u64 i = 0; i < mBuffer.size(); ++i)
		//{
		//if (eq(mBuffer[i], ZeroBlock))
		//Log::out << "eq" << Log::endl;
		//}

		//Log::out << Log::endl;
		mBytesIdx = 0;
	}
}
