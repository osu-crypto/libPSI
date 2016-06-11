#pragma once
#include "Crypto/AES.h"
#include "Common/sha1.h"

namespace libPSI {

	///// an **** INSECURE **** PRF. TODO make it secure
	//class PRF
	//{
	//	AES128::Key mKey;

	//public: 


	//	void ReSeed(block& b)
	//	{
	//		AES128::EncKeyGen(b, mKey);
	//	}


	//	block operator()(u8* data, u64 length)
	//	{
	//		block ret;

	//		SHA1 sha;
	//		u8 out[SHA1::HashSize];

	//		sha.Update(data, length);
	//		sha.Final(out);

	//		AES128::EcbEncBlock(mKey, *(block*)out, ret);

	//		return ret;
	//	}


	//};

}
