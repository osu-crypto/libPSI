#pragma once

#include "Network/Channel.h"
#include "Common/BitVector.h"
#include "typedefs.h"
#include <ctime>
#include "miracl/include/big.h"

#include <iostream>
#include <cstring>
#include <fstream>
#include <time.h>
#include "Crypto/PRNG.h"
#include "Crypto/sha1.h"
#include "crypto/crypto.h"
namespace libPSI
{


	Miracl* GetPrecision();
	Miracl* GetPrecision(int bits, int b);
	void deletePercision();

	class BaseOT
	{
	public:
		//BaseOT() {}; 
		//BaseOT(crypto* crypt)
		//{
		//	m_cCrypto = crypt;

		//	uint8_t* pkseed = (uint8_t*)malloc(sizeof(uint8_t) * (crypt->secparam.symbits >> 3));
		//	//gen_rnd(pkseed, secparam.symbits >> 3);
		//	crypt->mPrng.get_u8s(pkseed, crypt->secparam.symbits >> 3);
		//	//if(ftype == P_FIELD) return new prime_field(secparam, pkseed);
		//	//else  

		//	m_cPKCrypto = new ecc_field(crypt->secparam, pkseed);
		//};
		//~BaseOT(){delete m_cPKCrypto; };
		virtual void Receiver(ArrayView<block> messages, BitVector& choices, Channel& chl, PRNG& prng, u64 numThreads) = 0;
		virtual void Sender(ArrayView<std::array<block, 2>> messages, Channel& sock, PRNG& prng, u64 numThreads) = 0;

		//crypto* m_cCrypto;
		//pk_crypto* m_cPKCrypto;

	};

}
