#pragma once
/* Class for defining Dual Mode Cryptosystem based on 
 * elliptic curves from the PVW paper
 */

#include "miracl/include/ecn.h"
#include "miracl/include/big.h"

namespace libPSI {

	class PK;
	class SK;

	// Class to hold the PK
	class CRS
	{
		ECn g[2], h[2];
		int num_bits;

	public:

		// Setup routines, initalises the elliptic curve as well
		// *** WARNING *** this is potentially insecure as the same CRS is used every time
		CRS(miracl* mip);

		ECn get_g(int i) const { return g[i]; }
		ECn get_h(int i) const { return h[i]; }
		int bit_size()   const { return num_bits; }

		friend void KeyGen(SK& sk, PK& pk, int sigma, const CRS& crs, csprng& RNG);
		friend class SK;
		friend class PK;
	};


	class SK
	{
	public:

		Big sk;

		void Decrypt(ECn& m, const ECn& c0, const ECn& c1);

		friend void KeyGen(SK& sk, PK& pk, int sigma, const CRS& crs, csprng& RNG);
	};



	class PK
	{
	public:

		ECn g, h;

		void Encrypt(ECn& c0, ECn& c1, const ECn& m, int branch, const CRS& crs, csprng& RNG);

		friend void KeyGen(SK& sk, PK& pk, int sigma, const CRS& crs, csprng& RNG);
	};



	void KeyGen(SK& sk, PK& pk, int sigma, const CRS& crs, csprng& RNG);


}
