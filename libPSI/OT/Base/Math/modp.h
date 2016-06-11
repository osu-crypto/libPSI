#pragma once

/* 
 * Currently we only support an MPIR based implementation.
 *
 * What ever is type-def'elem to bigint is assumed to have
 * operator overloading for all standard operators, has
 * comparison operations and istream/ostream operators >>/<<.
 *
 * All "integer" operations will be done using operator notation
 * all "modp" operations should be done using the function calls
 * below (interchange with Montgomery arithmetic).
 *
 */

#include "Common/ByteStream.h"
#include "OT/Base/Math/bigint.h"

namespace libPSI {
	class Zp_Data;

#ifdef LargeM
#define MAX_MOD_SZ 20
#else
#ifndef MAX_MOD_SZ
	// The following is 1024 bits on 64 bit machines
#define MAX_MOD_SZ 16
#endif
#endif

	class modp
	{
		static bool rewind;

		mp_limb_t x[MAX_MOD_SZ];

	public:

		// NEXT FUNCTION IS FOR DEBUG PURPOSES ONLY
		mp_limb_t get_limb(int i) { return x[i]; }

		modp()
		{
			mpn_zero(x, MAX_MOD_SZ);
		}
		modp(const modp& y)
		{
			mpn_copyi(x, y.x, MAX_MOD_SZ);
		}
		modp& operator=(const modp& y)
		{
			if (this != &y) { mpn_copyi(x, y.x, MAX_MOD_SZ); }
			return *this;
		}

		// Pack and unpack in native format
		//   i.e. Dont care about conversion to human readable form
		//   i.e. When we do montgomery we dont care about decoding
		void pack(ByteStream& o, const Zp_Data& ZpD) const;
		void unpack(ByteStream& o, const Zp_Data& ZpD);


		/**********************************
		 *         Modp Operations        *
		 **********************************/

		 // Convert representation to and from a modp number
		friend void to_bigint(bigint& ans, const modp& x, const Zp_Data& ZpD, bool reduce);

		friend void to_modp(modp& ans, int x, const Zp_Data& ZpD);
		friend void to_modp(modp& ans, const bigint& x, const Zp_Data& ZpD);

		friend void Add(modp& ans, const modp& x, const modp& y, const Zp_Data& ZpD);
		friend void Sub(modp& ans, const modp& x, const modp& y, const Zp_Data& ZpD);
		friend void Mul(modp& ans, const modp& x, const modp& y, const Zp_Data& ZpD);
		friend void Sqr(modp& ans, const modp& x, const Zp_Data& ZpD);
		friend void Negate(modp& ans, const modp& x, const Zp_Data& ZpD);
		friend void Inv(modp& ans, const modp& x, const Zp_Data& ZpD);

		friend void Power(modp& ans, const modp& x, int exp, const Zp_Data& ZpD);
		friend void Power(modp& ans, const modp& x, const bigint& exp, const Zp_Data& ZpD);

		friend void assignOne(modp& x, const Zp_Data& ZpD);
		friend void assignZero(modp& x, const Zp_Data& ZpD);
		friend bool isZero(const modp& x, const Zp_Data& ZpD);
		friend bool isOne(const modp& x, const Zp_Data& ZpD);
		friend bool areEqual(const modp& x, const modp& y, const Zp_Data& ZpD);

		// Input and output from a stream
		//  - Can do in human or machine only format (later should be faster)
		//  - If human output appends a space to help with reading
		//    and also convert back/forth from Montgomery if needed
		void output(std::ostream& s, const Zp_Data& ZpD, bool human) const;
		void input(std::istream& s, const Zp_Data& ZpD, bool human);

		friend class gfp;

	};


}
