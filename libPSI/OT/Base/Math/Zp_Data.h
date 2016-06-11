#pragma once

/* Class to define helper information for a Zp element
 *
 * Basically the data needed for Montgomery operations 
 *
 * All data is public as this is basically a container class
 *
 */

#include "OT/Base/Math/modp.h"
#include <iostream>

namespace libPSI {

	class Zp_Data
	{
		bool        montgomery;  // True if we are using Montgomery arithmetic
		mp_limb_t   R[MAX_MOD_SZ], R2[MAX_MOD_SZ], R3[MAX_MOD_SZ], pi;
		mp_limb_t   prA[MAX_MOD_SZ];
		int         t;           // More Montgomery data

		void Mont_Mult(mp_limb_t* z, const mp_limb_t* x, const mp_limb_t* y) const;

	public:

		bigint       pr;
		mp_limb_t    mask;

		void assign(const Zp_Data& Zp);
		void init(const bigint& p, bool mont = true);
		int get_t() const { return t; }

		// This one does nothing, needed so as to make vectors of Zp_Data
		Zp_Data() { t = 1; }

		// The main init funciton
		Zp_Data(const bigint& p, bool mont = true)
		{
			init(p, mont);
		}

		Zp_Data(const Zp_Data& Zp) { assign(Zp); }
		Zp_Data& operator=(const Zp_Data& Zp)
		{
			if (this != &Zp) { assign(Zp); }
			return *this;
		}
		~Zp_Data() { ; }

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

		friend class modp;

		friend std::ostream& operator<<(std::ostream& s, const Zp_Data& ZpD);
		friend std::istream& operator>>(std::istream& s, Zp_Data& ZpD);
	};
}
