#pragma once

#ifdef _MSC_VER
#pragma warning(disable:4146)
#pragma warning(disable:4800)
#endif

#include <iostream> 
#include <stddef.h>


#include "Common/Defines.h"
#include "Common/Exceptions.h"
#include "mpir/mpirxx.h"
#include "mpir/mpir.h"

namespace libPSI {
	typedef mpz_class bigint;

	/**********************************
	 *       Utility Functions        *
	 **********************************/

	inline int CEIL_LOG2(int x)
	{
		int result = 0;
		x--;
		while (x > 0)
		{
			result++;
			x >>= 1;
		}
		return result;
	}

	inline int FLOOR_LOG2(int x)
	{
		int result = 0;
		while (x > 1)
		{
			result++;
			x >>= 1;
		}
		return result;
	}

	// ceil(n / k)
	inline int DIV_CEIL(int n, int k)
	{
		return (n + k - 1) / k;
	}

	inline int gcd(const int x, const int y)
	{
		bigint xx = x;
		return (int)mpz_gcd_ui(NULL, xx.get_mpz_t(), y);
	}


	inline bigint gcd(const bigint& x, const bigint& y)
	{
		bigint g;
		mpz_gcd(g.get_mpz_t(), x.get_mpz_t(), y.get_mpz_t());
		return g;
	}


	inline void invMod(bigint& ans, const bigint& x, const bigint& p)
	{
		mpz_invert(ans.get_mpz_t(), x.get_mpz_t(), p.get_mpz_t());
	}

	inline int numBits(const bigint& m)
	{
		return (int)mpz_sizeinbase(m.get_mpz_t(), 2);
	}



	inline int numBits(int m)
	{
		bigint te = m;
		return (int)mpz_sizeinbase(te.get_mpz_t(), 2);
	}



	inline int numBytes(const bigint& m)
	{
		return (int)mpz_sizeinbase(m.get_mpz_t(), 256);
	}





	inline int probPrime(const bigint& x)
	{
		gmp_randstate_t rand_state;
		gmp_randinit_default(rand_state);
		int ans = mpz_probable_prime_p(x.get_mpz_t(), rand_state, 40, 0);
		gmp_randclear(rand_state);
		return ans;
	}


	inline void bigintFromBytes(bigint& x, u8* mData, int len)
	{
		mpz_import(x.get_mpz_t(), len, 1, sizeof(u8), 0, 0, mData);
	}


	inline void bytesFromBigint(u8* mData, const bigint& x, unsigned int len)
	{
		size_t ll;
		mpz_export(mData, &ll, 1, sizeof(u8), 0, 0, x.get_mpz_t());
		if (ll > len)
		{
			throw invalid_length();
		}
		for (unsigned int i = (unsigned int)ll; i < len; i++)
		{
			mData[i] = 0;
		}
	}


	inline int isOdd(const bigint& x)
	{
		return mpz_odd_p(x.get_mpz_t());
	}


	bigint sqrRootMod(const bigint& x, const bigint& p);

	bigint powerMod(const bigint& x, const bigint& e, const bigint& p);

	// Assume e>=0
	int powerMod(int x, int e, int p);


}
