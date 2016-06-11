
#include "DMC.h"
#include <thread>

#ifndef MR_NOFULLWIDTH

#else
Miracl precision(50,MAXBASE);
#endif

namespace libPSI {
	CRS::CRS(miracl *mip)
	{
		Big a, b, p, q;

		mip->IOBASE = 16;
		/* The standard curve ecc-p256 */
		num_bits = 256;
		a = -3;
		b = (char*)"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
		p = (char*)"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
		q = (char*)"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";
		ecurve(a, b, p, MR_BEST);
		mip->IOBASE = 10;

		/* Find the CRS by ust searching for the smallest four
		 * points with smallest x-coord. Need to make this deterministic
		 * even if sqrt is probabilistic
		 */
		Big x = 1, y, y2;
		int count = 0;
		while (count < 4)
		{
			y2 = x*x*x + a*x + b;
			if (jacobi(y2, p) == 1)
			{
				y = sqrt(y2, p);
				if (y > p / 2) { y = p - y; }
				if (count == 0)
				{
					g[0] = ECn(x, y);
				}
				else if (count == 1)
				{
					h[0] = ECn(x, y);
				}
				else if (count == 2)
				{
					g[1] = ECn(x, y);
				}
				else
				{
					h[1] = ECn(x, y);
				}
				count++;
			}
			x = x + 1;
		}
	}



	void KeyGen(SK& sk, PK& pk, int sigma, const CRS& crs, csprng& RNG)
	{
		sk.sk = strong_rand(&RNG, crs.num_bits, 2);
		pk.g = sk.sk*crs.g[sigma];
		pk.h = sk.sk*crs.h[sigma];
	}



	void Randomize(ECn& u, ECn& v,
		const ECn& g, const ECn& h,
		const ECn& gd, const ECn& hd,
		int bitsize, csprng& RNG)
	{
		Big s, t;
		s = strong_rand(&RNG, bitsize, 2);
		t = strong_rand(&RNG, bitsize, 2);
		u = mul(s, g, t, h);
		v = mul(s, gd, t, hd);
	}



	void PK::Encrypt(ECn& c0, ECn& c1, const ECn& m, int branch, const CRS& crs, csprng& RNG)
	{
		Randomize(c0, c1, crs.g[branch], crs.h[branch], g, h, 256, RNG);
		c1 += m;
	}


	void SK::Decrypt(ECn& m, const ECn& c0, const ECn& c1)
	{
		m = c1;
		m -= sk*c0;
	}

}