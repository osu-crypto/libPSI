#include <iostream>

using namespace std;
#include "UnitTests.h" 
#include "Common/Defines.h"
using namespace libPSI;

#include "bloomFilterMain.h"
#include "dcwMain.h"
#include "dktMain.h"

#include "OT/KosOtExtReceiver.h"
//#include "OT/KosOtExtReceiver2.h"
#include "OT/KosOtExtSender.h"
//#include "OT/KosOtExtSender2.h"
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"
#include <numeric>
#include "Common/Log.h"
int miraclTestMain();
//
//void KosTest()
//{
//
//
//
//	BtIOService ios(0);
//	BtEndpoint ep0(ios, "127.0.0.1", 1212, true, "ep");
//	BtEndpoint ep1(ios, "127.0.0.1", 1212, false, "ep");
//	Channel& senderChannel = ep1.addChannel("chl", "chl");
//	Channel& recvChannel = ep0.addChannel("chl", "chl");
//
//	PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
//	PRNG prng1(_mm_set_epi32(4253233465, 334565, 0, 235));
//
//	u64 numOTs =  1024 * 1024 * 16;
//
//	std::vector<block> recvMsg(numOTs), baseRecv(128);
//	std::vector<std::array<block, 2>> sendMsg(numOTs), baseSend(128);
//	BitVector choices(numOTs), baseChoice(128);
//	choices.randomize(prng0);
//	baseChoice.randomize(prng0);
//
//
//	for (u64 i = 0; i < 128; ++i)
//	{
//		baseSend[i][0] = prng0.get_block();
//		baseSend[i][1] = prng0.get_block();
//		baseRecv[i] = baseSend[i][baseChoice[i]];
//	}
//	for (int i = 0; i < 3;++i)
//	{
//		KosOtExtSender2 sender;
//		KosOtExtReceiver2 recv;
//
//		std::thread thrd = std::thread([&]() {
//			Log::setThreadName("receiver");
//			recv.setBaseOts(baseSend);
//			recv.Extend(choices, recvMsg, prng0, recvChannel);
//		});
//
//
//		sender.setBaseOts(baseRecv, baseChoice);
//
//		Timer tt;
//		tt.setTimePoint("start2");
//		sender.Extend(sendMsg, prng1, senderChannel);
//		thrd.join();
//		tt.setTimePoint("end2");
//
//
//		Log::out << tt;
//
//	}
//	
//	
//	for (int i = 0; i < 3; ++i)
//	{
//		KosOtExtSender sender;
//		KosOtExtReceiver recv;
//
//		std::thread thrd = std::thread([&]() {
//			Log::setThreadName("receiver");
//			recv.setBaseOts(baseSend);
//			recv.Extend(choices, recvMsg, prng0, recvChannel);
//		});
//
//
//		sender.setBaseOts(baseRecv, baseChoice);
//
//		Timer tt;
//		tt.setTimePoint("start");
//		sender.Extend(sendMsg, prng1, senderChannel);
//		thrd.join();
//		tt.setTimePoint("end");
//
//
//		Log::out << tt;
//
//	}
//
//	senderChannel.close();
//	recvChannel.close();
//
//
//	ep1.stop();
//	ep0.stop();
//
//	ios.stop();
//
//
//}

u64 sqrt(u64 x, u64 p)
{
	x = x % p;
	for (u64 i = 0; i < p; ++i)
	{
		if ((i * i) % p == x)
		{
			return i;
		}
	}

	return p;
	Log::out << "failed to find sqrt for " << x << Log::endl;
	throw std::runtime_error("");
}

u64 neg(u64 x, u64 p)
{
	return (p - x) % p;
}

u64 inverse(u64 x, u64 p)
{
	x = x % p;
	if (x)
	{
		for (u64 i = 1; i < p; ++i)
		{
			if ((x * i) % p == 1)
			{
				return i;
			}
		}
		Log::out << "failed to find invers for " << x << Log::endl;
		throw std::runtime_error("");
	}
	else
	{
		Log::out << "no invers for " << x << Log::endl;
		throw std::runtime_error("");
	}
}

struct Curve;
struct Point
{
	Point(Curve& c);

	u64 x, y, p, a;
	bool isInf;

	Point operator+(Point& Q)
	{
		Point ret = *this;

		auto & P = *this;
		if (P == Q)
		{
			ret = doubl();
		}
		if (P != -Q)
		{
			auto s
				= (
				(P.y + neg(Q.y, p))
					* inverse(P.x + neg(Q.x, p), p)
					) % p;
			//Log::out << s << Log::endl;
			ret.x = (s * s + neg(P.x, p) + neg(Q.x, p)) % p;
			ret.y = (neg(P.y, p) + s * (P.x + neg(ret.x, p))) % p;
		}
		else
		{
			ret.x = -1;
			ret.y = -1;
			ret.isInf = true;
		}

		return ret;
	}

	Point operator-()
	{
		Point ret = *this;
		ret.y = neg(ret.y, p);
		return ret;
	}

	bool operator!=(Point& cmp)
	{
		return !(*this == cmp);
	}
	bool operator==(Point& cmp)
	{
		return x == cmp.x && y == cmp.y;
	}

	Point doubl()
	{
		Point ret = *this;
		if (y == 0)
		{
			ret.x = -1;
			ret.y = -1;
			ret.isInf = true;
		}
		else
		{

			//Log::out << "(" << (3 * x * x) % p << " + " << a << ") / (" << (2 * y)% p << ") mod " << p << Log::endl;
			//Log::out << "(" << (3 * x * x + a) % p << " * " << inverse(2 * y, p) << " mod " << p << Log::endl;
			auto s = ((3 * x * x + a)  * inverse(2 * y, p)) % p;

			//Log::out << s << Log::endl;
			ret.x = (s * s + neg(2 * x, p)) % p;
			ret.y = (neg(y, p) + s * (x + neg(ret.x, p))) % p;
		}

		return ret;
	}

	Point operator*(u64 i)
	{
		//i = i & p;
		Point ret = *this;
		ret.x = 0;
		ret.y = 0;

		if (x)
		{
			Point temp = *this;
			while (i)
			{
				if (i & 1)
				{
					ret = ret + temp;
				}

				i >>= 1;
				temp.doubl();
			}
		}

		return ret;
	}


};

std::ostream& operator<<(std::ostream& out, Point p)
{
	if (p.isInf)
	{
		out << "(infinity)";
	}
	else
	{
		out << "(" << p.x << ", " << p.y << ")";
	}

	return out;
}

struct Curve
{

	Curve(i64 aa, i64 bb, u64 pp)
	{
		a = aa;
		b = bb;
		p = pp;
	}
	i64 a, b;
	u64 p;



	u64 getRhs(u64 x)
	{
		u64 yy = ((x * x * x) + a * x + b) % p;

		return sqrt(yy, p);
	}

	std::vector<Point> getPoints()
	{
		std::vector<Point> ret;
		ret.reserve(p);
		for (u64 i = 0; i < p; ++i)
		{
			//Log::out << "(" << i << ", " << c.getRhs(i)<< ")" << Log::endl;
			u64 y;
			if ((y = getRhs(i)) != p)
			{
				ret.emplace_back(*this);
				ret.back().x = i;
				ret.back().y = y;

				if (y != neg(y, p))
				{

					ret.emplace_back(*this);
					ret.back().x = i;
					ret.back().y = neg(y, p);
				}
			}
		}

		return ret;
	}
};

Point::Point(Curve& c)
{
	a = c.a;
	p = c.p;
	isInf = false;
}










void test2()
{

	Curve c(1, 7, 17);

	Point p(c);

	auto points = c.getPoints();

	//Log::out << points[2] + points[0] << Log::endl;
	//return;

	u64 ig = 0;
	for (; ig < points.size(); ++ig)
	{
		//Log::out << "(" << points[i].x << ", " << points[i].y << ")" << Log::endl;

		auto& pnt = points[ig];
		std::vector<u8> sets(points.size());
		Log::out << "p " << pnt << Log::endl;

		for (u64 i = 1; i < points.size(); ++i)
		{
			auto val = pnt  * i;

			for (u64 j = 0; j < points.size(); ++j)
			{
				if (points[j] == val)
				{
					sets[j] = 1;
					break;
				}
			}

			Log::out << pnt << "^" << i << " = " << val << Log::endl;
		}
		u64 v = std::accumulate(sets.begin(), sets.end(), 0);
		Log::out << Log::endl;
		if (v == 22)
			break;
	}


	Log::out << points.size() << Log::endl;
	if (ig < points.size())
		Log::out << "g = (" << points[ig].x << ", " << points[ig].y << ")" << Log::endl;
	//for (u64 i = 0; i < c.p; ++i)
	//{
	//	Log::out << "(" << i << ", " << c.getRhs(i)<< ")" << Log::endl;
	//}
}








u64 modExp(u64 b, u64 e, u64 mod)
{
	u64 ret = 1;

	for (u64 i = 0; i < e; ++i)
	{
		ret *= b;
		ret %= mod;
	}

	return ret;
}

void test()
{
	u64 p = 23;
	i64 aa = 1, bb = 0;
	PRNG prng(ZeroBlock);
	Curve curve(aa, bb, p);

	u64 g = 2;
	while (g < p)
	{

		std::vector<u8> sets(p);

		for (u64 i = 1; i < p; ++i)
		{
			u64 gi = modExp(g, i, p);

			sets[gi] = 1;
		}

		u64 v = std::accumulate(sets.begin(), sets.end(), 0);

		if (v == 22)
			Log::out << "g " << g << Log::endl;
		//break;

		++g;

	}

	Log::out << "g " << g << Log::endl;

	//for (u64 i = 1; i < 2 * p; ++i)
	//{
	//	u64 gi = modExp(g, i, p);
	//	Log::out << "g^" << i << "  " << gi << Log::endl;
	//}
	;


	u64 a(prng.get_u32() % p);
	u64 b(prng.get_u32() % p);
	u64 r(prng.get_u32() % p);

	auto a_br = a + b * r;


	auto ga = modExp(g, a, p);
	auto gbr = modExp(modExp(g,b, p) , r, p);
	auto gbr2 = modExp(g ,(b * r), p);


	auto ga_br = ga * gbr % p;
	auto ga_br2 = ga * gbr2 % p;
	auto ga_br3 = modExp(g, a_br,p);

	//if (ga_br != ga_br2)
	{
		//Log::out << "ga_br != ga_br2" << Log::endl;
		Log::out << ga_br << Log::endl;
		Log::out << ga_br2 << Log::endl;
		Log::out << ga_br3 << Log::endl;

		//throw UnitTestFail("ga_br != ga_br2")
	}
}

int main(int argc, char** argv)
{
	miraclTestMain();
	return 0;

	//test2();
	//return 0;
	//kpPSI();
	//return 0 ;

	//sim();
	//return 0;
	if (argc == 2)
	{
		DktSend();

		//bfSend();
		//DcwSend();
		//DcwRSend();
		//otBinSend();
	}
	else if (argc == 3)
	{
		DktRecv();
		//bfRecv();
		//DcwRecv();
		//DcwRRecv();
		//otBinRecv();
	}
	else
	{
		auto thrd = std::thread([]() {

			DktRecv();
		});

		DktSend();
		thrd.join();
		//blogb();
		//otBin();

		//params();
		//bf(3);
		//KosTest();
		//run_all();
	}

	return 0;
}