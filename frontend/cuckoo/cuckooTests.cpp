
#include "SimpleCuckoo.h"
#include <cryptoTools/Common/CuckooIndex.h>
using namespace osuCrypto;
#include "cryptoTools/Common/CLP.h"
#include <fstream>
#include "cuckooTests.h"
#include <iomanip>

void tt()
{
	u64 n = 10000;

	double e = 2;
	u64 h = 3;
	std::vector<u64> idx(n);
	std::vector<block> hashes(n);
	PRNG prng(ZeroBlock);

	for (u64 i = 0; i < hashes.size(); ++i)
	{
		idx[i] = i;
		hashes[i] = prng.get<block>();
	}

	CuckooIndex<> hashMap1;
	hashMap1.mParams.mBinScaler = e;
	hashMap1.mParams.mNumHashes = h;
	hashMap1.mParams.mStashSize = 400;


	hashMap1.init(n, 40, 0, 3);


	hashMap1.insert(idx, hashes);

	std::vector<u64> idxret(n);


	hashMap1.find(hashes, idxret);
	for (u64 i = 0; i < n; ++i)
	{
		if (idxret[i] != i)
		{
			std::cout << i << std::endl;
			throw std::runtime_error("");
		}
	}
}




void runOne(
	const osuCrypto::u64 &setSize,
	const osuCrypto::u64 &h,
	double &e,
	const osuCrypto::u64 &t,
	const osuCrypto::u64 &numThrds,
	bool varyCuckooSize,
	const osuCrypto::u64 &stashSize,
	std::fstream &out,
	bool simple)
{
	u64 cuckooSize = setSize * e;

	//std::cout << "|set|=" << setSize << " |Cuckoo|=" << cuckooSize << "  h=" << h << "  e=" << e << "  t=" << t << std::endl;

	std::atomic<u64> max(0);

	//std::cout << "n=" << n << "  h=" << h << "  e=" << e << "  t=" << t << std::endl;

	std::vector<std::array<u64, 400>> counts(numThrds);
	memset(counts.data(), 0, sizeof(u64) * 400 * numThrds);

	u64 tries = u64(1) << t;
	//std::atomic<u64> completed(0);
	max = 0;

	auto routine = [tries, &counts, setSize, h, e, numThrds, simple](u64 tIdx)
	{
		PRNG prng(_mm_set1_epi64x(tIdx));

		std::vector<block> hashs(setSize);
		std::vector<u64> idxs(setSize);

		u64 startIdx = tIdx * tries / numThrds;
		u64 endIdx = (tIdx + 1) * tries / numThrds;
		u64 count = endIdx - startIdx;

		for (u64 i = 0; i < count; ++i)
		{
			//if (i % step == 0)std::cout << "\r" << (i / step) << "%" << flush;
			prng.mAes.ecbEncCounterMode(prng.mBlockIdx, setSize, (block*)hashs.data());
			prng.mBlockIdx += setSize;

			for (u64 i = 0; i < setSize; ++i) {
				idxs[i] = i;
			}





			u64 stashSize;

			if (simple)
			{
				SimpleCuckoo cc;
				cc.mParams.mBinScaler = e;
				cc.mParams.mNumHashes = h;
				cc.mParams.mStashSize = 400;
				cc.mParams.mN = setSize;

				cc.init();
				cc.insert(idxs, hashs);
				stashSize = cc.stashUtilization();
			}
			else
			{
				CuckooIndex<> c;
				//throw std::runtime_error(LOCATION);
				c.mParams.mBinScaler = e;
				c.mParams.mNumHashes = h;
				c.mParams.mStashSize = 400;
				c.mParams.mN = setSize;

				c.init(c.mParams);
				c.insert(idxs, hashs);
				stashSize = c.stashUtilization();
			}

			//for (u64 ss = 0; ss <= stashSize; ++ss)
			//	++counts[tIdx][ss];

			++counts[tIdx][stashSize];

		}

		return 0;
	};

	std::vector<std::thread> thrds(numThrds);

	for (u64 i = 0; i < numThrds; ++i) {
		thrds[i] = std::thread([&, i]() {routine(i); });
	}

	///////////////////////////////////////////////////////////////////
	//               Process printing below here                     //
	///////////////////////////////////////////////////////////////////


	u64 curTotal(0);
	u64 total = (u64(1) << t);
	while ((u64)curTotal != total)
	{
		std::array<u64, 400> count;
		for (u64 i = 0; i < count.size(); ++i)
			count[i] = 0;

		for (u64 t = 0; t < numThrds; ++t)
			for (u64 i = 0; i < count.size(); ++i)
				count[i] += counts[t][i];

		curTotal = 0;
		for (u64 i = 0; i < count.size(); ++i) {
			curTotal += count[i];
		}

		double percent = curTotal * 10000 / tries / 100.0;

		std::cout << "\r " << std::setw(5) << percent << "%  e=" << e << " |set|=" << setSize << " |cuckoo|=" << cuckooSize;
		auto p = std::setprecision(3);
		//auto w = std::setw(5);
		u64 good = 0;
		for (u64 i = 0; i < stashSize; ++i)
		{
			good += count[i];
			u64 bad = curTotal - good;
			double secLevel = std::log2(std::max(u64(1), good)) - std::log2(std::max(u64(1), bad));

			if (bad == 0) {
				std::cout << "  >" << std::fixed << p << secLevel;
			}
			else if (good == 0) {
				std::cout 
					<< "  <" << std::fixed << p << secLevel;
			}
			else {
				std::cout << "  " << secLevel;
			}
			//std::cout << "  "<< std::fixed <<p << secLevel << "  (" << good << " " << bad<<")";
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}


	std::array<u64, 400> count;
	for (u64 i = 0; i < count.size(); ++i)
		count[i] = 0;

	for (u64 t = 0; t < numThrds; ++t)
		for (u64 i = 0; i < count.size(); ++i)
			count[i] += counts[t][i];

	curTotal = 0;
	for (u64 i = 0; i < count.size(); ++i) {
		curTotal += count[i];
	}

	std::cout << "\re=" << e << "   |set|=" << setSize << "  |cuckoo|=" << cuckooSize;
	out << "e " << e << "   |set| " << setSize << "  |cuckoo|=" << cuckooSize;
	u64 good = 0;
	for (u64 i = 0; i < stashSize; ++i)
	{
		// the count of all good events;
		good += count[i];

		// the count of all bad events.
		u64 bad = curTotal - good;

		//std::cout << " (" << i<<" "<< good << ", " << bad << ") ";

		double secLevel = std::log2(std::max(u64(1), good)) - std::log2(std::max(u64(1), bad));

		if (bad == 0) {
			//std::cout << "  >" << secLevel;
			out << "  >" << secLevel;
		}
		else if (good == 0) {
			//std::cout << "  <" << secLevel;
			out << "  <" << secLevel;
		}
		else {
			std::cout << "  " << secLevel;
			out << "  " << secLevel << ((secLevel >= t - 5) ? "*" : "");
		}
	}
	std::cout << "                                 " << std::endl;
	out << std::endl;

	//for (u64 i = 0; i < counts.size(); ++i) {
	//    out << i << "  " << count[i] << std::endl;
	//}

	for (u64 i = 0; i < numThrds; ++i) {
		thrds[i].join();
	}

}



void simpleTest(int argc, char** argv)
{
	//tt();
	//return;

	std::fstream out;
	out.open("./stashSizes.txt", out.out | out.trunc);

	CLP cmd;
	cmd.parse(argc, argv);
	cmd.setDefault("n", "1024");
	cmd.setDefault("h", "3");
	cmd.setDefault("e", "1.35");
	cmd.setDefault("t", "12");
	cmd.setDefault("x", "3");
	cmd.setDefault("eStep", "0.05");
	cmd.setDefault("nStep", "2");
	cmd.setDefault("ss", "6");

	// a parameter that shows the security level up to a stash size stashSize. Does not
	// effect performance.
	u64 stashSize = cmd.get<u64>("ss");;


	// the expension factor. see N.
	const double e = cmd.get<double>("e");

	// N is the size of the hash table. n = N / e items will be inserted...
	// if varyN, we change N and keep the #items fixed at n
	bool varyCuckooSize = !cmd.isSet("veryN");

	// set size = |set| or Cuckoo table size = |cuckoo|
	u64 n, nEnd;
	n = cmd.isSet("nn") ? 1ull << cmd.get<u64>("nn") : cmd.get<u64>("n");
	nEnd = cmd.isSet("nnEnd") ? 1ull << cmd.get<u64>("nnEnd") : n;

	// number of hash functions
	u64 h = cmd.get<u64>("h");

	// log2(...) the number of times we construct the cuckoo table.
	u64 t = cmd.get<u64>("t");

	// the last expansion factor that is considered. If set, all e between e and eEnd in steps of step are tried.
	double eEnd = cmd.isSet("eEnd") ? cmd.get<double>("eEnd") : e;
	// the step size of e that should be tried.
	double eStep = cmd.get<double>("eStep");
	u64 nStep = cmd.get<u64>("nStep");

	auto simple = cmd.isSet("simple");

	// the number of threads
	u64 numThrds = cmd.get<u64>("x");
	std::cout << "#threads=" << numThrds << " h=" << h << "  trials=" << t << " n=" << n << " nEnd=" << nEnd << std::endl;
	//for(u64 n )
	while (n <= nEnd)
	{
		auto curE = e;

		while (eStep > 0 ? curE <= eEnd : curE >= eEnd)
		{
			u64 curSetSize = varyCuckooSize ? n : u64(n / curE);

			runOne(curSetSize, h, curE,
				t, numThrds, varyCuckooSize,
				stashSize, out, simple);
			curE += eStep;
		}

		n *= (1ull << nStep);
	}
	std::cout << std::endl;
}

//void simpleTest(int argc, char** argv)
//{
//    simpleTest_find_e(argc, argv);
//    return;
//}








	//std::fstream out;
	//out.open("./stashSizes.txt", out.out | out.trunc);

	//CLP cmd;
	//cmd.parse(argc, argv);
	//cmd.setDefault("n", "1000");
	//cmd.setDefault("h", "2");
	//cmd.setDefault("e", "2");
	//cmd.setDefault("t", "16");
	//cmd.setDefault("x", "1");
	//cmd.setDefault("s", "1.1");

	//u64 n = cmd.get<u64>("n");
	//u64 h = cmd.get<u64>("h");
	//double e = cmd.get<double>("e");
	//u64 t = cmd.get<u64>("t");
	//u64 numThrds = cmd.get<u64>("x");
	//double step = cmd.get<double>("s");

	////std::cout << "n=" << n << "  h=" << h << "  e=" << e << "  t=" << t << std::endl;

	//u64 max = 1;

	//while (max)
	//{

	//    std::cout << "n=" << n << "  h=" << h << "  e=" << e << "  t=" << t << std::endl;

	//    std::array<std::atomic<u64>, 400> counts;

	//    for (u64 i = 0; i < counts.size(); ++i)
	//        counts[i] = 0;

	//    u64 tries = u64(1) << t;
	//    std::atomic<u64> completed(0);


	//    auto routine = [tries, &completed, &counts, n, h, e, numThrds](u64 tIdx)
	//    {

	//        PRNG prng(_mm_set1_epi64x(tIdx));

	//        std::vector<u64> hashs(n * h + 1);
	//        std::vector<u64> idxs(n);


	//        SimpleCuckoo::Workspace ws(n, h);

	//        u64 startIdx = tIdx * tries / numThrds;
	//        u64 endIdx = (tIdx + 1) * tries / numThrds;
	//        u64 count = endIdx - startIdx;


	//        for (u64 i = 0; i < count; ++i)
	//        {
	//            //if (i % step == 0)std::cout << "\r" << (i / step) << "%" << flush;


	//            prng.mAes.ecbEncCounterMode(prng.mBlockIdx, n * h / 2, (block*)hashs.data());
	//            prng.mBlockIdx += n;
	//            for (u64 i = 0; i < n; ++i)
	//            {
	//                idxs[i] = i;
	//            }



	//            SimpleCuckoo c;

	//            c.mParams.mBinScaler = e;
	//            c.mParams.mNumHashes = h;
	//            c.mParams.mStashSize = 400;

	//            c.init(n, 40, false);


	//            MatrixView<u64> hashsView((u64*)hashs.data(), n, h);

	//            c.insertBatch(idxs, hashsView, ws);

	//            u64 stashSize = c.stashUtilization();
	//            ++counts[stashSize];

	//            ++completed;
	//            //maxStash = std::max((u64)maxStash, stashSize);
	//            //std::cout << stashSize << std::endl;
	//        }
	//        //std::cout << "\r";

	//    };

	//    std::vector<std::thread> thrds(numThrds);

	//    for (u64 i = 0; i < numThrds; ++i)
	//    {
	//        thrds[i] = std::thread([&, i]() {routine(i); });
	//    }

	//    //u64 stringLength = 0;
	//    while ((u64)completed != tries)
	//    {
	//        double percent = completed * 10000 / tries / 100.0;

	//        u64 max = 0;
	//        for (u64 i = counts.size() - 1; i != 0; --i)
	//        {
	//            if (counts[i])
	//            {
	//                max = i;
	//                break;
	//            }
	//        }

	//        std::stringstream ss;
	//        ss << "\r " << std::setw(5) << percent << "%  (" << completed << " / " << tries << ")   count[" << max << "] = " << counts[max];
	//        std::string str = ss.str();

	//        // first print spaces to clear what was on screen, then print the actual string.
	//        //std::cout << '\r' << std::string(' ', stringLength) << flush << str << flush;

	//        // update how long the string that we just printed is.
	//        //stringLength = str.size();

	//        //stop = max;

	//        std::this_thread::sleep_for(std::chrono::seconds(1));
	//    }

	//    max = 0;
	//    u64 min = 0;
	//    for (u64 i = counts.size() - 1; i != 0; --i)
	//    {
	//        if (counts[i])
	//        {
	//            max = i;
	//            break;
	//        }
	//    }
	//    for (u64 i = 0; i < counts.size(); ++i)
	//    {
	//        if (counts[i])
	//        {
	//            min = i;
	//            break;
	//        }
	//    }

	//    std::cout << "\r                                                " << std::endl;

	//    for (u64 i = min; i <= max; ++i)
	//    {
	//        std::cout << i << "  " << counts[i] << std::endl;
	//    }

	//    //if (!stop)
	//    //{

	//    //    std::cout << "\r" << "h=" << h << "  e=" << e << " passed                                                " << std::endl;
	//    //    out << "h=" << h << "  e=" << e << " passed" << std::endl;
	//    //}
	//    //else
	//    //{
	//    //    std::cout << "\r" << "h=" << h << "  e=" << e << " failed " << completed << " / " << tries << "                  "<< std::endl;
	//    //    out << "h=" << h << "  e=" << e << " failed " << completed << " / " << tries << std::endl;
	//    //}

	//    for (u64 i = 0; i < numThrds; ++i)
	//    {
	//        thrds[i].join();
	//    }

	//    e *= step;

	//}
//}

//
//
//void simpleTest_var_h(int argc, char** argv)
//{
//    //tt();
//    //return;
//
//    std::fstream out;
//    out.open("./stashSizes.txt", out.out | out.trunc);
//
//    CLP cmd;
//    cmd.parse(argc, argv);
//    cmd.setDefault("n", "1000");
//    cmd.setDefault("h", "2");
//    cmd.setDefault("e", "2");
//    cmd.setDefault("t", "16");
//    cmd.setDefault("x", "1");
//
//    u64 n = cmd.get<u64>("n");
//    //u64 h = cmd.get<u64>("h");
//    double e = cmd.get<double>("e");
//    u64 t = cmd.get<u64>("t");
//    u64 numThrds = cmd.get<u64>("x");
//
//    //std::cout << "n=" << n << "  h=" << h << "  e=" << e << "  t=" << t << std::endl;
//
//    e = 1;
//    double step = 0.05;
//
//    for (u64 h = 6; h > 1; --h)
//    {
//        u64 max = 1;
//
//        while (max)
//        {
//
//            std::cout << "n=" << n << "  h=" << h << "  e=" << e << "  t=" << t << std::endl;
//
//            std::atomic<bool>  stop(false);
//            std::array<std::atomic<u64>, 400> counts;
//
//            for (u64 i = 0; i < counts.size(); ++i)
//                counts[i] = 0;
//
//            u64 tries = u64(1) << t;
//            std::atomic<u64> completed(0);
//
//
//            auto routine = [tries, &completed, &counts, &stop, n, h, e, numThrds](u64 tIdx)
//            {
//
//                PRNG prng(_mm_set1_epi64x(tIdx));
//
//                std::vector<u64> hashs(n * h + 1);
//                std::vector<u64> idxs(n);
//
//
//                SimpleCuckoo::Workspace ws(n, h);
//
//                u64 startIdx = tIdx * tries / numThrds;
//                u64 endIdx = (tIdx + 1) * tries / numThrds;
//                u64 count = endIdx - startIdx;
//
//
//                for (u64 i = 0; i < count && !stop; ++i)
//                {
//                    //if (i % step == 0)std::cout << "\r" << (i / step) << "%" << flush;
//
//
//                    prng.mAes.ecbEncCounterMode(prng.mBlockIdx, n * h / 2, (block*)hashs.data());
//                    prng.mBlockIdx += n;
//                    for (u64 i = 0; i < n; ++i)
//                    {
//                        idxs[i] = i;
//                    }
//
//
//
//                    SimpleCuckoo c;
//
//                    c.mParams.mBinScaler = e;
//                    c.mParams.mNumHashes = h;
//                    c.mParams.mStashSize = 400;
//
//                    c.init(n, 40, false);
//
//
//                    MatrixView<u64> hashsView((u64*)hashs.data(), n, h);
//
//                    c.insertBatch(idxs, hashsView, ws);
//
//                    u64 stashSize = c.stashUtilization();
//                    ++counts[stashSize];
//
//                    ++completed;
//                    //maxStash = std::max((u64)maxStash, stashSize);
//                    //std::cout << stashSize << std::endl;
//                }
//                //std::cout << "\r";
//
//            };
//
//            std::vector<std::thread> thrds(numThrds);
//
//            for (u64 i = 0; i < numThrds; ++i)
//            {
//                thrds[i] = std::thread([&, i]() {routine(i); });
//            }
//
//            //u64 stringLength = 0;
//            while ((u64)completed != tries && !stop)
//            {
//                double percent = completed * 10000 / tries / 100.0;
//
//                u64 max = 0;
//                for (u64 i = counts.size() - 1; i != 0; --i)
//                {
//                    if (counts[i])
//                    {
//                        max = i;
//                        break;
//                    }
//                }
//
//                std::stringstream ss;
//                ss << "\r " << std::setw(5) << percent << "%  (" << completed << " / " << tries << ")   count[" << max << "] = " << counts[max];
//                std::string str = ss.str();
//
//                // first print spaces to clear what was on screen, then print the actual string.
//                //std::cout << '\r' << std::string(' ', stringLength) << flush << str << flush;
//
//                // update how long the string that we just printed is.
//                //stringLength = str.size();
//
//                stop = bool(max);
//
//                std::this_thread::sleep_for(std::chrono::seconds(1));
//            }
//            std::cout << "\r" << std::endl;
//
//            max = 0;
//            for (u64 i = counts.size() - 1; i != 0; --i)
//            {
//                if (counts[i])
//                {
//                    max = i;
//                    break;
//                }
//            }
//
//            if (!stop)
//            {
//
//                out << "h=" << h << "  e=" << e << " passed" << std::endl;
//            }
//            else
//            {
//                out << "h=" << h << "  e=" << e << " failed " << completed << " / " << tries << std::endl;
//            }
//
//            for (u64 i = 0; i < numThrds; ++i)
//            {
//                thrds[i].join();
//            }
//
//            if (max) e += step;
//
//        }
//    }
//}
