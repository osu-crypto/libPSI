#include <iostream>
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"

//using namespace std;
#include "UnitTests.h"
#include "cryptoTools/Common/Defines.h"
//#include "cryptoTools/Common/Version.h"

//#if !defined(CRYPTO_TOOLS_VERSION_MAJOR) || CRYPTO_TOOLS_VERSION_MAJOR != 1 || CRYPTO_TOOLS_VERSION_MAJOR != 1
//#error "Wrong crypto tools version."
//#endif

#include "libPSI/Tools/RandomShuffle.h"

using namespace osuCrypto;

#include "bloomFilterMain.h"
#include "dcwMain.h"
#include "dktMain.h"
#include "ecdhMain.h"
#include "OtBinMain.h"
#include "util.h"

#include "cryptoTools/Common/MatrixView.h"
#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
#include "libOTe/TwoChooseOne/KosOtExtSender.h"
#include <fstream>
#include <numeric>
#include <chrono>
#include "tests_cryptoTools/UnitTests.h"
#include "libOTe_Tests/UnitTests.h"
#include "libPSI_Tests/UnitTests.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libPSI/PIR/BgiPirClient.h"
#include "libPSI/PIR/BgiPirServer.h"
#include "cryptoTools/Crypto/RandomOracle.h"

#include "cuckoo/cuckooTests.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "libPSI/Tools/SimpleIndex.h"
#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/bch511.h"
std::vector<std::string>
DcwrTags{ "dcwr" },
rr16Tags{ "rr16" },
rr17aTags{ "rr17a" },
rr17aSMTags{ "rr17a-sm" },
rr17bTags{ "rr17b" },
kkrtTag{ "kkrt" },
drrnTag{ "drrt" },
ecdhTags{ "ecdh" },
dktTags{ "dkt" },
grrTags{ "grr" },
helpTags{ "h", "help" },
numThreads{ "t", "threads" },
numItems{ "n","numItems" },
numItems2{ "n2","srvNumItems" },
powNumItems{ "nn","powNumItems" },
powNumItems2{ "nn2","srvPowNumItems" },
verboseTags{ "v", "verbose" },
trialsTags{ "trials" },
roleTag{ "r", "role" },
hostNameTag{ "ip" },
pingTag{ "ping" },
bitSizeTag{ "b","bitSize" },
binScalerTag{ "s", "binScaler" },
statSecParamTag{ "ssp" },
numHashTag{ "nh" },
bigBlockTag{ "bigBlock" };

bool firstRun(true);

std::function<void(LaunchParams&)> NoOp;



void Drrn17Send(
    LaunchParams& params);

void Drrn17Recv(
    LaunchParams& params);

void banchmarkPIR(
	std::vector<std::string> tag,
	CLP& cmd,
	std::function<void(LaunchParams&)> recvProtol,
	std::function<void(LaunchParams&)> sendProtol)
{

	if (cmd.isSet(tag))
	{
		LaunchParams params;
		params.mCmd = &cmd;
		params.mNumThreads = cmd.getMany<u64>(numThreads);
		params.mVerbose = cmd.get<u64>(verboseTags);
		params.mTrials = cmd.get<u64>(trialsTags);
		params.mHostName = cmd.get<std::string>(hostNameTag);
		params.mBitSize = cmd.get<u64>(bitSizeTag);
		params.mBinScaler = cmd.getMany<double>(binScalerTag);
		params.mNumHash = cmd.get<u64>(numHashTag);

		if (cmd.isSet(powNumItems)) {
			params.mNumItems = cmd.getMany<u64>(powNumItems);
			std::transform(
				params.mNumItems.begin(),
				params.mNumItems.end(),
				params.mNumItems.begin(),
				[](u64 v) { return 1 << v; });
		}
		else {
			params.mNumItems = cmd.getMany<u64>(numItems);
		}
		if (cmd.isSet(powNumItems2)) {
			params.mNumItems2 = cmd.getMany<u64>(powNumItems2);
			std::transform(
				params.mNumItems2.begin(),
				params.mNumItems2.end(),
				params.mNumItems2.begin(),
				[](u64 v) { return 1 << v; });
		}
		else {
			params.mNumItems2 = cmd.getMany<u64>(numItems2);
		}

		IOService ios(0);

		auto go = [&](LaunchParams& params)
		{
			EpMode m1, m2;
			if (params.mIdx == 0)
			{
				m1 = m2 = EpMode::Client;
			}
			else if (params.mIdx == 1) {
				m1 = EpMode::Server;
				m2 = EpMode::Client;
			}
			else {
				m1 = m2 = EpMode::Server;
			}

			Endpoint ep1(ios, params.mHostName, m1);
			Endpoint ep2(ios, params.mHostName, m2);
			params.mChls.resize(*std::max_element(params.mNumThreads.begin(), params.mNumThreads.end()));
			params.mChls2.resize(*std::max_element(params.mNumThreads.begin(), params.mNumThreads.end()));

			for (u64 i = 0; i < params.mChls.size(); ++i) {
				params.mChls[i] = ep1.addChannel();
				params.mChls2[i] = ep2.addChannel();
			}

			if (params.mIdx == 0) {
				if (firstRun) printHeader();
				recvProtol(params);
			}
			else sendProtol(params);

			params.mChls.clear();
			params.mChls2.clear();
		};

		if (cmd.hasValue(roleTag))
		{
			params.mIdx = cmd.get<u32>(roleTag);
			go(params);

		}
		else
		{
			auto srv0 = std::thread([&]() {
				auto params2 = params;
				params2.mIdx = 1;
				go(params2);
			});
			auto srv1 = std::thread([&]() {
				auto params2 = params;
				params2.mIdx = 2;
				go(params2);
			});

			params.mIdx = 0;
			go(params);
			srv0.join();
			srv1.join();
		}

		firstRun = false;
		//ios.stop();
	}
}


void benchmark(
	std::vector<std::string> tag,
	CLP& cmd,
	std::function<void(LaunchParams&)> recvProtol,
	std::function<void(LaunchParams&)> sendProtol)
{
	if (cmd.isSet(tag))
	{
		LaunchParams params;

		params.mIP = cmd.get<std::string>(hostNameTag);
        params.mNumThreads = cmd.getMany<u64>(numThreads);
        params.mVerbose = cmd.get<u64>(verboseTags);
        params.mTrials = cmd.get<u64>(trialsTags);
        params.mHostName = cmd.get<std::string>(hostNameTag);
        params.mBitSize = cmd.get<u64>(bitSizeTag);
        params.mBinScaler = cmd.getMany<double>(binScalerTag);
        params.mStatSecParam = cmd.get<u64>(statSecParamTag);
        params.mCmd = &cmd;


		if (cmd.isSet(powNumItems))
		{
			params.mNumItems = cmd.getMany<u64>(powNumItems);
			std::transform(
				params.mNumItems.begin(),
				params.mNumItems.end(),
				params.mNumItems.begin(),
				[](u64 v) { return 1 << v; });
		}
		else
		{
			params.mNumItems = cmd.getMany<u64>(numItems);
		}

		IOService ios(0);

		auto go = [&](LaunchParams& params)
		{
			auto mode = params.mIdx ? EpMode::Server : EpMode::Client;
			Endpoint ep(ios, params.mIP, mode);
			params.mChls.resize(*std::max_element(params.mNumThreads.begin(), params.mNumThreads.end()));

			for (u64 i = 0; i < params.mChls.size(); ++i)
				params.mChls[i] = ep.addChannel();

            if (params.mIdx == 0)
            {
                if (firstRun) printHeader();
                firstRun = false;

				recvProtol(params);
			}
			else
			{
				sendProtol(params);
			}

			for (u64 i = 0; i < params.mChls.size(); ++i)
				params.mChls[i].close();


			params.mChls.clear();
			ep.stop();
		};

        if (cmd.hasValue(roleTag))
        {
            params.mIdx = cmd.get<u32>(roleTag);
            go(params);
        }
        else
        {
            auto thrd = std::thread([&]()
            {
                auto params2 = params;
                params2.mIdx = 1;
                go(params2);
            });
            params.mIdx = 0;
            go(params);
            thrd.join();
        }

        ios.stop();
    }
}

void pingTest(CLP& cmd)
{

	IOService ios(0);

	if (cmd.hasValue(roleTag))
	{
		if (cmd.get<bool>(roleTag))
		{
			Endpoint sendEP(ios, cmd.get<std::string>(hostNameTag), EpMode::Server, "pringTest");
			auto chl = sendEP.addChannel("test");
			senderGetLatency(chl);
			chl.close();
			sendEP.stop();
		}
		else
		{
			Endpoint recvEP(ios, cmd.get<std::string>(hostNameTag), EpMode::Client, "pringTest");
			auto chl = recvEP.addChannel("test");
			recverGetLatency(chl);
			chl.close();
			recvEP.stop();
		}
	}
	else
	{
		auto thrd = std::thread([&]()
		{
			Endpoint sendEP(ios, cmd.get<std::string>(hostNameTag), EpMode::Server, "pringTest");
			auto chl = sendEP.addChannel("test");
			senderGetLatency(chl);
			chl.close();
			sendEP.stop();
		});

		Endpoint recvEP(ios, cmd.get<std::string>(hostNameTag), EpMode::Client, "pringTest");
		auto chl = recvEP.addChannel("test");
		recverGetLatency(chl);
		chl.close();
		recvEP.stop();
		thrd.join();
	}

	ios.stop();
}


void shuffle()
{

    u64 n = 1ull << 22;
    std::vector<u64> vals(n);
    PRNG prng(ZeroBlock, 256);

    RandomShuffle ss;
    Timer timer;
    timer.setTimePoint("s");
    for (u64 jj = 0; jj < 10; ++jj)
    {

        ss.shuffle(vals, prng);

    }
    timer.setTimePoint("s");
    std::cout << timer << std::endl;
    timer.reset();
    timer.setTimePoint("s");

    for (u64 jj = 0; jj < 10; ++jj)
    {
        ss.mergeShuffle(vals, prng);
    }
    timer.setTimePoint("m");
    std::cout << timer << std::endl;
    timer.reset();


}

void BallsAndBins(CLP& cmd)
{
    auto Ns = cmd.getMany<int>("nn");
    auto s = cmd.getMany<int>("s");
    for (auto nn : Ns)
    {
        for (auto mm : s)
        {
            auto n = 1ull << nn;
            auto m = n / mm;
            std::cout << "n=" << n << " m=" << m << " -> binSize " << SimpleIndex::get_bin_size(m, n, 40) << std::endl;;
            gTimer.setTimePoint("b" + std::to_string(nn) + " " + std::to_string(mm));
        }
    }
}

void doFilePSI(const CLP& cmd);

void padSmallSet(std::vector<osuCrypto::block>& set, osuCrypto::u64& theirSize, osuCrypto::CLP& cmd);

int main(int argc, char** argv)
{
    CLP cmd;
    cmd.parse(argc, argv);

	// run cuckoo analysis
	if (cmd.isSet("cuckoo"))
	{
		simpleTest(argc, argv);
		return 0;
	}

	// compute the ping.
	if (cmd.isSet(pingTag))
	{
		pingTest(cmd);
		return 0;
	}

	// run the balls-in-bins analysis
	if (cmd.isSet("ballsBins"))
	{
		BallsAndBins(cmd);
		return 0;
	}

	// Unit tests.
	auto tests = tests_cryptoTools::Tests;
	tests += tests_libOTe::Tests;
	tests += libPSI_Tests::Tests;
	auto result = tests.runIf(cmd);


	// default parameters for various things
	cmd.setDefault(numThreads, "1");
	cmd.setDefault(numItems, std::to_string(1 << 8));
	cmd.setDefault(numItems2, std::to_string(1 << 8));
	cmd.setDefault(trialsTags, "1");
	cmd.setDefault(bitSizeTag, "-1");
	cmd.setDefault(binScalerTag, "1");
	cmd.setDefault(hostNameTag, "127.0.0.1:1212");
	cmd.setDefault(numHashTag, "3");
	cmd.setDefault(bigBlockTag, "16");
    cmd.setDefault(statSecParamTag, 40);
    cmd.setDefault("eps", "0.1");
	cmd.setDefault(verboseTags, std::to_string(1 & (u8)cmd.isSet(verboseTags)));

	// main protocols, they run if the flag is set.
    bool hasProtocolTag = false;
	if (cmd.isSet("in"))
	{
		hasProtocolTag = true;
		doFilePSI(cmd);
	}
	else
	{
		benchmark(DcwrTags, cmd, DcwRRecv, DcwRSend);
		benchmark(rr16Tags, cmd, bfRecv, bfSend);
		benchmark(rr17aTags, cmd, rr17aRecv, rr17aSend);
		benchmark(rr17aSMTags, cmd, rr17aRecv_StandardModel, rr17aSend_StandardModel);
		benchmark(rr17bTags, cmd, rr17bRecv, rr17bSend);
		benchmark(kkrtTag, cmd, kkrtRecv, kkrtSend);
		benchmark(grrTags, cmd, grr18Recv, grr18Send);
		benchmark(dktTags, cmd, DktRecv, DktSend);
		benchmark(ecdhTags, cmd, EcdhRecv, EcdhSend);
		banchmarkPIR(drrnTag, cmd, Drrn17Recv, Drrn17Send);
	}


	if ((result == TestCollection::Result::skipped &&
		hasProtocolTag == false &&
		cmd.isSet(DcwrTags) == false &&
		cmd.isSet(rr16Tags) == false &&
		cmd.isSet(rr17aTags) == false &&
		cmd.isSet(rr17aSMTags) == false &&
		cmd.isSet(rr17bTags) == false &&
		cmd.isSet(kkrtTag) == false &&
        cmd.isSet(drrnTag) == false &&
        cmd.isSet(grrTags) == false &&
        cmd.isSet(dktTags) == false &&
		cmd.isSet(ecdhTags) == false &&
		cmd.isSet(pingTag) == false) ||
		cmd.isSet(helpTags))
	{
		std::cout << Color::Red 
			<< "#######################################################\n"
			<< "#                      - libPSI -                     #\n"
			<< "#               A library for performing              #\n"
			<< "#               private set intersection              #\n"
			<< "#                      Peter Rindal                   #\n"
			<< "#######################################################\n" << std::endl;

		std::cout << Color::Green << "Protocols:\n" << Color::Default


			<< "   -" << DcwrTags[0] << " : DCW13+PSZ14  - Random Garbled Bloom Filter (semi-honest*)\n"
            << "   -" << rr16Tags[0] << "    : RR16    - Random Garbled Bloom Filter (malicious secure)\n"
            << "   -" << rr17aTags[0] << "   : RR17    - Hash to bins & compare style (malicious secure, fastest)\n"
            << "   -" << rr17aSMTags[0] << ": RR17sm  - Hash to bins & compare style (standard model malicious secure)\n"
            << "   -" << rr17bTags[0] << "   : RR17b   - Hash to bins & commit compare style (malicious secure)\n"
			<< "   -" << grrTags[0] << ": GRR19   - Hash to bins & commit compare style (differential private & malicious secure)\n"

			<< "   -" << dktTags[0] << "     : DKT12   - Public key style (malicious secure)\n"
			<< "   -" << ecdhTags[0] << "     : ECHD   - Diffie-Hellma key exchange (semihonest secure)\n"

			<< "   -" << kkrtTag[0] << "    : KKRT16  - Hash to Bin & compare style (semi-honest secure, fastest)\n"
            << "   -" << drrnTag[0] << "  : DRRN17  - Two server PIR style (semi-honest secure)\n" 
			<< std::endl;

		std::cout << Color::Green << "File based PSI Parameters: " << Color::Default
			<< "Should be combined with one of the protocol flags above.\n"
			<< "   -in: The path to the party's set. Should either be a binary file containing 16 byte elements with a .bin extension. "
			<< "Otherwise the path should have a .csv extension and have one element per row, 32 char hex rows are prefered. \n"

			<< "   -r:  Value should be in { 0, 1 } where 0 means PSI sender.\n"

			<< "   -out: The output file path. Will be writen in the same format as the input. (Default = in || \".out\")\n"
			<< "   -ip: IP address and port of the server = PSI receiver. (Default = localhost:1212)\n"
			<< "   -server: Value should be in {0, 1} and indicates if this party should be the IP server. (Default = r)\n"

			<< "   -bin: Optional flag to always interpret the input file as binary.\n"
			<< "   -csv: Optional flag to always interpret the input file as a CSV.\n"
			<< "   -receiverSize: An optional parameter to specify the receiver's set size.\n"
			<< "   -senderSize: An optional parameter to specify the sender's set size.\n\n"
			;
		std::cout << Color::Green << "Benchmark Parameters:\n" << Color::Default
			<< "   -" << roleTag[0]
			<< ": Two terminal mode. Value should be in { 0, 1 } where 0 means PSI sender and network server.\n"

			<< "   -ip: IP address and port of the server = PSI receiver. (Default = localhost:1212)\n"

			<< "   -" << numItems[0]
			<< ": Number of items each party has, white space delimited. (Default = " << cmd.get<std::string>(numItems) << ")\n"

            << "   -" << powNumItems[0]
            << ": 2^n number of items each party has, white space delimited.\n"

            << "   -" << powNumItems2[0]
            << ": 2^n number of items the server in PIR PSI has, white space delimited.\n"

			<< "   -" << numThreads[0]
			<< ": Number of theads each party has, white space delimited. (Default = " << cmd.get<std::string>(numThreads) << ")\n"

			<< "   -" << trialsTags[0]
			<< ": Number of trials performed. (Default = " << cmd.get<std::string>(trialsTags) << ")\n"

			<< "   -" << verboseTags[0]
			<< ": print extra information. (Default = " << cmd.get<std::string>(verboseTags) << ")\n"

			<< "   -" << hostNameTag[0]
			<< ": The server's address (Default = " << cmd.get<std::string>(hostNameTag) << ")\n"

			<< "   -" << pingTag[0]
			<< ": Perform a ping and bandwidth test (Default = " << cmd.isSet(pingTag) << ")\n"

			<< "   -" << bitSizeTag[0]
			<< ":  Bit size for protocols that depend on it.\n"

            << "   -" << binScalerTag[0]
            << ":  Have the Hash to bin type protocols use n / " << binScalerTag[0] << " number of bins (Default = 1)\n"

            << "   -bigBlock"
            << ":  The number of entries from the PSI-PSI server database each PIR contributes to the PSI. Larger=smaller PIR queries but larger PSI (Default = 16)\n"

            << std::endl;


		std::cout << Color::Green << "Unit Tests:\n" << Color::Default
			<< "   -u: Run all unit tests\n" << std::endl;

	}
	return 0;
}