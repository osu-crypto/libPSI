#include "BinOtPsi_Tests.h"

#include "Common.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"

#include "libPSI/PSI/KeywordPsiClient.h"
#include "libPSI/PSI/KeywordPsiServer.h"

#include <array>

using namespace osuCrypto;

void Psi_Keyword_EmptySet_Test_Impl()
{
	setThreadName("client");
	u64 psiSecParam = 40;
	u64 clientSetSize = 32;
	u64 srvSetSize = 1 << 9;

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253465, 34354565, 1, 23987045));

	std::vector<block> clientSet(clientSetSize), srvSet(srvSetSize);
	for (u64 i = 0; i < clientSetSize; ++i)
	{
		clientSet[i] = prng.get<block>();
	}

	for (u64 i = 0; i < srvSet.size(); ++i)
	{
		srvSet[i] = prng1.get<block>();
	}

	// whp no match

	IOService ios(0);
	Endpoint epcs0(ios, "localhost", EpMode::Server, "cs0");
	Endpoint epcs1(ios, "localhost", EpMode::Server, "cs1");
	Endpoint eps0c(ios, "localhost", EpMode::Client, "cs0");
	Endpoint eps1c(ios, "localhost", EpMode::Client, "cs1");
	

	Channel cs0Chl = epcs0.addChannel("c");
	Channel cs1Chl = epcs1.addChannel("c");
	Channel s0cChl = eps0c.addChannel("c");
	Channel s1cChl = eps1c.addChannel("c");

	KeywordPsiClient client;
	KeywordPsiServer s0, s1;

	client.init(cs0Chl, cs1Chl, srvSetSize, clientSetSize, prng.get<block>());

	auto s0thrd = std::thread([&]() { 
		s0.init(0, s0cChl, srvSetSize, clientSetSize, prng.get<block>());
		s0.send(s0cChl, srvSet); });
	auto s1thrd = std::thread([&]() { 
		s1.init(1, s1cChl, srvSetSize, clientSetSize, prng.get<block>()); 
		s1.send(s1cChl, srvSet); });
	client.recv(cs0Chl, cs1Chl, clientSet);

	s0thrd.join();
	s1thrd.join();

	if (client.mIntersection.size() > 0) {
		throw UnitTestFail();
	}
}

void Psi_Keyword_SingletonSet_Test_Impl()
{
	setThreadName("client");
	u64 psiSecParam = 40;
	u64 clientSetSize = 32;
	u64 srvSetSize = 1 << 9;

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253465, 34354565, 1, 23987045));

	std::vector<block> clientSet(clientSetSize), srvSet(srvSetSize);
	for (u64 i = 0; i < clientSetSize; ++i)
	{
		clientSet[i] = prng.get<block>();
	}

	for (u64 i = 0; i < srvSet.size(); ++i)
	{
		srvSet[i] = prng1.get<block>();
	}

	clientSet[5] = srvSet[23];


	IOService ios(0);
	Endpoint epcs0(ios, "localhost", EpMode::Server, "cs0");
	Endpoint epcs1(ios, "localhost", EpMode::Server, "cs1");
	Endpoint eps0c(ios, "localhost", EpMode::Client, "cs0");
	Endpoint eps1c(ios, "localhost", EpMode::Client, "cs1");


	Channel cs0Chl = epcs0.addChannel("c");
	Channel cs1Chl = epcs1.addChannel("c");
	Channel s0cChl = eps0c.addChannel("c");
	Channel s1cChl = eps1c.addChannel("c");

	KeywordPsiClient client;
	KeywordPsiServer s0, s1;

	client.init(cs0Chl, cs1Chl, srvSetSize, clientSetSize, prng.get<block>());

	auto s0thrd = std::thread([&]() {
		s0.init(0, s0cChl, srvSetSize, clientSetSize, prng.get<block>());
		s0.send(s0cChl, srvSet); });
	auto s1thrd = std::thread([&]() {
		s1.init(1, s1cChl, srvSetSize, clientSetSize, prng.get<block>());
		s1.send(s1cChl, srvSet); });
	client.recv(cs0Chl, cs1Chl, clientSet);

	s0thrd.join();
	s1thrd.join();

	if (client.mIntersection.size() != 1 || client.mIntersection[0] != 5) {
		throw UnitTestFail();
	}
}


void Psi_Keyword_FullSet_Test_Impl()
{
	setThreadName("client");
	u64 psiSecParam = 40;
	u64 clientSetSize = 32;
	u64 srvSetSize = 1 << 9;

	PRNG prng(_mm_set_epi32(4253465, 34354565, 234435, 23987045));
	PRNG prng1(_mm_set_epi32(4253465, 34354565, 0, 23987045));

	std::vector<block> clientSet(clientSetSize), srvSet(srvSetSize);

	for (u64 i = 0; i < srvSet.size(); ++i)
	{
		srvSet[i] = prng1.get<block>();
	}
	for (u64 i = 0; i < clientSetSize; ++i)
	{
		clientSet[i] = srvSet[i];
	}


	IOService ios(0);
	Endpoint epcs0(ios, "localhost", EpMode::Server, "cs0");
	Endpoint epcs1(ios, "localhost", EpMode::Server, "cs1");
	Endpoint eps0c(ios, "localhost", EpMode::Client, "cs0");
	Endpoint eps1c(ios, "localhost", EpMode::Client, "cs1");


	Channel cs0Chl = epcs0.addChannel("c");
	Channel cs1Chl = epcs1.addChannel("c");
	Channel s0cChl = eps0c.addChannel("c");
	Channel s1cChl = eps1c.addChannel("c");

	KeywordPsiClient client;
	KeywordPsiServer s0, s1;

	client.init(cs0Chl, cs1Chl, srvSetSize, clientSetSize, prng.get<block>());

	auto s0thrd = std::thread([&]() {
		s0.init(0, s0cChl, srvSetSize, clientSetSize, prng.get<block>());
		s0.send(s0cChl, srvSet); });
	auto s1thrd = std::thread([&]() {
		s1.init(1, s1cChl, srvSetSize, clientSetSize, prng.get<block>());
		s1.send(s1cChl, srvSet); });
	client.recv(cs0Chl, cs1Chl, clientSet);

	s0thrd.join();
	s1thrd.join();

	bool failed = false;

	std::sort(client.mIntersection.begin(), client.mIntersection.end());

	if (client.mIntersection.size() != clientSetSize) {
		std::cout << "wrong size " << client.mIntersection.size() << std::endl;
		//throw UnitTestFail();
		failed = true;
	}

	for (u64 i = 0; i < clientSetSize; ++i)
	{
		bool b = std::find(client.mIntersection.begin(), client.mIntersection.end(), i) == client.mIntersection.end();
		if (b)
		{
			std::cout << "missing " << i << std::endl;
			//throw UnitTestFail();
			failed = true;
		}
	}

	if (failed) throw UnitTestFail();
}
