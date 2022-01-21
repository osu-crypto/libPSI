#include "FileBase_Tests.h"

#include "libPSI/Tools/fileBased.h"

using namespace oc;

template<typename T>
std::vector<u64> setItersect(std::vector<T>& v, std::vector<T>& sub)
{
	std::unordered_set<T> ss(sub.begin(), sub.end());

	std::vector<u64> r;
	for (u64 i = 0; i < v.size(); ++i)
	{
		if (ss.find(v[i]) != ss.end())
			r.push_back(i);
	}

	return r;
}

std::vector<block> writeFile(std::string path, u64 step, u64 size, FileType ft)
{
	std::ofstream o;
	std::vector<block> r; r.reserve(size);
	if (ft == FileType::Bin)
	{
		o.open(path, std::ios::trunc | std::ios::binary);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = i * step;
			block b(v, v);
			r.push_back(b);
			o.write((char*)&b, 16);
		}
	}
	else if(ft == FileType::Csv)
	{
		o.open(path, std::ios::trunc);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = i * step;
			block b(v, v);
			r.push_back(b);
			o << b << "\n";
		}
	}
	else
	{
		o.open(path, std::ios::trunc);

		if (o.is_open() == false)
			throw RTE_LOC;

		for (u64 i = 0; i < size; ++i)
		{
			auto v = "prefix_" + std::to_string(i * step) + "\n";

			oc::RandomOracle ro(16);
			ro.Update(v.data(), v.size());
			block b;
			ro.Final(b);
			r.push_back(b);

			o << v;
		}
	}

	return r;
}

bool checkFile(std::string path,std::vector<u64>& exp, FileType ft)
{

	if (ft == FileType::Bin)
	{
		std::ifstream o;
		o.open(path, std::ios::in | std::ios::binary);
		if (o.is_open() == false)
			throw std::runtime_error("failed to open file: " + path);

		auto size = static_cast<size_t>(filesize(o));
		if (size % sizeof(u64))
			throw RTE_LOC;

		auto s = size / sizeof(u64);
		if (s != exp.size())
			return false;

		std::vector<u64> vals(s);

		o.read((char*)vals.data(), size);

		std::unordered_set<u64> ss(vals.begin(), vals.end());

		if (ss.size() != s)
			throw RTE_LOC;

		for (u64 i = 0; i < exp.size(); ++i)
		{
			if (ss.find(exp[i]) == ss.end())
				return false;
		}
	}
	else 
	{
		std::ifstream file(path, std::ios::in);
		if (file.is_open() == false)
			throw std::runtime_error("failed to open file: " + path);

		std::unordered_set<u64> ss;

		while (file.eof() == false)
		{
			u64 i = -1;
			file >> i;

			if (ss.find(i) != ss.end())
				throw RTE_LOC;
			ss.insert(i);
		}

		for (u64 i = 0; i < exp.size(); ++i)
		{
			if (ss.find(exp[i]) == ss.end())
				return false;
		}
	}

	return true;
}

void filebase_readSet_Test()
{
	u64 ns = 34234;
	auto ft = FileType::Bin;
	std::string sFile = "./sFile_deleteMe";
	auto s = writeFile(sFile, 1, ns, ft);

	auto s2 = readSet(sFile, ft, true);

	if (s != s2)
		throw RTE_LOC;
}

void filebase_kkrt_bin_Test()
{
#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)

	u64 ns = 3124;
	u64 nr = 12352;
	auto ft = FileType::Bin;

	std::string sFile = "./sFile_deleteMe";
	std::string rFile = "./rFile_deleteMe";
	std::string oFile = "./oFile_deleteMe";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("kkrt");
	rCmd.set("kkrt");

	sCmd.set("bin");
	rCmd.set("bin");

	sCmd.set("debug");
	rCmd.set("debug");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);
	
	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, ft);

	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;

#endif
}

void filebase_kkrt_csv_Test()
{
#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)

	u64 ns = 34234;
	u64 nr = 24356;
	auto ft = FileType::Csv;

	std::string sFile = "./sFile_deleteMe";
	std::string rFile = "./rFile_deleteMe";
	std::string oFile = "./oFile_deleteMe";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("kkrt");
	rCmd.set("kkrt");

	sCmd.set("csv");
	rCmd.set("csv");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);

	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, ft);

	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;
#endif
}


void filebase_kkrt_csvh_Test()
{
#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)

	u64 ns = 34234;
	u64 nr = 24356;
	auto ft = FileType::Unspecified;

	std::string sFile = "./sFile_deleteMe";
	std::string rFile = "./rFile_deleteMe";
	std::string oFile = "./oFile_deleteMe";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("kkrt");
	rCmd.set("kkrt");

	sCmd.set("csv");
	rCmd.set("csv");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);

	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, FileType::Csv);

	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;

#endif
}

void filebase_rr17a_bin_Test()
{
#if defined(ENABLE_OOS) && defined(ENABLE_RR17_PSI)

	u64 ns = 3124;
	u64 nr = 12352;
	auto ft = FileType::Bin;

	std::string sFile = "./sFile_deleteMe";
	std::string rFile = "./rFile_deleteMe";
	std::string oFile = "./oFile_deleteMe";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("rr17a");
	rCmd.set("rr17a");

	sCmd.set("bin");
	rCmd.set("bin");

	sCmd.set("debug");
	rCmd.set("debug");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);

	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	rCmd.set("padSmallSet");
	sCmd.set("padSmallSet");

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, ft);

	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;
#endif
}

void filebase_ecdh_bin_Test()
{

#if defined(ENABLE_ECDH_PSI)

	u64 ns = 314;
	u64 nr = 122;
	auto ft = FileType::Bin;

	std::string sFile = "./sFile_deleteMe";
	std::string rFile = "./rFile_deleteMe";
	std::string oFile = "./oFile_deleteMe";

	auto s = writeFile(sFile, 1, ns, ft);
	auto r = writeFile(rFile, 2, nr, ft);
	auto i = setItersect(r, s);

	CLP sCmd, rCmd;
	sCmd.setDefault("server", "0");
	rCmd.setDefault("server", "1");

	sCmd.setDefault("r", "0");
	rCmd.setDefault("r", "1");

	sCmd.set("ecdh");
	rCmd.set("ecdh");

	sCmd.set("bin");
	rCmd.set("bin");

	sCmd.set("debug");
	rCmd.set("debug");

	sCmd.setDefault("senderSize", ns);
	rCmd.setDefault("senderSize", ns);

	sCmd.setDefault("receiverSize", nr);
	rCmd.setDefault("receiverSize", nr);

	rCmd.setDefault("in", rFile);
	sCmd.setDefault("in", sFile);

	rCmd.setDefault("out", oFile);

	rCmd.set("padSmallSet");
	sCmd.set("padSmallSet");

	auto f0 = std::async([&]() { doFilePSI(sCmd); });
	auto f1 = std::async([&]() { doFilePSI(rCmd); });

	f0.get();
	f1.get();

	bool passed = checkFile(oFile, i, ft);

	std::remove(sFile.c_str());
	std::remove(rFile.c_str());
	std::remove(oFile.c_str());

	if (!passed)
		throw RTE_LOC;
#endif
}

