#include <fstream>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <string>
#include <vector>
#include <assert.h>

#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiSender.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"

#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libPSI/PSI/ECDH/EcdhPsiReceiver.h"
#include "libPSI/PSI/ECDH/EcdhPsiSender.h"

#include "libPSI/MPSI/DKT/DktMPsiReceiver.h"
#include "libPSI/MPSI/DKT/DktMPsiSender.h"

using namespace osuCrypto;

std::ifstream::pos_type filesize(std::ifstream& file)
{
	auto pos = file.tellg();
	file.seekg(0, std::ios_base::end);
	auto size = file.tellg();
	file.seekg(pos, std::ios_base::beg);
	return size;
}

bool hasSuffix(std::string const& value, std::string const& ending)
{
	if (ending.size() > value.size()) return false;
	return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

bool isHexBlock(const std::string& buff)
{
	if (buff.size() != 32)
		return false;
	auto ret = true;
	for (u64 i = 0; i < 32; ++i)
		ret &= std::isxdigit(buff[i]);
	return ret;
}
block hexToBlock(const std::string& buff)
{
	assert(buff.size() == 32);

	std::array<u8, 16> vv;
	char b[3];
	b[2] = 0;

	for (u64 i = 0; i < 16; ++i)
	{
		b[0] = buff[2 * i + 0];
		b[1] = buff[2 * i + 1];
		vv[15 - i] = (char)strtol(b, nullptr, 16);;
	}
	return toBlock(vv.data());
}

enum class FileType
{
	Bin,
	Csv,
	Unspecified
};

enum class Role {
	Sender = 0,
	Receiver = 1,
	Invalid
};

std::vector<block> readSet(const std::string& path, FileType ft)
{
	std::vector<block> ret;
	if (ft == FileType::Bin)
	{
		std::ifstream file(path, std::ios::binary | std::ios::in);
		if (file.is_open() == false)
			throw std::runtime_error("failed to open file: " + path);
		auto size = filesize(file);
		if (size % 16)
			throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

		ret.resize(size / 16);
		file.read((char*)ret.data(), size);
	}
	else if (ft == FileType::Csv)
	{
		// we will use this to hash large inputs
		RandomOracle hash(sizeof(block));

		std::ifstream file(path, std::ios::in);
		if (file.is_open() == false)
			throw std::runtime_error("failed to open file: " + path);
		std::string buffer;
		while (std::getline(file, buffer))
		{
			// if the input is already a 32 char hex 
			// value, just parse it as is.
			if (isHexBlock(buffer))
			{
				ret.push_back(hexToBlock(buffer));
			}
			else
			{
				ret.emplace_back();
				hash.Reset();
				hash.Update(buffer.data(), buffer.size());
				hash.Final(ret.back());
			}
		}
	}
	else
	{
		throw std::runtime_error("unknown file type");
	}

	return ret;
}

void writeOutput(std::string outPath, FileType ft, const std::vector<u64>& intersection)
{
	std::ofstream file;
	
	if (ft == FileType::Bin)
		file.open(outPath, std::ios::out | std::ios::trunc | std::ios::binary);
	else
		file.open(outPath, std::ios::out | std::ios::trunc);

	if (file.is_open() == false)
		throw std::runtime_error("failed to open the output file: " + outPath);

	if (ft == FileType::Bin)
	{
		file.write((char*)intersection.data(), intersection.size() * sizeof(u64));
	}
	else
	{
		for (auto i : intersection)
			file << i << "\n";
	}
}



void padSmallSet(std::vector<block>& set, u64& theirSize, const CLP& cmd)
{
	if (set.size() != theirSize)
	{
		if (cmd.isSet("padSmallSet") == false)
			throw std::runtime_error("This protocol currently requires equal set sizes. Use the -padSmallSet flag to add padding to the smaller set. Note that a malicious party can now have a larger set. If this is an problem feel free to open a github issue. ");

		if (set.size() < theirSize)
		{
			set.reserve(theirSize);
			PRNG prng(sysRandomSeed());
			while (set.size() != theirSize)
				set.push_back(prng.get<block>());
		}
		else
			theirSize = set.size();
	}
}

void doFilePSI(const CLP& cmd)
{
	try {
		auto path = cmd.get<std::string>("in");
		auto outPath = cmd.getOr<std::string>("out", path+".out");

		FileType ft = FileType::Unspecified;
		if (cmd.isSet("bin")) ft = FileType::Bin;
		if (cmd.isSet("csv")) ft = FileType::Csv;
		if (ft == FileType::Unspecified)
		{
			if(hasSuffix(path, ".bin"))
				ft = FileType::Bin;
			else if (hasSuffix(path, ".csv"))
				ft = FileType::Csv;
		}
		if (ft == FileType::Unspecified)
			throw std::runtime_error("unknown file extension, must be .csv or .bin or you must specify the -bin or -csv flags.");

		std::vector<block> set = readSet(path, ft);

		auto ip = cmd.getOr<std::string>("ip", "localhost:1212");
		auto r = (Role)cmd.getOr<int>("r", 2);
		if (r != Role::Sender && r != Role::Receiver)
			throw std::runtime_error("-r tag must be set with value 0 (sender) or 1 (receiver).");

		auto isServer = cmd.getOr<int>("server", (int)r);
		if (r != Role::Sender && r != Role::Receiver)
			throw std::runtime_error("-server tag must be set with value 0 or 1.");

		auto mode = isServer ? SessionMode::Server : SessionMode::Client;
		IOService ios;
		Session ses(ios, ip, mode);
		Channel chl = ses.addChannel();

		if (!chl.waitForConnection(std::chrono::milliseconds(1000)))
		{
			std::cout << "waiting for connection" << std::flush;
			while (!chl.waitForConnection(std::chrono::milliseconds(1000)))
				std::cout << "." << std::flush;
			std::cout << " done" << std::endl;
		}

		if (set.size() != cmd.getOr((r == Role::Sender) ? "senderSize" : "receiverSize", set.size()))
			throw std::runtime_error("File does not contain the specified set size.");

		u64 theirSize;
		chl.send(set.size());
		chl.recv(theirSize);
		if (theirSize != cmd.getOr((r != Role::Sender) ? "senderSize" : "receiverSize", theirSize))
			throw std::runtime_error("Other party's set size does not match.");

		u64 statSetParam = cmd.getOr("ssp", 40);

		if (cmd.isSet("kkrt"))
		{
#if defined(ENABLE_KKRT) && defined(ENABLE_KKRT_PSI)
			if (r == Role::Sender)
			{
				KkrtNcoOtSender ot;
				KkrtPsiSender sender;
				sender.init(set.size(), theirSize, statSetParam, chl, ot, sysRandomSeed());
				sender.sendInput(set, chl);
			}
			else
			{

				KkrtNcoOtReceiver ot;
				KkrtPsiReceiver recver;
				recver.init(theirSize, set.size(), statSetParam, chl, ot, sysRandomSeed());
				recver.sendInput(set, chl);
				writeOutput(outPath, ft, recver.mIntersection);
			}
#else 
			throw std::runtime_error("ENABLE_KKRT_PSI not defined.");
#endif
		}
		else if (cmd.isSet("rr17a"))
		{
#if defined(ENABLE_OOS) && defined(ENABLE_RR17_PSI)
			padSmallSet(set, theirSize, cmd);

			if (r == Role::Sender)
			{
				OosNcoOtSender ots;
				OosNcoOtReceiver otr;
				Rr17aMPsiSender sender;
				sender.init(set.size(),statSetParam, chl, ots, otr, sysRandomSeed());
				sender.sendInput(set, chl);
			}
			else
			{
				OosNcoOtSender ots;
				OosNcoOtReceiver otr;
				Rr17aMPsiReceiver recver;
				recver.init(set.size(), statSetParam, chl, otr, ots, sysRandomSeed());
				recver.sendInput(set, chl);
				writeOutput(outPath, ft, recver.mIntersection);
			}
#else 
			throw std::runtime_error("ENABLE_RR17_PSI not defined.");
#endif
		}
		else if (cmd.isSet("ecdh"))
		{
#ifdef ENABLE_ECDH_PSI
			padSmallSet(set, theirSize, cmd);

			if (r == Role::Sender)
			{
				EcdhPsiSender sender;
				sender.init(set.size(), statSetParam, sysRandomSeed());
				sender.sendInput(set, span<Channel>{&chl, 1});
			}
			else
			{
				EcdhPsiReceiver recver;
				recver.init(set.size(), statSetParam, sysRandomSeed());
				recver.sendInput(set, span<Channel>{&chl, 1});
				writeOutput(outPath, ft, recver.mIntersection);
			}
#else 
			throw std::runtime_error("ENABLE_ECDH_PSI not defined.");
#endif
		}
		//else if (cmd.isSet("dkt"))
		//{
		//	
		//	padSmallSet(set, theirSize, cmd);

		//	if (r == Role::Sender)
		//	{
		//		DktMPsiSender sender;
		//		sender.init(set.size(), statSetParam, sysRandomSeed());
		//		sender.sendInput(set, span<Channel>{&chl, 1});
		//	}
		//	else
		//	{
		//		DktMPsiReceiver recver;
		//		recver.init(set.size(), statSetParam, sysRandomSeed());
		//		recver.sendInput(set, span<Channel>{&chl, 1});
		//		writeOutput(outPath, ft, recver.mIntersection);
		//	}
		//}
		else
		{
			throw std::runtime_error("Please add one of the protocol flags, -kkrt, -rr17a, -ecdh");
		}

	}
	catch (std::exception & e)
	{
		std::cout << Color::Red << "Exception: " << e.what() << std::endl << Color::Default;
	}
}
