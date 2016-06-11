#include "Common/Log.h"
#include <functional>

#include "AES_Tests.h"
#include "AknBfPsi_Tests.h"
#include "AknOt_Tests.h"
#include "BtChannel_Tests.h"
//#include "nkOt_Tests.h"
#include "BaseOT_Tests.h"
#include "OT_Tests.h"
#include "AknOt_Tests.h"
#include "AknBfPsi_Tests.h"


#include "ShamirSSScheme_Tests.h"
#include "DcwBfPsi_Tests.h"

using namespace libPSI;

void run(std::string name, std::function<void(void)> func)
{
	Log::out << name;

	auto start = std::chrono::high_resolution_clock::now();
	try
	{
		func(); Log::out << Log::Color::Green << "  Passed" << Log::ColorDefault;
	}
	catch (const std::exception& e)
	{
		Log::out << Log::Color::Red << "Failed - " << e.what() << Log::ColorDefault;
	}

	auto end = std::chrono::high_resolution_clock::now();

	u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

	Log::out << "   " << time << "ms" << Log::endl;


	if (Log::out.mSink != &std::cout)
		throw std::runtime_error("");
}


void NetWork_all()
{
	Log::out << Log::endl;
	run("BtNetwork_Connect1_Boost_Test        ", BtNetwork_Connect1_Boost_Test);
	run("BtNetwork_OneMegabyteSend_Boost_Test ", BtNetwork_OneMegabyteSend_Boost_Test);
	run("BtNetwork_ConnectMany_Boost_Test     ", BtNetwork_ConnectMany_Boost_Test);
	run("BtNetwork_CrossConnect_Test          ", BtNetwork_CrossConnect_Test);
	run("BtNetwork_ManyEndpoints_Test         ", BtNetwork_ManyEndpoints_Test);

}

void bitVec_all()
{
	Log::out << Log::endl;
	run("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
	run("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
	run("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
	run("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);
}

void OT_all()
{
	Log::out << Log::endl;

	run("Transpose_Test_Impl                     ", Transpose_Test_Impl);
	run("KosOtExt_100Receive_Test_Impl           ", KosOtExt_100Receive_Test_Impl);
	run("IknpOtExt_100Receive_Test_Impl          ", IknpOtExt_100Receive_Test_Impl);
	run("AknOt_sendRecv1000_Test                 ", AknOt_sendRecv1000_Test);
	run("NaorPinkasOt_Test                       ", NaorPinkasOt_Test_Impl);
}

void DcwPsi_all()
{
	Log::out << Log::endl;
	run("DcwPsi_EmptrySet_Test_Impl              ", DcwBfPsi_EmptrySet_Test_Impl);
	run("DcwPsi_FullSet_Test_Impl                ", DcwBfPsi_FullSet_Test_Impl);
	run("DcwPsi_SingltonSet_Test_Imp             ", DcwBfPsi_SingltonSet_Test_Impl);
}

void AknBfPsi_all()
{
	Log::out << Log::endl;
	run("AknBfPsi_EmptrySet_Test_Impl            ", AknBfPsi_EmptrySet_Test_Impl);
	run("AknBfPsi_FullSet_Test_Impl              ", AknBfPsi_FullSet_Test_Impl);
	run("AknBfPsi_SingltonSet_Test_Impl          ", AknBfPsi_SingltonSet_Test_Impl);
}
void ShamirSSScheme_all()
{
	Log::out << Log::endl;
	run("ShamirSSScheme_GF2X_Test                 ", ShamirSSScheme_Test);
}

void run_all()
{
	//AES128_all();
	NetWork_all();
	OT_all();
	AknBfPsi_all();
	//ShamirSSScheme_all();
	DcwPsi_all();
}
