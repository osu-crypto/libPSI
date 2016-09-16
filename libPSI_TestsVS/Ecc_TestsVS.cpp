#include "stdafx.h"
#ifdef  _MSC_VER
#include "CppUnitTest.h"

#include "Ecc_Tests.h"
#include "Common.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace libPSI_tests
{
	TEST_CLASS(LocalChannel_Tests)
	{
	public:

		TEST_METHOD(Ecc_Number_TestVS)
		{
			InitDebugPrinting();
			EccNumber_Test();
		}

		TEST_METHOD(Eccp_Point_TestVS)
		{
			InitDebugPrinting();
			EccpPoint_Test();
		}

	};
}
#endif
