#include "stdafx.h"
#include "CppUnitTest.h"
#include "DrrnPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(OtBinPsi_Tests)
    {
    public:


        TEST_METHOD(Psi_drrn_SingletonSet_Test)
        {
            InitDebugPrinting();
            Psi_drrn_SingletonSet_Test_Impl();
        }


        TEST_METHOD(Psi_drrn_FullSet_Test)
        {
            InitDebugPrinting();
            Psi_drrn_FullSet_Test_Impl();
        }

		TEST_METHOD(Psi_drrn_EmptySet_Test)
		{
			InitDebugPrinting();
			Psi_drrn_EmptySet_Test_Impl();
		}

    };
}