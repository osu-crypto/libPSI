#include "stdafx.h"
#include "CppUnitTest.h"
#include "BinOtPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(OtBinPsi_Tests)
    {
    public:

        TEST_METHOD(OtBinPsi_EmptrySet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_EmptrySet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_FullSet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_FullSet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_SingltonSet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_SingltonSet_Test_Impl();
        }


        //TEST_METHOD(OtBinPsi_SingltonSet_serial_Test)
        //{
        //    InitDebugPrinting();
        //    OtBinPsi_SingltonSet_serial_Test_Impl();
        //}
    };
}