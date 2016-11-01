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

        TEST_METHOD(OtBinPsi_CuckooHasher_Test)
        {
            InitDebugPrinting();
            OtBinPsi_CuckooHasher_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_Kkrt_EmptrySet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_Kkrt_EmptrySet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_Kkrt_FullSet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_Kkrt_FullSet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_Kkrt_SingltonSet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_Kkrt_SingltonSet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_Oos_EmptrySet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_Oos_EmptrySet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_Oos_FullSet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_Oos_FullSet_Test_Impl();
        }

        TEST_METHOD(OtBinPsi_Oos_SingltonSet_Test)
        {
            InitDebugPrinting();
            OtBinPsi_Oos_SingltonSet_Test_Impl();
        }

        //TEST_METHOD(OtBinPsi_SingltonSet_serial_Test)
        //{
        //    InitDebugPrinting();
        //    OtBinPsi_SingltonSet_serial_Test_Impl();
        //}
    };
}