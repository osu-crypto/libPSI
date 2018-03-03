#include "stdafx.h"
#include "CppUnitTest.h"
#include "EcdhPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(EcdhPsi_Tests)
    {
    public:

        TEST_METHOD(EcdhPsi_EmptrySet_Test)
        {
            InitDebugPrinting();
            EcdhPsi_EmptrySet_Test_Impl();
        }


        TEST_METHOD(EcdhPsi_FullSet_Test)
        {
            InitDebugPrinting();
            EcdhPsi_FullSet_Test_Impl();
        }

        TEST_METHOD(EcdhPsi_SingltonSet_Test)
        {
            InitDebugPrinting();
            EcdhPsi_SingltonSet_Test_Impl();
        }


        //TEST_METHOD(EcdhPsi_SingltonSet_serial_Test)
        //{
        //    InitDebugPrinting();
        //    EcdhPsi_SingltonSet_serial_Test_Impl();
        //}
    };
}