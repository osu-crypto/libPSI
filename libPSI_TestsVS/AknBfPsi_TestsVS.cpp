#include "stdafx.h"
#include "CppUnitTest.h"
#include "AknBfPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(AknBfPsi_Tests)
    {
    public:

        TEST_METHOD(AknBfPsi_EmptrySet_Test)
        {
            InitDebugPrinting();
            AknBfPsi_EmptrySet_Test_Impl();
        }

        TEST_METHOD(AknBfPsi_FullSet_Test)
        {
            InitDebugPrinting();
            AknBfPsi_FullSet_Test_Impl();
        }

        TEST_METHOD(AknBfPsi_SingltonSet_Test)
        {
            InitDebugPrinting();
            AknBfPsi_SingltonSet_Test_Impl();
        }


        //TEST_METHOD(AknBfPsi_SingltonSet_serial_Test)
        //{
        //    InitDebugPrinting();
        //    AknBfPsi_SingltonSet_serial_Test_Impl();
        //}
    };
}