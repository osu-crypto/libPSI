#include "stdafx.h"
#include "CppUnitTest.h"
#include "DktMPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(DktMPsi_Tests)
    {
    public:

        TEST_METHOD(DktMPsi_EmptrySet_Test)
        {
            InitDebugPrinting();
            DktMPsi_EmptrySet_Test_Impl();
        }

        TEST_METHOD(DktMPsi_FullSet_Test)
        {
            InitDebugPrinting();
            DktMPsi_FullSet_Test_Impl();
        }

        TEST_METHOD(DktMPsi_SingltonSet_Test)
        {
            InitDebugPrinting();
            DktMPsi_SingltonSet_Test_Impl();
        }


        //TEST_METHOD(DktMPsi_SingltonSet_serial_Test)
        //{
        //    InitDebugPrinting();
        //    DktMPsi_SingltonSet_serial_Test_Impl();
        //}
    };
}