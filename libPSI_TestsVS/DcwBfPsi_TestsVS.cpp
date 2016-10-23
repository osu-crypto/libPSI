#include "stdafx.h"
#include "CppUnitTest.h"
#include "DcwBfPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(DcwBfPsi_Tests)
    {
    public:

        TEST_METHOD(DcwBfPsi_EmptrySet_Test)
        {
            InitDebugPrinting();
            DcwBfPsi_EmptrySet_Test_Impl();
        }

        TEST_METHOD(DcwBfPsi_FullSet_Test)
        {
            InitDebugPrinting();
            DcwBfPsi_FullSet_Test_Impl();
        }

        TEST_METHOD(DcwBfPsi_SingltonSet_Test)
        {
            InitDebugPrinting();
            DcwBfPsi_SingltonSet_Test_Impl();
        }
        TEST_METHOD(DcwRBfPsi_EmptrySet_Test)
        {
            InitDebugPrinting();
            DcwRBfPsi_EmptrySet_Test_Impl();
        }

        TEST_METHOD(DcwRBfPsi_FullSet_Test)
        {
            InitDebugPrinting();
            DcwRBfPsi_FullSet_Test_Impl();
        }

        TEST_METHOD(DcwRBfPsi_SingltonSet_Test)
        {
            InitDebugPrinting();
            DcwRBfPsi_SingltonSet_Test_Impl();
        }

    };
}