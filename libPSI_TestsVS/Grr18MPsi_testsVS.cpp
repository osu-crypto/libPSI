#include "stdafx.h"
#include "CppUnitTest.h"
#include "Grr18MPSI_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace WeGarbleTests
{
    TEST_CLASS(Grr18MPsi_Tests)
    {
    public:


        TEST_METHOD(Grr18_Oos_EmptrySet_Test)
        {
            InitDebugPrinting();
            Grr18_Oos_EmptrySet_Test_Impl();
        }

        TEST_METHOD(Grr18_Oos_FullSet_Test)
        {
            InitDebugPrinting();
            Grr18_Oos_FullSet_Test_Impl();
        }

        TEST_METHOD(Grr18_Oos_parallel_FullSet_Test)
        {
            InitDebugPrinting();
            Grr18_Oos_parallel_FullSet_Test_Impl();
        }

        TEST_METHOD(Grr18_Oos_SingltonSet_Test)
        {
            InitDebugPrinting();
            Grr18_Oos_SingltonSet_Test_Impl();
        }
    };
}