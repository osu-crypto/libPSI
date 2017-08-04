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

        TEST_METHOD(CuckooHasher_Test)
        {
            InitDebugPrinting();
            CuckooHasher_Test_Impl();
        }

        TEST_METHOD(CuckooHasher_parallel_Test)
        {
            InitDebugPrinting();
            CuckooHasher_parallel_Test_Impl();
        }

        TEST_METHOD(Psi_kkrt_EmptrySet_Test)
        {
            InitDebugPrinting();
            Psi_kkrt_EmptySet_Test_Impl();
        }

        TEST_METHOD(Psi_kkrt_FullSet_Test)
        {
            InitDebugPrinting();
            Psi_kkrt_FullSet_Test_Impl();
        }

        TEST_METHOD(Psi_kkrt_SingltonSet_Test)
        {
            InitDebugPrinting();
            Psi_kkrt_SingletonSet_Test_Impl();
        }

        TEST_METHOD(Rr17a_Oos_EmptrySet_Test)
        {
            InitDebugPrinting();
            Rr17a_Oos_EmptrySet_Test_Impl();
        }

        TEST_METHOD(Rr17a_Oos_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17a_Oos_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17a_Oos_parallel_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17a_Oos_parallel_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17a_Oos_SingltonSet_Test)
        {
            InitDebugPrinting();
            Rr17a_Oos_SingltonSet_Test_Impl();
        }


        TEST_METHOD(Rr17a_SM_EmptrySet_Test)
        {
            InitDebugPrinting();
            Rr17a_SM_EmptrySet_Test_Impl();
        }

        TEST_METHOD(Rr17a_SM_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17a_SM_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17a_SM_parallel_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17a_SM_parallel_FullSet_Test_Impl();
        }
        
        TEST_METHOD(Rr17b_Oos_SingltonSet_Test)
        {
            InitDebugPrinting();
            Rr17b_Oos_SingltonSet_Test_Impl();
        }

        TEST_METHOD(Rr17b_Oos_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17b_Oos_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17b_Oos_parallel_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17b_Oos_parallel_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17b_Oos_EmptrySet_Test)
        {
            InitDebugPrinting();
            Rr17b_Oos_EmptrySet_Test_Impl();
        }

        TEST_METHOD(Rr17b_SM_SingltonSet_Test)
        {
            InitDebugPrinting();
            Rr17b_SM_SingltonSet_Test_Impl();
        }

        TEST_METHOD(Rr17b_SM_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17b_SM_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17b_SM_parallel_FullSet_Test)
        {
            InitDebugPrinting();
            Rr17b_SM_parallel_FullSet_Test_Impl();
        }

        TEST_METHOD(Rr17b_SM_EmptrySet_Test)
        {
            InitDebugPrinting();
            Rr17b_SM_EmptrySet_Test_Impl();
        }

    };
}