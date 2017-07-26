#include "stdafx.h"
#include "CppUnitTest.h"
#include "BgiPirTests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace testsVS_apollo
{
    TEST_CLASS(BgiPirTests)
    {
    public:

        TEST_METHOD(BgiPir_keyGen_testVS)
        {
            InitDebugPrinting();
            BgiPir_keyGen_test();
        }

        TEST_METHOD(BgiPir_keyGen_128_testVS)
        {
            InitDebugPrinting();
            BgiPir_keyGen_128_test();
        }

        TEST_METHOD(BgiPir_PIR_testVS)
        {
            InitDebugPrinting();
            BgiPir_PIR_test();
        }

        TEST_METHOD(BgiPir_FullDomain_testVS)
        {
            InitDebugPrinting();
			BgiPir_FullDomain_test();
        }

		TEST_METHOD(BgiPir_FullDomain_iterator_testVS)
		{
			InitDebugPrinting();
			BgiPir_FullDomain_iterator_test();
		}

		TEST_METHOD(BgiPir_FullDomain_multikey_testVS)
		{
			InitDebugPrinting();
			BgiPir_FullDomain_multikey_test();
		}
    };
}