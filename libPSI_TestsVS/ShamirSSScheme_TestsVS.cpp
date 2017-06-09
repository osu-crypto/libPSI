#include "stdafx.h"
#ifdef  _MSC_VER
#ifdef ENABLE_DCW

#include "CppUnitTest.h"

#include "ShamirSSScheme_Tests.h"

#include "Common.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace osuCrypto_tests
{
    TEST_CLASS(ShamirSSScheme_Tests)
    {
    public:
        TEST_METHOD(ShamirSSScheme_TestVS)
        {
            InitDebugPrinting();

            ShamirSSScheme_Test(); 
        }


    };
}
#endif
#endif
