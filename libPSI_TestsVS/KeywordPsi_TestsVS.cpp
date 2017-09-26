#include "stdafx.h"
#include "CppUnitTest.h"
#include "KeywordPsi_Tests.h"
#include "Common.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace KeywordPsiTests
{
	TEST_CLASS(KeywordPsi_Tests)
	{
	public:


		TEST_METHOD(Psi_Keyword_SingletonSet_Test)
		{
			InitDebugPrinting();
			Psi_Keyword_SingletonSet_Test_Impl();
		}

		TEST_METHOD(Psi_Keyword_FullSet_Test)
		{
			InitDebugPrinting();
			Psi_Keyword_FullSet_Test_Impl();
		}

		TEST_METHOD(Psi_Keyword_EmptySet_Test)
		{
			InitDebugPrinting();
			Psi_Keyword_EmptySet_Test_Impl();
		}

	};
}