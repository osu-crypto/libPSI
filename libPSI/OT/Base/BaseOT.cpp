
#include "BaseOT.h"
namespace libPSI
{


	thread_local Miracl* precision2;// = []() { return new Miracl(50, 0); }();
	static bool Miracl_threading_Init = []()
	{
		mr_init_threading();
		return true;
	}();


	Miracl* GetPrecision()
	{
		return GetPrecision(283, 2);
	}

	Miracl* GetPrecision(int bit, int b)
	{
		if (!precision2)
		{
			precision2 = new Miracl(bit, b);
		}
		return precision2;
	}

	void deletePercision()
	{
		if (precision2)
		{
			delete precision2;
			precision2 = nullptr;
		}
	}
}
