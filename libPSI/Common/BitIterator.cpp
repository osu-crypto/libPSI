#include "BitIterator.h"

namespace libPSI
{

	BitReference::operator u8() const
	{
		return (*mByte & mMask) >> mShift;
	}

}