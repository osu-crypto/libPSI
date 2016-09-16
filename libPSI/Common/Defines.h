#pragma once

#include <cinttypes>
#include <iomanip>
#include <vector>
#include <sstream>
#include <iostream>
#include "boost/lexical_cast.hpp"
#include <emmintrin.h>
#include <smmintrin.h>
#include <memory>
#include "Common/Timer.h"
//#include <mmintrin.h>
//#include <xmmintrin.h>
#ifdef GetMessage
#undef GetMessage
#endif

#ifdef _MSC_VER 
#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define TODO(x) __pragma(message (__FILE__ ":"__STR1__(__LINE__) " Warning:TODO - " #x))
#define ALIGNED(__Declaration, __alignment) __declspec(align(__alignment)) __Declaration 
#else
//#if defined(__llvm__)
#define TODO(x) 
//#else
//#define TODO(x) DO_PRAGMA( message ("Warning:TODO - " #x))
//#endif

#define ALIGNED(__Declaration, __alignment) __Declaration __attribute__((aligned (16)))
#endif

#define STRINGIZE_DETAIL(x) #x
#define STRINGIZE(x) STRINGIZE_DETAIL(x)
#define LOCATION __FILE__ ":" STRINGIZE(__LINE__)


namespace libPSI {
	template<typename T> using ptr = T*;
	template<typename T> using uPtr = std::unique_ptr<T>;
	template<typename T> using sPtr = std::shared_ptr<T>;

	typedef uint64_t u64;
	typedef int64_t i64;
	typedef uint32_t u32;
	typedef int32_t i32;
	typedef uint16_t u16;
	typedef int16_t i16;
	typedef uint8_t u8;
	typedef int8_t i8;

	enum Role
	{
		First = 0,
		Second = 1
	};

	extern Timer gTimer;
	template<typename T>
	static std::string ToString(const T& t)
	{
		return boost::lexical_cast<std::string>(t);
	}

	typedef  __m128i block;
	inline block toBlock(u8*data)
	{ return _mm_set_epi64x(((u64*)data)[0], ((u64*)data)[1]);}

	

struct blockRIOT
	{
		block elem[4];
		//u64 elem3;

		inline  blockRIOT operator=(blockRIOT blk512)
		{
			elem[0] = blk512.elem[0];
			elem[1] = blk512.elem[1];
			elem[2] = blk512.elem[2];
			elem[3] = blk512.elem[3];
			return *this;
		}
		

	};

#ifdef _MSC_VER
	inline block operator^(const block& lhs, const block& rhs)
	{
		return _mm_xor_si128(lhs, rhs);
	}
	inline block operator&(const block& lhs, const block& rhs)
	{
		return _mm_and_si128(lhs, rhs);
	}

	inline block operator<<(const block& lhs, const u8& rhs)
	{
		return _mm_slli_epi64(lhs, rhs);
	}
	inline block operator>>(const block& lhs, const u8& rhs)
	{
		return _mm_srli_epi64(lhs, rhs);
	}
	inline block operator+(const block& lhs, const block& rhs)
	{
		return _mm_add_epi64(lhs, rhs);
	}

	
#endif
	inline blockRIOT operator^(const blockRIOT& lhs, const blockRIOT& rhs)
	{
		blockRIOT rs;
		rs.elem[0] = lhs.elem[0] ^ rhs.elem[0];
		rs.elem[1] = lhs.elem[1] ^ rhs.elem[1];
		rs.elem[2] = lhs.elem[2] ^ rhs.elem[2];
		rs.elem[3] = lhs.elem[3] ^ rhs.elem[3];
		return rs;
	}

	inline blockRIOT operator&(const blockRIOT& lhs, const blockRIOT& rhs)
	{
		blockRIOT rs;
		rs.elem[0] = lhs.elem[0] & rhs.elem[0];
		rs.elem[1] = lhs.elem[1] & rhs.elem[1];
		rs.elem[2] = lhs.elem[2] & rhs.elem[2];
		rs.elem[3] = lhs.elem[3] & rhs.elem[3];
		//rs.elem3 = lhs.elem3&rhs.elem3;
		return rs;
	}

	extern const block ZeroBlock;
	extern const block OneBlock;
	extern const block AllOneBlock;
	extern const block CCBlock;

	inline u64 roundUpTo(u64 val, u64 step)
	{
		return ((val + step - 1) / step) * step;
	}

	inline u8* ByteArray(const block& b)
	{
		return ((u8 *)(&b));
	}
	inline u8* ByteArray(const blockRIOT& b)
	{
		return ((u8 *)(&b));
	}

	std::ostream& operator<<(std::ostream& out, const block& block);
	std::ostream& operator<<(std::ostream& out, const blockRIOT& block);

	class Commit;
	class BitVector;

	std::ostream& operator<<(std::ostream& out, const Commit& comm);
	//std::ostream& operator<<(std::ostream& out, const BitVector& vec);
	//typedef block block;

	block PRF(const block& b, u64 i);


	template <u32 N> struct Unroll {
		template <typename F> static void call(F const& f) {
			f(N - 1);
			Unroll<N - 1>::call(f);
		}
	};

	template <> struct Unroll < 0u > {
		template <typename F> static void call(F const&) {}
	};

	void split(const std::string &s, char delim, std::vector<std::string> &elems);
	std::vector<std::string> split(const std::string &s, char delim);


	u64 log2ceil(u64);
	u64 log2floor(u64);

}

inline bool eq(const libPSI::block& lhs, const libPSI::block& rhs)
{
	libPSI::block neq = _mm_xor_si128(lhs, rhs);
	return _mm_test_all_zeros(neq, neq) != 0;
}

inline bool neq(const libPSI::block& lhs, const libPSI::block& rhs)
{
	libPSI::block neq = _mm_xor_si128(lhs, rhs);
	return _mm_test_all_zeros(neq, neq) == 0;
}

inline bool neq(const libPSI::blockRIOT& lhs, const libPSI::blockRIOT& rhs)
{
	libPSI::blockRIOT neq = lhs^ rhs;
	return _mm_test_all_zeros(neq.elem[0], neq.elem[0]) == 0 || _mm_test_all_zeros(neq.elem[0], neq.elem[0]) == 0
|| _mm_test_all_zeros(neq.elem[0], neq.elem[0]) == 0|| _mm_test_all_zeros(neq.elem[0], neq.elem[0]) == 0;
}


#ifdef _MSC_VER
inline bool operator==(const libPSI::block& lhs, const libPSI::block& rhs)
{
	return eq(lhs, rhs);
}

inline bool operator!=(const libPSI::block& lhs, const libPSI::block& rhs)
{
	return neq(lhs, rhs);
}
inline bool operator<(const libPSI::block& lhs, const libPSI::block& rhs)
{
	return lhs.m128i_u64[1] < rhs.m128i_u64[1] || (eq(lhs, rhs) && lhs.m128i_u64[0] < rhs.m128i_u64[0]);
}


#endif
//typedef struct largeBlock {
//
//} largeBlock;
//typedef  std::array<block, 4>  blockRIOT;

//
//#ifdef _MSC_VER // if Visual C/C++
//__inline __m64 _mm_set_pi64x(const __int64 i) {
//	union {
//		__int64 i;
//		__m64 v;
//	} u;
//
//	u.i = i;
//	return u.v;
//}
//#endif
