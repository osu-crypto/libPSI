#pragma once
#include "Common/Defines.h"
#include <vector>
#include <array>
namespace libPSI {

	template<class T>
	class ArrayView
	{

		T* mData;
		u64 mSize;
		bool mOwner;
	public:
		typedef T* Iterator;


		ArrayView()
			:mData(nullptr),
			mSize(0),
			mOwner(false)
		{
		}

		ArrayView(const ArrayView& av) :
			mData(av.mData),
			mSize(av.mSize),
			mOwner(false)
		{ }

		ArrayView(ArrayView&& av) :
			mData(av.mData),
			mSize(av.mSize),
			mOwner(true)
		{
			av.mData = nullptr;
			av.mSize = 0;
			av.mOwner = false;
		}

		ArrayView(u64 size) :
			mData(new T[size]),
			mSize(size),
			mOwner(true)
		{ }

		ArrayView(T* data, u64 size, bool owner = false) :
			mData(data),
			mSize(size),
			mOwner(owner)
		{}

		//template<typename Container>
		
		template <class Iter>
		ArrayView(Iter start, Iter end, typename Iter::iterator_category *p = 0) :
			mData(&*start),
			mSize(end - start),
			mOwner(false)
		{
		}

		ArrayView(T* begin, T* end, bool owner) :
			mData(begin),
			mSize(end - begin),
			mOwner(owner)
		{}

		ArrayView(std::vector<T>& container)
			: mData(container.data()),
			mSize(container.size()),
			mOwner(false)
		{
		}

		template<u64 n>
		ArrayView(std::array<T,n>& container)
			: mData(container.data()),
			mSize(container.size()),
			mOwner(false)
		{
		}

		~ArrayView()
		{
			if (mOwner) delete[] mData;
		}


		const ArrayView<T>& operator=(const ArrayView<T>& copy)
		{
			mData = copy.mData;
			mSize = copy.mSize;
			mOwner = false;

			return copy;
		}


		u64 size() const { return mSize; }

		T* data() const { return mData; };

		Iterator begin() const { return mData; };
		Iterator end() const { return mData + mSize; }

		//T& operator[](int idx) { if (idx >= mSize) throw std::runtime_error(LOCATION); return mData[idx]; }
		T& operator[](u64 idx) const
		{
#ifndef NDEBUG
			if (idx >= mSize) throw std::runtime_error(LOCATION); 
#endif

			return mData[idx];
		}
	};

	template<typename T>
	ArrayView<T> makeArrayView(T* data, u64 size)
	{
		return ArrayView<T>(data, size);
	}
}