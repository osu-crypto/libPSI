#pragma once
#include "Common/Defines.h"
#include <array>
#include "Common/ArrayView.h"


namespace osuCrypto
{


    template<class T>
    class MatrixView
    {

        T* mData;

        // Matrix is index by [rowIdx][columnIdx]
        std::array<u64,2> mSize;
        bool mOwner;

    public:
        typedef T* Iterator;


        MatrixView()
            :mData(nullptr),
            mSize({0,0}),
            mOwner(false)
        {
        }

        MatrixView(const MatrixView& av) :
            mData(av.mData),
            mSize(av.mSize),
            mOwner(false)
        { }

        MatrixView(MatrixView&& av) :
            mData(av.mData),
            mSize(av.mSize),
            mOwner(av.mOwner)
        {
            av.mData = nullptr;
            av.mSize = {0,0};
            av.mOwner = false;
        }


        MatrixView(u64 rowSize, u64 columnSize) :
            mData(new T[rowSize * columnSize]),
            mSize({ rowSize, columnSize }),
            mOwner(true)
        { }


        MatrixView(T* data, u64 rowSize, u64 columnSize, bool owner) :
            mData(data),
            mSize({ rowSize, columnSize }),
            mOwner(owner)
        {}

        template <class Iter>
        MatrixView(Iter start, Iter end, u64 numColumns, typename Iter::iterator_category *p = 0) :
            mData(&*start),
            mSize({ (end - start) / numColumns, numColumns }),
            mOwner(false)
        {
        }

        //MatrixView(T* data, u64 rowSize, u64 columnSize) :
        //    mData(data),
        //    mSize({ rowSize, columnSize }),
        //    mOwner(false)
        //{}


        ~MatrixView()
        {
            if (mOwner) delete[] mData;
        }

        const MatrixView<T>& operator=(MatrixView<T>&& copy)
        {
            if (mOwner) delete[] mData;

            mData = copy.mData;
            mSize = copy.mSize;
            mOwner = copy.mOwner;

            copy.mData = nullptr;
            copy.mSize = std::array<u64, 2>{0,0};
            copy.mOwner = false;

            return copy;
        }

        const MatrixView<T>& operator=(const MatrixView<T>& copy)
        {

            mData = copy.mData;
            mSize = copy.mSize;
            mOwner = false;

            return copy;
        }

        const std::array<u64, 2>& size() const { return mSize; }
        T* data() const { return mData; };

        Iterator begin() const { return mData; };
        Iterator end() const { return mData + mSize; }

        ArrayView<T> operator[](u64 rowIdx) const
        {
#ifndef NDEBUG
            if (rowIdx >= mSize[0]) throw std::runtime_error(LOCATION);
#endif

            return ArrayView<T>(mData + rowIdx * mSize[1], mSize[1]);
        }

    };
}

