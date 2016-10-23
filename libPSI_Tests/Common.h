#pragma once
#include <string>

//
void InitDebugPrinting(std::string file = "../../testout.txt");
//
 extern std::string SolutionDir;

class UnitTestFail : public std::exception
{
    std::string mWhat;
public:
    explicit UnitTestFail(std::string reason)
        :std::exception(),
        mWhat(reason)
    {}

    explicit UnitTestFail()
        :std::exception(),
        mWhat("UnitTestFailed exception")
    {
    }

    virtual  const char* what() const throw()
    {
        return mWhat.c_str();
    }
};

