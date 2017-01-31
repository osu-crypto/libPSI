#pragma once

#include <unordered_map>
#include <set>
#include <list>
#include <vector>

class CommandLineParserError : public std::exception
{

};

class CLP
{
public:

    std::string mProgramName;
    std::unordered_map<std::string, std::list<std::string>> mKeyValues;

    void parse(int argc, char** argv);

    void setDefault(std::string key, std::string value);
    void setDefault(std::vector<std::string> keys, std::string value);

    bool isSet(std::string name);
    bool isSet(std::vector<std::string> names);

    bool hasValue(std::string name);
    bool hasValue(std::vector<std::string> names);


    template<typename T>
    T get(const std::string& name)
    {
        std::stringstream ss;
        ss << *mKeyValues[name].begin();

        T ret;
        ss >> ret;

        return ret;
    }

    template<typename T>
    T get(const std::vector<std::string>& names, const std::string& failMessage = "")
    {
        for (auto name : names)
        {
            if (hasValue(name))
            {
                return get<T>(name);
            }
        }

        if (failMessage != "")
            std::cout << failMessage << std::endl;

        throw CommandLineParserError();
    }

    template<typename T>
    std::vector<T> getMany(const std::string& name)
    {

        std::vector<T> ret(mKeyValues[name].size());

        auto iter = mKeyValues[name].begin();

        for (u64 i = 0; i < ret.size(); ++i)
        {
            std::stringstream ss(*iter++);
            ss >> ret[i];
        }

        return ret;
    }

    template<typename T>
    std::vector<T> getMany(const std::vector<std::string>& names)
    {
        for (auto name : names)
        {
            if (hasValue(name))
            {
                return getMany<T>(name);
            }
        }

        throw CommandLineParserError();
    }


    template<typename T>
    std::vector<T> getMany(const std::vector<std::string>& names, const std::string& failMessage)
    {
        for (auto name : names)
        {
            if (hasValue(name))
            {
                return getMany<T>(name);
            }
        }

        if (failMessage != "")
            std::cout << failMessage << std::endl;

        throw CommandLineParserError();
    }

    //double getDouble(std::string name);
    //double getDouble(std::vector<std::string> names, std::string failMessage = "");

    //std::vector<int> getInts(const std::string& name);
    //std::vector<int> getInts(const std::vector<std::string>& names);

    //std::string getString(std::string name);
    //std::list<std::string> getStrings(std::string name);

    //std::string getString(std::vector<std::string> names, std::string failMessage = "");
    //std::list<std::string> getStrings(std::vector<std::string> names, std::string failMessage = "");
};

