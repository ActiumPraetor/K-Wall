/*
  Simple Configuration File Parser
  Written by "sarmanu" and posted at dreamincode.net

  Full article:
  "Create A Simple Configuration File Parser."
  http://www.dreamincode.net/forums/topic/183191-create-a-simple-configuration-file-parser/

  PLEASE NOTE that while a usage license has not been provided by "sarmanu," he or she is still
  considered the owner of Copyright to this sourcecode.

  Updated by ActiumPraetor to add widestring support for K*Wall
*/

#include "stdafx.h"

#include <iostream>
#include <string>
#include <sstream>
#include <map>
#include <fstream>
#include <codecvt>


class Convert
{
public:
	template <typename T>
	static std::string T_to_wstring(T const &val) 
	{
		std::ostringstream ostr;
		ostr << val;

		return ostr.str();
	}
		
	template <typename T>
	static T wstring_to_T(std::wstring const &val) 
	{
		std::istringstream istr(val);
		T returnVal;
		if (!(istr >> returnVal))
			exitWithError("CFG: Not a valid " + (std::string)typeid(T).name() + " received!\n");

		return returnVal;
	}

	template <>
	static std::wstring wstring_to_T(std::wstring const &val)
	{
		return val;
	}

	void ThrowError(const std::string &error)
	{
		throw std::invalid_argument(error);
	}
};

//void ThrowError(const std::string &error) 
//{
	//std::cout << error;
	//std::cin.ignore();
	//std::cin.get();

	//exit(EXIT_FAILURE);
	//throw std::invalid_argument(error);
//}

class ConfigFile
{
private:
	std::map<std::wstring, std::wstring> contents;
	std::wstring fName;

	void removeComment(std::wstring &line) const
	{
		if (line.find(L';') != line.npos)
			line.erase(line.find(L';'));
	}

	bool onlyWhitespace(const std::wstring &line) const
	{
		return (line.find_first_not_of(' ') == line.npos);
	}
	bool validLine(const std::wstring &line) const
	{
		std::wstring temp = line;
		temp.erase(0, temp.find_first_not_of(L"\t "));
		if (temp[0] == '=')
			return false;

		for (size_t i = temp.find('=') + 1; i < temp.length(); i++)
			if (temp[i] != ' ')
				return true;

		return false;
	}

	void extractKey(std::wstring &key, size_t const &sepPos, const std::wstring &line) const
	{
		key = line.substr(0, sepPos);
		if (key.find('\t') != line.npos || key.find(' ') != line.npos)
			key.erase(key.find_first_of(L"\t "));
	}
	void extractValue(std::wstring &value, size_t const &sepPos, const std::wstring &line) const
	{
		value = line.substr(sepPos + 1);
		value.erase(0, value.find_first_not_of(L"\t "));
		value.erase(value.find_last_not_of(L"\t ") + 1);
	}

	void extractContents(const std::wstring &line) 
	{
		std::wstring temp = line;
		temp.erase(0, temp.find_first_not_of(L"\t "));
		size_t sepPos = temp.find(L'=');

		std::wstring key, value;
		extractKey(key, sepPos, temp);
		extractValue(value, sepPos, temp);

		if (!keyExists(key))
			contents.insert(std::pair<std::wstring, std::wstring>(key, value));
		else
			ThrowError("CFG: Can only have unique key names!\n");
	}

	void parseLine(const std::wstring &line, size_t const lineNo)
	{
		// Only parse lines that have a "key=value" pair and appear to be valid.
		if ((line.find('=') != line.npos) && (validLine(line)))
			extractContents(line);
	}

	void ExtractKeys()
	{
		std::wifstream file;
		std::wstring line;
		size_t lineNo = 0;
		wchar_t churr;
		std::wstring temp;

		// Open for binary read
		file.open(fName.c_str(), 0x01 | _IOSbinary);
		if (!file)
			ThrowError("CFG: File not found!\n");

		while (file.read(&churr, 1))
		{
			// Kludge that replaces std::getline with something not confused by Unicode.
			line.clear();
			while ((file.read(&churr, 1)) && (churr != 13))
			{
				if ((churr > 0) && (churr != 10)) // Skip Windows' CR before the LF, and ignore nulls.
					line = line + churr;
			}

			lineNo++;
			temp = line;

			if (temp.empty())
				continue;

			removeComment(temp);
			if (onlyWhitespace(temp))
				continue;

			parseLine(temp, lineNo);
		}

		file.close();
	}

	void ThrowError(const std::string &error)
	{
		throw std::invalid_argument(error);
	}
public:
	ConfigFile(const std::wstring &fName)
	{
		this->fName = fName;
		ExtractKeys();
	}

	bool keyExists(const std::wstring &key) const
	{
		return contents.find(key) != contents.end();
	}

	template <typename ValueType>
	ValueType getValueOfKey(const std::wstring &key, ValueType const &defaultValue = ValueType()) const
	{
		if (!keyExists(key))
			return defaultValue;

		return Convert::wstring_to_T<ValueType>(contents.find(key)->second);
	}
};
/*
int main()
{
	ConfigFile cfg("config.cfg");

	bool exists = cfg.keyExists("car");
	std::cout << "car key: " << std::boolalpha << exists << "\n";
	exists = cfg.keyExists("fruits");
	std::cout << "fruits key: " << exists << "\n";

	std::string someValue = cfg.getValueOfKey<std::string>("mykey", "Unknown");
	std::cout << "value of key mykey: " << someValue << "\n";
	std::string carValue = cfg.getValueOfKey<std::string>("car");
	std::cout << "value of key car: " << carValue << "\n";
	double doubleVal = cfg.getValueOfKey<double>("double");
	std::cout << "value of key double: " << doubleVal << "\n\n";

	std::cin.get();
	return 0;
}
*/