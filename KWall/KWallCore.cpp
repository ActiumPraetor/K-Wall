/*

	K*Wall, the open-source anti-RMT-spam firewall
	by ActiumPraetor, et al
	Master branch, 0.1 alpha

	Released under the terms of the GNU LESSER GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
	See the K*Wall git repository for a copy of the license if it wasn't included with this code:
	https://github.com/ActiumPraetor/K-Wall


	Please be aware of the following if you'd like to help with the development end of this project:

	1. My philosophy for coding is a combination of two ideals:
	1: First make it WORK, THEN make it pretty.
	2: Test and optimize as you go, not after you finish.
	The original source will likely reflect this. Expect the occasional kludge if it solved a
	problem. (Or, if it looks dumb, but it -works-...)

	2. I usually use Allman-style indenting instead of K&R ("One True Brace") style, since I spent
	a lot of time developing in Pascal. OTB fans will just have to deal.

	3. We're not "using namespace"-ing. Anything involving a namespace needs to indicate that namespace
	everywhere it's used. This should save a lot of headaches later on.

	4. I like to use "CamelCase" convention for procedure names and "lowercase_words_and_underscores"
	convention for variable names, so that they can be distinguished at a glance.

*/

// The solution should have Unicode support enabled, negating the need for this define.
//#define UNICODE

#include "stdafx.h"
#include "KWallCore.h"

#include "windivert.h"
#include "richedit.h"
#include "shellapi.h"
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <algorithm>

#include "ws2tcpip.h"
#include "winsock2.h"

#include "unicode/ustring.h"
#include "unicode/utypes.h"
#include "unicode/regex.h"
#include "unicode/normlzr.h"
#include "unicode/translit.h"
#include "unicode/ustdio.h"

#include "simple_parser.cpp"



// zlib stuffs: this is intended to prevent Windows from trying to convert line endings in binary data.
#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#include <fcntl.h>
#include <io.h>
#define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384




// This is used by the IP address validation check.
#pragma comment(lib, "Ws2_32.lib")




/*

	Simple High-Resolution Timer (C++11 version) by gongzhitaao
	Posted on Guthub Gist: https://gist.github.com/gongzhitaao/7062087

*/
class Timer
{
public:
	Timer() : beg_(clock_::now()) {}
	void reset() { beg_ = clock_::now(); }
	double elapsed() const
	{
		return std::chrono::duration_cast<second_>
			(clock_::now() - beg_).count();
	}

private:
	typedef std::chrono::high_resolution_clock clock_;
	typedef std::chrono::duration<double, std::ratio<1> > second_;
	std::chrono::time_point<clock_> beg_;
};



/*

	The Core - the guts of the K*Wall codebase: the configuration loader and packet monitor/filter thread code.

	As an aside, we are defining the class here instead of in the header because the ICU library calls tend to 
	choke the compiler when trying to separate the class' interfaces. Apparently UnicodeStrings in procedure calls
	don't play well with header files. This isn't ideal slash best practice, but sometimes ya gotta go with function
	over form...

*/
class KWallCore
{
public:
	static UINT mon_thread_count;							// Number of active monitor threads
	static HANDLE windivert_filter;							// WinDivert filter handle
	static BOOL killthreads;								// Should monitor threads commit seppuku?
	static BOOL bypass_mode;								// To process packets, or not to process packets...
	static HANDLE multithread_mutex;						// Mutex handle, for thread synchronization
	static BOOL crapped_ourself;							// If true, we had a bad hair day.
	static HANDLE monitor_thread[64];						// Hold those thread handles...
	struct confusables_conversion
	{
		UnicodeString from;
		UnicodeString to;
	};
	static std::vector<confusables_conversion> confusables_map;



/*
	ConfigureAndStart
	-----------------

	This procedure tries to load the configuration file and configure K*Wall. If everything goes well, it then 
	invokes the workhorse threads to do work.

	(No input vars, no result.)
*/
	void ConfigureAndStart()
	{
		UINT i, ii, len;
		//UChar unicode_char;
		UINT num_threads = 1;
		std::string filter;
		std::wstring cfgfilename;

		const wchar_t alphabet[] = L"0123456789abcdef";



		// Clear variables.
		mon_thread_count = 0;
		windivert_filter = 0;
		killthreads = false;
		bypass_mode = false;
		multithread_mutex = 0;
		crapped_ourself = false;
		confusables_map.clear();
		for (i = 0; i < 16; ++i)
		{
			detect_patterns[i] = "";
			detect_weight[i] = 0;
		}
		strip_punctuation.setTo("");
		strip_whitespace.setTo("");
		skeletonize = false;
		deob_from.clear();
		deob_to.clear();
		utf_from.clear();
		utf_to.clear();
		ignore_start = 0;
		for (i = 0; i < 64; ++i)
		{
			monitor_thread[i] = 0;
		}
		passed_packets = 0;
		dropped_packets = 0;
		encoding = L"";



		// Fetch command-line arguments.
		int argcount;
		LPWSTR *args;
		args = CommandLineToArgvW(GetCommandLineW(), &argcount);

		// If we don't have the right number of command-line arguments, pitch a fit and bail.
		if (argcount != 2)
		{
			UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
			UpdateRichEdit(L"ERROR: Missing config file as a command-line parameter! Please correct this and relaunch K*Wall.\n",
				false, false, RGB(255, 0, 0), L"Tahoma", 16);

			UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

			crapped_ourself = true;
		}



		// Try to load the config file. 
		if (!crapped_ourself)
		{
			try
			{
				UpdateRichEdit(L"Loading configuration file... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);

				cfgfilename = args[1];

				// Is this a valid filename?
				if (!std::ifstream(cfgfilename).good())
				{
					wchar_t module_name[MAX_PATH];
					GetModuleFileNameW(0, (LPWSTR)&module_name, MAX_PATH);
					std::wstring path(module_name);
					path.erase(path.find_last_of('\\'), std::string::npos);
					cfgfilename = path + L"\\";
					cfgfilename.append(args[1]);
				}

				ConfigFile cfg(cfgfilename.c_str());

				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);

				// Let's start pullling stuff from the config file.  
				UpdateRichEdit(L"Time to configure K*Wall!\nSetting up packet redirection filter... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);

				// Start by trying to build the filter. We'll support up to 8 grouped sets of protocol/ip/port.
				filter = "inbound and ";
				std::string thisgroup;
				for (i = 1; i < 9; ++i)
				{
					// Check to see if the trio of keys exist. If not, skip it.
					if ((cfg.keyExists(L"protocol" + std::to_wstring(i))) && (cfg.keyExists(L"ip" + std::to_wstring(i))) && (cfg.keyExists(L"port" + std::to_wstring(i))))
					{
						thisgroup = "(";

						// First, fetch the source IP.
						std::wstring ip = cfg.getValueOfKey<std::wstring>(L"ip" + std::to_wstring(i), L"127.0.0.1");

						// We'll validate it real quick before using it.
						if (!IsIPAddress(ip))
						{
							UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
							UpdateRichEdit(L"ERROR: Config file contains a bad IP address entry! Please correct this and relaunch K*Wall.\n",
								false, false, RGB(255, 0, 0), L"Tahoma", 16);

							std::wstring bad_cfg_line = L"Look for the line in the config file that reads:\nip" + std::to_wstring(i) + L"=" + ip + L"\n";
							UpdateRichEdit(const_cast<wchar_t*>(bad_cfg_line.c_str()), false, false, RGB(255, 0, 0), L"Tahoma", 12);

							UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

							crapped_ourself = true;
						}

						// If the IP checked out, tack it on.
						thisgroup = thisgroup + "ip.SrcAddr == ";
						for (ii = 0, len = ip.length(); ii < len; ++ii)
						{
							if (ip[ii] > 31)
							{
								thisgroup = thisgroup + char(ip[ii]);
							}
						}


						// Then, and this is kinda optional, fetch the source port. The setting has to be included but can be zero.
						std::wstring port = cfg.getValueOfKey<std::wstring>(L"port" + std::to_wstring(i), L"0");
						if (_wtoi(port.c_str()) > 0)
						{
							thisgroup = thisgroup + " and ip.DestPort == " + std::to_string(_wtoi(port.c_str()));
						}


						// Finally, fetch the protocol.
						std::wstring protocol = cfg.getValueOfKey<std::wstring>(L"protocol" + std::to_wstring(i), L"tcp");
						if (protocol == L"tcp") { thisgroup = thisgroup + " and tcp.PayloadLength > 0"; }
						if (protocol == L"udp") { thisgroup = thisgroup + " and udp.PayloadLength > 0"; }


						// Close the group.
						thisgroup = thisgroup + ")";


						// Tack this group onto the filter string, throwing an "or" in if needed.
						char lastchar = filter.back();
						if (lastchar == 41) { filter = filter + " or "; }
						filter = filter + thisgroup;
					}
				}

				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
				UpdateRichEdit(L"Loading regex list...\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);

				// With this done, we can try loading the up-to-16 regex entries.
				std::wstring regex_val;
				for (i = 0; i < 16; ++i)
				{
					if ((cfg.keyExists(L"regex" + std::to_wstring(i + 1))) && (cfg.keyExists(L"weight" + std::to_wstring(i + 1))))
					{
						regex_val = cfg.getValueOfKey<std::wstring>(L"regex" + std::to_wstring(i + 1), L"");

						UpdateRichEdit(const_cast<wchar_t*>(std::to_wstring(i + 1).c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L": ", false, false, RGB(0, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(const_cast<wchar_t*>(regex_val.c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);

						for (ii = 0, len = regex_val.length(); ii < len; ++ii)
						{
							detect_patterns[i].append(regex_val[ii]); // Ugly kludge for copying a unicode-aware wstring into a UnicodeString
						}
						detect_weight[i] = _wtoi(cfg.getValueOfKey<std::wstring>(L"weight" + std::to_wstring(i + 1), L"0").c_str());

					}
					else
					{
						UpdateRichEdit(const_cast<wchar_t*>(std::to_wstring(i + 1).c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L": (empty)\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
					}
				}

				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
				UpdateRichEdit(L"Loading multiple-character deobfuscation list... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);


				// Fetch the deobfuscation list, which is a pair of dynamic arrays without a predetermined size. Note that this is
				// ugly-kludge, as ICU's UnicodeString doesn't speak directly with any of the C++ standard string types so we get to
				// play copy-char-by-char.
				i = 0;
				std::wstring value;
				UnicodeString temp;
				while ((cfg.keyExists(L"deob_from" + std::to_wstring(i + 1))) && (cfg.keyExists(L"deob_to" + std::to_wstring(i + 1))))
				{
					value = cfg.getValueOfKey<std::wstring>(L"deob_from" + std::to_wstring(i + 1), L"");
					temp.setTo("");
					temp = ParseUnicodeValues(value);
					deob_from.push_back(temp);

					value = cfg.getValueOfKey<std::wstring>(L"deob_to" + std::to_wstring(i + 1), L"");
					temp.setTo("");
					if (value != L"\\x00") // A "null" basically means "replace with empty string."
					{
						for (ii = 0; ii < value.length(); ++ii)
						{
							temp.append((UChar)value[ii]);
						}
					}
					else
					{
						temp.truncate(0);
					}
					deob_to.push_back(temp);

					++i;
				}

				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
				UpdateRichEdit(const_cast<wchar_t*>(std::to_wstring(i).c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L" entries loaded.\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);

				UpdateRichEdit(L"Loading Unicode deobfuscation list... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);


				// Fetch the UTF conversion list, which also is a pair of dynamic arrays without a predetermined size. See previous
				// note re: kludge.
				i = 0;
				std::vector<std::wstring>unicode_hexes;
				while ((cfg.keyExists(L"utf_from" + std::to_wstring(i + 1))) && (cfg.keyExists(L"utf_to" + std::to_wstring(i + 1))))
				{
					value = cfg.getValueOfKey<std::wstring>(L"utf_from" + std::to_wstring(i + 1), L"");

					temp.setTo("");
					temp = ParseUnicodeValues(value);
					utf_from.push_back(temp);
					
					value = cfg.getValueOfKey<std::wstring>(L"utf_to" + std::to_wstring(i + 1), L"");
					temp.setTo("");
					if (value != L"\\x00") // A "null" basically means "replace with empty string."
					{
						for (ii = 0; ii < value.length(); ++ii)
						{
							temp.append((UChar)value[ii]);
						}
					}
					else
					{
						temp.truncate(0);
					}
					utf_to.push_back(temp);

					++i;
				}

				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
				UpdateRichEdit(const_cast<wchar_t*>(std::to_wstring(i).c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L" entries loaded.\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);


				UpdateRichEdit(L"Loading options... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);

				// How many threads are we devoting to the task?
				if (cfg.keyExists(L"threads"))
				{
					num_threads = _wtoi(cfg.getValueOfKey<std::wstring>(L"threads", L"2").c_str());
					if (num_threads < 1) { num_threads = 1; }
					if (num_threads > 64) { num_threads = 64; }
				}

				// Are we ignoring some bytes at the start of the packet?
				ignore_start = 0;
				if (cfg.keyExists(L"ignore_start"))
				{
					ignore_start = _wtoi(cfg.getValueOfKey<std::wstring>(L"ignore_start", L"0").c_str());
				}

				// What punctuation characters are we stripping out prior to doing the regex-a-thon?
				strip_punctuation.setTo("");
				if (cfg.keyExists(L"strip_punctuation"))
				{
					value = cfg.getValueOfKey<std::wstring>(L"strip_punctuation" + std::to_wstring(i + 1), L"");
					strip_punctuation = ParseUnicodeValues(value);
				}

				// What whitespace characters are we stripping out as well prior to doing the regex-a-thon?
				strip_whitespace.setTo("");
				if (cfg.keyExists(L"strip_whitespace"))
				{
					value = cfg.getValueOfKey<std::wstring>(L"strip_whitespace" + std::to_wstring(i + 1), L"");
					strip_whitespace = ParseUnicodeValues(value);
				}

				// Are we skeletonizing the packet? (This basically strips out Unicode confusables.)
				skeletonize = false;
				if (cfg.keyExists(L"skeletonize"))
				{
					if (cfg.getValueOfKey<std::wstring>(L"skeletonize", L"no").c_str() == L"yes")
						skeletonize = true;
				}


/*
				// Packet compression types that we'll support
				// WARNING: These are MUTUALLY EXCLUSIVE - only one can be enabled!
				zlib_decompress = false;

				// Are we using zlib to decompress compressed packet payloads?
				if (cfg.keyExists(L"zlib_decompress"))
				{
					if (cfg.getValueOfKey<std::wstring>(L"zlib_decompress", L"no").c_str() == L"yes")
					{
						zlib_decompress = true;
					}
				}
*/


				// Are we aware of the encoding type? This can be "utf-8", "utf-16le", "utf-16be", "utf-32", or "unknown". If
				// one of the known UTF flavors, the workhorse will convert packet payloads only to the given encoding. If 
				// encoding is unknown or not provided, the workhorse will basically try all possible permutations at one shot.
				encoding = L"unknown";
				if (cfg.keyExists(L"encoding"))
				{
					encoding = cfg.getValueOfKey<std::wstring>(L"encoding", L"unknown").c_str();
					std::transform(encoding.begin(), encoding.end(), encoding.begin(), tolower);
				}

				// Finished with the important config bits.
				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);


				// For our next trick, grab the config file's description/author
				if ((cfg.keyExists(L"description")) && (cfg.keyExists(L"author")))
				{
					std::wstring desc = cfg.getValueOfKey<std::wstring>(L"description");
					std::wstring author = cfg.getValueOfKey<std::wstring>(L"author");

					std::wstring byline = L"\nConfiguration created by " + author + L". Description:\n" + desc + L"\n\n";
					UpdateRichEdit(const_cast<wchar_t*>(byline.c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);

					std::wstring new_title;
					new_title = szTitle;
					new_title = new_title + L" :: ";
					new_title = new_title + desc;
					SetWindowTextW(kwall, (LPCWSTR)new_title.c_str());
				}
			}
			catch (...)
			{
				UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				std::wstring lasterr = std::to_wstring(GetLastError());
				UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

				crapped_ourself = true;
			}
		}


		// Check for elevated privileges, as WinDivert requires the calling thread to be administrator-level to function.
		if (!crapped_ourself)
		{
			if (!IsElevated())
			{
				UpdateRichEdit(L" \n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L"ERROR: Running without elevated privileges! Please correct this and relaunch K*Wall.\n",
					false, false, RGB(255, 0, 0), L"Tahoma", 16);
				UpdateRichEdit(L"K*Wall MUST be run as an Administrator.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

				crapped_ourself = true;
			}
		}


		// See about creating a mutex to sync the various threads. If this fails, we're not gonna do any multithreading.
		if (!crapped_ourself)
		{
			multithread_mutex = CreateMutex(NULL, FALSE, NULL);
			if (multithread_mutex == NULL)
			{
				UpdateRichEdit(L" \n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L"ERROR: Failed to create a mutex! Please correct this and relaunch K*Wall.\n",
					false, false, RGB(255, 0, 0), L"Tahoma", 16);
				UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				std::wstring lasterr = std::to_wstring(GetLastError());
				UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

				crapped_ourself = true;
			}
		}


		// If all went well in the sanity-check department, we SHOULD be able to fire up the WinDivert driver and have it 
		// redirect packet traffic. We'll do one last sanity check first, though: we'll check to ensure we can actually
		// invoke WinDivert successfully by building and testing the filter terms.
		if (!crapped_ourself)
		{
			UpdateRichEdit(L"Checking filter structure...", false, false, RGB(0, 0, 0), L"Tahoma", 12);

			// This is basically a little debug-type snippet that posts the filter into the richedit.
			//std::wstring wide_filter;
			//wide_filter = L" ";
			//wide_filter.append(filter.begin(), filter.end());
			//wide_filter = wide_filter + L" \n";
			//UpdateRichEdit(const_cast<wchar_t*>(wide_filter.c_str()), false, false, RGB(0, 0, 0), L"Tahoma", 12);

			if (!WinDivertHelperCheckFilter(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0))
			{
				UpdateRichEdit(L" \n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L"ERROR: WinDivert filter failed our sanity check! Please correct this and relaunch K*Wall.\n",
					false, false, RGB(255, 0, 0), L"Tahoma", 16);

				UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

				crapped_ourself = true;
			}
			else
			{
				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
			}
		}


		// Sanity checks complete! If we didn't crap ourselves, we can fire up the important bit.
		if (!crapped_ourself)
		{
			UpdateRichEdit(L"Initial startup and sanity checks complete.\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
			UpdateRichEdit(L"Initializing WinDivert driver... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);

			// Try to start WinDivert.
			windivert_filter = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
			if (windivert_filter == INVALID_HANDLE_VALUE)
			{
				UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				std::wstring lasterr = std::to_wstring(GetLastError());
				UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
				UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

				UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

				crapped_ourself = true;
			}
			else
			{
				// WinDivert started.
				UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);

				// Try to bump the queue length so we have a bigger packet buffer before packets start falling off unprocessed.
				UpdateRichEdit(L"Modifying queue length... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);
				if (!WinDivertSetParam(windivert_filter, WINDIVERT_PARAM_QUEUE_LEN, 8192))
				{
					UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
					UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					std::wstring lasterr = std::to_wstring(GetLastError());
					UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
					UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					UpdateRichEdit(L"Attempting to close WinDivert...", false, false, RGB(255, 0, 0), L"Tahoma", 16);

					if (!WinDivertClose(windivert_filter))
					{
						UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						std::wstring lasterr = std::to_wstring(GetLastError());
						UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						UpdateRichEdit(L"WARNING: Windows networking may be left in an inconsistent state. You may need to reboot.\n",
							false, false, RGB(255, 0, 0), L"Tahoma", 16);
					}
					else
					{
						UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
					}
					windivert_filter = 0;

					UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

					crapped_ourself = true;
				}
				else
				{
					// Succeess!
					UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);

					// Try to bump the queue time so packets don't time out while waiting in queue.
					UpdateRichEdit(L"Modifying queue time... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);
					if (!WinDivertSetParam(windivert_filter, WINDIVERT_PARAM_QUEUE_TIME, 2048))
					{
						UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						std::wstring lasterr = std::to_wstring(GetLastError());
						UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						UpdateRichEdit(L"Attempting to close WinDivert...", false, false, RGB(255, 0, 0), L"Tahoma", 16);

						if (!WinDivertClose(windivert_filter))
						{
							UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
							UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

							std::wstring lasterr = std::to_wstring(GetLastError());
							UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
							UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

							UpdateRichEdit(L"WARNING: Windows networking may be left in an inconsistent state. You may need to reboot.\n",
								false, false, RGB(255, 0, 0), L"Tahoma", 16);
						}
						else
						{
							UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
						}
						windivert_filter = 0;

						UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

						crapped_ourself = true;
					}
					else
					{
						UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);

						DefineConsumablesList();

						// Everything started successfully where WinDivert is concerned, so let's fire up the monitor threads.
						UpdateRichEdit(L"Starting processing threads... ", false, false, RGB(0, 0, 0), L"Tahoma", 12);
						for (i = 0; i < num_threads; ++i)
						{
							monitor_thread[i] = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)WorkhorseThread,
								(LPVOID)windivert_filter, 0, NULL);
							if (monitor_thread[i] == NULL)
							{
								UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"Attempting to close WinDivert...", false, false, RGB(255, 0, 0), L"Tahoma", 16);

								if (!WinDivertClose(windivert_filter))
								{
									UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
									UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

									std::wstring lasterr = std::to_wstring(GetLastError());
									UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
									UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

									UpdateRichEdit(L"WARNING: Windows networking may be left in an inconsistent state. You may need to reboot.\n",
										false, false, RGB(255, 0, 0), L"Tahoma", 16);
								}
								else
								{
									UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
								}
								windivert_filter = 0;

								UpdateRichEdit(L"Please press any key to exit.\n", false, false, RGB(255, 0, 0), L"Tahoma", 16);

								crapped_ourself = true;

							}
							else
							{
								++mon_thread_count;
							}
						}
						UpdateRichEdit(L"Done.\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
					}
				}
			}
		}
		UpdateRichEdit(L" \n", false, false, RGB(0, 0, 0), L"Tahoma", 12);


		// Since we're done with them, free the command-line arguments.
		LocalFree(args);
	}



/*
	WorkhorseThread
	---------------

	This is the guts of the operation: the packet scanner code.

	arg (LPVOID) : thread handle.

	returns (DWORD) : standard thread exit code.
*/
	static DWORD WorkhorseThread(LPVOID arg)
	{
		// Increment the thread count.
		//mon_thread_count++;


		// "For" indices
		size_t i, ii, len;

		// WinDivert packet handling
		HANDLE handle = (HANDLE)arg;
		unsigned char packet[MAXBUF];
		PVOID data;
		unsigned char payload_c[MAXBUF];
		UINT packet_len, data_len;
		WINDIVERT_ADDRESS addr;
		WINDIVERT_IPHDR ipheader;
		WINDIVERT_IPV6HDR ipv6header;
		WINDIVERT_ICMPHDR icmpheader;
		WINDIVERT_ICMPV6HDR icmpv6header;
		WINDIVERT_TCPHDR tcpheader;
		WINDIVERT_UDPHDR udpheader;

		//IUC library stuff
		UnicodeString payload, payload_n, payload_s;
		std::wstring dump_wstring, regex_matches;
		UnicodeString /*payload_values,*/ payload_dump;
		char converted_byte, byteone, bytetwo, bytethree;
		UINT codepoint;
		UChar converted_char, surrogate_high, surrogate_low;
		UChar32 big_char;
		UErrorCode icu_error = U_ZERO_ERROR;
		const Normalizer2 *nfkc = Normalizer2::getNFKCCasefoldInstance(icu_error);

		// Regex matching 
		BOOL drop_packet;
		UINT match_count;

		// This is an ugly kludge, but a necessary one, as ICU's RegexMatcher doesn't "do" arrays/vectors cleanly, or at least
		// I coudln't get it to work that way. So, instead of having to constantly redeclare a single RegexMatcher, we'll
		// do the next best thing and create a series of them. This saves on create/destroy overhead at the expense of a higher
		// initial memory load. (ICU also recommends caching and reusing objects, so, yeah.)
		RegexMatcher *matcher_00 = new RegexMatcher(detect_patterns[0], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_01 = new RegexMatcher(detect_patterns[1], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_02 = new RegexMatcher(detect_patterns[2], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_03 = new RegexMatcher(detect_patterns[3], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_04 = new RegexMatcher(detect_patterns[4], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_05 = new RegexMatcher(detect_patterns[5], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_06 = new RegexMatcher(detect_patterns[6], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_07 = new RegexMatcher(detect_patterns[7], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_08 = new RegexMatcher(detect_patterns[8], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_09 = new RegexMatcher(detect_patterns[9], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_10 = new RegexMatcher(detect_patterns[10], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_11 = new RegexMatcher(detect_patterns[11], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_12 = new RegexMatcher(detect_patterns[12], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_13 = new RegexMatcher(detect_patterns[13], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_14 = new RegexMatcher(detect_patterns[14], UREGEX_CASE_INSENSITIVE, icu_error);
		RegexMatcher *matcher_15 = new RegexMatcher(detect_patterns[15], UREGEX_CASE_INSENSITIVE, icu_error);

		// Mutex stuff
		DWORD wait_result;

		// Status info for GUI
		std::wstring status;

		// Hexadecimal digits for our packet payload hex display
		static const wchar_t alphabet[] = L"0123456789ABCDEF";

		// High-res timer for tracking processing time
		Timer processtime;
		double timetaken;

		// zlib decompression stuff
		//z_stream infstream;
		//unsigned char payload_d[MAXBUF];




		// Main Loop!
		while (!killthreads)
		{
			try
			{
				// Set the drop flag to false. If this ends up set to true, the packet won't be relayed.
				drop_packet = false;

				// Zero the regex match counter. If we hit enough matches we flag the packet for discard.
				match_count = 0;

				// Read a matching packet.
				if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
				{
					// Since the packet-read failed, send text to the richedit. Since this code is running in a seperate thread,
					// we will be using a mutex for synchronization. This lets us multithread the packet scanning while the interface
					// can continue to run in its own thread without any of these threads stepping all over each other's proverbial toes.
					wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
					if (wait_result == WAIT_OBJECT_0)
					{
						UpdateRichEdit(L"Packet read failed.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						std::wstring lasterr = std::to_wstring(GetLastError());
						UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
						UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						UpdateRichEdit(L"If you see this message a lot, you may need to reboot.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

						ReleaseMutex(multithread_mutex);
						continue;
					}
				}
				else {
					// If-not-bypass-mode lets us provide a bypass feature, wherein any packet that comes through the filter is 
					// handed off to the client without being checked. This gives users the option to shut down the spam scanner
					// if there's a need to do so.
					if (!bypass_mode)
					{
						// Prepare our process timer, so we can see how long this packet takes to work over.
						processtime.reset();

						// Clear some storage vars.
						ZeroMemory(&ipheader, sizeof(ipheader));
						ZeroMemory(&ipv6header, sizeof(ipv6header));
						ZeroMemory(&icmpheader, sizeof(icmpheader));
						ZeroMemory(&icmpv6header, sizeof(icmpv6header));
						ZeroMemory(&tcpheader, sizeof(tcpheader));
						ZeroMemory(&udpheader, sizeof(udpheader));

						// Parse the packet to break apart its header and payload information.
						WinDivertHelperParsePacket(packet, packet_len, (PWINDIVERT_IPHDR*)&ipheader, (PWINDIVERT_IPV6HDR*)&ipv6header,
							(PWINDIVERT_ICMPHDR*)&icmpheader, (PWINDIVERT_ICMPV6HDR*)&icmpv6header, (PWINDIVERT_TCPHDR*)&tcpheader,
							(PWINDIVERT_UDPHDR*)&udpheader, &data, &data_len);

						
						// Clear the payload array.
						ZeroMemory(payload_c, sizeof(payload_c));

						// Copy the payload data from a pvoid into a structure we can work with more readily (in this case an unsigned-char array).
						memcpy(payload_c, data, data_len);



						/*
						// zlib packet payload decompression
						// WARNING: EXPERIMENTAL!
						// Followup: Worked, but the original zlib code was not at all thread-safe.
						if (zlib_decompress)
						{
							// Clear things at start.
							infstream.zalloc = Z_NULL;
							infstream.zfree = Z_NULL;
							infstream.opaque = Z_NULL;
							infstream.data_type = Z_BINARY;

							// Clear the decompressed-payload holder array.
							ZeroMemory(payload_d, sizeof(payload_d));

							// Tell zlib what our ins and outs are.
							infstream.avail_in = (uInt)(sizeof(payload_c));
							infstream.next_in = (Bytef *)payload_c;
							infstream.avail_out = (uInt)(sizeof(payload_d));
							infstream.next_out = (Bytef *)payload_d;

							// Try a decompress operation.
							inflateInit(&infstream);
							inflate(&infstream, Z_NO_FLUSH);
							inflateEnd(&infstream);

							// Copy the decompressed payload into the payload holder array.
							memcpy(payload_c, payload_d, sizeof(payload_d));
						}
						*/


						// And now, we convert the char array "payload_c" into the UnicodeString "payload". How exactly we will do this
						// will depend on what we expect to see...



						// Clear the Unicode payload string, and reset its iteration pointer to the beginning.
						payload.setTo((UnicodeString)"", 0);

						// For UTF-8, we have to work the UTF-8 encoding scheme, which can use 1-4 bytes to encode each codepoint. A simple
						// "for" loop won't suffice here, as we have variable encoding lengths to process.
						if ((encoding == L"utf-8") || (encoding == L"unknown"))
						{
							if (encoding == L"unknown")
							{
								payload = payload + "UTF8";
							}

							i = ignore_start;
							while (i < data_len)
							{
								converted_char = UChar(0);

								// Converting bytes to codepoints in UTF-8 requires that we understand the encoding scheme. If a byte starts with
								// the seventh bit unset, the byte is ASCII/ANSI and can be translated over as-is. If the seventh bit is a 1, the 
								// codepoint is encoded in bits of subsequent bytes (up to 3 more), which will all start with 10xxxxxx, and the 
								// number of set bits from MSB down on the lead byte indicates how many additional bytes will be required.
								converted_byte = payload_c[i];
								if (converted_byte < 127) // 0xxxxxxx - ASCII/ANSI range (0x00-0x7F), single-byte encoding
								{
									converted_char = UChar(converted_byte);
									++i;
								}
								if ((converted_byte & 0xE0) == 0xC0) // 110xxxxx - codepoints 0x0080-0x07FF, two-byte encoding
								{
									byteone = payload_c[i + 1];
									codepoint = ((converted_byte - 192) * 64) + (byteone - 128);
									converted_char = UChar(codepoint);
									i = i + 2;
								}
								if ((converted_byte & 0xF0) == 0xE0) // 1110xxxx - codepoints 0x0800-0xD7FF/skip surrogate range/0xE000-0xFFFF, three-byte encoding
								{
									byteone = payload_c[i + 1];
									bytetwo = payload_c[i + 2];
									codepoint = ((converted_byte - 224) * 4096) + ((byteone - 128) * 64) + (bytetwo - 128);
									converted_char = UChar();
									i = i + 3;
								}
								if ((converted_byte & 0xF8) == 0xF0) // 11110xxx, codepoints 0x00010000-0x00010FFF, four-byte encoding
								{
									byteone = payload_c[i + 1];
									bytetwo = payload_c[i + 2];
									bytethree = payload_c[i + 3];
									codepoint = ((converted_byte - 240) * 262144) + ((byteone - 128) * 4096) + ((bytetwo - 128) * 64) + (bytethree - 128);
									converted_char = UChar(codepoint);
									i = i + 4;
								}
								// In theory this encoding scheme goes to six bytes, but the codepoint limit for Unicode is 0x00010FFF, which ends at
								// four bytes.

								payload = payload + converted_char;
							}
						}

						// UTF-16LE conversion is a litle less problematic than UTF-8 in that the extended version is only one range of
						// codepoints (0x0010000-0x0010FFFF) and only increases the encoded datagram size by one step instead of three.
						// The gist is that if the word falls within a reserved range of values (0xD800-oxDBFF), it's the high-order chunk
						// of a surrogate pair, with the next word carrying the the low-order chunk.
						if ((encoding == L"utf-16le") || (encoding == L"unknown"))
						{
							if (encoding == L"unknown")
							{
								payload = payload + "UTF16LE";
							}

							i = ignore_start;
							while (i < data_len)
							{
								surrogate_high = UChar(MAKEWORD(payload_c[i], payload_c[i + 1]));

								if ((surrogate_high >= 0xD800) && (surrogate_high <= 0xDBFF))
								{
									// Whee, a surrogate! Grab the next word.
									surrogate_low = UChar(MAKEWORD(payload_c[i + 2], payload_c[i + 3]));

									// Is the next word a valid low surrogate?
									if ((surrogate_low >= 0xDC00) && (surrogate_low <= 0xDFFF))
									{
										// Yep, valid, so let's convert the two words into a codepoint and stuff that into the payload.
										converted_char = 0x10000 + (surrogate_high - 0xD800) * 0x400 + (surrogate_low - 0xDC00);
										payload = payload + converted_char;
										i = i + 4;
									}
									else
									{
										// Nope, not valid. Let's throw an invalid-codepoint marker and move forward. (The next word will
										// be processed like an ordinary UTF-16 codepoint.)
										payload = payload + 0xFFFD;
										i = i + 2;
									}
								}
								else
								{
									payload = payload + surrogate_high;
									i = i + 2;
								}
							}
						}

						// Converting bytes to codepoints in UTF-16BE also isn't as fancy as UTF-8, again due to the surrogate system.
						if ((encoding == L"utf-16be") || (encoding == L"unknown"))
						{
							if (encoding == L"unknown")
							{
								payload = payload + "UTF16BE";
							}

							i = ignore_start;
							while (i < data_len)
							{
								surrogate_high = UChar(MAKEWORD(payload_c[i + 1], payload_c[i]));

								if ((surrogate_high >= 0xD800) && (surrogate_high <= 0xDBFF))
								{
									// Whee, a surrogate! Grab the next word.
									surrogate_low = UChar(MAKEWORD(payload_c[i + 3], payload_c[i + 2]));	

									// Is the next word a valid low surrogate?
									if ((surrogate_low >= 0xDC00) && (surrogate_low <= 0xDFFF))
									{
										// Yep, valid, so let's convert the two words into a codepoint and stuff that into the payload.
										converted_char = 0x10000 + (surrogate_high - 0xD800) * 0x400 + (surrogate_low - 0xDC00);
										payload = payload + converted_char;
										i = i + 4;
									}
									else
									{
										// Nope, not valid. Let's throw an invalid-codepoint marker and move forward. (The next word will
										// be processed like an ordinary UTF-16 codepoint.)
										payload = payload + 0xFFFD;
										i = i + 2;
									}
								}
								else
								{
									payload = payload + surrogate_high;
									i = i + 2;
								}
							}
						}

						// UTF-32 is the easiest - make a long out of four bytes, convert that to a UTF-32 "character," and ram it into the UnicodeString.

						// First, the little-endian...
						if ((encoding == L"utf-32le") || (encoding == L"unknown"))
						{
							if (encoding == L"unknown")
							{
								payload = payload + "UTF32BE";
							}

							for (i = ignore_start; i < data_len; i = i + 4)
							{
								big_char = UChar(MAKELONG(MAKEWORD(payload_c[i], payload_c[i + 1]), MAKEWORD(payload_c[i + 2], payload_c[i + 3])));
								if (big_char > 0)
								{
									payload.append(big_char);
								}
							}
						}

						// Then, the big-endian flavor, which is likely pretty rare in practical application...
						if ((encoding == L"utf-32be") || (encoding == L"unknown"))
						{
							if (encoding == L"unknown")
							{
								payload = payload + "UTF32LE";
							}

							for (i = ignore_start; i < data_len; i = i + 4)
							{
								big_char = UChar(MAKELONG(MAKEWORD(payload_c[i + 3], payload_c[i + 2]), MAKEWORD(payload_c[i], payload_c[i + 1])));
								if (big_char > 0)
								{
									payload.append(big_char);
								}
							}
						}


						// Normalize the payload. This will help strip out some sneaky ways to obfuscate spam enough to slip it past
						// spam finters.
						icu_error = U_ZERO_ERROR;
						payload_n = nfkc->normalize(payload, icu_error);



						// Unicode skeletons - normalized srings with confusable characters converted to their non-confused versions -
						// make a simple means of removing any attempt to use lookalike characters to get past the filters. This code
						// basically uses the spoof checking code included with ICU.
						if (skeletonize)
						{
							payload_n = ConvertToSkeleton(payload_n);
						}



						// Force the payload into lowercase. This will remove case specificity and make for smaller regexes.
						payload_n.toLower();



						// Now for something a bit different: Unicode deobfuscation. The point of this is to stop RMT spam from getting
						// away with using .ĆØΜ for .com, etc. to avoid detection. Basically, any single Unicode character in each utf_from
						// entry is replaced with the single character in the corresponding utf_to entry.
						for (i = 0, len = utf_from.size(); i < len; ++i)
						{
							for (ii = 0, len = utf_from.operator[](i).length(); ii < len; ++ii)
							{
								payload_n.findAndReplace(utf_from.operator[](i).charAt(ii), utf_to[i]);
							}
						}



						// Convert some of the more common multi-character methods of obfuscating characters to get past regex-based filters.
						// The next code chunk grabs individual characters, but these grab multi-character sequences like HTML specials.
						for (i = 0, len = deob_from.size(); i < len; ++i)
						{
							payload_n.findAndReplace(deob_from[i], deob_to[i]);
						}


						// Clear the stripped-payload recipient var.
						payload_s.setTo("");

						// Strip punctuation and whitespace.
						for (i = 0, len = payload_n.length(); i < len; ++i)
						{
							// Fetch a char off the payload.
							big_char = payload_n.char32At(i);

							// Check to see if it's in either the strip_punctuation or strip_whitespace vars. If it's not, add it to the
							// post-strip var. If so, discard it by NOT copying it over. The easiest way to check this is an indexOf check 
							// against the punctuation and whitespace vars - if indexOf returns anything but -1 (for "not found"), the char
							// is within one of the two vars and can be discarded.
							if ((strip_punctuation.indexOf(big_char) == -1) && (strip_whitespace.indexOf(big_char) == -1))
							{
								payload_s.append(big_char);
							}
						}



						// Prepare for regex checking! Again, this is a kludge since RegexMatcher doesn't play well with arrays/vectors.
						// Note the "regex_matches" string, which will be populated with characters to indicate which regex filters were
						// tripped by the packet - Y for yes, n for no, and a period if there's no regex in that slot. This should help 
						// with regex fine-tuning.
						regex_matches = L"Regex Matches: [";

						// Oh, we're also framing each check with a try/catch block, because a bad regex string can cause the ICU regex
						// handler to crap itself with an access violation.

						// TODO: Find another way to do this, probably by moving it to a procedure and passing the relevant RegexMatcher
						// by reference.
						try
						{
							if (detect_patterns[0] != "")
							{
								matcher_00->reset(payload_s);
								if (matcher_00->find())
								{
									match_count = match_count + detect_weight[0];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 1 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try {
							if (detect_patterns[1] != "")
							{
								matcher_01->reset(payload_s);
								if (matcher_01->find())
								{
									match_count = match_count + detect_weight[1];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 2 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[2] != "")
							{
								matcher_02->reset(payload_s);
								if (matcher_02->find())
								{
									match_count = match_count + detect_weight[2];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 3 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[3] != "")
							{
								matcher_03->reset(payload_s);
								if (matcher_03->find())
								{
									match_count = match_count + detect_weight[3];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 4 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[4] != "")
							{
								matcher_04->reset(payload_s);
								if (matcher_04->find())
								{
									match_count = match_count + detect_weight[4];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 5 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[5] != "")
							{
								matcher_05->reset(payload_s);
								if (matcher_05->find())
								{
									match_count = match_count + detect_weight[5];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 6 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[6] != "")
							{
								matcher_06->reset(payload_s);
								if (matcher_06->find())
								{
									match_count = match_count + detect_weight[6];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 7 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[7] != "")
							{
								matcher_07->reset(payload_s);
								if (matcher_07->find())
								{
									match_count = match_count + detect_weight[7];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 8 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[8] != "")
							{
								matcher_08->reset(payload_s);
								if (matcher_08->find())
								{
									match_count = match_count + detect_weight[8];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 9 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[9] != "")
							{
								matcher_09->reset(payload_s);
								if (matcher_09->find())
								{
									match_count = match_count + detect_weight[9];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 10 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[10] != "")
							{
								matcher_10->reset(payload_s);
								if (matcher_10->find())
								{
									match_count = match_count + detect_weight[10];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 11 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[11] != "")
							{
								matcher_11->reset(payload_s);
								if (matcher_11->find())
								{
									match_count = match_count + detect_weight[11];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 12 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[12] != "")
							{
								matcher_12->reset(payload_s);
								if (matcher_12->find())
								{
									match_count = match_count + detect_weight[12];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 13 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[13] != "")
							{
								matcher_13->reset(payload_s);
								if (matcher_13->find())
								{
									match_count = match_count + detect_weight[13];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 14 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[14] != "")
							{
								matcher_14->reset(payload_s);
								if (matcher_14->find())
								{
									match_count = match_count + detect_weight[14];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 15 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}

						try
						{
							if (detect_patterns[15] != "")
							{
								matcher_15->reset(payload_s);
								if (matcher_15->find())
								{
									match_count = match_count + detect_weight[15];
									regex_matches = regex_matches + L"Y";
								}
								else {
									regex_matches = regex_matches + L"n";
								}
							}
							else {
								regex_matches = regex_matches + L".";
							}
						}
						catch (...)
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"WARNING: Regex filter 16 threw an exception\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"You might want to close K*Wall and check the filter.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}



						// I really wish RegexMatcher would work in a vector so I could just iterate them... Ugh!



						// Finish up with text indicating regexes that matched.
						regex_matches = regex_matches + L"], total weight: " + std::to_wstring(match_count) + L"/100";



						// If we saw enough regex matches, consider the packet as spam and flag it for discard.
						if (match_count >= 100) { drop_packet = true; }



						// Re-inject the packet if it didn't get flagged. This will effectively hand the packet over to the game client.
						if (!drop_packet)
						{
							if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
							{
								wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
								if (wait_result == WAIT_OBJECT_0)
								{
									UpdateRichEdit(L"Packet reinjection failed.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
									UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

									std::wstring lasterr = std::to_wstring(GetLastError());
									UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
									UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

									UpdateRichEdit(L"If you see this message a lot, you may need to reboot.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

									ReleaseMutex(multithread_mutex);
								}
							}
						}



						// Aaaand done with the busywork - snapshot the process timer.
						timetaken = processtime.elapsed();
						regex_matches = regex_matches + L". Process time required: " + std::to_wstring(match_count) + L" ns\n";



						// Send a "passed" or "dropped" message to the richedit along with a dump of the packet's payload's contents.
						wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
						if (wait_result == WAIT_OBJECT_0)
						{
							status = L"";
							if (!drop_packet)
							{
								passed_packets++;
								status = L"Packet # " + std::to_wstring(passed_packets) + L" passed on to client.\n";
								UpdateRichEdit(const_cast<wchar_t*>(status.c_str()), false, false, RGB(0, 128, 0), L"Tahoma", 12);
							}
							else
							{
								dropped_packets++;
								status = L"RMT spam detected. Packet # " + std::to_wstring(dropped_packets) + L" dropped.\n";
								UpdateRichEdit(const_cast<wchar_t*>(status.c_str()), false, false, RGB(128, 0, 0), L"Tahoma", 12);
							}

							// Prepare our packet dump variable.
							dump_wstring.clear();
							dump_wstring.append(regex_matches);


							// This next bit basically converts the packet payload into a series of hexadecimal bytes followed
							// by the characters those bytes represent, assuming they translate into a printable character.
							// The end result resembles a hex editor's output. That info gets logged, so false positives and 
							// missed spam can be analyzed and filters can be adjusted.
							for (i = 0; i < ((UINT(payload_n.length() / 16) + 1) * 16); ++i)
							{
								// Place the actual characters at the end, assuming they are printable.
								if ((i % 16 == 0) && (i > 0))
								{
									dump_wstring = dump_wstring + L"| ";
									for (ii = 0; ii < 16; ++ii)
									{
										if (int32_t(i + ii - 16) < payload_s.length())
										{
											if ((payload_s.charAt(i + ii - 16) > 31) && (payload_s.charAt(i + ii - 16) < 1023))
											{
												dump_wstring = dump_wstring + wchar_t(payload_s.charAt(i + ii - 16));
											}
											else
											{
												dump_wstring = dump_wstring + L".";
											}
										}
									}
									dump_wstring = dump_wstring + L"\n";
								}

								// This part builds the hxadecimal byte values for each byte
								if ((i % 8 == 0) && (i > 0) && (i % 16 != 0))
								{
									dump_wstring = dump_wstring + L" ";
								}

								if (int32_t(i) < payload_n.length())
								{
									dump_wstring = dump_wstring + alphabet[HIBYTE(payload_s.charAt(i)) / 16];
									dump_wstring = dump_wstring + alphabet[HIBYTE(payload_s.charAt(i)) % 16];
									dump_wstring = dump_wstring + alphabet[LOBYTE(payload_s.charAt(i)) / 16];
									dump_wstring = dump_wstring + alphabet[LOBYTE(payload_s.charAt(i)) % 16];
									dump_wstring = dump_wstring + L" ";
								}
								else
								{
									dump_wstring = dump_wstring + L".... ";
								}
							}

							// Go back through and place the actual characters at the end of the last line, assuming they're printable.
							dump_wstring = dump_wstring + L"| ";
							for (ii = 0; ii < 16; ++ii)
							{
								if (int32_t(i + ii - 16) < payload_n.length())
								{
									if ((payload_s.charAt(i + ii - 16) > 31) && (payload_s.charAt(i + ii - 16) < 1023))
									{
										dump_wstring = dump_wstring + wchar_t(payload_s.charAt(i + ii - 16));
									}
									else
									{
										dump_wstring = dump_wstring + L".";
									}
								}
							}
							dump_wstring = dump_wstring + L"\n";

							UpdateRichEdit(const_cast<wchar_t*>(dump_wstring.c_str()), false, false, RGB(0, 0, 0), L"DejaVu Sans Mono", 8);

							UpdateRichEdit(L"\n\n", false, false, RGB(0, 0, 0), L"DejaVu Sans Mono", 10);

							ReleaseMutex(multithread_mutex);
						}
					}
					else
					{
						if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
						{
							wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
							if (wait_result == WAIT_OBJECT_0)
							{
								UpdateRichEdit(L"Packet reinjection failed.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								std::wstring lasterr = std::to_wstring(GetLastError());
								UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
								UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								UpdateRichEdit(L"If you see this message a lot, you may need to reboot.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

								ReleaseMutex(multithread_mutex);
							}
						}
					}
				}
			}
			catch (...)
			{
				// Something went seriously wrong, so we'll attempt to catch and log the exception and then shut down.
				wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
				if (wait_result == WAIT_OBJECT_0)
				{
					UpdateRichEdit(L"Uh oh, we just had an unhandled exception.\n", true, false, RGB(255, 0, 0), L"Tahoma", 16);
					UpdateRichEdit(L"Under normal circumstances this should never happen. Hopefully this will get stored in the log.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);
					UpdateRichEdit(L"Windows reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					std::wstring lasterr = std::to_wstring(GetLastError());
					UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
					UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					UpdateRichEdit(L"K*Wall will attempt to shut down gracefully. If K*Wall can't, you may need to kill the process manually.\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					ReleaseMutex(multithread_mutex);

					killthreads = true;
				}
			}
		}

		wait_result = WaitForSingleObject(multithread_mutex, INFINITE);
		if (wait_result == WAIT_OBJECT_0)
		{
			UpdateRichEdit(L"Closing monitor thread.\n\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);

			ReleaseMutex(multithread_mutex);
		}



		// When the thread is exiting, decrement the thread counter.
		mon_thread_count--;
		return 0;
	}



private:
	static UnicodeString detect_patterns[16];				// Regex patterns get put in here
	static UINT detect_weight[16];							// How much a match is worth toward flagging a packet, when 100 total flags it
	static UnicodeString strip_punctuation;					// Punctuation characters to strip before regex checking
	static UnicodeString strip_whitespace;					// Whitespace characters to strip before regex checking
	static BOOL skeletonize;								// Are we stripping out Unicode confusables?
	static std::vector<UnicodeString> deob_from, deob_to;	// Multiple-character deobfuscation arrays
	static std::vector<UnicodeString> utf_from, utf_to;		// Unicode deobfuscation arrays
	static UINT ignore_start;								// Ignore how many bytes at the start of a packet?
	static UINT passed_packets, dropped_packets;			// Keeping tally of what we dropped and didn't drop.
	static std::wstring encoding;							// So what flavor of Unicode did we discover?
	static BOOL zlib_decompress;							// Try using zlib to unpack the packet payload



/*
	ReplaceStringW
	--------------

	Widestring version of a basic high-speed string replace.

	NOTE: This is an in-place function - "subject" is modified.

	IN/OUT subject (std::wstring) : the string to search.
	search (std::wstring) : a substring to search for.
	replace (std::wstring) : a substring with which to replace the "search" string.

	(No result.)
*/
	void ReplaceStringW(std::wstring& subject, const std::wstring& search, const std::wstring& replace) {
		size_t pos = 0;
		while ((pos = subject.find(search, pos)) != std::wstring::npos) {
			subject.replace(pos, search.length(), replace);
			pos += replace.length();
		}
	}



/*
	ParseUnicodeValues
	------------------

	This procedure converts all 16- or 32-bit hexadecimal numbers within a string into Unicode codepoint equivalents.

	USAGE NOTES:
	· Hexadecimal values MUST be four or eight hexadecimal digits - no other digit count will be considered as valid.
	· Hexadecimal numbers MUST be led with either "0x" or "\x" in order to be detected. If not so marked, they will 
	  not be translated but will instead be copied over to the output unparsed.

	NOTE: This code does NOT attempt to validate whether any hexadecimal number translates to valid Unicode odepoints.
	The hexadecimal is simply converted into an unsigned long and appended as a "character."

	source (std::wstring) : source string to process.

	returns (UnicodeString) : source string with all hexadecimal values converted into Unicode codepoints.
*/
	UnicodeString ParseUnicodeValues(std::wstring source)
	{
		UnicodeString hex_chars = "0123456789abcdefABCDEF";
		std::wstring two_chars = L"";
		std::wstring hex_string = L"";
		UnicodeString converted = L"";
#if DEBUG
		std::wstring snoopable = L"";
#endif // DEBUG
		UINT i = 0;
		BOOL found_hex = false;


		// The gist of this routine is that we enumerate the source string, and if we encounter "0x" or "\x", we then check the 
		// next four and eight characters to see if they are valid hexadecimal digits.
		while (i < source.length())
		{
			if (i + 1 < source.length())
			{
				// Grab the current character and the one that follows.
				two_chars = L"";
				two_chars = two_chars + source[i] + source[i + 1];

				// Check to see if these two characters may be markers leading a string of hex characters.
				if ((two_chars == L"0x") || (two_chars == L"\\x"))
				{
					// Unset our found flag - if this remains false, we know the "0x" or "\x" is not escaping a working four- or
					// eight-character hexadecimal number.
					found_hex = false;

					// We found the "0x" or "\x" marker, so let's check the next eight characters to see if they're possible hex.
					if (i + 9 < source.length()) // This check is basically there to avoid "index out of bounds" errors.
					{
						if ((hex_chars.indexOf(source[i + 2]) != std::wstring::npos) && (hex_chars.indexOf(source[i + 3]) != std::wstring::npos) &&
							(hex_chars.indexOf(source[i + 4]) != std::wstring::npos) && (hex_chars.indexOf(source[i + 5]) != std::wstring::npos) &&
							(hex_chars.indexOf(source[i + 6]) != std::wstring::npos) && (hex_chars.indexOf(source[i + 7]) != std::wstring::npos) &&
							(hex_chars.indexOf(source[i + 8]) != std::wstring::npos) && (hex_chars.indexOf(source[i + 9]) != std::wstring::npos))
						{
							// If they are hex, just push them into a widestring. We're not concerned about encoding or codepage
							// conversions since they have to be ordinary ASCII/ANSI to clear our check.
							hex_string = L"";
							hex_string = hex_string + source[i + 2] + source[i + 3] + source[i + 4] + source[i + 5]
								+ source[i + 6] + source[i + 7] + source[i + 8] + source[i + 9];

								// Convert the resulting hex value into a UChar and push that into the converted string.
								converted = converted + UChar(wcstoul(hex_string.c_str(), NULL, 16));
#if DEBUG
								snoopable = snoopable + UChar(wcstoul(hex_string.c_str(), NULL, 16));
#endif // DEBUG

								// Move our index forward ten spaces.
								i = i + 10;

								// Set our found flag.
								found_hex = true;
						}
					}

					// We should probably also handle four-char hex for the not-so-big numbers...
					if ((i + 5 < source.length()) && (!found_hex))
					{
						if ((hex_chars.indexOf(source[i + 2]) != std::wstring::npos) && (hex_chars.indexOf(source[i + 3]) != std::wstring::npos) &&
							(hex_chars.indexOf(source[i + 4]) != std::wstring::npos) && (hex_chars.indexOf(source[i + 5]) != std::wstring::npos))
						{
							// If they are hex, just push them into a widestring. We're not concerned about encoding or codepage
							// conversions since they have to be ordinary ASCII/ANSI to clear our check.
							hex_string = L"";
							hex_string = hex_string + source[i + 2] + source[i + 3] + source[i + 4] + source[i + 5];

							// Convert the resulting hex value into a UChar and push that into the converted string.
							converted = converted + UChar(wcstoul(hex_string.c_str(), NULL, 16));
#if DEBUG
							snoopable = snoopable + UChar(wcstoul(hex_string.c_str(), NULL, 16));
#endif // DEBUG

							// Move our index forward six spaces.
							i = i + 6;

							// Set our found flag.
							found_hex = true;
						}
					}

					if (!found_hex)
					{
						// Found the marker, but the characters that followed were not valid hexadecimal, so we will assume
						// the marker is part of what we're checking for.
						converted = converted + source[i] + source[i + 1];
#if DEBUG
						snoopable = snoopable + source[i] + source[i + 1];
#endif // DEBUG
						i = i + 2;
					}
				}
				else
				{
					// No hex marker, so just copy from source to destination.
					converted = converted + source[i];
#if DEBUG
					snoopable = snoopable + source[i];
#endif // DEBUG
					++i;
				}
			}
			else
			{
				// Not enough length, so just copy from source to destination.
				converted = converted + source[i];
#if DEBUG
				snoopable = snoopable + source[i];
#endif // DEBUG
				++i;
			}
		}

		// Pass the results to the caller.
#if DEBUG
		snoopable = L""; // Leave a breakpoint here.  Be aware that widestrings won't render Unicode codepoints properly!
#endif // DEBUG

		return converted;
	}



/*
	split
	-----

	This procedure splits a string by a given delimeter, and returns the split string as a vector of strings.

	text (std::wstring) : the string to split.
	sep (wchar_t*) : delimiter character at which to split the string.

	returns (std::vector<std::wstring>) : vector of substrings of input split by delimeter.
*/
	std::vector<std::wstring> split(const std::wstring &text, wchar_t* sep) {
		std::vector<std::wstring> tokens;
		std::size_t start = 0, end = 0;
		while ((end = text.find(sep, start)) != std::wstring::npos) {
			std::wstring temp = text.substr(start, end - start);
			if (temp != L"") tokens.push_back(temp);
			start = end + 1;
		}
		std::wstring temp = text.substr(start);
		if (temp != L"") tokens.push_back(temp);
		return tokens;
	}


/*
	IsIPAddress
	-----------
	
	This procedure tests an IP address, whether in IPv4 or IPv6 format, to see if it's in valid enough form to 
	be accepted by the winsock.
	
	str (std::wstring) : string to test.
	
	returns (BOOL) : true if the string is a valid IPv4 or IPv6 address.
*/	
	bool IsIPAddress(std::wstring str)
	{
		struct sockaddr_in sa;
		struct sockaddr_in6 sb;

		return (InetPtonW(AF_INET, str.c_str(), &(sa.sin_addr)) != 0) | (InetPtonW(AF_INET6, str.c_str(), &(sb.sin6_addr)) != 0);
	}


/*
	IsElevated
	----------

	This procedure tests whether the running process has elevated privileges. 

	(No input vars.)
	
	returns (BOOL) : true if the caller has elevated privileges.
*/
	BOOL IsElevated() {
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			TOKEN_ELEVATION Elevation;
			DWORD cbSize = sizeof(TOKEN_ELEVATION);
			if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
				fRet = Elevation.TokenIsElevated;
			}
		}
		if (hToken) {
			CloseHandle(hToken);
		}
		return fRet;
	}


/*
	ConvertToSkeleton
	-----------------

	This procedure performs a conversion to a "skeleton" using the method outlined in Unicode Consortium 
	Technical Standard 39 - "Unicode Security Mechanisms." This basically remaps over six thousand 
	lookalike characters and character sequences into their lowest-level equivalent.

	source (UnicodeString) : Unicode string to skeletonize.

	returns (UnicodeString) : skeletonized Unicode string.
*/
	// http://www.unicode.org/reports/tr39/#Confusable_Detection
	static UnicodeString ConvertToSkeleton(UnicodeString source)
	{
		UErrorCode icu_error = U_ZERO_ERROR;
		const Normalizer2 *nfd = Normalizer2::getNFDInstance(icu_error);
		UINT i;
		UnicodeString normalized, renormalized;

		// Perform a NFD normalization
		icu_error = U_ZERO_ERROR;
		normalized = nfd->normalize(source, icu_error);

		// Remap confusables into their base-level equivalents
		for (i = 0; i < confusables_map.size(); ++i)
		{
			normalized.findAndReplace(confusables_map[i].from, confusables_map[i].to);
		}

		// Perform a NFD normalization again
		icu_error = U_ZERO_ERROR;
		renormalized = nfd->normalize(normalized, icu_error);

		return renormalized;
	}



/*
	DefineConsumablesList
	---------------------

	Here comes the giant scrollfest: the confusables list! (This procedure only exists to define the 
	consumables_map set for the "ConvertToSkeleton" procedure.)

	(No input vars, no result.)
*/
	void DefineConsumablesList()
	{
		confusables_map =
		{
			// Taken from the "Recommended Cunfusable Map for IDN," published by the Unicode Consortium.
			// Version 8.0.0, generated on 17 Mar 2015, revision 1.32

			{ L"\x05AD",L"\x0596" }, //( ֭ → ֖ ) HEBREW ACCENT DEHI → HEBREW ACCENT TIPEHA	# 

			{ L"\x05AE",L"\x0598" }, //( ֮ → ֘ ) HEBREW ACCENT ZINOR → HEBREW ACCENT ZARQA	# 

			{ L"\x05A8",L"\x0599" }, //( ֨ → ֙ ) HEBREW ACCENT QADMA → HEBREW ACCENT PASHTA	# 

			{ L"\x05A4",L"\x059A" }, //( ֤ → ֚ ) HEBREW ACCENT MAHAPAKH → HEBREW ACCENT YETIV	# 

			{ L"\x1AB4",L"\x06DB" }, //( ᪴ → ۛ ) COMBINING TRIPLE DOT → ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\x20DB",L"\x06DB" }, //( ⃛ → ۛ ) COMBINING THREE DOTS ABOVE → ARABIC SMALL HIGH THREE DOTS	# →᪴→

			{ L"\x0619",L"\x0313" }, //( ؙ → ̓ ) ARABIC SMALL DAMMA → COMBINING COMMA ABOVE	# →ُ→
			{ L"\x08F3",L"\x0313" }, //( ࣳ → ̓ ) ARABIC SMALL HIGH WAW → COMBINING COMMA ABOVE	# →ُ→
			{ L"\x0343",L"\x0313" }, //( ̓ → ̓ ) COMBINING GREEK KORONIS → COMBINING COMMA ABOVE	# 
			{ L"\x0315",L"\x0313" }, //( ̕ → ̓ ) COMBINING COMMA ABOVE RIGHT → COMBINING COMMA ABOVE	# 
			{ L"\x064F",L"\x0313" }, //( ُ → ̓ ) ARABIC DAMMA → COMBINING COMMA ABOVE	# 

			{ L"\x065D",L"\x0314" }, //( ٝ → ̔ ) ARABIC REVERSED DAMMA → COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x059C",L"\x0301" }, //( ֜ → ́ ) HEBREW ACCENT GERESH → COMBINING ACUTE ACCENT	# 
			{ L"\x059D",L"\x0301" }, //( ֝ → ́ ) HEBREW ACCENT GERESH MUQDAM → COMBINING ACUTE ACCENT	# →֜→
			{ L"\x0618",L"\x0301" }, //( ؘ → ́ ) ARABIC SMALL FATHA → COMBINING ACUTE ACCENT	# →َ→
			{ L"\x0747",L"\x0301" }, //( ݇ → ́ ) SYRIAC OBLIQUE LINE ABOVE → COMBINING ACUTE ACCENT	# 
			{ L"\x0341",L"\x0301" }, //( ́ → ́ ) COMBINING ACUTE TONE MARK → COMBINING ACUTE ACCENT	# 
			{ L"\x0954",L"\x0301" }, //( ॔ → ́ ) DEVANAGARI ACUTE ACCENT → COMBINING ACUTE ACCENT	# 
			{ L"\x064E",L"\x0301" }, //( َ → ́ ) ARABIC FATHA → COMBINING ACUTE ACCENT	# 

			{ L"\x0340",L"\x0300" }, //( ̀ → ̀ ) COMBINING GRAVE TONE MARK → COMBINING GRAVE ACCENT	# 
			{ L"\x0953",L"\x0300" }, //( ॓ → ̀ ) DEVANAGARI GRAVE ACCENT → COMBINING GRAVE ACCENT	# 

			{ L"\x030C",L"\x0306" }, //( ̌ → ̆ ) COMBINING CARON → COMBINING BREVE	# 
			{ L"\xA67C",L"\x0306" }, //( ꙼ → ̆ ) COMBINING CYRILLIC KAVYKA → COMBINING BREVE	# 
			{ L"\x0658",L"\x0306" }, //( ٘ → ̆ ) ARABIC MARK NOON GHUNNA → COMBINING BREVE	# 
			{ L"\x065A",L"\x0306" }, //( ٚ → ̆ ) ARABIC VOWEL SIGN SMALL V ABOVE → COMBINING BREVE	# →̌→
			{ L"\x036E",L"\x0306" }, //( ͮ → ̆ ) COMBINING LATIN SMALL LETTER V → COMBINING BREVE	# →̌→

			{ L"\x06E8",L"\x0306\x0307" }, //( ۨ → ̆̇ ) ARABIC SMALL HIGH NOON → COMBINING BREVE, COMBINING DOT ABOVE	# →̐→
			{ L"\x0310",L"\x0306\x0307" }, //( ̐ → ̆̇ ) COMBINING CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# 
			{ L"\x0901",L"\x0306\x0307" }, //( ँ → ̆̇ ) DEVANAGARI SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →̐→
			{ L"\x0981",L"\x0306\x0307" }, //( ঁ → ̆̇ ) BENGALI SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →̐→
			{ L"\x0A81",L"\x0306\x0307" }, //( ઁ → ̆̇ ) GUJARATI SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →̐→
			{ L"\x0B01",L"\x0306\x0307" }, //( ଁ → ̆̇ ) ORIYA SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →̐→
			{ L"\x0C00",L"\x0306\x0307" }, //( ఀ → ̆̇ ) TELUGU SIGN COMBINING CANDRABINDU ABOVE → COMBINING BREVE, COMBINING DOT ABOVE	# →ँ→→̐→
			{ L"\x0C81",L"\x0306\x0307" }, //( ಁ → ̆̇ ) KANNADA SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →ँ→→̐→
			{ L"\x0D01",L"\x0306\x0307" }, //( ഁ → ̆̇ ) MALAYALAM SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →ँ→→̐→
			{ L"\x0001\x14BF",L"\x0306\x0307" }, //( 𑒿 → ̆̇ ) TIRHUTA SIGN CANDRABINDU → COMBINING BREVE, COMBINING DOT ABOVE	# →ঁ→→̐→

			{ L"\x1CD0",L"\x0302" }, //( ᳐ → ̂ ) VEDIC TONE KARSHANA → COMBINING CIRCUMFLEX ACCENT	# 
			{ L"\x0311",L"\x0302" }, //( ̑ → ̂ ) COMBINING INVERTED BREVE → COMBINING CIRCUMFLEX ACCENT	# 
			{ L"\x065B",L"\x0302" }, //( ٛ → ̂ ) ARABIC VOWEL SIGN INVERTED SMALL V ABOVE → COMBINING CIRCUMFLEX ACCENT	# 
			{ L"\x07EE",L"\x0302" }, //( ߮ → ̂ ) NKO COMBINING LONG DESCENDING TONE → COMBINING CIRCUMFLEX ACCENT	# 

			{ L"\x05AF",L"\x030A" }, //( ֯ → ̊ ) HEBREW MARK MASORA CIRCLE → COMBINING RING ABOVE	# 
			{ L"\x06DF",L"\x030A" }, //( ۟ → ̊ ) ARABIC SMALL HIGH ROUNDED ZERO → COMBINING RING ABOVE	# →ْ→
			{ L"\x17D3",L"\x030A" }, //( ៓ → ̊ ) KHMER SIGN BATHAMASAT → COMBINING RING ABOVE	# 
			{ L"\x309A",L"\x030A" }, //( ゚ → ̊ ) COMBINING KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK → COMBINING RING ABOVE	# 
			{ L"\x0652",L"\x030A" }, //( ْ → ̊ ) ARABIC SUKUN → COMBINING RING ABOVE	# 
			{ L"\x0B82",L"\x030A" }, //( ஂ → ̊ ) TAMIL SIGN ANUSVARA → COMBINING RING ABOVE	# 
			{ L"\x1036",L"\x030A" }, //( ံ → ̊ ) MYANMAR SIGN ANUSVARA → COMBINING RING ABOVE	# 
			{ L"\x17C6",L"\x030A" }, //( ំ → ̊ ) KHMER SIGN NIKAHIT → COMBINING RING ABOVE	# 
			{ L"\x0E4D",L"\x030A" }, //( ํ → ̊ ) THAI CHARACTER NIKHAHIT → COMBINING RING ABOVE	# 
			{ L"\x0ECD",L"\x030A" }, //( ໍ → ̊ ) LAO NIGGAHITA → COMBINING RING ABOVE	# 
			{ L"\x0366",L"\x030A" }, //( ͦ → ̊ ) COMBINING LATIN SMALL LETTER O → COMBINING RING ABOVE	# 

			{ L"\x08EB",L"\x0308" }, //( ࣫ → ̈ ) ARABIC TONE TWO DOTS ABOVE → COMBINING DIAERESIS	# 
			{ L"\x07F3",L"\x0308" }, //( ߳ → ̈ ) NKO COMBINING DOUBLE DOT ABOVE → COMBINING DIAERESIS	# 

			{ L"\x064B",L"\x030B" }, //( ً → ̋ ) ARABIC FATHATAN → COMBINING DOUBLE ACUTE ACCENT	# 
			{ L"\x08F0",L"\x030B" }, //( ࣰ → ̋ ) ARABIC OPEN FATHATAN → COMBINING DOUBLE ACUTE ACCENT	# →ً→

			{ L"\x0342",L"\x0303" }, //( ͂ → ̃ ) COMBINING GREEK PERISPOMENI → COMBINING TILDE	# 
			{ L"\x0653",L"\x0303" }, //( ٓ → ̃ ) ARABIC MADDAH ABOVE → COMBINING TILDE	# 

			{ L"\x05C4",L"\x0307" }, //( ׄ → ̇ ) HEBREW MARK UPPER DOT → COMBINING DOT ABOVE	# 
			{ L"\x06EC",L"\x0307" }, //( ۬ → ̇ ) ARABIC ROUNDED HIGH STOP WITH FILLED CENTRE → COMBINING DOT ABOVE	# 
			{ L"\x0740",L"\x0307" }, //( ݀ → ̇ ) SYRIAC FEMININE DOT → COMBINING DOT ABOVE	# →݁→
			{ L"\x08EA",L"\x0307" }, //( ࣪ → ̇ ) ARABIC TONE ONE DOT ABOVE → COMBINING DOT ABOVE	# 
			{ L"\x0741",L"\x0307" }, //( ݁ → ̇ ) SYRIAC QUSHSHAYA → COMBINING DOT ABOVE	# 
			{ L"\x0358",L"\x0307" }, //( ͘ → ̇ ) COMBINING DOT ABOVE RIGHT → COMBINING DOT ABOVE	# 
			{ L"\x05B9",L"\x0307" }, //( ֹ → ̇ ) HEBREW POINT HOLAM → COMBINING DOT ABOVE	# 
			{ L"\x05BA",L"\x0307" }, //( ֺ → ̇ ) HEBREW POINT HOLAM HASER FOR VAV → COMBINING DOT ABOVE	# →ׁ→
			{ L"\x05C2",L"\x0307" }, //( ׂ → ̇ ) HEBREW POINT SIN DOT → COMBINING DOT ABOVE	# 
			{ L"\x05C1",L"\x0307" }, //( ׁ → ̇ ) HEBREW POINT SHIN DOT → COMBINING DOT ABOVE	# 
			{ L"\x07ED",L"\x0307" }, //( ߭ → ̇ ) NKO COMBINING SHORT RISING TONE → COMBINING DOT ABOVE	# 
			{ L"\x0902",L"\x0307" }, //( ं → ̇ ) DEVANAGARI SIGN ANUSVARA → COMBINING DOT ABOVE	# 
			{ L"\x0A02",L"\x0307" }, //( ਂ → ̇ ) GURMUKHI SIGN BINDI → COMBINING DOT ABOVE	# 
			{ L"\x0A82",L"\x0307" }, //( ં → ̇ ) GUJARATI SIGN ANUSVARA → COMBINING DOT ABOVE	# 
			{ L"\x0BCD",L"\x0307" }, //( ் → ̇ ) TAMIL SIGN VIRAMA → COMBINING DOT ABOVE	# 

			{ L"\x0337",L"\x0338" }, //( ̷ → ̸ ) COMBINING SHORT SOLIDUS OVERLAY → COMBINING LONG SOLIDUS OVERLAY	# 

			{ L"\x1AB7",L"\x0328" }, //( ᪷ → ̨ ) COMBINING OPEN MARK BELOW → COMBINING OGONEK	# 
			{ L"\x0322",L"\x0328" }, //( ̢ → ̨ ) COMBINING RETROFLEX HOOK BELOW → COMBINING OGONEK	# 
			{ L"\x0345",L"\x0328" }, //( ͅ → ̨ ) COMBINING GREEK YPOGEGRAMMENI → COMBINING OGONEK	# 

			{ L"\x1CD2",L"\x0304" }, //( ᳒ → ̄ ) VEDIC TONE PRENKHA → COMBINING MACRON	# 
			{ L"\x0305",L"\x0304" }, //( ̅ → ̄ ) COMBINING OVERLINE → COMBINING MACRON	# 
			{ L"\x0659",L"\x0304" }, //( ٙ → ̄ ) ARABIC ZWARAKAY → COMBINING MACRON	# 
			{ L"\x07EB",L"\x0304" }, //( ߫ → ̄ ) NKO COMBINING SHORT HIGH TONE → COMBINING MACRON	# 

			{ L"\x1CDA",L"\x030E" }, //( ᳚ → ̎ ) VEDIC TONE DOUBLE SVARITA → COMBINING DOUBLE VERTICAL LINE ABOVE	# 

			{ L"\x0657",L"\x0312" }, //( ٗ → ̒ ) ARABIC INVERTED DAMMA → COMBINING TURNED COMMA ABOVE	# 

			{ L"\x0357",L"\x0350" }, //( ͗ → ͐ ) COMBINING RIGHT HALF RING ABOVE → COMBINING RIGHT ARROWHEAD ABOVE	# →ࣿ→→ࣸ→
			{ L"\x08FF",L"\x0350" }, //( ࣿ → ͐ ) ARABIC MARK SIDEWAYS NOON GHUNNA → COMBINING RIGHT ARROWHEAD ABOVE	# →ࣸ→
			{ L"\x08F8",L"\x0350" }, //( ࣸ → ͐ ) ARABIC RIGHT ARROWHEAD ABOVE → COMBINING RIGHT ARROWHEAD ABOVE	# 

			{ L"\x0900",L"\x0352" }, //( ऀ → ͒ ) DEVANAGARI SIGN INVERTED CANDRABINDU → COMBINING FERMATA	# 

			{ L"\x1CED",L"\x0316" }, //( ᳭ → ̖ ) VEDIC SIGN TIRYAK → COMBINING GRAVE ACCENT BELOW	# 

			{ L"\x1CDC",L"\x0329" }, //( ᳜ → ̩ ) VEDIC TONE KATHAKA ANUDATTA → COMBINING VERTICAL LINE BELOW	# 
			{ L"\x0656",L"\x0329" }, //( ٖ → ̩ ) ARABIC SUBSCRIPT ALEF → COMBINING VERTICAL LINE BELOW	# 

			{ L"\x1CD5",L"\x032B" }, //( ᳕ → ̫ ) VEDIC TONE YAJURVEDIC AGGRAVATED INDEPENDENT SVARITA → COMBINING INVERTED DOUBLE ARCH BELOW	# 

			{ L"\x0347",L"\x0333" }, //( ͇ → ̳ ) COMBINING EQUALS SIGN BELOW → COMBINING DOUBLE LOW LINE	# 

			{ L"\x08F9",L"\x0354" }, //( ࣹ → ͔ ) ARABIC LEFT ARROWHEAD BELOW → COMBINING LEFT ARROWHEAD BELOW	# 

			{ L"\x08FA",L"\x0355" }, //( ࣺ → ͕ ) ARABIC RIGHT ARROWHEAD BELOW → COMBINING RIGHT ARROWHEAD BELOW	# 

			{ L"\x309B",L"\xFF9E" }, //( ゛ → ﾞ ) KATAKANA-HIRAGANA VOICED SOUND MARK → HALFWIDTH KATAKANA VOICED SOUND MARK	# 

			{ L"\x309C",L"\xFF9F" }, //( ゜ → ﾟ ) KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK → HALFWIDTH KATAKANA SEMI-VOICED SOUND MARK	# 

			{ L"\x0336",L"\x0335" }, //( ̶ → ̵ ) COMBINING LONG STROKE OVERLAY → COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x302C",L"\x0309" }, //( 〬 → ̉ ) IDEOGRAPHIC DEPARTING TONE MARK → COMBINING HOOK ABOVE	# 

			{ L"\x05C5",L"\x0323" }, //( ׅ → ̣ ) HEBREW MARK LOWER DOT → COMBINING DOT BELOW	# 
			{ L"\x08ED",L"\x0323" }, //( ࣭ → ̣ ) ARABIC TONE ONE DOT BELOW → COMBINING DOT BELOW	# 
			{ L"\x1CDD",L"\x0323" }, //( ᳝ → ̣ ) VEDIC TONE DOT BELOW → COMBINING DOT BELOW	# 
			{ L"\x05B4",L"\x0323" }, //( ִ → ̣ ) HEBREW POINT HIRIQ → COMBINING DOT BELOW	# 
			{ L"\x065C",L"\x0323" }, //( ٜ → ̣ ) ARABIC VOWEL SIGN DOT BELOW → COMBINING DOT BELOW	# 
			{ L"\x093C",L"\x0323" }, //( ़ → ̣ ) DEVANAGARI SIGN NUKTA → COMBINING DOT BELOW	# 
			{ L"\x09BC",L"\x0323" }, //( ় → ̣ ) BENGALI SIGN NUKTA → COMBINING DOT BELOW	# 
			{ L"\x0A3C",L"\x0323" }, //( ਼ → ̣ ) GURMUKHI SIGN NUKTA → COMBINING DOT BELOW	# 
			{ L"\x0ABC",L"\x0323" }, //( ઼ → ̣ ) GUJARATI SIGN NUKTA → COMBINING DOT BELOW	# 
			{ L"\x0B3C",L"\x0323" }, //( ଼ → ̣ ) ORIYA SIGN NUKTA → COMBINING DOT BELOW	# 
			{ L"\x0001\x14C3",L"\x0323" }, //( 𑓃 → ̣ ) TIRHUTA SIGN NUKTA → COMBINING DOT BELOW	# →়→
			{ L"\x0001\x0A3A",L"\x0323" }, //( 𐨺 → ̣ ) KHAROSHTHI SIGN DOT BELOW → COMBINING DOT BELOW	# 

			{ L"\x08EE",L"\x0324" }, //( ࣮ → ̤ ) ARABIC TONE TWO DOTS BELOW → COMBINING DIAERESIS BELOW	# 
			{ L"\x1CDE",L"\x0324" }, //( ᳞ → ̤ ) VEDIC TONE TWO DOTS BELOW → COMBINING DIAERESIS BELOW	# 

			{ L"\x302D",L"\x0325" }, //( 〭 → ̥ ) IDEOGRAPHIC ENTERING TONE MARK → COMBINING RING BELOW	# 

			{ L"\x0327",L"\x0326" }, //( ̧ → ̦ ) COMBINING CEDILLA → COMBINING COMMA BELOW	# →̡→
			{ L"\x0321",L"\x0326" }, //( ̡ → ̦ ) COMBINING PALATALIZED HOOK BELOW → COMBINING COMMA BELOW	# 
			{ L"\x0339",L"\x0326" }, //( ̹ → ̦ ) COMBINING RIGHT HALF RING BELOW → COMBINING COMMA BELOW	# →̧→→̡→

			{ L"\x1CD9",L"\x032D" }, //( ᳙ → ̭ ) VEDIC TONE YAJURVEDIC KATHAKA INDEPENDENT SVARITA SCHROEDER → COMBINING CIRCUMFLEX ACCENT BELOW	# 

			{ L"\x1CD8",L"\x032E" }, //( ᳘ → ̮ ) VEDIC TONE CANDRA BELOW → COMBINING BREVE BELOW	# 

			{ L"\x0952",L"\x0331" }, //( ॒ → ̱ ) DEVANAGARI STRESS SIGN ANUDATTA → COMBINING MACRON BELOW	# 
			{ L"\x0320",L"\x0331" }, //( ̠ → ̱ ) COMBINING MINUS SIGN BELOW → COMBINING MACRON BELOW	# 

			{ L"\x08F1",L"\x064C" }, //( ࣱ → ٌ ) ARABIC OPEN DAMMATAN → ARABIC DAMMATAN	# 
			{ L"\x08E8",L"\x064C" }, //( ࣨ → ٌ ) ARABIC CURLY DAMMATAN → ARABIC DAMMATAN	# 
			{ L"\x08E5",L"\x064C" }, //( ࣥ → ٌ ) ARABIC CURLY DAMMA → ARABIC DAMMATAN	# 

			{ L"\xFC5E",L"\xFE72\x0651" }, //( ‎ﱞ‎ → ‎ﹲّ‎ ) ARABIC LIGATURE SHADDA WITH DAMMATAN ISOLATED FORM → ARABIC DAMMATAN ISOLATED FORM, ARABIC SHADDA	# 

			{ L"\x08F2",L"\x064D" }, //( ࣲ → ٍ ) ARABIC OPEN KASRATAN → ARABIC KASRATAN	# 

			{ L"\xFC5F",L"\xFE74\x0651" }, //( ‎ﱟ‎ → ‎ﹴّ‎ ) ARABIC LIGATURE SHADDA WITH KASRATAN ISOLATED FORM → ARABIC KASRATAN ISOLATED FORM, ARABIC SHADDA	# 

			{ L"\xFCF2",L"\xFE77\x0651" }, //( ‎ﳲ‎ → ‎ﹷّ‎ ) ARABIC LIGATURE SHADDA WITH FATHA MEDIAL FORM → ARABIC FATHA MEDIAL FORM, ARABIC SHADDA	# 

			{ L"\xFC60",L"\xFE76\x0651" }, //( ‎ﱠ‎ → ‎ﹶّ‎ ) ARABIC LIGATURE SHADDA WITH FATHA ISOLATED FORM → ARABIC FATHA ISOLATED FORM, ARABIC SHADDA	# 

			{ L"\xFCF3",L"\xFE79\x0651" }, //( ‎ﳳ‎ → ‎ﹹّ‎ ) ARABIC LIGATURE SHADDA WITH DAMMA MEDIAL FORM → ARABIC DAMMA MEDIAL FORM, ARABIC SHADDA	# 

			{ L"\xFC61",L"\xFE78\x0651" }, //( ‎ﱡ‎ → ‎ﹸّ‎ ) ARABIC LIGATURE SHADDA WITH DAMMA ISOLATED FORM → ARABIC DAMMA ISOLATED FORM, ARABIC SHADDA	# 

			{ L"\x061A",L"\x0650" }, //( ؚ → ِ ) ARABIC SMALL KASRA → ARABIC KASRA	# 
			{ L"\x0317",L"\x0650" }, //( ̗ → ِ ) COMBINING ACUTE ACCENT BELOW → ARABIC KASRA	# 

			{ L"\xFCF4",L"\xFE7B\x0651" }, //( ‎ﳴ‎ → ‎ﹻّ‎ ) ARABIC LIGATURE SHADDA WITH KASRA MEDIAL FORM → ARABIC KASRA MEDIAL FORM, ARABIC SHADDA	# 

			{ L"\xFC62",L"\xFE7A\x0651" }, //( ‎ﱢ‎ → ‎ﹺّ‎ ) ARABIC LIGATURE SHADDA WITH KASRA ISOLATED FORM → ARABIC KASRA ISOLATED FORM, ARABIC SHADDA	# 

			{ L"\xFC63",L"\xFE7C\x0670" }, //( ‎ﱣ‎ → ‎ﹼٰ‎ ) ARABIC LIGATURE SHADDA WITH SUPERSCRIPT ALEF ISOLATED FORM → ARABIC SHADDA ISOLATED FORM, ARABIC LETTER SUPERSCRIPT ALEF	# 

			{ L"\x065F",L"\x0655" }, //( ٟ → ٕ ) ARABIC WAVY HAMZA BELOW → ARABIC HAMZA BELOW	# 

			{ L"\x030D",L"\x0670" }, //( ̍ → ٰ ) COMBINING VERTICAL LINE ABOVE → ARABIC LETTER SUPERSCRIPT ALEF	# 

			{ L"\x0742",L"\x073C" }, //( ݂ → ܼ ) SYRIAC RUKKAKHA → SYRIAC HBASA-ESASA DOTTED	# 

			{ L"\x0A03",L"\x0983" }, //( ਃ → ঃ ) GURMUKHI SIGN VISARGA → BENGALI SIGN VISARGA	# 
			{ L"\x0C03",L"\x0983" }, //( ః → ঃ ) TELUGU SIGN VISARGA → BENGALI SIGN VISARGA	# →ਃ→
			{ L"\x0C83",L"\x0983" }, //( ಃ → ঃ ) KANNADA SIGN VISARGA → BENGALI SIGN VISARGA	# →ః→→ਃ→
			{ L"\x0D03",L"\x0983" }, //( ഃ → ঃ ) MALAYALAM SIGN VISARGA → BENGALI SIGN VISARGA	# →ಃ→→ః→→ਃ→
			{ L"\x0D83",L"\x0983" }, //( ඃ → ঃ ) SINHALA SIGN VISARGAYA → BENGALI SIGN VISARGA	# →ഃ→→ಃ→→ః→→ਃ→
			{ L"\x1038",L"\x0983" }, //( း → ঃ ) MYANMAR SIGN VISARGA → BENGALI SIGN VISARGA	# →ඃ→→ഃ→→ಃ→→ః→→ਃ→
			{ L"\x0001\x14C1",L"\x0983" }, //( 𑓁 → ঃ ) TIRHUTA SIGN VISARGA → BENGALI SIGN VISARGA	# 

			{ L"\x17CB",L"\x0E48" }, //( ់ → ่ ) KHMER SIGN BANTOC → THAI CHARACTER MAI EK	# 
			{ L"\x0EC8",L"\x0E48" }, //( ່ → ่ ) LAO TONE MAI EK → THAI CHARACTER MAI EK	# 

			{ L"\x0EC9",L"\x0E49" }, //( ້ → ้ ) LAO TONE MAI THO → THAI CHARACTER MAI THO	# 

			{ L"\x0ECA",L"\x0E4A" }, //( ໊ → ๊ ) LAO TONE MAI TI → THAI CHARACTER MAI TRI	# 

			{ L"\x0ECB",L"\x0E4B" }, //( ໋ → ๋ ) LAO TONE MAI CATAWA → THAI CHARACTER MAI CHATTAWA	# 

			{ L"\x2028",L"\x0020" }, //(  →   ) LINE SEPARATOR → SPACE	# 
			{ L"\x2029",L"\x0020" }, //(  →   ) PARAGRAPH SEPARATOR → SPACE	# 
			{ L"\x1680",L"\x0020" }, //(   →   ) OGHAM SPACE MARK → SPACE	# 
			{ L"\x2000",L"\x0020" }, //(   →   ) EN QUAD → SPACE	# 
			{ L"\x2001",L"\x0020" }, //(   →   ) EM QUAD → SPACE	# 
			{ L"\x2002",L"\x0020" }, //(   →   ) EN SPACE → SPACE	# 
			{ L"\x2003",L"\x0020" }, //(   →   ) EM SPACE → SPACE	# 
			{ L"\x2004",L"\x0020" }, //(   →   ) THREE-PER-EM SPACE → SPACE	# 
			{ L"\x2005",L"\x0020" }, //(   →   ) FOUR-PER-EM SPACE → SPACE	# 
			{ L"\x2006",L"\x0020" }, //(   →   ) SIX-PER-EM SPACE → SPACE	# 
			{ L"\x2008",L"\x0020" }, //(   →   ) PUNCTUATION SPACE → SPACE	# 
			{ L"\x2009",L"\x0020" }, //(   →   ) THIN SPACE → SPACE	# 
			{ L"\x200A",L"\x0020" }, //(   →   ) HAIR SPACE → SPACE	# 
			{ L"\x205F",L"\x0020" }, //(   →   ) MEDIUM MATHEMATICAL SPACE → SPACE	# 
			{ L"\x00A0",L"\x0020" }, //(   →   ) NO-BREAK SPACE → SPACE	# 
			{ L"\x2007",L"\x0020" }, //(   →   ) FIGURE SPACE → SPACE	# 
			{ L"\x202F",L"\x0020" }, //(   →   ) NARROW NO-BREAK SPACE → SPACE	# 

			{ L"\x07FA",L"\x005F" }, //( ‎ߺ‎ → _ ) NKO LAJANYALAN → LOW LINE	# 
			{ L"\xFE4D",L"\x005F" }, //( ﹍ → _ ) DASHED LOW LINE → LOW LINE	# 
			{ L"\xFE4E",L"\x005F" }, //( ﹎ → _ ) CENTRELINE LOW LINE → LOW LINE	# 
			{ L"\xFE4F",L"\x005F" }, //( ﹏ → _ ) WAVY LOW LINE → LOW LINE	# 

			{ L"\x2010",L"\x002D" }, //( ‐ → - ) HYPHEN → HYPHEN-MINUS	# 
			{ L"\x2011",L"\x002D" }, //( ‑ → - ) NON-BREAKING HYPHEN → HYPHEN-MINUS	# 
			{ L"\x2012",L"\x002D" }, //( ‒ → - ) FIGURE DASH → HYPHEN-MINUS	# 
			{ L"\x2013",L"\x002D" }, //( – → - ) EN DASH → HYPHEN-MINUS	# 
			{ L"\xFE58",L"\x002D" }, //( ﹘ → - ) SMALL EM DASH → HYPHEN-MINUS	# 
			{ L"\x06D4",L"\x002D" }, //( ‎۔‎ → - ) ARABIC FULL STOP → HYPHEN-MINUS	# →‐→
			{ L"\x2043",L"\x002D" }, //( ⁃ → - ) HYPHEN BULLET → HYPHEN-MINUS	# →‐→
			{ L"\x02D7",L"\x002D" }, //( ˗ → - ) MODIFIER LETTER MINUS SIGN → HYPHEN-MINUS	# 
			{ L"\x2212",L"\x002D" }, //( − → - ) MINUS SIGN → HYPHEN-MINUS	# 
			{ L"\x2796",L"\x002D" }, //( ➖ → - ) HEAVY MINUS SIGN → HYPHEN-MINUS	# →−→
			{ L"\x2CBA",L"\x002D" }, //( Ⲻ → - ) COPTIC CAPITAL LETTER DIALECT-P NI → HYPHEN-MINUS	# →‒→

			{ L"\x2A29",L"\x002D\x0313" }, //( ⨩ → -̓ ) MINUS SIGN WITH COMMA ABOVE → HYPHEN-MINUS, COMBINING COMMA ABOVE	# →−̓→

			{ L"\x2E1A",L"\x002D\x0308" }, //( ⸚ → -̈ ) HYPHEN WITH DIAERESIS → HYPHEN-MINUS, COMBINING DIAERESIS	# 

			{ L"\xFB29",L"\x002D\x0307" }, //( ﬩ → -̇ ) HEBREW LETTER ALTERNATIVE PLUS SIGN → HYPHEN-MINUS, COMBINING DOT ABOVE	# →∸→→−̇→
			{ L"\x2238",L"\x002D\x0307" }, //( ∸ → -̇ ) DOT MINUS → HYPHEN-MINUS, COMBINING DOT ABOVE	# →−̇→

			{ L"\x2A2A",L"\x002D\x0323" }, //( ⨪ → -̣ ) MINUS SIGN WITH DOT BELOW → HYPHEN-MINUS, COMBINING DOT BELOW	# →−̣→

			{ L"\xA4FE",L"\x002D\x002E" }, //( ꓾ → -. ) LISU PUNCTUATION COMMA → HYPHEN-MINUS, FULL STOP	# 

			{ L"\xFF5E",L"\x301C" }, //( ～ → 〜 ) FULLWIDTH TILDE → WAVE DASH	# 

			{ L"\x060D",L"\x002C" }, //( ‎؍‎ → , ) ARABIC DATE SEPARATOR → COMMA	# →‎٫‎→
			{ L"\x066B",L"\x002C" }, //( ‎٫‎ → , ) ARABIC DECIMAL SEPARATOR → COMMA	# 
			{ L"\x201A",L"\x002C" }, //( ‚ → , ) SINGLE LOW-9 QUOTATION MARK → COMMA	# 
			{ L"\x00B8",L"\x002C" }, //( ¸ → , ) CEDILLA → COMMA	# 
			{ L"\xA4F9",L"\x002C" }, //( ꓹ → , ) LISU LETTER TONE NA PO → COMMA	# 

			{ L"\x2E32",L"\x060C" }, //( ⸲ → ، ) TURNED COMMA → ARABIC COMMA	# 
			{ L"\x066C",L"\x060C" }, //( ‎٬‎ → ، ) ARABIC THOUSANDS SEPARATOR → ARABIC COMMA	# 

			{ L"\x037E",L"\x003B" }, //( ; → ; ) GREEK QUESTION MARK → SEMICOLON	# 

			{ L"\x2E35",L"\x061B" }, //( ⸵ → ‎؛‎ ) TURNED SEMICOLON → ARABIC SEMICOLON	# 

			{ L"\x0903",L"\x003A" }, //( ः → : ) DEVANAGARI SIGN VISARGA → COLON	# 
			{ L"\x0A83",L"\x003A" }, //( ઃ → : ) GUJARATI SIGN VISARGA → COLON	# 
			{ L"\xFF1A",L"\x003A" }, //( ： → : ) FULLWIDTH COLON → COLON	# →︰→
			{ L"\x0589",L"\x003A" }, //( ։ → : ) ARMENIAN FULL STOP → COLON	# 
			{ L"\x0703",L"\x003A" }, //( ‎܃‎ → : ) SYRIAC SUPRALINEAR COLON → COLON	# 
			{ L"\x0704",L"\x003A" }, //( ‎܄‎ → : ) SYRIAC SUBLINEAR COLON → COLON	# 
			{ L"\x16EC",L"\x003A" }, //( ᛬ → : ) RUNIC MULTIPLE PUNCTUATION → COLON	# 
			{ L"\xFE30",L"\x003A" }, //( ︰ → : ) PRESENTATION FORM FOR VERTICAL TWO DOT LEADER → COLON	# 
			{ L"\x1803",L"\x003A" }, //( ᠃ → : ) MONGOLIAN FULL STOP → COLON	# 
			{ L"\x1809",L"\x003A" }, //( ᠉ → : ) MONGOLIAN MANCHU FULL STOP → COLON	# 
			{ L"\x205A",L"\x003A" }, //( ⁚ → : ) TWO DOT PUNCTUATION → COLON	# 
			{ L"\x05C3",L"\x003A" }, //( ‎׃‎ → : ) HEBREW PUNCTUATION SOF PASUQ → COLON	# 
			{ L"\x02F8",L"\x003A" }, //( ˸ → : ) MODIFIER LETTER RAISED COLON → COLON	# 
			{ L"\xA789",L"\x003A" }, //( ꞉ → : ) MODIFIER LETTER COLON → COLON	# 
			{ L"\x2236",L"\x003A" }, //( ∶ → : ) RATIO → COLON	# 
			{ L"\x02D0",L"\x003A" }, //( ː → : ) MODIFIER LETTER TRIANGULAR COLON → COLON	# 
			{ L"\xA4FD",L"\x003A" }, //( ꓽ → : ) LISU LETTER TONE MYA JEU → COLON	# 

			{ L"\x2A74",L"\x003A\x003A\x003D" }, //( ⩴ → ::= ) DOUBLE COLON EQUAL → COLON, COLON, EQUALS SIGN	# 

			{ L"\x29F4",L"\x003A\x2192" }, //( ⧴ → :→ ) RULE-DELAYED → COLON, RIGHTWARDS ARROW	# 

			{ L"\xFF01",L"\x0021" }, //( ！ → ! ) FULLWIDTH EXCLAMATION MARK → EXCLAMATION MARK	# →ǃ→
			{ L"\x01C3",L"\x0021" }, //( ǃ → ! ) LATIN LETTER RETROFLEX CLICK → EXCLAMATION MARK	# 
			{ L"\x2D51",L"\x0021" }, //( ⵑ → ! ) TIFINAGH LETTER TUAREG YANG → EXCLAMATION MARK	# 

			{ L"\x203C",L"\x0021\x0021" }, //( ‼ → !! ) DOUBLE EXCLAMATION MARK → EXCLAMATION MARK, EXCLAMATION MARK	# 

			{ L"\x2049",L"\x0021\x003F" }, //( ⁉ → !? ) EXCLAMATION QUESTION MARK → EXCLAMATION MARK, QUESTION MARK	# 

			{ L"\x0294",L"\x003F" }, //( ʔ → ? ) LATIN LETTER GLOTTAL STOP → QUESTION MARK	# 
			{ L"\x0241",L"\x003F" }, //( Ɂ → ? ) LATIN CAPITAL LETTER GLOTTAL STOP → QUESTION MARK	# →ʔ→
			{ L"\x097D",L"\x003F" }, //( ॽ → ? ) DEVANAGARI LETTER GLOTTAL STOP → QUESTION MARK	# 
			{ L"\x13AE",L"\x003F" }, //( Ꭾ → ? ) CHEROKEE LETTER HE → QUESTION MARK	# →Ɂ→→ʔ→

			{ L"\x2048",L"\x003F\x0021" }, //( ⁈ → ?! ) QUESTION EXCLAMATION MARK → QUESTION MARK, EXCLAMATION MARK	# 

			{ L"\x2047",L"\x003F\x003F" }, //( ⁇ → ?? ) DOUBLE QUESTION MARK → QUESTION MARK, QUESTION MARK	# 

			{ L"\x2E2E",L"\x061F" }, //( ⸮ → ‎؟‎ ) REVERSED QUESTION MARK → ARABIC QUESTION MARK	# 

			{ L"\x0000\x01D1\x6D",L"\x002E" }, //( 𝅭 → . ) MUSICAL SYMBOL COMBINING AUGMENTATION DOT → FULL STOP	# 
			{ L"\x2024",L"\x002E" }, //( ․ → . ) ONE DOT LEADER → FULL STOP	# 
			{ L"\x0701",L"\x002E" }, //( ‎܁‎ → . ) SYRIAC SUPRALINEAR FULL STOP → FULL STOP	# 
			{ L"\x0702",L"\x002E" }, //( ‎܂‎ → . ) SYRIAC SUBLINEAR FULL STOP → FULL STOP	# 
			{ L"\xA60E",L"\x002E" }, //( ꘎ → . ) VAI FULL STOP → FULL STOP	# 
			{ L"\x0000\x010A\x50",L"\x002E" }, //( ‎𐩐‎ → . ) KHAROSHTHI PUNCTUATION DOT → FULL STOP	# 
			{ L"\x0660",L"\x002E" }, //( ‎٠‎ → . ) ARABIC-INDIC DIGIT ZERO → FULL STOP	# 
			{ L"\x06F0",L"\x002E" }, //( ۰ → . ) EXTENDED ARABIC-INDIC DIGIT ZERO → FULL STOP	# →‎٠‎→
			{ L"\xA4F8",L"\x002E" }, //( ꓸ → . ) LISU LETTER TONE MYA TI → FULL STOP	# 

			{ L"\xA4FB",L"\x002E\x002C" }, //( ꓻ → ., ) LISU LETTER TONE MYA BO → FULL STOP, COMMA	# 

			{ L"\x2025",L"\x002E\x002E" }, //( ‥ → .. ) TWO DOT LEADER → FULL STOP, FULL STOP	# 
			{ L"\xA4FA",L"\x002E\x002E" }, //( ꓺ → .. ) LISU LETTER TONE MYA CYA → FULL STOP, FULL STOP	# 

			{ L"\x2026",L"\x002E\x002E\x002E" }, //( … → ... ) HORIZONTAL ELLIPSIS → FULL STOP, FULL STOP, FULL STOP	# 

			{ L"\x30FB",L"\x00B7" }, //( ・ → · ) KATAKANA MIDDLE DOT → MIDDLE DOT	# →•→
			{ L"\xFF65",L"\x00B7" }, //( ･ → · ) HALFWIDTH KATAKANA MIDDLE DOT → MIDDLE DOT	# →•→
			{ L"\x16EB",L"\x00B7" }, //( ᛫ → · ) RUNIC SINGLE PUNCTUATION → MIDDLE DOT	# 
			{ L"\x0387",L"\x00B7" }, //( · → · ) GREEK ANO TELEIA → MIDDLE DOT	# 
			{ L"\x2E31",L"\x00B7" }, //( ⸱ → · ) WORD SEPARATOR MIDDLE DOT → MIDDLE DOT	# 
			{ L"\x0001\x0101",L"\x00B7" }, //( 𐄁 → · ) AEGEAN WORD SEPARATOR DOT → MIDDLE DOT	# 
			{ L"\x2022",L"\x00B7" }, //( • → · ) BULLET → MIDDLE DOT	# 
			{ L"\x2027",L"\x00B7" }, //( ‧ → · ) HYPHENATION POINT → MIDDLE DOT	# 
			{ L"\x2219",L"\x00B7" }, //( ∙ → · ) BULLET OPERATOR → MIDDLE DOT	# 
			{ L"\x22C5",L"\x00B7" }, //( ⋅ → · ) DOT OPERATOR → MIDDLE DOT	# 
			{ L"\x1427",L"\x00B7" }, //( ᐧ → · ) CANADIAN SYLLABICS FINAL MIDDLE DOT → MIDDLE DOT	# 
			{ L"\xA78F",L"\x00B7" }, //( ꞏ → · ) LATIN LETTER SINOLOGICAL DOT → MIDDLE DOT	# 

			{ L"\x22EF",L"\x00B7\x00B7\x00B7" }, //( ⋯ → ··· ) MIDLINE HORIZONTAL ELLIPSIS → MIDDLE DOT, MIDDLE DOT, MIDDLE DOT	# 
			{ L"\x2D48",L"\x00B7\x00B7\x00B7" }, //( ⵈ → ··· ) TIFINAGH LETTER TUAREG YAQ → MIDDLE DOT, MIDDLE DOT, MIDDLE DOT	# →⋯→

			{ L"\x1444",L"\x00B7\x003C" }, //( ᑄ → ·< ) CANADIAN SYLLABICS PWA → MIDDLE DOT, LESS-THAN SIGN	# →ᐧᐸ→

			{ L"\x22D7",L"\x00B7\x003E" }, //( ⋗ → ·> ) GREATER-THAN WITH DOT → MIDDLE DOT, GREATER-THAN SIGN	# →ᑀ→→ᐧᐳ→
			{ L"\x1437",L"\x00B7\x003E" }, //( ᐷ → ·> ) CANADIAN SYLLABICS CARRIER HI → MIDDLE DOT, GREATER-THAN SIGN	# →ᑀ→→ᐧᐳ→
			{ L"\x1440",L"\x00B7\x003E" }, //( ᑀ → ·> ) CANADIAN SYLLABICS PWO → MIDDLE DOT, GREATER-THAN SIGN	# →ᐧᐳ→

			{ L"\x152F",L"\x00B7\x0034" }, //( ᔯ → ·4 ) CANADIAN SYLLABICS YWE → MIDDLE DOT, DIGIT FOUR	# →ᐧ4→

			{ L"\x147A",L"\x00B7\x0064" }, //( ᑺ → ·d ) CANADIAN SYLLABICS KWO → MIDDLE DOT, LATIN SMALL LETTER D	# →ᐧᑯ→

			{ L"\x1498",L"\x00B7\x004A" }, //( ᒘ → ·J ) CANADIAN SYLLABICS CWO → MIDDLE DOT, LATIN CAPITAL LETTER J	# →ᐧᒍ→

			{ L"\x14B6",L"\x00B7\x004C" }, //( ᒶ → ·L ) CANADIAN SYLLABICS MWA → MIDDLE DOT, LATIN CAPITAL LETTER L	# →ᐧL→

			{ L"\x1476",L"\x00B7\x0050" }, //( ᑶ → ·P ) CANADIAN SYLLABICS KWI → MIDDLE DOT, LATIN CAPITAL LETTER P	# →ᐧᑭ→

			{ L"\x1457",L"\x00B7\x0055" }, //( ᑗ → ·U ) CANADIAN SYLLABICS TWE → MIDDLE DOT, LATIN CAPITAL LETTER U	# →ᐧᑌ→→·ᑌ→

			{ L"\x143A",L"\x00B7\x0056" }, //( ᐺ → ·V ) CANADIAN SYLLABICS PWE → MIDDLE DOT, LATIN CAPITAL LETTER V	# →ᐧᐯ→

			{ L"\x143C",L"\x00B7\x0245" }, //( ᐼ → ·Ʌ ) CANADIAN SYLLABICS PWI → MIDDLE DOT, LATIN CAPITAL LETTER TURNED V	# →ᐧᐱ→→·ᐱ→

			{ L"\x14AE",L"\x00B7\x0393" }, //( ᒮ → ·Γ ) CANADIAN SYLLABICS MWI → MIDDLE DOT, GREEK CAPITAL LETTER GAMMA	# →ᐧᒥ→→·ᒥ→

			{ L"\x140E",L"\x00B7\x0394" }, //( ᐎ → ·Δ ) CANADIAN SYLLABICS WI → MIDDLE DOT, GREEK CAPITAL LETTER DELTA	# →ᐧᐃ→

			{ L"\x1459",L"\x00B7\x0548" }, //( ᑙ → ·Ո ) CANADIAN SYLLABICS TWI → MIDDLE DOT, ARMENIAN CAPITAL LETTER VO	# →ᐧᑎ→→·ᑎ→

			{ L"\x140C",L"\x00B7\x1401" }, //( ᐌ → ·ᐁ ) CANADIAN SYLLABICS WE → MIDDLE DOT, CANADIAN SYLLABICS E	# →ᐧᐁ→

			{ L"\x1410",L"\x00B7\x1404" }, //( ᐐ → ·ᐄ ) CANADIAN SYLLABICS WII → MIDDLE DOT, CANADIAN SYLLABICS II	# →ᐧᐄ→

			{ L"\x1412",L"\x00B7\x1405" }, //( ᐒ → ·ᐅ ) CANADIAN SYLLABICS WO → MIDDLE DOT, CANADIAN SYLLABICS O	# →ᐧᐅ→

			{ L"\x1414",L"\x00B7\x1406" }, //( ᐔ → ·ᐆ ) CANADIAN SYLLABICS WOO → MIDDLE DOT, CANADIAN SYLLABICS OO	# →ᐧᐆ→

			{ L"\x1417",L"\x00B7\x140A" }, //( ᐗ → ·ᐊ ) CANADIAN SYLLABICS WA → MIDDLE DOT, CANADIAN SYLLABICS A	# →ᐧᐊ→

			{ L"\x1419",L"\x00B7\x140B" }, //( ᐙ → ·ᐋ ) CANADIAN SYLLABICS WAA → MIDDLE DOT, CANADIAN SYLLABICS AA	# →ᐧᐋ→

			{ L"\x143E",L"\x00B7\x1432" }, //( ᐾ → ·ᐲ ) CANADIAN SYLLABICS PWII → MIDDLE DOT, CANADIAN SYLLABICS PII	# →ᐧᐲ→

			{ L"\x1442",L"\x00B7\x1434" }, //( ᑂ → ·ᐴ ) CANADIAN SYLLABICS PWOO → MIDDLE DOT, CANADIAN SYLLABICS POO	# →ᐧᐴ→

			{ L"\x1446",L"\x00B7\x1439" }, //( ᑆ → ·ᐹ ) CANADIAN SYLLABICS PWAA → MIDDLE DOT, CANADIAN SYLLABICS PAA	# →ᐧᐹ→

			{ L"\x145B",L"\x00B7\x144F" }, //( ᑛ → ·ᑏ ) CANADIAN SYLLABICS TWII → MIDDLE DOT, CANADIAN SYLLABICS TII	# →ᐧᑏ→

			{ L"\x1454",L"\x00B7\x1450" }, //( ᑔ → ·ᑐ ) CANADIAN SYLLABICS CARRIER DI → MIDDLE DOT, CANADIAN SYLLABICS TO	# →ᑝ→→ᐧᑐ→
			{ L"\x145D",L"\x00B7\x1450" }, //( ᑝ → ·ᑐ ) CANADIAN SYLLABICS TWO → MIDDLE DOT, CANADIAN SYLLABICS TO	# →ᐧᑐ→

			{ L"\x145F",L"\x00B7\x1451" }, //( ᑟ → ·ᑑ ) CANADIAN SYLLABICS TWOO → MIDDLE DOT, CANADIAN SYLLABICS TOO	# →ᐧᑑ→

			{ L"\x1461",L"\x00B7\x1455" }, //( ᑡ → ·ᑕ ) CANADIAN SYLLABICS TWA → MIDDLE DOT, CANADIAN SYLLABICS TA	# →ᐧᑕ→

			{ L"\x1463",L"\x00B7\x1456" }, //( ᑣ → ·ᑖ ) CANADIAN SYLLABICS TWAA → MIDDLE DOT, CANADIAN SYLLABICS TAA	# →ᐧᑖ→

			{ L"\x1474",L"\x00B7\x146B" }, //( ᑴ → ·ᑫ ) CANADIAN SYLLABICS KWE → MIDDLE DOT, CANADIAN SYLLABICS KE	# →ᐧᑫ→

			{ L"\x1478",L"\x00B7\x146E" }, //( ᑸ → ·ᑮ ) CANADIAN SYLLABICS KWII → MIDDLE DOT, CANADIAN SYLLABICS KII	# →ᐧᑮ→

			{ L"\x147C",L"\x00B7\x1470" }, //( ᑼ → ·ᑰ ) CANADIAN SYLLABICS KWOO → MIDDLE DOT, CANADIAN SYLLABICS KOO	# →ᐧᑰ→

			{ L"\x147E",L"\x00B7\x1472" }, //( ᑾ → ·ᑲ ) CANADIAN SYLLABICS KWA → MIDDLE DOT, CANADIAN SYLLABICS KA	# →ᐧᑲ→

			{ L"\x1480",L"\x00B7\x1473" }, //( ᒀ → ·ᑳ ) CANADIAN SYLLABICS KWAA → MIDDLE DOT, CANADIAN SYLLABICS KAA	# →ᐧᑳ→

			{ L"\x1492",L"\x00B7\x1489" }, //( ᒒ → ·ᒉ ) CANADIAN SYLLABICS CWE → MIDDLE DOT, CANADIAN SYLLABICS CE	# →ᐧᒉ→

			{ L"\x1494",L"\x00B7\x148B" }, //( ᒔ → ·ᒋ ) CANADIAN SYLLABICS CWI → MIDDLE DOT, CANADIAN SYLLABICS CI	# →ᐧᒋ→

			{ L"\x1496",L"\x00B7\x148C" }, //( ᒖ → ·ᒌ ) CANADIAN SYLLABICS CWII → MIDDLE DOT, CANADIAN SYLLABICS CII	# →ᐧᒌ→

			{ L"\x149A",L"\x00B7\x148E" }, //( ᒚ → ·ᒎ ) CANADIAN SYLLABICS CWOO → MIDDLE DOT, CANADIAN SYLLABICS COO	# →ᐧᒎ→

			{ L"\x149C",L"\x00B7\x1490" }, //( ᒜ → ·ᒐ ) CANADIAN SYLLABICS CWA → MIDDLE DOT, CANADIAN SYLLABICS CA	# →ᐧᒐ→

			{ L"\x149E",L"\x00B7\x1491" }, //( ᒞ → ·ᒑ ) CANADIAN SYLLABICS CWAA → MIDDLE DOT, CANADIAN SYLLABICS CAA	# →ᐧᒑ→

			{ L"\x14AC",L"\x00B7\x14A3" }, //( ᒬ → ·ᒣ ) CANADIAN SYLLABICS MWE → MIDDLE DOT, CANADIAN SYLLABICS ME	# →ᐧᒣ→

			{ L"\x14B0",L"\x00B7\x14A6" }, //( ᒰ → ·ᒦ ) CANADIAN SYLLABICS MWII → MIDDLE DOT, CANADIAN SYLLABICS MII	# →ᐧᒦ→

			{ L"\x14B2",L"\x00B7\x14A7" }, //( ᒲ → ·ᒧ ) CANADIAN SYLLABICS MWO → MIDDLE DOT, CANADIAN SYLLABICS MO	# →ᐧᒧ→

			{ L"\x14B4",L"\x00B7\x14A8" }, //( ᒴ → ·ᒨ ) CANADIAN SYLLABICS MWOO → MIDDLE DOT, CANADIAN SYLLABICS MOO	# →ᐧᒨ→

			{ L"\x14B8",L"\x00B7\x14AB" }, //( ᒸ → ·ᒫ ) CANADIAN SYLLABICS MWAA → MIDDLE DOT, CANADIAN SYLLABICS MAA	# →ᐧᒫ→

			{ L"\x14C9",L"\x00B7\x14C0" }, //( ᓉ → ·ᓀ ) CANADIAN SYLLABICS NWE → MIDDLE DOT, CANADIAN SYLLABICS NE	# →ᐧᓀ→

			{ L"\x14CB",L"\x00B7\x14C7" }, //( ᓋ → ·ᓇ ) CANADIAN SYLLABICS NWA → MIDDLE DOT, CANADIAN SYLLABICS NA	# →ᐧᓇ→

			{ L"\x14CD",L"\x00B7\x14C8" }, //( ᓍ → ·ᓈ ) CANADIAN SYLLABICS NWAA → MIDDLE DOT, CANADIAN SYLLABICS NAA	# →ᐧᓈ→

			{ L"\x14DC",L"\x00B7\x14D3" }, //( ᓜ → ·ᓓ ) CANADIAN SYLLABICS LWE → MIDDLE DOT, CANADIAN SYLLABICS LE	# →ᐧᓓ→

			{ L"\x14DE",L"\x00B7\x14D5" }, //( ᓞ → ·ᓕ ) CANADIAN SYLLABICS LWI → MIDDLE DOT, CANADIAN SYLLABICS LI	# →ᐧᓕ→

			{ L"\x14E0",L"\x00B7\x14D6" }, //( ᓠ → ·ᓖ ) CANADIAN SYLLABICS LWII → MIDDLE DOT, CANADIAN SYLLABICS LII	# →ᐧᓖ→

			{ L"\x14E2",L"\x00B7\x14D7" }, //( ᓢ → ·ᓗ ) CANADIAN SYLLABICS LWO → MIDDLE DOT, CANADIAN SYLLABICS LO	# →ᐧᓗ→

			{ L"\x14E4",L"\x00B7\x14D8" }, //( ᓤ → ·ᓘ ) CANADIAN SYLLABICS LWOO → MIDDLE DOT, CANADIAN SYLLABICS LOO	# →ᐧᓘ→

			{ L"\x14E6",L"\x00B7\x14DA" }, //( ᓦ → ·ᓚ ) CANADIAN SYLLABICS LWA → MIDDLE DOT, CANADIAN SYLLABICS LA	# →ᐧᓚ→

			{ L"\x14E8",L"\x00B7\x14DB" }, //( ᓨ → ·ᓛ ) CANADIAN SYLLABICS LWAA → MIDDLE DOT, CANADIAN SYLLABICS LAA	# →ᐧᓛ→

			{ L"\x14F6",L"\x00B7\x14ED" }, //( ᓶ → ·ᓭ ) CANADIAN SYLLABICS SWE → MIDDLE DOT, CANADIAN SYLLABICS SE	# →ᐧᓭ→

			{ L"\x14F8",L"\x00B7\x14EF" }, //( ᓸ → ·ᓯ ) CANADIAN SYLLABICS SWI → MIDDLE DOT, CANADIAN SYLLABICS SI	# →ᐧᓯ→

			{ L"\x14FA",L"\x00B7\x14F0" }, //( ᓺ → ·ᓰ ) CANADIAN SYLLABICS SWII → MIDDLE DOT, CANADIAN SYLLABICS SII	# →ᐧᓰ→

			{ L"\x14FC",L"\x00B7\x14F1" }, //( ᓼ → ·ᓱ ) CANADIAN SYLLABICS SWO → MIDDLE DOT, CANADIAN SYLLABICS SO	# →ᐧᓱ→

			{ L"\x14FE",L"\x00B7\x14F2" }, //( ᓾ → ·ᓲ ) CANADIAN SYLLABICS SWOO → MIDDLE DOT, CANADIAN SYLLABICS SOO	# →ᐧᓲ→

			{ L"\x1500",L"\x00B7\x14F4" }, //( ᔀ → ·ᓴ ) CANADIAN SYLLABICS SWA → MIDDLE DOT, CANADIAN SYLLABICS SA	# →ᐧᓴ→

			{ L"\x1502",L"\x00B7\x14F5" }, //( ᔂ → ·ᓵ ) CANADIAN SYLLABICS SWAA → MIDDLE DOT, CANADIAN SYLLABICS SAA	# →ᐧᓵ→

			{ L"\x1517",L"\x00B7\x1510" }, //( ᔗ → ·ᔐ ) CANADIAN SYLLABICS SHWE → MIDDLE DOT, CANADIAN SYLLABICS SHE	# →ᐧᔐ→

			{ L"\x1519",L"\x00B7\x1511" }, //( ᔙ → ·ᔑ ) CANADIAN SYLLABICS SHWI → MIDDLE DOT, CANADIAN SYLLABICS SHI	# →ᐧᔑ→

			{ L"\x151B",L"\x00B7\x1512" }, //( ᔛ → ·ᔒ ) CANADIAN SYLLABICS SHWII → MIDDLE DOT, CANADIAN SYLLABICS SHII	# →ᐧᔒ→

			{ L"\x151D",L"\x00B7\x1513" }, //( ᔝ → ·ᔓ ) CANADIAN SYLLABICS SHWO → MIDDLE DOT, CANADIAN SYLLABICS SHO	# →ᐧᔓ→

			{ L"\x151F",L"\x00B7\x1514" }, //( ᔟ → ·ᔔ ) CANADIAN SYLLABICS SHWOO → MIDDLE DOT, CANADIAN SYLLABICS SHOO	# →ᐧᔔ→

			{ L"\x1521",L"\x00B7\x1515" }, //( ᔡ → ·ᔕ ) CANADIAN SYLLABICS SHWA → MIDDLE DOT, CANADIAN SYLLABICS SHA	# →ᐧᔕ→

			{ L"\x1523",L"\x00B7\x1516" }, //( ᔣ → ·ᔖ ) CANADIAN SYLLABICS SHWAA → MIDDLE DOT, CANADIAN SYLLABICS SHAA	# →ᐧᔖ→

			{ L"\x1531",L"\x00B7\x1528" }, //( ᔱ → ·ᔨ ) CANADIAN SYLLABICS YWI → MIDDLE DOT, CANADIAN SYLLABICS YI	# →ᐧᔨ→

			{ L"\x1533",L"\x00B7\x1529" }, //( ᔳ → ·ᔩ ) CANADIAN SYLLABICS YWII → MIDDLE DOT, CANADIAN SYLLABICS YII	# →ᐧᔩ→

			{ L"\x1535",L"\x00B7\x152A" }, //( ᔵ → ·ᔪ ) CANADIAN SYLLABICS YWO → MIDDLE DOT, CANADIAN SYLLABICS YO	# →ᐧᔪ→

			{ L"\x1537",L"\x00B7\x152B" }, //( ᔷ → ·ᔫ ) CANADIAN SYLLABICS YWOO → MIDDLE DOT, CANADIAN SYLLABICS YOO	# →ᐧᔫ→

			{ L"\x1539",L"\x00B7\x152D" }, //( ᔹ → ·ᔭ ) CANADIAN SYLLABICS YWA → MIDDLE DOT, CANADIAN SYLLABICS YA	# →ᐧᔭ→

			{ L"\x153B",L"\x00B7\x152E" }, //( ᔻ → ·ᔮ ) CANADIAN SYLLABICS YWAA → MIDDLE DOT, CANADIAN SYLLABICS YAA	# →ᐧᔮ→

			{ L"\x154E",L"\x00B7\x154C" }, //( ᕎ → ·ᕌ ) CANADIAN SYLLABICS RWAA → MIDDLE DOT, CANADIAN SYLLABICS RAA	# →ᐧᕌ→

			{ L"\x155B",L"\x00B7\x155A" }, //( ᕛ → ·ᕚ ) CANADIAN SYLLABICS FWAA → MIDDLE DOT, CANADIAN SYLLABICS FAA	# →ᐧᕚ→

			{ L"\x1568",L"\x00B7\x1567" }, //( ᕨ → ·ᕧ ) CANADIAN SYLLABICS THWAA → MIDDLE DOT, CANADIAN SYLLABICS THAA	# →ᐧᕧ→

			{ L"\x18B3",L"\x00B7\x18B1" }, //( ᢳ → ·ᢱ ) CANADIAN SYLLABICS WAY → MIDDLE DOT, CANADIAN SYLLABICS AY	# →ᐧᢱ→

			{ L"\x18B6",L"\x00B7\x18B4" }, //( ᢶ → ·ᢴ ) CANADIAN SYLLABICS PWOY → MIDDLE DOT, CANADIAN SYLLABICS POY	# →ᐧᢴ→

			{ L"\x18B9",L"\x00B7\x18B8" }, //( ᢹ → ·ᢸ ) CANADIAN SYLLABICS KWAY → MIDDLE DOT, CANADIAN SYLLABICS KAY	# →ᐧᢸ→

			{ L"\x18C2",L"\x00B7\x18C0" }, //( ᣂ → ·ᣀ ) CANADIAN SYLLABICS SHWOY → MIDDLE DOT, CANADIAN SYLLABICS SHOY	# →ᐧᣀ→

			{ L"\x0965",L"\x0964\x0964" }, //( ॥ → ।। ) DEVANAGARI DOUBLE DANDA → DEVANAGARI DANDA, DEVANAGARI DANDA	# 

			{ L"\x1C3C",L"\x1C3B\x1C3B" }, //( ᰼ → ᰻᰻ ) LEPCHA PUNCTUATION NYET THYOOM TA-ROL → LEPCHA PUNCTUATION TA-ROL, LEPCHA PUNCTUATION TA-ROL	# 

			{ L"\x104B",L"\x104A\x104A" }, //( ။ → ၊၊ ) MYANMAR SIGN SECTION → MYANMAR SIGN LITTLE SECTION, MYANMAR SIGN LITTLE SECTION	# 

			{ L"\x1AA9",L"\x1AA8\x1AA8" }, //( ᪩ → ᪨᪨ ) TAI THAM SIGN KAANKUU → TAI THAM SIGN KAAN, TAI THAM SIGN KAAN	# 

			{ L"\x1AAB",L"\x1AAA\x1AA8" }, //( ᪫ → ᪪᪨ ) TAI THAM SIGN SATKAANKUU → TAI THAM SIGN SATKAAN, TAI THAM SIGN KAAN	# 

			{ L"\x1B5F",L"\x1B5E\x1B5E" }, //( ᭟ → ᭞᭞ ) BALINESE CARIK PAREREN → BALINESE CARIK SIKI, BALINESE CARIK SIKI	# 

			{ L"\x0001\x0A57",L"\x0001\x0A56\x0001\x0A56" }, //( ‎𐩗‎ → ‎𐩖𐩖‎ ) KHAROSHTHI PUNCTUATION DOUBLE DANDA → KHAROSHTHI PUNCTUATION DANDA, KHAROSHTHI PUNCTUATION DANDA	# 

			{ L"\x1C7F",L"\x1C7E\x1C7E" }, //( ᱿ → ᱾᱾ ) OL CHIKI PUNCTUATION DOUBLE MUCAAD → OL CHIKI PUNCTUATION MUCAAD, OL CHIKI PUNCTUATION MUCAAD	# 

			{ L"\x055D",L"\x0027" }, //( ՝ → ' ) ARMENIAN COMMA → APOSTROPHE	# →ˋ→→｀→→‘→
			{ L"\xFF07",L"\x0027" }, //( ＇ → ' ) FULLWIDTH APOSTROPHE → APOSTROPHE	# →’→
			{ L"\x2018",L"\x0027" }, //( ‘ → ' ) LEFT SINGLE QUOTATION MARK → APOSTROPHE	# 
			{ L"\x2019",L"\x0027" }, //( ’ → ' ) RIGHT SINGLE QUOTATION MARK → APOSTROPHE	# 
			{ L"\x201B",L"\x0027" }, //( ‛ → ' ) SINGLE HIGH-REVERSED-9 QUOTATION MARK → APOSTROPHE	# →′→
			{ L"\x2032",L"\x0027" }, //( ′ → ' ) PRIME → APOSTROPHE	# 
			{ L"\x2035",L"\x0027" }, //( ‵ → ' ) REVERSED PRIME → APOSTROPHE	# →ʽ→→‘→
			{ L"\x055A",L"\x0027" }, //( ՚ → ' ) ARMENIAN APOSTROPHE → APOSTROPHE	# →’→
			{ L"\x05F3",L"\x0027" }, //( ‎׳‎ → ' ) HEBREW PUNCTUATION GERESH → APOSTROPHE	# 
			{ L"\x0060",L"\x0027" }, //( ` → ' ) GRAVE ACCENT → APOSTROPHE	# →ˋ→→｀→→‘→
			{ L"\x1FEF",L"\x0027" }, //( ` → ' ) GREEK VARIA → APOSTROPHE	# →ˋ→→｀→→‘→
			{ L"\xFF40",L"\x0027" }, //( ｀ → ' ) FULLWIDTH GRAVE ACCENT → APOSTROPHE	# →‘→
			{ L"\x00B4",L"\x0027" }, //( ´ → ' ) ACUTE ACCENT → APOSTROPHE	# →΄→→ʹ→
			{ L"\x0384",L"\x0027" }, //( ΄ → ' ) GREEK TONOS → APOSTROPHE	# →ʹ→
			{ L"\x1FFD",L"\x0027" }, //( ´ → ' ) GREEK OXIA → APOSTROPHE	# →´→→΄→→ʹ→
			{ L"\x1FBD",L"\x0027" }, //( ᾽ → ' ) GREEK KORONIS → APOSTROPHE	# →’→
			{ L"\x1FBF",L"\x0027" }, //( ᾿ → ' ) GREEK PSILI → APOSTROPHE	# →’→
			{ L"\x1FFE",L"\x0027" }, //( ῾ → ' ) GREEK DASIA → APOSTROPHE	# →‛→→′→
			{ L"\x02B9",L"\x0027" }, //( ʹ → ' ) MODIFIER LETTER PRIME → APOSTROPHE	# 
			{ L"\x0374",L"\x0027" }, //( ʹ → ' ) GREEK NUMERAL SIGN → APOSTROPHE	# →′→
			{ L"\x02C8",L"\x0027" }, //( ˈ → ' ) MODIFIER LETTER VERTICAL LINE → APOSTROPHE	# 
			{ L"\x02CA",L"\x0027" }, //( ˊ → ' ) MODIFIER LETTER ACUTE ACCENT → APOSTROPHE	# →ʹ→→′→
			{ L"\x02CB",L"\x0027" }, //( ˋ → ' ) MODIFIER LETTER GRAVE ACCENT → APOSTROPHE	# →｀→→‘→
			{ L"\x02F4",L"\x0027" }, //( ˴ → ' ) MODIFIER LETTER MIDDLE GRAVE ACCENT → APOSTROPHE	# →ˋ→→｀→→‘→
			{ L"\x02BB",L"\x0027" }, //( ʻ → ' ) MODIFIER LETTER TURNED COMMA → APOSTROPHE	# →‘→
			{ L"\x02BD",L"\x0027" }, //( ʽ → ' ) MODIFIER LETTER REVERSED COMMA → APOSTROPHE	# →‘→
			{ L"\x02BC",L"\x0027" }, //( ʼ → ' ) MODIFIER LETTER APOSTROPHE → APOSTROPHE	# →′→
			{ L"\x02BE",L"\x0027" }, //( ʾ → ' ) MODIFIER LETTER RIGHT HALF RING → APOSTROPHE	# →ʼ→→′→
			{ L"\xA78C",L"\x0027" }, //( ꞌ → ' ) LATIN SMALL LETTER SALTILLO → APOSTROPHE	# 
			{ L"\x05D9",L"\x0027" }, //( ‎י‎ → ' ) HEBREW LETTER YOD → APOSTROPHE	# 
			{ L"\x07F4",L"\x0027" }, //( ‎ߴ‎ → ' ) NKO HIGH TONE APOSTROPHE → APOSTROPHE	# →’→
			{ L"\x07F5",L"\x0027" }, //( ‎ߵ‎ → ' ) NKO LOW TONE APOSTROPHE → APOSTROPHE	# →‘→
			{ L"\x144A",L"\x0027" }, //( ᑊ → ' ) CANADIAN SYLLABICS WEST-CREE P → APOSTROPHE	# →ˈ→
			{ L"\x16CC",L"\x0027" }, //( ᛌ → ' ) RUNIC LETTER SHORT-TWIG-SOL S → APOSTROPHE	# 

			{ L"\x1CD3",L"\x0027\x0027" }, //( ᳓ → '' ) VEDIC SIGN NIHSHVASA → APOSTROPHE, APOSTROPHE	# →″→→"→
			{ L"\x0022",L"\x0027\x0027" }, //( " → '' ) QUOTATION MARK → APOSTROPHE, APOSTROPHE	# 
			{ L"\xFF02",L"\x0027\x0027" }, //( ＂ → '' ) FULLWIDTH QUOTATION MARK → APOSTROPHE, APOSTROPHE	# →”→→"→
			{ L"\x201C",L"\x0027\x0027" }, //( “ → '' ) LEFT DOUBLE QUOTATION MARK → APOSTROPHE, APOSTROPHE	# →"→
			{ L"\x201D",L"\x0027\x0027" }, //( ” → '' ) RIGHT DOUBLE QUOTATION MARK → APOSTROPHE, APOSTROPHE	# →"→
			{ L"\x201F",L"\x0027\x0027" }, //( ‟ → '' ) DOUBLE HIGH-REVERSED-9 QUOTATION MARK → APOSTROPHE, APOSTROPHE	# →“→→"→
			{ L"\x2033",L"\x0027\x0027" }, //( ″ → '' ) DOUBLE PRIME → APOSTROPHE, APOSTROPHE	# →"→
			{ L"\x2036",L"\x0027\x0027" }, //( ‶ → '' ) REVERSED DOUBLE PRIME → APOSTROPHE, APOSTROPHE	# →‵‵→
			{ L"\x3003",L"\x0027\x0027" }, //( 〃 → '' ) DITTO MARK → APOSTROPHE, APOSTROPHE	# →″→→"→
			{ L"\x05F4",L"\x0027\x0027" }, //( ‎״‎ → '' ) HEBREW PUNCTUATION GERSHAYIM → APOSTROPHE, APOSTROPHE	# →"→
			{ L"\x02DD",L"\x0027\x0027" }, //( ˝ → '' ) DOUBLE ACUTE ACCENT → APOSTROPHE, APOSTROPHE	# →"→
			{ L"\x02BA",L"\x0027\x0027" }, //( ʺ → '' ) MODIFIER LETTER DOUBLE PRIME → APOSTROPHE, APOSTROPHE	# →"→
			{ L"\x02F6",L"\x0027\x0027" }, //( ˶ → '' ) MODIFIER LETTER MIDDLE DOUBLE ACUTE ACCENT → APOSTROPHE, APOSTROPHE	# →˝→→"→
			{ L"\x02EE",L"\x0027\x0027" }, //( ˮ → '' ) MODIFIER LETTER DOUBLE APOSTROPHE → APOSTROPHE, APOSTROPHE	# →″→→"→
			{ L"\x05F2",L"\x0027\x0027" }, //( ‎ײ‎ → '' ) HEBREW LIGATURE YIDDISH DOUBLE YOD → APOSTROPHE, APOSTROPHE	# →‎יי‎→

			{ L"\x2034",L"\x0027\x0027\x0027" }, //( ‴ → ''' ) TRIPLE PRIME → APOSTROPHE, APOSTROPHE, APOSTROPHE	# →′′′→
			{ L"\x2037",L"\x0027\x0027\x0027" }, //( ‷ → ''' ) REVERSED TRIPLE PRIME → APOSTROPHE, APOSTROPHE, APOSTROPHE	# →‵‵‵→

			{ L"\x2057",L"\x0027\x0027\x0027\x0027" }, //( ⁗ → '''' ) QUADRUPLE PRIME → APOSTROPHE, APOSTROPHE, APOSTROPHE, APOSTROPHE	# →′′′′→

			{ L"\x0181",L"\x0027\x0042" }, //( Ɓ → 'B ) LATIN CAPITAL LETTER B WITH HOOK → APOSTROPHE, LATIN CAPITAL LETTER B	# →ʽB→

			{ L"\x018A",L"\x0027\x0044" }, //( Ɗ → 'D ) LATIN CAPITAL LETTER D WITH HOOK → APOSTROPHE, LATIN CAPITAL LETTER D	# →ʽD→

			{ L"\x0149",L"\x0027\x006E" }, //( ŉ → 'n ) LATIN SMALL LETTER N PRECEDED BY APOSTROPHE → APOSTROPHE, LATIN SMALL LETTER N	# →ʼn→

			{ L"\x01A4",L"\x0027\x0050" }, //( Ƥ → 'P ) LATIN CAPITAL LETTER P WITH HOOK → APOSTROPHE, LATIN CAPITAL LETTER P	# →ʽP→

			{ L"\x01AC",L"\x0027\x0054" }, //( Ƭ → 'T ) LATIN CAPITAL LETTER T WITH HOOK → APOSTROPHE, LATIN CAPITAL LETTER T	# →ʽT→

			{ L"\x01B3",L"\x0027\x0059" }, //( Ƴ → 'Y ) LATIN CAPITAL LETTER Y WITH HOOK → APOSTROPHE, LATIN CAPITAL LETTER Y	# →ʽY→

			{ L"\xFF3B",L"\x0028" }, //( ［ → ( ) FULLWIDTH LEFT SQUARE BRACKET → LEFT PARENTHESIS	# →〔→
			{ L"\x2768",L"\x0028" }, //( ❨ → ( ) MEDIUM LEFT PARENTHESIS ORNAMENT → LEFT PARENTHESIS	# 
			{ L"\x2772",L"\x0028" }, //( ❲ → ( ) LIGHT LEFT TORTOISE SHELL BRACKET ORNAMENT → LEFT PARENTHESIS	# →〔→
			{ L"\x3014",L"\x0028" }, //( 〔 → ( ) LEFT TORTOISE SHELL BRACKET → LEFT PARENTHESIS	# 
			{ L"\xFD3E",L"\x0028" }, //( ﴾ → ( ) ORNATE LEFT PARENTHESIS → LEFT PARENTHESIS	# 

			{ L"\x2E28",L"\x0028\x0028" }, //( ⸨ → (( ) LEFT DOUBLE PARENTHESIS → LEFT PARENTHESIS, LEFT PARENTHESIS	# 

			{ L"\x3220",L"\x0028\x30FC\x0029" }, //( ㈠ → (ー) ) PARENTHESIZED IDEOGRAPH ONE → LEFT PARENTHESIS, KATAKANA-HIRAGANA PROLONGED SOUND MARK, RIGHT PARENTHESIS	# →(一)→

			{ L"\x2475",L"\x0028\x0032\x0029" }, //( ⑵ → (2) ) PARENTHESIZED DIGIT TWO → LEFT PARENTHESIS, DIGIT TWO, RIGHT PARENTHESIS	# 

			{ L"\x2487",L"\x0028\x0032\x004F\x0029" }, //( ⒇ → (2O) ) PARENTHESIZED NUMBER TWENTY → LEFT PARENTHESIS, DIGIT TWO, LATIN CAPITAL LETTER O, RIGHT PARENTHESIS	# →(20)→

			{ L"\x2476",L"\x0028\x0033\x0029" }, //( ⑶ → (3) ) PARENTHESIZED DIGIT THREE → LEFT PARENTHESIS, DIGIT THREE, RIGHT PARENTHESIS	# 

			{ L"\x2477",L"\x0028\x0034\x0029" }, //( ⑷ → (4) ) PARENTHESIZED DIGIT FOUR → LEFT PARENTHESIS, DIGIT FOUR, RIGHT PARENTHESIS	# 

			{ L"\x2478",L"\x0028\x0035\x0029" }, //( ⑸ → (5) ) PARENTHESIZED DIGIT FIVE → LEFT PARENTHESIS, DIGIT FIVE, RIGHT PARENTHESIS	# 

			{ L"\x2479",L"\x0028\x0036\x0029" }, //( ⑹ → (6) ) PARENTHESIZED DIGIT SIX → LEFT PARENTHESIS, DIGIT SIX, RIGHT PARENTHESIS	# 

			{ L"\x247A",L"\x0028\x0037\x0029" }, //( ⑺ → (7) ) PARENTHESIZED DIGIT SEVEN → LEFT PARENTHESIS, DIGIT SEVEN, RIGHT PARENTHESIS	# 

			{ L"\x247B",L"\x0028\x0038\x0029" }, //( ⑻ → (8) ) PARENTHESIZED DIGIT EIGHT → LEFT PARENTHESIS, DIGIT EIGHT, RIGHT PARENTHESIS	# 

			{ L"\x247C",L"\x0028\x0039\x0029" }, //( ⑼ → (9) ) PARENTHESIZED DIGIT NINE → LEFT PARENTHESIS, DIGIT NINE, RIGHT PARENTHESIS	# 

			{ L"\x249C",L"\x0028\x0061\x0029" }, //( ⒜ → (a) ) PARENTHESIZED LATIN SMALL LETTER A → LEFT PARENTHESIS, LATIN SMALL LETTER A, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF110",L"\x0028\x0041\x0029" }, //( 🄐 → (A) ) PARENTHESIZED LATIN CAPITAL LETTER A → LEFT PARENTHESIS, LATIN CAPITAL LETTER A, RIGHT PARENTHESIS	# 

			{ L"\x249D",L"\x0028\x0062\x0029" }, //( ⒝ → (b) ) PARENTHESIZED LATIN SMALL LETTER B → LEFT PARENTHESIS, LATIN SMALL LETTER B, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF111",L"\x0028\x0042\x0029" }, //( 🄑 → (B) ) PARENTHESIZED LATIN CAPITAL LETTER B → LEFT PARENTHESIS, LATIN CAPITAL LETTER B, RIGHT PARENTHESIS	# 

			{ L"\x249E",L"\x0028\x0063\x0029" }, //( ⒞ → (c) ) PARENTHESIZED LATIN SMALL LETTER C → LEFT PARENTHESIS, LATIN SMALL LETTER C, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF112",L"\x0028\x0043\x0029" }, //( 🄒 → (C) ) PARENTHESIZED LATIN CAPITAL LETTER C → LEFT PARENTHESIS, LATIN CAPITAL LETTER C, RIGHT PARENTHESIS	# 

			{ L"\x249F",L"\x0028\x0064\x0029" }, //( ⒟ → (d) ) PARENTHESIZED LATIN SMALL LETTER D → LEFT PARENTHESIS, LATIN SMALL LETTER D, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF113",L"\x0028\x0044\x0029" }, //( 🄓 → (D) ) PARENTHESIZED LATIN CAPITAL LETTER D → LEFT PARENTHESIS, LATIN CAPITAL LETTER D, RIGHT PARENTHESIS	# 

			{ L"\x24A0",L"\x0028\x0065\x0029" }, //( ⒠ → (e) ) PARENTHESIZED LATIN SMALL LETTER E → LEFT PARENTHESIS, LATIN SMALL LETTER E, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF114",L"\x0028\x0045\x0029" }, //( 🄔 → (E) ) PARENTHESIZED LATIN CAPITAL LETTER E → LEFT PARENTHESIS, LATIN CAPITAL LETTER E, RIGHT PARENTHESIS	# 

			{ L"\x24A1",L"\x0028\x0066\x0029" }, //( ⒡ → (f) ) PARENTHESIZED LATIN SMALL LETTER F → LEFT PARENTHESIS, LATIN SMALL LETTER F, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF115",L"\x0028\x0046\x0029" }, //( 🄕 → (F) ) PARENTHESIZED LATIN CAPITAL LETTER F → LEFT PARENTHESIS, LATIN CAPITAL LETTER F, RIGHT PARENTHESIS	# 

			{ L"\x24A2",L"\x0028\x0067\x0029" }, //( ⒢ → (g) ) PARENTHESIZED LATIN SMALL LETTER G → LEFT PARENTHESIS, LATIN SMALL LETTER G, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF116",L"\x0028\x0047\x0029" }, //( 🄖 → (G) ) PARENTHESIZED LATIN CAPITAL LETTER G → LEFT PARENTHESIS, LATIN CAPITAL LETTER G, RIGHT PARENTHESIS	# 

			{ L"\x24A3",L"\x0028\x0068\x0029" }, //( ⒣ → (h) ) PARENTHESIZED LATIN SMALL LETTER H → LEFT PARENTHESIS, LATIN SMALL LETTER H, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF117",L"\x0028\x0048\x0029" }, //( 🄗 → (H) ) PARENTHESIZED LATIN CAPITAL LETTER H → LEFT PARENTHESIS, LATIN CAPITAL LETTER H, RIGHT PARENTHESIS	# 

			{ L"\x24A4",L"\x0028\x0069\x0029" }, //( ⒤ → (i) ) PARENTHESIZED LATIN SMALL LETTER I → LEFT PARENTHESIS, LATIN SMALL LETTER I, RIGHT PARENTHESIS	# 

			{ L"\x24A5",L"\x0028\x006A\x0029" }, //( ⒥ → (j) ) PARENTHESIZED LATIN SMALL LETTER J → LEFT PARENTHESIS, LATIN SMALL LETTER J, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF119",L"\x0028\x004A\x0029" }, //( 🄙 → (J) ) PARENTHESIZED LATIN CAPITAL LETTER J → LEFT PARENTHESIS, LATIN CAPITAL LETTER J, RIGHT PARENTHESIS	# 

			{ L"\x24A6",L"\x0028\x006B\x0029" }, //( ⒦ → (k) ) PARENTHESIZED LATIN SMALL LETTER K → LEFT PARENTHESIS, LATIN SMALL LETTER K, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF11A",L"\x0028\x004B\x0029" }, //( 🄚 → (K) ) PARENTHESIZED LATIN CAPITAL LETTER K → LEFT PARENTHESIS, LATIN CAPITAL LETTER K, RIGHT PARENTHESIS	# 

			{ L"\x2474",L"\x0028\x006C\x0029" }, //( ⑴ → (l) ) PARENTHESIZED DIGIT ONE → LEFT PARENTHESIS, LATIN SMALL LETTER L, RIGHT PARENTHESIS	# →(1)→
			{ L"\x0001\xF118",L"\x0028\x006C\x0029" }, //( 🄘 → (l) ) PARENTHESIZED LATIN CAPITAL LETTER I → LEFT PARENTHESIS, LATIN SMALL LETTER L, RIGHT PARENTHESIS	# →(I)→
			{ L"\x24A7",L"\x0028\x006C\x0029" }, //( ⒧ → (l) ) PARENTHESIZED LATIN SMALL LETTER L → LEFT PARENTHESIS, LATIN SMALL LETTER L, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF11B",L"\x0028\x004C\x0029" }, //( 🄛 → (L) ) PARENTHESIZED LATIN CAPITAL LETTER L → LEFT PARENTHESIS, LATIN CAPITAL LETTER L, RIGHT PARENTHESIS	# 

			{ L"\x247F",L"\x0028\x006C\x0032\x0029" }, //( ⑿ → (l2) ) PARENTHESIZED NUMBER TWELVE → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT TWO, RIGHT PARENTHESIS	# →(12)→

			{ L"\x2480",L"\x0028\x006C\x0033\x0029" }, //( ⒀ → (l3) ) PARENTHESIZED NUMBER THIRTEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT THREE, RIGHT PARENTHESIS	# →(13)→

			{ L"\x2481",L"\x0028\x006C\x0034\x0029" }, //( ⒁ → (l4) ) PARENTHESIZED NUMBER FOURTEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT FOUR, RIGHT PARENTHESIS	# →(14)→

			{ L"\x2482",L"\x0028\x006C\x0035\x0029" }, //( ⒂ → (l5) ) PARENTHESIZED NUMBER FIFTEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT FIVE, RIGHT PARENTHESIS	# →(15)→

			{ L"\x2483",L"\x0028\x006C\x0036\x0029" }, //( ⒃ → (l6) ) PARENTHESIZED NUMBER SIXTEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT SIX, RIGHT PARENTHESIS	# →(16)→

			{ L"\x2484",L"\x0028\x006C\x0037\x0029" }, //( ⒄ → (l7) ) PARENTHESIZED NUMBER SEVENTEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT SEVEN, RIGHT PARENTHESIS	# →(17)→

			{ L"\x2485",L"\x0028\x006C\x0038\x0029" }, //( ⒅ → (l8) ) PARENTHESIZED NUMBER EIGHTEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT EIGHT, RIGHT PARENTHESIS	# →(18)→

			{ L"\x2486",L"\x0028\x006C\x0039\x0029" }, //( ⒆ → (l9) ) PARENTHESIZED NUMBER NINETEEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, DIGIT NINE, RIGHT PARENTHESIS	# →(19)→

			{ L"\x247E",L"\x0028\x006C\x006C\x0029" }, //( ⑾ → (ll) ) PARENTHESIZED NUMBER ELEVEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, LATIN SMALL LETTER L, RIGHT PARENTHESIS	# →(11)→

			{ L"\x247D",L"\x0028\x006C\x004F\x0029" }, //( ⑽ → (lO) ) PARENTHESIZED NUMBER TEN → LEFT PARENTHESIS, LATIN SMALL LETTER L, LATIN CAPITAL LETTER O, RIGHT PARENTHESIS	# →(10)→

			{ L"\x0001\xF11C",L"\x0028\x004D\x0029" }, //( 🄜 → (M) ) PARENTHESIZED LATIN CAPITAL LETTER M → LEFT PARENTHESIS, LATIN CAPITAL LETTER M, RIGHT PARENTHESIS	# 

			{ L"\x24A9",L"\x0028\x006E\x0029" }, //( ⒩ → (n) ) PARENTHESIZED LATIN SMALL LETTER N → LEFT PARENTHESIS, LATIN SMALL LETTER N, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF11D",L"\x0028\x004E\x0029" }, //( 🄝 → (N) ) PARENTHESIZED LATIN CAPITAL LETTER N → LEFT PARENTHESIS, LATIN CAPITAL LETTER N, RIGHT PARENTHESIS	# 

			{ L"\x24AA",L"\x0028\x006F\x0029" }, //( ⒪ → (o) ) PARENTHESIZED LATIN SMALL LETTER O → LEFT PARENTHESIS, LATIN SMALL LETTER O, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF11E",L"\x0028\x004F\x0029" }, //( 🄞 → (O) ) PARENTHESIZED LATIN CAPITAL LETTER O → LEFT PARENTHESIS, LATIN CAPITAL LETTER O, RIGHT PARENTHESIS	# 

			{ L"\x24AB",L"\x0028\x0070\x0029" }, //( ⒫ → (p) ) PARENTHESIZED LATIN SMALL LETTER P → LEFT PARENTHESIS, LATIN SMALL LETTER P, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF11F",L"\x0028\x0050\x0029" }, //( 🄟 → (P) ) PARENTHESIZED LATIN CAPITAL LETTER P → LEFT PARENTHESIS, LATIN CAPITAL LETTER P, RIGHT PARENTHESIS	# 

			{ L"\x24AC",L"\x0028\x0071\x0029" }, //( ⒬ → (q) ) PARENTHESIZED LATIN SMALL LETTER Q → LEFT PARENTHESIS, LATIN SMALL LETTER Q, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF120",L"\x0028\x0051\x0029" }, //( 🄠 → (Q) ) PARENTHESIZED LATIN CAPITAL LETTER Q → LEFT PARENTHESIS, LATIN CAPITAL LETTER Q, RIGHT PARENTHESIS	# 

			{ L"\x24AD",L"\x0028\x0072\x0029" }, //( ⒭ → (r) ) PARENTHESIZED LATIN SMALL LETTER R → LEFT PARENTHESIS, LATIN SMALL LETTER R, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF121",L"\x0028\x0052\x0029" }, //( 🄡 → (R) ) PARENTHESIZED LATIN CAPITAL LETTER R → LEFT PARENTHESIS, LATIN CAPITAL LETTER R, RIGHT PARENTHESIS	# 

			{ L"\x24A8",L"\x0028\x0072\x006E\x0029" }, //( ⒨ → (rn) ) PARENTHESIZED LATIN SMALL LETTER M → LEFT PARENTHESIS, LATIN SMALL LETTER R, LATIN SMALL LETTER N, RIGHT PARENTHESIS	# →(m)→

			{ L"\x24AE",L"\x0028\x0073\x0029" }, //( ⒮ → (s) ) PARENTHESIZED LATIN SMALL LETTER S → LEFT PARENTHESIS, LATIN SMALL LETTER S, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF122",L"\x0028\x0053\x0029" }, //( 🄢 → (S) ) PARENTHESIZED LATIN CAPITAL LETTER S → LEFT PARENTHESIS, LATIN CAPITAL LETTER S, RIGHT PARENTHESIS	# 
			{ L"\x0001\xF12A",L"\x0028\x0053\x0029" }, //( 🄪 → (S) ) TORTOISE SHELL BRACKETED LATIN CAPITAL LETTER S → LEFT PARENTHESIS, LATIN CAPITAL LETTER S, RIGHT PARENTHESIS	# →〔S〕→

			{ L"\x24AF",L"\x0028\x0074\x0029" }, //( ⒯ → (t) ) PARENTHESIZED LATIN SMALL LETTER T → LEFT PARENTHESIS, LATIN SMALL LETTER T, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF123",L"\x0028\x0054\x0029" }, //( 🄣 → (T) ) PARENTHESIZED LATIN CAPITAL LETTER T → LEFT PARENTHESIS, LATIN CAPITAL LETTER T, RIGHT PARENTHESIS	# 

			{ L"\x24B0",L"\x0028\x0075\x0029" }, //( ⒰ → (u) ) PARENTHESIZED LATIN SMALL LETTER U → LEFT PARENTHESIS, LATIN SMALL LETTER U, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF124",L"\x0028\x0055\x0029" }, //( 🄤 → (U) ) PARENTHESIZED LATIN CAPITAL LETTER U → LEFT PARENTHESIS, LATIN CAPITAL LETTER U, RIGHT PARENTHESIS	# 

			{ L"\x24B1",L"\x0028\x0076\x0029" }, //( ⒱ → (v) ) PARENTHESIZED LATIN SMALL LETTER V → LEFT PARENTHESIS, LATIN SMALL LETTER V, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF125",L"\x0028\x0056\x0029" }, //( 🄥 → (V) ) PARENTHESIZED LATIN CAPITAL LETTER V → LEFT PARENTHESIS, LATIN CAPITAL LETTER V, RIGHT PARENTHESIS	# 

			{ L"\x24B2",L"\x0028\x0076\x0076\x0029" }, //( ⒲ → (vv) ) PARENTHESIZED LATIN SMALL LETTER W → LEFT PARENTHESIS, LATIN SMALL LETTER V, LATIN SMALL LETTER V, RIGHT PARENTHESIS	# →(w)→

			{ L"\x0001\xF126",L"\x0028\x0057\x0029" }, //( 🄦 → (W) ) PARENTHESIZED LATIN CAPITAL LETTER W → LEFT PARENTHESIS, LATIN CAPITAL LETTER W, RIGHT PARENTHESIS	# 

			{ L"\x24B3",L"\x0028\x0078\x0029" }, //( ⒳ → (x) ) PARENTHESIZED LATIN SMALL LETTER X → LEFT PARENTHESIS, LATIN SMALL LETTER X, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF127",L"\x0028\x0058\x0029" }, //( 🄧 → (X) ) PARENTHESIZED LATIN CAPITAL LETTER X → LEFT PARENTHESIS, LATIN CAPITAL LETTER X, RIGHT PARENTHESIS	# 

			{ L"\x24B4",L"\x0028\x0079\x0029" }, //( ⒴ → (y) ) PARENTHESIZED LATIN SMALL LETTER Y → LEFT PARENTHESIS, LATIN SMALL LETTER Y, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF128",L"\x0028\x0059\x0029" }, //( 🄨 → (Y) ) PARENTHESIZED LATIN CAPITAL LETTER Y → LEFT PARENTHESIS, LATIN CAPITAL LETTER Y, RIGHT PARENTHESIS	# 

			{ L"\x24B5",L"\x0028\x007A\x0029" }, //( ⒵ → (z) ) PARENTHESIZED LATIN SMALL LETTER Z → LEFT PARENTHESIS, LATIN SMALL LETTER Z, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF129",L"\x0028\x005A\x0029" }, //( 🄩 → (Z) ) PARENTHESIZED LATIN CAPITAL LETTER Z → LEFT PARENTHESIS, LATIN CAPITAL LETTER Z, RIGHT PARENTHESIS	# 

			{ L"\x3200",L"\x0028\x1100\x0029" }, //( ㈀ → (ᄀ) ) PARENTHESIZED HANGUL KIYEOK → LEFT PARENTHESIS, HANGUL CHOSEONG KIYEOK, RIGHT PARENTHESIS	# 

			{ L"\x320E",L"\x0028\xAC00\x0029" }, //( ㈎ → (가) ) PARENTHESIZED HANGUL KIYEOK A → LEFT PARENTHESIS, HANGUL SYLLABLE GA, RIGHT PARENTHESIS	# 

			{ L"\x3201",L"\x0028\x1102\x0029" }, //( ㈁ → (ᄂ) ) PARENTHESIZED HANGUL NIEUN → LEFT PARENTHESIS, HANGUL CHOSEONG NIEUN, RIGHT PARENTHESIS	# 

			{ L"\x320F",L"\x0028\xB098\x0029" }, //( ㈏ → (나) ) PARENTHESIZED HANGUL NIEUN A → LEFT PARENTHESIS, HANGUL SYLLABLE NA, RIGHT PARENTHESIS	# 

			{ L"\x3202",L"\x0028\x1103\x0029" }, //( ㈂ → (ᄃ) ) PARENTHESIZED HANGUL TIKEUT → LEFT PARENTHESIS, HANGUL CHOSEONG TIKEUT, RIGHT PARENTHESIS	# 

			{ L"\x3210",L"\x0028\xB2E4\x0029" }, //( ㈐ → (다) ) PARENTHESIZED HANGUL TIKEUT A → LEFT PARENTHESIS, HANGUL SYLLABLE DA, RIGHT PARENTHESIS	# 

			{ L"\x3203",L"\x0028\x1105\x0029" }, //( ㈃ → (ᄅ) ) PARENTHESIZED HANGUL RIEUL → LEFT PARENTHESIS, HANGUL CHOSEONG RIEUL, RIGHT PARENTHESIS	# 

			{ L"\x3211",L"\x0028\xB77C\x0029" }, //( ㈑ → (라) ) PARENTHESIZED HANGUL RIEUL A → LEFT PARENTHESIS, HANGUL SYLLABLE RA, RIGHT PARENTHESIS	# 

			{ L"\x3204",L"\x0028\x1106\x0029" }, //( ㈄ → (ᄆ) ) PARENTHESIZED HANGUL MIEUM → LEFT PARENTHESIS, HANGUL CHOSEONG MIEUM, RIGHT PARENTHESIS	# 

			{ L"\x3212",L"\x0028\xB9C8\x0029" }, //( ㈒ → (마) ) PARENTHESIZED HANGUL MIEUM A → LEFT PARENTHESIS, HANGUL SYLLABLE MA, RIGHT PARENTHESIS	# 

			{ L"\x3205",L"\x0028\x1107\x0029" }, //( ㈅ → (ᄇ) ) PARENTHESIZED HANGUL PIEUP → LEFT PARENTHESIS, HANGUL CHOSEONG PIEUP, RIGHT PARENTHESIS	# 

			{ L"\x3213",L"\x0028\xBC14\x0029" }, //( ㈓ → (바) ) PARENTHESIZED HANGUL PIEUP A → LEFT PARENTHESIS, HANGUL SYLLABLE BA, RIGHT PARENTHESIS	# 

			{ L"\x3206",L"\x0028\x1109\x0029" }, //( ㈆ → (ᄉ) ) PARENTHESIZED HANGUL SIOS → LEFT PARENTHESIS, HANGUL CHOSEONG SIOS, RIGHT PARENTHESIS	# 

			{ L"\x3214",L"\x0028\xC0AC\x0029" }, //( ㈔ → (사) ) PARENTHESIZED HANGUL SIOS A → LEFT PARENTHESIS, HANGUL SYLLABLE SA, RIGHT PARENTHESIS	# 

			{ L"\x3207",L"\x0028\x110B\x0029" }, //( ㈇ → (ᄋ) ) PARENTHESIZED HANGUL IEUNG → LEFT PARENTHESIS, HANGUL CHOSEONG IEUNG, RIGHT PARENTHESIS	# 

			{ L"\x3215",L"\x0028\xC544\x0029" }, //( ㈕ → (아) ) PARENTHESIZED HANGUL IEUNG A → LEFT PARENTHESIS, HANGUL SYLLABLE A, RIGHT PARENTHESIS	# 

			{ L"\x321D",L"\x0028\xC624\xC804\x0029" }, //( ㈝ → (오전) ) PARENTHESIZED KOREAN CHARACTER OJEON → LEFT PARENTHESIS, HANGUL SYLLABLE O, HANGUL SYLLABLE JEON, RIGHT PARENTHESIS	# 

			{ L"\x321E",L"\x0028\xC624\xD6C4\x0029" }, //( ㈞ → (오후) ) PARENTHESIZED KOREAN CHARACTER O HU → LEFT PARENTHESIS, HANGUL SYLLABLE O, HANGUL SYLLABLE HU, RIGHT PARENTHESIS	# 

			{ L"\x3208",L"\x0028\x110C\x0029" }, //( ㈈ → (ᄌ) ) PARENTHESIZED HANGUL CIEUC → LEFT PARENTHESIS, HANGUL CHOSEONG CIEUC, RIGHT PARENTHESIS	# 

			{ L"\x3216",L"\x0028\xC790\x0029" }, //( ㈖ → (자) ) PARENTHESIZED HANGUL CIEUC A → LEFT PARENTHESIS, HANGUL SYLLABLE JA, RIGHT PARENTHESIS	# 

			{ L"\x321C",L"\x0028\xC8FC\x0029" }, //( ㈜ → (주) ) PARENTHESIZED HANGUL CIEUC U → LEFT PARENTHESIS, HANGUL SYLLABLE JU, RIGHT PARENTHESIS	# 

			{ L"\x3209",L"\x0028\x110E\x0029" }, //( ㈉ → (ᄎ) ) PARENTHESIZED HANGUL CHIEUCH → LEFT PARENTHESIS, HANGUL CHOSEONG CHIEUCH, RIGHT PARENTHESIS	# 

			{ L"\x3217",L"\x0028\xCC28\x0029" }, //( ㈗ → (차) ) PARENTHESIZED HANGUL CHIEUCH A → LEFT PARENTHESIS, HANGUL SYLLABLE CA, RIGHT PARENTHESIS	# 

			{ L"\x320A",L"\x0028\x110F\x0029" }, //( ㈊ → (ᄏ) ) PARENTHESIZED HANGUL KHIEUKH → LEFT PARENTHESIS, HANGUL CHOSEONG KHIEUKH, RIGHT PARENTHESIS	# 

			{ L"\x3218",L"\x0028\xCE74\x0029" }, //( ㈘ → (카) ) PARENTHESIZED HANGUL KHIEUKH A → LEFT PARENTHESIS, HANGUL SYLLABLE KA, RIGHT PARENTHESIS	# 

			{ L"\x320B",L"\x0028\x1110\x0029" }, //( ㈋ → (ᄐ) ) PARENTHESIZED HANGUL THIEUTH → LEFT PARENTHESIS, HANGUL CHOSEONG THIEUTH, RIGHT PARENTHESIS	# 

			{ L"\x3219",L"\x0028\xD0C0\x0029" }, //( ㈙ → (타) ) PARENTHESIZED HANGUL THIEUTH A → LEFT PARENTHESIS, HANGUL SYLLABLE TA, RIGHT PARENTHESIS	# 

			{ L"\x320C",L"\x0028\x1111\x0029" }, //( ㈌ → (ᄑ) ) PARENTHESIZED HANGUL PHIEUPH → LEFT PARENTHESIS, HANGUL CHOSEONG PHIEUPH, RIGHT PARENTHESIS	# 

			{ L"\x321A",L"\x0028\xD30C\x0029" }, //( ㈚ → (파) ) PARENTHESIZED HANGUL PHIEUPH A → LEFT PARENTHESIS, HANGUL SYLLABLE PA, RIGHT PARENTHESIS	# 

			{ L"\x320D",L"\x0028\x1112\x0029" }, //( ㈍ → (ᄒ) ) PARENTHESIZED HANGUL HIEUH → LEFT PARENTHESIS, HANGUL CHOSEONG HIEUH, RIGHT PARENTHESIS	# 

			{ L"\x321B",L"\x0028\xD558\x0029" }, //( ㈛ → (하) ) PARENTHESIZED HANGUL HIEUH A → LEFT PARENTHESIS, HANGUL SYLLABLE HA, RIGHT PARENTHESIS	# 

			{ L"\x3226",L"\x0028\x4E03\x0029" }, //( ㈦ → (七) ) PARENTHESIZED IDEOGRAPH SEVEN → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E03, RIGHT PARENTHESIS	# 

			{ L"\x3222",L"\x0028\x4E09\x0029" }, //( ㈢ → (三) ) PARENTHESIZED IDEOGRAPH THREE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E09, RIGHT PARENTHESIS	# 
			{ L"\x0001\xF241",L"\x0028\x4E09\x0029" }, //( 🉁 → (三) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-4E09 → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E09, RIGHT PARENTHESIS	# →〔三〕→

			{ L"\x3228",L"\x0028\x4E5D\x0029" }, //( ㈨ → (九) ) PARENTHESIZED IDEOGRAPH NINE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E5D, RIGHT PARENTHESIS	# 

			{ L"\x3221",L"\x0028\x4E8C\x0029" }, //( ㈡ → (二) ) PARENTHESIZED IDEOGRAPH TWO → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E8C, RIGHT PARENTHESIS	# 
			{ L"\x0001\xF242",L"\x0028\x4E8C\x0029" }, //( 🉂 → (二) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-4E8C → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E8C, RIGHT PARENTHESIS	# →〔二〕→

			{ L"\x3224",L"\x0028\x4E94\x0029" }, //( ㈤ → (五) ) PARENTHESIZED IDEOGRAPH FIVE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4E94, RIGHT PARENTHESIS	# 

			{ L"\x3239",L"\x0028\x4EE3\x0029" }, //( ㈹ → (代) ) PARENTHESIZED IDEOGRAPH REPRESENT → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4EE3, RIGHT PARENTHESIS	# 

			{ L"\x323D",L"\x0028\x4F01\x0029" }, //( ㈽ → (企) ) PARENTHESIZED IDEOGRAPH ENTERPRISE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4F01, RIGHT PARENTHESIS	# 

			{ L"\x3241",L"\x0028\x4F11\x0029" }, //( ㉁ → (休) ) PARENTHESIZED IDEOGRAPH REST → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-4F11, RIGHT PARENTHESIS	# 

			{ L"\x3227",L"\x0028\x516B\x0029" }, //( ㈧ → (八) ) PARENTHESIZED IDEOGRAPH EIGHT → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-516B, RIGHT PARENTHESIS	# 

			{ L"\x3225",L"\x0028\x516D\x0029" }, //( ㈥ → (六) ) PARENTHESIZED IDEOGRAPH SIX → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-516D, RIGHT PARENTHESIS	# 

			{ L"\x3238",L"\x0028\x52B4\x0029" }, //( ㈸ → (労) ) PARENTHESIZED IDEOGRAPH LABOR → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-52B4, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF247",L"\x0028\x52DD\x0029" }, //( 🉇 → (勝) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-52DD → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-52DD, RIGHT PARENTHESIS	# →〔勝〕→

			{ L"\x3229",L"\x0028\x5341\x0029" }, //( ㈩ → (十) ) PARENTHESIZED IDEOGRAPH TEN → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-5341, RIGHT PARENTHESIS	# 

			{ L"\x323F",L"\x0028\x5354\x0029" }, //( ㈿ → (協) ) PARENTHESIZED IDEOGRAPH ALLIANCE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-5354, RIGHT PARENTHESIS	# 

			{ L"\x3234",L"\x0028\x540D\x0029" }, //( ㈴ → (名) ) PARENTHESIZED IDEOGRAPH NAME → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-540D, RIGHT PARENTHESIS	# 

			{ L"\x323A",L"\x0028\x547C\x0029" }, //( ㈺ → (呼) ) PARENTHESIZED IDEOGRAPH CALL → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-547C, RIGHT PARENTHESIS	# 

			{ L"\x3223",L"\x0028\x56DB\x0029" }, //( ㈣ → (四) ) PARENTHESIZED IDEOGRAPH FOUR → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-56DB, RIGHT PARENTHESIS	# 

			{ L"\x322F",L"\x0028\x571F\x0029" }, //( ㈯ → (土) ) PARENTHESIZED IDEOGRAPH EARTH → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-571F, RIGHT PARENTHESIS	# 

			{ L"\x323B",L"\x0028\x5B66\x0029" }, //( ㈻ → (学) ) PARENTHESIZED IDEOGRAPH STUDY → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-5B66, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF243",L"\x0028\x5B89\x0029" }, //( 🉃 → (安) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-5B89 → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-5B89, RIGHT PARENTHESIS	# →〔安〕→

			{ L"\x0001\xF245",L"\x0028\x6253\x0029" }, //( 🉅 → (打) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-6253 → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-6253, RIGHT PARENTHESIS	# →〔打〕→

			{ L"\x0001\xF248",L"\x0028\x6557\x0029" }, //( 🉈 → (敗) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-6557 → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-6557, RIGHT PARENTHESIS	# →〔敗〕→

			{ L"\x3230",L"\x0028\x65E5\x0029" }, //( ㈰ → (日) ) PARENTHESIZED IDEOGRAPH SUN → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-65E5, RIGHT PARENTHESIS	# 

			{ L"\x322A",L"\x0028\x6708\x0029" }, //( ㈪ → (月) ) PARENTHESIZED IDEOGRAPH MOON → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-6708, RIGHT PARENTHESIS	# 

			{ L"\x3232",L"\x0028\x6709\x0029" }, //( ㈲ → (有) ) PARENTHESIZED IDEOGRAPH HAVE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-6709, RIGHT PARENTHESIS	# 

			{ L"\x322D",L"\x0028\x6728\x0029" }, //( ㈭ → (木) ) PARENTHESIZED IDEOGRAPH WOOD → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-6728, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF240",L"\x0028\x672C\x0029" }, //( 🉀 → (本) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-672C → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-672C, RIGHT PARENTHESIS	# →〔本〕→

			{ L"\x3231",L"\x0028\x682A\x0029" }, //( ㈱ → (株) ) PARENTHESIZED IDEOGRAPH STOCK → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-682A, RIGHT PARENTHESIS	# 

			{ L"\x322C",L"\x0028\x6C34\x0029" }, //( ㈬ → (水) ) PARENTHESIZED IDEOGRAPH WATER → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-6C34, RIGHT PARENTHESIS	# 

			{ L"\x322B",L"\x0028\x706B\x0029" }, //( ㈫ → (火) ) PARENTHESIZED IDEOGRAPH FIRE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-706B, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF244",L"\x0028\x70B9\x0029" }, //( 🉄 → (点) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-70B9 → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-70B9, RIGHT PARENTHESIS	# →〔点〕→

			{ L"\x3235",L"\x0028\x7279\x0029" }, //( ㈵ → (特) ) PARENTHESIZED IDEOGRAPH SPECIAL → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-7279, RIGHT PARENTHESIS	# 

			{ L"\x0001\xF246",L"\x0028\x76D7\x0029" }, //( 🉆 → (盗) ) TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-76D7 → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-76D7, RIGHT PARENTHESIS	# →〔盗〕→

			{ L"\x323C",L"\x0028\x76E3\x0029" }, //( ㈼ → (監) ) PARENTHESIZED IDEOGRAPH SUPERVISE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-76E3, RIGHT PARENTHESIS	# 

			{ L"\x3233",L"\x0028\x793E\x0029" }, //( ㈳ → (社) ) PARENTHESIZED IDEOGRAPH SOCIETY → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-793E, RIGHT PARENTHESIS	# 

			{ L"\x3237",L"\x0028\x795D\x0029" }, //( ㈷ → (祝) ) PARENTHESIZED IDEOGRAPH CONGRATULATION → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-795D, RIGHT PARENTHESIS	# 

			{ L"\x3240",L"\x0028\x796D\x0029" }, //( ㉀ → (祭) ) PARENTHESIZED IDEOGRAPH FESTIVAL → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-796D, RIGHT PARENTHESIS	# 

			{ L"\x3242",L"\x0028\x81EA\x0029" }, //( ㉂ → (自) ) PARENTHESIZED IDEOGRAPH SELF → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-81EA, RIGHT PARENTHESIS	# 

			{ L"\x3243",L"\x0028\x81F3\x0029" }, //( ㉃ → (至) ) PARENTHESIZED IDEOGRAPH REACH → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-81F3, RIGHT PARENTHESIS	# 

			{ L"\x3236",L"\x0028\x8CA1\x0029" }, //( ㈶ → (財) ) PARENTHESIZED IDEOGRAPH FINANCIAL → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-8CA1, RIGHT PARENTHESIS	# 

			{ L"\x323E",L"\x0028\x8CC7\x0029" }, //( ㈾ → (資) ) PARENTHESIZED IDEOGRAPH RESOURCE → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-8CC7, RIGHT PARENTHESIS	# 

			{ L"\x322E",L"\x0028\x91D1\x0029" }, //( ㈮ → (金) ) PARENTHESIZED IDEOGRAPH METAL → LEFT PARENTHESIS, CJK UNIFIED IDEOGRAPH-91D1, RIGHT PARENTHESIS	# 

			{ L"\xFF3D",L"\x0029" }, //( ］ → ) ) FULLWIDTH RIGHT SQUARE BRACKET → RIGHT PARENTHESIS	# →〕→
			{ L"\x2769",L"\x0029" }, //( ❩ → ) ) MEDIUM RIGHT PARENTHESIS ORNAMENT → RIGHT PARENTHESIS	# 
			{ L"\x2773",L"\x0029" }, //( ❳ → ) ) LIGHT RIGHT TORTOISE SHELL BRACKET ORNAMENT → RIGHT PARENTHESIS	# →〕→
			{ L"\x3015",L"\x0029" }, //( 〕 → ) ) RIGHT TORTOISE SHELL BRACKET → RIGHT PARENTHESIS	# 
			{ L"\xFD3F",L"\x0029" }, //( ﴿ → ) ) ORNATE RIGHT PARENTHESIS → RIGHT PARENTHESIS	# 

			{ L"\x2E29",L"\x0029\x0029" }, //( ⸩ → )) ) RIGHT DOUBLE PARENTHESIS → RIGHT PARENTHESIS, RIGHT PARENTHESIS	# 

			{ L"\x2774",L"\x007B" }, //( ❴ → { ) MEDIUM LEFT CURLY BRACKET ORNAMENT → LEFT CURLY BRACKET	# 
			{ L"\x0001\xD114",L"\x007B" }, //( 𝄔 → { ) MUSICAL SYMBOL BRACE → LEFT CURLY BRACKET	# 

			{ L"\x2775",L"\x007D" }, //( ❵ → } ) MEDIUM RIGHT CURLY BRACKET ORNAMENT → RIGHT CURLY BRACKET	# 

			{ L"\x301A",L"\x27E6" }, //( 〚 → ⟦ ) LEFT WHITE SQUARE BRACKET → MATHEMATICAL LEFT WHITE SQUARE BRACKET	# 

			{ L"\x301B",L"\x27E7" }, //( 〛 → ⟧ ) RIGHT WHITE SQUARE BRACKET → MATHEMATICAL RIGHT WHITE SQUARE BRACKET	# 

			{ L"\x27E8",L"\x276C" }, //( ⟨ → ❬ ) MATHEMATICAL LEFT ANGLE BRACKET → MEDIUM LEFT-POINTING ANGLE BRACKET ORNAMENT	# →〈→
			{ L"\x2329",L"\x276C" }, //( 〈 → ❬ ) LEFT-POINTING ANGLE BRACKET → MEDIUM LEFT-POINTING ANGLE BRACKET ORNAMENT	# →〈→
			{ L"\x3008",L"\x276C" }, //( 〈 → ❬ ) LEFT ANGLE BRACKET → MEDIUM LEFT-POINTING ANGLE BRACKET ORNAMENT	# 

			{ L"\x27E9",L"\x276D" }, //( ⟩ → ❭ ) MATHEMATICAL RIGHT ANGLE BRACKET → MEDIUM RIGHT-POINTING ANGLE BRACKET ORNAMENT	# →〉→
			{ L"\x232A",L"\x276D" }, //( 〉 → ❭ ) RIGHT-POINTING ANGLE BRACKET → MEDIUM RIGHT-POINTING ANGLE BRACKET ORNAMENT	# →〉→
			{ L"\x3009",L"\x276D" }, //( 〉 → ❭ ) RIGHT ANGLE BRACKET → MEDIUM RIGHT-POINTING ANGLE BRACKET ORNAMENT	# 

			{ L"\xFF3E",L"\xFE3F" }, //( ＾ → ︿ ) FULLWIDTH CIRCUMFLEX ACCENT → PRESENTATION FORM FOR VERTICAL LEFT ANGLE BRACKET	# 

			{ L"\x2E3F",L"\x00B6" }, //( ⸿ → ¶ ) CAPITULUM → PILCROW SIGN	# 

			{ L"\x204E",L"\x002A" }, //( ⁎ → * ) LOW ASTERISK → ASTERISK	# 
			{ L"\x066D",L"\x002A" }, //( ‎٭‎ → * ) ARABIC FIVE POINTED STAR → ASTERISK	# 
			{ L"\x2217",L"\x002A" }, //( ∗ → * ) ASTERISK OPERATOR → ASTERISK	# 
			{ L"\x0001\x031F",L"\x002A" }, //( 𐌟 → * ) OLD ITALIC LETTER ESS → ASTERISK	# 

			{ L"\x1735",L"\x002F" }, //( ᜵ → / ) PHILIPPINE SINGLE PUNCTUATION → SOLIDUS	# 
			{ L"\x2041",L"\x002F" }, //( ⁁ → / ) CARET INSERTION POINT → SOLIDUS	# 
			{ L"\x2215",L"\x002F" }, //( ∕ → / ) DIVISION SLASH → SOLIDUS	# 
			{ L"\x2044",L"\x002F" }, //( ⁄ → / ) FRACTION SLASH → SOLIDUS	# 
			{ L"\x2571",L"\x002F" }, //( ╱ → / ) BOX DRAWINGS LIGHT DIAGONAL UPPER RIGHT TO LOWER LEFT → SOLIDUS	# 
			{ L"\x27CB",L"\x002F" }, //( ⟋ → / ) MATHEMATICAL RISING DIAGONAL → SOLIDUS	# 
			{ L"\x29F8",L"\x002F" }, //( ⧸ → / ) BIG SOLIDUS → SOLIDUS	# 
			{ L"\x31D3",L"\x002F" }, //( ㇓ → / ) CJK STROKE SP → SOLIDUS	# →⼃→
			{ L"\x3033",L"\x002F" }, //( 〳 → / ) VERTICAL KANA REPEAT MARK UPPER HALF → SOLIDUS	# 
			{ L"\x2CC6",L"\x002F" }, //( Ⳇ → / ) COPTIC CAPITAL LETTER OLD COPTIC ESH → SOLIDUS	# 
			{ L"\x4E3F",L"\x002F" }, //( 丿 → / ) CJK UNIFIED IDEOGRAPH-4E3F → SOLIDUS	# →⼃→
			{ L"\x2F03",L"\x002F" }, //( ⼃ → / ) KANGXI RADICAL SLASH → SOLIDUS	# 

			{ L"\x29F6",L"\x002F\x0304" }, //( ⧶ → /̄ ) SOLIDUS WITH OVERBAR → SOLIDUS, COMBINING MACRON	# 

			{ L"\x2AFD",L"\x002F\x002F" }, //( ⫽ → // ) DOUBLE SOLIDUS OPERATOR → SOLIDUS, SOLIDUS	# 

			{ L"\x2AFB",L"\x002F\x002F\x002F" }, //( ⫻ → /// ) TRIPLE SOLIDUS BINARY RELATION → SOLIDUS, SOLIDUS, SOLIDUS	# 

			{ L"\xFF3C",L"\x005C" }, //( ＼ → \ ) FULLWIDTH REVERSE SOLIDUS → REVERSE SOLIDUS	# →∖→
			{ L"\xFE68",L"\x005C" }, //( ﹨ → \ ) SMALL REVERSE SOLIDUS → REVERSE SOLIDUS	# →∖→
			{ L"\x2216",L"\x005C" }, //( ∖ → \ ) SET MINUS → REVERSE SOLIDUS	# 
			{ L"\x27CD",L"\x005C" }, //( ⟍ → \ ) MATHEMATICAL FALLING DIAGONAL → REVERSE SOLIDUS	# 
			{ L"\x29F5",L"\x005C" }, //( ⧵ → \ ) REVERSE SOLIDUS OPERATOR → REVERSE SOLIDUS	# 
			{ L"\x29F9",L"\x005C" }, //( ⧹ → \ ) BIG REVERSE SOLIDUS → REVERSE SOLIDUS	# 
			{ L"\x31D4",L"\x005C" }, //( ㇔ → \ ) CJK STROKE D → REVERSE SOLIDUS	# →⼂→
			{ L"\x4E36",L"\x005C" }, //( 丶 → \ ) CJK UNIFIED IDEOGRAPH-4E36 → REVERSE SOLIDUS	# →⼂→
			{ L"\x2F02",L"\x005C" }, //( ⼂ → \ ) KANGXI RADICAL DOT → REVERSE SOLIDUS	# 

			{ L"\x2CF9",L"\x005C\x005C" }, //( ⳹ → \\ ) COPTIC OLD NUBIAN FULL STOP → REVERSE SOLIDUS, REVERSE SOLIDUS	# 
			{ L"\x244A",L"\x005C\x005C" }, //( ⑊ → \\ ) OCR DOUBLE BACKSLASH → REVERSE SOLIDUS, REVERSE SOLIDUS	# 

			{ L"\x27C8",L"\x005C\x1455" }, //( ⟈ → \ᑕ ) REVERSE SOLIDUS PRECEDING SUBSET → REVERSE SOLIDUS, CANADIAN SYLLABICS TA	# →\⊂→

			{ L"\xA778",L"\x0026" }, //( ꝸ → & ) LATIN SMALL LETTER UM → AMPERSAND	# 

			{ L"\x0AF0",L"\x0970" }, //( ૰ → ॰ ) GUJARATI ABBREVIATION SIGN → DEVANAGARI ABBREVIATION SIGN	# 
			{ L"\x0001\x10BB",L"\x0970" }, //( 𑂻 → ॰ ) KAITHI ABBREVIATION SIGN → DEVANAGARI ABBREVIATION SIGN	# 
			{ L"\x0001\x11C7",L"\x0970" }, //( 𑇇 → ॰ ) SHARADA ABBREVIATION SIGN → DEVANAGARI ABBREVIATION SIGN	# 
			{ L"\x26AC",L"\x0970" }, //( ⚬ → ॰ ) MEDIUM SMALL WHITE CIRCLE → DEVANAGARI ABBREVIATION SIGN	# 

			{ L"\x17D9",L"\x0E4F" }, //( ៙ → ๏ ) KHMER SIGN PHNAEK MUAN → THAI CHARACTER FONGMAN	# 

			{ L"\x17D5",L"\x0E5A" }, //( ៕ → ๚ ) KHMER SIGN BARIYOOSAN → THAI CHARACTER ANGKHANKHU	# 

			{ L"\x17DA",L"\x0E5B" }, //( ៚ → ๛ ) KHMER SIGN KOOMUUT → THAI CHARACTER KHOMUT	# 

			{ L"\x0F0C",L"\x0F0B" }, //( ༌ → ་ ) TIBETAN MARK DELIMITER TSHEG BSTAR → TIBETAN MARK INTERSYLLABIC TSHEG	# 

			{ L"\x0F0E",L"\x0F0D\x0F0D" }, //( ༎ → །། ) TIBETAN MARK NYIS SHAD → TIBETAN MARK SHAD, TIBETAN MARK SHAD	# 

			{ L"\x02C4",L"\x005E" }, //( ˄ → ^ ) MODIFIER LETTER UP ARROWHEAD → CIRCUMFLEX ACCENT	# 
			{ L"\x02C6",L"\x005E" }, //( ˆ → ^ ) MODIFIER LETTER CIRCUMFLEX ACCENT → CIRCUMFLEX ACCENT	# 

			{ L"\xA67E",L"\x02C7" }, //( ꙾ → ˇ ) CYRILLIC KAVYKA → CARON	# →˘→
			{ L"\x02D8",L"\x02C7" }, //( ˘ → ˇ ) BREVE → CARON	# 

			{ L"\x203E",L"\x02C9" }, //( ‾ → ˉ ) OVERLINE → MODIFIER LETTER MACRON	# 
			{ L"\xFE49",L"\x02C9" }, //( ﹉ → ˉ ) DASHED OVERLINE → MODIFIER LETTER MACRON	# →‾→
			{ L"\xFE4A",L"\x02C9" }, //( ﹊ → ˉ ) CENTRELINE OVERLINE → MODIFIER LETTER MACRON	# →‾→
			{ L"\xFE4B",L"\x02C9" }, //( ﹋ → ˉ ) WAVY OVERLINE → MODIFIER LETTER MACRON	# →‾→
			{ L"\xFE4C",L"\x02C9" }, //( ﹌ → ˉ ) DOUBLE WAVY OVERLINE → MODIFIER LETTER MACRON	# →‾→
			{ L"\x00AF",L"\x02C9" }, //( ¯ → ˉ ) MACRON → MODIFIER LETTER MACRON	# 
			{ L"\xFFE3",L"\x02C9" }, //( ￣ → ˉ ) FULLWIDTH MACRON → MODIFIER LETTER MACRON	# →‾→
			{ L"\x2594",L"\x02C9" }, //( ▔ → ˉ ) UPPER ONE EIGHTH BLOCK → MODIFIER LETTER MACRON	# →¯→

			{ L"\x044A",L"\x02C9\x0062" }, //( ъ → ˉb ) CYRILLIC SMALL LETTER HARD SIGN → MODIFIER LETTER MACRON, LATIN SMALL LETTER B	# →¯b→

			{ L"\x0375",L"\x02CF" }, //( ͵ → ˏ ) GREEK LOWER NUMERAL SIGN → MODIFIER LETTER LOW ACUTE ACCENT	# 

			{ L"\x02FB",L"\x02EA" }, //( ˻ → ˪ ) MODIFIER LETTER BEGIN LOW TONE → MODIFIER LETTER YIN DEPARTING TONE MARK	# 
			{ L"\xA716",L"\x02EA" }, //( ꜖ → ˪ ) MODIFIER LETTER EXTRA-LOW LEFT-STEM TONE BAR → MODIFIER LETTER YIN DEPARTING TONE MARK	# 

			{ L"\xA714",L"\x02EB" }, //( ꜔ → ˫ ) MODIFIER LETTER MID LEFT-STEM TONE BAR → MODIFIER LETTER YANG DEPARTING TONE MARK	# 

			{ L"\x3002",L"\x02F3" }, //( 。 → ˳ ) IDEOGRAPHIC FULL STOP → MODIFIER LETTER LOW RING	# 

			{ L"\x2E30",L"\x00B0" }, //( ⸰ → ° ) RING POINT → DEGREE SIGN	# →∘→
			{ L"\x02DA",L"\x00B0" }, //( ˚ → ° ) RING ABOVE → DEGREE SIGN	# 
			{ L"\x2218",L"\x00B0" }, //( ∘ → ° ) RING OPERATOR → DEGREE SIGN	# 
			{ L"\x25CB",L"\x00B0" }, //( ○ → ° ) WHITE CIRCLE → DEGREE SIGN	# →◦→→∘→
			{ L"\x25E6",L"\x00B0" }, //( ◦ → ° ) WHITE BULLET → DEGREE SIGN	# →∘→

			{ L"\x235C",L"\x00B0\x0332" }, //( ⍜ → °̲ ) APL FUNCTIONAL SYMBOL CIRCLE UNDERBAR → DEGREE SIGN, COMBINING LOW LINE	# →○̲→→∘̲→

			{ L"\x2364",L"\x00B0\x0308" }, //( ⍤ → °̈ ) APL FUNCTIONAL SYMBOL JOT DIAERESIS → DEGREE SIGN, COMBINING DIAERESIS	# →◦̈→→∘̈→

			{ L"\x2103",L"\x00B0\x0043" }, //( ℃ → °C ) DEGREE CELSIUS → DEGREE SIGN, LATIN CAPITAL LETTER C	# 

			{ L"\x2109",L"\x00B0\x0046" }, //( ℉ → °F ) DEGREE FAHRENHEIT → DEGREE SIGN, LATIN CAPITAL LETTER F	# 

			{ L"\x0BF5",L"\x0BF3" }, //( ௵ → ௳ ) TAMIL YEAR SIGN → TAMIL DAY SIGN	# 

			{ L"\x0F1B",L"\x0F1A\x0F1A" }, //( ༛ → ༚༚ ) TIBETAN SIGN RDEL DKAR GNYIS → TIBETAN SIGN RDEL DKAR GCIG, TIBETAN SIGN RDEL DKAR GCIG	# 

			{ L"\x0F1F",L"\x0F1A\x0F1D" }, //( ༟ → ༚༝ ) TIBETAN SIGN RDEL DKAR RDEL NAG → TIBETAN SIGN RDEL DKAR GCIG, TIBETAN SIGN RDEL NAG GCIG	# 

			{ L"\x0FCE",L"\x0F1D\x0F1A" }, //( ࿎ → ༝༚ ) TIBETAN SIGN RDEL NAG RDEL DKAR → TIBETAN SIGN RDEL NAG GCIG, TIBETAN SIGN RDEL DKAR GCIG	# 

			{ L"\x0F1E",L"\x0F1D\x0F1D" }, //( ༞ → ༝༝ ) TIBETAN SIGN RDEL NAG GNYIS → TIBETAN SIGN RDEL NAG GCIG, TIBETAN SIGN RDEL NAG GCIG	# 

			{ L"\x24B8",L"\x00A9" }, //( Ⓒ → © ) CIRCLED LATIN CAPITAL LETTER C → COPYRIGHT SIGN	# 

			{ L"\x24C7",L"\x00AE" }, //( Ⓡ → ® ) CIRCLED LATIN CAPITAL LETTER R → REGISTERED SIGN	# 

			{ L"\x24C5",L"\x2117" }, //( Ⓟ → ℗ ) CIRCLED LATIN CAPITAL LETTER P → SOUND RECORDING COPYRIGHT	# 

			{ L"\x2BEC",L"\x219E" }, //( ⯬ → ↞ ) LEFTWARDS TWO-HEADED ARROW WITH TRIANGLE ARROWHEADS → LEFTWARDS TWO HEADED ARROW	# 

			{ L"\x2BED",L"\x219F" }, //( ⯭ → ↟ ) UPWARDS TWO-HEADED ARROW WITH TRIANGLE ARROWHEADS → UPWARDS TWO HEADED ARROW	# 

			{ L"\x2BEE",L"\x21A0" }, //( ⯮ → ↠ ) RIGHTWARDS TWO-HEADED ARROW WITH TRIANGLE ARROWHEADS → RIGHTWARDS TWO HEADED ARROW	# 

			{ L"\x2BEF",L"\x21A1" }, //( ⯯ → ↡ ) DOWNWARDS TWO-HEADED ARROW WITH TRIANGLE ARROWHEADS → DOWNWARDS TWO HEADED ARROW	# 

			{ L"\x21B5",L"\x21B2" }, //( ↵ → ↲ ) DOWNWARDS ARROW WITH CORNER LEFTWARDS → DOWNWARDS ARROW WITH TIP LEFTWARDS	# 

			{ L"\x2965",L"\x21C3\x21C2" }, //( ⥥ → ⇃⇂ ) DOWNWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT → DOWNWARDS HARPOON WITH BARB LEFTWARDS, DOWNWARDS HARPOON WITH BARB RIGHTWARDS	# 

			{ L"\x296F",L"\x21C3\x16DA" }, //( ⥯ → ⇃ᛚ ) DOWNWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT → DOWNWARDS HARPOON WITH BARB LEFTWARDS, RUNIC LETTER LAUKAZ LAGU LOGR L	# →⇃↾→

			{ L"\x0001\xD6DB",L"\x2202" }, //( 𝛛 → ∂ ) MATHEMATICAL BOLD PARTIAL DIFFERENTIAL → PARTIAL DIFFERENTIAL	# 
			{ L"\x0001\xD715",L"\x2202" }, //( 𝜕 → ∂ ) MATHEMATICAL ITALIC PARTIAL DIFFERENTIAL → PARTIAL DIFFERENTIAL	# 
			{ L"\x0001\xD74F",L"\x2202" }, //( 𝝏 → ∂ ) MATHEMATICAL BOLD ITALIC PARTIAL DIFFERENTIAL → PARTIAL DIFFERENTIAL	# 
			{ L"\x0001\xD789",L"\x2202" }, //( 𝞉 → ∂ ) MATHEMATICAL SANS-SERIF BOLD PARTIAL DIFFERENTIAL → PARTIAL DIFFERENTIAL	# 
			{ L"\x0001\xD7C3",L"\x2202" }, //( 𝟃 → ∂ ) MATHEMATICAL SANS-SERIF BOLD ITALIC PARTIAL DIFFERENTIAL → PARTIAL DIFFERENTIAL	# 
			{ L"\x0001\xE8CC",L"\x2202" }, //( ‎𞣌‎ → ∂ ) MENDE KIKAKUI DIGIT SIX → PARTIAL DIFFERENTIAL	# 

			{ L"\x0001\xE8CD",L"\x2202\x0335" }, //( ‎𞣍‎ → ∂̵ ) MENDE KIKAKUI DIGIT SEVEN → PARTIAL DIFFERENTIAL, COMBINING SHORT STROKE OVERLAY	# →ð→
			{ L"\x00F0",L"\x2202\x0335" }, //( ð → ∂̵ ) LATIN SMALL LETTER ETH → PARTIAL DIFFERENTIAL, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x2300",L"\x2205" }, //( ⌀ → ∅ ) DIAMETER SIGN → EMPTY SET	# 

			{ L"\x0001\xD6C1",L"\x2207" }, //( 𝛁 → ∇ ) MATHEMATICAL BOLD NABLA → NABLA	# 
			{ L"\x0001\xD6FB",L"\x2207" }, //( 𝛻 → ∇ ) MATHEMATICAL ITALIC NABLA → NABLA	# 
			{ L"\x0001\xD735",L"\x2207" }, //( 𝜵 → ∇ ) MATHEMATICAL BOLD ITALIC NABLA → NABLA	# 
			{ L"\x0001\xD76F",L"\x2207" }, //( 𝝯 → ∇ ) MATHEMATICAL SANS-SERIF BOLD NABLA → NABLA	# 
			{ L"\x0001\xD7A9",L"\x2207" }, //( 𝞩 → ∇ ) MATHEMATICAL SANS-SERIF BOLD ITALIC NABLA → NABLA	# 
			{ L"\x0001\x18A8",L"\x2207" }, //( 𑢨 → ∇ ) WARANG CITI CAPITAL LETTER E → NABLA	# 

			{ L"\x2362",L"\x2207\x0308" }, //( ⍢ → ∇̈ ) APL FUNCTIONAL SYMBOL DEL DIAERESIS → NABLA, COMBINING DIAERESIS	# 

			{ L"\x236B",L"\x2207\x0334" }, //( ⍫ → ∇̴ ) APL FUNCTIONAL SYMBOL DEL TILDE → NABLA, COMBINING TILDE OVERLAY	# 

			{ L"\x2588",L"\x220E" }, //( █ → ∎ ) FULL BLOCK → END OF PROOF	# →■→
			{ L"\x25A0",L"\x220E" }, //( ■ → ∎ ) BLACK SQUARE → END OF PROOF	# 

			{ L"\x2A3F",L"\x2210" }, //( ⨿ → ∐ ) AMALGAMATION OR COPRODUCT → N-ARY COPRODUCT	# 

			{ L"\x16ED",L"\x002B" }, //( ᛭ → + ) RUNIC CROSS PUNCTUATION → PLUS SIGN	# 
			{ L"\x2795",L"\x002B" }, //( ➕ → + ) HEAVY PLUS SIGN → PLUS SIGN	# 
			{ L"\x0001\x029B",L"\x002B" }, //( 𐊛 → + ) LYCIAN LETTER H → PLUS SIGN	# 

			{ L"\x2A23",L"\x002B\x0302" }, //( ⨣ → +̂ ) PLUS SIGN WITH CIRCUMFLEX ACCENT ABOVE → PLUS SIGN, COMBINING CIRCUMFLEX ACCENT	# 

			{ L"\x2A22",L"\x002B\x030A" }, //( ⨢ → +̊ ) PLUS SIGN WITH SMALL CIRCLE ABOVE → PLUS SIGN, COMBINING RING ABOVE	# 

			{ L"\x2A24",L"\x002B\x0303" }, //( ⨤ → +̃ ) PLUS SIGN WITH TILDE ABOVE → PLUS SIGN, COMBINING TILDE	# 

			{ L"\x2214",L"\x002B\x0307" }, //( ∔ → +̇ ) DOT PLUS → PLUS SIGN, COMBINING DOT ABOVE	# 

			{ L"\x2A25",L"\x002B\x0323" }, //( ⨥ → +̣ ) PLUS SIGN WITH DOT BELOW → PLUS SIGN, COMBINING DOT BELOW	# 

			{ L"\x2A26",L"\x002B\x0330" }, //( ⨦ → +̰ ) PLUS SIGN WITH TILDE BELOW → PLUS SIGN, COMBINING TILDE BELOW	# 

			{ L"\x2A27",L"\x002B\x2082" }, //( ⨧ → +₂ ) PLUS SIGN WITH SUBSCRIPT TWO → PLUS SIGN, SUBSCRIPT TWO	# 

			{ L"\x2797",L"\x00F7" }, //( ➗ → ÷ ) HEAVY DIVISION SIGN → DIVISION SIGN	# 

			{ L"\x2039",L"\x003C" }, //( ‹ → < ) SINGLE LEFT-POINTING ANGLE QUOTATION MARK → LESS-THAN SIGN	# 
			{ L"\x276E",L"\x003C" }, //( ❮ → < ) HEAVY LEFT-POINTING ANGLE QUOTATION MARK ORNAMENT → LESS-THAN SIGN	# →‹→
			{ L"\x02C2",L"\x003C" }, //( ˂ → < ) MODIFIER LETTER LEFT ARROWHEAD → LESS-THAN SIGN	# 
			{ L"\x1438",L"\x003C" }, //( ᐸ → < ) CANADIAN SYLLABICS PA → LESS-THAN SIGN	# 
			{ L"\x16B2",L"\x003C" }, //( ᚲ → < ) RUNIC LETTER KAUNA → LESS-THAN SIGN	# 

			{ L"\x22D6",L"\x003C\x00B7" }, //( ⋖ → <· ) LESS-THAN WITH DOT → LESS-THAN SIGN, MIDDLE DOT	# →ᑅ→→ᐸᐧ→
			{ L"\x2CB4",L"\x003C\x00B7" }, //( Ⲵ → <· ) COPTIC CAPITAL LETTER OLD COPTIC AIN → LESS-THAN SIGN, MIDDLE DOT	# →ᑅ→→ᐸᐧ→
			{ L"\x1445",L"\x003C\x00B7" }, //( ᑅ → <· ) CANADIAN SYLLABICS WEST-CREE PWA → LESS-THAN SIGN, MIDDLE DOT	# →ᐸᐧ→

			{ L"\x226A",L"\x003C\x003C" }, //( ≪ → << ) MUCH LESS-THAN → LESS-THAN SIGN, LESS-THAN SIGN	# 

			{ L"\x22D8",L"\x003C\x003C\x003C" }, //( ⋘ → <<< ) VERY MUCH LESS-THAN → LESS-THAN SIGN, LESS-THAN SIGN, LESS-THAN SIGN	# 

			{ L"\x1400",L"\x003D" }, //( ᐀ → = ) CANADIAN SYLLABICS HYPHEN → EQUALS SIGN	# 
			{ L"\x2E40",L"\x003D" }, //( ⹀ → = ) DOUBLE HYPHEN → EQUALS SIGN	# 
			{ L"\x30A0",L"\x003D" }, //( ゠ → = ) KATAKANA-HIRAGANA DOUBLE HYPHEN → EQUALS SIGN	# 
			{ L"\xA4FF",L"\x003D" }, //( ꓿ → = ) LISU PUNCTUATION FULL STOP → EQUALS SIGN	# 

			{ L"\x225A",L"\x003D\x0306" }, //( ≚ → =̆ ) EQUIANGULAR TO → EQUALS SIGN, COMBINING BREVE	# →=̌→

			{ L"\x2259",L"\x003D\x0302" }, //( ≙ → =̂ ) ESTIMATES → EQUALS SIGN, COMBINING CIRCUMFLEX ACCENT	# 

			{ L"\x2257",L"\x003D\x030A" }, //( ≗ → =̊ ) RING EQUAL TO → EQUALS SIGN, COMBINING RING ABOVE	# 

			{ L"\x2250",L"\x003D\x0307" }, //( ≐ → =̇ ) APPROACHES THE LIMIT → EQUALS SIGN, COMBINING DOT ABOVE	# 

			{ L"\x2251",L"\x003D\x0307\x0323" }, //( ≑ → =̣̇ ) GEOMETRICALLY EQUAL TO → EQUALS SIGN, COMBINING DOT ABOVE, COMBINING DOT BELOW	# →≐̣→

			{ L"\x2A6E",L"\x003D\x20F0" }, //( ⩮ → =⃰ ) EQUALS WITH ASTERISK → EQUALS SIGN, COMBINING ASTERISK ABOVE	# 

			{ L"\x2A75",L"\x003D\x003D" }, //( ⩵ → == ) TWO CONSECUTIVE EQUALS SIGNS → EQUALS SIGN, EQUALS SIGN	# 

			{ L"\x2A76",L"\x003D\x003D\x003D" }, //( ⩶ → === ) THREE CONSECUTIVE EQUALS SIGNS → EQUALS SIGN, EQUALS SIGN, EQUALS SIGN	# 

			{ L"\x225E",L"\x003D\x036B" }, //( ≞ → =ͫ ) MEASURED BY → EQUALS SIGN, COMBINING LATIN SMALL LETTER M	# 

			{ L"\x203A",L"\x003E" }, //( › → > ) SINGLE RIGHT-POINTING ANGLE QUOTATION MARK → GREATER-THAN SIGN	# 
			{ L"\x276F",L"\x003E" }, //( ❯ → > ) HEAVY RIGHT-POINTING ANGLE QUOTATION MARK ORNAMENT → GREATER-THAN SIGN	# →›→
			{ L"\x02C3",L"\x003E" }, //( ˃ → > ) MODIFIER LETTER RIGHT ARROWHEAD → GREATER-THAN SIGN	# 
			{ L"\x1433",L"\x003E" }, //( ᐳ → > ) CANADIAN SYLLABICS PO → GREATER-THAN SIGN	# 

			{ L"\x1441",L"\x003E\x00B7" }, //( ᑁ → >· ) CANADIAN SYLLABICS WEST-CREE PWO → GREATER-THAN SIGN, MIDDLE DOT	# →ᐳᐧ→

			{ L"\x2AA5",L"\x003E\x003C" }, //( ⪥ → >< ) GREATER-THAN BESIDE LESS-THAN → GREATER-THAN SIGN, LESS-THAN SIGN	# 

			{ L"\x226B",L"\x003E\x003E" }, //( ≫ → >> ) MUCH GREATER-THAN → GREATER-THAN SIGN, GREATER-THAN SIGN	# 
			{ L"\x2A20",L"\x003E\x003E" }, //( ⨠ → >> ) Z NOTATION SCHEMA PIPING → GREATER-THAN SIGN, GREATER-THAN SIGN	# →≫→

			{ L"\x22D9",L"\x003E\x003E\x003E" }, //( ⋙ → >>> ) VERY MUCH GREATER-THAN → GREATER-THAN SIGN, GREATER-THAN SIGN, GREATER-THAN SIGN	# 

			{ L"\x2053",L"\x007E" }, //( ⁓ → ~ ) SWUNG DASH → TILDE	# 
			{ L"\x02DC",L"\x007E" }, //( ˜ → ~ ) SMALL TILDE → TILDE	# 
			{ L"\x1FC0",L"\x007E" }, //( ῀ → ~ ) GREEK PERISPOMENI → TILDE	# →˜→
			{ L"\x223C",L"\x007E" }, //( ∼ → ~ ) TILDE OPERATOR → TILDE	# 

			{ L"\x2368",L"\x007E\x0308" }, //( ⍨ → ~̈ ) APL FUNCTIONAL SYMBOL TILDE DIAERESIS → TILDE, COMBINING DIAERESIS	# 

			{ L"\x2E1E",L"\x007E\x0307" }, //( ⸞ → ~̇ ) TILDE WITH DOT ABOVE → TILDE, COMBINING DOT ABOVE	# →⩪→→∼̇→→⁓̇→
			{ L"\x2A6A",L"\x007E\x0307" }, //( ⩪ → ~̇ ) TILDE OPERATOR WITH DOT ABOVE → TILDE, COMBINING DOT ABOVE	# →∼̇→→⁓̇→

			{ L"\x2E1F",L"\x007E\x0323" }, //( ⸟ → ~̣ ) TILDE WITH DOT BELOW → TILDE, COMBINING DOT BELOW	# 

			{ L"\x0001\xE8C8",L"\x2220" }, //( ‎𞣈‎ → ∠ ) MENDE KIKAKUI DIGIT TWO → ANGLE	# 

			{ L"\x22C0",L"\x2227" }, //( ⋀ → ∧ ) N-ARY LOGICAL AND → LOGICAL AND	# 

			{ L"\x222F",L"\x222E\x222E" }, //( ∯ → ∮∮ ) SURFACE INTEGRAL → CONTOUR INTEGRAL, CONTOUR INTEGRAL	# 

			{ L"\x2230",L"\x222E\x222E\x222E" }, //( ∰ → ∮∮∮ ) VOLUME INTEGRAL → CONTOUR INTEGRAL, CONTOUR INTEGRAL, CONTOUR INTEGRAL	# 

			{ L"\x2E2B",L"\x2234" }, //( ⸫ → ∴ ) ONE DOT OVER TWO DOTS PUNCTUATION → THEREFORE	# 

			{ L"\x2E2A",L"\x2235" }, //( ⸪ → ∵ ) TWO DOTS OVER ONE DOT PUNCTUATION → BECAUSE	# 

			{ L"\x2E2C",L"\x2237" }, //( ⸬ → ∷ ) SQUARED FOUR DOT PUNCTUATION → PROPORTION	# 

			{ L"\x0001\x11DE",L"\x2248" }, //( 𑇞 → ≈ ) SHARADA SECTION MARK-1 → ALMOST EQUAL TO	# 

			{ L"\x264E",L"\x224F" }, //( ♎ → ≏ ) LIBRA → DIFFERENCE BETWEEN	# 
			{ L"\x0001\xF75E",L"\x224F" }, //( 🝞 → ≏ ) ALCHEMICAL SYMBOL FOR SUBLIMATION → DIFFERENCE BETWEEN	# →♎→

			{ L"\x2263",L"\x2261" }, //( ≣ → ≡ ) STRICTLY EQUIVALENT TO → IDENTICAL TO	# 

			{ L"\x2A03",L"\x228D" }, //( ⨃ → ⊍ ) N-ARY UNION OPERATOR WITH DOT → MULTISET MULTIPLICATION	# 

			{ L"\x2A04",L"\x228E" }, //( ⨄ → ⊎ ) N-ARY UNION OPERATOR WITH PLUS → MULTISET UNION	# 

			{ L"\x2A05",L"\x2293" }, //( ⨅ → ⊓ ) N-ARY SQUARE INTERSECTION OPERATOR → SQUARE CAP	# 

			{ L"\x2A06",L"\x2294" }, //( ⨆ → ⊔ ) N-ARY SQUARE UNION OPERATOR → SQUARE CUP	# 

			{ L"\x2A02",L"\x2297" }, //( ⨂ → ⊗ ) N-ARY CIRCLED TIMES OPERATOR → CIRCLED TIMES	# 

			{ L"\x235F",L"\x229B" }, //( ⍟ → ⊛ ) APL FUNCTIONAL SYMBOL CIRCLE STAR → CIRCLED ASTERISK OPERATOR	# 

			{ L"\x0001\xF771",L"\x22A0" }, //( 🝱 → ⊠ ) ALCHEMICAL SYMBOL FOR MONTH → SQUARED TIMES	# 

			{ L"\x0001\xF755",L"\x22A1" }, //( 🝕 → ⊡ ) ALCHEMICAL SYMBOL FOR URINE → SQUARED DOT OPERATOR	# 

			{ L"\x25C1",L"\x22B2" }, //( ◁ → ⊲ ) WHITE LEFT-POINTING TRIANGLE → NORMAL SUBGROUP OF	# 

			{ L"\x25B7",L"\x22B3" }, //( ▷ → ⊳ ) WHITE RIGHT-POINTING TRIANGLE → CONTAINS AS NORMAL SUBGROUP	# 

			{ L"\x2363",L"\x22C6\x0308" }, //( ⍣ → ⋆̈ ) APL FUNCTIONAL SYMBOL STAR DIAERESIS → STAR OPERATOR, COMBINING DIAERESIS	# 

			{ L"\xFE34",L"\x2307" }, //( ︴ → ⌇ ) PRESENTATION FORM FOR VERTICAL WAVY LOW LINE → WAVY LINE	# 

			{ L"\x25E0",L"\x2312" }, //( ◠ → ⌒ ) UPPER HALF CIRCLE → ARC	# 

			{ L"\x2A3D",L"\x2319" }, //( ⨽ → ⌙ ) RIGHTHAND INTERIOR PRODUCT → TURNED NOT SIGN	# 

			{ L"\x2325",L"\x2324" }, //( ⌥ → ⌤ ) OPTION KEY → UP ARROWHEAD BETWEEN TWO HORIZONTAL BARS	# 

			{ L"\x29C7",L"\x233B" }, //( ⧇ → ⌻ ) SQUARED SMALL CIRCLE → APL FUNCTIONAL SYMBOL QUAD JOT	# 

			{ L"\x25CE",L"\x233E" }, //( ◎ → ⌾ ) BULLSEYE → APL FUNCTIONAL SYMBOL CIRCLE JOT	# →⦾→
			{ L"\x29BE",L"\x233E" }, //( ⦾ → ⌾ ) CIRCLED WHITE BULLET → APL FUNCTIONAL SYMBOL CIRCLE JOT	# 

			{ L"\x29C5",L"\x2342" }, //( ⧅ → ⍂ ) SQUARED FALLING DIAGONAL SLASH → APL FUNCTIONAL SYMBOL QUAD BACKSLASH	# 

			{ L"\x29B0",L"\x2349" }, //( ⦰ → ⍉ ) REVERSED EMPTY SET → APL FUNCTIONAL SYMBOL CIRCLE BACKSLASH	# 

			{ L"\x23C3",L"\x234B" }, //( ⏃ → ⍋ ) DENTISTRY SYMBOL LIGHT VERTICAL WITH TRIANGLE → APL FUNCTIONAL SYMBOL DELTA STILE	# 

			{ L"\x23C2",L"\x234E" }, //( ⏂ → ⍎ ) DENTISTRY SYMBOL LIGHT UP AND HORIZONTAL WITH CIRCLE → APL FUNCTIONAL SYMBOL DOWN TACK JOT	# 

			{ L"\x23C1",L"\x2355" }, //( ⏁ → ⍕ ) DENTISTRY SYMBOL LIGHT DOWN AND HORIZONTAL WITH CIRCLE → APL FUNCTIONAL SYMBOL UP TACK JOT	# 

			{ L"\x00D6",L"\x2365" }, //( Ö → ⍥ ) LATIN CAPITAL LETTER O WITH DIAERESIS → APL FUNCTIONAL SYMBOL CIRCLE DIAERESIS	# 
			{ L"\x0150",L"\x2365" }, //( Ő → ⍥ ) LATIN CAPITAL LETTER O WITH DOUBLE ACUTE → APL FUNCTIONAL SYMBOL CIRCLE DIAERESIS	# →Ö→

			{ L"\x23C6",L"\x236D" }, //( ⏆ → ⍭ ) DENTISTRY SYMBOL LIGHT VERTICAL AND WAVE → APL FUNCTIONAL SYMBOL STILE TILDE	# 

			{ L"\x2638",L"\x2388" }, //( ☸ → ⎈ ) WHEEL OF DHARMA → HELM SYMBOL	# 

			{ L"\xFE35",L"\x23DC" }, //( ︵ → ⏜ ) PRESENTATION FORM FOR VERTICAL LEFT PARENTHESIS → TOP PARENTHESIS	# 

			{ L"\xFE36",L"\x23DD" }, //( ︶ → ⏝ ) PRESENTATION FORM FOR VERTICAL RIGHT PARENTHESIS → BOTTOM PARENTHESIS	# 

			{ L"\xFE37",L"\x23DE" }, //( ︷ → ⏞ ) PRESENTATION FORM FOR VERTICAL LEFT CURLY BRACKET → TOP CURLY BRACKET	# 

			{ L"\xFE38",L"\x23DF" }, //( ︸ → ⏟ ) PRESENTATION FORM FOR VERTICAL RIGHT CURLY BRACKET → BOTTOM CURLY BRACKET	# 

			{ L"\xFE39",L"\x23E0" }, //( ︹ → ⏠ ) PRESENTATION FORM FOR VERTICAL LEFT TORTOISE SHELL BRACKET → TOP TORTOISE SHELL BRACKET	# 

			{ L"\xFE3A",L"\x23E1" }, //( ︺ → ⏡ ) PRESENTATION FORM FOR VERTICAL RIGHT TORTOISE SHELL BRACKET → BOTTOM TORTOISE SHELL BRACKET	# 

			{ L"\x25B1",L"\x23E5" }, //( ▱ → ⏥ ) WHITE PARALLELOGRAM → FLATNESS	# 

			{ L"\xFE31",L"\x2502" }, //( ︱ → │ ) PRESENTATION FORM FOR VERTICAL EM DASH → BOX DRAWINGS LIGHT VERTICAL	# →｜→
			{ L"\xFF5C",L"\x2502" }, //( ｜ → │ ) FULLWIDTH VERTICAL LINE → BOX DRAWINGS LIGHT VERTICAL	# 
			{ L"\x2503",L"\x2502" }, //( ┃ → │ ) BOX DRAWINGS HEAVY VERTICAL → BOX DRAWINGS LIGHT VERTICAL	# 

			{ L"\x250F",L"\x250C" }, //( ┏ → ┌ ) BOX DRAWINGS HEAVY DOWN AND RIGHT → BOX DRAWINGS LIGHT DOWN AND RIGHT	# 

			{ L"\x2523",L"\x251C" }, //( ┣ → ├ ) BOX DRAWINGS HEAVY VERTICAL AND RIGHT → BOX DRAWINGS LIGHT VERTICAL AND RIGHT	# 

			{ L"\x2590",L"\x258C" }, //( ▐ → ▌ ) RIGHT HALF BLOCK → LEFT HALF BLOCK	# 

			{ L"\x2597",L"\x2596" }, //( ▗ → ▖ ) QUADRANT LOWER RIGHT → QUADRANT LOWER LEFT	# 

			{ L"\x259D",L"\x2598" }, //( ▝ → ▘ ) QUADRANT UPPER RIGHT → QUADRANT UPPER LEFT	# 

			{ L"\x2610",L"\x25A1" }, //( ☐ → □ ) BALLOT BOX → WHITE SQUARE	# 

			{ L"\xFFED",L"\x25AA" }, //( ￭ → ▪ ) HALFWIDTH BLACK SQUARE → BLACK SMALL SQUARE	# 

			{ L"\x25B8",L"\x25B6" }, //( ▸ → ▶ ) BLACK RIGHT-POINTING SMALL TRIANGLE → BLACK RIGHT-POINTING TRIANGLE	# →►→
			{ L"\x25BA",L"\x25B6" }, //( ► → ▶ ) BLACK RIGHT-POINTING POINTER → BLACK RIGHT-POINTING TRIANGLE	# 

			{ L"\x2CE9",L"\x2627" }, //( ⳩ → ☧ ) COPTIC SYMBOL KHI RO → CHI RHO	# 

			{ L"\x0001\xF70A",L"\x2629" }, //( 🜊 → ☩ ) ALCHEMICAL SYMBOL FOR VINEGAR → CROSS OF JERUSALEM	# 

			{ L"\x0001\xF312",L"\x263D" }, //( 🌒 → ☽ ) WAXING CRESCENT MOON SYMBOL → FIRST QUARTER MOON	# 
			{ L"\x0001\xF319",L"\x263D" }, //( 🌙 → ☽ ) CRESCENT MOON → FIRST QUARTER MOON	# 

			{ L"\x0001\xF318",L"\x263E" }, //( 🌘 → ☾ ) WANING CRESCENT MOON SYMBOL → LAST QUARTER MOON	# 

			{ L"\x29D9",L"\x299A" }, //( ⧙ → ⦚ ) RIGHT WIGGLY FENCE → VERTICAL ZIGZAG LINE	# 

			{ L"\x0001\xF73A",L"\x29DF" }, //( 🜺 → ⧟ ) ALCHEMICAL SYMBOL FOR ARSENIC → DOUBLE-ENDED MULTIMAP	# 

			{ L"\x2A3E",L"\x2A1F" }, //( ⨾ → ⨟ ) Z NOTATION RELATIONAL COMPOSITION → Z NOTATION SCHEMA COMPOSITION	# 

			{ L"\x2669",L"\x0001\xD158\x0001\xD165" }, //( ♩ → 𝅘𝅥 ) QUARTER NOTE → MUSICAL SYMBOL NOTEHEAD BLACK, MUSICAL SYMBOL COMBINING STEM	# 

			{ L"\x266A",L"\x0001\xD158\x0001\xD165\x0001\xD16E" }, //( ♪ → 𝅘𝅥𝅮 ) EIGHTH NOTE → MUSICAL SYMBOL NOTEHEAD BLACK, MUSICAL SYMBOL COMBINING STEM, MUSICAL SYMBOL COMBINING FLAG-1	# 

			{ L"\x02D9",L"\x0971" }, //( ˙ → ॱ ) DOT ABOVE → DEVANAGARI SIGN HIGH SPACING DOT	# 
			{ L"\x0D4E",L"\x0971" }, //( ൎ → ॱ ) MALAYALAM LETTER DOT REPH → DEVANAGARI SIGN HIGH SPACING DOT	# →˙→

			{ L"\xFF0D",L"\x30FC" }, //( － → ー ) FULLWIDTH HYPHEN-MINUS → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# 
			{ L"\x2014",L"\x30FC" }, //( — → ー ) EM DASH → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →一→
			{ L"\x2015",L"\x30FC" }, //( ― → ー ) HORIZONTAL BAR → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →—→→一→
			{ L"\x2500",L"\x30FC" }, //( ─ → ー ) BOX DRAWINGS LIGHT HORIZONTAL → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →━→→—→→一→
			{ L"\x2501",L"\x30FC" }, //( ━ → ー ) BOX DRAWINGS HEAVY HORIZONTAL → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →—→→一→
			{ L"\x31D0",L"\x30FC" }, //( ㇐ → ー ) CJK STROKE H → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →一→
			{ L"\xA7F7",L"\x30FC" }, //( ꟷ → ー ) LATIN EPIGRAPHIC LETTER SIDEWAYS I → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →—→→一→
			{ L"\x1173",L"\x30FC" }, //( ᅳ → ー ) HANGUL JUNGSEONG EU → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →ㅡ→→—→→一→
			{ L"\x3161",L"\x30FC" }, //( ㅡ → ー ) HANGUL LETTER EU → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →—→→一→
			{ L"\x4E00",L"\x30FC" }, //( 一 → ー ) CJK UNIFIED IDEOGRAPH-4E00 → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# 
			{ L"\x2F00",L"\x30FC" }, //( ⼀ → ー ) KANGXI RADICAL ONE → KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →一→

			{ L"\x1196",L"\x30FC\x30FC" }, //( ᆖ → ーー ) HANGUL JUNGSEONG EU-EU → KATAKANA-HIRAGANA PROLONGED SOUND MARK, KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →ᅳᅳ→

			{ L"\xD7B9",L"\x30FC\x1161" }, //( ힹ → ーᅡ ) HANGUL JUNGSEONG EU-A → KATAKANA-HIRAGANA PROLONGED SOUND MARK, HANGUL JUNGSEONG A	# →ᅳᅡ→

			{ L"\xD7BA",L"\x30FC\x1165" }, //( ힺ → ーᅥ ) HANGUL JUNGSEONG EU-EO → KATAKANA-HIRAGANA PROLONGED SOUND MARK, HANGUL JUNGSEONG EO	# →ᅳᅥ→

			{ L"\xD7BB",L"\x30FC\x1165\x4E28" }, //( ힻ → ーᅥ丨 ) HANGUL JUNGSEONG EU-E → KATAKANA-HIRAGANA PROLONGED SOUND MARK, HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅳᅥᅵ→

			{ L"\xD7BC",L"\x30FC\x1169" }, //( ힼ → ーᅩ ) HANGUL JUNGSEONG EU-O → KATAKANA-HIRAGANA PROLONGED SOUND MARK, HANGUL JUNGSEONG O	# →ᅳᅩ→

			{ L"\x1195",L"\x30FC\x116E" }, //( ᆕ → ーᅮ ) HANGUL JUNGSEONG EU-U → KATAKANA-HIRAGANA PROLONGED SOUND MARK, HANGUL JUNGSEONG U	# →ᅳᅮ→

			{ L"\x1174",L"\x30FC\x4E28" }, //( ᅴ → ー丨 ) HANGUL JUNGSEONG YI → KATAKANA-HIRAGANA PROLONGED SOUND MARK, CJK UNIFIED IDEOGRAPH-4E28	# →ᅳᅵ→
			{ L"\x3162",L"\x30FC\x4E28" }, //( ㅢ → ー丨 ) HANGUL LETTER YI → KATAKANA-HIRAGANA PROLONGED SOUND MARK, CJK UNIFIED IDEOGRAPH-4E28	# →ᅴ→→ᅳᅵ→

			{ L"\x1197",L"\x30FC\x4E28\x116E" }, //( ᆗ → ー丨ᅮ ) HANGUL JUNGSEONG YI-U → KATAKANA-HIRAGANA PROLONGED SOUND MARK, CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG U	# →ᅳᅵᅮ→

			{ L"\x20A4",L"\x00A3" }, //( ₤ → £ ) LIRA SIGN → POUND SIGN	# 

			{ L"\x3012",L"\x20B8" }, //( 〒 → ₸ ) POSTAL MARK → TENGE SIGN	# 
			{ L"\x3036",L"\x20B8" }, //( 〶 → ₸ ) CIRCLED POSTAL MARK → TENGE SIGN	# →〒→

			{ L"\x1B5C",L"\x1B50" }, //( ᭜ → ᭐ ) BALINESE WINDU → BALINESE DIGIT ZERO	# 

			{ L"\xA9C6",L"\xA9D0" }, //( ꧆ → ꧐ ) JAVANESE PADA WINDU → JAVANESE DIGIT ZERO	# 

			{ L"\x0001\x14D1",L"\x09E7" }, //( 𑓑 → ১ ) TIRHUTA DIGIT ONE → BENGALI DIGIT ONE	# 

			{ L"\x0CE7",L"\x0C67" }, //( ೧ → ౧ ) KANNADA DIGIT ONE → TELUGU DIGIT ONE	# 

			{ L"\x1065",L"\x1041" }, //( ၥ → ၁ ) MYANMAR LETTER WESTERN PWO KAREN THA → MYANMAR DIGIT ONE	# 

			{ L"\x2460",L"\x2780" }, //( ① → ➀ ) CIRCLED DIGIT ONE → DINGBAT CIRCLED SANS-SERIF DIGIT ONE	# 

			{ L"\x2469",L"\x2789" }, //( ⑩ → ➉ ) CIRCLED NUMBER TEN → DINGBAT CIRCLED SANS-SERIF NUMBER TEN	# 

			{ L"\x23E8",L"\x2081\x2080" }, //( ⏨ → ₁₀ ) DECIMAL EXPONENT SYMBOL → SUBSCRIPT ONE, SUBSCRIPT ZERO	# 

			{ L"\x0001\xD7D0",L"\x0032" }, //( 𝟐 → 2 ) MATHEMATICAL BOLD DIGIT TWO → DIGIT TWO	# 
			{ L"\x0001\xD7DA",L"\x0032" }, //( 𝟚 → 2 ) MATHEMATICAL DOUBLE-STRUCK DIGIT TWO → DIGIT TWO	# 
			{ L"\x0001\xD7E4",L"\x0032" }, //( 𝟤 → 2 ) MATHEMATICAL SANS-SERIF DIGIT TWO → DIGIT TWO	# 
			{ L"\x0001\xD7EE",L"\x0032" }, //( 𝟮 → 2 ) MATHEMATICAL SANS-SERIF BOLD DIGIT TWO → DIGIT TWO	# 
			{ L"\x0001\xD7F8",L"\x0032" }, //( 𝟸 → 2 ) MATHEMATICAL MONOSPACE DIGIT TWO → DIGIT TWO	# 
			{ L"\xA75A",L"\x0032" }, //( Ꝛ → 2 ) LATIN CAPITAL LETTER R ROTUNDA → DIGIT TWO	# 
			{ L"\x01A7",L"\x0032" }, //( Ƨ → 2 ) LATIN CAPITAL LETTER TONE TWO → DIGIT TWO	# 
			{ L"\x03E8",L"\x0032" }, //( Ϩ → 2 ) COPTIC CAPITAL LETTER HORI → DIGIT TWO	# →Ƨ→
			{ L"\xA644",L"\x0032" }, //( Ꙅ → 2 ) CYRILLIC CAPITAL LETTER REVERSED DZE → DIGIT TWO	# →Ƨ→
			{ L"\x14BF",L"\x0032" }, //( ᒿ → 2 ) CANADIAN SYLLABICS SAYISI M → DIGIT TWO	# 

			{ L"\xA9CF",L"\x0662" }, //( ꧏ → ‎٢‎ ) JAVANESE PANGRANGKEP → ARABIC-INDIC DIGIT TWO	# 
			{ L"\x06F2",L"\x0662" }, //( ۲ → ‎٢‎ ) EXTENDED ARABIC-INDIC DIGIT TWO → ARABIC-INDIC DIGIT TWO	# 

			{ L"\x0AE8",L"\x0968" }, //( ૨ → २ ) GUJARATI DIGIT TWO → DEVANAGARI DIGIT TWO	# 

			{ L"\x0001\x14D2",L"\x09E8" }, //( 𑓒 → ২ ) TIRHUTA DIGIT TWO → BENGALI DIGIT TWO	# 

			{ L"\x0CE8",L"\x0C68" }, //( ೨ → ౨ ) KANNADA DIGIT TWO → TELUGU DIGIT TWO	# 

			{ L"\x2461",L"\x2781" }, //( ② → ➁ ) CIRCLED DIGIT TWO → DINGBAT CIRCLED SANS-SERIF DIGIT TWO	# 

			{ L"\x01BB",L"\x0032\x0335" }, //( ƻ → 2̵ ) LATIN LETTER TWO WITH STROKE → DIGIT TWO, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x0001\xF103",L"\x0032\x002C" }, //( 🄃 → 2, ) DIGIT TWO COMMA → DIGIT TWO, COMMA	# 

			{ L"\x2489",L"\x0032\x002E" }, //( ⒉ → 2. ) DIGIT TWO FULL STOP → DIGIT TWO, FULL STOP	# 

			{ L"\x33F5",L"\x0032\x0032\x65E5" }, //( ㏵ → 22日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-TWO → DIGIT TWO, DIGIT TWO, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x336E",L"\x0032\x0032\x70B9" }, //( ㍮ → 22点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWENTY-TWO → DIGIT TWO, DIGIT TWO, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x33F6",L"\x0032\x0033\x65E5" }, //( ㏶ → 23日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-THREE → DIGIT TWO, DIGIT THREE, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x336F",L"\x0032\x0033\x70B9" }, //( ㍯ → 23点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWENTY-THREE → DIGIT TWO, DIGIT THREE, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x33F7",L"\x0032\x0034\x65E5" }, //( ㏷ → 24日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-FOUR → DIGIT TWO, DIGIT FOUR, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x3370",L"\x0032\x0034\x70B9" }, //( ㍰ → 24点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWENTY-FOUR → DIGIT TWO, DIGIT FOUR, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x33F8",L"\x0032\x0035\x65E5" }, //( ㏸ → 25日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-FIVE → DIGIT TWO, DIGIT FIVE, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x33F9",L"\x0032\x0036\x65E5" }, //( ㏹ → 26日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-SIX → DIGIT TWO, DIGIT SIX, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x33FA",L"\x0032\x0037\x65E5" }, //( ㏺ → 27日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-SEVEN → DIGIT TWO, DIGIT SEVEN, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x33FB",L"\x0032\x0038\x65E5" }, //( ㏻ → 28日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-EIGHT → DIGIT TWO, DIGIT EIGHT, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x33FC",L"\x0032\x0039\x65E5" }, //( ㏼ → 29日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-NINE → DIGIT TWO, DIGIT NINE, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x33F4",L"\x0032\x006C\x65E5" }, //( ㏴ → 2l日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY-ONE → DIGIT TWO, LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-65E5	# →21日→

			{ L"\x336D",L"\x0032\x006C\x70B9" }, //( ㍭ → 2l点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWENTY-ONE → DIGIT TWO, LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-70B9	# →21点→

			{ L"\x249B",L"\x0032\x004F\x002E" }, //( ⒛ → 2O. ) NUMBER TWENTY FULL STOP → DIGIT TWO, LATIN CAPITAL LETTER O, FULL STOP	# →20.→

			{ L"\x33F3",L"\x0032\x004F\x65E5" }, //( ㏳ → 2O日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWENTY → DIGIT TWO, LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-65E5	# →20日→

			{ L"\x336C",L"\x0032\x004F\x70B9" }, //( ㍬ → 2O点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWENTY → DIGIT TWO, LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-70B9	# →20点→

			{ L"\x0DE9",L"\x0DE8\x0DCF" }, //( ෩ → ෨ා ) SINHALA LITH DIGIT THREE → SINHALA LITH DIGIT TWO, SINHALA VOWEL SIGN AELA-PILLA	# 

			{ L"\x0DEF",L"\x0DE8\x0DD3" }, //( ෯ → ෨ී ) SINHALA LITH DIGIT NINE → SINHALA LITH DIGIT TWO, SINHALA VOWEL SIGN DIGA IS-PILLA	# 

			{ L"\x33E1",L"\x0032\x65E5" }, //( ㏡ → 2日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWO → DIGIT TWO, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C1",L"\x0032\x6708" }, //( ㋁ → 2月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR FEBRUARY → DIGIT TWO, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x335A",L"\x0032\x70B9" }, //( ㍚ → 2点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWO → DIGIT TWO, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0001\xD7D1",L"\x0033" }, //( 𝟑 → 3 ) MATHEMATICAL BOLD DIGIT THREE → DIGIT THREE	# 
			{ L"\x0001\xD7DB",L"\x0033" }, //( 𝟛 → 3 ) MATHEMATICAL DOUBLE-STRUCK DIGIT THREE → DIGIT THREE	# 
			{ L"\x0001\xD7E5",L"\x0033" }, //( 𝟥 → 3 ) MATHEMATICAL SANS-SERIF DIGIT THREE → DIGIT THREE	# 
			{ L"\x0001\xD7EF",L"\x0033" }, //( 𝟯 → 3 ) MATHEMATICAL SANS-SERIF BOLD DIGIT THREE → DIGIT THREE	# 
			{ L"\x0001\xD7F9",L"\x0033" }, //( 𝟹 → 3 ) MATHEMATICAL MONOSPACE DIGIT THREE → DIGIT THREE	# 
			{ L"\xA7AB",L"\x0033" }, //( Ɜ → 3 ) LATIN CAPITAL LETTER REVERSED OPEN E → DIGIT THREE	# 
			{ L"\x021C",L"\x0033" }, //( Ȝ → 3 ) LATIN CAPITAL LETTER YOGH → DIGIT THREE	# →Ʒ→
			{ L"\x01B7",L"\x0033" }, //( Ʒ → 3 ) LATIN CAPITAL LETTER EZH → DIGIT THREE	# 
			{ L"\xA76A",L"\x0033" }, //( Ꝫ → 3 ) LATIN CAPITAL LETTER ET → DIGIT THREE	# 
			{ L"\x2CCC",L"\x0033" }, //( Ⳍ → 3 ) COPTIC CAPITAL LETTER OLD COPTIC HORI → DIGIT THREE	# →Ȝ→→Ʒ→
			{ L"\x0417",L"\x0033" }, //( З → 3 ) CYRILLIC CAPITAL LETTER ZE → DIGIT THREE	# 
			{ L"\x04E0",L"\x0033" }, //( Ӡ → 3 ) CYRILLIC CAPITAL LETTER ABKHASIAN DZE → DIGIT THREE	# →Ʒ→
			{ L"\x0001\x18CA",L"\x0033" }, //( 𑣊 → 3 ) WARANG CITI SMALL LETTER ANG → DIGIT THREE	# 

			{ L"\x06F3",L"\x0663" }, //( ۳ → ‎٣‎ ) EXTENDED ARABIC-INDIC DIGIT THREE → ARABIC-INDIC DIGIT THREE	# 
			{ L"\x0001\xE8C9",L"\x0663" }, //( ‎𞣉‎ → ‎٣‎ ) MENDE KIKAKUI DIGIT THREE → ARABIC-INDIC DIGIT THREE	# 

			{ L"\x0AE9",L"\x0969" }, //( ૩ → ३ ) GUJARATI DIGIT THREE → DEVANAGARI DIGIT THREE	# 

			{ L"\x2462",L"\x2782" }, //( ③ → ➂ ) CIRCLED DIGIT THREE → DINGBAT CIRCLED SANS-SERIF DIGIT THREE	# 

			{ L"\x0498",L"\x0033\x0326" }, //( Ҙ → 3̦ ) CYRILLIC CAPITAL LETTER ZE WITH DESCENDER → DIGIT THREE, COMBINING COMMA BELOW	# →З̧→

			{ L"\x0001\xF104",L"\x0033\x002C" }, //( 🄄 → 3, ) DIGIT THREE COMMA → DIGIT THREE, COMMA	# 

			{ L"\x248A",L"\x0033\x002E" }, //( ⒊ → 3. ) DIGIT THREE FULL STOP → DIGIT THREE, FULL STOP	# 

			{ L"\x33FE",L"\x0033\x006C\x65E5" }, //( ㏾ → 3l日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY THIRTY-ONE → DIGIT THREE, LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-65E5	# →31日→

			{ L"\x33FD",L"\x0033\x004F\x65E5" }, //( ㏽ → 3O日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY THIRTY → DIGIT THREE, LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-65E5	# →30日→

			{ L"\x33E2",L"\x0033\x65E5" }, //( ㏢ → 3日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY THREE → DIGIT THREE, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C2",L"\x0033\x6708" }, //( ㋂ → 3月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR MARCH → DIGIT THREE, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x335B",L"\x0033\x70B9" }, //( ㍛ → 3点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR THREE → DIGIT THREE, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0001\xD7D2",L"\x0034" }, //( 𝟒 → 4 ) MATHEMATICAL BOLD DIGIT FOUR → DIGIT FOUR	# 
			{ L"\x0001\xD7DC",L"\x0034" }, //( 𝟜 → 4 ) MATHEMATICAL DOUBLE-STRUCK DIGIT FOUR → DIGIT FOUR	# 
			{ L"\x0001\xD7E6",L"\x0034" }, //( 𝟦 → 4 ) MATHEMATICAL SANS-SERIF DIGIT FOUR → DIGIT FOUR	# 
			{ L"\x0001\xD7F0",L"\x0034" }, //( 𝟰 → 4 ) MATHEMATICAL SANS-SERIF BOLD DIGIT FOUR → DIGIT FOUR	# 
			{ L"\x0001\xD7FA",L"\x0034" }, //( 𝟺 → 4 ) MATHEMATICAL MONOSPACE DIGIT FOUR → DIGIT FOUR	# 
			{ L"\x13CE",L"\x0034" }, //( Ꮞ → 4 ) CHEROKEE LETTER SE → DIGIT FOUR	# 
			{ L"\x0001\x18AF",L"\x0034" }, //( 𑢯 → 4 ) WARANG CITI CAPITAL LETTER UC → DIGIT FOUR	# 

			{ L"\x06F4",L"\x0664" }, //( ۴ → ‎٤‎ ) EXTENDED ARABIC-INDIC DIGIT FOUR → ARABIC-INDIC DIGIT FOUR	# 

			{ L"\x0AEA",L"\x096A" }, //( ૪ → ४ ) GUJARATI DIGIT FOUR → DEVANAGARI DIGIT FOUR	# 

			{ L"\x2463",L"\x2783" }, //( ④ → ➃ ) CIRCLED DIGIT FOUR → DINGBAT CIRCLED SANS-SERIF DIGIT FOUR	# 

			{ L"\x0001\xF105",L"\x0034\x002C" }, //( 🄅 → 4, ) DIGIT FOUR COMMA → DIGIT FOUR, COMMA	# 

			{ L"\x248B",L"\x0034\x002E" }, //( ⒋ → 4. ) DIGIT FOUR FULL STOP → DIGIT FOUR, FULL STOP	# 

			{ L"\x1530",L"\x0034\x00B7" }, //( ᔰ → 4· ) CANADIAN SYLLABICS WEST-CREE YWE → DIGIT FOUR, MIDDLE DOT	# →4ᐧ→

			{ L"\x33E3",L"\x0034\x65E5" }, //( ㏣ → 4日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY FOUR → DIGIT FOUR, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C3",L"\x0034\x6708" }, //( ㋃ → 4月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR APRIL → DIGIT FOUR, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x335C",L"\x0034\x70B9" }, //( ㍜ → 4点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR FOUR → DIGIT FOUR, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0001\xD7D3",L"\x0035" }, //( 𝟓 → 5 ) MATHEMATICAL BOLD DIGIT FIVE → DIGIT FIVE	# 
			{ L"\x0001\xD7DD",L"\x0035" }, //( 𝟝 → 5 ) MATHEMATICAL DOUBLE-STRUCK DIGIT FIVE → DIGIT FIVE	# 
			{ L"\x0001\xD7E7",L"\x0035" }, //( 𝟧 → 5 ) MATHEMATICAL SANS-SERIF DIGIT FIVE → DIGIT FIVE	# 
			{ L"\x0001\xD7F1",L"\x0035" }, //( 𝟱 → 5 ) MATHEMATICAL SANS-SERIF BOLD DIGIT FIVE → DIGIT FIVE	# 
			{ L"\x0001\xD7FB",L"\x0035" }, //( 𝟻 → 5 ) MATHEMATICAL MONOSPACE DIGIT FIVE → DIGIT FIVE	# 
			{ L"\x01BC",L"\x0035" }, //( Ƽ → 5 ) LATIN CAPITAL LETTER TONE FIVE → DIGIT FIVE	# 
			{ L"\x0001\x18BB",L"\x0035" }, //( 𑢻 → 5 ) WARANG CITI CAPITAL LETTER HORR → DIGIT FIVE	# 

			{ L"\x2464",L"\x2784" }, //( ⑤ → ➄ ) CIRCLED DIGIT FIVE → DINGBAT CIRCLED SANS-SERIF DIGIT FIVE	# 

			{ L"\x0001\xF106",L"\x0035\x002C" }, //( 🄆 → 5, ) DIGIT FIVE COMMA → DIGIT FIVE, COMMA	# 

			{ L"\x248C",L"\x0035\x002E" }, //( ⒌ → 5. ) DIGIT FIVE FULL STOP → DIGIT FIVE, FULL STOP	# 

			{ L"\x33E4",L"\x0035\x65E5" }, //( ㏤ → 5日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY FIVE → DIGIT FIVE, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C4",L"\x0035\x6708" }, //( ㋄ → 5月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR MAY → DIGIT FIVE, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x335D",L"\x0035\x70B9" }, //( ㍝ → 5点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR FIVE → DIGIT FIVE, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0001\xD7D4",L"\x0036" }, //( 𝟔 → 6 ) MATHEMATICAL BOLD DIGIT SIX → DIGIT SIX	# 
			{ L"\x0001\xD7DE",L"\x0036" }, //( 𝟞 → 6 ) MATHEMATICAL DOUBLE-STRUCK DIGIT SIX → DIGIT SIX	# 
			{ L"\x0001\xD7E8",L"\x0036" }, //( 𝟨 → 6 ) MATHEMATICAL SANS-SERIF DIGIT SIX → DIGIT SIX	# 
			{ L"\x0001\xD7F2",L"\x0036" }, //( 𝟲 → 6 ) MATHEMATICAL SANS-SERIF BOLD DIGIT SIX → DIGIT SIX	# 
			{ L"\x0001\xD7FC",L"\x0036" }, //( 𝟼 → 6 ) MATHEMATICAL MONOSPACE DIGIT SIX → DIGIT SIX	# 
			{ L"\x2CD2",L"\x0036" }, //( Ⳓ → 6 ) COPTIC CAPITAL LETTER OLD COPTIC HEI → DIGIT SIX	# 
			{ L"\x0431",L"\x0036" }, //( б → 6 ) CYRILLIC SMALL LETTER BE → DIGIT SIX	# 
			{ L"\x13EE",L"\x0036" }, //( Ꮾ → 6 ) CHEROKEE LETTER WV → DIGIT SIX	# 
			{ L"\x0001\x18D5",L"\x0036" }, //( 𑣕 → 6 ) WARANG CITI SMALL LETTER AT → DIGIT SIX	# 

			{ L"\x06F6",L"\x0666" }, //( ۶ → ‎٦‎ ) EXTENDED ARABIC-INDIC DIGIT SIX → ARABIC-INDIC DIGIT SIX	# 

			{ L"\x0001\x14D6",L"\x09EC" }, //( 𑓖 → ৬ ) TIRHUTA DIGIT SIX → BENGALI DIGIT SIX	# 

			{ L"\x2465",L"\x2785" }, //( ⑥ → ➅ ) CIRCLED DIGIT SIX → DINGBAT CIRCLED SANS-SERIF DIGIT SIX	# 

			{ L"\x0001\xF107",L"\x0036\x002C" }, //( 🄇 → 6, ) DIGIT SIX COMMA → DIGIT SIX, COMMA	# 

			{ L"\x248D",L"\x0036\x002E" }, //( ⒍ → 6. ) DIGIT SIX FULL STOP → DIGIT SIX, FULL STOP	# 

			{ L"\x33E5",L"\x0036\x65E5" }, //( ㏥ → 6日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY SIX → DIGIT SIX, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C5",L"\x0036\x6708" }, //( ㋅ → 6月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR JUNE → DIGIT SIX, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x335E",L"\x0036\x70B9" }, //( ㍞ → 6点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR SIX → DIGIT SIX, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0001\xD7D5",L"\x0037" }, //( 𝟕 → 7 ) MATHEMATICAL BOLD DIGIT SEVEN → DIGIT SEVEN	# 
			{ L"\x0001\xD7DF",L"\x0037" }, //( 𝟟 → 7 ) MATHEMATICAL DOUBLE-STRUCK DIGIT SEVEN → DIGIT SEVEN	# 
			{ L"\x0001\xD7E9",L"\x0037" }, //( 𝟩 → 7 ) MATHEMATICAL SANS-SERIF DIGIT SEVEN → DIGIT SEVEN	# 
			{ L"\x0001\xD7F3",L"\x0037" }, //( 𝟳 → 7 ) MATHEMATICAL SANS-SERIF BOLD DIGIT SEVEN → DIGIT SEVEN	# 
			{ L"\x0001\xD7FD",L"\x0037" }, //( 𝟽 → 7 ) MATHEMATICAL MONOSPACE DIGIT SEVEN → DIGIT SEVEN	# 
			{ L"\x0001\x18C6",L"\x0037" }, //( 𑣆 → 7 ) WARANG CITI SMALL LETTER II → DIGIT SEVEN	# 

			{ L"\x2466",L"\x2786" }, //( ⑦ → ➆ ) CIRCLED DIGIT SEVEN → DINGBAT CIRCLED SANS-SERIF DIGIT SEVEN	# 

			{ L"\x0001\xF108",L"\x0037\x002C" }, //( 🄈 → 7, ) DIGIT SEVEN COMMA → DIGIT SEVEN, COMMA	# 

			{ L"\x248E",L"\x0037\x002E" }, //( ⒎ → 7. ) DIGIT SEVEN FULL STOP → DIGIT SEVEN, FULL STOP	# 

			{ L"\x33E6",L"\x0037\x65E5" }, //( ㏦ → 7日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY SEVEN → DIGIT SEVEN, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C6",L"\x0037\x6708" }, //( ㋆ → 7月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR JULY → DIGIT SEVEN, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x335F",L"\x0037\x70B9" }, //( ㍟ → 7点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR SEVEN → DIGIT SEVEN, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0B03",L"\x0038" }, //( ଃ → 8 ) ORIYA SIGN VISARGA → DIGIT EIGHT	# 
			{ L"\x09EA",L"\x0038" }, //( ৪ → 8 ) BENGALI DIGIT FOUR → DIGIT EIGHT	# 
			{ L"\x0A6A",L"\x0038" }, //( ੪ → 8 ) GURMUKHI DIGIT FOUR → DIGIT EIGHT	# 
			{ L"\x0001\xE8CB",L"\x0038" }, //( ‎𞣋‎ → 8 ) MENDE KIKAKUI DIGIT FIVE → DIGIT EIGHT	# 
			{ L"\x0001\xD7D6",L"\x0038" }, //( 𝟖 → 8 ) MATHEMATICAL BOLD DIGIT EIGHT → DIGIT EIGHT	# 
			{ L"\x0001\xD7E0",L"\x0038" }, //( 𝟠 → 8 ) MATHEMATICAL DOUBLE-STRUCK DIGIT EIGHT → DIGIT EIGHT	# 
			{ L"\x0001\xD7EA",L"\x0038" }, //( 𝟪 → 8 ) MATHEMATICAL SANS-SERIF DIGIT EIGHT → DIGIT EIGHT	# 
			{ L"\x0001\xD7F4",L"\x0038" }, //( 𝟴 → 8 ) MATHEMATICAL SANS-SERIF BOLD DIGIT EIGHT → DIGIT EIGHT	# 
			{ L"\x0001\xD7FE",L"\x0038" }, //( 𝟾 → 8 ) MATHEMATICAL MONOSPACE DIGIT EIGHT → DIGIT EIGHT	# 
			{ L"\x0223",L"\x0038" }, //( ȣ → 8 ) LATIN SMALL LETTER OU → DIGIT EIGHT	# 
			{ L"\x0222",L"\x0038" }, //( Ȣ → 8 ) LATIN CAPITAL LETTER OU → DIGIT EIGHT	# 
			{ L"\x0001\x031A",L"\x0038" }, //( 𐌚 → 8 ) OLD ITALIC LETTER EF → DIGIT EIGHT	# 

			{ L"\x0AEE",L"\x096E" }, //( ૮ → ८ ) GUJARATI DIGIT EIGHT → DEVANAGARI DIGIT EIGHT	# 

			{ L"\x2467",L"\x2787" }, //( ⑧ → ➇ ) CIRCLED DIGIT EIGHT → DINGBAT CIRCLED SANS-SERIF DIGIT EIGHT	# 

			{ L"\x0001\xF109",L"\x0038\x002C" }, //( 🄉 → 8, ) DIGIT EIGHT COMMA → DIGIT EIGHT, COMMA	# 

			{ L"\x248F",L"\x0038\x002E" }, //( ⒏ → 8. ) DIGIT EIGHT FULL STOP → DIGIT EIGHT, FULL STOP	# 

			{ L"\x33E7",L"\x0038\x65E5" }, //( ㏧ → 8日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY EIGHT → DIGIT EIGHT, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C7",L"\x0038\x6708" }, //( ㋇ → 8月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR AUGUST → DIGIT EIGHT, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x3360",L"\x0038\x70B9" }, //( ㍠ → 8点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR EIGHT → DIGIT EIGHT, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x0A67",L"\x0039" }, //( ੧ → 9 ) GURMUKHI DIGIT ONE → DIGIT NINE	# 
			{ L"\x0B68",L"\x0039" }, //( ୨ → 9 ) ORIYA DIGIT TWO → DIGIT NINE	# 
			{ L"\x09ED",L"\x0039" }, //( ৭ → 9 ) BENGALI DIGIT SEVEN → DIGIT NINE	# 
			{ L"\x0001\xD7D7",L"\x0039" }, //( 𝟗 → 9 ) MATHEMATICAL BOLD DIGIT NINE → DIGIT NINE	# 
			{ L"\x0001\xD7E1",L"\x0039" }, //( 𝟡 → 9 ) MATHEMATICAL DOUBLE-STRUCK DIGIT NINE → DIGIT NINE	# 
			{ L"\x0001\xD7EB",L"\x0039" }, //( 𝟫 → 9 ) MATHEMATICAL SANS-SERIF DIGIT NINE → DIGIT NINE	# 
			{ L"\x0001\xD7F5",L"\x0039" }, //( 𝟵 → 9 ) MATHEMATICAL SANS-SERIF BOLD DIGIT NINE → DIGIT NINE	# 
			{ L"\x0001\xD7FF",L"\x0039" }, //( 𝟿 → 9 ) MATHEMATICAL MONOSPACE DIGIT NINE → DIGIT NINE	# 
			{ L"\xA76E",L"\x0039" }, //( Ꝯ → 9 ) LATIN CAPITAL LETTER CON → DIGIT NINE	# 
			{ L"\x2CCA",L"\x0039" }, //( Ⳋ → 9 ) COPTIC CAPITAL LETTER DIALECT-P HORI → DIGIT NINE	# 
			{ L"\x0001\x18CC",L"\x0039" }, //( 𑣌 → 9 ) WARANG CITI SMALL LETTER KO → DIGIT NINE	# 
			{ L"\x0001\x18AC",L"\x0039" }, //( 𑢬 → 9 ) WARANG CITI CAPITAL LETTER KO → DIGIT NINE	# 
			{ L"\x0001\x18D6",L"\x0039" }, //( 𑣖 → 9 ) WARANG CITI SMALL LETTER AM → DIGIT NINE	# 

			{ L"\x0967",L"\x0669" }, //( १ → ‎٩‎ ) DEVANAGARI DIGIT ONE → ARABIC-INDIC DIGIT NINE	# 
			{ L"\x0001\x18E4",L"\x0669" }, //( 𑣤 → ‎٩‎ ) WARANG CITI DIGIT FOUR → ARABIC-INDIC DIGIT NINE	# 
			{ L"\x06F9",L"\x0669" }, //( ۹ → ‎٩‎ ) EXTENDED ARABIC-INDIC DIGIT NINE → ARABIC-INDIC DIGIT NINE	# 

			{ L"\x0CEF",L"\x0C6F" }, //( ೯ → ౯ ) KANNADA DIGIT NINE → TELUGU DIGIT NINE	# 

			{ L"\x2468",L"\x2788" }, //( ⑨ → ➈ ) CIRCLED DIGIT NINE → DINGBAT CIRCLED SANS-SERIF DIGIT NINE	# 

			{ L"\x0001\xF10A",L"\x0039\x002C" }, //( 🄊 → 9, ) DIGIT NINE COMMA → DIGIT NINE, COMMA	# 

			{ L"\x2490",L"\x0039\x002E" }, //( ⒐ → 9. ) DIGIT NINE FULL STOP → DIGIT NINE, FULL STOP	# 

			{ L"\x33E8",L"\x0039\x65E5" }, //( ㏨ → 9日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY NINE → DIGIT NINE, CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\x32C8",L"\x0039\x6708" }, //( ㋈ → 9月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR SEPTEMBER → DIGIT NINE, CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x3361",L"\x0039\x70B9" }, //( ㍡ → 9点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR NINE → DIGIT NINE, CJK UNIFIED IDEOGRAPH-70B9	# 

			{ L"\x237A",L"\x0061" }, //( ⍺ → a ) APL FUNCTIONAL SYMBOL ALPHA → LATIN SMALL LETTER A	# →α→
			{ L"\xFF41",L"\x0061" }, //( ａ → a ) FULLWIDTH LATIN SMALL LETTER A → LATIN SMALL LETTER A	# →а→
			{ L"\x0001\xD41A",L"\x0061" }, //( 𝐚 → a ) MATHEMATICAL BOLD SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD44E",L"\x0061" }, //( 𝑎 → a ) MATHEMATICAL ITALIC SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD482",L"\x0061" }, //( 𝒂 → a ) MATHEMATICAL BOLD ITALIC SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD4B6",L"\x0061" }, //( 𝒶 → a ) MATHEMATICAL SCRIPT SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD4EA",L"\x0061" }, //( 𝓪 → a ) MATHEMATICAL BOLD SCRIPT SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD51E",L"\x0061" }, //( 𝔞 → a ) MATHEMATICAL FRAKTUR SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD552",L"\x0061" }, //( 𝕒 → a ) MATHEMATICAL DOUBLE-STRUCK SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD586",L"\x0061" }, //( 𝖆 → a ) MATHEMATICAL BOLD FRAKTUR SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD5BA",L"\x0061" }, //( 𝖺 → a ) MATHEMATICAL SANS-SERIF SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD5EE",L"\x0061" }, //( 𝗮 → a ) MATHEMATICAL SANS-SERIF BOLD SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD622",L"\x0061" }, //( 𝘢 → a ) MATHEMATICAL SANS-SERIF ITALIC SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD656",L"\x0061" }, //( 𝙖 → a ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD68A",L"\x0061" }, //( 𝚊 → a ) MATHEMATICAL MONOSPACE SMALL A → LATIN SMALL LETTER A	# 
			{ L"\x0251",L"\x0061" }, //( ɑ → a ) LATIN SMALL LETTER ALPHA → LATIN SMALL LETTER A	# 
			{ L"\x03B1",L"\x0061" }, //( α → a ) GREEK SMALL LETTER ALPHA → LATIN SMALL LETTER A	# 
			{ L"\x0001\xD6C2",L"\x0061" }, //( 𝛂 → a ) MATHEMATICAL BOLD SMALL ALPHA → LATIN SMALL LETTER A	# →α→
			{ L"\x0001\xD6FC",L"\x0061" }, //( 𝛼 → a ) MATHEMATICAL ITALIC SMALL ALPHA → LATIN SMALL LETTER A	# →α→
			{ L"\x0001\xD736",L"\x0061" }, //( 𝜶 → a ) MATHEMATICAL BOLD ITALIC SMALL ALPHA → LATIN SMALL LETTER A	# →α→
			{ L"\x0001\xD770",L"\x0061" }, //( 𝝰 → a ) MATHEMATICAL SANS-SERIF BOLD SMALL ALPHA → LATIN SMALL LETTER A	# →α→
			{ L"\x0001\xD7AA",L"\x0061" }, //( 𝞪 → a ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL ALPHA → LATIN SMALL LETTER A	# →α→
			{ L"\x0430",L"\x0061" }, //( а → a ) CYRILLIC SMALL LETTER A → LATIN SMALL LETTER A	# 

			{ L"\xFF21",L"\x0041" }, //( Ａ → A ) FULLWIDTH LATIN CAPITAL LETTER A → LATIN CAPITAL LETTER A	# →А→
			{ L"\x0001\xD400",L"\x0041" }, //( 𝐀 → A ) MATHEMATICAL BOLD CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD434",L"\x0041" }, //( 𝐴 → A ) MATHEMATICAL ITALIC CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD468",L"\x0041" }, //( 𝑨 → A ) MATHEMATICAL BOLD ITALIC CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD49C",L"\x0041" }, //( 𝒜 → A ) MATHEMATICAL SCRIPT CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD4D0",L"\x0041" }, //( 𝓐 → A ) MATHEMATICAL BOLD SCRIPT CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD504",L"\x0041" }, //( 𝔄 → A ) MATHEMATICAL FRAKTUR CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD538",L"\x0041" }, //( 𝔸 → A ) MATHEMATICAL DOUBLE-STRUCK CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD56C",L"\x0041" }, //( 𝕬 → A ) MATHEMATICAL BOLD FRAKTUR CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD5A0",L"\x0041" }, //( 𝖠 → A ) MATHEMATICAL SANS-SERIF CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD5D4",L"\x0041" }, //( 𝗔 → A ) MATHEMATICAL SANS-SERIF BOLD CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD608",L"\x0041" }, //( 𝘈 → A ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD63C",L"\x0041" }, //( 𝘼 → A ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD670",L"\x0041" }, //( 𝙰 → A ) MATHEMATICAL MONOSPACE CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x1D00",L"\x0041" }, //( ᴀ → A ) LATIN LETTER SMALL CAPITAL A → LATIN CAPITAL LETTER A	# 
			{ L"\x0391",L"\x0041" }, //( Α → A ) GREEK CAPITAL LETTER ALPHA → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\xD6A8",L"\x0041" }, //( 𝚨 → A ) MATHEMATICAL BOLD CAPITAL ALPHA → LATIN CAPITAL LETTER A	# →𝐀→
			{ L"\x0001\xD6E2",L"\x0041" }, //( 𝛢 → A ) MATHEMATICAL ITALIC CAPITAL ALPHA → LATIN CAPITAL LETTER A	# →Α→
			{ L"\x0001\xD71C",L"\x0041" }, //( 𝜜 → A ) MATHEMATICAL BOLD ITALIC CAPITAL ALPHA → LATIN CAPITAL LETTER A	# →Α→
			{ L"\x0001\xD756",L"\x0041" }, //( 𝝖 → A ) MATHEMATICAL SANS-SERIF BOLD CAPITAL ALPHA → LATIN CAPITAL LETTER A	# →Α→
			{ L"\x0001\xD790",L"\x0041" }, //( 𝞐 → A ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL ALPHA → LATIN CAPITAL LETTER A	# →Α→
			{ L"\x0410",L"\x0041" }, //( А → A ) CYRILLIC CAPITAL LETTER A → LATIN CAPITAL LETTER A	# 
			{ L"\x13AA",L"\x0041" }, //( Ꭺ → A ) CHEROKEE LETTER GO → LATIN CAPITAL LETTER A	# 
			{ L"\x15C5",L"\x0041" }, //( ᗅ → A ) CANADIAN SYLLABICS CARRIER GHO → LATIN CAPITAL LETTER A	# 
			{ L"\xA4EE",L"\x0041" }, //( ꓮ → A ) LISU LETTER A → LATIN CAPITAL LETTER A	# 
			{ L"\x0001\x02A0",L"\x0041" }, //( 𐊠 → A ) CARIAN LETTER A → LATIN CAPITAL LETTER A	# 

			{ L"\x2376",L"\x0061\x0332" }, //( ⍶ → a̲ ) APL FUNCTIONAL SYMBOL ALPHA UNDERBAR → LATIN SMALL LETTER A, COMBINING LOW LINE	# →α̲→→ɑ̲→

			{ L"\x01CE",L"\x0103" }, //( ǎ → ă ) LATIN SMALL LETTER A WITH CARON → LATIN SMALL LETTER A WITH BREVE	# 

			{ L"\x01CD",L"\x0102" }, //( Ǎ → Ă ) LATIN CAPITAL LETTER A WITH CARON → LATIN CAPITAL LETTER A WITH BREVE	# 

			{ L"\x0227",L"\x00E5" }, //( ȧ → å ) LATIN SMALL LETTER A WITH DOT ABOVE → LATIN SMALL LETTER A WITH RING ABOVE	# 

			{ L"\x0226",L"\x00C5" }, //( Ȧ → Å ) LATIN CAPITAL LETTER A WITH DOT ABOVE → LATIN CAPITAL LETTER A WITH RING ABOVE	# 

			{ L"\x1E9A",L"\x1EA3" }, //( ẚ → ả ) LATIN SMALL LETTER A WITH RIGHT HALF RING → LATIN SMALL LETTER A WITH HOOK ABOVE	# 

			{ L"\x2100",L"\x0061\x002F\x0063" }, //( ℀ → a/c ) ACCOUNT OF → LATIN SMALL LETTER A, SOLIDUS, LATIN SMALL LETTER C	# 

			{ L"\x2101",L"\x0061\x002F\x0073" }, //( ℁ → a/s ) ADDRESSED TO THE SUBJECT → LATIN SMALL LETTER A, SOLIDUS, LATIN SMALL LETTER S	# 

			{ L"\xA733",L"\x0061\x0061" }, //( ꜳ → aa ) LATIN SMALL LETTER AA → LATIN SMALL LETTER A, LATIN SMALL LETTER A	# 

			{ L"\xA732",L"\x0041\x0041" }, //( Ꜳ → AA ) LATIN CAPITAL LETTER AA → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER A	# 

			{ L"\x00E6",L"\x0061\x0065" }, //( æ → ae ) LATIN SMALL LETTER AE → LATIN SMALL LETTER A, LATIN SMALL LETTER E	# 
			{ L"\x04D5",L"\x0061\x0065" }, //( ӕ → ae ) CYRILLIC SMALL LIGATURE A IE → LATIN SMALL LETTER A, LATIN SMALL LETTER E	# →ае→

			{ L"\x00C6",L"\x0041\x0045" }, //( Æ → AE ) LATIN CAPITAL LETTER AE → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER E	# 
			{ L"\x04D4",L"\x0041\x0045" }, //( Ӕ → AE ) CYRILLIC CAPITAL LIGATURE A IE → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER E	# →Æ→

			{ L"\xA735",L"\x0061\x006F" }, //( ꜵ → ao ) LATIN SMALL LETTER AO → LATIN SMALL LETTER A, LATIN SMALL LETTER O	# 

			{ L"\xA734",L"\x0041\x004F" }, //( Ꜵ → AO ) LATIN CAPITAL LETTER AO → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER O	# 

			{ L"\x0001\xF707",L"\x0041\x0052" }, //( 🜇 → AR ) ALCHEMICAL SYMBOL FOR AQUA REGIA-2 → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER R	# 

			{ L"\xA737",L"\x0061\x0075" }, //( ꜷ → au ) LATIN SMALL LETTER AU → LATIN SMALL LETTER A, LATIN SMALL LETTER U	# 

			{ L"\xA736",L"\x0041\x0055" }, //( Ꜷ → AU ) LATIN CAPITAL LETTER AU → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER U	# 

			{ L"\xA739",L"\x0061\x0076" }, //( ꜹ → av ) LATIN SMALL LETTER AV → LATIN SMALL LETTER A, LATIN SMALL LETTER V	# 
			{ L"\xA73B",L"\x0061\x0076" }, //( ꜻ → av ) LATIN SMALL LETTER AV WITH HORIZONTAL BAR → LATIN SMALL LETTER A, LATIN SMALL LETTER V	# 

			{ L"\xA738",L"\x0041\x0056" }, //( Ꜹ → AV ) LATIN CAPITAL LETTER AV → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER V	# 
			{ L"\xA73A",L"\x0041\x0056" }, //( Ꜻ → AV ) LATIN CAPITAL LETTER AV WITH HORIZONTAL BAR → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER V	# 

			{ L"\xA73D",L"\x0061\x0079" }, //( ꜽ → ay ) LATIN SMALL LETTER AY → LATIN SMALL LETTER A, LATIN SMALL LETTER Y	# 

			{ L"\xA73C",L"\x0041\x0059" }, //( Ꜽ → AY ) LATIN CAPITAL LETTER AY → LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER Y	# 

			{ L"\x2200",L"\x2C6F" }, //( ∀ → Ɐ ) FOR ALL → LATIN CAPITAL LETTER TURNED A	# 
			{ L"\x15C4",L"\x2C6F" }, //( ᗄ → Ɐ ) CANADIAN SYLLABICS CARRIER GHU → LATIN CAPITAL LETTER TURNED A	# →∀→
			{ L"\xA4EF",L"\x2C6F" }, //( ꓯ → Ɐ ) LISU LETTER AE → LATIN CAPITAL LETTER TURNED A	# 

			{ L"\x0001\x041F",L"\x2C70" }, //( 𐐟 → Ɒ ) DESERET CAPITAL LETTER ESH → LATIN CAPITAL LETTER TURNED ALPHA	# 

			{ L"\x0001\xD41B",L"\x0062" }, //( 𝐛 → b ) MATHEMATICAL BOLD SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD44F",L"\x0062" }, //( 𝑏 → b ) MATHEMATICAL ITALIC SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD483",L"\x0062" }, //( 𝒃 → b ) MATHEMATICAL BOLD ITALIC SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD4B7",L"\x0062" }, //( 𝒷 → b ) MATHEMATICAL SCRIPT SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD4EB",L"\x0062" }, //( 𝓫 → b ) MATHEMATICAL BOLD SCRIPT SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD51F",L"\x0062" }, //( 𝔟 → b ) MATHEMATICAL FRAKTUR SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD553",L"\x0062" }, //( 𝕓 → b ) MATHEMATICAL DOUBLE-STRUCK SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD587",L"\x0062" }, //( 𝖇 → b ) MATHEMATICAL BOLD FRAKTUR SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD5BB",L"\x0062" }, //( 𝖻 → b ) MATHEMATICAL SANS-SERIF SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD5EF",L"\x0062" }, //( 𝗯 → b ) MATHEMATICAL SANS-SERIF BOLD SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD623",L"\x0062" }, //( 𝘣 → b ) MATHEMATICAL SANS-SERIF ITALIC SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD657",L"\x0062" }, //( 𝙗 → b ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0001\xD68B",L"\x0062" }, //( 𝚋 → b ) MATHEMATICAL MONOSPACE SMALL B → LATIN SMALL LETTER B	# 
			{ L"\x0184",L"\x0062" }, //( Ƅ → b ) LATIN CAPITAL LETTER TONE SIX → LATIN SMALL LETTER B	# 
			{ L"\x042C",L"\x0062" }, //( Ь → b ) CYRILLIC CAPITAL LETTER SOFT SIGN → LATIN SMALL LETTER B	# →Ƅ→
			{ L"\x13CF",L"\x0062" }, //( Ꮟ → b ) CHEROKEE LETTER SI → LATIN SMALL LETTER B	# 
			{ L"\x15AF",L"\x0062" }, //( ᖯ → b ) CANADIAN SYLLABICS AIVILIK B → LATIN SMALL LETTER B	# 

			{ L"\xFF22",L"\x0042" }, //( Ｂ → B ) FULLWIDTH LATIN CAPITAL LETTER B → LATIN CAPITAL LETTER B	# →Β→
			{ L"\x212C",L"\x0042" }, //( ℬ → B ) SCRIPT CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD401",L"\x0042" }, //( 𝐁 → B ) MATHEMATICAL BOLD CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD435",L"\x0042" }, //( 𝐵 → B ) MATHEMATICAL ITALIC CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD469",L"\x0042" }, //( 𝑩 → B ) MATHEMATICAL BOLD ITALIC CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD4D1",L"\x0042" }, //( 𝓑 → B ) MATHEMATICAL BOLD SCRIPT CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD505",L"\x0042" }, //( 𝔅 → B ) MATHEMATICAL FRAKTUR CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD539",L"\x0042" }, //( 𝔹 → B ) MATHEMATICAL DOUBLE-STRUCK CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD56D",L"\x0042" }, //( 𝕭 → B ) MATHEMATICAL BOLD FRAKTUR CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD5A1",L"\x0042" }, //( 𝖡 → B ) MATHEMATICAL SANS-SERIF CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD5D5",L"\x0042" }, //( 𝗕 → B ) MATHEMATICAL SANS-SERIF BOLD CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD609",L"\x0042" }, //( 𝘉 → B ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD63D",L"\x0042" }, //( 𝘽 → B ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD671",L"\x0042" }, //( 𝙱 → B ) MATHEMATICAL MONOSPACE CAPITAL B → LATIN CAPITAL LETTER B	# 
			{ L"\x0392",L"\x0042" }, //( Β → B ) GREEK CAPITAL LETTER BETA → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\xD6A9",L"\x0042" }, //( 𝚩 → B ) MATHEMATICAL BOLD CAPITAL BETA → LATIN CAPITAL LETTER B	# →Β→
			{ L"\x0001\xD6E3",L"\x0042" }, //( 𝛣 → B ) MATHEMATICAL ITALIC CAPITAL BETA → LATIN CAPITAL LETTER B	# →Β→
			{ L"\x0001\xD71D",L"\x0042" }, //( 𝜝 → B ) MATHEMATICAL BOLD ITALIC CAPITAL BETA → LATIN CAPITAL LETTER B	# →Β→
			{ L"\x0001\xD757",L"\x0042" }, //( 𝝗 → B ) MATHEMATICAL SANS-SERIF BOLD CAPITAL BETA → LATIN CAPITAL LETTER B	# →Β→
			{ L"\x0001\xD791",L"\x0042" }, //( 𝞑 → B ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL BETA → LATIN CAPITAL LETTER B	# →Β→
			{ L"\x0412",L"\x0042" }, //( В → B ) CYRILLIC CAPITAL LETTER VE → LATIN CAPITAL LETTER B	# 
			{ L"\x13F4",L"\x0042" }, //( Ᏼ → B ) CHEROKEE LETTER YV → LATIN CAPITAL LETTER B	# 
			{ L"\x15F7",L"\x0042" }, //( ᗷ → B ) CANADIAN SYLLABICS CARRIER KHE → LATIN CAPITAL LETTER B	# 
			{ L"\xA4D0",L"\x0042" }, //( ꓐ → B ) LISU LETTER BA → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\x0282",L"\x0042" }, //( 𐊂 → B ) LYCIAN LETTER B → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\x02A1",L"\x0042" }, //( 𐊡 → B ) CARIAN LETTER P2 → LATIN CAPITAL LETTER B	# 
			{ L"\x0001\x0301",L"\x0042" }, //( 𐌁 → B ) OLD ITALIC LETTER BE → LATIN CAPITAL LETTER B	# 
			{ L"\xA7B4",L"\x0042" }, //( Ꞵ → B ) LATIN CAPITAL LETTER BETA → LATIN CAPITAL LETTER B	# 

			{ L"\x0253",L"\x0062\x0314" }, //( ɓ → b̔ ) LATIN SMALL LETTER B WITH HOOK → LATIN SMALL LETTER B, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x0183",L"\x0062\x0304" }, //( ƃ → b̄ ) LATIN SMALL LETTER B WITH TOPBAR → LATIN SMALL LETTER B, COMBINING MACRON	# 
			{ L"\x0182",L"\x0062\x0304" }, //( Ƃ → b̄ ) LATIN CAPITAL LETTER B WITH TOPBAR → LATIN SMALL LETTER B, COMBINING MACRON	# 
			{ L"\x0411",L"\x0062\x0304" }, //( Б → b̄ ) CYRILLIC CAPITAL LETTER BE → LATIN SMALL LETTER B, COMBINING MACRON	# →Ƃ→

			{ L"\x0180",L"\x0062\x0335" }, //( ƀ → b̵ ) LATIN SMALL LETTER B WITH STROKE → LATIN SMALL LETTER B, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x048D",L"\x0062\x0335" }, //( ҍ → b̵ ) CYRILLIC SMALL LETTER SEMISOFT SIGN → LATIN SMALL LETTER B, COMBINING SHORT STROKE OVERLAY	# →ѣ→→Ь̵→
			{ L"\x048C",L"\x0062\x0335" }, //( Ҍ → b̵ ) CYRILLIC CAPITAL LETTER SEMISOFT SIGN → LATIN SMALL LETTER B, COMBINING SHORT STROKE OVERLAY	# →Ѣ→→Ь̵→
			{ L"\x0463",L"\x0062\x0335" }, //( ѣ → b̵ ) CYRILLIC SMALL LETTER YAT → LATIN SMALL LETTER B, COMBINING SHORT STROKE OVERLAY	# →Ь̵→
			{ L"\x0462",L"\x0062\x0335" }, //( Ѣ → b̵ ) CYRILLIC CAPITAL LETTER YAT → LATIN SMALL LETTER B, COMBINING SHORT STROKE OVERLAY	# →Ь̵→

			{ L"\x042B",L"\x0062\x006C" }, //( Ы → bl ) CYRILLIC CAPITAL LETTER YERU → LATIN SMALL LETTER B, LATIN SMALL LETTER L	# →ЬІ→→Ь1→

			{ L"\x0432",L"\x0299" }, //( в → ʙ ) CYRILLIC SMALL LETTER VE → LATIN LETTER SMALL CAPITAL B	# 

			{ L"\xFF43",L"\x0063" }, //( ｃ → c ) FULLWIDTH LATIN SMALL LETTER C → LATIN SMALL LETTER C	# →с→
			{ L"\x217D",L"\x0063" }, //( ⅽ → c ) SMALL ROMAN NUMERAL ONE HUNDRED → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD41C",L"\x0063" }, //( 𝐜 → c ) MATHEMATICAL BOLD SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD450",L"\x0063" }, //( 𝑐 → c ) MATHEMATICAL ITALIC SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD484",L"\x0063" }, //( 𝒄 → c ) MATHEMATICAL BOLD ITALIC SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD4B8",L"\x0063" }, //( 𝒸 → c ) MATHEMATICAL SCRIPT SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD4EC",L"\x0063" }, //( 𝓬 → c ) MATHEMATICAL BOLD SCRIPT SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD520",L"\x0063" }, //( 𝔠 → c ) MATHEMATICAL FRAKTUR SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD554",L"\x0063" }, //( 𝕔 → c ) MATHEMATICAL DOUBLE-STRUCK SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD588",L"\x0063" }, //( 𝖈 → c ) MATHEMATICAL BOLD FRAKTUR SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD5BC",L"\x0063" }, //( 𝖼 → c ) MATHEMATICAL SANS-SERIF SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD5F0",L"\x0063" }, //( 𝗰 → c ) MATHEMATICAL SANS-SERIF BOLD SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD624",L"\x0063" }, //( 𝘤 → c ) MATHEMATICAL SANS-SERIF ITALIC SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD658",L"\x0063" }, //( 𝙘 → c ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x0001\xD68C",L"\x0063" }, //( 𝚌 → c ) MATHEMATICAL MONOSPACE SMALL C → LATIN SMALL LETTER C	# 
			{ L"\x1D04",L"\x0063" }, //( ᴄ → c ) LATIN LETTER SMALL CAPITAL C → LATIN SMALL LETTER C	# 
			{ L"\x03F2",L"\x0063" }, //( ϲ → c ) GREEK LUNATE SIGMA SYMBOL → LATIN SMALL LETTER C	# 
			{ L"\x2CA5",L"\x0063" }, //( ⲥ → c ) COPTIC SMALL LETTER SIMA → LATIN SMALL LETTER C	# →ϲ→
			{ L"\x0441",L"\x0063" }, //( с → c ) CYRILLIC SMALL LETTER ES → LATIN SMALL LETTER C	# 
			{ L"\x0001\x043D",L"\x0063" }, //( 𐐽 → c ) DESERET SMALL LETTER CHEE → LATIN SMALL LETTER C	# 

			{ L"\x0001\xF74C",L"\x0043" }, //( 🝌 → C ) ALCHEMICAL SYMBOL FOR CALX → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\x18F2",L"\x0043" }, //( 𑣲 → C ) WARANG CITI NUMBER NINETY → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\x18E9",L"\x0043" }, //( 𑣩 → C ) WARANG CITI DIGIT NINE → LATIN CAPITAL LETTER C	# 
			{ L"\xFF23",L"\x0043" }, //( Ｃ → C ) FULLWIDTH LATIN CAPITAL LETTER C → LATIN CAPITAL LETTER C	# →С→
			{ L"\x216D",L"\x0043" }, //( Ⅽ → C ) ROMAN NUMERAL ONE HUNDRED → LATIN CAPITAL LETTER C	# 
			{ L"\x2102",L"\x0043" }, //( ℂ → C ) DOUBLE-STRUCK CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x212D",L"\x0043" }, //( ℭ → C ) BLACK-LETTER CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD402",L"\x0043" }, //( 𝐂 → C ) MATHEMATICAL BOLD CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD436",L"\x0043" }, //( 𝐶 → C ) MATHEMATICAL ITALIC CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD46A",L"\x0043" }, //( 𝑪 → C ) MATHEMATICAL BOLD ITALIC CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD49E",L"\x0043" }, //( 𝒞 → C ) MATHEMATICAL SCRIPT CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD4D2",L"\x0043" }, //( 𝓒 → C ) MATHEMATICAL BOLD SCRIPT CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD56E",L"\x0043" }, //( 𝕮 → C ) MATHEMATICAL BOLD FRAKTUR CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD5A2",L"\x0043" }, //( 𝖢 → C ) MATHEMATICAL SANS-SERIF CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD5D6",L"\x0043" }, //( 𝗖 → C ) MATHEMATICAL SANS-SERIF BOLD CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD60A",L"\x0043" }, //( 𝘊 → C ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD63E",L"\x0043" }, //( 𝘾 → C ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\xD672",L"\x0043" }, //( 𝙲 → C ) MATHEMATICAL MONOSPACE CAPITAL C → LATIN CAPITAL LETTER C	# 
			{ L"\x03F9",L"\x0043" }, //( Ϲ → C ) GREEK CAPITAL LUNATE SIGMA SYMBOL → LATIN CAPITAL LETTER C	# 
			{ L"\x2CA4",L"\x0043" }, //( Ⲥ → C ) COPTIC CAPITAL LETTER SIMA → LATIN CAPITAL LETTER C	# →Ϲ→
			{ L"\x0421",L"\x0043" }, //( С → C ) CYRILLIC CAPITAL LETTER ES → LATIN CAPITAL LETTER C	# 
			{ L"\x13DF",L"\x0043" }, //( Ꮯ → C ) CHEROKEE LETTER TLI → LATIN CAPITAL LETTER C	# 
			{ L"\xA4DA",L"\x0043" }, //( ꓚ → C ) LISU LETTER CA → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\x02A2",L"\x0043" }, //( 𐊢 → C ) CARIAN LETTER D → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\x0302",L"\x0043" }, //( 𐌂 → C ) OLD ITALIC LETTER KE → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\x0415",L"\x0043" }, //( 𐐕 → C ) DESERET CAPITAL LETTER CHEE → LATIN CAPITAL LETTER C	# 
			{ L"\x0001\x051C",L"\x0043" }, //( 𐔜 → C ) ELBASAN LETTER SHE → LATIN CAPITAL LETTER C	# 

			{ L"\x00A2",L"\x0063\x0338" }, //( ¢ → c̸ ) CENT SIGN → LATIN SMALL LETTER C, COMBINING LONG SOLIDUS OVERLAY	# 
			{ L"\x023C",L"\x0063\x0338" }, //( ȼ → c̸ ) LATIN SMALL LETTER C WITH STROKE → LATIN SMALL LETTER C, COMBINING LONG SOLIDUS OVERLAY	# →¢→

			{ L"\x20A1",L"\x0043\x20EB" }, //( ₡ → C⃫ ) COLON SIGN → LATIN CAPITAL LETTER C, COMBINING LONG DOUBLE SOLIDUS OVERLAY	# 

			{ L"\x00E7",L"\x0063\x0326" }, //( ç → c̦ ) LATIN SMALL LETTER C WITH CEDILLA → LATIN SMALL LETTER C, COMBINING COMMA BELOW	# →ҫ→→с̡→
			{ L"\x04AB",L"\x0063\x0326" }, //( ҫ → c̦ ) CYRILLIC SMALL LETTER ES WITH DESCENDER → LATIN SMALL LETTER C, COMBINING COMMA BELOW	# →с̡→

			{ L"\x00C7",L"\x0043\x0326" }, //( Ç → C̦ ) LATIN CAPITAL LETTER C WITH CEDILLA → LATIN CAPITAL LETTER C, COMBINING COMMA BELOW	# →Ҫ→→С̡→
			{ L"\x04AA",L"\x0043\x0326" }, //( Ҫ → C̦ ) CYRILLIC CAPITAL LETTER ES WITH DESCENDER → LATIN CAPITAL LETTER C, COMBINING COMMA BELOW	# →С̡→

			{ L"\x0187",L"\x0043\x0027" }, //( Ƈ → C' ) LATIN CAPITAL LETTER C WITH HOOK → LATIN CAPITAL LETTER C, APOSTROPHE	# →Cʽ→

			{ L"\x2105",L"\x0063\x002F\x006F" }, //( ℅ → c/o ) CARE OF → LATIN SMALL LETTER C, SOLIDUS, LATIN SMALL LETTER O	# 

			{ L"\x2106",L"\x0063\x002F\x0075" }, //( ℆ → c/u ) CADA UNA → LATIN SMALL LETTER C, SOLIDUS, LATIN SMALL LETTER U	# 

			{ L"\x22F4",L"\xA793" }, //( ⋴ → ꞓ ) SMALL ELEMENT OF WITH VERTICAL BAR AT END OF HORIZONTAL STROKE → LATIN SMALL LETTER C WITH BAR	# →ɛ→→є→
			{ L"\x025B",L"\xA793" }, //( ɛ → ꞓ ) LATIN SMALL LETTER OPEN E → LATIN SMALL LETTER C WITH BAR	# →є→
			{ L"\x03B5",L"\xA793" }, //( ε → ꞓ ) GREEK SMALL LETTER EPSILON → LATIN SMALL LETTER C WITH BAR	# →є→
			{ L"\x03F5",L"\xA793" }, //( ϵ → ꞓ ) GREEK LUNATE EPSILON SYMBOL → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD6C6",L"\xA793" }, //( 𝛆 → ꞓ ) MATHEMATICAL BOLD SMALL EPSILON → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD6DC",L"\xA793" }, //( 𝛜 → ꞓ ) MATHEMATICAL BOLD EPSILON SYMBOL → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD700",L"\xA793" }, //( 𝜀 → ꞓ ) MATHEMATICAL ITALIC SMALL EPSILON → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD716",L"\xA793" }, //( 𝜖 → ꞓ ) MATHEMATICAL ITALIC EPSILON SYMBOL → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD73A",L"\xA793" }, //( 𝜺 → ꞓ ) MATHEMATICAL BOLD ITALIC SMALL EPSILON → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD750",L"\xA793" }, //( 𝝐 → ꞓ ) MATHEMATICAL BOLD ITALIC EPSILON SYMBOL → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD774",L"\xA793" }, //( 𝝴 → ꞓ ) MATHEMATICAL SANS-SERIF BOLD SMALL EPSILON → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD78A",L"\xA793" }, //( 𝞊 → ꞓ ) MATHEMATICAL SANS-SERIF BOLD EPSILON SYMBOL → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD7AE",L"\xA793" }, //( 𝞮 → ꞓ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL EPSILON → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\xD7C4",L"\xA793" }, //( 𝟄 → ꞓ ) MATHEMATICAL SANS-SERIF BOLD ITALIC EPSILON SYMBOL → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x2C89",L"\xA793" }, //( ⲉ → ꞓ ) COPTIC SMALL LETTER EIE → LATIN SMALL LETTER C WITH BAR	# →є→
			{ L"\x0454",L"\xA793" }, //( є → ꞓ ) CYRILLIC SMALL LETTER UKRAINIAN IE → LATIN SMALL LETTER C WITH BAR	# 
			{ L"\x0511",L"\xA793" }, //( ԑ → ꞓ ) CYRILLIC SMALL LETTER REVERSED ZE → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\x18CE",L"\xA793" }, //( 𑣎 → ꞓ ) WARANG CITI SMALL LETTER YUJ → LATIN SMALL LETTER C WITH BAR	# →ε→→є→
			{ L"\x0001\x0429",L"\xA793" }, //( 𐐩 → ꞓ ) DESERET SMALL LETTER LONG E → LATIN SMALL LETTER C WITH BAR	# →ɛ→→є→

			{ L"\x20AC",L"\xA792" }, //( € → Ꞓ ) EURO SIGN → LATIN CAPITAL LETTER C WITH BAR	# →Є→
			{ L"\x2C88",L"\xA792" }, //( Ⲉ → Ꞓ ) COPTIC CAPITAL LETTER EIE → LATIN CAPITAL LETTER C WITH BAR	# →Є→
			{ L"\x0404",L"\xA792" }, //( Є → Ꞓ ) CYRILLIC CAPITAL LETTER UKRAINIAN IE → LATIN CAPITAL LETTER C WITH BAR	# 

			{ L"\x2377",L"\xA793\x0332" }, //( ⍷ → ꞓ̲ ) APL FUNCTIONAL SYMBOL EPSILON UNDERBAR → LATIN SMALL LETTER C WITH BAR, COMBINING LOW LINE	# →ε̲→

			{ L"\x037D",L"\xA73F" }, //( ͽ → ꜿ ) GREEK SMALL REVERSED DOTTED LUNATE SIGMA SYMBOL → LATIN SMALL LETTER REVERSED C WITH DOT	# 

			{ L"\x03FF",L"\xA73E" }, //( Ͽ → Ꜿ ) GREEK CAPITAL REVERSED DOTTED LUNATE SIGMA SYMBOL → LATIN CAPITAL LETTER REVERSED C WITH DOT	# 

			{ L"\x217E",L"\x0064" }, //( ⅾ → d ) SMALL ROMAN NUMERAL FIVE HUNDRED → LATIN SMALL LETTER D	# 
			{ L"\x2146",L"\x0064" }, //( ⅆ → d ) DOUBLE-STRUCK ITALIC SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD41D",L"\x0064" }, //( 𝐝 → d ) MATHEMATICAL BOLD SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD451",L"\x0064" }, //( 𝑑 → d ) MATHEMATICAL ITALIC SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD485",L"\x0064" }, //( 𝒅 → d ) MATHEMATICAL BOLD ITALIC SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD4B9",L"\x0064" }, //( 𝒹 → d ) MATHEMATICAL SCRIPT SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD4ED",L"\x0064" }, //( 𝓭 → d ) MATHEMATICAL BOLD SCRIPT SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD521",L"\x0064" }, //( 𝔡 → d ) MATHEMATICAL FRAKTUR SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD555",L"\x0064" }, //( 𝕕 → d ) MATHEMATICAL DOUBLE-STRUCK SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD589",L"\x0064" }, //( 𝖉 → d ) MATHEMATICAL BOLD FRAKTUR SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD5BD",L"\x0064" }, //( 𝖽 → d ) MATHEMATICAL SANS-SERIF SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD5F1",L"\x0064" }, //( 𝗱 → d ) MATHEMATICAL SANS-SERIF BOLD SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD625",L"\x0064" }, //( 𝘥 → d ) MATHEMATICAL SANS-SERIF ITALIC SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD659",L"\x0064" }, //( 𝙙 → d ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0001\xD68D",L"\x0064" }, //( 𝚍 → d ) MATHEMATICAL MONOSPACE SMALL D → LATIN SMALL LETTER D	# 
			{ L"\x0501",L"\x0064" }, //( ԁ → d ) CYRILLIC SMALL LETTER KOMI DE → LATIN SMALL LETTER D	# 
			{ L"\x13E7",L"\x0064" }, //( Ꮷ → d ) CHEROKEE LETTER TSU → LATIN SMALL LETTER D	# 
			{ L"\x146F",L"\x0064" }, //( ᑯ → d ) CANADIAN SYLLABICS KO → LATIN SMALL LETTER D	# 
			{ L"\xA4D2",L"\x0064" }, //( ꓒ → d ) LISU LETTER PHA → LATIN SMALL LETTER D	# 

			{ L"\x216E",L"\x0044" }, //( Ⅾ → D ) ROMAN NUMERAL FIVE HUNDRED → LATIN CAPITAL LETTER D	# 
			{ L"\x2145",L"\x0044" }, //( ⅅ → D ) DOUBLE-STRUCK ITALIC CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD403",L"\x0044" }, //( 𝐃 → D ) MATHEMATICAL BOLD CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD437",L"\x0044" }, //( 𝐷 → D ) MATHEMATICAL ITALIC CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD46B",L"\x0044" }, //( 𝑫 → D ) MATHEMATICAL BOLD ITALIC CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD49F",L"\x0044" }, //( 𝒟 → D ) MATHEMATICAL SCRIPT CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD4D3",L"\x0044" }, //( 𝓓 → D ) MATHEMATICAL BOLD SCRIPT CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD507",L"\x0044" }, //( 𝔇 → D ) MATHEMATICAL FRAKTUR CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD53B",L"\x0044" }, //( 𝔻 → D ) MATHEMATICAL DOUBLE-STRUCK CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD56F",L"\x0044" }, //( 𝕯 → D ) MATHEMATICAL BOLD FRAKTUR CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD5A3",L"\x0044" }, //( 𝖣 → D ) MATHEMATICAL SANS-SERIF CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD5D7",L"\x0044" }, //( 𝗗 → D ) MATHEMATICAL SANS-SERIF BOLD CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD60B",L"\x0044" }, //( 𝘋 → D ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD63F",L"\x0044" }, //( 𝘿 → D ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x0001\xD673",L"\x0044" }, //( 𝙳 → D ) MATHEMATICAL MONOSPACE CAPITAL D → LATIN CAPITAL LETTER D	# 
			{ L"\x13A0",L"\x0044" }, //( Ꭰ → D ) CHEROKEE LETTER A → LATIN CAPITAL LETTER D	# 
			{ L"\x15DE",L"\x0044" }, //( ᗞ → D ) CANADIAN SYLLABICS CARRIER THE → LATIN CAPITAL LETTER D	# 
			{ L"\x15EA",L"\x0044" }, //( ᗪ → D ) CANADIAN SYLLABICS CARRIER PE → LATIN CAPITAL LETTER D	# →ᗞ→
			{ L"\xA4D3",L"\x0044" }, //( ꓓ → D ) LISU LETTER DA → LATIN CAPITAL LETTER D	# 

			{ L"\x0257",L"\x0064\x0314" }, //( ɗ → d̔ ) LATIN SMALL LETTER D WITH HOOK → LATIN SMALL LETTER D, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x0256",L"\x0064\x0328" }, //( ɖ → d̨ ) LATIN SMALL LETTER D WITH TAIL → LATIN SMALL LETTER D, COMBINING OGONEK	# →d̢→

			{ L"\x018C",L"\x0064\x0304" }, //( ƌ → d̄ ) LATIN SMALL LETTER D WITH TOPBAR → LATIN SMALL LETTER D, COMBINING MACRON	# 

			{ L"\x0111",L"\x0064\x0335" }, //( đ → d̵ ) LATIN SMALL LETTER D WITH STROKE → LATIN SMALL LETTER D, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x0110",L"\x0044\x0335" }, //( Đ → D̵ ) LATIN CAPITAL LETTER D WITH STROKE → LATIN CAPITAL LETTER D, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x00D0",L"\x0044\x0335" }, //( Ð → D̵ ) LATIN CAPITAL LETTER ETH → LATIN CAPITAL LETTER D, COMBINING SHORT STROKE OVERLAY	# →Đ→
			{ L"\x0189",L"\x0044\x0335" }, //( Ɖ → D̵ ) LATIN CAPITAL LETTER AFRICAN D → LATIN CAPITAL LETTER D, COMBINING SHORT STROKE OVERLAY	# →Đ→

			{ L"\x20AB",L"\x0064\x0335\x0331" }, //( ₫ → ḏ̵ ) DONG SIGN → LATIN SMALL LETTER D, COMBINING SHORT STROKE OVERLAY, COMBINING MACRON BELOW	# →đ̱→

			{ L"\xA77A",L"\xA779" }, //( ꝺ → Ꝺ ) LATIN SMALL LETTER INSULAR D → LATIN CAPITAL LETTER INSULAR D	# 

			{ L"\x147B",L"\x0064\x00B7" }, //( ᑻ → d· ) CANADIAN SYLLABICS WEST-CREE KWO → LATIN SMALL LETTER D, MIDDLE DOT	# →ᑯᐧ→

			{ L"\x1487",L"\x0064\x0027" }, //( ᒇ → d' ) CANADIAN SYLLABICS SOUTH-SLAVEY KOH → LATIN SMALL LETTER D, APOSTROPHE	# →ᑯᑊ→

			{ L"\x02A4",L"\x0064\x021D" }, //( ʤ → dȝ ) LATIN SMALL LETTER DEZH DIGRAPH → LATIN SMALL LETTER D, LATIN SMALL LETTER YOGH	# →dʒ→

			{ L"\x01F3",L"\x0064\x007A" }, //( ǳ → dz ) LATIN SMALL LETTER DZ → LATIN SMALL LETTER D, LATIN SMALL LETTER Z	# 
			{ L"\x02A3",L"\x0064\x007A" }, //( ʣ → dz ) LATIN SMALL LETTER DZ DIGRAPH → LATIN SMALL LETTER D, LATIN SMALL LETTER Z	# 

			{ L"\x01F2",L"\x0044\x007A" }, //( ǲ → Dz ) LATIN CAPITAL LETTER D WITH SMALL LETTER Z → LATIN CAPITAL LETTER D, LATIN SMALL LETTER Z	# 

			{ L"\x01F1",L"\x0044\x005A" }, //( Ǳ → DZ ) LATIN CAPITAL LETTER DZ → LATIN CAPITAL LETTER D, LATIN CAPITAL LETTER Z	# 

			{ L"\x01C6",L"\x0064\x017E" }, //( ǆ → dž ) LATIN SMALL LETTER DZ WITH CARON → LATIN SMALL LETTER D, LATIN SMALL LETTER Z WITH CARON	# 

			{ L"\x01C5",L"\x0044\x017E" }, //( ǅ → Dž ) LATIN CAPITAL LETTER D WITH SMALL LETTER Z WITH CARON → LATIN CAPITAL LETTER D, LATIN SMALL LETTER Z WITH CARON	# 

			{ L"\x01C4",L"\x0044\x017D" }, //( Ǆ → DŽ ) LATIN CAPITAL LETTER DZ WITH CARON → LATIN CAPITAL LETTER D, LATIN CAPITAL LETTER Z WITH CARON	# 

			{ L"\x02A5",L"\x0064\x0291" }, //( ʥ → dʑ ) LATIN SMALL LETTER DZ DIGRAPH WITH CURL → LATIN SMALL LETTER D, LATIN SMALL LETTER Z WITH CURL	# 

			{ L"\x2E39",L"\x1E9F" }, //( ⸹ → ẟ ) TOP HALF SECTION SIGN → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x03B4",L"\x1E9F" }, //( δ → ẟ ) GREEK SMALL LETTER DELTA → LATIN SMALL LETTER DELTA	# 
			{ L"\x0001\xD6C5",L"\x1E9F" }, //( 𝛅 → ẟ ) MATHEMATICAL BOLD SMALL DELTA → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x0001\xD6FF",L"\x1E9F" }, //( 𝛿 → ẟ ) MATHEMATICAL ITALIC SMALL DELTA → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x0001\xD739",L"\x1E9F" }, //( 𝜹 → ẟ ) MATHEMATICAL BOLD ITALIC SMALL DELTA → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x0001\xD773",L"\x1E9F" }, //( 𝝳 → ẟ ) MATHEMATICAL SANS-SERIF BOLD SMALL DELTA → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x0001\xD7AD",L"\x1E9F" }, //( 𝞭 → ẟ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL DELTA → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x056E",L"\x1E9F" }, //( ծ → ẟ ) ARMENIAN SMALL LETTER CA → LATIN SMALL LETTER DELTA	# →δ→
			{ L"\x1577",L"\x1E9F" }, //( ᕷ → ẟ ) CANADIAN SYLLABICS NUNAVIK HO → LATIN SMALL LETTER DELTA	# →δ→

			{ L"\x212E",L"\x0065" }, //( ℮ → e ) ESTIMATED SYMBOL → LATIN SMALL LETTER E	# 
			{ L"\xFF45",L"\x0065" }, //( ｅ → e ) FULLWIDTH LATIN SMALL LETTER E → LATIN SMALL LETTER E	# →е→
			{ L"\x212F",L"\x0065" }, //( ℯ → e ) SCRIPT SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x2147",L"\x0065" }, //( ⅇ → e ) DOUBLE-STRUCK ITALIC SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD41E",L"\x0065" }, //( 𝐞 → e ) MATHEMATICAL BOLD SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD452",L"\x0065" }, //( 𝑒 → e ) MATHEMATICAL ITALIC SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD486",L"\x0065" }, //( 𝒆 → e ) MATHEMATICAL BOLD ITALIC SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD4EE",L"\x0065" }, //( 𝓮 → e ) MATHEMATICAL BOLD SCRIPT SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD522",L"\x0065" }, //( 𝔢 → e ) MATHEMATICAL FRAKTUR SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD556",L"\x0065" }, //( 𝕖 → e ) MATHEMATICAL DOUBLE-STRUCK SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD58A",L"\x0065" }, //( 𝖊 → e ) MATHEMATICAL BOLD FRAKTUR SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD5BE",L"\x0065" }, //( 𝖾 → e ) MATHEMATICAL SANS-SERIF SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD5F2",L"\x0065" }, //( 𝗲 → e ) MATHEMATICAL SANS-SERIF BOLD SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD626",L"\x0065" }, //( 𝘦 → e ) MATHEMATICAL SANS-SERIF ITALIC SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD65A",L"\x0065" }, //( 𝙚 → e ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL E → LATIN SMALL LETTER E	# 
			{ L"\x0001\xD68E",L"\x0065" }, //( 𝚎 → e ) MATHEMATICAL MONOSPACE SMALL E → LATIN SMALL LETTER E	# 
			{ L"\xAB32",L"\x0065" }, //( ꬲ → e ) LATIN SMALL LETTER BLACKLETTER E → LATIN SMALL LETTER E	# 
			{ L"\x0435",L"\x0065" }, //( е → e ) CYRILLIC SMALL LETTER IE → LATIN SMALL LETTER E	# 
			{ L"\x04BD",L"\x0065" }, //( ҽ → e ) CYRILLIC SMALL LETTER ABKHASIAN CHE → LATIN SMALL LETTER E	# 

			{ L"\x22FF",L"\x0045" }, //( ⋿ → E ) Z NOTATION BAG MEMBERSHIP → LATIN CAPITAL LETTER E	# 
			{ L"\xFF25",L"\x0045" }, //( Ｅ → E ) FULLWIDTH LATIN CAPITAL LETTER E → LATIN CAPITAL LETTER E	# →Ε→
			{ L"\x2130",L"\x0045" }, //( ℰ → E ) SCRIPT CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD404",L"\x0045" }, //( 𝐄 → E ) MATHEMATICAL BOLD CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD438",L"\x0045" }, //( 𝐸 → E ) MATHEMATICAL ITALIC CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD46C",L"\x0045" }, //( 𝑬 → E ) MATHEMATICAL BOLD ITALIC CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD4D4",L"\x0045" }, //( 𝓔 → E ) MATHEMATICAL BOLD SCRIPT CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD508",L"\x0045" }, //( 𝔈 → E ) MATHEMATICAL FRAKTUR CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD53C",L"\x0045" }, //( 𝔼 → E ) MATHEMATICAL DOUBLE-STRUCK CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD570",L"\x0045" }, //( 𝕰 → E ) MATHEMATICAL BOLD FRAKTUR CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD5A4",L"\x0045" }, //( 𝖤 → E ) MATHEMATICAL SANS-SERIF CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD5D8",L"\x0045" }, //( 𝗘 → E ) MATHEMATICAL SANS-SERIF BOLD CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD60C",L"\x0045" }, //( 𝘌 → E ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD640",L"\x0045" }, //( 𝙀 → E ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD674",L"\x0045" }, //( 𝙴 → E ) MATHEMATICAL MONOSPACE CAPITAL E → LATIN CAPITAL LETTER E	# 
			{ L"\x0395",L"\x0045" }, //( Ε → E ) GREEK CAPITAL LETTER EPSILON → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\xD6AC",L"\x0045" }, //( 𝚬 → E ) MATHEMATICAL BOLD CAPITAL EPSILON → LATIN CAPITAL LETTER E	# →𝐄→
			{ L"\x0001\xD6E6",L"\x0045" }, //( 𝛦 → E ) MATHEMATICAL ITALIC CAPITAL EPSILON → LATIN CAPITAL LETTER E	# →Ε→
			{ L"\x0001\xD720",L"\x0045" }, //( 𝜠 → E ) MATHEMATICAL BOLD ITALIC CAPITAL EPSILON → LATIN CAPITAL LETTER E	# →Ε→
			{ L"\x0001\xD75A",L"\x0045" }, //( 𝝚 → E ) MATHEMATICAL SANS-SERIF BOLD CAPITAL EPSILON → LATIN CAPITAL LETTER E	# →Ε→
			{ L"\x0001\xD794",L"\x0045" }, //( 𝞔 → E ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL EPSILON → LATIN CAPITAL LETTER E	# →Ε→
			{ L"\x0415",L"\x0045" }, //( Е → E ) CYRILLIC CAPITAL LETTER IE → LATIN CAPITAL LETTER E	# 
			{ L"\x2D39",L"\x0045" }, //( ⴹ → E ) TIFINAGH LETTER YADD → LATIN CAPITAL LETTER E	# 
			{ L"\x13AC",L"\x0045" }, //( Ꭼ → E ) CHEROKEE LETTER GV → LATIN CAPITAL LETTER E	# 
			{ L"\xA4F0",L"\x0045" }, //( ꓰ → E ) LISU LETTER E → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\x18A6",L"\x0045" }, //( 𑢦 → E ) WARANG CITI CAPITAL LETTER II → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\x18AE",L"\x0045" }, //( 𑢮 → E ) WARANG CITI CAPITAL LETTER YUJ → LATIN CAPITAL LETTER E	# 
			{ L"\x0001\x0286",L"\x0045" }, //( 𐊆 → E ) LYCIAN LETTER I → LATIN CAPITAL LETTER E	# 

			{ L"\x011B",L"\x0115" }, //( ě → ĕ ) LATIN SMALL LETTER E WITH CARON → LATIN SMALL LETTER E WITH BREVE	# 

			{ L"\x011A",L"\x0114" }, //( Ě → Ĕ ) LATIN CAPITAL LETTER E WITH CARON → LATIN CAPITAL LETTER E WITH BREVE	# 

			{ L"\x0247",L"\x0065\x0338" }, //( ɇ → e̸ ) LATIN SMALL LETTER E WITH STROKE → LATIN SMALL LETTER E, COMBINING LONG SOLIDUS OVERLAY	# →e̷→

			{ L"\x0246",L"\x0045\x0338" }, //( Ɇ → E̸ ) LATIN CAPITAL LETTER E WITH STROKE → LATIN CAPITAL LETTER E, COMBINING LONG SOLIDUS OVERLAY	# 

			{ L"\x04BF",L"\x0065\x0328" }, //( ҿ → ę ) CYRILLIC SMALL LETTER ABKHASIAN CHE WITH DESCENDER → LATIN SMALL LETTER E, COMBINING OGONEK	# →ҽ̢→

			{ L"\x0259",L"\x01DD" }, //( ə → ǝ ) LATIN SMALL LETTER SCHWA → LATIN SMALL LETTER TURNED E	# 
			{ L"\x04D9",L"\x01DD" }, //( ә → ǝ ) CYRILLIC SMALL LETTER SCHWA → LATIN SMALL LETTER TURNED E	# 

			{ L"\x2203",L"\x018E" }, //( ∃ → Ǝ ) THERE EXISTS → LATIN CAPITAL LETTER REVERSED E	# 
			{ L"\x2D3A",L"\x018E" }, //( ⴺ → Ǝ ) TIFINAGH LETTER YADDH → LATIN CAPITAL LETTER REVERSED E	# 
			{ L"\xA4F1",L"\x018E" }, //( ꓱ → Ǝ ) LISU LETTER EU → LATIN CAPITAL LETTER REVERSED E	# 

			{ L"\x025A",L"\x01DD\x02DE" }, //( ɚ → ǝ˞ ) LATIN SMALL LETTER SCHWA WITH HOOK → LATIN SMALL LETTER TURNED E, MODIFIER LETTER RHOTIC HOOK	# →ə˞→

			{ L"\x1D14",L"\x01DD\x006F" }, //( ᴔ → ǝo ) LATIN SMALL LETTER TURNED OE → LATIN SMALL LETTER TURNED E, LATIN SMALL LETTER O	# →əo→

			{ L"\x04D8",L"\x018F" }, //( Ә → Ə ) CYRILLIC CAPITAL LETTER SCHWA → LATIN CAPITAL LETTER SCHWA	# 

			{ L"\x2107",L"\x0190" }, //( ℇ → Ɛ ) EULER CONSTANT → LATIN CAPITAL LETTER OPEN E	# 
			{ L"\x0510",L"\x0190" }, //( Ԑ → Ɛ ) CYRILLIC CAPITAL LETTER REVERSED ZE → LATIN CAPITAL LETTER OPEN E	# 
			{ L"\x13CB",L"\x0190" }, //( Ꮛ → Ɛ ) CHEROKEE LETTER QUV → LATIN CAPITAL LETTER OPEN E	# 
			{ L"\x0001\x0401",L"\x0190" }, //( 𐐁 → Ɛ ) DESERET CAPITAL LETTER LONG E → LATIN CAPITAL LETTER OPEN E	# 

			{ L"\x1D9F",L"\x1D4B" }, //( ᶟ → ᵋ ) MODIFIER LETTER SMALL REVERSED OPEN E → MODIFIER LETTER SMALL OPEN E	# 

			{ L"\x1D08",L"\x025C" }, //( ᴈ → ɜ ) LATIN SMALL LETTER TURNED OPEN E → LATIN SMALL LETTER REVERSED OPEN E	# 
			{ L"\x0437",L"\x025C" }, //( з → ɜ ) CYRILLIC SMALL LETTER ZE → LATIN SMALL LETTER REVERSED OPEN E	# 

			{ L"\x0499",L"\x025C\x0326" }, //( ҙ → ɜ̦ ) CYRILLIC SMALL LETTER ZE WITH DESCENDER → LATIN SMALL LETTER REVERSED OPEN E, COMBINING COMMA BELOW	# →з̡→

			{ L"\xA79D",L"\x025E" }, //( ꞝ → ɞ ) LATIN SMALL LETTER VOLAPUK OE → LATIN SMALL LETTER CLOSED REVERSED OPEN E	# 
			{ L"\x0001\x0442",L"\x025E" }, //( 𐑂 → ɞ ) DESERET SMALL LETTER VEE → LATIN SMALL LETTER CLOSED REVERSED OPEN E	# 

			{ L"\x0001\x042A",L"\x029A" }, //( 𐐪 → ʚ ) DESERET SMALL LETTER LONG A → LATIN SMALL LETTER CLOSED OPEN E	# 

			{ L"\x0001\xD41F",L"\x0066" }, //( 𝐟 → f ) MATHEMATICAL BOLD SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD453",L"\x0066" }, //( 𝑓 → f ) MATHEMATICAL ITALIC SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD487",L"\x0066" }, //( 𝒇 → f ) MATHEMATICAL BOLD ITALIC SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD4BB",L"\x0066" }, //( 𝒻 → f ) MATHEMATICAL SCRIPT SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD4EF",L"\x0066" }, //( 𝓯 → f ) MATHEMATICAL BOLD SCRIPT SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD523",L"\x0066" }, //( 𝔣 → f ) MATHEMATICAL FRAKTUR SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD557",L"\x0066" }, //( 𝕗 → f ) MATHEMATICAL DOUBLE-STRUCK SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD58B",L"\x0066" }, //( 𝖋 → f ) MATHEMATICAL BOLD FRAKTUR SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD5BF",L"\x0066" }, //( 𝖿 → f ) MATHEMATICAL SANS-SERIF SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD5F3",L"\x0066" }, //( 𝗳 → f ) MATHEMATICAL SANS-SERIF BOLD SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD627",L"\x0066" }, //( 𝘧 → f ) MATHEMATICAL SANS-SERIF ITALIC SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD65B",L"\x0066" }, //( 𝙛 → f ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL F → LATIN SMALL LETTER F	# 
			{ L"\x0001\xD68F",L"\x0066" }, //( 𝚏 → f ) MATHEMATICAL MONOSPACE SMALL F → LATIN SMALL LETTER F	# 
			{ L"\xAB35",L"\x0066" }, //( ꬵ → f ) LATIN SMALL LETTER LENIS F → LATIN SMALL LETTER F	# 
			{ L"\xA799",L"\x0066" }, //( ꞙ → f ) LATIN SMALL LETTER F WITH STROKE → LATIN SMALL LETTER F	# 
			{ L"\x017F",L"\x0066" }, //( ſ → f ) LATIN SMALL LETTER LONG S → LATIN SMALL LETTER F	# 
			{ L"\x1E9D",L"\x0066" }, //( ẝ → f ) LATIN SMALL LETTER LONG S WITH HIGH STROKE → LATIN SMALL LETTER F	# 
			{ L"\x0584",L"\x0066" }, //( ք → f ) ARMENIAN SMALL LETTER KEH → LATIN SMALL LETTER F	# 

			{ L"\x2131",L"\x0046" }, //( ℱ → F ) SCRIPT CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD405",L"\x0046" }, //( 𝐅 → F ) MATHEMATICAL BOLD CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD439",L"\x0046" }, //( 𝐹 → F ) MATHEMATICAL ITALIC CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD46D",L"\x0046" }, //( 𝑭 → F ) MATHEMATICAL BOLD ITALIC CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD4D5",L"\x0046" }, //( 𝓕 → F ) MATHEMATICAL BOLD SCRIPT CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD509",L"\x0046" }, //( 𝔉 → F ) MATHEMATICAL FRAKTUR CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD53D",L"\x0046" }, //( 𝔽 → F ) MATHEMATICAL DOUBLE-STRUCK CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD571",L"\x0046" }, //( 𝕱 → F ) MATHEMATICAL BOLD FRAKTUR CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD5A5",L"\x0046" }, //( 𝖥 → F ) MATHEMATICAL SANS-SERIF CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD5D9",L"\x0046" }, //( 𝗙 → F ) MATHEMATICAL SANS-SERIF BOLD CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD60D",L"\x0046" }, //( 𝘍 → F ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD641",L"\x0046" }, //( 𝙁 → F ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD675",L"\x0046" }, //( 𝙵 → F ) MATHEMATICAL MONOSPACE CAPITAL F → LATIN CAPITAL LETTER F	# 
			{ L"\xA798",L"\x0046" }, //( Ꞙ → F ) LATIN CAPITAL LETTER F WITH STROKE → LATIN CAPITAL LETTER F	# 
			{ L"\x03DC",L"\x0046" }, //( Ϝ → F ) GREEK LETTER DIGAMMA → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\xD7CA",L"\x0046" }, //( 𝟊 → F ) MATHEMATICAL BOLD CAPITAL DIGAMMA → LATIN CAPITAL LETTER F	# →Ϝ→
			{ L"\x15B4",L"\x0046" }, //( ᖴ → F ) CANADIAN SYLLABICS BLACKFOOT WE → LATIN CAPITAL LETTER F	# 
			{ L"\xA4DD",L"\x0046" }, //( ꓝ → F ) LISU LETTER TSA → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\x18C2",L"\x0046" }, //( 𑣂 → F ) WARANG CITI SMALL LETTER WI → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\x18A2",L"\x0046" }, //( 𑢢 → F ) WARANG CITI CAPITAL LETTER WI → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\x0287",L"\x0046" }, //( 𐊇 → F ) LYCIAN LETTER W → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\x02A5",L"\x0046" }, //( 𐊥 → F ) CARIAN LETTER R → LATIN CAPITAL LETTER F	# 
			{ L"\x0001\x0525",L"\x0046" }, //( 𐔥 → F ) ELBASAN LETTER GHE → LATIN CAPITAL LETTER F	# 

			{ L"\x0192",L"\x0066\x0326" }, //( ƒ → f̦ ) LATIN SMALL LETTER F WITH HOOK → LATIN SMALL LETTER F, COMBINING COMMA BELOW	# →f̡→

			{ L"\x0191",L"\x0046\x0326" }, //( Ƒ → F̦ ) LATIN CAPITAL LETTER F WITH HOOK → LATIN CAPITAL LETTER F, COMBINING COMMA BELOW	# →F̡→

			{ L"\x1D6E",L"\x0066\x0334" }, //( ᵮ → f̴ ) LATIN SMALL LETTER F WITH MIDDLE TILDE → LATIN SMALL LETTER F, COMBINING TILDE OVERLAY	# 

			{ L"\x213B",L"\x0046\x0041\x0058" }, //( ℻ → FAX ) FACSIMILE SIGN → LATIN CAPITAL LETTER F, LATIN CAPITAL LETTER A, LATIN CAPITAL LETTER X	# 

			{ L"\xFB00",L"\x0066\x0066" }, //( ﬀ → ff ) LATIN SMALL LIGATURE FF → LATIN SMALL LETTER F, LATIN SMALL LETTER F	# 

			{ L"\xFB03",L"\x0066\x0066\x0069" }, //( ﬃ → ffi ) LATIN SMALL LIGATURE FFI → LATIN SMALL LETTER F, LATIN SMALL LETTER F, LATIN SMALL LETTER I	# 

			{ L"\xFB04",L"\x0066\x0066\x006C" }, //( ﬄ → ffl ) LATIN SMALL LIGATURE FFL → LATIN SMALL LETTER F, LATIN SMALL LETTER F, LATIN SMALL LETTER L	# 

			{ L"\xFB01",L"\x0066\x0069" }, //( ﬁ → fi ) LATIN SMALL LIGATURE FI → LATIN SMALL LETTER F, LATIN SMALL LETTER I	# 

			{ L"\xFB02",L"\x0066\x006C" }, //( ﬂ → fl ) LATIN SMALL LIGATURE FL → LATIN SMALL LETTER F, LATIN SMALL LETTER L	# 

			{ L"\x02A9",L"\x0066\x014B" }, //( ʩ → fŋ ) LATIN SMALL LETTER FENG DIGRAPH → LATIN SMALL LETTER F, LATIN SMALL LETTER ENG	# 

			{ L"\x15B5",L"\x2132" }, //( ᖵ → Ⅎ ) CANADIAN SYLLABICS BLACKFOOT WI → TURNED CAPITAL F	# 
			{ L"\xA4DE",L"\x2132" }, //( ꓞ → Ⅎ ) LISU LETTER TSHA → TURNED CAPITAL F	# 

			{ L"\x15B7",L"\xA7FB" }, //( ᖷ → ꟻ ) CANADIAN SYLLABICS BLACKFOOT WA → LATIN EPIGRAPHIC LETTER REVERSED F	# 

			{ L"\xFF47",L"\x0067" }, //( ｇ → g ) FULLWIDTH LATIN SMALL LETTER G → LATIN SMALL LETTER G	# →ɡ→
			{ L"\x210A",L"\x0067" }, //( ℊ → g ) SCRIPT SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD420",L"\x0067" }, //( 𝐠 → g ) MATHEMATICAL BOLD SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD454",L"\x0067" }, //( 𝑔 → g ) MATHEMATICAL ITALIC SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD488",L"\x0067" }, //( 𝒈 → g ) MATHEMATICAL BOLD ITALIC SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD4F0",L"\x0067" }, //( 𝓰 → g ) MATHEMATICAL BOLD SCRIPT SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD524",L"\x0067" }, //( 𝔤 → g ) MATHEMATICAL FRAKTUR SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD558",L"\x0067" }, //( 𝕘 → g ) MATHEMATICAL DOUBLE-STRUCK SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD58C",L"\x0067" }, //( 𝖌 → g ) MATHEMATICAL BOLD FRAKTUR SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD5C0",L"\x0067" }, //( 𝗀 → g ) MATHEMATICAL SANS-SERIF SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD5F4",L"\x0067" }, //( 𝗴 → g ) MATHEMATICAL SANS-SERIF BOLD SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD628",L"\x0067" }, //( 𝘨 → g ) MATHEMATICAL SANS-SERIF ITALIC SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD65C",L"\x0067" }, //( 𝙜 → g ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0001\xD690",L"\x0067" }, //( 𝚐 → g ) MATHEMATICAL MONOSPACE SMALL G → LATIN SMALL LETTER G	# 
			{ L"\x0261",L"\x0067" }, //( ɡ → g ) LATIN SMALL LETTER SCRIPT G → LATIN SMALL LETTER G	# 
			{ L"\x1D83",L"\x0067" }, //( ᶃ → g ) LATIN SMALL LETTER G WITH PALATAL HOOK → LATIN SMALL LETTER G	# 
			{ L"\x018D",L"\x0067" }, //( ƍ → g ) LATIN SMALL LETTER TURNED DELTA → LATIN SMALL LETTER G	# 
			{ L"\x0581",L"\x0067" }, //( ց → g ) ARMENIAN SMALL LETTER CO → LATIN SMALL LETTER G	# 

			{ L"\x0001\xD406",L"\x0047" }, //( 𝐆 → G ) MATHEMATICAL BOLD CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD43A",L"\x0047" }, //( 𝐺 → G ) MATHEMATICAL ITALIC CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD46E",L"\x0047" }, //( 𝑮 → G ) MATHEMATICAL BOLD ITALIC CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD4A2",L"\x0047" }, //( 𝒢 → G ) MATHEMATICAL SCRIPT CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD4D6",L"\x0047" }, //( 𝓖 → G ) MATHEMATICAL BOLD SCRIPT CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD50A",L"\x0047" }, //( 𝔊 → G ) MATHEMATICAL FRAKTUR CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD53E",L"\x0047" }, //( 𝔾 → G ) MATHEMATICAL DOUBLE-STRUCK CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD572",L"\x0047" }, //( 𝕲 → G ) MATHEMATICAL BOLD FRAKTUR CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD5A6",L"\x0047" }, //( 𝖦 → G ) MATHEMATICAL SANS-SERIF CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD5DA",L"\x0047" }, //( 𝗚 → G ) MATHEMATICAL SANS-SERIF BOLD CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD60E",L"\x0047" }, //( 𝘎 → G ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD642",L"\x0047" }, //( 𝙂 → G ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x0001\xD676",L"\x0047" }, //( 𝙶 → G ) MATHEMATICAL MONOSPACE CAPITAL G → LATIN CAPITAL LETTER G	# 
			{ L"\x050C",L"\x0047" }, //( Ԍ → G ) CYRILLIC CAPITAL LETTER KOMI SJE → LATIN CAPITAL LETTER G	# 
			{ L"\x13C0",L"\x0047" }, //( Ꮐ → G ) CHEROKEE LETTER NAH → LATIN CAPITAL LETTER G	# 
			{ L"\x13F3",L"\x0047" }, //( Ᏻ → G ) CHEROKEE LETTER YU → LATIN CAPITAL LETTER G	# 
			{ L"\xA4D6",L"\x0047" }, //( ꓖ → G ) LISU LETTER GA → LATIN CAPITAL LETTER G	# 

			{ L"\x1DA2",L"\x1D4D" }, //( ᶢ → ᵍ ) MODIFIER LETTER SMALL SCRIPT G → MODIFIER LETTER SMALL G	# 

			{ L"\x0260",L"\x0067\x0314" }, //( ɠ → g̔ ) LATIN SMALL LETTER G WITH HOOK → LATIN SMALL LETTER G, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x01E7",L"\x011F" }, //( ǧ → ğ ) LATIN SMALL LETTER G WITH CARON → LATIN SMALL LETTER G WITH BREVE	# 

			{ L"\x01E6",L"\x011E" }, //( Ǧ → Ğ ) LATIN CAPITAL LETTER G WITH CARON → LATIN CAPITAL LETTER G WITH BREVE	# 

			{ L"\x01F5",L"\x0123" }, //( ǵ → ģ ) LATIN SMALL LETTER G WITH ACUTE → LATIN SMALL LETTER G WITH CEDILLA	# 

			{ L"\x01E5",L"\x0067\x0335" }, //( ǥ → g̵ ) LATIN SMALL LETTER G WITH STROKE → LATIN SMALL LETTER G, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x01E4",L"\x0047\x0335" }, //( Ǥ → G̵ ) LATIN CAPITAL LETTER G WITH STROKE → LATIN CAPITAL LETTER G, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x0193",L"\x0047\x0027" }, //( Ɠ → G' ) LATIN CAPITAL LETTER G WITH HOOK → LATIN CAPITAL LETTER G, APOSTROPHE	# →Gʽ→

			{ L"\x050D",L"\x0262" }, //( ԍ → ɢ ) CYRILLIC SMALL LETTER KOMI SJE → LATIN LETTER SMALL CAPITAL G	# 

			{ L"\xFF48",L"\x0068" }, //( ｈ → h ) FULLWIDTH LATIN SMALL LETTER H → LATIN SMALL LETTER H	# →һ→
			{ L"\x210E",L"\x0068" }, //( ℎ → h ) PLANCK CONSTANT → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD421",L"\x0068" }, //( 𝐡 → h ) MATHEMATICAL BOLD SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD489",L"\x0068" }, //( 𝒉 → h ) MATHEMATICAL BOLD ITALIC SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD4BD",L"\x0068" }, //( 𝒽 → h ) MATHEMATICAL SCRIPT SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD4F1",L"\x0068" }, //( 𝓱 → h ) MATHEMATICAL BOLD SCRIPT SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD525",L"\x0068" }, //( 𝔥 → h ) MATHEMATICAL FRAKTUR SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD559",L"\x0068" }, //( 𝕙 → h ) MATHEMATICAL DOUBLE-STRUCK SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD58D",L"\x0068" }, //( 𝖍 → h ) MATHEMATICAL BOLD FRAKTUR SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD5C1",L"\x0068" }, //( 𝗁 → h ) MATHEMATICAL SANS-SERIF SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD5F5",L"\x0068" }, //( 𝗵 → h ) MATHEMATICAL SANS-SERIF BOLD SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD629",L"\x0068" }, //( 𝘩 → h ) MATHEMATICAL SANS-SERIF ITALIC SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD65D",L"\x0068" }, //( 𝙝 → h ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x0001\xD691",L"\x0068" }, //( 𝚑 → h ) MATHEMATICAL MONOSPACE SMALL H → LATIN SMALL LETTER H	# 
			{ L"\x04BB",L"\x0068" }, //( һ → h ) CYRILLIC SMALL LETTER SHHA → LATIN SMALL LETTER H	# 
			{ L"\x0570",L"\x0068" }, //( հ → h ) ARMENIAN SMALL LETTER HO → LATIN SMALL LETTER H	# 
			{ L"\x13C2",L"\x0068" }, //( Ꮒ → h ) CHEROKEE LETTER NI → LATIN SMALL LETTER H	# 

			{ L"\xFF28",L"\x0048" }, //( Ｈ → H ) FULLWIDTH LATIN CAPITAL LETTER H → LATIN CAPITAL LETTER H	# →Η→
			{ L"\x210B",L"\x0048" }, //( ℋ → H ) SCRIPT CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x210C",L"\x0048" }, //( ℌ → H ) BLACK-LETTER CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x210D",L"\x0048" }, //( ℍ → H ) DOUBLE-STRUCK CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD407",L"\x0048" }, //( 𝐇 → H ) MATHEMATICAL BOLD CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD43B",L"\x0048" }, //( 𝐻 → H ) MATHEMATICAL ITALIC CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD46F",L"\x0048" }, //( 𝑯 → H ) MATHEMATICAL BOLD ITALIC CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD4D7",L"\x0048" }, //( 𝓗 → H ) MATHEMATICAL BOLD SCRIPT CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD573",L"\x0048" }, //( 𝕳 → H ) MATHEMATICAL BOLD FRAKTUR CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD5A7",L"\x0048" }, //( 𝖧 → H ) MATHEMATICAL SANS-SERIF CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD5DB",L"\x0048" }, //( 𝗛 → H ) MATHEMATICAL SANS-SERIF BOLD CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD60F",L"\x0048" }, //( 𝘏 → H ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD643",L"\x0048" }, //( 𝙃 → H ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD677",L"\x0048" }, //( 𝙷 → H ) MATHEMATICAL MONOSPACE CAPITAL H → LATIN CAPITAL LETTER H	# 
			{ L"\x0397",L"\x0048" }, //( Η → H ) GREEK CAPITAL LETTER ETA → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\xD6AE",L"\x0048" }, //( 𝚮 → H ) MATHEMATICAL BOLD CAPITAL ETA → LATIN CAPITAL LETTER H	# →Η→
			{ L"\x0001\xD6E8",L"\x0048" }, //( 𝛨 → H ) MATHEMATICAL ITALIC CAPITAL ETA → LATIN CAPITAL LETTER H	# →Η→
			{ L"\x0001\xD722",L"\x0048" }, //( 𝜢 → H ) MATHEMATICAL BOLD ITALIC CAPITAL ETA → LATIN CAPITAL LETTER H	# →𝑯→
			{ L"\x0001\xD75C",L"\x0048" }, //( 𝝜 → H ) MATHEMATICAL SANS-SERIF BOLD CAPITAL ETA → LATIN CAPITAL LETTER H	# →Η→
			{ L"\x0001\xD796",L"\x0048" }, //( 𝞖 → H ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL ETA → LATIN CAPITAL LETTER H	# →Η→
			{ L"\x2C8E",L"\x0048" }, //( Ⲏ → H ) COPTIC CAPITAL LETTER HATE → LATIN CAPITAL LETTER H	# →Η→
			{ L"\x041D",L"\x0048" }, //( Н → H ) CYRILLIC CAPITAL LETTER EN → LATIN CAPITAL LETTER H	# 
			{ L"\x13BB",L"\x0048" }, //( Ꮋ → H ) CHEROKEE LETTER MI → LATIN CAPITAL LETTER H	# 
			{ L"\x157C",L"\x0048" }, //( ᕼ → H ) CANADIAN SYLLABICS NUNAVUT H → LATIN CAPITAL LETTER H	# 
			{ L"\xA4E7",L"\x0048" }, //( ꓧ → H ) LISU LETTER XA → LATIN CAPITAL LETTER H	# 
			{ L"\x0001\x02CF",L"\x0048" }, //( 𐋏 → H ) CARIAN LETTER E2 → LATIN CAPITAL LETTER H	# 

			{ L"\x1D78",L"\x1D34" }, //( ᵸ → ᴴ ) MODIFIER LETTER CYRILLIC EN → MODIFIER LETTER CAPITAL H	# 

			{ L"\x0266",L"\x0068\x0314" }, //( ɦ → h̔ ) LATIN SMALL LETTER H WITH HOOK → LATIN SMALL LETTER H, COMBINING REVERSED COMMA ABOVE	# 
			{ L"\xA695",L"\x0068\x0314" }, //( ꚕ → h̔ ) CYRILLIC SMALL LETTER HWE → LATIN SMALL LETTER H, COMBINING REVERSED COMMA ABOVE	# →ɦ→
			{ L"\x13F2",L"\x0068\x0314" }, //( Ᏺ → h̔ ) CHEROKEE LETTER YO → LATIN SMALL LETTER H, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x2C67",L"\x0048\x0329" }, //( Ⱨ → H̩ ) LATIN CAPITAL LETTER H WITH DESCENDER → LATIN CAPITAL LETTER H, COMBINING VERTICAL LINE BELOW	# →Ң→→Н̩→
			{ L"\x04A2",L"\x0048\x0329" }, //( Ң → H̩ ) CYRILLIC CAPITAL LETTER EN WITH DESCENDER → LATIN CAPITAL LETTER H, COMBINING VERTICAL LINE BELOW	# →Н̩→

			{ L"\x0127",L"\x0068\x0335" }, //( ħ → h̵ ) LATIN SMALL LETTER H WITH STROKE → LATIN SMALL LETTER H, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x210F",L"\x0068\x0335" }, //( ℏ → h̵ ) PLANCK CONSTANT OVER TWO PI → LATIN SMALL LETTER H, COMBINING SHORT STROKE OVERLAY	# →ħ→
			{ L"\x045B",L"\x0068\x0335" }, //( ћ → h̵ ) CYRILLIC SMALL LETTER TSHE → LATIN SMALL LETTER H, COMBINING SHORT STROKE OVERLAY	# →ħ→

			{ L"\x0126",L"\x0048\x0335" }, //( Ħ → H̵ ) LATIN CAPITAL LETTER H WITH STROKE → LATIN CAPITAL LETTER H, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x04C9",L"\x0048\x0326" }, //( Ӊ → H̦ ) CYRILLIC CAPITAL LETTER EN WITH TAIL → LATIN CAPITAL LETTER H, COMBINING COMMA BELOW	# →Н̡→
			{ L"\x04C7",L"\x0048\x0326" }, //( Ӈ → H̦ ) CYRILLIC CAPITAL LETTER EN WITH HOOK → LATIN CAPITAL LETTER H, COMBINING COMMA BELOW	# →Н̡→

			{ L"\x043D",L"\x029C" }, //( н → ʜ ) CYRILLIC SMALL LETTER EN → LATIN LETTER SMALL CAPITAL H	# 

			{ L"\x04A3",L"\x029C\x0329" }, //( ң → ʜ̩ ) CYRILLIC SMALL LETTER EN WITH DESCENDER → LATIN LETTER SMALL CAPITAL H, COMBINING VERTICAL LINE BELOW	# →н̩→

			{ L"\x04CA",L"\x029C\x0326" }, //( ӊ → ʜ̦ ) CYRILLIC SMALL LETTER EN WITH TAIL → LATIN LETTER SMALL CAPITAL H, COMBINING COMMA BELOW	# →н̡→
			{ L"\x04C8",L"\x029C\x0326" }, //( ӈ → ʜ̦ ) CYRILLIC SMALL LETTER EN WITH HOOK → LATIN LETTER SMALL CAPITAL H, COMBINING COMMA BELOW	# →н̡→

			{ L"\x050A",L"\x01F6" }, //( Ԋ → Ƕ ) CYRILLIC CAPITAL LETTER KOMI NJE → LATIN CAPITAL LETTER HWAIR	# 

			{ L"\x0370",L"\x2C75" }, //( Ͱ → Ⱶ ) GREEK CAPITAL LETTER HETA → LATIN CAPITAL LETTER HALF H	# →Ꮀ→
			{ L"\x13A8",L"\x2C75" }, //( Ꭸ → Ⱶ ) CHEROKEE LETTER GE → LATIN CAPITAL LETTER HALF H	# →Ͱ→→Ꮀ→
			{ L"\x13B0",L"\x2C75" }, //( Ꮀ → Ⱶ ) CHEROKEE LETTER HO → LATIN CAPITAL LETTER HALF H	# 

			{ L"\xA795",L"\xA727" }, //( ꞕ → ꜧ ) LATIN SMALL LETTER H WITH PALATAL HOOK → LATIN SMALL LETTER HENG	# 

			{ L"\x02DB",L"\x0069" }, //( ˛ → i ) OGONEK → LATIN SMALL LETTER I	# →ͺ→→ι→→ι→
			{ L"\x2373",L"\x0069" }, //( ⍳ → i ) APL FUNCTIONAL SYMBOL IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\xFF49",L"\x0069" }, //( ｉ → i ) FULLWIDTH LATIN SMALL LETTER I → LATIN SMALL LETTER I	# →і→
			{ L"\x2170",L"\x0069" }, //( ⅰ → i ) SMALL ROMAN NUMERAL ONE → LATIN SMALL LETTER I	# 
			{ L"\x2139",L"\x0069" }, //( ℹ → i ) INFORMATION SOURCE → LATIN SMALL LETTER I	# 
			{ L"\x2148",L"\x0069" }, //( ⅈ → i ) DOUBLE-STRUCK ITALIC SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD422",L"\x0069" }, //( 𝐢 → i ) MATHEMATICAL BOLD SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD456",L"\x0069" }, //( 𝑖 → i ) MATHEMATICAL ITALIC SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD48A",L"\x0069" }, //( 𝒊 → i ) MATHEMATICAL BOLD ITALIC SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD4BE",L"\x0069" }, //( 𝒾 → i ) MATHEMATICAL SCRIPT SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD4F2",L"\x0069" }, //( 𝓲 → i ) MATHEMATICAL BOLD SCRIPT SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD526",L"\x0069" }, //( 𝔦 → i ) MATHEMATICAL FRAKTUR SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD55A",L"\x0069" }, //( 𝕚 → i ) MATHEMATICAL DOUBLE-STRUCK SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD58E",L"\x0069" }, //( 𝖎 → i ) MATHEMATICAL BOLD FRAKTUR SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD5C2",L"\x0069" }, //( 𝗂 → i ) MATHEMATICAL SANS-SERIF SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD5F6",L"\x0069" }, //( 𝗶 → i ) MATHEMATICAL SANS-SERIF BOLD SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD62A",L"\x0069" }, //( 𝘪 → i ) MATHEMATICAL SANS-SERIF ITALIC SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD65E",L"\x0069" }, //( 𝙞 → i ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD692",L"\x0069" }, //( 𝚒 → i ) MATHEMATICAL MONOSPACE SMALL I → LATIN SMALL LETTER I	# 
			{ L"\x0131",L"\x0069" }, //( ı → i ) LATIN SMALL LETTER DOTLESS I → LATIN SMALL LETTER I	# 
			{ L"\x0001\xD6A4",L"\x0069" }, //( 𝚤 → i ) MATHEMATICAL ITALIC SMALL DOTLESS I → LATIN SMALL LETTER I	# →ı→
			{ L"\x026A",L"\x0069" }, //( ɪ → i ) LATIN LETTER SMALL CAPITAL I → LATIN SMALL LETTER I	# →ı→
			{ L"\x0269",L"\x0069" }, //( ɩ → i ) LATIN SMALL LETTER IOTA → LATIN SMALL LETTER I	# 
			{ L"\x03B9",L"\x0069" }, //( ι → i ) GREEK SMALL LETTER IOTA → LATIN SMALL LETTER I	# 
			{ L"\x1FBE",L"\x0069" }, //( ι → i ) GREEK PROSGEGRAMMENI → LATIN SMALL LETTER I	# →ι→
			{ L"\x037A",L"\x0069" }, //( ͺ → i ) GREEK YPOGEGRAMMENI → LATIN SMALL LETTER I	# →ι→→ι→
			{ L"\x0001\xD6CA",L"\x0069" }, //( 𝛊 → i ) MATHEMATICAL BOLD SMALL IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\x0001\xD704",L"\x0069" }, //( 𝜄 → i ) MATHEMATICAL ITALIC SMALL IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\x0001\xD73E",L"\x0069" }, //( 𝜾 → i ) MATHEMATICAL BOLD ITALIC SMALL IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\x0001\xD778",L"\x0069" }, //( 𝝸 → i ) MATHEMATICAL SANS-SERIF BOLD SMALL IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\x0001\xD7B2",L"\x0069" }, //( 𝞲 → i ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\x0456",L"\x0069" }, //( і → i ) CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I → LATIN SMALL LETTER I	# 
			{ L"\xA647",L"\x0069" }, //( ꙇ → i ) CYRILLIC SMALL LETTER IOTA → LATIN SMALL LETTER I	# →ι→
			{ L"\x04CF",L"\x0069" }, //( ӏ → i ) CYRILLIC SMALL LETTER PALOCHKA → LATIN SMALL LETTER I	# →ı→
			{ L"\x13A5",L"\x0069" }, //( Ꭵ → i ) CHEROKEE LETTER V → LATIN SMALL LETTER I	# 
			{ L"\x0001\x18C3",L"\x0069" }, //( 𑣃 → i ) WARANG CITI SMALL LETTER YU → LATIN SMALL LETTER I	# →ι→

			{ L"\x24DB",L"\x24BE" }, //( ⓛ → Ⓘ ) CIRCLED LATIN SMALL LETTER L → CIRCLED LATIN CAPITAL LETTER I	# 

			{ L"\x2378",L"\x0069\x0332" }, //( ⍸ → i̲ ) APL FUNCTIONAL SYMBOL IOTA UNDERBAR → LATIN SMALL LETTER I, COMBINING LOW LINE	# →ι̲→

			{ L"\x01D0",L"\x012D" }, //( ǐ → ĭ ) LATIN SMALL LETTER I WITH CARON → LATIN SMALL LETTER I WITH BREVE	# 

			{ L"\x01CF",L"\x012C" }, //( Ǐ → Ĭ ) LATIN CAPITAL LETTER I WITH CARON → LATIN CAPITAL LETTER I WITH BREVE	# 

			{ L"\x0268",L"\x0069\x0335" }, //( ɨ → i̵ ) LATIN SMALL LETTER I WITH STROKE → LATIN SMALL LETTER I, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x1D7B",L"\x0069\x0335" }, //( ᵻ → i̵ ) LATIN SMALL CAPITAL LETTER I WITH STROKE → LATIN SMALL LETTER I, COMBINING SHORT STROKE OVERLAY	# →ɪ̵→
			{ L"\x1D7C",L"\x0069\x0335" }, //( ᵼ → i̵ ) LATIN SMALL LETTER IOTA WITH STROKE → LATIN SMALL LETTER I, COMBINING SHORT STROKE OVERLAY	# →ɩ̵→

			{ L"\x2171",L"\x0069\x0069" }, //( ⅱ → ii ) SMALL ROMAN NUMERAL TWO → LATIN SMALL LETTER I, LATIN SMALL LETTER I	# 

			{ L"\x2172",L"\x0069\x0069\x0069" }, //( ⅲ → iii ) SMALL ROMAN NUMERAL THREE → LATIN SMALL LETTER I, LATIN SMALL LETTER I, LATIN SMALL LETTER I	# 

			{ L"\x0133",L"\x0069\x006A" }, //( ĳ → ij ) LATIN SMALL LIGATURE IJ → LATIN SMALL LETTER I, LATIN SMALL LETTER J	# 

			{ L"\x2173",L"\x0069\x0076" }, //( ⅳ → iv ) SMALL ROMAN NUMERAL FOUR → LATIN SMALL LETTER I, LATIN SMALL LETTER V	# 

			{ L"\x2178",L"\x0069\x0078" }, //( ⅸ → ix ) SMALL ROMAN NUMERAL NINE → LATIN SMALL LETTER I, LATIN SMALL LETTER X	# 

			{ L"\xFF4A",L"\x006A" }, //( ｊ → j ) FULLWIDTH LATIN SMALL LETTER J → LATIN SMALL LETTER J	# →ϳ→
			{ L"\x2149",L"\x006A" }, //( ⅉ → j ) DOUBLE-STRUCK ITALIC SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD423",L"\x006A" }, //( 𝐣 → j ) MATHEMATICAL BOLD SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD457",L"\x006A" }, //( 𝑗 → j ) MATHEMATICAL ITALIC SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD48B",L"\x006A" }, //( 𝒋 → j ) MATHEMATICAL BOLD ITALIC SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD4BF",L"\x006A" }, //( 𝒿 → j ) MATHEMATICAL SCRIPT SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD4F3",L"\x006A" }, //( 𝓳 → j ) MATHEMATICAL BOLD SCRIPT SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD527",L"\x006A" }, //( 𝔧 → j ) MATHEMATICAL FRAKTUR SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD55B",L"\x006A" }, //( 𝕛 → j ) MATHEMATICAL DOUBLE-STRUCK SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD58F",L"\x006A" }, //( 𝖏 → j ) MATHEMATICAL BOLD FRAKTUR SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD5C3",L"\x006A" }, //( 𝗃 → j ) MATHEMATICAL SANS-SERIF SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD5F7",L"\x006A" }, //( 𝗷 → j ) MATHEMATICAL SANS-SERIF BOLD SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD62B",L"\x006A" }, //( 𝘫 → j ) MATHEMATICAL SANS-SERIF ITALIC SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD65F",L"\x006A" }, //( 𝙟 → j ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x0001\xD693",L"\x006A" }, //( 𝚓 → j ) MATHEMATICAL MONOSPACE SMALL J → LATIN SMALL LETTER J	# 
			{ L"\x03F3",L"\x006A" }, //( ϳ → j ) GREEK LETTER YOT → LATIN SMALL LETTER J	# 
			{ L"\x0458",L"\x006A" }, //( ј → j ) CYRILLIC SMALL LETTER JE → LATIN SMALL LETTER J	# 

			{ L"\xFF2A",L"\x004A" }, //( Ｊ → J ) FULLWIDTH LATIN CAPITAL LETTER J → LATIN CAPITAL LETTER J	# →Ј→
			{ L"\x0001\xD409",L"\x004A" }, //( 𝐉 → J ) MATHEMATICAL BOLD CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD43D",L"\x004A" }, //( 𝐽 → J ) MATHEMATICAL ITALIC CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD471",L"\x004A" }, //( 𝑱 → J ) MATHEMATICAL BOLD ITALIC CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD4A5",L"\x004A" }, //( 𝒥 → J ) MATHEMATICAL SCRIPT CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD4D9",L"\x004A" }, //( 𝓙 → J ) MATHEMATICAL BOLD SCRIPT CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD50D",L"\x004A" }, //( 𝔍 → J ) MATHEMATICAL FRAKTUR CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD541",L"\x004A" }, //( 𝕁 → J ) MATHEMATICAL DOUBLE-STRUCK CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD575",L"\x004A" }, //( 𝕵 → J ) MATHEMATICAL BOLD FRAKTUR CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD5A9",L"\x004A" }, //( 𝖩 → J ) MATHEMATICAL SANS-SERIF CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD5DD",L"\x004A" }, //( 𝗝 → J ) MATHEMATICAL SANS-SERIF BOLD CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD611",L"\x004A" }, //( 𝘑 → J ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD645",L"\x004A" }, //( 𝙅 → J ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x0001\xD679",L"\x004A" }, //( 𝙹 → J ) MATHEMATICAL MONOSPACE CAPITAL J → LATIN CAPITAL LETTER J	# 
			{ L"\x037F",L"\x004A" }, //( Ϳ → J ) GREEK CAPITAL LETTER YOT → LATIN CAPITAL LETTER J	# 
			{ L"\x0408",L"\x004A" }, //( Ј → J ) CYRILLIC CAPITAL LETTER JE → LATIN CAPITAL LETTER J	# 
			{ L"\x13AB",L"\x004A" }, //( Ꭻ → J ) CHEROKEE LETTER GU → LATIN CAPITAL LETTER J	# 
			{ L"\x148D",L"\x004A" }, //( ᒍ → J ) CANADIAN SYLLABICS CO → LATIN CAPITAL LETTER J	# 
			{ L"\xA4D9",L"\x004A" }, //( ꓙ → J ) LISU LETTER JA → LATIN CAPITAL LETTER J	# 
			{ L"\xA7B2",L"\x004A" }, //( Ʝ → J ) LATIN CAPITAL LETTER J WITH CROSSED-TAIL → LATIN CAPITAL LETTER J	# 

			{ L"\x0249",L"\x006A\x0335" }, //( ɉ → j̵ ) LATIN SMALL LETTER J WITH STROKE → LATIN SMALL LETTER J, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x0248",L"\x004A\x0335" }, //( Ɉ → J̵ ) LATIN CAPITAL LETTER J WITH STROKE → LATIN CAPITAL LETTER J, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x1499",L"\x004A\x00B7" }, //( ᒙ → J· ) CANADIAN SYLLABICS WEST-CREE CWO → LATIN CAPITAL LETTER J, MIDDLE DOT	# →ᒍᐧ→

			{ L"\x0001\xD6A5",L"\x0237" }, //( 𝚥 → ȷ ) MATHEMATICAL ITALIC SMALL DOTLESS J → LATIN SMALL LETTER DOTLESS J	# 
			{ L"\x0575",L"\x0237" }, //( յ → ȷ ) ARMENIAN SMALL LETTER YI → LATIN SMALL LETTER DOTLESS J	# 

			{ L"\x0001\xD424",L"\x006B" }, //( 𝐤 → k ) MATHEMATICAL BOLD SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD458",L"\x006B" }, //( 𝑘 → k ) MATHEMATICAL ITALIC SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD48C",L"\x006B" }, //( 𝒌 → k ) MATHEMATICAL BOLD ITALIC SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD4C0",L"\x006B" }, //( 𝓀 → k ) MATHEMATICAL SCRIPT SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD4F4",L"\x006B" }, //( 𝓴 → k ) MATHEMATICAL BOLD SCRIPT SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD528",L"\x006B" }, //( 𝔨 → k ) MATHEMATICAL FRAKTUR SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD55C",L"\x006B" }, //( 𝕜 → k ) MATHEMATICAL DOUBLE-STRUCK SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD590",L"\x006B" }, //( 𝖐 → k ) MATHEMATICAL BOLD FRAKTUR SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD5C4",L"\x006B" }, //( 𝗄 → k ) MATHEMATICAL SANS-SERIF SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD5F8",L"\x006B" }, //( 𝗸 → k ) MATHEMATICAL SANS-SERIF BOLD SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD62C",L"\x006B" }, //( 𝘬 → k ) MATHEMATICAL SANS-SERIF ITALIC SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD660",L"\x006B" }, //( 𝙠 → k ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x0001\xD694",L"\x006B" }, //( 𝚔 → k ) MATHEMATICAL MONOSPACE SMALL K → LATIN SMALL LETTER K	# 
			{ L"\x1D0B",L"\x006B" }, //( ᴋ → k ) LATIN LETTER SMALL CAPITAL K → LATIN SMALL LETTER K	# →к→
			{ L"\x0138",L"\x006B" }, //( ĸ → k ) LATIN SMALL LETTER KRA → LATIN SMALL LETTER K	# →к→
			{ L"\x03BA",L"\x006B" }, //( κ → k ) GREEK SMALL LETTER KAPPA → LATIN SMALL LETTER K	# →к→
			{ L"\x03F0",L"\x006B" }, //( ϰ → k ) GREEK KAPPA SYMBOL → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD6CB",L"\x006B" }, //( 𝛋 → k ) MATHEMATICAL BOLD SMALL KAPPA → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD6DE",L"\x006B" }, //( 𝛞 → k ) MATHEMATICAL BOLD KAPPA SYMBOL → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD705",L"\x006B" }, //( 𝜅 → k ) MATHEMATICAL ITALIC SMALL KAPPA → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD718",L"\x006B" }, //( 𝜘 → k ) MATHEMATICAL ITALIC KAPPA SYMBOL → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD73F",L"\x006B" }, //( 𝜿 → k ) MATHEMATICAL BOLD ITALIC SMALL KAPPA → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD752",L"\x006B" }, //( 𝝒 → k ) MATHEMATICAL BOLD ITALIC KAPPA SYMBOL → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD779",L"\x006B" }, //( 𝝹 → k ) MATHEMATICAL SANS-SERIF BOLD SMALL KAPPA → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD78C",L"\x006B" }, //( 𝞌 → k ) MATHEMATICAL SANS-SERIF BOLD KAPPA SYMBOL → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD7B3",L"\x006B" }, //( 𝞳 → k ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL KAPPA → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x0001\xD7C6",L"\x006B" }, //( 𝟆 → k ) MATHEMATICAL SANS-SERIF BOLD ITALIC KAPPA SYMBOL → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x2C95",L"\x006B" }, //( ⲕ → k ) COPTIC SMALL LETTER KAPA → LATIN SMALL LETTER K	# →κ→→к→
			{ L"\x043A",L"\x006B" }, //( к → k ) CYRILLIC SMALL LETTER KA → LATIN SMALL LETTER K	# 

			{ L"\x212A",L"\x004B" }, //( K → K ) KELVIN SIGN → LATIN CAPITAL LETTER K	# 
			{ L"\xFF2B",L"\x004B" }, //( Ｋ → K ) FULLWIDTH LATIN CAPITAL LETTER K → LATIN CAPITAL LETTER K	# →Κ→
			{ L"\x0001\xD40A",L"\x004B" }, //( 𝐊 → K ) MATHEMATICAL BOLD CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD43E",L"\x004B" }, //( 𝐾 → K ) MATHEMATICAL ITALIC CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD472",L"\x004B" }, //( 𝑲 → K ) MATHEMATICAL BOLD ITALIC CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD4A6",L"\x004B" }, //( 𝒦 → K ) MATHEMATICAL SCRIPT CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD4DA",L"\x004B" }, //( 𝓚 → K ) MATHEMATICAL BOLD SCRIPT CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD50E",L"\x004B" }, //( 𝔎 → K ) MATHEMATICAL FRAKTUR CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD542",L"\x004B" }, //( 𝕂 → K ) MATHEMATICAL DOUBLE-STRUCK CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD576",L"\x004B" }, //( 𝕶 → K ) MATHEMATICAL BOLD FRAKTUR CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD5AA",L"\x004B" }, //( 𝖪 → K ) MATHEMATICAL SANS-SERIF CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD5DE",L"\x004B" }, //( 𝗞 → K ) MATHEMATICAL SANS-SERIF BOLD CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD612",L"\x004B" }, //( 𝘒 → K ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD646",L"\x004B" }, //( 𝙆 → K ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD67A",L"\x004B" }, //( 𝙺 → K ) MATHEMATICAL MONOSPACE CAPITAL K → LATIN CAPITAL LETTER K	# 
			{ L"\x039A",L"\x004B" }, //( Κ → K ) GREEK CAPITAL LETTER KAPPA → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\xD6B1",L"\x004B" }, //( 𝚱 → K ) MATHEMATICAL BOLD CAPITAL KAPPA → LATIN CAPITAL LETTER K	# →Κ→
			{ L"\x0001\xD6EB",L"\x004B" }, //( 𝛫 → K ) MATHEMATICAL ITALIC CAPITAL KAPPA → LATIN CAPITAL LETTER K	# →𝐾→
			{ L"\x0001\xD725",L"\x004B" }, //( 𝜥 → K ) MATHEMATICAL BOLD ITALIC CAPITAL KAPPA → LATIN CAPITAL LETTER K	# →𝑲→
			{ L"\x0001\xD75F",L"\x004B" }, //( 𝝟 → K ) MATHEMATICAL SANS-SERIF BOLD CAPITAL KAPPA → LATIN CAPITAL LETTER K	# →Κ→
			{ L"\x0001\xD799",L"\x004B" }, //( 𝞙 → K ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL KAPPA → LATIN CAPITAL LETTER K	# →Κ→
			{ L"\x2C94",L"\x004B" }, //( Ⲕ → K ) COPTIC CAPITAL LETTER KAPA → LATIN CAPITAL LETTER K	# →Κ→
			{ L"\x041A",L"\x004B" }, //( К → K ) CYRILLIC CAPITAL LETTER KA → LATIN CAPITAL LETTER K	# 
			{ L"\x13E6",L"\x004B" }, //( Ꮶ → K ) CHEROKEE LETTER TSO → LATIN CAPITAL LETTER K	# 
			{ L"\x16D5",L"\x004B" }, //( ᛕ → K ) RUNIC LETTER OPEN-P → LATIN CAPITAL LETTER K	# 
			{ L"\xA4D7",L"\x004B" }, //( ꓗ → K ) LISU LETTER KA → LATIN CAPITAL LETTER K	# 
			{ L"\x0001\x0518",L"\x004B" }, //( 𐔘 → K ) ELBASAN LETTER QE → LATIN CAPITAL LETTER K	# 

			{ L"\x0199",L"\x006B\x0314" }, //( ƙ → k̔ ) LATIN SMALL LETTER K WITH HOOK → LATIN SMALL LETTER K, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x049B",L"\x006B\x0329" }, //( қ → k̩ ) CYRILLIC SMALL LETTER KA WITH DESCENDER → LATIN SMALL LETTER K, COMBINING VERTICAL LINE BELOW	# →к̩→

			{ L"\x2C69",L"\x004B\x0329" }, //( Ⱪ → K̩ ) LATIN CAPITAL LETTER K WITH DESCENDER → LATIN CAPITAL LETTER K, COMBINING VERTICAL LINE BELOW	# →Қ→→К̩→
			{ L"\x049A",L"\x004B\x0329" }, //( Қ → K̩ ) CYRILLIC CAPITAL LETTER KA WITH DESCENDER → LATIN CAPITAL LETTER K, COMBINING VERTICAL LINE BELOW	# →К̩→

			{ L"\x049F",L"\x006B\x0335" }, //( ҟ → k̵ ) CYRILLIC SMALL LETTER KA WITH STROKE → LATIN SMALL LETTER K, COMBINING SHORT STROKE OVERLAY	# →к̵→

			{ L"\x20AD",L"\x004B\x0335" }, //( ₭ → K̵ ) KIP SIGN → LATIN CAPITAL LETTER K, COMBINING SHORT STROKE OVERLAY	# →K̶→
			{ L"\xA740",L"\x004B\x0335" }, //( Ꝁ → K̵ ) LATIN CAPITAL LETTER K WITH STROKE → LATIN CAPITAL LETTER K, COMBINING SHORT STROKE OVERLAY	# →Ҟ→→К̵→
			{ L"\x049E",L"\x004B\x0335" }, //( Ҟ → K̵ ) CYRILLIC CAPITAL LETTER KA WITH STROKE → LATIN CAPITAL LETTER K, COMBINING SHORT STROKE OVERLAY	# →К̵→

			{ L"\x0198",L"\x004B\x0027" }, //( Ƙ → K' ) LATIN CAPITAL LETTER K WITH HOOK → LATIN CAPITAL LETTER K, APOSTROPHE	# →Kʽ→

			{ L"\x05C0",L"\x006C" }, //( ‎׀‎ → l ) HEBREW PUNCTUATION PASEQ → LATIN SMALL LETTER L	# →|→
			{ L"\x007C",L"\x006C" }, //( | → l ) VERTICAL LINE → LATIN SMALL LETTER L	# 
			{ L"\x2223",L"\x006C" }, //( ∣ → l ) DIVIDES → LATIN SMALL LETTER L	# →ǀ→
			{ L"\xFFE8",L"\x006C" }, //( ￨ → l ) HALFWIDTH FORMS LIGHT VERTICAL → LATIN SMALL LETTER L	# →|→
			{ L"\x0031",L"\x006C" }, //( 1 → l ) DIGIT ONE → LATIN SMALL LETTER L	# 
			{ L"\x0661",L"\x006C" }, //( ‎١‎ → l ) ARABIC-INDIC DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x06F1",L"\x006C" }, //( ۱ → l ) EXTENDED ARABIC-INDIC DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x0001\x0320",L"\x006C" }, //( 𐌠 → l ) OLD ITALIC NUMERAL ONE → LATIN SMALL LETTER L	# →𐌉→→I→
			{ L"\x0001\xE8C7",L"\x006C" }, //( ‎𞣇‎ → l ) MENDE KIKAKUI DIGIT ONE → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD7CF",L"\x006C" }, //( 𝟏 → l ) MATHEMATICAL BOLD DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x0001\xD7D9",L"\x006C" }, //( 𝟙 → l ) MATHEMATICAL DOUBLE-STRUCK DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x0001\xD7E3",L"\x006C" }, //( 𝟣 → l ) MATHEMATICAL SANS-SERIF DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x0001\xD7ED",L"\x006C" }, //( 𝟭 → l ) MATHEMATICAL SANS-SERIF BOLD DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x0001\xD7F7",L"\x006C" }, //( 𝟷 → l ) MATHEMATICAL MONOSPACE DIGIT ONE → LATIN SMALL LETTER L	# →1→
			{ L"\x0049",L"\x006C" }, //( I → l ) LATIN CAPITAL LETTER I → LATIN SMALL LETTER L	# 
			{ L"\xFF29",L"\x006C" }, //( Ｉ → l ) FULLWIDTH LATIN CAPITAL LETTER I → LATIN SMALL LETTER L	# →Ӏ→
			{ L"\x2160",L"\x006C" }, //( Ⅰ → l ) ROMAN NUMERAL ONE → LATIN SMALL LETTER L	# →Ӏ→
			{ L"\x2110",L"\x006C" }, //( ℐ → l ) SCRIPT CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x2111",L"\x006C" }, //( ℑ → l ) BLACK-LETTER CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD408",L"\x006C" }, //( 𝐈 → l ) MATHEMATICAL BOLD CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD43C",L"\x006C" }, //( 𝐼 → l ) MATHEMATICAL ITALIC CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD470",L"\x006C" }, //( 𝑰 → l ) MATHEMATICAL BOLD ITALIC CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD4D8",L"\x006C" }, //( 𝓘 → l ) MATHEMATICAL BOLD SCRIPT CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD540",L"\x006C" }, //( 𝕀 → l ) MATHEMATICAL DOUBLE-STRUCK CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD574",L"\x006C" }, //( 𝕴 → l ) MATHEMATICAL BOLD FRAKTUR CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD5A8",L"\x006C" }, //( 𝖨 → l ) MATHEMATICAL SANS-SERIF CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD5DC",L"\x006C" }, //( 𝗜 → l ) MATHEMATICAL SANS-SERIF BOLD CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD610",L"\x006C" }, //( 𝘐 → l ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD644",L"\x006C" }, //( 𝙄 → l ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\xD678",L"\x006C" }, //( 𝙸 → l ) MATHEMATICAL MONOSPACE CAPITAL I → LATIN SMALL LETTER L	# →I→
			{ L"\x0196",L"\x006C" }, //( Ɩ → l ) LATIN CAPITAL LETTER IOTA → LATIN SMALL LETTER L	# 
			{ L"\xFF4C",L"\x006C" }, //( ｌ → l ) FULLWIDTH LATIN SMALL LETTER L → LATIN SMALL LETTER L	# →Ⅰ→→Ӏ→
			{ L"\x217C",L"\x006C" }, //( ⅼ → l ) SMALL ROMAN NUMERAL FIFTY → LATIN SMALL LETTER L	# 
			{ L"\x2113",L"\x006C" }, //( ℓ → l ) SCRIPT SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD425",L"\x006C" }, //( 𝐥 → l ) MATHEMATICAL BOLD SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD459",L"\x006C" }, //( 𝑙 → l ) MATHEMATICAL ITALIC SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD48D",L"\x006C" }, //( 𝒍 → l ) MATHEMATICAL BOLD ITALIC SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD4C1",L"\x006C" }, //( 𝓁 → l ) MATHEMATICAL SCRIPT SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD4F5",L"\x006C" }, //( 𝓵 → l ) MATHEMATICAL BOLD SCRIPT SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD529",L"\x006C" }, //( 𝔩 → l ) MATHEMATICAL FRAKTUR SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD55D",L"\x006C" }, //( 𝕝 → l ) MATHEMATICAL DOUBLE-STRUCK SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD591",L"\x006C" }, //( 𝖑 → l ) MATHEMATICAL BOLD FRAKTUR SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD5C5",L"\x006C" }, //( 𝗅 → l ) MATHEMATICAL SANS-SERIF SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD5F9",L"\x006C" }, //( 𝗹 → l ) MATHEMATICAL SANS-SERIF BOLD SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD62D",L"\x006C" }, //( 𝘭 → l ) MATHEMATICAL SANS-SERIF ITALIC SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD661",L"\x006C" }, //( 𝙡 → l ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD695",L"\x006C" }, //( 𝚕 → l ) MATHEMATICAL MONOSPACE SMALL L → LATIN SMALL LETTER L	# 
			{ L"\x01C0",L"\x006C" }, //( ǀ → l ) LATIN LETTER DENTAL CLICK → LATIN SMALL LETTER L	# 
			{ L"\x0399",L"\x006C" }, //( Ι → l ) GREEK CAPITAL LETTER IOTA → LATIN SMALL LETTER L	# 
			{ L"\x0001\xD6B0",L"\x006C" }, //( 𝚰 → l ) MATHEMATICAL BOLD CAPITAL IOTA → LATIN SMALL LETTER L	# →Ι→
			{ L"\x0001\xD6EA",L"\x006C" }, //( 𝛪 → l ) MATHEMATICAL ITALIC CAPITAL IOTA → LATIN SMALL LETTER L	# →Ι→
			{ L"\x0001\xD724",L"\x006C" }, //( 𝜤 → l ) MATHEMATICAL BOLD ITALIC CAPITAL IOTA → LATIN SMALL LETTER L	# →Ι→
			{ L"\x0001\xD75E",L"\x006C" }, //( 𝝞 → l ) MATHEMATICAL SANS-SERIF BOLD CAPITAL IOTA → LATIN SMALL LETTER L	# →Ι→
			{ L"\x0001\xD798",L"\x006C" }, //( 𝞘 → l ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL IOTA → LATIN SMALL LETTER L	# →Ι→
			{ L"\x2C92",L"\x006C" }, //( Ⲓ → l ) COPTIC CAPITAL LETTER IAUDA → LATIN SMALL LETTER L	# →Ӏ→
			{ L"\x0406",L"\x006C" }, //( І → l ) CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I → LATIN SMALL LETTER L	# 
			{ L"\x04C0",L"\x006C" }, //( Ӏ → l ) CYRILLIC LETTER PALOCHKA → LATIN SMALL LETTER L	# 
			{ L"\x05D5",L"\x006C" }, //( ‎ו‎ → l ) HEBREW LETTER VAV → LATIN SMALL LETTER L	# 
			{ L"\x05DF",L"\x006C" }, //( ‎ן‎ → l ) HEBREW LETTER FINAL NUN → LATIN SMALL LETTER L	# 
			{ L"\x0627",L"\x006C" }, //( ‎ا‎ → l ) ARABIC LETTER ALEF → LATIN SMALL LETTER L	# →1→
			{ L"\x0001\xEE00",L"\x006C" }, //( ‎𞸀‎ → l ) ARABIC MATHEMATICAL ALEF → LATIN SMALL LETTER L	# →‎ا‎→→1→
			{ L"\x0001\xEE80",L"\x006C" }, //( ‎𞺀‎ → l ) ARABIC MATHEMATICAL LOOPED ALEF → LATIN SMALL LETTER L	# →‎ا‎→→1→
			{ L"\xFE8E",L"\x006C" }, //( ‎ﺎ‎ → l ) ARABIC LETTER ALEF FINAL FORM → LATIN SMALL LETTER L	# →‎ا‎→→1→
			{ L"\xFE8D",L"\x006C" }, //( ‎ﺍ‎ → l ) ARABIC LETTER ALEF ISOLATED FORM → LATIN SMALL LETTER L	# →‎ا‎→→1→
			{ L"\x07CA",L"\x006C" }, //( ‎ߊ‎ → l ) NKO LETTER A → LATIN SMALL LETTER L	# →∣→→ǀ→
			{ L"\x2D4F",L"\x006C" }, //( ⵏ → l ) TIFINAGH LETTER YAN → LATIN SMALL LETTER L	# →Ӏ→
			{ L"\x16C1",L"\x006C" }, //( ᛁ → l ) RUNIC LETTER ISAZ IS ISS I → LATIN SMALL LETTER L	# →I→
			{ L"\xA4F2",L"\x006C" }, //( ꓲ → l ) LISU LETTER I → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\x028A",L"\x006C" }, //( 𐊊 → l ) LYCIAN LETTER J → LATIN SMALL LETTER L	# →I→
			{ L"\x0001\x0309",L"\x006C" }, //( 𐌉 → l ) OLD ITALIC LETTER I → LATIN SMALL LETTER L	# →I→

			{ L"\x216C",L"\x004C" }, //( Ⅼ → L ) ROMAN NUMERAL FIFTY → LATIN CAPITAL LETTER L	# 
			{ L"\x2112",L"\x004C" }, //( ℒ → L ) SCRIPT CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD40B",L"\x004C" }, //( 𝐋 → L ) MATHEMATICAL BOLD CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD43F",L"\x004C" }, //( 𝐿 → L ) MATHEMATICAL ITALIC CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD473",L"\x004C" }, //( 𝑳 → L ) MATHEMATICAL BOLD ITALIC CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD4DB",L"\x004C" }, //( 𝓛 → L ) MATHEMATICAL BOLD SCRIPT CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD50F",L"\x004C" }, //( 𝔏 → L ) MATHEMATICAL FRAKTUR CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD543",L"\x004C" }, //( 𝕃 → L ) MATHEMATICAL DOUBLE-STRUCK CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD577",L"\x004C" }, //( 𝕷 → L ) MATHEMATICAL BOLD FRAKTUR CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD5AB",L"\x004C" }, //( 𝖫 → L ) MATHEMATICAL SANS-SERIF CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD5DF",L"\x004C" }, //( 𝗟 → L ) MATHEMATICAL SANS-SERIF BOLD CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD613",L"\x004C" }, //( 𝘓 → L ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD647",L"\x004C" }, //( 𝙇 → L ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\xD67B",L"\x004C" }, //( 𝙻 → L ) MATHEMATICAL MONOSPACE CAPITAL L → LATIN CAPITAL LETTER L	# 
			{ L"\x2CD0",L"\x004C" }, //( Ⳑ → L ) COPTIC CAPITAL LETTER L-SHAPED HA → LATIN CAPITAL LETTER L	# 
			{ L"\x13DE",L"\x004C" }, //( Ꮮ → L ) CHEROKEE LETTER TLE → LATIN CAPITAL LETTER L	# 
			{ L"\x14AA",L"\x004C" }, //( ᒪ → L ) CANADIAN SYLLABICS MA → LATIN CAPITAL LETTER L	# 
			{ L"\xA4E1",L"\x004C" }, //( ꓡ → L ) LISU LETTER LA → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\x18A3",L"\x004C" }, //( 𑢣 → L ) WARANG CITI CAPITAL LETTER YU → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\x18B2",L"\x004C" }, //( 𑢲 → L ) WARANG CITI CAPITAL LETTER TTE → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\x041B",L"\x004C" }, //( 𐐛 → L ) DESERET CAPITAL LETTER ETH → LATIN CAPITAL LETTER L	# 
			{ L"\x0001\x0526",L"\x004C" }, //( 𐔦 → L ) ELBASAN LETTER GHAMMA → LATIN CAPITAL LETTER L	# 

			{ L"\xFD3C",L"\x006C\x030B" }, //( ‎ﴼ‎ → l̋ ) ARABIC LIGATURE ALEF WITH FATHATAN FINAL FORM → LATIN SMALL LETTER L, COMBINING DOUBLE ACUTE ACCENT	# →‎اً‎→
			{ L"\xFD3D",L"\x006C\x030B" }, //( ‎ﴽ‎ → l̋ ) ARABIC LIGATURE ALEF WITH FATHATAN ISOLATED FORM → LATIN SMALL LETTER L, COMBINING DOUBLE ACUTE ACCENT	# →‎اً‎→

			{ L"\x0142",L"\x006C\x0338" }, //( ł → l̸ ) LATIN SMALL LETTER L WITH STROKE → LATIN SMALL LETTER L, COMBINING LONG SOLIDUS OVERLAY	# →l̷→

			{ L"\x0141",L"\x004C\x0338" }, //( Ł → L̸ ) LATIN CAPITAL LETTER L WITH STROKE → LATIN CAPITAL LETTER L, COMBINING LONG SOLIDUS OVERLAY	# →L̷→

			{ L"\x026D",L"\x006C\x0328" }, //( ɭ → l̨ ) LATIN SMALL LETTER L WITH RETROFLEX HOOK → LATIN SMALL LETTER L, COMBINING OGONEK	# →l̢→

			{ L"\x0197",L"\x006C\x0335" }, //( Ɨ → l̵ ) LATIN CAPITAL LETTER I WITH STROKE → LATIN SMALL LETTER L, COMBINING SHORT STROKE OVERLAY	# →ƚ→
			{ L"\x019A",L"\x006C\x0335" }, //( ƚ → l̵ ) LATIN SMALL LETTER L WITH BAR → LATIN SMALL LETTER L, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x026B",L"\x006C\x0334" }, //( ɫ → l̴ ) LATIN SMALL LETTER L WITH MIDDLE TILDE → LATIN SMALL LETTER L, COMBINING TILDE OVERLAY	# 

			{ L"\x0625",L"\x006C\x0655" }, //( ‎إ‎ → lٕ ) ARABIC LETTER ALEF WITH HAMZA BELOW → LATIN SMALL LETTER L, ARABIC HAMZA BELOW	# →‎ٳ‎→→‎اٟ‎→
			{ L"\xFE88",L"\x006C\x0655" }, //( ‎ﺈ‎ → lٕ ) ARABIC LETTER ALEF WITH HAMZA BELOW FINAL FORM → LATIN SMALL LETTER L, ARABIC HAMZA BELOW	# →‎إ‎→→‎ٳ‎→→‎اٟ‎→
			{ L"\xFE87",L"\x006C\x0655" }, //( ‎ﺇ‎ → lٕ ) ARABIC LETTER ALEF WITH HAMZA BELOW ISOLATED FORM → LATIN SMALL LETTER L, ARABIC HAMZA BELOW	# →‎إ‎→→‎ٳ‎→→‎اٟ‎→
			{ L"\x0673",L"\x006C\x0655" }, //( ‎ٳ‎ → lٕ ) ARABIC LETTER ALEF WITH WAVY HAMZA BELOW → LATIN SMALL LETTER L, ARABIC HAMZA BELOW	# →‎اٟ‎→

			{ L"\x0140",L"\x006C\x00B7" }, //( ŀ → l· ) LATIN SMALL LETTER L WITH MIDDLE DOT → LATIN SMALL LETTER L, MIDDLE DOT	# 
			{ L"\x013F",L"\x006C\x00B7" }, //( Ŀ → l· ) LATIN CAPITAL LETTER L WITH MIDDLE DOT → LATIN SMALL LETTER L, MIDDLE DOT	# →L·→→ᒪ·→→ᒪᐧ→→ᒷ→→1ᐧ→
			{ L"\x14B7",L"\x006C\x00B7" }, //( ᒷ → l· ) CANADIAN SYLLABICS WEST-CREE MWA → LATIN SMALL LETTER L, MIDDLE DOT	# →1ᐧ→

			{ L"\x0001\xF102",L"\x006C\x002C" }, //( 🄂 → l, ) DIGIT ONE COMMA → LATIN SMALL LETTER L, COMMA	# →1,→

			{ L"\x2488",L"\x006C\x002E" }, //( ⒈ → l. ) DIGIT ONE FULL STOP → LATIN SMALL LETTER L, FULL STOP	# →1.→

			{ L"\x05F1",L"\x006C\x0027" }, //( ‎ױ‎ → l' ) HEBREW LIGATURE YIDDISH VAV YOD → LATIN SMALL LETTER L, APOSTROPHE	# →‎וי‎→

			{ L"\x2493",L"\x006C\x0032\x002E" }, //( ⒓ → l2. ) NUMBER TWELVE FULL STOP → LATIN SMALL LETTER L, DIGIT TWO, FULL STOP	# →12.→

			{ L"\x33EB",L"\x006C\x0032\x65E5" }, //( ㏫ → l2日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TWELVE → LATIN SMALL LETTER L, DIGIT TWO, CJK UNIFIED IDEOGRAPH-65E5	# →12日→

			{ L"\x32CB",L"\x006C\x0032\x6708" }, //( ㋋ → l2月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DECEMBER → LATIN SMALL LETTER L, DIGIT TWO, CJK UNIFIED IDEOGRAPH-6708	# →12月→

			{ L"\x3364",L"\x006C\x0032\x70B9" }, //( ㍤ → l2点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TWELVE → LATIN SMALL LETTER L, DIGIT TWO, CJK UNIFIED IDEOGRAPH-70B9	# →12点→

			{ L"\x2494",L"\x006C\x0033\x002E" }, //( ⒔ → l3. ) NUMBER THIRTEEN FULL STOP → LATIN SMALL LETTER L, DIGIT THREE, FULL STOP	# →13.→

			{ L"\x33EC",L"\x006C\x0033\x65E5" }, //( ㏬ → l3日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY THIRTEEN → LATIN SMALL LETTER L, DIGIT THREE, CJK UNIFIED IDEOGRAPH-65E5	# →13日→

			{ L"\x3365",L"\x006C\x0033\x70B9" }, //( ㍥ → l3点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR THIRTEEN → LATIN SMALL LETTER L, DIGIT THREE, CJK UNIFIED IDEOGRAPH-70B9	# →13点→

			{ L"\x2495",L"\x006C\x0034\x002E" }, //( ⒕ → l4. ) NUMBER FOURTEEN FULL STOP → LATIN SMALL LETTER L, DIGIT FOUR, FULL STOP	# →14.→

			{ L"\x33ED",L"\x006C\x0034\x65E5" }, //( ㏭ → l4日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY FOURTEEN → LATIN SMALL LETTER L, DIGIT FOUR, CJK UNIFIED IDEOGRAPH-65E5	# →14日→

			{ L"\x3366",L"\x006C\x0034\x70B9" }, //( ㍦ → l4点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR FOURTEEN → LATIN SMALL LETTER L, DIGIT FOUR, CJK UNIFIED IDEOGRAPH-70B9	# →14点→

			{ L"\x2496",L"\x006C\x0035\x002E" }, //( ⒖ → l5. ) NUMBER FIFTEEN FULL STOP → LATIN SMALL LETTER L, DIGIT FIVE, FULL STOP	# →15.→

			{ L"\x33EE",L"\x006C\x0035\x65E5" }, //( ㏮ → l5日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY FIFTEEN → LATIN SMALL LETTER L, DIGIT FIVE, CJK UNIFIED IDEOGRAPH-65E5	# →15日→

			{ L"\x3367",L"\x006C\x0035\x70B9" }, //( ㍧ → l5点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR FIFTEEN → LATIN SMALL LETTER L, DIGIT FIVE, CJK UNIFIED IDEOGRAPH-70B9	# →15点→

			{ L"\x2497",L"\x006C\x0036\x002E" }, //( ⒗ → l6. ) NUMBER SIXTEEN FULL STOP → LATIN SMALL LETTER L, DIGIT SIX, FULL STOP	# →16.→

			{ L"\x33EF",L"\x006C\x0036\x65E5" }, //( ㏯ → l6日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY SIXTEEN → LATIN SMALL LETTER L, DIGIT SIX, CJK UNIFIED IDEOGRAPH-65E5	# →16日→

			{ L"\x3368",L"\x006C\x0036\x70B9" }, //( ㍨ → l6点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR SIXTEEN → LATIN SMALL LETTER L, DIGIT SIX, CJK UNIFIED IDEOGRAPH-70B9	# →16点→

			{ L"\x2498",L"\x006C\x0037\x002E" }, //( ⒘ → l7. ) NUMBER SEVENTEEN FULL STOP → LATIN SMALL LETTER L, DIGIT SEVEN, FULL STOP	# →17.→

			{ L"\x33F0",L"\x006C\x0037\x65E5" }, //( ㏰ → l7日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY SEVENTEEN → LATIN SMALL LETTER L, DIGIT SEVEN, CJK UNIFIED IDEOGRAPH-65E5	# →17日→

			{ L"\x3369",L"\x006C\x0037\x70B9" }, //( ㍩ → l7点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR SEVENTEEN → LATIN SMALL LETTER L, DIGIT SEVEN, CJK UNIFIED IDEOGRAPH-70B9	# →17点→

			{ L"\x2499",L"\x006C\x0038\x002E" }, //( ⒙ → l8. ) NUMBER EIGHTEEN FULL STOP → LATIN SMALL LETTER L, DIGIT EIGHT, FULL STOP	# →18.→

			{ L"\x33F1",L"\x006C\x0038\x65E5" }, //( ㏱ → l8日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY EIGHTEEN → LATIN SMALL LETTER L, DIGIT EIGHT, CJK UNIFIED IDEOGRAPH-65E5	# →18日→

			{ L"\x336A",L"\x006C\x0038\x70B9" }, //( ㍪ → l8点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR EIGHTEEN → LATIN SMALL LETTER L, DIGIT EIGHT, CJK UNIFIED IDEOGRAPH-70B9	# →18点→

			{ L"\x249A",L"\x006C\x0039\x002E" }, //( ⒚ → l9. ) NUMBER NINETEEN FULL STOP → LATIN SMALL LETTER L, DIGIT NINE, FULL STOP	# →19.→

			{ L"\x33F2",L"\x006C\x0039\x65E5" }, //( ㏲ → l9日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY NINETEEN → LATIN SMALL LETTER L, DIGIT NINE, CJK UNIFIED IDEOGRAPH-65E5	# →19日→

			{ L"\x336B",L"\x006C\x0039\x70B9" }, //( ㍫ → l9点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR NINETEEN → LATIN SMALL LETTER L, DIGIT NINE, CJK UNIFIED IDEOGRAPH-70B9	# →19点→

			{ L"\x01C9",L"\x006C\x006A" }, //( ǉ → lj ) LATIN SMALL LETTER LJ → LATIN SMALL LETTER L, LATIN SMALL LETTER J	# 

			{ L"\x0132",L"\x006C\x004A" }, //( Ĳ → lJ ) LATIN CAPITAL LIGATURE IJ → LATIN SMALL LETTER L, LATIN CAPITAL LETTER J	# →IJ→

			{ L"\x01C8",L"\x004C\x006A" }, //( ǈ → Lj ) LATIN CAPITAL LETTER L WITH SMALL LETTER J → LATIN CAPITAL LETTER L, LATIN SMALL LETTER J	# 

			{ L"\x01C7",L"\x004C\x004A" }, //( Ǉ → LJ ) LATIN CAPITAL LETTER LJ → LATIN CAPITAL LETTER L, LATIN CAPITAL LETTER J	# 

			{ L"\x2016",L"\x006C\x006C" }, //( ‖ → ll ) DOUBLE VERTICAL LINE → LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →∥→→||→
			{ L"\x2225",L"\x006C\x006C" }, //( ∥ → ll ) PARALLEL TO → LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →||→
			{ L"\x2161",L"\x006C\x006C" }, //( Ⅱ → ll ) ROMAN NUMERAL TWO → LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →II→
			{ L"\x01C1",L"\x006C\x006C" }, //( ǁ → ll ) LATIN LETTER LATERAL CLICK → LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →‖→→∥→→||→
			{ L"\x05F0",L"\x006C\x006C" }, //( ‎װ‎ → ll ) HEBREW LIGATURE YIDDISH DOUBLE VAV → LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →‎וו‎→

			{ L"\x2492",L"\x006C\x006C\x002E" }, //( ⒒ → ll. ) NUMBER ELEVEN FULL STOP → LATIN SMALL LETTER L, LATIN SMALL LETTER L, FULL STOP	# →11.→

			{ L"\x2162",L"\x006C\x006C\x006C" }, //( Ⅲ → lll ) ROMAN NUMERAL THREE → LATIN SMALL LETTER L, LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →III→

			{ L"\x33EA",L"\x006C\x006C\x65E5" }, //( ㏪ → ll日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY ELEVEN → LATIN SMALL LETTER L, LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-65E5	# →11日→

			{ L"\x32CA",L"\x006C\x006C\x6708" }, //( ㋊ → ll月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR NOVEMBER → LATIN SMALL LETTER L, LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-6708	# →11月→

			{ L"\x3363",L"\x006C\x006C\x70B9" }, //( ㍣ → ll点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR ELEVEN → LATIN SMALL LETTER L, LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-70B9	# →11点→

			{ L"\x042E",L"\x006C\x004F" }, //( Ю → lO ) CYRILLIC CAPITAL LETTER YU → LATIN SMALL LETTER L, LATIN CAPITAL LETTER O	# →IO→

			{ L"\x2491",L"\x006C\x004F\x002E" }, //( ⒑ → lO. ) NUMBER TEN FULL STOP → LATIN SMALL LETTER L, LATIN CAPITAL LETTER O, FULL STOP	# →10.→

			{ L"\x33E9",L"\x006C\x004F\x65E5" }, //( ㏩ → lO日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY TEN → LATIN SMALL LETTER L, LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-65E5	# →10日→

			{ L"\x32C9",L"\x006C\x004F\x6708" }, //( ㋉ → lO月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR OCTOBER → LATIN SMALL LETTER L, LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-6708	# →10月→

			{ L"\x3362",L"\x006C\x004F\x70B9" }, //( ㍢ → lO点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR TEN → LATIN SMALL LETTER L, LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-70B9	# →10点→

			{ L"\x02AA",L"\x006C\x0073" }, //( ʪ → ls ) LATIN SMALL LETTER LS DIGRAPH → LATIN SMALL LETTER L, LATIN SMALL LETTER S	# 

			{ L"\x20B6",L"\x006C\x0074" }, //( ₶ → lt ) LIVRE TOURNOIS SIGN → LATIN SMALL LETTER L, LATIN SMALL LETTER T	# 

			{ L"\x2163",L"\x006C\x0056" }, //( Ⅳ → lV ) ROMAN NUMERAL FOUR → LATIN SMALL LETTER L, LATIN CAPITAL LETTER V	# →IV→

			{ L"\x2168",L"\x006C\x0058" }, //( Ⅸ → lX ) ROMAN NUMERAL NINE → LATIN SMALL LETTER L, LATIN CAPITAL LETTER X	# →IX→

			{ L"\x026E",L"\x006C\x021D" }, //( ɮ → lȝ ) LATIN SMALL LETTER LEZH → LATIN SMALL LETTER L, LATIN SMALL LETTER YOGH	# →lʒ→

			{ L"\x02AB",L"\x006C\x007A" }, //( ʫ → lz ) LATIN SMALL LETTER LZ DIGRAPH → LATIN SMALL LETTER L, LATIN SMALL LETTER Z	# 

			{ L"\x0623",L"\x006C\x0674" }, //( ‎أ‎ → ‎lٴ‎ ) ARABIC LETTER ALEF WITH HAMZA ABOVE → LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎ٵ‎→→‎اٴ‎→
			{ L"\xFE84",L"\x006C\x0674" }, //( ‎ﺄ‎ → ‎lٴ‎ ) ARABIC LETTER ALEF WITH HAMZA ABOVE FINAL FORM → LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎أ‎→→‎ٵ‎→→‎اٴ‎→
			{ L"\xFE83",L"\x006C\x0674" }, //( ‎ﺃ‎ → ‎lٴ‎ ) ARABIC LETTER ALEF WITH HAMZA ABOVE ISOLATED FORM → LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎ٵ‎→→‎اٴ‎→
			{ L"\x0672",L"\x006C\x0674" }, //( ‎ٲ‎ → ‎lٴ‎ ) ARABIC LETTER ALEF WITH WAVY HAMZA ABOVE → LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎أ‎→→‎ٵ‎→→‎اٴ‎→
			{ L"\x0675",L"\x006C\x0674" }, //( ‎ٵ‎ → ‎lٴ‎ ) ARABIC LETTER HIGH HAMZA ALEF → LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎اٴ‎→

			{ L"\xFDF3",L"\x006C\x0643\x0628\x0631" }, //( ‎ﷳ‎ → ‎lكبر‎ ) ARABIC LIGATURE AKBAR ISOLATED FORM → LATIN SMALL LETTER L, ARABIC LETTER KAF, ARABIC LETTER BEH, ARABIC LETTER REH	# →‎اكبر‎→

			{ L"\xFDF2",L"\x006C\x0644\x0644\x0651\x0670\x006F" }, //( ‎ﷲ‎ → ‎lللّٰo‎ ) ARABIC LIGATURE ALLAH ISOLATED FORM → LATIN SMALL LETTER L, ARABIC LETTER LAM, ARABIC LETTER LAM, ARABIC SHADDA, ARABIC LETTER SUPERSCRIPT ALEF, LATIN SMALL LETTER O	# →‎اللّٰه‎→

			{ L"\x33E0",L"\x006C\x65E5" }, //( ㏠ → l日 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR DAY ONE → LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-65E5	# →1日→

			{ L"\x32C0",L"\x006C\x6708" }, //( ㋀ → l月 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR JANUARY → LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-6708	# →1月→

			{ L"\x3359",L"\x006C\x70B9" }, //( ㍙ → l点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR ONE → LATIN SMALL LETTER L, CJK UNIFIED IDEOGRAPH-70B9	# →1点→

			{ L"\x2CD1",L"\x029F" }, //( ⳑ → ʟ ) COPTIC SMALL LETTER L-SHAPED HA → LATIN LETTER SMALL CAPITAL L	# 
			{ L"\x0001\x0443",L"\x029F" }, //( 𐑃 → ʟ ) DESERET SMALL LETTER ETH → LATIN LETTER SMALL CAPITAL L	# 

			{ L"\xFF2D",L"\x004D" }, //( Ｍ → M ) FULLWIDTH LATIN CAPITAL LETTER M → LATIN CAPITAL LETTER M	# →Μ→
			{ L"\x216F",L"\x004D" }, //( Ⅿ → M ) ROMAN NUMERAL ONE THOUSAND → LATIN CAPITAL LETTER M	# 
			{ L"\x2133",L"\x004D" }, //( ℳ → M ) SCRIPT CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD40C",L"\x004D" }, //( 𝐌 → M ) MATHEMATICAL BOLD CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD440",L"\x004D" }, //( 𝑀 → M ) MATHEMATICAL ITALIC CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD474",L"\x004D" }, //( 𝑴 → M ) MATHEMATICAL BOLD ITALIC CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD4DC",L"\x004D" }, //( 𝓜 → M ) MATHEMATICAL BOLD SCRIPT CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD510",L"\x004D" }, //( 𝔐 → M ) MATHEMATICAL FRAKTUR CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD544",L"\x004D" }, //( 𝕄 → M ) MATHEMATICAL DOUBLE-STRUCK CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD578",L"\x004D" }, //( 𝕸 → M ) MATHEMATICAL BOLD FRAKTUR CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD5AC",L"\x004D" }, //( 𝖬 → M ) MATHEMATICAL SANS-SERIF CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD5E0",L"\x004D" }, //( 𝗠 → M ) MATHEMATICAL SANS-SERIF BOLD CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD614",L"\x004D" }, //( 𝘔 → M ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD648",L"\x004D" }, //( 𝙈 → M ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD67C",L"\x004D" }, //( 𝙼 → M ) MATHEMATICAL MONOSPACE CAPITAL M → LATIN CAPITAL LETTER M	# 
			{ L"\x039C",L"\x004D" }, //( Μ → M ) GREEK CAPITAL LETTER MU → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\xD6B3",L"\x004D" }, //( 𝚳 → M ) MATHEMATICAL BOLD CAPITAL MU → LATIN CAPITAL LETTER M	# →𝐌→
			{ L"\x0001\xD6ED",L"\x004D" }, //( 𝛭 → M ) MATHEMATICAL ITALIC CAPITAL MU → LATIN CAPITAL LETTER M	# →𝑀→
			{ L"\x0001\xD727",L"\x004D" }, //( 𝜧 → M ) MATHEMATICAL BOLD ITALIC CAPITAL MU → LATIN CAPITAL LETTER M	# →𝑴→
			{ L"\x0001\xD761",L"\x004D" }, //( 𝝡 → M ) MATHEMATICAL SANS-SERIF BOLD CAPITAL MU → LATIN CAPITAL LETTER M	# →Μ→
			{ L"\x0001\xD79B",L"\x004D" }, //( 𝞛 → M ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL MU → LATIN CAPITAL LETTER M	# →Μ→
			{ L"\x03FA",L"\x004D" }, //( Ϻ → M ) GREEK CAPITAL LETTER SAN → LATIN CAPITAL LETTER M	# 
			{ L"\x2C98",L"\x004D" }, //( Ⲙ → M ) COPTIC CAPITAL LETTER MI → LATIN CAPITAL LETTER M	# 
			{ L"\x041C",L"\x004D" }, //( М → M ) CYRILLIC CAPITAL LETTER EM → LATIN CAPITAL LETTER M	# 
			{ L"\x13B7",L"\x004D" }, //( Ꮇ → M ) CHEROKEE LETTER LU → LATIN CAPITAL LETTER M	# 
			{ L"\x15F0",L"\x004D" }, //( ᗰ → M ) CANADIAN SYLLABICS CARRIER GO → LATIN CAPITAL LETTER M	# 
			{ L"\x16D6",L"\x004D" }, //( ᛖ → M ) RUNIC LETTER EHWAZ EH E → LATIN CAPITAL LETTER M	# 
			{ L"\xA4DF",L"\x004D" }, //( ꓟ → M ) LISU LETTER MA → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\x02B0",L"\x004D" }, //( 𐊰 → M ) CARIAN LETTER S → LATIN CAPITAL LETTER M	# 
			{ L"\x0001\x0311",L"\x004D" }, //( 𐌑 → M ) OLD ITALIC LETTER SHE → LATIN CAPITAL LETTER M	# 

			{ L"\x04CD",L"\x004D\x0326" }, //( Ӎ → M̦ ) CYRILLIC CAPITAL LETTER EM WITH TAIL → LATIN CAPITAL LETTER M, COMBINING COMMA BELOW	# →М̡→

			{ L"\x0001\xF76B",L"\x004D\x0042" }, //( 🝫 → MB ) ALCHEMICAL SYMBOL FOR BATH OF MARY → LATIN CAPITAL LETTER M, LATIN CAPITAL LETTER B	# 

			{ L"\x2DE8",L"\x1DDF" }, //( ⷨ → ᷟ ) COMBINING CYRILLIC LETTER EM → COMBINING LATIN LETTER SMALL CAPITAL M	# 

			{ L"\x0001\xD427",L"\x006E" }, //( 𝐧 → n ) MATHEMATICAL BOLD SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD45B",L"\x006E" }, //( 𝑛 → n ) MATHEMATICAL ITALIC SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD48F",L"\x006E" }, //( 𝒏 → n ) MATHEMATICAL BOLD ITALIC SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD4C3",L"\x006E" }, //( 𝓃 → n ) MATHEMATICAL SCRIPT SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD4F7",L"\x006E" }, //( 𝓷 → n ) MATHEMATICAL BOLD SCRIPT SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD52B",L"\x006E" }, //( 𝔫 → n ) MATHEMATICAL FRAKTUR SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD55F",L"\x006E" }, //( 𝕟 → n ) MATHEMATICAL DOUBLE-STRUCK SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD593",L"\x006E" }, //( 𝖓 → n ) MATHEMATICAL BOLD FRAKTUR SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD5C7",L"\x006E" }, //( 𝗇 → n ) MATHEMATICAL SANS-SERIF SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD5FB",L"\x006E" }, //( 𝗻 → n ) MATHEMATICAL SANS-SERIF BOLD SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD62F",L"\x006E" }, //( 𝘯 → n ) MATHEMATICAL SANS-SERIF ITALIC SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD663",L"\x006E" }, //( 𝙣 → n ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x0001\xD697",L"\x006E" }, //( 𝚗 → n ) MATHEMATICAL MONOSPACE SMALL N → LATIN SMALL LETTER N	# 
			{ L"\x03C0",L"\x006E" }, //( π → n ) GREEK SMALL LETTER PI → LATIN SMALL LETTER N	# 
			{ L"\x03D6",L"\x006E" }, //( ϖ → n ) GREEK PI SYMBOL → LATIN SMALL LETTER N	# →π→
			{ L"\x213C",L"\x006E" }, //( ℼ → n ) DOUBLE-STRUCK SMALL PI → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD6D1",L"\x006E" }, //( 𝛑 → n ) MATHEMATICAL BOLD SMALL PI → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD6E1",L"\x006E" }, //( 𝛡 → n ) MATHEMATICAL BOLD PI SYMBOL → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD70B",L"\x006E" }, //( 𝜋 → n ) MATHEMATICAL ITALIC SMALL PI → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD71B",L"\x006E" }, //( 𝜛 → n ) MATHEMATICAL ITALIC PI SYMBOL → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD745",L"\x006E" }, //( 𝝅 → n ) MATHEMATICAL BOLD ITALIC SMALL PI → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD755",L"\x006E" }, //( 𝝕 → n ) MATHEMATICAL BOLD ITALIC PI SYMBOL → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD77F",L"\x006E" }, //( 𝝿 → n ) MATHEMATICAL SANS-SERIF BOLD SMALL PI → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD78F",L"\x006E" }, //( 𝞏 → n ) MATHEMATICAL SANS-SERIF BOLD PI SYMBOL → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD7B9",L"\x006E" }, //( 𝞹 → n ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL PI → LATIN SMALL LETTER N	# →π→
			{ L"\x0001\xD7C9",L"\x006E" }, //( 𝟉 → n ) MATHEMATICAL SANS-SERIF BOLD ITALIC PI SYMBOL → LATIN SMALL LETTER N	# →π→
			{ L"\x1D28",L"\x006E" }, //( ᴨ → n ) GREEK LETTER SMALL CAPITAL PI → LATIN SMALL LETTER N	# →п→
			{ L"\x043F",L"\x006E" }, //( п → n ) CYRILLIC SMALL LETTER PE → LATIN SMALL LETTER N	# 
			{ L"\x0578",L"\x006E" }, //( ո → n ) ARMENIAN SMALL LETTER VO → LATIN SMALL LETTER N	# 
			{ L"\x057C",L"\x006E" }, //( ռ → n ) ARMENIAN SMALL LETTER RA → LATIN SMALL LETTER N	# 

			{ L"\xFF2E",L"\x004E" }, //( Ｎ → N ) FULLWIDTH LATIN CAPITAL LETTER N → LATIN CAPITAL LETTER N	# →Ν→
			{ L"\x2115",L"\x004E" }, //( ℕ → N ) DOUBLE-STRUCK CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD40D",L"\x004E" }, //( 𝐍 → N ) MATHEMATICAL BOLD CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD441",L"\x004E" }, //( 𝑁 → N ) MATHEMATICAL ITALIC CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD475",L"\x004E" }, //( 𝑵 → N ) MATHEMATICAL BOLD ITALIC CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD4A9",L"\x004E" }, //( 𝒩 → N ) MATHEMATICAL SCRIPT CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD4DD",L"\x004E" }, //( 𝓝 → N ) MATHEMATICAL BOLD SCRIPT CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD511",L"\x004E" }, //( 𝔑 → N ) MATHEMATICAL FRAKTUR CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD579",L"\x004E" }, //( 𝕹 → N ) MATHEMATICAL BOLD FRAKTUR CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD5AD",L"\x004E" }, //( 𝖭 → N ) MATHEMATICAL SANS-SERIF CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD5E1",L"\x004E" }, //( 𝗡 → N ) MATHEMATICAL SANS-SERIF BOLD CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD615",L"\x004E" }, //( 𝘕 → N ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD649",L"\x004E" }, //( 𝙉 → N ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD67D",L"\x004E" }, //( 𝙽 → N ) MATHEMATICAL MONOSPACE CAPITAL N → LATIN CAPITAL LETTER N	# 
			{ L"\x039D",L"\x004E" }, //( Ν → N ) GREEK CAPITAL LETTER NU → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\xD6B4",L"\x004E" }, //( 𝚴 → N ) MATHEMATICAL BOLD CAPITAL NU → LATIN CAPITAL LETTER N	# →𝐍→
			{ L"\x0001\xD6EE",L"\x004E" }, //( 𝛮 → N ) MATHEMATICAL ITALIC CAPITAL NU → LATIN CAPITAL LETTER N	# →𝑁→
			{ L"\x0001\xD728",L"\x004E" }, //( 𝜨 → N ) MATHEMATICAL BOLD ITALIC CAPITAL NU → LATIN CAPITAL LETTER N	# →𝑵→
			{ L"\x0001\xD762",L"\x004E" }, //( 𝝢 → N ) MATHEMATICAL SANS-SERIF BOLD CAPITAL NU → LATIN CAPITAL LETTER N	# →Ν→
			{ L"\x0001\xD79C",L"\x004E" }, //( 𝞜 → N ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL NU → LATIN CAPITAL LETTER N	# →Ν→
			{ L"\x2C9A",L"\x004E" }, //( Ⲛ → N ) COPTIC CAPITAL LETTER NI → LATIN CAPITAL LETTER N	# 
			{ L"\xA4E0",L"\x004E" }, //( ꓠ → N ) LISU LETTER NA → LATIN CAPITAL LETTER N	# 
			{ L"\x0001\x0513",L"\x004E" }, //( 𐔓 → N ) ELBASAN LETTER NE → LATIN CAPITAL LETTER N	# 

			{ L"\x0273",L"\x006E\x0328" }, //( ɳ → n̨ ) LATIN SMALL LETTER N WITH RETROFLEX HOOK → LATIN SMALL LETTER N, COMBINING OGONEK	# →n̢→

			{ L"\x019E",L"\x006E\x0329" }, //( ƞ → n̩ ) LATIN SMALL LETTER N WITH LONG RIGHT LEG → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# 
			{ L"\x03B7",L"\x006E\x0329" }, //( η → n̩ ) GREEK SMALL LETTER ETA → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# →ƞ→
			{ L"\x0001\xD6C8",L"\x006E\x0329" }, //( 𝛈 → n̩ ) MATHEMATICAL BOLD SMALL ETA → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# →η→→ƞ→
			{ L"\x0001\xD702",L"\x006E\x0329" }, //( 𝜂 → n̩ ) MATHEMATICAL ITALIC SMALL ETA → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# →η→→ƞ→
			{ L"\x0001\xD73C",L"\x006E\x0329" }, //( 𝜼 → n̩ ) MATHEMATICAL BOLD ITALIC SMALL ETA → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# →η→→ƞ→
			{ L"\x0001\xD776",L"\x006E\x0329" }, //( 𝝶 → n̩ ) MATHEMATICAL SANS-SERIF BOLD SMALL ETA → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# →η→→ƞ→
			{ L"\x0001\xD7B0",L"\x006E\x0329" }, //( 𝞰 → n̩ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL ETA → LATIN SMALL LETTER N, COMBINING VERTICAL LINE BELOW	# →η→→ƞ→

			{ L"\x019D",L"\x004E\x0326" }, //( Ɲ → N̦ ) LATIN CAPITAL LETTER N WITH LEFT HOOK → LATIN CAPITAL LETTER N, COMBINING COMMA BELOW	# →N̡→

			{ L"\x1D70",L"\x006E\x0334" }, //( ᵰ → n̴ ) LATIN SMALL LETTER N WITH MIDDLE TILDE → LATIN SMALL LETTER N, COMBINING TILDE OVERLAY	# 

			{ L"\x01CC",L"\x006E\x006A" }, //( ǌ → nj ) LATIN SMALL LETTER NJ → LATIN SMALL LETTER N, LATIN SMALL LETTER J	# 

			{ L"\x01CB",L"\x004E\x006A" }, //( ǋ → Nj ) LATIN CAPITAL LETTER N WITH SMALL LETTER J → LATIN CAPITAL LETTER N, LATIN SMALL LETTER J	# 

			{ L"\x01CA",L"\x004E\x004A" }, //( Ǌ → NJ ) LATIN CAPITAL LETTER NJ → LATIN CAPITAL LETTER N, LATIN CAPITAL LETTER J	# 

			{ L"\x2116",L"\x004E\x006F" }, //( № → No ) NUMERO SIGN → LATIN CAPITAL LETTER N, LATIN SMALL LETTER O	# 

			{ L"\x0377",L"\x1D0E" }, //( ͷ → ᴎ ) GREEK SMALL LETTER PAMPHYLIAN DIGAMMA → LATIN LETTER SMALL CAPITAL REVERSED N	# →и→
			{ L"\x0438",L"\x1D0E" }, //( и → ᴎ ) CYRILLIC SMALL LETTER I → LATIN LETTER SMALL CAPITAL REVERSED N	# 
			{ L"\x0001\x044D",L"\x1D0E" }, //( 𐑍 → ᴎ ) DESERET SMALL LETTER ENG → LATIN LETTER SMALL CAPITAL REVERSED N	# →и→

			{ L"\x0146",L"\x0272" }, //( ņ → ɲ ) LATIN SMALL LETTER N WITH CEDILLA → LATIN SMALL LETTER N WITH LEFT HOOK	# 

			{ L"\x0C02",L"\x006F" }, //( ం → o ) TELUGU SIGN ANUSVARA → LATIN SMALL LETTER O	# 
			{ L"\x0C82",L"\x006F" }, //( ಂ → o ) KANNADA SIGN ANUSVARA → LATIN SMALL LETTER O	# 
			{ L"\x0D02",L"\x006F" }, //( ം → o ) MALAYALAM SIGN ANUSVARA → LATIN SMALL LETTER O	# 
			{ L"\x0D82",L"\x006F" }, //( ං → o ) SINHALA SIGN ANUSVARAYA → LATIN SMALL LETTER O	# 
			{ L"\x0966",L"\x006F" }, //( ० → o ) DEVANAGARI DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0A66",L"\x006F" }, //( ੦ → o ) GURMUKHI DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0AE6",L"\x006F" }, //( ૦ → o ) GUJARATI DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0BE6",L"\x006F" }, //( ௦ → o ) TAMIL DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0C66",L"\x006F" }, //( ౦ → o ) TELUGU DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0CE6",L"\x006F" }, //( ೦ → o ) KANNADA DIGIT ZERO → LATIN SMALL LETTER O	# →౦→
			{ L"\x0D66",L"\x006F" }, //( ൦ → o ) MALAYALAM DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0E50",L"\x006F" }, //( ๐ → o ) THAI DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0ED0",L"\x006F" }, //( ໐ → o ) LAO DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x1040",L"\x006F" }, //( ၀ → o ) MYANMAR DIGIT ZERO → LATIN SMALL LETTER O	# 
			{ L"\x0665",L"\x006F" }, //( ‎٥‎ → o ) ARABIC-INDIC DIGIT FIVE → LATIN SMALL LETTER O	# 
			{ L"\x06F5",L"\x006F" }, //( ۵ → o ) EXTENDED ARABIC-INDIC DIGIT FIVE → LATIN SMALL LETTER O	# →‎٥‎→
			{ L"\xFF4F",L"\x006F" }, //( ｏ → o ) FULLWIDTH LATIN SMALL LETTER O → LATIN SMALL LETTER O	# →о→
			{ L"\x2134",L"\x006F" }, //( ℴ → o ) SCRIPT SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD428",L"\x006F" }, //( 𝐨 → o ) MATHEMATICAL BOLD SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD45C",L"\x006F" }, //( 𝑜 → o ) MATHEMATICAL ITALIC SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD490",L"\x006F" }, //( 𝒐 → o ) MATHEMATICAL BOLD ITALIC SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD4F8",L"\x006F" }, //( 𝓸 → o ) MATHEMATICAL BOLD SCRIPT SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD52C",L"\x006F" }, //( 𝔬 → o ) MATHEMATICAL FRAKTUR SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD560",L"\x006F" }, //( 𝕠 → o ) MATHEMATICAL DOUBLE-STRUCK SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD594",L"\x006F" }, //( 𝖔 → o ) MATHEMATICAL BOLD FRAKTUR SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD5C8",L"\x006F" }, //( 𝗈 → o ) MATHEMATICAL SANS-SERIF SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD5FC",L"\x006F" }, //( 𝗼 → o ) MATHEMATICAL SANS-SERIF BOLD SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD630",L"\x006F" }, //( 𝘰 → o ) MATHEMATICAL SANS-SERIF ITALIC SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD664",L"\x006F" }, //( 𝙤 → o ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD698",L"\x006F" }, //( 𝚘 → o ) MATHEMATICAL MONOSPACE SMALL O → LATIN SMALL LETTER O	# 
			{ L"\x1D0F",L"\x006F" }, //( ᴏ → o ) LATIN LETTER SMALL CAPITAL O → LATIN SMALL LETTER O	# 
			{ L"\x1D11",L"\x006F" }, //( ᴑ → o ) LATIN SMALL LETTER SIDEWAYS O → LATIN SMALL LETTER O	# 
			{ L"\xAB3D",L"\x006F" }, //( ꬽ → o ) LATIN SMALL LETTER BLACKLETTER O → LATIN SMALL LETTER O	# 
			{ L"\x03BF",L"\x006F" }, //( ο → o ) GREEK SMALL LETTER OMICRON → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD6D0",L"\x006F" }, //( 𝛐 → o ) MATHEMATICAL BOLD SMALL OMICRON → LATIN SMALL LETTER O	# →𝐨→
			{ L"\x0001\xD70A",L"\x006F" }, //( 𝜊 → o ) MATHEMATICAL ITALIC SMALL OMICRON → LATIN SMALL LETTER O	# →𝑜→
			{ L"\x0001\xD744",L"\x006F" }, //( 𝝄 → o ) MATHEMATICAL BOLD ITALIC SMALL OMICRON → LATIN SMALL LETTER O	# →𝒐→
			{ L"\x0001\xD77E",L"\x006F" }, //( 𝝾 → o ) MATHEMATICAL SANS-SERIF BOLD SMALL OMICRON → LATIN SMALL LETTER O	# →ο→
			{ L"\x0001\xD7B8",L"\x006F" }, //( 𝞸 → o ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL OMICRON → LATIN SMALL LETTER O	# →ο→
			{ L"\x03C3",L"\x006F" }, //( σ → o ) GREEK SMALL LETTER SIGMA → LATIN SMALL LETTER O	# 
			{ L"\x0001\xD6D4",L"\x006F" }, //( 𝛔 → o ) MATHEMATICAL BOLD SMALL SIGMA → LATIN SMALL LETTER O	# →σ→
			{ L"\x0001\xD70E",L"\x006F" }, //( 𝜎 → o ) MATHEMATICAL ITALIC SMALL SIGMA → LATIN SMALL LETTER O	# →σ→
			{ L"\x0001\xD748",L"\x006F" }, //( 𝝈 → o ) MATHEMATICAL BOLD ITALIC SMALL SIGMA → LATIN SMALL LETTER O	# →σ→
			{ L"\x0001\xD782",L"\x006F" }, //( 𝞂 → o ) MATHEMATICAL SANS-SERIF BOLD SMALL SIGMA → LATIN SMALL LETTER O	# →σ→
			{ L"\x0001\xD7BC",L"\x006F" }, //( 𝞼 → o ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL SIGMA → LATIN SMALL LETTER O	# →σ→
			{ L"\x2C9F",L"\x006F" }, //( ⲟ → o ) COPTIC SMALL LETTER O → LATIN SMALL LETTER O	# 
			{ L"\x043E",L"\x006F" }, //( о → o ) CYRILLIC SMALL LETTER O → LATIN SMALL LETTER O	# 
			{ L"\x10FF",L"\x006F" }, //( ჿ → o ) GEORGIAN LETTER LABIAL SIGN → LATIN SMALL LETTER O	# 
			{ L"\x0585",L"\x006F" }, //( օ → o ) ARMENIAN SMALL LETTER OH → LATIN SMALL LETTER O	# 
			{ L"\x05E1",L"\x006F" }, //( ‎ס‎ → o ) HEBREW LETTER SAMEKH → LATIN SMALL LETTER O	# 
			{ L"\x0647",L"\x006F" }, //( ‎ه‎ → o ) ARABIC LETTER HEH → LATIN SMALL LETTER O	# 
			{ L"\x0001\xEE24",L"\x006F" }, //( ‎𞸤‎ → o ) ARABIC MATHEMATICAL INITIAL HEH → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\x0001\xEE64",L"\x006F" }, //( ‎𞹤‎ → o ) ARABIC MATHEMATICAL STRETCHED HEH → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\x0001\xEE84",L"\x006F" }, //( ‎𞺄‎ → o ) ARABIC MATHEMATICAL LOOPED HEH → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\xFEEB",L"\x006F" }, //( ‎ﻫ‎ → o ) ARABIC LETTER HEH INITIAL FORM → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\xFEEC",L"\x006F" }, //( ‎ﻬ‎ → o ) ARABIC LETTER HEH MEDIAL FORM → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\xFEEA",L"\x006F" }, //( ‎ﻪ‎ → o ) ARABIC LETTER HEH FINAL FORM → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\xFEE9",L"\x006F" }, //( ‎ﻩ‎ → o ) ARABIC LETTER HEH ISOLATED FORM → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\x06BE",L"\x006F" }, //( ‎ھ‎ → o ) ARABIC LETTER HEH DOACHASHMEE → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\xFBAC",L"\x006F" }, //( ‎ﮬ‎ → o ) ARABIC LETTER HEH DOACHASHMEE INITIAL FORM → LATIN SMALL LETTER O	# →‎ﻫ‎→→‎ه‎→
			{ L"\xFBAD",L"\x006F" }, //( ‎ﮭ‎ → o ) ARABIC LETTER HEH DOACHASHMEE MEDIAL FORM → LATIN SMALL LETTER O	# →‎ﻬ‎→→‎ه‎→
			{ L"\xFBAB",L"\x006F" }, //( ‎ﮫ‎ → o ) ARABIC LETTER HEH DOACHASHMEE FINAL FORM → LATIN SMALL LETTER O	# →‎ﻪ‎→→‎ه‎→
			{ L"\xFBAA",L"\x006F" }, //( ‎ﮪ‎ → o ) ARABIC LETTER HEH DOACHASHMEE ISOLATED FORM → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\x06C1",L"\x006F" }, //( ‎ہ‎ → o ) ARABIC LETTER HEH GOAL → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\xFBA8",L"\x006F" }, //( ‎ﮨ‎ → o ) ARABIC LETTER HEH GOAL INITIAL FORM → LATIN SMALL LETTER O	# →‎ہ‎→→‎ه‎→
			{ L"\xFBA9",L"\x006F" }, //( ‎ﮩ‎ → o ) ARABIC LETTER HEH GOAL MEDIAL FORM → LATIN SMALL LETTER O	# →‎ہ‎→→‎ه‎→
			{ L"\xFBA7",L"\x006F" }, //( ‎ﮧ‎ → o ) ARABIC LETTER HEH GOAL FINAL FORM → LATIN SMALL LETTER O	# →‎ہ‎→→‎ه‎→
			{ L"\xFBA6",L"\x006F" }, //( ‎ﮦ‎ → o ) ARABIC LETTER HEH GOAL ISOLATED FORM → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\x06D5",L"\x006F" }, //( ‎ە‎ → o ) ARABIC LETTER AE → LATIN SMALL LETTER O	# →‎ه‎→
			{ L"\x101D",L"\x006F" }, //( ဝ → o ) MYANMAR LETTER WA → LATIN SMALL LETTER O	# 
			{ L"\x0001\x18C8",L"\x006F" }, //( 𑣈 → o ) WARANG CITI SMALL LETTER E → LATIN SMALL LETTER O	# 
			{ L"\x0001\x18D7",L"\x006F" }, //( 𑣗 → o ) WARANG CITI SMALL LETTER BU → LATIN SMALL LETTER O	# 
			{ L"\x0001\x042C",L"\x006F" }, //( 𐐬 → o ) DESERET SMALL LETTER LONG O → LATIN SMALL LETTER O	# 

			{ L"\x0030",L"\x004F" }, //( 0 → O ) DIGIT ZERO → LATIN CAPITAL LETTER O	# 
			{ L"\x07C0",L"\x004F" }, //( ‎߀‎ → O ) NKO DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x09E6",L"\x004F" }, //( ০ → O ) BENGALI DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x0B66",L"\x004F" }, //( ୦ → O ) ORIYA DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x3007",L"\x004F" }, //( 〇 → O ) IDEOGRAPHIC NUMBER ZERO → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\x14D0",L"\x004F" }, //( 𑓐 → O ) TIRHUTA DIGIT ZERO → LATIN CAPITAL LETTER O	# →০→→0→
			{ L"\x0001\x18E0",L"\x004F" }, //( 𑣠 → O ) WARANG CITI DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x0001\xD7CE",L"\x004F" }, //( 𝟎 → O ) MATHEMATICAL BOLD DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x0001\xD7D8",L"\x004F" }, //( 𝟘 → O ) MATHEMATICAL DOUBLE-STRUCK DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x0001\xD7E2",L"\x004F" }, //( 𝟢 → O ) MATHEMATICAL SANS-SERIF DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x0001\xD7EC",L"\x004F" }, //( 𝟬 → O ) MATHEMATICAL SANS-SERIF BOLD DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\x0001\xD7F6",L"\x004F" }, //( 𝟶 → O ) MATHEMATICAL MONOSPACE DIGIT ZERO → LATIN CAPITAL LETTER O	# →0→
			{ L"\xFF2F",L"\x004F" }, //( Ｏ → O ) FULLWIDTH LATIN CAPITAL LETTER O → LATIN CAPITAL LETTER O	# →О→
			{ L"\x0001\xD40E",L"\x004F" }, //( 𝐎 → O ) MATHEMATICAL BOLD CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD442",L"\x004F" }, //( 𝑂 → O ) MATHEMATICAL ITALIC CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD476",L"\x004F" }, //( 𝑶 → O ) MATHEMATICAL BOLD ITALIC CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD4AA",L"\x004F" }, //( 𝒪 → O ) MATHEMATICAL SCRIPT CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD4DE",L"\x004F" }, //( 𝓞 → O ) MATHEMATICAL BOLD SCRIPT CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD512",L"\x004F" }, //( 𝔒 → O ) MATHEMATICAL FRAKTUR CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD546",L"\x004F" }, //( 𝕆 → O ) MATHEMATICAL DOUBLE-STRUCK CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD57A",L"\x004F" }, //( 𝕺 → O ) MATHEMATICAL BOLD FRAKTUR CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD5AE",L"\x004F" }, //( 𝖮 → O ) MATHEMATICAL SANS-SERIF CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD5E2",L"\x004F" }, //( 𝗢 → O ) MATHEMATICAL SANS-SERIF BOLD CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD616",L"\x004F" }, //( 𝘖 → O ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD64A",L"\x004F" }, //( 𝙊 → O ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD67E",L"\x004F" }, //( 𝙾 → O ) MATHEMATICAL MONOSPACE CAPITAL O → LATIN CAPITAL LETTER O	# 
			{ L"\x039F",L"\x004F" }, //( Ο → O ) GREEK CAPITAL LETTER OMICRON → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\xD6B6",L"\x004F" }, //( 𝚶 → O ) MATHEMATICAL BOLD CAPITAL OMICRON → LATIN CAPITAL LETTER O	# →𝐎→
			{ L"\x0001\xD6F0",L"\x004F" }, //( 𝛰 → O ) MATHEMATICAL ITALIC CAPITAL OMICRON → LATIN CAPITAL LETTER O	# →𝑂→
			{ L"\x0001\xD72A",L"\x004F" }, //( 𝜪 → O ) MATHEMATICAL BOLD ITALIC CAPITAL OMICRON → LATIN CAPITAL LETTER O	# →𝑶→
			{ L"\x0001\xD764",L"\x004F" }, //( 𝝤 → O ) MATHEMATICAL SANS-SERIF BOLD CAPITAL OMICRON → LATIN CAPITAL LETTER O	# →Ο→
			{ L"\x0001\xD79E",L"\x004F" }, //( 𝞞 → O ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL OMICRON → LATIN CAPITAL LETTER O	# →Ο→
			{ L"\x2C9E",L"\x004F" }, //( Ⲟ → O ) COPTIC CAPITAL LETTER O → LATIN CAPITAL LETTER O	# 
			{ L"\x041E",L"\x004F" }, //( О → O ) CYRILLIC CAPITAL LETTER O → LATIN CAPITAL LETTER O	# 
			{ L"\x0555",L"\x004F" }, //( Օ → O ) ARMENIAN CAPITAL LETTER OH → LATIN CAPITAL LETTER O	# 
			{ L"\x2D54",L"\x004F" }, //( ⵔ → O ) TIFINAGH LETTER YAR → LATIN CAPITAL LETTER O	# 
			{ L"\x0B20",L"\x004F" }, //( ଠ → O ) ORIYA LETTER TTHA → LATIN CAPITAL LETTER O	# →୦→→0→
			{ L"\x0D20",L"\x004F" }, //( ഠ → O ) MALAYALAM LETTER TTHA → LATIN CAPITAL LETTER O	# 
			{ L"\xA4F3",L"\x004F" }, //( ꓳ → O ) LISU LETTER O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\x18B5",L"\x004F" }, //( 𑢵 → O ) WARANG CITI CAPITAL LETTER AT → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\x0292",L"\x004F" }, //( 𐊒 → O ) LYCIAN LETTER U → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\x02AB",L"\x004F" }, //( 𐊫 → O ) CARIAN LETTER O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\x0404",L"\x004F" }, //( 𐐄 → O ) DESERET CAPITAL LETTER LONG O → LATIN CAPITAL LETTER O	# 
			{ L"\x0001\x0516",L"\x004F" }, //( 𐔖 → O ) ELBASAN LETTER O → LATIN CAPITAL LETTER O	# 

			{ L"\x2070",L"\x00BA" }, //( ⁰ → º ) SUPERSCRIPT ZERO → MASCULINE ORDINAL INDICATOR	# 
			{ L"\x1D52",L"\x00BA" }, //( ᵒ → º ) MODIFIER LETTER SMALL O → MASCULINE ORDINAL INDICATOR	# →⁰→

			{ L"\x01D2",L"\x014F" }, //( ǒ → ŏ ) LATIN SMALL LETTER O WITH CARON → LATIN SMALL LETTER O WITH BREVE	# 

			{ L"\x01D1",L"\x014E" }, //( Ǒ → Ŏ ) LATIN CAPITAL LETTER O WITH CARON → LATIN CAPITAL LETTER O WITH BREVE	# 

			{ L"\x06FF",L"\x006F\x0302" }, //( ‎ۿ‎ → ô ) ARABIC LETTER HEH WITH INVERTED V → LATIN SMALL LETTER O, COMBINING CIRCUMFLEX ACCENT	# →‎ھٛ‎→

			{ L"\x00F8",L"\x006F\x0338" }, //( ø → o̸ ) LATIN SMALL LETTER O WITH STROKE → LATIN SMALL LETTER O, COMBINING LONG SOLIDUS OVERLAY	# →o̷→
			{ L"\xAB3E",L"\x006F\x0338" }, //( ꬾ → o̸ ) LATIN SMALL LETTER BLACKLETTER O WITH STROKE → LATIN SMALL LETTER O, COMBINING LONG SOLIDUS OVERLAY	# →ø→→o̷→

			{ L"\x00D8",L"\x004F\x0338" }, //( Ø → O̸ ) LATIN CAPITAL LETTER O WITH STROKE → LATIN CAPITAL LETTER O, COMBINING LONG SOLIDUS OVERLAY	# 
			{ L"\x2D41",L"\x004F\x0338" }, //( ⵁ → O̸ ) TIFINAGH LETTER BERBER ACADEMY YAH → LATIN CAPITAL LETTER O, COMBINING LONG SOLIDUS OVERLAY	# →Ø→

			{ L"\x01FE",L"\x004F\x0338\x0301" }, //( Ǿ → Ó̸ ) LATIN CAPITAL LETTER O WITH STROKE AND ACUTE → LATIN CAPITAL LETTER O, COMBINING LONG SOLIDUS OVERLAY, COMBINING ACUTE ACCENT	# 

			{ L"\x0275",L"\x006F\x0335" }, //( ɵ → o̵ ) LATIN SMALL LETTER BARRED O → LATIN SMALL LETTER O, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\xA74B",L"\x006F\x0335" }, //( ꝋ → o̵ ) LATIN SMALL LETTER O WITH LONG STROKE OVERLAY → LATIN SMALL LETTER O, COMBINING SHORT STROKE OVERLAY	# →o̶→
			{ L"\x04E9",L"\x006F\x0335" }, //( ө → o̵ ) CYRILLIC SMALL LETTER BARRED O → LATIN SMALL LETTER O, COMBINING SHORT STROKE OVERLAY	# →ѳ→
			{ L"\x0473",L"\x006F\x0335" }, //( ѳ → o̵ ) CYRILLIC SMALL LETTER FITA → LATIN SMALL LETTER O, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x2296",L"\x004F\x0335" }, //( ⊖ → O̵ ) CIRCLED MINUS → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x229D",L"\x004F\x0335" }, //( ⊝ → O̵ ) CIRCLED DASH → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →⊖→→θ→→Ꮎ→
			{ L"\x236C",L"\x004F\x0335" }, //( ⍬ → O̵ ) APL FUNCTIONAL SYMBOL ZILDE → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xF714",L"\x004F\x0335" }, //( 🜔 → O̵ ) ALCHEMICAL SYMBOL FOR SALT → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ɵ→→O̶→
			{ L"\x019F",L"\x004F\x0335" }, //( Ɵ → O̵ ) LATIN CAPITAL LETTER O WITH MIDDLE TILDE → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →O̶→
			{ L"\xA74A",L"\x004F\x0335" }, //( Ꝋ → O̵ ) LATIN CAPITAL LETTER O WITH LONG STROKE OVERLAY → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →O̶→
			{ L"\x03B8",L"\x004F\x0335" }, //( θ → O̵ ) GREEK SMALL LETTER THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ꮎ→
			{ L"\x03D1",L"\x004F\x0335" }, //( ϑ → O̵ ) GREEK THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD6C9",L"\x004F\x0335" }, //( 𝛉 → O̵ ) MATHEMATICAL BOLD SMALL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD6DD",L"\x004F\x0335" }, //( 𝛝 → O̵ ) MATHEMATICAL BOLD THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD703",L"\x004F\x0335" }, //( 𝜃 → O̵ ) MATHEMATICAL ITALIC SMALL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD717",L"\x004F\x0335" }, //( 𝜗 → O̵ ) MATHEMATICAL ITALIC THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD73D",L"\x004F\x0335" }, //( 𝜽 → O̵ ) MATHEMATICAL BOLD ITALIC SMALL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD751",L"\x004F\x0335" }, //( 𝝑 → O̵ ) MATHEMATICAL BOLD ITALIC THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD777",L"\x004F\x0335" }, //( 𝝷 → O̵ ) MATHEMATICAL SANS-SERIF BOLD SMALL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD78B",L"\x004F\x0335" }, //( 𝞋 → O̵ ) MATHEMATICAL SANS-SERIF BOLD THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD7B1",L"\x004F\x0335" }, //( 𝞱 → O̵ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0001\xD7C5",L"\x004F\x0335" }, //( 𝟅 → O̵ ) MATHEMATICAL SANS-SERIF BOLD ITALIC THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →θ→→Ꮎ→
			{ L"\x0398",L"\x004F\x0335" }, //( Θ → O̵ ) GREEK CAPITAL LETTER THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ꮎ→
			{ L"\x03F4",L"\x004F\x0335" }, //( ϴ → O̵ ) GREEK CAPITAL THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ѳ→→О̵→
			{ L"\x0001\xD6AF",L"\x004F\x0335" }, //( 𝚯 → O̵ ) MATHEMATICAL BOLD CAPITAL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD6B9",L"\x004F\x0335" }, //( 𝚹 → O̵ ) MATHEMATICAL BOLD CAPITAL THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD6E9",L"\x004F\x0335" }, //( 𝛩 → O̵ ) MATHEMATICAL ITALIC CAPITAL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD6F3",L"\x004F\x0335" }, //( 𝛳 → O̵ ) MATHEMATICAL ITALIC CAPITAL THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD723",L"\x004F\x0335" }, //( 𝜣 → O̵ ) MATHEMATICAL BOLD ITALIC CAPITAL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD72D",L"\x004F\x0335" }, //( 𝜭 → O̵ ) MATHEMATICAL BOLD ITALIC CAPITAL THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD75D",L"\x004F\x0335" }, //( 𝝝 → O̵ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD767",L"\x004F\x0335" }, //( 𝝧 → O̵ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD797",L"\x004F\x0335" }, //( 𝞗 → O̵ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL THETA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x0001\xD7A1",L"\x004F\x0335" }, //( 𝞡 → O̵ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL THETA SYMBOL → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Θ→→Ꮎ→
			{ L"\x04E8",L"\x004F\x0335" }, //( Ө → O̵ ) CYRILLIC CAPITAL LETTER BARRED O → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ѳ→→О̵→
			{ L"\x0472",L"\x004F\x0335" }, //( Ѳ → O̵ ) CYRILLIC CAPITAL LETTER FITA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →О̵→
			{ L"\x2D31",L"\x004F\x0335" }, //( ⴱ → O̵ ) TIFINAGH LETTER YAB → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ɵ→→O̶→
			{ L"\x13BE",L"\x004F\x0335" }, //( Ꮎ → O̵ ) CHEROKEE LETTER NA → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x13EB",L"\x004F\x0335" }, //( Ꮻ → O̵ ) CHEROKEE LETTER WI → LATIN CAPITAL LETTER O, COMBINING SHORT STROKE OVERLAY	# →Ѳ→→О̵→

			{ L"\xFCD9",L"\x006F\x0670" }, //( ‎ﳙ‎ → oٰ ) ARABIC LIGATURE HEH WITH SUPERSCRIPT ALEF INITIAL FORM → LATIN SMALL LETTER O, ARABIC LETTER SUPERSCRIPT ALEF	# →‎هٰ‎→

			{ L"\x0001\xF101",L"\x004F\x002C" }, //( 🄁 → O, ) DIGIT ZERO COMMA → LATIN CAPITAL LETTER O, COMMA	# →0,→

			{ L"\x0001\xF100",L"\x004F\x002E" }, //( 🄀 → O. ) DIGIT ZERO FULL STOP → LATIN CAPITAL LETTER O, FULL STOP	# →0.→

			{ L"\x01A1",L"\x006F\x0027" }, //( ơ → o' ) LATIN SMALL LETTER O WITH HORN → LATIN SMALL LETTER O, APOSTROPHE	# →oʼ→

			{ L"\x01A0",L"\x004F\x0027" }, //( Ơ → O' ) LATIN CAPITAL LETTER O WITH HORN → LATIN CAPITAL LETTER O, APOSTROPHE	# →Oʼ→
			{ L"\x13A4",L"\x004F\x0027" }, //( Ꭴ → O' ) CHEROKEE LETTER U → LATIN CAPITAL LETTER O, APOSTROPHE	# →Ơ→→Oʼ→

			{ L"\x0025",L"\x00BA\x002F\x2080" }, //( % → º/₀ ) PERCENT SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO	# →⁰/₀→
			{ L"\x066A",L"\x00BA\x002F\x2080" }, //( ٪ → º/₀ ) ARABIC PERCENT SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO	# →%→→⁰/₀→
			{ L"\x2052",L"\x00BA\x002F\x2080" }, //( ⁒ → º/₀ ) COMMERCIAL MINUS SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO	# →%→→⁰/₀→

			{ L"\x2030",L"\x00BA\x002F\x2080\x2080" }, //( ‰ → º/₀₀ ) PER MILLE SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO, SUBSCRIPT ZERO	# →⁰/₀₀→
			{ L"\x0609",L"\x00BA\x002F\x2080\x2080" }, //( ؉ → º/₀₀ ) ARABIC-INDIC PER MILLE SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO, SUBSCRIPT ZERO	# →‰→→⁰/₀₀→

			{ L"\x2031",L"\x00BA\x002F\x2080\x2080\x2080" }, //( ‱ → º/₀₀₀ ) PER TEN THOUSAND SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO, SUBSCRIPT ZERO, SUBSCRIPT ZERO	# →⁰/₀₀₀→
			{ L"\x060A",L"\x00BA\x002F\x2080\x2080\x2080" }, //( ؊ → º/₀₀₀ ) ARABIC-INDIC PER TEN THOUSAND SIGN → MASCULINE ORDINAL INDICATOR, SOLIDUS, SUBSCRIPT ZERO, SUBSCRIPT ZERO, SUBSCRIPT ZERO	# →‱→→⁰/₀₀₀→

			{ L"\x0153",L"\x006F\x0065" }, //( œ → oe ) LATIN SMALL LIGATURE OE → LATIN SMALL LETTER O, LATIN SMALL LETTER E	# 

			{ L"\x0152",L"\x004F\x0045" }, //( Œ → OE ) LATIN CAPITAL LIGATURE OE → LATIN CAPITAL LETTER O, LATIN CAPITAL LETTER E	# 

			{ L"\x0276",L"\x006F\x1D07" }, //( ɶ → oᴇ ) LATIN LETTER SMALL CAPITAL OE → LATIN SMALL LETTER O, LATIN LETTER SMALL CAPITAL E	# 

			{ L"\x221E",L"\x006F\x006F" }, //( ∞ → oo ) INFINITY → LATIN SMALL LETTER O, LATIN SMALL LETTER O	# →ꝏ→
			{ L"\xA74F",L"\x006F\x006F" }, //( ꝏ → oo ) LATIN SMALL LETTER OO → LATIN SMALL LETTER O, LATIN SMALL LETTER O	# 
			{ L"\xA699",L"\x006F\x006F" }, //( ꚙ → oo ) CYRILLIC SMALL LETTER DOUBLE O → LATIN SMALL LETTER O, LATIN SMALL LETTER O	# 

			{ L"\xA74E",L"\x004F\x004F" }, //( Ꝏ → OO ) LATIN CAPITAL LETTER OO → LATIN CAPITAL LETTER O, LATIN CAPITAL LETTER O	# 
			{ L"\xA698",L"\x004F\x004F" }, //( Ꚙ → OO ) CYRILLIC CAPITAL LETTER DOUBLE O → LATIN CAPITAL LETTER O, LATIN CAPITAL LETTER O	# 

			{ L"\xFCD7",L"\x006F\x062C" }, //( ‎ﳗ‎ → ‎oج‎ ) ARABIC LIGATURE HEH WITH JEEM INITIAL FORM → LATIN SMALL LETTER O, ARABIC LETTER JEEM	# →‎هج‎→
			{ L"\xFC51",L"\x006F\x062C" }, //( ‎ﱑ‎ → ‎oج‎ ) ARABIC LIGATURE HEH WITH JEEM ISOLATED FORM → LATIN SMALL LETTER O, ARABIC LETTER JEEM	# →‎هج‎→

			{ L"\xFCD8",L"\x006F\x0645" }, //( ‎ﳘ‎ → ‎oم‎ ) ARABIC LIGATURE HEH WITH MEEM INITIAL FORM → LATIN SMALL LETTER O, ARABIC LETTER MEEM	# →‎هم‎→
			{ L"\xFC52",L"\x006F\x0645" }, //( ‎ﱒ‎ → ‎oم‎ ) ARABIC LIGATURE HEH WITH MEEM ISOLATED FORM → LATIN SMALL LETTER O, ARABIC LETTER MEEM	# →‎هم‎→

			{ L"\xFD93",L"\x006F\x0645\x062C" }, //( ‎ﶓ‎ → ‎oمج‎ ) ARABIC LIGATURE HEH WITH MEEM WITH JEEM INITIAL FORM → LATIN SMALL LETTER O, ARABIC LETTER MEEM, ARABIC LETTER JEEM	# →‎همج‎→

			{ L"\xFD94",L"\x006F\x0645\x0645" }, //( ‎ﶔ‎ → ‎oمم‎ ) ARABIC LIGATURE HEH WITH MEEM WITH MEEM INITIAL FORM → LATIN SMALL LETTER O, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# →‎همم‎→

			{ L"\xFC53",L"\x006F\x0649" }, //( ‎ﱓ‎ → ‎oى‎ ) ARABIC LIGATURE HEH WITH ALEF MAKSURA ISOLATED FORM → LATIN SMALL LETTER O, ARABIC LETTER ALEF MAKSURA	# →‎هى‎→
			{ L"\xFC54",L"\x006F\x0649" }, //( ‎ﱔ‎ → ‎oى‎ ) ARABIC LIGATURE HEH WITH YEH ISOLATED FORM → LATIN SMALL LETTER O, ARABIC LETTER ALEF MAKSURA	# →‎هي‎→

			{ L"\x0D5F",L"\x006F\x0D30\x006F" }, //( ൟ → oരo ) MALAYALAM LETTER ARCHAIC II → LATIN SMALL LETTER O, MALAYALAM LETTER RA, LATIN SMALL LETTER O	# →൦ര൦→

			{ L"\x1010",L"\x006F\x102C" }, //( တ → oာ ) MYANMAR LETTER TA → LATIN SMALL LETTER O, MYANMAR VOWEL SIGN AA	# →ဝာ→

			{ L"\x3358",L"\x004F\x70B9" }, //( ㍘ → O点 ) IDEOGRAPHIC TELEGRAPH SYMBOL FOR HOUR ZERO → LATIN CAPITAL LETTER O, CJK UNIFIED IDEOGRAPH-70B9	# →0点→

			{ L"\x2184",L"\x0254" }, //( ↄ → ɔ ) LATIN SMALL LETTER REVERSED C → LATIN SMALL LETTER OPEN O	# 
			{ L"\x1D10",L"\x0254" }, //( ᴐ → ɔ ) LATIN LETTER SMALL CAPITAL OPEN O → LATIN SMALL LETTER OPEN O	# 
			{ L"\x037B",L"\x0254" }, //( ͻ → ɔ ) GREEK SMALL REVERSED LUNATE SIGMA SYMBOL → LATIN SMALL LETTER OPEN O	# 
			{ L"\x0001\x044B",L"\x0254" }, //( 𐑋 → ɔ ) DESERET SMALL LETTER EM → LATIN SMALL LETTER OPEN O	# 

			{ L"\x2183",L"\x0186" }, //( Ↄ → Ɔ ) ROMAN NUMERAL REVERSED ONE HUNDRED → LATIN CAPITAL LETTER OPEN O	# 
			{ L"\x03FD",L"\x0186" }, //( Ͻ → Ɔ ) GREEK CAPITAL REVERSED LUNATE SIGMA SYMBOL → LATIN CAPITAL LETTER OPEN O	# 
			{ L"\xA4DB",L"\x0186" }, //( ꓛ → Ɔ ) LISU LETTER CHA → LATIN CAPITAL LETTER OPEN O	# 
			{ L"\x0001\x0423",L"\x0186" }, //( 𐐣 → Ɔ ) DESERET CAPITAL LETTER EM → LATIN CAPITAL LETTER OPEN O	# 

			{ L"\x0001\x043F",L"\x0277" }, //( 𐐿 → ɷ ) DESERET SMALL LETTER KAY → LATIN SMALL LETTER CLOSED OMEGA	# 

			{ L"\x2374",L"\x0070" }, //( ⍴ → p ) APL FUNCTIONAL SYMBOL RHO → LATIN SMALL LETTER P	# →ρ→
			{ L"\xFF50",L"\x0070" }, //( ｐ → p ) FULLWIDTH LATIN SMALL LETTER P → LATIN SMALL LETTER P	# →р→
			{ L"\x0001\xD429",L"\x0070" }, //( 𝐩 → p ) MATHEMATICAL BOLD SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD45D",L"\x0070" }, //( 𝑝 → p ) MATHEMATICAL ITALIC SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD491",L"\x0070" }, //( 𝒑 → p ) MATHEMATICAL BOLD ITALIC SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD4C5",L"\x0070" }, //( 𝓅 → p ) MATHEMATICAL SCRIPT SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD4F9",L"\x0070" }, //( 𝓹 → p ) MATHEMATICAL BOLD SCRIPT SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD52D",L"\x0070" }, //( 𝔭 → p ) MATHEMATICAL FRAKTUR SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD561",L"\x0070" }, //( 𝕡 → p ) MATHEMATICAL DOUBLE-STRUCK SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD595",L"\x0070" }, //( 𝖕 → p ) MATHEMATICAL BOLD FRAKTUR SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD5C9",L"\x0070" }, //( 𝗉 → p ) MATHEMATICAL SANS-SERIF SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD5FD",L"\x0070" }, //( 𝗽 → p ) MATHEMATICAL SANS-SERIF BOLD SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD631",L"\x0070" }, //( 𝘱 → p ) MATHEMATICAL SANS-SERIF ITALIC SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD665",L"\x0070" }, //( 𝙥 → p ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x0001\xD699",L"\x0070" }, //( 𝚙 → p ) MATHEMATICAL MONOSPACE SMALL P → LATIN SMALL LETTER P	# 
			{ L"\x03C1",L"\x0070" }, //( ρ → p ) GREEK SMALL LETTER RHO → LATIN SMALL LETTER P	# 
			{ L"\x03F1",L"\x0070" }, //( ϱ → p ) GREEK RHO SYMBOL → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD6D2",L"\x0070" }, //( 𝛒 → p ) MATHEMATICAL BOLD SMALL RHO → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD6E0",L"\x0070" }, //( 𝛠 → p ) MATHEMATICAL BOLD RHO SYMBOL → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD70C",L"\x0070" }, //( 𝜌 → p ) MATHEMATICAL ITALIC SMALL RHO → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD71A",L"\x0070" }, //( 𝜚 → p ) MATHEMATICAL ITALIC RHO SYMBOL → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD746",L"\x0070" }, //( 𝝆 → p ) MATHEMATICAL BOLD ITALIC SMALL RHO → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD754",L"\x0070" }, //( 𝝔 → p ) MATHEMATICAL BOLD ITALIC RHO SYMBOL → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD780",L"\x0070" }, //( 𝞀 → p ) MATHEMATICAL SANS-SERIF BOLD SMALL RHO → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD78E",L"\x0070" }, //( 𝞎 → p ) MATHEMATICAL SANS-SERIF BOLD RHO SYMBOL → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD7BA",L"\x0070" }, //( 𝞺 → p ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL RHO → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0001\xD7C8",L"\x0070" }, //( 𝟈 → p ) MATHEMATICAL SANS-SERIF BOLD ITALIC RHO SYMBOL → LATIN SMALL LETTER P	# →ρ→
			{ L"\x2CA3",L"\x0070" }, //( ⲣ → p ) COPTIC SMALL LETTER RO → LATIN SMALL LETTER P	# →ρ→
			{ L"\x0440",L"\x0070" }, //( р → p ) CYRILLIC SMALL LETTER ER → LATIN SMALL LETTER P	# 

			{ L"\xFF30",L"\x0050" }, //( Ｐ → P ) FULLWIDTH LATIN CAPITAL LETTER P → LATIN CAPITAL LETTER P	# →Р→
			{ L"\x2119",L"\x0050" }, //( ℙ → P ) DOUBLE-STRUCK CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD40F",L"\x0050" }, //( 𝐏 → P ) MATHEMATICAL BOLD CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD443",L"\x0050" }, //( 𝑃 → P ) MATHEMATICAL ITALIC CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD477",L"\x0050" }, //( 𝑷 → P ) MATHEMATICAL BOLD ITALIC CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD4AB",L"\x0050" }, //( 𝒫 → P ) MATHEMATICAL SCRIPT CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD4DF",L"\x0050" }, //( 𝓟 → P ) MATHEMATICAL BOLD SCRIPT CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD513",L"\x0050" }, //( 𝔓 → P ) MATHEMATICAL FRAKTUR CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD57B",L"\x0050" }, //( 𝕻 → P ) MATHEMATICAL BOLD FRAKTUR CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD5AF",L"\x0050" }, //( 𝖯 → P ) MATHEMATICAL SANS-SERIF CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD5E3",L"\x0050" }, //( 𝗣 → P ) MATHEMATICAL SANS-SERIF BOLD CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD617",L"\x0050" }, //( 𝘗 → P ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD64B",L"\x0050" }, //( 𝙋 → P ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD67F",L"\x0050" }, //( 𝙿 → P ) MATHEMATICAL MONOSPACE CAPITAL P → LATIN CAPITAL LETTER P	# 
			{ L"\x03A1",L"\x0050" }, //( Ρ → P ) GREEK CAPITAL LETTER RHO → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\xD6B8",L"\x0050" }, //( 𝚸 → P ) MATHEMATICAL BOLD CAPITAL RHO → LATIN CAPITAL LETTER P	# →𝐏→
			{ L"\x0001\xD6F2",L"\x0050" }, //( 𝛲 → P ) MATHEMATICAL ITALIC CAPITAL RHO → LATIN CAPITAL LETTER P	# →Ρ→
			{ L"\x0001\xD72C",L"\x0050" }, //( 𝜬 → P ) MATHEMATICAL BOLD ITALIC CAPITAL RHO → LATIN CAPITAL LETTER P	# →Ρ→
			{ L"\x0001\xD766",L"\x0050" }, //( 𝝦 → P ) MATHEMATICAL SANS-SERIF BOLD CAPITAL RHO → LATIN CAPITAL LETTER P	# →Ρ→
			{ L"\x0001\xD7A0",L"\x0050" }, //( 𝞠 → P ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL RHO → LATIN CAPITAL LETTER P	# →Ρ→
			{ L"\x2CA2",L"\x0050" }, //( Ⲣ → P ) COPTIC CAPITAL LETTER RO → LATIN CAPITAL LETTER P	# 
			{ L"\x0420",L"\x0050" }, //( Р → P ) CYRILLIC CAPITAL LETTER ER → LATIN CAPITAL LETTER P	# 
			{ L"\x13E2",L"\x0050" }, //( Ꮲ → P ) CHEROKEE LETTER TLV → LATIN CAPITAL LETTER P	# 
			{ L"\x146D",L"\x0050" }, //( ᑭ → P ) CANADIAN SYLLABICS KI → LATIN CAPITAL LETTER P	# 
			{ L"\xA4D1",L"\x0050" }, //( ꓑ → P ) LISU LETTER PA → LATIN CAPITAL LETTER P	# 
			{ L"\x0001\x0295",L"\x0050" }, //( 𐊕 → P ) LYCIAN LETTER R → LATIN CAPITAL LETTER P	# 

			{ L"\x01A5",L"\x0070\x0314" }, //( ƥ → p̔ ) LATIN SMALL LETTER P WITH HOOK → LATIN SMALL LETTER P, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x1D7D",L"\x0070\x0335" }, //( ᵽ → p̵ ) LATIN SMALL LETTER P WITH STROKE → LATIN SMALL LETTER P, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x1477",L"\x0070\x00B7" }, //( ᑷ → p· ) CANADIAN SYLLABICS WEST-CREE KWI → LATIN SMALL LETTER P, MIDDLE DOT	# →pᐧ→

			{ L"\x1486",L"\x0050\x0027" }, //( ᒆ → P' ) CANADIAN SYLLABICS SOUTH-SLAVEY KIH → LATIN CAPITAL LETTER P, APOSTROPHE	# →ᑭᑊ→

			{ L"\x1D29",L"\x1D18" }, //( ᴩ → ᴘ ) GREEK LETTER SMALL CAPITAL RHO → LATIN LETTER SMALL CAPITAL P	# 

			{ L"\x03C6",L"\x0278" }, //( φ → ɸ ) GREEK SMALL LETTER PHI → LATIN SMALL LETTER PHI	# 
			{ L"\x03D5",L"\x0278" }, //( ϕ → ɸ ) GREEK PHI SYMBOL → LATIN SMALL LETTER PHI	# 
			{ L"\x0001\xD6D7",L"\x0278" }, //( 𝛗 → ɸ ) MATHEMATICAL BOLD SMALL PHI → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD6DF",L"\x0278" }, //( 𝛟 → ɸ ) MATHEMATICAL BOLD PHI SYMBOL → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD711",L"\x0278" }, //( 𝜑 → ɸ ) MATHEMATICAL ITALIC SMALL PHI → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD719",L"\x0278" }, //( 𝜙 → ɸ ) MATHEMATICAL ITALIC PHI SYMBOL → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD74B",L"\x0278" }, //( 𝝋 → ɸ ) MATHEMATICAL BOLD ITALIC SMALL PHI → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD753",L"\x0278" }, //( 𝝓 → ɸ ) MATHEMATICAL BOLD ITALIC PHI SYMBOL → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD785",L"\x0278" }, //( 𝞅 → ɸ ) MATHEMATICAL SANS-SERIF BOLD SMALL PHI → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD78D",L"\x0278" }, //( 𝞍 → ɸ ) MATHEMATICAL SANS-SERIF BOLD PHI SYMBOL → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD7BF",L"\x0278" }, //( 𝞿 → ɸ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL PHI → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x0001\xD7C7",L"\x0278" }, //( 𝟇 → ɸ ) MATHEMATICAL SANS-SERIF BOLD ITALIC PHI SYMBOL → LATIN SMALL LETTER PHI	# →φ→
			{ L"\x2CAB",L"\x0278" }, //( ⲫ → ɸ ) COPTIC SMALL LETTER FI → LATIN SMALL LETTER PHI	# →ϕ→
			{ L"\x0444",L"\x0278" }, //( ф → ɸ ) CYRILLIC SMALL LETTER EF → LATIN SMALL LETTER PHI	# 

			{ L"\x0001\xD42A",L"\x0071" }, //( 𝐪 → q ) MATHEMATICAL BOLD SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD45E",L"\x0071" }, //( 𝑞 → q ) MATHEMATICAL ITALIC SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD492",L"\x0071" }, //( 𝒒 → q ) MATHEMATICAL BOLD ITALIC SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD4C6",L"\x0071" }, //( 𝓆 → q ) MATHEMATICAL SCRIPT SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD4FA",L"\x0071" }, //( 𝓺 → q ) MATHEMATICAL BOLD SCRIPT SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD52E",L"\x0071" }, //( 𝔮 → q ) MATHEMATICAL FRAKTUR SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD562",L"\x0071" }, //( 𝕢 → q ) MATHEMATICAL DOUBLE-STRUCK SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD596",L"\x0071" }, //( 𝖖 → q ) MATHEMATICAL BOLD FRAKTUR SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD5CA",L"\x0071" }, //( 𝗊 → q ) MATHEMATICAL SANS-SERIF SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD5FE",L"\x0071" }, //( 𝗾 → q ) MATHEMATICAL SANS-SERIF BOLD SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD632",L"\x0071" }, //( 𝘲 → q ) MATHEMATICAL SANS-SERIF ITALIC SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD666",L"\x0071" }, //( 𝙦 → q ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x0001\xD69A",L"\x0071" }, //( 𝚚 → q ) MATHEMATICAL MONOSPACE SMALL Q → LATIN SMALL LETTER Q	# 
			{ L"\x051B",L"\x0071" }, //( ԛ → q ) CYRILLIC SMALL LETTER QA → LATIN SMALL LETTER Q	# 
			{ L"\x0563",L"\x0071" }, //( գ → q ) ARMENIAN SMALL LETTER GIM → LATIN SMALL LETTER Q	# 
			{ L"\x0566",L"\x0071" }, //( զ → q ) ARMENIAN SMALL LETTER ZA → LATIN SMALL LETTER Q	# 

			{ L"\x211A",L"\x0051" }, //( ℚ → Q ) DOUBLE-STRUCK CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD410",L"\x0051" }, //( 𝐐 → Q ) MATHEMATICAL BOLD CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD444",L"\x0051" }, //( 𝑄 → Q ) MATHEMATICAL ITALIC CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD478",L"\x0051" }, //( 𝑸 → Q ) MATHEMATICAL BOLD ITALIC CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD4AC",L"\x0051" }, //( 𝒬 → Q ) MATHEMATICAL SCRIPT CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD4E0",L"\x0051" }, //( 𝓠 → Q ) MATHEMATICAL BOLD SCRIPT CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD514",L"\x0051" }, //( 𝔔 → Q ) MATHEMATICAL FRAKTUR CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD57C",L"\x0051" }, //( 𝕼 → Q ) MATHEMATICAL BOLD FRAKTUR CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD5B0",L"\x0051" }, //( 𝖰 → Q ) MATHEMATICAL SANS-SERIF CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD5E4",L"\x0051" }, //( 𝗤 → Q ) MATHEMATICAL SANS-SERIF BOLD CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD618",L"\x0051" }, //( 𝘘 → Q ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD64C",L"\x0051" }, //( 𝙌 → Q ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x0001\xD680",L"\x0051" }, //( 𝚀 → Q ) MATHEMATICAL MONOSPACE CAPITAL Q → LATIN CAPITAL LETTER Q	# 
			{ L"\x2D55",L"\x0051" }, //( ⵕ → Q ) TIFINAGH LETTER YARR → LATIN CAPITAL LETTER Q	# 

			{ L"\x02A0",L"\x0071\x0314" }, //( ʠ → q̔ ) LATIN SMALL LETTER Q WITH HOOK → LATIN SMALL LETTER Q, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x0001\xF700",L"\x0051\x0045" }, //( 🜀 → QE ) ALCHEMICAL SYMBOL FOR QUINTESSENCE → LATIN CAPITAL LETTER Q, LATIN CAPITAL LETTER E	# 

			{ L"\x1D90",L"\x024B" }, //( ᶐ → ɋ ) LATIN SMALL LETTER ALPHA WITH RETROFLEX HOOK → LATIN SMALL LETTER Q WITH HOOK TAIL	# 

			{ L"\x0001\xD42B",L"\x0072" }, //( 𝐫 → r ) MATHEMATICAL BOLD SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD45F",L"\x0072" }, //( 𝑟 → r ) MATHEMATICAL ITALIC SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD493",L"\x0072" }, //( 𝒓 → r ) MATHEMATICAL BOLD ITALIC SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD4C7",L"\x0072" }, //( 𝓇 → r ) MATHEMATICAL SCRIPT SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD4FB",L"\x0072" }, //( 𝓻 → r ) MATHEMATICAL BOLD SCRIPT SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD52F",L"\x0072" }, //( 𝔯 → r ) MATHEMATICAL FRAKTUR SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD563",L"\x0072" }, //( 𝕣 → r ) MATHEMATICAL DOUBLE-STRUCK SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD597",L"\x0072" }, //( 𝖗 → r ) MATHEMATICAL BOLD FRAKTUR SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD5CB",L"\x0072" }, //( 𝗋 → r ) MATHEMATICAL SANS-SERIF SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD5FF",L"\x0072" }, //( 𝗿 → r ) MATHEMATICAL SANS-SERIF BOLD SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD633",L"\x0072" }, //( 𝘳 → r ) MATHEMATICAL SANS-SERIF ITALIC SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD667",L"\x0072" }, //( 𝙧 → r ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL R → LATIN SMALL LETTER R	# 
			{ L"\x0001\xD69B",L"\x0072" }, //( 𝚛 → r ) MATHEMATICAL MONOSPACE SMALL R → LATIN SMALL LETTER R	# 
			{ L"\xAB47",L"\x0072" }, //( ꭇ → r ) LATIN SMALL LETTER R WITHOUT HANDLE → LATIN SMALL LETTER R	# 
			{ L"\xAB48",L"\x0072" }, //( ꭈ → r ) LATIN SMALL LETTER DOUBLE R → LATIN SMALL LETTER R	# 
			{ L"\x1D26",L"\x0072" }, //( ᴦ → r ) GREEK LETTER SMALL CAPITAL GAMMA → LATIN SMALL LETTER R	# →г→
			{ L"\x2C85",L"\x0072" }, //( ⲅ → r ) COPTIC SMALL LETTER GAMMA → LATIN SMALL LETTER R	# →г→
			{ L"\x0433",L"\x0072" }, //( г → r ) CYRILLIC SMALL LETTER GHE → LATIN SMALL LETTER R	# 

			{ L"\x211B",L"\x0052" }, //( ℛ → R ) SCRIPT CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x211C",L"\x0052" }, //( ℜ → R ) BLACK-LETTER CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x211D",L"\x0052" }, //( ℝ → R ) DOUBLE-STRUCK CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD411",L"\x0052" }, //( 𝐑 → R ) MATHEMATICAL BOLD CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD445",L"\x0052" }, //( 𝑅 → R ) MATHEMATICAL ITALIC CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD479",L"\x0052" }, //( 𝑹 → R ) MATHEMATICAL BOLD ITALIC CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD4E1",L"\x0052" }, //( 𝓡 → R ) MATHEMATICAL BOLD SCRIPT CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD57D",L"\x0052" }, //( 𝕽 → R ) MATHEMATICAL BOLD FRAKTUR CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD5B1",L"\x0052" }, //( 𝖱 → R ) MATHEMATICAL SANS-SERIF CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD5E5",L"\x0052" }, //( 𝗥 → R ) MATHEMATICAL SANS-SERIF BOLD CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD619",L"\x0052" }, //( 𝘙 → R ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD64D",L"\x0052" }, //( 𝙍 → R ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x0001\xD681",L"\x0052" }, //( 𝚁 → R ) MATHEMATICAL MONOSPACE CAPITAL R → LATIN CAPITAL LETTER R	# 
			{ L"\x01A6",L"\x0052" }, //( Ʀ → R ) LATIN LETTER YR → LATIN CAPITAL LETTER R	# 
			{ L"\x13A1",L"\x0052" }, //( Ꭱ → R ) CHEROKEE LETTER E → LATIN CAPITAL LETTER R	# 
			{ L"\x13D2",L"\x0052" }, //( Ꮢ → R ) CHEROKEE LETTER SV → LATIN CAPITAL LETTER R	# 
			{ L"\x1587",L"\x0052" }, //( ᖇ → R ) CANADIAN SYLLABICS TLHI → LATIN CAPITAL LETTER R	# 
			{ L"\xA4E3",L"\x0052" }, //( ꓣ → R ) LISU LETTER ZHA → LATIN CAPITAL LETTER R	# 

			{ L"\x027D",L"\x0072\x0328" }, //( ɽ → r̨ ) LATIN SMALL LETTER R WITH TAIL → LATIN SMALL LETTER R, COMBINING OGONEK	# 

			{ L"\x027C",L"\x0072\x0329" }, //( ɼ → r̩ ) LATIN SMALL LETTER R WITH LONG LEG → LATIN SMALL LETTER R, COMBINING VERTICAL LINE BELOW	# 

			{ L"\x024D",L"\x0072\x0335" }, //( ɍ → r̵ ) LATIN SMALL LETTER R WITH STROKE → LATIN SMALL LETTER R, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x0493",L"\x0072\x0335" }, //( ғ → r̵ ) CYRILLIC SMALL LETTER GHE WITH STROKE → LATIN SMALL LETTER R, COMBINING SHORT STROKE OVERLAY	# →г̵→

			{ L"\x1D72",L"\x0072\x0334" }, //( ᵲ → r̴ ) LATIN SMALL LETTER R WITH MIDDLE TILDE → LATIN SMALL LETTER R, COMBINING TILDE OVERLAY	# 

			{ L"\x0491",L"\x0072\x0027" }, //( ґ → r' ) CYRILLIC SMALL LETTER GHE WITH UPTURN → LATIN SMALL LETTER R, APOSTROPHE	# →гˈ→

			{ L"\x0001\x18E3",L"\x0072\x006E" }, //( 𑣣 → rn ) WARANG CITI DIGIT THREE → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x006D",L"\x0072\x006E" }, //( m → rn ) LATIN SMALL LETTER M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# 
			{ L"\x217F",L"\x0072\x006E" }, //( ⅿ → rn ) SMALL ROMAN NUMERAL ONE THOUSAND → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD426",L"\x0072\x006E" }, //( 𝐦 → rn ) MATHEMATICAL BOLD SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD45A",L"\x0072\x006E" }, //( 𝑚 → rn ) MATHEMATICAL ITALIC SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD48E",L"\x0072\x006E" }, //( 𝒎 → rn ) MATHEMATICAL BOLD ITALIC SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD4C2",L"\x0072\x006E" }, //( 𝓂 → rn ) MATHEMATICAL SCRIPT SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD4F6",L"\x0072\x006E" }, //( 𝓶 → rn ) MATHEMATICAL BOLD SCRIPT SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD52A",L"\x0072\x006E" }, //( 𝔪 → rn ) MATHEMATICAL FRAKTUR SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD55E",L"\x0072\x006E" }, //( 𝕞 → rn ) MATHEMATICAL DOUBLE-STRUCK SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD592",L"\x0072\x006E" }, //( 𝖒 → rn ) MATHEMATICAL BOLD FRAKTUR SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD5C6",L"\x0072\x006E" }, //( 𝗆 → rn ) MATHEMATICAL SANS-SERIF SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD5FA",L"\x0072\x006E" }, //( 𝗺 → rn ) MATHEMATICAL SANS-SERIF BOLD SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD62E",L"\x0072\x006E" }, //( 𝘮 → rn ) MATHEMATICAL SANS-SERIF ITALIC SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD662",L"\x0072\x006E" }, //( 𝙢 → rn ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\xD696",L"\x0072\x006E" }, //( 𝚖 → rn ) MATHEMATICAL MONOSPACE SMALL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x1D0D",L"\x0072\x006E" }, //( ᴍ → rn ) LATIN LETTER SMALL CAPITAL M → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →м→→m→
			{ L"\xAB51",L"\x0072\x006E" }, //( ꭑ → rn ) LATIN SMALL LETTER TURNED UI → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x028D",L"\x0072\x006E" }, //( ʍ → rn ) LATIN SMALL LETTER TURNED W → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x043C",L"\x0072\x006E" }, //( м → rn ) CYRILLIC SMALL LETTER EM → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→
			{ L"\x0001\x1700",L"\x0072\x006E" }, //( 𑜀 → rn ) AHOM LETTER KA → LATIN SMALL LETTER R, LATIN SMALL LETTER N	# →m→

			{ L"\x20A5",L"\x0072\x006E\x0338" }, //( ₥ → rn̸ ) MILL SIGN → LATIN SMALL LETTER R, LATIN SMALL LETTER N, COMBINING LONG SOLIDUS OVERLAY	# →m̷→

			{ L"\x0271",L"\x0072\x006E\x0326" }, //( ɱ → rn̦ ) LATIN SMALL LETTER M WITH HOOK → LATIN SMALL LETTER R, LATIN SMALL LETTER N, COMBINING COMMA BELOW	# →m̡→
			{ L"\x04CE",L"\x0072\x006E\x0326" }, //( ӎ → rn̦ ) CYRILLIC SMALL LETTER EM WITH TAIL → LATIN SMALL LETTER R, LATIN SMALL LETTER N, COMBINING COMMA BELOW	# →м̡→

			{ L"\x1D6F",L"\x0072\x006E\x0334" }, //( ᵯ → rn̴ ) LATIN SMALL LETTER M WITH MIDDLE TILDE → LATIN SMALL LETTER R, LATIN SMALL LETTER N, COMBINING TILDE OVERLAY	# →m̴→

			{ L"\x20A8",L"\x0052\x0073" }, //( ₨ → Rs ) RUPEE SIGN → LATIN CAPITAL LETTER R, LATIN SMALL LETTER S	# 

			{ L"\x044F",L"\x1D19" }, //( я → ᴙ ) CYRILLIC SMALL LETTER YA → LATIN LETTER SMALL CAPITAL REVERSED R	# 

			{ L"\x1D73",L"\x027E\x0334" }, //( ᵳ → ɾ̴ ) LATIN SMALL LETTER R WITH FISHHOOK AND MIDDLE TILDE → LATIN SMALL LETTER R WITH FISHHOOK, COMBINING TILDE OVERLAY	# 

			{ L"\x2129",L"\x027F" }, //( ℩ → ɿ ) TURNED GREEK SMALL LETTER IOTA → LATIN SMALL LETTER REVERSED R WITH FISHHOOK	# 

			{ L"\xFF53",L"\x0073" }, //( ｓ → s ) FULLWIDTH LATIN SMALL LETTER S → LATIN SMALL LETTER S	# →ѕ→
			{ L"\x0001\xD42C",L"\x0073" }, //( 𝐬 → s ) MATHEMATICAL BOLD SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD460",L"\x0073" }, //( 𝑠 → s ) MATHEMATICAL ITALIC SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD494",L"\x0073" }, //( 𝒔 → s ) MATHEMATICAL BOLD ITALIC SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD4C8",L"\x0073" }, //( 𝓈 → s ) MATHEMATICAL SCRIPT SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD4FC",L"\x0073" }, //( 𝓼 → s ) MATHEMATICAL BOLD SCRIPT SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD530",L"\x0073" }, //( 𝔰 → s ) MATHEMATICAL FRAKTUR SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD564",L"\x0073" }, //( 𝕤 → s ) MATHEMATICAL DOUBLE-STRUCK SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD598",L"\x0073" }, //( 𝖘 → s ) MATHEMATICAL BOLD FRAKTUR SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD5CC",L"\x0073" }, //( 𝗌 → s ) MATHEMATICAL SANS-SERIF SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD600",L"\x0073" }, //( 𝘀 → s ) MATHEMATICAL SANS-SERIF BOLD SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD634",L"\x0073" }, //( 𝘴 → s ) MATHEMATICAL SANS-SERIF ITALIC SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD668",L"\x0073" }, //( 𝙨 → s ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL S → LATIN SMALL LETTER S	# 
			{ L"\x0001\xD69C",L"\x0073" }, //( 𝚜 → s ) MATHEMATICAL MONOSPACE SMALL S → LATIN SMALL LETTER S	# 
			{ L"\xA731",L"\x0073" }, //( ꜱ → s ) LATIN LETTER SMALL CAPITAL S → LATIN SMALL LETTER S	# 
			{ L"\x01BD",L"\x0073" }, //( ƽ → s ) LATIN SMALL LETTER TONE FIVE → LATIN SMALL LETTER S	# 
			{ L"\x0455",L"\x0073" }, //( ѕ → s ) CYRILLIC SMALL LETTER DZE → LATIN SMALL LETTER S	# 
			{ L"\x0001\x18C1",L"\x0073" }, //( 𑣁 → s ) WARANG CITI SMALL LETTER A → LATIN SMALL LETTER S	# 
			{ L"\x0001\x0448",L"\x0073" }, //( 𐑈 → s ) DESERET SMALL LETTER ZHEE → LATIN SMALL LETTER S	# 

			{ L"\xFF33",L"\x0053" }, //( Ｓ → S ) FULLWIDTH LATIN CAPITAL LETTER S → LATIN CAPITAL LETTER S	# →Ѕ→
			{ L"\x0001\xD412",L"\x0053" }, //( 𝐒 → S ) MATHEMATICAL BOLD CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD446",L"\x0053" }, //( 𝑆 → S ) MATHEMATICAL ITALIC CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD47A",L"\x0053" }, //( 𝑺 → S ) MATHEMATICAL BOLD ITALIC CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD4AE",L"\x0053" }, //( 𝒮 → S ) MATHEMATICAL SCRIPT CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD4E2",L"\x0053" }, //( 𝓢 → S ) MATHEMATICAL BOLD SCRIPT CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD516",L"\x0053" }, //( 𝔖 → S ) MATHEMATICAL FRAKTUR CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD54A",L"\x0053" }, //( 𝕊 → S ) MATHEMATICAL DOUBLE-STRUCK CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD57E",L"\x0053" }, //( 𝕾 → S ) MATHEMATICAL BOLD FRAKTUR CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD5B2",L"\x0053" }, //( 𝖲 → S ) MATHEMATICAL SANS-SERIF CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD5E6",L"\x0053" }, //( 𝗦 → S ) MATHEMATICAL SANS-SERIF BOLD CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD61A",L"\x0053" }, //( 𝘚 → S ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD64E",L"\x0053" }, //( 𝙎 → S ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\xD682",L"\x0053" }, //( 𝚂 → S ) MATHEMATICAL MONOSPACE CAPITAL S → LATIN CAPITAL LETTER S	# 
			{ L"\x0405",L"\x0053" }, //( Ѕ → S ) CYRILLIC CAPITAL LETTER DZE → LATIN CAPITAL LETTER S	# 
			{ L"\x054F",L"\x0053" }, //( Տ → S ) ARMENIAN CAPITAL LETTER TIWN → LATIN CAPITAL LETTER S	# 
			{ L"\x13D5",L"\x0053" }, //( Ꮥ → S ) CHEROKEE LETTER DE → LATIN CAPITAL LETTER S	# 
			{ L"\x13DA",L"\x0053" }, //( Ꮪ → S ) CHEROKEE LETTER DU → LATIN CAPITAL LETTER S	# 
			{ L"\xA4E2",L"\x0053" }, //( ꓢ → S ) LISU LETTER SA → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\x0296",L"\x0053" }, //( 𐊖 → S ) LYCIAN LETTER S → LATIN CAPITAL LETTER S	# 
			{ L"\x0001\x0420",L"\x0053" }, //( 𐐠 → S ) DESERET CAPITAL LETTER ZHEE → LATIN CAPITAL LETTER S	# 

			{ L"\x0282",L"\x0073\x0328" }, //( ʂ → s̨ ) LATIN SMALL LETTER S WITH HOOK → LATIN SMALL LETTER S, COMBINING OGONEK	# 

			{ L"\x1D74",L"\x0073\x0334" }, //( ᵴ → s̴ ) LATIN SMALL LETTER S WITH MIDDLE TILDE → LATIN SMALL LETTER S, COMBINING TILDE OVERLAY	# 

			{ L"\x03B2",L"\x00DF" }, //( β → ß ) GREEK SMALL LETTER BETA → LATIN SMALL LETTER SHARP S	# 
			{ L"\x03D0",L"\x00DF" }, //( ϐ → ß ) GREEK BETA SYMBOL → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\x0001\xD6C3",L"\x00DF" }, //( 𝛃 → ß ) MATHEMATICAL BOLD SMALL BETA → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\x0001\xD6FD",L"\x00DF" }, //( 𝛽 → ß ) MATHEMATICAL ITALIC SMALL BETA → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\x0001\xD737",L"\x00DF" }, //( 𝜷 → ß ) MATHEMATICAL BOLD ITALIC SMALL BETA → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\x0001\xD771",L"\x00DF" }, //( 𝝱 → ß ) MATHEMATICAL SANS-SERIF BOLD SMALL BETA → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\x0001\xD7AB",L"\x00DF" }, //( 𝞫 → ß ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL BETA → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\x13F0",L"\x00DF" }, //( Ᏸ → ß ) CHEROKEE LETTER YE → LATIN SMALL LETTER SHARP S	# →β→
			{ L"\xA7B5",L"\x00DF" }, //( ꞵ → ß ) LATIN SMALL LETTER BETA → LATIN SMALL LETTER SHARP S	# →β→

			{ L"\x0001\xF75C",L"\x0073\x0073\x0073" }, //( 🝜 → sss ) ALCHEMICAL SYMBOL FOR STRATUM SUPER STRATUM → LATIN SMALL LETTER S, LATIN SMALL LETTER S, LATIN SMALL LETTER S	# 

			{ L"\xFB06",L"\x0073\x0074" }, //( ﬆ → st ) LATIN SMALL LIGATURE ST → LATIN SMALL LETTER S, LATIN SMALL LETTER T	# 

			{ L"\x222B",L"\x0283" }, //( ∫ → ʃ ) INTEGRAL → LATIN SMALL LETTER ESH	# 
			{ L"\xAB4D",L"\x0283" }, //( ꭍ → ʃ ) LATIN SMALL LETTER BASELINE ESH → LATIN SMALL LETTER ESH	# 

			{ L"\x2211",L"\x01A9" }, //( ∑ → Ʃ ) N-ARY SUMMATION → LATIN CAPITAL LETTER ESH	# 
			{ L"\x2140",L"\x01A9" }, //( ⅀ → Ʃ ) DOUBLE-STRUCK N-ARY SUMMATION → LATIN CAPITAL LETTER ESH	# →∑→
			{ L"\x03A3",L"\x01A9" }, //( Σ → Ʃ ) GREEK CAPITAL LETTER SIGMA → LATIN CAPITAL LETTER ESH	# 
			{ L"\x0001\xD6BA",L"\x01A9" }, //( 𝚺 → Ʃ ) MATHEMATICAL BOLD CAPITAL SIGMA → LATIN CAPITAL LETTER ESH	# →Σ→
			{ L"\x0001\xD6F4",L"\x01A9" }, //( 𝛴 → Ʃ ) MATHEMATICAL ITALIC CAPITAL SIGMA → LATIN CAPITAL LETTER ESH	# →Σ→
			{ L"\x0001\xD72E",L"\x01A9" }, //( 𝜮 → Ʃ ) MATHEMATICAL BOLD ITALIC CAPITAL SIGMA → LATIN CAPITAL LETTER ESH	# →Σ→
			{ L"\x0001\xD768",L"\x01A9" }, //( 𝝨 → Ʃ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL SIGMA → LATIN CAPITAL LETTER ESH	# →Σ→
			{ L"\x0001\xD7A2",L"\x01A9" }, //( 𝞢 → Ʃ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL SIGMA → LATIN CAPITAL LETTER ESH	# →Σ→
			{ L"\x2D49",L"\x01A9" }, //( ⵉ → Ʃ ) TIFINAGH LETTER YI → LATIN CAPITAL LETTER ESH	# 

			{ L"\x222C",L"\x0283\x0283" }, //( ∬ → ʃʃ ) DOUBLE INTEGRAL → LATIN SMALL LETTER ESH, LATIN SMALL LETTER ESH	# →∫∫→

			{ L"\x222D",L"\x0283\x0283\x0283" }, //( ∭ → ʃʃʃ ) TRIPLE INTEGRAL → LATIN SMALL LETTER ESH, LATIN SMALL LETTER ESH, LATIN SMALL LETTER ESH	# →∫∫∫→

			{ L"\x2A0C",L"\x0283\x0283\x0283\x0283" }, //( ⨌ → ʃʃʃʃ ) QUADRUPLE INTEGRAL OPERATOR → LATIN SMALL LETTER ESH, LATIN SMALL LETTER ESH, LATIN SMALL LETTER ESH, LATIN SMALL LETTER ESH	# →∫∫∫∫→

			{ L"\x0001\xD42D",L"\x0074" }, //( 𝐭 → t ) MATHEMATICAL BOLD SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD461",L"\x0074" }, //( 𝑡 → t ) MATHEMATICAL ITALIC SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD495",L"\x0074" }, //( 𝒕 → t ) MATHEMATICAL BOLD ITALIC SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD4C9",L"\x0074" }, //( 𝓉 → t ) MATHEMATICAL SCRIPT SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD4FD",L"\x0074" }, //( 𝓽 → t ) MATHEMATICAL BOLD SCRIPT SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD531",L"\x0074" }, //( 𝔱 → t ) MATHEMATICAL FRAKTUR SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD565",L"\x0074" }, //( 𝕥 → t ) MATHEMATICAL DOUBLE-STRUCK SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD599",L"\x0074" }, //( 𝖙 → t ) MATHEMATICAL BOLD FRAKTUR SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD5CD",L"\x0074" }, //( 𝗍 → t ) MATHEMATICAL SANS-SERIF SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD601",L"\x0074" }, //( 𝘁 → t ) MATHEMATICAL SANS-SERIF BOLD SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD635",L"\x0074" }, //( 𝘵 → t ) MATHEMATICAL SANS-SERIF ITALIC SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD669",L"\x0074" }, //( 𝙩 → t ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD69D",L"\x0074" }, //( 𝚝 → t ) MATHEMATICAL MONOSPACE SMALL T → LATIN SMALL LETTER T	# 
			{ L"\x1D1B",L"\x0074" }, //( ᴛ → t ) LATIN LETTER SMALL CAPITAL T → LATIN SMALL LETTER T	# →т→→τ→
			{ L"\x03C4",L"\x0074" }, //( τ → t ) GREEK SMALL LETTER TAU → LATIN SMALL LETTER T	# 
			{ L"\x0001\xD6D5",L"\x0074" }, //( 𝛕 → t ) MATHEMATICAL BOLD SMALL TAU → LATIN SMALL LETTER T	# →τ→
			{ L"\x0001\xD70F",L"\x0074" }, //( 𝜏 → t ) MATHEMATICAL ITALIC SMALL TAU → LATIN SMALL LETTER T	# →τ→
			{ L"\x0001\xD749",L"\x0074" }, //( 𝝉 → t ) MATHEMATICAL BOLD ITALIC SMALL TAU → LATIN SMALL LETTER T	# →τ→
			{ L"\x0001\xD783",L"\x0074" }, //( 𝞃 → t ) MATHEMATICAL SANS-SERIF BOLD SMALL TAU → LATIN SMALL LETTER T	# →τ→
			{ L"\x0001\xD7BD",L"\x0074" }, //( 𝞽 → t ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL TAU → LATIN SMALL LETTER T	# →τ→
			{ L"\x0442",L"\x0074" }, //( т → t ) CYRILLIC SMALL LETTER TE → LATIN SMALL LETTER T	# →τ→

			{ L"\x22A4",L"\x0054" }, //( ⊤ → T ) DOWN TACK → LATIN CAPITAL LETTER T	# 
			{ L"\x27D9",L"\x0054" }, //( ⟙ → T ) LARGE DOWN TACK → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xF768",L"\x0054" }, //( 🝨 → T ) ALCHEMICAL SYMBOL FOR CRUCIBLE-4 → LATIN CAPITAL LETTER T	# 
			{ L"\xFF34",L"\x0054" }, //( Ｔ → T ) FULLWIDTH LATIN CAPITAL LETTER T → LATIN CAPITAL LETTER T	# →Т→
			{ L"\x0001\xD413",L"\x0054" }, //( 𝐓 → T ) MATHEMATICAL BOLD CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD447",L"\x0054" }, //( 𝑇 → T ) MATHEMATICAL ITALIC CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD47B",L"\x0054" }, //( 𝑻 → T ) MATHEMATICAL BOLD ITALIC CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD4AF",L"\x0054" }, //( 𝒯 → T ) MATHEMATICAL SCRIPT CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD4E3",L"\x0054" }, //( 𝓣 → T ) MATHEMATICAL BOLD SCRIPT CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD517",L"\x0054" }, //( 𝔗 → T ) MATHEMATICAL FRAKTUR CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD54B",L"\x0054" }, //( 𝕋 → T ) MATHEMATICAL DOUBLE-STRUCK CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD57F",L"\x0054" }, //( 𝕿 → T ) MATHEMATICAL BOLD FRAKTUR CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD5B3",L"\x0054" }, //( 𝖳 → T ) MATHEMATICAL SANS-SERIF CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD5E7",L"\x0054" }, //( 𝗧 → T ) MATHEMATICAL SANS-SERIF BOLD CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD61B",L"\x0054" }, //( 𝘛 → T ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD64F",L"\x0054" }, //( 𝙏 → T ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD683",L"\x0054" }, //( 𝚃 → T ) MATHEMATICAL MONOSPACE CAPITAL T → LATIN CAPITAL LETTER T	# 
			{ L"\x03A4",L"\x0054" }, //( Τ → T ) GREEK CAPITAL LETTER TAU → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\xD6BB",L"\x0054" }, //( 𝚻 → T ) MATHEMATICAL BOLD CAPITAL TAU → LATIN CAPITAL LETTER T	# →Τ→
			{ L"\x0001\xD6F5",L"\x0054" }, //( 𝛵 → T ) MATHEMATICAL ITALIC CAPITAL TAU → LATIN CAPITAL LETTER T	# →Τ→
			{ L"\x0001\xD72F",L"\x0054" }, //( 𝜯 → T ) MATHEMATICAL BOLD ITALIC CAPITAL TAU → LATIN CAPITAL LETTER T	# →Τ→
			{ L"\x0001\xD769",L"\x0054" }, //( 𝝩 → T ) MATHEMATICAL SANS-SERIF BOLD CAPITAL TAU → LATIN CAPITAL LETTER T	# →Τ→
			{ L"\x0001\xD7A3",L"\x0054" }, //( 𝞣 → T ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL TAU → LATIN CAPITAL LETTER T	# →Τ→
			{ L"\x2CA6",L"\x0054" }, //( Ⲧ → T ) COPTIC CAPITAL LETTER TAU → LATIN CAPITAL LETTER T	# 
			{ L"\x0422",L"\x0054" }, //( Т → T ) CYRILLIC CAPITAL LETTER TE → LATIN CAPITAL LETTER T	# 
			{ L"\x13A2",L"\x0054" }, //( Ꭲ → T ) CHEROKEE LETTER I → LATIN CAPITAL LETTER T	# 
			{ L"\xA4D4",L"\x0054" }, //( ꓔ → T ) LISU LETTER TA → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\x18BC",L"\x0054" }, //( 𑢼 → T ) WARANG CITI CAPITAL LETTER HAR → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\x0297",L"\x0054" }, //( 𐊗 → T ) LYCIAN LETTER T → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\x02B1",L"\x0054" }, //( 𐊱 → T ) CARIAN LETTER C-18 → LATIN CAPITAL LETTER T	# 
			{ L"\x0001\x0315",L"\x0054" }, //( 𐌕 → T ) OLD ITALIC LETTER TE → LATIN CAPITAL LETTER T	# 

			{ L"\x01AD",L"\x0074\x0314" }, //( ƭ → t̔ ) LATIN SMALL LETTER T WITH HOOK → LATIN SMALL LETTER T, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x2361",L"\x0054\x0308" }, //( ⍡ → T̈ ) APL FUNCTIONAL SYMBOL UP TACK DIAERESIS → LATIN CAPITAL LETTER T, COMBINING DIAERESIS	# →⊤̈→

			{ L"\x023E",L"\x0054\x0338" }, //( Ⱦ → T̸ ) LATIN CAPITAL LETTER T WITH DIAGONAL STROKE → LATIN CAPITAL LETTER T, COMBINING LONG SOLIDUS OVERLAY	# 

			{ L"\x021A",L"\x0162" }, //( Ț → Ţ ) LATIN CAPITAL LETTER T WITH COMMA BELOW → LATIN CAPITAL LETTER T WITH CEDILLA	# 

			{ L"\x01AE",L"\x0054\x0328" }, //( Ʈ → T̨ ) LATIN CAPITAL LETTER T WITH RETROFLEX HOOK → LATIN CAPITAL LETTER T, COMBINING OGONEK	# 

			{ L"\x04AD",L"\x0074\x0329" }, //( ҭ → t̩ ) CYRILLIC SMALL LETTER TE WITH DESCENDER → LATIN SMALL LETTER T, COMBINING VERTICAL LINE BELOW	# →т̩→

			{ L"\x04AC",L"\x0054\x0329" }, //( Ҭ → T̩ ) CYRILLIC CAPITAL LETTER TE WITH DESCENDER → LATIN CAPITAL LETTER T, COMBINING VERTICAL LINE BELOW	# →Т̩→

			{ L"\x20AE",L"\x0054\x20EB" }, //( ₮ → T⃫ ) TUGRIK SIGN → LATIN CAPITAL LETTER T, COMBINING LONG DOUBLE SOLIDUS OVERLAY	# →Т⃫→

			{ L"\x0167",L"\x0074\x0335" }, //( ŧ → t̵ ) LATIN SMALL LETTER T WITH STROKE → LATIN SMALL LETTER T, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x0166",L"\x0054\x0335" }, //( Ŧ → T̵ ) LATIN CAPITAL LETTER T WITH STROKE → LATIN CAPITAL LETTER T, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x1D75",L"\x0074\x0334" }, //( ᵵ → t̴ ) LATIN SMALL LETTER T WITH MIDDLE TILDE → LATIN SMALL LETTER T, COMBINING TILDE OVERLAY	# 

			{ L"\x10A0",L"\xA786" }, //( Ⴀ → Ꞇ ) GEORGIAN CAPITAL LETTER AN → LATIN CAPITAL LETTER INSULAR T	# 

			{ L"\xA728",L"\x0054\x0033" }, //( Ꜩ → T3 ) LATIN CAPITAL LETTER TZ → LATIN CAPITAL LETTER T, DIGIT THREE	# →TƷ→

			{ L"\x02A8",L"\x0074\x0255" }, //( ʨ → tɕ ) LATIN SMALL LETTER TC DIGRAPH WITH CURL → LATIN SMALL LETTER T, LATIN SMALL LETTER C WITH CURL	# 

			{ L"\x2121",L"\x0054\x0045\x004C" }, //( ℡ → TEL ) TELEPHONE SIGN → LATIN CAPITAL LETTER T, LATIN CAPITAL LETTER E, LATIN CAPITAL LETTER L	# 

			{ L"\xA777",L"\x0074\x0066" }, //( ꝷ → tf ) LATIN SMALL LETTER TUM → LATIN SMALL LETTER T, LATIN SMALL LETTER F	# 

			{ L"\x02A6",L"\x0074\x0073" }, //( ʦ → ts ) LATIN SMALL LETTER TS DIGRAPH → LATIN SMALL LETTER T, LATIN SMALL LETTER S	# 

			{ L"\x02A7",L"\x0074\x0283" }, //( ʧ → tʃ ) LATIN SMALL LETTER TESH DIGRAPH → LATIN SMALL LETTER T, LATIN SMALL LETTER ESH	# 

			{ L"\xA729",L"\x0074\x021D" }, //( ꜩ → tȝ ) LATIN SMALL LETTER TZ → LATIN SMALL LETTER T, LATIN SMALL LETTER YOGH	# 

			{ L"\x0163",L"\x01AB" }, //( ţ → ƫ ) LATIN SMALL LETTER T WITH CEDILLA → LATIN SMALL LETTER T WITH PALATAL HOOK	# 
			{ L"\x021B",L"\x01AB" }, //( ț → ƫ ) LATIN SMALL LETTER T WITH COMMA BELOW → LATIN SMALL LETTER T WITH PALATAL HOOK	# →ţ→
			{ L"\x13BF",L"\x01AB" }, //( Ꮏ → ƫ ) CHEROKEE LETTER HNA → LATIN SMALL LETTER T WITH PALATAL HOOK	# 

			{ L"\x0001\xD42E",L"\x0075" }, //( 𝐮 → u ) MATHEMATICAL BOLD SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD462",L"\x0075" }, //( 𝑢 → u ) MATHEMATICAL ITALIC SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD496",L"\x0075" }, //( 𝒖 → u ) MATHEMATICAL BOLD ITALIC SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD4CA",L"\x0075" }, //( 𝓊 → u ) MATHEMATICAL SCRIPT SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD4FE",L"\x0075" }, //( 𝓾 → u ) MATHEMATICAL BOLD SCRIPT SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD532",L"\x0075" }, //( 𝔲 → u ) MATHEMATICAL FRAKTUR SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD566",L"\x0075" }, //( 𝕦 → u ) MATHEMATICAL DOUBLE-STRUCK SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD59A",L"\x0075" }, //( 𝖚 → u ) MATHEMATICAL BOLD FRAKTUR SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD5CE",L"\x0075" }, //( 𝗎 → u ) MATHEMATICAL SANS-SERIF SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD602",L"\x0075" }, //( 𝘂 → u ) MATHEMATICAL SANS-SERIF BOLD SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD636",L"\x0075" }, //( 𝘶 → u ) MATHEMATICAL SANS-SERIF ITALIC SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD66A",L"\x0075" }, //( 𝙪 → u ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL U → LATIN SMALL LETTER U	# 
			{ L"\x0001\xD69E",L"\x0075" }, //( 𝚞 → u ) MATHEMATICAL MONOSPACE SMALL U → LATIN SMALL LETTER U	# 
			{ L"\xA79F",L"\x0075" }, //( ꞟ → u ) LATIN SMALL LETTER VOLAPUK UE → LATIN SMALL LETTER U	# 
			{ L"\x1D1C",L"\x0075" }, //( ᴜ → u ) LATIN LETTER SMALL CAPITAL U → LATIN SMALL LETTER U	# 
			{ L"\xAB4E",L"\x0075" }, //( ꭎ → u ) LATIN SMALL LETTER U WITH SHORT RIGHT LEG → LATIN SMALL LETTER U	# 
			{ L"\xAB52",L"\x0075" }, //( ꭒ → u ) LATIN SMALL LETTER U WITH LEFT HOOK → LATIN SMALL LETTER U	# 
			{ L"\x028B",L"\x0075" }, //( ʋ → u ) LATIN SMALL LETTER V WITH HOOK → LATIN SMALL LETTER U	# 
			{ L"\x03C5",L"\x0075" }, //( υ → u ) GREEK SMALL LETTER UPSILON → LATIN SMALL LETTER U	# →ʋ→
			{ L"\x0001\xD6D6",L"\x0075" }, //( 𝛖 → u ) MATHEMATICAL BOLD SMALL UPSILON → LATIN SMALL LETTER U	# →υ→→ʋ→
			{ L"\x0001\xD710",L"\x0075" }, //( 𝜐 → u ) MATHEMATICAL ITALIC SMALL UPSILON → LATIN SMALL LETTER U	# →υ→→ʋ→
			{ L"\x0001\xD74A",L"\x0075" }, //( 𝝊 → u ) MATHEMATICAL BOLD ITALIC SMALL UPSILON → LATIN SMALL LETTER U	# →υ→→ʋ→
			{ L"\x0001\xD784",L"\x0075" }, //( 𝞄 → u ) MATHEMATICAL SANS-SERIF BOLD SMALL UPSILON → LATIN SMALL LETTER U	# →υ→→ʋ→
			{ L"\x0001\xD7BE",L"\x0075" }, //( 𝞾 → u ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL UPSILON → LATIN SMALL LETTER U	# →υ→→ʋ→
			{ L"\x0446",L"\x0075" }, //( ц → u ) CYRILLIC SMALL LETTER TSE → LATIN SMALL LETTER U	# 
			{ L"\x057D",L"\x0075" }, //( ս → u ) ARMENIAN SMALL LETTER SEH → LATIN SMALL LETTER U	# 
			{ L"\x0001\x18D8",L"\x0075" }, //( 𑣘 → u ) WARANG CITI SMALL LETTER PU → LATIN SMALL LETTER U	# →υ→→ʋ→

			{ L"\x222A",L"\x0055" }, //( ∪ → U ) UNION → LATIN CAPITAL LETTER U	# →ᑌ→
			{ L"\x22C3",L"\x0055" }, //( ⋃ → U ) N-ARY UNION → LATIN CAPITAL LETTER U	# →∪→→ᑌ→
			{ L"\x0001\xD414",L"\x0055" }, //( 𝐔 → U ) MATHEMATICAL BOLD CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD448",L"\x0055" }, //( 𝑈 → U ) MATHEMATICAL ITALIC CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD47C",L"\x0055" }, //( 𝑼 → U ) MATHEMATICAL BOLD ITALIC CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD4B0",L"\x0055" }, //( 𝒰 → U ) MATHEMATICAL SCRIPT CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD4E4",L"\x0055" }, //( 𝓤 → U ) MATHEMATICAL BOLD SCRIPT CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD518",L"\x0055" }, //( 𝔘 → U ) MATHEMATICAL FRAKTUR CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD54C",L"\x0055" }, //( 𝕌 → U ) MATHEMATICAL DOUBLE-STRUCK CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD580",L"\x0055" }, //( 𝖀 → U ) MATHEMATICAL BOLD FRAKTUR CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD5B4",L"\x0055" }, //( 𝖴 → U ) MATHEMATICAL SANS-SERIF CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD5E8",L"\x0055" }, //( 𝗨 → U ) MATHEMATICAL SANS-SERIF BOLD CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD61C",L"\x0055" }, //( 𝘜 → U ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD650",L"\x0055" }, //( 𝙐 → U ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\xD684",L"\x0055" }, //( 𝚄 → U ) MATHEMATICAL MONOSPACE CAPITAL U → LATIN CAPITAL LETTER U	# 
			{ L"\x054D",L"\x0055" }, //( Ս → U ) ARMENIAN CAPITAL LETTER SEH → LATIN CAPITAL LETTER U	# 
			{ L"\x144C",L"\x0055" }, //( ᑌ → U ) CANADIAN SYLLABICS TE → LATIN CAPITAL LETTER U	# 
			{ L"\xA4F4",L"\x0055" }, //( ꓴ → U ) LISU LETTER U → LATIN CAPITAL LETTER U	# 
			{ L"\x0001\x18B8",L"\x0055" }, //( 𑢸 → U ) WARANG CITI CAPITAL LETTER PU → LATIN CAPITAL LETTER U	# 

			{ L"\x01D4",L"\x016D" }, //( ǔ → ŭ ) LATIN SMALL LETTER U WITH CARON → LATIN SMALL LETTER U WITH BREVE	# 

			{ L"\x01D3",L"\x016C" }, //( Ǔ → Ŭ ) LATIN CAPITAL LETTER U WITH CARON → LATIN CAPITAL LETTER U WITH BREVE	# 

			{ L"\x1D7E",L"\x0075\x0335" }, //( ᵾ → u̵ ) LATIN SMALL CAPITAL LETTER U WITH STROKE → LATIN SMALL LETTER U, COMBINING SHORT STROKE OVERLAY	# →ᴜ̵→

			{ L"\x0244",L"\x0055\x0335" }, //( Ʉ → U̵ ) LATIN CAPITAL LETTER U BAR → LATIN CAPITAL LETTER U, COMBINING SHORT STROKE OVERLAY	# →U̶→
			{ L"\x13CC",L"\x0055\x0335" }, //( Ꮜ → U̵ ) CHEROKEE LETTER SA → LATIN CAPITAL LETTER U, COMBINING SHORT STROKE OVERLAY	# →Ʉ→→U̶→

			{ L"\x1458",L"\x0055\x00B7" }, //( ᑘ → U· ) CANADIAN SYLLABICS WEST-CREE TWE → LATIN CAPITAL LETTER U, MIDDLE DOT	# →ᑌᐧ→→ᑌ·→

			{ L"\x1467",L"\x0055\x0027" }, //( ᑧ → U' ) CANADIAN SYLLABICS TTE → LATIN CAPITAL LETTER U, APOSTROPHE	# →ᑌᑊ→→ᑌ'→

			{ L"\x1D6B",L"\x0075\x0065" }, //( ᵫ → ue ) LATIN SMALL LETTER UE → LATIN SMALL LETTER U, LATIN SMALL LETTER E	# 

			{ L"\x057A",L"\x0270" }, //( պ → ɰ ) ARMENIAN SMALL LETTER PEH → LATIN SMALL LETTER TURNED M WITH LONG LEG	# 

			{ L"\x2127",L"\x01B1" }, //( ℧ → Ʊ ) INVERTED OHM SIGN → LATIN CAPITAL LETTER UPSILON	# 
			{ L"\x162E",L"\x01B1" }, //( ᘮ → Ʊ ) CANADIAN SYLLABICS CARRIER LHU → LATIN CAPITAL LETTER UPSILON	# →℧→
			{ L"\x1634",L"\x01B1" }, //( ᘴ → Ʊ ) CANADIAN SYLLABICS CARRIER TLHU → LATIN CAPITAL LETTER UPSILON	# →ᘮ→→℧→

			{ L"\x1D7F",L"\x028A\x0335" }, //( ᵿ → ʊ̵ ) LATIN SMALL LETTER UPSILON WITH STROKE → LATIN SMALL LETTER UPSILON, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x2228",L"\x0076" }, //( ∨ → v ) LOGICAL OR → LATIN SMALL LETTER V	# 
			{ L"\x22C1",L"\x0076" }, //( ⋁ → v ) N-ARY LOGICAL OR → LATIN SMALL LETTER V	# →∨→
			{ L"\xFF56",L"\x0076" }, //( ｖ → v ) FULLWIDTH LATIN SMALL LETTER V → LATIN SMALL LETTER V	# →ν→
			{ L"\x2174",L"\x0076" }, //( ⅴ → v ) SMALL ROMAN NUMERAL FIVE → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD42F",L"\x0076" }, //( 𝐯 → v ) MATHEMATICAL BOLD SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD463",L"\x0076" }, //( 𝑣 → v ) MATHEMATICAL ITALIC SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD497",L"\x0076" }, //( 𝒗 → v ) MATHEMATICAL BOLD ITALIC SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD4CB",L"\x0076" }, //( 𝓋 → v ) MATHEMATICAL SCRIPT SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD4FF",L"\x0076" }, //( 𝓿 → v ) MATHEMATICAL BOLD SCRIPT SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD533",L"\x0076" }, //( 𝔳 → v ) MATHEMATICAL FRAKTUR SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD567",L"\x0076" }, //( 𝕧 → v ) MATHEMATICAL DOUBLE-STRUCK SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD59B",L"\x0076" }, //( 𝖛 → v ) MATHEMATICAL BOLD FRAKTUR SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD5CF",L"\x0076" }, //( 𝗏 → v ) MATHEMATICAL SANS-SERIF SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD603",L"\x0076" }, //( 𝘃 → v ) MATHEMATICAL SANS-SERIF BOLD SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD637",L"\x0076" }, //( 𝘷 → v ) MATHEMATICAL SANS-SERIF ITALIC SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD66B",L"\x0076" }, //( 𝙫 → v ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD69F",L"\x0076" }, //( 𝚟 → v ) MATHEMATICAL MONOSPACE SMALL V → LATIN SMALL LETTER V	# 
			{ L"\x1D20",L"\x0076" }, //( ᴠ → v ) LATIN LETTER SMALL CAPITAL V → LATIN SMALL LETTER V	# 
			{ L"\x03BD",L"\x0076" }, //( ν → v ) GREEK SMALL LETTER NU → LATIN SMALL LETTER V	# 
			{ L"\x0001\xD6CE",L"\x0076" }, //( 𝛎 → v ) MATHEMATICAL BOLD SMALL NU → LATIN SMALL LETTER V	# →ν→
			{ L"\x0001\xD708",L"\x0076" }, //( 𝜈 → v ) MATHEMATICAL ITALIC SMALL NU → LATIN SMALL LETTER V	# →ν→
			{ L"\x0001\xD742",L"\x0076" }, //( 𝝂 → v ) MATHEMATICAL BOLD ITALIC SMALL NU → LATIN SMALL LETTER V	# →ν→
			{ L"\x0001\xD77C",L"\x0076" }, //( 𝝼 → v ) MATHEMATICAL SANS-SERIF BOLD SMALL NU → LATIN SMALL LETTER V	# →ν→
			{ L"\x0001\xD7B6",L"\x0076" }, //( 𝞶 → v ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL NU → LATIN SMALL LETTER V	# →ν→
			{ L"\x0475",L"\x0076" }, //( ѵ → v ) CYRILLIC SMALL LETTER IZHITSA → LATIN SMALL LETTER V	# 
			{ L"\x05D8",L"\x0076" }, //( ‎ט‎ → v ) HEBREW LETTER TET → LATIN SMALL LETTER V	# 
			{ L"\x0001\x18C0",L"\x0076" }, //( 𑣀 → v ) WARANG CITI SMALL LETTER NGAA → LATIN SMALL LETTER V	# 

			{ L"\x0667",L"\x0056" }, //( ‎٧‎ → V ) ARABIC-INDIC DIGIT SEVEN → LATIN CAPITAL LETTER V	# 
			{ L"\x06F7",L"\x0056" }, //( ۷ → V ) EXTENDED ARABIC-INDIC DIGIT SEVEN → LATIN CAPITAL LETTER V	# →‎٧‎→
			{ L"\x2164",L"\x0056" }, //( Ⅴ → V ) ROMAN NUMERAL FIVE → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD415",L"\x0056" }, //( 𝐕 → V ) MATHEMATICAL BOLD CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD449",L"\x0056" }, //( 𝑉 → V ) MATHEMATICAL ITALIC CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD47D",L"\x0056" }, //( 𝑽 → V ) MATHEMATICAL BOLD ITALIC CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD4B1",L"\x0056" }, //( 𝒱 → V ) MATHEMATICAL SCRIPT CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD4E5",L"\x0056" }, //( 𝓥 → V ) MATHEMATICAL BOLD SCRIPT CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD519",L"\x0056" }, //( 𝔙 → V ) MATHEMATICAL FRAKTUR CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD54D",L"\x0056" }, //( 𝕍 → V ) MATHEMATICAL DOUBLE-STRUCK CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD581",L"\x0056" }, //( 𝖁 → V ) MATHEMATICAL BOLD FRAKTUR CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD5B5",L"\x0056" }, //( 𝖵 → V ) MATHEMATICAL SANS-SERIF CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD5E9",L"\x0056" }, //( 𝗩 → V ) MATHEMATICAL SANS-SERIF BOLD CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD61D",L"\x0056" }, //( 𝘝 → V ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD651",L"\x0056" }, //( 𝙑 → V ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\xD685",L"\x0056" }, //( 𝚅 → V ) MATHEMATICAL MONOSPACE CAPITAL V → LATIN CAPITAL LETTER V	# 
			{ L"\x0474",L"\x0056" }, //( Ѵ → V ) CYRILLIC CAPITAL LETTER IZHITSA → LATIN CAPITAL LETTER V	# 
			{ L"\x2D38",L"\x0056" }, //( ⴸ → V ) TIFINAGH LETTER YADH → LATIN CAPITAL LETTER V	# 
			{ L"\x13D9",L"\x0056" }, //( Ꮩ → V ) CHEROKEE LETTER DO → LATIN CAPITAL LETTER V	# 
			{ L"\x142F",L"\x0056" }, //( ᐯ → V ) CANADIAN SYLLABICS PE → LATIN CAPITAL LETTER V	# 
			{ L"\xA4E6",L"\x0056" }, //( ꓦ → V ) LISU LETTER HA → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\x18A0",L"\x0056" }, //( 𑢠 → V ) WARANG CITI CAPITAL LETTER NGAA → LATIN CAPITAL LETTER V	# 
			{ L"\x0001\x051D",L"\x0056" }, //( 𐔝 → V ) ELBASAN LETTER TE → LATIN CAPITAL LETTER V	# 

			{ L"\x143B",L"\x0056\x00B7" }, //( ᐻ → V· ) CANADIAN SYLLABICS WEST-CREE PWE → LATIN CAPITAL LETTER V, MIDDLE DOT	# →ᐯᐧ→

			{ L"\x0001\xF76C",L"\x0056\x0042" }, //( 🝬 → VB ) ALCHEMICAL SYMBOL FOR BATH OF VAPOURS → LATIN CAPITAL LETTER V, LATIN CAPITAL LETTER B	# 

			{ L"\x2175",L"\x0076\x0069" }, //( ⅵ → vi ) SMALL ROMAN NUMERAL SIX → LATIN SMALL LETTER V, LATIN SMALL LETTER I	# 

			{ L"\x2176",L"\x0076\x0069\x0069" }, //( ⅶ → vii ) SMALL ROMAN NUMERAL SEVEN → LATIN SMALL LETTER V, LATIN SMALL LETTER I, LATIN SMALL LETTER I	# 

			{ L"\x2177",L"\x0076\x0069\x0069\x0069" }, //( ⅷ → viii ) SMALL ROMAN NUMERAL EIGHT → LATIN SMALL LETTER V, LATIN SMALL LETTER I, LATIN SMALL LETTER I, LATIN SMALL LETTER I	# 

			{ L"\x2165",L"\x0056\x006C" }, //( Ⅵ → Vl ) ROMAN NUMERAL SIX → LATIN CAPITAL LETTER V, LATIN SMALL LETTER L	# →VI→

			{ L"\x2166",L"\x0056\x006C\x006C" }, //( Ⅶ → Vll ) ROMAN NUMERAL SEVEN → LATIN CAPITAL LETTER V, LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →VII→

			{ L"\x2167",L"\x0056\x006C\x006C\x006C" }, //( Ⅷ → Vlll ) ROMAN NUMERAL EIGHT → LATIN CAPITAL LETTER V, LATIN SMALL LETTER L, LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →VIII→

			{ L"\x0001\xF708",L"\x0056\x1DE4" }, //( 🜈 → Vᷤ ) ALCHEMICAL SYMBOL FOR AQUA VITAE → LATIN CAPITAL LETTER V, COMBINING LATIN SMALL LETTER S	# 

			{ L"\x026F",L"\x0076\x0076" }, //( ɯ → vv ) LATIN SMALL LETTER TURNED M → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0077",L"\x0076\x0076" }, //( w → vv ) LATIN SMALL LETTER W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# 
			{ L"\x0001\xD430",L"\x0076\x0076" }, //( 𝐰 → vv ) MATHEMATICAL BOLD SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD464",L"\x0076\x0076" }, //( 𝑤 → vv ) MATHEMATICAL ITALIC SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD498",L"\x0076\x0076" }, //( 𝒘 → vv ) MATHEMATICAL BOLD ITALIC SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD4CC",L"\x0076\x0076" }, //( 𝓌 → vv ) MATHEMATICAL SCRIPT SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD500",L"\x0076\x0076" }, //( 𝔀 → vv ) MATHEMATICAL BOLD SCRIPT SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD534",L"\x0076\x0076" }, //( 𝔴 → vv ) MATHEMATICAL FRAKTUR SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD568",L"\x0076\x0076" }, //( 𝕨 → vv ) MATHEMATICAL DOUBLE-STRUCK SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD59C",L"\x0076\x0076" }, //( 𝖜 → vv ) MATHEMATICAL BOLD FRAKTUR SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD5D0",L"\x0076\x0076" }, //( 𝗐 → vv ) MATHEMATICAL SANS-SERIF SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD604",L"\x0076\x0076" }, //( 𝘄 → vv ) MATHEMATICAL SANS-SERIF BOLD SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD638",L"\x0076\x0076" }, //( 𝘸 → vv ) MATHEMATICAL SANS-SERIF ITALIC SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD66C",L"\x0076\x0076" }, //( 𝙬 → vv ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\xD6A0",L"\x0076\x0076" }, //( 𝚠 → vv ) MATHEMATICAL MONOSPACE SMALL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x1D21",L"\x0076\x0076" }, //( ᴡ → vv ) LATIN LETTER SMALL CAPITAL W → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0461",L"\x0076\x0076" }, //( ѡ → vv ) CYRILLIC SMALL LETTER OMEGA → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x051D",L"\x0076\x0076" }, //( ԝ → vv ) CYRILLIC SMALL LETTER WE → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0561",L"\x0076\x0076" }, //( ա → vv ) ARMENIAN SMALL LETTER AYB → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →ɯ→→w→
			{ L"\x0001\x170E",L"\x0076\x0076" }, //( 𑜎 → vv ) AHOM LETTER LA → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→
			{ L"\x0001\x170F",L"\x0076\x0076" }, //( 𑜏 → vv ) AHOM LETTER SA → LATIN SMALL LETTER V, LATIN SMALL LETTER V	# →w→

			{ L"\x0001\x14C5",L"\x0076\x0076\x0307" }, //( 𑓅 → vv̇ ) TIRHUTA GVANG → LATIN SMALL LETTER V, LATIN SMALL LETTER V, COMBINING DOT ABOVE	# →ẇ→

			{ L"\x047D",L"\x0076\x0076\x0483" }, //( ѽ → vv҃ ) CYRILLIC SMALL LETTER OMEGA WITH TITLO → LATIN SMALL LETTER V, LATIN SMALL LETTER V, COMBINING CYRILLIC TITLO	# →ѡ҃→

			{ L"\xA761",L"\x0076\x0079" }, //( ꝡ → vy ) LATIN SMALL LETTER VY → LATIN SMALL LETTER V, LATIN SMALL LETTER Y	# 

			{ L"\x1D27",L"\x028C" }, //( ᴧ → ʌ ) GREEK LETTER SMALL CAPITAL LAMDA → LATIN SMALL LETTER TURNED V	# 

			{ L"\x0668",L"\x0245" }, //( ‎٨‎ → Ʌ ) ARABIC-INDIC DIGIT EIGHT → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x06F8",L"\x0245" }, //( ۸ → Ʌ ) EXTENDED ARABIC-INDIC DIGIT EIGHT → LATIN CAPITAL LETTER TURNED V	# →‎٨‎→→Λ→
			{ L"\x039B",L"\x0245" }, //( Λ → Ʌ ) GREEK CAPITAL LETTER LAMDA → LATIN CAPITAL LETTER TURNED V	# 
			{ L"\x0001\xD6B2",L"\x0245" }, //( 𝚲 → Ʌ ) MATHEMATICAL BOLD CAPITAL LAMDA → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x0001\xD6EC",L"\x0245" }, //( 𝛬 → Ʌ ) MATHEMATICAL ITALIC CAPITAL LAMDA → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x0001\xD726",L"\x0245" }, //( 𝜦 → Ʌ ) MATHEMATICAL BOLD ITALIC CAPITAL LAMDA → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x0001\xD760",L"\x0245" }, //( 𝝠 → Ʌ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL LAMDA → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x0001\xD79A",L"\x0245" }, //( 𝞚 → Ʌ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL LAMDA → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x041B",L"\x0245" }, //( Л → Ʌ ) CYRILLIC CAPITAL LETTER EL → LATIN CAPITAL LETTER TURNED V	# →Λ→
			{ L"\x2D37",L"\x0245" }, //( ⴷ → Ʌ ) TIFINAGH LETTER YAD → LATIN CAPITAL LETTER TURNED V	# 
			{ L"\x1431",L"\x0245" }, //( ᐱ → Ʌ ) CANADIAN SYLLABICS PI → LATIN CAPITAL LETTER TURNED V	# 
			{ L"\xA4E5",L"\x0245" }, //( ꓥ → Ʌ ) LISU LETTER NGA → LATIN CAPITAL LETTER TURNED V	# 
			{ L"\x0001\x028D",L"\x0245" }, //( 𐊍 → Ʌ ) LYCIAN LETTER L → LATIN CAPITAL LETTER TURNED V	# →Λ→

			{ L"\x04C5",L"\x0245\x0326" }, //( Ӆ → Ʌ̦ ) CYRILLIC CAPITAL LETTER EL WITH TAIL → LATIN CAPITAL LETTER TURNED V, COMBINING COMMA BELOW	# →Л̡→

			{ L"\x143D",L"\x0245\x00B7" }, //( ᐽ → Ʌ· ) CANADIAN SYLLABICS WEST-CREE PWI → LATIN CAPITAL LETTER TURNED V, MIDDLE DOT	# →ᐱᐧ→→ᐱ·→

			{ L"\x0001\x18EF",L"\x0057" }, //( 𑣯 → W ) WARANG CITI NUMBER SIXTY → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\x18E6",L"\x0057" }, //( 𑣦 → W ) WARANG CITI DIGIT SIX → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD416",L"\x0057" }, //( 𝐖 → W ) MATHEMATICAL BOLD CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD44A",L"\x0057" }, //( 𝑊 → W ) MATHEMATICAL ITALIC CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD47E",L"\x0057" }, //( 𝑾 → W ) MATHEMATICAL BOLD ITALIC CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD4B2",L"\x0057" }, //( 𝒲 → W ) MATHEMATICAL SCRIPT CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD4E6",L"\x0057" }, //( 𝓦 → W ) MATHEMATICAL BOLD SCRIPT CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD51A",L"\x0057" }, //( 𝔚 → W ) MATHEMATICAL FRAKTUR CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD54E",L"\x0057" }, //( 𝕎 → W ) MATHEMATICAL DOUBLE-STRUCK CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD582",L"\x0057" }, //( 𝖂 → W ) MATHEMATICAL BOLD FRAKTUR CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD5B6",L"\x0057" }, //( 𝖶 → W ) MATHEMATICAL SANS-SERIF CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD5EA",L"\x0057" }, //( 𝗪 → W ) MATHEMATICAL SANS-SERIF BOLD CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD61E",L"\x0057" }, //( 𝘞 → W ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD652",L"\x0057" }, //( 𝙒 → W ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x0001\xD686",L"\x0057" }, //( 𝚆 → W ) MATHEMATICAL MONOSPACE CAPITAL W → LATIN CAPITAL LETTER W	# 
			{ L"\x051C",L"\x0057" }, //( Ԝ → W ) CYRILLIC CAPITAL LETTER WE → LATIN CAPITAL LETTER W	# 
			{ L"\x13B3",L"\x0057" }, //( Ꮃ → W ) CHEROKEE LETTER LA → LATIN CAPITAL LETTER W	# 
			{ L"\x13D4",L"\x0057" }, //( Ꮤ → W ) CHEROKEE LETTER TA → LATIN CAPITAL LETTER W	# 
			{ L"\xA4EA",L"\x0057" }, //( ꓪ → W ) LISU LETTER WA → LATIN CAPITAL LETTER W	# 

			{ L"\x20A9",L"\x0057\x0335" }, //( ₩ → W̵ ) WON SIGN → LATIN CAPITAL LETTER W, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x166E",L"\x0078" }, //( ᙮ → x ) CANADIAN SYLLABICS FULL STOP → LATIN SMALL LETTER X	# 
			{ L"\x00D7",L"\x0078" }, //( × → x ) MULTIPLICATION SIGN → LATIN SMALL LETTER X	# 
			{ L"\x292B",L"\x0078" }, //( ⤫ → x ) RISING DIAGONAL CROSSING FALLING DIAGONAL → LATIN SMALL LETTER X	# 
			{ L"\x292C",L"\x0078" }, //( ⤬ → x ) FALLING DIAGONAL CROSSING RISING DIAGONAL → LATIN SMALL LETTER X	# 
			{ L"\x2A2F",L"\x0078" }, //( ⨯ → x ) VECTOR OR CROSS PRODUCT → LATIN SMALL LETTER X	# →×→
			{ L"\xFF58",L"\x0078" }, //( ｘ → x ) FULLWIDTH LATIN SMALL LETTER X → LATIN SMALL LETTER X	# →х→
			{ L"\x2179",L"\x0078" }, //( ⅹ → x ) SMALL ROMAN NUMERAL TEN → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD431",L"\x0078" }, //( 𝐱 → x ) MATHEMATICAL BOLD SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD465",L"\x0078" }, //( 𝑥 → x ) MATHEMATICAL ITALIC SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD499",L"\x0078" }, //( 𝒙 → x ) MATHEMATICAL BOLD ITALIC SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD4CD",L"\x0078" }, //( 𝓍 → x ) MATHEMATICAL SCRIPT SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD501",L"\x0078" }, //( 𝔁 → x ) MATHEMATICAL BOLD SCRIPT SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD535",L"\x0078" }, //( 𝔵 → x ) MATHEMATICAL FRAKTUR SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD569",L"\x0078" }, //( 𝕩 → x ) MATHEMATICAL DOUBLE-STRUCK SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD59D",L"\x0078" }, //( 𝖝 → x ) MATHEMATICAL BOLD FRAKTUR SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD5D1",L"\x0078" }, //( 𝗑 → x ) MATHEMATICAL SANS-SERIF SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD605",L"\x0078" }, //( 𝘅 → x ) MATHEMATICAL SANS-SERIF BOLD SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD639",L"\x0078" }, //( 𝘹 → x ) MATHEMATICAL SANS-SERIF ITALIC SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD66D",L"\x0078" }, //( 𝙭 → x ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0001\xD6A1",L"\x0078" }, //( 𝚡 → x ) MATHEMATICAL MONOSPACE SMALL X → LATIN SMALL LETTER X	# 
			{ L"\x0445",L"\x0078" }, //( х → x ) CYRILLIC SMALL LETTER HA → LATIN SMALL LETTER X	# 
			{ L"\x1541",L"\x0078" }, //( ᕁ → x ) CANADIAN SYLLABICS SAYISI YI → LATIN SMALL LETTER X	# →᙮→
			{ L"\x157D",L"\x0078" }, //( ᕽ → x ) CANADIAN SYLLABICS HK → LATIN SMALL LETTER X	# →ᕁ→→᙮→

			{ L"\x166D",L"\x0058" }, //( ᙭ → X ) CANADIAN SYLLABICS CHI SIGN → LATIN CAPITAL LETTER X	# 
			{ L"\x2573",L"\x0058" }, //( ╳ → X ) BOX DRAWINGS LIGHT DIAGONAL CROSS → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\x0322",L"\x0058" }, //( 𐌢 → X ) OLD ITALIC NUMERAL TEN → LATIN CAPITAL LETTER X	# →𐌗→
			{ L"\x0001\x18EC",L"\x0058" }, //( 𑣬 → X ) WARANG CITI NUMBER THIRTY → LATIN CAPITAL LETTER X	# 
			{ L"\xFF38",L"\x0058" }, //( Ｘ → X ) FULLWIDTH LATIN CAPITAL LETTER X → LATIN CAPITAL LETTER X	# →Х→
			{ L"\x2169",L"\x0058" }, //( Ⅹ → X ) ROMAN NUMERAL TEN → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD417",L"\x0058" }, //( 𝐗 → X ) MATHEMATICAL BOLD CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD44B",L"\x0058" }, //( 𝑋 → X ) MATHEMATICAL ITALIC CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD47F",L"\x0058" }, //( 𝑿 → X ) MATHEMATICAL BOLD ITALIC CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD4B3",L"\x0058" }, //( 𝒳 → X ) MATHEMATICAL SCRIPT CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD4E7",L"\x0058" }, //( 𝓧 → X ) MATHEMATICAL BOLD SCRIPT CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD51B",L"\x0058" }, //( 𝔛 → X ) MATHEMATICAL FRAKTUR CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD54F",L"\x0058" }, //( 𝕏 → X ) MATHEMATICAL DOUBLE-STRUCK CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD583",L"\x0058" }, //( 𝖃 → X ) MATHEMATICAL BOLD FRAKTUR CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD5B7",L"\x0058" }, //( 𝖷 → X ) MATHEMATICAL SANS-SERIF CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD5EB",L"\x0058" }, //( 𝗫 → X ) MATHEMATICAL SANS-SERIF BOLD CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD61F",L"\x0058" }, //( 𝘟 → X ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD653",L"\x0058" }, //( 𝙓 → X ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD687",L"\x0058" }, //( 𝚇 → X ) MATHEMATICAL MONOSPACE CAPITAL X → LATIN CAPITAL LETTER X	# 
			{ L"\x03A7",L"\x0058" }, //( Χ → X ) GREEK CAPITAL LETTER CHI → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\xD6BE",L"\x0058" }, //( 𝚾 → X ) MATHEMATICAL BOLD CAPITAL CHI → LATIN CAPITAL LETTER X	# →Χ→
			{ L"\x0001\xD6F8",L"\x0058" }, //( 𝛸 → X ) MATHEMATICAL ITALIC CAPITAL CHI → LATIN CAPITAL LETTER X	# →Χ→
			{ L"\x0001\xD732",L"\x0058" }, //( 𝜲 → X ) MATHEMATICAL BOLD ITALIC CAPITAL CHI → LATIN CAPITAL LETTER X	# →𝑿→
			{ L"\x0001\xD76C",L"\x0058" }, //( 𝝬 → X ) MATHEMATICAL SANS-SERIF BOLD CAPITAL CHI → LATIN CAPITAL LETTER X	# →Χ→
			{ L"\x0001\xD7A6",L"\x0058" }, //( 𝞦 → X ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL CHI → LATIN CAPITAL LETTER X	# →Χ→
			{ L"\x2CAC",L"\x0058" }, //( Ⲭ → X ) COPTIC CAPITAL LETTER KHI → LATIN CAPITAL LETTER X	# →Х→
			{ L"\x0425",L"\x0058" }, //( Х → X ) CYRILLIC CAPITAL LETTER HA → LATIN CAPITAL LETTER X	# 
			{ L"\x2D5D",L"\x0058" }, //( ⵝ → X ) TIFINAGH LETTER YATH → LATIN CAPITAL LETTER X	# 
			{ L"\x16B7",L"\x0058" }, //( ᚷ → X ) RUNIC LETTER GEBO GYFU G → LATIN CAPITAL LETTER X	# 
			{ L"\xA4EB",L"\x0058" }, //( ꓫ → X ) LISU LETTER SHA → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\x0290",L"\x0058" }, //( 𐊐 → X ) LYCIAN LETTER MM → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\x02B4",L"\x0058" }, //( 𐊴 → X ) CARIAN LETTER X → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\x0317",L"\x0058" }, //( 𐌗 → X ) OLD ITALIC LETTER EKS → LATIN CAPITAL LETTER X	# 
			{ L"\x0001\x0527",L"\x0058" }, //( 𐔧 → X ) ELBASAN LETTER KHE → LATIN CAPITAL LETTER X	# 
			{ L"\xA7B3",L"\x0058" }, //( Ꭓ → X ) LATIN CAPITAL LETTER CHI → LATIN CAPITAL LETTER X	# 

			{ L"\x2A30",L"\x0078\x0307" }, //( ⨰ → ẋ ) MULTIPLICATION SIGN WITH DOT ABOVE → LATIN SMALL LETTER X, COMBINING DOT ABOVE	# →×̇→

			{ L"\x04B2",L"\x0058\x0329" }, //( Ҳ → X̩ ) CYRILLIC CAPITAL LETTER HA WITH DESCENDER → LATIN CAPITAL LETTER X, COMBINING VERTICAL LINE BELOW	# →Х̩→

			{ L"\x217A",L"\x0078\x0069" }, //( ⅺ → xi ) SMALL ROMAN NUMERAL ELEVEN → LATIN SMALL LETTER X, LATIN SMALL LETTER I	# 

			{ L"\x217B",L"\x0078\x0069\x0069" }, //( ⅻ → xii ) SMALL ROMAN NUMERAL TWELVE → LATIN SMALL LETTER X, LATIN SMALL LETTER I, LATIN SMALL LETTER I	# 

			{ L"\x216A",L"\x0058\x006C" }, //( Ⅺ → Xl ) ROMAN NUMERAL ELEVEN → LATIN CAPITAL LETTER X, LATIN SMALL LETTER L	# →XI→

			{ L"\x216B",L"\x0058\x006C\x006C" }, //( Ⅻ → Xll ) ROMAN NUMERAL TWELVE → LATIN CAPITAL LETTER X, LATIN SMALL LETTER L, LATIN SMALL LETTER L	# →XII→

			{ L"\x0263",L"\x0079" }, //( ɣ → y ) LATIN SMALL LETTER GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x1D8C",L"\x0079" }, //( ᶌ → y ) LATIN SMALL LETTER V WITH PALATAL HOOK → LATIN SMALL LETTER Y	# 
			{ L"\xFF59",L"\x0079" }, //( ｙ → y ) FULLWIDTH LATIN SMALL LETTER Y → LATIN SMALL LETTER Y	# →у→
			{ L"\x0001\xD432",L"\x0079" }, //( 𝐲 → y ) MATHEMATICAL BOLD SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD466",L"\x0079" }, //( 𝑦 → y ) MATHEMATICAL ITALIC SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD49A",L"\x0079" }, //( 𝒚 → y ) MATHEMATICAL BOLD ITALIC SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD4CE",L"\x0079" }, //( 𝓎 → y ) MATHEMATICAL SCRIPT SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD502",L"\x0079" }, //( 𝔂 → y ) MATHEMATICAL BOLD SCRIPT SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD536",L"\x0079" }, //( 𝔶 → y ) MATHEMATICAL FRAKTUR SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD56A",L"\x0079" }, //( 𝕪 → y ) MATHEMATICAL DOUBLE-STRUCK SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD59E",L"\x0079" }, //( 𝖞 → y ) MATHEMATICAL BOLD FRAKTUR SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD5D2",L"\x0079" }, //( 𝗒 → y ) MATHEMATICAL SANS-SERIF SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD606",L"\x0079" }, //( 𝘆 → y ) MATHEMATICAL SANS-SERIF BOLD SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD63A",L"\x0079" }, //( 𝘺 → y ) MATHEMATICAL SANS-SERIF ITALIC SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD66E",L"\x0079" }, //( 𝙮 → y ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x0001\xD6A2",L"\x0079" }, //( 𝚢 → y ) MATHEMATICAL MONOSPACE SMALL Y → LATIN SMALL LETTER Y	# 
			{ L"\x028F",L"\x0079" }, //( ʏ → y ) LATIN LETTER SMALL CAPITAL Y → LATIN SMALL LETTER Y	# →ү→→γ→
			{ L"\x1EFF",L"\x0079" }, //( ỿ → y ) LATIN SMALL LETTER Y WITH LOOP → LATIN SMALL LETTER Y	# 
			{ L"\xAB5A",L"\x0079" }, //( ꭚ → y ) LATIN SMALL LETTER Y WITH SHORT RIGHT LEG → LATIN SMALL LETTER Y	# 
			{ L"\x03B3",L"\x0079" }, //( γ → y ) GREEK SMALL LETTER GAMMA → LATIN SMALL LETTER Y	# 
			{ L"\x213D",L"\x0079" }, //( ℽ → y ) DOUBLE-STRUCK SMALL GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x0001\xD6C4",L"\x0079" }, //( 𝛄 → y ) MATHEMATICAL BOLD SMALL GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x0001\xD6FE",L"\x0079" }, //( 𝛾 → y ) MATHEMATICAL ITALIC SMALL GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x0001\xD738",L"\x0079" }, //( 𝜸 → y ) MATHEMATICAL BOLD ITALIC SMALL GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x0001\xD772",L"\x0079" }, //( 𝝲 → y ) MATHEMATICAL SANS-SERIF BOLD SMALL GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x0001\xD7AC",L"\x0079" }, //( 𝞬 → y ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL GAMMA → LATIN SMALL LETTER Y	# →γ→
			{ L"\x0443",L"\x0079" }, //( у → y ) CYRILLIC SMALL LETTER U → LATIN SMALL LETTER Y	# 
			{ L"\x04AF",L"\x0079" }, //( ү → y ) CYRILLIC SMALL LETTER STRAIGHT U → LATIN SMALL LETTER Y	# →γ→
			{ L"\x10E7",L"\x0079" }, //( ყ → y ) GEORGIAN LETTER QAR → LATIN SMALL LETTER Y	# 
			{ L"\x0001\x18DC",L"\x0079" }, //( 𑣜 → y ) WARANG CITI SMALL LETTER HAR → LATIN SMALL LETTER Y	# →ɣ→→γ→

			{ L"\xFF39",L"\x0059" }, //( Ｙ → Y ) FULLWIDTH LATIN CAPITAL LETTER Y → LATIN CAPITAL LETTER Y	# →Υ→
			{ L"\x0001\xD418",L"\x0059" }, //( 𝐘 → Y ) MATHEMATICAL BOLD CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD44C",L"\x0059" }, //( 𝑌 → Y ) MATHEMATICAL ITALIC CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD480",L"\x0059" }, //( 𝒀 → Y ) MATHEMATICAL BOLD ITALIC CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD4B4",L"\x0059" }, //( 𝒴 → Y ) MATHEMATICAL SCRIPT CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD4E8",L"\x0059" }, //( 𝓨 → Y ) MATHEMATICAL BOLD SCRIPT CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD51C",L"\x0059" }, //( 𝔜 → Y ) MATHEMATICAL FRAKTUR CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD550",L"\x0059" }, //( 𝕐 → Y ) MATHEMATICAL DOUBLE-STRUCK CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD584",L"\x0059" }, //( 𝖄 → Y ) MATHEMATICAL BOLD FRAKTUR CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD5B8",L"\x0059" }, //( 𝖸 → Y ) MATHEMATICAL SANS-SERIF CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD5EC",L"\x0059" }, //( 𝗬 → Y ) MATHEMATICAL SANS-SERIF BOLD CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD620",L"\x0059" }, //( 𝘠 → Y ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD654",L"\x0059" }, //( 𝙔 → Y ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD688",L"\x0059" }, //( 𝚈 → Y ) MATHEMATICAL MONOSPACE CAPITAL Y → LATIN CAPITAL LETTER Y	# 
			{ L"\x03A5",L"\x0059" }, //( Υ → Y ) GREEK CAPITAL LETTER UPSILON → LATIN CAPITAL LETTER Y	# 
			{ L"\x03D2",L"\x0059" }, //( ϒ → Y ) GREEK UPSILON WITH HOOK SYMBOL → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\xD6BC",L"\x0059" }, //( 𝚼 → Y ) MATHEMATICAL BOLD CAPITAL UPSILON → LATIN CAPITAL LETTER Y	# →Υ→
			{ L"\x0001\xD6F6",L"\x0059" }, //( 𝛶 → Y ) MATHEMATICAL ITALIC CAPITAL UPSILON → LATIN CAPITAL LETTER Y	# →Υ→
			{ L"\x0001\xD730",L"\x0059" }, //( 𝜰 → Y ) MATHEMATICAL BOLD ITALIC CAPITAL UPSILON → LATIN CAPITAL LETTER Y	# →Υ→
			{ L"\x0001\xD76A",L"\x0059" }, //( 𝝪 → Y ) MATHEMATICAL SANS-SERIF BOLD CAPITAL UPSILON → LATIN CAPITAL LETTER Y	# →Υ→
			{ L"\x0001\xD7A4",L"\x0059" }, //( 𝞤 → Y ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL UPSILON → LATIN CAPITAL LETTER Y	# →Υ→
			{ L"\x2CA8",L"\x0059" }, //( Ⲩ → Y ) COPTIC CAPITAL LETTER UA → LATIN CAPITAL LETTER Y	# 
			{ L"\x04AE",L"\x0059" }, //( Ү → Y ) CYRILLIC CAPITAL LETTER STRAIGHT U → LATIN CAPITAL LETTER Y	# 
			{ L"\x13A9",L"\x0059" }, //( Ꭹ → Y ) CHEROKEE LETTER GI → LATIN CAPITAL LETTER Y	# 
			{ L"\x13BD",L"\x0059" }, //( Ꮍ → Y ) CHEROKEE LETTER MU → LATIN CAPITAL LETTER Y	# →Ꭹ→
			{ L"\xA4EC",L"\x0059" }, //( ꓬ → Y ) LISU LETTER YA → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\x18A4",L"\x0059" }, //( 𑢤 → Y ) WARANG CITI CAPITAL LETTER YA → LATIN CAPITAL LETTER Y	# 
			{ L"\x0001\x02B2",L"\x0059" }, //( 𐊲 → Y ) CARIAN LETTER U → LATIN CAPITAL LETTER Y	# 

			{ L"\x01B4",L"\x0079\x0314" }, //( ƴ → y̔ ) LATIN SMALL LETTER Y WITH HOOK → LATIN SMALL LETTER Y, COMBINING REVERSED COMMA ABOVE	# 

			{ L"\x024F",L"\x0079\x0335" }, //( ɏ → y̵ ) LATIN SMALL LETTER Y WITH STROKE → LATIN SMALL LETTER Y, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x04B1",L"\x0079\x0335" }, //( ұ → y̵ ) CYRILLIC SMALL LETTER STRAIGHT U WITH STROKE → LATIN SMALL LETTER Y, COMBINING SHORT STROKE OVERLAY	# →ү̵→

			{ L"\x00A5",L"\x0059\x0335" }, //( ¥ → Y̵ ) YEN SIGN → LATIN CAPITAL LETTER Y, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x024E",L"\x0059\x0335" }, //( Ɏ → Y̵ ) LATIN CAPITAL LETTER Y WITH STROKE → LATIN CAPITAL LETTER Y, COMBINING SHORT STROKE OVERLAY	# 
			{ L"\x04B0",L"\x0059\x0335" }, //( Ұ → Y̵ ) CYRILLIC CAPITAL LETTER STRAIGHT U WITH STROKE → LATIN CAPITAL LETTER Y, COMBINING SHORT STROKE OVERLAY	# →Ү̵→

			{ L"\x0292",L"\x021D" }, //( ʒ → ȝ ) LATIN SMALL LETTER EZH → LATIN SMALL LETTER YOGH	# 
			{ L"\xA76B",L"\x021D" }, //( ꝫ → ȝ ) LATIN SMALL LETTER ET → LATIN SMALL LETTER YOGH	# 
			{ L"\x2CCD",L"\x021D" }, //( ⳍ → ȝ ) COPTIC SMALL LETTER OLD COPTIC HORI → LATIN SMALL LETTER YOGH	# 
			{ L"\x04E1",L"\x021D" }, //( ӡ → ȝ ) CYRILLIC SMALL LETTER ABKHASIAN DZE → LATIN SMALL LETTER YOGH	# →ʒ→
			{ L"\x10F3",L"\x021D" }, //( ჳ → ȝ ) GEORGIAN LETTER WE → LATIN SMALL LETTER YOGH	# →ʒ→

			{ L"\x0001\xD433",L"\x007A" }, //( 𝐳 → z ) MATHEMATICAL BOLD SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD467",L"\x007A" }, //( 𝑧 → z ) MATHEMATICAL ITALIC SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD49B",L"\x007A" }, //( 𝒛 → z ) MATHEMATICAL BOLD ITALIC SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD4CF",L"\x007A" }, //( 𝓏 → z ) MATHEMATICAL SCRIPT SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD503",L"\x007A" }, //( 𝔃 → z ) MATHEMATICAL BOLD SCRIPT SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD537",L"\x007A" }, //( 𝔷 → z ) MATHEMATICAL FRAKTUR SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD56B",L"\x007A" }, //( 𝕫 → z ) MATHEMATICAL DOUBLE-STRUCK SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD59F",L"\x007A" }, //( 𝖟 → z ) MATHEMATICAL BOLD FRAKTUR SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD5D3",L"\x007A" }, //( 𝗓 → z ) MATHEMATICAL SANS-SERIF SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD607",L"\x007A" }, //( 𝘇 → z ) MATHEMATICAL SANS-SERIF BOLD SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD63B",L"\x007A" }, //( 𝘻 → z ) MATHEMATICAL SANS-SERIF ITALIC SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD66F",L"\x007A" }, //( 𝙯 → z ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\xD6A3",L"\x007A" }, //( 𝚣 → z ) MATHEMATICAL MONOSPACE SMALL Z → LATIN SMALL LETTER Z	# 
			{ L"\x1D22",L"\x007A" }, //( ᴢ → z ) LATIN LETTER SMALL CAPITAL Z → LATIN SMALL LETTER Z	# 
			{ L"\x0001\x18C4",L"\x007A" }, //( 𑣄 → z ) WARANG CITI SMALL LETTER YA → LATIN SMALL LETTER Z	# 

			{ L"\x0001\x02F5",L"\x005A" }, //( 𐋵 → Z ) COPTIC EPACT NUMBER THREE HUNDRED → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\x18E5",L"\x005A" }, //( 𑣥 → Z ) WARANG CITI DIGIT FIVE → LATIN CAPITAL LETTER Z	# 
			{ L"\xFF3A",L"\x005A" }, //( Ｚ → Z ) FULLWIDTH LATIN CAPITAL LETTER Z → LATIN CAPITAL LETTER Z	# →Ζ→
			{ L"\x2124",L"\x005A" }, //( ℤ → Z ) DOUBLE-STRUCK CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x2128",L"\x005A" }, //( ℨ → Z ) BLACK-LETTER CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD419",L"\x005A" }, //( 𝐙 → Z ) MATHEMATICAL BOLD CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD44D",L"\x005A" }, //( 𝑍 → Z ) MATHEMATICAL ITALIC CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD481",L"\x005A" }, //( 𝒁 → Z ) MATHEMATICAL BOLD ITALIC CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD4B5",L"\x005A" }, //( 𝒵 → Z ) MATHEMATICAL SCRIPT CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD4E9",L"\x005A" }, //( 𝓩 → Z ) MATHEMATICAL BOLD SCRIPT CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD585",L"\x005A" }, //( 𝖅 → Z ) MATHEMATICAL BOLD FRAKTUR CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD5B9",L"\x005A" }, //( 𝖹 → Z ) MATHEMATICAL SANS-SERIF CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD5ED",L"\x005A" }, //( 𝗭 → Z ) MATHEMATICAL SANS-SERIF BOLD CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD621",L"\x005A" }, //( 𝘡 → Z ) MATHEMATICAL SANS-SERIF ITALIC CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD655",L"\x005A" }, //( 𝙕 → Z ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD689",L"\x005A" }, //( 𝚉 → Z ) MATHEMATICAL MONOSPACE CAPITAL Z → LATIN CAPITAL LETTER Z	# 
			{ L"\x0396",L"\x005A" }, //( Ζ → Z ) GREEK CAPITAL LETTER ZETA → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\xD6AD",L"\x005A" }, //( 𝚭 → Z ) MATHEMATICAL BOLD CAPITAL ZETA → LATIN CAPITAL LETTER Z	# →Ζ→
			{ L"\x0001\xD6E7",L"\x005A" }, //( 𝛧 → Z ) MATHEMATICAL ITALIC CAPITAL ZETA → LATIN CAPITAL LETTER Z	# →𝑍→
			{ L"\x0001\xD721",L"\x005A" }, //( 𝜡 → Z ) MATHEMATICAL BOLD ITALIC CAPITAL ZETA → LATIN CAPITAL LETTER Z	# →Ζ→
			{ L"\x0001\xD75B",L"\x005A" }, //( 𝝛 → Z ) MATHEMATICAL SANS-SERIF BOLD CAPITAL ZETA → LATIN CAPITAL LETTER Z	# →Ζ→
			{ L"\x0001\xD795",L"\x005A" }, //( 𝞕 → Z ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL ZETA → LATIN CAPITAL LETTER Z	# →Ζ→
			{ L"\x13C3",L"\x005A" }, //( Ꮓ → Z ) CHEROKEE LETTER NO → LATIN CAPITAL LETTER Z	# 
			{ L"\xA4DC",L"\x005A" }, //( ꓜ → Z ) LISU LETTER DZA → LATIN CAPITAL LETTER Z	# 
			{ L"\x0001\x18A9",L"\x005A" }, //( 𑢩 → Z ) WARANG CITI CAPITAL LETTER O → LATIN CAPITAL LETTER Z	# 

			{ L"\x0290",L"\x007A\x0328" }, //( ʐ → z̨ ) LATIN SMALL LETTER Z WITH RETROFLEX HOOK → LATIN SMALL LETTER Z, COMBINING OGONEK	# →z̢→

			{ L"\x01B6",L"\x007A\x0335" }, //( ƶ → z̵ ) LATIN SMALL LETTER Z WITH STROKE → LATIN SMALL LETTER Z, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x01B5",L"\x005A\x0335" }, //( Ƶ → Z̵ ) LATIN CAPITAL LETTER Z WITH STROKE → LATIN CAPITAL LETTER Z, COMBINING SHORT STROKE OVERLAY	# 

			{ L"\x0225",L"\x007A\x0326" }, //( ȥ → z̦ ) LATIN SMALL LETTER Z WITH HOOK → LATIN SMALL LETTER Z, COMBINING COMMA BELOW	# →z̡→

			{ L"\x0224",L"\x005A\x0326" }, //( Ȥ → Z̦ ) LATIN CAPITAL LETTER Z WITH HOOK → LATIN CAPITAL LETTER Z, COMBINING COMMA BELOW	# →Z̧→

			{ L"\x1D76",L"\x007A\x0334" }, //( ᵶ → z̴ ) LATIN SMALL LETTER Z WITH MIDDLE TILDE → LATIN SMALL LETTER Z, COMBINING TILDE OVERLAY	# 

			{ L"\x01BF",L"\x00FE" }, //( ƿ → þ ) LATIN LETTER WYNN → LATIN SMALL LETTER THORN	# 
			{ L"\x03F8",L"\x00FE" }, //( ϸ → þ ) GREEK SMALL LETTER SHO → LATIN SMALL LETTER THORN	# 

			{ L"\x03F7",L"\x00DE" }, //( Ϸ → Þ ) GREEK CAPITAL LETTER SHO → LATIN CAPITAL LETTER THORN	# 

			{ L"\x1D24",L"\x01A8" }, //( ᴤ → ƨ ) LATIN LETTER VOICED LARYNGEAL SPIRANT → LATIN SMALL LETTER TONE TWO	# 
			{ L"\x03E9",L"\x01A8" }, //( ϩ → ƨ ) COPTIC SMALL LETTER HORI → LATIN SMALL LETTER TONE TWO	# 
			{ L"\xA645",L"\x01A8" }, //( ꙅ → ƨ ) CYRILLIC SMALL LETTER REVERSED DZE → LATIN SMALL LETTER TONE TWO	# 

			{ L"\x044C",L"\x0185" }, //( ь → ƅ ) CYRILLIC SMALL LETTER SOFT SIGN → LATIN SMALL LETTER TONE SIX	# 

			{ L"\x044B",L"\x0185\x0069" }, //( ы → ƅi ) CYRILLIC SMALL LETTER YERU → LATIN SMALL LETTER TONE SIX, LATIN SMALL LETTER I	# →ьı→

			{ L"\x02E4",L"\x02C1" }, //( ˤ → ˁ ) MODIFIER LETTER SMALL REVERSED GLOTTAL STOP → MODIFIER LETTER REVERSED GLOTTAL STOP	# 

			{ L"\x2299",L"\x0298" }, //( ⊙ → ʘ ) CIRCLED DOT OPERATOR → LATIN LETTER BILABIAL CLICK	# 
			{ L"\x2609",L"\x0298" }, //( ☉ → ʘ ) SUN → LATIN LETTER BILABIAL CLICK	# →⊙→
			{ L"\x2A00",L"\x0298" }, //( ⨀ → ʘ ) N-ARY CIRCLED DOT OPERATOR → LATIN LETTER BILABIAL CLICK	# →⊙→
			{ L"\xA668",L"\x0298" }, //( Ꙩ → ʘ ) CYRILLIC CAPITAL LETTER MONOCULAR O → LATIN LETTER BILABIAL CLICK	# 
			{ L"\x2D59",L"\x0298" }, //( ⵙ → ʘ ) TIFINAGH LETTER YAS → LATIN LETTER BILABIAL CLICK	# →⊙→

			{ L"\x213E",L"\x0393" }, //( ℾ → Γ ) DOUBLE-STRUCK CAPITAL GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x0001\xD6AA",L"\x0393" }, //( 𝚪 → Γ ) MATHEMATICAL BOLD CAPITAL GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x0001\xD6E4",L"\x0393" }, //( 𝛤 → Γ ) MATHEMATICAL ITALIC CAPITAL GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x0001\xD71E",L"\x0393" }, //( 𝜞 → Γ ) MATHEMATICAL BOLD ITALIC CAPITAL GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x0001\xD758",L"\x0393" }, //( 𝝘 → Γ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x0001\xD792",L"\x0393" }, //( 𝞒 → Γ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x2C84",L"\x0393" }, //( Ⲅ → Γ ) COPTIC CAPITAL LETTER GAMMA → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x0413",L"\x0393" }, //( Г → Γ ) CYRILLIC CAPITAL LETTER GHE → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x13B1",L"\x0393" }, //( Ꮁ → Γ ) CHEROKEE LETTER HU → GREEK CAPITAL LETTER GAMMA	# 
			{ L"\x14A5",L"\x0393" }, //( ᒥ → Γ ) CANADIAN SYLLABICS MI → GREEK CAPITAL LETTER GAMMA	# 

			{ L"\x0492",L"\x0393\x0335" }, //( Ғ → Γ̵ ) CYRILLIC CAPITAL LETTER GHE WITH STROKE → GREEK CAPITAL LETTER GAMMA, COMBINING SHORT STROKE OVERLAY	# →Г̵→

			{ L"\x14AF",L"\x0393\x00B7" }, //( ᒯ → Γ· ) CANADIAN SYLLABICS WEST-CREE MWI → GREEK CAPITAL LETTER GAMMA, MIDDLE DOT	# →ᒥᐧ→→ᒥ·→

			{ L"\x0490",L"\x0393\x0027" }, //( Ґ → Γ' ) CYRILLIC CAPITAL LETTER GHE WITH UPTURN → GREEK CAPITAL LETTER GAMMA, APOSTROPHE	# →Гˈ→

			{ L"\x2206",L"\x0394" }, //( ∆ → Δ ) INCREMENT → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x25B3",L"\x0394" }, //( △ → Δ ) WHITE UP-POINTING TRIANGLE → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\xF702",L"\x0394" }, //( 🜂 → Δ ) ALCHEMICAL SYMBOL FOR FIRE → GREEK CAPITAL LETTER DELTA	# →△→
			{ L"\x0001\xD6AB",L"\x0394" }, //( 𝚫 → Δ ) MATHEMATICAL BOLD CAPITAL DELTA → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\xD6E5",L"\x0394" }, //( 𝛥 → Δ ) MATHEMATICAL ITALIC CAPITAL DELTA → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\xD71F",L"\x0394" }, //( 𝜟 → Δ ) MATHEMATICAL BOLD ITALIC CAPITAL DELTA → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\xD759",L"\x0394" }, //( 𝝙 → Δ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL DELTA → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\xD793",L"\x0394" }, //( 𝞓 → Δ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL DELTA → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x2C86",L"\x0394" }, //( Ⲇ → Δ ) COPTIC CAPITAL LETTER DALDA → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x2D60",L"\x0394" }, //( ⵠ → Δ ) TIFINAGH LETTER YAV → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x1403",L"\x0394" }, //( ᐃ → Δ ) CANADIAN SYLLABICS I → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\x0285",L"\x0394" }, //( 𐊅 → Δ ) LYCIAN LETTER D → GREEK CAPITAL LETTER DELTA	# 
			{ L"\x0001\x02A3",L"\x0394" }, //( 𐊣 → Δ ) CARIAN LETTER L → GREEK CAPITAL LETTER DELTA	# 

			{ L"\x2359",L"\x0394\x0332" }, //( ⍙ → Δ̲ ) APL FUNCTIONAL SYMBOL DELTA UNDERBAR → GREEK CAPITAL LETTER DELTA, COMBINING LOW LINE	# 

			{ L"\x140F",L"\x0394\x00B7" }, //( ᐏ → Δ· ) CANADIAN SYLLABICS WEST-CREE WI → GREEK CAPITAL LETTER DELTA, MIDDLE DOT	# →ᐃᐧ→

			{ L"\x142C",L"\x0394\x1420" }, //( ᐬ → Δᐠ ) CANADIAN SYLLABICS IN → GREEK CAPITAL LETTER DELTA, CANADIAN SYLLABICS FINAL GRAVE	# →ᐃᐠ→

			{ L"\x0001\xD7CB",L"\x03DD" }, //( 𝟋 → ϝ ) MATHEMATICAL BOLD SMALL DIGAMMA → GREEK SMALL LETTER DIGAMMA	# 

			{ L"\x0001\xD6C7",L"\x03B6" }, //( 𝛇 → ζ ) MATHEMATICAL BOLD SMALL ZETA → GREEK SMALL LETTER ZETA	# 
			{ L"\x0001\xD701",L"\x03B6" }, //( 𝜁 → ζ ) MATHEMATICAL ITALIC SMALL ZETA → GREEK SMALL LETTER ZETA	# 
			{ L"\x0001\xD73B",L"\x03B6" }, //( 𝜻 → ζ ) MATHEMATICAL BOLD ITALIC SMALL ZETA → GREEK SMALL LETTER ZETA	# 
			{ L"\x0001\xD775",L"\x03B6" }, //( 𝝵 → ζ ) MATHEMATICAL SANS-SERIF BOLD SMALL ZETA → GREEK SMALL LETTER ZETA	# 
			{ L"\x0001\xD7AF",L"\x03B6" }, //( 𝞯 → ζ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL ZETA → GREEK SMALL LETTER ZETA	# 

			{ L"\x2CE4",L"\x03D7" }, //( ⳤ → ϗ ) COPTIC SYMBOL KAI → GREEK KAI SYMBOL	# 

			{ L"\x0001\xD6CC",L"\x03BB" }, //( 𝛌 → λ ) MATHEMATICAL BOLD SMALL LAMDA → GREEK SMALL LETTER LAMDA	# 
			{ L"\x0001\xD706",L"\x03BB" }, //( 𝜆 → λ ) MATHEMATICAL ITALIC SMALL LAMDA → GREEK SMALL LETTER LAMDA	# 
			{ L"\x0001\xD740",L"\x03BB" }, //( 𝝀 → λ ) MATHEMATICAL BOLD ITALIC SMALL LAMDA → GREEK SMALL LETTER LAMDA	# 
			{ L"\x0001\xD77A",L"\x03BB" }, //( 𝝺 → λ ) MATHEMATICAL SANS-SERIF BOLD SMALL LAMDA → GREEK SMALL LETTER LAMDA	# 
			{ L"\x0001\xD7B4",L"\x03BB" }, //( 𝞴 → λ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL LAMDA → GREEK SMALL LETTER LAMDA	# 
			{ L"\x2C96",L"\x03BB" }, //( Ⲗ → λ ) COPTIC CAPITAL LETTER LAULA → GREEK SMALL LETTER LAMDA	# 

			{ L"\x00B5",L"\x03BC" }, //( µ → μ ) MICRO SIGN → GREEK SMALL LETTER MU	# 
			{ L"\x0001\xD6CD",L"\x03BC" }, //( 𝛍 → μ ) MATHEMATICAL BOLD SMALL MU → GREEK SMALL LETTER MU	# 
			{ L"\x0001\xD707",L"\x03BC" }, //( 𝜇 → μ ) MATHEMATICAL ITALIC SMALL MU → GREEK SMALL LETTER MU	# 
			{ L"\x0001\xD741",L"\x03BC" }, //( 𝝁 → μ ) MATHEMATICAL BOLD ITALIC SMALL MU → GREEK SMALL LETTER MU	# 
			{ L"\x0001\xD77B",L"\x03BC" }, //( 𝝻 → μ ) MATHEMATICAL SANS-SERIF BOLD SMALL MU → GREEK SMALL LETTER MU	# 
			{ L"\x0001\xD7B5",L"\x03BC" }, //( 𝞵 → μ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL MU → GREEK SMALL LETTER MU	# 

			{ L"\x0001\xD6CF",L"\x03BE" }, //( 𝛏 → ξ ) MATHEMATICAL BOLD SMALL XI → GREEK SMALL LETTER XI	# 
			{ L"\x0001\xD709",L"\x03BE" }, //( 𝜉 → ξ ) MATHEMATICAL ITALIC SMALL XI → GREEK SMALL LETTER XI	# 
			{ L"\x0001\xD743",L"\x03BE" }, //( 𝝃 → ξ ) MATHEMATICAL BOLD ITALIC SMALL XI → GREEK SMALL LETTER XI	# 
			{ L"\x0001\xD77D",L"\x03BE" }, //( 𝝽 → ξ ) MATHEMATICAL SANS-SERIF BOLD SMALL XI → GREEK SMALL LETTER XI	# 
			{ L"\x0001\xD7B7",L"\x03BE" }, //( 𝞷 → ξ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL XI → GREEK SMALL LETTER XI	# 

			{ L"\x0001\xD6B5",L"\x039E" }, //( 𝚵 → Ξ ) MATHEMATICAL BOLD CAPITAL XI → GREEK CAPITAL LETTER XI	# 
			{ L"\x0001\xD6EF",L"\x039E" }, //( 𝛯 → Ξ ) MATHEMATICAL ITALIC CAPITAL XI → GREEK CAPITAL LETTER XI	# 
			{ L"\x0001\xD729",L"\x039E" }, //( 𝜩 → Ξ ) MATHEMATICAL BOLD ITALIC CAPITAL XI → GREEK CAPITAL LETTER XI	# 
			{ L"\x0001\xD763",L"\x039E" }, //( 𝝣 → Ξ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL XI → GREEK CAPITAL LETTER XI	# 
			{ L"\x0001\xD79D",L"\x039E" }, //( 𝞝 → Ξ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL XI → GREEK CAPITAL LETTER XI	# 

			{ L"\x220F",L"\x03A0" }, //( ∏ → Π ) N-ARY PRODUCT → GREEK CAPITAL LETTER PI	# 
			{ L"\x213F",L"\x03A0" }, //( ℿ → Π ) DOUBLE-STRUCK CAPITAL PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x0001\xD6B7",L"\x03A0" }, //( 𝚷 → Π ) MATHEMATICAL BOLD CAPITAL PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x0001\xD6F1",L"\x03A0" }, //( 𝛱 → Π ) MATHEMATICAL ITALIC CAPITAL PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x0001\xD72B",L"\x03A0" }, //( 𝜫 → Π ) MATHEMATICAL BOLD ITALIC CAPITAL PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x0001\xD765",L"\x03A0" }, //( 𝝥 → Π ) MATHEMATICAL SANS-SERIF BOLD CAPITAL PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x0001\xD79F",L"\x03A0" }, //( 𝞟 → Π ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x2CA0",L"\x03A0" }, //( Ⲡ → Π ) COPTIC CAPITAL LETTER PI → GREEK CAPITAL LETTER PI	# 
			{ L"\x041F",L"\x03A0" }, //( П → Π ) CYRILLIC CAPITAL LETTER PE → GREEK CAPITAL LETTER PI	# 

			{ L"\x0001\x02AD",L"\x03D8" }, //( 𐊭 → Ϙ ) CARIAN LETTER T → GREEK LETTER ARCHAIC KOPPA	# 
			{ L"\x0001\x0312",L"\x03D8" }, //( 𐌒 → Ϙ ) OLD ITALIC LETTER KU → GREEK LETTER ARCHAIC KOPPA	# 

			{ L"\x03DB",L"\x03C2" }, //( ϛ → ς ) GREEK SMALL LETTER STIGMA → GREEK SMALL LETTER FINAL SIGMA	# 
			{ L"\x0001\xD6D3",L"\x03C2" }, //( 𝛓 → ς ) MATHEMATICAL BOLD SMALL FINAL SIGMA → GREEK SMALL LETTER FINAL SIGMA	# 
			{ L"\x0001\xD70D",L"\x03C2" }, //( 𝜍 → ς ) MATHEMATICAL ITALIC SMALL FINAL SIGMA → GREEK SMALL LETTER FINAL SIGMA	# 
			{ L"\x0001\xD747",L"\x03C2" }, //( 𝝇 → ς ) MATHEMATICAL BOLD ITALIC SMALL FINAL SIGMA → GREEK SMALL LETTER FINAL SIGMA	# 
			{ L"\x0001\xD781",L"\x03C2" }, //( 𝞁 → ς ) MATHEMATICAL SANS-SERIF BOLD SMALL FINAL SIGMA → GREEK SMALL LETTER FINAL SIGMA	# 
			{ L"\x0001\xD7BB",L"\x03C2" }, //( 𝞻 → ς ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL FINAL SIGMA → GREEK SMALL LETTER FINAL SIGMA	# 

			{ L"\x0001\xD6BD",L"\x03A6" }, //( 𝚽 → Φ ) MATHEMATICAL BOLD CAPITAL PHI → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0001\xD6F7",L"\x03A6" }, //( 𝛷 → Φ ) MATHEMATICAL ITALIC CAPITAL PHI → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0001\xD731",L"\x03A6" }, //( 𝜱 → Φ ) MATHEMATICAL BOLD ITALIC CAPITAL PHI → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0001\xD76B",L"\x03A6" }, //( 𝝫 → Φ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL PHI → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0001\xD7A5",L"\x03A6" }, //( 𝞥 → Φ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL PHI → GREEK CAPITAL LETTER PHI	# 
			{ L"\x2CAA",L"\x03A6" }, //( Ⲫ → Φ ) COPTIC CAPITAL LETTER FI → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0424",L"\x03A6" }, //( Ф → Φ ) CYRILLIC CAPITAL LETTER EF → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0553",L"\x03A6" }, //( Փ → Φ ) ARMENIAN CAPITAL LETTER PIWR → GREEK CAPITAL LETTER PHI	# 
			{ L"\x16F0",L"\x03A6" }, //( ᛰ → Φ ) RUNIC BELGTHOR SYMBOL → GREEK CAPITAL LETTER PHI	# 
			{ L"\x0001\x02B3",L"\x03A6" }, //( 𐊳 → Φ ) CARIAN LETTER NN → GREEK CAPITAL LETTER PHI	# 

			{ L"\xAB53",L"\x03C7" }, //( ꭓ → χ ) LATIN SMALL LETTER CHI → GREEK SMALL LETTER CHI	# 
			{ L"\xAB55",L"\x03C7" }, //( ꭕ → χ ) LATIN SMALL LETTER CHI WITH LOW LEFT SERIF → GREEK SMALL LETTER CHI	# 
			{ L"\x0001\xD6D8",L"\x03C7" }, //( 𝛘 → χ ) MATHEMATICAL BOLD SMALL CHI → GREEK SMALL LETTER CHI	# 
			{ L"\x0001\xD712",L"\x03C7" }, //( 𝜒 → χ ) MATHEMATICAL ITALIC SMALL CHI → GREEK SMALL LETTER CHI	# 
			{ L"\x0001\xD74C",L"\x03C7" }, //( 𝝌 → χ ) MATHEMATICAL BOLD ITALIC SMALL CHI → GREEK SMALL LETTER CHI	# 
			{ L"\x0001\xD786",L"\x03C7" }, //( 𝞆 → χ ) MATHEMATICAL SANS-SERIF BOLD SMALL CHI → GREEK SMALL LETTER CHI	# 
			{ L"\x0001\xD7C0",L"\x03C7" }, //( 𝟀 → χ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL CHI → GREEK SMALL LETTER CHI	# 
			{ L"\x2CAD",L"\x03C7" }, //( ⲭ → χ ) COPTIC SMALL LETTER KHI → GREEK SMALL LETTER CHI	# 

			{ L"\x0001\xD6D9",L"\x03C8" }, //( 𝛙 → ψ ) MATHEMATICAL BOLD SMALL PSI → GREEK SMALL LETTER PSI	# 
			{ L"\x0001\xD713",L"\x03C8" }, //( 𝜓 → ψ ) MATHEMATICAL ITALIC SMALL PSI → GREEK SMALL LETTER PSI	# 
			{ L"\x0001\xD74D",L"\x03C8" }, //( 𝝍 → ψ ) MATHEMATICAL BOLD ITALIC SMALL PSI → GREEK SMALL LETTER PSI	# 
			{ L"\x0001\xD787",L"\x03C8" }, //( 𝞇 → ψ ) MATHEMATICAL SANS-SERIF BOLD SMALL PSI → GREEK SMALL LETTER PSI	# 
			{ L"\x0001\xD7C1",L"\x03C8" }, //( 𝟁 → ψ ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL PSI → GREEK SMALL LETTER PSI	# 
			{ L"\x0471",L"\x03C8" }, //( ѱ → ψ ) CYRILLIC SMALL LETTER PSI → GREEK SMALL LETTER PSI	# 

			{ L"\x0001\xD6BF",L"\x03A8" }, //( 𝚿 → Ψ ) MATHEMATICAL BOLD CAPITAL PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x0001\xD6F9",L"\x03A8" }, //( 𝛹 → Ψ ) MATHEMATICAL ITALIC CAPITAL PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x0001\xD733",L"\x03A8" }, //( 𝜳 → Ψ ) MATHEMATICAL BOLD ITALIC CAPITAL PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x0001\xD76D",L"\x03A8" }, //( 𝝭 → Ψ ) MATHEMATICAL SANS-SERIF BOLD CAPITAL PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x0001\xD7A7",L"\x03A8" }, //( 𝞧 → Ψ ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x2CAE",L"\x03A8" }, //( Ⲯ → Ψ ) COPTIC CAPITAL LETTER PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x0470",L"\x03A8" }, //( Ѱ → Ψ ) CYRILLIC CAPITAL LETTER PSI → GREEK CAPITAL LETTER PSI	# 
			{ L"\x16D8",L"\x03A8" }, //( ᛘ → Ψ ) RUNIC LETTER LONG-BRANCH-MADR M → GREEK CAPITAL LETTER PSI	# 
			{ L"\x0001\x02B5",L"\x03A8" }, //( 𐊵 → Ψ ) CARIAN LETTER N → GREEK CAPITAL LETTER PSI	# 

			{ L"\x2375",L"\x03C9" }, //( ⍵ → ω ) APL FUNCTIONAL SYMBOL OMEGA → GREEK SMALL LETTER OMEGA	# 
			{ L"\x0001\xD6DA",L"\x03C9" }, //( 𝛚 → ω ) MATHEMATICAL BOLD SMALL OMEGA → GREEK SMALL LETTER OMEGA	# 
			{ L"\x0001\xD714",L"\x03C9" }, //( 𝜔 → ω ) MATHEMATICAL ITALIC SMALL OMEGA → GREEK SMALL LETTER OMEGA	# 
			{ L"\x0001\xD74E",L"\x03C9" }, //( 𝝎 → ω ) MATHEMATICAL BOLD ITALIC SMALL OMEGA → GREEK SMALL LETTER OMEGA	# 
			{ L"\x0001\xD788",L"\x03C9" }, //( 𝞈 → ω ) MATHEMATICAL SANS-SERIF BOLD SMALL OMEGA → GREEK SMALL LETTER OMEGA	# 
			{ L"\x0001\xD7C2",L"\x03C9" }, //( 𝟂 → ω ) MATHEMATICAL SANS-SERIF BOLD ITALIC SMALL OMEGA → GREEK SMALL LETTER OMEGA	# 
			{ L"\x2CB1",L"\x03C9" }, //( ⲱ → ω ) COPTIC SMALL LETTER OOU → GREEK SMALL LETTER OMEGA	# 
			{ L"\xA64D",L"\x03C9" }, //( ꙍ → ω ) CYRILLIC SMALL LETTER BROAD OMEGA → GREEK SMALL LETTER OMEGA	# →ꞷ→
			{ L"\xA7B7",L"\x03C9" }, //( ꞷ → ω ) LATIN SMALL LETTER OMEGA → GREEK SMALL LETTER OMEGA	# 

			{ L"\x2126",L"\x03A9" }, //( Ω → Ω ) OHM SIGN → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x0001\xD6C0",L"\x03A9" }, //( 𝛀 → Ω ) MATHEMATICAL BOLD CAPITAL OMEGA → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x0001\xD6FA",L"\x03A9" }, //( 𝛺 → Ω ) MATHEMATICAL ITALIC CAPITAL OMEGA → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x0001\xD734",L"\x03A9" }, //( 𝜴 → Ω ) MATHEMATICAL BOLD ITALIC CAPITAL OMEGA → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x0001\xD76E",L"\x03A9" }, //( 𝝮 → Ω ) MATHEMATICAL SANS-SERIF BOLD CAPITAL OMEGA → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x0001\xD7A8",L"\x03A9" }, //( 𝞨 → Ω ) MATHEMATICAL SANS-SERIF BOLD ITALIC CAPITAL OMEGA → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x162F",L"\x03A9" }, //( ᘯ → Ω ) CANADIAN SYLLABICS CARRIER LHO → GREEK CAPITAL LETTER OMEGA	# 
			{ L"\x1635",L"\x03A9" }, //( ᘵ → Ω ) CANADIAN SYLLABICS CARRIER TLHO → GREEK CAPITAL LETTER OMEGA	# →ᘯ→
			{ L"\x0001\x02B6",L"\x03A9" }, //( 𐊶 → Ω ) CARIAN LETTER TT2 → GREEK CAPITAL LETTER OMEGA	# 

			{ L"\x2379",L"\x03C9\x0332" }, //( ⍹ → ω̲ ) APL FUNCTIONAL SYMBOL OMEGA UNDERBAR → GREEK SMALL LETTER OMEGA, COMBINING LOW LINE	# 

			{ L"\x1F7D",L"\x1FF4" }, //( ώ → ῴ ) GREEK SMALL LETTER OMEGA WITH OXIA → GREEK SMALL LETTER OMEGA WITH OXIA AND YPOGEGRAMMENI	# 

			{ L"\x2630",L"\x2CB6" }, //( ☰ → Ⲷ ) TRIGRAM FOR HEAVEN → COPTIC CAPITAL LETTER CRYPTOGRAMMIC EIE	# 

			{ L"\x2CDC",L"\x03EC" }, //( Ⳝ → Ϭ ) COPTIC CAPITAL LETTER OLD NUBIAN SHIMA → COPTIC CAPITAL LETTER SHIMA	# 

			{ L"\x0497",L"\x0436\x0329" }, //( җ → ж̩ ) CYRILLIC SMALL LETTER ZHE WITH DESCENDER → CYRILLIC SMALL LETTER ZHE, COMBINING VERTICAL LINE BELOW	# 

			{ L"\x0496",L"\x0416\x0329" }, //( Җ → Ж̩ ) CYRILLIC CAPITAL LETTER ZHE WITH DESCENDER → CYRILLIC CAPITAL LETTER ZHE, COMBINING VERTICAL LINE BELOW	# 

			{ L"\x0376",L"\x0418" }, //( Ͷ → И ) GREEK CAPITAL LETTER PAMPHYLIAN DIGAMMA → CYRILLIC CAPITAL LETTER I	# 
			{ L"\x0001\x0425",L"\x0418" }, //( 𐐥 → И ) DESERET CAPITAL LETTER ENG → CYRILLIC CAPITAL LETTER I	# 

			{ L"\x0419",L"\x040D" }, //( Й → Ѝ ) CYRILLIC CAPITAL LETTER SHORT I → CYRILLIC CAPITAL LETTER I WITH GRAVE	# 

			{ L"\x048A",L"\x040D\x0326" }, //( Ҋ → Ѝ̦ ) CYRILLIC CAPITAL LETTER SHORT I WITH TAIL → CYRILLIC CAPITAL LETTER I WITH GRAVE, COMBINING COMMA BELOW	# →Й̡→

			{ L"\x045D",L"\x0439" }, //( ѝ → й ) CYRILLIC SMALL LETTER I WITH GRAVE → CYRILLIC SMALL LETTER SHORT I	# 

			{ L"\x048B",L"\x0439\x0326" }, //( ҋ → й̦ ) CYRILLIC SMALL LETTER SHORT I WITH TAIL → CYRILLIC SMALL LETTER SHORT I, COMBINING COMMA BELOW	# →й̡→

			{ L"\x1D2B",L"\x043B" }, //( ᴫ → л ) CYRILLIC LETTER SMALL CAPITAL EL → CYRILLIC SMALL LETTER EL	# 

			{ L"\x04C6",L"\x043B\x0326" }, //( ӆ → л̦ ) CYRILLIC SMALL LETTER EL WITH TAIL → CYRILLIC SMALL LETTER EL, COMBINING COMMA BELOW	# →л̡→

			{ L"\xAB60",L"\x0459" }, //( ꭠ → љ ) LATIN SMALL LETTER SAKHA YAT → CYRILLIC SMALL LETTER LJE	# 

			{ L"\x13C7",L"\x0460" }, //( Ꮗ → Ѡ ) CHEROKEE LETTER QUE → CYRILLIC CAPITAL LETTER OMEGA	# 
			{ L"\x15EF",L"\x0460" }, //( ᗯ → Ѡ ) CANADIAN SYLLABICS CARRIER GU → CYRILLIC CAPITAL LETTER OMEGA	# 

			{ L"\x047C",L"\x0460\x0483" }, //( Ѽ → Ѡ҃ ) CYRILLIC CAPITAL LETTER OMEGA WITH TITLO → CYRILLIC CAPITAL LETTER OMEGA, COMBINING CYRILLIC TITLO	# 

			{ L"\x18ED",L"\x0460\x00B7" }, //( ᣭ → Ѡ· ) CANADIAN SYLLABICS CARRIER GWU → CYRILLIC CAPITAL LETTER OMEGA, MIDDLE DOT	# →ᗯᐧ→

			{ L"\xA7B6",L"\xA64C" }, //( Ꞷ → Ꙍ ) LATIN CAPITAL LETTER OMEGA → CYRILLIC CAPITAL LETTER BROAD OMEGA	# 

			{ L"\x04CC",L"\x04B7" }, //( ӌ → ҷ ) CYRILLIC SMALL LETTER KHAKASSIAN CHE → CYRILLIC SMALL LETTER CHE WITH DESCENDER	# 

			{ L"\x04CB",L"\x04B6" }, //( Ӌ → Ҷ ) CYRILLIC CAPITAL LETTER KHAKASSIAN CHE → CYRILLIC CAPITAL LETTER CHE WITH DESCENDER	# 

			{ L"\x04BE",L"\x04BC\x0328" }, //( Ҿ → Ҽ̨ ) CYRILLIC CAPITAL LETTER ABKHASIAN CHE WITH DESCENDER → CYRILLIC CAPITAL LETTER ABKHASIAN CHE, COMBINING OGONEK	# 

			{ L"\x2CBD",L"\x0448" }, //( ⲽ → ш ) COPTIC SMALL LETTER CRYPTOGRAMMIC NI → CYRILLIC SMALL LETTER SHA	# 

			{ L"\x2CBC",L"\x0428" }, //( Ⲽ → Ш ) COPTIC CAPITAL LETTER CRYPTOGRAMMIC NI → CYRILLIC CAPITAL LETTER SHA	# 

			{ L"\x2108",L"\x042D" }, //( ℈ → Э ) SCRUPLE → CYRILLIC CAPITAL LETTER E	# 

			{ L"\x0587",L"\x0565\x0582" }, //( և → եւ ) ARMENIAN SMALL LIGATURE ECH YIWN → ARMENIAN SMALL LETTER ECH, ARMENIAN SMALL LETTER YIWN	# 

			{ L"\xFB14",L"\x0574\x0565" }, //( ﬔ → մե ) ARMENIAN SMALL LIGATURE MEN ECH → ARMENIAN SMALL LETTER MEN, ARMENIAN SMALL LETTER ECH	# 

			{ L"\xFB15",L"\x0574\x056B" }, //( ﬕ → մի ) ARMENIAN SMALL LIGATURE MEN INI → ARMENIAN SMALL LETTER MEN, ARMENIAN SMALL LETTER INI	# 

			{ L"\xFB17",L"\x0574\x056D" }, //( ﬗ → մխ ) ARMENIAN SMALL LIGATURE MEN XEH → ARMENIAN SMALL LETTER MEN, ARMENIAN SMALL LETTER XEH	# 

			{ L"\xFB13",L"\x0574\x0576" }, //( ﬓ → մն ) ARMENIAN SMALL LIGATURE MEN NOW → ARMENIAN SMALL LETTER MEN, ARMENIAN SMALL LETTER NOW	# 

			{ L"\x2229",L"\x0548" }, //( ∩ → Ո ) INTERSECTION → ARMENIAN CAPITAL LETTER VO	# →ᑎ→
			{ L"\x22C2",L"\x0548" }, //( ⋂ → Ո ) N-ARY INTERSECTION → ARMENIAN CAPITAL LETTER VO	# →∩→→ᑎ→
			{ L"\x144E",L"\x0548" }, //( ᑎ → Ո ) CANADIAN SYLLABICS TI → ARMENIAN CAPITAL LETTER VO	# 
			{ L"\xA4F5",L"\x0548" }, //( ꓵ → Ո ) LISU LETTER UE → ARMENIAN CAPITAL LETTER VO	# →∩→→ᑎ→

			{ L"\x145A",L"\x0548\x00B7" }, //( ᑚ → Ո· ) CANADIAN SYLLABICS WEST-CREE TWI → ARMENIAN CAPITAL LETTER VO, MIDDLE DOT	# →ᑎᐧ→→ᑎ·→

			{ L"\x1468",L"\x0548\x0027" }, //( ᑨ → Ո' ) CANADIAN SYLLABICS TTI → ARMENIAN CAPITAL LETTER VO, APOSTROPHE	# →ᑎᑊ→→ᑎ'→

			{ L"\xFB16",L"\x057E\x0576" }, //( ﬖ → վն ) ARMENIAN SMALL LIGATURE VEW NOW → ARMENIAN SMALL LETTER VEW, ARMENIAN SMALL LETTER NOW	# 

			{ L"\x20BD",L"\x0554" }, //( ₽ → Ք ) RUBLE SIGN → ARMENIAN CAPITAL LETTER KEH	# 

			{ L"\x02D3",L"\x0559" }, //( ˓ → ՙ ) MODIFIER LETTER CENTRED LEFT HALF RING → ARMENIAN MODIFIER LETTER LEFT HALF RING	# 
			{ L"\x02BF",L"\x0559" }, //( ʿ → ՙ ) MODIFIER LETTER LEFT HALF RING → ARMENIAN MODIFIER LETTER LEFT HALF RING	# 

			{ L"\x2135",L"\x05D0" }, //( ℵ → ‎א‎ ) ALEF SYMBOL → HEBREW LETTER ALEF	# 
			{ L"\xFB21",L"\x05D0" }, //( ‎ﬡ‎ → ‎א‎ ) HEBREW LETTER WIDE ALEF → HEBREW LETTER ALEF	# 

			{ L"\xFB2F",L"\xFB2E" }, //( ‎אָ‎ → ‎אַ‎ ) HEBREW LETTER ALEF WITH QAMATS → HEBREW LETTER ALEF WITH PATAH	# 
			{ L"\xFB30",L"\xFB2E" }, //( ‎אּ‎ → ‎אַ‎ ) HEBREW LETTER ALEF WITH MAPIQ → HEBREW LETTER ALEF WITH PATAH	# 

			{ L"\xFB4F",L"\x05D0\x05DC" }, //( ‎ﭏ‎ → ‎אל‎ ) HEBREW LIGATURE ALEF LAMED → HEBREW LETTER ALEF, HEBREW LETTER LAMED	# 

			{ L"\x2136",L"\x05D1" }, //( ℶ → ‎ב‎ ) BET SYMBOL → HEBREW LETTER BET	# 

			{ L"\x2137",L"\x05D2" }, //( ℷ → ‎ג‎ ) GIMEL SYMBOL → HEBREW LETTER GIMEL	# 

			{ L"\x2138",L"\x05D3" }, //( ℸ → ‎ד‎ ) DALET SYMBOL → HEBREW LETTER DALET	# 
			{ L"\xFB22",L"\x05D3" }, //( ‎ﬢ‎ → ‎ד‎ ) HEBREW LETTER WIDE DALET → HEBREW LETTER DALET	# 

			{ L"\xFB23",L"\x05D4" }, //( ‎ﬣ‎ → ‎ה‎ ) HEBREW LETTER WIDE HE → HEBREW LETTER HE	# 

			{ L"\xFB39",L"\xFB1D" }, //( ‎יּ‎ → ‎יִ‎ ) HEBREW LETTER YOD WITH DAGESH → HEBREW LETTER YOD WITH HIRIQ	# 

			{ L"\xFB24",L"\x05DB" }, //( ‎ﬤ‎ → ‎כ‎ ) HEBREW LETTER WIDE KAF → HEBREW LETTER KAF	# 

			{ L"\xFB25",L"\x05DC" }, //( ‎ﬥ‎ → ‎ל‎ ) HEBREW LETTER WIDE LAMED → HEBREW LETTER LAMED	# 

			{ L"\xFB26",L"\x05DD" }, //( ‎ﬦ‎ → ‎ם‎ ) HEBREW LETTER WIDE FINAL MEM → HEBREW LETTER FINAL MEM	# 

			{ L"\xFB20",L"\x05E2" }, //( ‎ﬠ‎ → ‎ע‎ ) HEBREW LETTER ALTERNATIVE AYIN → HEBREW LETTER AYIN	# 

			{ L"\xFB27",L"\x05E8" }, //( ‎ﬧ‎ → ‎ר‎ ) HEBREW LETTER WIDE RESH → HEBREW LETTER RESH	# 

			{ L"\xFB2B",L"\xFB2A" }, //( ‎שׂ‎ → ‎שׁ‎ ) HEBREW LETTER SHIN WITH SIN DOT → HEBREW LETTER SHIN WITH SHIN DOT	# 
			{ L"\xFB49",L"\xFB2A" }, //( ‎שּ‎ → ‎שׁ‎ ) HEBREW LETTER SHIN WITH DAGESH → HEBREW LETTER SHIN WITH SHIN DOT	# 

			{ L"\xFB2D",L"\xFB2C" }, //( ‎שּׂ‎ → ‎שּׁ‎ ) HEBREW LETTER SHIN WITH DAGESH AND SIN DOT → HEBREW LETTER SHIN WITH DAGESH AND SHIN DOT	# 

			{ L"\xFB28",L"\x05EA" }, //( ‎ﬨ‎ → ‎ת‎ ) HEBREW LETTER WIDE TAV → HEBREW LETTER TAV	# 

			{ L"\xFE80",L"\x0621" }, //( ‎ﺀ‎ → ‎ء‎ ) ARABIC LETTER HAMZA ISOLATED FORM → ARABIC LETTER HAMZA	# 

			{ L"\x06FD",L"\x0621\x0348" }, //( ‎۽‎ → ‎ء͈‎ ) ARABIC SIGN SINDHI AMPERSAND → ARABIC LETTER HAMZA, COMBINING DOUBLE VERTICAL LINE BELOW	# 

			{ L"\xFE82",L"\x0622" }, //( ‎ﺂ‎ → ‎آ‎ ) ARABIC LETTER ALEF WITH MADDA ABOVE FINAL FORM → ARABIC LETTER ALEF WITH MADDA ABOVE	# 
			{ L"\xFE81",L"\x0622" }, //( ‎ﺁ‎ → ‎آ‎ ) ARABIC LETTER ALEF WITH MADDA ABOVE ISOLATED FORM → ARABIC LETTER ALEF WITH MADDA ABOVE	# 

			{ L"\xFB51",L"\x0671" }, //( ‎ﭑ‎ → ‎ٱ‎ ) ARABIC LETTER ALEF WASLA FINAL FORM → ARABIC LETTER ALEF WASLA	# 
			{ L"\xFB50",L"\x0671" }, //( ‎ﭐ‎ → ‎ٱ‎ ) ARABIC LETTER ALEF WASLA ISOLATED FORM → ARABIC LETTER ALEF WASLA	# 

			{ L"\x0001\xEE01",L"\x0628" }, //( ‎𞸁‎ → ‎ب‎ ) ARABIC MATHEMATICAL BEH → ARABIC LETTER BEH	# 
			{ L"\x0001\xEE21",L"\x0628" }, //( ‎𞸡‎ → ‎ب‎ ) ARABIC MATHEMATICAL INITIAL BEH → ARABIC LETTER BEH	# 
			{ L"\x0001\xEE61",L"\x0628" }, //( ‎𞹡‎ → ‎ب‎ ) ARABIC MATHEMATICAL STRETCHED BEH → ARABIC LETTER BEH	# 
			{ L"\x0001\xEE81",L"\x0628" }, //( ‎𞺁‎ → ‎ب‎ ) ARABIC MATHEMATICAL LOOPED BEH → ARABIC LETTER BEH	# 
			{ L"\x0001\xEEA1",L"\x0628" }, //( ‎𞺡‎ → ‎ب‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK BEH → ARABIC LETTER BEH	# 
			{ L"\xFE91",L"\x0628" }, //( ‎ﺑ‎ → ‎ب‎ ) ARABIC LETTER BEH INITIAL FORM → ARABIC LETTER BEH	# 
			{ L"\xFE92",L"\x0628" }, //( ‎ﺒ‎ → ‎ب‎ ) ARABIC LETTER BEH MEDIAL FORM → ARABIC LETTER BEH	# 
			{ L"\xFE90",L"\x0628" }, //( ‎ﺐ‎ → ‎ب‎ ) ARABIC LETTER BEH FINAL FORM → ARABIC LETTER BEH	# 
			{ L"\xFE8F",L"\x0628" }, //( ‎ﺏ‎ → ‎ب‎ ) ARABIC LETTER BEH ISOLATED FORM → ARABIC LETTER BEH	# 

			{ L"\x0751",L"\x0628\x06DB" }, //( ‎ݑ‎ → ‎بۛ‎ ) ARABIC LETTER BEH WITH DOT BELOW AND THREE DOTS ABOVE → ARABIC LETTER BEH, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\x08A1",L"\x0628\x0654" }, //( ‎ࢡ‎ → ‎بٔ‎ ) ARABIC LETTER BEH WITH HAMZA ABOVE → ARABIC LETTER BEH, ARABIC HAMZA ABOVE	# 

			{ L"\xFCA0",L"\x0628\x006F" }, //( ‎ﲠ‎ → ‎بo‎ ) ARABIC LIGATURE BEH WITH HEH INITIAL FORM → ARABIC LETTER BEH, LATIN SMALL LETTER O	# →‎به‎→
			{ L"\xFCE2",L"\x0628\x006F" }, //( ‎ﳢ‎ → ‎بo‎ ) ARABIC LIGATURE BEH WITH HEH MEDIAL FORM → ARABIC LETTER BEH, LATIN SMALL LETTER O	# →‎به‎→

			{ L"\xFC9C",L"\x0628\x062C" }, //( ‎ﲜ‎ → ‎بج‎ ) ARABIC LIGATURE BEH WITH JEEM INITIAL FORM → ARABIC LETTER BEH, ARABIC LETTER JEEM	# 
			{ L"\xFC05",L"\x0628\x062C" }, //( ‎ﰅ‎ → ‎بج‎ ) ARABIC LIGATURE BEH WITH JEEM ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER JEEM	# 

			{ L"\xFC9D",L"\x0628\x062D" }, //( ‎ﲝ‎ → ‎بح‎ ) ARABIC LIGATURE BEH WITH HAH INITIAL FORM → ARABIC LETTER BEH, ARABIC LETTER HAH	# 
			{ L"\xFC06",L"\x0628\x062D" }, //( ‎ﰆ‎ → ‎بح‎ ) ARABIC LIGATURE BEH WITH HAH ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER HAH	# 

			{ L"\xFDC2",L"\x0628\x062D\x0649" }, //( ‎ﷂ‎ → ‎بحى‎ ) ARABIC LIGATURE BEH WITH HAH WITH YEH FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎بحي‎→

			{ L"\xFC9E",L"\x0628\x062E" }, //( ‎ﲞ‎ → ‎بخ‎ ) ARABIC LIGATURE BEH WITH KHAH INITIAL FORM → ARABIC LETTER BEH, ARABIC LETTER KHAH	# 
			{ L"\xFC07",L"\x0628\x062E" }, //( ‎ﰇ‎ → ‎بخ‎ ) ARABIC LIGATURE BEH WITH KHAH ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER KHAH	# 
			{ L"\xFCD2",L"\x0628\x062E" }, //( ‎ﳒ‎ → ‎بخ‎ ) ARABIC LIGATURE NOON WITH JEEM INITIAL FORM → ARABIC LETTER BEH, ARABIC LETTER KHAH	# →‎ﲞ‎→
			{ L"\xFC4B",L"\x0628\x062E" }, //( ‎ﱋ‎ → ‎بخ‎ ) ARABIC LIGATURE NOON WITH JEEM ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER KHAH	# →‎نج‎→→‎ﳒ‎→→‎ﲞ‎→

			{ L"\xFD9E",L"\x0628\x062E\x0649" }, //( ‎ﶞ‎ → ‎بخى‎ ) ARABIC LIGATURE BEH WITH KHAH WITH YEH FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# →‎بخي‎→

			{ L"\xFC6A",L"\x0628\x0631" }, //( ‎ﱪ‎ → ‎بر‎ ) ARABIC LIGATURE BEH WITH REH FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER REH	# 

			{ L"\xFC6B",L"\x0628\x0632" }, //( ‎ﱫ‎ → ‎بز‎ ) ARABIC LIGATURE BEH WITH ZAIN FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER ZAIN	# 

			{ L"\xFC9F",L"\x0628\x0645" }, //( ‎ﲟ‎ → ‎بم‎ ) ARABIC LIGATURE BEH WITH MEEM INITIAL FORM → ARABIC LETTER BEH, ARABIC LETTER MEEM	# 
			{ L"\xFCE1",L"\x0628\x0645" }, //( ‎ﳡ‎ → ‎بم‎ ) ARABIC LIGATURE BEH WITH MEEM MEDIAL FORM → ARABIC LETTER BEH, ARABIC LETTER MEEM	# 
			{ L"\xFC6C",L"\x0628\x0645" }, //( ‎ﱬ‎ → ‎بم‎ ) ARABIC LIGATURE BEH WITH MEEM FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER MEEM	# 
			{ L"\xFC08",L"\x0628\x0645" }, //( ‎ﰈ‎ → ‎بم‎ ) ARABIC LIGATURE BEH WITH MEEM ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER MEEM	# 

			{ L"\xFC6D",L"\x0628\x0646" }, //( ‎ﱭ‎ → ‎بن‎ ) ARABIC LIGATURE BEH WITH NOON FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER NOON	# 

			{ L"\xFC6E",L"\x0628\x0649" }, //( ‎ﱮ‎ → ‎بى‎ ) ARABIC LIGATURE BEH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC09",L"\x0628\x0649" }, //( ‎ﰉ‎ → ‎بى‎ ) ARABIC LIGATURE BEH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC6F",L"\x0628\x0649" }, //( ‎ﱯ‎ → ‎بى‎ ) ARABIC LIGATURE BEH WITH YEH FINAL FORM → ARABIC LETTER BEH, ARABIC LETTER ALEF MAKSURA	# →‎بي‎→
			{ L"\xFC0A",L"\x0628\x0649" }, //( ‎ﰊ‎ → ‎بى‎ ) ARABIC LIGATURE BEH WITH YEH ISOLATED FORM → ARABIC LETTER BEH, ARABIC LETTER ALEF MAKSURA	# →‎بي‎→

			{ L"\xFB54",L"\x067B" }, //( ‎ﭔ‎ → ‎ٻ‎ ) ARABIC LETTER BEEH INITIAL FORM → ARABIC LETTER BEEH	# 
			{ L"\xFB55",L"\x067B" }, //( ‎ﭕ‎ → ‎ٻ‎ ) ARABIC LETTER BEEH MEDIAL FORM → ARABIC LETTER BEEH	# 
			{ L"\xFB53",L"\x067B" }, //( ‎ﭓ‎ → ‎ٻ‎ ) ARABIC LETTER BEEH FINAL FORM → ARABIC LETTER BEEH	# 
			{ L"\xFB52",L"\x067B" }, //( ‎ﭒ‎ → ‎ٻ‎ ) ARABIC LETTER BEEH ISOLATED FORM → ARABIC LETTER BEEH	# 
			{ L"\x06D0",L"\x067B" }, //( ‎ې‎ → ‎ٻ‎ ) ARABIC LETTER E → ARABIC LETTER BEEH	# 
			{ L"\xFBE6",L"\x067B" }, //( ‎ﯦ‎ → ‎ٻ‎ ) ARABIC LETTER E INITIAL FORM → ARABIC LETTER BEEH	# →‎ې‎→
			{ L"\xFBE7",L"\x067B" }, //( ‎ﯧ‎ → ‎ٻ‎ ) ARABIC LETTER E MEDIAL FORM → ARABIC LETTER BEEH	# →‎ې‎→
			{ L"\xFBE5",L"\x067B" }, //( ‎ﯥ‎ → ‎ٻ‎ ) ARABIC LETTER E FINAL FORM → ARABIC LETTER BEEH	# →‎ې‎→
			{ L"\xFBE4",L"\x067B" }, //( ‎ﯤ‎ → ‎ٻ‎ ) ARABIC LETTER E ISOLATED FORM → ARABIC LETTER BEEH	# →‎ې‎→

			{ L"\xFB5C",L"\x0680" }, //( ‎ﭜ‎ → ‎ڀ‎ ) ARABIC LETTER BEHEH INITIAL FORM → ARABIC LETTER BEHEH	# 
			{ L"\xFB5D",L"\x0680" }, //( ‎ﭝ‎ → ‎ڀ‎ ) ARABIC LETTER BEHEH MEDIAL FORM → ARABIC LETTER BEHEH	# 
			{ L"\xFB5B",L"\x0680" }, //( ‎ﭛ‎ → ‎ڀ‎ ) ARABIC LETTER BEHEH FINAL FORM → ARABIC LETTER BEHEH	# 
			{ L"\xFB5A",L"\x0680" }, //( ‎ﭚ‎ → ‎ڀ‎ ) ARABIC LETTER BEHEH ISOLATED FORM → ARABIC LETTER BEHEH	# 

			{ L"\x08A9",L"\x0754" }, //( ‎ࢩ‎ → ‎ݔ‎ ) ARABIC LETTER YEH WITH TWO DOTS BELOW AND DOT ABOVE → ARABIC LETTER BEH WITH TWO DOTS BELOW AND DOT ABOVE	# 
			{ L"\x0767",L"\x0754" }, //( ‎ݧ‎ → ‎ݔ‎ ) ARABIC LETTER NOON WITH TWO DOTS BELOW → ARABIC LETTER BEH WITH TWO DOTS BELOW AND DOT ABOVE	# 

			{ L"\x00F6",L"\x0629" }, //( ö → ‎ة‎ ) LATIN SMALL LETTER O WITH DIAERESIS → ARABIC LETTER TEH MARBUTA	# 
			{ L"\xFE94",L"\x0629" }, //( ‎ﺔ‎ → ‎ة‎ ) ARABIC LETTER TEH MARBUTA FINAL FORM → ARABIC LETTER TEH MARBUTA	# 
			{ L"\xFE93",L"\x0629" }, //( ‎ﺓ‎ → ‎ة‎ ) ARABIC LETTER TEH MARBUTA ISOLATED FORM → ARABIC LETTER TEH MARBUTA	# 
			{ L"\x06C3",L"\x0629" }, //( ‎ۃ‎ → ‎ة‎ ) ARABIC LETTER TEH MARBUTA GOAL → ARABIC LETTER TEH MARBUTA	# 

			{ L"\x0001\xEE15",L"\x062A" }, //( ‎𞸕‎ → ‎ت‎ ) ARABIC MATHEMATICAL TEH → ARABIC LETTER TEH	# 
			{ L"\x0001\xEE35",L"\x062A" }, //( ‎𞸵‎ → ‎ت‎ ) ARABIC MATHEMATICAL INITIAL TEH → ARABIC LETTER TEH	# 
			{ L"\x0001\xEE75",L"\x062A" }, //( ‎𞹵‎ → ‎ت‎ ) ARABIC MATHEMATICAL STRETCHED TEH → ARABIC LETTER TEH	# 
			{ L"\x0001\xEE95",L"\x062A" }, //( ‎𞺕‎ → ‎ت‎ ) ARABIC MATHEMATICAL LOOPED TEH → ARABIC LETTER TEH	# 
			{ L"\x0001\xEEB5",L"\x062A" }, //( ‎𞺵‎ → ‎ت‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK TEH → ARABIC LETTER TEH	# 
			{ L"\xFE97",L"\x062A" }, //( ‎ﺗ‎ → ‎ت‎ ) ARABIC LETTER TEH INITIAL FORM → ARABIC LETTER TEH	# 
			{ L"\xFE98",L"\x062A" }, //( ‎ﺘ‎ → ‎ت‎ ) ARABIC LETTER TEH MEDIAL FORM → ARABIC LETTER TEH	# 
			{ L"\xFE96",L"\x062A" }, //( ‎ﺖ‎ → ‎ت‎ ) ARABIC LETTER TEH FINAL FORM → ARABIC LETTER TEH	# 
			{ L"\xFE95",L"\x062A" }, //( ‎ﺕ‎ → ‎ت‎ ) ARABIC LETTER TEH ISOLATED FORM → ARABIC LETTER TEH	# 

			{ L"\xFCA5",L"\x062A\x006F" }, //( ‎ﲥ‎ → ‎تo‎ ) ARABIC LIGATURE TEH WITH HEH INITIAL FORM → ARABIC LETTER TEH, LATIN SMALL LETTER O	# →‎ته‎→
			{ L"\xFCE4",L"\x062A\x006F" }, //( ‎ﳤ‎ → ‎تo‎ ) ARABIC LIGATURE TEH WITH HEH MEDIAL FORM → ARABIC LETTER TEH, LATIN SMALL LETTER O	# →‎ته‎→

			{ L"\xFCA1",L"\x062A\x062C" }, //( ‎ﲡ‎ → ‎تج‎ ) ARABIC LIGATURE TEH WITH JEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER JEEM	# 
			{ L"\xFC0B",L"\x062A\x062C" }, //( ‎ﰋ‎ → ‎تج‎ ) ARABIC LIGATURE TEH WITH JEEM ISOLATED FORM → ARABIC LETTER TEH, ARABIC LETTER JEEM	# 

			{ L"\xFD50",L"\x062A\x062C\x0645" }, //( ‎ﵐ‎ → ‎تجم‎ ) ARABIC LIGATURE TEH WITH JEEM WITH MEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDA0",L"\x062A\x062C\x0649" }, //( ‎ﶠ‎ → ‎تجى‎ ) ARABIC LIGATURE TEH WITH JEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD9F",L"\x062A\x062C\x0649" }, //( ‎ﶟ‎ → ‎تجى‎ ) ARABIC LIGATURE TEH WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎تجي‎→

			{ L"\xFCA2",L"\x062A\x062D" }, //( ‎ﲢ‎ → ‎تح‎ ) ARABIC LIGATURE TEH WITH HAH INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER HAH	# 
			{ L"\xFC0C",L"\x062A\x062D" }, //( ‎ﰌ‎ → ‎تح‎ ) ARABIC LIGATURE TEH WITH HAH ISOLATED FORM → ARABIC LETTER TEH, ARABIC LETTER HAH	# 

			{ L"\xFD52",L"\x062A\x062D\x062C" }, //( ‎ﵒ‎ → ‎تحج‎ ) ARABIC LIGATURE TEH WITH HAH WITH JEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER HAH, ARABIC LETTER JEEM	# 
			{ L"\xFD51",L"\x062A\x062D\x062C" }, //( ‎ﵑ‎ → ‎تحج‎ ) ARABIC LIGATURE TEH WITH HAH WITH JEEM FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER HAH, ARABIC LETTER JEEM	# 

			{ L"\xFD53",L"\x062A\x062D\x0645" }, //( ‎ﵓ‎ → ‎تحم‎ ) ARABIC LIGATURE TEH WITH HAH WITH MEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER HAH, ARABIC LETTER MEEM	# 

			{ L"\xFCA3",L"\x062A\x062E" }, //( ‎ﲣ‎ → ‎تخ‎ ) ARABIC LIGATURE TEH WITH KHAH INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER KHAH	# 
			{ L"\xFC0D",L"\x062A\x062E" }, //( ‎ﰍ‎ → ‎تخ‎ ) ARABIC LIGATURE TEH WITH KHAH ISOLATED FORM → ARABIC LETTER TEH, ARABIC LETTER KHAH	# 

			{ L"\xFD54",L"\x062A\x062E\x0645" }, //( ‎ﵔ‎ → ‎تخم‎ ) ARABIC LIGATURE TEH WITH KHAH WITH MEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 

			{ L"\xFDA2",L"\x062A\x062E\x0649" }, //( ‎ﶢ‎ → ‎تخى‎ ) ARABIC LIGATURE TEH WITH KHAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDA1",L"\x062A\x062E\x0649" }, //( ‎ﶡ‎ → ‎تخى‎ ) ARABIC LIGATURE TEH WITH KHAH WITH YEH FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# →‎تخي‎→

			{ L"\xFC70",L"\x062A\x0631" }, //( ‎ﱰ‎ → ‎تر‎ ) ARABIC LIGATURE TEH WITH REH FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER REH	# 

			{ L"\xFC71",L"\x062A\x0632" }, //( ‎ﱱ‎ → ‎تز‎ ) ARABIC LIGATURE TEH WITH ZAIN FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER ZAIN	# 

			{ L"\xFCA4",L"\x062A\x0645" }, //( ‎ﲤ‎ → ‎تم‎ ) ARABIC LIGATURE TEH WITH MEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM	# 
			{ L"\xFCE3",L"\x062A\x0645" }, //( ‎ﳣ‎ → ‎تم‎ ) ARABIC LIGATURE TEH WITH MEEM MEDIAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM	# 
			{ L"\xFC72",L"\x062A\x0645" }, //( ‎ﱲ‎ → ‎تم‎ ) ARABIC LIGATURE TEH WITH MEEM FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM	# 
			{ L"\xFC0E",L"\x062A\x0645" }, //( ‎ﰎ‎ → ‎تم‎ ) ARABIC LIGATURE TEH WITH MEEM ISOLATED FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM	# 

			{ L"\xFD55",L"\x062A\x0645\x062C" }, //( ‎ﵕ‎ → ‎تمج‎ ) ARABIC LIGATURE TEH WITH MEEM WITH JEEM INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM, ARABIC LETTER JEEM	# 

			{ L"\xFD56",L"\x062A\x0645\x062D" }, //( ‎ﵖ‎ → ‎تمح‎ ) ARABIC LIGATURE TEH WITH MEEM WITH HAH INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFD57",L"\x062A\x0645\x062E" }, //( ‎ﵗ‎ → ‎تمخ‎ ) ARABIC LIGATURE TEH WITH MEEM WITH KHAH INITIAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM, ARABIC LETTER KHAH	# 

			{ L"\xFDA4",L"\x062A\x0645\x0649" }, //( ‎ﶤ‎ → ‎تمى‎ ) ARABIC LIGATURE TEH WITH MEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDA3",L"\x062A\x0645\x0649" }, //( ‎ﶣ‎ → ‎تمى‎ ) ARABIC LIGATURE TEH WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎تمي‎→

			{ L"\xFC73",L"\x062A\x0646" }, //( ‎ﱳ‎ → ‎تن‎ ) ARABIC LIGATURE TEH WITH NOON FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER NOON	# 

			{ L"\xFC74",L"\x062A\x0649" }, //( ‎ﱴ‎ → ‎تى‎ ) ARABIC LIGATURE TEH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC0F",L"\x062A\x0649" }, //( ‎ﰏ‎ → ‎تى‎ ) ARABIC LIGATURE TEH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER TEH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC75",L"\x062A\x0649" }, //( ‎ﱵ‎ → ‎تى‎ ) ARABIC LIGATURE TEH WITH YEH FINAL FORM → ARABIC LETTER TEH, ARABIC LETTER ALEF MAKSURA	# →‎تي‎→
			{ L"\xFC10",L"\x062A\x0649" }, //( ‎ﰐ‎ → ‎تى‎ ) ARABIC LIGATURE TEH WITH YEH ISOLATED FORM → ARABIC LETTER TEH, ARABIC LETTER ALEF MAKSURA	# →‎تي‎→

			{ L"\xFB60",L"\x067A" }, //( ‎ﭠ‎ → ‎ٺ‎ ) ARABIC LETTER TTEHEH INITIAL FORM → ARABIC LETTER TTEHEH	# 
			{ L"\xFB61",L"\x067A" }, //( ‎ﭡ‎ → ‎ٺ‎ ) ARABIC LETTER TTEHEH MEDIAL FORM → ARABIC LETTER TTEHEH	# 
			{ L"\xFB5F",L"\x067A" }, //( ‎ﭟ‎ → ‎ٺ‎ ) ARABIC LETTER TTEHEH FINAL FORM → ARABIC LETTER TTEHEH	# 
			{ L"\xFB5E",L"\x067A" }, //( ‎ﭞ‎ → ‎ٺ‎ ) ARABIC LETTER TTEHEH ISOLATED FORM → ARABIC LETTER TTEHEH	# 

			{ L"\xFB64",L"\x067F" }, //( ‎ﭤ‎ → ‎ٿ‎ ) ARABIC LETTER TEHEH INITIAL FORM → ARABIC LETTER TEHEH	# 
			{ L"\xFB65",L"\x067F" }, //( ‎ﭥ‎ → ‎ٿ‎ ) ARABIC LETTER TEHEH MEDIAL FORM → ARABIC LETTER TEHEH	# 
			{ L"\xFB63",L"\x067F" }, //( ‎ﭣ‎ → ‎ٿ‎ ) ARABIC LETTER TEHEH FINAL FORM → ARABIC LETTER TEHEH	# 
			{ L"\xFB62",L"\x067F" }, //( ‎ﭢ‎ → ‎ٿ‎ ) ARABIC LETTER TEHEH ISOLATED FORM → ARABIC LETTER TEHEH	# 

			{ L"\x0001\xEE02",L"\x062C" }, //( ‎𞸂‎ → ‎ج‎ ) ARABIC MATHEMATICAL JEEM → ARABIC LETTER JEEM	# 
			{ L"\x0001\xEE22",L"\x062C" }, //( ‎𞸢‎ → ‎ج‎ ) ARABIC MATHEMATICAL INITIAL JEEM → ARABIC LETTER JEEM	# 
			{ L"\x0001\xEE42",L"\x062C" }, //( ‎𞹂‎ → ‎ج‎ ) ARABIC MATHEMATICAL TAILED JEEM → ARABIC LETTER JEEM	# 
			{ L"\x0001\xEE62",L"\x062C" }, //( ‎𞹢‎ → ‎ج‎ ) ARABIC MATHEMATICAL STRETCHED JEEM → ARABIC LETTER JEEM	# 
			{ L"\x0001\xEE82",L"\x062C" }, //( ‎𞺂‎ → ‎ج‎ ) ARABIC MATHEMATICAL LOOPED JEEM → ARABIC LETTER JEEM	# 
			{ L"\x0001\xEEA2",L"\x062C" }, //( ‎𞺢‎ → ‎ج‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK JEEM → ARABIC LETTER JEEM	# 
			{ L"\xFE9F",L"\x062C" }, //( ‎ﺟ‎ → ‎ج‎ ) ARABIC LETTER JEEM INITIAL FORM → ARABIC LETTER JEEM	# 
			{ L"\xFEA0",L"\x062C" }, //( ‎ﺠ‎ → ‎ج‎ ) ARABIC LETTER JEEM MEDIAL FORM → ARABIC LETTER JEEM	# 
			{ L"\xFE9E",L"\x062C" }, //( ‎ﺞ‎ → ‎ج‎ ) ARABIC LETTER JEEM FINAL FORM → ARABIC LETTER JEEM	# 
			{ L"\xFE9D",L"\x062C" }, //( ‎ﺝ‎ → ‎ج‎ ) ARABIC LETTER JEEM ISOLATED FORM → ARABIC LETTER JEEM	# 

			{ L"\xFCA7",L"\x062C\x062D" }, //( ‎ﲧ‎ → ‎جح‎ ) ARABIC LIGATURE JEEM WITH HAH INITIAL FORM → ARABIC LETTER JEEM, ARABIC LETTER HAH	# 
			{ L"\xFC15",L"\x062C\x062D" }, //( ‎ﰕ‎ → ‎جح‎ ) ARABIC LIGATURE JEEM WITH HAH ISOLATED FORM → ARABIC LETTER JEEM, ARABIC LETTER HAH	# 

			{ L"\xFDA6",L"\x062C\x062D\x0649" }, //( ‎ﶦ‎ → ‎جحى‎ ) ARABIC LIGATURE JEEM WITH HAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDBE",L"\x062C\x062D\x0649" }, //( ‎ﶾ‎ → ‎جحى‎ ) ARABIC LIGATURE JEEM WITH HAH WITH YEH FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎جحي‎→

			{ L"\xFDFB",L"\x062C\x0644\x0020\x062C\x0644\x006C\x0644\x006F" }, //( ‎ﷻ‎ → ‎جل جلlلo‎ ) ARABIC LIGATURE JALLAJALALOUHOU → ARABIC LETTER JEEM, ARABIC LETTER LAM, SPACE, ARABIC LETTER JEEM, ARABIC LETTER LAM, LATIN SMALL LETTER L, ARABIC LETTER LAM, LATIN SMALL LETTER O	# →‎جل جلاله‎→

			{ L"\xFCA8",L"\x062C\x0645" }, //( ‎ﲨ‎ → ‎جم‎ ) ARABIC LIGATURE JEEM WITH MEEM INITIAL FORM → ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 
			{ L"\xFC16",L"\x062C\x0645" }, //( ‎ﰖ‎ → ‎جم‎ ) ARABIC LIGATURE JEEM WITH MEEM ISOLATED FORM → ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD59",L"\x062C\x0645\x062D" }, //( ‎ﵙ‎ → ‎جمح‎ ) ARABIC LIGATURE JEEM WITH MEEM WITH HAH INITIAL FORM → ARABIC LETTER JEEM, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 
			{ L"\xFD58",L"\x062C\x0645\x062D" }, //( ‎ﵘ‎ → ‎جمح‎ ) ARABIC LIGATURE JEEM WITH MEEM WITH HAH FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFDA7",L"\x062C\x0645\x0649" }, //( ‎ﶧ‎ → ‎جمى‎ ) ARABIC LIGATURE JEEM WITH MEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDA5",L"\x062C\x0645\x0649" }, //( ‎ﶥ‎ → ‎جمى‎ ) ARABIC LIGATURE JEEM WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎جمي‎→

			{ L"\xFD1D",L"\x062C\x0649" }, //( ‎ﴝ‎ → ‎جى‎ ) ARABIC LIGATURE JEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD01",L"\x062C\x0649" }, //( ‎ﴁ‎ → ‎جى‎ ) ARABIC LIGATURE JEEM WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD1E",L"\x062C\x0649" }, //( ‎ﴞ‎ → ‎جى‎ ) ARABIC LIGATURE JEEM WITH YEH FINAL FORM → ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎جي‎→
			{ L"\xFD02",L"\x062C\x0649" }, //( ‎ﴂ‎ → ‎جى‎ ) ARABIC LIGATURE JEEM WITH YEH ISOLATED FORM → ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎جي‎→

			{ L"\xFB78",L"\x0683" }, //( ‎ﭸ‎ → ‎ڃ‎ ) ARABIC LETTER NYEH INITIAL FORM → ARABIC LETTER NYEH	# 
			{ L"\xFB79",L"\x0683" }, //( ‎ﭹ‎ → ‎ڃ‎ ) ARABIC LETTER NYEH MEDIAL FORM → ARABIC LETTER NYEH	# 
			{ L"\xFB77",L"\x0683" }, //( ‎ﭷ‎ → ‎ڃ‎ ) ARABIC LETTER NYEH FINAL FORM → ARABIC LETTER NYEH	# 
			{ L"\xFB76",L"\x0683" }, //( ‎ﭶ‎ → ‎ڃ‎ ) ARABIC LETTER NYEH ISOLATED FORM → ARABIC LETTER NYEH	# 

			{ L"\xFB74",L"\x0684" }, //( ‎ﭴ‎ → ‎ڄ‎ ) ARABIC LETTER DYEH INITIAL FORM → ARABIC LETTER DYEH	# 
			{ L"\xFB75",L"\x0684" }, //( ‎ﭵ‎ → ‎ڄ‎ ) ARABIC LETTER DYEH MEDIAL FORM → ARABIC LETTER DYEH	# 
			{ L"\xFB73",L"\x0684" }, //( ‎ﭳ‎ → ‎ڄ‎ ) ARABIC LETTER DYEH FINAL FORM → ARABIC LETTER DYEH	# 
			{ L"\xFB72",L"\x0684" }, //( ‎ﭲ‎ → ‎ڄ‎ ) ARABIC LETTER DYEH ISOLATED FORM → ARABIC LETTER DYEH	# 

			{ L"\xFB7C",L"\x0686" }, //( ‎ﭼ‎ → ‎چ‎ ) ARABIC LETTER TCHEH INITIAL FORM → ARABIC LETTER TCHEH	# 
			{ L"\xFB7D",L"\x0686" }, //( ‎ﭽ‎ → ‎چ‎ ) ARABIC LETTER TCHEH MEDIAL FORM → ARABIC LETTER TCHEH	# 
			{ L"\xFB7B",L"\x0686" }, //( ‎ﭻ‎ → ‎چ‎ ) ARABIC LETTER TCHEH FINAL FORM → ARABIC LETTER TCHEH	# 
			{ L"\xFB7A",L"\x0686" }, //( ‎ﭺ‎ → ‎چ‎ ) ARABIC LETTER TCHEH ISOLATED FORM → ARABIC LETTER TCHEH	# 

			{ L"\xFB80",L"\x0687" }, //( ‎ﮀ‎ → ‎ڇ‎ ) ARABIC LETTER TCHEHEH INITIAL FORM → ARABIC LETTER TCHEHEH	# 
			{ L"\xFB81",L"\x0687" }, //( ‎ﮁ‎ → ‎ڇ‎ ) ARABIC LETTER TCHEHEH MEDIAL FORM → ARABIC LETTER TCHEHEH	# 
			{ L"\xFB7F",L"\x0687" }, //( ‎ﭿ‎ → ‎ڇ‎ ) ARABIC LETTER TCHEHEH FINAL FORM → ARABIC LETTER TCHEHEH	# 
			{ L"\xFB7E",L"\x0687" }, //( ‎ﭾ‎ → ‎ڇ‎ ) ARABIC LETTER TCHEHEH ISOLATED FORM → ARABIC LETTER TCHEHEH	# 

			{ L"\x0001\xEE07",L"\x062D" }, //( ‎𞸇‎ → ‎ح‎ ) ARABIC MATHEMATICAL HAH → ARABIC LETTER HAH	# 
			{ L"\x0001\xEE27",L"\x062D" }, //( ‎𞸧‎ → ‎ح‎ ) ARABIC MATHEMATICAL INITIAL HAH → ARABIC LETTER HAH	# 
			{ L"\x0001\xEE47",L"\x062D" }, //( ‎𞹇‎ → ‎ح‎ ) ARABIC MATHEMATICAL TAILED HAH → ARABIC LETTER HAH	# 
			{ L"\x0001\xEE67",L"\x062D" }, //( ‎𞹧‎ → ‎ح‎ ) ARABIC MATHEMATICAL STRETCHED HAH → ARABIC LETTER HAH	# 
			{ L"\x0001\xEE87",L"\x062D" }, //( ‎𞺇‎ → ‎ح‎ ) ARABIC MATHEMATICAL LOOPED HAH → ARABIC LETTER HAH	# 
			{ L"\x0001\xEEA7",L"\x062D" }, //( ‎𞺧‎ → ‎ح‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK HAH → ARABIC LETTER HAH	# 
			{ L"\xFEA3",L"\x062D" }, //( ‎ﺣ‎ → ‎ح‎ ) ARABIC LETTER HAH INITIAL FORM → ARABIC LETTER HAH	# 
			{ L"\xFEA4",L"\x062D" }, //( ‎ﺤ‎ → ‎ح‎ ) ARABIC LETTER HAH MEDIAL FORM → ARABIC LETTER HAH	# 
			{ L"\xFEA2",L"\x062D" }, //( ‎ﺢ‎ → ‎ح‎ ) ARABIC LETTER HAH FINAL FORM → ARABIC LETTER HAH	# 
			{ L"\xFEA1",L"\x062D" }, //( ‎ﺡ‎ → ‎ح‎ ) ARABIC LETTER HAH ISOLATED FORM → ARABIC LETTER HAH	# 

			{ L"\x0685",L"\x062D\x06DB" }, //( ‎څ‎ → ‎حۛ‎ ) ARABIC LETTER HAH WITH THREE DOTS ABOVE → ARABIC LETTER HAH, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\x0681",L"\x062D\x0654" }, //( ‎ځ‎ → ‎حٔ‎ ) ARABIC LETTER HAH WITH HAMZA ABOVE → ARABIC LETTER HAH, ARABIC HAMZA ABOVE	# 
			{ L"\x0772",L"\x062D\x0654" }, //( ‎ݲ‎ → ‎حٔ‎ ) ARABIC LETTER HAH WITH SMALL ARABIC LETTER TAH ABOVE → ARABIC LETTER HAH, ARABIC HAMZA ABOVE	# 

			{ L"\xFCA9",L"\x062D\x062C" }, //( ‎ﲩ‎ → ‎حج‎ ) ARABIC LIGATURE HAH WITH JEEM INITIAL FORM → ARABIC LETTER HAH, ARABIC LETTER JEEM	# 
			{ L"\xFC17",L"\x062D\x062C" }, //( ‎ﰗ‎ → ‎حج‎ ) ARABIC LIGATURE HAH WITH JEEM ISOLATED FORM → ARABIC LETTER HAH, ARABIC LETTER JEEM	# 

			{ L"\xFDBF",L"\x062D\x062C\x0649" }, //( ‎ﶿ‎ → ‎حجى‎ ) ARABIC LIGATURE HAH WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER HAH, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎حجي‎→

			{ L"\xFCAA",L"\x062D\x0645" }, //( ‎ﲪ‎ → ‎حم‎ ) ARABIC LIGATURE HAH WITH MEEM INITIAL FORM → ARABIC LETTER HAH, ARABIC LETTER MEEM	# 
			{ L"\xFC18",L"\x062D\x0645" }, //( ‎ﰘ‎ → ‎حم‎ ) ARABIC LIGATURE HAH WITH MEEM ISOLATED FORM → ARABIC LETTER HAH, ARABIC LETTER MEEM	# 

			{ L"\xFD5B",L"\x062D\x0645\x0649" }, //( ‎ﵛ‎ → ‎حمى‎ ) ARABIC LIGATURE HAH WITH MEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER HAH, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD5A",L"\x062D\x0645\x0649" }, //( ‎ﵚ‎ → ‎حمى‎ ) ARABIC LIGATURE HAH WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER HAH, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎حمي‎→

			{ L"\xFD1B",L"\x062D\x0649" }, //( ‎ﴛ‎ → ‎حى‎ ) ARABIC LIGATURE HAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFCFF",L"\x062D\x0649" }, //( ‎ﳿ‎ → ‎حى‎ ) ARABIC LIGATURE HAH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD1C",L"\x062D\x0649" }, //( ‎ﴜ‎ → ‎حى‎ ) ARABIC LIGATURE HAH WITH YEH FINAL FORM → ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎حي‎→
			{ L"\xFD00",L"\x062D\x0649" }, //( ‎ﴀ‎ → ‎حى‎ ) ARABIC LIGATURE HAH WITH YEH ISOLATED FORM → ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎حي‎→

			{ L"\x0001\xEE17",L"\x062E" }, //( ‎𞸗‎ → ‎خ‎ ) ARABIC MATHEMATICAL KHAH → ARABIC LETTER KHAH	# 
			{ L"\x0001\xEE37",L"\x062E" }, //( ‎𞸷‎ → ‎خ‎ ) ARABIC MATHEMATICAL INITIAL KHAH → ARABIC LETTER KHAH	# 
			{ L"\x0001\xEE57",L"\x062E" }, //( ‎𞹗‎ → ‎خ‎ ) ARABIC MATHEMATICAL TAILED KHAH → ARABIC LETTER KHAH	# 
			{ L"\x0001\xEE77",L"\x062E" }, //( ‎𞹷‎ → ‎خ‎ ) ARABIC MATHEMATICAL STRETCHED KHAH → ARABIC LETTER KHAH	# 
			{ L"\x0001\xEE97",L"\x062E" }, //( ‎𞺗‎ → ‎خ‎ ) ARABIC MATHEMATICAL LOOPED KHAH → ARABIC LETTER KHAH	# 
			{ L"\x0001\xEEB7",L"\x062E" }, //( ‎𞺷‎ → ‎خ‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK KHAH → ARABIC LETTER KHAH	# 
			{ L"\xFEA7",L"\x062E" }, //( ‎ﺧ‎ → ‎خ‎ ) ARABIC LETTER KHAH INITIAL FORM → ARABIC LETTER KHAH	# 
			{ L"\xFEA8",L"\x062E" }, //( ‎ﺨ‎ → ‎خ‎ ) ARABIC LETTER KHAH MEDIAL FORM → ARABIC LETTER KHAH	# 
			{ L"\xFEA6",L"\x062E" }, //( ‎ﺦ‎ → ‎خ‎ ) ARABIC LETTER KHAH FINAL FORM → ARABIC LETTER KHAH	# 
			{ L"\xFEA5",L"\x062E" }, //( ‎ﺥ‎ → ‎خ‎ ) ARABIC LETTER KHAH ISOLATED FORM → ARABIC LETTER KHAH	# 

			{ L"\xFCAB",L"\x062E\x062C" }, //( ‎ﲫ‎ → ‎خج‎ ) ARABIC LIGATURE KHAH WITH JEEM INITIAL FORM → ARABIC LETTER KHAH, ARABIC LETTER JEEM	# 
			{ L"\xFC19",L"\x062E\x062C" }, //( ‎ﰙ‎ → ‎خج‎ ) ARABIC LIGATURE KHAH WITH JEEM ISOLATED FORM → ARABIC LETTER KHAH, ARABIC LETTER JEEM	# 

			{ L"\xFC1A",L"\x062E\x062D" }, //( ‎ﰚ‎ → ‎خح‎ ) ARABIC LIGATURE KHAH WITH HAH ISOLATED FORM → ARABIC LETTER KHAH, ARABIC LETTER HAH	# 

			{ L"\xFCAC",L"\x062E\x0645" }, //( ‎ﲬ‎ → ‎خم‎ ) ARABIC LIGATURE KHAH WITH MEEM INITIAL FORM → ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 
			{ L"\xFC1B",L"\x062E\x0645" }, //( ‎ﰛ‎ → ‎خم‎ ) ARABIC LIGATURE KHAH WITH MEEM ISOLATED FORM → ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 

			{ L"\xFD1F",L"\x062E\x0649" }, //( ‎ﴟ‎ → ‎خى‎ ) ARABIC LIGATURE KHAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD03",L"\x062E\x0649" }, //( ‎ﴃ‎ → ‎خى‎ ) ARABIC LIGATURE KHAH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD20",L"\x062E\x0649" }, //( ‎ﴠ‎ → ‎خى‎ ) ARABIC LIGATURE KHAH WITH YEH FINAL FORM → ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# →‎خي‎→
			{ L"\xFD04",L"\x062E\x0649" }, //( ‎ﴄ‎ → ‎خى‎ ) ARABIC LIGATURE KHAH WITH YEH ISOLATED FORM → ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# →‎خي‎→

			{ L"\x0001\x02E1",L"\x062F" }, //( 𐋡 → ‎د‎ ) COPTIC EPACT DIGIT ONE → ARABIC LETTER DAL	# 
			{ L"\x0001\xEE03",L"\x062F" }, //( ‎𞸃‎ → ‎د‎ ) ARABIC MATHEMATICAL DAL → ARABIC LETTER DAL	# 
			{ L"\x0001\xEE83",L"\x062F" }, //( ‎𞺃‎ → ‎د‎ ) ARABIC MATHEMATICAL LOOPED DAL → ARABIC LETTER DAL	# 
			{ L"\x0001\xEEA3",L"\x062F" }, //( ‎𞺣‎ → ‎د‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK DAL → ARABIC LETTER DAL	# 
			{ L"\xFEAA",L"\x062F" }, //( ‎ﺪ‎ → ‎د‎ ) ARABIC LETTER DAL FINAL FORM → ARABIC LETTER DAL	# 
			{ L"\xFEA9",L"\x062F" }, //( ‎ﺩ‎ → ‎د‎ ) ARABIC LETTER DAL ISOLATED FORM → ARABIC LETTER DAL	# 

			{ L"\x0688",L"\x062F\x0615" }, //( ‎ڈ‎ → ‎دؕ‎ ) ARABIC LETTER DDAL → ARABIC LETTER DAL, ARABIC SMALL HIGH TAH	# 
			{ L"\xFB89",L"\x062F\x0615" }, //( ‎ﮉ‎ → ‎دؕ‎ ) ARABIC LETTER DDAL FINAL FORM → ARABIC LETTER DAL, ARABIC SMALL HIGH TAH	# →‎ڈ‎→
			{ L"\xFB88",L"\x062F\x0615" }, //( ‎ﮈ‎ → ‎دؕ‎ ) ARABIC LETTER DDAL ISOLATED FORM → ARABIC LETTER DAL, ARABIC SMALL HIGH TAH	# →‎ڈ‎→

			{ L"\x068E",L"\x062F\x06DB" }, //( ‎ڎ‎ → ‎دۛ‎ ) ARABIC LETTER DUL → ARABIC LETTER DAL, ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\xFB87",L"\x062F\x06DB" }, //( ‎ﮇ‎ → ‎دۛ‎ ) ARABIC LETTER DUL FINAL FORM → ARABIC LETTER DAL, ARABIC SMALL HIGH THREE DOTS	# →‎ڎ‎→
			{ L"\xFB86",L"\x062F\x06DB" }, //( ‎ﮆ‎ → ‎دۛ‎ ) ARABIC LETTER DUL ISOLATED FORM → ARABIC LETTER DAL, ARABIC SMALL HIGH THREE DOTS	# →‎ڎ‎→

			{ L"\x06EE",L"\x062F\x0302" }, //( ‎ۮ‎ → ‎د̂‎ ) ARABIC LETTER DAL WITH INVERTED V → ARABIC LETTER DAL, COMBINING CIRCUMFLEX ACCENT	# →‎دٛ‎→

			{ L"\x08AE",L"\x062F\x0324\x0323" }, //( ‎ࢮ‎ → ‎د̤̣‎ ) ARABIC LETTER DAL WITH THREE DOTS BELOW → ARABIC LETTER DAL, COMBINING DIAERESIS BELOW, COMBINING DOT BELOW	# →‎د࣮࣭‎→

			{ L"\x0001\xEE18",L"\x0630" }, //( ‎𞸘‎ → ‎ذ‎ ) ARABIC MATHEMATICAL THAL → ARABIC LETTER THAL	# 
			{ L"\x0001\xEE98",L"\x0630" }, //( ‎𞺘‎ → ‎ذ‎ ) ARABIC MATHEMATICAL LOOPED THAL → ARABIC LETTER THAL	# 
			{ L"\x0001\xEEB8",L"\x0630" }, //( ‎𞺸‎ → ‎ذ‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK THAL → ARABIC LETTER THAL	# 
			{ L"\xFEAC",L"\x0630" }, //( ‎ﺬ‎ → ‎ذ‎ ) ARABIC LETTER THAL FINAL FORM → ARABIC LETTER THAL	# 
			{ L"\xFEAB",L"\x0630" }, //( ‎ﺫ‎ → ‎ذ‎ ) ARABIC LETTER THAL ISOLATED FORM → ARABIC LETTER THAL	# 

			{ L"\xFC5B",L"\x0630\x0670" }, //( ‎ﱛ‎ → ‎ذٰ‎ ) ARABIC LIGATURE THAL WITH SUPERSCRIPT ALEF ISOLATED FORM → ARABIC LETTER THAL, ARABIC LETTER SUPERSCRIPT ALEF	# 

			{ L"\x068B",L"\x068A\x0615" }, //( ‎ڋ‎ → ‎ڊؕ‎ ) ARABIC LETTER DAL WITH DOT BELOW AND SMALL TAH → ARABIC LETTER DAL WITH DOT BELOW, ARABIC SMALL HIGH TAH	# 

			{ L"\xFB85",L"\x068C" }, //( ‎ﮅ‎ → ‎ڌ‎ ) ARABIC LETTER DAHAL FINAL FORM → ARABIC LETTER DAHAL	# 
			{ L"\xFB84",L"\x068C" }, //( ‎ﮄ‎ → ‎ڌ‎ ) ARABIC LETTER DAHAL ISOLATED FORM → ARABIC LETTER DAHAL	# 

			{ L"\xFB83",L"\x068D" }, //( ‎ﮃ‎ → ‎ڍ‎ ) ARABIC LETTER DDAHAL FINAL FORM → ARABIC LETTER DDAHAL	# 
			{ L"\xFB82",L"\x068D" }, //( ‎ﮂ‎ → ‎ڍ‎ ) ARABIC LETTER DDAHAL ISOLATED FORM → ARABIC LETTER DDAHAL	# 

			{ L"\x0001\xEE13",L"\x0631" }, //( ‎𞸓‎ → ‎ر‎ ) ARABIC MATHEMATICAL REH → ARABIC LETTER REH	# 
			{ L"\x0001\xEE93",L"\x0631" }, //( ‎𞺓‎ → ‎ر‎ ) ARABIC MATHEMATICAL LOOPED REH → ARABIC LETTER REH	# 
			{ L"\x0001\xEEB3",L"\x0631" }, //( ‎𞺳‎ → ‎ر‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK REH → ARABIC LETTER REH	# 
			{ L"\xFEAE",L"\x0631" }, //( ‎ﺮ‎ → ‎ر‎ ) ARABIC LETTER REH FINAL FORM → ARABIC LETTER REH	# 
			{ L"\xFEAD",L"\x0631" }, //( ‎ﺭ‎ → ‎ر‎ ) ARABIC LETTER REH ISOLATED FORM → ARABIC LETTER REH	# 

			{ L"\x0691",L"\x0631\x0615" }, //( ‎ڑ‎ → ‎رؕ‎ ) ARABIC LETTER RREH → ARABIC LETTER REH, ARABIC SMALL HIGH TAH	# 
			{ L"\xFB8D",L"\x0631\x0615" }, //( ‎ﮍ‎ → ‎رؕ‎ ) ARABIC LETTER RREH FINAL FORM → ARABIC LETTER REH, ARABIC SMALL HIGH TAH	# →‎ڑ‎→
			{ L"\xFB8C",L"\x0631\x0615" }, //( ‎ﮌ‎ → ‎رؕ‎ ) ARABIC LETTER RREH ISOLATED FORM → ARABIC LETTER REH, ARABIC SMALL HIGH TAH	# →‎ڑ‎→

			{ L"\x0698",L"\x0631\x06DB" }, //( ‎ژ‎ → ‎رۛ‎ ) ARABIC LETTER JEH → ARABIC LETTER REH, ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\xFB8B",L"\x0631\x06DB" }, //( ‎ﮋ‎ → ‎رۛ‎ ) ARABIC LETTER JEH FINAL FORM → ARABIC LETTER REH, ARABIC SMALL HIGH THREE DOTS	# →‎ژ‎→
			{ L"\xFB8A",L"\x0631\x06DB" }, //( ‎ﮊ‎ → ‎رۛ‎ ) ARABIC LETTER JEH ISOLATED FORM → ARABIC LETTER REH, ARABIC SMALL HIGH THREE DOTS	# →‎ژ‎→

			{ L"\x0692",L"\x0631\x0306" }, //( ‎ڒ‎ → ‎ر̆‎ ) ARABIC LETTER REH WITH SMALL V → ARABIC LETTER REH, COMBINING BREVE	# →‎رٚ‎→

			{ L"\x06EF",L"\x0631\x0302" }, //( ‎ۯ‎ → ‎ر̂‎ ) ARABIC LETTER REH WITH INVERTED V → ARABIC LETTER REH, COMBINING CIRCUMFLEX ACCENT	# →‎رٛ‎→

			{ L"\x076C",L"\x0631\x0654" }, //( ‎ݬ‎ → ‎رٔ‎ ) ARABIC LETTER REH WITH HAMZA ABOVE → ARABIC LETTER REH, ARABIC HAMZA ABOVE	# 

			{ L"\xFC5C",L"\x0631\x0670" }, //( ‎ﱜ‎ → ‎رٰ‎ ) ARABIC LIGATURE REH WITH SUPERSCRIPT ALEF ISOLATED FORM → ARABIC LETTER REH, ARABIC LETTER SUPERSCRIPT ALEF	# 

			{ L"\xFDF6",L"\x0631\x0633\x0648\x0644" }, //( ‎ﷶ‎ → ‎رسول‎ ) ARABIC LIGATURE RASOUL ISOLATED FORM → ARABIC LETTER REH, ARABIC LETTER SEEN, ARABIC LETTER WAW, ARABIC LETTER LAM	# 

			{ L"\xFDFC",L"\x0631\x0649\x006C\x0644" }, //( ‎﷼‎ → ‎رىlل‎ ) RIAL SIGN → ARABIC LETTER REH, ARABIC LETTER ALEF MAKSURA, LATIN SMALL LETTER L, ARABIC LETTER LAM	# →‎ریال‎→

			{ L"\x0001\xEE06",L"\x0632" }, //( ‎𞸆‎ → ‎ز‎ ) ARABIC MATHEMATICAL ZAIN → ARABIC LETTER ZAIN	# 
			{ L"\x0001\xEE86",L"\x0632" }, //( ‎𞺆‎ → ‎ز‎ ) ARABIC MATHEMATICAL LOOPED ZAIN → ARABIC LETTER ZAIN	# 
			{ L"\x0001\xEEA6",L"\x0632" }, //( ‎𞺦‎ → ‎ز‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK ZAIN → ARABIC LETTER ZAIN	# 
			{ L"\xFEB0",L"\x0632" }, //( ‎ﺰ‎ → ‎ز‎ ) ARABIC LETTER ZAIN FINAL FORM → ARABIC LETTER ZAIN	# 
			{ L"\xFEAF",L"\x0632" }, //( ‎ﺯ‎ → ‎ز‎ ) ARABIC LETTER ZAIN ISOLATED FORM → ARABIC LETTER ZAIN	# 

			{ L"\x08B2",L"\x0632\x0302" }, //( ‎ࢲ‎ → ‎ز̂‎ ) ARABIC LETTER ZAIN WITH INVERTED V ABOVE → ARABIC LETTER ZAIN, COMBINING CIRCUMFLEX ACCENT	# →‎زٛ‎→

			{ L"\x0771",L"\x0697\x0615" }, //( ‎ݱ‎ → ‎ڗؕ‎ ) ARABIC LETTER REH WITH SMALL ARABIC LETTER TAH AND TWO DOTS → ARABIC LETTER REH WITH TWO DOTS ABOVE, ARABIC SMALL HIGH TAH	# 

			{ L"\x0001\xEE0E",L"\x0633" }, //( ‎𞸎‎ → ‎س‎ ) ARABIC MATHEMATICAL SEEN → ARABIC LETTER SEEN	# 
			{ L"\x0001\xEE2E",L"\x0633" }, //( ‎𞸮‎ → ‎س‎ ) ARABIC MATHEMATICAL INITIAL SEEN → ARABIC LETTER SEEN	# 
			{ L"\x0001\xEE4E",L"\x0633" }, //( ‎𞹎‎ → ‎س‎ ) ARABIC MATHEMATICAL TAILED SEEN → ARABIC LETTER SEEN	# 
			{ L"\x0001\xEE6E",L"\x0633" }, //( ‎𞹮‎ → ‎س‎ ) ARABIC MATHEMATICAL STRETCHED SEEN → ARABIC LETTER SEEN	# 
			{ L"\x0001\xEE8E",L"\x0633" }, //( ‎𞺎‎ → ‎س‎ ) ARABIC MATHEMATICAL LOOPED SEEN → ARABIC LETTER SEEN	# 
			{ L"\x0001\xEEAE",L"\x0633" }, //( ‎𞺮‎ → ‎س‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK SEEN → ARABIC LETTER SEEN	# 
			{ L"\xFEB3",L"\x0633" }, //( ‎ﺳ‎ → ‎س‎ ) ARABIC LETTER SEEN INITIAL FORM → ARABIC LETTER SEEN	# 
			{ L"\xFEB4",L"\x0633" }, //( ‎ﺴ‎ → ‎س‎ ) ARABIC LETTER SEEN MEDIAL FORM → ARABIC LETTER SEEN	# 
			{ L"\xFEB2",L"\x0633" }, //( ‎ﺲ‎ → ‎س‎ ) ARABIC LETTER SEEN FINAL FORM → ARABIC LETTER SEEN	# 
			{ L"\xFEB1",L"\x0633" }, //( ‎ﺱ‎ → ‎س‎ ) ARABIC LETTER SEEN ISOLATED FORM → ARABIC LETTER SEEN	# 

			{ L"\x0634",L"\x0633\x06DB" }, //( ‎ش‎ → ‎سۛ‎ ) ARABIC LETTER SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\x0001\xEE14",L"\x0633\x06DB" }, //( ‎𞸔‎ → ‎سۛ‎ ) ARABIC MATHEMATICAL SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\x0001\xEE34",L"\x0633\x06DB" }, //( ‎𞸴‎ → ‎سۛ‎ ) ARABIC MATHEMATICAL INITIAL SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\x0001\xEE54",L"\x0633\x06DB" }, //( ‎𞹔‎ → ‎سۛ‎ ) ARABIC MATHEMATICAL TAILED SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\x0001\xEE74",L"\x0633\x06DB" }, //( ‎𞹴‎ → ‎سۛ‎ ) ARABIC MATHEMATICAL STRETCHED SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\x0001\xEE94",L"\x0633\x06DB" }, //( ‎𞺔‎ → ‎سۛ‎ ) ARABIC MATHEMATICAL LOOPED SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\x0001\xEEB4",L"\x0633\x06DB" }, //( ‎𞺴‎ → ‎سۛ‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK SHEEN → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\xFEB7",L"\x0633\x06DB" }, //( ‎ﺷ‎ → ‎سۛ‎ ) ARABIC LETTER SHEEN INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\xFEB8",L"\x0633\x06DB" }, //( ‎ﺸ‎ → ‎سۛ‎ ) ARABIC LETTER SHEEN MEDIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\xFEB6",L"\x0633\x06DB" }, //( ‎ﺶ‎ → ‎سۛ‎ ) ARABIC LETTER SHEEN FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→
			{ L"\xFEB5",L"\x0633\x06DB" }, //( ‎ﺵ‎ → ‎سۛ‎ ) ARABIC LETTER SHEEN ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS	# →‎ش‎→

			{ L"\x077E",L"\x0633\x0302" }, //( ‎ݾ‎ → ‎س̂‎ ) ARABIC LETTER SEEN WITH INVERTED V → ARABIC LETTER SEEN, COMBINING CIRCUMFLEX ACCENT	# →‎سٛ‎→

			{ L"\xFD31",L"\x0633\x006F" }, //( ‎ﴱ‎ → ‎سo‎ ) ARABIC LIGATURE SEEN WITH HEH INITIAL FORM → ARABIC LETTER SEEN, LATIN SMALL LETTER O	# →‎سه‎→
			{ L"\xFCE8",L"\x0633\x006F" }, //( ‎ﳨ‎ → ‎سo‎ ) ARABIC LIGATURE SEEN WITH HEH MEDIAL FORM → ARABIC LETTER SEEN, LATIN SMALL LETTER O	# →‎سه‎→

			{ L"\xFD32",L"\x0633\x06DB\x006F" }, //( ‎ﴲ‎ → ‎سۛo‎ ) ARABIC LIGATURE SHEEN WITH HEH INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, LATIN SMALL LETTER O	# →‎شه‎→
			{ L"\xFCEA",L"\x0633\x06DB\x006F" }, //( ‎ﳪ‎ → ‎سۛo‎ ) ARABIC LIGATURE SHEEN WITH HEH MEDIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, LATIN SMALL LETTER O	# →‎شه‎→

			{ L"\xFCAD",L"\x0633\x062C" }, //( ‎ﲭ‎ → ‎سج‎ ) ARABIC LIGATURE SEEN WITH JEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER JEEM	# 
			{ L"\xFD34",L"\x0633\x062C" }, //( ‎ﴴ‎ → ‎سج‎ ) ARABIC LIGATURE SEEN WITH JEEM MEDIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER JEEM	# 
			{ L"\xFC1C",L"\x0633\x062C" }, //( ‎ﰜ‎ → ‎سج‎ ) ARABIC LIGATURE SEEN WITH JEEM ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER JEEM	# 

			{ L"\xFD2D",L"\x0633\x06DB\x062C" }, //( ‎ﴭ‎ → ‎سۛج‎ ) ARABIC LIGATURE SHEEN WITH JEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER JEEM	# →‎شج‎→
			{ L"\xFD37",L"\x0633\x06DB\x062C" }, //( ‎ﴷ‎ → ‎سۛج‎ ) ARABIC LIGATURE SHEEN WITH JEEM MEDIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER JEEM	# →‎شج‎→
			{ L"\xFD25",L"\x0633\x06DB\x062C" }, //( ‎ﴥ‎ → ‎سۛج‎ ) ARABIC LIGATURE SHEEN WITH JEEM FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER JEEM	# →‎شج‎→
			{ L"\xFD09",L"\x0633\x06DB\x062C" }, //( ‎ﴉ‎ → ‎سۛج‎ ) ARABIC LIGATURE SHEEN WITH JEEM ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER JEEM	# →‎شج‎→

			{ L"\xFD5D",L"\x0633\x062C\x062D" }, //( ‎ﵝ‎ → ‎سجح‎ ) ARABIC LIGATURE SEEN WITH JEEM WITH HAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER JEEM, ARABIC LETTER HAH	# 

			{ L"\xFD5E",L"\x0633\x062C\x0649" }, //( ‎ﵞ‎ → ‎سجى‎ ) ARABIC LIGATURE SEEN WITH JEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# 

			{ L"\xFD69",L"\x0633\x06DB\x062C\x0649" }, //( ‎ﵩ‎ → ‎سۛجى‎ ) ARABIC LIGATURE SHEEN WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎شجي‎→

			{ L"\xFCAE",L"\x0633\x062D" }, //( ‎ﲮ‎ → ‎سح‎ ) ARABIC LIGATURE SEEN WITH HAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER HAH	# 
			{ L"\xFD35",L"\x0633\x062D" }, //( ‎ﴵ‎ → ‎سح‎ ) ARABIC LIGATURE SEEN WITH HAH MEDIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER HAH	# 
			{ L"\xFC1D",L"\x0633\x062D" }, //( ‎ﰝ‎ → ‎سح‎ ) ARABIC LIGATURE SEEN WITH HAH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER HAH	# 

			{ L"\xFD2E",L"\x0633\x06DB\x062D" }, //( ‎ﴮ‎ → ‎سۛح‎ ) ARABIC LIGATURE SHEEN WITH HAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH	# →‎شح‎→
			{ L"\xFD38",L"\x0633\x06DB\x062D" }, //( ‎ﴸ‎ → ‎سۛح‎ ) ARABIC LIGATURE SHEEN WITH HAH MEDIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH	# →‎شح‎→
			{ L"\xFD26",L"\x0633\x06DB\x062D" }, //( ‎ﴦ‎ → ‎سۛح‎ ) ARABIC LIGATURE SHEEN WITH HAH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH	# →‎شح‎→
			{ L"\xFD0A",L"\x0633\x06DB\x062D" }, //( ‎ﴊ‎ → ‎سۛح‎ ) ARABIC LIGATURE SHEEN WITH HAH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH	# →‎شح‎→

			{ L"\xFD5C",L"\x0633\x062D\x062C" }, //( ‎ﵜ‎ → ‎سحج‎ ) ARABIC LIGATURE SEEN WITH HAH WITH JEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER HAH, ARABIC LETTER JEEM	# 

			{ L"\xFD68",L"\x0633\x06DB\x062D\x0645" }, //( ‎ﵨ‎ → ‎سۛحم‎ ) ARABIC LIGATURE SHEEN WITH HAH WITH MEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH, ARABIC LETTER MEEM	# →‎شحم‎→
			{ L"\xFD67",L"\x0633\x06DB\x062D\x0645" }, //( ‎ﵧ‎ → ‎سۛحم‎ ) ARABIC LIGATURE SHEEN WITH HAH WITH MEEM FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH, ARABIC LETTER MEEM	# →‎شحم‎→

			{ L"\xFDAA",L"\x0633\x06DB\x062D\x0649" }, //( ‎ﶪ‎ → ‎سۛحى‎ ) ARABIC LIGATURE SHEEN WITH HAH WITH YEH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎شحي‎→

			{ L"\xFCAF",L"\x0633\x062E" }, //( ‎ﲯ‎ → ‎سخ‎ ) ARABIC LIGATURE SEEN WITH KHAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER KHAH	# 
			{ L"\xFD36",L"\x0633\x062E" }, //( ‎ﴶ‎ → ‎سخ‎ ) ARABIC LIGATURE SEEN WITH KHAH MEDIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER KHAH	# 
			{ L"\xFC1E",L"\x0633\x062E" }, //( ‎ﰞ‎ → ‎سخ‎ ) ARABIC LIGATURE SEEN WITH KHAH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER KHAH	# 

			{ L"\xFD2F",L"\x0633\x06DB\x062E" }, //( ‎ﴯ‎ → ‎سۛخ‎ ) ARABIC LIGATURE SHEEN WITH KHAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER KHAH	# →‎شخ‎→
			{ L"\xFD39",L"\x0633\x06DB\x062E" }, //( ‎ﴹ‎ → ‎سۛخ‎ ) ARABIC LIGATURE SHEEN WITH KHAH MEDIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER KHAH	# →‎شخ‎→
			{ L"\xFD27",L"\x0633\x06DB\x062E" }, //( ‎ﴧ‎ → ‎سۛخ‎ ) ARABIC LIGATURE SHEEN WITH KHAH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER KHAH	# →‎شخ‎→
			{ L"\xFD0B",L"\x0633\x06DB\x062E" }, //( ‎ﴋ‎ → ‎سۛخ‎ ) ARABIC LIGATURE SHEEN WITH KHAH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER KHAH	# →‎شخ‎→

			{ L"\xFDA8",L"\x0633\x062E\x0649" }, //( ‎ﶨ‎ → ‎سخى‎ ) ARABIC LIGATURE SEEN WITH KHAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDC6",L"\x0633\x062E\x0649" }, //( ‎ﷆ‎ → ‎سخى‎ ) ARABIC LIGATURE SEEN WITH KHAH WITH YEH FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# →‎سخي‎→

			{ L"\xFD2A",L"\x0633\x0631" }, //( ‎ﴪ‎ → ‎سر‎ ) ARABIC LIGATURE SEEN WITH REH FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER REH	# 
			{ L"\xFD0E",L"\x0633\x0631" }, //( ‎ﴎ‎ → ‎سر‎ ) ARABIC LIGATURE SEEN WITH REH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER REH	# 

			{ L"\xFD29",L"\x0633\x06DB\x0631" }, //( ‎ﴩ‎ → ‎سۛر‎ ) ARABIC LIGATURE SHEEN WITH REH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER REH	# →‎شر‎→
			{ L"\xFD0D",L"\x0633\x06DB\x0631" }, //( ‎ﴍ‎ → ‎سۛر‎ ) ARABIC LIGATURE SHEEN WITH REH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER REH	# →‎شر‎→

			{ L"\xFCB0",L"\x0633\x0645" }, //( ‎ﲰ‎ → ‎سم‎ ) ARABIC LIGATURE SEEN WITH MEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM	# 
			{ L"\xFCE7",L"\x0633\x0645" }, //( ‎ﳧ‎ → ‎سم‎ ) ARABIC LIGATURE SEEN WITH MEEM MEDIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM	# 
			{ L"\xFC1F",L"\x0633\x0645" }, //( ‎ﰟ‎ → ‎سم‎ ) ARABIC LIGATURE SEEN WITH MEEM ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM	# 

			{ L"\xFD30",L"\x0633\x06DB\x0645" }, //( ‎ﴰ‎ → ‎سۛم‎ ) ARABIC LIGATURE SHEEN WITH MEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎شم‎→
			{ L"\xFCE9",L"\x0633\x06DB\x0645" }, //( ‎ﳩ‎ → ‎سۛم‎ ) ARABIC LIGATURE SHEEN WITH MEEM MEDIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎شم‎→
			{ L"\xFD28",L"\x0633\x06DB\x0645" }, //( ‎ﴨ‎ → ‎سۛم‎ ) ARABIC LIGATURE SHEEN WITH MEEM FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎شم‎→
			{ L"\xFD0C",L"\x0633\x06DB\x0645" }, //( ‎ﴌ‎ → ‎سۛم‎ ) ARABIC LIGATURE SHEEN WITH MEEM ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎شم‎→

			{ L"\xFD61",L"\x0633\x0645\x062C" }, //( ‎ﵡ‎ → ‎سمج‎ ) ARABIC LIGATURE SEEN WITH MEEM WITH JEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM, ARABIC LETTER JEEM	# 

			{ L"\xFD60",L"\x0633\x0645\x062D" }, //( ‎ﵠ‎ → ‎سمح‎ ) ARABIC LIGATURE SEEN WITH MEEM WITH HAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 
			{ L"\xFD5F",L"\x0633\x0645\x062D" }, //( ‎ﵟ‎ → ‎سمح‎ ) ARABIC LIGATURE SEEN WITH MEEM WITH HAH FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFD6B",L"\x0633\x06DB\x0645\x062E" }, //( ‎ﵫ‎ → ‎سۛمخ‎ ) ARABIC LIGATURE SHEEN WITH MEEM WITH KHAH INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM, ARABIC LETTER KHAH	# →‎شمخ‎→
			{ L"\xFD6A",L"\x0633\x06DB\x0645\x062E" }, //( ‎ﵪ‎ → ‎سۛمخ‎ ) ARABIC LIGATURE SHEEN WITH MEEM WITH KHAH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM, ARABIC LETTER KHAH	# →‎شمخ‎→

			{ L"\xFD63",L"\x0633\x0645\x0645" }, //( ‎ﵣ‎ → ‎سمم‎ ) ARABIC LIGATURE SEEN WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 
			{ L"\xFD62",L"\x0633\x0645\x0645" }, //( ‎ﵢ‎ → ‎سمم‎ ) ARABIC LIGATURE SEEN WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD6D",L"\x0633\x06DB\x0645\x0645" }, //( ‎ﵭ‎ → ‎سۛمم‎ ) ARABIC LIGATURE SHEEN WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# →‎شمم‎→
			{ L"\xFD6C",L"\x0633\x06DB\x0645\x0645" }, //( ‎ﵬ‎ → ‎سۛمم‎ ) ARABIC LIGATURE SHEEN WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# →‎شمم‎→

			{ L"\xFD17",L"\x0633\x0649" }, //( ‎ﴗ‎ → ‎سى‎ ) ARABIC LIGATURE SEEN WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFCFB",L"\x0633\x0649" }, //( ‎ﳻ‎ → ‎سى‎ ) ARABIC LIGATURE SEEN WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD18",L"\x0633\x0649" }, //( ‎ﴘ‎ → ‎سى‎ ) ARABIC LIGATURE SEEN WITH YEH FINAL FORM → ARABIC LETTER SEEN, ARABIC LETTER ALEF MAKSURA	# →‎سي‎→
			{ L"\xFCFC",L"\x0633\x0649" }, //( ‎ﳼ‎ → ‎سى‎ ) ARABIC LIGATURE SEEN WITH YEH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC LETTER ALEF MAKSURA	# →‎سي‎→

			{ L"\xFD19",L"\x0633\x06DB\x0649" }, //( ‎ﴙ‎ → ‎سۛى‎ ) ARABIC LIGATURE SHEEN WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎شى‎→
			{ L"\xFCFD",L"\x0633\x06DB\x0649" }, //( ‎ﳽ‎ → ‎سۛى‎ ) ARABIC LIGATURE SHEEN WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎شى‎→
			{ L"\xFD1A",L"\x0633\x06DB\x0649" }, //( ‎ﴚ‎ → ‎سۛى‎ ) ARABIC LIGATURE SHEEN WITH YEH FINAL FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎شي‎→
			{ L"\xFCFE",L"\x0633\x06DB\x0649" }, //( ‎ﳾ‎ → ‎سۛى‎ ) ARABIC LIGATURE SHEEN WITH YEH ISOLATED FORM → ARABIC LETTER SEEN, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎شي‎→

			{ L"\x0001\x02F2",L"\x0635" }, //( 𐋲 → ‎ص‎ ) COPTIC EPACT NUMBER NINETY → ARABIC LETTER SAD	# 
			{ L"\x0001\xEE11",L"\x0635" }, //( ‎𞸑‎ → ‎ص‎ ) ARABIC MATHEMATICAL SAD → ARABIC LETTER SAD	# 
			{ L"\x0001\xEE31",L"\x0635" }, //( ‎𞸱‎ → ‎ص‎ ) ARABIC MATHEMATICAL INITIAL SAD → ARABIC LETTER SAD	# 
			{ L"\x0001\xEE51",L"\x0635" }, //( ‎𞹑‎ → ‎ص‎ ) ARABIC MATHEMATICAL TAILED SAD → ARABIC LETTER SAD	# 
			{ L"\x0001\xEE71",L"\x0635" }, //( ‎𞹱‎ → ‎ص‎ ) ARABIC MATHEMATICAL STRETCHED SAD → ARABIC LETTER SAD	# 
			{ L"\x0001\xEE91",L"\x0635" }, //( ‎𞺑‎ → ‎ص‎ ) ARABIC MATHEMATICAL LOOPED SAD → ARABIC LETTER SAD	# 
			{ L"\x0001\xEEB1",L"\x0635" }, //( ‎𞺱‎ → ‎ص‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK SAD → ARABIC LETTER SAD	# 
			{ L"\xFEBB",L"\x0635" }, //( ‎ﺻ‎ → ‎ص‎ ) ARABIC LETTER SAD INITIAL FORM → ARABIC LETTER SAD	# 
			{ L"\xFEBC",L"\x0635" }, //( ‎ﺼ‎ → ‎ص‎ ) ARABIC LETTER SAD MEDIAL FORM → ARABIC LETTER SAD	# 
			{ L"\xFEBA",L"\x0635" }, //( ‎ﺺ‎ → ‎ص‎ ) ARABIC LETTER SAD FINAL FORM → ARABIC LETTER SAD	# 
			{ L"\xFEB9",L"\x0635" }, //( ‎ﺹ‎ → ‎ص‎ ) ARABIC LETTER SAD ISOLATED FORM → ARABIC LETTER SAD	# 

			{ L"\x069E",L"\x0635\x06DB" }, //( ‎ڞ‎ → ‎صۛ‎ ) ARABIC LETTER SAD WITH THREE DOTS ABOVE → ARABIC LETTER SAD, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\x08AF",L"\x0635\x0324\x0323" }, //( ‎ࢯ‎ → ‎ص̤̣‎ ) ARABIC LETTER SAD WITH THREE DOTS BELOW → ARABIC LETTER SAD, COMBINING DIAERESIS BELOW, COMBINING DOT BELOW	# →‎ص࣮࣭‎→

			{ L"\xFCB1",L"\x0635\x062D" }, //( ‎ﲱ‎ → ‎صح‎ ) ARABIC LIGATURE SAD WITH HAH INITIAL FORM → ARABIC LETTER SAD, ARABIC LETTER HAH	# 
			{ L"\xFC20",L"\x0635\x062D" }, //( ‎ﰠ‎ → ‎صح‎ ) ARABIC LIGATURE SAD WITH HAH ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER HAH	# 

			{ L"\xFD65",L"\x0635\x062D\x062D" }, //( ‎ﵥ‎ → ‎صحح‎ ) ARABIC LIGATURE SAD WITH HAH WITH HAH INITIAL FORM → ARABIC LETTER SAD, ARABIC LETTER HAH, ARABIC LETTER HAH	# 
			{ L"\xFD64",L"\x0635\x062D\x062D" }, //( ‎ﵤ‎ → ‎صحح‎ ) ARABIC LIGATURE SAD WITH HAH WITH HAH FINAL FORM → ARABIC LETTER SAD, ARABIC LETTER HAH, ARABIC LETTER HAH	# 

			{ L"\xFDA9",L"\x0635\x062D\x0649" }, //( ‎ﶩ‎ → ‎صحى‎ ) ARABIC LIGATURE SAD WITH HAH WITH YEH FINAL FORM → ARABIC LETTER SAD, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎صحي‎→

			{ L"\xFCB2",L"\x0635\x062E" }, //( ‎ﲲ‎ → ‎صخ‎ ) ARABIC LIGATURE SAD WITH KHAH INITIAL FORM → ARABIC LETTER SAD, ARABIC LETTER KHAH	# 

			{ L"\xFD2B",L"\x0635\x0631" }, //( ‎ﴫ‎ → ‎صر‎ ) ARABIC LIGATURE SAD WITH REH FINAL FORM → ARABIC LETTER SAD, ARABIC LETTER REH	# 
			{ L"\xFD0F",L"\x0635\x0631" }, //( ‎ﴏ‎ → ‎صر‎ ) ARABIC LIGATURE SAD WITH REH ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER REH	# 

			{ L"\xFDF5",L"\x0635\x0644\x0639\x0645" }, //( ‎ﷵ‎ → ‎صلعم‎ ) ARABIC LIGATURE SALAM ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER LAM, ARABIC LETTER AIN, ARABIC LETTER MEEM	# 

			{ L"\xFDF9",L"\x0635\x0644\x0649" }, //( ‎ﷹ‎ → ‎صلى‎ ) ARABIC LIGATURE SALLA ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDF0",L"\x0635\x0644\x0649" }, //( ‎ﷰ‎ → ‎صلى‎ ) ARABIC LIGATURE SALLA USED AS KORANIC STOP SIGN ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# →‎صلے‎→

			{ L"\xFDFA",L"\x0635\x0644\x0649\x0020\x006C\x0644\x0644\x006F\x0020\x0639\x0644\x0649\x006F\x0020\x0648\x0633\x0644\x0645" }, //( ‎ﷺ‎ → ‎صلى lللo علىo وسلم‎ ) ARABIC LIGATURE SALLALLAHOU ALAYHE WASALLAM → ARABIC LETTER SAD, ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA, SPACE, LATIN SMALL LETTER L, ARABIC LETTER LAM, ARABIC LETTER LAM, LATIN SMALL LETTER O, SPACE, ARABIC LETTER AIN, ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA, LATIN SMALL LETTER O, SPACE, ARABIC LETTER WAW, ARABIC LETTER SEEN, ARABIC LETTER LAM, ARABIC LETTER MEEM	# →‎صلى الله عليه وسلم‎→

			{ L"\xFCB3",L"\x0635\x0645" }, //( ‎ﲳ‎ → ‎صم‎ ) ARABIC LIGATURE SAD WITH MEEM INITIAL FORM → ARABIC LETTER SAD, ARABIC LETTER MEEM	# 
			{ L"\xFC21",L"\x0635\x0645" }, //( ‎ﰡ‎ → ‎صم‎ ) ARABIC LIGATURE SAD WITH MEEM ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER MEEM	# 

			{ L"\xFDC5",L"\x0635\x0645\x0645" }, //( ‎ﷅ‎ → ‎صمم‎ ) ARABIC LIGATURE SAD WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER SAD, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 
			{ L"\xFD66",L"\x0635\x0645\x0645" }, //( ‎ﵦ‎ → ‎صمم‎ ) ARABIC LIGATURE SAD WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER SAD, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD21",L"\x0635\x0649" }, //( ‎ﴡ‎ → ‎صى‎ ) ARABIC LIGATURE SAD WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER SAD, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD05",L"\x0635\x0649" }, //( ‎ﴅ‎ → ‎صى‎ ) ARABIC LIGATURE SAD WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD22",L"\x0635\x0649" }, //( ‎ﴢ‎ → ‎صى‎ ) ARABIC LIGATURE SAD WITH YEH FINAL FORM → ARABIC LETTER SAD, ARABIC LETTER ALEF MAKSURA	# →‎صي‎→
			{ L"\xFD06",L"\x0635\x0649" }, //( ‎ﴆ‎ → ‎صى‎ ) ARABIC LIGATURE SAD WITH YEH ISOLATED FORM → ARABIC LETTER SAD, ARABIC LETTER ALEF MAKSURA	# →‎صي‎→

			{ L"\x0001\xEE19",L"\x0636" }, //( ‎𞸙‎ → ‎ض‎ ) ARABIC MATHEMATICAL DAD → ARABIC LETTER DAD	# 
			{ L"\x0001\xEE39",L"\x0636" }, //( ‎𞸹‎ → ‎ض‎ ) ARABIC MATHEMATICAL INITIAL DAD → ARABIC LETTER DAD	# 
			{ L"\x0001\xEE59",L"\x0636" }, //( ‎𞹙‎ → ‎ض‎ ) ARABIC MATHEMATICAL TAILED DAD → ARABIC LETTER DAD	# 
			{ L"\x0001\xEE79",L"\x0636" }, //( ‎𞹹‎ → ‎ض‎ ) ARABIC MATHEMATICAL STRETCHED DAD → ARABIC LETTER DAD	# 
			{ L"\x0001\xEE99",L"\x0636" }, //( ‎𞺙‎ → ‎ض‎ ) ARABIC MATHEMATICAL LOOPED DAD → ARABIC LETTER DAD	# 
			{ L"\x0001\xEEB9",L"\x0636" }, //( ‎𞺹‎ → ‎ض‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK DAD → ARABIC LETTER DAD	# 
			{ L"\xFEBF",L"\x0636" }, //( ‎ﺿ‎ → ‎ض‎ ) ARABIC LETTER DAD INITIAL FORM → ARABIC LETTER DAD	# 
			{ L"\xFEC0",L"\x0636" }, //( ‎ﻀ‎ → ‎ض‎ ) ARABIC LETTER DAD MEDIAL FORM → ARABIC LETTER DAD	# 
			{ L"\xFEBE",L"\x0636" }, //( ‎ﺾ‎ → ‎ض‎ ) ARABIC LETTER DAD FINAL FORM → ARABIC LETTER DAD	# 
			{ L"\xFEBD",L"\x0636" }, //( ‎ﺽ‎ → ‎ض‎ ) ARABIC LETTER DAD ISOLATED FORM → ARABIC LETTER DAD	# 

			{ L"\xFCB4",L"\x0636\x062C" }, //( ‎ﲴ‎ → ‎ضج‎ ) ARABIC LIGATURE DAD WITH JEEM INITIAL FORM → ARABIC LETTER DAD, ARABIC LETTER JEEM	# 
			{ L"\xFC22",L"\x0636\x062C" }, //( ‎ﰢ‎ → ‎ضج‎ ) ARABIC LIGATURE DAD WITH JEEM ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER JEEM	# 

			{ L"\xFCB5",L"\x0636\x062D" }, //( ‎ﲵ‎ → ‎ضح‎ ) ARABIC LIGATURE DAD WITH HAH INITIAL FORM → ARABIC LETTER DAD, ARABIC LETTER HAH	# 
			{ L"\xFC23",L"\x0636\x062D" }, //( ‎ﰣ‎ → ‎ضح‎ ) ARABIC LIGATURE DAD WITH HAH ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER HAH	# 

			{ L"\xFD6E",L"\x0636\x062D\x0649" }, //( ‎ﵮ‎ → ‎ضحى‎ ) ARABIC LIGATURE DAD WITH HAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER DAD, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDAB",L"\x0636\x062D\x0649" }, //( ‎ﶫ‎ → ‎ضحى‎ ) ARABIC LIGATURE DAD WITH HAH WITH YEH FINAL FORM → ARABIC LETTER DAD, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎ضحي‎→

			{ L"\xFCB6",L"\x0636\x062E" }, //( ‎ﲶ‎ → ‎ضخ‎ ) ARABIC LIGATURE DAD WITH KHAH INITIAL FORM → ARABIC LETTER DAD, ARABIC LETTER KHAH	# 
			{ L"\xFC24",L"\x0636\x062E" }, //( ‎ﰤ‎ → ‎ضخ‎ ) ARABIC LIGATURE DAD WITH KHAH ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER KHAH	# 

			{ L"\xFD70",L"\x0636\x062E\x0645" }, //( ‎ﵰ‎ → ‎ضخم‎ ) ARABIC LIGATURE DAD WITH KHAH WITH MEEM INITIAL FORM → ARABIC LETTER DAD, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 
			{ L"\xFD6F",L"\x0636\x062E\x0645" }, //( ‎ﵯ‎ → ‎ضخم‎ ) ARABIC LIGATURE DAD WITH KHAH WITH MEEM FINAL FORM → ARABIC LETTER DAD, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 

			{ L"\xFD2C",L"\x0636\x0631" }, //( ‎ﴬ‎ → ‎ضر‎ ) ARABIC LIGATURE DAD WITH REH FINAL FORM → ARABIC LETTER DAD, ARABIC LETTER REH	# 
			{ L"\xFD10",L"\x0636\x0631" }, //( ‎ﴐ‎ → ‎ضر‎ ) ARABIC LIGATURE DAD WITH REH ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER REH	# 

			{ L"\xFCB7",L"\x0636\x0645" }, //( ‎ﲷ‎ → ‎ضم‎ ) ARABIC LIGATURE DAD WITH MEEM INITIAL FORM → ARABIC LETTER DAD, ARABIC LETTER MEEM	# 
			{ L"\xFC25",L"\x0636\x0645" }, //( ‎ﰥ‎ → ‎ضم‎ ) ARABIC LIGATURE DAD WITH MEEM ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER MEEM	# 

			{ L"\xFD23",L"\x0636\x0649" }, //( ‎ﴣ‎ → ‎ضى‎ ) ARABIC LIGATURE DAD WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER DAD, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD07",L"\x0636\x0649" }, //( ‎ﴇ‎ → ‎ضى‎ ) ARABIC LIGATURE DAD WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD24",L"\x0636\x0649" }, //( ‎ﴤ‎ → ‎ضى‎ ) ARABIC LIGATURE DAD WITH YEH FINAL FORM → ARABIC LETTER DAD, ARABIC LETTER ALEF MAKSURA	# →‎ضي‎→
			{ L"\xFD08",L"\x0636\x0649" }, //( ‎ﴈ‎ → ‎ضى‎ ) ARABIC LIGATURE DAD WITH YEH ISOLATED FORM → ARABIC LETTER DAD, ARABIC LETTER ALEF MAKSURA	# →‎ضي‎→

			{ L"\x0001\x02E8",L"\x0637" }, //( 𐋨 → ‎ط‎ ) COPTIC EPACT DIGIT EIGHT → ARABIC LETTER TAH	# 
			{ L"\x0001\xEE08",L"\x0637" }, //( ‎𞸈‎ → ‎ط‎ ) ARABIC MATHEMATICAL TAH → ARABIC LETTER TAH	# 
			{ L"\x0001\xEE68",L"\x0637" }, //( ‎𞹨‎ → ‎ط‎ ) ARABIC MATHEMATICAL STRETCHED TAH → ARABIC LETTER TAH	# 
			{ L"\x0001\xEE88",L"\x0637" }, //( ‎𞺈‎ → ‎ط‎ ) ARABIC MATHEMATICAL LOOPED TAH → ARABIC LETTER TAH	# 
			{ L"\x0001\xEEA8",L"\x0637" }, //( ‎𞺨‎ → ‎ط‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK TAH → ARABIC LETTER TAH	# 
			{ L"\xFEC3",L"\x0637" }, //( ‎ﻃ‎ → ‎ط‎ ) ARABIC LETTER TAH INITIAL FORM → ARABIC LETTER TAH	# 
			{ L"\xFEC4",L"\x0637" }, //( ‎ﻄ‎ → ‎ط‎ ) ARABIC LETTER TAH MEDIAL FORM → ARABIC LETTER TAH	# 
			{ L"\xFEC2",L"\x0637" }, //( ‎ﻂ‎ → ‎ط‎ ) ARABIC LETTER TAH FINAL FORM → ARABIC LETTER TAH	# 
			{ L"\xFEC1",L"\x0637" }, //( ‎ﻁ‎ → ‎ط‎ ) ARABIC LETTER TAH ISOLATED FORM → ARABIC LETTER TAH	# 

			{ L"\x069F",L"\x0637\x06DB" }, //( ‎ڟ‎ → ‎طۛ‎ ) ARABIC LETTER TAH WITH THREE DOTS ABOVE → ARABIC LETTER TAH, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\xFCB8",L"\x0637\x062D" }, //( ‎ﲸ‎ → ‎طح‎ ) ARABIC LIGATURE TAH WITH HAH INITIAL FORM → ARABIC LETTER TAH, ARABIC LETTER HAH	# 
			{ L"\xFC26",L"\x0637\x062D" }, //( ‎ﰦ‎ → ‎طح‎ ) ARABIC LIGATURE TAH WITH HAH ISOLATED FORM → ARABIC LETTER TAH, ARABIC LETTER HAH	# 

			{ L"\xFD33",L"\x0637\x0645" }, //( ‎ﴳ‎ → ‎طم‎ ) ARABIC LIGATURE TAH WITH MEEM INITIAL FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM	# 
			{ L"\xFD3A",L"\x0637\x0645" }, //( ‎ﴺ‎ → ‎طم‎ ) ARABIC LIGATURE TAH WITH MEEM MEDIAL FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM	# 
			{ L"\xFC27",L"\x0637\x0645" }, //( ‎ﰧ‎ → ‎طم‎ ) ARABIC LIGATURE TAH WITH MEEM ISOLATED FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM	# 

			{ L"\xFD72",L"\x0637\x0645\x062D" }, //( ‎ﵲ‎ → ‎طمح‎ ) ARABIC LIGATURE TAH WITH MEEM WITH HAH INITIAL FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 
			{ L"\xFD71",L"\x0637\x0645\x062D" }, //( ‎ﵱ‎ → ‎طمح‎ ) ARABIC LIGATURE TAH WITH MEEM WITH HAH FINAL FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFD73",L"\x0637\x0645\x0645" }, //( ‎ﵳ‎ → ‎طمم‎ ) ARABIC LIGATURE TAH WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD74",L"\x0637\x0645\x0649" }, //( ‎ﵴ‎ → ‎طمى‎ ) ARABIC LIGATURE TAH WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER TAH, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎طمي‎→

			{ L"\xFD11",L"\x0637\x0649" }, //( ‎ﴑ‎ → ‎طى‎ ) ARABIC LIGATURE TAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER TAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFCF5",L"\x0637\x0649" }, //( ‎ﳵ‎ → ‎طى‎ ) ARABIC LIGATURE TAH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER TAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD12",L"\x0637\x0649" }, //( ‎ﴒ‎ → ‎طى‎ ) ARABIC LIGATURE TAH WITH YEH FINAL FORM → ARABIC LETTER TAH, ARABIC LETTER ALEF MAKSURA	# →‎طي‎→
			{ L"\xFCF6",L"\x0637\x0649" }, //( ‎ﳶ‎ → ‎طى‎ ) ARABIC LIGATURE TAH WITH YEH ISOLATED FORM → ARABIC LETTER TAH, ARABIC LETTER ALEF MAKSURA	# →‎طي‎→

			{ L"\x0001\xEE1A",L"\x0638" }, //( ‎𞸚‎ → ‎ظ‎ ) ARABIC MATHEMATICAL ZAH → ARABIC LETTER ZAH	# 
			{ L"\x0001\xEE7A",L"\x0638" }, //( ‎𞹺‎ → ‎ظ‎ ) ARABIC MATHEMATICAL STRETCHED ZAH → ARABIC LETTER ZAH	# 
			{ L"\x0001\xEE9A",L"\x0638" }, //( ‎𞺚‎ → ‎ظ‎ ) ARABIC MATHEMATICAL LOOPED ZAH → ARABIC LETTER ZAH	# 
			{ L"\x0001\xEEBA",L"\x0638" }, //( ‎𞺺‎ → ‎ظ‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK ZAH → ARABIC LETTER ZAH	# 
			{ L"\xFEC7",L"\x0638" }, //( ‎ﻇ‎ → ‎ظ‎ ) ARABIC LETTER ZAH INITIAL FORM → ARABIC LETTER ZAH	# 
			{ L"\xFEC8",L"\x0638" }, //( ‎ﻈ‎ → ‎ظ‎ ) ARABIC LETTER ZAH MEDIAL FORM → ARABIC LETTER ZAH	# 
			{ L"\xFEC6",L"\x0638" }, //( ‎ﻆ‎ → ‎ظ‎ ) ARABIC LETTER ZAH FINAL FORM → ARABIC LETTER ZAH	# 
			{ L"\xFEC5",L"\x0638" }, //( ‎ﻅ‎ → ‎ظ‎ ) ARABIC LETTER ZAH ISOLATED FORM → ARABIC LETTER ZAH	# 

			{ L"\xFCB9",L"\x0638\x0645" }, //( ‎ﲹ‎ → ‎ظم‎ ) ARABIC LIGATURE ZAH WITH MEEM INITIAL FORM → ARABIC LETTER ZAH, ARABIC LETTER MEEM	# 
			{ L"\xFD3B",L"\x0638\x0645" }, //( ‎ﴻ‎ → ‎ظم‎ ) ARABIC LIGATURE ZAH WITH MEEM MEDIAL FORM → ARABIC LETTER ZAH, ARABIC LETTER MEEM	# 
			{ L"\xFC28",L"\x0638\x0645" }, //( ‎ﰨ‎ → ‎ظم‎ ) ARABIC LIGATURE ZAH WITH MEEM ISOLATED FORM → ARABIC LETTER ZAH, ARABIC LETTER MEEM	# 

			{ L"\x060F",L"\x0639" }, //( ؏ → ‎ع‎ ) ARABIC SIGN MISRA → ARABIC LETTER AIN	# 
			{ L"\x0001\xEE0F",L"\x0639" }, //( ‎𞸏‎ → ‎ع‎ ) ARABIC MATHEMATICAL AIN → ARABIC LETTER AIN	# 
			{ L"\x0001\xEE2F",L"\x0639" }, //( ‎𞸯‎ → ‎ع‎ ) ARABIC MATHEMATICAL INITIAL AIN → ARABIC LETTER AIN	# 
			{ L"\x0001\xEE4F",L"\x0639" }, //( ‎𞹏‎ → ‎ع‎ ) ARABIC MATHEMATICAL TAILED AIN → ARABIC LETTER AIN	# 
			{ L"\x0001\xEE6F",L"\x0639" }, //( ‎𞹯‎ → ‎ع‎ ) ARABIC MATHEMATICAL STRETCHED AIN → ARABIC LETTER AIN	# 
			{ L"\x0001\xEE8F",L"\x0639" }, //( ‎𞺏‎ → ‎ع‎ ) ARABIC MATHEMATICAL LOOPED AIN → ARABIC LETTER AIN	# 
			{ L"\x0001\xEEAF",L"\x0639" }, //( ‎𞺯‎ → ‎ع‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK AIN → ARABIC LETTER AIN	# 
			{ L"\xFECB",L"\x0639" }, //( ‎ﻋ‎ → ‎ع‎ ) ARABIC LETTER AIN INITIAL FORM → ARABIC LETTER AIN	# 
			{ L"\xFECC",L"\x0639" }, //( ‎ﻌ‎ → ‎ع‎ ) ARABIC LETTER AIN MEDIAL FORM → ARABIC LETTER AIN	# 
			{ L"\xFECA",L"\x0639" }, //( ‎ﻊ‎ → ‎ع‎ ) ARABIC LETTER AIN FINAL FORM → ARABIC LETTER AIN	# 
			{ L"\xFEC9",L"\x0639" }, //( ‎ﻉ‎ → ‎ع‎ ) ARABIC LETTER AIN ISOLATED FORM → ARABIC LETTER AIN	# 

			{ L"\xFCBA",L"\x0639\x062C" }, //( ‎ﲺ‎ → ‎عج‎ ) ARABIC LIGATURE AIN WITH JEEM INITIAL FORM → ARABIC LETTER AIN, ARABIC LETTER JEEM	# 
			{ L"\xFC29",L"\x0639\x062C" }, //( ‎ﰩ‎ → ‎عج‎ ) ARABIC LIGATURE AIN WITH JEEM ISOLATED FORM → ARABIC LETTER AIN, ARABIC LETTER JEEM	# 

			{ L"\xFDC4",L"\x0639\x062C\x0645" }, //( ‎ﷄ‎ → ‎عجم‎ ) ARABIC LIGATURE AIN WITH JEEM WITH MEEM INITIAL FORM → ARABIC LETTER AIN, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 
			{ L"\xFD75",L"\x0639\x062C\x0645" }, //( ‎ﵵ‎ → ‎عجم‎ ) ARABIC LIGATURE AIN WITH JEEM WITH MEEM FINAL FORM → ARABIC LETTER AIN, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDF7",L"\x0639\x0644\x0649\x006F" }, //( ‎ﷷ‎ → ‎علىo‎ ) ARABIC LIGATURE ALAYHE ISOLATED FORM → ARABIC LETTER AIN, ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA, LATIN SMALL LETTER O	# →‎عليه‎→

			{ L"\xFCBB",L"\x0639\x0645" }, //( ‎ﲻ‎ → ‎عم‎ ) ARABIC LIGATURE AIN WITH MEEM INITIAL FORM → ARABIC LETTER AIN, ARABIC LETTER MEEM	# 
			{ L"\xFC2A",L"\x0639\x0645" }, //( ‎ﰪ‎ → ‎عم‎ ) ARABIC LIGATURE AIN WITH MEEM ISOLATED FORM → ARABIC LETTER AIN, ARABIC LETTER MEEM	# 

			{ L"\xFD77",L"\x0639\x0645\x0645" }, //( ‎ﵷ‎ → ‎عمم‎ ) ARABIC LIGATURE AIN WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER AIN, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 
			{ L"\xFD76",L"\x0639\x0645\x0645" }, //( ‎ﵶ‎ → ‎عمم‎ ) ARABIC LIGATURE AIN WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER AIN, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD78",L"\x0639\x0645\x0649" }, //( ‎ﵸ‎ → ‎عمى‎ ) ARABIC LIGATURE AIN WITH MEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER AIN, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDB6",L"\x0639\x0645\x0649" }, //( ‎ﶶ‎ → ‎عمى‎ ) ARABIC LIGATURE AIN WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER AIN, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎عمي‎→

			{ L"\xFD13",L"\x0639\x0649" }, //( ‎ﴓ‎ → ‎عى‎ ) ARABIC LIGATURE AIN WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER AIN, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFCF7",L"\x0639\x0649" }, //( ‎ﳷ‎ → ‎عى‎ ) ARABIC LIGATURE AIN WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER AIN, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD14",L"\x0639\x0649" }, //( ‎ﴔ‎ → ‎عى‎ ) ARABIC LIGATURE AIN WITH YEH FINAL FORM → ARABIC LETTER AIN, ARABIC LETTER ALEF MAKSURA	# →‎عي‎→
			{ L"\xFCF8",L"\x0639\x0649" }, //( ‎ﳸ‎ → ‎عى‎ ) ARABIC LIGATURE AIN WITH YEH ISOLATED FORM → ARABIC LETTER AIN, ARABIC LETTER ALEF MAKSURA	# →‎عي‎→

			{ L"\x0001\xEE1B",L"\x063A" }, //( ‎𞸛‎ → ‎غ‎ ) ARABIC MATHEMATICAL GHAIN → ARABIC LETTER GHAIN	# 
			{ L"\x0001\xEE3B",L"\x063A" }, //( ‎𞸻‎ → ‎غ‎ ) ARABIC MATHEMATICAL INITIAL GHAIN → ARABIC LETTER GHAIN	# 
			{ L"\x0001\xEE5B",L"\x063A" }, //( ‎𞹛‎ → ‎غ‎ ) ARABIC MATHEMATICAL TAILED GHAIN → ARABIC LETTER GHAIN	# 
			{ L"\x0001\xEE7B",L"\x063A" }, //( ‎𞹻‎ → ‎غ‎ ) ARABIC MATHEMATICAL STRETCHED GHAIN → ARABIC LETTER GHAIN	# 
			{ L"\x0001\xEE9B",L"\x063A" }, //( ‎𞺛‎ → ‎غ‎ ) ARABIC MATHEMATICAL LOOPED GHAIN → ARABIC LETTER GHAIN	# 
			{ L"\x0001\xEEBB",L"\x063A" }, //( ‎𞺻‎ → ‎غ‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK GHAIN → ARABIC LETTER GHAIN	# 
			{ L"\xFECF",L"\x063A" }, //( ‎ﻏ‎ → ‎غ‎ ) ARABIC LETTER GHAIN INITIAL FORM → ARABIC LETTER GHAIN	# 
			{ L"\xFED0",L"\x063A" }, //( ‎ﻐ‎ → ‎غ‎ ) ARABIC LETTER GHAIN MEDIAL FORM → ARABIC LETTER GHAIN	# 
			{ L"\xFECE",L"\x063A" }, //( ‎ﻎ‎ → ‎غ‎ ) ARABIC LETTER GHAIN FINAL FORM → ARABIC LETTER GHAIN	# 
			{ L"\xFECD",L"\x063A" }, //( ‎ﻍ‎ → ‎غ‎ ) ARABIC LETTER GHAIN ISOLATED FORM → ARABIC LETTER GHAIN	# 

			{ L"\xFCBC",L"\x063A\x062C" }, //( ‎ﲼ‎ → ‎غج‎ ) ARABIC LIGATURE GHAIN WITH JEEM INITIAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER JEEM	# 
			{ L"\xFC2B",L"\x063A\x062C" }, //( ‎ﰫ‎ → ‎غج‎ ) ARABIC LIGATURE GHAIN WITH JEEM ISOLATED FORM → ARABIC LETTER GHAIN, ARABIC LETTER JEEM	# 

			{ L"\xFCBD",L"\x063A\x0645" }, //( ‎ﲽ‎ → ‎غم‎ ) ARABIC LIGATURE GHAIN WITH MEEM INITIAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER MEEM	# 
			{ L"\xFC2C",L"\x063A\x0645" }, //( ‎ﰬ‎ → ‎غم‎ ) ARABIC LIGATURE GHAIN WITH MEEM ISOLATED FORM → ARABIC LETTER GHAIN, ARABIC LETTER MEEM	# 

			{ L"\xFD79",L"\x063A\x0645\x0645" }, //( ‎ﵹ‎ → ‎غمم‎ ) ARABIC LIGATURE GHAIN WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD7B",L"\x063A\x0645\x0649" }, //( ‎ﵻ‎ → ‎غمى‎ ) ARABIC LIGATURE GHAIN WITH MEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD7A",L"\x063A\x0645\x0649" }, //( ‎ﵺ‎ → ‎غمى‎ ) ARABIC LIGATURE GHAIN WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎غمي‎→

			{ L"\xFD15",L"\x063A\x0649" }, //( ‎ﴕ‎ → ‎غى‎ ) ARABIC LIGATURE GHAIN WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFCF9",L"\x063A\x0649" }, //( ‎ﳹ‎ → ‎غى‎ ) ARABIC LIGATURE GHAIN WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER GHAIN, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD16",L"\x063A\x0649" }, //( ‎ﴖ‎ → ‎غى‎ ) ARABIC LIGATURE GHAIN WITH YEH FINAL FORM → ARABIC LETTER GHAIN, ARABIC LETTER ALEF MAKSURA	# →‎غي‎→
			{ L"\xFCFA",L"\x063A\x0649" }, //( ‎ﳺ‎ → ‎غى‎ ) ARABIC LIGATURE GHAIN WITH YEH ISOLATED FORM → ARABIC LETTER GHAIN, ARABIC LETTER ALEF MAKSURA	# →‎غي‎→

			{ L"\x0001\xEE10",L"\x0641" }, //( ‎𞸐‎ → ‎ف‎ ) ARABIC MATHEMATICAL FEH → ARABIC LETTER FEH	# 
			{ L"\x0001\xEE30",L"\x0641" }, //( ‎𞸰‎ → ‎ف‎ ) ARABIC MATHEMATICAL INITIAL FEH → ARABIC LETTER FEH	# 
			{ L"\x0001\xEE70",L"\x0641" }, //( ‎𞹰‎ → ‎ف‎ ) ARABIC MATHEMATICAL STRETCHED FEH → ARABIC LETTER FEH	# 
			{ L"\x0001\xEE90",L"\x0641" }, //( ‎𞺐‎ → ‎ف‎ ) ARABIC MATHEMATICAL LOOPED FEH → ARABIC LETTER FEH	# 
			{ L"\x0001\xEEB0",L"\x0641" }, //( ‎𞺰‎ → ‎ف‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK FEH → ARABIC LETTER FEH	# 
			{ L"\xFED3",L"\x0641" }, //( ‎ﻓ‎ → ‎ف‎ ) ARABIC LETTER FEH INITIAL FORM → ARABIC LETTER FEH	# 
			{ L"\xFED4",L"\x0641" }, //( ‎ﻔ‎ → ‎ف‎ ) ARABIC LETTER FEH MEDIAL FORM → ARABIC LETTER FEH	# 
			{ L"\xFED2",L"\x0641" }, //( ‎ﻒ‎ → ‎ف‎ ) ARABIC LETTER FEH FINAL FORM → ARABIC LETTER FEH	# 
			{ L"\xFED1",L"\x0641" }, //( ‎ﻑ‎ → ‎ف‎ ) ARABIC LETTER FEH ISOLATED FORM → ARABIC LETTER FEH	# 
			{ L"\x06A7",L"\x0641" }, //( ‎ڧ‎ → ‎ف‎ ) ARABIC LETTER QAF WITH DOT ABOVE → ARABIC LETTER FEH	# 

			{ L"\xFCBE",L"\x0641\x062C" }, //( ‎ﲾ‎ → ‎فج‎ ) ARABIC LIGATURE FEH WITH JEEM INITIAL FORM → ARABIC LETTER FEH, ARABIC LETTER JEEM	# 
			{ L"\xFC2D",L"\x0641\x062C" }, //( ‎ﰭ‎ → ‎فج‎ ) ARABIC LIGATURE FEH WITH JEEM ISOLATED FORM → ARABIC LETTER FEH, ARABIC LETTER JEEM	# 

			{ L"\xFCBF",L"\x0641\x062D" }, //( ‎ﲿ‎ → ‎فح‎ ) ARABIC LIGATURE FEH WITH HAH INITIAL FORM → ARABIC LETTER FEH, ARABIC LETTER HAH	# 
			{ L"\xFC2E",L"\x0641\x062D" }, //( ‎ﰮ‎ → ‎فح‎ ) ARABIC LIGATURE FEH WITH HAH ISOLATED FORM → ARABIC LETTER FEH, ARABIC LETTER HAH	# 

			{ L"\xFCC0",L"\x0641\x062E" }, //( ‎ﳀ‎ → ‎فخ‎ ) ARABIC LIGATURE FEH WITH KHAH INITIAL FORM → ARABIC LETTER FEH, ARABIC LETTER KHAH	# 
			{ L"\xFC2F",L"\x0641\x062E" }, //( ‎ﰯ‎ → ‎فخ‎ ) ARABIC LIGATURE FEH WITH KHAH ISOLATED FORM → ARABIC LETTER FEH, ARABIC LETTER KHAH	# 

			{ L"\xFD7D",L"\x0641\x062E\x0645" }, //( ‎ﵽ‎ → ‎فخم‎ ) ARABIC LIGATURE FEH WITH KHAH WITH MEEM INITIAL FORM → ARABIC LETTER FEH, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 
			{ L"\xFD7C",L"\x0641\x062E\x0645" }, //( ‎ﵼ‎ → ‎فخم‎ ) ARABIC LIGATURE FEH WITH KHAH WITH MEEM FINAL FORM → ARABIC LETTER FEH, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 

			{ L"\xFCC1",L"\x0641\x0645" }, //( ‎ﳁ‎ → ‎فم‎ ) ARABIC LIGATURE FEH WITH MEEM INITIAL FORM → ARABIC LETTER FEH, ARABIC LETTER MEEM	# 
			{ L"\xFC30",L"\x0641\x0645" }, //( ‎ﰰ‎ → ‎فم‎ ) ARABIC LIGATURE FEH WITH MEEM ISOLATED FORM → ARABIC LETTER FEH, ARABIC LETTER MEEM	# 

			{ L"\xFDC1",L"\x0641\x0645\x0649" }, //( ‎ﷁ‎ → ‎فمى‎ ) ARABIC LIGATURE FEH WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER FEH, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎فمي‎→

			{ L"\xFC7C",L"\x0641\x0649" }, //( ‎ﱼ‎ → ‎فى‎ ) ARABIC LIGATURE FEH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER FEH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC31",L"\x0641\x0649" }, //( ‎ﰱ‎ → ‎فى‎ ) ARABIC LIGATURE FEH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER FEH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC7D",L"\x0641\x0649" }, //( ‎ﱽ‎ → ‎فى‎ ) ARABIC LIGATURE FEH WITH YEH FINAL FORM → ARABIC LETTER FEH, ARABIC LETTER ALEF MAKSURA	# →‎في‎→
			{ L"\xFC32",L"\x0641\x0649" }, //( ‎ﰲ‎ → ‎فى‎ ) ARABIC LIGATURE FEH WITH YEH ISOLATED FORM → ARABIC LETTER FEH, ARABIC LETTER ALEF MAKSURA	# →‎في‎→

			{ L"\x0001\xEE1E",L"\x06A1" }, //( ‎𞸞‎ → ‎ڡ‎ ) ARABIC MATHEMATICAL DOTLESS FEH → ARABIC LETTER DOTLESS FEH	# 
			{ L"\x0001\xEE7E",L"\x06A1" }, //( ‎𞹾‎ → ‎ڡ‎ ) ARABIC MATHEMATICAL STRETCHED DOTLESS FEH → ARABIC LETTER DOTLESS FEH	# 
			{ L"\x066F",L"\x06A1" }, //( ‎ٯ‎ → ‎ڡ‎ ) ARABIC LETTER DOTLESS QAF → ARABIC LETTER DOTLESS FEH	# 
			{ L"\x0001\xEE1F",L"\x06A1" }, //( ‎𞸟‎ → ‎ڡ‎ ) ARABIC MATHEMATICAL DOTLESS QAF → ARABIC LETTER DOTLESS FEH	# →‎ٯ‎→
			{ L"\x0001\xEE5F",L"\x06A1" }, //( ‎𞹟‎ → ‎ڡ‎ ) ARABIC MATHEMATICAL TAILED DOTLESS QAF → ARABIC LETTER DOTLESS FEH	# →‎ٯ‎→

			{ L"\x06A4",L"\x06A1\x06DB" }, //( ‎ڤ‎ → ‎ڡۛ‎ ) ARABIC LETTER VEH → ARABIC LETTER DOTLESS FEH, ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\xFB6C",L"\x06A1\x06DB" }, //( ‎ﭬ‎ → ‎ڡۛ‎ ) ARABIC LETTER VEH INITIAL FORM → ARABIC LETTER DOTLESS FEH, ARABIC SMALL HIGH THREE DOTS	# →‎ڤ‎→
			{ L"\xFB6D",L"\x06A1\x06DB" }, //( ‎ﭭ‎ → ‎ڡۛ‎ ) ARABIC LETTER VEH MEDIAL FORM → ARABIC LETTER DOTLESS FEH, ARABIC SMALL HIGH THREE DOTS	# →‎ڤ‎→
			{ L"\xFB6B",L"\x06A1\x06DB" }, //( ‎ﭫ‎ → ‎ڡۛ‎ ) ARABIC LETTER VEH FINAL FORM → ARABIC LETTER DOTLESS FEH, ARABIC SMALL HIGH THREE DOTS	# →‎ڤ‎→
			{ L"\xFB6A",L"\x06A1\x06DB" }, //( ‎ﭪ‎ → ‎ڡۛ‎ ) ARABIC LETTER VEH ISOLATED FORM → ARABIC LETTER DOTLESS FEH, ARABIC SMALL HIGH THREE DOTS	# →‎ڤ‎→
			{ L"\x06A8",L"\x06A1\x06DB" }, //( ‎ڨ‎ → ‎ڡۛ‎ ) ARABIC LETTER QAF WITH THREE DOTS ABOVE → ARABIC LETTER DOTLESS FEH, ARABIC SMALL HIGH THREE DOTS	# →‎ڤ‎→

			{ L"\x08A4",L"\x06A2\x06DB" }, //( ‎ࢤ‎ → ‎ڢۛ‎ ) ARABIC LETTER FEH WITH DOT BELOW AND THREE DOTS ABOVE → ARABIC LETTER FEH WITH DOT MOVED BELOW, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\xFB70",L"\x06A6" }, //( ‎ﭰ‎ → ‎ڦ‎ ) ARABIC LETTER PEHEH INITIAL FORM → ARABIC LETTER PEHEH	# 
			{ L"\xFB71",L"\x06A6" }, //( ‎ﭱ‎ → ‎ڦ‎ ) ARABIC LETTER PEHEH MEDIAL FORM → ARABIC LETTER PEHEH	# 
			{ L"\xFB6F",L"\x06A6" }, //( ‎ﭯ‎ → ‎ڦ‎ ) ARABIC LETTER PEHEH FINAL FORM → ARABIC LETTER PEHEH	# 
			{ L"\xFB6E",L"\x06A6" }, //( ‎ﭮ‎ → ‎ڦ‎ ) ARABIC LETTER PEHEH ISOLATED FORM → ARABIC LETTER PEHEH	# 

			{ L"\x0001\xEE12",L"\x0642" }, //( ‎𞸒‎ → ‎ق‎ ) ARABIC MATHEMATICAL QAF → ARABIC LETTER QAF	# 
			{ L"\x0001\xEE32",L"\x0642" }, //( ‎𞸲‎ → ‎ق‎ ) ARABIC MATHEMATICAL INITIAL QAF → ARABIC LETTER QAF	# 
			{ L"\x0001\xEE52",L"\x0642" }, //( ‎𞹒‎ → ‎ق‎ ) ARABIC MATHEMATICAL TAILED QAF → ARABIC LETTER QAF	# 
			{ L"\x0001\xEE72",L"\x0642" }, //( ‎𞹲‎ → ‎ق‎ ) ARABIC MATHEMATICAL STRETCHED QAF → ARABIC LETTER QAF	# 
			{ L"\x0001\xEE92",L"\x0642" }, //( ‎𞺒‎ → ‎ق‎ ) ARABIC MATHEMATICAL LOOPED QAF → ARABIC LETTER QAF	# 
			{ L"\x0001\xEEB2",L"\x0642" }, //( ‎𞺲‎ → ‎ق‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK QAF → ARABIC LETTER QAF	# 
			{ L"\xFED7",L"\x0642" }, //( ‎ﻗ‎ → ‎ق‎ ) ARABIC LETTER QAF INITIAL FORM → ARABIC LETTER QAF	# 
			{ L"\xFED8",L"\x0642" }, //( ‎ﻘ‎ → ‎ق‎ ) ARABIC LETTER QAF MEDIAL FORM → ARABIC LETTER QAF	# 
			{ L"\xFED6",L"\x0642" }, //( ‎ﻖ‎ → ‎ق‎ ) ARABIC LETTER QAF FINAL FORM → ARABIC LETTER QAF	# 
			{ L"\xFED5",L"\x0642" }, //( ‎ﻕ‎ → ‎ق‎ ) ARABIC LETTER QAF ISOLATED FORM → ARABIC LETTER QAF	# 

			{ L"\xFCC2",L"\x0642\x062D" }, //( ‎ﳂ‎ → ‎قح‎ ) ARABIC LIGATURE QAF WITH HAH INITIAL FORM → ARABIC LETTER QAF, ARABIC LETTER HAH	# 
			{ L"\xFC33",L"\x0642\x062D" }, //( ‎ﰳ‎ → ‎قح‎ ) ARABIC LIGATURE QAF WITH HAH ISOLATED FORM → ARABIC LETTER QAF, ARABIC LETTER HAH	# 

			{ L"\xFDF1",L"\x0642\x0644\x0649" }, //( ‎ﷱ‎ → ‎قلى‎ ) ARABIC LIGATURE QALA USED AS KORANIC STOP SIGN ISOLATED FORM → ARABIC LETTER QAF, ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# →‎قلے‎→

			{ L"\xFCC3",L"\x0642\x0645" }, //( ‎ﳃ‎ → ‎قم‎ ) ARABIC LIGATURE QAF WITH MEEM INITIAL FORM → ARABIC LETTER QAF, ARABIC LETTER MEEM	# 
			{ L"\xFC34",L"\x0642\x0645" }, //( ‎ﰴ‎ → ‎قم‎ ) ARABIC LIGATURE QAF WITH MEEM ISOLATED FORM → ARABIC LETTER QAF, ARABIC LETTER MEEM	# 

			{ L"\xFDB4",L"\x0642\x0645\x062D" }, //( ‎ﶴ‎ → ‎قمح‎ ) ARABIC LIGATURE QAF WITH MEEM WITH HAH INITIAL FORM → ARABIC LETTER QAF, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 
			{ L"\xFD7E",L"\x0642\x0645\x062D" }, //( ‎ﵾ‎ → ‎قمح‎ ) ARABIC LIGATURE QAF WITH MEEM WITH HAH FINAL FORM → ARABIC LETTER QAF, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFD7F",L"\x0642\x0645\x0645" }, //( ‎ﵿ‎ → ‎قمم‎ ) ARABIC LIGATURE QAF WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER QAF, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDB2",L"\x0642\x0645\x0649" }, //( ‎ﶲ‎ → ‎قمى‎ ) ARABIC LIGATURE QAF WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER QAF, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎قمي‎→

			{ L"\xFC7E",L"\x0642\x0649" }, //( ‎ﱾ‎ → ‎قى‎ ) ARABIC LIGATURE QAF WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER QAF, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC35",L"\x0642\x0649" }, //( ‎ﰵ‎ → ‎قى‎ ) ARABIC LIGATURE QAF WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER QAF, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC7F",L"\x0642\x0649" }, //( ‎ﱿ‎ → ‎قى‎ ) ARABIC LIGATURE QAF WITH YEH FINAL FORM → ARABIC LETTER QAF, ARABIC LETTER ALEF MAKSURA	# →‎قي‎→
			{ L"\xFC36",L"\x0642\x0649" }, //( ‎ﰶ‎ → ‎قى‎ ) ARABIC LIGATURE QAF WITH YEH ISOLATED FORM → ARABIC LETTER QAF, ARABIC LETTER ALEF MAKSURA	# →‎قي‎→

			{ L"\x0001\xEE0A",L"\x0643" }, //( ‎𞸊‎ → ‎ك‎ ) ARABIC MATHEMATICAL KAF → ARABIC LETTER KAF	# 
			{ L"\x0001\xEE2A",L"\x0643" }, //( ‎𞸪‎ → ‎ك‎ ) ARABIC MATHEMATICAL INITIAL KAF → ARABIC LETTER KAF	# 
			{ L"\x0001\xEE6A",L"\x0643" }, //( ‎𞹪‎ → ‎ك‎ ) ARABIC MATHEMATICAL STRETCHED KAF → ARABIC LETTER KAF	# 
			{ L"\xFEDB",L"\x0643" }, //( ‎ﻛ‎ → ‎ك‎ ) ARABIC LETTER KAF INITIAL FORM → ARABIC LETTER KAF	# 
			{ L"\xFEDC",L"\x0643" }, //( ‎ﻜ‎ → ‎ك‎ ) ARABIC LETTER KAF MEDIAL FORM → ARABIC LETTER KAF	# 
			{ L"\xFEDA",L"\x0643" }, //( ‎ﻚ‎ → ‎ك‎ ) ARABIC LETTER KAF FINAL FORM → ARABIC LETTER KAF	# 
			{ L"\xFED9",L"\x0643" }, //( ‎ﻙ‎ → ‎ك‎ ) ARABIC LETTER KAF ISOLATED FORM → ARABIC LETTER KAF	# 
			{ L"\x06A9",L"\x0643" }, //( ‎ک‎ → ‎ك‎ ) ARABIC LETTER KEHEH → ARABIC LETTER KAF	# 
			{ L"\xFB90",L"\x0643" }, //( ‎ﮐ‎ → ‎ك‎ ) ARABIC LETTER KEHEH INITIAL FORM → ARABIC LETTER KAF	# →‎ک‎→
			{ L"\xFB91",L"\x0643" }, //( ‎ﮑ‎ → ‎ك‎ ) ARABIC LETTER KEHEH MEDIAL FORM → ARABIC LETTER KAF	# →‎ک‎→
			{ L"\xFB8F",L"\x0643" }, //( ‎ﮏ‎ → ‎ك‎ ) ARABIC LETTER KEHEH FINAL FORM → ARABIC LETTER KAF	# →‎ک‎→
			{ L"\xFB8E",L"\x0643" }, //( ‎ﮎ‎ → ‎ك‎ ) ARABIC LETTER KEHEH ISOLATED FORM → ARABIC LETTER KAF	# →‎ک‎→
			{ L"\x06AA",L"\x0643" }, //( ‎ڪ‎ → ‎ك‎ ) ARABIC LETTER SWASH KAF → ARABIC LETTER KAF	# 

			{ L"\x06AD",L"\x0643\x06DB" }, //( ‎ڭ‎ → ‎كۛ‎ ) ARABIC LETTER NG → ARABIC LETTER KAF, ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\xFBD5",L"\x0643\x06DB" }, //( ‎ﯕ‎ → ‎كۛ‎ ) ARABIC LETTER NG INITIAL FORM → ARABIC LETTER KAF, ARABIC SMALL HIGH THREE DOTS	# →‎ڭ‎→
			{ L"\xFBD6",L"\x0643\x06DB" }, //( ‎ﯖ‎ → ‎كۛ‎ ) ARABIC LETTER NG MEDIAL FORM → ARABIC LETTER KAF, ARABIC SMALL HIGH THREE DOTS	# →‎ڭ‎→
			{ L"\xFBD4",L"\x0643\x06DB" }, //( ‎ﯔ‎ → ‎كۛ‎ ) ARABIC LETTER NG FINAL FORM → ARABIC LETTER KAF, ARABIC SMALL HIGH THREE DOTS	# →‎ڭ‎→
			{ L"\xFBD3",L"\x0643\x06DB" }, //( ‎ﯓ‎ → ‎كۛ‎ ) ARABIC LETTER NG ISOLATED FORM → ARABIC LETTER KAF, ARABIC SMALL HIGH THREE DOTS	# →‎ڭ‎→
			{ L"\x0763",L"\x0643\x06DB" }, //( ‎ݣ‎ → ‎كۛ‎ ) ARABIC LETTER KEHEH WITH THREE DOTS ABOVE → ARABIC LETTER KAF, ARABIC SMALL HIGH THREE DOTS	# →‎ڭ‎→

			{ L"\xFC80",L"\x0643\x006C" }, //( ‎ﲀ‎ → ‎كl‎ ) ARABIC LIGATURE KAF WITH ALEF FINAL FORM → ARABIC LETTER KAF, LATIN SMALL LETTER L	# →‎كا‎→
			{ L"\xFC37",L"\x0643\x006C" }, //( ‎ﰷ‎ → ‎كl‎ ) ARABIC LIGATURE KAF WITH ALEF ISOLATED FORM → ARABIC LETTER KAF, LATIN SMALL LETTER L	# →‎كا‎→

			{ L"\xFCC4",L"\x0643\x062C" }, //( ‎ﳄ‎ → ‎كج‎ ) ARABIC LIGATURE KAF WITH JEEM INITIAL FORM → ARABIC LETTER KAF, ARABIC LETTER JEEM	# 
			{ L"\xFC38",L"\x0643\x062C" }, //( ‎ﰸ‎ → ‎كج‎ ) ARABIC LIGATURE KAF WITH JEEM ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER JEEM	# 

			{ L"\xFCC5",L"\x0643\x062D" }, //( ‎ﳅ‎ → ‎كح‎ ) ARABIC LIGATURE KAF WITH HAH INITIAL FORM → ARABIC LETTER KAF, ARABIC LETTER HAH	# 
			{ L"\xFC39",L"\x0643\x062D" }, //( ‎ﰹ‎ → ‎كح‎ ) ARABIC LIGATURE KAF WITH HAH ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER HAH	# 

			{ L"\xFCC6",L"\x0643\x062E" }, //( ‎ﳆ‎ → ‎كخ‎ ) ARABIC LIGATURE KAF WITH KHAH INITIAL FORM → ARABIC LETTER KAF, ARABIC LETTER KHAH	# 
			{ L"\xFC3A",L"\x0643\x062E" }, //( ‎ﰺ‎ → ‎كخ‎ ) ARABIC LIGATURE KAF WITH KHAH ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER KHAH	# 

			{ L"\xFCC7",L"\x0643\x0644" }, //( ‎ﳇ‎ → ‎كل‎ ) ARABIC LIGATURE KAF WITH LAM INITIAL FORM → ARABIC LETTER KAF, ARABIC LETTER LAM	# 
			{ L"\xFCEB",L"\x0643\x0644" }, //( ‎ﳫ‎ → ‎كل‎ ) ARABIC LIGATURE KAF WITH LAM MEDIAL FORM → ARABIC LETTER KAF, ARABIC LETTER LAM	# 
			{ L"\xFC81",L"\x0643\x0644" }, //( ‎ﲁ‎ → ‎كل‎ ) ARABIC LIGATURE KAF WITH LAM FINAL FORM → ARABIC LETTER KAF, ARABIC LETTER LAM	# 
			{ L"\xFC3B",L"\x0643\x0644" }, //( ‎ﰻ‎ → ‎كل‎ ) ARABIC LIGATURE KAF WITH LAM ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER LAM	# 

			{ L"\xFCC8",L"\x0643\x0645" }, //( ‎ﳈ‎ → ‎كم‎ ) ARABIC LIGATURE KAF WITH MEEM INITIAL FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM	# 
			{ L"\xFCEC",L"\x0643\x0645" }, //( ‎ﳬ‎ → ‎كم‎ ) ARABIC LIGATURE KAF WITH MEEM MEDIAL FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM	# 
			{ L"\xFC82",L"\x0643\x0645" }, //( ‎ﲂ‎ → ‎كم‎ ) ARABIC LIGATURE KAF WITH MEEM FINAL FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM	# 
			{ L"\xFC3C",L"\x0643\x0645" }, //( ‎ﰼ‎ → ‎كم‎ ) ARABIC LIGATURE KAF WITH MEEM ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM	# 

			{ L"\xFDC3",L"\x0643\x0645\x0645" }, //( ‎ﷃ‎ → ‎كمم‎ ) ARABIC LIGATURE KAF WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 
			{ L"\xFDBB",L"\x0643\x0645\x0645" }, //( ‎ﶻ‎ → ‎كمم‎ ) ARABIC LIGATURE KAF WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDB7",L"\x0643\x0645\x0649" }, //( ‎ﶷ‎ → ‎كمى‎ ) ARABIC LIGATURE KAF WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER KAF, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎كمي‎→

			{ L"\xFC83",L"\x0643\x0649" }, //( ‎ﲃ‎ → ‎كى‎ ) ARABIC LIGATURE KAF WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER KAF, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC3D",L"\x0643\x0649" }, //( ‎ﰽ‎ → ‎كى‎ ) ARABIC LIGATURE KAF WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC84",L"\x0643\x0649" }, //( ‎ﲄ‎ → ‎كى‎ ) ARABIC LIGATURE KAF WITH YEH FINAL FORM → ARABIC LETTER KAF, ARABIC LETTER ALEF MAKSURA	# →‎كي‎→
			{ L"\xFC3E",L"\x0643\x0649" }, //( ‎ﰾ‎ → ‎كى‎ ) ARABIC LIGATURE KAF WITH YEH ISOLATED FORM → ARABIC LETTER KAF, ARABIC LETTER ALEF MAKSURA	# →‎كي‎→

			{ L"\x0762",L"\x06AC" }, //( ‎ݢ‎ → ‎ڬ‎ ) ARABIC LETTER KEHEH WITH DOT ABOVE → ARABIC LETTER KAF WITH DOT ABOVE	# 

			{ L"\xFB94",L"\x06AF" }, //( ‎ﮔ‎ → ‎گ‎ ) ARABIC LETTER GAF INITIAL FORM → ARABIC LETTER GAF	# 
			{ L"\xFB95",L"\x06AF" }, //( ‎ﮕ‎ → ‎گ‎ ) ARABIC LETTER GAF MEDIAL FORM → ARABIC LETTER GAF	# 
			{ L"\xFB93",L"\x06AF" }, //( ‎ﮓ‎ → ‎گ‎ ) ARABIC LETTER GAF FINAL FORM → ARABIC LETTER GAF	# 
			{ L"\xFB92",L"\x06AF" }, //( ‎ﮒ‎ → ‎گ‎ ) ARABIC LETTER GAF ISOLATED FORM → ARABIC LETTER GAF	# 
			{ L"\x08B0",L"\x06AF" }, //( ‎ࢰ‎ → ‎گ‎ ) ARABIC LETTER GAF WITH INVERTED STROKE → ARABIC LETTER GAF	# 

			{ L"\x06B4",L"\x06AF\x06DB" }, //( ‎ڴ‎ → ‎گۛ‎ ) ARABIC LETTER GAF WITH THREE DOTS ABOVE → ARABIC LETTER GAF, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\xFB9C",L"\x06B1" }, //( ‎ﮜ‎ → ‎ڱ‎ ) ARABIC LETTER NGOEH INITIAL FORM → ARABIC LETTER NGOEH	# 
			{ L"\xFB9D",L"\x06B1" }, //( ‎ﮝ‎ → ‎ڱ‎ ) ARABIC LETTER NGOEH MEDIAL FORM → ARABIC LETTER NGOEH	# 
			{ L"\xFB9B",L"\x06B1" }, //( ‎ﮛ‎ → ‎ڱ‎ ) ARABIC LETTER NGOEH FINAL FORM → ARABIC LETTER NGOEH	# 
			{ L"\xFB9A",L"\x06B1" }, //( ‎ﮚ‎ → ‎ڱ‎ ) ARABIC LETTER NGOEH ISOLATED FORM → ARABIC LETTER NGOEH	# 

			{ L"\xFB98",L"\x06B3" }, //( ‎ﮘ‎ → ‎ڳ‎ ) ARABIC LETTER GUEH INITIAL FORM → ARABIC LETTER GUEH	# 
			{ L"\xFB99",L"\x06B3" }, //( ‎ﮙ‎ → ‎ڳ‎ ) ARABIC LETTER GUEH MEDIAL FORM → ARABIC LETTER GUEH	# 
			{ L"\xFB97",L"\x06B3" }, //( ‎ﮗ‎ → ‎ڳ‎ ) ARABIC LETTER GUEH FINAL FORM → ARABIC LETTER GUEH	# 
			{ L"\xFB96",L"\x06B3" }, //( ‎ﮖ‎ → ‎ڳ‎ ) ARABIC LETTER GUEH ISOLATED FORM → ARABIC LETTER GUEH	# 

			{ L"\x0001\xEE0B",L"\x0644" }, //( ‎𞸋‎ → ‎ل‎ ) ARABIC MATHEMATICAL LAM → ARABIC LETTER LAM	# 
			{ L"\x0001\xEE2B",L"\x0644" }, //( ‎𞸫‎ → ‎ل‎ ) ARABIC MATHEMATICAL INITIAL LAM → ARABIC LETTER LAM	# 
			{ L"\x0001\xEE4B",L"\x0644" }, //( ‎𞹋‎ → ‎ل‎ ) ARABIC MATHEMATICAL TAILED LAM → ARABIC LETTER LAM	# 
			{ L"\x0001\xEE8B",L"\x0644" }, //( ‎𞺋‎ → ‎ل‎ ) ARABIC MATHEMATICAL LOOPED LAM → ARABIC LETTER LAM	# 
			{ L"\x0001\xEEAB",L"\x0644" }, //( ‎𞺫‎ → ‎ل‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK LAM → ARABIC LETTER LAM	# 
			{ L"\xFEDF",L"\x0644" }, //( ‎ﻟ‎ → ‎ل‎ ) ARABIC LETTER LAM INITIAL FORM → ARABIC LETTER LAM	# 
			{ L"\xFEE0",L"\x0644" }, //( ‎ﻠ‎ → ‎ل‎ ) ARABIC LETTER LAM MEDIAL FORM → ARABIC LETTER LAM	# 
			{ L"\xFEDE",L"\x0644" }, //( ‎ﻞ‎ → ‎ل‎ ) ARABIC LETTER LAM FINAL FORM → ARABIC LETTER LAM	# 
			{ L"\xFEDD",L"\x0644" }, //( ‎ﻝ‎ → ‎ل‎ ) ARABIC LETTER LAM ISOLATED FORM → ARABIC LETTER LAM	# 

			{ L"\x06B7",L"\x0644\x06DB" }, //( ‎ڷ‎ → ‎لۛ‎ ) ARABIC LETTER LAM WITH THREE DOTS ABOVE → ARABIC LETTER LAM, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\x06B5",L"\x0644\x0306" }, //( ‎ڵ‎ → ‎ل̆‎ ) ARABIC LETTER LAM WITH SMALL V → ARABIC LETTER LAM, COMBINING BREVE	# →‎لٚ‎→

			{ L"\xFEFC",L"\x0644\x006C" }, //( ‎ﻼ‎ → ‎لl‎ ) ARABIC LIGATURE LAM WITH ALEF FINAL FORM → ARABIC LETTER LAM, LATIN SMALL LETTER L	# →‎لا‎→
			{ L"\xFEFB",L"\x0644\x006C" }, //( ‎ﻻ‎ → ‎لl‎ ) ARABIC LIGATURE LAM WITH ALEF ISOLATED FORM → ARABIC LETTER LAM, LATIN SMALL LETTER L	# →‎لا‎→

			{ L"\xFEFA",L"\x0644\x006C\x0655" }, //( ‎ﻺ‎ → ‎لlٕ‎ ) ARABIC LIGATURE LAM WITH ALEF WITH HAMZA BELOW FINAL FORM → ARABIC LETTER LAM, LATIN SMALL LETTER L, ARABIC HAMZA BELOW	# →‎لإ‎→
			{ L"\xFEF9",L"\x0644\x006C\x0655" }, //( ‎ﻹ‎ → ‎لlٕ‎ ) ARABIC LIGATURE LAM WITH ALEF WITH HAMZA BELOW ISOLATED FORM → ARABIC LETTER LAM, LATIN SMALL LETTER L, ARABIC HAMZA BELOW	# →‎لإ‎→

			{ L"\xFEF8",L"\x0644\x006C\x0674" }, //( ‎ﻸ‎ → ‎لlٴ‎ ) ARABIC LIGATURE LAM WITH ALEF WITH HAMZA ABOVE FINAL FORM → ARABIC LETTER LAM, LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎لأ‎→
			{ L"\xFEF7",L"\x0644\x006C\x0674" }, //( ‎ﻷ‎ → ‎لlٴ‎ ) ARABIC LIGATURE LAM WITH ALEF WITH HAMZA ABOVE ISOLATED FORM → ARABIC LETTER LAM, LATIN SMALL LETTER L, ARABIC LETTER HIGH HAMZA	# →‎لأ‎→

			{ L"\xFCCD",L"\x0644\x006F" }, //( ‎ﳍ‎ → ‎لo‎ ) ARABIC LIGATURE LAM WITH HEH INITIAL FORM → ARABIC LETTER LAM, LATIN SMALL LETTER O	# →‎له‎→

			{ L"\xFEF6",L"\x0644\x0622" }, //( ‎ﻶ‎ → ‎لآ‎ ) ARABIC LIGATURE LAM WITH ALEF WITH MADDA ABOVE FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER ALEF WITH MADDA ABOVE	# 
			{ L"\xFEF5",L"\x0644\x0622" }, //( ‎ﻵ‎ → ‎لآ‎ ) ARABIC LIGATURE LAM WITH ALEF WITH MADDA ABOVE ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER ALEF WITH MADDA ABOVE	# 

			{ L"\xFCC9",L"\x0644\x062C" }, //( ‎ﳉ‎ → ‎لج‎ ) ARABIC LIGATURE LAM WITH JEEM INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM	# 
			{ L"\xFC3F",L"\x0644\x062C" }, //( ‎ﰿ‎ → ‎لج‎ ) ARABIC LIGATURE LAM WITH JEEM ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM	# 

			{ L"\xFD83",L"\x0644\x062C\x062C" }, //( ‎ﶃ‎ → ‎لجج‎ ) ARABIC LIGATURE LAM WITH JEEM WITH JEEM INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM, ARABIC LETTER JEEM	# 
			{ L"\xFD84",L"\x0644\x062C\x062C" }, //( ‎ﶄ‎ → ‎لجج‎ ) ARABIC LIGATURE LAM WITH JEEM WITH JEEM FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM, ARABIC LETTER JEEM	# 

			{ L"\xFDBA",L"\x0644\x062C\x0645" }, //( ‎ﶺ‎ → ‎لجم‎ ) ARABIC LIGATURE LAM WITH JEEM WITH MEEM INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 
			{ L"\xFDBC",L"\x0644\x062C\x0645" }, //( ‎ﶼ‎ → ‎لجم‎ ) ARABIC LIGATURE LAM WITH JEEM WITH MEEM FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDAC",L"\x0644\x062C\x0649" }, //( ‎ﶬ‎ → ‎لجى‎ ) ARABIC LIGATURE LAM WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎لجي‎→

			{ L"\xFCCA",L"\x0644\x062D" }, //( ‎ﳊ‎ → ‎لح‎ ) ARABIC LIGATURE LAM WITH HAH INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER HAH	# 
			{ L"\xFC40",L"\x0644\x062D" }, //( ‎ﱀ‎ → ‎لح‎ ) ARABIC LIGATURE LAM WITH HAH ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER HAH	# 

			{ L"\xFDB5",L"\x0644\x062D\x0645" }, //( ‎ﶵ‎ → ‎لحم‎ ) ARABIC LIGATURE LAM WITH HAH WITH MEEM INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER HAH, ARABIC LETTER MEEM	# 
			{ L"\xFD80",L"\x0644\x062D\x0645" }, //( ‎ﶀ‎ → ‎لحم‎ ) ARABIC LIGATURE LAM WITH HAH WITH MEEM FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER HAH, ARABIC LETTER MEEM	# 

			{ L"\xFD82",L"\x0644\x062D\x0649" }, //( ‎ﶂ‎ → ‎لحى‎ ) ARABIC LIGATURE LAM WITH HAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD81",L"\x0644\x062D\x0649" }, //( ‎ﶁ‎ → ‎لحى‎ ) ARABIC LIGATURE LAM WITH HAH WITH YEH FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎لحي‎→

			{ L"\xFCCB",L"\x0644\x062E" }, //( ‎ﳋ‎ → ‎لخ‎ ) ARABIC LIGATURE LAM WITH KHAH INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER KHAH	# 
			{ L"\xFC41",L"\x0644\x062E" }, //( ‎ﱁ‎ → ‎لخ‎ ) ARABIC LIGATURE LAM WITH KHAH ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER KHAH	# 

			{ L"\xFD86",L"\x0644\x062E\x0645" }, //( ‎ﶆ‎ → ‎لخم‎ ) ARABIC LIGATURE LAM WITH KHAH WITH MEEM INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 
			{ L"\xFD85",L"\x0644\x062E\x0645" }, //( ‎ﶅ‎ → ‎لخم‎ ) ARABIC LIGATURE LAM WITH KHAH WITH MEEM FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 

			{ L"\xFCCC",L"\x0644\x0645" }, //( ‎ﳌ‎ → ‎لم‎ ) ARABIC LIGATURE LAM WITH MEEM INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM	# 
			{ L"\xFCED",L"\x0644\x0645" }, //( ‎ﳭ‎ → ‎لم‎ ) ARABIC LIGATURE LAM WITH MEEM MEDIAL FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM	# 
			{ L"\xFC85",L"\x0644\x0645" }, //( ‎ﲅ‎ → ‎لم‎ ) ARABIC LIGATURE LAM WITH MEEM FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM	# 
			{ L"\xFC42",L"\x0644\x0645" }, //( ‎ﱂ‎ → ‎لم‎ ) ARABIC LIGATURE LAM WITH MEEM ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM	# 

			{ L"\xFD88",L"\x0644\x0645\x062D" }, //( ‎ﶈ‎ → ‎لمح‎ ) ARABIC LIGATURE LAM WITH MEEM WITH HAH INITIAL FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 
			{ L"\xFD87",L"\x0644\x0645\x062D" }, //( ‎ﶇ‎ → ‎لمح‎ ) ARABIC LIGATURE LAM WITH MEEM WITH HAH FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFDAD",L"\x0644\x0645\x0649" }, //( ‎ﶭ‎ → ‎لمى‎ ) ARABIC LIGATURE LAM WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎لمي‎→

			{ L"\xFC86",L"\x0644\x0649" }, //( ‎ﲆ‎ → ‎لى‎ ) ARABIC LIGATURE LAM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC43",L"\x0644\x0649" }, //( ‎ﱃ‎ → ‎لى‎ ) ARABIC LIGATURE LAM WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC87",L"\x0644\x0649" }, //( ‎ﲇ‎ → ‎لى‎ ) ARABIC LIGATURE LAM WITH YEH FINAL FORM → ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# →‎لي‎→
			{ L"\xFC44",L"\x0644\x0649" }, //( ‎ﱄ‎ → ‎لى‎ ) ARABIC LIGATURE LAM WITH YEH ISOLATED FORM → ARABIC LETTER LAM, ARABIC LETTER ALEF MAKSURA	# →‎لي‎→

			{ L"\x0001\xEE0C",L"\x0645" }, //( ‎𞸌‎ → ‎م‎ ) ARABIC MATHEMATICAL MEEM → ARABIC LETTER MEEM	# 
			{ L"\x0001\xEE2C",L"\x0645" }, //( ‎𞸬‎ → ‎م‎ ) ARABIC MATHEMATICAL INITIAL MEEM → ARABIC LETTER MEEM	# 
			{ L"\x0001\xEE6C",L"\x0645" }, //( ‎𞹬‎ → ‎م‎ ) ARABIC MATHEMATICAL STRETCHED MEEM → ARABIC LETTER MEEM	# 
			{ L"\x0001\xEE8C",L"\x0645" }, //( ‎𞺌‎ → ‎م‎ ) ARABIC MATHEMATICAL LOOPED MEEM → ARABIC LETTER MEEM	# 
			{ L"\x0001\xEEAC",L"\x0645" }, //( ‎𞺬‎ → ‎م‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK MEEM → ARABIC LETTER MEEM	# 
			{ L"\xFEE3",L"\x0645" }, //( ‎ﻣ‎ → ‎م‎ ) ARABIC LETTER MEEM INITIAL FORM → ARABIC LETTER MEEM	# 
			{ L"\xFEE4",L"\x0645" }, //( ‎ﻤ‎ → ‎م‎ ) ARABIC LETTER MEEM MEDIAL FORM → ARABIC LETTER MEEM	# 
			{ L"\xFEE2",L"\x0645" }, //( ‎ﻢ‎ → ‎م‎ ) ARABIC LETTER MEEM FINAL FORM → ARABIC LETTER MEEM	# 
			{ L"\xFEE1",L"\x0645" }, //( ‎ﻡ‎ → ‎م‎ ) ARABIC LETTER MEEM ISOLATED FORM → ARABIC LETTER MEEM	# 

			{ L"\x08A7",L"\x0645\x06DB" }, //( ‎ࢧ‎ → ‎مۛ‎ ) ARABIC LETTER MEEM WITH THREE DOTS ABOVE → ARABIC LETTER MEEM, ARABIC SMALL HIGH THREE DOTS	# 

			{ L"\x06FE",L"\x0645\x0348" }, //( ‎۾‎ → ‎م͈‎ ) ARABIC SIGN SINDHI POSTPOSITION MEN → ARABIC LETTER MEEM, COMBINING DOUBLE VERTICAL LINE BELOW	# 

			{ L"\xFC88",L"\x0645\x006C" }, //( ‎ﲈ‎ → ‎مl‎ ) ARABIC LIGATURE MEEM WITH ALEF FINAL FORM → ARABIC LETTER MEEM, LATIN SMALL LETTER L	# →‎ما‎→

			{ L"\xFCCE",L"\x0645\x062C" }, //( ‎ﳎ‎ → ‎مج‎ ) ARABIC LIGATURE MEEM WITH JEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER JEEM	# 
			{ L"\xFC45",L"\x0645\x062C" }, //( ‎ﱅ‎ → ‎مج‎ ) ARABIC LIGATURE MEEM WITH JEEM ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER JEEM	# 

			{ L"\xFD8C",L"\x0645\x062C\x062D" }, //( ‎ﶌ‎ → ‎مجح‎ ) ARABIC LIGATURE MEEM WITH JEEM WITH HAH INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER JEEM, ARABIC LETTER HAH	# 

			{ L"\xFD92",L"\x0645\x062C\x062E" }, //( ‎ﶒ‎ → ‎مجخ‎ ) ARABIC LIGATURE MEEM WITH JEEM WITH KHAH INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER JEEM, ARABIC LETTER KHAH	# 

			{ L"\xFD8D",L"\x0645\x062C\x0645" }, //( ‎ﶍ‎ → ‎مجم‎ ) ARABIC LIGATURE MEEM WITH JEEM WITH MEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDC0",L"\x0645\x062C\x0649" }, //( ‎ﷀ‎ → ‎مجى‎ ) ARABIC LIGATURE MEEM WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER MEEM, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎مجي‎→

			{ L"\xFCCF",L"\x0645\x062D" }, //( ‎ﳏ‎ → ‎مح‎ ) ARABIC LIGATURE MEEM WITH HAH INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER HAH	# 
			{ L"\xFC46",L"\x0645\x062D" }, //( ‎ﱆ‎ → ‎مح‎ ) ARABIC LIGATURE MEEM WITH HAH ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER HAH	# 

			{ L"\xFD89",L"\x0645\x062D\x062C" }, //( ‎ﶉ‎ → ‎محج‎ ) ARABIC LIGATURE MEEM WITH HAH WITH JEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER HAH, ARABIC LETTER JEEM	# 

			{ L"\xFD8A",L"\x0645\x062D\x0645" }, //( ‎ﶊ‎ → ‎محم‎ ) ARABIC LIGATURE MEEM WITH HAH WITH MEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER HAH, ARABIC LETTER MEEM	# 

			{ L"\xFDF4",L"\x0645\x062D\x0645\x062F" }, //( ‎ﷴ‎ → ‎محمد‎ ) ARABIC LIGATURE MOHAMMAD ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER HAH, ARABIC LETTER MEEM, ARABIC LETTER DAL	# 

			{ L"\xFD8B",L"\x0645\x062D\x0649" }, //( ‎ﶋ‎ → ‎محى‎ ) ARABIC LIGATURE MEEM WITH HAH WITH YEH FINAL FORM → ARABIC LETTER MEEM, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎محي‎→

			{ L"\xFCD0",L"\x0645\x062E" }, //( ‎ﳐ‎ → ‎مخ‎ ) ARABIC LIGATURE MEEM WITH KHAH INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER KHAH	# 
			{ L"\xFC47",L"\x0645\x062E" }, //( ‎ﱇ‎ → ‎مخ‎ ) ARABIC LIGATURE MEEM WITH KHAH ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER KHAH	# 

			{ L"\xFD8E",L"\x0645\x062E\x062C" }, //( ‎ﶎ‎ → ‎مخج‎ ) ARABIC LIGATURE MEEM WITH KHAH WITH JEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER KHAH, ARABIC LETTER JEEM	# 

			{ L"\xFD8F",L"\x0645\x062E\x0645" }, //( ‎ﶏ‎ → ‎مخم‎ ) ARABIC LIGATURE MEEM WITH KHAH WITH MEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER KHAH, ARABIC LETTER MEEM	# 

			{ L"\xFDB9",L"\x0645\x062E\x0649" }, //( ‎ﶹ‎ → ‎مخى‎ ) ARABIC LIGATURE MEEM WITH KHAH WITH YEH FINAL FORM → ARABIC LETTER MEEM, ARABIC LETTER KHAH, ARABIC LETTER ALEF MAKSURA	# →‎مخي‎→

			{ L"\xFCD1",L"\x0645\x0645" }, //( ‎ﳑ‎ → ‎مم‎ ) ARABIC LIGATURE MEEM WITH MEEM INITIAL FORM → ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 
			{ L"\xFC89",L"\x0645\x0645" }, //( ‎ﲉ‎ → ‎مم‎ ) ARABIC LIGATURE MEEM WITH MEEM FINAL FORM → ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 
			{ L"\xFC48",L"\x0645\x0645" }, //( ‎ﱈ‎ → ‎مم‎ ) ARABIC LIGATURE MEEM WITH MEEM ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER MEEM	# 

			{ L"\xFDB1",L"\x0645\x0645\x0649" }, //( ‎ﶱ‎ → ‎ممى‎ ) ARABIC LIGATURE MEEM WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER MEEM, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎ممي‎→

			{ L"\xFC49",L"\x0645\x0649" }, //( ‎ﱉ‎ → ‎مى‎ ) ARABIC LIGATURE MEEM WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC4A",L"\x0645\x0649" }, //( ‎ﱊ‎ → ‎مى‎ ) ARABIC LIGATURE MEEM WITH YEH ISOLATED FORM → ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎مي‎→

			{ L"\x0001\xEE0D",L"\x0646" }, //( ‎𞸍‎ → ‎ن‎ ) ARABIC MATHEMATICAL NOON → ARABIC LETTER NOON	# 
			{ L"\x0001\xEE2D",L"\x0646" }, //( ‎𞸭‎ → ‎ن‎ ) ARABIC MATHEMATICAL INITIAL NOON → ARABIC LETTER NOON	# 
			{ L"\x0001\xEE4D",L"\x0646" }, //( ‎𞹍‎ → ‎ن‎ ) ARABIC MATHEMATICAL TAILED NOON → ARABIC LETTER NOON	# 
			{ L"\x0001\xEE6D",L"\x0646" }, //( ‎𞹭‎ → ‎ن‎ ) ARABIC MATHEMATICAL STRETCHED NOON → ARABIC LETTER NOON	# 
			{ L"\x0001\xEE8D",L"\x0646" }, //( ‎𞺍‎ → ‎ن‎ ) ARABIC MATHEMATICAL LOOPED NOON → ARABIC LETTER NOON	# 
			{ L"\x0001\xEEAD",L"\x0646" }, //( ‎𞺭‎ → ‎ن‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK NOON → ARABIC LETTER NOON	# 
			{ L"\xFEE7",L"\x0646" }, //( ‎ﻧ‎ → ‎ن‎ ) ARABIC LETTER NOON INITIAL FORM → ARABIC LETTER NOON	# 
			{ L"\xFEE8",L"\x0646" }, //( ‎ﻨ‎ → ‎ن‎ ) ARABIC LETTER NOON MEDIAL FORM → ARABIC LETTER NOON	# 
			{ L"\xFEE6",L"\x0646" }, //( ‎ﻦ‎ → ‎ن‎ ) ARABIC LETTER NOON FINAL FORM → ARABIC LETTER NOON	# 
			{ L"\xFEE5",L"\x0646" }, //( ‎ﻥ‎ → ‎ن‎ ) ARABIC LETTER NOON ISOLATED FORM → ARABIC LETTER NOON	# 

			{ L"\x0768",L"\x0646\x0615" }, //( ‎ݨ‎ → ‎نؕ‎ ) ARABIC LETTER NOON WITH SMALL TAH → ARABIC LETTER NOON, ARABIC SMALL HIGH TAH	# 

			{ L"\x0769",L"\x0646\x0306" }, //( ‎ݩ‎ → ‎ن̆‎ ) ARABIC LETTER NOON WITH SMALL V → ARABIC LETTER NOON, COMBINING BREVE	# →‎نٚ‎→

			{ L"\xFCD6",L"\x0646\x006F" }, //( ‎ﳖ‎ → ‎نo‎ ) ARABIC LIGATURE NOON WITH HEH INITIAL FORM → ARABIC LETTER NOON, LATIN SMALL LETTER O	# →‎نه‎→
			{ L"\xFCEF",L"\x0646\x006F" }, //( ‎ﳯ‎ → ‎نo‎ ) ARABIC LIGATURE NOON WITH HEH MEDIAL FORM → ARABIC LETTER NOON, LATIN SMALL LETTER O	# →‎نه‎→

			{ L"\xFDB8",L"\x0646\x062C\x062D" }, //( ‎ﶸ‎ → ‎نجح‎ ) ARABIC LIGATURE NOON WITH JEEM WITH HAH INITIAL FORM → ARABIC LETTER NOON, ARABIC LETTER JEEM, ARABIC LETTER HAH	# 
			{ L"\xFDBD",L"\x0646\x062C\x062D" }, //( ‎ﶽ‎ → ‎نجح‎ ) ARABIC LIGATURE NOON WITH JEEM WITH HAH FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER JEEM, ARABIC LETTER HAH	# 

			{ L"\xFD98",L"\x0646\x062C\x0645" }, //( ‎ﶘ‎ → ‎نجم‎ ) ARABIC LIGATURE NOON WITH JEEM WITH MEEM INITIAL FORM → ARABIC LETTER NOON, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 
			{ L"\xFD97",L"\x0646\x062C\x0645" }, //( ‎ﶗ‎ → ‎نجم‎ ) ARABIC LIGATURE NOON WITH JEEM WITH MEEM FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER JEEM, ARABIC LETTER MEEM	# 

			{ L"\xFD99",L"\x0646\x062C\x0649" }, //( ‎ﶙ‎ → ‎نجى‎ ) ARABIC LIGATURE NOON WITH JEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDC7",L"\x0646\x062C\x0649" }, //( ‎ﷇ‎ → ‎نجى‎ ) ARABIC LIGATURE NOON WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎نجي‎→

			{ L"\xFCD3",L"\x0646\x062D" }, //( ‎ﳓ‎ → ‎نح‎ ) ARABIC LIGATURE NOON WITH HAH INITIAL FORM → ARABIC LETTER NOON, ARABIC LETTER HAH	# 
			{ L"\xFC4C",L"\x0646\x062D" }, //( ‎ﱌ‎ → ‎نح‎ ) ARABIC LIGATURE NOON WITH HAH ISOLATED FORM → ARABIC LETTER NOON, ARABIC LETTER HAH	# 

			{ L"\xFD95",L"\x0646\x062D\x0645" }, //( ‎ﶕ‎ → ‎نحم‎ ) ARABIC LIGATURE NOON WITH HAH WITH MEEM INITIAL FORM → ARABIC LETTER NOON, ARABIC LETTER HAH, ARABIC LETTER MEEM	# 

			{ L"\xFD96",L"\x0646\x062D\x0649" }, //( ‎ﶖ‎ → ‎نحى‎ ) ARABIC LIGATURE NOON WITH HAH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFDB3",L"\x0646\x062D\x0649" }, //( ‎ﶳ‎ → ‎نحى‎ ) ARABIC LIGATURE NOON WITH HAH WITH YEH FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎نحي‎→

			{ L"\xFCD4",L"\x0646\x062E" }, //( ‎ﳔ‎ → ‎نخ‎ ) ARABIC LIGATURE NOON WITH KHAH INITIAL FORM → ARABIC LETTER NOON, ARABIC LETTER KHAH	# 
			{ L"\xFC4D",L"\x0646\x062E" }, //( ‎ﱍ‎ → ‎نخ‎ ) ARABIC LIGATURE NOON WITH KHAH ISOLATED FORM → ARABIC LETTER NOON, ARABIC LETTER KHAH	# 

			{ L"\xFC8A",L"\x0646\x0631" }, //( ‎ﲊ‎ → ‎نر‎ ) ARABIC LIGATURE NOON WITH REH FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER REH	# 

			{ L"\xFC8B",L"\x0646\x0632" }, //( ‎ﲋ‎ → ‎نز‎ ) ARABIC LIGATURE NOON WITH ZAIN FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER ZAIN	# 

			{ L"\xFCD5",L"\x0646\x0645" }, //( ‎ﳕ‎ → ‎نم‎ ) ARABIC LIGATURE NOON WITH MEEM INITIAL FORM → ARABIC LETTER NOON, ARABIC LETTER MEEM	# 
			{ L"\xFCEE",L"\x0646\x0645" }, //( ‎ﳮ‎ → ‎نم‎ ) ARABIC LIGATURE NOON WITH MEEM MEDIAL FORM → ARABIC LETTER NOON, ARABIC LETTER MEEM	# 
			{ L"\xFC8C",L"\x0646\x0645" }, //( ‎ﲌ‎ → ‎نم‎ ) ARABIC LIGATURE NOON WITH MEEM FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER MEEM	# 
			{ L"\xFC4E",L"\x0646\x0645" }, //( ‎ﱎ‎ → ‎نم‎ ) ARABIC LIGATURE NOON WITH MEEM ISOLATED FORM → ARABIC LETTER NOON, ARABIC LETTER MEEM	# 

			{ L"\xFD9B",L"\x0646\x0645\x0649" }, //( ‎ﶛ‎ → ‎نمى‎ ) ARABIC LIGATURE NOON WITH MEEM WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFD9A",L"\x0646\x0645\x0649" }, //( ‎ﶚ‎ → ‎نمى‎ ) ARABIC LIGATURE NOON WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎نمي‎→

			{ L"\xFC8D",L"\x0646\x0646" }, //( ‎ﲍ‎ → ‎نن‎ ) ARABIC LIGATURE NOON WITH NOON FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER NOON	# 

			{ L"\xFC8E",L"\x0646\x0649" }, //( ‎ﲎ‎ → ‎نى‎ ) ARABIC LIGATURE NOON WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC4F",L"\x0646\x0649" }, //( ‎ﱏ‎ → ‎نى‎ ) ARABIC LIGATURE NOON WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER NOON, ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFC8F",L"\x0646\x0649" }, //( ‎ﲏ‎ → ‎نى‎ ) ARABIC LIGATURE NOON WITH YEH FINAL FORM → ARABIC LETTER NOON, ARABIC LETTER ALEF MAKSURA	# →‎ني‎→
			{ L"\xFC50",L"\x0646\x0649" }, //( ‎ﱐ‎ → ‎نى‎ ) ARABIC LIGATURE NOON WITH YEH ISOLATED FORM → ARABIC LETTER NOON, ARABIC LETTER ALEF MAKSURA	# →‎ني‎→

			{ L"\x06C2",L"\x06C0" }, //( ‎ۂ‎ → ‎ۀ‎ ) ARABIC LETTER HEH GOAL WITH HAMZA ABOVE → ARABIC LETTER HEH WITH YEH ABOVE	# →‎ﮤ‎→
			{ L"\xFBA5",L"\x06C0" }, //( ‎ﮥ‎ → ‎ۀ‎ ) ARABIC LETTER HEH WITH YEH ABOVE FINAL FORM → ARABIC LETTER HEH WITH YEH ABOVE	# 
			{ L"\xFBA4",L"\x06C0" }, //( ‎ﮤ‎ → ‎ۀ‎ ) ARABIC LETTER HEH WITH YEH ABOVE ISOLATED FORM → ARABIC LETTER HEH WITH YEH ABOVE	# 

			{ L"\x0001\x02E4",L"\x0648" }, //( 𐋤 → ‎و‎ ) COPTIC EPACT DIGIT FOUR → ARABIC LETTER WAW	# 
			{ L"\x0001\xEE05",L"\x0648" }, //( ‎𞸅‎ → ‎و‎ ) ARABIC MATHEMATICAL WAW → ARABIC LETTER WAW	# 
			{ L"\x0001\xEE85",L"\x0648" }, //( ‎𞺅‎ → ‎و‎ ) ARABIC MATHEMATICAL LOOPED WAW → ARABIC LETTER WAW	# 
			{ L"\x0001\xEEA5",L"\x0648" }, //( ‎𞺥‎ → ‎و‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK WAW → ARABIC LETTER WAW	# 
			{ L"\xFEEE",L"\x0648" }, //( ‎ﻮ‎ → ‎و‎ ) ARABIC LETTER WAW FINAL FORM → ARABIC LETTER WAW	# 
			{ L"\xFEED",L"\x0648" }, //( ‎ﻭ‎ → ‎و‎ ) ARABIC LETTER WAW ISOLATED FORM → ARABIC LETTER WAW	# 
			{ L"\x08B1",L"\x0648" }, //( ‎ࢱ‎ → ‎و‎ ) ARABIC LETTER STRAIGHT WAW → ARABIC LETTER WAW	# 

			{ L"\x06CB",L"\x0648\x06DB" }, //( ‎ۋ‎ → ‎وۛ‎ ) ARABIC LETTER VE → ARABIC LETTER WAW, ARABIC SMALL HIGH THREE DOTS	# 
			{ L"\xFBDF",L"\x0648\x06DB" }, //( ‎ﯟ‎ → ‎وۛ‎ ) ARABIC LETTER VE FINAL FORM → ARABIC LETTER WAW, ARABIC SMALL HIGH THREE DOTS	# →‎ۋ‎→
			{ L"\xFBDE",L"\x0648\x06DB" }, //( ‎ﯞ‎ → ‎وۛ‎ ) ARABIC LETTER VE ISOLATED FORM → ARABIC LETTER WAW, ARABIC SMALL HIGH THREE DOTS	# →‎ۋ‎→

			{ L"\x06C7",L"\x0648\x0313" }, //( ‎ۇ‎ → ‎و̓‎ ) ARABIC LETTER U → ARABIC LETTER WAW, COMBINING COMMA ABOVE	# →‎وُ‎→
			{ L"\xFBD8",L"\x0648\x0313" }, //( ‎ﯘ‎ → ‎و̓‎ ) ARABIC LETTER U FINAL FORM → ARABIC LETTER WAW, COMBINING COMMA ABOVE	# →‎ۇ‎→→‎وُ‎→
			{ L"\xFBD7",L"\x0648\x0313" }, //( ‎ﯗ‎ → ‎و̓‎ ) ARABIC LETTER U ISOLATED FORM → ARABIC LETTER WAW, COMBINING COMMA ABOVE	# →‎ۇ‎→→‎وُ‎→

			{ L"\x06C6",L"\x0648\x0306" }, //( ‎ۆ‎ → ‎و̆‎ ) ARABIC LETTER OE → ARABIC LETTER WAW, COMBINING BREVE	# →‎وٚ‎→
			{ L"\xFBDA",L"\x0648\x0306" }, //( ‎ﯚ‎ → ‎و̆‎ ) ARABIC LETTER OE FINAL FORM → ARABIC LETTER WAW, COMBINING BREVE	# →‎ۆ‎→→‎وٚ‎→
			{ L"\xFBD9",L"\x0648\x0306" }, //( ‎ﯙ‎ → ‎و̆‎ ) ARABIC LETTER OE ISOLATED FORM → ARABIC LETTER WAW, COMBINING BREVE	# →‎ۆ‎→→‎وٚ‎→

			{ L"\x06C9",L"\x0648\x0302" }, //( ‎ۉ‎ → ‎و̂‎ ) ARABIC LETTER KIRGHIZ YU → ARABIC LETTER WAW, COMBINING CIRCUMFLEX ACCENT	# →‎وٛ‎→
			{ L"\xFBE3",L"\x0648\x0302" }, //( ‎ﯣ‎ → ‎و̂‎ ) ARABIC LETTER KIRGHIZ YU FINAL FORM → ARABIC LETTER WAW, COMBINING CIRCUMFLEX ACCENT	# →‎ۉ‎→→‎وٛ‎→
			{ L"\xFBE2",L"\x0648\x0302" }, //( ‎ﯢ‎ → ‎و̂‎ ) ARABIC LETTER KIRGHIZ YU ISOLATED FORM → ARABIC LETTER WAW, COMBINING CIRCUMFLEX ACCENT	# →‎ۉ‎→→‎وٛ‎→

			{ L"\x06C8",L"\x0648\x0670" }, //( ‎ۈ‎ → ‎وٰ‎ ) ARABIC LETTER YU → ARABIC LETTER WAW, ARABIC LETTER SUPERSCRIPT ALEF	# 
			{ L"\xFBDC",L"\x0648\x0670" }, //( ‎ﯜ‎ → ‎وٰ‎ ) ARABIC LETTER YU FINAL FORM → ARABIC LETTER WAW, ARABIC LETTER SUPERSCRIPT ALEF	# →‎ۈ‎→
			{ L"\xFBDB",L"\x0648\x0670" }, //( ‎ﯛ‎ → ‎وٰ‎ ) ARABIC LETTER YU ISOLATED FORM → ARABIC LETTER WAW, ARABIC LETTER SUPERSCRIPT ALEF	# →‎ۈ‎→

			{ L"\x0624",L"\x0648\x0674" }, //( ‎ؤ‎ → ‎وٴ‎ ) ARABIC LETTER WAW WITH HAMZA ABOVE → ARABIC LETTER WAW, ARABIC LETTER HIGH HAMZA	# →‎ٶ‎→
			{ L"\xFE86",L"\x0648\x0674" }, //( ‎ﺆ‎ → ‎وٴ‎ ) ARABIC LETTER WAW WITH HAMZA ABOVE FINAL FORM → ARABIC LETTER WAW, ARABIC LETTER HIGH HAMZA	# →‎ٶ‎→
			{ L"\xFE85",L"\x0648\x0674" }, //( ‎ﺅ‎ → ‎وٴ‎ ) ARABIC LETTER WAW WITH HAMZA ABOVE ISOLATED FORM → ARABIC LETTER WAW, ARABIC LETTER HIGH HAMZA	# →‎ٶ‎→
			{ L"\x0676",L"\x0648\x0674" }, //( ‎ٶ‎ → ‎وٴ‎ ) ARABIC LETTER HIGH HAMZA WAW → ARABIC LETTER WAW, ARABIC LETTER HIGH HAMZA	# 

			{ L"\x0677",L"\x0648\x0313\x0674" }, //( ‎ٷ‎ → ‎و̓ٴ‎ ) ARABIC LETTER U WITH HAMZA ABOVE → ARABIC LETTER WAW, COMBINING COMMA ABOVE, ARABIC LETTER HIGH HAMZA	# →‎ۇٴ‎→
			{ L"\xFBDD",L"\x0648\x0313\x0674" }, //( ‎ﯝ‎ → ‎و̓ٴ‎ ) ARABIC LETTER U WITH HAMZA ABOVE ISOLATED FORM → ARABIC LETTER WAW, COMBINING COMMA ABOVE, ARABIC LETTER HIGH HAMZA	# →‎ۇٴ‎→

			{ L"\xFDF8",L"\x0648\x0633\x0644\x0645" }, //( ‎ﷸ‎ → ‎وسلم‎ ) ARABIC LIGATURE WASALLAM ISOLATED FORM → ARABIC LETTER WAW, ARABIC LETTER SEEN, ARABIC LETTER LAM, ARABIC LETTER MEEM	# 

			{ L"\xFBE1",L"\x06C5" }, //( ‎ﯡ‎ → ‎ۅ‎ ) ARABIC LETTER KIRGHIZ OE FINAL FORM → ARABIC LETTER KIRGHIZ OE	# 
			{ L"\xFBE0",L"\x06C5" }, //( ‎ﯠ‎ → ‎ۅ‎ ) ARABIC LETTER KIRGHIZ OE ISOLATED FORM → ARABIC LETTER KIRGHIZ OE	# 

			{ L"\x066E",L"\x0649" }, //( ‎ٮ‎ → ‎ى‎ ) ARABIC LETTER DOTLESS BEH → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\x0001\xEE1C",L"\x0649" }, //( ‎𞸜‎ → ‎ى‎ ) ARABIC MATHEMATICAL DOTLESS BEH → ARABIC LETTER ALEF MAKSURA	# →‎ٮ‎→
			{ L"\x0001\xEE7C",L"\x0649" }, //( ‎𞹼‎ → ‎ى‎ ) ARABIC MATHEMATICAL STRETCHED DOTLESS BEH → ARABIC LETTER ALEF MAKSURA	# →‎ٮ‎→
			{ L"\x06BA",L"\x0649" }, //( ‎ں‎ → ‎ى‎ ) ARABIC LETTER NOON GHUNNA → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\x0001\xEE1D",L"\x0649" }, //( ‎𞸝‎ → ‎ى‎ ) ARABIC MATHEMATICAL DOTLESS NOON → ARABIC LETTER ALEF MAKSURA	# →‎ں‎→
			{ L"\x0001\xEE5D",L"\x0649" }, //( ‎𞹝‎ → ‎ى‎ ) ARABIC MATHEMATICAL TAILED DOTLESS NOON → ARABIC LETTER ALEF MAKSURA	# →‎ں‎→
			{ L"\xFB9F",L"\x0649" }, //( ‎ﮟ‎ → ‎ى‎ ) ARABIC LETTER NOON GHUNNA FINAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ں‎→
			{ L"\xFB9E",L"\x0649" }, //( ‎ﮞ‎ → ‎ى‎ ) ARABIC LETTER NOON GHUNNA ISOLATED FORM → ARABIC LETTER ALEF MAKSURA	# →‎ں‎→
			{ L"\xFBE8",L"\x0649" }, //( ‎ﯨ‎ → ‎ى‎ ) ARABIC LETTER UIGHUR KAZAKH KIRGHIZ ALEF MAKSURA INITIAL FORM → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFBE9",L"\x0649" }, //( ‎ﯩ‎ → ‎ى‎ ) ARABIC LETTER UIGHUR KAZAKH KIRGHIZ ALEF MAKSURA MEDIAL FORM → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFEF0",L"\x0649" }, //( ‎ﻰ‎ → ‎ى‎ ) ARABIC LETTER ALEF MAKSURA FINAL FORM → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFEEF",L"\x0649" }, //( ‎ﻯ‎ → ‎ى‎ ) ARABIC LETTER ALEF MAKSURA ISOLATED FORM → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\x064A",L"\x0649" }, //( ‎ي‎ → ‎ى‎ ) ARABIC LETTER YEH → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\x0001\xEE09",L"\x0649" }, //( ‎𞸉‎ → ‎ى‎ ) ARABIC MATHEMATICAL YEH → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\x0001\xEE29",L"\x0649" }, //( ‎𞸩‎ → ‎ى‎ ) ARABIC MATHEMATICAL INITIAL YEH → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\x0001\xEE49",L"\x0649" }, //( ‎𞹉‎ → ‎ى‎ ) ARABIC MATHEMATICAL TAILED YEH → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\x0001\xEE69",L"\x0649" }, //( ‎𞹩‎ → ‎ى‎ ) ARABIC MATHEMATICAL STRETCHED YEH → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\x0001\xEE89",L"\x0649" }, //( ‎𞺉‎ → ‎ى‎ ) ARABIC MATHEMATICAL LOOPED YEH → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\x0001\xEEA9",L"\x0649" }, //( ‎𞺩‎ → ‎ى‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK YEH → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\xFEF3",L"\x0649" }, //( ‎ﻳ‎ → ‎ى‎ ) ARABIC LETTER YEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\xFEF4",L"\x0649" }, //( ‎ﻴ‎ → ‎ى‎ ) ARABIC LETTER YEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\xFEF2",L"\x0649" }, //( ‎ﻲ‎ → ‎ى‎ ) ARABIC LETTER YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\xFEF1",L"\x0649" }, //( ‎ﻱ‎ → ‎ى‎ ) ARABIC LETTER YEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\x06CC",L"\x0649" }, //( ‎ی‎ → ‎ى‎ ) ARABIC LETTER FARSI YEH → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\xFBFE",L"\x0649" }, //( ‎ﯾ‎ → ‎ى‎ ) ARABIC LETTER FARSI YEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ی‎→
			{ L"\xFBFF",L"\x0649" }, //( ‎ﯿ‎ → ‎ى‎ ) ARABIC LETTER FARSI YEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ی‎→
			{ L"\xFBFD",L"\x0649" }, //( ‎ﯽ‎ → ‎ى‎ ) ARABIC LETTER FARSI YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ﻰ‎→
			{ L"\xFBFC",L"\x0649" }, //( ‎ﯼ‎ → ‎ى‎ ) ARABIC LETTER FARSI YEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA	# 
			{ L"\x06D2",L"\x0649" }, //( ‎ے‎ → ‎ى‎ ) ARABIC LETTER YEH BARREE → ARABIC LETTER ALEF MAKSURA	# →‎ي‎→
			{ L"\xFBAF",L"\x0649" }, //( ‎ﮯ‎ → ‎ى‎ ) ARABIC LETTER YEH BARREE FINAL FORM → ARABIC LETTER ALEF MAKSURA	# →‎ے‎→→‎ي‎→
			{ L"\xFBAE",L"\x0649" }, //( ‎ﮮ‎ → ‎ى‎ ) ARABIC LETTER YEH BARREE ISOLATED FORM → ARABIC LETTER ALEF MAKSURA	# →‎ے‎→→‎ي‎→

			{ L"\x0679",L"\x0649\x0615" }, //( ‎ٹ‎ → ‎ىؕ‎ ) ARABIC LETTER TTEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ٮؕ‎→
			{ L"\xFB68",L"\x0649\x0615" }, //( ‎ﭨ‎ → ‎ىؕ‎ ) ARABIC LETTER TTEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ٹ‎→→‎ٮؕ‎→
			{ L"\xFB69",L"\x0649\x0615" }, //( ‎ﭩ‎ → ‎ىؕ‎ ) ARABIC LETTER TTEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ٹ‎→→‎ٮؕ‎→
			{ L"\xFB67",L"\x0649\x0615" }, //( ‎ﭧ‎ → ‎ىؕ‎ ) ARABIC LETTER TTEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ٹ‎→→‎ٮؕ‎→
			{ L"\xFB66",L"\x0649\x0615" }, //( ‎ﭦ‎ → ‎ىؕ‎ ) ARABIC LETTER TTEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ٹ‎→→‎ٮؕ‎→
			{ L"\x06BB",L"\x0649\x0615" }, //( ‎ڻ‎ → ‎ىؕ‎ ) ARABIC LETTER RNOON → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ںؕ‎→
			{ L"\xFBA2",L"\x0649\x0615" }, //( ‎ﮢ‎ → ‎ىؕ‎ ) ARABIC LETTER RNOON INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ڻ‎→→‎ںؕ‎→
			{ L"\xFBA3",L"\x0649\x0615" }, //( ‎ﮣ‎ → ‎ىؕ‎ ) ARABIC LETTER RNOON MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ڻ‎→→‎ںؕ‎→
			{ L"\xFBA1",L"\x0649\x0615" }, //( ‎ﮡ‎ → ‎ىؕ‎ ) ARABIC LETTER RNOON FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ڻ‎→→‎ںؕ‎→
			{ L"\xFBA0",L"\x0649\x0615" }, //( ‎ﮠ‎ → ‎ىؕ‎ ) ARABIC LETTER RNOON ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH TAH	# →‎ڻ‎→→‎ںؕ‎→

			{ L"\x067E",L"\x0649\x06DB" }, //( ‎پ‎ → ‎ىۛ‎ ) ARABIC LETTER PEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ڽ‎→→‎ںۛ‎→
			{ L"\xFB58",L"\x0649\x06DB" }, //( ‎ﭘ‎ → ‎ىۛ‎ ) ARABIC LETTER PEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎پ‎→→‎ڽ‎→→‎ںۛ‎→
			{ L"\xFB59",L"\x0649\x06DB" }, //( ‎ﭙ‎ → ‎ىۛ‎ ) ARABIC LETTER PEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎پ‎→→‎ڽ‎→→‎ںۛ‎→
			{ L"\xFB57",L"\x0649\x06DB" }, //( ‎ﭗ‎ → ‎ىۛ‎ ) ARABIC LETTER PEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎پ‎→→‎ڽ‎→→‎ںۛ‎→
			{ L"\xFB56",L"\x0649\x06DB" }, //( ‎ﭖ‎ → ‎ىۛ‎ ) ARABIC LETTER PEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎پ‎→→‎ڽ‎→→‎ںۛ‎→
			{ L"\x062B",L"\x0649\x06DB" }, //( ‎ث‎ → ‎ىۛ‎ ) ARABIC LETTER THEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ٮۛ‎→
			{ L"\x0001\xEE16",L"\x0649\x06DB" }, //( ‎𞸖‎ → ‎ىۛ‎ ) ARABIC MATHEMATICAL THEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\x0001\xEE36",L"\x0649\x06DB" }, //( ‎𞸶‎ → ‎ىۛ‎ ) ARABIC MATHEMATICAL INITIAL THEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\x0001\xEE76",L"\x0649\x06DB" }, //( ‎𞹶‎ → ‎ىۛ‎ ) ARABIC MATHEMATICAL STRETCHED THEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\x0001\xEE96",L"\x0649\x06DB" }, //( ‎𞺖‎ → ‎ىۛ‎ ) ARABIC MATHEMATICAL LOOPED THEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\x0001\xEEB6",L"\x0649\x06DB" }, //( ‎𞺶‎ → ‎ىۛ‎ ) ARABIC MATHEMATICAL DOUBLE-STRUCK THEH → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\xFE9B",L"\x0649\x06DB" }, //( ‎ﺛ‎ → ‎ىۛ‎ ) ARABIC LETTER THEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\xFE9C",L"\x0649\x06DB" }, //( ‎ﺜ‎ → ‎ىۛ‎ ) ARABIC LETTER THEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\xFE9A",L"\x0649\x06DB" }, //( ‎ﺚ‎ → ‎ىۛ‎ ) ARABIC LETTER THEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\xFE99",L"\x0649\x06DB" }, //( ‎ﺙ‎ → ‎ىۛ‎ ) ARABIC LETTER THEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ث‎→→‎ٮۛ‎→
			{ L"\x06BD",L"\x0649\x06DB" }, //( ‎ڽ‎ → ‎ىۛ‎ ) ARABIC LETTER NOON WITH THREE DOTS ABOVE → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎ںۛ‎→
			{ L"\x06D1",L"\x0649\x06DB" }, //( ‎ۑ‎ → ‎ىۛ‎ ) ARABIC LETTER YEH WITH THREE DOTS BELOW → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎پ‎→→‎ڽ‎→→‎ںۛ‎→
			{ L"\x063F",L"\x0649\x06DB" }, //( ‎ؿ‎ → ‎ىۛ‎ ) ARABIC LETTER FARSI YEH WITH THREE DOTS ABOVE → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS	# →‎یۛ‎→

			{ L"\x0756",L"\x0649\x0306" }, //( ‎ݖ‎ → ‎ى̆‎ ) ARABIC LETTER BEH WITH SMALL V → ARABIC LETTER ALEF MAKSURA, COMBINING BREVE	# →‎ٮٚ‎→
			{ L"\x06CE",L"\x0649\x0306" }, //( ‎ێ‎ → ‎ى̆‎ ) ARABIC LETTER YEH WITH SMALL V → ARABIC LETTER ALEF MAKSURA, COMBINING BREVE	# →‎یٚ‎→

			{ L"\x063D",L"\x0649\x0302" }, //( ‎ؽ‎ → ‎ى̂‎ ) ARABIC LETTER FARSI YEH WITH INVERTED V → ARABIC LETTER ALEF MAKSURA, COMBINING CIRCUMFLEX ACCENT	# →‎یٛ‎→

			{ L"\x08A8",L"\x0649\x0654" }, //( ‎ࢨ‎ → ‎ىٔ‎ ) ARABIC LETTER YEH WITH TWO DOTS BELOW AND HAMZA ABOVE → ARABIC LETTER ALEF MAKSURA, ARABIC HAMZA ABOVE	# →‎ئ‎→

			{ L"\xFC90",L"\x0649\x0670" }, //( ‎ﲐ‎ → ‎ىٰ‎ ) ARABIC LIGATURE ALEF MAKSURA WITH SUPERSCRIPT ALEF FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER SUPERSCRIPT ALEF	# 
			{ L"\xFC5D",L"\x0649\x0670" }, //( ‎ﱝ‎ → ‎ىٰ‎ ) ARABIC LIGATURE ALEF MAKSURA WITH SUPERSCRIPT ALEF ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER SUPERSCRIPT ALEF	# 

			{ L"\xFCDE",L"\x0649\x006F" }, //( ‎ﳞ‎ → ‎ىo‎ ) ARABIC LIGATURE YEH WITH HEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, LATIN SMALL LETTER O	# →‎يه‎→
			{ L"\xFCF1",L"\x0649\x006F" }, //( ‎ﳱ‎ → ‎ىo‎ ) ARABIC LIGATURE YEH WITH HEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, LATIN SMALL LETTER O	# →‎يه‎→

			{ L"\xFCE6",L"\x0649\x06DB\x006F" }, //( ‎ﳦ‎ → ‎ىۛo‎ ) ARABIC LIGATURE THEH WITH HEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, LATIN SMALL LETTER O	# →‎ثه‎→

			{ L"\x0626",L"\x0649\x0674" }, //( ‎ئ‎ → ‎ىٴ‎ ) ARABIC LETTER YEH WITH HAMZA ABOVE → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA	# →‎ٸ‎→→‎يٴ‎→
			{ L"\xFE8B",L"\x0649\x0674" }, //( ‎ﺋ‎ → ‎ىٴ‎ ) ARABIC LETTER YEH WITH HAMZA ABOVE INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA	# →‎ئ‎→→‎ٸ‎→→‎يٴ‎→
			{ L"\xFE8C",L"\x0649\x0674" }, //( ‎ﺌ‎ → ‎ىٴ‎ ) ARABIC LETTER YEH WITH HAMZA ABOVE MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA	# →‎ئ‎→→‎ٸ‎→→‎يٴ‎→
			{ L"\xFE8A",L"\x0649\x0674" }, //( ‎ﺊ‎ → ‎ىٴ‎ ) ARABIC LETTER YEH WITH HAMZA ABOVE FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA	# →‎ئ‎→→‎ٸ‎→→‎يٴ‎→
			{ L"\xFE89",L"\x0649\x0674" }, //( ‎ﺉ‎ → ‎ىٴ‎ ) ARABIC LETTER YEH WITH HAMZA ABOVE ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA	# →‎ٸ‎→→‎يٴ‎→
			{ L"\x0678",L"\x0649\x0674" }, //( ‎ٸ‎ → ‎ىٴ‎ ) ARABIC LETTER HIGH HAMZA YEH → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA	# →‎يٴ‎→

			{ L"\xFBEB",L"\x0649\x0674\x006C" }, //( ‎ﯫ‎ → ‎ىٴl‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH ALEF FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, LATIN SMALL LETTER L	# →‎ئا‎→
			{ L"\xFBEA",L"\x0649\x0674\x006C" }, //( ‎ﯪ‎ → ‎ىٴl‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH ALEF ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, LATIN SMALL LETTER L	# →‎ئا‎→

			{ L"\xFC9B",L"\x0649\x0674\x006F" }, //( ‎ﲛ‎ → ‎ىٴo‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH HEH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, LATIN SMALL LETTER O	# →‎ئه‎→
			{ L"\xFCE0",L"\x0649\x0674\x006F" }, //( ‎ﳠ‎ → ‎ىٴo‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH HEH MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, LATIN SMALL LETTER O	# →‎ئه‎→
			{ L"\xFBED",L"\x0649\x0674\x006F" }, //( ‎ﯭ‎ → ‎ىٴo‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH AE FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, LATIN SMALL LETTER O	# →‎ئە‎→→‎ٴىo‎→→‎ئه‎→
			{ L"\xFBEC",L"\x0649\x0674\x006F" }, //( ‎ﯬ‎ → ‎ىٴo‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH AE ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, LATIN SMALL LETTER O	# →‎ئە‎→→‎ٴىo‎→→‎ئه‎→

			{ L"\xFBF8",L"\x0649\x0674\x067B" }, //( ‎ﯸ‎ → ‎ىٴٻ‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH E INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER BEEH	# →‎ئې‎→
			{ L"\xFBF7",L"\x0649\x0674\x067B" }, //( ‎ﯷ‎ → ‎ىٴٻ‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH E FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER BEEH	# →‎ئې‎→
			{ L"\xFBF6",L"\x0649\x0674\x067B" }, //( ‎ﯶ‎ → ‎ىٴٻ‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH E ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER BEEH	# →‎ئې‎→

			{ L"\xFC97",L"\x0649\x0674\x062C" }, //( ‎ﲗ‎ → ‎ىٴج‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH JEEM INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER JEEM	# →‎ئج‎→
			{ L"\xFC00",L"\x0649\x0674\x062C" }, //( ‎ﰀ‎ → ‎ىٴج‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH JEEM ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER JEEM	# →‎ئج‎→

			{ L"\xFC98",L"\x0649\x0674\x062D" }, //( ‎ﲘ‎ → ‎ىٴح‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH HAH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER HAH	# →‎ئح‎→
			{ L"\xFC01",L"\x0649\x0674\x062D" }, //( ‎ﰁ‎ → ‎ىٴح‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH HAH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER HAH	# →‎ئح‎→

			{ L"\xFC99",L"\x0649\x0674\x062E" }, //( ‎ﲙ‎ → ‎ىٴخ‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH KHAH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER KHAH	# →‎ئخ‎→

			{ L"\xFC64",L"\x0649\x0674\x0631" }, //( ‎ﱤ‎ → ‎ىٴر‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH REH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER REH	# →‎ئر‎→

			{ L"\xFC65",L"\x0649\x0674\x0632" }, //( ‎ﱥ‎ → ‎ىٴز‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH ZAIN FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ZAIN	# →‎ئز‎→

			{ L"\xFC9A",L"\x0649\x0674\x0645" }, //( ‎ﲚ‎ → ‎ىٴم‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH MEEM INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER MEEM	# →‎ئم‎→
			{ L"\xFCDF",L"\x0649\x0674\x0645" }, //( ‎ﳟ‎ → ‎ىٴم‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH MEEM MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER MEEM	# →‎ئم‎→
			{ L"\xFC66",L"\x0649\x0674\x0645" }, //( ‎ﱦ‎ → ‎ىٴم‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH MEEM FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER MEEM	# →‎ئم‎→
			{ L"\xFC02",L"\x0649\x0674\x0645" }, //( ‎ﰂ‎ → ‎ىٴم‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH MEEM ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER MEEM	# →‎ئم‎→

			{ L"\xFC67",L"\x0649\x0674\x0646" }, //( ‎ﱧ‎ → ‎ىٴن‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH NOON FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER NOON	# →‎ئن‎→

			{ L"\xFBEF",L"\x0649\x0674\x0648" }, //( ‎ﯯ‎ → ‎ىٴو‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH WAW FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW	# →‎ئو‎→
			{ L"\xFBEE",L"\x0649\x0674\x0648" }, //( ‎ﯮ‎ → ‎ىٴو‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH WAW ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW	# →‎ئو‎→

			{ L"\xFBF1",L"\x0649\x0674\x0648\x0313" }, //( ‎ﯱ‎ → ‎ىٴو̓‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH U FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW, COMBINING COMMA ABOVE	# →‎ئۇ‎→
			{ L"\xFBF0",L"\x0649\x0674\x0648\x0313" }, //( ‎ﯰ‎ → ‎ىٴو̓‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH U ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW, COMBINING COMMA ABOVE	# →‎ئۇ‎→

			{ L"\xFBF3",L"\x0649\x0674\x0648\x0306" }, //( ‎ﯳ‎ → ‎ىٴو̆‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH OE FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW, COMBINING BREVE	# →‎ئۆ‎→
			{ L"\xFBF2",L"\x0649\x0674\x0648\x0306" }, //( ‎ﯲ‎ → ‎ىٴو̆‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH OE ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW, COMBINING BREVE	# →‎ئۆ‎→

			{ L"\xFBF5",L"\x0649\x0674\x0648\x0670" }, //( ‎ﯵ‎ → ‎ىٴوٰ‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH YU FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW, ARABIC LETTER SUPERSCRIPT ALEF	# →‎ئۈ‎→
			{ L"\xFBF4",L"\x0649\x0674\x0648\x0670" }, //( ‎ﯴ‎ → ‎ىٴوٰ‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH YU ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER WAW, ARABIC LETTER SUPERSCRIPT ALEF	# →‎ئۈ‎→

			{ L"\xFBFB",L"\x0649\x0674\x0649" }, //( ‎ﯻ‎ → ‎ىٴى‎ ) ARABIC LIGATURE UIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WITH ALEF MAKSURA INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئى‎→
			{ L"\xFBFA",L"\x0649\x0674\x0649" }, //( ‎ﯺ‎ → ‎ىٴى‎ ) ARABIC LIGATURE UIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئى‎→
			{ L"\xFC68",L"\x0649\x0674\x0649" }, //( ‎ﱨ‎ → ‎ىٴى‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئى‎→
			{ L"\xFBF9",L"\x0649\x0674\x0649" }, //( ‎ﯹ‎ → ‎ىٴى‎ ) ARABIC LIGATURE UIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئى‎→
			{ L"\xFC03",L"\x0649\x0674\x0649" }, //( ‎ﰃ‎ → ‎ىٴى‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئى‎→
			{ L"\xFC69",L"\x0649\x0674\x0649" }, //( ‎ﱩ‎ → ‎ىٴى‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئي‎→→‎ٴىى‎→→‎ئى‎→
			{ L"\xFC04",L"\x0649\x0674\x0649" }, //( ‎ﰄ‎ → ‎ىٴى‎ ) ARABIC LIGATURE YEH WITH HAMZA ABOVE WITH YEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HIGH HAMZA, ARABIC LETTER ALEF MAKSURA	# →‎ئي‎→→‎ٴىى‎→→‎ئى‎→

			{ L"\xFCDA",L"\x0649\x062C" }, //( ‎ﳚ‎ → ‎ىج‎ ) ARABIC LIGATURE YEH WITH JEEM INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER JEEM	# →‎يج‎→
			{ L"\xFC55",L"\x0649\x062C" }, //( ‎ﱕ‎ → ‎ىج‎ ) ARABIC LIGATURE YEH WITH JEEM ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER JEEM	# →‎يج‎→

			{ L"\xFC11",L"\x0649\x06DB\x062C" }, //( ‎ﰑ‎ → ‎ىۛج‎ ) ARABIC LIGATURE THEH WITH JEEM ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER JEEM	# →‎ثج‎→

			{ L"\xFDAF",L"\x0649\x062C\x0649" }, //( ‎ﶯ‎ → ‎ىجى‎ ) ARABIC LIGATURE YEH WITH JEEM WITH YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER JEEM, ARABIC LETTER ALEF MAKSURA	# →‎يجي‎→

			{ L"\xFCDB",L"\x0649\x062D" }, //( ‎ﳛ‎ → ‎ىح‎ ) ARABIC LIGATURE YEH WITH HAH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HAH	# →‎يح‎→
			{ L"\xFC56",L"\x0649\x062D" }, //( ‎ﱖ‎ → ‎ىح‎ ) ARABIC LIGATURE YEH WITH HAH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HAH	# →‎يح‎→

			{ L"\xFDAE",L"\x0649\x062D\x0649" }, //( ‎ﶮ‎ → ‎ىحى‎ ) ARABIC LIGATURE YEH WITH HAH WITH YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER HAH, ARABIC LETTER ALEF MAKSURA	# →‎يحي‎→

			{ L"\xFCDC",L"\x0649\x062E" }, //( ‎ﳜ‎ → ‎ىخ‎ ) ARABIC LIGATURE YEH WITH KHAH INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER KHAH	# →‎يخ‎→
			{ L"\xFC57",L"\x0649\x062E" }, //( ‎ﱗ‎ → ‎ىخ‎ ) ARABIC LIGATURE YEH WITH KHAH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER KHAH	# →‎يخ‎→

			{ L"\xFC91",L"\x0649\x0631" }, //( ‎ﲑ‎ → ‎ىر‎ ) ARABIC LIGATURE YEH WITH REH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER REH	# →‎ير‎→

			{ L"\xFC76",L"\x0649\x06DB\x0631" }, //( ‎ﱶ‎ → ‎ىۛر‎ ) ARABIC LIGATURE THEH WITH REH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER REH	# →‎ثر‎→

			{ L"\xFC92",L"\x0649\x0632" }, //( ‎ﲒ‎ → ‎ىز‎ ) ARABIC LIGATURE YEH WITH ZAIN FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER ZAIN	# →‎يز‎→

			{ L"\xFC77",L"\x0649\x06DB\x0632" }, //( ‎ﱷ‎ → ‎ىۛز‎ ) ARABIC LIGATURE THEH WITH ZAIN FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ZAIN	# →‎ثز‎→

			{ L"\xFCDD",L"\x0649\x0645" }, //( ‎ﳝ‎ → ‎ىم‎ ) ARABIC LIGATURE YEH WITH MEEM INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM	# →‎يم‎→
			{ L"\xFCF0",L"\x0649\x0645" }, //( ‎ﳰ‎ → ‎ىم‎ ) ARABIC LIGATURE YEH WITH MEEM MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM	# →‎يم‎→
			{ L"\xFC93",L"\x0649\x0645" }, //( ‎ﲓ‎ → ‎ىم‎ ) ARABIC LIGATURE YEH WITH MEEM FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM	# →‎يم‎→
			{ L"\xFC58",L"\x0649\x0645" }, //( ‎ﱘ‎ → ‎ىم‎ ) ARABIC LIGATURE YEH WITH MEEM ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM	# →‎يم‎→

			{ L"\xFCA6",L"\x0649\x06DB\x0645" }, //( ‎ﲦ‎ → ‎ىۛم‎ ) ARABIC LIGATURE THEH WITH MEEM INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎ثم‎→
			{ L"\xFCE5",L"\x0649\x06DB\x0645" }, //( ‎ﳥ‎ → ‎ىۛم‎ ) ARABIC LIGATURE THEH WITH MEEM MEDIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎ثم‎→
			{ L"\xFC78",L"\x0649\x06DB\x0645" }, //( ‎ﱸ‎ → ‎ىۛم‎ ) ARABIC LIGATURE THEH WITH MEEM FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎ثم‎→
			{ L"\xFC12",L"\x0649\x06DB\x0645" }, //( ‎ﰒ‎ → ‎ىۛم‎ ) ARABIC LIGATURE THEH WITH MEEM ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER MEEM	# →‎ثم‎→

			{ L"\xFD9D",L"\x0649\x0645\x0645" }, //( ‎ﶝ‎ → ‎ىمم‎ ) ARABIC LIGATURE YEH WITH MEEM WITH MEEM INITIAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# →‎يمم‎→
			{ L"\xFD9C",L"\x0649\x0645\x0645" }, //( ‎ﶜ‎ → ‎ىمم‎ ) ARABIC LIGATURE YEH WITH MEEM WITH MEEM FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM, ARABIC LETTER MEEM	# →‎يمم‎→

			{ L"\xFDB0",L"\x0649\x0645\x0649" }, //( ‎ﶰ‎ → ‎ىمى‎ ) ARABIC LIGATURE YEH WITH MEEM WITH YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER MEEM, ARABIC LETTER ALEF MAKSURA	# →‎يمي‎→

			{ L"\xFC94",L"\x0649\x0646" }, //( ‎ﲔ‎ → ‎ىن‎ ) ARABIC LIGATURE YEH WITH NOON FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER NOON	# →‎ين‎→

			{ L"\xFC79",L"\x0649\x06DB\x0646" }, //( ‎ﱹ‎ → ‎ىۛن‎ ) ARABIC LIGATURE THEH WITH NOON FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER NOON	# →‎ثن‎→

			{ L"\xFC95",L"\x0649\x0649" }, //( ‎ﲕ‎ → ‎ىى‎ ) ARABIC LIGATURE YEH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER ALEF MAKSURA	# →‎يى‎→
			{ L"\xFC59",L"\x0649\x0649" }, //( ‎ﱙ‎ → ‎ىى‎ ) ARABIC LIGATURE YEH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER ALEF MAKSURA	# →‎يى‎→
			{ L"\xFC96",L"\x0649\x0649" }, //( ‎ﲖ‎ → ‎ىى‎ ) ARABIC LIGATURE YEH WITH YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER ALEF MAKSURA	# →‎يي‎→
			{ L"\xFC5A",L"\x0649\x0649" }, //( ‎ﱚ‎ → ‎ىى‎ ) ARABIC LIGATURE YEH WITH YEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC LETTER ALEF MAKSURA	# →‎يي‎→

			{ L"\xFC7A",L"\x0649\x06DB\x0649" }, //( ‎ﱺ‎ → ‎ىۛى‎ ) ARABIC LIGATURE THEH WITH ALEF MAKSURA FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎ثى‎→
			{ L"\xFC13",L"\x0649\x06DB\x0649" }, //( ‎ﰓ‎ → ‎ىۛى‎ ) ARABIC LIGATURE THEH WITH ALEF MAKSURA ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎ثى‎→
			{ L"\xFC7B",L"\x0649\x06DB\x0649" }, //( ‎ﱻ‎ → ‎ىۛى‎ ) ARABIC LIGATURE THEH WITH YEH FINAL FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎ثي‎→
			{ L"\xFC14",L"\x0649\x06DB\x0649" }, //( ‎ﰔ‎ → ‎ىۛى‎ ) ARABIC LIGATURE THEH WITH YEH ISOLATED FORM → ARABIC LETTER ALEF MAKSURA, ARABIC SMALL HIGH THREE DOTS, ARABIC LETTER ALEF MAKSURA	# →‎ثي‎→

			{ L"\xFBB1",L"\x06D3" }, //( ‎ﮱ‎ → ‎ۓ‎ ) ARABIC LETTER YEH BARREE WITH HAMZA ABOVE FINAL FORM → ARABIC LETTER YEH BARREE WITH HAMZA ABOVE	# 
			{ L"\xFBB0",L"\x06D3" }, //( ‎ﮰ‎ → ‎ۓ‎ ) ARABIC LETTER YEH BARREE WITH HAMZA ABOVE ISOLATED FORM → ARABIC LETTER YEH BARREE WITH HAMZA ABOVE	# 

			{ L"\x0001\x02B8",L"\x2D40" }, //( 𐊸 → ⵀ ) CARIAN LETTER SS → TIFINAGH LETTER YAH	# 

			{ L"\x205E",L"\x2D42" }, //( ⁞ → ⵂ ) VERTICAL FOUR DOTS → TIFINAGH LETTER TUAREG YAH	# 
			{ L"\x2E3D",L"\x2D42" }, //( ⸽ → ⵂ ) VERTICAL SIX DOTS → TIFINAGH LETTER TUAREG YAH	# →⁞→
			{ L"\x2999",L"\x2D42" }, //( ⦙ → ⵂ ) DOTTED FENCE → TIFINAGH LETTER TUAREG YAH	# →⁞→

			{ L"\xFE19",L"\x2D57" }, //( ︙ → ⵗ ) PRESENTATION FORM FOR VERTICAL HORIZONTAL ELLIPSIS → TIFINAGH LETTER TUAREG YAGH	# →⁝→
			{ L"\x205D",L"\x2D57" }, //( ⁝ → ⵗ ) TRICOLON → TIFINAGH LETTER TUAREG YAGH	# 
			{ L"\x22EE",L"\x2D57" }, //( ⋮ → ⵗ ) VERTICAL ELLIPSIS → TIFINAGH LETTER TUAREG YAGH	# →︙→→⁝→

			{ L"\x0906",L"\x0905\x093E" }, //( आ → अा ) DEVANAGARI LETTER AA → DEVANAGARI LETTER A, DEVANAGARI VOWEL SIGN AA	# 

			{ L"\x0912",L"\x0905\x093E\x0946" }, //( ऒ → अाॆ ) DEVANAGARI LETTER SHORT O → DEVANAGARI LETTER A, DEVANAGARI VOWEL SIGN AA, DEVANAGARI VOWEL SIGN SHORT E	# →अॊ→→आॆ→

			{ L"\x0913",L"\x0905\x093E\x0947" }, //( ओ → अाे ) DEVANAGARI LETTER O → DEVANAGARI LETTER A, DEVANAGARI VOWEL SIGN AA, DEVANAGARI VOWEL SIGN E	# →अो→→आे→

			{ L"\x0914",L"\x0905\x093E\x0948" }, //( औ → अाै ) DEVANAGARI LETTER AU → DEVANAGARI LETTER A, DEVANAGARI VOWEL SIGN AA, DEVANAGARI VOWEL SIGN AI	# →अौ→→आै→

			{ L"\x0904",L"\x0905\x0946" }, //( ऄ → अॆ ) DEVANAGARI LETTER SHORT A → DEVANAGARI LETTER A, DEVANAGARI VOWEL SIGN SHORT E	# 

			{ L"\x0911",L"\x0905\x0949" }, //( ऑ → अॉ ) DEVANAGARI LETTER CANDRA O → DEVANAGARI LETTER A, DEVANAGARI VOWEL SIGN CANDRA O	# 

			{ L"\x090D",L"\x090F\x0945" }, //( ऍ → एॅ ) DEVANAGARI LETTER CANDRA E → DEVANAGARI LETTER E, DEVANAGARI VOWEL SIGN CANDRA E	# 

			{ L"\x090E",L"\x090F\x0946" }, //( ऎ → एॆ ) DEVANAGARI LETTER SHORT E → DEVANAGARI LETTER E, DEVANAGARI VOWEL SIGN SHORT E	# 

			{ L"\x0910",L"\x090F\x0947" }, //( ऐ → एे ) DEVANAGARI LETTER AI → DEVANAGARI LETTER E, DEVANAGARI VOWEL SIGN E	# 

			{ L"\x0908",L"\x0930\x094D\x0907" }, //( ई → र्इ ) DEVANAGARI LETTER II → DEVANAGARI LETTER RA, DEVANAGARI SIGN VIRAMA, DEVANAGARI LETTER I	# 

			{ L"\x0ABD",L"\x093D" }, //( ઽ → ऽ ) GUJARATI SIGN AVAGRAHA → DEVANAGARI SIGN AVAGRAHA	# 

			{ L"\x0001\x11DC",L"\xA8FB" }, //( 𑇜 → ꣻ ) SHARADA HEADSTROKE → DEVANAGARI HEADSTROKE	# 

			{ L"\x0AC1",L"\x0941" }, //( ુ → ु ) GUJARATI VOWEL SIGN U → DEVANAGARI VOWEL SIGN U	# 

			{ L"\x0AC2",L"\x0942" }, //( ૂ → ू ) GUJARATI VOWEL SIGN UU → DEVANAGARI VOWEL SIGN UU	# 

			{ L"\x0A4B",L"\x0946" }, //( ੋ → ॆ ) GURMUKHI VOWEL SIGN OO → DEVANAGARI VOWEL SIGN SHORT E	# 

			{ L"\x0A4D",L"\x094D" }, //( ੍ → ् ) GURMUKHI SIGN VIRAMA → DEVANAGARI SIGN VIRAMA	# 
			{ L"\x0ACD",L"\x094D" }, //( ્ → ् ) GUJARATI SIGN VIRAMA → DEVANAGARI SIGN VIRAMA	# 

			{ L"\x0986",L"\x0985\x09BE" }, //( আ → অা ) BENGALI LETTER AA → BENGALI LETTER A, BENGALI VOWEL SIGN AA	# 

			{ L"\x09E0",L"\x098B\x09C3" }, //( ৠ → ঋৃ ) BENGALI LETTER VOCALIC RR → BENGALI LETTER VOCALIC R, BENGALI VOWEL SIGN VOCALIC R	# 
			{ L"\x09E1",L"\x098B\x09C3" }, //( ৡ → ঋৃ ) BENGALI LETTER VOCALIC LL → BENGALI LETTER VOCALIC R, BENGALI VOWEL SIGN VOCALIC R	# →ঌৢ→→ৠ→

			{ L"\x0001\x1492",L"\x0998" }, //( 𑒒 → ঘ ) TIRHUTA LETTER GHA → BENGALI LETTER GHA	# 

			{ L"\x0001\x1494",L"\x099A" }, //( 𑒔 → চ ) TIRHUTA LETTER CA → BENGALI LETTER CA	# 

			{ L"\x0001\x1496",L"\x099C" }, //( 𑒖 → জ ) TIRHUTA LETTER JA → BENGALI LETTER JA	# 

			{ L"\x0001\x1498",L"\x099E" }, //( 𑒘 → ঞ ) TIRHUTA LETTER NYA → BENGALI LETTER NYA	# 

			{ L"\x0001\x1499",L"\x099F" }, //( 𑒙 → ট ) TIRHUTA LETTER TTA → BENGALI LETTER TTA	# 

			{ L"\x0001\x149B",L"\x09A1" }, //( 𑒛 → ড ) TIRHUTA LETTER DDA → BENGALI LETTER DDA	# 

			{ L"\x0001\x14AA",L"\x09A3" }, //( 𑒪 → ণ ) TIRHUTA LETTER LA → BENGALI LETTER NNA	# 

			{ L"\x0001\x149E",L"\x09A4" }, //( 𑒞 → ত ) TIRHUTA LETTER TA → BENGALI LETTER TA	# 

			{ L"\x0001\x149F",L"\x09A5" }, //( 𑒟 → থ ) TIRHUTA LETTER THA → BENGALI LETTER THA	# 

			{ L"\x0001\x14A0",L"\x09A6" }, //( 𑒠 → দ ) TIRHUTA LETTER DA → BENGALI LETTER DA	# 

			{ L"\x0001\x14A1",L"\x09A7" }, //( 𑒡 → ধ ) TIRHUTA LETTER DHA → BENGALI LETTER DHA	# 

			{ L"\x0001\x14A2",L"\x09A8" }, //( 𑒢 → ন ) TIRHUTA LETTER NA → BENGALI LETTER NA	# 

			{ L"\x0001\x14A3",L"\x09AA" }, //( 𑒣 → প ) TIRHUTA LETTER PA → BENGALI LETTER PA	# 

			{ L"\x0001\x14A9",L"\x09AC" }, //( 𑒩 → ব ) TIRHUTA LETTER RA → BENGALI LETTER BA	# 

			{ L"\x0001\x14A7",L"\x09AE" }, //( 𑒧 → ম ) TIRHUTA LETTER MA → BENGALI LETTER MA	# 

			{ L"\x0001\x14A8",L"\x09AF" }, //( 𑒨 → য ) TIRHUTA LETTER YA → BENGALI LETTER YA	# 

			{ L"\x0001\x14AB",L"\x09B0" }, //( 𑒫 → র ) TIRHUTA LETTER VA → BENGALI LETTER RA	# 

			{ L"\x0001\x149D",L"\x09B2" }, //( 𑒝 → ল ) TIRHUTA LETTER NNA → BENGALI LETTER LA	# 

			{ L"\x0001\x14AD",L"\x09B7" }, //( 𑒭 → ষ ) TIRHUTA LETTER SSA → BENGALI LETTER SSA	# 

			{ L"\x0001\x14AE",L"\x09B8" }, //( 𑒮 → স ) TIRHUTA LETTER SA → BENGALI LETTER SA	# 

			{ L"\x0001\x14C4",L"\x09BD" }, //( 𑓄 → ঽ ) TIRHUTA SIGN AVAGRAHA → BENGALI SIGN AVAGRAHA	# 

			{ L"\x0001\x14B0",L"\x09BE" }, //( 𑒰 → া ) TIRHUTA VOWEL SIGN AA → BENGALI VOWEL SIGN AA	# 

			{ L"\x0001\x14B1",L"\x09BF" }, //( 𑒱 → ি ) TIRHUTA VOWEL SIGN I → BENGALI VOWEL SIGN I	# 

			{ L"\x0001\x14B9",L"\x09C7" }, //( 𑒹 → ে ) TIRHUTA VOWEL SIGN E → BENGALI VOWEL SIGN E	# 

			{ L"\x0001\x14BC",L"\x09CB" }, //( 𑒼 → ো ) TIRHUTA VOWEL SIGN O → BENGALI VOWEL SIGN O	# 

			{ L"\x0001\x14BE",L"\x09CC" }, //( 𑒾 → ৌ ) TIRHUTA VOWEL SIGN AU → BENGALI VOWEL SIGN AU	# 

			{ L"\x0001\x14C2",L"\x09CD" }, //( 𑓂 → ্ ) TIRHUTA SIGN VIRAMA → BENGALI SIGN VIRAMA	# 

			{ L"\x0001\x14BD",L"\x09D7" }, //( 𑒽 → ৗ ) TIRHUTA VOWEL SIGN SHORT O → BENGALI AU LENGTH MARK	# 

			{ L"\x0A09",L"\x0A73\x0A41" }, //( ਉ → ੳੁ ) GURMUKHI LETTER U → GURMUKHI URA, GURMUKHI VOWEL SIGN U	# 

			{ L"\x0A0A",L"\x0A73\x0A42" }, //( ਊ → ੳੂ ) GURMUKHI LETTER UU → GURMUKHI URA, GURMUKHI VOWEL SIGN UU	# 

			{ L"\x0A06",L"\x0A05\x0A3E" }, //( ਆ → ਅਾ ) GURMUKHI LETTER AA → GURMUKHI LETTER A, GURMUKHI VOWEL SIGN AA	# 

			{ L"\x0A10",L"\x0A05\x0A48" }, //( ਐ → ਅੈ ) GURMUKHI LETTER AI → GURMUKHI LETTER A, GURMUKHI VOWEL SIGN AI	# 

			{ L"\x0A14",L"\x0A05\x0A4C" }, //( ਔ → ਅੌ ) GURMUKHI LETTER AU → GURMUKHI LETTER A, GURMUKHI VOWEL SIGN AU	# 

			{ L"\x0A07",L"\x0A72\x0A3F" }, //( ਇ → ੲਿ ) GURMUKHI LETTER I → GURMUKHI IRI, GURMUKHI VOWEL SIGN I	# 

			{ L"\x0A08",L"\x0A72\x0A40" }, //( ਈ → ੲੀ ) GURMUKHI LETTER II → GURMUKHI IRI, GURMUKHI VOWEL SIGN II	# 

			{ L"\x0A0F",L"\x0A72\x0A47" }, //( ਏ → ੲੇ ) GURMUKHI LETTER EE → GURMUKHI IRI, GURMUKHI VOWEL SIGN EE	# 

			{ L"\x0A86",L"\x0A85\x0ABE" }, //( આ → અા ) GUJARATI LETTER AA → GUJARATI LETTER A, GUJARATI VOWEL SIGN AA	# 

			{ L"\x0A91",L"\x0A85\x0ABE\x0AC5" }, //( ઑ → અાૅ ) GUJARATI VOWEL CANDRA O → GUJARATI LETTER A, GUJARATI VOWEL SIGN AA, GUJARATI VOWEL SIGN CANDRA E	# →અૉ→→આૅ→

			{ L"\x0A93",L"\x0A85\x0ABE\x0AC7" }, //( ઓ → અાે ) GUJARATI LETTER O → GUJARATI LETTER A, GUJARATI VOWEL SIGN AA, GUJARATI VOWEL SIGN E	# →અો→→આે→

			{ L"\x0A94",L"\x0A85\x0ABE\x0AC8" }, //( ઔ → અાૈ ) GUJARATI LETTER AU → GUJARATI LETTER A, GUJARATI VOWEL SIGN AA, GUJARATI VOWEL SIGN AI	# →અૌ→→આૈ→

			{ L"\x0A8D",L"\x0A85\x0AC5" }, //( ઍ → અૅ ) GUJARATI VOWEL CANDRA E → GUJARATI LETTER A, GUJARATI VOWEL SIGN CANDRA E	# 

			{ L"\x0A8F",L"\x0A85\x0AC7" }, //( એ → અે ) GUJARATI LETTER E → GUJARATI LETTER A, GUJARATI VOWEL SIGN E	# 

			{ L"\x0A90",L"\x0A85\x0AC8" }, //( ઐ → અૈ ) GUJARATI LETTER AI → GUJARATI LETTER A, GUJARATI VOWEL SIGN AI	# 

			{ L"\x0B06",L"\x0B05\x0B3E" }, //( ଆ → ଅା ) ORIYA LETTER AA → ORIYA LETTER A, ORIYA VOWEL SIGN AA	# 

			{ L"\x0BEE",L"\x0B85" }, //( ௮ → அ ) TAMIL DIGIT EIGHT → TAMIL LETTER A	# 

			{ L"\x0BB0",L"\x0B88" }, //( ர → ஈ ) TAMIL LETTER RA → TAMIL LETTER II	# →ா→
			{ L"\x0BBE",L"\x0B88" }, //( ா → ஈ ) TAMIL VOWEL SIGN AA → TAMIL LETTER II	# 

			{ L"\x0BEB",L"\x0B88\x0BC1" }, //( ௫ → ஈு ) TAMIL DIGIT FIVE → TAMIL LETTER II, TAMIL VOWEL SIGN U	# →ரு→

			{ L"\x0BE8",L"\x0B89" }, //( ௨ → உ ) TAMIL DIGIT TWO → TAMIL LETTER U	# 
			{ L"\x0D09",L"\x0B89" }, //( ഉ → உ ) MALAYALAM LETTER U → TAMIL LETTER U	# 

			{ L"\x0B8A",L"\x0B89\x0BB3" }, //( ஊ → உள ) TAMIL LETTER UU → TAMIL LETTER U, TAMIL LETTER LLA	# 

			{ L"\x0D0A",L"\x0B89\x0D57" }, //( ഊ → உൗ ) MALAYALAM LETTER UU → TAMIL LETTER U, MALAYALAM AU LENGTH MARK	# →ഉൗ→

			{ L"\x0BED",L"\x0B8E" }, //( ௭ → எ ) TAMIL DIGIT SEVEN → TAMIL LETTER E	# 

			{ L"\x0BF7",L"\x0B8E\x0BB5" }, //( ௷ → எவ ) TAMIL CREDIT SIGN → TAMIL LETTER E, TAMIL LETTER VA	# 

			{ L"\x0B9C",L"\x0B90" }, //( ஜ → ஐ ) TAMIL LETTER JA → TAMIL LETTER AI	# 
			{ L"\x0D1C",L"\x0B90" }, //( ജ → ஐ ) MALAYALAM LETTER JA → TAMIL LETTER AI	# →ஜ→

			{ L"\x0BE7",L"\x0B95" }, //( ௧ → க ) TAMIL DIGIT ONE → TAMIL LETTER KA	# 

			{ L"\x0BEA",L"\x0B9A" }, //( ௪ → ச ) TAMIL DIGIT FOUR → TAMIL LETTER CA	# 

			{ L"\x0BEC",L"\x0B9A\x0BC1" }, //( ௬ → சு ) TAMIL DIGIT SIX → TAMIL LETTER CA, TAMIL VOWEL SIGN U	# 

			{ L"\x0BF2",L"\x0B9A\x0BC2" }, //( ௲ → சூ ) TAMIL NUMBER ONE THOUSAND → TAMIL LETTER CA, TAMIL VOWEL SIGN UU	# 

			{ L"\x0D3A",L"\x0B9F\x0BBF" }, //( ഺ → டி ) MALAYALAM LETTER TTTA → TAMIL LETTER TTA, TAMIL VOWEL SIGN I	# 

			{ L"\x0D23",L"\x0BA3" }, //( ണ → ண ) MALAYALAM LETTER NNA → TAMIL LETTER NNA	# 

			{ L"\x0BFA",L"\x0BA8\x0BC0" }, //( ௺ → நீ ) TAMIL NUMBER SIGN → TAMIL LETTER NA, TAMIL VOWEL SIGN II	# 

			{ L"\x0BF4",L"\x0BAE\x0BC0" }, //( ௴ → மீ ) TAMIL MONTH SIGN → TAMIL LETTER MA, TAMIL VOWEL SIGN II	# 

			{ L"\x0BF0",L"\x0BAF" }, //( ௰ → ய ) TAMIL NUMBER TEN → TAMIL LETTER YA	# 

			{ L"\x0D34",L"\x0BB4" }, //( ഴ → ழ ) MALAYALAM LETTER LLLA → TAMIL LETTER LLLA	# 

			{ L"\x0BD7",L"\x0BB3" }, //( ௗ → ள ) TAMIL AU LENGTH MARK → TAMIL LETTER LLA	# 

			{ L"\x0BC8",L"\x0BA9" }, //( ை → ன ) TAMIL VOWEL SIGN AI → TAMIL LETTER NNNA	# 

			{ L"\x0D36",L"\x0BB6" }, //( ശ → ஶ ) MALAYALAM LETTER SHA → TAMIL LETTER SHA	# 

			{ L"\x0BF8",L"\x0BB7" }, //( ௸ → ஷ ) TAMIL AS ABOVE SIGN → TAMIL LETTER SSA	# 

			{ L"\x0D3F",L"\x0BBF" }, //( ി → ி ) MALAYALAM VOWEL SIGN I → TAMIL VOWEL SIGN I	# 
			{ L"\x0D40",L"\x0BBF" }, //( ീ → ி ) MALAYALAM VOWEL SIGN II → TAMIL VOWEL SIGN I	# 

			{ L"\x0BCA",L"\x0BC6\x0B88" }, //( ொ → ெஈ ) TAMIL VOWEL SIGN O → TAMIL VOWEL SIGN E, TAMIL LETTER II	# →ெர→

			{ L"\x0BCC",L"\x0BC6\x0BB3" }, //( ௌ → ெள ) TAMIL VOWEL SIGN AU → TAMIL VOWEL SIGN E, TAMIL LETTER LLA	# 

			{ L"\x0BCB",L"\x0BC7\x0B88" }, //( ோ → ேஈ ) TAMIL VOWEL SIGN OO → TAMIL VOWEL SIGN EE, TAMIL LETTER II	# →ேர→

			{ L"\x0C85",L"\x0C05" }, //( ಅ → అ ) KANNADA LETTER A → TELUGU LETTER A	# 

			{ L"\x0C86",L"\x0C06" }, //( ಆ → ఆ ) KANNADA LETTER AA → TELUGU LETTER AA	# 

			{ L"\x0C87",L"\x0C07" }, //( ಇ → ఇ ) KANNADA LETTER I → TELUGU LETTER I	# 

			{ L"\x0C60",L"\x0C0B\x0C3E" }, //( ౠ → ఋా ) TELUGU LETTER VOCALIC RR → TELUGU LETTER VOCALIC R, TELUGU VOWEL SIGN AA	# 

			{ L"\x0C61",L"\x0C0C\x0C3E" }, //( ౡ → ఌా ) TELUGU LETTER VOCALIC LL → TELUGU LETTER VOCALIC L, TELUGU VOWEL SIGN AA	# 

			{ L"\x0C92",L"\x0C12" }, //( ಒ → ఒ ) KANNADA LETTER O → TELUGU LETTER O	# 

			{ L"\x0C14",L"\x0C12\x0C4C" }, //( ఔ → ఒౌ ) TELUGU LETTER AU → TELUGU LETTER O, TELUGU VOWEL SIGN AU	# 
			{ L"\x0C94",L"\x0C12\x0C4C" }, //( ಔ → ఒౌ ) KANNADA LETTER AU → TELUGU LETTER O, TELUGU VOWEL SIGN AU	# →ఔ→

			{ L"\x0C13",L"\x0C12\x0C55" }, //( ఓ → ఒౕ ) TELUGU LETTER OO → TELUGU LETTER O, TELUGU LENGTH MARK	# 
			{ L"\x0C93",L"\x0C12\x0C55" }, //( ಓ → ఒౕ ) KANNADA LETTER OO → TELUGU LETTER O, TELUGU LENGTH MARK	# →ఓ→

			{ L"\x0C9C",L"\x0C1C" }, //( ಜ → జ ) KANNADA LETTER JA → TELUGU LETTER JA	# 

			{ L"\x0C9E",L"\x0C1E" }, //( ಞ → ఞ ) KANNADA LETTER NYA → TELUGU LETTER NYA	# 

			{ L"\x0C22",L"\x0C21\x0323" }, //( ఢ → డ̣ ) TELUGU LETTER DDHA → TELUGU LETTER DDA, COMBINING DOT BELOW	# 

			{ L"\x0CA3",L"\x0C23" }, //( ಣ → ణ ) KANNADA LETTER NNA → TELUGU LETTER NNA	# 

			{ L"\x0C25",L"\x0C27\x05BC" }, //( థ → ధּ ) TELUGU LETTER THA → TELUGU LETTER DHA, HEBREW POINT DAGESH OR MAPIQ	# 

			{ L"\x0C2D",L"\x0C2C\x0323" }, //( భ → బ̣ ) TELUGU LETTER BHA → TELUGU LETTER BA, COMBINING DOT BELOW	# 

			{ L"\x0CAF",L"\x0C2F" }, //( ಯ → య ) KANNADA LETTER YA → TELUGU LETTER YA	# 

			{ L"\x0C20",L"\x0C30\x05BC" }, //( ఠ → రּ ) TELUGU LETTER TTHA → TELUGU LETTER RA, HEBREW POINT DAGESH OR MAPIQ	# 

			{ L"\x0CB1",L"\x0C31" }, //( ಱ → ఱ ) KANNADA LETTER RRA → TELUGU LETTER RRA	# 

			{ L"\x0CB2",L"\x0C32" }, //( ಲ → ల ) KANNADA LETTER LA → TELUGU LETTER LA	# 

			{ L"\x0C37",L"\x0C35\x0323" }, //( ష → వ̣ ) TELUGU LETTER SSA → TELUGU LETTER VA, COMBINING DOT BELOW	# 

			{ L"\x0C39",L"\x0C35\x0C3E" }, //( హ → వా ) TELUGU LETTER HA → TELUGU LETTER VA, TELUGU VOWEL SIGN AA	# 

			{ L"\x0C2E",L"\x0C35\x0C41" }, //( మ → వు ) TELUGU LETTER MA → TELUGU LETTER VA, TELUGU VOWEL SIGN U	# 

			{ L"\x0C42",L"\x0C41\x0C3E" }, //( ూ → ుా ) TELUGU VOWEL SIGN UU → TELUGU VOWEL SIGN U, TELUGU VOWEL SIGN AA	# 

			{ L"\x0C44",L"\x0C43\x0C3E" }, //( ౄ → ృా ) TELUGU VOWEL SIGN VOCALIC RR → TELUGU VOWEL SIGN VOCALIC R, TELUGU VOWEL SIGN AA	# 

			{ L"\x0CE1",L"\x0C8C\x0CBE" }, //( ೡ → ಌಾ ) KANNADA LETTER VOCALIC LL → KANNADA LETTER VOCALIC L, KANNADA VOWEL SIGN AA	# 

			{ L"\x0D08",L"\x0D07\x0D57" }, //( ഈ → ഇൗ ) MALAYALAM LETTER II → MALAYALAM LETTER I, MALAYALAM AU LENGTH MARK	# 

			{ L"\x0D10",L"\x0D0E\x0D46" }, //( ഐ → എെ ) MALAYALAM LETTER AI → MALAYALAM LETTER E, MALAYALAM VOWEL SIGN E	# 

			{ L"\x0D13",L"\x0D12\x0D3E" }, //( ഓ → ഒാ ) MALAYALAM LETTER OO → MALAYALAM LETTER O, MALAYALAM VOWEL SIGN AA	# 

			{ L"\x0D14",L"\x0D12\x0D57" }, //( ഔ → ഒൗ ) MALAYALAM LETTER AU → MALAYALAM LETTER O, MALAYALAM AU LENGTH MARK	# 

			{ L"\x0D61",L"\x0D1E" }, //( ൡ → ഞ ) MALAYALAM LETTER VOCALIC LL → MALAYALAM LETTER NYA	# 

			{ L"\x0D6B",L"\x0D26\x0D4D\x0D30" }, //( ൫ → ദ്ര ) MALAYALAM DIGIT FIVE → MALAYALAM LETTER DA, MALAYALAM SIGN VIRAMA, MALAYALAM LETTER RA	# 

			{ L"\x0D0C",L"\x0D28\x0D41" }, //( ഌ → നു ) MALAYALAM LETTER VOCALIC L → MALAYALAM LETTER NA, MALAYALAM VOWEL SIGN U	# 
			{ L"\x0D19",L"\x0D28\x0D41" }, //( ങ → നു ) MALAYALAM LETTER NGA → MALAYALAM LETTER NA, MALAYALAM VOWEL SIGN U	# →ഌ→

			{ L"\x0D6F",L"\x0D28\x0D4D" }, //( ൯ → ന് ) MALAYALAM DIGIT NINE → MALAYALAM LETTER NA, MALAYALAM SIGN VIRAMA	# 

			{ L"\x0D8C",L"\x0D28\x0D4D\x0D28" }, //( ඌ → ന്ന ) SINHALA LETTER UUYANNA → MALAYALAM LETTER NA, MALAYALAM SIGN VIRAMA, MALAYALAM LETTER NA	# 

			{ L"\x0D31",L"\x0D30" }, //( റ → ര ) MALAYALAM LETTER RRA → MALAYALAM LETTER RA	# 

			{ L"\x0D6A",L"\x0D30\x0D4D" }, //( ൪ → ര് ) MALAYALAM DIGIT FOUR → MALAYALAM LETTER RA, MALAYALAM SIGN VIRAMA	# 

			{ L"\x0D6E",L"\x0D35\x0D4D" }, //( ൮ → വ് ) MALAYALAM DIGIT EIGHT → MALAYALAM LETTER VA, MALAYALAM SIGN VIRAMA	# 

			{ L"\x0D42",L"\x0D41" }, //( ൂ → ു ) MALAYALAM VOWEL SIGN UU → MALAYALAM VOWEL SIGN U	# 
			{ L"\x0D43",L"\x0D41" }, //( ൃ → ു ) MALAYALAM VOWEL SIGN VOCALIC R → MALAYALAM VOWEL SIGN U	# →ൂ→

			{ L"\x0D48",L"\x0D46\x0D46" }, //( ൈ → െെ ) MALAYALAM VOWEL SIGN AI → MALAYALAM VOWEL SIGN E, MALAYALAM VOWEL SIGN E	# 

			{ L"\x0DEA",L"\x0DA2" }, //( ෪ → ජ ) SINHALA LITH DIGIT FOUR → SINHALA LETTER ALPAPRAANA JAYANNA	# 

			{ L"\x0DEB",L"\x0DAF" }, //( ෫ → ද ) SINHALA LITH DIGIT FIVE → SINHALA LETTER ALPAPRAANA DAYANNA	# 

			{ L"\x0001\x15D8",L"\x0001\x1582" }, //( 𑗘 → 𑖂 ) SIDDHAM LETTER THREE-CIRCLE ALTERNATE I → SIDDHAM LETTER I	# 
			{ L"\x0001\x15D9",L"\x0001\x1582" }, //( 𑗙 → 𑖂 ) SIDDHAM LETTER TWO-CIRCLE ALTERNATE I → SIDDHAM LETTER I	# 

			{ L"\x0001\x15DA",L"\x0001\x1583" }, //( 𑗚 → 𑖃 ) SIDDHAM LETTER TWO-CIRCLE ALTERNATE II → SIDDHAM LETTER II	# 

			{ L"\x0001\x15DB",L"\x0001\x1584" }, //( 𑗛 → 𑖄 ) SIDDHAM LETTER ALTERNATE U → SIDDHAM LETTER U	# 

			{ L"\x0E03",L"\x0E02" }, //( ฃ → ข ) THAI CHARACTER KHO KHUAT → THAI CHARACTER KHO KHAI	# 

			{ L"\x0E14",L"\x0E04" }, //( ด → ค ) THAI CHARACTER DO DEK → THAI CHARACTER KHO KHWAI	# 
			{ L"\x0E15",L"\x0E04" }, //( ต → ค ) THAI CHARACTER TO TAO → THAI CHARACTER KHO KHWAI	# →ด→

			{ L"\x0E21",L"\x0E06" }, //( ม → ฆ ) THAI CHARACTER MO MA → THAI CHARACTER KHO RAKHANG	# 

			{ L"\x0E88",L"\x0E08" }, //( ຈ → จ ) LAO LETTER CO → THAI CHARACTER CHO CHAN	# 

			{ L"\x0E0B",L"\x0E0A" }, //( ซ → ช ) THAI CHARACTER SO SO → THAI CHARACTER CHO CHANG	# 

			{ L"\x0E0F",L"\x0E0E" }, //( ฏ → ฎ ) THAI CHARACTER TO PATAK → THAI CHARACTER DO CHADA	# 

			{ L"\x0E17",L"\x0E11" }, //( ท → ฑ ) THAI CHARACTER THO THAHAN → THAI CHARACTER THO NANGMONTHO	# 

			{ L"\x0E9A",L"\x0E1A" }, //( ບ → บ ) LAO LETTER BO → THAI CHARACTER BO BAIMAI	# 

			{ L"\x0E9B",L"\x0E1B" }, //( ປ → ป ) LAO LETTER PO → THAI CHARACTER PO PLA	# 

			{ L"\x0E9D",L"\x0E1D" }, //( ຝ → ฝ ) LAO LETTER FO TAM → THAI CHARACTER FO FA	# 

			{ L"\x0E9E",L"\x0E1E" }, //( ພ → พ ) LAO LETTER PHO TAM → THAI CHARACTER PHO PHAN	# 

			{ L"\x0E9F",L"\x0E1F" }, //( ຟ → ฟ ) LAO LETTER FO SUNG → THAI CHARACTER FO FAN	# 

			{ L"\x0E26",L"\x0E20" }, //( ฦ → ภ ) THAI CHARACTER LU → THAI CHARACTER PHO SAMPHAO	# 

			{ L"\x0E8D",L"\x0E22" }, //( ຍ → ย ) LAO LETTER NYO → THAI CHARACTER YO YAK	# 

			{ L"\x17D4",L"\x0E2F" }, //( ។ → ฯ ) KHMER SIGN KHAN → THAI CHARACTER PAIYANNOI	# 

			{ L"\x0E45",L"\x0E32" }, //( ๅ → า ) THAI CHARACTER LAKKHANGYAO → THAI CHARACTER SARA AA	# 

			{ L"\x0E33",L"\x030A\x0E32" }, //( ำ → ̊า ) THAI CHARACTER SARA AM → COMBINING RING ABOVE, THAI CHARACTER SARA AA	# →ํา→

			{ L"\x17B7",L"\x0E34" }, //( ិ → ิ ) KHMER VOWEL SIGN I → THAI CHARACTER SARA I	# 

			{ L"\x17B8",L"\x0E35" }, //( ី → ี ) KHMER VOWEL SIGN II → THAI CHARACTER SARA II	# 

			{ L"\x17B9",L"\x0E36" }, //( ឹ → ึ ) KHMER VOWEL SIGN Y → THAI CHARACTER SARA UE	# 

			{ L"\x17BA",L"\x0E37" }, //( ឺ → ื ) KHMER VOWEL SIGN YY → THAI CHARACTER SARA UEE	# 

			{ L"\x0EB8",L"\x0E38" }, //( ຸ → ุ ) LAO VOWEL SIGN U → THAI CHARACTER SARA U	# 

			{ L"\x0EB9",L"\x0E39" }, //( ູ → ู ) LAO VOWEL SIGN UU → THAI CHARACTER SARA UU	# 

			{ L"\x0E41",L"\x0E40\x0E40" }, //( แ → เเ ) THAI CHARACTER SARA AE → THAI CHARACTER SARA E, THAI CHARACTER SARA E	# 

			{ L"\x0EDC",L"\x0EAB\x0E99" }, //( ໜ → ຫນ ) LAO HO NO → LAO LETTER HO SUNG, LAO LETTER NO	# 

			{ L"\x0EDD",L"\x0EAB\x0EA1" }, //( ໝ → ຫມ ) LAO HO MO → LAO LETTER HO SUNG, LAO LETTER MO	# 

			{ L"\x0EB3",L"\x030A\x0EB2" }, //( ຳ → ̊າ ) LAO VOWEL SIGN AM → COMBINING RING ABOVE, LAO VOWEL SIGN AA	# →ໍາ→

			{ L"\x0F6A",L"\x0F62" }, //( ཪ → ར ) TIBETAN LETTER FIXED-FORM RA → TIBETAN LETTER RA	# 

			{ L"\x0F00",L"\x0F68\x0F7C\x0F7E" }, //( ༀ → ཨོཾ ) TIBETAN SYLLABLE OM → TIBETAN LETTER A, TIBETAN VOWEL SIGN O, TIBETAN SIGN RJES SU NGA RO	# 

			{ L"\x0F77",L"\x0FB2\x0F71\x0F80" }, //( ཷ → ྲཱྀ ) TIBETAN VOWEL SIGN VOCALIC RR → TIBETAN SUBJOINED LETTER RA, TIBETAN VOWEL SIGN AA, TIBETAN VOWEL SIGN REVERSED I	# 

			{ L"\x0F79",L"\x0FB3\x0F71\x0F80" }, //( ཹ → ླཱྀ ) TIBETAN VOWEL SIGN VOCALIC LL → TIBETAN SUBJOINED LETTER LA, TIBETAN VOWEL SIGN AA, TIBETAN VOWEL SIGN REVERSED I	# 

			{ L"\x1081",L"\x1002\x103E" }, //( ႁ → ဂှ ) MYANMAR LETTER SHAN HA → MYANMAR LETTER GA, MYANMAR CONSONANT SIGN MEDIAL HA	# 

			{ L"\x1000",L"\x1002\x102C" }, //( က → ဂာ ) MYANMAR LETTER KA → MYANMAR LETTER GA, MYANMAR VOWEL SIGN AA	# 

			{ L"\x1070",L"\x1003\x103E" }, //( ၰ → ဃှ ) MYANMAR LETTER EASTERN PWO KAREN GHWA → MYANMAR LETTER GHA, MYANMAR CONSONANT SIGN MEDIAL HA	# 

			{ L"\x1066",L"\x1015\x103E" }, //( ၦ → ပှ ) MYANMAR LETTER WESTERN PWO KAREN PWA → MYANMAR LETTER PA, MYANMAR CONSONANT SIGN MEDIAL HA	# 

			{ L"\x101F",L"\x1015\x102C" }, //( ဟ → ပာ ) MYANMAR LETTER HA → MYANMAR LETTER PA, MYANMAR VOWEL SIGN AA	# 

			{ L"\x106F",L"\x1015\x102C\x103E" }, //( ၯ → ပာှ ) MYANMAR LETTER EASTERN PWO KAREN YWA → MYANMAR LETTER PA, MYANMAR VOWEL SIGN AA, MYANMAR CONSONANT SIGN MEDIAL HA	# →ဟှ→

			{ L"\x102A",L"\x1029\x1031\x102C\x103A" }, //( ဪ → ဩော် ) MYANMAR LETTER AU → MYANMAR LETTER O, MYANMAR VOWEL SIGN E, MYANMAR VOWEL SIGN AA, MYANMAR SIGN ASAT	# 

			{ L"\x109E",L"\x1083\x030A" }, //( ႞ → ႃ̊ ) MYANMAR SYMBOL SHAN ONE → MYANMAR VOWEL SIGN SHAN AA, COMBINING RING ABOVE	# →ႃံ→

			{ L"\x17A3",L"\x17A2" }, //( ឣ → អ ) KHMER INDEPENDENT VOWEL QAQ → KHMER LETTER QA	# 

			{ L"\x19D0",L"\x199E" }, //( ᧐ → ᦞ ) NEW TAI LUE DIGIT ZERO → NEW TAI LUE LETTER LOW VA	# 

			{ L"\x19D1",L"\x19B1" }, //( ᧑ → ᦱ ) NEW TAI LUE DIGIT ONE → NEW TAI LUE VOWEL SIGN AA	# 

			{ L"\x1A80",L"\x1A45" }, //( ᪀ → ᩅ ) TAI THAM HORA DIGIT ZERO → TAI THAM LETTER WA	# 
			{ L"\x1A90",L"\x1A45" }, //( ᪐ → ᩅ ) TAI THAM THAM DIGIT ZERO → TAI THAM LETTER WA	# 

			{ L"\xAA53",L"\xAA01" }, //( ꩓ → ꨁ ) CHAM DIGIT THREE → CHAM LETTER I	# 

			{ L"\xAA56",L"\xAA23" }, //( ꩖ → ꨣ ) CHAM DIGIT SIX → CHAM LETTER RA	# 

			{ L"\x1B52",L"\x1B0D" }, //( ᭒ → ᬍ ) BALINESE DIGIT TWO → BALINESE LETTER LA LENGA	# 

			{ L"\x1B53",L"\x1B11" }, //( ᭓ → ᬑ ) BALINESE DIGIT THREE → BALINESE LETTER OKARA	# 

			{ L"\x1B58",L"\x1B28" }, //( ᭘ → ᬨ ) BALINESE DIGIT EIGHT → BALINESE LETTER PA KAPAL	# 

			{ L"\x1896",L"\x185C" }, //( ᢖ → ᡜ ) MONGOLIAN LETTER ALI GALI ZA → MONGOLIAN LETTER TODO DZA	# 

			{ L"\x1855",L"\x1835" }, //( ᡕ → ᠵ ) MONGOLIAN LETTER TODO YA → MONGOLIAN LETTER JA	# 

			{ L"\x1FF6",L"\x13EF" }, //( ῶ → Ꮿ ) GREEK SMALL LETTER OMEGA WITH PERISPOMENI → CHEROKEE LETTER YA	# 

			{ L"\x140D",L"\x1401\x00B7" }, //( ᐍ → ᐁ· ) CANADIAN SYLLABICS WEST-CREE WE → CANADIAN SYLLABICS E, MIDDLE DOT	# →ᐁᐧ→

			{ L"\x142B",L"\x1401\x1420" }, //( ᐫ → ᐁᐠ ) CANADIAN SYLLABICS EN → CANADIAN SYLLABICS E, CANADIAN SYLLABICS FINAL GRAVE	# 

			{ L"\x1411",L"\x1404\x00B7" }, //( ᐑ → ᐄ· ) CANADIAN SYLLABICS WEST-CREE WII → CANADIAN SYLLABICS II, MIDDLE DOT	# →ᐄᐧ→

			{ L"\x1413",L"\x1405\x00B7" }, //( ᐓ → ᐅ· ) CANADIAN SYLLABICS WEST-CREE WO → CANADIAN SYLLABICS O, MIDDLE DOT	# →ᐅᐧ→

			{ L"\x142D",L"\x1405\x1420" }, //( ᐭ → ᐅᐠ ) CANADIAN SYLLABICS ON → CANADIAN SYLLABICS O, CANADIAN SYLLABICS FINAL GRAVE	# 

			{ L"\x1415",L"\x1406\x00B7" }, //( ᐕ → ᐆ· ) CANADIAN SYLLABICS WEST-CREE WOO → CANADIAN SYLLABICS OO, MIDDLE DOT	# →ᐆᐧ→

			{ L"\x1418",L"\x140A\x00B7" }, //( ᐘ → ᐊ· ) CANADIAN SYLLABICS WEST-CREE WA → CANADIAN SYLLABICS A, MIDDLE DOT	# →ᐊᐧ→

			{ L"\x142E",L"\x140A\x1420" }, //( ᐮ → ᐊᐠ ) CANADIAN SYLLABICS AN → CANADIAN SYLLABICS A, CANADIAN SYLLABICS FINAL GRAVE	# 

			{ L"\x141A",L"\x140B\x00B7" }, //( ᐚ → ᐋ· ) CANADIAN SYLLABICS WEST-CREE WAA → CANADIAN SYLLABICS AA, MIDDLE DOT	# →ᐋᐧ→

			{ L"\x14D1",L"\x1421" }, //( ᓑ → ᐡ ) CANADIAN SYLLABICS CARRIER NG → CANADIAN SYLLABICS FINAL BOTTOM HALF RING	# 

			{ L"\x1540",L"\x1429" }, //( ᕀ → ᐩ ) CANADIAN SYLLABICS WEST-CREE Y → CANADIAN SYLLABICS FINAL PLUS	# 

			{ L"\x143F",L"\x1432\x00B7" }, //( ᐿ → ᐲ· ) CANADIAN SYLLABICS WEST-CREE PWII → CANADIAN SYLLABICS PII, MIDDLE DOT	# →ᐲᐧ→

			{ L"\x1443",L"\x1434\x00B7" }, //( ᑃ → ᐴ· ) CANADIAN SYLLABICS WEST-CREE PWOO → CANADIAN SYLLABICS POO, MIDDLE DOT	# →ᐴᐧ→

			{ L"\x2369",L"\x1435" }, //( ⍩ → ᐵ ) APL FUNCTIONAL SYMBOL GREATER-THAN DIAERESIS → CANADIAN SYLLABICS Y-CREE POO	# 

			{ L"\x1447",L"\x1439\x00B7" }, //( ᑇ → ᐹ· ) CANADIAN SYLLABICS WEST-CREE PWAA → CANADIAN SYLLABICS PAA, MIDDLE DOT	# →ᐹᐧ→

			{ L"\x145C",L"\x144F\x00B7" }, //( ᑜ → ᑏ· ) CANADIAN SYLLABICS WEST-CREE TWII → CANADIAN SYLLABICS TII, MIDDLE DOT	# →ᑏᐧ→

			{ L"\x2E27",L"\x1450" }, //( ⸧ → ᑐ ) RIGHT SIDEWAYS U BRACKET → CANADIAN SYLLABICS TO	# →⊃→
			{ L"\x2283",L"\x1450" }, //( ⊃ → ᑐ ) SUPERSET OF → CANADIAN SYLLABICS TO	# 

			{ L"\x145E",L"\x1450\x00B7" }, //( ᑞ → ᑐ· ) CANADIAN SYLLABICS WEST-CREE TWO → CANADIAN SYLLABICS TO, MIDDLE DOT	# →ᑐᐧ→

			{ L"\x1469",L"\x1450\x0027" }, //( ᑩ → ᑐ' ) CANADIAN SYLLABICS TTO → CANADIAN SYLLABICS TO, APOSTROPHE	# →ᑐᑊ→

			{ L"\x27C9",L"\x1450\x002F" }, //( ⟉ → ᑐ/ ) SUPERSET PRECEDING SOLIDUS → CANADIAN SYLLABICS TO, SOLIDUS	# →⊃/→

			{ L"\x2AD7",L"\x1450\x1455" }, //( ⫗ → ᑐᑕ ) SUPERSET BESIDE SUBSET → CANADIAN SYLLABICS TO, CANADIAN SYLLABICS TA	# →⊃⊂→

			{ L"\x1460",L"\x1451\x00B7" }, //( ᑠ → ᑑ· ) CANADIAN SYLLABICS WEST-CREE TWOO → CANADIAN SYLLABICS TOO, MIDDLE DOT	# →ᑑᐧ→

			{ L"\x2E26",L"\x1455" }, //( ⸦ → ᑕ ) LEFT SIDEWAYS U BRACKET → CANADIAN SYLLABICS TA	# →⊂→
			{ L"\x2282",L"\x1455" }, //( ⊂ → ᑕ ) SUBSET OF → CANADIAN SYLLABICS TA	# 

			{ L"\x1462",L"\x1455\x00B7" }, //( ᑢ → ᑕ· ) CANADIAN SYLLABICS WEST-CREE TWA → CANADIAN SYLLABICS TA, MIDDLE DOT	# →ᑕᐧ→

			{ L"\x146A",L"\x1455\x0027" }, //( ᑪ → ᑕ' ) CANADIAN SYLLABICS TTA → CANADIAN SYLLABICS TA, APOSTROPHE	# →ᑕᑊ→

			{ L"\x1464",L"\x1456\x00B7" }, //( ᑤ → ᑖ· ) CANADIAN SYLLABICS WEST-CREE TWAA → CANADIAN SYLLABICS TAA, MIDDLE DOT	# →ᑖᐧ→

			{ L"\x1475",L"\x146B\x00B7" }, //( ᑵ → ᑫ· ) CANADIAN SYLLABICS WEST-CREE KWE → CANADIAN SYLLABICS KE, MIDDLE DOT	# →ᑫᐧ→

			{ L"\x1485",L"\x146B\x0027" }, //( ᒅ → ᑫ' ) CANADIAN SYLLABICS SOUTH-SLAVEY KEH → CANADIAN SYLLABICS KE, APOSTROPHE	# →ᑫᑊ→

			{ L"\x1479",L"\x146E\x00B7" }, //( ᑹ → ᑮ· ) CANADIAN SYLLABICS WEST-CREE KWII → CANADIAN SYLLABICS KII, MIDDLE DOT	# →ᑮᐧ→

			{ L"\x147D",L"\x1470\x00B7" }, //( ᑽ → ᑰ· ) CANADIAN SYLLABICS WEST-CREE KWOO → CANADIAN SYLLABICS KOO, MIDDLE DOT	# →ᑰᐧ→

			{ L"\x147F",L"\x1472\x00B7" }, //( ᑿ → ᑲ· ) CANADIAN SYLLABICS WEST-CREE KWA → CANADIAN SYLLABICS KA, MIDDLE DOT	# →ᑲᐧ→

			{ L"\x1488",L"\x1472\x0027" }, //( ᒈ → ᑲ' ) CANADIAN SYLLABICS SOUTH-SLAVEY KAH → CANADIAN SYLLABICS KA, APOSTROPHE	# →ᑲᑊ→

			{ L"\x1481",L"\x1473\x00B7" }, //( ᒁ → ᑳ· ) CANADIAN SYLLABICS WEST-CREE KWAA → CANADIAN SYLLABICS KAA, MIDDLE DOT	# →ᑳᐧ→

			{ L"\x1603",L"\x1489" }, //( ᘃ → ᒉ ) CANADIAN SYLLABICS CARRIER NO → CANADIAN SYLLABICS CE	# 

			{ L"\x1493",L"\x1489\x00B7" }, //( ᒓ → ᒉ· ) CANADIAN SYLLABICS WEST-CREE CWE → CANADIAN SYLLABICS CE, MIDDLE DOT	# →ᒉᐧ→

			{ L"\x1495",L"\x148B\x00B7" }, //( ᒕ → ᒋ· ) CANADIAN SYLLABICS WEST-CREE CWI → CANADIAN SYLLABICS CI, MIDDLE DOT	# →ᒋᐧ→

			{ L"\x1497",L"\x148C\x00B7" }, //( ᒗ → ᒌ· ) CANADIAN SYLLABICS WEST-CREE CWII → CANADIAN SYLLABICS CII, MIDDLE DOT	# →ᒌᐧ→

			{ L"\x149B",L"\x148E\x00B7" }, //( ᒛ → ᒎ· ) CANADIAN SYLLABICS WEST-CREE CWOO → CANADIAN SYLLABICS COO, MIDDLE DOT	# →ᒎᐧ→

			{ L"\x1602",L"\x1490" }, //( ᘂ → ᒐ ) CANADIAN SYLLABICS CARRIER NU → CANADIAN SYLLABICS CA	# 

			{ L"\x149D",L"\x1490\x00B7" }, //( ᒝ → ᒐ· ) CANADIAN SYLLABICS WEST-CREE CWA → CANADIAN SYLLABICS CA, MIDDLE DOT	# →ᒐᐧ→

			{ L"\x149F",L"\x1491\x00B7" }, //( ᒟ → ᒑ· ) CANADIAN SYLLABICS WEST-CREE CWAA → CANADIAN SYLLABICS CAA, MIDDLE DOT	# →ᒑᐧ→

			{ L"\x14AD",L"\x14A3\x00B7" }, //( ᒭ → ᒣ· ) CANADIAN SYLLABICS WEST-CREE MWE → CANADIAN SYLLABICS ME, MIDDLE DOT	# →ᒣᐧ→

			{ L"\x14B1",L"\x14A6\x00B7" }, //( ᒱ → ᒦ· ) CANADIAN SYLLABICS WEST-CREE MWII → CANADIAN SYLLABICS MII, MIDDLE DOT	# →ᒦᐧ→

			{ L"\x14B3",L"\x14A7\x00B7" }, //( ᒳ → ᒧ· ) CANADIAN SYLLABICS WEST-CREE MWO → CANADIAN SYLLABICS MO, MIDDLE DOT	# →ᒧᐧ→

			{ L"\x14B5",L"\x14A8\x00B7" }, //( ᒵ → ᒨ· ) CANADIAN SYLLABICS WEST-CREE MWOO → CANADIAN SYLLABICS MOO, MIDDLE DOT	# →ᒨᐧ→

			{ L"\x14B9",L"\x14AB\x00B7" }, //( ᒹ → ᒫ· ) CANADIAN SYLLABICS WEST-CREE MWAA → CANADIAN SYLLABICS MAA, MIDDLE DOT	# →ᒫᐧ→

			{ L"\x14CA",L"\x14C0\x00B7" }, //( ᓊ → ᓀ· ) CANADIAN SYLLABICS WEST-CREE NWE → CANADIAN SYLLABICS NE, MIDDLE DOT	# →ᓀᐧ→

			{ L"\x14CC",L"\x14C7\x00B7" }, //( ᓌ → ᓇ· ) CANADIAN SYLLABICS WEST-CREE NWA → CANADIAN SYLLABICS NA, MIDDLE DOT	# →ᓇᐧ→

			{ L"\x14CE",L"\x14C8\x00B7" }, //( ᓎ → ᓈ· ) CANADIAN SYLLABICS WEST-CREE NWAA → CANADIAN SYLLABICS NAA, MIDDLE DOT	# →ᓈᐧ→

			{ L"\x1604",L"\x14D3" }, //( ᘄ → ᓓ ) CANADIAN SYLLABICS CARRIER NE → CANADIAN SYLLABICS LE	# 

			{ L"\x14DD",L"\x14D3\x00B7" }, //( ᓝ → ᓓ· ) CANADIAN SYLLABICS WEST-CREE LWE → CANADIAN SYLLABICS LE, MIDDLE DOT	# →ᓓᐧ→

			{ L"\x14DF",L"\x14D5\x00B7" }, //( ᓟ → ᓕ· ) CANADIAN SYLLABICS WEST-CREE LWI → CANADIAN SYLLABICS LI, MIDDLE DOT	# →ᓕᐧ→

			{ L"\x14E1",L"\x14D6\x00B7" }, //( ᓡ → ᓖ· ) CANADIAN SYLLABICS WEST-CREE LWII → CANADIAN SYLLABICS LII, MIDDLE DOT	# →ᓖᐧ→

			{ L"\x14E3",L"\x14D7\x00B7" }, //( ᓣ → ᓗ· ) CANADIAN SYLLABICS WEST-CREE LWO → CANADIAN SYLLABICS LO, MIDDLE DOT	# →ᓗᐧ→

			{ L"\x14E5",L"\x14D8\x00B7" }, //( ᓥ → ᓘ· ) CANADIAN SYLLABICS WEST-CREE LWOO → CANADIAN SYLLABICS LOO, MIDDLE DOT	# →ᓘᐧ→

			{ L"\x1607",L"\x14DA" }, //( ᘇ → ᓚ ) CANADIAN SYLLABICS CARRIER NA → CANADIAN SYLLABICS LA	# 

			{ L"\x14E7",L"\x14DA\x00B7" }, //( ᓧ → ᓚ· ) CANADIAN SYLLABICS WEST-CREE LWA → CANADIAN SYLLABICS LA, MIDDLE DOT	# →ᓚᐧ→

			{ L"\x14E9",L"\x14DB\x00B7" }, //( ᓩ → ᓛ· ) CANADIAN SYLLABICS WEST-CREE LWAA → CANADIAN SYLLABICS LAA, MIDDLE DOT	# →ᓛᐧ→

			{ L"\x14F7",L"\x14ED\x00B7" }, //( ᓷ → ᓭ· ) CANADIAN SYLLABICS WEST-CREE SWE → CANADIAN SYLLABICS SE, MIDDLE DOT	# →ᓭᐧ→

			{ L"\x14F9",L"\x14EF\x00B7" }, //( ᓹ → ᓯ· ) CANADIAN SYLLABICS WEST-CREE SWI → CANADIAN SYLLABICS SI, MIDDLE DOT	# →ᓯᐧ→

			{ L"\x14FB",L"\x14F0\x00B7" }, //( ᓻ → ᓰ· ) CANADIAN SYLLABICS WEST-CREE SWII → CANADIAN SYLLABICS SII, MIDDLE DOT	# →ᓰᐧ→

			{ L"\x14FD",L"\x14F1\x00B7" }, //( ᓽ → ᓱ· ) CANADIAN SYLLABICS WEST-CREE SWO → CANADIAN SYLLABICS SO, MIDDLE DOT	# →ᓱᐧ→

			{ L"\x14FF",L"\x14F2\x00B7" }, //( ᓿ → ᓲ· ) CANADIAN SYLLABICS WEST-CREE SWOO → CANADIAN SYLLABICS SOO, MIDDLE DOT	# →ᓲᐧ→

			{ L"\x1501",L"\x14F4\x00B7" }, //( ᔁ → ᓴ· ) CANADIAN SYLLABICS WEST-CREE SWA → CANADIAN SYLLABICS SA, MIDDLE DOT	# →ᓴᐧ→

			{ L"\x1503",L"\x14F5\x00B7" }, //( ᔃ → ᓵ· ) CANADIAN SYLLABICS WEST-CREE SWAA → CANADIAN SYLLABICS SAA, MIDDLE DOT	# →ᓵᐧ→

			{ L"\x150C",L"\x150B\x003C" }, //( ᔌ → ᔋ< ) CANADIAN SYLLABICS NASKAPI SPWA → CANADIAN SYLLABICS NASKAPI S-W, LESS-THAN SIGN	# →ᔋᐸ→

			{ L"\x150D",L"\x150B\x1455" }, //( ᔍ → ᔋᑕ ) CANADIAN SYLLABICS NASKAPI STWA → CANADIAN SYLLABICS NASKAPI S-W, CANADIAN SYLLABICS TA	# 

			{ L"\x150E",L"\x150B\x1472" }, //( ᔎ → ᔋᑲ ) CANADIAN SYLLABICS NASKAPI SKWA → CANADIAN SYLLABICS NASKAPI S-W, CANADIAN SYLLABICS KA	# 

			{ L"\x150F",L"\x150B\x1490" }, //( ᔏ → ᔋᒐ ) CANADIAN SYLLABICS NASKAPI SCWA → CANADIAN SYLLABICS NASKAPI S-W, CANADIAN SYLLABICS CA	# 

			{ L"\x1518",L"\x1510\x00B7" }, //( ᔘ → ᔐ· ) CANADIAN SYLLABICS WEST-CREE SHWE → CANADIAN SYLLABICS SHE, MIDDLE DOT	# →ᔐᐧ→

			{ L"\x151A",L"\x1511\x00B7" }, //( ᔚ → ᔑ· ) CANADIAN SYLLABICS WEST-CREE SHWI → CANADIAN SYLLABICS SHI, MIDDLE DOT	# →ᔑᐧ→

			{ L"\x151C",L"\x1512\x00B7" }, //( ᔜ → ᔒ· ) CANADIAN SYLLABICS WEST-CREE SHWII → CANADIAN SYLLABICS SHII, MIDDLE DOT	# →ᔒᐧ→

			{ L"\x151E",L"\x1513\x00B7" }, //( ᔞ → ᔓ· ) CANADIAN SYLLABICS WEST-CREE SHWO → CANADIAN SYLLABICS SHO, MIDDLE DOT	# →ᔓᐧ→

			{ L"\x1520",L"\x1514\x00B7" }, //( ᔠ → ᔔ· ) CANADIAN SYLLABICS WEST-CREE SHWOO → CANADIAN SYLLABICS SHOO, MIDDLE DOT	# →ᔔᐧ→

			{ L"\x1522",L"\x1515\x00B7" }, //( ᔢ → ᔕ· ) CANADIAN SYLLABICS WEST-CREE SHWA → CANADIAN SYLLABICS SHA, MIDDLE DOT	# →ᔕᐧ→

			{ L"\x1524",L"\x1516\x00B7" }, //( ᔤ → ᔖ· ) CANADIAN SYLLABICS WEST-CREE SHWAA → CANADIAN SYLLABICS SHAA, MIDDLE DOT	# →ᔖᐧ→

			{ L"\x1532",L"\x1528\x00B7" }, //( ᔲ → ᔨ· ) CANADIAN SYLLABICS WEST-CREE YWI → CANADIAN SYLLABICS YI, MIDDLE DOT	# →ᔨᐧ→

			{ L"\x1534",L"\x1529\x00B7" }, //( ᔴ → ᔩ· ) CANADIAN SYLLABICS WEST-CREE YWII → CANADIAN SYLLABICS YII, MIDDLE DOT	# →ᔩᐧ→

			{ L"\x1536",L"\x152A\x00B7" }, //( ᔶ → ᔪ· ) CANADIAN SYLLABICS WEST-CREE YWO → CANADIAN SYLLABICS YO, MIDDLE DOT	# →ᔪᐧ→

			{ L"\x1538",L"\x152B\x00B7" }, //( ᔸ → ᔫ· ) CANADIAN SYLLABICS WEST-CREE YWOO → CANADIAN SYLLABICS YOO, MIDDLE DOT	# →ᔫᐧ→

			{ L"\x153A",L"\x152D\x00B7" }, //( ᔺ → ᔭ· ) CANADIAN SYLLABICS WEST-CREE YWA → CANADIAN SYLLABICS YA, MIDDLE DOT	# →ᔭᐧ→

			{ L"\x153C",L"\x152E\x00B7" }, //( ᔼ → ᔮ· ) CANADIAN SYLLABICS WEST-CREE YWAA → CANADIAN SYLLABICS YAA, MIDDLE DOT	# →ᔮᐧ→

			{ L"\x1622",L"\x1543" }, //( ᘢ → ᕃ ) CANADIAN SYLLABICS CARRIER LU → CANADIAN SYLLABICS R-CREE RE	# 

			{ L"\x18E0",L"\x1543\x00B7" }, //( ᣠ → ᕃ· ) CANADIAN SYLLABICS R-CREE RWE → CANADIAN SYLLABICS R-CREE RE, MIDDLE DOT	# →ᕃᐧ→

			{ L"\x1623",L"\x1546" }, //( ᘣ → ᕆ ) CANADIAN SYLLABICS CARRIER LO → CANADIAN SYLLABICS RI	# 

			{ L"\x1624",L"\x154A" }, //( ᘤ → ᕊ ) CANADIAN SYLLABICS CARRIER LE → CANADIAN SYLLABICS WEST-CREE LO	# 

			{ L"\x154F",L"\x154C\x00B7" }, //( ᕏ → ᕌ· ) CANADIAN SYLLABICS WEST-CREE RWAA → CANADIAN SYLLABICS RAA, MIDDLE DOT	# →ᕌᐧ→

			{ L"\x1581",L"\x1550\x0064" }, //( ᖁ → ᕐd ) CANADIAN SYLLABICS QO → CANADIAN SYLLABICS R, LATIN SMALL LETTER D	# →ᕐᑯ→

			{ L"\x157F",L"\x1550\x0050" }, //( ᕿ → ᕐP ) CANADIAN SYLLABICS QI → CANADIAN SYLLABICS R, LATIN CAPITAL LETTER P	# →ᕐᑭ→

			{ L"\x166F",L"\x1550\x146B" }, //( ᙯ → ᕐᑫ ) CANADIAN SYLLABICS QAI → CANADIAN SYLLABICS R, CANADIAN SYLLABICS KE	# 

			{ L"\x157E",L"\x1550\x146C" }, //( ᕾ → ᕐᑬ ) CANADIAN SYLLABICS QAAI → CANADIAN SYLLABICS R, CANADIAN SYLLABICS KAAI	# 

			{ L"\x1580",L"\x1550\x146E" }, //( ᖀ → ᕐᑮ ) CANADIAN SYLLABICS QII → CANADIAN SYLLABICS R, CANADIAN SYLLABICS KII	# 

			{ L"\x1582",L"\x1550\x1470" }, //( ᖂ → ᕐᑰ ) CANADIAN SYLLABICS QOO → CANADIAN SYLLABICS R, CANADIAN SYLLABICS KOO	# 

			{ L"\x1583",L"\x1550\x1472" }, //( ᖃ → ᕐᑲ ) CANADIAN SYLLABICS QA → CANADIAN SYLLABICS R, CANADIAN SYLLABICS KA	# 

			{ L"\x1584",L"\x1550\x1473" }, //( ᖄ → ᕐᑳ ) CANADIAN SYLLABICS QAA → CANADIAN SYLLABICS R, CANADIAN SYLLABICS KAA	# 

			{ L"\x1585",L"\x1550\x1483" }, //( ᖅ → ᕐᒃ ) CANADIAN SYLLABICS Q → CANADIAN SYLLABICS R, CANADIAN SYLLABICS K	# 

			{ L"\x155C",L"\x155A\x00B7" }, //( ᕜ → ᕚ· ) CANADIAN SYLLABICS WEST-CREE FWAA → CANADIAN SYLLABICS FAA, MIDDLE DOT	# →ᕚᐧ→

			{ L"\x18E3",L"\x155E\x00B7" }, //( ᣣ → ᕞ· ) CANADIAN SYLLABICS THWE → CANADIAN SYLLABICS THE, MIDDLE DOT	# →ᕞᐧ→

			{ L"\x18E4",L"\x1566\x00B7" }, //( ᣤ → ᕦ· ) CANADIAN SYLLABICS THWA → CANADIAN SYLLABICS THA, MIDDLE DOT	# →ᕦᐧ→

			{ L"\x1569",L"\x1567\x00B7" }, //( ᕩ → ᕧ· ) CANADIAN SYLLABICS WEST-CREE THWAA → CANADIAN SYLLABICS THAA, MIDDLE DOT	# →ᕧᐧ→

			{ L"\x18E5",L"\x156B\x00B7" }, //( ᣥ → ᕫ· ) CANADIAN SYLLABICS TTHWE → CANADIAN SYLLABICS TTHE, MIDDLE DOT	# →ᕫᐧ→

			{ L"\x18E8",L"\x1586\x00B7" }, //( ᣨ → ᖆ· ) CANADIAN SYLLABICS TLHWE → CANADIAN SYLLABICS TLHE, MIDDLE DOT	# →ᖆᐧ→

			{ L"\x1591",L"\x1595\x004A" }, //( ᖑ → ᖕJ ) CANADIAN SYLLABICS NGO → CANADIAN SYLLABICS NG, LATIN CAPITAL LETTER J	# →ᖕᒍ→

			{ L"\x1670",L"\x1595\x1489" }, //( ᙰ → ᖕᒉ ) CANADIAN SYLLABICS NGAI → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS CE	# 

			{ L"\x158E",L"\x1595\x148A" }, //( ᖎ → ᖕᒊ ) CANADIAN SYLLABICS NGAAI → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS CAAI	# 

			{ L"\x158F",L"\x1595\x148B" }, //( ᖏ → ᖕᒋ ) CANADIAN SYLLABICS NGI → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS CI	# 

			{ L"\x1590",L"\x1595\x148C" }, //( ᖐ → ᖕᒌ ) CANADIAN SYLLABICS NGII → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS CII	# 

			{ L"\x1592",L"\x1595\x148E" }, //( ᖒ → ᖕᒎ ) CANADIAN SYLLABICS NGOO → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS COO	# 

			{ L"\x1593",L"\x1595\x1490" }, //( ᖓ → ᖕᒐ ) CANADIAN SYLLABICS NGA → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS CA	# 

			{ L"\x1594",L"\x1595\x1491" }, //( ᖔ → ᖕᒑ ) CANADIAN SYLLABICS NGAA → CANADIAN SYLLABICS NG, CANADIAN SYLLABICS CAA	# 

			{ L"\x1673",L"\x1596\x004A" }, //( ᙳ → ᖖJ ) CANADIAN SYLLABICS NNGO → CANADIAN SYLLABICS NNG, LATIN CAPITAL LETTER J	# →ᖖᒍ→

			{ L"\x1671",L"\x1596\x148B" }, //( ᙱ → ᖖᒋ ) CANADIAN SYLLABICS NNGI → CANADIAN SYLLABICS NNG, CANADIAN SYLLABICS CI	# 

			{ L"\x1672",L"\x1596\x148C" }, //( ᙲ → ᖖᒌ ) CANADIAN SYLLABICS NNGII → CANADIAN SYLLABICS NNG, CANADIAN SYLLABICS CII	# 

			{ L"\x1674",L"\x1596\x148E" }, //( ᙴ → ᖖᒎ ) CANADIAN SYLLABICS NNGOO → CANADIAN SYLLABICS NNG, CANADIAN SYLLABICS COO	# 

			{ L"\x1675",L"\x1596\x1490" }, //( ᙵ → ᖖᒐ ) CANADIAN SYLLABICS NNGA → CANADIAN SYLLABICS NNG, CANADIAN SYLLABICS CA	# 

			{ L"\x1676",L"\x1596\x1491" }, //( ᙶ → ᖖᒑ ) CANADIAN SYLLABICS NNGAA → CANADIAN SYLLABICS NNG, CANADIAN SYLLABICS CAA	# 

			{ L"\x18EA",L"\x1597\x00B7" }, //( ᣪ → ᖗ· ) CANADIAN SYLLABICS SAYISI SHWE → CANADIAN SYLLABICS SAYISI SHE, MIDDLE DOT	# →ᖗᐧ→

			{ L"\x1677",L"\x15A7\x00B7" }, //( ᙷ → ᖧ· ) CANADIAN SYLLABICS WOODS-CREE THWEE → CANADIAN SYLLABICS TH-CREE THE, MIDDLE DOT	# →ᖧᐧ→

			{ L"\x1678",L"\x15A8\x00B7" }, //( ᙸ → ᖨ· ) CANADIAN SYLLABICS WOODS-CREE THWI → CANADIAN SYLLABICS TH-CREE THI, MIDDLE DOT	# →ᖨᐧ→

			{ L"\x1679",L"\x15A9\x00B7" }, //( ᙹ → ᖩ· ) CANADIAN SYLLABICS WOODS-CREE THWII → CANADIAN SYLLABICS TH-CREE THII, MIDDLE DOT	# →ᖩᐧ→

			{ L"\x167A",L"\x15AA\x00B7" }, //( ᙺ → ᖪ· ) CANADIAN SYLLABICS WOODS-CREE THWO → CANADIAN SYLLABICS TH-CREE THO, MIDDLE DOT	# →ᖪᐧ→

			{ L"\x167B",L"\x15AB\x00B7" }, //( ᙻ → ᖫ· ) CANADIAN SYLLABICS WOODS-CREE THWOO → CANADIAN SYLLABICS TH-CREE THOO, MIDDLE DOT	# →ᖫᐧ→

			{ L"\x167C",L"\x15AC\x00B7" }, //( ᙼ → ᖬ· ) CANADIAN SYLLABICS WOODS-CREE THWA → CANADIAN SYLLABICS TH-CREE THA, MIDDLE DOT	# →ᖬᐧ→

			{ L"\x167D",L"\x15AD\x00B7" }, //( ᙽ → ᖭ· ) CANADIAN SYLLABICS WOODS-CREE THWAA → CANADIAN SYLLABICS TH-CREE THAA, MIDDLE DOT	# →ᖭᐧ→

			{ L"\x2AAB",L"\x15D2" }, //( ⪫ → ᗒ ) LARGER THAN → CANADIAN SYLLABICS CARRIER WE	# 

			{ L"\x2AAA",L"\x15D5" }, //( ⪪ → ᗕ ) SMALLER THAN → CANADIAN SYLLABICS CARRIER WA	# 

			{ L"\xA4F7",L"\x15E1" }, //( ꓷ → ᗡ ) LISU LETTER OE → CANADIAN SYLLABICS CARRIER THA	# 

			{ L"\x18F0",L"\x15F4\x00B7" }, //( ᣰ → ᗴ· ) CANADIAN SYLLABICS CARRIER GWA → CANADIAN SYLLABICS CARRIER GA, MIDDLE DOT	# →ᗴᐧ→

			{ L"\x18F2",L"\x161B\x00B7" }, //( ᣲ → ᘛ· ) CANADIAN SYLLABICS CARRIER JWA → CANADIAN SYLLABICS CARRIER JA, MIDDLE DOT	# →ᘛᐧ→

			{ L"\x1DBB",L"\x1646" }, //( ᶻ → ᙆ ) MODIFIER LETTER SMALL Z → CANADIAN SYLLABICS CARRIER Z	# 

			{ L"\xA4ED",L"\x1660" }, //( ꓭ → ᙠ ) LISU LETTER GHA → CANADIAN SYLLABICS CARRIER TSA	# 

			{ L"\x02E1",L"\x18F3" }, //( ˡ → ᣳ ) MODIFIER LETTER SMALL L → CANADIAN SYLLABICS BEAVER DENE L	# 

			{ L"\x02B3",L"\x18F4" }, //( ʳ → ᣴ ) MODIFIER LETTER SMALL R → CANADIAN SYLLABICS BEAVER DENE R	# 

			{ L"\x02E2",L"\x18F5" }, //( ˢ → ᣵ ) MODIFIER LETTER SMALL S → CANADIAN SYLLABICS CARRIER DENTAL S	# 

			{ L"\x16E1",L"\x16BC" }, //( ᛡ → ᚼ ) RUNIC LETTER IOR → RUNIC LETTER LONG-BRANCH-HAGALL H	# 

			{ L"\x237F",L"\x16BD" }, //( ⍿ → ᚽ ) VERTICAL LINE WITH MIDDLE DOT → RUNIC LETTER SHORT-TWIG-HAGALL H	# →ᛂ→
			{ L"\x16C2",L"\x16BD" }, //( ᛂ → ᚽ ) RUNIC LETTER E → RUNIC LETTER SHORT-TWIG-HAGALL H	# 

			{ L"\x2191",L"\x16CF" }, //( ↑ → ᛏ ) UPWARDS ARROW → RUNIC LETTER TIWAZ TIR TYR T	# 

			{ L"\x21BF",L"\x16D0" }, //( ↿ → ᛐ ) UPWARDS HARPOON WITH BARB LEFTWARDS → RUNIC LETTER SHORT-TWIG-TYR T	# 

			{ L"\x296E",L"\x16D0\x21C2" }, //( ⥮ → ᛐ⇂ ) UPWARDS HARPOON WITH BARB LEFT BESIDE DOWNWARDS HARPOON WITH BARB RIGHT → RUNIC LETTER SHORT-TWIG-TYR T, DOWNWARDS HARPOON WITH BARB RIGHTWARDS	# →↿⇂→

			{ L"\x2963",L"\x16D0\x16DA" }, //( ⥣ → ᛐᛚ ) UPWARDS HARPOON WITH BARB LEFT BESIDE UPWARDS HARPOON WITH BARB RIGHT → RUNIC LETTER SHORT-TWIG-TYR T, RUNIC LETTER LAUKAZ LAGU LOGR L	# →↿↾→

			{ L"\x2D63",L"\x16EF" }, //( ⵣ → ᛯ ) TIFINAGH LETTER YAZ → RUNIC TVIMADUR SYMBOL	# 

			{ L"\x21BE",L"\x16DA" }, //( ↾ → ᛚ ) UPWARDS HARPOON WITH BARB RIGHTWARDS → RUNIC LETTER LAUKAZ LAGU LOGR L	# 
			{ L"\x2A21",L"\x16DA" }, //( ⨡ → ᛚ ) Z NOTATION SCHEMA PROJECTION → RUNIC LETTER LAUKAZ LAGU LOGR L	# →↾→

			{ L"\x22C4",L"\x16DC" }, //( ⋄ → ᛜ ) DIAMOND OPERATOR → RUNIC LETTER INGWAZ	# →◇→
			{ L"\x25C7",L"\x16DC" }, //( ◇ → ᛜ ) WHITE DIAMOND → RUNIC LETTER INGWAZ	# 
			{ L"\x25CA",L"\x16DC" }, //( ◊ → ᛜ ) LOZENGE → RUNIC LETTER INGWAZ	# →⋄→→◇→
			{ L"\x2662",L"\x16DC" }, //( ♢ → ᛜ ) WHITE DIAMOND SUIT → RUNIC LETTER INGWAZ	# →◊→→⋄→→◇→
			{ L"\x0001\xF754",L"\x16DC" }, //( 🝔 → ᛜ ) ALCHEMICAL SYMBOL FOR SOAP → RUNIC LETTER INGWAZ	# →◇→
			{ L"\x0001\x18B7",L"\x16DC" }, //( 𑢷 → ᛜ ) WARANG CITI CAPITAL LETTER BU → RUNIC LETTER INGWAZ	# →◇→
			{ L"\x0001\x0294",L"\x16DC" }, //( 𐊔 → ᛜ ) LYCIAN LETTER KK → RUNIC LETTER INGWAZ	# →◇→

			{ L"\x235A",L"\x16DC\x0332" }, //( ⍚ → ᛜ̲ ) APL FUNCTIONAL SYMBOL DIAMOND UNDERBAR → RUNIC LETTER INGWAZ, COMBINING LOW LINE	# →◇̲→

			{ L"\x22C8",L"\x16DE" }, //( ⋈ → ᛞ ) BOWTIE → RUNIC LETTER DAGAZ DAEG D	# 
			{ L"\x2A1D",L"\x16DE" }, //( ⨝ → ᛞ ) JOIN → RUNIC LETTER DAGAZ DAEG D	# →⋈→

			{ L"\x2195",L"\x16E8" }, //( ↕ → ᛨ ) UP DOWN ARROW → RUNIC LETTER ICELANDIC-YR	# 

			{ L"\x3131",L"\x1100" }, //( ㄱ → ᄀ ) HANGUL LETTER KIYEOK → HANGUL CHOSEONG KIYEOK	# 
			{ L"\x11A8",L"\x1100" }, //( ᆨ → ᄀ ) HANGUL JONGSEONG KIYEOK → HANGUL CHOSEONG KIYEOK	# 

			{ L"\x1101",L"\x1100\x1100" }, //( ᄁ → ᄀᄀ ) HANGUL CHOSEONG SSANGKIYEOK → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x3132",L"\x1100\x1100" }, //( ㄲ → ᄀᄀ ) HANGUL LETTER SSANGKIYEOK → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KIYEOK	# →ᄁ→
			{ L"\x11A9",L"\x1100\x1100" }, //( ᆩ → ᄀᄀ ) HANGUL JONGSEONG SSANGKIYEOK → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KIYEOK	# →ᄁ→

			{ L"\x11FA",L"\x1100\x1102" }, //( ᇺ → ᄀᄂ ) HANGUL JONGSEONG KIYEOK-NIEUN → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG NIEUN	# →ᆨᆫ→

			{ L"\x115A",L"\x1100\x1103" }, //( ᅚ → ᄀᄃ ) HANGUL CHOSEONG KIYEOK-TIKEUT → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG TIKEUT	# 

			{ L"\x11C3",L"\x1100\x1105" }, //( ᇃ → ᄀᄅ ) HANGUL JONGSEONG KIYEOK-RIEUL → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG RIEUL	# →ᆨᆯ→

			{ L"\x11FB",L"\x1100\x1107" }, //( ᇻ → ᄀᄇ ) HANGUL JONGSEONG KIYEOK-PIEUP → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG PIEUP	# →ᆨᆸ→

			{ L"\x11AA",L"\x1100\x1109" }, //( ᆪ → ᄀᄉ ) HANGUL JONGSEONG KIYEOK-SIOS → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG SIOS	# →ᆨᆺ→
			{ L"\x3133",L"\x1100\x1109" }, //( ㄳ → ᄀᄉ ) HANGUL LETTER KIYEOK-SIOS → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG SIOS	# →ᆪ→→ᆨᆺ→

			{ L"\x11C4",L"\x1100\x1109\x1100" }, //( ᇄ → ᄀᄉᄀ ) HANGUL JONGSEONG KIYEOK-SIOS-KIYEOK → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# →ᆨᆺᆨ→

			{ L"\x11FC",L"\x1100\x110E" }, //( ᇼ → ᄀᄎ ) HANGUL JONGSEONG KIYEOK-CHIEUCH → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG CHIEUCH	# →ᆨᆾ→

			{ L"\x11FD",L"\x1100\x110F" }, //( ᇽ → ᄀᄏ ) HANGUL JONGSEONG KIYEOK-KHIEUKH → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KHIEUKH	# →ᆨᆿ→

			{ L"\x11FE",L"\x1100\x1112" }, //( ᇾ → ᄀᄒ ) HANGUL JONGSEONG KIYEOK-HIEUH → HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG HIEUH	# →ᆨᇂ→

			{ L"\x3134",L"\x1102" }, //( ㄴ → ᄂ ) HANGUL LETTER NIEUN → HANGUL CHOSEONG NIEUN	# 
			{ L"\x11AB",L"\x1102" }, //( ᆫ → ᄂ ) HANGUL JONGSEONG NIEUN → HANGUL CHOSEONG NIEUN	# 

			{ L"\x1113",L"\x1102\x1100" }, //( ᄓ → ᄂᄀ ) HANGUL CHOSEONG NIEUN-KIYEOK → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x11C5",L"\x1102\x1100" }, //( ᇅ → ᄂᄀ ) HANGUL JONGSEONG NIEUN-KIYEOK → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG KIYEOK	# →ᄓ→

			{ L"\x1114",L"\x1102\x1102" }, //( ᄔ → ᄂᄂ ) HANGUL CHOSEONG SSANGNIEUN → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG NIEUN	# 
			{ L"\x3165",L"\x1102\x1102" }, //( ㅥ → ᄂᄂ ) HANGUL LETTER SSANGNIEUN → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG NIEUN	# →ᄔ→
			{ L"\x11FF",L"\x1102\x1102" }, //( ᇿ → ᄂᄂ ) HANGUL JONGSEONG SSANGNIEUN → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG NIEUN	# →ᆫᆫ→

			{ L"\x1115",L"\x1102\x1103" }, //( ᄕ → ᄂᄃ ) HANGUL CHOSEONG NIEUN-TIKEUT → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG TIKEUT	# 
			{ L"\x3166",L"\x1102\x1103" }, //( ㅦ → ᄂᄃ ) HANGUL LETTER NIEUN-TIKEUT → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG TIKEUT	# →ᄕ→
			{ L"\x11C6",L"\x1102\x1103" }, //( ᇆ → ᄂᄃ ) HANGUL JONGSEONG NIEUN-TIKEUT → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG TIKEUT	# →ᄕ→

			{ L"\xD7CB",L"\x1102\x1105" }, //( ퟋ → ᄂᄅ ) HANGUL JONGSEONG NIEUN-RIEUL → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG RIEUL	# →ᆫᆯ→

			{ L"\x1116",L"\x1102\x1107" }, //( ᄖ → ᄂᄇ ) HANGUL CHOSEONG NIEUN-PIEUP → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG PIEUP	# 

			{ L"\x115B",L"\x1102\x1109" }, //( ᅛ → ᄂᄉ ) HANGUL CHOSEONG NIEUN-SIOS → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG SIOS	# 
			{ L"\x11C7",L"\x1102\x1109" }, //( ᇇ → ᄂᄉ ) HANGUL JONGSEONG NIEUN-SIOS → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG SIOS	# →ᆫᆺ→
			{ L"\x3167",L"\x1102\x1109" }, //( ㅧ → ᄂᄉ ) HANGUL LETTER NIEUN-SIOS → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG SIOS	# →ᇇ→→ᆫᆺ→

			{ L"\x115C",L"\x1102\x110C" }, //( ᅜ → ᄂᄌ ) HANGUL CHOSEONG NIEUN-CIEUC → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG CIEUC	# 
			{ L"\x11AC",L"\x1102\x110C" }, //( ᆬ → ᄂᄌ ) HANGUL JONGSEONG NIEUN-CIEUC → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG CIEUC	# →ᆫᆽ→
			{ L"\x3135",L"\x1102\x110C" }, //( ㄵ → ᄂᄌ ) HANGUL LETTER NIEUN-CIEUC → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG CIEUC	# →ᆬ→→ᆫᆽ→

			{ L"\xD7CC",L"\x1102\x110E" }, //( ퟌ → ᄂᄎ ) HANGUL JONGSEONG NIEUN-CHIEUCH → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG CHIEUCH	# →ᆫᆾ→

			{ L"\x11C9",L"\x1102\x1110" }, //( ᇉ → ᄂᄐ ) HANGUL JONGSEONG NIEUN-THIEUTH → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG THIEUTH	# →ᆫᇀ→

			{ L"\x115D",L"\x1102\x1112" }, //( ᅝ → ᄂᄒ ) HANGUL CHOSEONG NIEUN-HIEUH → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG HIEUH	# 
			{ L"\x11AD",L"\x1102\x1112" }, //( ᆭ → ᄂᄒ ) HANGUL JONGSEONG NIEUN-HIEUH → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG HIEUH	# →ᆫᇂ→
			{ L"\x3136",L"\x1102\x1112" }, //( ㄶ → ᄂᄒ ) HANGUL LETTER NIEUN-HIEUH → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG HIEUH	# →ᆭ→→ᆫᇂ→

			{ L"\x11C8",L"\x1102\x1140" }, //( ᇈ → ᄂᅀ ) HANGUL JONGSEONG NIEUN-PANSIOS → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG PANSIOS	# →ᆫᇫ→
			{ L"\x3168",L"\x1102\x1140" }, //( ㅨ → ᄂᅀ ) HANGUL LETTER NIEUN-PANSIOS → HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG PANSIOS	# →ᇈ→→ᆫᇫ→

			{ L"\x3137",L"\x1103" }, //( ㄷ → ᄃ ) HANGUL LETTER TIKEUT → HANGUL CHOSEONG TIKEUT	# 
			{ L"\x11AE",L"\x1103" }, //( ᆮ → ᄃ ) HANGUL JONGSEONG TIKEUT → HANGUL CHOSEONG TIKEUT	# 

			{ L"\x1117",L"\x1103\x1100" }, //( ᄗ → ᄃᄀ ) HANGUL CHOSEONG TIKEUT-KIYEOK → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x11CA",L"\x1103\x1100" }, //( ᇊ → ᄃᄀ ) HANGUL JONGSEONG TIKEUT-KIYEOK → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG KIYEOK	# →ᄗ→

			{ L"\x1104",L"\x1103\x1103" }, //( ᄄ → ᄃᄃ ) HANGUL CHOSEONG SSANGTIKEUT → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG TIKEUT	# 
			{ L"\x3138",L"\x1103\x1103" }, //( ㄸ → ᄃᄃ ) HANGUL LETTER SSANGTIKEUT → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG TIKEUT	# →ᄄ→
			{ L"\xD7CD",L"\x1103\x1103" }, //( ퟍ → ᄃᄃ ) HANGUL JONGSEONG SSANGTIKEUT → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG TIKEUT	# →ᆮᆮ→

			{ L"\xD7CE",L"\x1103\x1103\x1107" }, //( ퟎ → ᄃᄃᄇ ) HANGUL JONGSEONG SSANGTIKEUT-PIEUP → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG PIEUP	# →ᆮᆮᆸ→

			{ L"\x115E",L"\x1103\x1105" }, //( ᅞ → ᄃᄅ ) HANGUL CHOSEONG TIKEUT-RIEUL → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG RIEUL	# 
			{ L"\x11CB",L"\x1103\x1105" }, //( ᇋ → ᄃᄅ ) HANGUL JONGSEONG TIKEUT-RIEUL → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG RIEUL	# →ᆮᆯ→

			{ L"\xA960",L"\x1103\x1106" }, //( ꥠ → ᄃᄆ ) HANGUL CHOSEONG TIKEUT-MIEUM → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG MIEUM	# 

			{ L"\xA961",L"\x1103\x1107" }, //( ꥡ → ᄃᄇ ) HANGUL CHOSEONG TIKEUT-PIEUP → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG PIEUP	# 
			{ L"\xD7CF",L"\x1103\x1107" }, //( ퟏ → ᄃᄇ ) HANGUL JONGSEONG TIKEUT-PIEUP → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG PIEUP	# →ᆮᆸ→

			{ L"\xA962",L"\x1103\x1109" }, //( ꥢ → ᄃᄉ ) HANGUL CHOSEONG TIKEUT-SIOS → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG SIOS	# 
			{ L"\xD7D0",L"\x1103\x1109" }, //( ퟐ → ᄃᄉ ) HANGUL JONGSEONG TIKEUT-SIOS → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG SIOS	# →ᆮᆺ→

			{ L"\xD7D1",L"\x1103\x1109\x1100" }, //( ퟑ → ᄃᄉᄀ ) HANGUL JONGSEONG TIKEUT-SIOS-KIYEOK → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# →ᆮᆺᆨ→

			{ L"\xA963",L"\x1103\x110C" }, //( ꥣ → ᄃᄌ ) HANGUL CHOSEONG TIKEUT-CIEUC → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG CIEUC	# 
			{ L"\xD7D2",L"\x1103\x110C" }, //( ퟒ → ᄃᄌ ) HANGUL JONGSEONG TIKEUT-CIEUC → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG CIEUC	# →ᆮᆽ→

			{ L"\xD7D3",L"\x1103\x110E" }, //( ퟓ → ᄃᄎ ) HANGUL JONGSEONG TIKEUT-CHIEUCH → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG CHIEUCH	# →ᆮᆾ→

			{ L"\xD7D4",L"\x1103\x1110" }, //( ퟔ → ᄃᄐ ) HANGUL JONGSEONG TIKEUT-THIEUTH → HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG THIEUTH	# →ᆮᇀ→

			{ L"\x3139",L"\x1105" }, //( ㄹ → ᄅ ) HANGUL LETTER RIEUL → HANGUL CHOSEONG RIEUL	# 
			{ L"\x11AF",L"\x1105" }, //( ᆯ → ᄅ ) HANGUL JONGSEONG RIEUL → HANGUL CHOSEONG RIEUL	# 

			{ L"\xA964",L"\x1105\x1100" }, //( ꥤ → ᄅᄀ ) HANGUL CHOSEONG RIEUL-KIYEOK → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x11B0",L"\x1105\x1100" }, //( ᆰ → ᄅᄀ ) HANGUL JONGSEONG RIEUL-KIYEOK → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK	# →ᆯᆨ→
			{ L"\x313A",L"\x1105\x1100" }, //( ㄺ → ᄅᄀ ) HANGUL LETTER RIEUL-KIYEOK → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK	# →ᆰ→→ᆯᆨ→

			{ L"\xA965",L"\x1105\x1100\x1100" }, //( ꥥ → ᄅᄀᄀ ) HANGUL CHOSEONG RIEUL-SSANGKIYEOK → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KIYEOK	# 
			{ L"\xD7D5",L"\x1105\x1100\x1100" }, //( ퟕ → ᄅᄀᄀ ) HANGUL JONGSEONG RIEUL-SSANGKIYEOK → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KIYEOK	# →ᆯᆨᆨ→

			{ L"\x11CC",L"\x1105\x1100\x1109" }, //( ᇌ → ᄅᄀᄉ ) HANGUL JONGSEONG RIEUL-KIYEOK-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG SIOS	# →ᆯᆨᆺ→
			{ L"\x3169",L"\x1105\x1100\x1109" }, //( ㅩ → ᄅᄀᄉ ) HANGUL LETTER RIEUL-KIYEOK-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG SIOS	# →ᇌ→→ᆯᆨᆺ→

			{ L"\xD7D6",L"\x1105\x1100\x1112" }, //( ퟖ → ᄅᄀᄒ ) HANGUL JONGSEONG RIEUL-KIYEOK-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG HIEUH	# →ᆯᆨᇂ→

			{ L"\x1118",L"\x1105\x1102" }, //( ᄘ → ᄅᄂ ) HANGUL CHOSEONG RIEUL-NIEUN → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG NIEUN	# 
			{ L"\x11CD",L"\x1105\x1102" }, //( ᇍ → ᄅᄂ ) HANGUL JONGSEONG RIEUL-NIEUN → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG NIEUN	# →ᄘ→

			{ L"\xA966",L"\x1105\x1103" }, //( ꥦ → ᄅᄃ ) HANGUL CHOSEONG RIEUL-TIKEUT → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG TIKEUT	# 
			{ L"\x11CE",L"\x1105\x1103" }, //( ᇎ → ᄅᄃ ) HANGUL JONGSEONG RIEUL-TIKEUT → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG TIKEUT	# →ᆯᆮ→
			{ L"\x316A",L"\x1105\x1103" }, //( ㅪ → ᄅᄃ ) HANGUL LETTER RIEUL-TIKEUT → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG TIKEUT	# →ᇎ→→ᆯᆮ→

			{ L"\xA967",L"\x1105\x1103\x1103" }, //( ꥧ → ᄅᄃᄃ ) HANGUL CHOSEONG RIEUL-SSANGTIKEUT → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG TIKEUT	# 

			{ L"\x11CF",L"\x1105\x1103\x1112" }, //( ᇏ → ᄅᄃᄒ ) HANGUL JONGSEONG RIEUL-TIKEUT-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG TIKEUT, HANGUL CHOSEONG HIEUH	# →ᆯᆮᇂ→

			{ L"\x1119",L"\x1105\x1105" }, //( ᄙ → ᄅᄅ ) HANGUL CHOSEONG SSANGRIEUL → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG RIEUL	# 
			{ L"\x11D0",L"\x1105\x1105" }, //( ᇐ → ᄅᄅ ) HANGUL JONGSEONG SSANGRIEUL → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG RIEUL	# →ᄙ→

			{ L"\xD7D7",L"\x1105\x1105\x110F" }, //( ퟗ → ᄅᄅᄏ ) HANGUL JONGSEONG SSANGRIEUL-KHIEUKH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KHIEUKH	# →ᆯᆯᆿ→

			{ L"\xA968",L"\x1105\x1106" }, //( ꥨ → ᄅᄆ ) HANGUL CHOSEONG RIEUL-MIEUM → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG MIEUM	# 
			{ L"\x11B1",L"\x1105\x1106" }, //( ᆱ → ᄅᄆ ) HANGUL JONGSEONG RIEUL-MIEUM → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG MIEUM	# →ᆯᆷ→
			{ L"\x313B",L"\x1105\x1106" }, //( ㄻ → ᄅᄆ ) HANGUL LETTER RIEUL-MIEUM → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG MIEUM	# →ᆱ→→ᆯᆷ→

			{ L"\x11D1",L"\x1105\x1106\x1100" }, //( ᇑ → ᄅᄆᄀ ) HANGUL JONGSEONG RIEUL-MIEUM-KIYEOK → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG KIYEOK	# →ᆯᆷᆨ→

			{ L"\x11D2",L"\x1105\x1106\x1109" }, //( ᇒ → ᄅᄆᄉ ) HANGUL JONGSEONG RIEUL-MIEUM-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG SIOS	# →ᆯᆷᆺ→

			{ L"\xD7D8",L"\x1105\x1106\x1112" }, //( ퟘ → ᄅᄆᄒ ) HANGUL JONGSEONG RIEUL-MIEUM-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG HIEUH	# →ᆯᆷᇂ→

			{ L"\xA969",L"\x1105\x1107" }, //( ꥩ → ᄅᄇ ) HANGUL CHOSEONG RIEUL-PIEUP → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP	# 
			{ L"\x11B2",L"\x1105\x1107" }, //( ᆲ → ᄅᄇ ) HANGUL JONGSEONG RIEUL-PIEUP → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP	# →ᆯᆸ→
			{ L"\x313C",L"\x1105\x1107" }, //( ㄼ → ᄅᄇ ) HANGUL LETTER RIEUL-PIEUP → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP	# →ᆲ→→ᆯᆸ→

			{ L"\xD7D9",L"\x1105\x1107\x1103" }, //( ퟙ → ᄅᄇᄃ ) HANGUL JONGSEONG RIEUL-PIEUP-TIKEUT → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG TIKEUT	# →ᆯᆸᆮ→

			{ L"\xA96A",L"\x1105\x1107\x1107" }, //( ꥪ → ᄅᄇᄇ ) HANGUL CHOSEONG RIEUL-SSANGPIEUP → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP	# 

			{ L"\x11D3",L"\x1105\x1107\x1109" }, //( ᇓ → ᄅᄇᄉ ) HANGUL JONGSEONG RIEUL-PIEUP-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS	# →ᆯᆸᆺ→
			{ L"\x316B",L"\x1105\x1107\x1109" }, //( ㅫ → ᄅᄇᄉ ) HANGUL LETTER RIEUL-PIEUP-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS	# →ᇓ→→ᆯᆸᆺ→

			{ L"\xA96B",L"\x1105\x1107\x110B" }, //( ꥫ → ᄅᄇᄋ ) HANGUL CHOSEONG RIEUL-KAPYEOUNPIEUP → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# 
			{ L"\x11D5",L"\x1105\x1107\x110B" }, //( ᇕ → ᄅᄇᄋ ) HANGUL JONGSEONG RIEUL-KAPYEOUNPIEUP → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# →ᆯᆸᆼ→

			{ L"\xD7DA",L"\x1105\x1107\x1111" }, //( ퟚ → ᄅᄇᄑ ) HANGUL JONGSEONG RIEUL-PIEUP-PHIEUPH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PHIEUPH	# →ᆯᆸᇁ→

			{ L"\x11D4",L"\x1105\x1107\x1112" }, //( ᇔ → ᄅᄇᄒ ) HANGUL JONGSEONG RIEUL-PIEUP-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG HIEUH	# →ᆯᆸᇂ→

			{ L"\xA96C",L"\x1105\x1109" }, //( ꥬ → ᄅᄉ ) HANGUL CHOSEONG RIEUL-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG SIOS	# 
			{ L"\x11B3",L"\x1105\x1109" }, //( ᆳ → ᄅᄉ ) HANGUL JONGSEONG RIEUL-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG SIOS	# →ᆯᆺ→
			{ L"\x313D",L"\x1105\x1109" }, //( ㄽ → ᄅᄉ ) HANGUL LETTER RIEUL-SIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG SIOS	# →ᆳ→→ᆯᆺ→

			{ L"\x11D6",L"\x1105\x1109\x1109" }, //( ᇖ → ᄅᄉᄉ ) HANGUL JONGSEONG RIEUL-SSANGSIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# →ᆯᆺᆺ→

			{ L"\x111B",L"\x1105\x110B" }, //( ᄛ → ᄅᄋ ) HANGUL CHOSEONG KAPYEOUNRIEUL → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG IEUNG	# 
			{ L"\xD7DD",L"\x1105\x110B" }, //( ퟝ → ᄅᄋ ) HANGUL JONGSEONG KAPYEOUNRIEUL → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG IEUNG	# →ᆯᆼ→

			{ L"\xA96D",L"\x1105\x110C" }, //( ꥭ → ᄅᄌ ) HANGUL CHOSEONG RIEUL-CIEUC → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG CIEUC	# 

			{ L"\xA96E",L"\x1105\x110F" }, //( ꥮ → ᄅᄏ ) HANGUL CHOSEONG RIEUL-KHIEUKH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KHIEUKH	# 
			{ L"\x11D8",L"\x1105\x110F" }, //( ᇘ → ᄅᄏ ) HANGUL JONGSEONG RIEUL-KHIEUKH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG KHIEUKH	# →ᆯᆿ→

			{ L"\x11B4",L"\x1105\x1110" }, //( ᆴ → ᄅᄐ ) HANGUL JONGSEONG RIEUL-THIEUTH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG THIEUTH	# →ᆯᇀ→
			{ L"\x313E",L"\x1105\x1110" }, //( ㄾ → ᄅᄐ ) HANGUL LETTER RIEUL-THIEUTH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG THIEUTH	# →ᆴ→→ᆯᇀ→

			{ L"\x11B5",L"\x1105\x1111" }, //( ᆵ → ᄅᄑ ) HANGUL JONGSEONG RIEUL-PHIEUPH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PHIEUPH	# →ᆯᇁ→
			{ L"\x313F",L"\x1105\x1111" }, //( ㄿ → ᄅᄑ ) HANGUL LETTER RIEUL-PHIEUPH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PHIEUPH	# →ᆵ→→ᆯᇁ→

			{ L"\x111A",L"\x1105\x1112" }, //( ᄚ → ᄅᄒ ) HANGUL CHOSEONG RIEUL-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG HIEUH	# 
			{ L"\x3140",L"\x1105\x1112" }, //( ㅀ → ᄅᄒ ) HANGUL LETTER RIEUL-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG HIEUH	# →ᄚ→
			{ L"\x113B",L"\x1105\x1112" }, //( ᄻ → ᄅᄒ ) HANGUL CHOSEONG SIOS-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG HIEUH	# →ᄚ→
			{ L"\x11B6",L"\x1105\x1112" }, //( ᆶ → ᄅᄒ ) HANGUL JONGSEONG RIEUL-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG HIEUH	# →ᄚ→
			{ L"\xD7F2",L"\x1105\x1112" }, //( ퟲ → ᄅᄒ ) HANGUL JONGSEONG SIOS-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG HIEUH	# →ᆺᇂ→→ᄉᄒ→→ᄻ→→ᄚ→

			{ L"\x11D7",L"\x1105\x1140" }, //( ᇗ → ᄅᅀ ) HANGUL JONGSEONG RIEUL-PANSIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PANSIOS	# →ᆯᇫ→
			{ L"\x316C",L"\x1105\x1140" }, //( ㅬ → ᄅᅀ ) HANGUL LETTER RIEUL-PANSIOS → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PANSIOS	# →ᇗ→→ᆯᇫ→

			{ L"\xD7DB",L"\x1105\x114C" }, //( ퟛ → ᄅᅌ ) HANGUL JONGSEONG RIEUL-YESIEUNG → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG YESIEUNG	# →ᆯᇰ→

			{ L"\x11D9",L"\x1105\x1159" }, //( ᇙ → ᄅᅙ ) HANGUL JONGSEONG RIEUL-YEORINHIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG YEORINHIEUH	# →ᆯᇹ→
			{ L"\x316D",L"\x1105\x1159" }, //( ㅭ → ᄅᅙ ) HANGUL LETTER RIEUL-YEORINHIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG YEORINHIEUH	# →ᇙ→→ᆯᇹ→

			{ L"\xD7DC",L"\x1105\x1159\x1112" }, //( ퟜ → ᄅᅙᄒ ) HANGUL JONGSEONG RIEUL-YEORINHIEUH-HIEUH → HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG YEORINHIEUH, HANGUL CHOSEONG HIEUH	# →ᆯᇹᇂ→

			{ L"\x3141",L"\x1106" }, //( ㅁ → ᄆ ) HANGUL LETTER MIEUM → HANGUL CHOSEONG MIEUM	# 
			{ L"\x11B7",L"\x1106" }, //( ᆷ → ᄆ ) HANGUL JONGSEONG MIEUM → HANGUL CHOSEONG MIEUM	# 

			{ L"\xA96F",L"\x1106\x1100" }, //( ꥯ → ᄆᄀ ) HANGUL CHOSEONG MIEUM-KIYEOK → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x11DA",L"\x1106\x1100" }, //( ᇚ → ᄆᄀ ) HANGUL JONGSEONG MIEUM-KIYEOK → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG KIYEOK	# →ᆷᆨ→

			{ L"\xD7DE",L"\x1106\x1102" }, //( ퟞ → ᄆᄂ ) HANGUL JONGSEONG MIEUM-NIEUN → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG NIEUN	# →ᆷᆫ→

			{ L"\xD7DF",L"\x1106\x1102\x1102" }, //( ퟟ → ᄆᄂᄂ ) HANGUL JONGSEONG MIEUM-SSANGNIEUN → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG NIEUN, HANGUL CHOSEONG NIEUN	# →ᆷᆫᆫ→

			{ L"\xA970",L"\x1106\x1103" }, //( ꥰ → ᄆᄃ ) HANGUL CHOSEONG MIEUM-TIKEUT → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG TIKEUT	# 

			{ L"\x11DB",L"\x1106\x1105" }, //( ᇛ → ᄆᄅ ) HANGUL JONGSEONG MIEUM-RIEUL → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG RIEUL	# →ᆷᆯ→

			{ L"\xD7E0",L"\x1106\x1106" }, //( ퟠ → ᄆᄆ ) HANGUL JONGSEONG SSANGMIEUM → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG MIEUM	# →ᆷᆷ→

			{ L"\x111C",L"\x1106\x1107" }, //( ᄜ → ᄆᄇ ) HANGUL CHOSEONG MIEUM-PIEUP → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG PIEUP	# 
			{ L"\x316E",L"\x1106\x1107" }, //( ㅮ → ᄆᄇ ) HANGUL LETTER MIEUM-PIEUP → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG PIEUP	# →ᄜ→
			{ L"\x11DC",L"\x1106\x1107" }, //( ᇜ → ᄆᄇ ) HANGUL JONGSEONG MIEUM-PIEUP → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG PIEUP	# →ᄜ→

			{ L"\xD7E1",L"\x1106\x1107\x1109" }, //( ퟡ → ᄆᄇᄉ ) HANGUL JONGSEONG MIEUM-PIEUP-SIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS	# →ᆷᆸᆺ→

			{ L"\xA971",L"\x1106\x1109" }, //( ꥱ → ᄆᄉ ) HANGUL CHOSEONG MIEUM-SIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG SIOS	# 
			{ L"\x11DD",L"\x1106\x1109" }, //( ᇝ → ᄆᄉ ) HANGUL JONGSEONG MIEUM-SIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG SIOS	# →ᆷᆺ→
			{ L"\x316F",L"\x1106\x1109" }, //( ㅯ → ᄆᄉ ) HANGUL LETTER MIEUM-SIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG SIOS	# →ᇝ→→ᆷᆺ→

			{ L"\x11DE",L"\x1106\x1109\x1109" }, //( ᇞ → ᄆᄉᄉ ) HANGUL JONGSEONG MIEUM-SSANGSIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# →ᆷᆺᆺ→

			{ L"\x111D",L"\x1106\x110B" }, //( ᄝ → ᄆᄋ ) HANGUL CHOSEONG KAPYEOUNMIEUM → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG IEUNG	# 
			{ L"\x3171",L"\x1106\x110B" }, //( ㅱ → ᄆᄋ ) HANGUL LETTER KAPYEOUNMIEUM → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG IEUNG	# →ᄝ→
			{ L"\x11E2",L"\x1106\x110B" }, //( ᇢ → ᄆᄋ ) HANGUL JONGSEONG KAPYEOUNMIEUM → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG IEUNG	# →ᄝ→

			{ L"\xD7E2",L"\x1106\x110C" }, //( ퟢ → ᄆᄌ ) HANGUL JONGSEONG MIEUM-CIEUC → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG CIEUC	# →ᆷᆽ→

			{ L"\x11E0",L"\x1106\x110E" }, //( ᇠ → ᄆᄎ ) HANGUL JONGSEONG MIEUM-CHIEUCH → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG CHIEUCH	# →ᆷᆾ→

			{ L"\x11E1",L"\x1106\x1112" }, //( ᇡ → ᄆᄒ ) HANGUL JONGSEONG MIEUM-HIEUH → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG HIEUH	# →ᆷᇂ→

			{ L"\x11DF",L"\x1106\x1140" }, //( ᇟ → ᄆᅀ ) HANGUL JONGSEONG MIEUM-PANSIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG PANSIOS	# →ᆷᇫ→
			{ L"\x3170",L"\x1106\x1140" }, //( ㅰ → ᄆᅀ ) HANGUL LETTER MIEUM-PANSIOS → HANGUL CHOSEONG MIEUM, HANGUL CHOSEONG PANSIOS	# →ᇟ→→ᆷᇫ→

			{ L"\x3142",L"\x1107" }, //( ㅂ → ᄇ ) HANGUL LETTER PIEUP → HANGUL CHOSEONG PIEUP	# 
			{ L"\x11B8",L"\x1107" }, //( ᆸ → ᄇ ) HANGUL JONGSEONG PIEUP → HANGUL CHOSEONG PIEUP	# 

			{ L"\x111E",L"\x1107\x1100" }, //( ᄞ → ᄇᄀ ) HANGUL CHOSEONG PIEUP-KIYEOK → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x3172",L"\x1107\x1100" }, //( ㅲ → ᄇᄀ ) HANGUL LETTER PIEUP-KIYEOK → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG KIYEOK	# →ᄞ→

			{ L"\x111F",L"\x1107\x1102" }, //( ᄟ → ᄇᄂ ) HANGUL CHOSEONG PIEUP-NIEUN → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG NIEUN	# 

			{ L"\x1120",L"\x1107\x1103" }, //( ᄠ → ᄇᄃ ) HANGUL CHOSEONG PIEUP-TIKEUT → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG TIKEUT	# 
			{ L"\x3173",L"\x1107\x1103" }, //( ㅳ → ᄇᄃ ) HANGUL LETTER PIEUP-TIKEUT → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG TIKEUT	# →ᄠ→
			{ L"\xD7E3",L"\x1107\x1103" }, //( ퟣ → ᄇᄃ ) HANGUL JONGSEONG PIEUP-TIKEUT → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG TIKEUT	# →ᆸᆮ→

			{ L"\x11E3",L"\x1107\x1105" }, //( ᇣ → ᄇᄅ ) HANGUL JONGSEONG PIEUP-RIEUL → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG RIEUL	# →ᆸᆯ→

			{ L"\xD7E4",L"\x1107\x1105\x1111" }, //( ퟤ → ᄇᄅᄑ ) HANGUL JONGSEONG PIEUP-RIEUL-PHIEUPH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG RIEUL, HANGUL CHOSEONG PHIEUPH	# →ᆸᆯᇁ→

			{ L"\xD7E5",L"\x1107\x1106" }, //( ퟥ → ᄇᄆ ) HANGUL JONGSEONG PIEUP-MIEUM → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG MIEUM	# →ᆸᆷ→

			{ L"\x1108",L"\x1107\x1107" }, //( ᄈ → ᄇᄇ ) HANGUL CHOSEONG SSANGPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP	# 
			{ L"\x3143",L"\x1107\x1107" }, //( ㅃ → ᄇᄇ ) HANGUL LETTER SSANGPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP	# →ᄈ→
			{ L"\xD7E6",L"\x1107\x1107" }, //( ퟦ → ᄇᄇ ) HANGUL JONGSEONG SSANGPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP	# →ᆸᆸ→

			{ L"\x112C",L"\x1107\x1107\x110B" }, //( ᄬ → ᄇᄇᄋ ) HANGUL CHOSEONG KAPYEOUNSSANGPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# 
			{ L"\x3179",L"\x1107\x1107\x110B" }, //( ㅹ → ᄇᄇᄋ ) HANGUL LETTER KAPYEOUNSSANGPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# →ᄬ→

			{ L"\x1121",L"\x1107\x1109" }, //( ᄡ → ᄇᄉ ) HANGUL CHOSEONG PIEUP-SIOS → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS	# 
			{ L"\x3144",L"\x1107\x1109" }, //( ㅄ → ᄇᄉ ) HANGUL LETTER PIEUP-SIOS → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS	# →ᄡ→
			{ L"\x11B9",L"\x1107\x1109" }, //( ᆹ → ᄇᄉ ) HANGUL JONGSEONG PIEUP-SIOS → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS	# →ᄡ→

			{ L"\x1122",L"\x1107\x1109\x1100" }, //( ᄢ → ᄇᄉᄀ ) HANGUL CHOSEONG PIEUP-SIOS-KIYEOK → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x3174",L"\x1107\x1109\x1100" }, //( ㅴ → ᄇᄉᄀ ) HANGUL LETTER PIEUP-SIOS-KIYEOK → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# →ᄢ→

			{ L"\x1123",L"\x1107\x1109\x1103" }, //( ᄣ → ᄇᄉᄃ ) HANGUL CHOSEONG PIEUP-SIOS-TIKEUT → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# 
			{ L"\x3175",L"\x1107\x1109\x1103" }, //( ㅵ → ᄇᄉᄃ ) HANGUL LETTER PIEUP-SIOS-TIKEUT → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# →ᄣ→
			{ L"\xD7E7",L"\x1107\x1109\x1103" }, //( ퟧ → ᄇᄉᄃ ) HANGUL JONGSEONG PIEUP-SIOS-TIKEUT → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# →ᆸᆺᆮ→

			{ L"\x1124",L"\x1107\x1109\x1107" }, //( ᄤ → ᄇᄉᄇ ) HANGUL CHOSEONG PIEUP-SIOS-PIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP	# 

			{ L"\x1125",L"\x1107\x1109\x1109" }, //( ᄥ → ᄇᄉᄉ ) HANGUL CHOSEONG PIEUP-SSANGSIOS → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# 

			{ L"\x1126",L"\x1107\x1109\x110C" }, //( ᄦ → ᄇᄉᄌ ) HANGUL CHOSEONG PIEUP-SIOS-CIEUC → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG CIEUC	# 

			{ L"\xA972",L"\x1107\x1109\x1110" }, //( ꥲ → ᄇᄉᄐ ) HANGUL CHOSEONG PIEUP-SIOS-THIEUTH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG THIEUTH	# 

			{ L"\x112B",L"\x1107\x110B" }, //( ᄫ → ᄇᄋ ) HANGUL CHOSEONG KAPYEOUNPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# 
			{ L"\x3178",L"\x1107\x110B" }, //( ㅸ → ᄇᄋ ) HANGUL LETTER KAPYEOUNPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# →ᄫ→
			{ L"\x11E6",L"\x1107\x110B" }, //( ᇦ → ᄇᄋ ) HANGUL JONGSEONG KAPYEOUNPIEUP → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# →ᄫ→

			{ L"\x1127",L"\x1107\x110C" }, //( ᄧ → ᄇᄌ ) HANGUL CHOSEONG PIEUP-CIEUC → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG CIEUC	# 
			{ L"\x3176",L"\x1107\x110C" }, //( ㅶ → ᄇᄌ ) HANGUL LETTER PIEUP-CIEUC → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG CIEUC	# →ᄧ→
			{ L"\xD7E8",L"\x1107\x110C" }, //( ퟨ → ᄇᄌ ) HANGUL JONGSEONG PIEUP-CIEUC → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG CIEUC	# →ᆸᆽ→

			{ L"\x1128",L"\x1107\x110E" }, //( ᄨ → ᄇᄎ ) HANGUL CHOSEONG PIEUP-CHIEUCH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG CHIEUCH	# 
			{ L"\xD7E9",L"\x1107\x110E" }, //( ퟩ → ᄇᄎ ) HANGUL JONGSEONG PIEUP-CHIEUCH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG CHIEUCH	# →ᆸᆾ→

			{ L"\xA973",L"\x1107\x110F" }, //( ꥳ → ᄇᄏ ) HANGUL CHOSEONG PIEUP-KHIEUKH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG KHIEUKH	# 

			{ L"\x1129",L"\x1107\x1110" }, //( ᄩ → ᄇᄐ ) HANGUL CHOSEONG PIEUP-THIEUTH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG THIEUTH	# 
			{ L"\x3177",L"\x1107\x1110" }, //( ㅷ → ᄇᄐ ) HANGUL LETTER PIEUP-THIEUTH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG THIEUTH	# →ᄩ→

			{ L"\x112A",L"\x1107\x1111" }, //( ᄪ → ᄇᄑ ) HANGUL CHOSEONG PIEUP-PHIEUPH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PHIEUPH	# 
			{ L"\x11E4",L"\x1107\x1111" }, //( ᇤ → ᄇᄑ ) HANGUL JONGSEONG PIEUP-PHIEUPH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PHIEUPH	# →ᄪ→

			{ L"\xA974",L"\x1107\x1112" }, //( ꥴ → ᄇᄒ ) HANGUL CHOSEONG PIEUP-HIEUH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG HIEUH	# 
			{ L"\x11E5",L"\x1107\x1112" }, //( ᇥ → ᄇᄒ ) HANGUL JONGSEONG PIEUP-HIEUH → HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG HIEUH	# →ᆸᇂ→

			{ L"\x3145",L"\x1109" }, //( ㅅ → ᄉ ) HANGUL LETTER SIOS → HANGUL CHOSEONG SIOS	# 
			{ L"\x11BA",L"\x1109" }, //( ᆺ → ᄉ ) HANGUL JONGSEONG SIOS → HANGUL CHOSEONG SIOS	# 

			{ L"\x112D",L"\x1109\x1100" }, //( ᄭ → ᄉᄀ ) HANGUL CHOSEONG SIOS-KIYEOK → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x317A",L"\x1109\x1100" }, //( ㅺ → ᄉᄀ ) HANGUL LETTER SIOS-KIYEOK → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# →ᄭ→
			{ L"\x11E7",L"\x1109\x1100" }, //( ᇧ → ᄉᄀ ) HANGUL JONGSEONG SIOS-KIYEOK → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# →ᄭ→

			{ L"\x112E",L"\x1109\x1102" }, //( ᄮ → ᄉᄂ ) HANGUL CHOSEONG SIOS-NIEUN → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG NIEUN	# 
			{ L"\x317B",L"\x1109\x1102" }, //( ㅻ → ᄉᄂ ) HANGUL LETTER SIOS-NIEUN → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG NIEUN	# →ᄮ→

			{ L"\x112F",L"\x1109\x1103" }, //( ᄯ → ᄉᄃ ) HANGUL CHOSEONG SIOS-TIKEUT → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# 
			{ L"\x317C",L"\x1109\x1103" }, //( ㅼ → ᄉᄃ ) HANGUL LETTER SIOS-TIKEUT → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# →ᄯ→
			{ L"\x11E8",L"\x1109\x1103" }, //( ᇨ → ᄉᄃ ) HANGUL JONGSEONG SIOS-TIKEUT → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# →ᄯ→

			{ L"\x1130",L"\x1109\x1105" }, //( ᄰ → ᄉᄅ ) HANGUL CHOSEONG SIOS-RIEUL → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG RIEUL	# 
			{ L"\x11E9",L"\x1109\x1105" }, //( ᇩ → ᄉᄅ ) HANGUL JONGSEONG SIOS-RIEUL → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG RIEUL	# →ᄰ→

			{ L"\x1131",L"\x1109\x1106" }, //( ᄱ → ᄉᄆ ) HANGUL CHOSEONG SIOS-MIEUM → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG MIEUM	# 
			{ L"\xD7EA",L"\x1109\x1106" }, //( ퟪ → ᄉᄆ ) HANGUL JONGSEONG SIOS-MIEUM → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG MIEUM	# →ᆺᆷ→

			{ L"\x1132",L"\x1109\x1107" }, //( ᄲ → ᄉᄇ ) HANGUL CHOSEONG SIOS-PIEUP → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP	# 
			{ L"\x317D",L"\x1109\x1107" }, //( ㅽ → ᄉᄇ ) HANGUL LETTER SIOS-PIEUP → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP	# →ᄲ→
			{ L"\x11EA",L"\x1109\x1107" }, //( ᇪ → ᄉᄇ ) HANGUL JONGSEONG SIOS-PIEUP → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP	# →ᄲ→

			{ L"\x1133",L"\x1109\x1107\x1100" }, //( ᄳ → ᄉᄇᄀ ) HANGUL CHOSEONG SIOS-PIEUP-KIYEOK → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG KIYEOK	# 

			{ L"\xD7EB",L"\x1109\x1107\x110B" }, //( ퟫ → ᄉᄇᄋ ) HANGUL JONGSEONG SIOS-KAPYEOUNPIEUP → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# →ᆺᆸᆼ→

			{ L"\x110A",L"\x1109\x1109" }, //( ᄊ → ᄉᄉ ) HANGUL CHOSEONG SSANGSIOS → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# 
			{ L"\x3146",L"\x1109\x1109" }, //( ㅆ → ᄉᄉ ) HANGUL LETTER SSANGSIOS → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# →ᄊ→
			{ L"\x11BB",L"\x1109\x1109" }, //( ᆻ → ᄉᄉ ) HANGUL JONGSEONG SSANGSIOS → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# →ᄊ→

			{ L"\xD7EC",L"\x1109\x1109\x1100" }, //( ퟬ → ᄉᄉᄀ ) HANGUL JONGSEONG SSANGSIOS-KIYEOK → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KIYEOK	# →ᆺᆺᆨ→

			{ L"\xD7ED",L"\x1109\x1109\x1103" }, //( ퟭ → ᄉᄉᄃ ) HANGUL JONGSEONG SSANGSIOS-TIKEUT → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG TIKEUT	# →ᆺᆺᆮ→

			{ L"\xA975",L"\x1109\x1109\x1107" }, //( ꥵ → ᄉᄉᄇ ) HANGUL CHOSEONG SSANGSIOS-PIEUP → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PIEUP	# 

			{ L"\x1134",L"\x1109\x1109\x1109" }, //( ᄴ → ᄉᄉᄉ ) HANGUL CHOSEONG SIOS-SSANGSIOS → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS, HANGUL CHOSEONG SIOS	# 

			{ L"\x1135",L"\x1109\x110B" }, //( ᄵ → ᄉᄋ ) HANGUL CHOSEONG SIOS-IEUNG → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG IEUNG	# 

			{ L"\x1136",L"\x1109\x110C" }, //( ᄶ → ᄉᄌ ) HANGUL CHOSEONG SIOS-CIEUC → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG CIEUC	# 
			{ L"\x317E",L"\x1109\x110C" }, //( ㅾ → ᄉᄌ ) HANGUL LETTER SIOS-CIEUC → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG CIEUC	# →ᄶ→
			{ L"\xD7EF",L"\x1109\x110C" }, //( ퟯ → ᄉᄌ ) HANGUL JONGSEONG SIOS-CIEUC → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG CIEUC	# →ᆺᆽ→

			{ L"\x1137",L"\x1109\x110E" }, //( ᄷ → ᄉᄎ ) HANGUL CHOSEONG SIOS-CHIEUCH → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG CHIEUCH	# 
			{ L"\xD7F0",L"\x1109\x110E" }, //( ퟰ → ᄉᄎ ) HANGUL JONGSEONG SIOS-CHIEUCH → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG CHIEUCH	# →ᆺᆾ→

			{ L"\x1138",L"\x1109\x110F" }, //( ᄸ → ᄉᄏ ) HANGUL CHOSEONG SIOS-KHIEUKH → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG KHIEUKH	# 

			{ L"\x1139",L"\x1109\x1110" }, //( ᄹ → ᄉᄐ ) HANGUL CHOSEONG SIOS-THIEUTH → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG THIEUTH	# 
			{ L"\xD7F1",L"\x1109\x1110" }, //( ퟱ → ᄉᄐ ) HANGUL JONGSEONG SIOS-THIEUTH → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG THIEUTH	# →ᆺᇀ→

			{ L"\x113A",L"\x1109\x1111" }, //( ᄺ → ᄉᄑ ) HANGUL CHOSEONG SIOS-PHIEUPH → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PHIEUPH	# 

			{ L"\xD7EE",L"\x1109\x1140" }, //( ퟮ → ᄉᅀ ) HANGUL JONGSEONG SIOS-PANSIOS → HANGUL CHOSEONG SIOS, HANGUL CHOSEONG PANSIOS	# →ᆺᇫ→

			{ L"\x3147",L"\x110B" }, //( ㅇ → ᄋ ) HANGUL LETTER IEUNG → HANGUL CHOSEONG IEUNG	# 
			{ L"\x11BC",L"\x110B" }, //( ᆼ → ᄋ ) HANGUL JONGSEONG IEUNG → HANGUL CHOSEONG IEUNG	# 

			{ L"\x1141",L"\x110B\x1100" }, //( ᅁ → ᄋᄀ ) HANGUL CHOSEONG IEUNG-KIYEOK → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG KIYEOK	# 
			{ L"\x11EC",L"\x110B\x1100" }, //( ᇬ → ᄋᄀ ) HANGUL JONGSEONG IEUNG-KIYEOK → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG KIYEOK	# →ᅁ→

			{ L"\x11ED",L"\x110B\x1100\x1100" }, //( ᇭ → ᄋᄀᄀ ) HANGUL JONGSEONG IEUNG-SSANGKIYEOK → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG KIYEOK, HANGUL CHOSEONG KIYEOK	# →ᆼᆨᆨ→

			{ L"\x1142",L"\x110B\x1103" }, //( ᅂ → ᄋᄃ ) HANGUL CHOSEONG IEUNG-TIKEUT → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG TIKEUT	# 

			{ L"\xA976",L"\x110B\x1105" }, //( ꥶ → ᄋᄅ ) HANGUL CHOSEONG IEUNG-RIEUL → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG RIEUL	# 

			{ L"\x1143",L"\x110B\x1106" }, //( ᅃ → ᄋᄆ ) HANGUL CHOSEONG IEUNG-MIEUM → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG MIEUM	# 

			{ L"\x1144",L"\x110B\x1107" }, //( ᅄ → ᄋᄇ ) HANGUL CHOSEONG IEUNG-PIEUP → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG PIEUP	# 

			{ L"\x1145",L"\x110B\x1109" }, //( ᅅ → ᄋᄉ ) HANGUL CHOSEONG IEUNG-SIOS → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG SIOS	# 
			{ L"\x11F1",L"\x110B\x1109" }, //( ᇱ → ᄋᄉ ) HANGUL JONGSEONG YESIEUNG-SIOS → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG SIOS	# →ᅅ→
			{ L"\x3182",L"\x110B\x1109" }, //( ㆂ → ᄋᄉ ) HANGUL LETTER YESIEUNG-SIOS → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG SIOS	# →ᇱ→→ᅅ→

			{ L"\x1147",L"\x110B\x110B" }, //( ᅇ → ᄋᄋ ) HANGUL CHOSEONG SSANGIEUNG → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG IEUNG	# 
			{ L"\x3180",L"\x110B\x110B" }, //( ㆀ → ᄋᄋ ) HANGUL LETTER SSANGIEUNG → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG IEUNG	# →ᅇ→
			{ L"\x11EE",L"\x110B\x110B" }, //( ᇮ → ᄋᄋ ) HANGUL JONGSEONG SSANGIEUNG → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG IEUNG	# →ᅇ→

			{ L"\x1148",L"\x110B\x110C" }, //( ᅈ → ᄋᄌ ) HANGUL CHOSEONG IEUNG-CIEUC → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG CIEUC	# 

			{ L"\x1149",L"\x110B\x110E" }, //( ᅉ → ᄋᄎ ) HANGUL CHOSEONG IEUNG-CHIEUCH → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG CHIEUCH	# 

			{ L"\x11EF",L"\x110B\x110F" }, //( ᇯ → ᄋᄏ ) HANGUL JONGSEONG IEUNG-KHIEUKH → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG KHIEUKH	# →ᆼᆿ→

			{ L"\x114A",L"\x110B\x1110" }, //( ᅊ → ᄋᄐ ) HANGUL CHOSEONG IEUNG-THIEUTH → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG THIEUTH	# 

			{ L"\x114B",L"\x110B\x1111" }, //( ᅋ → ᄋᄑ ) HANGUL CHOSEONG IEUNG-PHIEUPH → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG PHIEUPH	# 

			{ L"\xA977",L"\x110B\x1112" }, //( ꥷ → ᄋᄒ ) HANGUL CHOSEONG IEUNG-HIEUH → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG HIEUH	# 

			{ L"\x1146",L"\x110B\x1140" }, //( ᅆ → ᄋᅀ ) HANGUL CHOSEONG IEUNG-PANSIOS → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG PANSIOS	# 
			{ L"\x11F2",L"\x110B\x1140" }, //( ᇲ → ᄋᅀ ) HANGUL JONGSEONG YESIEUNG-PANSIOS → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG PANSIOS	# →ᅆ→
			{ L"\x3183",L"\x110B\x1140" }, //( ㆃ → ᄋᅀ ) HANGUL LETTER YESIEUNG-PANSIOS → HANGUL CHOSEONG IEUNG, HANGUL CHOSEONG PANSIOS	# →ᇲ→→ᅆ→

			{ L"\x3148",L"\x110C" }, //( ㅈ → ᄌ ) HANGUL LETTER CIEUC → HANGUL CHOSEONG CIEUC	# 
			{ L"\x11BD",L"\x110C" }, //( ᆽ → ᄌ ) HANGUL JONGSEONG CIEUC → HANGUL CHOSEONG CIEUC	# 

			{ L"\xD7F7",L"\x110C\x1107" }, //( ퟷ → ᄌᄇ ) HANGUL JONGSEONG CIEUC-PIEUP → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG PIEUP	# →ᆽᆸ→

			{ L"\xD7F8",L"\x110C\x1107\x1107" }, //( ퟸ → ᄌᄇᄇ ) HANGUL JONGSEONG CIEUC-SSANGPIEUP → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG PIEUP	# →ᆽᆸᆸ→

			{ L"\x114D",L"\x110C\x110B" }, //( ᅍ → ᄌᄋ ) HANGUL CHOSEONG CIEUC-IEUNG → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG IEUNG	# 

			{ L"\x110D",L"\x110C\x110C" }, //( ᄍ → ᄌᄌ ) HANGUL CHOSEONG SSANGCIEUC → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG CIEUC	# 
			{ L"\x3149",L"\x110C\x110C" }, //( ㅉ → ᄌᄌ ) HANGUL LETTER SSANGCIEUC → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG CIEUC	# →ᄍ→
			{ L"\xD7F9",L"\x110C\x110C" }, //( ퟹ → ᄌᄌ ) HANGUL JONGSEONG SSANGCIEUC → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG CIEUC	# →ᆽᆽ→

			{ L"\xA978",L"\x110C\x110C\x1112" }, //( ꥸ → ᄌᄌᄒ ) HANGUL CHOSEONG SSANGCIEUC-HIEUH → HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG CIEUC, HANGUL CHOSEONG HIEUH	# 

			{ L"\x314A",L"\x110E" }, //( ㅊ → ᄎ ) HANGUL LETTER CHIEUCH → HANGUL CHOSEONG CHIEUCH	# 
			{ L"\x11BE",L"\x110E" }, //( ᆾ → ᄎ ) HANGUL JONGSEONG CHIEUCH → HANGUL CHOSEONG CHIEUCH	# 

			{ L"\x1152",L"\x110E\x110F" }, //( ᅒ → ᄎᄏ ) HANGUL CHOSEONG CHIEUCH-KHIEUKH → HANGUL CHOSEONG CHIEUCH, HANGUL CHOSEONG KHIEUKH	# 

			{ L"\x1153",L"\x110E\x1112" }, //( ᅓ → ᄎᄒ ) HANGUL CHOSEONG CHIEUCH-HIEUH → HANGUL CHOSEONG CHIEUCH, HANGUL CHOSEONG HIEUH	# 

			{ L"\x314B",L"\x110F" }, //( ㅋ → ᄏ ) HANGUL LETTER KHIEUKH → HANGUL CHOSEONG KHIEUKH	# 
			{ L"\x11BF",L"\x110F" }, //( ᆿ → ᄏ ) HANGUL JONGSEONG KHIEUKH → HANGUL CHOSEONG KHIEUKH	# 

			{ L"\x314C",L"\x1110" }, //( ㅌ → ᄐ ) HANGUL LETTER THIEUTH → HANGUL CHOSEONG THIEUTH	# 
			{ L"\x11C0",L"\x1110" }, //( ᇀ → ᄐ ) HANGUL JONGSEONG THIEUTH → HANGUL CHOSEONG THIEUTH	# 

			{ L"\xA979",L"\x1110\x1110" }, //( ꥹ → ᄐᄐ ) HANGUL CHOSEONG SSANGTHIEUTH → HANGUL CHOSEONG THIEUTH, HANGUL CHOSEONG THIEUTH	# 

			{ L"\x314D",L"\x1111" }, //( ㅍ → ᄑ ) HANGUL LETTER PHIEUPH → HANGUL CHOSEONG PHIEUPH	# 
			{ L"\x11C1",L"\x1111" }, //( ᇁ → ᄑ ) HANGUL JONGSEONG PHIEUPH → HANGUL CHOSEONG PHIEUPH	# 

			{ L"\x1156",L"\x1111\x1107" }, //( ᅖ → ᄑᄇ ) HANGUL CHOSEONG PHIEUPH-PIEUP → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG PIEUP	# 
			{ L"\x11F3",L"\x1111\x1107" }, //( ᇳ → ᄑᄇ ) HANGUL JONGSEONG PHIEUPH-PIEUP → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG PIEUP	# →ᅖ→

			{ L"\xD7FA",L"\x1111\x1109" }, //( ퟺ → ᄑᄉ ) HANGUL JONGSEONG PHIEUPH-SIOS → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG SIOS	# →ᇁᆺ→

			{ L"\x1157",L"\x1111\x110B" }, //( ᅗ → ᄑᄋ ) HANGUL CHOSEONG KAPYEOUNPHIEUPH → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG IEUNG	# 
			{ L"\x3184",L"\x1111\x110B" }, //( ㆄ → ᄑᄋ ) HANGUL LETTER KAPYEOUNPHIEUPH → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG IEUNG	# →ᅗ→
			{ L"\x11F4",L"\x1111\x110B" }, //( ᇴ → ᄑᄋ ) HANGUL JONGSEONG KAPYEOUNPHIEUPH → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG IEUNG	# →ᅗ→

			{ L"\xD7FB",L"\x1111\x1110" }, //( ퟻ → ᄑᄐ ) HANGUL JONGSEONG PHIEUPH-THIEUTH → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG THIEUTH	# →ᇁᇀ→

			{ L"\xA97A",L"\x1111\x1112" }, //( ꥺ → ᄑᄒ ) HANGUL CHOSEONG PHIEUPH-HIEUH → HANGUL CHOSEONG PHIEUPH, HANGUL CHOSEONG HIEUH	# 

			{ L"\x314E",L"\x1112" }, //( ㅎ → ᄒ ) HANGUL LETTER HIEUH → HANGUL CHOSEONG HIEUH	# 
			{ L"\x11C2",L"\x1112" }, //( ᇂ → ᄒ ) HANGUL JONGSEONG HIEUH → HANGUL CHOSEONG HIEUH	# 

			{ L"\x11F5",L"\x1112\x1102" }, //( ᇵ → ᄒᄂ ) HANGUL JONGSEONG HIEUH-NIEUN → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG NIEUN	# →ᇂᆫ→

			{ L"\x11F6",L"\x1112\x1105" }, //( ᇶ → ᄒᄅ ) HANGUL JONGSEONG HIEUH-RIEUL → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG RIEUL	# →ᇂᆯ→

			{ L"\x11F7",L"\x1112\x1106" }, //( ᇷ → ᄒᄆ ) HANGUL JONGSEONG HIEUH-MIEUM → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG MIEUM	# →ᇂᆷ→

			{ L"\x11F8",L"\x1112\x1107" }, //( ᇸ → ᄒᄇ ) HANGUL JONGSEONG HIEUH-PIEUP → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG PIEUP	# →ᇂᆸ→

			{ L"\xA97B",L"\x1112\x1109" }, //( ꥻ → ᄒᄉ ) HANGUL CHOSEONG HIEUH-SIOS → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG SIOS	# 

			{ L"\x1158",L"\x1112\x1112" }, //( ᅘ → ᄒᄒ ) HANGUL CHOSEONG SSANGHIEUH → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG HIEUH	# 
			{ L"\x3185",L"\x1112\x1112" }, //( ㆅ → ᄒᄒ ) HANGUL LETTER SSANGHIEUH → HANGUL CHOSEONG HIEUH, HANGUL CHOSEONG HIEUH	# →ᅘ→

			{ L"\x113D",L"\x113C\x113C" }, //( ᄽ → ᄼᄼ ) HANGUL CHOSEONG CHITUEUMSSANGSIOS → HANGUL CHOSEONG CHITUEUMSIOS, HANGUL CHOSEONG CHITUEUMSIOS	# 

			{ L"\x113F",L"\x113E\x113E" }, //( ᄿ → ᄾᄾ ) HANGUL CHOSEONG CEONGCHIEUMSSANGSIOS → HANGUL CHOSEONG CEONGCHIEUMSIOS, HANGUL CHOSEONG CEONGCHIEUMSIOS	# 

			{ L"\x317F",L"\x1140" }, //( ㅿ → ᅀ ) HANGUL LETTER PANSIOS → HANGUL CHOSEONG PANSIOS	# 
			{ L"\x11EB",L"\x1140" }, //( ᇫ → ᅀ ) HANGUL JONGSEONG PANSIOS → HANGUL CHOSEONG PANSIOS	# 

			{ L"\xD7F3",L"\x1140\x1107" }, //( ퟳ → ᅀᄇ ) HANGUL JONGSEONG PANSIOS-PIEUP → HANGUL CHOSEONG PANSIOS, HANGUL CHOSEONG PIEUP	# →ᇫᆸ→

			{ L"\xD7F4",L"\x1140\x1107\x110B" }, //( ퟴ → ᅀᄇᄋ ) HANGUL JONGSEONG PANSIOS-KAPYEOUNPIEUP → HANGUL CHOSEONG PANSIOS, HANGUL CHOSEONG PIEUP, HANGUL CHOSEONG IEUNG	# →ᇫᆸᆼ→

			{ L"\x3181",L"\x114C" }, //( ㆁ → ᅌ ) HANGUL LETTER YESIEUNG → HANGUL CHOSEONG YESIEUNG	# 
			{ L"\x11F0",L"\x114C" }, //( ᇰ → ᅌ ) HANGUL JONGSEONG YESIEUNG → HANGUL CHOSEONG YESIEUNG	# 

			{ L"\xD7F5",L"\x114C\x1106" }, //( ퟵ → ᅌᄆ ) HANGUL JONGSEONG YESIEUNG-MIEUM → HANGUL CHOSEONG YESIEUNG, HANGUL CHOSEONG MIEUM	# →ᇰᆷ→

			{ L"\xD7F6",L"\x114C\x1112" }, //( ퟶ → ᅌᄒ ) HANGUL JONGSEONG YESIEUNG-HIEUH → HANGUL CHOSEONG YESIEUNG, HANGUL CHOSEONG HIEUH	# →ᇰᇂ→

			{ L"\x114F",L"\x114E\x114E" }, //( ᅏ → ᅎᅎ ) HANGUL CHOSEONG CHITUEUMSSANGCIEUC → HANGUL CHOSEONG CHITUEUMCIEUC, HANGUL CHOSEONG CHITUEUMCIEUC	# 

			{ L"\x1151",L"\x1150\x1150" }, //( ᅑ → ᅐᅐ ) HANGUL CHOSEONG CEONGCHIEUMSSANGCIEUC → HANGUL CHOSEONG CEONGCHIEUMCIEUC, HANGUL CHOSEONG CEONGCHIEUMCIEUC	# 

			{ L"\x3186",L"\x1159" }, //( ㆆ → ᅙ ) HANGUL LETTER YEORINHIEUH → HANGUL CHOSEONG YEORINHIEUH	# 
			{ L"\x11F9",L"\x1159" }, //( ᇹ → ᅙ ) HANGUL JONGSEONG YEORINHIEUH → HANGUL CHOSEONG YEORINHIEUH	# 

			{ L"\xA97C",L"\x1159\x1159" }, //( ꥼ → ᅙᅙ ) HANGUL CHOSEONG SSANGYEORINHIEUH → HANGUL CHOSEONG YEORINHIEUH, HANGUL CHOSEONG YEORINHIEUH	# 

			{ L"\x3164",L"\x1160" }, //(  →  ) HANGUL FILLER → HANGUL JUNGSEONG FILLER	# 

			{ L"\x314F",L"\x1161" }, //( ㅏ → ᅡ ) HANGUL LETTER A → HANGUL JUNGSEONG A	# 

			{ L"\x11A3",L"\x1161\x30FC" }, //( ᆣ → ᅡー ) HANGUL JUNGSEONG A-EU → HANGUL JUNGSEONG A, KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →ᅡᅳ→

			{ L"\x1176",L"\x1161\x1169" }, //( ᅶ → ᅡᅩ ) HANGUL JUNGSEONG A-O → HANGUL JUNGSEONG A, HANGUL JUNGSEONG O	# 

			{ L"\x1177",L"\x1161\x116E" }, //( ᅷ → ᅡᅮ ) HANGUL JUNGSEONG A-U → HANGUL JUNGSEONG A, HANGUL JUNGSEONG U	# 

			{ L"\x1162",L"\x1161\x4E28" }, //( ᅢ → ᅡ丨 ) HANGUL JUNGSEONG AE → HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅡᅵ→
			{ L"\x3150",L"\x1161\x4E28" }, //( ㅐ → ᅡ丨 ) HANGUL LETTER AE → HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅢ→→ᅡᅵ→

			{ L"\x3151",L"\x1163" }, //( ㅑ → ᅣ ) HANGUL LETTER YA → HANGUL JUNGSEONG YA	# 

			{ L"\x1178",L"\x1163\x1169" }, //( ᅸ → ᅣᅩ ) HANGUL JUNGSEONG YA-O → HANGUL JUNGSEONG YA, HANGUL JUNGSEONG O	# 

			{ L"\x1179",L"\x1163\x116D" }, //( ᅹ → ᅣᅭ ) HANGUL JUNGSEONG YA-YO → HANGUL JUNGSEONG YA, HANGUL JUNGSEONG YO	# 

			{ L"\x11A4",L"\x1163\x116E" }, //( ᆤ → ᅣᅮ ) HANGUL JUNGSEONG YA-U → HANGUL JUNGSEONG YA, HANGUL JUNGSEONG U	# 

			{ L"\x1164",L"\x1163\x4E28" }, //( ᅤ → ᅣ丨 ) HANGUL JUNGSEONG YAE → HANGUL JUNGSEONG YA, CJK UNIFIED IDEOGRAPH-4E28	# →ᅣᅵ→
			{ L"\x3152",L"\x1163\x4E28" }, //( ㅒ → ᅣ丨 ) HANGUL LETTER YAE → HANGUL JUNGSEONG YA, CJK UNIFIED IDEOGRAPH-4E28	# →ᅤ→→ᅣᅵ→

			{ L"\x3153",L"\x1165" }, //( ㅓ → ᅥ ) HANGUL LETTER EO → HANGUL JUNGSEONG EO	# 

			{ L"\x117C",L"\x1165\x30FC" }, //( ᅼ → ᅥー ) HANGUL JUNGSEONG EO-EU → HANGUL JUNGSEONG EO, KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →ᅥᅳ→

			{ L"\x117A",L"\x1165\x1169" }, //( ᅺ → ᅥᅩ ) HANGUL JUNGSEONG EO-O → HANGUL JUNGSEONG EO, HANGUL JUNGSEONG O	# 

			{ L"\x117B",L"\x1165\x116E" }, //( ᅻ → ᅥᅮ ) HANGUL JUNGSEONG EO-U → HANGUL JUNGSEONG EO, HANGUL JUNGSEONG U	# 

			{ L"\x1166",L"\x1165\x4E28" }, //( ᅦ → ᅥ丨 ) HANGUL JUNGSEONG E → HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅥᅵ→
			{ L"\x3154",L"\x1165\x4E28" }, //( ㅔ → ᅥ丨 ) HANGUL LETTER E → HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅦ→→ᅥᅵ→

			{ L"\x3155",L"\x1167" }, //( ㅕ → ᅧ ) HANGUL LETTER YEO → HANGUL JUNGSEONG YEO	# 

			{ L"\x11A5",L"\x1167\x1163" }, //( ᆥ → ᅧᅣ ) HANGUL JUNGSEONG YEO-YA → HANGUL JUNGSEONG YEO, HANGUL JUNGSEONG YA	# 

			{ L"\x117D",L"\x1167\x1169" }, //( ᅽ → ᅧᅩ ) HANGUL JUNGSEONG YEO-O → HANGUL JUNGSEONG YEO, HANGUL JUNGSEONG O	# 

			{ L"\x117E",L"\x1167\x116E" }, //( ᅾ → ᅧᅮ ) HANGUL JUNGSEONG YEO-U → HANGUL JUNGSEONG YEO, HANGUL JUNGSEONG U	# 

			{ L"\x1168",L"\x1167\x4E28" }, //( ᅨ → ᅧ丨 ) HANGUL JUNGSEONG YE → HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅧᅵ→
			{ L"\x3156",L"\x1167\x4E28" }, //( ㅖ → ᅧ丨 ) HANGUL LETTER YE → HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅨ→→ᅧᅵ→

			{ L"\x3157",L"\x1169" }, //( ㅗ → ᅩ ) HANGUL LETTER O → HANGUL JUNGSEONG O	# 

			{ L"\x116A",L"\x1169\x1161" }, //( ᅪ → ᅩᅡ ) HANGUL JUNGSEONG WA → HANGUL JUNGSEONG O, HANGUL JUNGSEONG A	# 
			{ L"\x3158",L"\x1169\x1161" }, //( ㅘ → ᅩᅡ ) HANGUL LETTER WA → HANGUL JUNGSEONG O, HANGUL JUNGSEONG A	# →ᅪ→

			{ L"\x116B",L"\x1169\x1161\x4E28" }, //( ᅫ → ᅩᅡ丨 ) HANGUL JUNGSEONG WAE → HANGUL JUNGSEONG O, HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅩᅡᅵ→
			{ L"\x3159",L"\x1169\x1161\x4E28" }, //( ㅙ → ᅩᅡ丨 ) HANGUL LETTER WAE → HANGUL JUNGSEONG O, HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅫ→→ᅩᅡᅵ→

			{ L"\x11A6",L"\x1169\x1163" }, //( ᆦ → ᅩᅣ ) HANGUL JUNGSEONG O-YA → HANGUL JUNGSEONG O, HANGUL JUNGSEONG YA	# 

			{ L"\x11A7",L"\x1169\x1163\x4E28" }, //( ᆧ → ᅩᅣ丨 ) HANGUL JUNGSEONG O-YAE → HANGUL JUNGSEONG O, HANGUL JUNGSEONG YA, CJK UNIFIED IDEOGRAPH-4E28	# →ᅩᅣᅵ→

			{ L"\x117F",L"\x1169\x1165" }, //( ᅿ → ᅩᅥ ) HANGUL JUNGSEONG O-EO → HANGUL JUNGSEONG O, HANGUL JUNGSEONG EO	# 

			{ L"\x1180",L"\x1169\x1165\x4E28" }, //( ᆀ → ᅩᅥ丨 ) HANGUL JUNGSEONG O-E → HANGUL JUNGSEONG O, HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅩᅥᅵ→

			{ L"\xD7B0",L"\x1169\x1167" }, //( ힰ → ᅩᅧ ) HANGUL JUNGSEONG O-YEO → HANGUL JUNGSEONG O, HANGUL JUNGSEONG YEO	# 

			{ L"\x1181",L"\x1169\x1167\x4E28" }, //( ᆁ → ᅩᅧ丨 ) HANGUL JUNGSEONG O-YE → HANGUL JUNGSEONG O, HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅩᅧᅵ→

			{ L"\x1182",L"\x1169\x1169" }, //( ᆂ → ᅩᅩ ) HANGUL JUNGSEONG O-O → HANGUL JUNGSEONG O, HANGUL JUNGSEONG O	# 

			{ L"\xD7B1",L"\x1169\x1169\x4E28" }, //( ힱ → ᅩᅩ丨 ) HANGUL JUNGSEONG O-O-I → HANGUL JUNGSEONG O, HANGUL JUNGSEONG O, CJK UNIFIED IDEOGRAPH-4E28	# →ᅩᅩᅵ→

			{ L"\x1183",L"\x1169\x116E" }, //( ᆃ → ᅩᅮ ) HANGUL JUNGSEONG O-U → HANGUL JUNGSEONG O, HANGUL JUNGSEONG U	# 

			{ L"\x116C",L"\x1169\x4E28" }, //( ᅬ → ᅩ丨 ) HANGUL JUNGSEONG OE → HANGUL JUNGSEONG O, CJK UNIFIED IDEOGRAPH-4E28	# →ᅩᅵ→
			{ L"\x315A",L"\x1169\x4E28" }, //( ㅚ → ᅩ丨 ) HANGUL LETTER OE → HANGUL JUNGSEONG O, CJK UNIFIED IDEOGRAPH-4E28	# →ᅬ→→ᅩᅵ→

			{ L"\x315B",L"\x116D" }, //( ㅛ → ᅭ ) HANGUL LETTER YO → HANGUL JUNGSEONG YO	# 

			{ L"\xD7B2",L"\x116D\x1161" }, //( ힲ → ᅭᅡ ) HANGUL JUNGSEONG YO-A → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG A	# 

			{ L"\xD7B3",L"\x116D\x1161\x4E28" }, //( ힳ → ᅭᅡ丨 ) HANGUL JUNGSEONG YO-AE → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅭᅡᅵ→

			{ L"\x1184",L"\x116D\x1163" }, //( ᆄ → ᅭᅣ ) HANGUL JUNGSEONG YO-YA → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG YA	# 
			{ L"\x3187",L"\x116D\x1163" }, //( ㆇ → ᅭᅣ ) HANGUL LETTER YO-YA → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG YA	# →ᆄ→
			{ L"\x1186",L"\x116D\x1163" }, //( ᆆ → ᅭᅣ ) HANGUL JUNGSEONG YO-YEO → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG YA	# →ᆄ→

			{ L"\x1185",L"\x116D\x1163\x4E28" }, //( ᆅ → ᅭᅣ丨 ) HANGUL JUNGSEONG YO-YAE → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG YA, CJK UNIFIED IDEOGRAPH-4E28	# →ᅭᅣᅵ→
			{ L"\x3188",L"\x116D\x1163\x4E28" }, //( ㆈ → ᅭᅣ丨 ) HANGUL LETTER YO-YAE → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG YA, CJK UNIFIED IDEOGRAPH-4E28	# →ᆅ→→ᅭᅣᅵ→

			{ L"\xD7B4",L"\x116D\x1165" }, //( ힴ → ᅭᅥ ) HANGUL JUNGSEONG YO-EO → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG EO	# 

			{ L"\x1187",L"\x116D\x1169" }, //( ᆇ → ᅭᅩ ) HANGUL JUNGSEONG YO-O → HANGUL JUNGSEONG YO, HANGUL JUNGSEONG O	# 

			{ L"\x1188",L"\x116D\x4E28" }, //( ᆈ → ᅭ丨 ) HANGUL JUNGSEONG YO-I → HANGUL JUNGSEONG YO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅭᅵ→
			{ L"\x3189",L"\x116D\x4E28" }, //( ㆉ → ᅭ丨 ) HANGUL LETTER YO-I → HANGUL JUNGSEONG YO, CJK UNIFIED IDEOGRAPH-4E28	# →ᆈ→→ᅭᅵ→

			{ L"\x315C",L"\x116E" }, //( ㅜ → ᅮ ) HANGUL LETTER U → HANGUL JUNGSEONG U	# 

			{ L"\x1189",L"\x116E\x1161" }, //( ᆉ → ᅮᅡ ) HANGUL JUNGSEONG U-A → HANGUL JUNGSEONG U, HANGUL JUNGSEONG A	# 

			{ L"\x118A",L"\x116E\x1161\x4E28" }, //( ᆊ → ᅮᅡ丨 ) HANGUL JUNGSEONG U-AE → HANGUL JUNGSEONG U, HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅮᅡᅵ→

			{ L"\x116F",L"\x116E\x1165" }, //( ᅯ → ᅮᅥ ) HANGUL JUNGSEONG WEO → HANGUL JUNGSEONG U, HANGUL JUNGSEONG EO	# 
			{ L"\x315D",L"\x116E\x1165" }, //( ㅝ → ᅮᅥ ) HANGUL LETTER WEO → HANGUL JUNGSEONG U, HANGUL JUNGSEONG EO	# →ᅯ→

			{ L"\x118B",L"\x116E\x1165\x30FC" }, //( ᆋ → ᅮᅥー ) HANGUL JUNGSEONG U-EO-EU → HANGUL JUNGSEONG U, HANGUL JUNGSEONG EO, KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →ᅮᅥᅳ→

			{ L"\x1170",L"\x116E\x1165\x4E28" }, //( ᅰ → ᅮᅥ丨 ) HANGUL JUNGSEONG WE → HANGUL JUNGSEONG U, HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅮᅥᅵ→
			{ L"\x315E",L"\x116E\x1165\x4E28" }, //( ㅞ → ᅮᅥ丨 ) HANGUL LETTER WE → HANGUL JUNGSEONG U, HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅰ→→ᅮᅥᅵ→

			{ L"\xD7B5",L"\x116E\x1167" }, //( ힵ → ᅮᅧ ) HANGUL JUNGSEONG U-YEO → HANGUL JUNGSEONG U, HANGUL JUNGSEONG YEO	# 

			{ L"\x118C",L"\x116E\x1167\x4E28" }, //( ᆌ → ᅮᅧ丨 ) HANGUL JUNGSEONG U-YE → HANGUL JUNGSEONG U, HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅮᅧᅵ→

			{ L"\x118D",L"\x116E\x116E" }, //( ᆍ → ᅮᅮ ) HANGUL JUNGSEONG U-U → HANGUL JUNGSEONG U, HANGUL JUNGSEONG U	# 

			{ L"\x1171",L"\x116E\x4E28" }, //( ᅱ → ᅮ丨 ) HANGUL JUNGSEONG WI → HANGUL JUNGSEONG U, CJK UNIFIED IDEOGRAPH-4E28	# →ᅮᅵ→
			{ L"\x315F",L"\x116E\x4E28" }, //( ㅟ → ᅮ丨 ) HANGUL LETTER WI → HANGUL JUNGSEONG U, CJK UNIFIED IDEOGRAPH-4E28	# →ᅱ→→ᅮᅵ→

			{ L"\xD7B6",L"\x116E\x4E28\x4E28" }, //( ힶ → ᅮ丨丨 ) HANGUL JUNGSEONG U-I-I → HANGUL JUNGSEONG U, CJK UNIFIED IDEOGRAPH-4E28, CJK UNIFIED IDEOGRAPH-4E28	# →ᅮᅵᅵ→

			{ L"\x3160",L"\x1172" }, //( ㅠ → ᅲ ) HANGUL LETTER YU → HANGUL JUNGSEONG YU	# 

			{ L"\x118E",L"\x1172\x1161" }, //( ᆎ → ᅲᅡ ) HANGUL JUNGSEONG YU-A → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG A	# 

			{ L"\xD7B7",L"\x1172\x1161\x4E28" }, //( ힷ → ᅲᅡ丨 ) HANGUL JUNGSEONG YU-AE → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG A, CJK UNIFIED IDEOGRAPH-4E28	# →ᅲᅡᅵ→

			{ L"\x118F",L"\x1172\x1165" }, //( ᆏ → ᅲᅥ ) HANGUL JUNGSEONG YU-EO → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG EO	# 

			{ L"\x1190",L"\x1172\x1165\x4E28" }, //( ᆐ → ᅲᅥ丨 ) HANGUL JUNGSEONG YU-E → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅲᅥᅵ→

			{ L"\x1191",L"\x1172\x1167" }, //( ᆑ → ᅲᅧ ) HANGUL JUNGSEONG YU-YEO → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG YEO	# 
			{ L"\x318A",L"\x1172\x1167" }, //( ㆊ → ᅲᅧ ) HANGUL LETTER YU-YEO → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG YEO	# →ᆑ→

			{ L"\x1192",L"\x1172\x1167\x4E28" }, //( ᆒ → ᅲᅧ丨 ) HANGUL JUNGSEONG YU-YE → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅲᅧᅵ→
			{ L"\x318B",L"\x1172\x1167\x4E28" }, //( ㆋ → ᅲᅧ丨 ) HANGUL LETTER YU-YE → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᆒ→→ᅲᅧᅵ→

			{ L"\xD7B8",L"\x1172\x1169" }, //( ힸ → ᅲᅩ ) HANGUL JUNGSEONG YU-O → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG O	# 

			{ L"\x1193",L"\x1172\x116E" }, //( ᆓ → ᅲᅮ ) HANGUL JUNGSEONG YU-U → HANGUL JUNGSEONG YU, HANGUL JUNGSEONG U	# 

			{ L"\x1194",L"\x1172\x4E28" }, //( ᆔ → ᅲ丨 ) HANGUL JUNGSEONG YU-I → HANGUL JUNGSEONG YU, CJK UNIFIED IDEOGRAPH-4E28	# →ᅲᅵ→
			{ L"\x318C",L"\x1172\x4E28" }, //( ㆌ → ᅲ丨 ) HANGUL LETTER YU-I → HANGUL JUNGSEONG YU, CJK UNIFIED IDEOGRAPH-4E28	# →ᆔ→→ᅲᅵ→

			{ L"\x318D",L"\x119E" }, //( ㆍ → ᆞ ) HANGUL LETTER ARAEA → HANGUL JUNGSEONG ARAEA	# 

			{ L"\xD7C5",L"\x119E\x1161" }, //( ퟅ → ᆞᅡ ) HANGUL JUNGSEONG ARAEA-A → HANGUL JUNGSEONG ARAEA, HANGUL JUNGSEONG A	# 

			{ L"\x119F",L"\x119E\x1165" }, //( ᆟ → ᆞᅥ ) HANGUL JUNGSEONG ARAEA-EO → HANGUL JUNGSEONG ARAEA, HANGUL JUNGSEONG EO	# 

			{ L"\xD7C6",L"\x119E\x1165\x4E28" }, //( ퟆ → ᆞᅥ丨 ) HANGUL JUNGSEONG ARAEA-E → HANGUL JUNGSEONG ARAEA, HANGUL JUNGSEONG EO, CJK UNIFIED IDEOGRAPH-4E28	# →ᆞᅥᅵ→

			{ L"\x11A0",L"\x119E\x116E" }, //( ᆠ → ᆞᅮ ) HANGUL JUNGSEONG ARAEA-U → HANGUL JUNGSEONG ARAEA, HANGUL JUNGSEONG U	# 

			{ L"\x11A2",L"\x119E\x119E" }, //( ᆢ → ᆞᆞ ) HANGUL JUNGSEONG SSANGARAEA → HANGUL JUNGSEONG ARAEA, HANGUL JUNGSEONG ARAEA	# 

			{ L"\x11A1",L"\x119E\x4E28" }, //( ᆡ → ᆞ丨 ) HANGUL JUNGSEONG ARAEA-I → HANGUL JUNGSEONG ARAEA, CJK UNIFIED IDEOGRAPH-4E28	# →ᆞᅵ→
			{ L"\x318E",L"\x119E\x4E28" }, //( ㆎ → ᆞ丨 ) HANGUL LETTER ARAEAE → HANGUL JUNGSEONG ARAEA, CJK UNIFIED IDEOGRAPH-4E28	# →ᆡ→→ᆞᅵ→

			{ L"\x30D8",L"\x3078" }, //( ヘ → へ ) KATAKANA LETTER HE → HIRAGANA LETTER HE	# 

			{ L"\x2341",L"\x303C" }, //( ⍁ → 〼 ) APL FUNCTIONAL SYMBOL QUAD SLASH → MASU MARK	# →⧄→
			{ L"\x29C4",L"\x303C" }, //( ⧄ → 〼 ) SQUARED RISING DIAGONAL SLASH → MASU MARK	# 

			{ L"\xA49E",L"\xA04A" }, //( ꒞ → ꁊ ) YI RADICAL PUT → YI SYLLABLE PUT	# 

			{ L"\xA4AC",L"\xA050" }, //( ꒬ → ꁐ ) YI RADICAL PYT → YI SYLLABLE PYT	# 

			{ L"\xA49C",L"\xA0C0" }, //( ꒜ → ꃀ ) YI RADICAL MOP → YI SYLLABLE MOP	# 

			{ L"\xA4A8",L"\xA132" }, //( ꒨ → ꄲ ) YI RADICAL TU → YI SYLLABLE TU	# 

			{ L"\xA4BF",L"\xA259" }, //( ꒿ → ꉙ ) YI RADICAL HXOP → YI SYLLABLE HXOP	# 

			{ L"\xA4BE",L"\xA2B1" }, //( ꒾ → ꊱ ) YI RADICAL CIP → YI SYLLABLE CIP	# 

			{ L"\xA494",L"\xA2CD" }, //( ꒔ → ꋍ ) YI RADICAL CYP → YI SYLLABLE CYP	# 

			{ L"\xA4C0",L"\xA3AB" }, //( ꓀ → ꎫ ) YI RADICAL SHAT → YI SYLLABLE SHAT	# 

			{ L"\xA4C2",L"\xA3B5" }, //( ꓂ → ꎵ ) YI RADICAL SHOP → YI SYLLABLE SHOP	# 

			{ L"\xA4BA",L"\xA3BF" }, //( ꒺ → ꎿ ) YI RADICAL SHUR → YI SYLLABLE SHUR	# 

			{ L"\xA4B0",L"\xA3C2" }, //( ꒰ → ꏂ ) YI RADICAL SHY → YI SYLLABLE SHY	# 

			{ L"\xA4A7",L"\xA458" }, //( ꒧ → ꑘ ) YI RADICAL NYOP → YI SYLLABLE NYOP	# 

			{ L"\x22A5",L"\xA4D5" }, //( ⊥ → ꓕ ) UP TACK → LISU LETTER THA	# 
			{ L"\x27C2",L"\xA4D5" }, //( ⟂ → ꓕ ) PERPENDICULAR → LISU LETTER THA	# →⊥→
			{ L"\xA7B1",L"\xA4D5" }, //( Ʇ → ꓕ ) LATIN CAPITAL LETTER TURNED T → LISU LETTER THA	# 

			{ L"\xA79E",L"\xA4E4" }, //( Ꞟ → ꓤ ) LATIN CAPITAL LETTER VOLAPUK UE → LISU LETTER ZA	# 

			{ L"\x2141",L"\xA4E8" }, //( ⅁ → ꓨ ) TURNED SANS-SERIF CAPITAL G → LISU LETTER HHA	# 

			{ L"\x2142",L"\xA4F6" }, //( ⅂ → ꓶ ) TURNED SANS-SERIF CAPITAL L → LISU LETTER UH	# 
			{ L"\x0001\x0411",L"\xA4F6" }, //( 𐐑 → ꓶ ) DESERET CAPITAL LETTER PEE → LISU LETTER UH	# →⅂→

			{ L"\x2295",L"\x0001\x02A8" }, //( ⊕ → 𐊨 ) CIRCLED PLUS → CARIAN LETTER Q	# 
			{ L"\x2A01",L"\x0001\x02A8" }, //( ⨁ → 𐊨 ) N-ARY CIRCLED PLUS OPERATOR → CARIAN LETTER Q	# →⊕→
			{ L"\x0001\xF728",L"\x0001\x02A8" }, //( 🜨 → 𐊨 ) ALCHEMICAL SYMBOL FOR VERDIGRIS → CARIAN LETTER Q	# →⊕→

			{ L"\x25BD",L"\x0001\x02BC" }, //( ▽ → 𐊼 ) WHITE DOWN-POINTING TRIANGLE → CARIAN LETTER K	# 
			{ L"\x0001\xF704",L"\x0001\x02BC" }, //( 🜄 → 𐊼 ) ALCHEMICAL SYMBOL FOR WATER → CARIAN LETTER K	# →▽→

			{ L"\x29D6",L"\x0001\x02C0" }, //( ⧖ → 𐋀 ) WHITE HOURGLASS → CARIAN LETTER G	# 

			{ L"\xA79B",L"\x0001\x043A" }, //( ꞛ → 𐐺 ) LATIN SMALL LETTER VOLAPUK AE → DESERET SMALL LETTER BEE	# 

			{ L"\xA79A",L"\x0001\x0412" }, //( Ꞛ → 𐐒 ) LATIN CAPITAL LETTER VOLAPUK AE → DESERET CAPITAL LETTER BEE	# 

			{ L"\x0001\x04A0",L"\x0001\x0486" }, //( 𐒠 → 𐒆 ) OSMANYA DIGIT ZERO → OSMANYA LETTER DEEL	# 

			{ L"\x0001\x03D1",L"\x0001\x0382" }, //( 𐏑 → 𐎂 ) OLD PERSIAN NUMBER ONE → UGARITIC LETTER GAMLA	# 

			{ L"\x0001\x03D3",L"\x0001\x0393" }, //( 𐏓 → 𐎓 ) OLD PERSIAN NUMBER TEN → UGARITIC LETTER AIN	# 

			{ L"\x0001\x2038",L"\x0001\x039A" }, //( 𒀸 → 𐎚 ) CUNEIFORM SIGN ASH → UGARITIC LETTER TO	# 

			{ L"\x2625",L"\x0001\x099E" }, //( ☥ → ‎𐦞‎ ) ANKH → MEROITIC HIEROGLYPHIC SYMBOL VIDJ	# 
			{ L"\x0001\x32F9",L"\x0001\x099E" }, //( 𓋹 → ‎𐦞‎ ) EGYPTIAN HIEROGLYPH S034 → MEROITIC HIEROGLYPHIC SYMBOL VIDJ	# →☥→

			{ L"\x3039",L"\x5344" }, //( 〹 → 卄 ) HANGZHOU NUMERAL TWENTY → CJK UNIFIED IDEOGRAPH-5344	# 

			{ L"\xF967",L"\x4E0D" }, //( 不 → 不 ) CJK COMPATIBILITY IDEOGRAPH-F967 → CJK UNIFIED IDEOGRAPH-4E0D	# 

			{ L"\x0002\xF800",L"\x4E3D" }, //( 丽 → 丽 ) CJK COMPATIBILITY IDEOGRAPH-2F800 → CJK UNIFIED IDEOGRAPH-4E3D	# 

			{ L"\xFA70",L"\x4E26" }, //( 並 → 並 ) CJK COMPATIBILITY IDEOGRAPH-FA70 → CJK UNIFIED IDEOGRAPH-4E26	# 

			{ L"\x239C",L"\x4E28" }, //( ⎜ → 丨 ) LEFT PARENTHESIS EXTENSION → CJK UNIFIED IDEOGRAPH-4E28	# →⎥→→⎮→
			{ L"\x239F",L"\x4E28" }, //( ⎟ → 丨 ) RIGHT PARENTHESIS EXTENSION → CJK UNIFIED IDEOGRAPH-4E28	# →⎥→→⎮→
			{ L"\x23A2",L"\x4E28" }, //( ⎢ → 丨 ) LEFT SQUARE BRACKET EXTENSION → CJK UNIFIED IDEOGRAPH-4E28	# →⎥→→⎮→
			{ L"\x23A5",L"\x4E28" }, //( ⎥ → 丨 ) RIGHT SQUARE BRACKET EXTENSION → CJK UNIFIED IDEOGRAPH-4E28	# →⎮→
			{ L"\x23AA",L"\x4E28" }, //( ⎪ → 丨 ) CURLY BRACKET EXTENSION → CJK UNIFIED IDEOGRAPH-4E28	# →⎥→→⎮→
			{ L"\x23AE",L"\x4E28" }, //( ⎮ → 丨 ) INTEGRAL EXTENSION → CJK UNIFIED IDEOGRAPH-4E28	# 
			{ L"\x31D1",L"\x4E28" }, //( ㇑ → 丨 ) CJK STROKE S → CJK UNIFIED IDEOGRAPH-4E28	# 
			{ L"\x1175",L"\x4E28" }, //( ᅵ → 丨 ) HANGUL JUNGSEONG I → CJK UNIFIED IDEOGRAPH-4E28	# →ㅣ→
			{ L"\x3163",L"\x4E28" }, //( ㅣ → 丨 ) HANGUL LETTER I → CJK UNIFIED IDEOGRAPH-4E28	# 
			{ L"\x2F01",L"\x4E28" }, //( ⼁ → 丨 ) KANGXI RADICAL LINE → CJK UNIFIED IDEOGRAPH-4E28	# 

			{ L"\x119C",L"\x4E28\x30FC" }, //( ᆜ → 丨ー ) HANGUL JUNGSEONG I-EU → CJK UNIFIED IDEOGRAPH-4E28, KATAKANA-HIRAGANA PROLONGED SOUND MARK	# →ᅵᅳ→

			{ L"\x1198",L"\x4E28\x1161" }, //( ᆘ → 丨ᅡ ) HANGUL JUNGSEONG I-A → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG A	# →ᅵᅡ→

			{ L"\x1199",L"\x4E28\x1163" }, //( ᆙ → 丨ᅣ ) HANGUL JUNGSEONG I-YA → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YA	# →ᅵᅣ→

			{ L"\xD7BD",L"\x4E28\x1163\x1169" }, //( ힽ → 丨ᅣᅩ ) HANGUL JUNGSEONG I-YA-O → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YA, HANGUL JUNGSEONG O	# →ᅵᅣᅩ→

			{ L"\xD7BE",L"\x4E28\x1163\x4E28" }, //( ힾ → 丨ᅣ丨 ) HANGUL JUNGSEONG I-YAE → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YA, CJK UNIFIED IDEOGRAPH-4E28	# →ᅵᅣᅵ→

			{ L"\xD7BF",L"\x4E28\x1167" }, //( ힿ → 丨ᅧ ) HANGUL JUNGSEONG I-YEO → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YEO	# →ᅵᅧ→

			{ L"\xD7C0",L"\x4E28\x1167\x4E28" }, //( ퟀ → 丨ᅧ丨 ) HANGUL JUNGSEONG I-YE → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YEO, CJK UNIFIED IDEOGRAPH-4E28	# →ᅵᅧᅵ→

			{ L"\x119A",L"\x4E28\x1169" }, //( ᆚ → 丨ᅩ ) HANGUL JUNGSEONG I-O → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG O	# →ᅵᅩ→

			{ L"\xD7C1",L"\x4E28\x1169\x4E28" }, //( ퟁ → 丨ᅩ丨 ) HANGUL JUNGSEONG I-O-I → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG O, CJK UNIFIED IDEOGRAPH-4E28	# →ᅵᅩᅵ→

			{ L"\xD7C2",L"\x4E28\x116D" }, //( ퟂ → 丨ᅭ ) HANGUL JUNGSEONG I-YO → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YO	# →ᅵᅭ→

			{ L"\x119B",L"\x4E28\x116E" }, //( ᆛ → 丨ᅮ ) HANGUL JUNGSEONG I-U → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG U	# →ᅵᅮ→

			{ L"\xD7C3",L"\x4E28\x1172" }, //( ퟃ → 丨ᅲ ) HANGUL JUNGSEONG I-YU → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG YU	# →ᅵᅲ→

			{ L"\x119D",L"\x4E28\x119E" }, //( ᆝ → 丨ᆞ ) HANGUL JUNGSEONG I-ARAEA → CJK UNIFIED IDEOGRAPH-4E28, HANGUL JUNGSEONG ARAEA	# →ᅵᆞ→

			{ L"\xD7C4",L"\x4E28\x4E28" }, //( ퟄ → 丨丨 ) HANGUL JUNGSEONG I-I → CJK UNIFIED IDEOGRAPH-4E28, CJK UNIFIED IDEOGRAPH-4E28	# →ᅵᅵ→

			{ L"\xF905",L"\x4E32" }, //( 串 → 串 ) CJK COMPATIBILITY IDEOGRAPH-F905 → CJK UNIFIED IDEOGRAPH-4E32	# 

			{ L"\x0002\xF801",L"\x4E38" }, //( 丸 → 丸 ) CJK COMPATIBILITY IDEOGRAPH-2F801 → CJK UNIFIED IDEOGRAPH-4E38	# 

			{ L"\xF95E",L"\x4E39" }, //( 丹 → 丹 ) CJK COMPATIBILITY IDEOGRAPH-F95E → CJK UNIFIED IDEOGRAPH-4E39	# 

			{ L"\x0002\xF802",L"\x4E41" }, //( 乁 → 乁 ) CJK COMPATIBILITY IDEOGRAPH-2F802 → CJK UNIFIED IDEOGRAPH-4E41	# 

			{ L"\x31E0",L"\x4E59" }, //( ㇠ → 乙 ) CJK STROKE HXWG → CJK UNIFIED IDEOGRAPH-4E59	# 
			{ L"\x2F04",L"\x4E59" }, //( ⼄ → 乙 ) KANGXI RADICAL SECOND → CJK UNIFIED IDEOGRAPH-4E59	# 

			{ L"\x31DF",L"\x4E5A" }, //( ㇟ → 乚 ) CJK STROKE SWG → CJK UNIFIED IDEOGRAPH-4E5A	# 
			{ L"\x2E83",L"\x4E5A" }, //( ⺃ → 乚 ) CJK RADICAL SECOND TWO → CJK UNIFIED IDEOGRAPH-4E5A	# 

			{ L"\x31D6",L"\x4E5B" }, //( ㇖ → 乛 ) CJK STROKE HG → CJK UNIFIED IDEOGRAPH-4E5B	# 

			{ L"\x2EF2",L"\x4E80" }, //( ⻲ → 亀 ) CJK RADICAL J-SIMPLIFIED TURTLE → CJK UNIFIED IDEOGRAPH-4E80	# 

			{ L"\xF91B",L"\x4E82" }, //( 亂 → 亂 ) CJK COMPATIBILITY IDEOGRAPH-F91B → CJK UNIFIED IDEOGRAPH-4E82	# 

			{ L"\x31DA",L"\x4E85" }, //( ㇚ → 亅 ) CJK STROKE SG → CJK UNIFIED IDEOGRAPH-4E85	# 
			{ L"\x2F05",L"\x4E85" }, //( ⼅ → 亅 ) KANGXI RADICAL HOOK → CJK UNIFIED IDEOGRAPH-4E85	# 

			{ L"\xF9BA",L"\x4E86" }, //( 了 → 了 ) CJK COMPATIBILITY IDEOGRAPH-F9BA → CJK UNIFIED IDEOGRAPH-4E86	# 

			{ L"\x2F06",L"\x4E8C" }, //( ⼆ → 二 ) KANGXI RADICAL TWO → CJK UNIFIED IDEOGRAPH-4E8C	# 

			{ L"\x0002\xF803",L"\x0002\x0122" }, //( 𠄢 → 𠄢 ) CJK COMPATIBILITY IDEOGRAPH-2F803 → CJK UNIFIED IDEOGRAPH-20122	# 

			{ L"\x2F07",L"\x4EA0" }, //( ⼇ → 亠 ) KANGXI RADICAL LID → CJK UNIFIED IDEOGRAPH-4EA0	# 

			{ L"\xF977",L"\x4EAE" }, //( 亮 → 亮 ) CJK COMPATIBILITY IDEOGRAPH-F977 → CJK UNIFIED IDEOGRAPH-4EAE	# 

			{ L"\x2F08",L"\x4EBA" }, //( ⼈ → 人 ) KANGXI RADICAL MAN → CJK UNIFIED IDEOGRAPH-4EBA	# 

			{ L"\x2E85",L"\x4EBB" }, //( ⺅ → 亻 ) CJK RADICAL PERSON → CJK UNIFIED IDEOGRAPH-4EBB	# 

			{ L"\xF9FD",L"\x4EC0" }, //( 什 → 什 ) CJK COMPATIBILITY IDEOGRAPH-F9FD → CJK UNIFIED IDEOGRAPH-4EC0	# 

			{ L"\x0002\xF819",L"\x4ECC" }, //( 仌 → 仌 ) CJK COMPATIBILITY IDEOGRAPH-2F819 → CJK UNIFIED IDEOGRAPH-4ECC	# 

			{ L"\xF9A8",L"\x4EE4" }, //( 令 → 令 ) CJK COMPATIBILITY IDEOGRAPH-F9A8 → CJK UNIFIED IDEOGRAPH-4EE4	# 

			{ L"\x0002\xF804",L"\x4F60" }, //( 你 → 你 ) CJK COMPATIBILITY IDEOGRAPH-2F804 → CJK UNIFIED IDEOGRAPH-4F60	# 

			{ L"\x5002",L"\x4F75" }, //( 倂 → 併 ) CJK UNIFIED IDEOGRAPH-5002 → CJK UNIFIED IDEOGRAPH-4F75	# 
			{ L"\x0002\xF807",L"\x4F75" }, //( 倂 → 併 ) CJK COMPATIBILITY IDEOGRAPH-2F807 → CJK UNIFIED IDEOGRAPH-4F75	# →倂→

			{ L"\xFA73",L"\x4F80" }, //( 侀 → 侀 ) CJK COMPATIBILITY IDEOGRAPH-FA73 → CJK UNIFIED IDEOGRAPH-4F80	# 

			{ L"\xF92D",L"\x4F86" }, //( 來 → 來 ) CJK COMPATIBILITY IDEOGRAPH-F92D → CJK UNIFIED IDEOGRAPH-4F86	# 

			{ L"\xF9B5",L"\x4F8B" }, //( 例 → 例 ) CJK COMPATIBILITY IDEOGRAPH-F9B5 → CJK UNIFIED IDEOGRAPH-4F8B	# 

			{ L"\xFA30",L"\x4FAE" }, //( 侮 → 侮 ) CJK COMPATIBILITY IDEOGRAPH-FA30 → CJK UNIFIED IDEOGRAPH-4FAE	# 
			{ L"\x0002\xF805",L"\x4FAE" }, //( 侮 → 侮 ) CJK COMPATIBILITY IDEOGRAPH-2F805 → CJK UNIFIED IDEOGRAPH-4FAE	# 

			{ L"\x0002\xF806",L"\x4FBB" }, //( 侻 → 侻 ) CJK COMPATIBILITY IDEOGRAPH-2F806 → CJK UNIFIED IDEOGRAPH-4FBB	# 

			{ L"\xF965",L"\x4FBF" }, //( 便 → 便 ) CJK COMPATIBILITY IDEOGRAPH-F965 → CJK UNIFIED IDEOGRAPH-4FBF	# 

			{ L"\x503C",L"\x5024" }, //( 值 → 値 ) CJK UNIFIED IDEOGRAPH-503C → CJK UNIFIED IDEOGRAPH-5024	# 

			{ L"\xF9D4",L"\x502B" }, //( 倫 → 倫 ) CJK COMPATIBILITY IDEOGRAPH-F9D4 → CJK UNIFIED IDEOGRAPH-502B	# 

			{ L"\x0002\xF808",L"\x507A" }, //( 偺 → 偺 ) CJK COMPATIBILITY IDEOGRAPH-2F808 → CJK UNIFIED IDEOGRAPH-507A	# 

			{ L"\x0002\xF809",L"\x5099" }, //( 備 → 備 ) CJK COMPATIBILITY IDEOGRAPH-2F809 → CJK UNIFIED IDEOGRAPH-5099	# 

			{ L"\x0002\xF80B",L"\x50CF" }, //( 像 → 像 ) CJK COMPATIBILITY IDEOGRAPH-2F80B → CJK UNIFIED IDEOGRAPH-50CF	# 

			{ L"\xF9BB",L"\x50DA" }, //( 僚 → 僚 ) CJK COMPATIBILITY IDEOGRAPH-F9BB → CJK UNIFIED IDEOGRAPH-50DA	# 

			{ L"\xFA31",L"\x50E7" }, //( 僧 → 僧 ) CJK COMPATIBILITY IDEOGRAPH-FA31 → CJK UNIFIED IDEOGRAPH-50E7	# 
			{ L"\x0002\xF80A",L"\x50E7" }, //( 僧 → 僧 ) CJK COMPATIBILITY IDEOGRAPH-2F80A → CJK UNIFIED IDEOGRAPH-50E7	# 

			{ L"\x0002\xF80C",L"\x349E" }, //( 㒞 → 㒞 ) CJK COMPATIBILITY IDEOGRAPH-2F80C → CJK UNIFIED IDEOGRAPH-349E	# 

			{ L"\x2F09",L"\x513F" }, //( ⼉ → 儿 ) KANGXI RADICAL LEGS → CJK UNIFIED IDEOGRAPH-513F	# 

			{ L"\xFA0C",L"\x5140" }, //( 兀 → 兀 ) CJK COMPATIBILITY IDEOGRAPH-FA0C → CJK UNIFIED IDEOGRAPH-5140	# 
			{ L"\x2E8E",L"\x5140" }, //( ⺎ → 兀 ) CJK RADICAL LAME ONE → CJK UNIFIED IDEOGRAPH-5140	# 

			{ L"\xFA74",L"\x5145" }, //( 充 → 充 ) CJK COMPATIBILITY IDEOGRAPH-FA74 → CJK UNIFIED IDEOGRAPH-5145	# 

			{ L"\xFA32",L"\x514D" }, //( 免 → 免 ) CJK COMPATIBILITY IDEOGRAPH-FA32 → CJK UNIFIED IDEOGRAPH-514D	# 
			{ L"\x0002\xF80E",L"\x514D" }, //( 免 → 免 ) CJK COMPATIBILITY IDEOGRAPH-2F80E → CJK UNIFIED IDEOGRAPH-514D	# 

			{ L"\x0002\xF80F",L"\x5154" }, //( 兔 → 兔 ) CJK COMPATIBILITY IDEOGRAPH-2F80F → CJK UNIFIED IDEOGRAPH-5154	# 

			{ L"\x0002\xF810",L"\x5164" }, //( 兤 → 兤 ) CJK COMPATIBILITY IDEOGRAPH-2F810 → CJK UNIFIED IDEOGRAPH-5164	# 

			{ L"\x2F0A",L"\x5165" }, //( ⼊ → 入 ) KANGXI RADICAL ENTER → CJK UNIFIED IDEOGRAPH-5165	# 

			{ L"\x0002\xF814",L"\x5167" }, //( 內 → 內 ) CJK COMPATIBILITY IDEOGRAPH-2F814 → CJK UNIFIED IDEOGRAPH-5167	# 

			{ L"\xFA72",L"\x5168" }, //( 全 → 全 ) CJK COMPATIBILITY IDEOGRAPH-FA72 → CJK UNIFIED IDEOGRAPH-5168	# 

			{ L"\xF978",L"\x5169" }, //( 兩 → 兩 ) CJK COMPATIBILITY IDEOGRAPH-F978 → CJK UNIFIED IDEOGRAPH-5169	# 

			{ L"\x2F0B",L"\x516B" }, //( ⼋ → 八 ) KANGXI RADICAL EIGHT → CJK UNIFIED IDEOGRAPH-516B	# 

			{ L"\xF9D1",L"\x516D" }, //( 六 → 六 ) CJK COMPATIBILITY IDEOGRAPH-F9D1 → CJK UNIFIED IDEOGRAPH-516D	# 

			{ L"\x0002\xF811",L"\x5177" }, //( 具 → 具 ) CJK COMPATIBILITY IDEOGRAPH-2F811 → CJK UNIFIED IDEOGRAPH-5177	# 

			{ L"\x0002\xF812",L"\x0002\x051C" }, //( 𠔜 → 𠔜 ) CJK COMPATIBILITY IDEOGRAPH-2F812 → CJK UNIFIED IDEOGRAPH-2051C	# 

			{ L"\x0002\xF91B",L"\x0002\x0525" }, //( 𠔥 → 𠔥 ) CJK COMPATIBILITY IDEOGRAPH-2F91B → CJK UNIFIED IDEOGRAPH-20525	# 

			{ L"\xFA75",L"\x5180" }, //( 冀 → 冀 ) CJK COMPATIBILITY IDEOGRAPH-FA75 → CJK UNIFIED IDEOGRAPH-5180	# 

			{ L"\x0002\xF813",L"\x34B9" }, //( 㒹 → 㒹 ) CJK COMPATIBILITY IDEOGRAPH-2F813 → CJK UNIFIED IDEOGRAPH-34B9	# 

			{ L"\x2F0C",L"\x5182" }, //( ⼌ → 冂 ) KANGXI RADICAL DOWN BOX → CJK UNIFIED IDEOGRAPH-5182	# 

			{ L"\x0002\xF815",L"\x518D" }, //( 再 → 再 ) CJK COMPATIBILITY IDEOGRAPH-2F815 → CJK UNIFIED IDEOGRAPH-518D	# 

			{ L"\x0002\xF816",L"\x0002\x054B" }, //( 𠕋 → 𠕋 ) CJK COMPATIBILITY IDEOGRAPH-2F816 → CJK UNIFIED IDEOGRAPH-2054B	# 

			{ L"\x0002\xF8D2",L"\x5192" }, //( 冒 → 冒 ) CJK COMPATIBILITY IDEOGRAPH-2F8D2 → CJK UNIFIED IDEOGRAPH-5192	# 

			{ L"\x0002\xF8D3",L"\x5195" }, //( 冕 → 冕 ) CJK COMPATIBILITY IDEOGRAPH-2F8D3 → CJK UNIFIED IDEOGRAPH-5195	# 

			{ L"\x0002\xF9CA",L"\x34BB" }, //( 㒻 → 㒻 ) CJK COMPATIBILITY IDEOGRAPH-2F9CA → CJK UNIFIED IDEOGRAPH-34BB	# 

			{ L"\x0002\xF8D4",L"\x6700" }, //( 最 → 最 ) CJK COMPATIBILITY IDEOGRAPH-2F8D4 → CJK UNIFIED IDEOGRAPH-6700	# 

			{ L"\x2F0D",L"\x5196" }, //( ⼍ → 冖 ) KANGXI RADICAL COVER → CJK UNIFIED IDEOGRAPH-5196	# 

			{ L"\x0002\xF817",L"\x5197" }, //( 冗 → 冗 ) CJK COMPATIBILITY IDEOGRAPH-2F817 → CJK UNIFIED IDEOGRAPH-5197	# 

			{ L"\x0002\xF818",L"\x51A4" }, //( 冤 → 冤 ) CJK COMPATIBILITY IDEOGRAPH-2F818 → CJK UNIFIED IDEOGRAPH-51A4	# 

			{ L"\x2F0E",L"\x51AB" }, //( ⼎ → 冫 ) KANGXI RADICAL ICE → CJK UNIFIED IDEOGRAPH-51AB	# 

			{ L"\x0002\xF81A",L"\x51AC" }, //( 冬 → 冬 ) CJK COMPATIBILITY IDEOGRAPH-2F81A → CJK UNIFIED IDEOGRAPH-51AC	# 

			{ L"\xFA71",L"\x51B5" }, //( 况 → 况 ) CJK COMPATIBILITY IDEOGRAPH-FA71 → CJK UNIFIED IDEOGRAPH-51B5	# 
			{ L"\x0002\xF81B",L"\x51B5" }, //( 况 → 况 ) CJK COMPATIBILITY IDEOGRAPH-2F81B → CJK UNIFIED IDEOGRAPH-51B5	# 

			{ L"\xF92E",L"\x51B7" }, //( 冷 → 冷 ) CJK COMPATIBILITY IDEOGRAPH-F92E → CJK UNIFIED IDEOGRAPH-51B7	# 

			{ L"\xF979",L"\x51C9" }, //( 凉 → 凉 ) CJK COMPATIBILITY IDEOGRAPH-F979 → CJK UNIFIED IDEOGRAPH-51C9	# 

			{ L"\xF955",L"\x51CC" }, //( 凌 → 凌 ) CJK COMPATIBILITY IDEOGRAPH-F955 → CJK UNIFIED IDEOGRAPH-51CC	# 

			{ L"\xF954",L"\x51DC" }, //( 凜 → 凜 ) CJK COMPATIBILITY IDEOGRAPH-F954 → CJK UNIFIED IDEOGRAPH-51DC	# 

			{ L"\xFA15",L"\x51DE" }, //( 凞 → 凞 ) CJK COMPATIBILITY IDEOGRAPH-FA15 → CJK UNIFIED IDEOGRAPH-51DE	# 

			{ L"\x2F0F",L"\x51E0" }, //( ⼏ → 几 ) KANGXI RADICAL TABLE → CJK UNIFIED IDEOGRAPH-51E0	# 

			{ L"\x0002\xF80D",L"\x0002\x063A" }, //( 𠘺 → 𠘺 ) CJK COMPATIBILITY IDEOGRAPH-2F80D → CJK UNIFIED IDEOGRAPH-2063A	# 

			{ L"\x0002\xF81D",L"\x51F5" }, //( 凵 → 凵 ) CJK COMPATIBILITY IDEOGRAPH-2F81D → CJK UNIFIED IDEOGRAPH-51F5	# 
			{ L"\x2F10",L"\x51F5" }, //( ⼐ → 凵 ) KANGXI RADICAL OPEN BOX → CJK UNIFIED IDEOGRAPH-51F5	# 

			{ L"\x2F11",L"\x5200" }, //( ⼑ → 刀 ) KANGXI RADICAL KNIFE → CJK UNIFIED IDEOGRAPH-5200	# 

			{ L"\x2E89",L"\x5202" }, //( ⺉ → 刂 ) CJK RADICAL KNIFE TWO → CJK UNIFIED IDEOGRAPH-5202	# 

			{ L"\x0002\xF81E",L"\x5203" }, //( 刃 → 刃 ) CJK COMPATIBILITY IDEOGRAPH-2F81E → CJK UNIFIED IDEOGRAPH-5203	# 

			{ L"\xFA00",L"\x5207" }, //( 切 → 切 ) CJK COMPATIBILITY IDEOGRAPH-FA00 → CJK UNIFIED IDEOGRAPH-5207	# 
			{ L"\x0002\xF850",L"\x5207" }, //( 切 → 切 ) CJK COMPATIBILITY IDEOGRAPH-2F850 → CJK UNIFIED IDEOGRAPH-5207	# 

			{ L"\xF99C",L"\x5217" }, //( 列 → 列 ) CJK COMPATIBILITY IDEOGRAPH-F99C → CJK UNIFIED IDEOGRAPH-5217	# 

			{ L"\xF9DD",L"\x5229" }, //( 利 → 利 ) CJK COMPATIBILITY IDEOGRAPH-F9DD → CJK UNIFIED IDEOGRAPH-5229	# 

			{ L"\x0002\xF81F",L"\x34DF" }, //( 㓟 → 㓟 ) CJK COMPATIBILITY IDEOGRAPH-2F81F → CJK UNIFIED IDEOGRAPH-34DF	# 

			{ L"\xF9FF",L"\x523A" }, //( 刺 → 刺 ) CJK COMPATIBILITY IDEOGRAPH-F9FF → CJK UNIFIED IDEOGRAPH-523A	# 

			{ L"\x0002\xF820",L"\x523B" }, //( 刻 → 刻 ) CJK COMPATIBILITY IDEOGRAPH-2F820 → CJK UNIFIED IDEOGRAPH-523B	# 

			{ L"\x0002\xF821",L"\x5246" }, //( 剆 → 剆 ) CJK COMPATIBILITY IDEOGRAPH-2F821 → CJK UNIFIED IDEOGRAPH-5246	# 

			{ L"\x0002\xF822",L"\x5272" }, //( 割 → 割 ) CJK COMPATIBILITY IDEOGRAPH-2F822 → CJK UNIFIED IDEOGRAPH-5272	# 

			{ L"\x0002\xF823",L"\x5277" }, //( 剷 → 剷 ) CJK COMPATIBILITY IDEOGRAPH-2F823 → CJK UNIFIED IDEOGRAPH-5277	# 

			{ L"\xF9C7",L"\x5289" }, //( 劉 → 劉 ) CJK COMPATIBILITY IDEOGRAPH-F9C7 → CJK UNIFIED IDEOGRAPH-5289	# 

			{ L"\x0002\xF9D9",L"\x0002\x0804" }, //( 𠠄 → 𠠄 ) CJK COMPATIBILITY IDEOGRAPH-2F9D9 → CJK UNIFIED IDEOGRAPH-20804	# 

			{ L"\xF98A",L"\x529B" }, //( 力 → 力 ) CJK COMPATIBILITY IDEOGRAPH-F98A → CJK UNIFIED IDEOGRAPH-529B	# 
			{ L"\x2F12",L"\x529B" }, //( ⼒ → 力 ) KANGXI RADICAL POWER → CJK UNIFIED IDEOGRAPH-529B	# 

			{ L"\xF99D",L"\x52A3" }, //( 劣 → 劣 ) CJK COMPATIBILITY IDEOGRAPH-F99D → CJK UNIFIED IDEOGRAPH-52A3	# 

			{ L"\x0002\xF824",L"\x3515" }, //( 㔕 → 㔕 ) CJK COMPATIBILITY IDEOGRAPH-2F824 → CJK UNIFIED IDEOGRAPH-3515	# 

			{ L"\x0002\xF992",L"\x52B3" }, //( 劳 → 劳 ) CJK COMPATIBILITY IDEOGRAPH-2F992 → CJK UNIFIED IDEOGRAPH-52B3	# 

			{ L"\xFA76",L"\x52C7" }, //( 勇 → 勇 ) CJK COMPATIBILITY IDEOGRAPH-FA76 → CJK UNIFIED IDEOGRAPH-52C7	# 
			{ L"\x0002\xF825",L"\x52C7" }, //( 勇 → 勇 ) CJK COMPATIBILITY IDEOGRAPH-2F825 → CJK UNIFIED IDEOGRAPH-52C7	# 

			{ L"\xFA33",L"\x52C9" }, //( 勉 → 勉 ) CJK COMPATIBILITY IDEOGRAPH-FA33 → CJK UNIFIED IDEOGRAPH-52C9	# 
			{ L"\x0002\xF826",L"\x52C9" }, //( 勉 → 勉 ) CJK COMPATIBILITY IDEOGRAPH-2F826 → CJK UNIFIED IDEOGRAPH-52C9	# 

			{ L"\xF952",L"\x52D2" }, //( 勒 → 勒 ) CJK COMPATIBILITY IDEOGRAPH-F952 → CJK UNIFIED IDEOGRAPH-52D2	# 

			{ L"\xF92F",L"\x52DE" }, //( 勞 → 勞 ) CJK COMPATIBILITY IDEOGRAPH-F92F → CJK UNIFIED IDEOGRAPH-52DE	# 

			{ L"\xFA34",L"\x52E4" }, //( 勤 → 勤 ) CJK COMPATIBILITY IDEOGRAPH-FA34 → CJK UNIFIED IDEOGRAPH-52E4	# 
			{ L"\x0002\xF827",L"\x52E4" }, //( 勤 → 勤 ) CJK COMPATIBILITY IDEOGRAPH-2F827 → CJK UNIFIED IDEOGRAPH-52E4	# 

			{ L"\xF97F",L"\x52F5" }, //( 勵 → 勵 ) CJK COMPATIBILITY IDEOGRAPH-F97F → CJK UNIFIED IDEOGRAPH-52F5	# 

			{ L"\x2F13",L"\x52F9" }, //( ⼓ → 勹 ) KANGXI RADICAL WRAP → CJK UNIFIED IDEOGRAPH-52F9	# 

			{ L"\xFA77",L"\x52FA" }, //( 勺 → 勺 ) CJK COMPATIBILITY IDEOGRAPH-FA77 → CJK UNIFIED IDEOGRAPH-52FA	# 
			{ L"\x0002\xF828",L"\x52FA" }, //( 勺 → 勺 ) CJK COMPATIBILITY IDEOGRAPH-2F828 → CJK UNIFIED IDEOGRAPH-52FA	# 

			{ L"\x0002\xF829",L"\x5305" }, //( 包 → 包 ) CJK COMPATIBILITY IDEOGRAPH-2F829 → CJK UNIFIED IDEOGRAPH-5305	# 

			{ L"\x0002\xF82A",L"\x5306" }, //( 匆 → 匆 ) CJK COMPATIBILITY IDEOGRAPH-2F82A → CJK UNIFIED IDEOGRAPH-5306	# 

			{ L"\x0002\xF9DD",L"\x0002\x08DE" }, //( 𠣞 → 𠣞 ) CJK COMPATIBILITY IDEOGRAPH-2F9DD → CJK UNIFIED IDEOGRAPH-208DE	# 

			{ L"\x2F14",L"\x5315" }, //( ⼔ → 匕 ) KANGXI RADICAL SPOON → CJK UNIFIED IDEOGRAPH-5315	# 

			{ L"\xF963",L"\x5317" }, //( 北 → 北 ) CJK COMPATIBILITY IDEOGRAPH-F963 → CJK UNIFIED IDEOGRAPH-5317	# 
			{ L"\x0002\xF82B",L"\x5317" }, //( 北 → 北 ) CJK COMPATIBILITY IDEOGRAPH-2F82B → CJK UNIFIED IDEOGRAPH-5317	# 

			{ L"\x2F15",L"\x531A" }, //( ⼕ → 匚 ) KANGXI RADICAL RIGHT OPEN BOX → CJK UNIFIED IDEOGRAPH-531A	# 

			{ L"\x2F16",L"\x5338" }, //( ⼖ → 匸 ) KANGXI RADICAL HIDING ENCLOSURE → CJK UNIFIED IDEOGRAPH-5338	# 

			{ L"\xF9EB",L"\x533F" }, //( 匿 → 匿 ) CJK COMPATIBILITY IDEOGRAPH-F9EB → CJK UNIFIED IDEOGRAPH-533F	# 

			{ L"\x2F17",L"\x5341" }, //( ⼗ → 十 ) KANGXI RADICAL TEN → CJK UNIFIED IDEOGRAPH-5341	# 
			{ L"\x3038",L"\x5341" }, //( 〸 → 十 ) HANGZHOU NUMERAL TEN → CJK UNIFIED IDEOGRAPH-5341	# 

			{ L"\x303A",L"\x5345" }, //( 〺 → 卅 ) HANGZHOU NUMERAL THIRTY → CJK UNIFIED IDEOGRAPH-5345	# 

			{ L"\x0002\xF82C",L"\x5349" }, //( 卉 → 卉 ) CJK COMPATIBILITY IDEOGRAPH-2F82C → CJK UNIFIED IDEOGRAPH-5349	# 

			{ L"\xFA35",L"\x5351" }, //( 卑 → 卑 ) CJK COMPATIBILITY IDEOGRAPH-FA35 → CJK UNIFIED IDEOGRAPH-5351	# 
			{ L"\x0002\xF82D",L"\x5351" }, //( 卑 → 卑 ) CJK COMPATIBILITY IDEOGRAPH-2F82D → CJK UNIFIED IDEOGRAPH-5351	# 

			{ L"\x0002\xF82E",L"\x535A" }, //( 博 → 博 ) CJK COMPATIBILITY IDEOGRAPH-2F82E → CJK UNIFIED IDEOGRAPH-535A	# 

			{ L"\x2F18",L"\x535C" }, //( ⼘ → 卜 ) KANGXI RADICAL DIVINATION → CJK UNIFIED IDEOGRAPH-535C	# 

			{ L"\x2F19",L"\x5369" }, //( ⼙ → 卩 ) KANGXI RADICAL SEAL → CJK UNIFIED IDEOGRAPH-5369	# 

			{ L"\x2E8B",L"\x353E" }, //( ⺋ → 㔾 ) CJK RADICAL SEAL → CJK UNIFIED IDEOGRAPH-353E	# 

			{ L"\x0002\xF82F",L"\x5373" }, //( 即 → 即 ) CJK COMPATIBILITY IDEOGRAPH-2F82F → CJK UNIFIED IDEOGRAPH-5373	# 

			{ L"\xF91C",L"\x5375" }, //( 卵 → 卵 ) CJK COMPATIBILITY IDEOGRAPH-F91C → CJK UNIFIED IDEOGRAPH-5375	# 

			{ L"\x0002\xF830",L"\x537D" }, //( 卽 → 卽 ) CJK COMPATIBILITY IDEOGRAPH-2F830 → CJK UNIFIED IDEOGRAPH-537D	# 

			{ L"\x0002\xF831",L"\x537F" }, //( 卿 → 卿 ) CJK COMPATIBILITY IDEOGRAPH-2F831 → CJK UNIFIED IDEOGRAPH-537F	# 
			{ L"\x0002\xF832",L"\x537F" }, //( 卿 → 卿 ) CJK COMPATIBILITY IDEOGRAPH-2F832 → CJK UNIFIED IDEOGRAPH-537F	# 
			{ L"\x0002\xF833",L"\x537F" }, //( 卿 → 卿 ) CJK COMPATIBILITY IDEOGRAPH-2F833 → CJK UNIFIED IDEOGRAPH-537F	# 

			{ L"\x2F1A",L"\x5382" }, //( ⼚ → 厂 ) KANGXI RADICAL CLIFF → CJK UNIFIED IDEOGRAPH-5382	# 

			{ L"\x0002\xF834",L"\x0002\x0A2C" }, //( 𠨬 → 𠨬 ) CJK COMPATIBILITY IDEOGRAPH-2F834 → CJK UNIFIED IDEOGRAPH-20A2C	# 

			{ L"\x2F1B",L"\x53B6" }, //( ⼛ → 厶 ) KANGXI RADICAL PRIVATE → CJK UNIFIED IDEOGRAPH-53B6	# 

			{ L"\xF96B",L"\x53C3" }, //( 參 → 參 ) CJK COMPATIBILITY IDEOGRAPH-F96B → CJK UNIFIED IDEOGRAPH-53C3	# 

			{ L"\x2F1C",L"\x53C8" }, //( ⼜ → 又 ) KANGXI RADICAL AGAIN → CJK UNIFIED IDEOGRAPH-53C8	# 

			{ L"\x0002\xF836",L"\x53CA" }, //( 及 → 及 ) CJK COMPATIBILITY IDEOGRAPH-2F836 → CJK UNIFIED IDEOGRAPH-53CA	# 

			{ L"\x0002\xF837",L"\x53DF" }, //( 叟 → 叟 ) CJK COMPATIBILITY IDEOGRAPH-2F837 → CJK UNIFIED IDEOGRAPH-53DF	# 

			{ L"\x0002\xF838",L"\x0002\x0B63" }, //( 𠭣 → 𠭣 ) CJK COMPATIBILITY IDEOGRAPH-2F838 → CJK UNIFIED IDEOGRAPH-20B63	# 

			{ L"\x2F1D",L"\x53E3" }, //( ⼝ → 口 ) KANGXI RADICAL MOUTH → CJK UNIFIED IDEOGRAPH-53E3	# 

			{ L"\xF906",L"\x53E5" }, //( 句 → 句 ) CJK COMPATIBILITY IDEOGRAPH-F906 → CJK UNIFIED IDEOGRAPH-53E5	# 

			{ L"\x0002\xF839",L"\x53EB" }, //( 叫 → 叫 ) CJK COMPATIBILITY IDEOGRAPH-2F839 → CJK UNIFIED IDEOGRAPH-53EB	# 

			{ L"\x0002\xF83A",L"\x53F1" }, //( 叱 → 叱 ) CJK COMPATIBILITY IDEOGRAPH-2F83A → CJK UNIFIED IDEOGRAPH-53F1	# 

			{ L"\x0002\xF83B",L"\x5406" }, //( 吆 → 吆 ) CJK COMPATIBILITY IDEOGRAPH-2F83B → CJK UNIFIED IDEOGRAPH-5406	# 

			{ L"\xF9DE",L"\x540F" }, //( 吏 → 吏 ) CJK COMPATIBILITY IDEOGRAPH-F9DE → CJK UNIFIED IDEOGRAPH-540F	# 

			{ L"\xF9ED",L"\x541D" }, //( 吝 → 吝 ) CJK COMPATIBILITY IDEOGRAPH-F9ED → CJK UNIFIED IDEOGRAPH-541D	# 

			{ L"\x0002\xF83D",L"\x5438" }, //( 吸 → 吸 ) CJK COMPATIBILITY IDEOGRAPH-2F83D → CJK UNIFIED IDEOGRAPH-5438	# 

			{ L"\xF980",L"\x5442" }, //( 呂 → 呂 ) CJK COMPATIBILITY IDEOGRAPH-F980 → CJK UNIFIED IDEOGRAPH-5442	# 

			{ L"\x0002\xF83E",L"\x5448" }, //( 呈 → 呈 ) CJK COMPATIBILITY IDEOGRAPH-2F83E → CJK UNIFIED IDEOGRAPH-5448	# 

			{ L"\x0002\xF83F",L"\x5468" }, //( 周 → 周 ) CJK COMPATIBILITY IDEOGRAPH-2F83F → CJK UNIFIED IDEOGRAPH-5468	# 

			{ L"\x0002\xF83C",L"\x549E" }, //( 咞 → 咞 ) CJK COMPATIBILITY IDEOGRAPH-2F83C → CJK UNIFIED IDEOGRAPH-549E	# 

			{ L"\x0002\xF840",L"\x54A2" }, //( 咢 → 咢 ) CJK COMPATIBILITY IDEOGRAPH-2F840 → CJK UNIFIED IDEOGRAPH-54A2	# 

			{ L"\xF99E",L"\x54BD" }, //( 咽 → 咽 ) CJK COMPATIBILITY IDEOGRAPH-F99E → CJK UNIFIED IDEOGRAPH-54BD	# 

			{ L"\x439B",L"\x3588" }, //( 䎛 → 㖈 ) CJK UNIFIED IDEOGRAPH-439B → CJK UNIFIED IDEOGRAPH-3588	# 

			{ L"\x0002\xF841",L"\x54F6" }, //( 哶 → 哶 ) CJK COMPATIBILITY IDEOGRAPH-2F841 → CJK UNIFIED IDEOGRAPH-54F6	# 

			{ L"\x0002\xF842",L"\x5510" }, //( 唐 → 唐 ) CJK COMPATIBILITY IDEOGRAPH-2F842 → CJK UNIFIED IDEOGRAPH-5510	# 

			{ L"\x0002\xF843",L"\x5553" }, //( 啓 → 啓 ) CJK COMPATIBILITY IDEOGRAPH-2F843 → CJK UNIFIED IDEOGRAPH-5553	# 
			{ L"\x555F",L"\x5553" }, //( 啟 → 啓 ) CJK UNIFIED IDEOGRAPH-555F → CJK UNIFIED IDEOGRAPH-5553	# 

			{ L"\xFA79",L"\x5555" }, //( 啕 → 啕 ) CJK COMPATIBILITY IDEOGRAPH-FA79 → CJK UNIFIED IDEOGRAPH-5555	# 

			{ L"\x0002\xF844",L"\x5563" }, //( 啣 → 啣 ) CJK COMPATIBILITY IDEOGRAPH-2F844 → CJK UNIFIED IDEOGRAPH-5563	# 

			{ L"\x0002\xF845",L"\x5584" }, //( 善 → 善 ) CJK COMPATIBILITY IDEOGRAPH-2F845 → CJK UNIFIED IDEOGRAPH-5584	# 
			{ L"\x0002\xF846",L"\x5584" }, //( 善 → 善 ) CJK COMPATIBILITY IDEOGRAPH-2F846 → CJK UNIFIED IDEOGRAPH-5584	# 

			{ L"\xF90B",L"\x5587" }, //( 喇 → 喇 ) CJK COMPATIBILITY IDEOGRAPH-F90B → CJK UNIFIED IDEOGRAPH-5587	# 

			{ L"\xFA7A",L"\x5599" }, //( 喙 → 喙 ) CJK COMPATIBILITY IDEOGRAPH-FA7A → CJK UNIFIED IDEOGRAPH-5599	# 
			{ L"\x0002\xF847",L"\x5599" }, //( 喙 → 喙 ) CJK COMPATIBILITY IDEOGRAPH-2F847 → CJK UNIFIED IDEOGRAPH-5599	# 

			{ L"\xFA36",L"\x559D" }, //( 喝 → 喝 ) CJK COMPATIBILITY IDEOGRAPH-FA36 → CJK UNIFIED IDEOGRAPH-559D	# 
			{ L"\xFA78",L"\x559D" }, //( 喝 → 喝 ) CJK COMPATIBILITY IDEOGRAPH-FA78 → CJK UNIFIED IDEOGRAPH-559D	# 

			{ L"\x0002\xF848",L"\x55AB" }, //( 喫 → 喫 ) CJK COMPATIBILITY IDEOGRAPH-2F848 → CJK UNIFIED IDEOGRAPH-55AB	# 

			{ L"\x0002\xF849",L"\x55B3" }, //( 喳 → 喳 ) CJK COMPATIBILITY IDEOGRAPH-2F849 → CJK UNIFIED IDEOGRAPH-55B3	# 

			{ L"\xFA0D",L"\x55C0" }, //( 嗀 → 嗀 ) CJK COMPATIBILITY IDEOGRAPH-FA0D → CJK UNIFIED IDEOGRAPH-55C0	# 

			{ L"\x0002\xF84A",L"\x55C2" }, //( 嗂 → 嗂 ) CJK COMPATIBILITY IDEOGRAPH-2F84A → CJK UNIFIED IDEOGRAPH-55C2	# 

			{ L"\xFA7B",L"\x55E2" }, //( 嗢 → 嗢 ) CJK COMPATIBILITY IDEOGRAPH-FA7B → CJK UNIFIED IDEOGRAPH-55E2	# 

			{ L"\xFA37",L"\x5606" }, //( 嘆 → 嘆 ) CJK COMPATIBILITY IDEOGRAPH-FA37 → CJK UNIFIED IDEOGRAPH-5606	# 
			{ L"\x0002\xF84C",L"\x5606" }, //( 嘆 → 嘆 ) CJK COMPATIBILITY IDEOGRAPH-2F84C → CJK UNIFIED IDEOGRAPH-5606	# 

			{ L"\x0002\xF84E",L"\x5651" }, //( 噑 → 噑 ) CJK COMPATIBILITY IDEOGRAPH-2F84E → CJK UNIFIED IDEOGRAPH-5651	# 

			{ L"\x0002\xF84F",L"\x5674" }, //( 噴 → 噴 ) CJK COMPATIBILITY IDEOGRAPH-2F84F → CJK UNIFIED IDEOGRAPH-5674	# 

			{ L"\xFA38",L"\x5668" }, //( 器 → 器 ) CJK COMPATIBILITY IDEOGRAPH-FA38 → CJK UNIFIED IDEOGRAPH-5668	# 

			{ L"\x2F1E",L"\x56D7" }, //( ⼞ → 囗 ) KANGXI RADICAL ENCLOSURE → CJK UNIFIED IDEOGRAPH-56D7	# 

			{ L"\xF9A9",L"\x56F9" }, //( 囹 → 囹 ) CJK COMPATIBILITY IDEOGRAPH-F9A9 → CJK UNIFIED IDEOGRAPH-56F9	# 

			{ L"\x0002\xF84B",L"\x5716" }, //( 圖 → 圖 ) CJK COMPATIBILITY IDEOGRAPH-2F84B → CJK UNIFIED IDEOGRAPH-5716	# 

			{ L"\x0002\xF84D",L"\x5717" }, //( 圗 → 圗 ) CJK COMPATIBILITY IDEOGRAPH-2F84D → CJK UNIFIED IDEOGRAPH-5717	# 

			{ L"\x2F1F",L"\x571F" }, //( ⼟ → 土 ) KANGXI RADICAL EARTH → CJK UNIFIED IDEOGRAPH-571F	# 

			{ L"\x0002\xF855",L"\x578B" }, //( 型 → 型 ) CJK COMPATIBILITY IDEOGRAPH-2F855 → CJK UNIFIED IDEOGRAPH-578B	# 

			{ L"\x0002\xF852",L"\x57CE" }, //( 城 → 城 ) CJK COMPATIBILITY IDEOGRAPH-2F852 → CJK UNIFIED IDEOGRAPH-57CE	# 

			{ L"\x39B3",L"\x363D" }, //( 㦳 → 㘽 ) CJK UNIFIED IDEOGRAPH-39B3 → CJK UNIFIED IDEOGRAPH-363D	# 

			{ L"\x0002\xF853",L"\x57F4" }, //( 埴 → 埴 ) CJK COMPATIBILITY IDEOGRAPH-2F853 → CJK UNIFIED IDEOGRAPH-57F4	# 

			{ L"\x0002\xF854",L"\x580D" }, //( 堍 → 堍 ) CJK COMPATIBILITY IDEOGRAPH-2F854 → CJK UNIFIED IDEOGRAPH-580D	# 

			{ L"\x0002\xF857",L"\x5831" }, //( 報 → 報 ) CJK COMPATIBILITY IDEOGRAPH-2F857 → CJK UNIFIED IDEOGRAPH-5831	# 

			{ L"\x0002\xF856",L"\x5832" }, //( 堲 → 堲 ) CJK COMPATIBILITY IDEOGRAPH-2F856 → CJK UNIFIED IDEOGRAPH-5832	# 

			{ L"\xFA39",L"\x5840" }, //( 塀 → 塀 ) CJK COMPATIBILITY IDEOGRAPH-FA39 → CJK UNIFIED IDEOGRAPH-5840	# 

			{ L"\xFA10",L"\x585A" }, //( 塚 → 塚 ) CJK COMPATIBILITY IDEOGRAPH-FA10 → CJK UNIFIED IDEOGRAPH-585A	# 
			{ L"\xFA7C",L"\x585A" }, //( 塚 → 塚 ) CJK COMPATIBILITY IDEOGRAPH-FA7C → CJK UNIFIED IDEOGRAPH-585A	# 

			{ L"\xF96C",L"\x585E" }, //( 塞 → 塞 ) CJK COMPATIBILITY IDEOGRAPH-F96C → CJK UNIFIED IDEOGRAPH-585E	# 

			{ L"\x586B",L"\x5861" }, //( 填 → 塡 ) CJK UNIFIED IDEOGRAPH-586B → CJK UNIFIED IDEOGRAPH-5861	# 

			{ L"\x58FF",L"\x58AB" }, //( 壿 → 墫 ) CJK UNIFIED IDEOGRAPH-58FF → CJK UNIFIED IDEOGRAPH-58AB	# 

			{ L"\x0002\xF858",L"\x58AC" }, //( 墬 → 墬 ) CJK COMPATIBILITY IDEOGRAPH-2F858 → CJK UNIFIED IDEOGRAPH-58AC	# 

			{ L"\xFA7D",L"\x58B3" }, //( 墳 → 墳 ) CJK COMPATIBILITY IDEOGRAPH-FA7D → CJK UNIFIED IDEOGRAPH-58B3	# 

			{ L"\xF94A",L"\x58D8" }, //( 壘 → 壘 ) CJK COMPATIBILITY IDEOGRAPH-F94A → CJK UNIFIED IDEOGRAPH-58D8	# 

			{ L"\xF942",L"\x58DF" }, //( 壟 → 壟 ) CJK COMPATIBILITY IDEOGRAPH-F942 → CJK UNIFIED IDEOGRAPH-58DF	# 

			{ L"\x0002\xF859",L"\x0002\x14E4" }, //( 𡓤 → 𡓤 ) CJK COMPATIBILITY IDEOGRAPH-2F859 → CJK UNIFIED IDEOGRAPH-214E4	# 

			{ L"\x2F20",L"\x58EB" }, //( ⼠ → 士 ) KANGXI RADICAL SCHOLAR → CJK UNIFIED IDEOGRAPH-58EB	# 

			{ L"\x0002\xF851",L"\x58EE" }, //( 壮 → 壮 ) CJK COMPATIBILITY IDEOGRAPH-2F851 → CJK UNIFIED IDEOGRAPH-58EE	# 

			{ L"\x0002\xF85A",L"\x58F2" }, //( 売 → 売 ) CJK COMPATIBILITY IDEOGRAPH-2F85A → CJK UNIFIED IDEOGRAPH-58F2	# 

			{ L"\x0002\xF85B",L"\x58F7" }, //( 壷 → 壷 ) CJK COMPATIBILITY IDEOGRAPH-2F85B → CJK UNIFIED IDEOGRAPH-58F7	# 

			{ L"\x2F21",L"\x5902" }, //( ⼡ → 夂 ) KANGXI RADICAL GO → CJK UNIFIED IDEOGRAPH-5902	# 

			{ L"\x0002\xF85C",L"\x5906" }, //( 夆 → 夆 ) CJK COMPATIBILITY IDEOGRAPH-2F85C → CJK UNIFIED IDEOGRAPH-5906	# 

			{ L"\x2F22",L"\x590A" }, //( ⼢ → 夊 ) KANGXI RADICAL GO SLOWLY → CJK UNIFIED IDEOGRAPH-590A	# 

			{ L"\x2F23",L"\x5915" }, //( ⼣ → 夕 ) KANGXI RADICAL EVENING → CJK UNIFIED IDEOGRAPH-5915	# 

			{ L"\x0002\xF85D",L"\x591A" }, //( 多 → 多 ) CJK COMPATIBILITY IDEOGRAPH-2F85D → CJK UNIFIED IDEOGRAPH-591A	# 

			{ L"\x0002\xF85E",L"\x5922" }, //( 夢 → 夢 ) CJK COMPATIBILITY IDEOGRAPH-2F85E → CJK UNIFIED IDEOGRAPH-5922	# 

			{ L"\x2F24",L"\x5927" }, //( ⼤ → 大 ) KANGXI RADICAL BIG → CJK UNIFIED IDEOGRAPH-5927	# 

			{ L"\xFA7E",L"\x5944" }, //( 奄 → 奄 ) CJK COMPATIBILITY IDEOGRAPH-FA7E → CJK UNIFIED IDEOGRAPH-5944	# 

			{ L"\xF90C",L"\x5948" }, //( 奈 → 奈 ) CJK COMPATIBILITY IDEOGRAPH-F90C → CJK UNIFIED IDEOGRAPH-5948	# 

			{ L"\xF909",L"\x5951" }, //( 契 → 契 ) CJK COMPATIBILITY IDEOGRAPH-F909 → CJK UNIFIED IDEOGRAPH-5951	# 

			{ L"\xFA7F",L"\x5954" }, //( 奔 → 奔 ) CJK COMPATIBILITY IDEOGRAPH-FA7F → CJK UNIFIED IDEOGRAPH-5954	# 

			{ L"\x0002\xF85F",L"\x5962" }, //( 奢 → 奢 ) CJK COMPATIBILITY IDEOGRAPH-2F85F → CJK UNIFIED IDEOGRAPH-5962	# 

			{ L"\xF981",L"\x5973" }, //( 女 → 女 ) CJK COMPATIBILITY IDEOGRAPH-F981 → CJK UNIFIED IDEOGRAPH-5973	# 
			{ L"\x2F25",L"\x5973" }, //( ⼥ → 女 ) KANGXI RADICAL WOMAN → CJK UNIFIED IDEOGRAPH-5973	# 

			{ L"\x0002\xF860",L"\x0002\x16A8" }, //( 𡚨 → 𡚨 ) CJK COMPATIBILITY IDEOGRAPH-2F860 → CJK UNIFIED IDEOGRAPH-216A8	# 

			{ L"\x0002\xF861",L"\x0002\x16EA" }, //( 𡛪 → 𡛪 ) CJK COMPATIBILITY IDEOGRAPH-2F861 → CJK UNIFIED IDEOGRAPH-216EA	# 

			{ L"\x0002\xF865",L"\x59D8" }, //( 姘 → 姘 ) CJK COMPATIBILITY IDEOGRAPH-2F865 → CJK UNIFIED IDEOGRAPH-59D8	# 

			{ L"\x0002\xF862",L"\x59EC" }, //( 姬 → 姬 ) CJK COMPATIBILITY IDEOGRAPH-2F862 → CJK UNIFIED IDEOGRAPH-59EC	# 

			{ L"\x0002\xF863",L"\x5A1B" }, //( 娛 → 娛 ) CJK COMPATIBILITY IDEOGRAPH-2F863 → CJK UNIFIED IDEOGRAPH-5A1B	# 

			{ L"\x0002\xF864",L"\x5A27" }, //( 娧 → 娧 ) CJK COMPATIBILITY IDEOGRAPH-2F864 → CJK UNIFIED IDEOGRAPH-5A27	# 

			{ L"\xFA80",L"\x5A62" }, //( 婢 → 婢 ) CJK COMPATIBILITY IDEOGRAPH-FA80 → CJK UNIFIED IDEOGRAPH-5A62	# 

			{ L"\x0002\xF866",L"\x5A66" }, //( 婦 → 婦 ) CJK COMPATIBILITY IDEOGRAPH-2F866 → CJK UNIFIED IDEOGRAPH-5A66	# 

			{ L"\x5B00",L"\x5AAF" }, //( 嬀 → 媯 ) CJK UNIFIED IDEOGRAPH-5B00 → CJK UNIFIED IDEOGRAPH-5AAF	# 

			{ L"\x0002\xF867",L"\x36EE" }, //( 㛮 → 㛮 ) CJK COMPATIBILITY IDEOGRAPH-2F867 → CJK UNIFIED IDEOGRAPH-36EE	# 

			{ L"\x0002\xF868",L"\x36FC" }, //( 㛼 → 㛼 ) CJK COMPATIBILITY IDEOGRAPH-2F868 → CJK UNIFIED IDEOGRAPH-36FC	# 

			{ L"\x0002\xF986",L"\x5AB5" }, //( 媵 → 媵 ) CJK COMPATIBILITY IDEOGRAPH-2F986 → CJK UNIFIED IDEOGRAPH-5AB5	# 

			{ L"\x0002\xF869",L"\x5B08" }, //( 嬈 → 嬈 ) CJK COMPATIBILITY IDEOGRAPH-2F869 → CJK UNIFIED IDEOGRAPH-5B08	# 

			{ L"\xFA81",L"\x5B28" }, //( 嬨 → 嬨 ) CJK COMPATIBILITY IDEOGRAPH-FA81 → CJK UNIFIED IDEOGRAPH-5B28	# 

			{ L"\x0002\xF86A",L"\x5B3E" }, //( 嬾 → 嬾 ) CJK COMPATIBILITY IDEOGRAPH-2F86A → CJK UNIFIED IDEOGRAPH-5B3E	# 
			{ L"\x0002\xF86B",L"\x5B3E" }, //( 嬾 → 嬾 ) CJK COMPATIBILITY IDEOGRAPH-2F86B → CJK UNIFIED IDEOGRAPH-5B3E	# 

			{ L"\x2F26",L"\x5B50" }, //( ⼦ → 子 ) KANGXI RADICAL CHILD → CJK UNIFIED IDEOGRAPH-5B50	# 

			{ L"\x2F27",L"\x5B80" }, //( ⼧ → 宀 ) KANGXI RADICAL ROOF → CJK UNIFIED IDEOGRAPH-5B80	# 

			{ L"\xFA04",L"\x5B85" }, //( 宅 → 宅 ) CJK COMPATIBILITY IDEOGRAPH-FA04 → CJK UNIFIED IDEOGRAPH-5B85	# 

			{ L"\x0002\xF86C",L"\x0002\x19C8" }, //( 𡧈 → 𡧈 ) CJK COMPATIBILITY IDEOGRAPH-2F86C → CJK UNIFIED IDEOGRAPH-219C8	# 

			{ L"\x0002\xF86D",L"\x5BC3" }, //( 寃 → 寃 ) CJK COMPATIBILITY IDEOGRAPH-2F86D → CJK UNIFIED IDEOGRAPH-5BC3	# 

			{ L"\x0002\xF86E",L"\x5BD8" }, //( 寘 → 寘 ) CJK COMPATIBILITY IDEOGRAPH-2F86E → CJK UNIFIED IDEOGRAPH-5BD8	# 

			{ L"\xF95F",L"\x5BE7" }, //( 寧 → 寧 ) CJK COMPATIBILITY IDEOGRAPH-F95F → CJK UNIFIED IDEOGRAPH-5BE7	# 
			{ L"\xF9AA",L"\x5BE7" }, //( 寧 → 寧 ) CJK COMPATIBILITY IDEOGRAPH-F9AA → CJK UNIFIED IDEOGRAPH-5BE7	# 
			{ L"\x0002\xF86F",L"\x5BE7" }, //( 寧 → 寧 ) CJK COMPATIBILITY IDEOGRAPH-2F86F → CJK UNIFIED IDEOGRAPH-5BE7	# 

			{ L"\xF9BC",L"\x5BEE" }, //( 寮 → 寮 ) CJK COMPATIBILITY IDEOGRAPH-F9BC → CJK UNIFIED IDEOGRAPH-5BEE	# 

			{ L"\x0002\xF870",L"\x5BF3" }, //( 寳 → 寳 ) CJK COMPATIBILITY IDEOGRAPH-2F870 → CJK UNIFIED IDEOGRAPH-5BF3	# 

			{ L"\x0002\xF871",L"\x0002\x1B18" }, //( 𡬘 → 𡬘 ) CJK COMPATIBILITY IDEOGRAPH-2F871 → CJK UNIFIED IDEOGRAPH-21B18	# 

			{ L"\x2F28",L"\x5BF8" }, //( ⼨ → 寸 ) KANGXI RADICAL INCH → CJK UNIFIED IDEOGRAPH-5BF8	# 

			{ L"\x0002\xF872",L"\x5BFF" }, //( 寿 → 寿 ) CJK COMPATIBILITY IDEOGRAPH-2F872 → CJK UNIFIED IDEOGRAPH-5BFF	# 

			{ L"\x0002\xF873",L"\x5C06" }, //( 将 → 将 ) CJK COMPATIBILITY IDEOGRAPH-2F873 → CJK UNIFIED IDEOGRAPH-5C06	# 

			{ L"\x2F29",L"\x5C0F" }, //( ⼩ → 小 ) KANGXI RADICAL SMALL → CJK UNIFIED IDEOGRAPH-5C0F	# 

			{ L"\x0002\xF875",L"\x5C22" }, //( 尢 → 尢 ) CJK COMPATIBILITY IDEOGRAPH-2F875 → CJK UNIFIED IDEOGRAPH-5C22	# 
			{ L"\x2E90",L"\x5C22" }, //( ⺐ → 尢 ) CJK RADICAL LAME THREE → CJK UNIFIED IDEOGRAPH-5C22	# 
			{ L"\x2F2A",L"\x5C22" }, //( ⼪ → 尢 ) KANGXI RADICAL LAME → CJK UNIFIED IDEOGRAPH-5C22	# 

			{ L"\x2E8F",L"\x5C23" }, //( ⺏ → 尣 ) CJK RADICAL LAME TWO → CJK UNIFIED IDEOGRAPH-5C23	# 

			{ L"\x0002\xF876",L"\x3781" }, //( 㞁 → 㞁 ) CJK COMPATIBILITY IDEOGRAPH-2F876 → CJK UNIFIED IDEOGRAPH-3781	# 

			{ L"\x2F2B",L"\x5C38" }, //( ⼫ → 尸 ) KANGXI RADICAL CORPSE → CJK UNIFIED IDEOGRAPH-5C38	# 

			{ L"\xF9BD",L"\x5C3F" }, //( 尿 → 尿 ) CJK COMPATIBILITY IDEOGRAPH-F9BD → CJK UNIFIED IDEOGRAPH-5C3F	# 

			{ L"\x0002\xF877",L"\x5C60" }, //( 屠 → 屠 ) CJK COMPATIBILITY IDEOGRAPH-2F877 → CJK UNIFIED IDEOGRAPH-5C60	# 

			{ L"\xF94B",L"\x5C62" }, //( 屢 → 屢 ) CJK COMPATIBILITY IDEOGRAPH-F94B → CJK UNIFIED IDEOGRAPH-5C62	# 

			{ L"\xFA3B",L"\x5C64" }, //( 層 → 層 ) CJK COMPATIBILITY IDEOGRAPH-FA3B → CJK UNIFIED IDEOGRAPH-5C64	# 

			{ L"\xF9DF",L"\x5C65" }, //( 履 → 履 ) CJK COMPATIBILITY IDEOGRAPH-F9DF → CJK UNIFIED IDEOGRAPH-5C65	# 

			{ L"\xFA3C",L"\x5C6E" }, //( 屮 → 屮 ) CJK COMPATIBILITY IDEOGRAPH-FA3C → CJK UNIFIED IDEOGRAPH-5C6E	# 
			{ L"\x0002\xF878",L"\x5C6E" }, //( 屮 → 屮 ) CJK COMPATIBILITY IDEOGRAPH-2F878 → CJK UNIFIED IDEOGRAPH-5C6E	# 
			{ L"\x2F2C",L"\x5C6E" }, //( ⼬ → 屮 ) KANGXI RADICAL SPROUT → CJK UNIFIED IDEOGRAPH-5C6E	# 

			{ L"\x0002\xF8F8",L"\x0002\x1D0B" }, //( 𡴋 → 𡴋 ) CJK COMPATIBILITY IDEOGRAPH-2F8F8 → CJK UNIFIED IDEOGRAPH-21D0B	# 

			{ L"\x2F2D",L"\x5C71" }, //( ⼭ → 山 ) KANGXI RADICAL MOUNTAIN → CJK UNIFIED IDEOGRAPH-5C71	# 

			{ L"\x0002\xF879",L"\x5CC0" }, //( 峀 → 峀 ) CJK COMPATIBILITY IDEOGRAPH-2F879 → CJK UNIFIED IDEOGRAPH-5CC0	# 

			{ L"\x0002\xF87A",L"\x5C8D" }, //( 岍 → 岍 ) CJK COMPATIBILITY IDEOGRAPH-2F87A → CJK UNIFIED IDEOGRAPH-5C8D	# 

			{ L"\x0002\xF87B",L"\x0002\x1DE4" }, //( 𡷤 → 𡷤 ) CJK COMPATIBILITY IDEOGRAPH-2F87B → CJK UNIFIED IDEOGRAPH-21DE4	# 

			{ L"\x0002\xF87D",L"\x0002\x1DE6" }, //( 𡷦 → 𡷦 ) CJK COMPATIBILITY IDEOGRAPH-2F87D → CJK UNIFIED IDEOGRAPH-21DE6	# 

			{ L"\xF9D5",L"\x5D19" }, //( 崙 → 崙 ) CJK COMPATIBILITY IDEOGRAPH-F9D5 → CJK UNIFIED IDEOGRAPH-5D19	# 

			{ L"\x0002\xF87C",L"\x5D43" }, //( 嵃 → 嵃 ) CJK COMPATIBILITY IDEOGRAPH-2F87C → CJK UNIFIED IDEOGRAPH-5D43	# 

			{ L"\xF921",L"\x5D50" }, //( 嵐 → 嵐 ) CJK COMPATIBILITY IDEOGRAPH-F921 → CJK UNIFIED IDEOGRAPH-5D50	# 

			{ L"\x0002\xF87F",L"\x5D6B" }, //( 嵫 → 嵫 ) CJK COMPATIBILITY IDEOGRAPH-2F87F → CJK UNIFIED IDEOGRAPH-5D6B	# 

			{ L"\x0002\xF87E",L"\x5D6E" }, //( 嵮 → 嵮 ) CJK COMPATIBILITY IDEOGRAPH-2F87E → CJK UNIFIED IDEOGRAPH-5D6E	# 

			{ L"\x0002\xF880",L"\x5D7C" }, //( 嵼 → 嵼 ) CJK COMPATIBILITY IDEOGRAPH-2F880 → CJK UNIFIED IDEOGRAPH-5D7C	# 

			{ L"\x0002\xF9F4",L"\x5DB2" }, //( 嶲 → 嶲 ) CJK COMPATIBILITY IDEOGRAPH-2F9F4 → CJK UNIFIED IDEOGRAPH-5DB2	# 

			{ L"\xF9AB",L"\x5DBA" }, //( 嶺 → 嶺 ) CJK COMPATIBILITY IDEOGRAPH-F9AB → CJK UNIFIED IDEOGRAPH-5DBA	# 

			{ L"\x2F2E",L"\x5DDB" }, //( ⼮ → 巛 ) KANGXI RADICAL RIVER → CJK UNIFIED IDEOGRAPH-5DDB	# 

			{ L"\x0002\xF882",L"\x5DE2" }, //( 巢 → 巢 ) CJK COMPATIBILITY IDEOGRAPH-2F882 → CJK UNIFIED IDEOGRAPH-5DE2	# 

			{ L"\x2F2F",L"\x5DE5" }, //( ⼯ → 工 ) KANGXI RADICAL WORK → CJK UNIFIED IDEOGRAPH-5DE5	# 

			{ L"\x2F30",L"\x5DF1" }, //( ⼰ → 己 ) KANGXI RADICAL ONESELF → CJK UNIFIED IDEOGRAPH-5DF1	# 

			{ L"\x2E92",L"\x5DF3" }, //( ⺒ → 巳 ) CJK RADICAL SNAKE → CJK UNIFIED IDEOGRAPH-5DF3	# 

			{ L"\x0002\xF883",L"\x382F" }, //( 㠯 → 㠯 ) CJK COMPATIBILITY IDEOGRAPH-2F883 → CJK UNIFIED IDEOGRAPH-382F	# 

			{ L"\x0002\xF884",L"\x5DFD" }, //( 巽 → 巽 ) CJK COMPATIBILITY IDEOGRAPH-2F884 → CJK UNIFIED IDEOGRAPH-5DFD	# 

			{ L"\x2F31",L"\x5DFE" }, //( ⼱ → 巾 ) KANGXI RADICAL TURBAN → CJK UNIFIED IDEOGRAPH-5DFE	# 

			{ L"\x5E32",L"\x5E21" }, //( 帲 → 帡 ) CJK UNIFIED IDEOGRAPH-5E32 → CJK UNIFIED IDEOGRAPH-5E21	# 

			{ L"\x0002\xF885",L"\x5E28" }, //( 帨 → 帨 ) CJK COMPATIBILITY IDEOGRAPH-2F885 → CJK UNIFIED IDEOGRAPH-5E28	# 

			{ L"\x0002\xF886",L"\x5E3D" }, //( 帽 → 帽 ) CJK COMPATIBILITY IDEOGRAPH-2F886 → CJK UNIFIED IDEOGRAPH-5E3D	# 

			{ L"\x0002\xF887",L"\x5E69" }, //( 幩 → 幩 ) CJK COMPATIBILITY IDEOGRAPH-2F887 → CJK UNIFIED IDEOGRAPH-5E69	# 

			{ L"\x0002\xF888",L"\x3862" }, //( 㡢 → 㡢 ) CJK COMPATIBILITY IDEOGRAPH-2F888 → CJK UNIFIED IDEOGRAPH-3862	# 

			{ L"\x0002\xF889",L"\x0002\x2183" }, //( 𢆃 → 𢆃 ) CJK COMPATIBILITY IDEOGRAPH-2F889 → CJK UNIFIED IDEOGRAPH-22183	# 

			{ L"\x2F32",L"\x5E72" }, //( ⼲ → 干 ) KANGXI RADICAL DRY → CJK UNIFIED IDEOGRAPH-5E72	# 

			{ L"\xF98E",L"\x5E74" }, //( 年 → 年 ) CJK COMPATIBILITY IDEOGRAPH-F98E → CJK UNIFIED IDEOGRAPH-5E74	# 

			{ L"\x0002\xF939",L"\x0002\x219F" }, //( 𢆟 → 𢆟 ) CJK COMPATIBILITY IDEOGRAPH-2F939 → CJK UNIFIED IDEOGRAPH-2219F	# 

			{ L"\x2E93",L"\x5E7A" }, //( ⺓ → 幺 ) CJK RADICAL THREAD → CJK UNIFIED IDEOGRAPH-5E7A	# 
			{ L"\x2F33",L"\x5E7A" }, //( ⼳ → 幺 ) KANGXI RADICAL SHORT THREAD → CJK UNIFIED IDEOGRAPH-5E7A	# 

			{ L"\x2F34",L"\x5E7F" }, //( ⼴ → 广 ) KANGXI RADICAL DOTTED CLIFF → CJK UNIFIED IDEOGRAPH-5E7F	# 

			{ L"\xFA01",L"\x5EA6" }, //( 度 → 度 ) CJK COMPATIBILITY IDEOGRAPH-FA01 → CJK UNIFIED IDEOGRAPH-5EA6	# 

			{ L"\x0002\xF88A",L"\x387C" }, //( 㡼 → 㡼 ) CJK COMPATIBILITY IDEOGRAPH-2F88A → CJK UNIFIED IDEOGRAPH-387C	# 

			{ L"\x0002\xF88B",L"\x5EB0" }, //( 庰 → 庰 ) CJK COMPATIBILITY IDEOGRAPH-2F88B → CJK UNIFIED IDEOGRAPH-5EB0	# 

			{ L"\x0002\xF88C",L"\x5EB3" }, //( 庳 → 庳 ) CJK COMPATIBILITY IDEOGRAPH-2F88C → CJK UNIFIED IDEOGRAPH-5EB3	# 

			{ L"\x0002\xF88D",L"\x5EB6" }, //( 庶 → 庶 ) CJK COMPATIBILITY IDEOGRAPH-2F88D → CJK UNIFIED IDEOGRAPH-5EB6	# 

			{ L"\xF928",L"\x5ECA" }, //( 廊 → 廊 ) CJK COMPATIBILITY IDEOGRAPH-F928 → CJK UNIFIED IDEOGRAPH-5ECA	# 
			{ L"\x0002\xF88E",L"\x5ECA" }, //( 廊 → 廊 ) CJK COMPATIBILITY IDEOGRAPH-2F88E → CJK UNIFIED IDEOGRAPH-5ECA	# 

			{ L"\xF9A2",L"\x5EC9" }, //( 廉 → 廉 ) CJK COMPATIBILITY IDEOGRAPH-F9A2 → CJK UNIFIED IDEOGRAPH-5EC9	# 

			{ L"\xFA82",L"\x5ED2" }, //( 廒 → 廒 ) CJK COMPATIBILITY IDEOGRAPH-FA82 → CJK UNIFIED IDEOGRAPH-5ED2	# 

			{ L"\xFA0B",L"\x5ED3" }, //( 廓 → 廓 ) CJK COMPATIBILITY IDEOGRAPH-FA0B → CJK UNIFIED IDEOGRAPH-5ED3	# 

			{ L"\xFA83",L"\x5ED9" }, //( 廙 → 廙 ) CJK COMPATIBILITY IDEOGRAPH-FA83 → CJK UNIFIED IDEOGRAPH-5ED9	# 

			{ L"\xF982",L"\x5EEC" }, //( 廬 → 廬 ) CJK COMPATIBILITY IDEOGRAPH-F982 → CJK UNIFIED IDEOGRAPH-5EEC	# 

			{ L"\x2F35",L"\x5EF4" }, //( ⼵ → 廴 ) KANGXI RADICAL LONG STRIDE → CJK UNIFIED IDEOGRAPH-5EF4	# 

			{ L"\x0002\xF890",L"\x5EFE" }, //( 廾 → 廾 ) CJK COMPATIBILITY IDEOGRAPH-2F890 → CJK UNIFIED IDEOGRAPH-5EFE	# 
			{ L"\x2F36",L"\x5EFE" }, //( ⼶ → 廾 ) KANGXI RADICAL TWO HANDS → CJK UNIFIED IDEOGRAPH-5EFE	# 

			{ L"\x0002\xF891",L"\x0002\x2331" }, //( 𢌱 → 𢌱 ) CJK COMPATIBILITY IDEOGRAPH-2F891 → CJK UNIFIED IDEOGRAPH-22331	# 
			{ L"\x0002\xF892",L"\x0002\x2331" }, //( 𢌱 → 𢌱 ) CJK COMPATIBILITY IDEOGRAPH-2F892 → CJK UNIFIED IDEOGRAPH-22331	# 

			{ L"\xF943",L"\x5F04" }, //( 弄 → 弄 ) CJK COMPATIBILITY IDEOGRAPH-F943 → CJK UNIFIED IDEOGRAPH-5F04	# 

			{ L"\x2F37",L"\x5F0B" }, //( ⼷ → 弋 ) KANGXI RADICAL SHOOT → CJK UNIFIED IDEOGRAPH-5F0B	# 

			{ L"\x2F38",L"\x5F13" }, //( ⼸ → 弓 ) KANGXI RADICAL BOW → CJK UNIFIED IDEOGRAPH-5F13	# 

			{ L"\x0002\xF894",L"\x5F22" }, //( 弢 → 弢 ) CJK COMPATIBILITY IDEOGRAPH-2F894 → CJK UNIFIED IDEOGRAPH-5F22	# 
			{ L"\x0002\xF895",L"\x5F22" }, //( 弢 → 弢 ) CJK COMPATIBILITY IDEOGRAPH-2F895 → CJK UNIFIED IDEOGRAPH-5F22	# 

			{ L"\x2F39",L"\x5F50" }, //( ⼹ → 彐 ) KANGXI RADICAL SNOUT → CJK UNIFIED IDEOGRAPH-5F50	# 

			{ L"\x2E94",L"\x5F51" }, //( ⺔ → 彑 ) CJK RADICAL SNOUT ONE → CJK UNIFIED IDEOGRAPH-5F51	# 

			{ L"\x0002\xF874",L"\x5F53" }, //( 当 → 当 ) CJK COMPATIBILITY IDEOGRAPH-2F874 → CJK UNIFIED IDEOGRAPH-5F53	# 

			{ L"\x0002\xF896",L"\x38C7" }, //( 㣇 → 㣇 ) CJK COMPATIBILITY IDEOGRAPH-2F896 → CJK UNIFIED IDEOGRAPH-38C7	# 

			{ L"\x2F3A",L"\x5F61" }, //( ⼺ → 彡 ) KANGXI RADICAL BRISTLE → CJK UNIFIED IDEOGRAPH-5F61	# 

			{ L"\x0002\xF899",L"\x5F62" }, //( 形 → 形 ) CJK COMPATIBILITY IDEOGRAPH-2F899 → CJK UNIFIED IDEOGRAPH-5F62	# 

			{ L"\xFA84",L"\x5F69" }, //( 彩 → 彩 ) CJK COMPATIBILITY IDEOGRAPH-FA84 → CJK UNIFIED IDEOGRAPH-5F69	# 

			{ L"\x0002\xF89A",L"\x5F6B" }, //( 彫 → 彫 ) CJK COMPATIBILITY IDEOGRAPH-2F89A → CJK UNIFIED IDEOGRAPH-5F6B	# 

			{ L"\x2F3B",L"\x5F73" }, //( ⼻ → 彳 ) KANGXI RADICAL STEP → CJK UNIFIED IDEOGRAPH-5F73	# 

			{ L"\xF9D8",L"\x5F8B" }, //( 律 → 律 ) CJK COMPATIBILITY IDEOGRAPH-F9D8 → CJK UNIFIED IDEOGRAPH-5F8B	# 

			{ L"\x0002\xF89B",L"\x38E3" }, //( 㣣 → 㣣 ) CJK COMPATIBILITY IDEOGRAPH-2F89B → CJK UNIFIED IDEOGRAPH-38E3	# 

			{ L"\x0002\xF89C",L"\x5F9A" }, //( 徚 → 徚 ) CJK COMPATIBILITY IDEOGRAPH-2F89C → CJK UNIFIED IDEOGRAPH-5F9A	# 

			{ L"\xF966",L"\x5FA9" }, //( 復 → 復 ) CJK COMPATIBILITY IDEOGRAPH-F966 → CJK UNIFIED IDEOGRAPH-5FA9	# 

			{ L"\xFA85",L"\x5FAD" }, //( 徭 → 徭 ) CJK COMPATIBILITY IDEOGRAPH-FA85 → CJK UNIFIED IDEOGRAPH-5FAD	# 

			{ L"\x2F3C",L"\x5FC3" }, //( ⼼ → 心 ) KANGXI RADICAL HEART → CJK UNIFIED IDEOGRAPH-5FC3	# 

			{ L"\x2E96",L"\x5FC4" }, //( ⺖ → 忄 ) CJK RADICAL HEART ONE → CJK UNIFIED IDEOGRAPH-5FC4	# 

			{ L"\x2E97",L"\x38FA" }, //( ⺗ → 㣺 ) CJK RADICAL HEART TWO → CJK UNIFIED IDEOGRAPH-38FA	# 

			{ L"\x0002\xF89D",L"\x5FCD" }, //( 忍 → 忍 ) CJK COMPATIBILITY IDEOGRAPH-2F89D → CJK UNIFIED IDEOGRAPH-5FCD	# 

			{ L"\x0002\xF89E",L"\x5FD7" }, //( 志 → 志 ) CJK COMPATIBILITY IDEOGRAPH-2F89E → CJK UNIFIED IDEOGRAPH-5FD7	# 

			{ L"\xF9A3",L"\x5FF5" }, //( 念 → 念 ) CJK COMPATIBILITY IDEOGRAPH-F9A3 → CJK UNIFIED IDEOGRAPH-5FF5	# 

			{ L"\x0002\xF89F",L"\x5FF9" }, //( 忹 → 忹 ) CJK COMPATIBILITY IDEOGRAPH-2F89F → CJK UNIFIED IDEOGRAPH-5FF9	# 

			{ L"\xF960",L"\x6012" }, //( 怒 → 怒 ) CJK COMPATIBILITY IDEOGRAPH-F960 → CJK UNIFIED IDEOGRAPH-6012	# 

			{ L"\xF9AC",L"\x601C" }, //( 怜 → 怜 ) CJK COMPATIBILITY IDEOGRAPH-F9AC → CJK UNIFIED IDEOGRAPH-601C	# 

			{ L"\xFA6B",L"\x6075" }, //( 恵 → 恵 ) CJK COMPATIBILITY IDEOGRAPH-FA6B → CJK UNIFIED IDEOGRAPH-6075	# 

			{ L"\x0002\xF8A2",L"\x391C" }, //( 㤜 → 㤜 ) CJK COMPATIBILITY IDEOGRAPH-2F8A2 → CJK UNIFIED IDEOGRAPH-391C	# 

			{ L"\x0002\xF8A1",L"\x393A" }, //( 㤺 → 㤺 ) CJK COMPATIBILITY IDEOGRAPH-2F8A1 → CJK UNIFIED IDEOGRAPH-393A	# 

			{ L"\x0002\xF8A0",L"\x6081" }, //( 悁 → 悁 ) CJK COMPATIBILITY IDEOGRAPH-2F8A0 → CJK UNIFIED IDEOGRAPH-6081	# 

			{ L"\xFA3D",L"\x6094" }, //( 悔 → 悔 ) CJK COMPATIBILITY IDEOGRAPH-FA3D → CJK UNIFIED IDEOGRAPH-6094	# 
			{ L"\x0002\xF8A3",L"\x6094" }, //( 悔 → 悔 ) CJK COMPATIBILITY IDEOGRAPH-2F8A3 → CJK UNIFIED IDEOGRAPH-6094	# 

			{ L"\x0002\xF8A5",L"\x60C7" }, //( 惇 → 惇 ) CJK COMPATIBILITY IDEOGRAPH-2F8A5 → CJK UNIFIED IDEOGRAPH-60C7	# 

			{ L"\xFA86",L"\x60D8" }, //( 惘 → 惘 ) CJK COMPATIBILITY IDEOGRAPH-FA86 → CJK UNIFIED IDEOGRAPH-60D8	# 

			{ L"\xF9B9",L"\x60E1" }, //( 惡 → 惡 ) CJK COMPATIBILITY IDEOGRAPH-F9B9 → CJK UNIFIED IDEOGRAPH-60E1	# 

			{ L"\x0002\xF8A4",L"\x0002\x26D4" }, //( 𢛔 → 𢛔 ) CJK COMPATIBILITY IDEOGRAPH-2F8A4 → CJK UNIFIED IDEOGRAPH-226D4	# 

			{ L"\xFA88",L"\x6108" }, //( 愈 → 愈 ) CJK COMPATIBILITY IDEOGRAPH-FA88 → CJK UNIFIED IDEOGRAPH-6108	# 

			{ L"\xFA3E",L"\x6168" }, //( 慨 → 慨 ) CJK COMPATIBILITY IDEOGRAPH-FA3E → CJK UNIFIED IDEOGRAPH-6168	# 

			{ L"\xF9D9",L"\x6144" }, //( 慄 → 慄 ) CJK COMPATIBILITY IDEOGRAPH-F9D9 → CJK UNIFIED IDEOGRAPH-6144	# 

			{ L"\x0002\xF8A6",L"\x6148" }, //( 慈 → 慈 ) CJK COMPATIBILITY IDEOGRAPH-2F8A6 → CJK UNIFIED IDEOGRAPH-6148	# 

			{ L"\x0002\xF8A7",L"\x614C" }, //( 慌 → 慌 ) CJK COMPATIBILITY IDEOGRAPH-2F8A7 → CJK UNIFIED IDEOGRAPH-614C	# 
			{ L"\x0002\xF8A9",L"\x614C" }, //( 慌 → 慌 ) CJK COMPATIBILITY IDEOGRAPH-2F8A9 → CJK UNIFIED IDEOGRAPH-614C	# 

			{ L"\xFA87",L"\x614E" }, //( 慎 → 慎 ) CJK COMPATIBILITY IDEOGRAPH-FA87 → CJK UNIFIED IDEOGRAPH-614E	# 
			{ L"\x0002\xF8A8",L"\x614E" }, //( 慎 → 慎 ) CJK COMPATIBILITY IDEOGRAPH-2F8A8 → CJK UNIFIED IDEOGRAPH-614E	# 

			{ L"\xFA8A",L"\x6160" }, //( 慠 → 慠 ) CJK COMPATIBILITY IDEOGRAPH-FA8A → CJK UNIFIED IDEOGRAPH-6160	# 

			{ L"\x0002\xF8AA",L"\x617A" }, //( 慺 → 慺 ) CJK COMPATIBILITY IDEOGRAPH-2F8AA → CJK UNIFIED IDEOGRAPH-617A	# 

			{ L"\xFA3F",L"\x618E" }, //( 憎 → 憎 ) CJK COMPATIBILITY IDEOGRAPH-FA3F → CJK UNIFIED IDEOGRAPH-618E	# 
			{ L"\xFA89",L"\x618E" }, //( 憎 → 憎 ) CJK COMPATIBILITY IDEOGRAPH-FA89 → CJK UNIFIED IDEOGRAPH-618E	# 
			{ L"\x0002\xF8AB",L"\x618E" }, //( 憎 → 憎 ) CJK COMPATIBILITY IDEOGRAPH-2F8AB → CJK UNIFIED IDEOGRAPH-618E	# 

			{ L"\xF98F",L"\x6190" }, //( 憐 → 憐 ) CJK COMPATIBILITY IDEOGRAPH-F98F → CJK UNIFIED IDEOGRAPH-6190	# 

			{ L"\x0002\xF8AD",L"\x61A4" }, //( 憤 → 憤 ) CJK COMPATIBILITY IDEOGRAPH-2F8AD → CJK UNIFIED IDEOGRAPH-61A4	# 

			{ L"\x0002\xF8AE",L"\x61AF" }, //( 憯 → 憯 ) CJK COMPATIBILITY IDEOGRAPH-2F8AE → CJK UNIFIED IDEOGRAPH-61AF	# 

			{ L"\x0002\xF8AC",L"\x61B2" }, //( 憲 → 憲 ) CJK COMPATIBILITY IDEOGRAPH-2F8AC → CJK UNIFIED IDEOGRAPH-61B2	# 

			{ L"\xFAD0",L"\x0002\x2844" }, //( 𢡄 → 𢡄 ) CJK COMPATIBILITY IDEOGRAPH-FAD0 → CJK UNIFIED IDEOGRAPH-22844	# 

			{ L"\xFACF",L"\x0002\x284A" }, //( 𢡊 → 𢡊 ) CJK COMPATIBILITY IDEOGRAPH-FACF → CJK UNIFIED IDEOGRAPH-2284A	# 

			{ L"\x0002\xF8AF",L"\x61DE" }, //( 懞 → 懞 ) CJK COMPATIBILITY IDEOGRAPH-2F8AF → CJK UNIFIED IDEOGRAPH-61DE	# 

			{ L"\xFA40",L"\x61F2" }, //( 懲 → 懲 ) CJK COMPATIBILITY IDEOGRAPH-FA40 → CJK UNIFIED IDEOGRAPH-61F2	# 
			{ L"\xFA8B",L"\x61F2" }, //( 懲 → 懲 ) CJK COMPATIBILITY IDEOGRAPH-FA8B → CJK UNIFIED IDEOGRAPH-61F2	# 
			{ L"\x0002\xF8B0",L"\x61F2" }, //( 懲 → 懲 ) CJK COMPATIBILITY IDEOGRAPH-2F8B0 → CJK UNIFIED IDEOGRAPH-61F2	# 

			{ L"\xF90D",L"\x61F6" }, //( 懶 → 懶 ) CJK COMPATIBILITY IDEOGRAPH-F90D → CJK UNIFIED IDEOGRAPH-61F6	# 
			{ L"\x0002\xF8B1",L"\x61F6" }, //( 懶 → 懶 ) CJK COMPATIBILITY IDEOGRAPH-2F8B1 → CJK UNIFIED IDEOGRAPH-61F6	# 

			{ L"\xF990",L"\x6200" }, //( 戀 → 戀 ) CJK COMPATIBILITY IDEOGRAPH-F990 → CJK UNIFIED IDEOGRAPH-6200	# 

			{ L"\x2F3D",L"\x6208" }, //( ⼽ → 戈 ) KANGXI RADICAL HALBERD → CJK UNIFIED IDEOGRAPH-6208	# 

			{ L"\x0002\xF8B2",L"\x6210" }, //( 成 → 成 ) CJK COMPATIBILITY IDEOGRAPH-2F8B2 → CJK UNIFIED IDEOGRAPH-6210	# 

			{ L"\x0002\xF8B3",L"\x621B" }, //( 戛 → 戛 ) CJK COMPATIBILITY IDEOGRAPH-2F8B3 → CJK UNIFIED IDEOGRAPH-621B	# 

			{ L"\xF9D2",L"\x622E" }, //( 戮 → 戮 ) CJK COMPATIBILITY IDEOGRAPH-F9D2 → CJK UNIFIED IDEOGRAPH-622E	# 

			{ L"\xFA8C",L"\x6234" }, //( 戴 → 戴 ) CJK COMPATIBILITY IDEOGRAPH-FA8C → CJK UNIFIED IDEOGRAPH-6234	# 

			{ L"\x2F3E",L"\x6236" }, //( ⼾ → 戶 ) KANGXI RADICAL DOOR → CJK UNIFIED IDEOGRAPH-6236	# 
			{ L"\x6238",L"\x6236" }, //( 戸 → 戶 ) CJK UNIFIED IDEOGRAPH-6238 → CJK UNIFIED IDEOGRAPH-6236	# →⼾→

			{ L"\x2F3F",L"\x624B" }, //( ⼿ → 手 ) KANGXI RADICAL HAND → CJK UNIFIED IDEOGRAPH-624B	# 

			{ L"\x2E98",L"\x624C" }, //( ⺘ → 扌 ) CJK RADICAL HAND → CJK UNIFIED IDEOGRAPH-624C	# 

			{ L"\x0002\xF8B4",L"\x625D" }, //( 扝 → 扝 ) CJK COMPATIBILITY IDEOGRAPH-2F8B4 → CJK UNIFIED IDEOGRAPH-625D	# 

			{ L"\x0002\xF8B5",L"\x62B1" }, //( 抱 → 抱 ) CJK COMPATIBILITY IDEOGRAPH-2F8B5 → CJK UNIFIED IDEOGRAPH-62B1	# 

			{ L"\xF925",L"\x62C9" }, //( 拉 → 拉 ) CJK COMPATIBILITY IDEOGRAPH-F925 → CJK UNIFIED IDEOGRAPH-62C9	# 

			{ L"\xF95B",L"\x62CF" }, //( 拏 → 拏 ) CJK COMPATIBILITY IDEOGRAPH-F95B → CJK UNIFIED IDEOGRAPH-62CF	# 

			{ L"\xFA02",L"\x62D3" }, //( 拓 → 拓 ) CJK COMPATIBILITY IDEOGRAPH-FA02 → CJK UNIFIED IDEOGRAPH-62D3	# 

			{ L"\x0002\xF8B6",L"\x62D4" }, //( 拔 → 拔 ) CJK COMPATIBILITY IDEOGRAPH-2F8B6 → CJK UNIFIED IDEOGRAPH-62D4	# 

			{ L"\x0002\xF8BA",L"\x62FC" }, //( 拼 → 拼 ) CJK COMPATIBILITY IDEOGRAPH-2F8BA → CJK UNIFIED IDEOGRAPH-62FC	# 

			{ L"\xF973",L"\x62FE" }, //( 拾 → 拾 ) CJK COMPATIBILITY IDEOGRAPH-F973 → CJK UNIFIED IDEOGRAPH-62FE	# 

			{ L"\x0002\xF8B8",L"\x0002\x2B0C" }, //( 𢬌 → 𢬌 ) CJK COMPATIBILITY IDEOGRAPH-2F8B8 → CJK UNIFIED IDEOGRAPH-22B0C	# 

			{ L"\x0002\xF8B9",L"\x633D" }, //( 挽 → 挽 ) CJK COMPATIBILITY IDEOGRAPH-2F8B9 → CJK UNIFIED IDEOGRAPH-633D	# 

			{ L"\x0002\xF8B7",L"\x6350" }, //( 捐 → 捐 ) CJK COMPATIBILITY IDEOGRAPH-2F8B7 → CJK UNIFIED IDEOGRAPH-6350	# 

			{ L"\x0002\xF8BB",L"\x6368" }, //( 捨 → 捨 ) CJK COMPATIBILITY IDEOGRAPH-2F8BB → CJK UNIFIED IDEOGRAPH-6368	# 

			{ L"\xF9A4",L"\x637B" }, //( 捻 → 捻 ) CJK COMPATIBILITY IDEOGRAPH-F9A4 → CJK UNIFIED IDEOGRAPH-637B	# 

			{ L"\x0002\xF8BC",L"\x6383" }, //( 掃 → 掃 ) CJK COMPATIBILITY IDEOGRAPH-2F8BC → CJK UNIFIED IDEOGRAPH-6383	# 

			{ L"\xF975",L"\x63A0" }, //( 掠 → 掠 ) CJK COMPATIBILITY IDEOGRAPH-F975 → CJK UNIFIED IDEOGRAPH-63A0	# 

			{ L"\x0002\xF8C1",L"\x63A9" }, //( 掩 → 掩 ) CJK COMPATIBILITY IDEOGRAPH-2F8C1 → CJK UNIFIED IDEOGRAPH-63A9	# 

			{ L"\xFA8D",L"\x63C4" }, //( 揄 → 揄 ) CJK COMPATIBILITY IDEOGRAPH-FA8D → CJK UNIFIED IDEOGRAPH-63C4	# 

			{ L"\x0002\xF8BD",L"\x63E4" }, //( 揤 → 揤 ) CJK COMPATIBILITY IDEOGRAPH-2F8BD → CJK UNIFIED IDEOGRAPH-63E4	# 

			{ L"\xFA8F",L"\x6452" }, //( 摒 → 摒 ) CJK COMPATIBILITY IDEOGRAPH-FA8F → CJK UNIFIED IDEOGRAPH-6452	# 

			{ L"\x0002\xF8BE",L"\x0002\x2BF1" }, //( 𢯱 → 𢯱 ) CJK COMPATIBILITY IDEOGRAPH-2F8BE → CJK UNIFIED IDEOGRAPH-22BF1	# 

			{ L"\xFA8E",L"\x641C" }, //( 搜 → 搜 ) CJK COMPATIBILITY IDEOGRAPH-FA8E → CJK UNIFIED IDEOGRAPH-641C	# 

			{ L"\x0002\xF8BF",L"\x6422" }, //( 搢 → 搢 ) CJK COMPATIBILITY IDEOGRAPH-2F8BF → CJK UNIFIED IDEOGRAPH-6422	# 

			{ L"\x0002\xF8C0",L"\x63C5" }, //( 揅 → 揅 ) CJK COMPATIBILITY IDEOGRAPH-2F8C0 → CJK UNIFIED IDEOGRAPH-63C5	# 

			{ L"\x0002\xF8C3",L"\x6469" }, //( 摩 → 摩 ) CJK COMPATIBILITY IDEOGRAPH-2F8C3 → CJK UNIFIED IDEOGRAPH-6469	# 

			{ L"\x0002\xF8C6",L"\x6477" }, //( 摷 → 摷 ) CJK COMPATIBILITY IDEOGRAPH-2F8C6 → CJK UNIFIED IDEOGRAPH-6477	# 

			{ L"\x0002\xF8C4",L"\x647E" }, //( 摾 → 摾 ) CJK COMPATIBILITY IDEOGRAPH-2F8C4 → CJK UNIFIED IDEOGRAPH-647E	# 

			{ L"\x0002\xF8C2",L"\x3A2E" }, //( 㨮 → 㨮 ) CJK COMPATIBILITY IDEOGRAPH-2F8C2 → CJK UNIFIED IDEOGRAPH-3A2E	# 

			{ L"\x6409",L"\x3A41" }, //( 搉 → 㩁 ) CJK UNIFIED IDEOGRAPH-6409 → CJK UNIFIED IDEOGRAPH-3A41	# 

			{ L"\xF991",L"\x649A" }, //( 撚 → 撚 ) CJK COMPATIBILITY IDEOGRAPH-F991 → CJK UNIFIED IDEOGRAPH-649A	# 

			{ L"\x0002\xF8C5",L"\x649D" }, //( 撝 → 撝 ) CJK COMPATIBILITY IDEOGRAPH-2F8C5 → CJK UNIFIED IDEOGRAPH-649D	# 

			{ L"\xF930",L"\x64C4" }, //( 擄 → 擄 ) CJK COMPATIBILITY IDEOGRAPH-F930 → CJK UNIFIED IDEOGRAPH-64C4	# 

			{ L"\x0002\xF8C7",L"\x3A6C" }, //( 㩬 → 㩬 ) CJK COMPATIBILITY IDEOGRAPH-2F8C7 → CJK UNIFIED IDEOGRAPH-3A6C	# 

			{ L"\x2F40",L"\x652F" }, //( ⽀ → 支 ) KANGXI RADICAL BRANCH → CJK UNIFIED IDEOGRAPH-652F	# 

			{ L"\x2F41",L"\x6534" }, //( ⽁ → 攴 ) KANGXI RADICAL RAP → CJK UNIFIED IDEOGRAPH-6534	# 

			{ L"\x2E99",L"\x6535" }, //( ⺙ → 攵 ) CJK RADICAL RAP → CJK UNIFIED IDEOGRAPH-6535	# 

			{ L"\xFA41",L"\x654F" }, //( 敏 → 敏 ) CJK COMPATIBILITY IDEOGRAPH-FA41 → CJK UNIFIED IDEOGRAPH-654F	# 
			{ L"\x0002\xF8C8",L"\x654F" }, //( 敏 → 敏 ) CJK COMPATIBILITY IDEOGRAPH-2F8C8 → CJK UNIFIED IDEOGRAPH-654F	# 

			{ L"\xFA90",L"\x6556" }, //( 敖 → 敖 ) CJK COMPATIBILITY IDEOGRAPH-FA90 → CJK UNIFIED IDEOGRAPH-6556	# 

			{ L"\x0002\xF8C9",L"\x656C" }, //( 敬 → 敬 ) CJK COMPATIBILITY IDEOGRAPH-2F8C9 → CJK UNIFIED IDEOGRAPH-656C	# 

			{ L"\xF969",L"\x6578" }, //( 數 → 數 ) CJK COMPATIBILITY IDEOGRAPH-F969 → CJK UNIFIED IDEOGRAPH-6578	# 

			{ L"\x0002\xF8CA",L"\x0002\x300A" }, //( 𣀊 → 𣀊 ) CJK COMPATIBILITY IDEOGRAPH-2F8CA → CJK UNIFIED IDEOGRAPH-2300A	# 

			{ L"\x2F42",L"\x6587" }, //( ⽂ → 文 ) KANGXI RADICAL SCRIPT → CJK UNIFIED IDEOGRAPH-6587	# 

			{ L"\x2EEB",L"\x6589" }, //( ⻫ → 斉 ) CJK RADICAL J-SIMPLIFIED EVEN → CJK UNIFIED IDEOGRAPH-6589	# 

			{ L"\x2F43",L"\x6597" }, //( ⽃ → 斗 ) KANGXI RADICAL DIPPER → CJK UNIFIED IDEOGRAPH-6597	# 

			{ L"\xF9BE",L"\x6599" }, //( 料 → 料 ) CJK COMPATIBILITY IDEOGRAPH-F9BE → CJK UNIFIED IDEOGRAPH-6599	# 

			{ L"\x2F44",L"\x65A4" }, //( ⽄ → 斤 ) KANGXI RADICAL AXE → CJK UNIFIED IDEOGRAPH-65A4	# 

			{ L"\x2F45",L"\x65B9" }, //( ⽅ → 方 ) KANGXI RADICAL SQUARE → CJK UNIFIED IDEOGRAPH-65B9	# 

			{ L"\xF983",L"\x65C5" }, //( 旅 → 旅 ) CJK COMPATIBILITY IDEOGRAPH-F983 → CJK UNIFIED IDEOGRAPH-65C5	# 

			{ L"\x2F46",L"\x65E0" }, //( ⽆ → 无 ) KANGXI RADICAL NOT → CJK UNIFIED IDEOGRAPH-65E0	# 

			{ L"\x2E9B",L"\x65E1" }, //( ⺛ → 旡 ) CJK RADICAL CHOKE → CJK UNIFIED IDEOGRAPH-65E1	# 

			{ L"\xFA42",L"\x65E2" }, //( 既 → 既 ) CJK COMPATIBILITY IDEOGRAPH-FA42 → CJK UNIFIED IDEOGRAPH-65E2	# 

			{ L"\x0002\xF8CB",L"\x65E3" }, //( 旣 → 旣 ) CJK COMPATIBILITY IDEOGRAPH-2F8CB → CJK UNIFIED IDEOGRAPH-65E3	# 

			{ L"\x2F47",L"\x65E5" }, //( ⽇ → 日 ) KANGXI RADICAL SUN → CJK UNIFIED IDEOGRAPH-65E5	# 

			{ L"\xF9E0",L"\x6613" }, //( 易 → 易 ) CJK COMPATIBILITY IDEOGRAPH-F9E0 → CJK UNIFIED IDEOGRAPH-6613	# 

			{ L"\x66F6",L"\x3ADA" }, //( 曶 → 㫚 ) CJK UNIFIED IDEOGRAPH-66F6 → CJK UNIFIED IDEOGRAPH-3ADA	# 

			{ L"\x0002\xF8D1",L"\x3AE4" }, //( 㫤 → 㫤 ) CJK COMPATIBILITY IDEOGRAPH-2F8D1 → CJK UNIFIED IDEOGRAPH-3AE4	# 

			{ L"\x0002\xF8CD",L"\x6649" }, //( 晉 → 晉 ) CJK COMPATIBILITY IDEOGRAPH-2F8CD → CJK UNIFIED IDEOGRAPH-6649	# 

			{ L"\x6669",L"\x665A" }, //( 晩 → 晚 ) CJK UNIFIED IDEOGRAPH-6669 → CJK UNIFIED IDEOGRAPH-665A	# 

			{ L"\xFA12",L"\x6674" }, //( 晴 → 晴 ) CJK COMPATIBILITY IDEOGRAPH-FA12 → CJK UNIFIED IDEOGRAPH-6674	# 
			{ L"\xFA91",L"\x6674" }, //( 晴 → 晴 ) CJK COMPATIBILITY IDEOGRAPH-FA91 → CJK UNIFIED IDEOGRAPH-6674	# 

			{ L"\xFA43",L"\x6691" }, //( 暑 → 暑 ) CJK COMPATIBILITY IDEOGRAPH-FA43 → CJK UNIFIED IDEOGRAPH-6691	# 
			{ L"\x0002\xF8CF",L"\x6691" }, //( 暑 → 暑 ) CJK COMPATIBILITY IDEOGRAPH-2F8CF → CJK UNIFIED IDEOGRAPH-6691	# 

			{ L"\xF9C5",L"\x6688" }, //( 暈 → 暈 ) CJK COMPATIBILITY IDEOGRAPH-F9C5 → CJK UNIFIED IDEOGRAPH-6688	# 

			{ L"\x0002\xF8D0",L"\x3B08" }, //( 㬈 → 㬈 ) CJK COMPATIBILITY IDEOGRAPH-2F8D0 → CJK UNIFIED IDEOGRAPH-3B08	# 

			{ L"\x0002\xF8D5",L"\x669C" }, //( 暜 → 暜 ) CJK COMPATIBILITY IDEOGRAPH-2F8D5 → CJK UNIFIED IDEOGRAPH-669C	# 

			{ L"\xFA06",L"\x66B4" }, //( 暴 → 暴 ) CJK COMPATIBILITY IDEOGRAPH-FA06 → CJK UNIFIED IDEOGRAPH-66B4	# 

			{ L"\xF98B",L"\x66C6" }, //( 曆 → 曆 ) CJK COMPATIBILITY IDEOGRAPH-F98B → CJK UNIFIED IDEOGRAPH-66C6	# 

			{ L"\x0002\xF8CE",L"\x3B19" }, //( 㬙 → 㬙 ) CJK COMPATIBILITY IDEOGRAPH-2F8CE → CJK UNIFIED IDEOGRAPH-3B19	# 

			{ L"\x0002\xF897",L"\x0002\x32B8" }, //( 𣊸 → 𣊸 ) CJK COMPATIBILITY IDEOGRAPH-2F897 → CJK UNIFIED IDEOGRAPH-232B8	# 

			{ L"\x2F48",L"\x66F0" }, //( ⽈ → 曰 ) KANGXI RADICAL SAY → CJK UNIFIED IDEOGRAPH-66F0	# 

			{ L"\xF901",L"\x66F4" }, //( 更 → 更 ) CJK COMPATIBILITY IDEOGRAPH-F901 → CJK UNIFIED IDEOGRAPH-66F4	# 

			{ L"\x0002\xF8CC",L"\x66F8" }, //( 書 → 書 ) CJK COMPATIBILITY IDEOGRAPH-2F8CC → CJK UNIFIED IDEOGRAPH-66F8	# 

			{ L"\x2F49",L"\x6708" }, //( ⽉ → 月 ) KANGXI RADICAL MOON → CJK UNIFIED IDEOGRAPH-6708	# 

			{ L"\x0002\xF980",L"\x0002\x335F" }, //( 𣍟 → 𣍟 ) CJK COMPATIBILITY IDEOGRAPH-2F980 → CJK UNIFIED IDEOGRAPH-2335F	# 

			{ L"\x80A6",L"\x670C" }, //( 肦 → 朌 ) CJK UNIFIED IDEOGRAPH-80A6 → CJK UNIFIED IDEOGRAPH-670C	# 

			{ L"\x80D0",L"\x670F" }, //( 胐 → 朏 ) CJK UNIFIED IDEOGRAPH-80D0 → CJK UNIFIED IDEOGRAPH-670F	# 

			{ L"\x80CA",L"\x6710" }, //( 胊 → 朐 ) CJK UNIFIED IDEOGRAPH-80CA → CJK UNIFIED IDEOGRAPH-6710	# 

			{ L"\x8101",L"\x6713" }, //( 脁 → 朓 ) CJK UNIFIED IDEOGRAPH-8101 → CJK UNIFIED IDEOGRAPH-6713	# 

			{ L"\x80F6",L"\x3B35" }, //( 胶 → 㬵 ) CJK UNIFIED IDEOGRAPH-80F6 → CJK UNIFIED IDEOGRAPH-3B35	# 

			{ L"\xF929",L"\x6717" }, //( 朗 → 朗 ) CJK COMPATIBILITY IDEOGRAPH-F929 → CJK UNIFIED IDEOGRAPH-6717	# 
			{ L"\xFA92",L"\x6717" }, //( 朗 → 朗 ) CJK COMPATIBILITY IDEOGRAPH-FA92 → CJK UNIFIED IDEOGRAPH-6717	# 
			{ L"\x0002\xF8D8",L"\x6717" }, //( 朗 → 朗 ) CJK COMPATIBILITY IDEOGRAPH-2F8D8 → CJK UNIFIED IDEOGRAPH-6717	# 

			{ L"\x8127",L"\x6718" }, //( 脧 → 朘 ) CJK UNIFIED IDEOGRAPH-8127 → CJK UNIFIED IDEOGRAPH-6718	# 

			{ L"\xFA93",L"\x671B" }, //( 望 → 望 ) CJK COMPATIBILITY IDEOGRAPH-FA93 → CJK UNIFIED IDEOGRAPH-671B	# 
			{ L"\x0002\xF8D9",L"\x671B" }, //( 望 → 望 ) CJK COMPATIBILITY IDEOGRAPH-2F8D9 → CJK UNIFIED IDEOGRAPH-671B	# 

			{ L"\x0002\xF8DA",L"\x6721" }, //( 朡 → 朡 ) CJK COMPATIBILITY IDEOGRAPH-2F8DA → CJK UNIFIED IDEOGRAPH-6721	# 

			{ L"\x5E50",L"\x3B3A" }, //( 幐 → 㬺 ) CJK UNIFIED IDEOGRAPH-5E50 → CJK UNIFIED IDEOGRAPH-3B3A	# 

			{ L"\x4420",L"\x3B3B" }, //( 䐠 → 㬻 ) CJK UNIFIED IDEOGRAPH-4420 → CJK UNIFIED IDEOGRAPH-3B3B	# 

			{ L"\x0002\xF989",L"\x0002\x3393" }, //( 𣎓 → 𣎓 ) CJK COMPATIBILITY IDEOGRAPH-2F989 → CJK UNIFIED IDEOGRAPH-23393	# 

			{ L"\x81A7",L"\x6723" }, //( 膧 → 朣 ) CJK UNIFIED IDEOGRAPH-81A7 → CJK UNIFIED IDEOGRAPH-6723	# 

			{ L"\x0002\xF98A",L"\x0002\x339C" }, //( 𣎜 → 𣎜 ) CJK COMPATIBILITY IDEOGRAPH-2F98A → CJK UNIFIED IDEOGRAPH-2339C	# 

			{ L"\x2F4A",L"\x6728" }, //( ⽊ → 木 ) KANGXI RADICAL TREE → CJK UNIFIED IDEOGRAPH-6728	# 

			{ L"\xF9E1",L"\x674E" }, //( 李 → 李 ) CJK COMPATIBILITY IDEOGRAPH-F9E1 → CJK UNIFIED IDEOGRAPH-674E	# 

			{ L"\x0002\xF8DC",L"\x6753" }, //( 杓 → 杓 ) CJK COMPATIBILITY IDEOGRAPH-2F8DC → CJK UNIFIED IDEOGRAPH-6753	# 

			{ L"\xFA94",L"\x6756" }, //( 杖 → 杖 ) CJK COMPATIBILITY IDEOGRAPH-FA94 → CJK UNIFIED IDEOGRAPH-6756	# 

			{ L"\x0002\xF8DB",L"\x675E" }, //( 杞 → 杞 ) CJK COMPATIBILITY IDEOGRAPH-2F8DB → CJK UNIFIED IDEOGRAPH-675E	# 

			{ L"\x0002\xF8DD",L"\x0002\x33C3" }, //( 𣏃 → 𣏃 ) CJK COMPATIBILITY IDEOGRAPH-2F8DD → CJK UNIFIED IDEOGRAPH-233C3	# 

			{ L"\x67FF",L"\x676E" }, //( 柿 → 杮 ) CJK UNIFIED IDEOGRAPH-67FF → CJK UNIFIED IDEOGRAPH-676E	# 

			{ L"\xF9C8",L"\x677B" }, //( 杻 → 杻 ) CJK COMPATIBILITY IDEOGRAPH-F9C8 → CJK UNIFIED IDEOGRAPH-677B	# 

			{ L"\x0002\xF8E0",L"\x6785" }, //( 枅 → 枅 ) CJK COMPATIBILITY IDEOGRAPH-2F8E0 → CJK UNIFIED IDEOGRAPH-6785	# 

			{ L"\xF9F4",L"\x6797" }, //( 林 → 林 ) CJK COMPATIBILITY IDEOGRAPH-F9F4 → CJK UNIFIED IDEOGRAPH-6797	# 

			{ L"\x0002\xF8DE",L"\x3B49" }, //( 㭉 → 㭉 ) CJK COMPATIBILITY IDEOGRAPH-2F8DE → CJK UNIFIED IDEOGRAPH-3B49	# 

			{ L"\xFAD1",L"\x0002\x33D5" }, //( 𣏕 → 𣏕 ) CJK COMPATIBILITY IDEOGRAPH-FAD1 → CJK UNIFIED IDEOGRAPH-233D5	# 

			{ L"\xF9C9",L"\x67F3" }, //( 柳 → 柳 ) CJK COMPATIBILITY IDEOGRAPH-F9C9 → CJK UNIFIED IDEOGRAPH-67F3	# 

			{ L"\x0002\xF8DF",L"\x67FA" }, //( 柺 → 柺 ) CJK COMPATIBILITY IDEOGRAPH-2F8DF → CJK UNIFIED IDEOGRAPH-67FA	# 

			{ L"\xF9DA",L"\x6817" }, //( 栗 → 栗 ) CJK COMPATIBILITY IDEOGRAPH-F9DA → CJK UNIFIED IDEOGRAPH-6817	# 

			{ L"\x0002\xF8E5",L"\x681F" }, //( 栟 → 栟 ) CJK COMPATIBILITY IDEOGRAPH-2F8E5 → CJK UNIFIED IDEOGRAPH-681F	# 

			{ L"\x0002\xF8E1",L"\x6852" }, //( 桒 → 桒 ) CJK COMPATIBILITY IDEOGRAPH-2F8E1 → CJK UNIFIED IDEOGRAPH-6852	# 

			{ L"\x0002\xF8E3",L"\x0002\x346D" }, //( 𣑭 → 𣑭 ) CJK COMPATIBILITY IDEOGRAPH-2F8E3 → CJK UNIFIED IDEOGRAPH-2346D	# 

			{ L"\xF97A",L"\x6881" }, //( 梁 → 梁 ) CJK COMPATIBILITY IDEOGRAPH-F97A → CJK UNIFIED IDEOGRAPH-6881	# 

			{ L"\xFA44",L"\x6885" }, //( 梅 → 梅 ) CJK COMPATIBILITY IDEOGRAPH-FA44 → CJK UNIFIED IDEOGRAPH-6885	# 
			{ L"\x0002\xF8E2",L"\x6885" }, //( 梅 → 梅 ) CJK COMPATIBILITY IDEOGRAPH-2F8E2 → CJK UNIFIED IDEOGRAPH-6885	# 

			{ L"\x0002\xF8E4",L"\x688E" }, //( 梎 → 梎 ) CJK COMPATIBILITY IDEOGRAPH-2F8E4 → CJK UNIFIED IDEOGRAPH-688E	# 

			{ L"\xF9E2",L"\x68A8" }, //( 梨 → 梨 ) CJK COMPATIBILITY IDEOGRAPH-F9E2 → CJK UNIFIED IDEOGRAPH-68A8	# 

			{ L"\x0002\xF8E6",L"\x6914" }, //( 椔 → 椔 ) CJK COMPATIBILITY IDEOGRAPH-2F8E6 → CJK UNIFIED IDEOGRAPH-6914	# 

			{ L"\x0002\xF8E8",L"\x6942" }, //( 楂 → 楂 ) CJK COMPATIBILITY IDEOGRAPH-2F8E8 → CJK UNIFIED IDEOGRAPH-6942	# 

			{ L"\xFAD2",L"\x3B9D" }, //( 㮝 → 㮝 ) CJK COMPATIBILITY IDEOGRAPH-FAD2 → CJK UNIFIED IDEOGRAPH-3B9D	# 
			{ L"\x0002\xF8E7",L"\x3B9D" }, //( 㮝 → 㮝 ) CJK COMPATIBILITY IDEOGRAPH-2F8E7 → CJK UNIFIED IDEOGRAPH-3B9D	# 

			{ L"\x69E9",L"\x3BA3" }, //( 槩 → 㮣 ) CJK UNIFIED IDEOGRAPH-69E9 → CJK UNIFIED IDEOGRAPH-3BA3	# 

			{ L"\x6A27",L"\x699D" }, //( 樧 → 榝 ) CJK UNIFIED IDEOGRAPH-6A27 → CJK UNIFIED IDEOGRAPH-699D	# 

			{ L"\x0002\xF8E9",L"\x69A3" }, //( 榣 → 榣 ) CJK COMPATIBILITY IDEOGRAPH-2F8E9 → CJK UNIFIED IDEOGRAPH-69A3	# 

			{ L"\x0002\xF8EA",L"\x69EA" }, //( 槪 → 槪 ) CJK COMPATIBILITY IDEOGRAPH-2F8EA → CJK UNIFIED IDEOGRAPH-69EA	# 

			{ L"\xF914",L"\x6A02" }, //( 樂 → 樂 ) CJK COMPATIBILITY IDEOGRAPH-F914 → CJK UNIFIED IDEOGRAPH-6A02	# 
			{ L"\xF95C",L"\x6A02" }, //( 樂 → 樂 ) CJK COMPATIBILITY IDEOGRAPH-F95C → CJK UNIFIED IDEOGRAPH-6A02	# 
			{ L"\xF9BF",L"\x6A02" }, //( 樂 → 樂 ) CJK COMPATIBILITY IDEOGRAPH-F9BF → CJK UNIFIED IDEOGRAPH-6A02	# 

			{ L"\xF94C",L"\x6A13" }, //( 樓 → 樓 ) CJK COMPATIBILITY IDEOGRAPH-F94C → CJK UNIFIED IDEOGRAPH-6A13	# 

			{ L"\x0002\xF8EC",L"\x0002\x36A3" }, //( 𣚣 → 𣚣 ) CJK COMPATIBILITY IDEOGRAPH-2F8EC → CJK UNIFIED IDEOGRAPH-236A3	# 

			{ L"\x0002\xF8EB",L"\x6AA8" }, //( 檨 → 檨 ) CJK COMPATIBILITY IDEOGRAPH-2F8EB → CJK UNIFIED IDEOGRAPH-6AA8	# 

			{ L"\xF931",L"\x6AD3" }, //( 櫓 → 櫓 ) CJK COMPATIBILITY IDEOGRAPH-F931 → CJK UNIFIED IDEOGRAPH-6AD3	# 

			{ L"\x0002\xF8ED",L"\x6ADB" }, //( 櫛 → 櫛 ) CJK COMPATIBILITY IDEOGRAPH-2F8ED → CJK UNIFIED IDEOGRAPH-6ADB	# 

			{ L"\xF91D",L"\x6B04" }, //( 欄 → 欄 ) CJK COMPATIBILITY IDEOGRAPH-F91D → CJK UNIFIED IDEOGRAPH-6B04	# 

			{ L"\x0002\xF8EE",L"\x3C18" }, //( 㰘 → 㰘 ) CJK COMPATIBILITY IDEOGRAPH-2F8EE → CJK UNIFIED IDEOGRAPH-3C18	# 

			{ L"\x2F4B",L"\x6B20" }, //( ⽋ → 欠 ) KANGXI RADICAL LACK → CJK UNIFIED IDEOGRAPH-6B20	# 

			{ L"\x0002\xF8EF",L"\x6B21" }, //( 次 → 次 ) CJK COMPATIBILITY IDEOGRAPH-2F8EF → CJK UNIFIED IDEOGRAPH-6B21	# 

			{ L"\x0002\xF8F0",L"\x0002\x38A7" }, //( 𣢧 → 𣢧 ) CJK COMPATIBILITY IDEOGRAPH-2F8F0 → CJK UNIFIED IDEOGRAPH-238A7	# 

			{ L"\x0002\xF8F1",L"\x6B54" }, //( 歔 → 歔 ) CJK COMPATIBILITY IDEOGRAPH-2F8F1 → CJK UNIFIED IDEOGRAPH-6B54	# 

			{ L"\x0002\xF8F2",L"\x3C4E" }, //( 㱎 → 㱎 ) CJK COMPATIBILITY IDEOGRAPH-2F8F2 → CJK UNIFIED IDEOGRAPH-3C4E	# 

			{ L"\x2F4C",L"\x6B62" }, //( ⽌ → 止 ) KANGXI RADICAL STOP → CJK UNIFIED IDEOGRAPH-6B62	# 

			{ L"\x2EED",L"\x6B6F" }, //( ⻭ → 歯 ) CJK RADICAL J-SIMPLIFIED TOOTH → CJK UNIFIED IDEOGRAPH-6B6F	# 

			{ L"\x0002\xF8F3",L"\x6B72" }, //( 歲 → 歲 ) CJK COMPATIBILITY IDEOGRAPH-2F8F3 → CJK UNIFIED IDEOGRAPH-6B72	# 

			{ L"\xF98C",L"\x6B77" }, //( 歷 → 歷 ) CJK COMPATIBILITY IDEOGRAPH-F98C → CJK UNIFIED IDEOGRAPH-6B77	# 

			{ L"\xFA95",L"\x6B79" }, //( 歹 → 歹 ) CJK COMPATIBILITY IDEOGRAPH-FA95 → CJK UNIFIED IDEOGRAPH-6B79	# 
			{ L"\x2F4D",L"\x6B79" }, //( ⽍ → 歹 ) KANGXI RADICAL DEATH → CJK UNIFIED IDEOGRAPH-6B79	# 

			{ L"\x2E9E",L"\x6B7A" }, //( ⺞ → 歺 ) CJK RADICAL DEATH → CJK UNIFIED IDEOGRAPH-6B7A	# 

			{ L"\x0002\xF8F4",L"\x6B9F" }, //( 殟 → 殟 ) CJK COMPATIBILITY IDEOGRAPH-2F8F4 → CJK UNIFIED IDEOGRAPH-6B9F	# 

			{ L"\xF9A5",L"\x6BAE" }, //( 殮 → 殮 ) CJK COMPATIBILITY IDEOGRAPH-F9A5 → CJK UNIFIED IDEOGRAPH-6BAE	# 

			{ L"\x2F4E",L"\x6BB3" }, //( ⽎ → 殳 ) KANGXI RADICAL WEAPON → CJK UNIFIED IDEOGRAPH-6BB3	# 

			{ L"\xF970",L"\x6BBA" }, //( 殺 → 殺 ) CJK COMPATIBILITY IDEOGRAPH-F970 → CJK UNIFIED IDEOGRAPH-6BBA	# 
			{ L"\xFA96",L"\x6BBA" }, //( 殺 → 殺 ) CJK COMPATIBILITY IDEOGRAPH-FA96 → CJK UNIFIED IDEOGRAPH-6BBA	# 
			{ L"\x0002\xF8F5",L"\x6BBA" }, //( 殺 → 殺 ) CJK COMPATIBILITY IDEOGRAPH-2F8F5 → CJK UNIFIED IDEOGRAPH-6BBA	# 

			{ L"\x0002\xF8F6",L"\x6BBB" }, //( 殻 → 殻 ) CJK COMPATIBILITY IDEOGRAPH-2F8F6 → CJK UNIFIED IDEOGRAPH-6BBB	# 

			{ L"\x0002\xF8F7",L"\x0002\x3A8D" }, //( 𣪍 → 𣪍 ) CJK COMPATIBILITY IDEOGRAPH-2F8F7 → CJK UNIFIED IDEOGRAPH-23A8D	# 

			{ L"\x2F4F",L"\x6BCB" }, //( ⽏ → 毋 ) KANGXI RADICAL DO NOT → CJK UNIFIED IDEOGRAPH-6BCB	# 

			{ L"\x2E9F",L"\x6BCD" }, //( ⺟ → 母 ) CJK RADICAL MOTHER → CJK UNIFIED IDEOGRAPH-6BCD	# 

			{ L"\x0002\xF8F9",L"\x0002\x3AFA" }, //( 𣫺 → 𣫺 ) CJK COMPATIBILITY IDEOGRAPH-2F8F9 → CJK UNIFIED IDEOGRAPH-23AFA	# 

			{ L"\x2F50",L"\x6BD4" }, //( ⽐ → 比 ) KANGXI RADICAL COMPARE → CJK UNIFIED IDEOGRAPH-6BD4	# 

			{ L"\x2F51",L"\x6BDB" }, //( ⽑ → 毛 ) KANGXI RADICAL FUR → CJK UNIFIED IDEOGRAPH-6BDB	# 

			{ L"\x2F52",L"\x6C0F" }, //( ⽒ → 氏 ) KANGXI RADICAL CLAN → CJK UNIFIED IDEOGRAPH-6C0F	# 

			{ L"\x2EA0",L"\x6C11" }, //( ⺠ → 民 ) CJK RADICAL CIVILIAN → CJK UNIFIED IDEOGRAPH-6C11	# 

			{ L"\x2F53",L"\x6C14" }, //( ⽓ → 气 ) KANGXI RADICAL STEAM → CJK UNIFIED IDEOGRAPH-6C14	# 

			{ L"\x2F54",L"\x6C34" }, //( ⽔ → 水 ) KANGXI RADICAL WATER → CJK UNIFIED IDEOGRAPH-6C34	# 

			{ L"\x2EA1",L"\x6C35" }, //( ⺡ → 氵 ) CJK RADICAL WATER ONE → CJK UNIFIED IDEOGRAPH-6C35	# 

			{ L"\x2EA2",L"\x6C3A" }, //( ⺢ → 氺 ) CJK RADICAL WATER TWO → CJK UNIFIED IDEOGRAPH-6C3A	# 

			{ L"\x0002\xF8FA",L"\x6C4E" }, //( 汎 → 汎 ) CJK COMPATIBILITY IDEOGRAPH-2F8FA → CJK UNIFIED IDEOGRAPH-6C4E	# 

			{ L"\x0002\xF8FE",L"\x6C67" }, //( 汧 → 汧 ) CJK COMPATIBILITY IDEOGRAPH-2F8FE → CJK UNIFIED IDEOGRAPH-6C67	# 

			{ L"\xF972",L"\x6C88" }, //( 沈 → 沈 ) CJK COMPATIBILITY IDEOGRAPH-F972 → CJK UNIFIED IDEOGRAPH-6C88	# 

			{ L"\x0002\xF8FC",L"\x6CBF" }, //( 沿 → 沿 ) CJK COMPATIBILITY IDEOGRAPH-2F8FC → CJK UNIFIED IDEOGRAPH-6CBF	# 

			{ L"\xF968",L"\x6CCC" }, //( 泌 → 泌 ) CJK COMPATIBILITY IDEOGRAPH-F968 → CJK UNIFIED IDEOGRAPH-6CCC	# 

			{ L"\x0002\xF8FD",L"\x6CCD" }, //( 泍 → 泍 ) CJK COMPATIBILITY IDEOGRAPH-2F8FD → CJK UNIFIED IDEOGRAPH-6CCD	# 

			{ L"\xF9E3",L"\x6CE5" }, //( 泥 → 泥 ) CJK COMPATIBILITY IDEOGRAPH-F9E3 → CJK UNIFIED IDEOGRAPH-6CE5	# 

			{ L"\x0002\xF8FB",L"\x0002\x3CBC" }, //( 𣲼 → 𣲼 ) CJK COMPATIBILITY IDEOGRAPH-2F8FB → CJK UNIFIED IDEOGRAPH-23CBC	# 

			{ L"\xF915",L"\x6D1B" }, //( 洛 → 洛 ) CJK COMPATIBILITY IDEOGRAPH-F915 → CJK UNIFIED IDEOGRAPH-6D1B	# 

			{ L"\xFA05",L"\x6D1E" }, //( 洞 → 洞 ) CJK COMPATIBILITY IDEOGRAPH-FA05 → CJK UNIFIED IDEOGRAPH-6D1E	# 

			{ L"\x0002\xF907",L"\x6D34" }, //( 洴 → 洴 ) CJK COMPATIBILITY IDEOGRAPH-2F907 → CJK UNIFIED IDEOGRAPH-6D34	# 

			{ L"\x0002\xF900",L"\x6D3E" }, //( 派 → 派 ) CJK COMPATIBILITY IDEOGRAPH-2F900 → CJK UNIFIED IDEOGRAPH-6D3E	# 

			{ L"\xF9CA",L"\x6D41" }, //( 流 → 流 ) CJK COMPATIBILITY IDEOGRAPH-F9CA → CJK UNIFIED IDEOGRAPH-6D41	# 
			{ L"\xFA97",L"\x6D41" }, //( 流 → 流 ) CJK COMPATIBILITY IDEOGRAPH-FA97 → CJK UNIFIED IDEOGRAPH-6D41	# 
			{ L"\x0002\xF902",L"\x6D41" }, //( 流 → 流 ) CJK COMPATIBILITY IDEOGRAPH-2F902 → CJK UNIFIED IDEOGRAPH-6D41	# 

			{ L"\x0002\xF8FF",L"\x6D16" }, //( 洖 → 洖 ) CJK COMPATIBILITY IDEOGRAPH-2F8FF → CJK UNIFIED IDEOGRAPH-6D16	# 

			{ L"\x0002\xF903",L"\x6D69" }, //( 浩 → 浩 ) CJK COMPATIBILITY IDEOGRAPH-2F903 → CJK UNIFIED IDEOGRAPH-6D69	# 

			{ L"\xF92A",L"\x6D6A" }, //( 浪 → 浪 ) CJK COMPATIBILITY IDEOGRAPH-F92A → CJK UNIFIED IDEOGRAPH-6D6A	# 

			{ L"\xFA45",L"\x6D77" }, //( 海 → 海 ) CJK COMPATIBILITY IDEOGRAPH-FA45 → CJK UNIFIED IDEOGRAPH-6D77	# 
			{ L"\x0002\xF901",L"\x6D77" }, //( 海 → 海 ) CJK COMPATIBILITY IDEOGRAPH-2F901 → CJK UNIFIED IDEOGRAPH-6D77	# 

			{ L"\x0002\xF904",L"\x6D78" }, //( 浸 → 浸 ) CJK COMPATIBILITY IDEOGRAPH-2F904 → CJK UNIFIED IDEOGRAPH-6D78	# 

			{ L"\x0002\xF905",L"\x6D85" }, //( 涅 → 涅 ) CJK COMPATIBILITY IDEOGRAPH-2F905 → CJK UNIFIED IDEOGRAPH-6D85	# 

			{ L"\x0002\xF906",L"\x0002\x3D1E" }, //( 𣴞 → 𣴞 ) CJK COMPATIBILITY IDEOGRAPH-2F906 → CJK UNIFIED IDEOGRAPH-23D1E	# 

			{ L"\xF9F5",L"\x6DCB" }, //( 淋 → 淋 ) CJK COMPATIBILITY IDEOGRAPH-F9F5 → CJK UNIFIED IDEOGRAPH-6DCB	# 

			{ L"\xF94D",L"\x6DDA" }, //( 淚 → 淚 ) CJK COMPATIBILITY IDEOGRAPH-F94D → CJK UNIFIED IDEOGRAPH-6DDA	# 

			{ L"\xF9D6",L"\x6DEA" }, //( 淪 → 淪 ) CJK COMPATIBILITY IDEOGRAPH-F9D6 → CJK UNIFIED IDEOGRAPH-6DEA	# 

			{ L"\x0002\xF90E",L"\x6DF9" }, //( 淹 → 淹 ) CJK COMPATIBILITY IDEOGRAPH-2F90E → CJK UNIFIED IDEOGRAPH-6DF9	# 

			{ L"\xFA46",L"\x6E1A" }, //( 渚 → 渚 ) CJK COMPATIBILITY IDEOGRAPH-FA46 → CJK UNIFIED IDEOGRAPH-6E1A	# 

			{ L"\x0002\xF908",L"\x6E2F" }, //( 港 → 港 ) CJK COMPATIBILITY IDEOGRAPH-2F908 → CJK UNIFIED IDEOGRAPH-6E2F	# 

			{ L"\x0002\xF909",L"\x6E6E" }, //( 湮 → 湮 ) CJK COMPATIBILITY IDEOGRAPH-2F909 → CJK UNIFIED IDEOGRAPH-6E6E	# 

			{ L"\x6F59",L"\x6E88" }, //( 潙 → 溈 ) CJK UNIFIED IDEOGRAPH-6F59 → CJK UNIFIED IDEOGRAPH-6E88	# 

			{ L"\xFA99",L"\x6ECB" }, //( 滋 → 滋 ) CJK COMPATIBILITY IDEOGRAPH-FA99 → CJK UNIFIED IDEOGRAPH-6ECB	# 
			{ L"\x0002\xF90B",L"\x6ECB" }, //( 滋 → 滋 ) CJK COMPATIBILITY IDEOGRAPH-2F90B → CJK UNIFIED IDEOGRAPH-6ECB	# 

			{ L"\xF9CB",L"\x6E9C" }, //( 溜 → 溜 ) CJK COMPATIBILITY IDEOGRAPH-F9CB → CJK UNIFIED IDEOGRAPH-6E9C	# 

			{ L"\xF9EC",L"\x6EBA" }, //( 溺 → 溺 ) CJK COMPATIBILITY IDEOGRAPH-F9EC → CJK UNIFIED IDEOGRAPH-6EBA	# 

			{ L"\x0002\xF90C",L"\x6EC7" }, //( 滇 → 滇 ) CJK COMPATIBILITY IDEOGRAPH-2F90C → CJK UNIFIED IDEOGRAPH-6EC7	# 

			{ L"\xF904",L"\x6ED1" }, //( 滑 → 滑 ) CJK COMPATIBILITY IDEOGRAPH-F904 → CJK UNIFIED IDEOGRAPH-6ED1	# 

			{ L"\xFA98",L"\x6EDB" }, //( 滛 → 滛 ) CJK COMPATIBILITY IDEOGRAPH-FA98 → CJK UNIFIED IDEOGRAPH-6EDB	# 

			{ L"\x0002\xF90A",L"\x3D33" }, //( 㴳 → 㴳 ) CJK COMPATIBILITY IDEOGRAPH-2F90A → CJK UNIFIED IDEOGRAPH-3D33	# 

			{ L"\xF94E",L"\x6F0F" }, //( 漏 → 漏 ) CJK COMPATIBILITY IDEOGRAPH-F94E → CJK UNIFIED IDEOGRAPH-6F0F	# 

			{ L"\xFA47",L"\x6F22" }, //( 漢 → 漢 ) CJK COMPATIBILITY IDEOGRAPH-FA47 → CJK UNIFIED IDEOGRAPH-6F22	# 
			{ L"\xFA9A",L"\x6F22" }, //( 漢 → 漢 ) CJK COMPATIBILITY IDEOGRAPH-FA9A → CJK UNIFIED IDEOGRAPH-6F22	# 

			{ L"\xF992",L"\x6F23" }, //( 漣 → 漣 ) CJK COMPATIBILITY IDEOGRAPH-F992 → CJK UNIFIED IDEOGRAPH-6F23	# 

			{ L"\x0002\xF90D",L"\x0002\x3ED1" }, //( 𣻑 → 𣻑 ) CJK COMPATIBILITY IDEOGRAPH-2F90D → CJK UNIFIED IDEOGRAPH-23ED1	# 

			{ L"\x0002\xF90F",L"\x6F6E" }, //( 潮 → 潮 ) CJK COMPATIBILITY IDEOGRAPH-2F90F → CJK UNIFIED IDEOGRAPH-6F6E	# 

			{ L"\x0002\xF910",L"\x0002\x3F5E" }, //( 𣽞 → 𣽞 ) CJK COMPATIBILITY IDEOGRAPH-2F910 → CJK UNIFIED IDEOGRAPH-23F5E	# 

			{ L"\x0002\xF911",L"\x0002\x3F8E" }, //( 𣾎 → 𣾎 ) CJK COMPATIBILITY IDEOGRAPH-2F911 → CJK UNIFIED IDEOGRAPH-23F8E	# 

			{ L"\x0002\xF912",L"\x6FC6" }, //( 濆 → 濆 ) CJK COMPATIBILITY IDEOGRAPH-2F912 → CJK UNIFIED IDEOGRAPH-6FC6	# 

			{ L"\xF922",L"\x6FEB" }, //( 濫 → 濫 ) CJK COMPATIBILITY IDEOGRAPH-F922 → CJK UNIFIED IDEOGRAPH-6FEB	# 

			{ L"\xF984",L"\x6FFE" }, //( 濾 → 濾 ) CJK COMPATIBILITY IDEOGRAPH-F984 → CJK UNIFIED IDEOGRAPH-6FFE	# 

			{ L"\x0002\xF915",L"\x701B" }, //( 瀛 → 瀛 ) CJK COMPATIBILITY IDEOGRAPH-2F915 → CJK UNIFIED IDEOGRAPH-701B	# 

			{ L"\xFA9B",L"\x701E" }, //( 瀞 → 瀞 ) CJK COMPATIBILITY IDEOGRAPH-FA9B → CJK UNIFIED IDEOGRAPH-701E	# 
			{ L"\x0002\xF914",L"\x701E" }, //( 瀞 → 瀞 ) CJK COMPATIBILITY IDEOGRAPH-2F914 → CJK UNIFIED IDEOGRAPH-701E	# 

			{ L"\x0002\xF913",L"\x7039" }, //( 瀹 → 瀹 ) CJK COMPATIBILITY IDEOGRAPH-2F913 → CJK UNIFIED IDEOGRAPH-7039	# 

			{ L"\x0002\xF917",L"\x704A" }, //( 灊 → 灊 ) CJK COMPATIBILITY IDEOGRAPH-2F917 → CJK UNIFIED IDEOGRAPH-704A	# 

			{ L"\x0002\xF916",L"\x3D96" }, //( 㶖 → 㶖 ) CJK COMPATIBILITY IDEOGRAPH-2F916 → CJK UNIFIED IDEOGRAPH-3D96	# 

			{ L"\x2F55",L"\x706B" }, //( ⽕ → 火 ) KANGXI RADICAL FIRE → CJK UNIFIED IDEOGRAPH-706B	# 

			{ L"\x2EA3",L"\x706C" }, //( ⺣ → 灬 ) CJK RADICAL FIRE → CJK UNIFIED IDEOGRAPH-706C	# 

			{ L"\x0002\xF835",L"\x7070" }, //( 灰 → 灰 ) CJK COMPATIBILITY IDEOGRAPH-2F835 → CJK UNIFIED IDEOGRAPH-7070	# 

			{ L"\x0002\xF919",L"\x7077" }, //( 灷 → 灷 ) CJK COMPATIBILITY IDEOGRAPH-2F919 → CJK UNIFIED IDEOGRAPH-7077	# 

			{ L"\x0002\xF918",L"\x707D" }, //( 災 → 災 ) CJK COMPATIBILITY IDEOGRAPH-2F918 → CJK UNIFIED IDEOGRAPH-707D	# 

			{ L"\xF9FB",L"\x7099" }, //( 炙 → 炙 ) CJK COMPATIBILITY IDEOGRAPH-F9FB → CJK UNIFIED IDEOGRAPH-7099	# 

			{ L"\x0002\xF91A",L"\x70AD" }, //( 炭 → 炭 ) CJK COMPATIBILITY IDEOGRAPH-2F91A → CJK UNIFIED IDEOGRAPH-70AD	# 

			{ L"\xF99F",L"\x70C8" }, //( 烈 → 烈 ) CJK COMPATIBILITY IDEOGRAPH-F99F → CJK UNIFIED IDEOGRAPH-70C8	# 

			{ L"\xF916",L"\x70D9" }, //( 烙 → 烙 ) CJK COMPATIBILITY IDEOGRAPH-F916 → CJK UNIFIED IDEOGRAPH-70D9	# 

			{ L"\xFA48",L"\x716E" }, //( 煮 → 煮 ) CJK COMPATIBILITY IDEOGRAPH-FA48 → CJK UNIFIED IDEOGRAPH-716E	# 
			{ L"\xFA9C",L"\x716E" }, //( 煮 → 煮 ) CJK COMPATIBILITY IDEOGRAPH-FA9C → CJK UNIFIED IDEOGRAPH-716E	# 

			{ L"\x0002\xF91D",L"\x0002\x4263" }, //( 𤉣 → 𤉣 ) CJK COMPATIBILITY IDEOGRAPH-2F91D → CJK UNIFIED IDEOGRAPH-24263	# 

			{ L"\x0002\xF91C",L"\x7145" }, //( 煅 → 煅 ) CJK COMPATIBILITY IDEOGRAPH-2F91C → CJK UNIFIED IDEOGRAPH-7145	# 

			{ L"\xF993",L"\x7149" }, //( 煉 → 煉 ) CJK COMPATIBILITY IDEOGRAPH-F993 → CJK UNIFIED IDEOGRAPH-7149	# 

			{ L"\xFA6C",L"\x0002\x42EE" }, //( 𤋮 → 𤋮 ) CJK COMPATIBILITY IDEOGRAPH-FA6C → CJK UNIFIED IDEOGRAPH-242EE	# 

			{ L"\x0002\xF91E",L"\x719C" }, //( 熜 → 熜 ) CJK COMPATIBILITY IDEOGRAPH-2F91E → CJK UNIFIED IDEOGRAPH-719C	# 

			{ L"\xF9C0",L"\x71CE" }, //( 燎 → 燎 ) CJK COMPATIBILITY IDEOGRAPH-F9C0 → CJK UNIFIED IDEOGRAPH-71CE	# 

			{ L"\xF9EE",L"\x71D0" }, //( 燐 → 燐 ) CJK COMPATIBILITY IDEOGRAPH-F9EE → CJK UNIFIED IDEOGRAPH-71D0	# 

			{ L"\x0002\xF91F",L"\x0002\x43AB" }, //( 𤎫 → 𤎫 ) CJK COMPATIBILITY IDEOGRAPH-2F91F → CJK UNIFIED IDEOGRAPH-243AB	# 

			{ L"\xF932",L"\x7210" }, //( 爐 → 爐 ) CJK COMPATIBILITY IDEOGRAPH-F932 → CJK UNIFIED IDEOGRAPH-7210	# 

			{ L"\xF91E",L"\x721B" }, //( 爛 → 爛 ) CJK COMPATIBILITY IDEOGRAPH-F91E → CJK UNIFIED IDEOGRAPH-721B	# 

			{ L"\x0002\xF920",L"\x7228" }, //( 爨 → 爨 ) CJK COMPATIBILITY IDEOGRAPH-2F920 → CJK UNIFIED IDEOGRAPH-7228	# 

			{ L"\x2F56",L"\x722A" }, //( ⽖ → 爪 ) KANGXI RADICAL CLAW → CJK UNIFIED IDEOGRAPH-722A	# 

			{ L"\xFA49",L"\x722B" }, //( 爫 → 爫 ) CJK COMPATIBILITY IDEOGRAPH-FA49 → CJK UNIFIED IDEOGRAPH-722B	# 
			{ L"\x2EA4",L"\x722B" }, //( ⺤ → 爫 ) CJK RADICAL PAW ONE → CJK UNIFIED IDEOGRAPH-722B	# 

			{ L"\xFA9E",L"\x7235" }, //( 爵 → 爵 ) CJK COMPATIBILITY IDEOGRAPH-FA9E → CJK UNIFIED IDEOGRAPH-7235	# 
			{ L"\x0002\xF921",L"\x7235" }, //( 爵 → 爵 ) CJK COMPATIBILITY IDEOGRAPH-2F921 → CJK UNIFIED IDEOGRAPH-7235	# 

			{ L"\x2F57",L"\x7236" }, //( ⽗ → 父 ) KANGXI RADICAL FATHER → CJK UNIFIED IDEOGRAPH-7236	# 

			{ L"\x2F58",L"\x723B" }, //( ⽘ → 爻 ) KANGXI RADICAL DOUBLE X → CJK UNIFIED IDEOGRAPH-723B	# 

			{ L"\x2EA6",L"\x4E2C" }, //( ⺦ → 丬 ) CJK RADICAL SIMPLIFIED HALF TREE TRUNK → CJK UNIFIED IDEOGRAPH-4E2C	# 

			{ L"\x2F59",L"\x723F" }, //( ⽙ → 爿 ) KANGXI RADICAL HALF TREE TRUNK → CJK UNIFIED IDEOGRAPH-723F	# 

			{ L"\x2F5A",L"\x7247" }, //( ⽚ → 片 ) KANGXI RADICAL SLICE → CJK UNIFIED IDEOGRAPH-7247	# 

			{ L"\x0002\xF922",L"\x7250" }, //( 牐 → 牐 ) CJK COMPATIBILITY IDEOGRAPH-2F922 → CJK UNIFIED IDEOGRAPH-7250	# 

			{ L"\x2F5B",L"\x7259" }, //( ⽛ → 牙 ) KANGXI RADICAL FANG → CJK UNIFIED IDEOGRAPH-7259	# 

			{ L"\x0002\xF923",L"\x0002\x4608" }, //( 𤘈 → 𤘈 ) CJK COMPATIBILITY IDEOGRAPH-2F923 → CJK UNIFIED IDEOGRAPH-24608	# 

			{ L"\x2F5C",L"\x725B" }, //( ⽜ → 牛 ) KANGXI RADICAL COW → CJK UNIFIED IDEOGRAPH-725B	# 

			{ L"\xF946",L"\x7262" }, //( 牢 → 牢 ) CJK COMPATIBILITY IDEOGRAPH-F946 → CJK UNIFIED IDEOGRAPH-7262	# 

			{ L"\x0002\xF924",L"\x7280" }, //( 犀 → 犀 ) CJK COMPATIBILITY IDEOGRAPH-2F924 → CJK UNIFIED IDEOGRAPH-7280	# 

			{ L"\x0002\xF925",L"\x7295" }, //( 犕 → 犕 ) CJK COMPATIBILITY IDEOGRAPH-2F925 → CJK UNIFIED IDEOGRAPH-7295	# 

			{ L"\x2F5D",L"\x72AC" }, //( ⽝ → 犬 ) KANGXI RADICAL DOG → CJK UNIFIED IDEOGRAPH-72AC	# 

			{ L"\x2EA8",L"\x72AD" }, //( ⺨ → 犭 ) CJK RADICAL DOG → CJK UNIFIED IDEOGRAPH-72AD	# 

			{ L"\xFA9F",L"\x72AF" }, //( 犯 → 犯 ) CJK COMPATIBILITY IDEOGRAPH-FA9F → CJK UNIFIED IDEOGRAPH-72AF	# 

			{ L"\xF9FA",L"\x72C0" }, //( 狀 → 狀 ) CJK COMPATIBILITY IDEOGRAPH-F9FA → CJK UNIFIED IDEOGRAPH-72C0	# 

			{ L"\x0002\xF926",L"\x0002\x4735" }, //( 𤜵 → 𤜵 ) CJK COMPATIBILITY IDEOGRAPH-2F926 → CJK UNIFIED IDEOGRAPH-24735	# 

			{ L"\xF92B",L"\x72FC" }, //( 狼 → 狼 ) CJK COMPATIBILITY IDEOGRAPH-F92B → CJK UNIFIED IDEOGRAPH-72FC	# 

			{ L"\xFA16",L"\x732A" }, //( 猪 → 猪 ) CJK COMPATIBILITY IDEOGRAPH-FA16 → CJK UNIFIED IDEOGRAPH-732A	# 
			{ L"\xFAA0",L"\x732A" }, //( 猪 → 猪 ) CJK COMPATIBILITY IDEOGRAPH-FAA0 → CJK UNIFIED IDEOGRAPH-732A	# 

			{ L"\x0002\xF927",L"\x0002\x4814" }, //( 𤠔 → 𤠔 ) CJK COMPATIBILITY IDEOGRAPH-2F927 → CJK UNIFIED IDEOGRAPH-24814	# 

			{ L"\xF9A7",L"\x7375" }, //( 獵 → 獵 ) CJK COMPATIBILITY IDEOGRAPH-F9A7 → CJK UNIFIED IDEOGRAPH-7375	# 

			{ L"\x0002\xF928",L"\x737A" }, //( 獺 → 獺 ) CJK COMPATIBILITY IDEOGRAPH-2F928 → CJK UNIFIED IDEOGRAPH-737A	# 

			{ L"\x2F5E",L"\x7384" }, //( ⽞ → 玄 ) KANGXI RADICAL PROFOUND → CJK UNIFIED IDEOGRAPH-7384	# 

			{ L"\xF961",L"\x7387" }, //( 率 → 率 ) CJK COMPATIBILITY IDEOGRAPH-F961 → CJK UNIFIED IDEOGRAPH-7387	# 
			{ L"\xF9DB",L"\x7387" }, //( 率 → 率 ) CJK COMPATIBILITY IDEOGRAPH-F9DB → CJK UNIFIED IDEOGRAPH-7387	# 

			{ L"\x2F5F",L"\x7389" }, //( ⽟ → 玉 ) KANGXI RADICAL JADE → CJK UNIFIED IDEOGRAPH-7389	# 

			{ L"\x0002\xF929",L"\x738B" }, //( 王 → 王 ) CJK COMPATIBILITY IDEOGRAPH-2F929 → CJK UNIFIED IDEOGRAPH-738B	# 

			{ L"\x0002\xF92A",L"\x3EAC" }, //( 㺬 → 㺬 ) CJK COMPATIBILITY IDEOGRAPH-2F92A → CJK UNIFIED IDEOGRAPH-3EAC	# 

			{ L"\x0002\xF92B",L"\x73A5" }, //( 玥 → 玥 ) CJK COMPATIBILITY IDEOGRAPH-2F92B → CJK UNIFIED IDEOGRAPH-73A5	# 

			{ L"\xF9AD",L"\x73B2" }, //( 玲 → 玲 ) CJK COMPATIBILITY IDEOGRAPH-F9AD → CJK UNIFIED IDEOGRAPH-73B2	# 

			{ L"\x0002\xF92C",L"\x3EB8" }, //( 㺸 → 㺸 ) CJK COMPATIBILITY IDEOGRAPH-2F92C → CJK UNIFIED IDEOGRAPH-3EB8	# 
			{ L"\x0002\xF92D",L"\x3EB8" }, //( 㺸 → 㺸 ) CJK COMPATIBILITY IDEOGRAPH-2F92D → CJK UNIFIED IDEOGRAPH-3EB8	# 

			{ L"\xF917",L"\x73DE" }, //( 珞 → 珞 ) CJK COMPATIBILITY IDEOGRAPH-F917 → CJK UNIFIED IDEOGRAPH-73DE	# 

			{ L"\xF9CC",L"\x7409" }, //( 琉 → 琉 ) CJK COMPATIBILITY IDEOGRAPH-F9CC → CJK UNIFIED IDEOGRAPH-7409	# 

			{ L"\xF9E4",L"\x7406" }, //( 理 → 理 ) CJK COMPATIBILITY IDEOGRAPH-F9E4 → CJK UNIFIED IDEOGRAPH-7406	# 

			{ L"\xFA4A",L"\x7422" }, //( 琢 → 琢 ) CJK COMPATIBILITY IDEOGRAPH-FA4A → CJK UNIFIED IDEOGRAPH-7422	# 

			{ L"\x0002\xF92E",L"\x7447" }, //( 瑇 → 瑇 ) CJK COMPATIBILITY IDEOGRAPH-2F92E → CJK UNIFIED IDEOGRAPH-7447	# 

			{ L"\x0002\xF92F",L"\x745C" }, //( 瑜 → 瑜 ) CJK COMPATIBILITY IDEOGRAPH-2F92F → CJK UNIFIED IDEOGRAPH-745C	# 

			{ L"\xF9AE",L"\x7469" }, //( 瑩 → 瑩 ) CJK COMPATIBILITY IDEOGRAPH-F9AE → CJK UNIFIED IDEOGRAPH-7469	# 

			{ L"\xFAA1",L"\x7471" }, //( 瑱 → 瑱 ) CJK COMPATIBILITY IDEOGRAPH-FAA1 → CJK UNIFIED IDEOGRAPH-7471	# 
			{ L"\x0002\xF930",L"\x7471" }, //( 瑱 → 瑱 ) CJK COMPATIBILITY IDEOGRAPH-2F930 → CJK UNIFIED IDEOGRAPH-7471	# 

			{ L"\x0002\xF931",L"\x7485" }, //( 璅 → 璅 ) CJK COMPATIBILITY IDEOGRAPH-2F931 → CJK UNIFIED IDEOGRAPH-7485	# 

			{ L"\xF994",L"\x7489" }, //( 璉 → 璉 ) CJK COMPATIBILITY IDEOGRAPH-F994 → CJK UNIFIED IDEOGRAPH-7489	# 

			{ L"\xF9EF",L"\x7498" }, //( 璘 → 璘 ) CJK COMPATIBILITY IDEOGRAPH-F9EF → CJK UNIFIED IDEOGRAPH-7498	# 

			{ L"\x0002\xF932",L"\x74CA" }, //( 瓊 → 瓊 ) CJK COMPATIBILITY IDEOGRAPH-2F932 → CJK UNIFIED IDEOGRAPH-74CA	# 

			{ L"\x2F60",L"\x74DC" }, //( ⽠ → 瓜 ) KANGXI RADICAL MELON → CJK UNIFIED IDEOGRAPH-74DC	# 

			{ L"\x2F61",L"\x74E6" }, //( ⽡ → 瓦 ) KANGXI RADICAL TILE → CJK UNIFIED IDEOGRAPH-74E6	# 

			{ L"\x0002\xF933",L"\x3F1B" }, //( 㼛 → 㼛 ) CJK COMPATIBILITY IDEOGRAPH-2F933 → CJK UNIFIED IDEOGRAPH-3F1B	# 

			{ L"\xFAA2",L"\x7506" }, //( 甆 → 甆 ) CJK COMPATIBILITY IDEOGRAPH-FAA2 → CJK UNIFIED IDEOGRAPH-7506	# 

			{ L"\x2F62",L"\x7518" }, //( ⽢ → 甘 ) KANGXI RADICAL SWEET → CJK UNIFIED IDEOGRAPH-7518	# 

			{ L"\x2F63",L"\x751F" }, //( ⽣ → 生 ) KANGXI RADICAL LIFE → CJK UNIFIED IDEOGRAPH-751F	# 

			{ L"\x0002\xF934",L"\x7524" }, //( 甤 → 甤 ) CJK COMPATIBILITY IDEOGRAPH-2F934 → CJK UNIFIED IDEOGRAPH-7524	# 

			{ L"\x2F64",L"\x7528" }, //( ⽤ → 用 ) KANGXI RADICAL USE → CJK UNIFIED IDEOGRAPH-7528	# 

			{ L"\x2F65",L"\x7530" }, //( ⽥ → 田 ) KANGXI RADICAL FIELD → CJK UNIFIED IDEOGRAPH-7530	# 

			{ L"\xFAA3",L"\x753B" }, //( 画 → 画 ) CJK COMPATIBILITY IDEOGRAPH-FAA3 → CJK UNIFIED IDEOGRAPH-753B	# 

			{ L"\x0002\xF936",L"\x753E" }, //( 甾 → 甾 ) CJK COMPATIBILITY IDEOGRAPH-2F936 → CJK UNIFIED IDEOGRAPH-753E	# 

			{ L"\x0002\xF935",L"\x0002\x4C36" }, //( 𤰶 → 𤰶 ) CJK COMPATIBILITY IDEOGRAPH-2F935 → CJK UNIFIED IDEOGRAPH-24C36	# 

			{ L"\xF9CD",L"\x7559" }, //( 留 → 留 ) CJK COMPATIBILITY IDEOGRAPH-F9CD → CJK UNIFIED IDEOGRAPH-7559	# 

			{ L"\xF976",L"\x7565" }, //( 略 → 略 ) CJK COMPATIBILITY IDEOGRAPH-F976 → CJK UNIFIED IDEOGRAPH-7565	# 

			{ L"\xF962",L"\x7570" }, //( 異 → 異 ) CJK COMPATIBILITY IDEOGRAPH-F962 → CJK UNIFIED IDEOGRAPH-7570	# 
			{ L"\x0002\xF938",L"\x7570" }, //( 異 → 異 ) CJK COMPATIBILITY IDEOGRAPH-2F938 → CJK UNIFIED IDEOGRAPH-7570	# 

			{ L"\x0002\xF937",L"\x0002\x4C92" }, //( 𤲒 → 𤲒 ) CJK COMPATIBILITY IDEOGRAPH-2F937 → CJK UNIFIED IDEOGRAPH-24C92	# 

			{ L"\x2F66",L"\x758B" }, //( ⽦ → 疋 ) KANGXI RADICAL BOLT OF CLOTH → CJK UNIFIED IDEOGRAPH-758B	# 

			{ L"\x2F67",L"\x7592" }, //( ⽧ → 疒 ) KANGXI RADICAL SICKNESS → CJK UNIFIED IDEOGRAPH-7592	# 

			{ L"\xF9E5",L"\x75E2" }, //( 痢 → 痢 ) CJK COMPATIBILITY IDEOGRAPH-F9E5 → CJK UNIFIED IDEOGRAPH-75E2	# 

			{ L"\x0002\xF93A",L"\x7610" }, //( 瘐 → 瘐 ) CJK COMPATIBILITY IDEOGRAPH-2F93A → CJK UNIFIED IDEOGRAPH-7610	# 

			{ L"\xFAA5",L"\x761F" }, //( 瘟 → 瘟 ) CJK COMPATIBILITY IDEOGRAPH-FAA5 → CJK UNIFIED IDEOGRAPH-761F	# 

			{ L"\xFAA4",L"\x761D" }, //( 瘝 → 瘝 ) CJK COMPATIBILITY IDEOGRAPH-FAA4 → CJK UNIFIED IDEOGRAPH-761D	# 

			{ L"\xF9C1",L"\x7642" }, //( 療 → 療 ) CJK COMPATIBILITY IDEOGRAPH-F9C1 → CJK UNIFIED IDEOGRAPH-7642	# 

			{ L"\xF90E",L"\x7669" }, //( 癩 → 癩 ) CJK COMPATIBILITY IDEOGRAPH-F90E → CJK UNIFIED IDEOGRAPH-7669	# 

			{ L"\x2F68",L"\x7676" }, //( ⽨ → 癶 ) KANGXI RADICAL DOTTED TENT → CJK UNIFIED IDEOGRAPH-7676	# 

			{ L"\x2F69",L"\x767D" }, //( ⽩ → 白 ) KANGXI RADICAL WHITE → CJK UNIFIED IDEOGRAPH-767D	# 

			{ L"\x0002\xF93B",L"\x0002\x4FA1" }, //( 𤾡 → 𤾡 ) CJK COMPATIBILITY IDEOGRAPH-2F93B → CJK UNIFIED IDEOGRAPH-24FA1	# 

			{ L"\x0002\xF93C",L"\x0002\x4FB8" }, //( 𤾸 → 𤾸 ) CJK COMPATIBILITY IDEOGRAPH-2F93C → CJK UNIFIED IDEOGRAPH-24FB8	# 

			{ L"\x2F6A",L"\x76AE" }, //( ⽪ → 皮 ) KANGXI RADICAL SKIN → CJK UNIFIED IDEOGRAPH-76AE	# 

			{ L"\x2F6B",L"\x76BF" }, //( ⽫ → 皿 ) KANGXI RADICAL DISH → CJK UNIFIED IDEOGRAPH-76BF	# 

			{ L"\x0002\xF93D",L"\x0002\x5044" }, //( 𥁄 → 𥁄 ) CJK COMPATIBILITY IDEOGRAPH-2F93D → CJK UNIFIED IDEOGRAPH-25044	# 

			{ L"\x0002\xF93E",L"\x3FFC" }, //( 㿼 → 㿼 ) CJK COMPATIBILITY IDEOGRAPH-2F93E → CJK UNIFIED IDEOGRAPH-3FFC	# 

			{ L"\xFA17",L"\x76CA" }, //( 益 → 益 ) CJK COMPATIBILITY IDEOGRAPH-FA17 → CJK UNIFIED IDEOGRAPH-76CA	# 
			{ L"\xFAA6",L"\x76CA" }, //( 益 → 益 ) CJK COMPATIBILITY IDEOGRAPH-FAA6 → CJK UNIFIED IDEOGRAPH-76CA	# 

			{ L"\xFAA7",L"\x76DB" }, //( 盛 → 盛 ) CJK COMPATIBILITY IDEOGRAPH-FAA7 → CJK UNIFIED IDEOGRAPH-76DB	# 

			{ L"\xF933",L"\x76E7" }, //( 盧 → 盧 ) CJK COMPATIBILITY IDEOGRAPH-F933 → CJK UNIFIED IDEOGRAPH-76E7	# 

			{ L"\x0002\xF93F",L"\x4008" }, //( 䀈 → 䀈 ) CJK COMPATIBILITY IDEOGRAPH-2F93F → CJK UNIFIED IDEOGRAPH-4008	# 

			{ L"\x2F6C",L"\x76EE" }, //( ⽬ → 目 ) KANGXI RADICAL EYE → CJK UNIFIED IDEOGRAPH-76EE	# 

			{ L"\xFAA8",L"\x76F4" }, //( 直 → 直 ) CJK COMPATIBILITY IDEOGRAPH-FAA8 → CJK UNIFIED IDEOGRAPH-76F4	# 
			{ L"\x0002\xF940",L"\x76F4" }, //( 直 → 直 ) CJK COMPATIBILITY IDEOGRAPH-2F940 → CJK UNIFIED IDEOGRAPH-76F4	# 

			{ L"\x0002\xF942",L"\x0002\x50F2" }, //( 𥃲 → 𥃲 ) CJK COMPATIBILITY IDEOGRAPH-2F942 → CJK UNIFIED IDEOGRAPH-250F2	# 

			{ L"\x0002\xF941",L"\x0002\x50F3" }, //( 𥃳 → 𥃳 ) CJK COMPATIBILITY IDEOGRAPH-2F941 → CJK UNIFIED IDEOGRAPH-250F3	# 

			{ L"\xF96D",L"\x7701" }, //( 省 → 省 ) CJK COMPATIBILITY IDEOGRAPH-F96D → CJK UNIFIED IDEOGRAPH-7701	# 

			{ L"\xFAD3",L"\x4018" }, //( 䀘 → 䀘 ) CJK COMPATIBILITY IDEOGRAPH-FAD3 → CJK UNIFIED IDEOGRAPH-4018	# 

			{ L"\x0002\xF943",L"\x0002\x5119" }, //( 𥄙 → 𥄙 ) CJK COMPATIBILITY IDEOGRAPH-2F943 → CJK UNIFIED IDEOGRAPH-25119	# 

			{ L"\x0002\xF945",L"\x771E" }, //( 眞 → 眞 ) CJK COMPATIBILITY IDEOGRAPH-2F945 → CJK UNIFIED IDEOGRAPH-771E	# 

			{ L"\x0002\xF946",L"\x771F" }, //( 真 → 真 ) CJK COMPATIBILITY IDEOGRAPH-2F946 → CJK UNIFIED IDEOGRAPH-771F	# 
			{ L"\x0002\xF947",L"\x771F" }, //( 真 → 真 ) CJK COMPATIBILITY IDEOGRAPH-2F947 → CJK UNIFIED IDEOGRAPH-771F	# 

			{ L"\x0002\xF944",L"\x0002\x5133" }, //( 𥄳 → 𥄳 ) CJK COMPATIBILITY IDEOGRAPH-2F944 → CJK UNIFIED IDEOGRAPH-25133	# 

			{ L"\xFAAA",L"\x7740" }, //( 着 → 着 ) CJK COMPATIBILITY IDEOGRAPH-FAAA → CJK UNIFIED IDEOGRAPH-7740	# 

			{ L"\xFAA9",L"\x774A" }, //( 睊 → 睊 ) CJK COMPATIBILITY IDEOGRAPH-FAA9 → CJK UNIFIED IDEOGRAPH-774A	# 
			{ L"\x0002\xF948",L"\x774A" }, //( 睊 → 睊 ) CJK COMPATIBILITY IDEOGRAPH-2F948 → CJK UNIFIED IDEOGRAPH-774A	# 

			{ L"\x9FC3",L"\x4039" }, //( 鿃 → 䀹 ) CJK UNIFIED IDEOGRAPH-9FC3 → CJK UNIFIED IDEOGRAPH-4039	# →䀹→
			{ L"\xFAD4",L"\x4039" }, //( 䀹 → 䀹 ) CJK COMPATIBILITY IDEOGRAPH-FAD4 → CJK UNIFIED IDEOGRAPH-4039	# 
			{ L"\x0002\xF949",L"\x4039" }, //( 䀹 → 䀹 ) CJK COMPATIBILITY IDEOGRAPH-2F949 → CJK UNIFIED IDEOGRAPH-4039	# 

			{ L"\x6663",L"\x403F" }, //( 晣 → 䀿 ) CJK UNIFIED IDEOGRAPH-6663 → CJK UNIFIED IDEOGRAPH-403F	# 

			{ L"\x0002\xF94B",L"\x4046" }, //( 䁆 → 䁆 ) CJK COMPATIBILITY IDEOGRAPH-2F94B → CJK UNIFIED IDEOGRAPH-4046	# 

			{ L"\x0002\xF94A",L"\x778B" }, //( 瞋 → 瞋 ) CJK COMPATIBILITY IDEOGRAPH-2F94A → CJK UNIFIED IDEOGRAPH-778B	# 

			{ L"\xFAD5",L"\x0002\x5249" }, //( 𥉉 → 𥉉 ) CJK COMPATIBILITY IDEOGRAPH-FAD5 → CJK UNIFIED IDEOGRAPH-25249	# 

			{ L"\xFA9D",L"\x77A7" }, //( 瞧 → 瞧 ) CJK COMPATIBILITY IDEOGRAPH-FA9D → CJK UNIFIED IDEOGRAPH-77A7	# 

			{ L"\x2F6D",L"\x77DB" }, //( ⽭ → 矛 ) KANGXI RADICAL SPEAR → CJK UNIFIED IDEOGRAPH-77DB	# 

			{ L"\x2F6E",L"\x77E2" }, //( ⽮ → 矢 ) KANGXI RADICAL ARROW → CJK UNIFIED IDEOGRAPH-77E2	# 

			{ L"\x2F6F",L"\x77F3" }, //( ⽯ → 石 ) KANGXI RADICAL STONE → CJK UNIFIED IDEOGRAPH-77F3	# 

			{ L"\x0002\xF94C",L"\x4096" }, //( 䂖 → 䂖 ) CJK COMPATIBILITY IDEOGRAPH-2F94C → CJK UNIFIED IDEOGRAPH-4096	# 

			{ L"\x0002\xF94D",L"\x0002\x541D" }, //( 𥐝 → 𥐝 ) CJK COMPATIBILITY IDEOGRAPH-2F94D → CJK UNIFIED IDEOGRAPH-2541D	# 

			{ L"\x784F",L"\x7814" }, //( 硏 → 研 ) CJK UNIFIED IDEOGRAPH-784F → CJK UNIFIED IDEOGRAPH-7814	# 

			{ L"\x0002\xF94E",L"\x784E" }, //( 硎 → 硎 ) CJK COMPATIBILITY IDEOGRAPH-2F94E → CJK UNIFIED IDEOGRAPH-784E	# 

			{ L"\xF9CE",L"\x786B" }, //( 硫 → 硫 ) CJK COMPATIBILITY IDEOGRAPH-F9CE → CJK UNIFIED IDEOGRAPH-786B	# 

			{ L"\xF93B",L"\x788C" }, //( 碌 → 碌 ) CJK COMPATIBILITY IDEOGRAPH-F93B → CJK UNIFIED IDEOGRAPH-788C	# 
			{ L"\x0002\xF94F",L"\x788C" }, //( 碌 → 碌 ) CJK COMPATIBILITY IDEOGRAPH-2F94F → CJK UNIFIED IDEOGRAPH-788C	# 

			{ L"\xFA4B",L"\x7891" }, //( 碑 → 碑 ) CJK COMPATIBILITY IDEOGRAPH-FA4B → CJK UNIFIED IDEOGRAPH-7891	# 

			{ L"\xF947",L"\x78CA" }, //( 磊 → 磊 ) CJK COMPATIBILITY IDEOGRAPH-F947 → CJK UNIFIED IDEOGRAPH-78CA	# 

			{ L"\xFAAB",L"\x78CC" }, //( 磌 → 磌 ) CJK COMPATIBILITY IDEOGRAPH-FAAB → CJK UNIFIED IDEOGRAPH-78CC	# 
			{ L"\x0002\xF950",L"\x78CC" }, //( 磌 → 磌 ) CJK COMPATIBILITY IDEOGRAPH-2F950 → CJK UNIFIED IDEOGRAPH-78CC	# 

			{ L"\xF964",L"\x78FB" }, //( 磻 → 磻 ) CJK COMPATIBILITY IDEOGRAPH-F964 → CJK UNIFIED IDEOGRAPH-78FB	# 

			{ L"\x0002\xF951",L"\x40E3" }, //( 䃣 → 䃣 ) CJK COMPATIBILITY IDEOGRAPH-2F951 → CJK UNIFIED IDEOGRAPH-40E3	# 

			{ L"\xF985",L"\x792A" }, //( 礪 → 礪 ) CJK COMPATIBILITY IDEOGRAPH-F985 → CJK UNIFIED IDEOGRAPH-792A	# 

			{ L"\x2F70",L"\x793A" }, //( ⽰ → 示 ) KANGXI RADICAL SPIRIT → CJK UNIFIED IDEOGRAPH-793A	# 

			{ L"\x2EAD",L"\x793B" }, //( ⺭ → 礻 ) CJK RADICAL SPIRIT TWO → CJK UNIFIED IDEOGRAPH-793B	# 

			{ L"\xFA18",L"\x793C" }, //( 礼 → 礼 ) CJK COMPATIBILITY IDEOGRAPH-FA18 → CJK UNIFIED IDEOGRAPH-793C	# 

			{ L"\xFA4C",L"\x793E" }, //( 社 → 社 ) CJK COMPATIBILITY IDEOGRAPH-FA4C → CJK UNIFIED IDEOGRAPH-793E	# 

			{ L"\xFA4E",L"\x7948" }, //( 祈 → 祈 ) CJK COMPATIBILITY IDEOGRAPH-FA4E → CJK UNIFIED IDEOGRAPH-7948	# 

			{ L"\xFA4D",L"\x7949" }, //( 祉 → 祉 ) CJK COMPATIBILITY IDEOGRAPH-FA4D → CJK UNIFIED IDEOGRAPH-7949	# 

			{ L"\x0002\xF952",L"\x0002\x5626" }, //( 𥘦 → 𥘦 ) CJK COMPATIBILITY IDEOGRAPH-2F952 → CJK UNIFIED IDEOGRAPH-25626	# 

			{ L"\xFA4F",L"\x7950" }, //( 祐 → 祐 ) CJK COMPATIBILITY IDEOGRAPH-FA4F → CJK UNIFIED IDEOGRAPH-7950	# 

			{ L"\xFA50",L"\x7956" }, //( 祖 → 祖 ) CJK COMPATIBILITY IDEOGRAPH-FA50 → CJK UNIFIED IDEOGRAPH-7956	# 
			{ L"\x0002\xF953",L"\x7956" }, //( 祖 → 祖 ) CJK COMPATIBILITY IDEOGRAPH-2F953 → CJK UNIFIED IDEOGRAPH-7956	# 

			{ L"\xFA51",L"\x795D" }, //( 祝 → 祝 ) CJK COMPATIBILITY IDEOGRAPH-FA51 → CJK UNIFIED IDEOGRAPH-795D	# 

			{ L"\xFA19",L"\x795E" }, //( 神 → 神 ) CJK COMPATIBILITY IDEOGRAPH-FA19 → CJK UNIFIED IDEOGRAPH-795E	# 

			{ L"\xFA1A",L"\x7965" }, //( 祥 → 祥 ) CJK COMPATIBILITY IDEOGRAPH-FA1A → CJK UNIFIED IDEOGRAPH-7965	# 

			{ L"\xFA61",L"\x8996" }, //( 視 → 視 ) CJK COMPATIBILITY IDEOGRAPH-FA61 → CJK UNIFIED IDEOGRAPH-8996	# 
			{ L"\xFAB8",L"\x8996" }, //( 視 → 視 ) CJK COMPATIBILITY IDEOGRAPH-FAB8 → CJK UNIFIED IDEOGRAPH-8996	# 

			{ L"\xF93C",L"\x797F" }, //( 祿 → 祿 ) CJK COMPATIBILITY IDEOGRAPH-F93C → CJK UNIFIED IDEOGRAPH-797F	# 

			{ L"\x0002\xF954",L"\x0002\x569A" }, //( 𥚚 → 𥚚 ) CJK COMPATIBILITY IDEOGRAPH-2F954 → CJK UNIFIED IDEOGRAPH-2569A	# 

			{ L"\xFA52",L"\x798D" }, //( 禍 → 禍 ) CJK COMPATIBILITY IDEOGRAPH-FA52 → CJK UNIFIED IDEOGRAPH-798D	# 

			{ L"\xFA53",L"\x798E" }, //( 禎 → 禎 ) CJK COMPATIBILITY IDEOGRAPH-FA53 → CJK UNIFIED IDEOGRAPH-798E	# 

			{ L"\xFA1B",L"\x798F" }, //( 福 → 福 ) CJK COMPATIBILITY IDEOGRAPH-FA1B → CJK UNIFIED IDEOGRAPH-798F	# 
			{ L"\x0002\xF956",L"\x798F" }, //( 福 → 福 ) CJK COMPATIBILITY IDEOGRAPH-2F956 → CJK UNIFIED IDEOGRAPH-798F	# 

			{ L"\x0002\xF955",L"\x0002\x56C5" }, //( 𥛅 → 𥛅 ) CJK COMPATIBILITY IDEOGRAPH-2F955 → CJK UNIFIED IDEOGRAPH-256C5	# 

			{ L"\xF9B6",L"\x79AE" }, //( 禮 → 禮 ) CJK COMPATIBILITY IDEOGRAPH-F9B6 → CJK UNIFIED IDEOGRAPH-79AE	# 

			{ L"\x2F71",L"\x79B8" }, //( ⽱ → 禸 ) KANGXI RADICAL TRACK → CJK UNIFIED IDEOGRAPH-79B8	# 

			{ L"\x2F72",L"\x79BE" }, //( ⽲ → 禾 ) KANGXI RADICAL GRAIN → CJK UNIFIED IDEOGRAPH-79BE	# 

			{ L"\xF995",L"\x79CA" }, //( 秊 → 秊 ) CJK COMPATIBILITY IDEOGRAPH-F995 → CJK UNIFIED IDEOGRAPH-79CA	# 

			{ L"\x0002\xF958",L"\x412F" }, //( 䄯 → 䄯 ) CJK COMPATIBILITY IDEOGRAPH-2F958 → CJK UNIFIED IDEOGRAPH-412F	# 

			{ L"\x0002\xF957",L"\x79EB" }, //( 秫 → 秫 ) CJK COMPATIBILITY IDEOGRAPH-2F957 → CJK UNIFIED IDEOGRAPH-79EB	# 

			{ L"\xF956",L"\x7A1C" }, //( 稜 → 稜 ) CJK COMPATIBILITY IDEOGRAPH-F956 → CJK UNIFIED IDEOGRAPH-7A1C	# 

			{ L"\x0002\xF95A",L"\x7A4A" }, //( 穊 → 穊 ) CJK COMPATIBILITY IDEOGRAPH-2F95A → CJK UNIFIED IDEOGRAPH-7A4A	# 

			{ L"\xFA54",L"\x7A40" }, //( 穀 → 穀 ) CJK COMPATIBILITY IDEOGRAPH-FA54 → CJK UNIFIED IDEOGRAPH-7A40	# 
			{ L"\x0002\xF959",L"\x7A40" }, //( 穀 → 穀 ) CJK COMPATIBILITY IDEOGRAPH-2F959 → CJK UNIFIED IDEOGRAPH-7A40	# 

			{ L"\x0002\xF95B",L"\x7A4F" }, //( 穏 → 穏 ) CJK COMPATIBILITY IDEOGRAPH-2F95B → CJK UNIFIED IDEOGRAPH-7A4F	# 

			{ L"\x2F73",L"\x7A74" }, //( ⽳ → 穴 ) KANGXI RADICAL CAVE → CJK UNIFIED IDEOGRAPH-7A74	# 

			{ L"\xFA55",L"\x7A81" }, //( 突 → 突 ) CJK COMPATIBILITY IDEOGRAPH-FA55 → CJK UNIFIED IDEOGRAPH-7A81	# 

			{ L"\x0002\xF95C",L"\x0002\x597C" }, //( 𥥼 → 𥥼 ) CJK COMPATIBILITY IDEOGRAPH-2F95C → CJK UNIFIED IDEOGRAPH-2597C	# 

			{ L"\xFAAC",L"\x7AB1" }, //( 窱 → 窱 ) CJK COMPATIBILITY IDEOGRAPH-FAAC → CJK UNIFIED IDEOGRAPH-7AB1	# 

			{ L"\xF9F7",L"\x7ACB" }, //( 立 → 立 ) CJK COMPATIBILITY IDEOGRAPH-F9F7 → CJK UNIFIED IDEOGRAPH-7ACB	# 
			{ L"\x2F74",L"\x7ACB" }, //( ⽴ → 立 ) KANGXI RADICAL STAND → CJK UNIFIED IDEOGRAPH-7ACB	# 

			{ L"\x2EEF",L"\x7ADC" }, //( ⻯ → 竜 ) CJK RADICAL J-SIMPLIFIED DRAGON → CJK UNIFIED IDEOGRAPH-7ADC	# 

			{ L"\x0002\xF95D",L"\x0002\x5AA7" }, //( 𥪧 → 𥪧 ) CJK COMPATIBILITY IDEOGRAPH-2F95D → CJK UNIFIED IDEOGRAPH-25AA7	# 
			{ L"\x0002\xF95E",L"\x0002\x5AA7" }, //( 𥪧 → 𥪧 ) CJK COMPATIBILITY IDEOGRAPH-2F95E → CJK UNIFIED IDEOGRAPH-25AA7	# 

			{ L"\x0002\xF95F",L"\x7AEE" }, //( 竮 → 竮 ) CJK COMPATIBILITY IDEOGRAPH-2F95F → CJK UNIFIED IDEOGRAPH-7AEE	# 

			{ L"\x2F75",L"\x7AF9" }, //( ⽵ → 竹 ) KANGXI RADICAL BAMBOO → CJK UNIFIED IDEOGRAPH-7AF9	# 

			{ L"\xF9F8",L"\x7B20" }, //( 笠 → 笠 ) CJK COMPATIBILITY IDEOGRAPH-F9F8 → CJK UNIFIED IDEOGRAPH-7B20	# 

			{ L"\xFA56",L"\x7BC0" }, //( 節 → 節 ) CJK COMPATIBILITY IDEOGRAPH-FA56 → CJK UNIFIED IDEOGRAPH-7BC0	# 
			{ L"\xFAAD",L"\x7BC0" }, //( 節 → 節 ) CJK COMPATIBILITY IDEOGRAPH-FAAD → CJK UNIFIED IDEOGRAPH-7BC0	# 

			{ L"\x0002\xF960",L"\x4202" }, //( 䈂 → 䈂 ) CJK COMPATIBILITY IDEOGRAPH-2F960 → CJK UNIFIED IDEOGRAPH-4202	# 

			{ L"\x0002\xF961",L"\x0002\x5BAB" }, //( 𥮫 → 𥮫 ) CJK COMPATIBILITY IDEOGRAPH-2F961 → CJK UNIFIED IDEOGRAPH-25BAB	# 

			{ L"\x0002\xF962",L"\x7BC6" }, //( 篆 → 篆 ) CJK COMPATIBILITY IDEOGRAPH-2F962 → CJK UNIFIED IDEOGRAPH-7BC6	# 

			{ L"\x0002\xF964",L"\x4227" }, //( 䈧 → 䈧 ) CJK COMPATIBILITY IDEOGRAPH-2F964 → CJK UNIFIED IDEOGRAPH-4227	# 

			{ L"\x0002\xF963",L"\x7BC9" }, //( 築 → 築 ) CJK COMPATIBILITY IDEOGRAPH-2F963 → CJK UNIFIED IDEOGRAPH-7BC9	# 

			{ L"\x0002\xF965",L"\x0002\x5C80" }, //( 𥲀 → 𥲀 ) CJK COMPATIBILITY IDEOGRAPH-2F965 → CJK UNIFIED IDEOGRAPH-25C80	# 

			{ L"\xFAD6",L"\x0002\x5CD0" }, //( 𥳐 → 𥳐 ) CJK COMPATIBILITY IDEOGRAPH-FAD6 → CJK UNIFIED IDEOGRAPH-25CD0	# 

			{ L"\xF9A6",L"\x7C3E" }, //( 簾 → 簾 ) CJK COMPATIBILITY IDEOGRAPH-F9A6 → CJK UNIFIED IDEOGRAPH-7C3E	# 

			{ L"\xF944",L"\x7C60" }, //( 籠 → 籠 ) CJK COMPATIBILITY IDEOGRAPH-F944 → CJK UNIFIED IDEOGRAPH-7C60	# 

			{ L"\x2F76",L"\x7C73" }, //( ⽶ → 米 ) KANGXI RADICAL RICE → CJK UNIFIED IDEOGRAPH-7C73	# 

			{ L"\xFAAE",L"\x7C7B" }, //( 类 → 类 ) CJK COMPATIBILITY IDEOGRAPH-FAAE → CJK UNIFIED IDEOGRAPH-7C7B	# 

			{ L"\xF9F9",L"\x7C92" }, //( 粒 → 粒 ) CJK COMPATIBILITY IDEOGRAPH-F9F9 → CJK UNIFIED IDEOGRAPH-7C92	# 

			{ L"\xFA1D",L"\x7CBE" }, //( 精 → 精 ) CJK COMPATIBILITY IDEOGRAPH-FA1D → CJK UNIFIED IDEOGRAPH-7CBE	# 

			{ L"\x0002\xF966",L"\x7CD2" }, //( 糒 → 糒 ) CJK COMPATIBILITY IDEOGRAPH-2F966 → CJK UNIFIED IDEOGRAPH-7CD2	# 

			{ L"\xFA03",L"\x7CD6" }, //( 糖 → 糖 ) CJK COMPATIBILITY IDEOGRAPH-FA03 → CJK UNIFIED IDEOGRAPH-7CD6	# 

			{ L"\x0002\xF968",L"\x7CE8" }, //( 糨 → 糨 ) CJK COMPATIBILITY IDEOGRAPH-2F968 → CJK UNIFIED IDEOGRAPH-7CE8	# 

			{ L"\x0002\xF967",L"\x42A0" }, //( 䊠 → 䊠 ) CJK COMPATIBILITY IDEOGRAPH-2F967 → CJK UNIFIED IDEOGRAPH-42A0	# 

			{ L"\x0002\xF969",L"\x7CE3" }, //( 糣 → 糣 ) CJK COMPATIBILITY IDEOGRAPH-2F969 → CJK UNIFIED IDEOGRAPH-7CE3	# 

			{ L"\xF97B",L"\x7CE7" }, //( 糧 → 糧 ) CJK COMPATIBILITY IDEOGRAPH-F97B → CJK UNIFIED IDEOGRAPH-7CE7	# 

			{ L"\x2F77",L"\x7CF8" }, //( ⽷ → 糸 ) KANGXI RADICAL SILK → CJK UNIFIED IDEOGRAPH-7CF8	# 

			{ L"\x2EAF",L"\x7CF9" }, //( ⺯ → 糹 ) CJK RADICAL SILK → CJK UNIFIED IDEOGRAPH-7CF9	# 

			{ L"\x0002\xF96B",L"\x0002\x5F86" }, //( 𥾆 → 𥾆 ) CJK COMPATIBILITY IDEOGRAPH-2F96B → CJK UNIFIED IDEOGRAPH-25F86	# 

			{ L"\x0002\xF96A",L"\x7D00" }, //( 紀 → 紀 ) CJK COMPATIBILITY IDEOGRAPH-2F96A → CJK UNIFIED IDEOGRAPH-7D00	# 

			{ L"\xF9CF",L"\x7D10" }, //( 紐 → 紐 ) CJK COMPATIBILITY IDEOGRAPH-F9CF → CJK UNIFIED IDEOGRAPH-7D10	# 

			{ L"\xF96A",L"\x7D22" }, //( 索 → 索 ) CJK COMPATIBILITY IDEOGRAPH-F96A → CJK UNIFIED IDEOGRAPH-7D22	# 

			{ L"\xF94F",L"\x7D2F" }, //( 累 → 累 ) CJK COMPATIBILITY IDEOGRAPH-F94F → CJK UNIFIED IDEOGRAPH-7D2F	# 

			{ L"\x7D76",L"\x7D55" }, //( 絶 → 絕 ) CJK UNIFIED IDEOGRAPH-7D76 → CJK UNIFIED IDEOGRAPH-7D55	# 

			{ L"\x0002\xF96C",L"\x7D63" }, //( 絣 → 絣 ) CJK COMPATIBILITY IDEOGRAPH-2F96C → CJK UNIFIED IDEOGRAPH-7D63	# 

			{ L"\xFAAF",L"\x7D5B" }, //( 絛 → 絛 ) CJK COMPATIBILITY IDEOGRAPH-FAAF → CJK UNIFIED IDEOGRAPH-7D5B	# 

			{ L"\xF93D",L"\x7DA0" }, //( 綠 → 綠 ) CJK COMPATIBILITY IDEOGRAPH-F93D → CJK UNIFIED IDEOGRAPH-7DA0	# 

			{ L"\xF957",L"\x7DBE" }, //( 綾 → 綾 ) CJK COMPATIBILITY IDEOGRAPH-F957 → CJK UNIFIED IDEOGRAPH-7DBE	# 

			{ L"\x0002\xF96E",L"\x7DC7" }, //( 緇 → 緇 ) CJK COMPATIBILITY IDEOGRAPH-2F96E → CJK UNIFIED IDEOGRAPH-7DC7	# 

			{ L"\xF996",L"\x7DF4" }, //( 練 → 練 ) CJK COMPATIBILITY IDEOGRAPH-F996 → CJK UNIFIED IDEOGRAPH-7DF4	# 
			{ L"\xFA57",L"\x7DF4" }, //( 練 → 練 ) CJK COMPATIBILITY IDEOGRAPH-FA57 → CJK UNIFIED IDEOGRAPH-7DF4	# 
			{ L"\xFAB0",L"\x7DF4" }, //( 練 → 練 ) CJK COMPATIBILITY IDEOGRAPH-FAB0 → CJK UNIFIED IDEOGRAPH-7DF4	# 

			{ L"\x0002\xF96F",L"\x7E02" }, //( 縂 → 縂 ) CJK COMPATIBILITY IDEOGRAPH-2F96F → CJK UNIFIED IDEOGRAPH-7E02	# 

			{ L"\x0002\xF96D",L"\x4301" }, //( 䌁 → 䌁 ) CJK COMPATIBILITY IDEOGRAPH-2F96D → CJK UNIFIED IDEOGRAPH-4301	# 

			{ L"\xFA58",L"\x7E09" }, //( 縉 → 縉 ) CJK COMPATIBILITY IDEOGRAPH-FA58 → CJK UNIFIED IDEOGRAPH-7E09	# 

			{ L"\xF950",L"\x7E37" }, //( 縷 → 縷 ) CJK COMPATIBILITY IDEOGRAPH-F950 → CJK UNIFIED IDEOGRAPH-7E37	# 

			{ L"\xFA59",L"\x7E41" }, //( 繁 → 繁 ) CJK COMPATIBILITY IDEOGRAPH-FA59 → CJK UNIFIED IDEOGRAPH-7E41	# 

			{ L"\x0002\xF970",L"\x7E45" }, //( 繅 → 繅 ) CJK COMPATIBILITY IDEOGRAPH-2F970 → CJK UNIFIED IDEOGRAPH-7E45	# 

			{ L"\x0002\xF898",L"\x0002\x61DA" }, //( 𦇚 → 𦇚 ) CJK COMPATIBILITY IDEOGRAPH-2F898 → CJK UNIFIED IDEOGRAPH-261DA	# 

			{ L"\x0002\xF971",L"\x4334" }, //( 䌴 → 䌴 ) CJK COMPATIBILITY IDEOGRAPH-2F971 → CJK UNIFIED IDEOGRAPH-4334	# 

			{ L"\x2F78",L"\x7F36" }, //( ⽸ → 缶 ) KANGXI RADICAL JAR → CJK UNIFIED IDEOGRAPH-7F36	# 

			{ L"\x0002\xF972",L"\x0002\x6228" }, //( 𦈨 → 𦈨 ) CJK COMPATIBILITY IDEOGRAPH-2F972 → CJK UNIFIED IDEOGRAPH-26228	# 

			{ L"\xFAB1",L"\x7F3E" }, //( 缾 → 缾 ) CJK COMPATIBILITY IDEOGRAPH-FAB1 → CJK UNIFIED IDEOGRAPH-7F3E	# 

			{ L"\x0002\xF973",L"\x0002\x6247" }, //( 𦉇 → 𦉇 ) CJK COMPATIBILITY IDEOGRAPH-2F973 → CJK UNIFIED IDEOGRAPH-26247	# 

			{ L"\x2F79",L"\x7F51" }, //( ⽹ → 网 ) KANGXI RADICAL NET → CJK UNIFIED IDEOGRAPH-7F51	# 

			{ L"\x2EAB",L"\x7F52" }, //( ⺫ → 罒 ) CJK RADICAL EYE → CJK UNIFIED IDEOGRAPH-7F52	# 
			{ L"\x2EB2",L"\x7F52" }, //( ⺲ → 罒 ) CJK RADICAL NET TWO → CJK UNIFIED IDEOGRAPH-7F52	# 

			{ L"\x2EB1",L"\x7F53" }, //( ⺱ → 罓 ) CJK RADICAL NET ONE → CJK UNIFIED IDEOGRAPH-7F53	# 

			{ L"\x0002\xF974",L"\x4359" }, //( 䍙 → 䍙 ) CJK COMPATIBILITY IDEOGRAPH-2F974 → CJK UNIFIED IDEOGRAPH-4359	# 

			{ L"\xFA5A",L"\x7F72" }, //( 署 → 署 ) CJK COMPATIBILITY IDEOGRAPH-FA5A → CJK UNIFIED IDEOGRAPH-7F72	# 

			{ L"\x0002\xF975",L"\x0002\x62D9" }, //( 𦋙 → 𦋙 ) CJK COMPATIBILITY IDEOGRAPH-2F975 → CJK UNIFIED IDEOGRAPH-262D9	# 

			{ L"\xF9E6",L"\x7F79" }, //( 罹 → 罹 ) CJK COMPATIBILITY IDEOGRAPH-F9E6 → CJK UNIFIED IDEOGRAPH-7F79	# 

			{ L"\x0002\xF976",L"\x7F7A" }, //( 罺 → 罺 ) CJK COMPATIBILITY IDEOGRAPH-2F976 → CJK UNIFIED IDEOGRAPH-7F7A	# 

			{ L"\xF90F",L"\x7F85" }, //( 羅 → 羅 ) CJK COMPATIBILITY IDEOGRAPH-F90F → CJK UNIFIED IDEOGRAPH-7F85	# 

			{ L"\x0002\xF977",L"\x0002\x633E" }, //( 𦌾 → 𦌾 ) CJK COMPATIBILITY IDEOGRAPH-2F977 → CJK UNIFIED IDEOGRAPH-2633E	# 

			{ L"\x2F7A",L"\x7F8A" }, //( ⽺ → 羊 ) KANGXI RADICAL SHEEP → CJK UNIFIED IDEOGRAPH-7F8A	# 

			{ L"\x0002\xF978",L"\x7F95" }, //( 羕 → 羕 ) CJK COMPATIBILITY IDEOGRAPH-2F978 → CJK UNIFIED IDEOGRAPH-7F95	# 

			{ L"\xF9AF",L"\x7F9A" }, //( 羚 → 羚 ) CJK COMPATIBILITY IDEOGRAPH-F9AF → CJK UNIFIED IDEOGRAPH-7F9A	# 

			{ L"\xFA1E",L"\x7FBD" }, //( 羽 → 羽 ) CJK COMPATIBILITY IDEOGRAPH-FA1E → CJK UNIFIED IDEOGRAPH-7FBD	# 
			{ L"\x2F7B",L"\x7FBD" }, //( ⽻ → 羽 ) KANGXI RADICAL FEATHER → CJK UNIFIED IDEOGRAPH-7FBD	# 

			{ L"\x0002\xF979",L"\x7FFA" }, //( 翺 → 翺 ) CJK COMPATIBILITY IDEOGRAPH-2F979 → CJK UNIFIED IDEOGRAPH-7FFA	# 

			{ L"\xF934",L"\x8001" }, //( 老 → 老 ) CJK COMPATIBILITY IDEOGRAPH-F934 → CJK UNIFIED IDEOGRAPH-8001	# 
			{ L"\x2F7C",L"\x8001" }, //( ⽼ → 老 ) KANGXI RADICAL OLD → CJK UNIFIED IDEOGRAPH-8001	# 

			{ L"\x2EB9",L"\x8002" }, //( ⺹ → 耂 ) CJK RADICAL OLD → CJK UNIFIED IDEOGRAPH-8002	# 

			{ L"\xFA5B",L"\x8005" }, //( 者 → 者 ) CJK COMPATIBILITY IDEOGRAPH-FA5B → CJK UNIFIED IDEOGRAPH-8005	# 
			{ L"\xFAB2",L"\x8005" }, //( 者 → 者 ) CJK COMPATIBILITY IDEOGRAPH-FAB2 → CJK UNIFIED IDEOGRAPH-8005	# 
			{ L"\x0002\xF97A",L"\x8005" }, //( 者 → 者 ) CJK COMPATIBILITY IDEOGRAPH-2F97A → CJK UNIFIED IDEOGRAPH-8005	# 

			{ L"\x2F7D",L"\x800C" }, //( ⽽ → 而 ) KANGXI RADICAL AND → CJK UNIFIED IDEOGRAPH-800C	# 

			{ L"\x0002\xF97B",L"\x0002\x64DA" }, //( 𦓚 → 𦓚 ) CJK COMPATIBILITY IDEOGRAPH-2F97B → CJK UNIFIED IDEOGRAPH-264DA	# 

			{ L"\x2F7E",L"\x8012" }, //( ⽾ → 耒 ) KANGXI RADICAL PLOW → CJK UNIFIED IDEOGRAPH-8012	# 

			{ L"\x0002\xF97C",L"\x0002\x6523" }, //( 𦔣 → 𦔣 ) CJK COMPATIBILITY IDEOGRAPH-2F97C → CJK UNIFIED IDEOGRAPH-26523	# 

			{ L"\x2F7F",L"\x8033" }, //( ⽿ → 耳 ) KANGXI RADICAL EAR → CJK UNIFIED IDEOGRAPH-8033	# 

			{ L"\xF9B0",L"\x8046" }, //( 聆 → 聆 ) CJK COMPATIBILITY IDEOGRAPH-F9B0 → CJK UNIFIED IDEOGRAPH-8046	# 

			{ L"\x0002\xF97D",L"\x8060" }, //( 聠 → 聠 ) CJK COMPATIBILITY IDEOGRAPH-2F97D → CJK UNIFIED IDEOGRAPH-8060	# 

			{ L"\x0002\xF97E",L"\x0002\x65A8" }, //( 𦖨 → 𦖨 ) CJK COMPATIBILITY IDEOGRAPH-2F97E → CJK UNIFIED IDEOGRAPH-265A8	# 

			{ L"\xF997",L"\x806F" }, //( 聯 → 聯 ) CJK COMPATIBILITY IDEOGRAPH-F997 → CJK UNIFIED IDEOGRAPH-806F	# 

			{ L"\x0002\xF97F",L"\x8070" }, //( 聰 → 聰 ) CJK COMPATIBILITY IDEOGRAPH-2F97F → CJK UNIFIED IDEOGRAPH-8070	# 

			{ L"\xF945",L"\x807E" }, //( 聾 → 聾 ) CJK COMPATIBILITY IDEOGRAPH-F945 → CJK UNIFIED IDEOGRAPH-807E	# 

			{ L"\x2F80",L"\x807F" }, //( ⾀ → 聿 ) KANGXI RADICAL BRUSH → CJK UNIFIED IDEOGRAPH-807F	# 

			{ L"\x2EBA",L"\x8080" }, //( ⺺ → 肀 ) CJK RADICAL BRUSH ONE → CJK UNIFIED IDEOGRAPH-8080	# 

			{ L"\x2F81",L"\x8089" }, //( ⾁ → 肉 ) KANGXI RADICAL MEAT → CJK UNIFIED IDEOGRAPH-8089	# 

			{ L"\xF953",L"\x808B" }, //( 肋 → 肋 ) CJK COMPATIBILITY IDEOGRAPH-F953 → CJK UNIFIED IDEOGRAPH-808B	# 

			{ L"\x0002\xF8D6",L"\x80AD" }, //( 肭 → 肭 ) CJK COMPATIBILITY IDEOGRAPH-2F8D6 → CJK UNIFIED IDEOGRAPH-80AD	# 

			{ L"\x0002\xF982",L"\x80B2" }, //( 育 → 育 ) CJK COMPATIBILITY IDEOGRAPH-2F982 → CJK UNIFIED IDEOGRAPH-80B2	# 

			{ L"\x0002\xF981",L"\x43D5" }, //( 䏕 → 䏕 ) CJK COMPATIBILITY IDEOGRAPH-2F981 → CJK UNIFIED IDEOGRAPH-43D5	# 

			{ L"\x0002\xF8D7",L"\x43D9" }, //( 䏙 → 䏙 ) CJK COMPATIBILITY IDEOGRAPH-2F8D7 → CJK UNIFIED IDEOGRAPH-43D9	# 

			{ L"\x8141",L"\x80FC" }, //( 腁 → 胼 ) CJK UNIFIED IDEOGRAPH-8141 → CJK UNIFIED IDEOGRAPH-80FC	# 

			{ L"\x0002\xF983",L"\x8103" }, //( 脃 → 脃 ) CJK COMPATIBILITY IDEOGRAPH-2F983 → CJK UNIFIED IDEOGRAPH-8103	# 

			{ L"\x0002\xF985",L"\x813E" }, //( 脾 → 脾 ) CJK COMPATIBILITY IDEOGRAPH-2F985 → CJK UNIFIED IDEOGRAPH-813E	# 

			{ L"\x0002\xF984",L"\x440B" }, //( 䐋 → 䐋 ) CJK COMPATIBILITY IDEOGRAPH-2F984 → CJK UNIFIED IDEOGRAPH-440B	# 

			{ L"\x0002\xF987",L"\x0002\x67A7" }, //( 𦞧 → 𦞧 ) CJK COMPATIBILITY IDEOGRAPH-2F987 → CJK UNIFIED IDEOGRAPH-267A7	# 

			{ L"\x0002\xF988",L"\x0002\x67B5" }, //( 𦞵 → 𦞵 ) CJK COMPATIBILITY IDEOGRAPH-2F988 → CJK UNIFIED IDEOGRAPH-267B5	# 

			{ L"\x6726",L"\x4443" }, //( 朦 → 䑃 ) CJK UNIFIED IDEOGRAPH-6726 → CJK UNIFIED IDEOGRAPH-4443	# 

			{ L"\xF926",L"\x81D8" }, //( 臘 → 臘 ) CJK COMPATIBILITY IDEOGRAPH-F926 → CJK UNIFIED IDEOGRAPH-81D8	# 

			{ L"\x2F82",L"\x81E3" }, //( ⾂ → 臣 ) KANGXI RADICAL MINISTER → CJK UNIFIED IDEOGRAPH-81E3	# 

			{ L"\xF9F6",L"\x81E8" }, //( 臨 → 臨 ) CJK COMPATIBILITY IDEOGRAPH-F9F6 → CJK UNIFIED IDEOGRAPH-81E8	# 

			{ L"\x2F83",L"\x81EA" }, //( ⾃ → 自 ) KANGXI RADICAL SELF → CJK UNIFIED IDEOGRAPH-81EA	# 

			{ L"\xFA5C",L"\x81ED" }, //( 臭 → 臭 ) CJK COMPATIBILITY IDEOGRAPH-FA5C → CJK UNIFIED IDEOGRAPH-81ED	# 

			{ L"\x2F84",L"\x81F3" }, //( ⾄ → 至 ) KANGXI RADICAL ARRIVE → CJK UNIFIED IDEOGRAPH-81F3	# 

			{ L"\x2F85",L"\x81FC" }, //( ⾅ → 臼 ) KANGXI RADICAL MORTAR → CJK UNIFIED IDEOGRAPH-81FC	# 

			{ L"\x0002\xF893",L"\x8201" }, //( 舁 → 舁 ) CJK COMPATIBILITY IDEOGRAPH-2F893 → CJK UNIFIED IDEOGRAPH-8201	# 
			{ L"\x0002\xF98B",L"\x8201" }, //( 舁 → 舁 ) CJK COMPATIBILITY IDEOGRAPH-2F98B → CJK UNIFIED IDEOGRAPH-8201	# 

			{ L"\x0002\xF98C",L"\x8204" }, //( 舄 → 舄 ) CJK COMPATIBILITY IDEOGRAPH-2F98C → CJK UNIFIED IDEOGRAPH-8204	# 

			{ L"\x2F86",L"\x820C" }, //( ⾆ → 舌 ) KANGXI RADICAL TONGUE → CJK UNIFIED IDEOGRAPH-820C	# 

			{ L"\xFA6D",L"\x8218" }, //( 舘 → 舘 ) CJK COMPATIBILITY IDEOGRAPH-FA6D → CJK UNIFIED IDEOGRAPH-8218	# 

			{ L"\x2F87",L"\x821B" }, //( ⾇ → 舛 ) KANGXI RADICAL OPPOSE → CJK UNIFIED IDEOGRAPH-821B	# 

			{ L"\x2F88",L"\x821F" }, //( ⾈ → 舟 ) KANGXI RADICAL BOAT → CJK UNIFIED IDEOGRAPH-821F	# 

			{ L"\x0002\xF98E",L"\x446B" }, //( 䑫 → 䑫 ) CJK COMPATIBILITY IDEOGRAPH-2F98E → CJK UNIFIED IDEOGRAPH-446B	# 

			{ L"\x2F89",L"\x826E" }, //( ⾉ → 艮 ) KANGXI RADICAL STOPPING → CJK UNIFIED IDEOGRAPH-826E	# 

			{ L"\xF97C",L"\x826F" }, //( 良 → 良 ) CJK COMPATIBILITY IDEOGRAPH-F97C → CJK UNIFIED IDEOGRAPH-826F	# 

			{ L"\x2F8A",L"\x8272" }, //( ⾊ → 色 ) KANGXI RADICAL COLOR → CJK UNIFIED IDEOGRAPH-8272	# 

			{ L"\x2F8B",L"\x8278" }, //( ⾋ → 艸 ) KANGXI RADICAL GRASS → CJK UNIFIED IDEOGRAPH-8278	# 

			{ L"\xFA5D",L"\x8279" }, //( 艹 → 艹 ) CJK COMPATIBILITY IDEOGRAPH-FA5D → CJK UNIFIED IDEOGRAPH-8279	# 
			{ L"\xFA5E",L"\x8279" }, //( 艹 → 艹 ) CJK COMPATIBILITY IDEOGRAPH-FA5E → CJK UNIFIED IDEOGRAPH-8279	# 
			{ L"\x2EBE",L"\x8279" }, //( ⺾ → 艹 ) CJK RADICAL GRASS ONE → CJK UNIFIED IDEOGRAPH-8279	# 
			{ L"\x2EBF",L"\x8279" }, //( ⺿ → 艹 ) CJK RADICAL GRASS TWO → CJK UNIFIED IDEOGRAPH-8279	# →艹→
			{ L"\x2EC0",L"\x8279" }, //( ⻀ → 艹 ) CJK RADICAL GRASS THREE → CJK UNIFIED IDEOGRAPH-8279	# →艹→

			{ L"\x0002\xF990",L"\x828B" }, //( 芋 → 芋 ) CJK COMPATIBILITY IDEOGRAPH-2F990 → CJK UNIFIED IDEOGRAPH-828B	# 

			{ L"\x0002\xF98F",L"\x8291" }, //( 芑 → 芑 ) CJK COMPATIBILITY IDEOGRAPH-2F98F → CJK UNIFIED IDEOGRAPH-8291	# 

			{ L"\x0002\xF991",L"\x829D" }, //( 芝 → 芝 ) CJK COMPATIBILITY IDEOGRAPH-2F991 → CJK UNIFIED IDEOGRAPH-829D	# 

			{ L"\x0002\xF993",L"\x82B1" }, //( 花 → 花 ) CJK COMPATIBILITY IDEOGRAPH-2F993 → CJK UNIFIED IDEOGRAPH-82B1	# 

			{ L"\x0002\xF994",L"\x82B3" }, //( 芳 → 芳 ) CJK COMPATIBILITY IDEOGRAPH-2F994 → CJK UNIFIED IDEOGRAPH-82B3	# 

			{ L"\x0002\xF995",L"\x82BD" }, //( 芽 → 芽 ) CJK COMPATIBILITY IDEOGRAPH-2F995 → CJK UNIFIED IDEOGRAPH-82BD	# 

			{ L"\xF974",L"\x82E5" }, //( 若 → 若 ) CJK COMPATIBILITY IDEOGRAPH-F974 → CJK UNIFIED IDEOGRAPH-82E5	# 
			{ L"\x0002\xF998",L"\x82E5" }, //( 若 → 若 ) CJK COMPATIBILITY IDEOGRAPH-2F998 → CJK UNIFIED IDEOGRAPH-82E5	# 

			{ L"\x0002\xF996",L"\x82E6" }, //( 苦 → 苦 ) CJK COMPATIBILITY IDEOGRAPH-2F996 → CJK UNIFIED IDEOGRAPH-82E6	# 

			{ L"\x0002\xF997",L"\x0002\x6B3C" }, //( 𦬼 → 𦬼 ) CJK COMPATIBILITY IDEOGRAPH-2F997 → CJK UNIFIED IDEOGRAPH-26B3C	# 

			{ L"\xF9FE",L"\x8336" }, //( 茶 → 茶 ) CJK COMPATIBILITY IDEOGRAPH-F9FE → CJK UNIFIED IDEOGRAPH-8336	# 

			{ L"\xFAB3",L"\x8352" }, //( 荒 → 荒 ) CJK COMPATIBILITY IDEOGRAPH-FAB3 → CJK UNIFIED IDEOGRAPH-8352	# 

			{ L"\x0002\xF99A",L"\x8363" }, //( 荣 → 荣 ) CJK COMPATIBILITY IDEOGRAPH-2F99A → CJK UNIFIED IDEOGRAPH-8363	# 

			{ L"\x0002\xF999",L"\x831D" }, //( 茝 → 茝 ) CJK COMPATIBILITY IDEOGRAPH-2F999 → CJK UNIFIED IDEOGRAPH-831D	# 

			{ L"\x0002\xF99C",L"\x8323" }, //( 茣 → 茣 ) CJK COMPATIBILITY IDEOGRAPH-2F99C → CJK UNIFIED IDEOGRAPH-8323	# 

			{ L"\x0002\xF99D",L"\x83BD" }, //( 莽 → 莽 ) CJK COMPATIBILITY IDEOGRAPH-2F99D → CJK UNIFIED IDEOGRAPH-83BD	# 

			{ L"\x0002\xF9A0",L"\x8353" }, //( 荓 → 荓 ) CJK COMPATIBILITY IDEOGRAPH-2F9A0 → CJK UNIFIED IDEOGRAPH-8353	# 

			{ L"\xF93E",L"\x83C9" }, //( 菉 → 菉 ) CJK COMPATIBILITY IDEOGRAPH-F93E → CJK UNIFIED IDEOGRAPH-83C9	# 

			{ L"\x0002\xF9A1",L"\x83CA" }, //( 菊 → 菊 ) CJK COMPATIBILITY IDEOGRAPH-2F9A1 → CJK UNIFIED IDEOGRAPH-83CA	# 

			{ L"\x0002\xF9A2",L"\x83CC" }, //( 菌 → 菌 ) CJK COMPATIBILITY IDEOGRAPH-2F9A2 → CJK UNIFIED IDEOGRAPH-83CC	# 

			{ L"\x0002\xF9A3",L"\x83DC" }, //( 菜 → 菜 ) CJK COMPATIBILITY IDEOGRAPH-2F9A3 → CJK UNIFIED IDEOGRAPH-83DC	# 

			{ L"\x0002\xF99E",L"\x83E7" }, //( 菧 → 菧 ) CJK COMPATIBILITY IDEOGRAPH-2F99E → CJK UNIFIED IDEOGRAPH-83E7	# 

			{ L"\xFAB4",L"\x83EF" }, //( 華 → 華 ) CJK COMPATIBILITY IDEOGRAPH-FAB4 → CJK UNIFIED IDEOGRAPH-83EF	# 

			{ L"\xF958",L"\x83F1" }, //( 菱 → 菱 ) CJK COMPATIBILITY IDEOGRAPH-F958 → CJK UNIFIED IDEOGRAPH-83F1	# 

			{ L"\xFA5F",L"\x8457" }, //( 著 → 著 ) CJK COMPATIBILITY IDEOGRAPH-FA5F → CJK UNIFIED IDEOGRAPH-8457	# 
			{ L"\x0002\xF99F",L"\x8457" }, //( 著 → 著 ) CJK COMPATIBILITY IDEOGRAPH-2F99F → CJK UNIFIED IDEOGRAPH-8457	# 

			{ L"\x0002\xF9A4",L"\x0002\x6C36" }, //( 𦰶 → 𦰶 ) CJK COMPATIBILITY IDEOGRAPH-2F9A4 → CJK UNIFIED IDEOGRAPH-26C36	# 

			{ L"\x0002\xF99B",L"\x83AD" }, //( 莭 → 莭 ) CJK COMPATIBILITY IDEOGRAPH-2F99B → CJK UNIFIED IDEOGRAPH-83AD	# 

			{ L"\xF918",L"\x843D" }, //( 落 → 落 ) CJK COMPATIBILITY IDEOGRAPH-F918 → CJK UNIFIED IDEOGRAPH-843D	# 

			{ L"\xF96E",L"\x8449" }, //( 葉 → 葉 ) CJK COMPATIBILITY IDEOGRAPH-F96E → CJK UNIFIED IDEOGRAPH-8449	# 

			{ L"\x853F",L"\x848D" }, //( 蔿 → 蒍 ) CJK UNIFIED IDEOGRAPH-853F → CJK UNIFIED IDEOGRAPH-848D	# 

			{ L"\x0002\xF9A6",L"\x0002\x6CD5" }, //( 𦳕 → 𦳕 ) CJK COMPATIBILITY IDEOGRAPH-2F9A6 → CJK UNIFIED IDEOGRAPH-26CD5	# 

			{ L"\x0002\xF9A5",L"\x0002\x6D6B" }, //( 𦵫 → 𦵫 ) CJK COMPATIBILITY IDEOGRAPH-2F9A5 → CJK UNIFIED IDEOGRAPH-26D6B	# 

			{ L"\xF999",L"\x84EE" }, //( 蓮 → 蓮 ) CJK COMPATIBILITY IDEOGRAPH-F999 → CJK UNIFIED IDEOGRAPH-84EE	# 

			{ L"\x0002\xF9A8",L"\x84F1" }, //( 蓱 → 蓱 ) CJK COMPATIBILITY IDEOGRAPH-2F9A8 → CJK UNIFIED IDEOGRAPH-84F1	# 

			{ L"\x0002\xF9A9",L"\x84F3" }, //( 蓳 → 蓳 ) CJK COMPATIBILITY IDEOGRAPH-2F9A9 → CJK UNIFIED IDEOGRAPH-84F3	# 

			{ L"\xF9C2",L"\x84FC" }, //( 蓼 → 蓼 ) CJK COMPATIBILITY IDEOGRAPH-F9C2 → CJK UNIFIED IDEOGRAPH-84FC	# 

			{ L"\x0002\xF9AA",L"\x8516" }, //( 蔖 → 蔖 ) CJK COMPATIBILITY IDEOGRAPH-2F9AA → CJK UNIFIED IDEOGRAPH-8516	# 

			{ L"\x0002\xF9A7",L"\x452B" }, //( 䔫 → 䔫 ) CJK COMPATIBILITY IDEOGRAPH-2F9A7 → CJK UNIFIED IDEOGRAPH-452B	# 

			{ L"\x0002\xF9AC",L"\x8564" }, //( 蕤 → 蕤 ) CJK COMPATIBILITY IDEOGRAPH-2F9AC → CJK UNIFIED IDEOGRAPH-8564	# 

			{ L"\x0002\xF9AD",L"\x0002\x6F2C" }, //( 𦼬 → 𦼬 ) CJK COMPATIBILITY IDEOGRAPH-2F9AD → CJK UNIFIED IDEOGRAPH-26F2C	# 

			{ L"\xF923",L"\x85CD" }, //( 藍 → 藍 ) CJK COMPATIBILITY IDEOGRAPH-F923 → CJK UNIFIED IDEOGRAPH-85CD	# 

			{ L"\x0002\xF9AE",L"\x455D" }, //( 䕝 → 䕝 ) CJK COMPATIBILITY IDEOGRAPH-2F9AE → CJK UNIFIED IDEOGRAPH-455D	# 

			{ L"\x0002\xF9B0",L"\x0002\x6FB1" }, //( 𦾱 → 𦾱 ) CJK COMPATIBILITY IDEOGRAPH-2F9B0 → CJK UNIFIED IDEOGRAPH-26FB1	# 

			{ L"\x0002\xF9AF",L"\x4561" }, //( 䕡 → 䕡 ) CJK COMPATIBILITY IDEOGRAPH-2F9AF → CJK UNIFIED IDEOGRAPH-4561	# 

			{ L"\xF9F0",L"\x85FA" }, //( 藺 → 藺 ) CJK COMPATIBILITY IDEOGRAPH-F9F0 → CJK UNIFIED IDEOGRAPH-85FA	# 

			{ L"\xF935",L"\x8606" }, //( 蘆 → 蘆 ) CJK COMPATIBILITY IDEOGRAPH-F935 → CJK UNIFIED IDEOGRAPH-8606	# 

			{ L"\x0002\xF9B2",L"\x456B" }, //( 䕫 → 䕫 ) CJK COMPATIBILITY IDEOGRAPH-2F9B2 → CJK UNIFIED IDEOGRAPH-456B	# 

			{ L"\xFA20",L"\x8612" }, //( 蘒 → 蘒 ) CJK COMPATIBILITY IDEOGRAPH-FA20 → CJK UNIFIED IDEOGRAPH-8612	# 

			{ L"\xF91F",L"\x862D" }, //( 蘭 → 蘭 ) CJK COMPATIBILITY IDEOGRAPH-F91F → CJK UNIFIED IDEOGRAPH-862D	# 

			{ L"\x0002\xF9B1",L"\x0002\x70D2" }, //( 𧃒 → 𧃒 ) CJK COMPATIBILITY IDEOGRAPH-2F9B1 → CJK UNIFIED IDEOGRAPH-270D2	# 

			{ L"\x8641",L"\x8637" }, //( 虁 → 蘷 ) CJK UNIFIED IDEOGRAPH-8641 → CJK UNIFIED IDEOGRAPH-8637	# 

			{ L"\xF910",L"\x863F" }, //( 蘿 → 蘿 ) CJK COMPATIBILITY IDEOGRAPH-F910 → CJK UNIFIED IDEOGRAPH-863F	# 

			{ L"\x2F8C",L"\x864D" }, //( ⾌ → 虍 ) KANGXI RADICAL TIGER → CJK UNIFIED IDEOGRAPH-864D	# 

			{ L"\x2EC1",L"\x864E" }, //( ⻁ → 虎 ) CJK RADICAL TIGER → CJK UNIFIED IDEOGRAPH-864E	# 

			{ L"\x0002\xF9B3",L"\x8650" }, //( 虐 → 虐 ) CJK COMPATIBILITY IDEOGRAPH-2F9B3 → CJK UNIFIED IDEOGRAPH-8650	# 

			{ L"\xF936",L"\x865C" }, //( 虜 → 虜 ) CJK COMPATIBILITY IDEOGRAPH-F936 → CJK UNIFIED IDEOGRAPH-865C	# 
			{ L"\x0002\xF9B4",L"\x865C" }, //( 虜 → 虜 ) CJK COMPATIBILITY IDEOGRAPH-2F9B4 → CJK UNIFIED IDEOGRAPH-865C	# 

			{ L"\x0002\xF9B5",L"\x8667" }, //( 虧 → 虧 ) CJK COMPATIBILITY IDEOGRAPH-2F9B5 → CJK UNIFIED IDEOGRAPH-8667	# 

			{ L"\x0002\xF9B6",L"\x8669" }, //( 虩 → 虩 ) CJK COMPATIBILITY IDEOGRAPH-2F9B6 → CJK UNIFIED IDEOGRAPH-8669	# 

			{ L"\x2F8D",L"\x866B" }, //( ⾍ → 虫 ) KANGXI RADICAL INSECT → CJK UNIFIED IDEOGRAPH-866B	# 

			{ L"\x0002\xF9B7",L"\x86A9" }, //( 蚩 → 蚩 ) CJK COMPATIBILITY IDEOGRAPH-2F9B7 → CJK UNIFIED IDEOGRAPH-86A9	# 

			{ L"\x0002\xF9B8",L"\x8688" }, //( 蚈 → 蚈 ) CJK COMPATIBILITY IDEOGRAPH-2F9B8 → CJK UNIFIED IDEOGRAPH-8688	# 

			{ L"\x0002\xF9BA",L"\x86E2" }, //( 蛢 → 蛢 ) CJK COMPATIBILITY IDEOGRAPH-2F9BA → CJK UNIFIED IDEOGRAPH-86E2	# 

			{ L"\x0002\xF9B9",L"\x870E" }, //( 蜎 → 蜎 ) CJK COMPATIBILITY IDEOGRAPH-2F9B9 → CJK UNIFIED IDEOGRAPH-870E	# 

			{ L"\x0002\xF9BC",L"\x8728" }, //( 蜨 → 蜨 ) CJK COMPATIBILITY IDEOGRAPH-2F9BC → CJK UNIFIED IDEOGRAPH-8728	# 

			{ L"\x0002\xF9BD",L"\x876B" }, //( 蝫 → 蝫 ) CJK COMPATIBILITY IDEOGRAPH-2F9BD → CJK UNIFIED IDEOGRAPH-876B	# 

			{ L"\x0002\xF9C0",L"\x87E1" }, //( 蟡 → 蟡 ) CJK COMPATIBILITY IDEOGRAPH-2F9C0 → CJK UNIFIED IDEOGRAPH-87E1	# 

			{ L"\xFAB5",L"\x8779" }, //( 蝹 → 蝹 ) CJK COMPATIBILITY IDEOGRAPH-FAB5 → CJK UNIFIED IDEOGRAPH-8779	# 
			{ L"\x0002\xF9BB",L"\x8779" }, //( 蝹 → 蝹 ) CJK COMPATIBILITY IDEOGRAPH-2F9BB → CJK UNIFIED IDEOGRAPH-8779	# 

			{ L"\x0002\xF9BE",L"\x8786" }, //( 螆 → 螆 ) CJK COMPATIBILITY IDEOGRAPH-2F9BE → CJK UNIFIED IDEOGRAPH-8786	# 

			{ L"\x0002\xF9BF",L"\x45D7" }, //( 䗗 → 䗗 ) CJK COMPATIBILITY IDEOGRAPH-2F9BF → CJK UNIFIED IDEOGRAPH-45D7	# 

			{ L"\x0002\xF9AB",L"\x0002\x73CA" }, //( 𧏊 → 𧏊 ) CJK COMPATIBILITY IDEOGRAPH-2F9AB → CJK UNIFIED IDEOGRAPH-273CA	# 

			{ L"\xF911",L"\x87BA" }, //( 螺 → 螺 ) CJK COMPATIBILITY IDEOGRAPH-F911 → CJK UNIFIED IDEOGRAPH-87BA	# 

			{ L"\x0002\xF9C1",L"\x8801" }, //( 蠁 → 蠁 ) CJK COMPATIBILITY IDEOGRAPH-2F9C1 → CJK UNIFIED IDEOGRAPH-8801	# 

			{ L"\x0002\xF9C2",L"\x45F9" }, //( 䗹 → 䗹 ) CJK COMPATIBILITY IDEOGRAPH-2F9C2 → CJK UNIFIED IDEOGRAPH-45F9	# 

			{ L"\xF927",L"\x881F" }, //( 蠟 → 蠟 ) CJK COMPATIBILITY IDEOGRAPH-F927 → CJK UNIFIED IDEOGRAPH-881F	# 

			{ L"\x2F8E",L"\x8840" }, //( ⾎ → 血 ) KANGXI RADICAL BLOOD → CJK UNIFIED IDEOGRAPH-8840	# 

			{ L"\xFA08",L"\x884C" }, //( 行 → 行 ) CJK COMPATIBILITY IDEOGRAPH-FA08 → CJK UNIFIED IDEOGRAPH-884C	# 
			{ L"\x2F8F",L"\x884C" }, //( ⾏ → 行 ) KANGXI RADICAL WALK ENCLOSURE → CJK UNIFIED IDEOGRAPH-884C	# 

			{ L"\x0002\xF9C3",L"\x8860" }, //( 衠 → 衠 ) CJK COMPATIBILITY IDEOGRAPH-2F9C3 → CJK UNIFIED IDEOGRAPH-8860	# 

			{ L"\x0002\xF9C4",L"\x8863" }, //( 衣 → 衣 ) CJK COMPATIBILITY IDEOGRAPH-2F9C4 → CJK UNIFIED IDEOGRAPH-8863	# 
			{ L"\x2F90",L"\x8863" }, //( ⾐ → 衣 ) KANGXI RADICAL CLOTHES → CJK UNIFIED IDEOGRAPH-8863	# 

			{ L"\x2EC2",L"\x8864" }, //( ⻂ → 衤 ) CJK RADICAL CLOTHES → CJK UNIFIED IDEOGRAPH-8864	# 

			{ L"\xF9A0",L"\x88C2" }, //( 裂 → 裂 ) CJK COMPATIBILITY IDEOGRAPH-F9A0 → CJK UNIFIED IDEOGRAPH-88C2	# 

			{ L"\x0002\xF9C5",L"\x0002\x7667" }, //( 𧙧 → 𧙧 ) CJK COMPATIBILITY IDEOGRAPH-2F9C5 → CJK UNIFIED IDEOGRAPH-27667	# 

			{ L"\xF9E7",L"\x88CF" }, //( 裏 → 裏 ) CJK COMPATIBILITY IDEOGRAPH-F9E7 → CJK UNIFIED IDEOGRAPH-88CF	# 

			{ L"\x0002\xF9C6",L"\x88D7" }, //( 裗 → 裗 ) CJK COMPATIBILITY IDEOGRAPH-2F9C6 → CJK UNIFIED IDEOGRAPH-88D7	# 

			{ L"\x0002\xF9C7",L"\x88DE" }, //( 裞 → 裞 ) CJK COMPATIBILITY IDEOGRAPH-2F9C7 → CJK UNIFIED IDEOGRAPH-88DE	# 

			{ L"\xF9E8",L"\x88E1" }, //( 裡 → 裡 ) CJK COMPATIBILITY IDEOGRAPH-F9E8 → CJK UNIFIED IDEOGRAPH-88E1	# 

			{ L"\xF912",L"\x88F8" }, //( 裸 → 裸 ) CJK COMPATIBILITY IDEOGRAPH-F912 → CJK UNIFIED IDEOGRAPH-88F8	# 

			{ L"\x0002\xF9C9",L"\x88FA" }, //( 裺 → 裺 ) CJK COMPATIBILITY IDEOGRAPH-2F9C9 → CJK UNIFIED IDEOGRAPH-88FA	# 

			{ L"\x0002\xF9C8",L"\x4635" }, //( 䘵 → 䘵 ) CJK COMPATIBILITY IDEOGRAPH-2F9C8 → CJK UNIFIED IDEOGRAPH-4635	# 

			{ L"\xFA60",L"\x8910" }, //( 褐 → 褐 ) CJK COMPATIBILITY IDEOGRAPH-FA60 → CJK UNIFIED IDEOGRAPH-8910	# 

			{ L"\xFAB6",L"\x8941" }, //( 襁 → 襁 ) CJK COMPATIBILITY IDEOGRAPH-FAB6 → CJK UNIFIED IDEOGRAPH-8941	# 

			{ L"\xF924",L"\x8964" }, //( 襤 → 襤 ) CJK COMPATIBILITY IDEOGRAPH-F924 → CJK UNIFIED IDEOGRAPH-8964	# 

			{ L"\x2F91",L"\x897E" }, //( ⾑ → 襾 ) KANGXI RADICAL WEST → CJK UNIFIED IDEOGRAPH-897E	# 

			{ L"\x2EC4",L"\x897F" }, //( ⻄ → 西 ) CJK RADICAL WEST TWO → CJK UNIFIED IDEOGRAPH-897F	# 

			{ L"\x2EC3",L"\x8980" }, //( ⻃ → 覀 ) CJK RADICAL WEST ONE → CJK UNIFIED IDEOGRAPH-8980	# 

			{ L"\xFAB7",L"\x8986" }, //( 覆 → 覆 ) CJK COMPATIBILITY IDEOGRAPH-FAB7 → CJK UNIFIED IDEOGRAPH-8986	# 

			{ L"\xFA0A",L"\x898B" }, //( 見 → 見 ) CJK COMPATIBILITY IDEOGRAPH-FA0A → CJK UNIFIED IDEOGRAPH-898B	# 
			{ L"\x2F92",L"\x898B" }, //( ⾒ → 見 ) KANGXI RADICAL SEE → CJK UNIFIED IDEOGRAPH-898B	# 

			{ L"\x0002\xF9CB",L"\x0002\x78AE" }, //( 𧢮 → 𧢮 ) CJK COMPATIBILITY IDEOGRAPH-2F9CB → CJK UNIFIED IDEOGRAPH-278AE	# 

			{ L"\x2EC5",L"\x89C1" }, //( ⻅ → 见 ) CJK RADICAL C-SIMPLIFIED SEE → CJK UNIFIED IDEOGRAPH-89C1	# 

			{ L"\x2F93",L"\x89D2" }, //( ⾓ → 角 ) KANGXI RADICAL HORN → CJK UNIFIED IDEOGRAPH-89D2	# 

			{ L"\x2F94",L"\x8A00" }, //( ⾔ → 言 ) KANGXI RADICAL SPEECH → CJK UNIFIED IDEOGRAPH-8A00	# 

			{ L"\x0002\xF9CC",L"\x0002\x7966" }, //( 𧥦 → 𧥦 ) CJK COMPATIBILITY IDEOGRAPH-2F9CC → CJK UNIFIED IDEOGRAPH-27966	# 

			{ L"\x8A7D",L"\x8A2E" }, //( 詽 → 訮 ) CJK UNIFIED IDEOGRAPH-8A7D → CJK UNIFIED IDEOGRAPH-8A2E	# 

			{ L"\x8A1E",L"\x46B6" }, //( 訞 → 䚶 ) CJK UNIFIED IDEOGRAPH-8A1E → CJK UNIFIED IDEOGRAPH-46B6	# 

			{ L"\x0002\xF9CD",L"\x46BE" }, //( 䚾 → 䚾 ) CJK COMPATIBILITY IDEOGRAPH-2F9CD → CJK UNIFIED IDEOGRAPH-46BE	# 

			{ L"\x0002\xF9CE",L"\x46C7" }, //( 䛇 → 䛇 ) CJK COMPATIBILITY IDEOGRAPH-2F9CE → CJK UNIFIED IDEOGRAPH-46C7	# 

			{ L"\x0002\xF9CF",L"\x8AA0" }, //( 誠 → 誠 ) CJK COMPATIBILITY IDEOGRAPH-2F9CF → CJK UNIFIED IDEOGRAPH-8AA0	# 

			{ L"\xF96F",L"\x8AAA" }, //( 說 → 說 ) CJK COMPATIBILITY IDEOGRAPH-F96F → CJK UNIFIED IDEOGRAPH-8AAA	# 
			{ L"\xF9A1",L"\x8AAA" }, //( 說 → 說 ) CJK COMPATIBILITY IDEOGRAPH-F9A1 → CJK UNIFIED IDEOGRAPH-8AAA	# 

			{ L"\xFAB9",L"\x8ABF" }, //( 調 → 調 ) CJK COMPATIBILITY IDEOGRAPH-FAB9 → CJK UNIFIED IDEOGRAPH-8ABF	# 

			{ L"\xFABB",L"\x8ACB" }, //( 請 → 請 ) CJK COMPATIBILITY IDEOGRAPH-FABB → CJK UNIFIED IDEOGRAPH-8ACB	# 

			{ L"\xF97D",L"\x8AD2" }, //( 諒 → 諒 ) CJK COMPATIBILITY IDEOGRAPH-F97D → CJK UNIFIED IDEOGRAPH-8AD2	# 

			{ L"\xF941",L"\x8AD6" }, //( 論 → 論 ) CJK COMPATIBILITY IDEOGRAPH-F941 → CJK UNIFIED IDEOGRAPH-8AD6	# 

			{ L"\xFABE",L"\x8AED" }, //( 諭 → 諭 ) CJK COMPATIBILITY IDEOGRAPH-FABE → CJK UNIFIED IDEOGRAPH-8AED	# 
			{ L"\x0002\xF9D0",L"\x8AED" }, //( 諭 → 諭 ) CJK COMPATIBILITY IDEOGRAPH-2F9D0 → CJK UNIFIED IDEOGRAPH-8AED	# 

			{ L"\xFA22",L"\x8AF8" }, //( 諸 → 諸 ) CJK COMPATIBILITY IDEOGRAPH-FA22 → CJK UNIFIED IDEOGRAPH-8AF8	# 
			{ L"\xFABA",L"\x8AF8" }, //( 諸 → 諸 ) CJK COMPATIBILITY IDEOGRAPH-FABA → CJK UNIFIED IDEOGRAPH-8AF8	# 

			{ L"\xF95D",L"\x8AFE" }, //( 諾 → 諾 ) CJK COMPATIBILITY IDEOGRAPH-F95D → CJK UNIFIED IDEOGRAPH-8AFE	# 
			{ L"\xFABD",L"\x8AFE" }, //( 諾 → 諾 ) CJK COMPATIBILITY IDEOGRAPH-FABD → CJK UNIFIED IDEOGRAPH-8AFE	# 

			{ L"\xFA62",L"\x8B01" }, //( 謁 → 謁 ) CJK COMPATIBILITY IDEOGRAPH-FA62 → CJK UNIFIED IDEOGRAPH-8B01	# 
			{ L"\xFABC",L"\x8B01" }, //( 謁 → 謁 ) CJK COMPATIBILITY IDEOGRAPH-FABC → CJK UNIFIED IDEOGRAPH-8B01	# 

			{ L"\xFA63",L"\x8B39" }, //( 謹 → 謹 ) CJK COMPATIBILITY IDEOGRAPH-FA63 → CJK UNIFIED IDEOGRAPH-8B39	# 
			{ L"\xFABF",L"\x8B39" }, //( 謹 → 謹 ) CJK COMPATIBILITY IDEOGRAPH-FABF → CJK UNIFIED IDEOGRAPH-8B39	# 

			{ L"\xF9FC",L"\x8B58" }, //( 識 → 識 ) CJK COMPATIBILITY IDEOGRAPH-F9FC → CJK UNIFIED IDEOGRAPH-8B58	# 

			{ L"\xF95A",L"\x8B80" }, //( 讀 → 讀 ) CJK COMPATIBILITY IDEOGRAPH-F95A → CJK UNIFIED IDEOGRAPH-8B80	# 

			{ L"\x8B8F",L"\x8B86" }, //( 讏 → 讆 ) CJK UNIFIED IDEOGRAPH-8B8F → CJK UNIFIED IDEOGRAPH-8B86	# 

			{ L"\xFAC0",L"\x8B8A" }, //( 變 → 變 ) CJK COMPATIBILITY IDEOGRAPH-FAC0 → CJK UNIFIED IDEOGRAPH-8B8A	# 
			{ L"\x0002\xF9D1",L"\x8B8A" }, //( 變 → 變 ) CJK COMPATIBILITY IDEOGRAPH-2F9D1 → CJK UNIFIED IDEOGRAPH-8B8A	# 

			{ L"\x2EC8",L"\x8BA0" }, //( ⻈ → 讠 ) CJK RADICAL C-SIMPLIFIED SPEECH → CJK UNIFIED IDEOGRAPH-8BA0	# 

			{ L"\x2F95",L"\x8C37" }, //( ⾕ → 谷 ) KANGXI RADICAL VALLEY → CJK UNIFIED IDEOGRAPH-8C37	# 

			{ L"\x2F96",L"\x8C46" }, //( ⾖ → 豆 ) KANGXI RADICAL BEAN → CJK UNIFIED IDEOGRAPH-8C46	# 

			{ L"\xF900",L"\x8C48" }, //( 豈 → 豈 ) CJK COMPATIBILITY IDEOGRAPH-F900 → CJK UNIFIED IDEOGRAPH-8C48	# 

			{ L"\x0002\xF9D2",L"\x8C55" }, //( 豕 → 豕 ) CJK COMPATIBILITY IDEOGRAPH-2F9D2 → CJK UNIFIED IDEOGRAPH-8C55	# 
			{ L"\x2F97",L"\x8C55" }, //( ⾗ → 豕 ) KANGXI RADICAL PIG → CJK UNIFIED IDEOGRAPH-8C55	# 

			{ L"\x8C63",L"\x8C5C" }, //( 豣 → 豜 ) CJK UNIFIED IDEOGRAPH-8C63 → CJK UNIFIED IDEOGRAPH-8C5C	# 

			{ L"\x2F98",L"\x8C78" }, //( ⾘ → 豸 ) KANGXI RADICAL BADGER → CJK UNIFIED IDEOGRAPH-8C78	# 

			{ L"\x0002\xF9D3",L"\x0002\x7CA8" }, //( 𧲨 → 𧲨 ) CJK COMPATIBILITY IDEOGRAPH-2F9D3 → CJK UNIFIED IDEOGRAPH-27CA8	# 

			{ L"\x2F99",L"\x8C9D" }, //( ⾙ → 貝 ) KANGXI RADICAL SHELL → CJK UNIFIED IDEOGRAPH-8C9D	# 

			{ L"\x0002\xF9D4",L"\x8CAB" }, //( 貫 → 貫 ) CJK COMPATIBILITY IDEOGRAPH-2F9D4 → CJK UNIFIED IDEOGRAPH-8CAB	# 

			{ L"\x0002\xF9D5",L"\x8CC1" }, //( 賁 → 賁 ) CJK COMPATIBILITY IDEOGRAPH-2F9D5 → CJK UNIFIED IDEOGRAPH-8CC1	# 

			{ L"\xF948",L"\x8CC2" }, //( 賂 → 賂 ) CJK COMPATIBILITY IDEOGRAPH-F948 → CJK UNIFIED IDEOGRAPH-8CC2	# 

			{ L"\xF903",L"\x8CC8" }, //( 賈 → 賈 ) CJK COMPATIBILITY IDEOGRAPH-F903 → CJK UNIFIED IDEOGRAPH-8CC8	# 

			{ L"\xFA64",L"\x8CD3" }, //( 賓 → 賓 ) CJK COMPATIBILITY IDEOGRAPH-FA64 → CJK UNIFIED IDEOGRAPH-8CD3	# 

			{ L"\xFA65",L"\x8D08" }, //( 贈 → 贈 ) CJK COMPATIBILITY IDEOGRAPH-FA65 → CJK UNIFIED IDEOGRAPH-8D08	# 
			{ L"\xFAC1",L"\x8D08" }, //( 贈 → 贈 ) CJK COMPATIBILITY IDEOGRAPH-FAC1 → CJK UNIFIED IDEOGRAPH-8D08	# 

			{ L"\x0002\xF9D6",L"\x8D1B" }, //( 贛 → 贛 ) CJK COMPATIBILITY IDEOGRAPH-2F9D6 → CJK UNIFIED IDEOGRAPH-8D1B	# 

			{ L"\x2EC9",L"\x8D1D" }, //( ⻉ → 贝 ) CJK RADICAL C-SIMPLIFIED SHELL → CJK UNIFIED IDEOGRAPH-8D1D	# 

			{ L"\x2F9A",L"\x8D64" }, //( ⾚ → 赤 ) KANGXI RADICAL RED → CJK UNIFIED IDEOGRAPH-8D64	# 

			{ L"\x2F9B",L"\x8D70" }, //( ⾛ → 走 ) KANGXI RADICAL RUN → CJK UNIFIED IDEOGRAPH-8D70	# 

			{ L"\x0002\xF9D7",L"\x8D77" }, //( 起 → 起 ) CJK COMPATIBILITY IDEOGRAPH-2F9D7 → CJK UNIFIED IDEOGRAPH-8D77	# 

			{ L"\x8D86",L"\x8D7F" }, //( 趆 → 赿 ) CJK UNIFIED IDEOGRAPH-8D86 → CJK UNIFIED IDEOGRAPH-8D7F	# 

			{ L"\xFAD7",L"\x0002\x7ED3" }, //( 𧻓 → 𧻓 ) CJK COMPATIBILITY IDEOGRAPH-FAD7 → CJK UNIFIED IDEOGRAPH-27ED3	# 

			{ L"\x0002\xF9D8",L"\x0002\x7F2F" }, //( 𧼯 → 𧼯 ) CJK COMPATIBILITY IDEOGRAPH-2F9D8 → CJK UNIFIED IDEOGRAPH-27F2F	# 

			{ L"\x2F9C",L"\x8DB3" }, //( ⾜ → 足 ) KANGXI RADICAL FOOT → CJK UNIFIED IDEOGRAPH-8DB3	# 

			{ L"\x0002\xF9DA",L"\x8DCB" }, //( 跋 → 跋 ) CJK COMPATIBILITY IDEOGRAPH-2F9DA → CJK UNIFIED IDEOGRAPH-8DCB	# 

			{ L"\x0002\xF9DB",L"\x8DBC" }, //( 趼 → 趼 ) CJK COMPATIBILITY IDEOGRAPH-2F9DB → CJK UNIFIED IDEOGRAPH-8DBC	# 

			{ L"\x8DFA",L"\x8DE5" }, //( 跺 → 跥 ) CJK UNIFIED IDEOGRAPH-8DFA → CJK UNIFIED IDEOGRAPH-8DE5	# 

			{ L"\xF937",L"\x8DEF" }, //( 路 → 路 ) CJK COMPATIBILITY IDEOGRAPH-F937 → CJK UNIFIED IDEOGRAPH-8DEF	# 

			{ L"\x0002\xF9DC",L"\x8DF0" }, //( 跰 → 跰 ) CJK COMPATIBILITY IDEOGRAPH-2F9DC → CJK UNIFIED IDEOGRAPH-8DF0	# 

			{ L"\x8E9B",L"\x8E97" }, //( 躛 → 躗 ) CJK UNIFIED IDEOGRAPH-8E9B → CJK UNIFIED IDEOGRAPH-8E97	# 

			{ L"\x2F9D",L"\x8EAB" }, //( ⾝ → 身 ) KANGXI RADICAL BODY → CJK UNIFIED IDEOGRAPH-8EAB	# 

			{ L"\xF902",L"\x8ECA" }, //( 車 → 車 ) CJK COMPATIBILITY IDEOGRAPH-F902 → CJK UNIFIED IDEOGRAPH-8ECA	# 
			{ L"\x2F9E",L"\x8ECA" }, //( ⾞ → 車 ) KANGXI RADICAL CART → CJK UNIFIED IDEOGRAPH-8ECA	# 

			{ L"\x0002\xF9DE",L"\x8ED4" }, //( 軔 → 軔 ) CJK COMPATIBILITY IDEOGRAPH-2F9DE → CJK UNIFIED IDEOGRAPH-8ED4	# 

			{ L"\x8F27",L"\x8EFF" }, //( 輧 → 軿 ) CJK UNIFIED IDEOGRAPH-8F27 → CJK UNIFIED IDEOGRAPH-8EFF	# 

			{ L"\xF998",L"\x8F26" }, //( 輦 → 輦 ) CJK COMPATIBILITY IDEOGRAPH-F998 → CJK UNIFIED IDEOGRAPH-8F26	# 

			{ L"\xF9D7",L"\x8F2A" }, //( 輪 → 輪 ) CJK COMPATIBILITY IDEOGRAPH-F9D7 → CJK UNIFIED IDEOGRAPH-8F2A	# 

			{ L"\xFAC2",L"\x8F38" }, //( 輸 → 輸 ) CJK COMPATIBILITY IDEOGRAPH-FAC2 → CJK UNIFIED IDEOGRAPH-8F38	# 
			{ L"\x0002\xF9DF",L"\x8F38" }, //( 輸 → 輸 ) CJK COMPATIBILITY IDEOGRAPH-2F9DF → CJK UNIFIED IDEOGRAPH-8F38	# 

			{ L"\xFA07",L"\x8F3B" }, //( 輻 → 輻 ) CJK COMPATIBILITY IDEOGRAPH-FA07 → CJK UNIFIED IDEOGRAPH-8F3B	# 

			{ L"\xF98D",L"\x8F62" }, //( 轢 → 轢 ) CJK COMPATIBILITY IDEOGRAPH-F98D → CJK UNIFIED IDEOGRAPH-8F62	# 

			{ L"\x2ECB",L"\x8F66" }, //( ⻋ → 车 ) CJK RADICAL C-SIMPLIFIED CART → CJK UNIFIED IDEOGRAPH-8F66	# 

			{ L"\x2F9F",L"\x8F9B" }, //( ⾟ → 辛 ) KANGXI RADICAL BITTER → CJK UNIFIED IDEOGRAPH-8F9B	# 

			{ L"\x0002\xF98D",L"\x8F9E" }, //( 辞 → 辞 ) CJK COMPATIBILITY IDEOGRAPH-2F98D → CJK UNIFIED IDEOGRAPH-8F9E	# 

			{ L"\xF971",L"\x8FB0" }, //( 辰 → 辰 ) CJK COMPATIBILITY IDEOGRAPH-F971 → CJK UNIFIED IDEOGRAPH-8FB0	# 
			{ L"\x2FA0",L"\x8FB0" }, //( ⾠ → 辰 ) KANGXI RADICAL MORNING → CJK UNIFIED IDEOGRAPH-8FB0	# 

			{ L"\x2FA1",L"\x8FB5" }, //( ⾡ → 辵 ) KANGXI RADICAL WALK → CJK UNIFIED IDEOGRAPH-8FB5	# 

			{ L"\xFA66",L"\x8FB6" }, //( 辶 → 辶 ) CJK COMPATIBILITY IDEOGRAPH-FA66 → CJK UNIFIED IDEOGRAPH-8FB6	# 
			{ L"\x2ECC",L"\x8FB6" }, //( ⻌ → 辶 ) CJK RADICAL SIMPLIFIED WALK → CJK UNIFIED IDEOGRAPH-8FB6	# 
			{ L"\x2ECD",L"\x8FB6" }, //( ⻍ → 辶 ) CJK RADICAL WALK ONE → CJK UNIFIED IDEOGRAPH-8FB6	# 

			{ L"\x0002\xF881",L"\x5DE1" }, //( 巡 → 巡 ) CJK COMPATIBILITY IDEOGRAPH-2F881 → CJK UNIFIED IDEOGRAPH-5DE1	# 

			{ L"\xF99A",L"\x9023" }, //( 連 → 連 ) CJK COMPATIBILITY IDEOGRAPH-F99A → CJK UNIFIED IDEOGRAPH-9023	# 

			{ L"\xFA25",L"\x9038" }, //( 逸 → 逸 ) CJK COMPATIBILITY IDEOGRAPH-FA25 → CJK UNIFIED IDEOGRAPH-9038	# 
			{ L"\xFA67",L"\x9038" }, //( 逸 → 逸 ) CJK COMPATIBILITY IDEOGRAPH-FA67 → CJK UNIFIED IDEOGRAPH-9038	# 

			{ L"\xFAC3",L"\x9072" }, //( 遲 → 遲 ) CJK COMPATIBILITY IDEOGRAPH-FAC3 → CJK UNIFIED IDEOGRAPH-9072	# 

			{ L"\xF9C3",L"\x907C" }, //( 遼 → 遼 ) CJK COMPATIBILITY IDEOGRAPH-F9C3 → CJK UNIFIED IDEOGRAPH-907C	# 

			{ L"\x0002\xF9E0",L"\x0002\x85D2" }, //( 𨗒 → 𨗒 ) CJK COMPATIBILITY IDEOGRAPH-2F9E0 → CJK UNIFIED IDEOGRAPH-285D2	# 

			{ L"\x0002\xF9E1",L"\x0002\x85ED" }, //( 𨗭 → 𨗭 ) CJK COMPATIBILITY IDEOGRAPH-2F9E1 → CJK UNIFIED IDEOGRAPH-285ED	# 

			{ L"\xF913",L"\x908F" }, //( 邏 → 邏 ) CJK COMPATIBILITY IDEOGRAPH-F913 → CJK UNIFIED IDEOGRAPH-908F	# 

			{ L"\x2FA2",L"\x9091" }, //( ⾢ → 邑 ) KANGXI RADICAL CITY → CJK UNIFIED IDEOGRAPH-9091	# 

			{ L"\x0002\xF9E2",L"\x9094" }, //( 邔 → 邔 ) CJK COMPATIBILITY IDEOGRAPH-2F9E2 → CJK UNIFIED IDEOGRAPH-9094	# 

			{ L"\xF92C",L"\x90CE" }, //( 郎 → 郎 ) CJK COMPATIBILITY IDEOGRAPH-F92C → CJK UNIFIED IDEOGRAPH-90CE	# 
			{ L"\x90DE",L"\x90CE" }, //( 郞 → 郎 ) CJK UNIFIED IDEOGRAPH-90DE → CJK UNIFIED IDEOGRAPH-90CE	# →郎→
			{ L"\xFA2E",L"\x90CE" }, //( 郞 → 郎 ) CJK COMPATIBILITY IDEOGRAPH-FA2E → CJK UNIFIED IDEOGRAPH-90CE	# →郞→→郎→

			{ L"\x0002\xF9E3",L"\x90F1" }, //( 郱 → 郱 ) CJK COMPATIBILITY IDEOGRAPH-2F9E3 → CJK UNIFIED IDEOGRAPH-90F1	# 

			{ L"\xFA26",L"\x90FD" }, //( 都 → 都 ) CJK COMPATIBILITY IDEOGRAPH-FA26 → CJK UNIFIED IDEOGRAPH-90FD	# 

			{ L"\x0002\xF9E5",L"\x0002\x872E" }, //( 𨜮 → 𨜮 ) CJK COMPATIBILITY IDEOGRAPH-2F9E5 → CJK UNIFIED IDEOGRAPH-2872E	# 

			{ L"\x0002\xF9E4",L"\x9111" }, //( 鄑 → 鄑 ) CJK COMPATIBILITY IDEOGRAPH-2F9E4 → CJK UNIFIED IDEOGRAPH-9111	# 

			{ L"\x0002\xF9E6",L"\x911B" }, //( 鄛 → 鄛 ) CJK COMPATIBILITY IDEOGRAPH-2F9E6 → CJK UNIFIED IDEOGRAPH-911B	# 

			{ L"\x2FA3",L"\x9149" }, //( ⾣ → 酉 ) KANGXI RADICAL WINE → CJK UNIFIED IDEOGRAPH-9149	# 

			{ L"\xF919",L"\x916A" }, //( 酪 → 酪 ) CJK COMPATIBILITY IDEOGRAPH-F919 → CJK UNIFIED IDEOGRAPH-916A	# 

			{ L"\xFAC4",L"\x9199" }, //( 醙 → 醙 ) CJK COMPATIBILITY IDEOGRAPH-FAC4 → CJK UNIFIED IDEOGRAPH-9199	# 

			{ L"\xF9B7",L"\x91B4" }, //( 醴 → 醴 ) CJK COMPATIBILITY IDEOGRAPH-F9B7 → CJK UNIFIED IDEOGRAPH-91B4	# 

			{ L"\x2FA4",L"\x91C6" }, //( ⾤ → 釆 ) KANGXI RADICAL DISTINGUISH → CJK UNIFIED IDEOGRAPH-91C6	# 

			{ L"\xF9E9",L"\x91CC" }, //( 里 → 里 ) CJK COMPATIBILITY IDEOGRAPH-F9E9 → CJK UNIFIED IDEOGRAPH-91CC	# 
			{ L"\x2FA5",L"\x91CC" }, //( ⾥ → 里 ) KANGXI RADICAL VILLAGE → CJK UNIFIED IDEOGRAPH-91CC	# 

			{ L"\xF97E",L"\x91CF" }, //( 量 → 量 ) CJK COMPATIBILITY IDEOGRAPH-F97E → CJK UNIFIED IDEOGRAPH-91CF	# 

			{ L"\xF90A",L"\x91D1" }, //( 金 → 金 ) CJK COMPATIBILITY IDEOGRAPH-F90A → CJK UNIFIED IDEOGRAPH-91D1	# 
			{ L"\x2FA6",L"\x91D1" }, //( ⾦ → 金 ) KANGXI RADICAL GOLD → CJK UNIFIED IDEOGRAPH-91D1	# 

			{ L"\xF9B1",L"\x9234" }, //( 鈴 → 鈴 ) CJK COMPATIBILITY IDEOGRAPH-F9B1 → CJK UNIFIED IDEOGRAPH-9234	# 

			{ L"\x0002\xF9E7",L"\x9238" }, //( 鈸 → 鈸 ) CJK COMPATIBILITY IDEOGRAPH-2F9E7 → CJK UNIFIED IDEOGRAPH-9238	# 

			{ L"\xFAC5",L"\x9276" }, //( 鉶 → 鉶 ) CJK COMPATIBILITY IDEOGRAPH-FAC5 → CJK UNIFIED IDEOGRAPH-9276	# 

			{ L"\x0002\xF9E8",L"\x92D7" }, //( 鋗 → 鋗 ) CJK COMPATIBILITY IDEOGRAPH-2F9E8 → CJK UNIFIED IDEOGRAPH-92D7	# 

			{ L"\x0002\xF9E9",L"\x92D8" }, //( 鋘 → 鋘 ) CJK COMPATIBILITY IDEOGRAPH-2F9E9 → CJK UNIFIED IDEOGRAPH-92D8	# 

			{ L"\x0002\xF9EA",L"\x927C" }, //( 鉼 → 鉼 ) CJK COMPATIBILITY IDEOGRAPH-2F9EA → CJK UNIFIED IDEOGRAPH-927C	# 

			{ L"\xF93F",L"\x9304" }, //( 錄 → 錄 ) CJK COMPATIBILITY IDEOGRAPH-F93F → CJK UNIFIED IDEOGRAPH-9304	# 

			{ L"\xF99B",L"\x934A" }, //( 鍊 → 鍊 ) CJK COMPATIBILITY IDEOGRAPH-F99B → CJK UNIFIED IDEOGRAPH-934A	# 

			{ L"\x93AE",L"\x93AD" }, //( 鎮 → 鎭 ) CJK UNIFIED IDEOGRAPH-93AE → CJK UNIFIED IDEOGRAPH-93AD	# 

			{ L"\x0002\xF9EB",L"\x93F9" }, //( 鏹 → 鏹 ) CJK COMPATIBILITY IDEOGRAPH-2F9EB → CJK UNIFIED IDEOGRAPH-93F9	# 

			{ L"\x0002\xF9EC",L"\x9415" }, //( 鐕 → 鐕 ) CJK COMPATIBILITY IDEOGRAPH-2F9EC → CJK UNIFIED IDEOGRAPH-9415	# 

			{ L"\x0002\xF9ED",L"\x0002\x8BFA" }, //( 𨯺 → 𨯺 ) CJK COMPATIBILITY IDEOGRAPH-2F9ED → CJK UNIFIED IDEOGRAPH-28BFA	# 

			{ L"\x2ED0",L"\x9485" }, //( ⻐ → 钅 ) CJK RADICAL C-SIMPLIFIED GOLD → CJK UNIFIED IDEOGRAPH-9485	# 

			{ L"\x2ED1",L"\x9577" }, //( ⻑ → 長 ) CJK RADICAL LONG ONE → CJK UNIFIED IDEOGRAPH-9577	# 
			{ L"\x2FA7",L"\x9577" }, //( ⾧ → 長 ) KANGXI RADICAL LONG → CJK UNIFIED IDEOGRAPH-9577	# 

			{ L"\x2ED2",L"\x9578" }, //( ⻒ → 镸 ) CJK RADICAL LONG TWO → CJK UNIFIED IDEOGRAPH-9578	# 

			{ L"\x2ED3",L"\x957F" }, //( ⻓ → 长 ) CJK RADICAL C-SIMPLIFIED LONG → CJK UNIFIED IDEOGRAPH-957F	# 

			{ L"\x2FA8",L"\x9580" }, //( ⾨ → 門 ) KANGXI RADICAL GATE → CJK UNIFIED IDEOGRAPH-9580	# 

			{ L"\x0002\xF9EE",L"\x958B" }, //( 開 → 開 ) CJK COMPATIBILITY IDEOGRAPH-2F9EE → CJK UNIFIED IDEOGRAPH-958B	# 

			{ L"\x0002\xF9EF",L"\x4995" }, //( 䦕 → 䦕 ) CJK COMPATIBILITY IDEOGRAPH-2F9EF → CJK UNIFIED IDEOGRAPH-4995	# 

			{ L"\xF986",L"\x95AD" }, //( 閭 → 閭 ) CJK COMPATIBILITY IDEOGRAPH-F986 → CJK UNIFIED IDEOGRAPH-95AD	# 

			{ L"\x0002\xF9F0",L"\x95B7" }, //( 閷 → 閷 ) CJK COMPATIBILITY IDEOGRAPH-2F9F0 → CJK UNIFIED IDEOGRAPH-95B7	# 

			{ L"\x0002\xF9F1",L"\x0002\x8D77" }, //( 𨵷 → 𨵷 ) CJK COMPATIBILITY IDEOGRAPH-2F9F1 → CJK UNIFIED IDEOGRAPH-28D77	# 

			{ L"\x2ED4",L"\x95E8" }, //( ⻔ → 门 ) CJK RADICAL C-SIMPLIFIED GATE → CJK UNIFIED IDEOGRAPH-95E8	# 

			{ L"\x2FA9",L"\x961C" }, //( ⾩ → 阜 ) KANGXI RADICAL MOUND → CJK UNIFIED IDEOGRAPH-961C	# 

			{ L"\x2ECF",L"\x961D" }, //( ⻏ → 阝 ) CJK RADICAL CITY → CJK UNIFIED IDEOGRAPH-961D	# 
			{ L"\x2ED6",L"\x961D" }, //( ⻖ → 阝 ) CJK RADICAL MOUND TWO → CJK UNIFIED IDEOGRAPH-961D	# 

			{ L"\xF9C6",L"\x962E" }, //( 阮 → 阮 ) CJK COMPATIBILITY IDEOGRAPH-F9C6 → CJK UNIFIED IDEOGRAPH-962E	# 

			{ L"\xF951",L"\x964B" }, //( 陋 → 陋 ) CJK COMPATIBILITY IDEOGRAPH-F951 → CJK UNIFIED IDEOGRAPH-964B	# 

			{ L"\xFA09",L"\x964D" }, //( 降 → 降 ) CJK COMPATIBILITY IDEOGRAPH-FA09 → CJK UNIFIED IDEOGRAPH-964D	# 

			{ L"\xF959",L"\x9675" }, //( 陵 → 陵 ) CJK COMPATIBILITY IDEOGRAPH-F959 → CJK UNIFIED IDEOGRAPH-9675	# 

			{ L"\xF9D3",L"\x9678" }, //( 陸 → 陸 ) CJK COMPATIBILITY IDEOGRAPH-F9D3 → CJK UNIFIED IDEOGRAPH-9678	# 

			{ L"\xFAC6",L"\x967C" }, //( 陼 → 陼 ) CJK COMPATIBILITY IDEOGRAPH-FAC6 → CJK UNIFIED IDEOGRAPH-967C	# 

			{ L"\xF9DC",L"\x9686" }, //( 隆 → 隆 ) CJK COMPATIBILITY IDEOGRAPH-F9DC → CJK UNIFIED IDEOGRAPH-9686	# 

			{ L"\xF9F1",L"\x96A3" }, //( 隣 → 隣 ) CJK COMPATIBILITY IDEOGRAPH-F9F1 → CJK UNIFIED IDEOGRAPH-96A3	# 

			{ L"\x0002\xF9F2",L"\x49E6" }, //( 䧦 → 䧦 ) CJK COMPATIBILITY IDEOGRAPH-2F9F2 → CJK UNIFIED IDEOGRAPH-49E6	# 

			{ L"\x2FAA",L"\x96B6" }, //( ⾪ → 隶 ) KANGXI RADICAL SLAVE → CJK UNIFIED IDEOGRAPH-96B6	# 

			{ L"\xFA2F",L"\x96B7" }, //( 隷 → 隷 ) CJK COMPATIBILITY IDEOGRAPH-FA2F → CJK UNIFIED IDEOGRAPH-96B7	# 
			{ L"\x96B8",L"\x96B7" }, //( 隸 → 隷 ) CJK UNIFIED IDEOGRAPH-96B8 → CJK UNIFIED IDEOGRAPH-96B7	# →隸→
			{ L"\xF9B8",L"\x96B7" }, //( 隸 → 隷 ) CJK COMPATIBILITY IDEOGRAPH-F9B8 → CJK UNIFIED IDEOGRAPH-96B7	# 

			{ L"\x2FAB",L"\x96B9" }, //( ⾫ → 隹 ) KANGXI RADICAL SHORT TAILED BIRD → CJK UNIFIED IDEOGRAPH-96B9	# 

			{ L"\x0002\xF9F3",L"\x96C3" }, //( 雃 → 雃 ) CJK COMPATIBILITY IDEOGRAPH-2F9F3 → CJK UNIFIED IDEOGRAPH-96C3	# 

			{ L"\xF9EA",L"\x96E2" }, //( 離 → 離 ) CJK COMPATIBILITY IDEOGRAPH-F9EA → CJK UNIFIED IDEOGRAPH-96E2	# 

			{ L"\xFA68",L"\x96E3" }, //( 難 → 難 ) CJK COMPATIBILITY IDEOGRAPH-FA68 → CJK UNIFIED IDEOGRAPH-96E3	# 
			{ L"\xFAC7",L"\x96E3" }, //( 難 → 難 ) CJK COMPATIBILITY IDEOGRAPH-FAC7 → CJK UNIFIED IDEOGRAPH-96E3	# 

			{ L"\x2FAC",L"\x96E8" }, //( ⾬ → 雨 ) KANGXI RADICAL RAIN → CJK UNIFIED IDEOGRAPH-96E8	# 

			{ L"\xF9B2",L"\x96F6" }, //( 零 → 零 ) CJK COMPATIBILITY IDEOGRAPH-F9B2 → CJK UNIFIED IDEOGRAPH-96F6	# 

			{ L"\xF949",L"\x96F7" }, //( 雷 → 雷 ) CJK COMPATIBILITY IDEOGRAPH-F949 → CJK UNIFIED IDEOGRAPH-96F7	# 

			{ L"\x0002\xF9F5",L"\x9723" }, //( 霣 → 霣 ) CJK COMPATIBILITY IDEOGRAPH-2F9F5 → CJK UNIFIED IDEOGRAPH-9723	# 

			{ L"\x0002\xF9F6",L"\x0002\x9145" }, //( 𩅅 → 𩅅 ) CJK COMPATIBILITY IDEOGRAPH-2F9F6 → CJK UNIFIED IDEOGRAPH-29145	# 

			{ L"\xF938",L"\x9732" }, //( 露 → 露 ) CJK COMPATIBILITY IDEOGRAPH-F938 → CJK UNIFIED IDEOGRAPH-9732	# 

			{ L"\xF9B3",L"\x9748" }, //( 靈 → 靈 ) CJK COMPATIBILITY IDEOGRAPH-F9B3 → CJK UNIFIED IDEOGRAPH-9748	# 

			{ L"\x2FAD",L"\x9751" }, //( ⾭ → 靑 ) KANGXI RADICAL BLUE → CJK UNIFIED IDEOGRAPH-9751	# 

			{ L"\x2ED8",L"\x9752" }, //( ⻘ → 青 ) CJK RADICAL BLUE → CJK UNIFIED IDEOGRAPH-9752	# 

			{ L"\xFA1C",L"\x9756" }, //( 靖 → 靖 ) CJK COMPATIBILITY IDEOGRAPH-FA1C → CJK UNIFIED IDEOGRAPH-9756	# 
			{ L"\xFAC8",L"\x9756" }, //( 靖 → 靖 ) CJK COMPATIBILITY IDEOGRAPH-FAC8 → CJK UNIFIED IDEOGRAPH-9756	# 

			{ L"\x0002\xF81C",L"\x0002\x91DF" }, //( 𩇟 → 𩇟 ) CJK COMPATIBILITY IDEOGRAPH-2F81C → CJK UNIFIED IDEOGRAPH-291DF	# 

			{ L"\x2FAE",L"\x975E" }, //( ⾮ → 非 ) KANGXI RADICAL WRONG → CJK UNIFIED IDEOGRAPH-975E	# 

			{ L"\x2FAF",L"\x9762" }, //( ⾯ → 面 ) KANGXI RADICAL FACE → CJK UNIFIED IDEOGRAPH-9762	# 

			{ L"\x0002\xF9F7",L"\x0002\x921A" }, //( 𩈚 → 𩈚 ) CJK COMPATIBILITY IDEOGRAPH-2F9F7 → CJK UNIFIED IDEOGRAPH-2921A	# 

			{ L"\x2FB0",L"\x9769" }, //( ⾰ → 革 ) KANGXI RADICAL LEATHER → CJK UNIFIED IDEOGRAPH-9769	# 

			{ L"\x0002\xF9F8",L"\x4A6E" }, //( 䩮 → 䩮 ) CJK COMPATIBILITY IDEOGRAPH-2F9F8 → CJK UNIFIED IDEOGRAPH-4A6E	# 

			{ L"\x0002\xF9F9",L"\x4A76" }, //( 䩶 → 䩶 ) CJK COMPATIBILITY IDEOGRAPH-2F9F9 → CJK UNIFIED IDEOGRAPH-4A76	# 

			{ L"\x2FB1",L"\x97CB" }, //( ⾱ → 韋 ) KANGXI RADICAL TANNED LEATHER → CJK UNIFIED IDEOGRAPH-97CB	# 

			{ L"\xFAC9",L"\x97DB" }, //( 韛 → 韛 ) CJK COMPATIBILITY IDEOGRAPH-FAC9 → CJK UNIFIED IDEOGRAPH-97DB	# 

			{ L"\x0002\xF9FA",L"\x97E0" }, //( 韠 → 韠 ) CJK COMPATIBILITY IDEOGRAPH-2F9FA → CJK UNIFIED IDEOGRAPH-97E0	# 

			{ L"\x2ED9",L"\x97E6" }, //( ⻙ → 韦 ) CJK RADICAL C-SIMPLIFIED TANNED LEATHER → CJK UNIFIED IDEOGRAPH-97E6	# 

			{ L"\x2FB2",L"\x97ED" }, //( ⾲ → 韭 ) KANGXI RADICAL LEEK → CJK UNIFIED IDEOGRAPH-97ED	# 

			{ L"\x0002\xF9FB",L"\x0002\x940A" }, //( 𩐊 → 𩐊 ) CJK COMPATIBILITY IDEOGRAPH-2F9FB → CJK UNIFIED IDEOGRAPH-2940A	# 

			{ L"\x2FB3",L"\x97F3" }, //( ⾳ → 音 ) KANGXI RADICAL SOUND → CJK UNIFIED IDEOGRAPH-97F3	# 

			{ L"\xFA69",L"\x97FF" }, //( 響 → 響 ) CJK COMPATIBILITY IDEOGRAPH-FA69 → CJK UNIFIED IDEOGRAPH-97FF	# 
			{ L"\xFACA",L"\x97FF" }, //( 響 → 響 ) CJK COMPATIBILITY IDEOGRAPH-FACA → CJK UNIFIED IDEOGRAPH-97FF	# 

			{ L"\x2FB4",L"\x9801" }, //( ⾴ → 頁 ) KANGXI RADICAL LEAF → CJK UNIFIED IDEOGRAPH-9801	# 

			{ L"\x0002\xF9FC",L"\x4AB2" }, //( 䪲 → 䪲 ) CJK COMPATIBILITY IDEOGRAPH-2F9FC → CJK UNIFIED IDEOGRAPH-4AB2	# 

			{ L"\xFACB",L"\x980B" }, //( 頋 → 頋 ) CJK COMPATIBILITY IDEOGRAPH-FACB → CJK UNIFIED IDEOGRAPH-980B	# 
			{ L"\x0002\xF9FE",L"\x980B" }, //( 頋 → 頋 ) CJK COMPATIBILITY IDEOGRAPH-2F9FE → CJK UNIFIED IDEOGRAPH-980B	# 
			{ L"\x0002\xF9FF",L"\x980B" }, //( 頋 → 頋 ) CJK COMPATIBILITY IDEOGRAPH-2F9FF → CJK UNIFIED IDEOGRAPH-980B	# 

			{ L"\xF9B4",L"\x9818" }, //( 領 → 領 ) CJK COMPATIBILITY IDEOGRAPH-F9B4 → CJK UNIFIED IDEOGRAPH-9818	# 

			{ L"\x0002\xFA00",L"\x9829" }, //( 頩 → 頩 ) CJK COMPATIBILITY IDEOGRAPH-2FA00 → CJK UNIFIED IDEOGRAPH-9829	# 

			{ L"\x0002\xF9FD",L"\x0002\x9496" }, //( 𩒖 → 𩒖 ) CJK COMPATIBILITY IDEOGRAPH-2F9FD → CJK UNIFIED IDEOGRAPH-29496	# 

			{ L"\xFA6A",L"\x983B" }, //( 頻 → 頻 ) CJK COMPATIBILITY IDEOGRAPH-FA6A → CJK UNIFIED IDEOGRAPH-983B	# 
			{ L"\xFACC",L"\x983B" }, //( 頻 → 頻 ) CJK COMPATIBILITY IDEOGRAPH-FACC → CJK UNIFIED IDEOGRAPH-983B	# 

			{ L"\xF9D0",L"\x985E" }, //( 類 → 類 ) CJK COMPATIBILITY IDEOGRAPH-F9D0 → CJK UNIFIED IDEOGRAPH-985E	# 

			{ L"\x2EDA",L"\x9875" }, //( ⻚ → 页 ) CJK RADICAL C-SIMPLIFIED LEAF → CJK UNIFIED IDEOGRAPH-9875	# 

			{ L"\x2FB5",L"\x98A8" }, //( ⾵ → 風 ) KANGXI RADICAL WIND → CJK UNIFIED IDEOGRAPH-98A8	# 

			{ L"\x0002\xFA01",L"\x0002\x95B6" }, //( 𩖶 → 𩖶 ) CJK COMPATIBILITY IDEOGRAPH-2FA01 → CJK UNIFIED IDEOGRAPH-295B6	# 

			{ L"\x2EDB",L"\x98CE" }, //( ⻛ → 风 ) CJK RADICAL C-SIMPLIFIED WIND → CJK UNIFIED IDEOGRAPH-98CE	# 

			{ L"\x2FB6",L"\x98DB" }, //( ⾶ → 飛 ) KANGXI RADICAL FLY → CJK UNIFIED IDEOGRAPH-98DB	# 

			{ L"\x2EDC",L"\x98DE" }, //( ⻜ → 飞 ) CJK RADICAL C-SIMPLIFIED FLY → CJK UNIFIED IDEOGRAPH-98DE	# 

			{ L"\x2EDD",L"\x98DF" }, //( ⻝ → 食 ) CJK RADICAL EAT ONE → CJK UNIFIED IDEOGRAPH-98DF	# 
			{ L"\x2FB7",L"\x98DF" }, //( ⾷ → 食 ) KANGXI RADICAL EAT → CJK UNIFIED IDEOGRAPH-98DF	# 

			{ L"\x2EDF",L"\x98E0" }, //( ⻟ → 飠 ) CJK RADICAL EAT THREE → CJK UNIFIED IDEOGRAPH-98E0	# 

			{ L"\x0002\xFA02",L"\x98E2" }, //( 飢 → 飢 ) CJK COMPATIBILITY IDEOGRAPH-2FA02 → CJK UNIFIED IDEOGRAPH-98E2	# 

			{ L"\xFA2A",L"\x98EF" }, //( 飯 → 飯 ) CJK COMPATIBILITY IDEOGRAPH-FA2A → CJK UNIFIED IDEOGRAPH-98EF	# 

			{ L"\xFA2B",L"\x98FC" }, //( 飼 → 飼 ) CJK COMPATIBILITY IDEOGRAPH-FA2B → CJK UNIFIED IDEOGRAPH-98FC	# 

			{ L"\x0002\xFA03",L"\x4B33" }, //( 䬳 → 䬳 ) CJK COMPATIBILITY IDEOGRAPH-2FA03 → CJK UNIFIED IDEOGRAPH-4B33	# 

			{ L"\xFA2C",L"\x9928" }, //( 館 → 館 ) CJK COMPATIBILITY IDEOGRAPH-FA2C → CJK UNIFIED IDEOGRAPH-9928	# 

			{ L"\x0002\xFA04",L"\x9929" }, //( 餩 → 餩 ) CJK COMPATIBILITY IDEOGRAPH-2FA04 → CJK UNIFIED IDEOGRAPH-9929	# 

			{ L"\x2EE0",L"\x9963" }, //( ⻠ → 饣 ) CJK RADICAL C-SIMPLIFIED EAT → CJK UNIFIED IDEOGRAPH-9963	# 

			{ L"\x2FB8",L"\x9996" }, //( ⾸ → 首 ) KANGXI RADICAL HEAD → CJK UNIFIED IDEOGRAPH-9996	# 

			{ L"\x2FB9",L"\x9999" }, //( ⾹ → 香 ) KANGXI RADICAL FRAGRANT → CJK UNIFIED IDEOGRAPH-9999	# 

			{ L"\x0002\xFA05",L"\x99A7" }, //( 馧 → 馧 ) CJK COMPATIBILITY IDEOGRAPH-2FA05 → CJK UNIFIED IDEOGRAPH-99A7	# 

			{ L"\x2FBA",L"\x99AC" }, //( ⾺ → 馬 ) KANGXI RADICAL HORSE → CJK UNIFIED IDEOGRAPH-99AC	# 

			{ L"\x0002\xFA06",L"\x99C2" }, //( 駂 → 駂 ) CJK COMPATIBILITY IDEOGRAPH-2FA06 → CJK UNIFIED IDEOGRAPH-99C2	# 

			{ L"\xF91A",L"\x99F1" }, //( 駱 → 駱 ) CJK COMPATIBILITY IDEOGRAPH-F91A → CJK UNIFIED IDEOGRAPH-99F1	# 

			{ L"\x0002\xFA07",L"\x99FE" }, //( 駾 → 駾 ) CJK COMPATIBILITY IDEOGRAPH-2FA07 → CJK UNIFIED IDEOGRAPH-99FE	# 

			{ L"\xF987",L"\x9A6A" }, //( 驪 → 驪 ) CJK COMPATIBILITY IDEOGRAPH-F987 → CJK UNIFIED IDEOGRAPH-9A6A	# 

			{ L"\x2EE2",L"\x9A6C" }, //( ⻢ → 马 ) CJK RADICAL C-SIMPLIFIED HORSE → CJK UNIFIED IDEOGRAPH-9A6C	# 

			{ L"\x2FBB",L"\x9AA8" }, //( ⾻ → 骨 ) KANGXI RADICAL BONE → CJK UNIFIED IDEOGRAPH-9AA8	# 

			{ L"\x0002\xFA08",L"\x4BCE" }, //( 䯎 → 䯎 ) CJK COMPATIBILITY IDEOGRAPH-2FA08 → CJK UNIFIED IDEOGRAPH-4BCE	# 

			{ L"\x2FBC",L"\x9AD8" }, //( ⾼ → 高 ) KANGXI RADICAL TALL → CJK UNIFIED IDEOGRAPH-9AD8	# 

			{ L"\x2FBD",L"\x9ADF" }, //( ⾽ → 髟 ) KANGXI RADICAL HAIR → CJK UNIFIED IDEOGRAPH-9ADF	# 

			{ L"\x0002\xFA09",L"\x0002\x9B30" }, //( 𩬰 → 𩬰 ) CJK COMPATIBILITY IDEOGRAPH-2FA09 → CJK UNIFIED IDEOGRAPH-29B30	# 

			{ L"\xFACD",L"\x9B12" }, //( 鬒 → 鬒 ) CJK COMPATIBILITY IDEOGRAPH-FACD → CJK UNIFIED IDEOGRAPH-9B12	# 
			{ L"\x0002\xFA0A",L"\x9B12" }, //( 鬒 → 鬒 ) CJK COMPATIBILITY IDEOGRAPH-2FA0A → CJK UNIFIED IDEOGRAPH-9B12	# 

			{ L"\x2FBE",L"\x9B25" }, //( ⾾ → 鬥 ) KANGXI RADICAL FIGHT → CJK UNIFIED IDEOGRAPH-9B25	# 

			{ L"\x2FBF",L"\x9B2F" }, //( ⾿ → 鬯 ) KANGXI RADICAL SACRIFICIAL WINE → CJK UNIFIED IDEOGRAPH-9B2F	# 

			{ L"\x2FC0",L"\x9B32" }, //( ⿀ → 鬲 ) KANGXI RADICAL CAULDRON → CJK UNIFIED IDEOGRAPH-9B32	# 

			{ L"\x2FC1",L"\x9B3C" }, //( ⿁ → 鬼 ) KANGXI RADICAL GHOST → CJK UNIFIED IDEOGRAPH-9B3C	# 
			{ L"\x2EE4",L"\x9B3C" }, //( ⻤ → 鬼 ) CJK RADICAL GHOST → CJK UNIFIED IDEOGRAPH-9B3C	# 

			{ L"\x2FC2",L"\x9B5A" }, //( ⿂ → 魚 ) KANGXI RADICAL FISH → CJK UNIFIED IDEOGRAPH-9B5A	# 

			{ L"\xF939",L"\x9B6F" }, //( 魯 → 魯 ) CJK COMPATIBILITY IDEOGRAPH-F939 → CJK UNIFIED IDEOGRAPH-9B6F	# 

			{ L"\x0002\xFA0B",L"\x9C40" }, //( 鱀 → 鱀 ) CJK COMPATIBILITY IDEOGRAPH-2FA0B → CJK UNIFIED IDEOGRAPH-9C40	# 

			{ L"\xF9F2",L"\x9C57" }, //( 鱗 → 鱗 ) CJK COMPATIBILITY IDEOGRAPH-F9F2 → CJK UNIFIED IDEOGRAPH-9C57	# 

			{ L"\x2EE5",L"\x9C7C" }, //( ⻥ → 鱼 ) CJK RADICAL C-SIMPLIFIED FISH → CJK UNIFIED IDEOGRAPH-9C7C	# 

			{ L"\x2FC3",L"\x9CE5" }, //( ⿃ → 鳥 ) KANGXI RADICAL BIRD → CJK UNIFIED IDEOGRAPH-9CE5	# 

			{ L"\x0002\xFA0C",L"\x9CFD" }, //( 鳽 → 鳽 ) CJK COMPATIBILITY IDEOGRAPH-2FA0C → CJK UNIFIED IDEOGRAPH-9CFD	# 

			{ L"\x0002\xFA0D",L"\x4CCE" }, //( 䳎 → 䳎 ) CJK COMPATIBILITY IDEOGRAPH-2FA0D → CJK UNIFIED IDEOGRAPH-4CCE	# 

			{ L"\x0002\xFA0F",L"\x9D67" }, //( 鵧 → 鵧 ) CJK COMPATIBILITY IDEOGRAPH-2FA0F → CJK UNIFIED IDEOGRAPH-9D67	# 

			{ L"\x0002\xFA0E",L"\x4CED" }, //( 䳭 → 䳭 ) CJK COMPATIBILITY IDEOGRAPH-2FA0E → CJK UNIFIED IDEOGRAPH-4CED	# 

			{ L"\x0002\xFA10",L"\x0002\xA0CE" }, //( 𪃎 → 𪃎 ) CJK COMPATIBILITY IDEOGRAPH-2FA10 → CJK UNIFIED IDEOGRAPH-2A0CE	# 

			{ L"\xFA2D",L"\x9DB4" }, //( 鶴 → 鶴 ) CJK COMPATIBILITY IDEOGRAPH-FA2D → CJK UNIFIED IDEOGRAPH-9DB4	# 

			{ L"\x0002\xFA12",L"\x0002\xA105" }, //( 𪄅 → 𪄅 ) CJK COMPATIBILITY IDEOGRAPH-2FA12 → CJK UNIFIED IDEOGRAPH-2A105	# 

			{ L"\x0002\xFA11",L"\x4CF8" }, //( 䳸 → 䳸 ) CJK COMPATIBILITY IDEOGRAPH-2FA11 → CJK UNIFIED IDEOGRAPH-4CF8	# 

			{ L"\xF93A",L"\x9DFA" }, //( 鷺 → 鷺 ) CJK COMPATIBILITY IDEOGRAPH-F93A → CJK UNIFIED IDEOGRAPH-9DFA	# 

			{ L"\x0002\xFA13",L"\x0002\xA20E" }, //( 𪈎 → 𪈎 ) CJK COMPATIBILITY IDEOGRAPH-2FA13 → CJK UNIFIED IDEOGRAPH-2A20E	# 

			{ L"\xF920",L"\x9E1E" }, //( 鸞 → 鸞 ) CJK COMPATIBILITY IDEOGRAPH-F920 → CJK UNIFIED IDEOGRAPH-9E1E	# 

			{ L"\x9E43",L"\x9E42" }, //( 鹃 → 鹂 ) CJK UNIFIED IDEOGRAPH-9E43 → CJK UNIFIED IDEOGRAPH-9E42	# 

			{ L"\x2FC4",L"\x9E75" }, //( ⿄ → 鹵 ) KANGXI RADICAL SALT → CJK UNIFIED IDEOGRAPH-9E75	# 

			{ L"\xF940",L"\x9E7F" }, //( 鹿 → 鹿 ) CJK COMPATIBILITY IDEOGRAPH-F940 → CJK UNIFIED IDEOGRAPH-9E7F	# 
			{ L"\x2FC5",L"\x9E7F" }, //( ⿅ → 鹿 ) KANGXI RADICAL DEER → CJK UNIFIED IDEOGRAPH-9E7F	# 

			{ L"\x0002\xFA14",L"\x0002\xA291" }, //( 𪊑 → 𪊑 ) CJK COMPATIBILITY IDEOGRAPH-2FA14 → CJK UNIFIED IDEOGRAPH-2A291	# 

			{ L"\xF988",L"\x9E97" }, //( 麗 → 麗 ) CJK COMPATIBILITY IDEOGRAPH-F988 → CJK UNIFIED IDEOGRAPH-9E97	# 

			{ L"\xF9F3",L"\x9E9F" }, //( 麟 → 麟 ) CJK COMPATIBILITY IDEOGRAPH-F9F3 → CJK UNIFIED IDEOGRAPH-9E9F	# 

			{ L"\x2FC6",L"\x9EA5" }, //( ⿆ → 麥 ) KANGXI RADICAL WHEAT → CJK UNIFIED IDEOGRAPH-9EA5	# 

			{ L"\x2EE8",L"\x9EA6" }, //( ⻨ → 麦 ) CJK RADICAL SIMPLIFIED WHEAT → CJK UNIFIED IDEOGRAPH-9EA6	# 

			{ L"\x0002\xFA15",L"\x9EBB" }, //( 麻 → 麻 ) CJK COMPATIBILITY IDEOGRAPH-2FA15 → CJK UNIFIED IDEOGRAPH-9EBB	# 
			{ L"\x2FC7",L"\x9EBB" }, //( ⿇ → 麻 ) KANGXI RADICAL HEMP → CJK UNIFIED IDEOGRAPH-9EBB	# 

			{ L"\x0002\xF88F",L"\x0002\xA392" }, //( 𪎒 → 𪎒 ) CJK COMPATIBILITY IDEOGRAPH-2F88F → CJK UNIFIED IDEOGRAPH-2A392	# 

			{ L"\x2FC8",L"\x9EC3" }, //( ⿈ → 黃 ) KANGXI RADICAL YELLOW → CJK UNIFIED IDEOGRAPH-9EC3	# 

			{ L"\x2EE9",L"\x9EC4" }, //( ⻩ → 黄 ) CJK RADICAL SIMPLIFIED YELLOW → CJK UNIFIED IDEOGRAPH-9EC4	# 

			{ L"\x2FC9",L"\x9ECD" }, //( ⿉ → 黍 ) KANGXI RADICAL MILLET → CJK UNIFIED IDEOGRAPH-9ECD	# 

			{ L"\xF989",L"\x9ECE" }, //( 黎 → 黎 ) CJK COMPATIBILITY IDEOGRAPH-F989 → CJK UNIFIED IDEOGRAPH-9ECE	# 

			{ L"\x0002\xFA16",L"\x4D56" }, //( 䵖 → 䵖 ) CJK COMPATIBILITY IDEOGRAPH-2FA16 → CJK UNIFIED IDEOGRAPH-4D56	# 

			{ L"\x2FCA",L"\x9ED1" }, //( ⿊ → 黑 ) KANGXI RADICAL BLACK → CJK UNIFIED IDEOGRAPH-9ED1	# 
			{ L"\x9ED2",L"\x9ED1" }, //( 黒 → 黑 ) CJK UNIFIED IDEOGRAPH-9ED2 → CJK UNIFIED IDEOGRAPH-9ED1	# →⿊→

			{ L"\xFA3A",L"\x58A8" }, //( 墨 → 墨 ) CJK COMPATIBILITY IDEOGRAPH-FA3A → CJK UNIFIED IDEOGRAPH-58A8	# 

			{ L"\x0002\xFA17",L"\x9EF9" }, //( 黹 → 黹 ) CJK COMPATIBILITY IDEOGRAPH-2FA17 → CJK UNIFIED IDEOGRAPH-9EF9	# 
			{ L"\x2FCB",L"\x9EF9" }, //( ⿋ → 黹 ) KANGXI RADICAL EMBROIDERY → CJK UNIFIED IDEOGRAPH-9EF9	# 

			{ L"\x2FCC",L"\x9EFD" }, //( ⿌ → 黽 ) KANGXI RADICAL FROG → CJK UNIFIED IDEOGRAPH-9EFD	# 

			{ L"\x0002\xFA19",L"\x9F05" }, //( 鼅 → 鼅 ) CJK COMPATIBILITY IDEOGRAPH-2FA19 → CJK UNIFIED IDEOGRAPH-9F05	# 

			{ L"\x0002\xFA18",L"\x9EFE" }, //( 黾 → 黾 ) CJK COMPATIBILITY IDEOGRAPH-2FA18 → CJK UNIFIED IDEOGRAPH-9EFE	# 

			{ L"\x2FCD",L"\x9F0E" }, //( ⿍ → 鼎 ) KANGXI RADICAL TRIPOD → CJK UNIFIED IDEOGRAPH-9F0E	# 

			{ L"\x0002\xFA1A",L"\x9F0F" }, //( 鼏 → 鼏 ) CJK COMPATIBILITY IDEOGRAPH-2FA1A → CJK UNIFIED IDEOGRAPH-9F0F	# 

			{ L"\x2FCE",L"\x9F13" }, //( ⿎ → 鼓 ) KANGXI RADICAL DRUM → CJK UNIFIED IDEOGRAPH-9F13	# 

			{ L"\x0002\xFA1B",L"\x9F16" }, //( 鼖 → 鼖 ) CJK COMPATIBILITY IDEOGRAPH-2FA1B → CJK UNIFIED IDEOGRAPH-9F16	# 

			{ L"\x2FCF",L"\x9F20" }, //( ⿏ → 鼠 ) KANGXI RADICAL RAT → CJK UNIFIED IDEOGRAPH-9F20	# 

			{ L"\x0002\xFA1C",L"\x9F3B" }, //( 鼻 → 鼻 ) CJK COMPATIBILITY IDEOGRAPH-2FA1C → CJK UNIFIED IDEOGRAPH-9F3B	# 
			{ L"\x2FD0",L"\x9F3B" }, //( ⿐ → 鼻 ) KANGXI RADICAL NOSE → CJK UNIFIED IDEOGRAPH-9F3B	# 

			{ L"\xFAD8",L"\x9F43" }, //( 齃 → 齃 ) CJK COMPATIBILITY IDEOGRAPH-FAD8 → CJK UNIFIED IDEOGRAPH-9F43	# 

			{ L"\x2FD1",L"\x9F4A" }, //( ⿑ → 齊 ) KANGXI RADICAL EVEN → CJK UNIFIED IDEOGRAPH-9F4A	# 

			{ L"\x2EEC",L"\x9F50" }, //( ⻬ → 齐 ) CJK RADICAL C-SIMPLIFIED EVEN → CJK UNIFIED IDEOGRAPH-9F50	# 

			{ L"\x2FD2",L"\x9F52" }, //( ⿒ → 齒 ) KANGXI RADICAL TOOTH → CJK UNIFIED IDEOGRAPH-9F52	# 

			{ L"\x0002\xFA1D",L"\x0002\xA600" }, //( 𪘀 → 𪘀 ) CJK COMPATIBILITY IDEOGRAPH-2FA1D → CJK UNIFIED IDEOGRAPH-2A600	# 

			{ L"\x2EEE",L"\x9F7F" }, //( ⻮ → 齿 ) CJK RADICAL C-SIMPLIFIED TOOTH → CJK UNIFIED IDEOGRAPH-9F7F	# 

			{ L"\xF9C4",L"\x9F8D" }, //( 龍 → 龍 ) CJK COMPATIBILITY IDEOGRAPH-F9C4 → CJK UNIFIED IDEOGRAPH-9F8D	# 
			{ L"\x2FD3",L"\x9F8D" }, //( ⿓ → 龍 ) KANGXI RADICAL DRAGON → CJK UNIFIED IDEOGRAPH-9F8D	# 

			{ L"\xFAD9",L"\x9F8E" }, //( 龎 → 龎 ) CJK COMPATIBILITY IDEOGRAPH-FAD9 → CJK UNIFIED IDEOGRAPH-9F8E	# 

			{ L"\x2EF0",L"\x9F99" }, //( ⻰ → 龙 ) CJK RADICAL C-SIMPLIFIED DRAGON → CJK UNIFIED IDEOGRAPH-9F99	# 

			{ L"\xF907",L"\x9F9C" }, //( 龜 → 龜 ) CJK COMPATIBILITY IDEOGRAPH-F907 → CJK UNIFIED IDEOGRAPH-9F9C	# 
			{ L"\xF908",L"\x9F9C" }, //( 龜 → 龜 ) CJK COMPATIBILITY IDEOGRAPH-F908 → CJK UNIFIED IDEOGRAPH-9F9C	# 
			{ L"\xFACE",L"\x9F9C" }, //( 龜 → 龜 ) CJK COMPATIBILITY IDEOGRAPH-FACE → CJK UNIFIED IDEOGRAPH-9F9C	# 
			{ L"\x2FD4",L"\x9F9C" }, //( ⿔ → 龜 ) KANGXI RADICAL TURTLE → CJK UNIFIED IDEOGRAPH-9F9C	# 

			{ L"\x2EF3",L"\x9F9F" }, //( ⻳ → 龟 ) CJK RADICAL C-SIMPLIFIED TURTLE → CJK UNIFIED IDEOGRAPH-9F9F	# 

			{ L"\x2FD5",L"\x9FA0" }, //( ⿕ → 龠 ) KANGXI RADICAL FLUTE → CJK UNIFIED IDEOGRAPH-9FA0	# 

			{ L"\x0001\x11DB",L"\xA8FC" }, //( 𑇛 → ꣼ ) SHARADA SIGN SIDDHAM → DEVANAGARI SIGN SIDDHAM	# 

		};
	}
};
