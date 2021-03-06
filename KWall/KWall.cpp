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
#include "KWall.h"

#include "KWallCore.h"

#include "richedit.h"
#include "shellapi.h"
#include <string>
#include <vector>

#include "unicode/ustring.h"

#include "KWallCore.cpp"



// Forward declarations (that cause compiler freakouts if they're in the header file instead of here...)
KWallCore core;
HANDLE KWallCore::multithread_mutex;						// Mutex handle, for thread synchronization
UINT KWallCore::mon_thread_count;							// Number of active monitor threads
BOOL KWallCore::crapped_ourself;							// If true, we had a bad hair day.
HANDLE KWallCore::windivert_filter;							// WinDivert filter handle
BOOL KWallCore::killthreads;								// Should monitor threads commit seppuku?
BOOL KWallCore::bypass_mode;								// To process packets, or not to process packets...
UnicodeString KWallCore::detect_patterns[16];				// Regex patterns get put in here
UINT KWallCore::detect_weight[16];							// How much a match is worth toward flagging a packet, when 100 total flags it
UnicodeString KWallCore::strip_punctuation;					// Punctuation characters to strip before regex checking
UnicodeString KWallCore::strip_whitespace;					// Whitespace characters to strip before regex checking
BOOL KWallCore::skeletonize;								// Are we stripping out Unicode confusables?
std::vector<UnicodeString> KWallCore::deob_from, KWallCore::deob_to; // Multiple-character deobfuscation arrays
std::vector<UnicodeString> KWallCore::utf_from, KWallCore::utf_to; // Unicode deobfuscation arrays
UINT KWallCore::ignore_start;								// Ignore how many bytes at the start of a packet?
HANDLE KWallCore::monitor_thread[64];						// Hold those thread handles...
UINT KWallCore::passed_packets, KWallCore::dropped_packets;	// Keeping tally of what we dropped and didn't drop.
std::wstring KWallCore::encoding;							// So what flavor of Unicode did we discover?
struct KWallCore::confusables_conversion;
std::vector<KWallCore::confusables_conversion> KWallCore::confusables_map;
BOOL KWallCore::zlib_decompress;							// Try using zlib to unpack the packet payload



/*
	UpdateRichEdit
	--------------

	This procedure pushes Unicode text to the richedit, and sets the font before doing so.

	txt (wchar_t*) : the incoming text to be pushed to the richedit.
	bold (BOOL) : true if the text should be emboldened.
	ital (BOOL) : true if the text should be italicized.
	color as RGB() () : the foreground (text) color - use RGB(x, y, z) to set.
	font_name(wchar_t*) : The name of the font. WARNING: will be forced to narrowstring by API - use ASCII/ANSI text only.
	font_size (INT) : font size, in points (autoconverted)

	(No result.)
	void UpdateRichEdit(wchar_t * txt, bool bold, bool ital, UINT32 color, wchar_t * font_name, int font_size)
	{
	}
*/
void UpdateRichEdit(wchar_t* txt, BOOL bold, BOOL ital, UINT32 color /*as RGB()*/, wchar_t* font_name, INT font_size /*in points*/)
{
	// First, we'll deal with modifying the font at the RichEdit's insertion point.
	CHARFORMAT rtf_font;
	int i = 0, tmp;

	ZeroMemory(&rtf_font, sizeof(rtf_font));

	rtf_font.cbSize = sizeof(CHARFORMAT);
	rtf_font.dwMask = CFM_COLOR | CFM_SIZE;
	if (bold) { rtf_font.dwMask = rtf_font.dwMask | CFM_BOLD; }
	if (ital) { rtf_font.dwMask = rtf_font.dwMask | CFM_ITALIC; }
	rtf_font.dwEffects = 0;
	if (bold) { rtf_font.dwEffects = rtf_font.dwEffects | CFE_BOLD; }
	if (ital) { rtf_font.dwMask = rtf_font.dwMask | CFE_ITALIC; }
	rtf_font.yHeight = font_size * 20;
	rtf_font.crTextColor = color;
	rtf_font.bCharSet = DEFAULT_CHARSET;

	// This is a bit kludgy, but basically we have to shove the font name (if any) into the szfaceName
	// var to hand over to the richedit. szFaceName is a char array, so we're basically copying over the 
	// characters. (Sure, we could use some other tactic but this does work.)
	if (font_name != L"")
	{
		rtf_font.dwMask = rtf_font.dwMask | CFM_FACE;
		for (i = 0; i <= 32; i++)
		{
			tmp = font_name[i];
			if (tmp > 31)
			{
				rtf_font.szFaceName[i] = tmp;
			}
		}
	}


	// Now we'll deal with processing the text. Essentially we're converting a UTF-16 std::wstring into 
	// a UTF-8 char array (std::string).
	DWORD WideLength = wcslen(txt) + 1;
	char Utf8[65535];
	DWORD Length;
	INT ReturnedLength;// , line_count;

	ZeroMemory(&Utf8, sizeof(Utf8));

	Length = WideLength * 4;

	ReturnedLength = WideCharToMultiByte(CP_UTF8,
		0,
		(LPCWCH)txt,
		WideLength,
		Utf8,
		Length,
		NULL,
		NULL);
	if (ReturnedLength)
	{
		// Need to zero terminate...
		Utf8[ReturnedLength] = 0;
	}

	// Tell the richedit to expect Unicode.
	SETTEXTEX TextInfo = { 0 };
	TextInfo.flags = ST_SELECTION;
	TextInfo.codepage = CP_UTF8;


	// Now that we've done our legwork, we can send messages to the RichEdit.

	// Set the selection to the end of the control's selection space.
	GETTEXTLENGTHEX lengthex = { 0 };
	CHARRANGE selrange;
	lengthex.codepage = CP_UTF8;
	lengthex.flags = GTL_PRECISE;
	UINT curlen = SendMessage(hRichEd, EM_GETTEXTLENGTHEX, (WPARAM)&lengthex, (LPARAM)0);
	selrange.cpMax = curlen;
	selrange.cpMin = curlen;
	if (curlen > 0)
		SendMessage(hRichEd, EM_EXSETSEL, (WPARAM)0, (LPARAM)&selrange);

	// Change font parameters for the upcoming text insertion.
	SendMessage(hRichEd, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&rtf_font);

	// Do the text insertion.
	SendMessage(hRichEd, EM_SETTEXTEX, (WPARAM)&TextInfo, (LPARAM)&Utf8);

	// Turn on vertical scroll bar.
	SendMessage(hRichEd, EM_SHOWSCROLLBAR, (WPARAM)SB_VERT, (LPARAM)true);

	// Scroll the richedit to the bottom.
	SendMessage(hRichEd, WM_VSCROLL, (WPARAM)SB_BOTTOM, (LPARAM)0);


	// We also need to make sure the richedit isn't getting too full, as it can get a bit pissy if you have a lot of
	// text in it. We'll cut off lines when we reach 256k.
	FINDTEXTW findex = { 0 };
	INT findpos;

	while (SendMessage(hRichEd, EM_GETTEXTLENGTHEX, (WPARAM)&lengthex, (LPARAM)0) > 262144)
	{
		// We'll search for a \n as the newline.
		findex = { 0 };
		findex.chrg.cpMin = 0; // Start at zero.
		findex.chrg.cpMax = -1; // Search the whole control.
		findex.lpstrText = L"\n";

		// Send a "find this pl0x" message. The response should be the location of the first \n.
		findpos = SendMessage(hRichEd, EM_FINDTEXTW, (WPARAM)1/*FR_DOWN*/, (LPARAM)&findex);
		if (findpos > 0)
		{
			// Set the selection to cover from the first character to the first \n.
			selrange.cpMin = 0;
			selrange.cpMax = findpos;
			SendMessage(hRichEd, EM_EXSETSEL, (WPARAM)0, (LPARAM)&selrange);

			// Set the text to nothing in that selection range.
			SendMessage(hRichEd, EM_SETTEXTEX, (WPARAM)&TextInfo, (LPARAM)&"");
		}
		else
		{
			// No linebreak found? Just strip off 256 bytes, over and over. Sure it'll leave a fscked-up line at the
			// top but who cares.
			selrange.cpMin = 0;
			selrange.cpMax = 256;
			SendMessage(hRichEd, EM_EXSETSEL, (WPARAM)0, (LPARAM)&selrange);

			// Set the text to nothing in that selection range.
			SendMessage(hRichEd, EM_SETTEXTEX, (WPARAM)&TextInfo, (LPARAM)&"");
		}
	}


	// Push a copy of the text to the log file.
	std::ofstream logfile;
	std::string logline = "";
	for (i = 0; i < sizeof(Utf8); i++)
	{
		// This first bit is to make a Windows-friendly log file.
		if (Utf8[i] == 10)
		{
			logline = logline + "\r\n";
		}
		if (Utf8[i] > 31)
		{
			logline = logline + Utf8[i];
		}
	}
	logfile.open(logfilename, std::ios::app | std::ios::binary);
	logfile << logline;
	logfile.close();
}



/*
	wWinMain
	--------

	The program's entry point!

	hInstance (HINSTANCE) : handle to the instance of this application.
	hPrevInstance (HINSTANCE) : handle to the instance of any previous run of this application.
	lpCmdLine (LPWSTR) : pointer to a widestring containing the full command line for the application, including any 
	                     passed parameters.
	nCmdShow (int) : control code for how this application's GUI is to be displayed.

	returns (INT) : standard application exit code.
*/
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	waiting_for_shutdown = false;

	// Initialize global strings
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
	LoadStringW(hInstance, IDC_KWALL, szWindowClass, MAX_LOADSTRING);
	MyRegisterClass(hInstance);
	core.mon_thread_count = 0;

	// Perform application initialization:
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}

	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_KWALL));


	// Throw out some preliminary text.
	UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
	UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
	UpdateRichEdit(L"Welcome to ", false, false, RGB(0, 0, 128), L"Tahoma", 16);
	UpdateRichEdit(L"K*Wall", true, false, RGB(0, 0, 128), L"Tahoma", 16);
	UpdateRichEdit(L"!\n", false, false, RGB(0, 0, 0), L"Tahoma", 16);
	UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);

	UpdateRichEdit(L"We will be starting up in a moment...\n", false, false, RGB(0, 0, 0), L"Tahoma", 16);
	UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);
	UpdateRichEdit(L"Launch the game now, and close this window to exit K*Wall when you finish playing.\n",
		false, false, RGB(0, 0, 0), L"Tahoma", 16);
	UpdateRichEdit(L"\n", false, false, RGB(0, 0, 0), L"Tahoma", 12);



	// Load config file details and start up some monitor threads.
	core.ConfigureAndStart();



	// Main message loop!
	MSG msg;
	while ((GetMessage(&msg, nullptr, 0, 0)) && (core.mon_thread_count > 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}



	// Shutdown!
	if (core.windivert_filter != 0)
	{
		// Stop the WinDivert filter.
		UpdateRichEdit(L"Attempting to close WinDivert...", false, false, RGB(255, 0, 0), L"Tahoma", 16);

		if (!WinDivertClose(core.windivert_filter))
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

		core.windivert_filter = 0;
	}



	// Secondary message loop, in case something went wrong during the startup process - this basically makes "press any
	// key to exit" work.
	if (core.crapped_ourself)
	{
		while (GetMessage(&msg, nullptr, 0, 0))
		{
			if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}



	// Close a few lingering handles and shut down.
	try
	{
		CloseHandle(core.multithread_mutex);
	}
	catch (...)
	{

	}
	DestroyWindow(hRichEd);
	DestroyWindow(kwall);
	PostQuitMessage(0);

	return (int)msg.wParam;
}



/*
	MyRegisterClass
	---------------

	Class registrar

	hInstance (HINSTANCE) : handle to this instance of this application.

	returns (ATOM) : class atom for window creation.
*/
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_KWALL));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_KWALL);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

	return RegisterClassExW(&wcex);
}



/*
	InitInstance
	------------

	Instance initializer (aka, windowed-app constructor)

	hInstance (HINSTANCE) : the handle to this instance of this application.
	nCmdShow (INT): control code for how this application's GUI is to be displayed.

	returns (BOOL) : standard exit code.
*/
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	UINT i;

	hInst = hInstance; // Store instance handle in our global variable

	// Create the main window.
	kwall = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPED | WS_VISIBLE | WS_CAPTION | WS_MINIMIZEBOX | WS_BORDER | WS_SYSMENU,
		CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

	if (!kwall)
	{
		return FALSE;
	}

	// Create the richedit.
	LoadLibrary(TEXT("MSFTEDIT.DLL"));

	RECT client_size;
	GetClientRect(kwall, &client_size);
	hRichEd = CreateWindowW(MSFTEDIT_CLASS, nullptr, WS_BORDER | WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY,
		8, 8, client_size.right - 16, client_size.bottom - 16, kwall, 0, riched, 0);

	// Set the margins for the richedit.
	SendMessage(hRichEd, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, (LPARAM)0x00080008);

	// Set the default font for the richedit. This takes a bit of work...
	CHARFORMAT2 defaultfont;
	ZeroMemory(&defaultfont, sizeof(defaultfont));
	defaultfont.dwMask = CFM_SIZE | CFM_COLOR | CFM_FACE | CFM_CHARSET | CFM_LCID;
	defaultfont.cbSize = 12 * 20;
	defaultfont.crTextColor = 0;
	defaultfont.yHeight = 12 * 20;
	defaultfont.bCharSet = DEFAULT_CHARSET;
	defaultfont.lcid = 0;
	defaultfont.bPitchAndFamily = FF_DONTCARE;
	std::string fontname = "DejaVu Sans Mono";
	for (i = 0; i <= fontname.length(); i++)
	{
		defaultfont.szFaceName[i] = fontname[i];
	}
	defaultfont.cbSize = sizeof(CHARFORMAT2);
	SendMessage(hRichEd, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&defaultfont);



	// Push focus onto the main window.
	ShowWindow(kwall, nCmdShow);
	UpdateWindow(kwall);

	// Create a name for the log file. Basically we'll use the system date/time as the filename and stick it in 
	// <app_path>\logs\ for convenient access.
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	localtime_s(&tstruct, &now);
	strftime(buf, sizeof(buf), "%Y-%m-%d_%H-%M-%S", &tstruct);

	char module_name[MAX_PATH];
	GetModuleFileNameA(0, (LPSTR)&module_name, MAX_PATH);
	std::string path(module_name);
	path.erase(path.find_last_of('\\'), std::string::npos);

	logfilename = path + "\\logs\\";

	// Let's check to see if the log path exists. If not, we should probably create it. (We're just doing a 
	// create - if it already exists the create will fail with ERROR_ALREADY_EXISTS, which we will ignore.)
	int res = CreateDirectoryA((LPCSTR)logfilename.c_str(), NULL);

	logfilename.append(buf);
	logfilename = logfilename +".txt";

	return TRUE;
}



/*
	CloseApp
	--------

	App close/deallocate/destruct on WM_CLOSE

	(no input vars, no result.)
*/
void CloseApp()
{
	DWORD wait_result;

	// Set a flag so that pounding close won't also spam copies of this proc into the stack.
	waiting_for_shutdown = true;

	// Tell the user we're shutting down. Note that we're doing a mutex lock even though this should be executed within
	// the same thread as the richedit - this is so that any monitor threads currently writing to the richedit don't get 
	// stepped on.
	wait_result = WaitForSingleObject(core.multithread_mutex, INFINITE);
	if (wait_result == WAIT_OBJECT_0)
	{
		UpdateRichEdit(L"Shutting down K*Wall - this may take a moment...\n\n", false, false, RGB(0, 0, 0), L"Tahoma", 16);

		ReleaseMutex(core.multithread_mutex);
	}

	// Tell the monitor threads to finish up.
	if (core.mon_thread_count > 0)
	{
		core.killthreads = true;
	}

	// Force threads to close.
	UINT i;
	for (i = 0; i < core.mon_thread_count; i++)
	{
		CloseHandle(core.monitor_thread[i]);
	}

	// Close a few lingering handles and shut down.
	CloseHandle(core.multithread_mutex);
	DestroyWindow(hRichEd);
	DestroyWindow(kwall);
	PostQuitMessage(0);

}



/*
	WndProc
	-------

	Message handler for main window.

	hWnd (HWND) : handle to the application's main window.
	message (UINT) : the message code being sent.
	wParam (WPARAM) : first parameter or pointer.
	lParam (LPARAM) : second parameter or pointer.

	returns (LRESULT) : zero if the message was handled, or the message to pass on if it wasn't.
*/
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	MENUITEMINFO mii = { sizeof(MENUITEMINFO) };
	HMENU hMenu;
	UINT i;
	DWORD wait_result;

	switch (message)
	{
		// Handle keypresses, but note we're only doing this if K*Wall crapped itself during configuration.
	case WM_KEYUP:
	{
		if (core.crapped_ourself)
		{
			CloseHandle(core.multithread_mutex);
			DestroyWindow(hRichEd);
			DestroyWindow(kwall);
			PostQuitMessage(0);
		}
	}
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;

		case IDM_EXIT:
			if (!waiting_for_shutdown) { CloseApp(); }

			if (core.crapped_ourself)
			{
				CloseHandle(core.multithread_mutex);
				DestroyWindow(hRichEd);
				DestroyWindow(kwall);
				PostQuitMessage(0);
			}
			break;

		case ID_CONTROLS_TOGGLEBYPASSMODE:
			core.bypass_mode = !core.bypass_mode;
			hMenu = GetMenu(hWnd);
			mii.fMask = MIIM_STATE;
			GetMenuItemInfo(hMenu, ID_CONTROLS_TOGGLEBYPASSMODE, FALSE, &mii);
			if (core.bypass_mode)
			{
				mii.fState |= MFS_CHECKED;
				SetMenuItemInfo(hMenu, ID_CONTROLS_TOGGLEBYPASSMODE, FALSE, &mii);
				UpdateRichEdit(L"Bypass mode ENABLED - all packet traffic is being passed through unchecked.\n\n",
					false, false, RGB(128, 128, 0), L"Tahoma", 16);
			}
			else
			{
				mii.fState ^= MFS_CHECKED;
				SetMenuItemInfo(hMenu, ID_CONTROLS_TOGGLEBYPASSMODE, FALSE, &mii);
				UpdateRichEdit(L"Bypass mode DISABLED - resuming packet scans...\n\n",
					false, false, RGB(128, 128, 0), L"Tahoma", 16);
			}
			break;



			
		case ID_CONTROLS_REPO:
			CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
			ShellExecuteW(NULL, L"open", L"https://github.com/ActiumPraetor/K-Wall/", L"", L".", SW_SHOWDEFAULT);
			break;

		case ID_CONTROLS_REDDIT:
			CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
			ShellExecuteW(NULL, L"open", L"https://www.reddit.com/r/KWall/", L"", L".", SW_SHOWDEFAULT);
			break;

		case ID_CONTROLS_SERIOUSLY_RELOAD:
			wait_result = WaitForSingleObject(core.multithread_mutex, INFINITE);
			if (wait_result == WAIT_OBJECT_0)
			{
				UpdateRichEdit(L"Shutting down monitor threads - this may take a moment...\n\n", false, false, RGB(0, 0, 0), L"Tahoma", 16);

				ReleaseMutex(core.multithread_mutex);
			}

			core.killthreads = true;

			for (i = 0; i < core.mon_thread_count; i++)
			{
				CloseHandle(core.monitor_thread[i]);
			}

			wait_result = WaitForSingleObject(core.multithread_mutex, INFINITE);
			if (wait_result == WAIT_OBJECT_0)
			{
				UpdateRichEdit(L"Attempting to close WinDivert...", false, false, RGB(0, 0, 0), L"Tahoma", 12);

				if (!WinDivertClose(core.windivert_filter))
				{
					UpdateRichEdit(L"FAILED.\n", true, false, RGB(255, 0, 0), L"Tahoma", 12);
					UpdateRichEdit(L"WinDivert reported error code ", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					std::wstring lasterr = std::to_wstring(GetLastError());
					UpdateRichEdit(const_cast<wchar_t*>(lasterr.c_str()), true, false, RGB(255, 0, 0), L"Tahoma", 12);
					UpdateRichEdit(L".\n", false, false, RGB(255, 0, 0), L"Tahoma", 12);

					UpdateRichEdit(L"WARNING: Windows networking may be left in an inconsistent state. You may need to reboot.\n\n",
						false, false, RGB(255, 0, 0), L"Tahoma", 16);
				}
				else
				{
					UpdateRichEdit(L"Done.\n\n", true, false, RGB(0, 128, 0), L"Tahoma", 12);
				}
				core.windivert_filter = 0;
			}

			wait_result = WaitForSingleObject(core.multithread_mutex, INFINITE);
			if (wait_result == WAIT_OBJECT_0)
			{
				UpdateRichEdit(L"Reloading configuration...\n\n", false, false, RGB(0, 0, 0), L"Tahoma", 16);

				ReleaseMutex(core.multithread_mutex);
			}

			core.ConfigureAndStart();
			break;

		default:
			return DefWindowProc(hWnd, message, wParam, lParam);// 
		}
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// Paint me like one of your French forms!
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_CLOSE:
		if (!waiting_for_shutdown) { CloseApp(); }

		if (core.crapped_ourself)
		{
			CloseHandle(core.multithread_mutex);
			DestroyWindow(hRichEd);
			DestroyWindow(kwall);
			PostQuitMessage(0);
		}
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}



/*
	About
	-----

	Message handler for "about" dialog window.

	hWnd (HWND) : handle to the application's "about" dialog window.
	message (UINT) : the message code being sent.
	wParam (WPARAM) : first parameter or pointer.
	lParam (LPARAM) : second parameter or pointer.

	returns (LRESULT) : standard exit code.
*/

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
