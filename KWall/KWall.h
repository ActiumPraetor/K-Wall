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
#pragma once



#ifndef __BASE_INCLUDED__
#define __BASE_INCLUDED__



#include "resource.h"
#include <string>



#define MAXBUF  0xFFFF
#define MAX_LOADSTRING 100



// ZOMG, global variables! Oh, the huge manatee! (This is where they get defined for everything - all other
// code units will refer to these via "extern.")
HINSTANCE hInst;                                // Our current instance
HWND kwall;										// Our main window handle
HINSTANCE riched;								// Our richedit control
HWND hRichEd;									// Our richedit control's hWnd
std::string logfilename;						// Logging FTW!	
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // The main window class name
BOOL waiting_for_shutdown;						// Are we waiting for things to unload and close?



// Forward declarations
void UpdateRichEdit(wchar_t* txt, BOOL bold, BOOL ital, UINT32 color /*as RGB()*/, wchar_t* font_name, INT font_size /*in points*/);
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow);
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
void CloseApp();
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK About(HWND, UINT, WPARAM, LPARAM);



#endif //  __BASE_INCLUDED__