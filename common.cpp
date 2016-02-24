#include "StdAfx.h"
#include "common.h"
#include <tlhelp32.h>

// http://www.codeproject.com/Articles/8810/Own-Crash-Minidump-with-Call-Stack
#pragma optimize("y", off)		// generate stack frame pointers for all functions - same as /Oy- in the project
#pragma warning(disable: 4200)	// nonstandard extension used : zero-sized array in struct/union
#pragma warning(disable: 4100)	// unreferenced formal parameter

// In case you don't have dbghelp.h.
#ifndef _DBGHELP_

typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
	DWORD	ThreadId;
	PEXCEPTION_POINTERS	ExceptionPointers;
	BOOL	ClientPointers;
} MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;

typedef enum _MINIDUMP_TYPE {
	MiniDumpNormal =			0x00000000,
	MiniDumpWithDataSegs =		0x00000001,
} MINIDUMP_TYPE;

typedef	BOOL (WINAPI * MINIDUMP_WRITE_DUMP)(
	IN HANDLE			hProcess,
	IN DWORD			ProcessId,
	IN HANDLE			hFile,
	IN MINIDUMP_TYPE	DumpType,
	IN CONST PMINIDUMP_EXCEPTION_INFORMATION	ExceptionParam, OPTIONAL
	IN PVOID									UserStreamParam, OPTIONAL
	IN PVOID									CallbackParam OPTIONAL
	);

#else

typedef	BOOL (WINAPI * MINIDUMP_WRITE_DUMP)(
	IN HANDLE			hProcess,
	IN DWORD			ProcessId,
	IN HANDLE			hFile,
	IN MINIDUMP_TYPE	DumpType,
	IN CONST PMINIDUMP_EXCEPTION_INFORMATION	ExceptionParam, OPTIONAL
	IN PMINIDUMP_USER_STREAM_INFORMATION		UserStreamParam, OPTIONAL
	IN PMINIDUMP_CALLBACK_INFORMATION			CallbackParam OPTIONAL
	);
#endif //#ifndef _DBGHELP_


HMODULE	hDbgHelp;
MINIDUMP_WRITE_DUMP	MiniDumpWriteDump_;

// Tool Help functions.
typedef	HANDLE (WINAPI * CREATE_TOOL_HELP32_SNAPSHOT)(DWORD dwFlags, DWORD th32ProcessID);
typedef	BOOL (WINAPI * MODULE32_FIRST)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
typedef	BOOL (WINAPI * MODULE32_NEST)(HANDLE hSnapshot, LPMODULEENTRY32 lpme);

CREATE_TOOL_HELP32_SNAPSHOT	CreateToolhelp32Snapshot_;
MODULE32_FIRST	Module32First_;
MODULE32_NEST	Module32Next_;

#define	DUMP_SIZE_MAX	8000	//max size of our dump
#define	CALL_TRACE_MAX	((DUMP_SIZE_MAX - 2000) / (MAX_PATH + 40))	//max number of traced calls
#define	NL				"\r\n"	//new line


//****************************************************************************************
// Find module by Ret_Addr (address in the module).
// Return Module_Name (full path) and Module_Addr (start address).
// Return TRUE if found.
BOOL WINAPI Get_Module_By_Ret_Addr(PBYTE Ret_Addr, PCHAR Module_Name, PBYTE & Module_Addr)
{
	MODULEENTRY32	M = {sizeof(M)};
	HANDLE	hSnapshot;

	Module_Name[0] = 0;
	
	if (CreateToolhelp32Snapshot_)
	{
		hSnapshot = CreateToolhelp32Snapshot_(TH32CS_SNAPMODULE, 0);
		
		if ((hSnapshot != INVALID_HANDLE_VALUE) &&
			Module32First_(hSnapshot, &M))
		{
			do
			{
				if (DWORD(Ret_Addr - M.modBaseAddr) < M.modBaseSize)
				{
					lstrcpyn(Module_Name, M.szExePath, MAX_PATH);
					Module_Addr = M.modBaseAddr;
					break;
				}
			} while (Module32Next_(hSnapshot, &M));
		}

		CloseHandle(hSnapshot);
	}

	return !!Module_Name[0];
} //Get_Module_By_Ret_Addr



//******************************************************************
// Fill Str with call stack info.
// pException can be either GetExceptionInformation() or NULL.
// If pException = NULL - get current call stack.
int WINAPI Get_Call_Stack(PEXCEPTION_POINTERS pException, PCHAR Str)
{
	CHAR	Module_Name[MAX_PATH];
	PBYTE	Module_Addr = 0;
	PBYTE	Module_Addr_1;
	int		Str_Len;
	
	typedef struct STACK
	{
		STACK *	Ebp;
		PBYTE	Ret_Addr;
		DWORD	Param[0];
	} STACK, * PSTACK;

	STACK	Stack = {0, 0};
	PSTACK	Ebp;

	if (pException)		//fake frame for exception address
	{
		Stack.Ebp = (PSTACK)pException->ContextRecord->Ebp;
		Stack.Ret_Addr = (PBYTE)pException->ExceptionRecord->ExceptionAddress;
		Ebp = &Stack;
	}
	else
	{
		Ebp = (PSTACK)&pException - 1;	//frame addr of Get_Call_Stack()

		// Skip frame of Get_Call_Stack().
		if (!IsBadReadPtr(Ebp, sizeof(PSTACK)))
			Ebp = Ebp->Ebp;		//caller ebp
	}

	Str[0] = 0;
	Str_Len = 0;

	// Trace CALL_TRACE_MAX calls maximum - not to exceed DUMP_SIZE_MAX.
	// Break trace on wrong stack frame.
	for (int Ret_Addr_I = 0;
		(Ret_Addr_I < CALL_TRACE_MAX) && !IsBadReadPtr(Ebp, sizeof(PSTACK)) && !IsBadCodePtr(FARPROC(Ebp->Ret_Addr));
		Ret_Addr_I++, Ebp = Ebp->Ebp)
	{
		// If module with Ebp->Ret_Addr found.
		if (Get_Module_By_Ret_Addr(Ebp->Ret_Addr, Module_Name, Module_Addr_1))
		{
			if (Module_Addr_1 != Module_Addr)	//new module
			{
				// Save module's address and full path.
				Module_Addr = Module_Addr_1;
				Str_Len += wsprintf(Str + Str_Len, NL "%08X  %s", Module_Addr, Module_Name);
			}

			// Save call offset.
			Str_Len += wsprintf(Str + Str_Len,
				NL "  +%08X", Ebp->Ret_Addr - Module_Addr);

			// Save 5 params of the call. We don't know the real number of params.
			if (pException && !Ret_Addr_I)	//fake frame for exception address
				Str_Len += wsprintf(Str + Str_Len, "  Exception Offset");
			else if (!IsBadReadPtr(Ebp, sizeof(PSTACK) + 5 * sizeof(DWORD)))
			{
				Str_Len += wsprintf(Str + Str_Len, "  (%X, %X, %X, %X, %X)",
					Ebp->Param[0], Ebp->Param[1], Ebp->Param[2], Ebp->Param[3], Ebp->Param[4]);
			}
		}
		else
			Str_Len += wsprintf(Str + Str_Len, NL "%08X", Ebp->Ret_Addr);
	}

	return Str_Len;
} //Get_Call_Stack




//***********************************
// Fill Str with Windows version.
int WINAPI Get_Version_Str(PCHAR Str)
{
	OSVERSIONINFOEX	V = {sizeof(OSVERSIONINFOEX)};	//EX for NT 5.0 and later

	if (!GetVersionEx((POSVERSIONINFO)&V))
	{
		ZeroMemory(&V, sizeof(V));
		V.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		GetVersionEx((POSVERSIONINFO)&V);
	}

	if (V.dwPlatformId != VER_PLATFORM_WIN32_NT)
		V.dwBuildNumber = LOWORD(V.dwBuildNumber);	//for 9x HIWORD(dwBuildNumber) = 0x04xx

	return wsprintf(Str,
		// NL "Windows:  %d.%d.%d, SP %d.%d, Product Type %d",	//SP - service pack, Product Type - VER_NT_WORKSTATION,...
		NL "Windows:  %d.%d.%d, SP %d.%d",	//SP - service pack, Product Type - VER_NT_WORKSTATION,...
		V.dwMajorVersion, V.dwMinorVersion, V.dwBuildNumber, V.wServicePackMajor, V.wServicePackMinor); //, V.wProductType);
}


//*************************************************************
// Allocate Str[DUMP_SIZE_MAX] and return Str with dump, if !pException - just return call stack in Str.
PCHAR WINAPI Get_Exception_Info(PEXCEPTION_POINTERS pException)
{
	PCHAR		Str;
	int			Str_Len;
	int			i;
	CHAR		Module_Name[MAX_PATH];
	PBYTE		Module_Addr;
	HANDLE		hFile;
	FILETIME	Last_Write_Time;
	FILETIME	Local_File_Time;
	SYSTEMTIME	T;
	
	Str = new CHAR[DUMP_SIZE_MAX];

	if (!Str)
		return NULL;

	Str_Len = 0;
	Str_Len += Get_Version_Str(Str + Str_Len);

	Str_Len += wsprintf(Str + Str_Len, NL "Process:  ");
	GetModuleFileName(NULL, Str + Str_Len, MAX_PATH);
	Str_Len = lstrlen(Str);

	// If exception occurred.
	if (pException)
	{
		EXCEPTION_RECORD &	E = *pException->ExceptionRecord;
		CONTEXT &			C = *pException->ContextRecord;

		// If module with E.ExceptionAddress found - save its path and date.
		if (Get_Module_By_Ret_Addr((PBYTE)E.ExceptionAddress, Module_Name, Module_Addr))
		{
			Str_Len += wsprintf(Str + Str_Len, NL "Module:  %s", Module_Name);

			if ((hFile = CreateFile(Module_Name, 
				GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE)
			{
				if (GetFileTime(hFile, NULL, NULL, &Last_Write_Time))
				{
					FileTimeToLocalFileTime(&Last_Write_Time, &Local_File_Time);
					FileTimeToSystemTime(&Local_File_Time, &T);

					Str_Len += wsprintf(Str + Str_Len,
						NL "Date Modified:  %02d/%02d/%d",
						T.wMonth, T.wDay, T.wYear);
				}
				CloseHandle(hFile);
			}
		}
		else
		{
			Str_Len += wsprintf(Str + Str_Len,
				NL "Exception Addr:  %08X", E.ExceptionAddress);
		}
		
		Str_Len += wsprintf(Str + Str_Len,
			NL "Exception Code:  %08X", E.ExceptionCode);
		
		if (E.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
		{
			// Access violation type - Write/Read.
			Str_Len += wsprintf(Str + Str_Len,
				NL "%s Address:  %08X",
				(E.ExceptionInformation[0]) ? "Write" : "Read", E.ExceptionInformation[1]);
		}

		// Save instruction that caused exception.
		Str_Len += wsprintf(Str + Str_Len, NL "Instruction: ");
		for (i = 0; i < 16; i++)
			Str_Len += wsprintf(Str + Str_Len, " %02X", PBYTE(E.ExceptionAddress)[i]);

		// Save registers at exception.
		Str_Len += wsprintf(Str + Str_Len, NL "Registers:");
		Str_Len += wsprintf(Str + Str_Len, NL "\tEAX: %08X  EBX: %08X  ECX: %08X  EDX: %08X", C.Eax, C.Ebx, C.Ecx, C.Edx);
		Str_Len += wsprintf(Str + Str_Len, NL "\tESI: %08X  EDI: %08X  ESP: %08X  EBP: %08X", C.Esi, C.Edi, C.Esp, C.Ebp);
		Str_Len += wsprintf(Str + Str_Len, NL "\tEIP: %08X  EFlags: %08X", C.Eip, C.EFlags);

	} // if (pException)
	
	// Save call stack info.
	Str_Len += wsprintf(Str + Str_Len, NL "Call Stack:");
	Get_Call_Stack(pException, Str + Str_Len);

	if (Str[0] == NL[0])
		lstrcpy(Str, Str + sizeof(NL) - 1);

	return Str;
}

//*************************************************************************************
// Create dump. 
// pException can be either GetExceptionInformation() or NULL.
// If File_Flag = TRUE - write dump files (.dmz and .dmp) with the name of the current process.
// If Show_Flag = TRUE - show message with Get_Exception_Info() dump.
void WINAPI Create_Dump(PEXCEPTION_POINTERS pException, BOOL File_Flag, BOOL Show_Flag)
{
	HANDLE	hFile;
	PCHAR	Str;
	CHAR	DumpPath[MAX_PATH];
	DWORD	Bytes;

	Str = Get_Exception_Info(pException);

	if (Show_Flag && Str)
		MessageBox(NULL, Str, "MiniDump", MB_ICONHAND | MB_OK);

	if (File_Flag)
	{
		GetModuleFileName(NULL, DumpPath, sizeof(DumpPath));	//path of current process

		if (Str)
		{
			lstrcpy (DumpPath + lstrlen(DumpPath) - 4, ".txt");

			hFile = CreateFile (DumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			WriteFile (hFile, Str, lstrlen(Str) + 1, &Bytes, NULL);

			CloseHandle (hFile);
		}

		// If MiniDumpWriteDump() of DbgHelp.dll available.
		if (MiniDumpWriteDump_)
		{
			MINIDUMP_EXCEPTION_INFORMATION	DmpInfo;

			DmpInfo.ThreadId = GetCurrentThreadId();
			DmpInfo.ExceptionPointers = pException;
			DmpInfo.ClientPointers = 0;

			lstrcpy (DumpPath + lstrlen(DumpPath) - 4, ".dmp");

			hFile = CreateFile (DumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			MiniDumpWriteDump_(GetCurrentProcess(), GetCurrentProcessId(), hFile,
				MiniDumpNormal, (pException) ? &DmpInfo : NULL, NULL, NULL);

			CloseHandle(hFile);
		}
	} //if (File_Flag)

	delete Str;
}



/**
	@breif	
	@param	lpszFuncName	[in]	
	@return 
*/
VOID PrintLastErrorMessage(LPCTSTR lpszFuncName)
{
	DWORD dwError = GetLastError();      
	LPVOID lpMsgBuf;	
	FormatMessage(								
		FORMAT_MESSAGE_FROM_SYSTEM | 								
		FORMAT_MESSAGE_IGNORE_INSERTS |								
		FORMAT_MESSAGE_ALLOCATE_BUFFER, 								
		NULL, 								
		dwError, 								
		MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), 								
		(PTSTR) &lpMsgBuf, 								
		0, 								
		NULL);
	printf("%s - %s\n", lpszFuncName, (LPTSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
}





/**
	@breif	Check exist lpszPath file.
	@param	lpszPath	[in]	It's file full path.
	@return 
*/
BOOL IsFileExists(LPCTSTR lpszPath)
{
	BOOL b = FALSE;
		
	try 
	{
		WIN32_FIND_DATA fd;
		HANDLE hFind = FindFirstFile(lpszPath, &fd);
		if (hFind != INVALID_HANDLE_VALUE)
		{
			FindClose(hFind);
			b = !(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
		}
	}
	catch (...)
	{
		//ode(_T("[EXCEPTION] __IsFileExists... FindFirstFile... %s"), pszPath);
	}
	
	if (!b)
	{
		try 
		{
			HANDLE hFile = CreateFile(lpszPath, \
				GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				CloseHandle(hFile);
				b = TRUE;
			}
		}
		catch (...)
		{
		}
	}
	
	return b;
}

