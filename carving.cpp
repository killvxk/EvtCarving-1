/******************************************************************************

  Copyright forensicinsight.org, Inc. since 2011, All rights reserved.

    Any part of this source code can not be copied with
    any method without prior written permission from
    the author or authorized person.

	Author : Park HoJin (hojinpk@gmail.com)
	Date : 2011.12.07

	File Name : carving.cpp
	File Description :

*****************************************************************************/

#include "stdafx.h"
#include "carving.h"
#include "cv_evt.h"
#include "cv_evtx.h"
#include "SimpleOpt.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


/////////////////////////////////////////////////////////////////////////////
// The one and only application object
#ifndef INVALID_FILE_ATTRIBUTES
# define INVALID_FILE_ATTRIBUTES    ((DWORD)-1)
#endif

#define MAX_ENUM_DIR	10

DWORD LoadImage(LPCTSTR lpszPath);
DWORD EnumDir(LPCTSTR pszDir, int nDepth=0);
BOOL g_bVerbose = FALSE;
BOOL g_bDB = FALSE;
CString g_strOutPath;
CString g_strOutputType;
CString g_strParsingFilePath;
int	g_chunk_maxnum = 1000;

extern CHUNKLIST g_chunk;

VOID ShowUsage()
{
	printf("\nevtrec_carver.exe [-i FILE|DIR] [-o DIR] [-v]\n");
	printf("   -i, --path=FILE|DIR    Path of input file or folder\n");
	printf("   -t, --type=evt|evtx    Set type of input file\n");
	printf("   -n, --chunkmax=NUM     Set chunk max count in a evtx file\n");
	printf("   -o, --output=DIR       Output folder path\n");
	printf("   -p, --parse=FILE       Target file path\n");
	printf("   -v, --verbose          Verbose mode\n");	
	printf("\n");
}

enum 
{
	OPT_INPUT,
	OPT_TYPE, 
	OPT_OUTPATH,
	OPT_CHUNKMAX,
	OPT_PARSE,
	OPT_VERBOSE, 
	OPT_HELP 
};

CSimpleOpt::SOption g_rgOptions[] =
{
	{ OPT_INPUT,		_T('i'),	_T("input"),		SO_REQ_SEP },
    { OPT_TYPE,			_T('t'),	_T("type"),			SO_REQ_SEP },
    { OPT_OUTPATH,		_T('o'),	_T("output"),		SO_REQ_SEP },
	{ OPT_CHUNKMAX,		_T('n'),	_T("chunkmax"),		SO_REQ_SEP },
	{ OPT_PARSE,		_T('p'),	_T("parse"),		SO_REQ_SEP },	
	{ OPT_VERBOSE,		_T('v'),	_T("verbose"),		SO_NONE },
    { OPT_HELP,			_T('h'),	_T("help"),			SO_NONE },
    SO_END_OF_OPTIONS
};


int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	UNUSED_ALWAYS(envp);
	
	if (!AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0))
		return EXIT_FAILURE;
	
	CString strTarget;
	
	BOOL bSort = FALSE;
	
	CSimpleOpt args(argc, argv, g_rgOptions, TRUE);
    while (args.Next()) 
	{
        if (args.LastError() != SO_SUCCESS) 
		{
            TCHAR* pszError = _T("Unknown error");
            switch (args.LastError()) 
			{
            case SO_OPT_INVALID:  pszError =     _T("Unrecognized option"); break;
            case SO_OPT_MULTIPLE: pszError =     _T("Option matched multiple strings"); break;
            case SO_ARG_INVALID:  pszError =     _T("Option does not accept argument"); break;
            case SO_ARG_INVALID_TYPE: pszError = _T("Invalid argument format"); break;
            case SO_ARG_MISSING:  pszError =     _T("Required argument is missing"); break;
            }
            printf(_T("%s: '%s' (use --help to get command line help)\n"), 
				pszError, args.OptionText());
            return 1;
        }
		
		switch (args.OptionId())
		{
		case OPT_INPUT:
			strTarget = args.OptionArg();
			strTarget.TrimRight(_T('\\'));
			break;

		case OPT_TYPE:
			g_strOutputType = args.OptionArg();
			if (g_strOutputType.CompareNoCase("evt")!=0 &&
				g_strOutputType.CompareNoCase("evtx")!=0 &&
				g_strOutputType.CompareNoCase("csv")!=0 &&
				g_strOutputType.CompareNoCase("sqlite")!=0)
			{
				printf("Error!!!\n'%s' is not supported output type.\n", g_strOutputType);
				printf("Sorry about that :-)\n");
				return EXIT_FAILURE;
			}
			break;

		case OPT_OUTPATH:
			g_strOutPath = args.OptionArg();
			break;

		case OPT_CHUNKMAX:			
			g_chunk_maxnum = atoi(args.OptionArg());
			break;

		case OPT_PARSE:
			g_strParsingFilePath = args.OptionArg();
			break;

		case OPT_VERBOSE: 
			g_bVerbose = TRUE; 
			break;
			
		case OPT_HELP: 
			ShowUsage(); 
			return EXIT_SUCCESS;
		}
    }

	if (g_strOutputType.IsEmpty())
		g_strOutputType = "evt";

	if (!g_strOutputType.Compare("evtx"))
		EvtxInit();


	// Just parsing...

	if (!g_strParsingFilePath.IsEmpty())
	{
		if (!g_strOutputType.Compare("evtx"))
		{
			ParseEvtx(g_strParsingFilePath);
		}
		else
		{
			printf("Sorry, It's not supported yet!\n");
		}
		return EXIT_SUCCESS;
	}


	// Carving...

	//
	// Check Invalid Parameter(s)
	//
	
	if (strTarget.IsEmpty() || 
		g_strOutPath.IsEmpty())
	{
		ShowUsage();
		return EXIT_FAILURE;
	}

	DWORD dwState = GetFileAttributes (strTarget);
	if (INVALID_FILE_ATTRIBUTES == dwState)
	{
		printf("%s is not found\n", strTarget);
		return EXIT_FAILURE;
	}

	LARGE_INTEGER liCounter1, liCounter2, liFrequency;
	QueryPerformanceFrequency(&liFrequency);
	QueryPerformanceCounter(&liCounter1);
	{		
		if (FILE_ATTRIBUTE_DIRECTORY & dwState)
		{	
			printf("Record count: %d\n", EnumDir(strTarget));
		}
		else
		{
			printf("%s ", strTarget);
			printf("(%d)\n", LoadImage(strTarget));
		}
	}
	QueryPerformanceCounter(&liCounter2);
	printf("Time : %f\n", (double)(liCounter2.QuadPart - liCounter1.QuadPart)/(double)liFrequency.QuadPart);

	if (!g_strOutputType.Compare("evt"))
	{
		printf("Write Windows Event Log File(s)...\n");
		EvtWriteByGroup(g_strOutPath);
	}
	else if (!g_strOutputType.Compare("evtx"))
	{
		printf("Write Windows Event Log File(s)...\n");
		WriteEvtx(g_strOutPath);
	}

	return EXIT_SUCCESS;
}





/**
	@brief	지정된 폴더 하위에 존재하는 파일을 카빙 대상으로하여 카빙을 수행함.
	@param	pszDir	[in]	폴더 경로
	@param	nDepth	[in]	폴더의 깊이, 폴더의 깊이가 최대 MAX_ENUM_DIR 까지만 지원함.
	@return	대상이 되는 전체 파일에서 찾은 윈도우 이벤트 로그 레코드 개수
 */
DWORD EnumDir(LPCTSTR pszDir, int nDepth)
{
	DWORD dwRecordAccumulateCnt = 0;
	CFileFind ff;
	
	CString	sWildCard = pszDir;
	sWildCard += _T("\\*.*");
	
	BOOL bWorking = ff.FindFile(sWildCard);
	while (bWorking && nDepth < MAX_ENUM_DIR)
	{
		bWorking = ff.FindNextFile();

		if (ff.IsDots())
			continue;
		
		CString sFilePath = ff.GetFilePath();

		if (ff.IsDirectory())
			dwRecordAccumulateCnt += EnumDir(sFilePath, nDepth+1);
		else
		{	
			printf("%s ", sFilePath);
			const DWORD dwRecordCnt = LoadImage(sFilePath);
			printf("(%d)\n", dwRecordCnt);
			
			dwRecordAccumulateCnt += dwRecordCnt;
		}
	}
	return dwRecordAccumulateCnt;
}







/**
	@brief	파일을 메모리에 올려 이벤트 로그 레코드 카빙을 수행함.
			대용량 파일을 지원하고 속도개선을 위해 메모리맵 파일을 이용함.
	@param	lpszPath	[in]	카빙 대상인 파일 경로
	@return	파일에서 찾은 윈도우 이벤트 로그 레코드 개수
 */
DWORD LoadImage(LPCTSTR lpszPath)
{
	// Open the data file
	SYSTEM_INFO _SystemInformation;
	GetSystemInfo(&_SystemInformation);
	
	HANDLE hFile = CreateFile(lpszPath, GENERIC_READ, FILE_SHARE_READ, NULL, 
		OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL) ;
	if (hFile == INVALID_HANDLE_VALUE) return FALSE;
	
	// Create the file-mapping object.
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL) ;
	if (hFileMapping == NULL) return FALSE;
	
	DWORD dwFileSizeHigh;
	__int64 qwFileSize = GetFileSize(hFile, &dwFileSizeHigh);
	qwFileSize += (((__int64)dwFileSizeHigh) << 32);
	const __int64 dwDumpFileSize = qwFileSize;

	// We no longer need access to the file object's handle
	CloseHandle(hFile) ;
	
	DWORD dwBytesInBlock;
	__int64 qwFileOffset = 0;
	LPVOID pFile;	
	DWORD dwFoundRecord = 0;
	
	BYTE* buf = NULL;
	DWORD size_front = 0;	
	
	__int64 nPrevPercent = -1;
	__int64 percent;
	
	while (qwFileSize > 0)
	{
		// Determine the number of bytes to be mapped.
		if (qwFileSize < _SystemInformation.dwAllocationGranularity)
			dwBytesInBlock = (DWORD) qwFileSize ;
		else
			dwBytesInBlock = _SystemInformation.dwAllocationGranularity ;
	
		pFile = MapViewOfFile(hFileMapping,
			FILE_MAP_READ,
			(DWORD) (qwFileOffset >> 32),
			(DWORD) (qwFileOffset & 0xFFFFFFFF),
			dwBytesInBlock);
		if (!pFile)
		{
			printf("\n");
			PrintLastErrorMessage("MapViewOfFile");
			break;
		}
		
		// 작업
		if (!g_strOutputType.Compare("evt"))
		{
			dwFoundRecord += EvtCarving(pFile, dwBytesInBlock, &buf, size_front);
		}
		else if (!g_strOutputType.Compare("evtx"))
		{
			dwFoundRecord += CarvingEvtx(pFile, dwBytesInBlock, size_front);
		}
		
		UnmapViewOfFile(pFile);

		qwFileOffset += dwBytesInBlock;
		qwFileSize -= dwBytesInBlock;

		percent = qwFileOffset*100/dwDumpFileSize;
		if (nPrevPercent/10 != percent/10)
		{
			nPrevPercent = percent;
			printf(".");
		}

		// WriteEvtx()
	}
	printf(" ");
	CloseHandle(hFileMapping);
	return dwFoundRecord;
}
//////////////////////////////////////////////////////////////////////////