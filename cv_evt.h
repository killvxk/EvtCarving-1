#pragma once

// Event Log File Format
// http://msdn.microsoft.com/en-us/library/windows/desktop/bb309026(v=vs.85).aspx

const BYTE  EVT_sigHEADER[4]		= {0x4C, 0x66, 0x4C, 0x65};

typedef struct _EVTHEADER
{
	UINT		Length1;
	UINT		Magic;					// CHAR		Magic[4];		// "LfLe"
	UINT		MajorVer;				// ??
	UINT		MinorVer;				// ??

	UINT		OfsFirst;				// 첫번째 레코드 위치
	UINT		OfsNext;				// 풋터의 위치
	UINT		NumNext;				// 전체개수 + 1
	UINT		NumFirst;				// 1로 고정하자.
	
	UINT		FileSize;				// evt 파일  최대 크기.
	UINT		Flag;					// 짝수(0x08,0x00) 닫침, 홀수(0x09,0x0B) 열림
	UINT		Retention;				// ??
	UINT		Length2;

	_EVTHEADER()
	{
		Length1  = 0x30;
		Magic	 = 0x654c664c;
		MajorVer = 0x01;				// EventLogParser.exe 가 evt 검증할 때 1인지 검사함.
		MinorVer = 0x01;				// EventLogParser.exe 가 evt 검증할 때 1인지 검사함.
		OfsFirst = 0x30;
		OfsNext  = 0x00;				// <---
		NumNext  = 0x00;				// <---
		NumFirst = 1;
		FileSize = 0x00010000;			// 0x40000000;			// <--- 100 MB
		Flag     = 0x08;
		Retention= 0x00093A80;
		Length2  = 0x30;
	}

} EVTHEADER, *PEVTHEADER;

typedef struct _EVTFOOTER
{
	DWORD		dwFooterSize1;
	DWORD		dwOne;
	DWORD		dwTwo;
	DWORD		dwThree;
	DWORD		dwFour;
	DWORD		dwOldestEvtOffset;
	DWORD		dwNextEvtOffset;
	DWORD		dwNextEventID;
	DWORD		dwOldestEvtID;
	DWORD		dwFooterSize2;

	_EVTFOOTER()
	{
		dwFooterSize1 = dwFooterSize2 = 0x28;
		dwOne				= 0x11111111;
		dwTwo				= 0x22222222;
		dwThree				= 0x33333333;
		dwFour				= 0x44444444;
		dwOldestEvtOffset	= 0x30;		// 해더의 크기를 넣으면 됨
		dwNextEvtOffset		= 0x00;		// 풋터의 시작 옵셋
		dwNextEventID		= 0x00;		// 전체개수 + 1		
		dwOldestEvtID		= 0x01;		// 1로 고정하자!
	}
} EVTFOOTER, *PEVTFOOTER;

typedef enum _EVENT_GROUP 
{
	Unknown          = 0x01,
	Security         = 0x02,
	System           = 0x04,
	Application      = 0x08,
	InternetExplorer = 0x10
} EVENT_GROUP, *PEVENT_GROUP;

struct EVTRECORD_BLOCK
{
	WORD  EventGroup;
	DWORD dwBlockSize;	
	BYTE* pBlock;
};

DWORD _EvtCarving(LPVOID pMap, DWORD dwFileSize, BYTE** evt_a_record, DWORD& size_front);
DWORD EvtCarving(LPVOID pMap, DWORD dwFileSize, BYTE** evt_a_record, DWORD& size_front);
VOID EvtFree();
VOID EvtWriteHeader(CFile& f, int nMax);
VOID EvtWriteRecord(CFile& f, EVENT_GROUP emGroup);
VOID EvtWriteFooter(CFile& f, int nMax);
VOID EvtWriteByGroup(CString& strOutputPath);

