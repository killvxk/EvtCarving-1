/******************************************************************************

  Copyright forensicinsight.org, Inc. since 2011, All rights reserved.

    Any part of this source code can not be copied with
    any method without prior written permission from
    the author or authorized person.

	Author : Park HoJin (hojinpk@gmail.com)
	Date : 2011.12.07

	File Name : cv_evt.cpp
	File Description :

*****************************************************************************/

#include "StdAfx.h"
#include "cv_evt.h"

// 이벤트 로그 레코드 저장소
CArray<EVTRECORD_BLOCK, EVTRECORD_BLOCK&> g_arEvtRecord;


/**
	@brief	바이너리 데이터를 SID 표기형식으로 변경한다.
	@param	sid		[in]	SID의 바이너리 데이터
	@return	SID 표기형식에 따른 SID 문자열
 */
CString ReadSID( SID &sid ) 
{
	short i;
	int id = 0;
	CString ret;
	CString ridstr;	

	for (i=1; i<=5; i++) 
		id = 256*id + sid.IdentifierAuthority.Value[i];
	if (sid.Revision != SID_REVISION)
		return "";
	ret.Format("S-%u-%u", sid.Revision, id);

	ret += sid.IdentifierAuthority.Value;
	for (i=0; i<sid.SubAuthorityCount; i++ ) 
	{
		ridstr.Format("-%u", sid.SubAuthority[i]);
		ret += ridstr;
	}
	return ret;
}



/**
	@brief	메모리(pMap)를 순차적으로 읽어 이벤트 레코드를 찾아 검증 후 해당 레코드를 기록한다.
	@param	pMap			[in]	카빙 대상 메모리
	@param	dwFileSize		[in]	메모리 크기
	@param	evt_a_record	[out]	하나의 이벤트 로그 레코드
	@param	size_front		[out]	레코드 앞부분
	@return the number of carving windows event log record
 */
DWORD _EvtCarving(LPVOID pMap, DWORD dwFileSize, BYTE** evt_a_record, DWORD& size_front)
{
	DWORD dwFoundRecord = 0;
	DWORD i = 0;
	CHAR* pOffset = NULL;
	DWORD dwSize1 = 0;
	DWORD dwSize2 = 0;
	DWORD dwMax = dwFileSize - (4+sizeof(EVT_sigHEADER));

	try
	{
		for (i=0; i < dwMax; i++)
		{	
			dwSize1 = dwSize2 = 0;

			// Search for EVT header signature
			pOffset = (CHAR*)pMap + i;
			
			if (pOffset[4]=='L' &&
				pOffset[5]=='f' &&
				pOffset[6]=='L' &&
				pOffset[7]=='e')
			{
				dwSize1 = (DWORD&)*pOffset;

				// 이벤트 레코드 기본 조건 검사.
				if ( dwSize1 <= 0x30 || dwSize1 > 0x400 )
					continue;

				// 읽어들인 메모리가 더 읽어야 하는 메모리보다 작은 경우
				// 해당 지점부터 다시 읽어들인다.
				const DWORD dw1 = (DWORD)((CHAR*)pMap+dwFileSize);
				const DWORD dw2 = (DWORD)(pOffset+dwSize1);
				if ( dw1 < dw2 )
				{
					// 비할당 영역의 파일을 메모리로 읽어들일 경우 align 에 맞춰야 하기 때문에
					// 한번 읽어들인 메모리의 끝자락에 레코드가 걸쳐 있을 수 있다.
					
					// 이러한 경우 앞부분을 저장하고
					// 다음번에 비할당 영역을 메모리에 올릴 때 
					// 뒷부분을 마져 붙여 하나의 온전한 이벤트 로그 레코드로 만든다.
					
					size_front = dwFileSize - i;
					*evt_a_record = (BYTE*)malloc(dwSize1);
					memset(*evt_a_record, 0x00, dwSize1);
					memcpy(*evt_a_record, pOffset, size_front);
					
					return dwFoundRecord;
				}

				const WORD EventType = (WORD&)*((CHAR*)pOffset+0x18);
				if (EventType != EVENTLOG_ERROR_TYPE &&
					EventType != EVENTLOG_AUDIT_FAILURE &&
					EventType != EVENTLOG_AUDIT_SUCCESS &&
					EventType != EVENTLOG_INFORMATION_TYPE &&
					EventType != EVENTLOG_WARNING_TYPE)
				{
					continue;
				}

				const DWORD StringOffset = (DWORD&)*((CHAR*)pOffset+0x24);
				if (StringOffset > dwSize1)
					continue;

				const DWORD UserSidLength = (DWORD&)*((CHAR*)pOffset+0x28);
				const DWORD UserSidOffset = (DWORD&)*((CHAR*)pOffset+0x2C);
				if (UserSidLength > dwSize1 || UserSidOffset > dwSize1)
					continue;

				if (UserSidLength > 0)
				{
					PSID pSID = (PSID)((CHAR*)pOffset+UserSidOffset);
					if(!IsValidSid(pSID)) 
						continue;
// 					CString strSid = ReadSID((SID&)*((CHAR*)pOffset+UserSidOffset));
// 					if (strSid.IsEmpty())
// 						continue;
//					LPTSTR sidString;
// 					if (!ConvertSidToStringSid((CHAR*)pOffset+UserSidOffset, &sidString))
// 						continue;
				}
				
				dwSize2 = (DWORD&)*(pOffset+dwSize1-sizeof(DWORD));
				if (dwSize1 == dwSize2)
				{
					EVTRECORD_BLOCK block;
					block.dwBlockSize = dwSize1;
					block.pBlock = (BYTE*)malloc(dwSize1);
					memcpy (block.pBlock, pOffset, dwSize1);


					EVENTLOGRECORD* pEvt = (EVENTLOGRECORD*)block.pBlock;
					int nCurPos = sizeof(EVENTLOGRECORD);
					WCHAR* SourceName = (WCHAR*)(pOffset + nCurPos);
					if (!lstrcmpW(SourceName, L"Security"))
					{
						block.EventGroup = Security;
					}
					else 
					{
						block.EventGroup = Unknown;
						// printf("%S\n", SourceName);
					}
 					
 					nCurPos += (wcslen(SourceName)+1)*2;
 					WCHAR* Computername = (WCHAR*)(pOffset + nCurPos);
 					// printf("%S\n", Computername);
 
// 					const int nDesc = (pEvt->DataOffset - pEvt->StringOffset) / 2;
// 					CHAR* szDesc = new CHAR[nDesc+1];
// 					memset(szDesc, 0x00, nDesc+1);
// 					int k=0;
// 					for(DWORD j=pEvt->StringOffset; j<pEvt->DataOffset; j+=2)
// 					{
// 						CHAR ch = (CHAR)*(pOffset + j);
// 						if (ch == 0x00) ch = ',';
// 						szDesc[k++] = ch;
// 						if (j > dwSize1)
// 						{
// 							pEvt->DataOffset = dwSize1 - sizeof(DWORD);
// 							break;
// 						}
// 					}
//					// printf("%s\n", szDesc);
// 					delete szDesc;
					
					if (pEvt->DataOffset > dwSize1)
						pEvt->DataOffset = dwSize1 - sizeof(DWORD);
					
					g_arEvtRecord.Add(block);
					
					dwFoundRecord++;
					
					i += (dwSize1-1);
				}
			}
		}
	}
	catch(...)
	{
		// dwFileSize = i;
	}

#ifdef _DEEP_DEBUG
	int nCnt1 = 0;
	int nCnt2 = 0;

	for(int q=0; q<g_arEvtRecord.GetSize(); q++)
	{
		EVTRECORD_BLOCK& block = g_arEvtRecord.GetAt(q);
// 		EVENTLOGRECORD* pEvt = (EVENTLOGRECORD*)block.pBlock;
// 		CTime tm(pEvt->TimeGenerated);
// 		printf("%s\n", tm.Format("%Y-%m-%d %H:%M:%S"));

		(block.EventGroup == Security)?nCnt1++:nCnt2++;
	}
	printf("nCnt1:%d, nCnt2:%d\n", nCnt1, nCnt2);
#endif
	
	return dwFoundRecord;
}


/**
	@brief	메모리(pMap)를 순차적으로 읽어 이벤트 레코드를 찾아 검증 후 해당 레코드를 기록한다.
	@param	pMap			[in]	카빙 대상 메모리
	@param	dwFileSize		[in]	메모리 크기
	@param	evt_a_record	[out]	하나의 이벤트 로그 레코드 버퍼
	@param	size_front		[out]	evt_a_record 에 기록된 앞부분 크기
									evt_a_record 의 크기는 이벤트 로그 구조상
									가장 앞 부분의 4바이트에 해당함으로 별도로 기록하지 않는다.
	@return the number of carving windows event log record
 */
DWORD EvtCarving(LPVOID pMap, DWORD dwFileSize, BYTE** evt_a_record, DWORD& size_front)
{
	DWORD dwCnt = 0;

	if (IsBadReadPtr (pMap, dwFileSize))
	{
		return 0;
	}

	if (size_front > 0)
	{
		DWORD dwSize1 = (DWORD&)*(*evt_a_record);
		DWORD size_rear = dwSize1 - size_front;
		DWORD dwSize2 = (DWORD&)*((CHAR*)pMap + (size_rear-sizeof(DWORD)));
		if (dwSize1 == dwSize2)
		{
			DWORD dwTemp = 0;
			memcpy(*evt_a_record+size_front, pMap, size_rear);

			dwCnt += _EvtCarving(*evt_a_record, dwSize1, NULL, dwTemp);
			
			free(*evt_a_record);
			*evt_a_record = NULL;
			size_front = 0;
			
			pMap = (CHAR*)pMap + size_rear;
			dwFileSize -= size_rear;
		}
	}
	
	dwCnt += _EvtCarving(pMap, dwFileSize, evt_a_record, size_front);

	return dwCnt;
}





/**
	@brief	이벤트 레코드의 해더를 넣는다.
	@param	f		[in]	윈도우 이벤트 레코드 해더를 기록할 파일의 객체
	@param	nMax	[in]	파일에 기록할 이벤트 레코드의 개수
	@return	void
 */
VOID EvtWriteHeader(CFile& f, int nMax)
{
	EVTHEADER evtHeader;
	evtHeader.OfsNext = 0;						// 풋터의 위치
	evtHeader.NumNext = nMax + 1;				// 전체개수 + 1
	evtHeader.FileSize = 0x10000;				// evt 파일 최대 크기. (일단고정)
	f.SeekToBegin();
	f.Write ((VOID*)&evtHeader, sizeof(EVTHEADER));	
}







/**
	@brief	emGroup 과 일치하는 윈도우 이벤트 레코드를 기록한다.
	@param	f		[in] 기록할 파일 객체
	@param	emGroup	[in] 윈도우 이벤트 그룹 식별자
	@return	void
 */
VOID EvtWriteRecord(CFile& f, EVENT_GROUP emGroup)
{
	f.SeekToEnd();
	const int nMax = g_arEvtRecord.GetSize();
	int nRecCnt = 1;
	for (int k=0; k<nMax; k++)
	{
		EVTRECORD_BLOCK& block = g_arEvtRecord[k];
		if ((block.EventGroup & emGroup) == emGroup)
		{			
			EVENTLOGRECORD* pEvt = (EVENTLOGRECORD*)block.pBlock;
			pEvt->RecordNumber = nRecCnt++;			// 레코드 일련변호를 순차적으로 기록한다.
			f.Write(block.pBlock, block.dwBlockSize);
		}
	}
}





/**
	@brief	이벤트 레코드의 풋터를 붙인다.
	@param	f		[in]	윈도우 이벤트 로그의 풋터를 기록할 파일 객체
	@param	nMax	[in]	윈도우 이벤트 로그 파일에 기록된 레코드의 개수
	@return	void
 */
VOID EvtWriteFooter(CFile& f, int nMax)
{
	const DWORD dwLastPos = f.GetPosition();
	
	EVTHEADER evtHeader;
	evtHeader.OfsNext = dwLastPos;					// 풋터의 위치
	evtHeader.NumNext = nMax + 1;					// 전체개수 + 1
	evtHeader.FileSize = 0x40000000;				// evt 파일 최대 크기. (일단고정)
	f.SeekToBegin();
	f.Write ((VOID*)&evtHeader, sizeof(EVTHEADER));
	
	EVTFOOTER evtFooter;
	evtFooter.dwNextEvtOffset = dwLastPos;			// 풋터의 시작 옵셋
	evtFooter.dwNextEventID = nMax+1;				// 전체개수 + 1	
	f.SeekToEnd();
	f.Write ((VOID*)&evtFooter, sizeof(EVTFOOTER));	
}






/**
	@brief	이벤트 레코드를 윈도우 이벤트 로그 형식에 따라 파일로 기록한다.
			단, Security 그룹은 레코드단위에서 구별할 수 있기때문에 별도의 파일로 기록했다.
	@param	strOutputPath		[in]	결과물을 저장할 폴더의 전체경로
	@return	void
 */
VOID EvtWriteByGroup(CString& strOutputPath)
{
	const int nMax = g_arEvtRecord.GetSize();
	int nSec = 0;
	int nUnknown = 0;
	for (int k=0; k<nMax; k++)
	{
		EVTRECORD_BLOCK& block = g_arEvtRecord[k];
		if (block.EventGroup == Security)
			nSec++;
	}
	nUnknown = nMax - nSec;
	
	if (nSec > 0)
	{
		CFile fSec;
		if (fSec.Open (strOutputPath+_T("\\SecEvent.evt"), CFile::modeCreate|CFile::modeWrite))
		{
			EvtWriteHeader(fSec, nSec);	
			EvtWriteRecord(fSec, Security);
			EvtWriteFooter(fSec, nSec);
			fSec.Close ();
		}
	}

	if (nUnknown > 0)
	{
		CFile fUnknown;
		if (fUnknown.Open (strOutputPath+_T("\\Unknown.evt"), CFile::modeCreate|CFile::modeWrite))
		{
			EvtWriteHeader(fUnknown, nUnknown);	
			// EvtWriteRecord(fOther, (EVENT_GROUP)(0xFF&~(Security)));
			EvtWriteRecord(fUnknown, Unknown);
			EvtWriteFooter(fUnknown, nUnknown);
			fUnknown.Close ();
		}
	}

	EvtFree();
}





/**
	@brief	free of dynamic allocated memeory
	@param	void
	@return	void
 */
VOID EvtFree()
{	
	const int nMax = g_arEvtRecord.GetSize();
  	for (int j=nMax; j>0; j--)
	{
		const EVTRECORD_BLOCK& block = g_arEvtRecord[j-1];
  		free (block.pBlock);
	}
	g_arEvtRecord.RemoveAll();
}
//////////////////////////////////////////////////////////////////////////