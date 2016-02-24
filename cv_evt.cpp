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

// �̺�Ʈ �α� ���ڵ� �����
CArray<EVTRECORD_BLOCK, EVTRECORD_BLOCK&> g_arEvtRecord;


/**
	@brief	���̳ʸ� �����͸� SID ǥ���������� �����Ѵ�.
	@param	sid		[in]	SID�� ���̳ʸ� ������
	@return	SID ǥ�����Ŀ� ���� SID ���ڿ�
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
	@brief	�޸�(pMap)�� ���������� �о� �̺�Ʈ ���ڵ带 ã�� ���� �� �ش� ���ڵ带 ����Ѵ�.
	@param	pMap			[in]	ī�� ��� �޸�
	@param	dwFileSize		[in]	�޸� ũ��
	@param	evt_a_record	[out]	�ϳ��� �̺�Ʈ �α� ���ڵ�
	@param	size_front		[out]	���ڵ� �պκ�
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

				// �̺�Ʈ ���ڵ� �⺻ ���� �˻�.
				if ( dwSize1 <= 0x30 || dwSize1 > 0x400 )
					continue;

				// �о���� �޸𸮰� �� �о�� �ϴ� �޸𸮺��� ���� ���
				// �ش� �������� �ٽ� �о���δ�.
				const DWORD dw1 = (DWORD)((CHAR*)pMap+dwFileSize);
				const DWORD dw2 = (DWORD)(pOffset+dwSize1);
				if ( dw1 < dw2 )
				{
					// ���Ҵ� ������ ������ �޸𸮷� �о���� ��� align �� ����� �ϱ� ������
					// �ѹ� �о���� �޸��� ���ڶ��� ���ڵ尡 ���� ���� �� �ִ�.
					
					// �̷��� ��� �պκ��� �����ϰ�
					// �������� ���Ҵ� ������ �޸𸮿� �ø� �� 
					// �޺κ��� ���� �ٿ� �ϳ��� ������ �̺�Ʈ �α� ���ڵ�� �����.
					
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
	@brief	�޸�(pMap)�� ���������� �о� �̺�Ʈ ���ڵ带 ã�� ���� �� �ش� ���ڵ带 ����Ѵ�.
	@param	pMap			[in]	ī�� ��� �޸�
	@param	dwFileSize		[in]	�޸� ũ��
	@param	evt_a_record	[out]	�ϳ��� �̺�Ʈ �α� ���ڵ� ����
	@param	size_front		[out]	evt_a_record �� ��ϵ� �պκ� ũ��
									evt_a_record �� ũ��� �̺�Ʈ �α� ������
									���� �� �κ��� 4����Ʈ�� �ش������� ������ ������� �ʴ´�.
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
	@brief	�̺�Ʈ ���ڵ��� �ش��� �ִ´�.
	@param	f		[in]	������ �̺�Ʈ ���ڵ� �ش��� ����� ������ ��ü
	@param	nMax	[in]	���Ͽ� ����� �̺�Ʈ ���ڵ��� ����
	@return	void
 */
VOID EvtWriteHeader(CFile& f, int nMax)
{
	EVTHEADER evtHeader;
	evtHeader.OfsNext = 0;						// ǲ���� ��ġ
	evtHeader.NumNext = nMax + 1;				// ��ü���� + 1
	evtHeader.FileSize = 0x10000;				// evt ���� �ִ� ũ��. (�ϴܰ���)
	f.SeekToBegin();
	f.Write ((VOID*)&evtHeader, sizeof(EVTHEADER));	
}







/**
	@brief	emGroup �� ��ġ�ϴ� ������ �̺�Ʈ ���ڵ带 ����Ѵ�.
	@param	f		[in] ����� ���� ��ü
	@param	emGroup	[in] ������ �̺�Ʈ �׷� �ĺ���
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
			pEvt->RecordNumber = nRecCnt++;			// ���ڵ� �Ϸú�ȣ�� ���������� ����Ѵ�.
			f.Write(block.pBlock, block.dwBlockSize);
		}
	}
}





/**
	@brief	�̺�Ʈ ���ڵ��� ǲ�͸� ���δ�.
	@param	f		[in]	������ �̺�Ʈ �α��� ǲ�͸� ����� ���� ��ü
	@param	nMax	[in]	������ �̺�Ʈ �α� ���Ͽ� ��ϵ� ���ڵ��� ����
	@return	void
 */
VOID EvtWriteFooter(CFile& f, int nMax)
{
	const DWORD dwLastPos = f.GetPosition();
	
	EVTHEADER evtHeader;
	evtHeader.OfsNext = dwLastPos;					// ǲ���� ��ġ
	evtHeader.NumNext = nMax + 1;					// ��ü���� + 1
	evtHeader.FileSize = 0x40000000;				// evt ���� �ִ� ũ��. (�ϴܰ���)
	f.SeekToBegin();
	f.Write ((VOID*)&evtHeader, sizeof(EVTHEADER));
	
	EVTFOOTER evtFooter;
	evtFooter.dwNextEvtOffset = dwLastPos;			// ǲ���� ���� �ɼ�
	evtFooter.dwNextEventID = nMax+1;				// ��ü���� + 1	
	f.SeekToEnd();
	f.Write ((VOID*)&evtFooter, sizeof(EVTFOOTER));	
}






/**
	@brief	�̺�Ʈ ���ڵ带 ������ �̺�Ʈ �α� ���Ŀ� ���� ���Ϸ� ����Ѵ�.
			��, Security �׷��� ���ڵ�������� ������ �� �ֱ⶧���� ������ ���Ϸ� ����ߴ�.
	@param	strOutputPath		[in]	������� ������ ������ ��ü���
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