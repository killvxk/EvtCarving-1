/******************************************************************************

  Copyright forensicinsight.org, Inc. since 2011, All rights reserved.

    Any part of this source code can not be copied with
    any method without prior written permission from
    the author or authorized person.

	Author : Park HoJin (hojinpk@gmail.com)
	Date : 2012.04.09

	File Name : cv_evtx.cpp
	File Description :

*************************s****************************************************/

#include "StdAfx.h"
#include "cv_evtx.h"
#include "cv_crc32.h"
#include "cv_bxml.h"

#define BLOCK_SIZE 0x10000		// 64KB

CHUNKLIST g_chunk;
extern int g_chunk_maxnum;
extern CString g_strOutPath;
int g_index_savefile = 0;

VOID EvtxFree()
{	
	for(DWORD i=0; i<=g_chunk.ChunkCount; i++)
	{
		free(g_chunk.chunk[i]);
		g_chunk.chunk[i] = NULL;
	}
}


// return value is offset find position.
DWORD FindEvtxRecordSignature(BYTE* buf, DWORD size)
{
	DWORD i = 0;
	for(; i<size; i++)
	{
		// "**  "
		if (buf[i]==0x2a &&
			buf[i+1]==0x2a &&
			buf[i+2]==0x00 &&
			buf[i+3]==0x00 )
		{
			return i;
		}
	}
	return 0;
}


BOOL WriteEvtx(CString& strOutputPath)
{
	const DWORD chunk_max = g_chunk.ChunkCount;
	// const DWORD chunk_max = 1;
	if (!chunk_max)
		return TRUE;

// 	int quotient = (int)(g_chunk.ChunkCount / chunk_max);
// 	if ((g_chunk.ChunkCount%chunk_max) != 0)
// 		quotient++;

	// quotient = 1;
	// dwCnt = 10;
	

	CString strFileName;
	strFileName.Format("%s\\carved_%03X.evtx", strOutputPath, g_index_savefile++);
	
	EVTX_FILE_HEADER header = {0, };
	memset((VOID*)&header, 0x00, sizeof(header));

	strcpy(header.Magic, "ElfFile");
	header.CurrentChunk = chunk_max-1;
	// header.NextRecord =  ???;
	header.Revision = 1;
	header.Version = 3;
	header.SizePart1 = 0x80;				// Evtx.pm ���� �������� Ȯ���ϰ� ����.
	header.Flags = 0;
	header.HeaderSizer = sizeof(header);
	header.ChunkCount = (WORD)chunk_max;

	// calc file header crc32
	unsigned long CRC = 0;
	unsigned long table[256];
	makeCRCtable(table, 0xEDB88320);
	header.CRC32 = calcCRC((BYTE*)&header, 0x78, CRC, table);	

	CFile fEvtx;
	if (fEvtx.Open (strFileName, CFile::modeCreate|CFile::modeWrite))
	{
		int file_record_number = 1;
		fEvtx.Write((VOID*)&header, sizeof(header));

		for(DWORD i=0; i<chunk_max; i++)		
		{
			// printf("chunk idx:%d\n", i);

			EVTX_CHUNK_HEADER* chunk_header = (EVTX_CHUNK_HEADER*)g_chunk.chunk[i];
			UINT chunk_record_number = (UINT)(chunk_header->NumLogRecLast - chunk_header->NumLogRecFirst);

			// strcpy(chunk_header->Magic, "ElfChnk");
			chunk_header->NumLogRecFirst = file_record_number;
			chunk_header->NumLogRecLast = chunk_header->NumLogRecFirst + chunk_record_number;
			chunk_header->NumFileRecFirst = chunk_header->NumLogRecFirst;
			chunk_header->NumFileRecLast = chunk_header->NumLogRecLast;
			// chunk_header->OfsTables = 0x80;
			// chunk_header->OfsLastRec = ??;
			// chunk_header->OfsNextRec = ??;

			// StringTable		0x100
			// TemplateTable	0x080

			VOID* ptRecordStart = g_chunk.chunk[i] + chunk_header->OfsTables + 0x100 + 0x80;
			DWORD dwNextRecordPt = 0;
			UINT nPrevPt = 0;
			BOOL b1 = FALSE;

			// [2012.06.30][hojinpk][2.0.0.4]
			// - ���ڵ��� �ñ״�ó�� ã�� �������� ���ڵ� ���̸� ������.
			//   ������ ī���غ��� ���ڵ尡 �� ���� �������� ��� ǥ�������� ���ϴ� ��찡 ����.
			

			for(UINT k=0; k<BLOCK_SIZE; NULL)
			{	
				// printf("\trecord idx:%d\n", k);

				BYTE* pBuf = ((BYTE*)ptRecordStart+k);
				
				// "**  " and length1 is not zero
				if ((pBuf[0]==0x2a && pBuf[1]==0x2a && pBuf[2]==0x00 && pBuf[3]==0x00) && 
					(pBuf[4]!=0x00 || pBuf[5]!=0x00 || pBuf[6]!=0x00 || pBuf[7]!=0x00))
				{
					EVTX_RECORD* pRecord = (EVTX_RECORD*)pBuf;

					const DWORD dwLength1 = pRecord->Length1;
					const DWORD dwLength2 = (DWORD&)*(pBuf+dwLength1-sizeof(DWORD));

					BOOL bLength = FALSE, bRecordSig = FALSE;
					
					if (dwLength1 == dwLength2)
						bLength = TRUE;
					
					BYTE* pNextBuf = (BYTE*)(pBuf+dwLength1);
					if (pNextBuf[0]==0x2a && pNextBuf[1]==0x2a && pNextBuf[2]==0x00 && pNextBuf[3]==0x00)
						bRecordSig = TRUE;
					
					if (bLength == TRUE && bRecordSig == TRUE)
					{
						k += dwLength1;
						continue;
					}
					else if (bLength == FALSE && bRecordSig == TRUE)
					{
						// pRecord->Length1 = dwLength1;
						(DWORD&)*(pBuf+dwLength1-sizeof(DWORD)) = dwLength1;
					}
					else if (bRecordSig == FALSE)
					{
						//printf("dwOfs: ");
						DWORD dwOfs = FindEvtxRecordSignature(pBuf+4, BLOCK_SIZE-k-4);
						//printf("%d\n", dwOfs);
						if (dwOfs > 0)
						{
							dwOfs-=4;
							pRecord->Length1 = dwOfs;
							(DWORD&)*(pBuf+dwOfs-sizeof(DWORD)) = dwOfs;
							
							k += dwOfs;
						}
						else
						{
							// ���ڵ� �ñ״�ó�� ��ã�� ���
							// (�������̶�� ��.)
							//pRecord->Length1 = BLOCK_SIZE - k;
							//(DWORD&)*(pBuf+dwOfs-sizeof(DWORD)) = pRecord->Length1;
							break;
						}
					}
					else
						printf("else\n");
				}
				else 
					k++;
			} // End of for

// 			EVTX_RECORD* pLastRecord = (EVTX_RECORD*)((char*)ptRecordStart+k);
// 			(DWORD&)*((CHAR*)pLastRecord+pLastRecord->Length1-sizeof(DWORD)) = pLastRecord->Length1;

			// printf("next loop\n");
			for(UINT j=0; j<=chunk_record_number; j++)
			{
				EVTX_RECORD* pEvtxRecord = (EVTX_RECORD*)((char*)ptRecordStart+dwNextRecordPt);
				
				// "**  "
				if (pEvtxRecord->Magic[0]==0x2a &&
					pEvtxRecord->Magic[1]==0x2a &&
					pEvtxRecord->Magic[2]==0x00 &&
					pEvtxRecord->Magic[3]==0x00 )
				{
					// TODO::�̻��ϰ� �̰� �����ϸ� LogParser �� ������ ����(CRC) ��� ����ó���Ѵ�.
// 					if (pEvtxRecord->Length1 != pEvtxRecord->Length2)
//					{
// 						pEvtxRecord->Length2 = pEvtxRecord->Length1;
// 						// continue;
// 					}

 					pEvtxRecord->NumRecord = file_record_number++;

 					if (((char*)chunk_header+BLOCK_SIZE) < ((char*)ptRecordStart+pEvtxRecord->Length1))
 						break;

					dwNextRecordPt += pEvtxRecord->Length1;
				}
				else
				{
					// [2012.06.28][hojinpk][2.0.0.2]
					// - ���ڵ尡 �߰��� ������ ���� ���, ����� ���������� �����Ѵ�.
					chunk_header->NumFileRecLast = chunk_header->NumLogRecLast = \
						chunk_header->NumLogRecFirst + j - 1;
					chunk_header->OfsNextRec = 0x200 + dwNextRecordPt;
					break;
				}
			}

			
			// chunk_header->OfsNextRec = 0x200 + dwNextRecordPt;

			// Calc DataCRC of a chunk
			// -> CRC32(chunk_header+0x200 ~ chunk_header->OfsNextRec)
			// ���ڵ��� CRC32 ��.
			
			unsigned long chunk_DataCRC = 0;
			chunk_header->DataCRC32 = \
				calcCRC((BYTE*)((DWORD&)chunk_header+0x200), \
				        chunk_header->OfsNextRec - 0x200, \
						chunk_DataCRC, table);
			
			// Calc HeaderCRC of a chunk
			// - chunk ����������� 0x200 ��ŭ ������ ��, 
			//   0x78 ���� 8 ����Ʈ�� ������ �������� CRC32 ��.
			unsigned long chunk_headerCRC = 0;
			BYTE chunk_blob[0x200];
			memset(chunk_blob, 0x00, 0x200);
			memcpy(chunk_blob, chunk_header, 0x78);
			memcpy(chunk_blob+0x78, (VOID*)((DWORD&)chunk_header+0x80), 0x180);
			chunk_header->HeaderCRC32 = calcCRC(chunk_blob, 0x1F8, chunk_headerCRC, table);

			fEvtx.Write(g_chunk.chunk[i], BLOCK_SIZE);
		}
		fEvtx.Close ();
	}


	EvtxFree();
	return TRUE;
}

VOID EvtxInit()
{
	g_chunk.ChunkCount = 0;
}

SHORT _CarvingEvtx(LPVOID pMap, DWORD dwFileSize, DWORD& size_front)
{	
	// if (dwFileSize<8) return 0;

	CHAR* pOffset = NULL;
	SHORT found_chunk_count = 0;
	DWORD i;

	__try
	{
		for (i=0; i < dwFileSize-8; i++)
		{		
			// Search for EVT chunk header signature
			pOffset = (CHAR*)pMap + i;
			
			// ElfChnk\0
			if (pOffset[0]==0x45 &&	pOffset[1]==0x6C &&	pOffset[2]==0x66 &&	pOffset[3]==0x43 &&
				pOffset[4]==0x68 &&	pOffset[5]==0x6E &&	pOffset[6]==0x6B &&	pOffset[7]==0x00 )
			{
				if (0 == size_front)
				{				
					// printf("%x\n", Ofs+i);
					// malloc ���� 32bit ������ �ִ� 2GB ���� ���� �� �ִ�.
					g_chunk.chunk[g_chunk.ChunkCount] = (BYTE*)malloc(BLOCK_SIZE);
					
					memset(g_chunk.chunk[g_chunk.ChunkCount], 0x00, BLOCK_SIZE);
				}
				
				const DWORD dw1 = (DWORD)((CHAR*)pMap+dwFileSize);
				const DWORD dw2 = (DWORD)(pOffset+BLOCK_SIZE);
				if ( dw1 < dw2 )
				{
					size_front = dwFileSize - i;
					memcpy(g_chunk.chunk[g_chunk.ChunkCount], pOffset, size_front);
					return 0;
				}

				// [2012.06.29][hojinpk][2.0.0.3]
				// - chunk �� �ּ� ����
				BOOL b1;
				
				// - ù��° ���ڵ尡 �����ϴ��� �˻�.
				// [TODO] size 200 �˻�
				b1 = (*(DWORD*)(pOffset+0x200) != 0x00002a2a);
				if (b1)
				{
					free(g_chunk.chunk[g_chunk.ChunkCount]);
				}
				else
				{
					// String Table �� �Ľ��ؼ� �����۾��� �Ѵ�.
					const DWORD dwStringTablePt = (DWORD)(g_chunk.chunk[g_chunk.ChunkCount]+0x80);
					for(int j=0; j<64; j++)
					{
						EVTX_STRENTRY pEntry = {NULL, };					
						pEntry.Ofs = (DWORD&)*((CHAR*)dwStringTablePt+(j*sizeof(DWORD)));
						if (pEntry.Ofs)
						{
							pEntry.Hash = (WORD&)*(g_chunk.chunk[g_chunk.ChunkCount] + pEntry.Ofs + 4);
							pEntry.len  = (WORD&)*(g_chunk.chunk[g_chunk.ChunkCount] + pEntry.Ofs + 4 + sizeof(WORD));
							if (pEntry.len > 0 && pEntry.len < 64)
							{
								// wprintf(L"%s, ", pEntry->str);
								// wprintf(L"%s, ", g_chunk.chunk[g_chunk.ChunkCount] + pEntry.Ofs + 4 + sizeof(WORD) + sizeof(WORD));
							}
							else if (pEntry.len >= 64)
							{
								// printf("*binary*", );
							}
							else if (pEntry.len == 0)
							{
								// printf("*blank*, ");
								// �����۾�, �������� ���̰� zero �� ��� pEntry �� Ofs �� 0 ���� �Ѵ�.
								// pEntry.Ofs = 0;
								(DWORD&)*((CHAR*)dwStringTablePt+(j*sizeof(DWORD))) = 0x00000000;
							}
						}
					}
					// printf("\n\n");


					memcpy(g_chunk.chunk[g_chunk.ChunkCount], pOffset, dwFileSize);
					g_chunk.ChunkCount++;
				
					// [2012.06.28][hojinpk][2.0.0.2]
					// - ������ ������ �� ����ϸ� ������ �߻��ϱ� ������
					//   ������(g_chunk_maxnum) ������ ���� ����ϴ� ������ ����.
					if (g_chunk.ChunkCount >= (DWORD)g_chunk_maxnum)
					{
						if (WriteEvtx(g_strOutPath))
						{
							EvtxInit();
						}
					}
					found_chunk_count++;
				}

				size_front = 0;
				i += BLOCK_SIZE;
			}
		}
	}
	__except(Create_Dump(GetExceptionInformation(), TRUE, FALSE), EXCEPTION_EXECUTE_HANDLER)
	{
		printf("\nOut of HEAP(%dMB)\n", g_chunk.ChunkCount*BLOCK_SIZE/1024/1024);
		printf("Sorry, Please reduce file size of unallocated space.\n");
		exit(1);
	}
	return found_chunk_count;
}


/**
	@brief	�޸�(pMap)�� ���������� �о� �̺�Ʈ ���ڵ带 ã�� ���� �� �ش� ���ڵ带 ����Ѵ�.
	@param	pMap			[in]	ī�� ��� �޸�
	@param	dwFileSize		[in]	�޸� ũ��	
	@param	size_front		[out]	evt_a_record �� ��ϵ� �պκ� ũ��
									evt_a_record �� ũ��� �̺�Ʈ �α� ������
									���� �� �κ��� 4����Ʈ�� �ش������� ������ ������� �ʴ´�.
	@return the number of carving windows event log record

	@comment
		- BLOCK_SIZE �ȿ� �ִ� �ñ״�ó�� ã�� ���ϹǷ� ��翡���Ϳ��� ���ڿ� �˻��� ������ �ٸ� �� �ִ�.
 */
SHORT CarvingEvtx(LPVOID pMap, DWORD dwFileSize, DWORD& size_front)
{
	SHORT dwCnt = 0;

	if (IsBadReadPtr (pMap, dwFileSize))
	{
		return 0;
	}

	if (size_front > 0)
	{
		DWORD size_rear = BLOCK_SIZE - size_front;
		
		if (size_rear > dwFileSize)
			size_rear = dwFileSize;
		
		memcpy(g_chunk.chunk[g_chunk.ChunkCount]+size_front, pMap, size_rear);

		dwCnt += _CarvingEvtx(g_chunk.chunk[g_chunk.ChunkCount], BLOCK_SIZE, size_front);
		
		pMap = (CHAR*)pMap + size_rear;
		dwFileSize -= size_rear;

		// Ofs+=size_rear;
	}

	if (dwFileSize > 8)
		dwCnt += _CarvingEvtx(pMap, dwFileSize, size_front);

	return dwCnt;
}





VOID ParseEvtx(LPCTSTR lpszPath)
{
	CFile f;
	if (!f.Open(lpszPath, CFile::modeRead|CFile::typeBinary))
		return;
	const DWORD dwFileSize = f.GetLength();

	BYTE* buf = (BYTE*)malloc(dwFileSize);
	memset(buf, 0x00, dwFileSize);
	DWORD dwReadSize = f.ReadHuge(buf, dwFileSize);
	if (dwReadSize != dwFileSize)
	{
		printf("[ERROR] Read a target file.\n");
		return;
	}

	// "ElfFile\0"
	if (buf[0]==0x45 &&	buf[1]==0x6C &&	buf[2]==0x66 &&	buf[3]==0x46 &&
		buf[4]==0x69 &&	buf[5]==0x6C &&	buf[6]==0x65 &&	buf[7]==0x00 )
	{			
		EVTX_FILE_HEADER* header = (EVTX_FILE_HEADER*)buf;
		EVTX_CHUNK_HEADER* chunk = (EVTX_CHUNK_HEADER*)((BYTE*)buf+header->HeaderSizer);
		for(WORD i=0; i<header->ChunkCount; i++)
		{	
			// "ElfChnk\0"
			if (chunk->Magic[0]!=0x45 || chunk->Magic[1]!=0x6C || chunk->Magic[2]!=0x66 || chunk->Magic[3]!=0x43 ||
				chunk->Magic[4]!=0x68 || chunk->Magic[5]!=0x6E || chunk->Magic[6]!=0x6B || chunk->Magic[7]!=0x00 )
			{
				printf("!ElfChnk\n");				
				break;
			}			
			printf("Chunk[%d], %I64u - %I64u\n", i, chunk->NumLogRecFirst, chunk->NumLogRecLast);

			WORD record_count = (WORD)(chunk->NumLogRecLast - chunk->NumLogRecFirst);
			EVTX_RECORD* pRecord = (EVTX_RECORD*)((BYTE*)chunk+0x200);
			for(WORD j=0; j<=record_count; j++)
			{
				// "**\0\0"
				if (pRecord->Magic[0]!=0x2A || pRecord->Magic[1]!=0x2A || pRecord->Magic[2]!=0x00 || pRecord->Magic[3]!=0x00)
				{
					printf("!Record\n");
					break;
				}
				printf(" Record[%d]\n", j);
				
				// EVENTLOGRECORD - http://msdn.microsoft.com/en-us/library/Aa363646
				// http://www.codeproject.com/KB/string/EventLogParser.aspx

				ParseBXml((BYTE*)pRecord+0x18, pRecord->Length1-0x1C);
				
				// Next to ...
				pRecord = (EVTX_RECORD*)((BYTE*)pRecord+pRecord->Length1);
			}
			
			// Next chunk.
			chunk = (EVTX_CHUNK_HEADER*)((BYTE*)chunk + BLOCK_SIZE);
		}
	}
	else
	{
		printf("It's not evtx format.\n(%s)\n", lpszPath);
	}

	free(buf);
	f.Close();
}
