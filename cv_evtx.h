#pragma once

typedef struct _CHUNKLIST
{
	DWORD ChunkCount;
	BYTE* chunk[0x10000];
}CHUNKLIST,*PCHUNKLIST;


typedef struct _EVTX_FILE_HEADER
{
	char Magic[8];					// "ElfFile"
	DWORDLONG unknown1;
	DWORDLONG CurrentChunk;
	DWORDLONG NextRecord;
	DWORD SizePart1;
	WORD Revision;
	WORD Version;
	WORD HeaderSizer;
	WORD ChunkCount;
	char unused1[76];
	DWORD Flags;					// DIRTY, LOGFULL
	DWORD CRC32;
	char unused2[3968];
}EVTX_FILE_HEADER,*PEVTX_FILE_HEADER;

typedef struct _EVTX_CHUNK_HEADER
{
	char Magic[8];					// "ElfChnk"
	DWORDLONG NumLogRecFirst;
	DWORDLONG NumLogRecLast;
	DWORDLONG NumFileRecFirst;
	DWORDLONG NumFileRecLast;
	DWORD OfsTables;
	DWORD OfsLastRec;
	DWORD OfsNextRec;				// chunk 데이터의 마지막 옵셋
	DWORD DataCRC32;
	char unknown[68];
	DWORD HeaderCRC32;	
}EVTX_CHUNK_HEADER,*PEVTX_CHUNK_HEADER;

typedef struct _EVTX_RECORD
{
	char Magic[4];					// "**"
	DWORD Length1;
	DWORDLONG NumRecord;
	FILETIME TimeCreated;
	// ...
	DWORD Length2;	
}EVTX_RECORD,*PEVTX_RECORD;

typedef struct _EVTX_STRENTRY
{
	DWORD Ofs;
	WORD  Hash;
	WORD  len;
	WCHAR *str;
}EVTX_STRENTRY,*PEVTX_STRENTRY;

typedef struct _EVTX_ENTRY
{
	EVTX_STRENTRY Entry[64];
}EVTX_ENTRY, *PEVTX_ENTRY;

SHORT CarvingEvtx(LPVOID pMap, DWORD dwFileSize, DWORD& size_front);
BOOL WriteEvtx(CString& strOutputPath);
VOID EvtxInit();
VOID ParseEvtx(LPCTSTR lpszPath);
