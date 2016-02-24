#include "StdAfx.h"
#include "cv_bxml.h"

VOID ParseBXml(BYTE* buf, DWORD size)
{
	DWORD dwMagic = (DWORD&)*buf;
	// 0f - StartOfBXmlStream
	if (0x0001010f != dwMagic)
	{
		printf("!ParseBXml-Magic\n");
		return;
	}
	buf+=4;	
	
	// create template instance
	buf+=2;		

	// template ID
	DWORD dwTemplateID = (DWORD&)*buf;
	buf+=4;

	// template offset
	DWORD dwTemplateOfs = (DWORD&)*buf;
	buf+=4;	

	// SubtitututionArray's element count
	const DWORD dwSubtitutionCnt = (DWORD&)*buf;
	buf+=4;

	// substitution array	
	for(DWORD i=0; i<dwSubtitutionCnt; i++)
	{
		BYTE opcode = buf[i];
		opcode = opcode & 0x0f;
		// typedef enum _EVT_VARIANT_TYPE {
		// http://msdn.microsoft.com/EN-US/library/aa385616.aspx
		printf("%d, ", opcode);
/*
		switch(opcode)
		{
			case 0;
				printf(")
				break;
		}
*/
	}
}
