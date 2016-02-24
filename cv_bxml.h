#pragma once

typedef enum _SystemToken
{
	EndOfBXmlStream			= 0,
	OpenStartElementTag		= 1,	// <
	CloseStartElementTag	= 2,	//         >
	CloseEmptyElementTag	= 3,	//        />
	EndElementTag			= 4,	// </ name >
	Value					= 5,	// 	Attribute = "value"
	Attribute				= 6,	// 	Attribute = "value"
	TemplateInstance		= 0xc,	// 	
	NormalSubstitution		= 0xd,	// 	
	OptionalSubstitution	= 0xe,	// 	
	StartOfBXmlStream		= 0xf,	// 

}SystemToken;

VOID ParseBXml(BYTE* buf, DWORD size);
