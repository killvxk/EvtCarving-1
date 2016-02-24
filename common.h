#pragma once

VOID PrintLastErrorMessage(LPCTSTR lpszFuncName);
BOOL IsFileExists(LPCTSTR lpszPath);
void WINAPI Create_Dump(PEXCEPTION_POINTERS pException, BOOL File_Flag, BOOL Show_Flag);


