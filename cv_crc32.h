#pragma once

unsigned long getFileCRC(FILE *);
unsigned long calcCRC (const unsigned char *, signed long, unsigned long, unsigned long *);
void makeCRCtable(unsigned long *, unsigned long);
