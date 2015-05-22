#ifndef READCONFFILE_H
#define READCONFFILE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct CFG_LINK
{
        char item[512];
        char field[512];
        char value[512];
        struct CFG_LINK * next ;
} ;


void ReadConfFile( char * FileName ) ;
void AnalyseString(char * string) ;
void ShowCfg() ;
char * QueryValue(char * item , char * field) ;


#endif