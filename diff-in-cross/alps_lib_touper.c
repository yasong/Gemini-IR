#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>



void alps_lib_toupper(char *dst, \
    const char *src, unsigned short len)
{
    unsigned short ii;

    for (ii = 0; ii < len; ++ii){
    dst[ii] = toupper(src[ii]);
    }
    dst[len] = 0x00;
}


int main(){
    char dst[100];

    char *c = "hello world!";

    alps_lib_toupper(dst,c, strlen(c));
}