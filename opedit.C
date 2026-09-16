#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE* fptr;

    fptr = fopen("filename","w");

    fprintf(fptr, "Some text");

    fclose(fptr);
}