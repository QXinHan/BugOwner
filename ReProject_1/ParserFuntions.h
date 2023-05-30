#pragma once
int judge(FILE* fileptr);
void DosHeader(FILE* fileptr);
void FileHeader(FILE* fileptr);
void OptionalHeader32(FILE* fileptr);//actually the way to parse 32-bit is similar to the 64-bit
void OptionalHeader64(FILE* fileptr);
//To parse the Section Headers i need to write a funtion to resolve address
void SectionHeaders(FILE* fileptr);