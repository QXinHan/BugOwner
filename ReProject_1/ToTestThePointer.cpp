#include<stdio.h>
#include <stdlib.h>
#include"winntdef.h"
#include"ParserFuntions.h"

//���FILEָ��Ĭ��Ϊ�Ѿ�������һ��exe
//������bug���Ҳ��������ҵĶ���
void judgeprint(FILE* fileptr) {
	WORD TypeFile;
	___IMAGE_DOS_HEADER PeDos;
	char* buffer = NULL;
	fseek(fileptr, 0, SEEK_SET);
	fread(&PeDos, sizeof(__IMAGE_DOS_HEADER), 1, fileptr);
	if (PeDos.e_magic != ___IMAGE_DOS_SIGNATURE)
	{
		printf("Error: The file is not a PE file!\n");
		return;
	}
	fseek(fileptr, PeDos.e_lfanew, SEEK_SET);
	for (int i = 0; i < sizeof(__IMAGE_FILE_HEADER); i++) {
		fseek(fileptr, PeDos.e_lfanew + i * sizeof(WORD), SEEK_SET);
		fread(&TypeFile, sizeof(WORD), 1, fileptr);
		printf("0x%X\n", TypeFile);
	}
	return;
	
}
