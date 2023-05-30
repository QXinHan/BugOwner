#include<stdio.h>
#include <stdlib.h>
#include"winntdef.h"
#include"ParserFuntions.h"

//这个FILE指针默认为已经导入了一个exe
int judge(FILE* fileptr) {
	WORD TypeFile;
	___IMAGE_DOS_HEADER PeDos;
	char* buffer = NULL;
	fseek(fileptr, 0, SEEK_SET);
	fread(&PeDos, sizeof(__IMAGE_DOS_HEADER),1, fileptr);
	if (PeDos.e_magic != ___IMAGE_DOS_SIGNATURE)
	{
		printf("Error: The file is not a PE file!\n");
		return 1;
	}
	fseek(fileptr, PeDos.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER), SEEK_SET);
	fread(&TypeFile, sizeof(WORD), 1, fileptr);
	if (TypeFile == ___IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 32;
	}
	else if (TypeFile == ___IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 64;
	}
	else {
		printf("Error: unknown file type!\n");
		return 1;
	}
}


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


void DosHeader(FILE* fileptr) {
	___IMAGE_DOS_HEADER PeDos;
	fseek(fileptr, 0, SEEK_SET);
	fread(&PeDos, sizeof(__IMAGE_DOS_HEADER), 1, fileptr);
	printf("DOS HEADER: \n");
	printf("----------------------------\n\n");
	printf("e_magic:0x%X\n", PeDos.e_magic);
	printf("e_cblp:0x%X\n", PeDos.e_cblp);
	printf("e_cp:0x%X\n", PeDos.e_cp);
	printf("e_cparhdr:0x%X\n", PeDos.e_cparhdr);
	printf("e_minalloc:0x%X\n", PeDos.e_minalloc);
	printf("e_maxalloc:0x%X\n", PeDos.e_maxalloc);
	printf("e_ss:0x%X\n", PeDos.e_ss);
	printf("e_sp:0x%X\n", PeDos.e_sp);
	printf("e_csum:0x%X\n", PeDos.e_csum);
	printf("e_ip:0x%X\n", PeDos.e_ip);
	printf("e_cs:0x%X\n", PeDos.e_cs);
	printf("e_lfarlc:0x%X\n", PeDos.e_lfarlc);
	printf("e_ovno:0x%X\n", PeDos.e_ovno);
	printf("e_res: ");
	for (int i = 0; i < 4; i++) {
		printf("%X", PeDos.e_res[i]);
		if (i != 3) {
			printf(", ");
		}
	}
	printf("\n");
	printf("e_oemid:0x%X\n", PeDos.e_oemid);
	printf("e_oeminfo:0x%X\n", PeDos.e_oeminfo);
	printf("e_res: ");
	for (int i = 0; i < 10; i++) {
		printf("%X",PeDos.e_res[i]);
		if (i != 9) {
			printf(", ");
		}
	}
	printf("\n");
	printf("e_lfanew:0x%X\n", PeDos.e_lfanew);
}

void FileHeader(FILE* fileptr) {
	WORD signature;
	___IMAGE_DOS_HEADER PeDos;
	___IMAGE_FILE_HEADER PeFile;
	fseek(fileptr, 0, SEEK_SET);
	fread(&PeDos, sizeof(__IMAGE_DOS_HEADER), 1, fileptr);
	fseek(fileptr, PeDos.e_lfanew, SEEK_SET);
	fread(&signature, sizeof(WORD), 1, fileptr);
	printf("\n\nNT_HEADER:\n");
	printf("---------------------------------------\n\n");
	printf("SIGNATURE: %X\n", signature);

	fseek(fileptr, PeDos.e_lfanew + sizeof(DWORD), SEEK_SET);
	fread(&PeFile, sizeof(__IMAGE_FILE_HEADER), 1, fileptr);
	printf("Machine: %X\n", PeFile.Machine);
	printf("NumberOfSections: %X\n", PeFile.NumberOfSections);
	printf("TimeDateStamp: %X\n", PeFile.TimeDateStamp);
	printf("PointerToSymbolTable: %X\n", PeFile.PointerToSymbolTable);
	printf("NumberOfSymbols: %X\n", PeFile.NumberOfSymbols);
	printf("SizeOfOptionalHeader: %X\n", PeFile.SizeOfOptionalHeader);
	printf("Characteristics: %X\n", PeFile.Characteristics);
	
}

//这里有点问题，类型不匹配！极其离谱，这个ULONGLONG我不知道怎么打印出来
//默认地%X是unsigned int所以会有精度损失。
void OptionalHeader64(FILE* fileptr) {
	
	___IMAGE_DOS_HEADER PeDos;
	___IMAGE_OPTIONAL_HEADER64 PeOp64;
	fseek(fileptr, 0, SEEK_SET);
	fread(&PeDos, sizeof(__IMAGE_DOS_HEADER), 1, fileptr);
	fseek(fileptr, PeDos.e_lfanew + sizeof(DWORD) + sizeof(__IMAGE_FILE_HEADER), SEEK_SET);
	fread(&PeOp64, sizeof(___IMAGE_OPTIONAL_HEADER64), 1, fileptr);
	printf("\n\nOPTIONAL HEADER64: \n");
	printf("-------------------------------------------\n\n");
	printf("Magic: %X\n", PeOp64.Magic); 
	printf("MajorLinkerVersion: %X\n", PeOp64.MajorLinkerVersion);
	printf("MinorLinkerVersion: %X\n", PeOp64.MinorLinkerVersion);
	printf("SizeOfCode: %X\n", PeOp64.SizeOfCode);
	printf("SizeOfInitializedData: %X\n", PeOp64.SizeOfInitializedData);
	printf("SizeOfUninitializedData: %X\n", PeOp64.SizeOfUninitializedData);
	printf("AddressOfEntryPoint: %X\n", PeOp64.AddressOfEntryPoint);
	printf("BaseOfCode: %X\n", PeOp64.BaseOfCode);
	printf("ImageBase: %l64X\n", PeOp64.ImageBase);
	printf("SectionAlignment: %X\n", PeOp64.SectionAlignment);
	printf("FileAlignment: %X\n", PeOp64.FileAlignment);
	printf("MajorOperatingSystemVersion: %X\n", PeOp64.MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion: %X\n", PeOp64.MinorOperatingSystemVersion);
	printf("MajorImageVersion: %X\n", PeOp64.MajorImageVersion);
	printf("MinorImageVersion: %X\n", PeOp64.MinorImageVersion);
	printf("Win32VersionValue: %X\n", PeOp64.Win32VersionValue);
	printf("SizeOfImage: %X\n", PeOp64.SizeOfImage);
	printf("SizeOfHeaders: %X\n", PeOp64.SizeOfHeaders);
	printf("CheckSum: %X\n", PeOp64.CheckSum);
	printf("Subsystem: %X\n", PeOp64.Subsystem);
	printf("DllCharacteristics: %X\n", PeOp64.DllCharacteristics);
	printf("SizeOfStackReserve: %X\n", PeOp64.SizeOfStackReserve);
	printf("SizeOfStackCommit: %X\n", PeOp64.SizeOfStackCommit);
	printf("SizeOfHeapReserve: %X\n", PeOp64.SizeOfHeapReserve);
	printf("SizeOfHeapCommit: %X\n", PeOp64.SizeOfHeapCommit);
	printf("LoaderFlags: %X\n", PeOp64.LoaderFlags);
	printf("NumberOfRvaAndSizes: %X\n", PeOp64.NumberOfRvaAndSizes);
	printf("\n\nThe DATADIRECTORY:\n\n");
		printf("___IMAGE_DIRECTORY_ENTRY_EXPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_EXPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_IMPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_IMPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_RESOURCE:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_RESOURCE:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_EXCEPTION:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_EXCEPTION:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_SECURITY:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_SECURITY:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_BASERELOC:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_BASERELOC:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_DEBUG:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_DEBUG:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_GLOBALPTR:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_GLOBALPTR:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_TLS:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_TLS:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_TLS].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_IAT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_IAT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_IAT].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
		printf("___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
		printf("___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:%X\n", PeOp64.DataDirectory[___IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);

}

void SectionHeaders(FILE* fileptr)
{
	___IMAGE_DOS_HEADER PeDos;
	___IMAGE_FILE_HEADER PeFile;
	fseek(fileptr, 0, SEEK_SET);
	fread(&PeDos, sizeof(__IMAGE_DOS_HEADER), 1, fileptr);
	fseek(fileptr, PeDos.e_lfanew, SEEK_SET);
	fseek(fileptr, PeDos.e_lfanew + sizeof(DWORD), SEEK_SET);
	fread(&PeFile, sizeof(__IMAGE_FILE_HEADER), 1, fileptr);
	WORD cntsecs = PeFile.NumberOfSections;

	fseek(fileptr, 0, SEEK_SET);
	___PIMAGE_SECTION_HEADER SecHeader = new ___IMAGE_SECTION_HEADER[cntsecs];
	for (int i = 0; i < cntsecs; i++) {
		fseek(fileptr, PeDos.e_lfanew + sizeof(__IMAGE_NT_HEADERS64) + i * ___IMAGE_SIZEOF_SECTION_HEADER, SEEK_SET);
		fread(&SecHeader[i], sizeof(__IMAGE_SECTION_HEADER), 1, fileptr);
	}
	for (int i = 0; i < cntsecs; i++) {
		printf("***%.8s\n", SecHeader[i].Name);
		printf("VirtualSize:%X\n", SecHeader[i].Misc.VirtualSize);
		printf("VirtualAddress:%X\n", SecHeader[i].VirtualAddress);
		printf("SizeOfRawData:%X\n", SecHeader[i].SizeOfRawData);
		printf("PointerToRawData:%X\n", SecHeader[i].PointerToRawData);
		printf("PointerToRelocations:%X\n", SecHeader[i].PointerToRelocations);
		printf("PointerToLinenumbers:%X\n", SecHeader[i].PointerToLinenumbers);
		printf("NumberOfRelocations:%X\n", SecHeader[i].NumberOfRelocations);
		printf("NumberOfLinenumbers:%X\n", SecHeader[i].NumberOfLinenumbers);
		printf("Characteristics:%X\n", SecHeader[i].Characteristics);

	}
}


int main() {
	FILE* PeFile = NULL;
	fopen_s(&PeFile, "C:\\Users\\86182\\Desktop\\AntiVirus Platinum.lnk", "rb");
	if (PeFile == NULL) {
		printf("Error: There is no file!\n");
		exit(1);
	}
	if (judge(PeFile) != 64 && judge(PeFile) != 32) {
		exit(1);
	}
	else if(judge(PeFile) == 64) {
		DosHeader(PeFile);
		FileHeader(PeFile);
		OptionalHeader64(PeFile);
		SectionHeaders(PeFile);
	}
	else {
		printf("32-bit的我还没写，待会再说吧\n");
	}
	return 0;
}