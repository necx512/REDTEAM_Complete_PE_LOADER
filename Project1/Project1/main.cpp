#include <iostream>
#include <windows.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <psapi.h>

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

int main()
{

	// Open file
	FILE* file;
	fopen_s(&file,"C:\\Windows\\System32\\calc.exe", "rb");
	if (file == NULL) {
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* pe_mem = (unsigned char*) calloc(1, size);
	if (pe_mem == NULL)
	{
		printf("err pemem\n");
		exit(1);
	}
	fread(pe_mem, size, 1, file);
	fclose(file);

	printf("%p of size %ld\n", pe_mem, size);

	// GET DOS header
	PIMAGE_DOS_HEADER DOS_Header = (PIMAGE_DOS_HEADER)pe_mem;
	PIMAGE_NT_HEADERS NT_Header = (PIMAGE_NT_HEADERS)(pe_mem + DOS_Header->e_lfanew);

	// ALLOCATE SPACE
	PCHAR base = (PCHAR)VirtualAlloc(NULL, NT_Header->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// COPY OF HEADER
	memcpy(base, pe_mem, NT_Header->OptionalHeader.SizeOfHeaders);

	// COPY SECTIONS
	PIMAGE_SECTION_HEADER section_headers = (PIMAGE_SECTION_HEADER)((PCHAR)NT_Header + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < NT_Header->FileHeader.NumberOfSections; i++) {
		memcpy(base + section_headers[i].VirtualAddress, (PCHAR)pe_mem + section_headers[i].PointerToRawData, section_headers[i].SizeOfRawData);
	}




	// Fix import
	PIMAGE_DATA_DIRECTORY img_directory_entry_import = &NT_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR	pImgDes = NULL;
	for (SIZE_T i = 0; i < img_directory_entry_import->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImgDes = (IMAGE_IMPORT_DESCRIPTOR*)(img_directory_entry_import->VirtualAddress + (ULONG_PTR)base + i);
		if (pImgDes->OriginalFirstThunk == NULL && pImgDes->FirstThunk == NULL) {
			break;
		}
		LPSTR		DllName = (LPSTR)((ULONGLONG)base + pImgDes->Name);
		ULONG_PTR	Head = pImgDes->FirstThunk;
		ULONG_PTR	Next = pImgDes->OriginalFirstThunk;
		SIZE_T		HeadSize = 0;
		SIZE_T		NextSize = 0;
		HMODULE		hModule = LoadLibraryA(DllName);
		if (hModule == NULL) {
			return FALSE;
		}
		if (Next == NULL) {
			Next = pImgDes->FirstThunk;
		}
		int nb_function = 0;
		while (TRUE) {
			PIMAGE_THUNK_DATA			_1stThunk = (IMAGE_THUNK_DATA*)(base + HeadSize + Head);
			PIMAGE_THUNK_DATA			Orig1stThunk = (IMAGE_THUNK_DATA*)(base + NextSize + Next);
			PIMAGE_IMPORT_BY_NAME		FuncName = NULL;
			ULONG_PTR					pFunction = NULL;
			if (_1stThunk->u1.Function == NULL) {
				break;
			}
			if (Orig1stThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				printf("HAS ORDINAL in %s\n", DllName);
				PIMAGE_DOS_HEADER		_dos;
				PIMAGE_NT_HEADERS		_nt;
				PIMAGE_EXPORT_DIRECTORY	_ExportDir;
				PDWORD					_FuncAddArray;

				_dos = (PIMAGE_DOS_HEADER)hModule;
				_nt = (PIMAGE_NT_HEADERS)(((ULONG_PTR)hModule) + _dos->e_lfanew);
				_ExportDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hModule) + _nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


				_FuncAddArray = (PDWORD)((ULONG_PTR)hModule + _ExportDir->AddressOfFunctions);

				pFunction = ((ULONG_PTR)hModule + _FuncAddArray[Orig1stThunk->u1.Ordinal]);
			}
			else {
				FuncName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)base + Orig1stThunk->u1.AddressOfData);
				pFunction = (ULONG_PTR)GetProcAddress(hModule, FuncName->Name);
				//printf("By functionname %s\n", FuncName);
			}
			if (pFunction == NULL) {
				return FALSE;
			}
			_1stThunk->u1.Function = (ULONGLONG)pFunction;
			HeadSize += sizeof(IMAGE_THUNK_DATA);
			NextSize += sizeof(IMAGE_THUNK_DATA);
			nb_function++;
		}
		printf("DONE\n");
	}


	// Relocation

	PIMAGE_DATA_DIRECTORY img_directory_entry_basereloc = (PIMAGE_DATA_DIRECTORY)&NT_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (base != (PCHAR)NT_Header->OptionalHeader.ImageBase && img_directory_entry_basereloc->VirtualAddress != 0)
	{

		ULONG_PTR ActualAddress = (ULONG_PTR)base;
		ULONG_PTR PreferableAddress = NT_Header->OptionalHeader.ImageBase;
		PIMAGE_BASE_RELOCATION BaseRelocDir = (PIMAGE_BASE_RELOCATION)(base + img_directory_entry_basereloc->VirtualAddress);
		DWORD size = img_directory_entry_basereloc->Size;

		PIMAGE_BASE_RELOCATION  pImageBR = BaseRelocDir;
		ULONG_PTR				OffsetIB = ActualAddress - PreferableAddress;
		PBASE_RELOCATION_ENTRY	Reloc = NULL;


		while (size > 0) {
			Reloc = (PBASE_RELOCATION_ENTRY)(pImageBR + 1);
			size -= pImageBR->SizeOfBlock;

			int num = 1;

			while ((PBYTE)Reloc != (PBYTE)pImageBR + pImageBR->SizeOfBlock) {
				switch (Reloc->Type) {
				case IMAGE_REL_BASED_DIR64:
					*((ULONG_PTR*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += OffsetIB;
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*((DWORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += (DWORD)OffsetIB;
					break;
				case IMAGE_REL_BASED_HIGH:
					*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += HIWORD(OffsetIB);
					break;
				case IMAGE_REL_BASED_LOW:
					*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += LOWORD(OffsetIB);
					break;
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				default:
					return FALSE;
				}
				Reloc++;
			}
			pImageBR = (PIMAGE_BASE_RELOCATION)Reloc;
		}
	}

	// Entry point
	PVOID EP = (PVOID)(base + NT_Header->OptionalHeader.AddressOfEntryPoint);
	((VOID(*)())EP)();

}