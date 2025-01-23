
#include <Windows.h>
#include <stdint.h>
#include <strsafe.h>
#include <winnt.h>
#include <subauth.h>

typedef BOOL(WINAPI *EntryProc)();

#define FLAG_DEAD 0x1

typedef struct module
{
	PIMAGE_DOS_HEADER DosHeaders;
	PIMAGE_NT_HEADERS NtHeaders;
	DWORD			  ImageSize;
	BYTE*			  ImageBase;
	BYTE*             OriginalBase;
	EntryProc		  Entry;
	HMODULE*		  Dependency;
	UINT32            CntOfDependency;
}module;


EXTERN_C LPVOID X_GetProcAddress(HMODULE hModule, const char*ProcName);
EXTERN_C module*  __load_module(const BYTE* data);
EXTERN_C int   __free_module(module * m);



typedef HMODULE(__stdcall * typeLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HANDLE(__stdcall * typeGetProcessHeap)();

typedef LPVOID(__stdcall * typeVirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);


typedef LPVOID(__stdcall * typeHeapAlloc)(
	_In_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	_In_ SIZE_T dwBytes
	);

typedef BOOL(__stdcall * typeHeapFree)(
	_Inout_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	__drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem
	);

typedef BOOL(__stdcall *typeVirtualProtect)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef WINBASEAPI FARPROC (__stdcall *typeGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
);

typedef LPVOID (__stdcall * typeHeapReAlloc)(
	_Inout_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	_Frees_ptr_opt_ LPVOID lpMem,
	_In_ SIZE_T dwBytes
);

typedef WINBASEAPI BOOL (__stdcall * typeFreeLibrary)(
	_In_ HMODULE hLibModule
);

typedef BOOL (__stdcall * typeVirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
);


typedef struct{
	typeLoadLibraryA	LoadLibraryA;
	typeFreeLibrary		FreeLibrary;
	typeGetProcessHeap	GetProcessHeap;
	typeVirtualAlloc	VirtualAlloc;
	typeVirtualFree		VirtualFree;
	typeHeapAlloc		HeapAlloc;
	typeHeapReAlloc		HeapRealloc;
	typeHeapFree		HeapFree;
	typeVirtualProtect	VirtualProtect;
	typeGetProcAddress	GetProcAddress;
}Functions;


int X_StrCmpIW(WCHAR * s1, WCHAR * s2){
	while (1){
		
		WCHAR ch1 = *s1;
		WCHAR ch2 = *s2;
		if (ch1 >= 'A' && ch1 <= 'Z'){
			ch1 = 'a' + ch1 - 'A';
		}
		if (ch2 >= 'A' && ch2 <= 'Z'){
			ch2 = 'a' + ch2 - 'A';
		}

		if (ch1 != ch2)
			return ch1 - ch2;

		if (ch1 == 0){
			break;
		}
		s1++, s2++;
	}
	return 0;
}


int X_StrCmpIA(CONST CHAR * s1, CONST CHAR * s2){
	while (1){
		CHAR ch1 = *s1;
		CHAR ch2 = *s2;
		if (ch1 >= 'A' && ch1 <= 'Z'){
			ch1 = 'a' + ch1 - 'A';
		}
		if (ch2 >= 'A' && ch2 <= 'Z'){
			ch2 = 'a' + ch2 - 'A';
		}

		if (ch1 != ch2)
			return ch1 - ch2;

		if (ch1 == 0){
			break;
		}
		s1++, s2++;
	}
	return 0;
}


__inline void  X_CopyMemory(void * dst, const void * src, int size){
	uint8_t * u8_src = (uint8_t *)src;
	uint8_t * u8_dst = (uint8_t*)dst;

	while (size){
		*u8_dst++ = *u8_src++;
		size--;
	}
}


int X_StrCmpWA(WCHAR * s1, char * s2){
	while (1){
		CHAR ch1 = *s1;
		CHAR ch2 = *s2;
		if (ch1 >= 'A' && ch1 <= 'Z'){
			ch1 = 'a' + ch1 - 'A';
		}
		if (ch2 >= 'A' && ch2 <= 'Z'){
			ch2 = 'a' + ch2 - 'A';
		}

		if (ch1 != ch2)
			return ch1 - ch2;

		if (ch1 == 0){
			break;
		}
		s1++, s2++;
	}
	return 0;
}


LPVOID X_GetProcAddress(HMODULE hModule, const char*ProcName)
{
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)(hModule);
	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS*)(pDosHeader->e_lfanew + (LPBYTE)hModule);
	IMAGE_DATA_DIRECTORY * DataDirectory = (IMAGE_DATA_DIRECTORY*)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	IMAGE_EXPORT_DIRECTORY*pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(
		DataDirectory->VirtualAddress +
		(LPBYTE)hModule);

	DWORD dwRavOfExportBegin = DataDirectory->VirtualAddress;
	DWORD dwRvaOfExportEnd = dwRavOfExportBegin + DataDirectory->Size;

	DWORD* FuncTable = (DWORD*)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);
	DWORD dwRvaOfFunc = 0;

	//there is no export table;
	if (dwRvaOfExportEnd == dwRavOfExportBegin){
		return NULL;
	}

	//by name
	DWORD * NameTable = (DWORD*)((LPBYTE)hModule + pExportDirectory->AddressOfNames);
	WORD *	OrdTable = (WORD*)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pExportDirectory->NumberOfNames; i++){
		char*name = (char*)(NameTable[i] + (LPBYTE)hModule);
		if (!X_StrCmpIA(name, ProcName)){
			dwRvaOfFunc = FuncTable[OrdTable[i]];
			break;
		}
	}
	return (void*)(dwRvaOfFunc + (LPBYTE)hModule);
}

int CopySections(module * m, const BYTE * data,Functions * functions)
{

	IMAGE_SECTION_HEADER * section;
	int NumOfSections = m->NtHeaders->FileHeader.NumberOfSections;
	BYTE* ImageBase = m->ImageBase;

	section = (IMAGE_SECTION_HEADER*)(
		m->ImageBase +
		m->DosHeaders->e_lfanew +
		sizeof(DWORD) +
		sizeof(IMAGE_FILE_HEADER) +
		m->NtHeaders->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < NumOfSections; i++, section++){
		//dbg_log("Section : %p ", section->VirtualAddress);
		if (section->SizeOfRawData == 0){
			DWORD section_size = m->NtHeaders->OptionalHeader.SectionAlignment;

			if (section_size > 0){
				LPVOID dest = (unsigned char *)functions->VirtualAlloc(
					(LPVOID)(ImageBase + section->VirtualAddress),
					section_size,
					MEM_COMMIT,
					PAGE_READWRITE);

				if (dest == NULL){
					return -1;
				}

				dest = (LPVOID)(ImageBase + section->VirtualAddress);
				for (int c = 0; c < section_size; c++){
					((uint8_t*)dest)[c] = 0;
				}
			}
			// section is empty
			continue;
		}
		else{
			//SizeOfRawData == 0, bss
			X_CopyMemory(
				(LPVOID)(ImageBase + section->VirtualAddress),
				data + section->PointerToRawData,
				section->SizeOfRawData);
		}
	}
	return 0;
}


int Relocate(module * m,Functions * functions)
{
	BYTE*     ImageBase = m->ImageBase;
	BYTE*     OriginalBase = m->OriginalBase;
	LONG64    Delta;
	PIMAGE_NT_HEADERS NtHeaders = m->NtHeaders;

	IMAGE_BASE_RELOCATION * relocation = (IMAGE_BASE_RELOCATION*)(
		ImageBase +
		NtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress);

	DWORD relocation_size = NtHeaders->OptionalHeader.DataDirectory[5].Size;

	//don't need relocate.
	if (ImageBase == OriginalBase)
	{
		return 0;
	}

	if (relocation_size == 0)
	{
		return -1;
	}

	Delta = ImageBase - OriginalBase;


	//dbg_log("relocation table address : %p", relocation);
	// dbg_log("relocation table size: %x", relocation_size);

	while (relocation_size)
	{
		DWORD dwItems = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		WORD * pAddrs = (WORD*)(sizeof(IMAGE_BASE_RELOCATION) + (LPBYTE)relocation);

		relocation_size -= relocation->SizeOfBlock;

		for (int i = 0; i < dwItems; i++)
		{
			WORD   dwType = (pAddrs[i] >> 12);
			WORD   dwOffset = (pAddrs[i] & 0xfff);
			LPBYTE* pRelocationAddr = (LPBYTE*)(ImageBase + relocation->VirtualAddress + dwOffset);
			//
			switch (dwType)
			{
				//0: »ùÖ·ÖØ¶¨Î»±»ºöÂÔ¡£ÕâÖÖÀàÐÍ¿ÉÒÔÓÃÀ´¶ÔÆäËü¿é½øÐÐÌî³ä¡£
			case IMAGE_REL_BASED_ABSOLUTE:		//block alignment
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				(*(uint32_t*)pRelocationAddr) += Delta;
				break;
			case IMAGE_REL_BASED_DIR64:
				*pRelocationAddr += Delta;
				break;
			default:
				return -1;
			}
		}
		//Next Block
		relocation = (IMAGE_BASE_RELOCATION*)(relocation->SizeOfBlock + (LPBYTE)relocation);
	}
	return 0;
}

int FixImport(module * m,Functions * functions)
{
	LPBYTE ImageBase = m->ImageBase;
	PIMAGE_NT_HEADERS NtHeaders = m->NtHeaders;
	PIMAGE_DATA_DIRECTORY DataDir = NtHeaders->OptionalHeader.DataDirectory;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	//ÐÞ¸´IAT
	//IMAGE_IMPORT_DESCRIPTOR ±£´æÁËdll nameºÍ´Ó¸Ãdllµ¼ÈëÄÄÐ©º¯Êý
	ImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(
		ImageBase +
		DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; ImportDescriptor->Characteristics; ImportDescriptor++)
	{
		uintptr_t * thunkRef = NULL;
		FARPROC *   funcRef = NULL;
		const char* szModuleName = (const char*)ImageBase + ImportDescriptor->Name;
		HMODULE     hModule = functions->LoadLibraryA(szModuleName);			//²»ÂÛÄ£¿éÊÇ·ñ´æÔÚ,¶¼Òªload,Ôö¼ÓÒýÓÃ¼ÆÊý.

		if (hModule == NULL)
		{
			return -1;
		}

		//add to Dependency.
		if (!m->Dependency)
		{
			m->Dependency = (HMODULE*)functions->HeapAlloc(
				functions->GetProcessHeap(),
				0,
				sizeof(HMODULE) * (m->CntOfDependency + 1));
		}
		else
		{
			m->Dependency = (HMODULE*)functions->HeapRealloc(
				functions->GetProcessHeap(),
				0,
				m->Dependency,
				sizeof(HMODULE) * (m->CntOfDependency + 1));
		}

		m->Dependency[m->CntOfDependency++] = hModule;

		if (ImportDescriptor->OriginalFirstThunk) {
			thunkRef = (uintptr_t *)(ImageBase + ImportDescriptor->OriginalFirstThunk);
			funcRef = (FARPROC *)(ImageBase + ImportDescriptor->FirstThunk);
		}
		else
		{
			// no hint table
			thunkRef = (uintptr_t *)(ImageBase + ImportDescriptor->FirstThunk);
			funcRef = (FARPROC *)(ImageBase + ImportDescriptor->FirstThunk);
		}

		for (; *thunkRef; thunkRef++, funcRef++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
			{
				*funcRef = (FARPROC)functions->GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(ImageBase + (*thunkRef));
				*funcRef = (FARPROC)functions->GetProcAddress(hModule, (LPCSTR)&thunkData->Name);
			}

			if (*funcRef == 0)
			{
				return -1;
			}
		}
	}
	return 0;
}



int FinalizeSections(module* m,Functions * functions)
{
	BOOL				  executable;
	BOOL				  readable;
	BOOL				  writeable;
	LPBYTE			      ImageBase = m->ImageBase;
	PIMAGE_NT_HEADERS     NtHeaders = m->NtHeaders;
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtHeaders);

	int ProtectionFlags[2][2][2] =
	{
		{
			// not executable
			{ PAGE_NOACCESS, PAGE_WRITECOPY },
			{ PAGE_READONLY, PAGE_READWRITE },
		}, {
			// executable
			{ PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
			{ PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE },
		},
	};

	//set section property
	for (int i = 0; i < m->NtHeaders->FileHeader.NumberOfSections; i++, section++)
	{
		DWORD protect = 0;
		DWORD old_protect = 0;
		DWORD section_size = 0;

		// determine protection flags based on characteristics
		executable = (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		readable = (section->Characteristics & IMAGE_SCN_MEM_READ) != 0;
		writeable = (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

		protect = ProtectionFlags[executable][readable][writeable];

		if (section->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
		{
			protect |= PAGE_NOCACHE;
		}

		//get section size
		if ((i + 1) == NtHeaders->FileHeader.NumberOfSections)
			section_size = NtHeaders->OptionalHeader.SizeOfImage - section->VirtualAddress;
		else
			section_size = section[1].VirtualAddress - section->VirtualAddress;

		//Is it correct ???
		section->Misc.PhysicalAddress = (DWORD)(ImageBase + section->VirtualAddress);

		//protect.
		if (!functions->VirtualProtect(
			(LPVOID)(ImageBase + section->VirtualAddress),
			section_size,
			protect,
			&old_protect))
		{
			return -1;
		}
	}
	return 0;
}

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                 // +0x00
	BOOLEAN Initialized;                          // +0x04
	PVOID SsHandle;                               // +0x08
	LIST_ENTRY InLoadOrderModuleList;             // +0x0c
	LIST_ENTRY InMemoryOrderModuleList;           // +0x14
	LIST_ENTRY InInitializationOrderModuleList;   // +0x1c
} PEB_LDR_DATA, *PPEB_LDR_DATA;              // +0x24

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;               // 0x0
	LIST_ENTRY InMemoryOrderLinks;             // 0x8
	LIST_ENTRY InInitializationOrderLinks;     // 0x10
	PVOID DllBase;                             // 0x18
	PVOID EntryPoint;                          // 0x1c
	ULONG SizeOfImage;                         // 0x20
	UNICODE_STRING FullDllName;                // 0x24
	UNICODE_STRING BaseDllName;                // 0x2c
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY; // 0xa4


void load_functions(Functions * funcs){
	char szKernel32[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	char szFreeLibrary[] = { 'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y',0 };
	char szGetProcessHeap[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'H', 'e','a','p' ,0 };
	char szHeapAlloc[] = { 'H', 'e', 'a', 'p', 'A', 'l', 'l', 'o', 'c',0 };
	char szHeapReAlloc[] = { 'H', 'e', 'a', 'p', 'R', 'e', 'A', 'l', 'l', 'o', 'c', 0 };
	char szHeapFree[] = { 'H', 'e', 'a', 'p', 'F', 'r', 'e', 'e', 0 };
	char szVAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l','A','l' ,'l', 'o', 'c', 0 };
	char szVFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
	char szVProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0 };
	char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };

	HMODULE hKernel32 = 0;

#ifdef _WIN64
	uint64_t peb = __readgsqword(0x60);
	PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)(peb + 0x18);
#endif
#ifdef _X86_
	uint32_t peb = (uint32_t)__readfsdword(0x30);
	PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)(peb + 0xc);
#endif

	
	PLIST_ENTRY moduleList = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY current = moduleList->Flink;

	while (current != moduleList){
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)current;
		if (X_StrCmpWA(entry->BaseDllName.Buffer, szKernel32) == 0) {
			hKernel32 = (HMODULE)entry->DllBase;
			break;
		}
		current = current->Flink;
	}

	funcs->GetProcAddress = (typeGetProcAddress)X_GetProcAddress(hKernel32, szGetProcAddress);
	funcs->LoadLibraryA = (typeLoadLibraryA)funcs->GetProcAddress(hKernel32, szLoadLibraryA);
	funcs->FreeLibrary = (typeFreeLibrary)funcs->GetProcAddress(hKernel32, szFreeLibrary);
	funcs->GetProcessHeap = (typeGetProcessHeap)funcs->GetProcAddress(hKernel32, szGetProcessHeap);
	funcs->HeapAlloc = (typeHeapAlloc)funcs->GetProcAddress(hKernel32, szHeapAlloc);
	funcs->HeapRealloc = (typeHeapReAlloc)funcs->GetProcAddress(hKernel32, szHeapReAlloc);
	funcs->HeapFree = (typeHeapFree)funcs->GetProcAddress(hKernel32, szHeapFree);
	funcs->VirtualAlloc = (typeVirtualAlloc)funcs->GetProcAddress(hKernel32, szVAlloc);
	funcs->VirtualFree = (typeVirtualFree)funcs->GetProcAddress(hKernel32, szVFree);
	funcs->VirtualProtect = (typeVirtualProtect)funcs->GetProcAddress(hKernel32, szVProtect);
}


extern "C" void run_exe(const uint8_t* data)
{
	IMAGE_DOS_HEADER *       pOldDosHeader = (IMAGE_DOS_HEADER*)data;
	IMAGE_NT_HEADERS *       pOldNtHeaders;
	DWORD					 dwNTHeaderOffset;
	module * m = NULL;
	Functions functions;


	load_functions(&functions);

	dwNTHeaderOffset = pOldDosHeader->e_lfanew;
	pOldNtHeaders = (IMAGE_NT_HEADERS*)(data + dwNTHeaderOffset);

	if (pOldDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
		pOldNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		goto failed;
	}

	//alloc module.
	m = (module*)functions.HeapAlloc(functions.GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(module));

	m->ImageSize = pOldNtHeaders->OptionalHeader.SizeOfImage;

	X_CopyMemory(&m->OriginalBase,
		&pOldNtHeaders->OptionalHeader.ImageBase,
		sizeof(pOldNtHeaders->OptionalHeader.ImageBase));

	m->ImageBase = (LPBYTE)functions.VirtualAlloc(
		(LPVOID)pOldNtHeaders->OptionalHeader.ImageBase,
		m->ImageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);


	if (m->ImageBase == NULL){
		m->ImageBase = (LPBYTE)functions.VirtualAlloc(
			NULL,
			m->ImageSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE);

		if (m->ImageBase == NULL){
			goto failed;
		}
	}

	m->DosHeaders = (IMAGE_DOS_HEADER*)m->ImageBase;

	//copy Headers (Dos Stub + PE Header + Section Headers)
	X_CopyMemory(
		(LPVOID)m->ImageBase,
		data,
		pOldNtHeaders->OptionalHeader.SizeOfHeaders);

	//reset pNtHeaders
	m->NtHeaders = (IMAGE_NT_HEADERS*)(m->ImageBase + dwNTHeaderOffset);

	X_CopyMemory(&m->NtHeaders->OptionalHeader.ImageBase,
		&m->ImageBase,
		sizeof(m->NtHeaders->OptionalHeader.ImageBase));

	//Copy Sections.
	if (CopySections(m, data,&functions))
		goto failed;

	//relocate.
	if (Relocate(m,&functions))
		goto failed;

	//fix import table.
	if (FixImport(m,&functions))
		goto failed;

	//tls......

	//...
	if (FinalizeSections(m,&functions))
		goto failed;

	m->Entry = (EntryProc)(
		m->NtHeaders->OptionalHeader.ImageBase +
		m->NtHeaders->OptionalHeader.AddressOfEntryPoint);

	//call main
	if (m->Entry){
		m->Entry();
	}
	
failed:
	//Clean up.
	if (m){
		//free libraries.
		for (int i = 0; i < m->CntOfDependency; i++){
			functions.FreeLibrary(m->Dependency[i]);
		}

		if (m->ImageBase)
			functions.VirtualFree((HINSTANCE)m->ImageBase, 0, MEM_RELEASE);
		//
		functions.HeapFree(functions.GetProcessHeap(), 0, m);
	}
	return;
}
