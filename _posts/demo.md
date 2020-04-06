```c
// TestShell.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "PEOperate.h"

/*
	以挂起的形式创建进程，
	获取Context
  */

#define KEY 0x56
#define isDebug	1



#pragma pack(push, 1)  
typedef struct{  
    unsigned long VirtualAddress;  
    unsigned long SizeOfBlock;  
} *PImageBaseRelocation;  
#pragma pack(pop)  			
			
// 重定向PE用到的地址  
//void DoRelocation(PIMAGE_NT_HEADERS peH, void *OldBase, void *NewBase)  
void DoRelocation(LPVOID pFileBuffer, void *OldBase, void *NewBase) 
{ 
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;	
	PIMAGE_NT_HEADERS peH = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	
    unsigned long Delta = (unsigned long)NewBase - peH->OptionalHeader.ImageBase;  
    PImageBaseRelocation p = (PImageBaseRelocation)((unsigned long)OldBase   
        + peH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);  
    while(p->VirtualAddress + p->SizeOfBlock)  
    {  
        unsigned short *pw = (unsigned short *)((int)p + sizeof(*p));  
        for(unsigned int i=1; i <= (p->SizeOfBlock - sizeof(*p)) / 2; ++i)  
        {  
            if((*pw) & 0xF000 == 0x3000){  
                unsigned long *t = (unsigned long *)((unsigned long)(OldBase) + p->VirtualAddress + ((*pw) & 0x0FFF));  
                *t += Delta;  
            }  
            ++pw;  
        }  
        p = (PImageBaseRelocation)pw;  
    }  
}  

VOID GetEncryptFileContext(LPVOID pFileBuffer,DWORD &OEP,DWORD &ImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//pFileBuffer= ReadPEFile(lpszFile);
	
	if(!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}
	
	//MZ标志
	if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}
	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	//打印DOS头
	printf("------------DOS头------------\n");
	printf("MZ标志: %x\n",pDosHeader->e_magic);
	printf("PE偏移: %x\n",pDosHeader->e_lfanew);
	
	//判断是否是有效的PE 
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew))!=IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}
	
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	
	//打印NT头
	printf("------------NT头------------\n");
	printf("Signature: %x\n",pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
	printf("------------标准PE头--------\n");
	printf("Machine: %x\n",pPEHeader->Machine);
	printf("节的数量: %x\n",pPEHeader->NumberOfSections);
	printf("SizeOfOptionHeaders: %x\n",pPEHeader->SizeOfOptionalHeader);
	
	//可选择PE头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	printf("------------OPTION_PE头--------\n");
	printf("Machine: %x \n",pOptionHeader->Magic);
	printf("OEP: %x \n",pOptionHeader->AddressOfEntryPoint);
	printf("ImageBase: %x \n",pOptionHeader->ImageBase);
	printf("SectionAlignment: %x \n",pOptionHeader->SectionAlignment);
	printf("FileAlignment: %x \n",pOptionHeader->FileAlignment);
	printf("SizeOfImage: %x \n",pOptionHeader->SizeOfImage);
	printf("SizeOfHeaders: %x \n",pOptionHeader->SizeOfHeaders);
	
	//获取信息
	OEP = pOptionHeader->AddressOfEntryPoint;
	ImageBase = pOptionHeader->ImageBase;

}

VOID GetNtHeaderInfo(LPVOID pFileBuffer,DWORD &ImageBase,DWORD &ImageSize)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//pFileBuffer= ReadPEFile(lpszFile);

	if(!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}
	
	//MZ标志
	if(*((PWORD)pFileBuffer)!=IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}
	
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	
	//打印DOS头
	printf("------------DOS头------------\n");
	printf("MZ标志: %x\n",pDosHeader->e_magic);
	printf("PE偏移: %x\n",pDosHeader->e_lfanew);

	//判断是否是有效的PE 
	if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew))!=IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);

	//打印NT头
	printf("------------NT头------------\n");
	printf("Signature: %x\n",pNTHeader->Signature);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
	printf("------------标准PE头--------\n");
	printf("Machine: %x\n",pPEHeader->Machine);
	printf("节的数量: %x\n",pPEHeader->NumberOfSections);
	printf("SizeOfOptionHeaders: %x\n",pPEHeader->SizeOfOptionalHeader);

	//可选择PE头
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	printf("------------OPTION_PE头--------\n");
	printf("Machine: %x \n",pOptionHeader->Magic);
	printf("OEP: %x \n",pOptionHeader->AddressOfEntryPoint);
	printf("ImageBase: %x \n",pOptionHeader->ImageBase);
	printf("SectionAlignment: %x \n",pOptionHeader->SectionAlignment);
	printf("FileAlignment: %x \n",pOptionHeader->FileAlignment);
	printf("SizeOfImage: %x \n",pOptionHeader->SizeOfImage);
	printf("SizeOfHeaders: %x \n",pOptionHeader->SizeOfHeaders);

	//获取信息
	ImageBase = pOptionHeader->ImageBase;
	ImageSize = pOptionHeader->SizeOfImage;
	
}


//是否有重定位表
BOOL HasRelocationTable(LPVOID pFileBuffer)  
{  
	/*
	LPVOID pFileBuffer = NULL;
	pFileBuffer= ReadPEFile(lpszFile);
	if(!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}
	*/
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY DataDirectory=NULL;
	
	//Header信息
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);

	//定位Directory_Data;
	DataDirectory = pOptionHeader->DataDirectory;
	
	//重定位表
	printf("IMAGE_DIRECTORY_ENTRY_BASERELOC: Address: %x ,Size: %x \n",DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
		DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);


    return (DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)  
        && (DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);  
}  

//BOOL isAlloc = AllocShellSize(shellDirectory,pi.hProcess,encryptFileBuffer);
//在指定位置分配空间
LPVOID AllocShellSize(LPSTR shellDirectory,HANDLE shellProcess,LPVOID encryptFileBuffer)
{
	typedef void *(__stdcall *pfVirtualAllocEx)(unsigned long, void *, unsigned long, unsigned long, unsigned long);  
	pfVirtualAllocEx MyVirtualAllocEx = NULL;  
	MyVirtualAllocEx = (pfVirtualAllocEx)GetProcAddress(GetModuleHandle("Kernel32.dll"), "VirtualAllocEx");  
	
	//p = MyVirtualAllocEx((unsigned long)res, (void *)peH->OptionalHeader.ImageBase, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);  
	//p = MyVirtualAllocEx((unsigned long)res, NULL, ImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	//定位原始的shell的信息
	LPVOID pShellBuffer = ReadPEFile(shellDirectory);
	//LPVOID encryptFileBuffer;
	//获得ImageBase ImageSize， 进行信息比较
	DWORD shellImageBase=0;
	DWORD shellImageSize=0;
	DWORD encryptImageBase=0;
	DWORD encryptImageSize=0;
	GetNtHeaderInfo(pShellBuffer,shellImageBase,shellImageSize);
	GetNtHeaderInfo(encryptFileBuffer,encryptImageBase,encryptImageSize);
	/*
	TCHAR szTempStr[256]={0};
	sprintf(szTempStr,"shell: Base-%x,Size-%x, Encrypt: Base-%x,Size-%x",shellImageBase,shellImageSize,encryptImageBase,encryptImageSize);
	MessageBox(0,szTempStr,"info",MB_OK);
	*/
	if(shellImageBase == 0 || shellImageSize==0)
	{
		MessageBox(0,"申请空间失败1","失败1",0);
		return NULL;
	}
	if(encryptImageBase == 0 || encryptImageSize==0)
	{
		MessageBox(0,"申请空间失败2","失败2",0);
		if(isDebug){
			return NULL;
		}
	}

	void *p = NULL;  
	//在指定进程中分配内存
	if(shellImageBase == encryptImageBase  && shellImageSize>=encryptImageSize)
	{
		// 最好的分配方式 
		p = VirtualAllocEx(shellProcess,(void*)shellImageBase,shellImageSize,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}else
	{
		//自定义分配内存
		p = VirtualAllocEx(shellProcess,(void*)encryptImageBase,encryptImageSize,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}
	
	// 分配内存失败并且目标进程支持重定向
	if((p == NULL) && HasRelocationTable(encryptFileBuffer)){  
		//任意位置分配空间
		p = VirtualAllocEx(shellProcess, NULL, encryptImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
	    //开始重定位处理
		if(p) {
			DoRelocation(encryptFileBuffer, (void*)encryptImageBase, p);
		}else{
			
				MessageBox(0,"申请空间失败3","失败3",0);
				if(isDebug){
					return NULL;
				}
		}
    }
	//把代码贴入该内存中

	return p;
}

// 卸载原外壳占用内存  
BOOL UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr)  
{  
    typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(unsigned long, unsigned long);  
    pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;  
    BOOL res = FALSE;  
    HMODULE m = LoadLibrary("ntdll.dll");  
    if(m){  
        ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection"); 
		//MessageBox(0,"1111",0,0);
        if(ZwUnmapViewOfSection)  
            res = (ZwUnmapViewOfSection((unsigned long)ProcHnd, BaseAddr) == 0);  
        FreeLibrary(m);  
    }  
    return res;  
}  


LPVOID GetLastSecData(LPSTR lpszFile,DWORD &fileSize)
{
	LPVOID pFileBuffer = NULL;
	pFileBuffer= ReadPEFile(lpszFile);
	if(!pFileBuffer)
	{
		printf("文件读取失败\n");
		return NULL;
	}
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader_LAST = NULL;

	//Header信息
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader)+4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader+pPEHeader->SizeOfOptionalHeader);
	pSectionHeader_LAST = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader+(pPEHeader->NumberOfSections-1)*40);

	int fileLength = pSectionHeader_LAST->PointerToRawData+pSectionHeader_LAST->SizeOfRawData;
	
	//判断是否已经加壳
	if(strcmp((char*)pSectionHeader_LAST->Name,".enSec")!=0)
	{
		MessageBox(0,"没有加壳","错误",0);
		return NULL;
	}
	
	fileSize = pSectionHeader_LAST->SizeOfRawData;
	LPVOID pEncryptBuffer = malloc(fileSize);
	memset(pEncryptBuffer,0,fileSize);
	CHAR* pNew = (CHAR*)pEncryptBuffer;

	CHAR* pOld = (CHAR*)((DWORD)pFileBuffer+pSectionHeader_LAST->PointerToRawData);

	//将最后一个段的数据拷贝到pEncryptBuffer中,并解密
	for(int i=0;i<(int)fileSize;i++)
	{
		pNew[i] = pOld[i]^KEY;
	}

	
	//关闭文件
	free(pFileBuffer);
	return pEncryptBuffer;
}





int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
 	// TODO: Place code here.
	
	TCHAR shellDirectory[256]={0};
	GetModuleFileName(NULL,shellDirectory,256);
	//MessageBox(0,shellDirectory,0,0);
	
	DWORD encryptSize = 0;

	LPVOID encryptFileBuffer = NULL;
	encryptFileBuffer = GetLastSecData(shellDirectory,encryptSize);
	
	//失败则结束
	if(encryptFileBuffer == NULL)
	{
		MessageBox(0,"解密失败","失败",0);
		//return 0;
		if(isDebug){
			return 0;
		}
	}
	
	//成功，goon
	//WirteToFile(encryptFileBuffer,encryptSize,"C:\\aaa.exe");
	//MessageBox(0,"结束","写出完成",MB_OK);
	
	//以挂起的形式创建进程
	
	STARTUPINFO si={0};
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi;
	CreateProcess(shellDirectory,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,&pi);
	
	TCHAR szTempStr[256]={0};
	
	sprintf(szTempStr,"进程消息： %x , %x \n",pi.hProcess,pi.hThread);
	CONTEXT contx;
	contx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread,&contx);
	DWORD shellOEP = contx.Eax;
	
	//获取IMAGE_BASE的信息
	char* baseAddress = (CHAR*)contx.Ebx+8;
	TCHAR szBuffer[4]={0};
	ReadProcessMemory(pi.hProcess,baseAddress,szBuffer,4,NULL);
	int* fileImageBase;
	fileImageBase = (int*)szBuffer;
	DWORD shellImageBase  = *fileImageBase;

	//卸载外壳程序内存
	BOOL isUnload = UnloadShell(pi.hProcess,shellImageBase);
	/*
	if(isUnload)
	{
		MessageBox(0,"成功","1",0);
	}else
	{
		MessageBox(0,"失败","0",0);
	}
	*/
	
	//在指定位置分配空间
	//位置： Src的ImageBase
	//大小:  Src的SizeOfImage
	//shellDirectory

	LPVOID p = AllocShellSize(shellDirectory,pi.hProcess,encryptFileBuffer);
	if(p == NULL)
	{
		MessageBox(0,"内存分配失败","错误",0);
		if(isDebug){
			return 0;
		}
	}
	
	//内存地址 p
	//fileBuffer -> ImageBuffer
	DWORD pEncryptImageSize=0;
	LPVOID pEncryptImageBuffer = FileBufferToImageBuffer(encryptFileBuffer,pEncryptImageSize);
	
	//拷贝到shell的进程空间中
	//WriteProcessMemory(res, (void *)(Ctx.Ebx+8), &p, sizeof(DWORD), &old); // 重置目标进程运行环境中的基址   
	//peH->OptionalHeader.ImageBase = (unsigned long)p;   
    //if(WriteProcessMemory(res, p, Ptr, ImageSize, &old)){// 复制PE数据到目标进程 
	//WriteProcessMemory(pi.hProcess,p,pEncryptImageBuffer,)
	unsigned long old;
	WriteProcessMemory(pi.hProcess, (void *)(contx.Ebx+8), &p, sizeof(DWORD), &old); 

	if(WriteProcessMemory(pi.hProcess, p, pEncryptImageBuffer, pEncryptImageSize, &old)){// 复制PE数据到目标进程  

				DWORD encryptFileOEP = 0;
				DWORD encryptFileImageBase = 0;
				
				GetEncryptFileContext(encryptFileBuffer,encryptFileOEP,encryptFileImageBase);

                contx.ContextFlags = CONTEXT_FULL; 
				
				//这里一定要注意
				contx.Eax = encryptFileOEP + (DWORD)p;
                SetThreadContext(pi.hThread, &contx);// 更新运行环境
				
				/*写出数据测试*/
				/*
				LPVOID szBufferTemp = malloc(pEncryptImageSize);
				memset(szBufferTemp,0,pEncryptImageSize);
				ReadProcessMemory(pi.hProcess,p,szBufferTemp,pEncryptImageSize,NULL);
				//写出一个文件
				//WirteToFile(szBufferTemp,pEncryptImageSize,"c://11111.exe");
				MemeryTOFile(szBufferTemp,"c://22222.exe");
				*/

                ResumeThread(pi.hThread);// 执行  
                CloseHandle(pi.hThread);  
     } 
	
	return 0;
}


```