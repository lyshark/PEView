#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <atlconv.h>
#include <vector>
#include <time.h> 
#include <sstream>  
#include <string>   
#include <cstdio>   
#include <vector>   
#include <cstdint>  
#include <inttypes.h>
#include <capstone/capstone.h>
#include <boost/tokenizer.hpp>

#pragma comment(lib,"capstone32.lib")

using namespace std;
using namespace boost;

// --------------------------------------------------
// 重定位类型常量定义（PE格式标准）
// --------------------------------------------------
#define IMAGE_REL_BASED_ABSOLUTE    0x00    // 无意义，用于填充
#define IMAGE_REL_BASED_HIGH        0x01    // 高16位重定位
#define IMAGE_REL_BASED_LOW         0x02    // 低16位重定位
#define IMAGE_REL_BASED_HIGHLOW     0x03    // 32位完整地址重定位
#define IMAGE_REL_BASED_REL32       0x04    // 32位相对地址重定位
#define IMAGE_REL_BASED_DIR64       0x0A    // 64位地址重定位（扩展）

struct TypeOffset
{
	WORD Offset : 12;       // 低12位代表重定位地址
	WORD Type : 4;          // 高4位代表重定位类型
};

// 修正常量定义（解决case值重复问题）
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#define IMAGE_SUBSYSTEM_WINDOWS_DRIVER 0x000B  // 修正为EFI引导服务驱动的标准值（避免与3冲突）
#define IMAGE_SUBSYSTEM_WINDOWS_NATIVE 0x0001  // 修正为原生系统的标准值
#define IMAGE_DLLCHARACTERISTICS_NO_UAC_DLL 0x0040
#define IMAGE_DLLCHARACTERISTICS_ISOLATION 0x0020

// --------------------------------------------------
// 读取并设置文件基址以及文件大小
// --------------------------------------------------
CHAR GlobalFilePath[2048] = { 0 }; // 保存文件路径
DWORD GlobalFileSize = 0;          // 定义文件大小
DWORD GlobalFileBase = 0;          // 保存文件的基地址
DWORD IsOpen = 0;                  // 设置文件是否已经打开

// --------------------------------------------------
// 定义全局变量,来存储 DOS头部/NT头部/Section头部
// --------------------------------------------------
PIMAGE_DOS_HEADER DosHeader = nullptr;
PIMAGE_NT_HEADERS NtHeader = nullptr;
PIMAGE_FILE_HEADER FileHead = nullptr;
PIMAGE_SECTION_HEADER pSection = nullptr;

// --------------------------------------------------
// 定义资源表解析结构
// --------------------------------------------------
static char* szResName[0x11] = {
	0,                                  // 0 - 未定义
	(char*)"鼠标指针",                  // 1 - RT_CURSOR
	(char*)"位图",                      // 2 - RT_BITMAP
	(char*)"图标",                      // 3 - RT_ICON
	(char*)"菜单",                      // 4 - RT_MENU
	(char*)"对话框",                    // 5 - RT_DIALOG
	(char*)"字符串列表",                // 6 - RT_STRING
	(char*)"字体目录",                  // 7 - RT_FONTDIR
	(char*)"字体",                      // 8 - RT_FONT
	(char*)"快捷键",                    // 9 - RT_ACCELERATOR
	(char*)"非格式化资源",              // 10 - RT_RCDATA
	(char*)"消息列表",                  // 11 - RT_MESSAGETABLE
	(char*)"鼠标指针组",                // 12 - RT_GROUP_CURSOR
	(char*)"即插即用资源",              // 13 - RT_PLUGPLAY（补充:硬件相关配置资源）
	(char*)"图标组",                    // 14 - RT_GROUP_ICON
	(char*)"保留/自定义类型",           // 15 - 无标准系统类型（原"xx"替换，通常为保留或自定义）
	(char*)"版本信息"                   // 16 - RT_VERSION
};

// PE结构解析系列
namespace PEView
{
	// --------------------------------------------------
	// 输出不等宽的各种线条
	// --------------------------------------------------
	void DisplayLine(int Count)
	{
		for (int x = 0; x < Count; x++)
			printf("-");
		printf("\n");
	}

	// --------------------------------------------------
	// 验证是否已经打开过文件
	// --------------------------------------------------
	void IsOpenFile()
	{
		if (IsOpen != 1)
		{
			printf("[-] 请先打开PE文件 \n");
			exit(0);
		}
	}

	// --------------------------------------------------
	// 临时将RVA转换为FOA的函数
	// --------------------------------------------------
	DWORD RVAtoFOA(DWORD rva)
	{
		IsOpenFile();
		auto SectionTables = IMAGE_FIRST_SECTION(NtHeader);    // 获取区段表
		WORD Count = NtHeader->FileHeader.NumberOfSections;    // 获取区段数量

		for (int i = 0; i < Count; ++i)
		{
			// 判断是否存在于区段中
			DWORD Section_Start = SectionTables[i].VirtualAddress;
			DWORD Section_Ends = SectionTables[i].VirtualAddress + SectionTables[i].SizeOfRawData;
			if (rva >= Section_Start && rva < Section_Ends)
			{
				// 找到之后计算位置并返回值
				return rva - SectionTables[i].VirtualAddress + SectionTables[i].PointerToRawData;
			}
		}
		return -1;
	}

	// --------------------------------------------------
	// 临时将FOA文件偏移转换为RVA相对地址
	// --------------------------------------------------
	DWORD FOAtoRVA(DWORD dwFOA)
	{
		IsOpenFile();
		DWORD NumberOfSectinsCount = 0;
		DWORD dwImageBase = 0;

		dwImageBase = NtHeader->OptionalHeader.ImageBase;
		NumberOfSectinsCount = NtHeader->FileHeader.NumberOfSections;
		for (DWORD each = 0; each < NumberOfSectinsCount; each++)
		{
			DWORD PointerRawStart = pSection[each].PointerToRawData;
			DWORD PointerRawEnds = pSection[each].PointerToRawData + pSection[each].SizeOfRawData;

			if (dwFOA >= PointerRawStart && dwFOA <= PointerRawEnds)
			{
				DWORD RVA = pSection[each].VirtualAddress + (dwFOA - pSection[each].PointerToRawData);
				return RVA;
			}
		}
		return 0;
	}

	// --------------------------------------------------
	// 传入一个十六进制字符串，将其自动转化为十进制格式:例如传入40158b转为4199819
	// --------------------------------------------------
	int HexStringToDec(char hexStr[])
	{
		int i, m, n, temp = 0;

		// 循环读入每一个十六进制数
		m = strlen(hexStr);
		for (i = 0; i < m; i++)
		{
			// 十六进制还要判断他是不是在A-F或0-9之间的数
			if (hexStr[i] >= 'A' && hexStr[i] <= 'F')
				n = hexStr[i] - 'A' + 10;
			else if (hexStr[i] >= 'a' && hexStr[i] <= 'f')
				n = hexStr[i] - 'a' + 10;
			else n = hexStr[i] - '0';
			// 将数据加起来
			temp = temp * 16 + n;
		}
		return temp;
	}

	// --------------------------------------------------
	// 将十进制整数转为十六进制字符串
	// --------------------------------------------------
	char* DexToHex(int dex)
	{
		char hex[9] = { 0 };
		char ref[9] = { 0 };
		if (dex != 0 && dex && dex >= 0)
		{
			_ltoa(dex, hex, 16);
			sprintf(ref, "0x%08s", hex);
			return ref;
		}
		return (char *)"0x00000000";
	}

	// --------------------------------------------------
	// 将十六进制字符串转为整数
	// --------------------------------------------------
	int HexToDex(char* Hex)
	{
		int ref = 0;
		if (Hex)
		{
			sscanf_s(Hex, "%x", &ref);
			return ref;
		}
		return 0;
	}

	// --------------------------------------------------
	// 解析特征码字符串（支持格式如"55 8B ?? EC"）
	// --------------------------------------------------
	std::vector<unsigned char> ParseSignature(const std::string& sig_str)
	{
		std::vector<unsigned char> sig;
		std::stringstream ss(sig_str);
		std::string token;

		while (std::getline(ss, token, ' '))
		{
			if (token.empty())
				continue;

			// 处理通配符??
			if (token == "??")
			{
				sig.push_back(0xFF); // 用0xFF标记通配符（实际文件中不会有此值作为匹配条件）
			}
			// 处理十六进制字节（如55、8B）
			else if (token.size() == 2)
			{
				try
				{
					unsigned char byte = static_cast<unsigned char>(std::stoul(token, nullptr, 16));
					sig.push_back(byte);
				}
				catch (...)
				{
					// 无效十六进制字符
					return{};
				}
			}
			// 无效格式（如单字符、三字符）
			else
			{
				return{};
			}
		}
		return sig;
	}

	// --------------------------------------------------
	// 获取指定DLL中特定函数的内存位置
	// --------------------------------------------------
	void GetProcessAddress(char* DllName, char* Function)
	{
		if (!DllName || !Function)
		{
			printf("[-] 无效参数:DLL名称或函数名不能为空\n");
			return;
		}

		DisplayLine(80);
		printf("[*] 尝试获取DLL函数地址:\n");
		printf("[*] DLL名称:%s\n", DllName);
		printf("[*] 函数名称:%s\n", Function);
		DisplayLine(80);

		// 加载目标DLL
		HMODULE hDll = LoadLibraryA(DllName);
		if (hDll == NULL)
		{
			DWORD dwErr = GetLastError();
			printf("[-] 加载DLL失败！错误码:0x%08X\n", dwErr);
			printf("[-] 可能原因:DLL不存在、路径错误或依赖缺失\n");
			return;
		}

		// 获取函数地址
		FARPROC pFunc = GetProcAddress(hDll, Function);
		if (pFunc == NULL)
		{
			DWORD dwErr = GetLastError();
			printf("[-] 获取函数地址失败！错误码:0x%08X\n", dwErr);
			printf("[-] 可能原因:函数不存在或不是导出函数\n");
			FreeLibrary(hDll);
			return;
		}

		// 成功获取地址，打印详细信息
		printf("[+] DLL加载基地址:0x%08X\n", (DWORD)hDll);
		printf("[+] 函数相对偏移（RVA）:0x%08X\n", (DWORD)pFunc - (DWORD)hDll);
		printf("[+] 函数绝对地址（VA）:0x%08X\n", (DWORD)pFunc);

		// 释放DLL资源
		if (!FreeLibrary(hDll))
		{
			DWORD dwErr = GetLastError();
			printf("[-] 释放DLL资源失败！错误码:0x%08X\n", dwErr);
		}
		DisplayLine(80);
	}

	// --------------------------------------------------
	// 打开文件操作
	// --------------------------------------------------
	void OpenPeFile(LPCSTR FileName)
	{
		HANDLE hFile, hMapFile, lpMapAddress = NULL;

		hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("[-] 打开文件失败 \n");
			exit(0);
		}
		GlobalFileSize = GetFileSize(hFile, NULL);
		if (GlobalFileSize != 0)
		{
			printf("[+] 已读入文件 \n");
		}

		hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, GlobalFileSize, NULL);
		if (hMapFile == NULL)
		{
			printf("[-] 创建映射对象失败\n");
			exit(0);
		}

		lpMapAddress = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, GlobalFileSize);
		if (lpMapAddress != NULL)
		{
			// 设置读入文件基地址
			GlobalFileBase = (DWORD)lpMapAddress;

			// 获取DOS头并判断是不是一个有效的DOS文件
			DosHeader = (PIMAGE_DOS_HEADER)GlobalFileBase;
			if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
				printf("[-] 文件不属于DOS结构 \n");
				exit(0);
			}

			// 获取 NT 头并判断是不是一个有效的PE文件
			NtHeader = (PIMAGE_NT_HEADERS)(GlobalFileBase + DosHeader->e_lfanew);
			if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				printf("[-] 文件不属于PE结构 \n");
				exit(0);
			}

			// 判断是不是32位程序
			if (NtHeader->OptionalHeader.Magic != 0x010B)
			{
				printf("[-] 无法调试非32位PE文件\n");
				exit(0);
			}

			// 获取到文件头指针
			FileHead = &NtHeader->FileHeader;

			// 获取到节表头
			pSection = IMAGE_FIRST_SECTION(NtHeader);
			IsOpen = 1;

			strcpy(GlobalFilePath, FileName);
		}
	}

	// --------------------------------------------------
	// 输出文件基本信息（包含路径、大小、PE结构标识及关键头信息）
	// --------------------------------------------------
	void ShowFileBasicInfo()
	{
		IsOpenFile();

		// 获取文件时间信息（创建时间、修改时间）
		HANDLE hFile = CreateFileA(GlobalFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		FILETIME createTime, modifyTime, accessTime;
		SYSTEMTIME localCreateTime, localModifyTime;
		GetFileTime(hFile, &createTime, &accessTime, &modifyTime);
		FileTimeToLocalFileTime(&createTime, &createTime);
		FileTimeToSystemTime(&createTime, &localCreateTime);
		FileTimeToLocalFileTime(&modifyTime, &modifyTime);
		FileTimeToSystemTime(&modifyTime, &localModifyTime);
		CloseHandle(hFile);

		// 获取文件属性
		DWORD fileAttr = GetFileAttributesA(GlobalFilePath);
		std::string attrStr;
		if (fileAttr & FILE_ATTRIBUTE_READONLY) attrStr += "只读; ";
		if (fileAttr & FILE_ATTRIBUTE_HIDDEN) attrStr += "隐藏; ";
		if (fileAttr & FILE_ATTRIBUTE_SYSTEM) attrStr += "系统; ";
		if (fileAttr & FILE_ATTRIBUTE_ARCHIVE) attrStr += "归档; ";
		if (attrStr.empty()) attrStr = "正常";

		// 计算文件大小（转换为KB/MB）
		double fileSizeKB = (double)GlobalFileSize / 1024;
		double fileSizeMB = fileSizeKB / 1024;

		DisplayLine(100);
		printf("文件基本信息\n");
		DisplayLine(100);

		// 1. 文件路径与名称信息
		printf("[文件路径]: %s\n", GlobalFilePath);
		printf("[文件大小]: %.2f KB \n", fileSizeKB);
		printf("[文件属性]: %s\n", attrStr.c_str());
		printf("[创建时间]: %04d-%02d-%02d %02d:%02d:%02d\n",
			localCreateTime.wYear, localCreateTime.wMonth, localCreateTime.wDay,
			localCreateTime.wHour, localCreateTime.wMinute, localCreateTime.wSecond);
		printf("[修改时间]: %04d-%02d-%02d %02d:%02d:%02d\n",
			localModifyTime.wYear, localModifyTime.wMonth, localModifyTime.wDay,
			localModifyTime.wHour, localModifyTime.wMinute, localModifyTime.wSecond);
		printf("[映射基址]: 0x%08X\n", GlobalFileBase);

		DisplayLine(80);
		printf("PE结构标识\n");
		DisplayLine(80);

		// 2. DOS头关键信息
		printf("[DOS签名]: 0x%04X (%s)\n", DosHeader->e_magic,
			DosHeader->e_magic == IMAGE_DOS_SIGNATURE ? "有效DOS签名(MZ)" : "无效DOS签名");
		printf("[PE头偏移]: 0x%08X (从文件开始的偏移)\n", DosHeader->e_lfanew);

		// 3. NT头基本信息
		printf("[NT签名]: 0x%08X (%s)\n", NtHeader->Signature,
			NtHeader->Signature == IMAGE_NT_SIGNATURE ? "有效PE签名(PE00)" : "无效PE签名");
		printf("[机器类型]: 0x%04X (", NtHeader->FileHeader.Machine);
		switch (NtHeader->FileHeader.Machine)
		{
			case IMAGE_FILE_MACHINE_I386:  printf("x86 (32位)"); break;
			case IMAGE_FILE_MACHINE_AMD64: printf("x64 (64位)"); break;
			case IMAGE_FILE_MACHINE_ARM:   printf("ARM架构"); break;
			default: printf("未知架构");
		}
		printf(")\n");
		printf("[节区数量]: %d 个\n", NtHeader->FileHeader.NumberOfSections);
		printf("[时间戳]: 0x%08X (", NtHeader->FileHeader.TimeDateStamp);
		SYSTEMTIME timestampSysTime;
		FILETIME timestampFileTime;
		ULARGE_INTEGER uli;
		uli.LowPart = NtHeader->FileHeader.TimeDateStamp;
		uli.HighPart = 0;
		timestampFileTime.dwLowDateTime = uli.LowPart;
		timestampFileTime.dwHighDateTime = uli.HighPart;
		FileTimeToLocalFileTime(&timestampFileTime, &timestampFileTime);
		FileTimeToSystemTime(&timestampFileTime, &timestampSysTime);
		printf("%04d-%02d-%02d %02d:%02d:%02d)",
			timestampSysTime.wYear, timestampSysTime.wMonth, timestampSysTime.wDay,
			timestampSysTime.wHour, timestampSysTime.wMinute, timestampSysTime.wSecond);
		printf("\n");
		printf("[特性标记]: 0x%04X (", NtHeader->FileHeader.Characteristics);
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) printf("可执行; ");
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) printf("DLL文件; ");
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) printf("系统文件; ");
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) printf("移除调试信息; ");
		printf(")\n");

		DisplayLine(80);
		printf("可选头关键信息\n");
		DisplayLine(80);

		// 4. 可选头信息
		printf("[入口点RVA]: 0x%08X (程序开始执行的相对虚拟地址)\n", NtHeader->OptionalHeader.AddressOfEntryPoint);
		printf("[镜像基址]: 0x%08X (加载到内存中的首选基地址)\n", NtHeader->OptionalHeader.ImageBase);
		printf("[图像大小]: 0x%08X 字节 (加载到内存后的总大小)\n", NtHeader->OptionalHeader.SizeOfImage);
		printf("[节区对齐]: 0x%08X 字节 (内存中节区的对齐粒度)\n", NtHeader->OptionalHeader.SectionAlignment);
		printf("[文件对齐]: 0x%08X 字节 (磁盘上节区的对齐粒度)\n", NtHeader->OptionalHeader.FileAlignment);
		printf("[子系统]: 0x%04X (", NtHeader->OptionalHeader.Subsystem);
		switch (NtHeader->OptionalHeader.Subsystem)
		{
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:   printf("Windows GUI (图形界面)"); break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:   printf("Windows CUI (控制台程序)"); break;
		case IMAGE_SUBSYSTEM_NATIVE:        printf("Native (系统内核模式)"); break;
		default: printf("未知子系统");
		}
		printf(")\n");
		printf("[DLL特性]: 0x%04X (", NtHeader->OptionalHeader.DllCharacteristics);
		if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) printf("ASLR支持; ");
		if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) printf("DEP支持; ");
		if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) printf("不使用SEH; ");
		printf(")\n");
		printf("[栈大小]: 保留 0x%08X 字节, 提交 0x%08X 字节\n",
			NtHeader->OptionalHeader.SizeOfStackReserve, NtHeader->OptionalHeader.SizeOfStackCommit);
		printf("[堆大小]: 保留 0x%08X 字节, 提交 0x%08X 字节\n",
			NtHeader->OptionalHeader.SizeOfHeapReserve, NtHeader->OptionalHeader.SizeOfHeapCommit);

		DisplayLine(100);
	}

	// --------------------------------------------------
	// 输出DOS头结构
	// --------------------------------------------------
	void ShowDosHead()
	{
		IsOpenFile();
		DisplayLine(70);
		printf("\t\t\t 十六进制 \t 十进制 \n");
		DisplayLine(70);
		printf("DOS标志(MZ):              %08X \t %08d \n", DosHeader->e_magic, DosHeader->e_magic);
		printf("文件最后一页的字节数:     %08X \t %08d \n", DosHeader->e_cblp, DosHeader->e_cblp);
		printf("文件中的页面数:           %08X \t %08d \n", DosHeader->e_cp, DosHeader->e_cp);
		printf("重定位项数量:             %08X \t %08d \n", DosHeader->e_crlc, DosHeader->e_crlc);
		printf("头部占用的段落数:         %08X \t %08d \n", DosHeader->e_cparhdr, DosHeader->e_cparhdr);
		printf("所需最小额外段落数:       %08X \t %08d \n", DosHeader->e_minalloc, DosHeader->e_minalloc);
		printf("所需最大额外段落数:       %08X \t %08d \n", DosHeader->e_maxalloc, DosHeader->e_maxalloc);
		printf("初始SS值(相对):          %08X \t %08d \n", DosHeader->e_ss, DosHeader->e_ss);
		printf("初始SP值:                 %08X \t %08d \n", DosHeader->e_sp, DosHeader->e_sp);
		printf("校验和:                   %08X \t %08d \n", DosHeader->e_csum, DosHeader->e_csum);
		printf("初始IP值:                 %08X \t %08d \n", DosHeader->e_ip, DosHeader->e_ip);
		printf("初始CS值(相对):          %08X \t %08d \n", DosHeader->e_cs, DosHeader->e_cs);
		printf("重定位表偏移:             %08X \t %08d \n", DosHeader->e_lfarlc, DosHeader->e_lfarlc);
		printf("叠加层数:                 %08X \t %08d \n", DosHeader->e_ovno, DosHeader->e_ovno);

		// 补充保留字段e_res[4]的详细信息（原代码只输出了第一个元素）
		for (int i = 0; i < 4; i++)
		{
			printf("保留字段e_res[%d]:        %08X \t %08d \n", i, DosHeader->e_res[i], DosHeader->e_res[i]);
		}

		printf("OEM标识符:                %08X \t %08d \n", DosHeader->e_oemid, DosHeader->e_oemid);
		printf("OEM信息:                  %08X \t %08d \n", DosHeader->e_oeminfo, DosHeader->e_oeminfo);

		// 补充保留字段e_res2[10]的详细信息（原代码未完整输出）
		for (int i = 0; i < 10; i++)
		{
			printf("保留字段e_res2[%d]:       %08X \t %08d \n", i, DosHeader->e_res2[i], DosHeader->e_res2[i]);
		}

		printf("PE头偏移指针:             %08X \t %08d \n", DosHeader->e_lfanew, DosHeader->e_lfanew);
		DisplayLine(70);
	}

	// --------------------------------------------------
	// 输出NT头结构
	// --------------------------------------------------
	void ShowNtHead()
	{
		IsOpenFile();
		DisplayLine(100);
		printf("\t\t\t 十六进制 \t 十进制 \t 描述 \n");
		DisplayLine(100);

		// ---------------------------- NT签名 ----------------------------
		printf("NT标志:               0x%08X \t %08d \t %s \n",
			NtHeader->Signature,
			NtHeader->Signature,
			(NtHeader->Signature == IMAGE_NT_SIGNATURE) ? "有效PE签名(PE00)" : "无效PE签名");

		// ---------------------------- 文件头(IMAGE_FILE_HEADER) ----------------------------
		printf("\n[文件头(IMAGE_FILE_HEADER)]\n");

		// 运行平台（Machine）解析
		const char* machineDesc = "未知平台";
		switch (NtHeader->FileHeader.Machine)
		{
			case IMAGE_FILE_MACHINE_I386:  machineDesc = "x86 (32位)"; break;
			case IMAGE_FILE_MACHINE_AMD64: machineDesc = "x64 (64位)"; break;
			case IMAGE_FILE_MACHINE_ARM:   machineDesc = "ARM架构"; break;
		}
		printf("运行平台:             0x%08X \t %08d \t %s \n",
			NtHeader->FileHeader.Machine,
			NtHeader->FileHeader.Machine,
			machineDesc);

		printf("区段数目:             0x%08X \t %08d \t  PE文件包含的区段数量 \n",
			NtHeader->FileHeader.NumberOfSections,
			NtHeader->FileHeader.NumberOfSections);

		// 时间戳转换为可读时间
		time_t timestamp = NtHeader->FileHeader.TimeDateStamp;
		struct tm* tm_info = localtime(&timestamp);
		char timeStr[26];
		asctime_s(timeStr, sizeof(timeStr), tm_info);
		printf("时间日期标志:         0x%08X \t %08d \t %s",
			NtHeader->FileHeader.TimeDateStamp,
			NtHeader->FileHeader.TimeDateStamp,
			timeStr);  // 注意asctime_s已包含换行

		// 特征值(Characteristics)解析
		string characDesc;
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)      characDesc += "移除重定位; ";
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)     characDesc += "可执行文件; ";
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)   characDesc += "移除行号; ";
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)  characDesc += "移除本地符号; ";
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)                  characDesc += "DLL文件; ";
		if (characDesc.empty()) characDesc = "无特殊特征";
		printf("特征值:               0x%08X \t %08d \t %s \n",
			NtHeader->FileHeader.Characteristics,
			NtHeader->FileHeader.Characteristics,
			characDesc.c_str());

		printf("可选头部大小:         0x%08X \t %08d \t 可选头的字节大小 \n",
			NtHeader->FileHeader.SizeOfOptionalHeader,
			NtHeader->FileHeader.SizeOfOptionalHeader);

		printf("符号数量:             0x%08X \t %08d \t 符号表中的符号数量 \n",
			NtHeader->FileHeader.NumberOfSymbols,
			NtHeader->FileHeader.NumberOfSymbols);

		printf("符号表指针:           0x%08X \t %08d \t 符号表在文件中的偏移 \n",
			NtHeader->FileHeader.PointerToSymbolTable,
			NtHeader->FileHeader.PointerToSymbolTable);

		// ---------------------------- 可选头(IMAGE_OPTIONAL_HEADER32) ----------------------------
		printf("\n[可选头(IMAGE_OPTIONAL_HEADER32)]\n");
		// 入口点（结合镜像基址计算VA）
		DWORD entryVA = NtHeader->OptionalHeader.ImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
		printf("入口点(RVA):          0x%08X \t %08d \t 入口点虚拟地址(VA: 0x%08X) \n",
			NtHeader->OptionalHeader.AddressOfEntryPoint,
			NtHeader->OptionalHeader.AddressOfEntryPoint,
			entryVA);

		printf("镜像基址:             0x%08X \t %08d \t 加载到内存的首选基地址 \n",
			NtHeader->OptionalHeader.ImageBase,
			NtHeader->OptionalHeader.ImageBase);

		printf("镜像大小:             0x%08X \t %08d \t 内存中整个镜像的大小(字节) \n",
			NtHeader->OptionalHeader.SizeOfImage,
			NtHeader->OptionalHeader.SizeOfImage);

		printf("代码基址(RVA):        0x%08X \t %08d \t 代码段的起始相对虚拟地址 \n",
			NtHeader->OptionalHeader.BaseOfCode,
			NtHeader->OptionalHeader.BaseOfCode);

		printf("数据基址(RVA):        0x%08X \t %08d \t 数据段的起始相对虚拟地址 \n",  // 原代码遗漏
			NtHeader->OptionalHeader.BaseOfData,
			NtHeader->OptionalHeader.BaseOfData);

		printf("代码大小:             0x%08X \t %08d \t 代码段的总大小(字节) \n",  // 原代码遗漏
			NtHeader->OptionalHeader.SizeOfCode,
			NtHeader->OptionalHeader.SizeOfCode);

		printf("已初始化数据大小:     0x%08X \t %08d \t 已初始化数据段的大小(字节) \n",  // 原代码遗漏
			NtHeader->OptionalHeader.SizeOfInitializedData,
			NtHeader->OptionalHeader.SizeOfInitializedData);

		printf("未初始化数据大小:     0x%08X \t %08d \t 未初始化数据段的大小(字节) \n",  // 原代码遗漏
			NtHeader->OptionalHeader.SizeOfUninitializedData,
			NtHeader->OptionalHeader.SizeOfUninitializedData);

		printf("内存对齐:             0x%08X \t %08d \t 内存中区块的对齐粒度(字节) \n",
			NtHeader->OptionalHeader.SectionAlignment,
			NtHeader->OptionalHeader.SectionAlignment);

		printf("文件对齐:             0x%08X \t %08d \t 文件中区块的对齐粒度(字节) \n",
			NtHeader->OptionalHeader.FileAlignment,
			NtHeader->OptionalHeader.FileAlignment);

		// 子系统(Subsystem)解析
		const char* subsystemDesc = "未知子系统";
		switch (NtHeader->OptionalHeader.Subsystem)
		{
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:  subsystemDesc = "Windows GUI(图形界面)"; break;
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:  subsystemDesc = "Windows CUI(控制台)"; break;
		case IMAGE_SUBSYSTEM_NATIVE:       subsystemDesc = "原生系统程序"; break;
		}
		printf("子系统:               0x%08X \t %08d \t %s \n",
			NtHeader->OptionalHeader.Subsystem,
			NtHeader->OptionalHeader.Subsystem,
			subsystemDesc);

		printf("首部大小:             0x%08X \t %08d \t DOS头+NT头+区段表的总大小 \n",
			NtHeader->OptionalHeader.SizeOfHeaders,
			NtHeader->OptionalHeader.SizeOfHeaders);

		printf("校验和:               0x%08X \t %08d \t 用于验证文件完整性(通常为0) \n",
			NtHeader->OptionalHeader.CheckSum,
			NtHeader->OptionalHeader.CheckSum);

		printf("数据目录数量:         0x%08X \t %08d \t 数据目录项的数量(通常为16) \n",  // 原代码描述优化
			NtHeader->OptionalHeader.NumberOfRvaAndSizes,
			NtHeader->OptionalHeader.NumberOfRvaAndSizes);

		// 链接器版本
		printf("链接器主版本:         0x%08X \t %08d \n",  // 原代码遗漏
			NtHeader->OptionalHeader.MajorLinkerVersion,
			NtHeader->OptionalHeader.MajorLinkerVersion);
		printf("链接器次版本:         0x%08X \t %08d \n",  // 原代码遗漏
			NtHeader->OptionalHeader.MinorLinkerVersion,
			NtHeader->OptionalHeader.MinorLinkerVersion);

		// 版本信息（补充完整）
		printf("操作系统版本:         %d.%d \t\t - \t 主版本.%d.次版本.%d \n",  // 格式优化
			NtHeader->OptionalHeader.MajorOperatingSystemVersion,
			NtHeader->OptionalHeader.MinorOperatingSystemVersion,
			NtHeader->OptionalHeader.MajorOperatingSystemVersion,
			NtHeader->OptionalHeader.MinorOperatingSystemVersion);

		printf("映像版本:             %d.%d \t\t - \t 主版本.%d.次版本.%d \n",  // 格式优化
			NtHeader->OptionalHeader.MajorImageVersion,
			NtHeader->OptionalHeader.MinorImageVersion,
			NtHeader->OptionalHeader.MajorImageVersion,
			NtHeader->OptionalHeader.MinorImageVersion);

		printf("子系统版本:           %d.%d \t\t - \t 主版本.%d.次版本.%d \n",  // 格式优化
			NtHeader->OptionalHeader.MajorSubsystemVersion,
			NtHeader->OptionalHeader.MinorSubsystemVersion,
			NtHeader->OptionalHeader.MajorSubsystemVersion,
			NtHeader->OptionalHeader.MinorSubsystemVersion);

		printf("Win32版本值:          0x%08X \t %08d \t 通常为0(保留) \n",
			NtHeader->OptionalHeader.Win32VersionValue,
			NtHeader->OptionalHeader.Win32VersionValue);

		// DLL特征(DllCharacteristics)解析
		string dllCharacDesc;
		if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)  dllCharacDesc += "支持ASLR; ";
		if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)     dllCharacDesc += "支持DEP; ";
		if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)        dllCharacDesc += "不使用SEH; ";
		if (dllCharacDesc.empty()) dllCharacDesc = "无特殊特征";
		printf("DLL特征:              0x%08X \t %08d \t %s \n",
			NtHeader->OptionalHeader.DllCharacteristics,
			NtHeader->OptionalHeader.DllCharacteristics,
			dllCharacDesc.c_str());

		// 栈和堆相关（补充说明）
		printf("栈保留大小:           0x%08X \t %08d \t 进程栈的保留大小 \n",
			NtHeader->OptionalHeader.SizeOfStackReserve,
			NtHeader->OptionalHeader.SizeOfStackReserve);
		printf("栈提交大小:           0x%08X \t %08d \t 进程栈的初始提交大小 \n",
			NtHeader->OptionalHeader.SizeOfStackCommit,
			NtHeader->OptionalHeader.SizeOfStackCommit);
		printf("堆保留大小:           0x%08X \t %08d \t 进程堆的保留大小 \n",
			NtHeader->OptionalHeader.SizeOfHeapReserve,
			NtHeader->OptionalHeader.SizeOfHeapReserve);
		printf("堆提交大小:           0x%08X \t %08d \t 进程堆的初始提交大小 \n",
			NtHeader->OptionalHeader.SizeOfHeapCommit,
			NtHeader->OptionalHeader.SizeOfHeapCommit);

		printf("加载器标志:           0x%08X \t %08d \t 已废弃(通常为0) \n",  // 补充说明
			NtHeader->OptionalHeader.LoaderFlags,
			NtHeader->OptionalHeader.LoaderFlags);

		DisplayLine(100);
	}

	// --------------------------------------------------
	//显示区段信息 
	// --------------------------------------------------
	void ShowSection()
	{
		IsOpenFile();
		// 使用局部指针遍历节表，避免修改全局pSection
		PIMAGE_SECTION_HEADER pLocalSection = IMAGE_FIRST_SECTION(NtHeader);
		DWORD sectionCount = NtHeader->FileHeader.NumberOfSections;

		DisplayLine(160);
		printf("编号\t 节区名称\t虚拟偏移(RVA)\t虚拟大小\t实际偏移(FOA)\t实际大小\t"
			"重定位偏移\t重定位数量\t行号偏移\t行号数量\t节区属性(十六进制)\t节区属性描述\n");
		DisplayLine(160);

		for (DWORD each = 0; each < sectionCount; each++, pLocalSection++)
		{
			// 解析节区属性标志（Characteristics）
			string attrDesc;
			if (pLocalSection->Characteristics & IMAGE_SCN_CNT_CODE)
				attrDesc += "代码节; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
				attrDesc += "已初始化数据; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				attrDesc += "未初始化数据; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
				attrDesc += "可执行; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_MEM_READ)
				attrDesc += "可读; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_MEM_WRITE)
				attrDesc += "可写; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
				attrDesc += "重定位溢出; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_1BYTES)
				attrDesc += "1字节对齐; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_2BYTES)
				attrDesc += "2字节对齐; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_4BYTES)
				attrDesc += "4字节对齐; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_8BYTES)
				attrDesc += "8字节对齐; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_16BYTES)
				attrDesc += "16字节对齐; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_32BYTES)
				attrDesc += "32字节对齐; ";
			if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_64BYTES)
				attrDesc += "64字节对齐; ";
			if (attrDesc.empty())
				attrDesc = "无特殊属性";

			// 打印节表完整信息
			printf("%-6d %-10s 0x%.8X\t 0x%.8X\t 0x%.8X\t 0x%.8X\t 0x%.8X\t %-10d 0x%.8X\t %-10d 0x%.8X\t %s\n",
				each + 1,
				pLocalSection->Name,                  // 节区名称
				pLocalSection->VirtualAddress,        // 虚拟偏移(RVA)
				pLocalSection->Misc.VirtualSize,      // 虚拟大小
				pLocalSection->PointerToRawData,      // 实际偏移(FOA)
				pLocalSection->SizeOfRawData,         // 实际大小
				pLocalSection->PointerToRelocations,  // 重定位信息偏移
				pLocalSection->NumberOfRelocations,   // 重定位项数量
				pLocalSection->PointerToLinenumbers,  // 行号信息偏移
				pLocalSection->NumberOfLinenumbers,   // 行号数量
				pLocalSection->Characteristics,       // 节区属性(十六进制)
				attrDesc.c_str()                      // 节区属性描述
				);
		}
		DisplayLine(160);
	}

	// --------------------------------------------------
	// 遍历数据目录表
	// --------------------------------------------------
	void ShowOptionalDataDirectoryInfo()
	{
		IsOpenFile();
		int Data_Size = NtHeader->OptionalHeader.NumberOfRvaAndSizes;
		DWORD ImageBase = NtHeader->OptionalHeader.ImageBase; // 基地址，用于计算VA

		// 定义数据目录标准名称和详细描述（对应IMAGE_DIRECTORY_ENTRY_*）
		const char* dirNames[16] = {
			"Export Table",
			"Import Table",
			"Resource Table",
			"Exception Table",
			"Security Table",
			"Base Relocation Table",
			"Debug Table",
			"Architecture",
			"Global Pointer",
			"TLS Table",
			"Load Configuration Table",
			"Bound Import Table",
			"Import Address Table",
			"Delay Import Descriptor",
			"COM Descriptor",
			"Reserved"
		};

		const char* dirDescriptions[16] = {
			"包含导出函数和符号信息，供其他模块调用",
			"包含导入的DLL和函数信息，需要在加载时解析",
			"包含程序资源（图标、字符串、对话框等）的索引信息",
			"包含异常处理相关结构，用于异常捕获和处理",
			"包含数字签名等安全信息，用于验证文件完整性",
			"包含基地址重定位信息，用于模块加载地址与默认不同时修正",
			"包含调试信息（如调试符号路径、类型等）",
			"版权信息字符串（通常为Unicode格式）",
			"全局指针（用于某些架构的全局变量访问）",
			"线程本地存储信息，用于线程私有数据",
			"加载配置信息（如安全cookie、SEH验证等）",
			"绑定导入表，预解析的导入函数地址以加速加载",
			"导入地址表，存储实际导入函数的内存地址",
			"延迟导入描述符，用于延迟加载DLL（运行时再加载）",
			"COM组件描述信息（如CLSID、接口信息等）",
			"保留未使用"
		};

		DisplayLine(180);
		printf("编号 \t 标准名称 \t\t 目录RVA \t 目录VA \t 目录FOA \t Size(十进制) \t Size(十六进制) \t 有效 \t 详细描述 \n");
		DisplayLine(180);

		for (int x = 0; x < Data_Size; x++)
		{
			// 获取当前目录项
			IMAGE_DATA_DIRECTORY dir = NtHeader->OptionalHeader.DataDirectory[x];
			DWORD rva = dir.VirtualAddress;
			DWORD size = dir.Size;
			DWORD foa = RVAtoFOA(rva);
			DWORD va = (rva != 0) ? (ImageBase + rva) : 0; // 计算虚拟地址(VA)
			bool is_valid = (rva != 0 && size != 0);       // 有效性判断（RVA和Size均非0）

			// 打印基础信息
			printf("%03d \t %-16s 0x%08X \t 0x%08X \t 0x%08X \t %010d \t 0x%08X \t\t %s \t ",
				x + 1,
				(x < 16) ? dirNames[x] : "Unknown",  // 标准名称
				rva,                                 // 目录RVA
				va,                                 // 目录VA（虚拟地址）
				foa,                                 // 目录FOA（文件偏移）
				size,                                // Size(十进制)
				size,                                // Size(十六进制)
				is_valid ? "√" : "×"                // 有效性标识
				);

			// 打印详细描述
			if (x < 16)
				printf("%s \n", dirDescriptions[x]);
			else
				printf("超出标准数据目录范围 \n");
		}
		DisplayLine(180);
	}

	// --------------------------------------------------
	// 遍历出该程序所加载的所有DLL动态库
	// --------------------------------------------------
	void ShowImportByDll()
	{
		IsOpenFile();
		int Count = 1;
		DWORD imageBase = NtHeader->OptionalHeader.ImageBase; // 基地址，用于计算VA
		DWORD importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
		auto ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(importDirRva) + GlobalFileBase);

		// 表格标题（新增INT/IAT地址、时间戳、转发链等字段）
		DisplayLine(140);
		printf("序号 \t DLL名称 \t\t INT RVA \t INT FOA \t INT VA \t IAT RVA \t IAT FOA \t IAT VA \t 时间戳(十六进制) \t 时间戳(UTC) \t ForwarderChain \t 名称RVA \t 名称FOA \n");
		DisplayLine(140);

		while (ImportTable->Name != 0) // 遍历所有导入描述符（以全0项结束）
		{
			// 基础信息
			CHAR* dllName = (CHAR*)(RVAtoFOA(ImportTable->Name) + GlobalFileBase);
			DWORD nameRva = ImportTable->Name;
			DWORD nameFoa = RVAtoFOA(nameRva);

			// INT（导入名称表）相关地址
			DWORD intRva = ImportTable->OriginalFirstThunk;
			DWORD intFoa = (intRva != 0) ? RVAtoFOA(intRva) : 0;
			DWORD intVa = (intRva != 0) ? (imageBase + intRva) : 0;

			// IAT（导入地址表）相关地址
			DWORD iatRva = ImportTable->FirstThunk;
			DWORD iatFoa = (iatRva != 0) ? RVAtoFOA(iatRva) : 0;
			DWORD iatVa = (iatRva != 0) ? (imageBase + iatRva) : 0;

			// 时间戳解析（转换为UTC时间字符串）
			DWORD timeStamp = ImportTable->TimeDateStamp;
			char timeStr[32] = "未绑定(0)";
			if (timeStamp != 0)
			{
				time_t t = (time_t)timeStamp;
				struct tm* utcTime = gmtime(&t);
				if (utcTime != nullptr)
				{
					strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", utcTime);
				}
				else
				{
					strcpy(timeStr, "无效时间戳");
				}
			}

			// 转发链解析（-1表示无转发）
			DWORD forwarderChain = ImportTable->ForwarderChain;
			const char* forwardStr = (forwarderChain == 0xFFFFFFFF) ? "无转发(-1)" : (forwarderChain == 0) ? "未设置(0)" : "有转发";

			// 打印完整信息（控制列宽确保对齐）
			printf("%-6d %-20s 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t\t %-19s %-16s 0x%08X \t 0x%08X \n",
				Count,
				dllName,               // DLL名称
				intRva,                // INT的RVA
				intFoa,                // INT的FOA
				intVa,                 // INT的VA（内存地址）
				iatRva,                // IAT的RVA
				iatFoa,                // IAT的FOA
				iatVa,                 // IAT的VA（内存地址）
				timeStamp,             // 时间戳（十六进制）
				timeStr,               // 时间戳（UTC字符串）
				forwardStr,            // ForwarderChain描述
				nameRva,               // 名称的RVA
				nameFoa                // 名称的FOA
				);

			Count++;
			ImportTable++;
		}
		DisplayLine(140);
	}

	// --------------------------------------------------
	// 传入一个导入DLL,输出该DLL中的导入函数
	// --------------------------------------------------
	void ShowImportByName(char* Dll)
	{
		IsOpenFile();
		DWORD imageBase = NtHeader->OptionalHeader.ImageBase; // 基地址，用于计算VA
		DWORD importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
		auto ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(importDirRva) + GlobalFileBase);

		DisplayLine(160);
		printf("序号 \t 导入类型 \t Hint值 \t INT RVA \t INT FOA \t INT VA \t IAT RVA \t IAT FOA \t IAT VA \t 函数名/序号 \t [当前模块: %s] \n", Dll);
		DisplayLine(160);

		int funcCount = 1;
		while (ImportTable->Name != 0)
		{
			CHAR* dllName = (CHAR*)(RVAtoFOA(ImportTable->Name) + GlobalFileBase);
			if (strcmp(dllName, Dll) != 0)
			{
				ImportTable++;
				continue;
			}

			// 获取INT和IAT的起始地址（修复指针类型转换）
			DWORD intRva = ImportTable->OriginalFirstThunk;
			DWORD iatRva = ImportTable->FirstThunk;

			// 修正:显式转换为LPVOID后再转为指针类型，解决nullptr转换问题
			PIMAGE_THUNK_DATA Int = nullptr;
			if (intRva != 0)
			{
				DWORD intFoa = RVAtoFOA(intRva);
				Int = (PIMAGE_THUNK_DATA)(LPVOID)(intFoa + GlobalFileBase);
			}

			PIMAGE_THUNK_DATA Iat = nullptr;
			if (iatRva != 0)
			{
				DWORD iatFoa = RVAtoFOA(iatRva);
				Iat = (PIMAGE_THUNK_DATA)(LPVOID)(iatFoa + GlobalFileBase);
			}

			// 遍历INT/IAT表项（修复空指针判断逻辑）
			while (Int != nullptr && Iat != nullptr    // 先判断指针非空
				&& Int->u1.Ordinal != 0
				&& Iat->u1.Ordinal != 0)
			{
				bool isOrdinal = (Int->u1.Ordinal & 0x80000000) != 0;
				const char* importType = isOrdinal ? "序号导入" : "名称导入";

				// 计算INT相关地址
				DWORD currentIntRva = intRva;
				DWORD intFoa = RVAtoFOA(currentIntRva);
				DWORD intVa = currentIntRva != 0 ? (imageBase + currentIntRva) : 0;

				// 计算IAT相关地址
				DWORD currentIatRva = iatRva;
				DWORD iatFoa = RVAtoFOA(currentIatRva);
				DWORD iatVa = currentIatRva != 0 ? (imageBase + currentIatRva) : 0;

				// 函数信息
				const char* funcInfo = "未知";
				WORD hint = 0;
				if (isOrdinal)
				{
					WORD ordinal = (WORD)(Int->u1.Ordinal & 0x7FFF);
					static char ordStr[32];
					sprintf(ordStr, "Ordinal: %d", ordinal);
					funcInfo = ordStr;
				}
				else
				{
					auto nameData = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(Int->u1.AddressOfData) + GlobalFileBase);
					if (nameData != nullptr)
					{
						hint = nameData->Hint;
						funcInfo = nameData->Name;
					}
				}

				// 打印信息
				printf("%-6d %-10s %-8hd 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t %-20s \n",
					funcCount++,
					importType,
					hint,
					currentIntRva,
					intFoa,
					intVa,
					currentIatRva,
					iatFoa,
					iatVa,
					funcInfo
					);

				// 移动到下一个表项
				Int++;
				Iat++;
				intRva += sizeof(IMAGE_THUNK_DATA);
				iatRva += sizeof(IMAGE_THUNK_DATA);
			}

			ImportTable++;
		}
		DisplayLine(160);
	}

	// --------------------------------------------------
	// 传入一个函数测试导入表中是否存在
	// --------------------------------------------------
	void ShowImportByFunction(char* Function, BOOL caseSensitive = FALSE, BOOL checkOrdinal = TRUE)
	{
		IsOpenFile();
		DWORD imageBase = NtHeader->OptionalHeader.ImageBase; // 模块基地址，用于计算VA
		DWORD importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
		auto ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(importDirRva) + GlobalFileBase);

		DisplayLine(160);
		printf("匹配序号 \t 导入类型 \t Hint值 \t INT RVA \t INT FOA \t INT VA \t IAT RVA \t IAT FOA \t IAT VA \t 所在DLL \n");
		DisplayLine(160);

		int matchCount = 1; // 匹配到的函数计数器
		DWORD funcOrdinal = 0;
		// 如果需要检查序号，尝试将Function转换为数字（序号）
		if (checkOrdinal)
		{
			char* endptr;
			funcOrdinal = strtoul(Function, &endptr, 10);
			if (*endptr != '\0')
			{
				funcOrdinal = 0; // 转换失败，不是有效序号
			}
		}

		while (ImportTable->Name != 0)
		{
			CHAR* dllName = (CHAR*)(RVAtoFOA(ImportTable->Name) + GlobalFileBase);
			DWORD intRva = ImportTable->OriginalFirstThunk;  // INT（导入名称表）RVA
			DWORD iatRva = ImportTable->FirstThunk;          // IAT（导入地址表）RVA

			// 修复:安全初始化指针，避免直接nullptr转换
			PIMAGE_THUNK_DATA Int = nullptr;
			if (intRva != 0)
			{
				DWORD intFoa = RVAtoFOA(intRva);
				Int = (PIMAGE_THUNK_DATA)(intFoa + GlobalFileBase);
			}

			PIMAGE_THUNK_DATA Iat = nullptr;
			if (iatRva != 0)
			{
				DWORD iatFoa = RVAtoFOA(iatRva);
				Iat = (PIMAGE_THUNK_DATA)(iatFoa + GlobalFileBase);
			}

			// 遍历INT和IAT表项（修复空指针判断逻辑）
			while (Int != nullptr && Iat != nullptr)
			{
				// 检查当前表项是否有效（避免访问空表项）
				if (Int->u1.Ordinal == 0 || Iat->u1.Ordinal == 0)
				{
					break;
				}

				BOOL isMatch = FALSE;
				const char* importType = "未知";
				WORD hint = 0;
				const char* funcInfo = "未知";

				// 检查是否为按序号导入（INT表项最高位为1）
				if (Int->u1.Ordinal & 0x80000000)
				{
					importType = "序号导入";
					WORD ordinal = (WORD)(Int->u1.Ordinal & 0x7FFF); // 提取低16位序号
					funcInfo = (char*)"[按序号导入]";
					// 如果需要检查序号且Function匹配当前序号
					if (checkOrdinal && funcOrdinal != 0 && ordinal == funcOrdinal)
					{
						isMatch = TRUE;
					}
				}
				// 按名称导入
				else
				{
					importType = "名称导入";
					auto nameData = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(Int->u1.AddressOfData) + GlobalFileBase);
					if (nameData != nullptr)
					{
						hint = nameData->Hint;
						funcInfo = nameData->Name;
						// 按名称匹配（区分/不区分大小写）
						if ((caseSensitive && strcmp(Function, nameData->Name) == 0) ||
							(!caseSensitive && _stricmp(Function, nameData->Name) == 0))
						{
							isMatch = TRUE;
						}
					}
				}

				// 匹配成功，展示详细信息
				if (isMatch)
				{
					// 计算INT相关地址
					DWORD currentIntRva = intRva;
					DWORD intFoa = RVAtoFOA(currentIntRva);
					DWORD intVa = currentIntRva + imageBase;

					// 计算IAT相关地址
					DWORD currentIatRva = iatRva;
					DWORD iatFoa = RVAtoFOA(currentIatRva);
					DWORD iatVa = currentIatRva + imageBase;

					printf("[%6d] \t %-10s %-8hd 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t %-20s \n",
						matchCount++,
						importType,
						hint,
						currentIntRva,   // INT的RVA
						intFoa,          // INT的FOA
						intVa,           // INT的VA（内存地址）
						currentIatRva,   // IAT的RVA
						iatFoa,          // IAT的FOA
						iatVa,           // IAT的VA（内存地址）
						dllName          // 所在DLL
						);
				}

				// 移动到下一个表项
				Int++;
				Iat++;
				intRva += sizeof(IMAGE_THUNK_DATA);
				iatRva += sizeof(IMAGE_THUNK_DATA);
			}

			ImportTable++;
		}

		if (matchCount == 1)
		{
			printf("未找到匹配的导入函数: %s\n", Function);
		}
		DisplayLine(160);
	}

	// --------------------------------------------------
	// 遍历出所有的导入函数和模块信息
	// --------------------------------------------------
	void ShowImportAll()
	{
		IsOpenFile();
		// 获取导入表在数据目录中的RVA
		DWORD importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
		if (importDirRva == 0)
		{
			printf("[-] 未找到导入表数据\n");
			return;
		}

		// 转换导入表地址（FOA -> 文件映射基地址）
		auto importTableBase = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(importDirRva) + GlobalFileBase);
		DWORD imageBase = NtHeader->OptionalHeader.ImageBase;  // 模块加载基地址
		int dllIndex = 1;  // DLL计数器

		DisplayLine(200);
		printf("导入表全局信息\n");
		printf("导入表数据目录RVA: 0x%08X, FOA: 0x%08X\n", importDirRva, RVAtoFOA(importDirRva));
		printf("模块加载基地址: 0x%08X\n", imageBase);
		DisplayLine(200);

		// 遍历所有导入模块（以全0结构结束）
		auto ImportTable = importTableBase;
		while (ImportTable->Name != 0)
		{
			// 获取当前DLL信息
			CHAR* dllName = (CHAR*)(RVAtoFOA(ImportTable->Name) + GlobalFileBase);
			DWORD intRva = ImportTable->OriginalFirstThunk;  // INT（导入名称表）RVA
			DWORD iatRva = ImportTable->FirstThunk;          // IAT（导入地址表）RVA
			DWORD descRva = (DWORD)((BYTE*)ImportTable - (BYTE*)GlobalFileBase) + FOAtoRVA((DWORD)((BYTE*)ImportTable - (BYTE*)GlobalFileBase) - GlobalFileBase); // 导入描述符自身RVA
			DWORD descFoa = RVAtoFOA(descRva);               // 导入描述符自身FOA

			// 初始化INT和IAT指针（处理空表情况）
			PIMAGE_THUNK_DATA Int = nullptr;
			if (intRva != 0)
			{
				Int = (PIMAGE_THUNK_DATA)(RVAtoFOA(intRva) + GlobalFileBase);
			}
			PIMAGE_THUNK_DATA Iat = nullptr;
			if (iatRva != 0)
			{
				Iat = (PIMAGE_THUNK_DATA)(RVAtoFOA(iatRva) + GlobalFileBase);
			}

			// 输出当前DLL标题及导入描述符信息
			DisplayLine(200);
			printf("[*] 导入模块 [%d]:%s\n", dllIndex++, dllName);
			printf("  导入描述符信息:\n");
			printf("  - 描述符RVA: 0x%08X, FOA: 0x%08X\n", descRva, descFoa);
			printf("  - TimeDateStamp: 0x%08X（%s）\n",
				ImportTable->TimeDateStamp,
				ImportTable->TimeDateStamp == 0 ? "未绑定" : "已绑定");
			printf("  - ForwarderChain: 0x%08X（%s）\n",
				ImportTable->ForwarderChain,
				ImportTable->ForwarderChain == (DWORD)-1 ? "无转发" : "存在转发");
			printf("  - INT（导入名称表）RVA: 0x%08X, FOA: 0x%08X\n", intRva, RVAtoFOA(intRva));
			printf("  - IAT（导入地址表）RVA: 0x%08X, FOA: 0x%08X\n", iatRva, RVAtoFOA(iatRva));
			DisplayLine(200);

			// 表头:新增INT/IAT原始数据、转发状态等
			printf("函数序号 \t 导入类型 \t Hint值 \t INT原始数据 \t IAT原始数据 \t INT VA \t IAT VA \t 函数名称/序号 \t 状态 \n");
			DisplayLine(200);

			// 遍历当前DLL的所有导入函数
			int funcIndex = 1;
			while ((Int != nullptr || Iat != nullptr) &&
				(Int == nullptr || Int->u1.Ordinal != 0) &&
				(Iat == nullptr || Iat->u1.Ordinal != 0))
			{
				const char* importType = "未知";
				const char* status = "正常";
				WORD hint = 0;
				const char* funcInfo = "未知";
				DWORD intRawData = 0;  // INT表项原始数据
				DWORD iatRawData = 0;  // IAT表项原始数据
				DWORD intVa = 0;       // INT表项内存地址
				DWORD iatVa = 0;       // IAT表项内存地址

				// 处理INT表项（可能为空）
				if (Int != nullptr)
				{
					intRawData = Int->u1.Ordinal;
					intVa = intRva + imageBase;  // INT表项的VA = INT的RVA + 基地址
				}
				// 处理IAT表项（可能为空）
				if (Iat != nullptr)
				{
					iatRawData = Iat->u1.Ordinal;
					iatVa = iatRva + imageBase;  // IAT表项的VA = IAT的RVA + 基地址
				}

				// 判断导入类型（优先用INT，INT为空则用IAT）
				PIMAGE_THUNK_DATA thunk = (Int != nullptr) ? Int : Iat;
				if (thunk != nullptr)
				{
					if (thunk->u1.Ordinal & 0x80000000)
					{
						// 序号导入（最高位为1）
						importType = "序号导入";
						WORD ordinal = (WORD)(thunk->u1.Ordinal & 0x7FFF);
						funcInfo = (char*)std::to_string(ordinal).c_str();
					}
					else
					{
						// 名称导入（最高位为0）
						importType = "名称导入";
						auto nameData = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(thunk->u1.AddressOfData) + GlobalFileBase);
						if (nameData != nullptr)
						{
							hint = nameData->Hint;
							funcInfo = nameData->Name;
						}
					}
				}

				// 判断状态（INT缺失、转发等）
				if (intRva == 0)
				{
					status = "INT缺失（IAT兼作INT）";
				}
				else if (ImportTable->ForwarderChain != (DWORD)-1)
				{
					status = "存在函数转发";
				}

				// 输出当前函数详细信息
				printf("[%6d] \t %-10s %-8hd 0x%08X \t 0x%08X \t 0x%08X \t 0x%08X \t %-20s \t %s \n",
					funcIndex++,
					importType,
					hint,
					intRawData,   // INT表项原始数据（十六进制）
					iatRawData,   // IAT表项原始数据（十六进制）
					intVa,        // INT表项在内存中的地址
					iatVa,        // IAT表项在内存中的地址
					funcInfo,
					status
					);

				// 移动到下一个表项
				if (Int != nullptr) Int++;
				if (Iat != nullptr) Iat++;
				if (intRva != 0) intRva += sizeof(IMAGE_THUNK_DATA);  // 累加INT表项大小（4字节）
				if (iatRva != 0) iatRva += sizeof(IMAGE_THUNK_DATA);  // 累加IAT表项大小（4字节）
			}

			// 处理空函数表情况
			if (funcIndex == 1)
			{
				printf("[-] 该模块无有效导入函数\n");
			}

			ImportTable++;  // 下一个导入模块
		}

		if (dllIndex == 1)
		{
			printf("[-] 未找到任何导入模块\n");
		}
		DisplayLine(200);
	}

	// --------------------------------------------------
	// 显示所有导出表数据
	// --------------------------------------------------
	void ShowExport()
	{
		IsOpenFile();
		// 0. 获取镜像基地址
		DWORD ImageBase = NtHeader->OptionalHeader.ImageBase;

		// 1. 获取导出表在数据目录中的RVA
		DWORD exportDirRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
		if (exportDirRva == 0)
		{
			printf("[-] 未找到导出表数据\n");
			return;
		}

		// 2. 计算导出表的FOA和文件中地址
		DWORD exportDirFoa = RVAtoFOA(exportDirRva);
		auto ExportTable = (PIMAGE_EXPORT_DIRECTORY)(exportDirFoa + GlobalFileBase);

		// 3. 获取导出表关键信息
		DWORD NameCount = ExportTable->NumberOfNames;
		DWORD FunctionCount = ExportTable->NumberOfFunctions;
		DWORD Base = ExportTable->Base;  // 起始序号
		CHAR* moduleName = (CHAR*)(RVAtoFOA(ExportTable->Name) + GlobalFileBase);  // 模块名

		// 4. 转换时间戳为本地时间（FILETIME->SYSTEMTIME）
		FILETIME ft;
		SYSTEMTIME stLocal;
		ft.dwLowDateTime = ExportTable->TimeDateStamp;
		ft.dwHighDateTime = 0;  // 时间戳为32位，高32位补0
		FileTimeToLocalFileTime(&ft, &ft);
		FileTimeToSystemTime(&ft, &stLocal);

		// 5. 获取三张核心表（地址表、名称表、序号表）
		DWORD* Addr_Table = (DWORD*)(RVAtoFOA(ExportTable->AddressOfFunctions) + GlobalFileBase);
		DWORD* Name_Table = (DWORD*)(RVAtoFOA(ExportTable->AddressOfNames) + GlobalFileBase);
		WORD* Id_Table = (WORD*)(RVAtoFOA(ExportTable->AddressOfNameOrdinals) + GlobalFileBase);

		// ---------------------- 输出导出表全局信息 ----------------------
		DisplayLine(120);
		printf("导出表全局信息\n");
		printf("导出表数据目录RVA: 0x%08X, FOA: 0x%08X\n", exportDirRva, exportDirFoa);
		printf("特征值(Characteristics): 0x%08X\n", ExportTable->Characteristics);
		printf("时间戳(TimeDateStamp): 0x%08X -> %04d-%02d-%02d %02d:%02d:%02d\n",
			ExportTable->TimeDateStamp,
			stLocal.wYear, stLocal.wMonth, stLocal.wDay,
			stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
		printf("版本号: %d.%d\n", ExportTable->MajorVersion, ExportTable->MinorVersion);
		printf("模块名: %s\n", moduleName);
		printf("起始序号(Base): 0x%04X\n", Base);
		printf("函数总数(NumberOfFunctions): %d\n", FunctionCount);
		printf("命名函数数(NumberOfNames): %d\n", NameCount);
		DisplayLine(120);

		// ---------------------- 输出函数列表表头 ----------------------
		printf("导出序号 \t 函数RVA \t 函数VA \t 函数FOA \t 所在节 \t 函数名称 \t 状态 \t 转发目标\n");
		DisplayLine(120);

		// 6. 遍历所有导出函数（地址表）
		for (DWORD i = 0; i < FunctionCount; ++i)
		{
			DWORD funcRva = Addr_Table[i];
			DWORD funcFoa = RVAtoFOA(funcRva);
			DWORD funcVa = ImageBase + funcRva;
			bool HaveName = FALSE;
			const char* funcName = "None";
			const char* sectionName = "未知";
			const char* status = "正常";
			const char* forwardTarget = "无";

			// 6.1 查找函数名称（通过序号表关联名称表）
			for (DWORD j = 0; j < NameCount; ++j)
			{
				if (i == Id_Table[j])
				{
					HaveName = TRUE;
					funcName = (CHAR*)(RVAtoFOA(Name_Table[j]) + GlobalFileBase);
					break;
				}
			}

			// 6.2 确定函数所在的节
			auto sections = IMAGE_FIRST_SECTION(NtHeader);
			for (WORD s = 0; s < NtHeader->FileHeader.NumberOfSections; ++s)
			{
				DWORD secStartRva = sections[s].VirtualAddress;
				DWORD secEndRva = secStartRva + sections[s].Misc.VirtualSize;
				if (funcRva >= secStartRva && funcRva < secEndRva)
				{
					sectionName = (char*)sections[s].Name;
					break;
				}
			}

			// 6.3 判断是否为转发函数（地址指向导出表所在节的字符串）
			if (funcRva != 0)  // 排除无效地址
			{
				// 转发函数的RVA通常落在导出表所在的节中，且指向以0结尾的字符串
				BYTE* possibleForwardStr = (BYTE*)(funcFoa + GlobalFileBase);
				if (possibleForwardStr != nullptr)
				{
					// 简单判断:字符串是否包含"!"（格式通常为"DLLName!FunctionName"）
					bool isForward = false;
					for (int c = 0; c < 256; ++c)  // 限制最大长度，避免越界
					{
						if (possibleForwardStr[c] == '\0') break;
						if (possibleForwardStr[c] == '!')
						{
							isForward = true;
							break;
						}
					}
					if (isForward)
					{
						status = "转发函数";
						forwardTarget = (char*)possibleForwardStr;
					}
				}
			}
			else
			{
				status = "无效地址";  // 函数地址为0，标记为无效
			}

			// 6.4 输出当前函数信息
			printf("%8d \t 0x%08X \t 0x%08X \t 0x%08X \t %-8s \t %-20s \t %-6s \t %s\n",
				i + Base,         // 导出序号（Base + 索引）
				funcRva,          // 函数RVA
				funcVa,           // 函数VA（内存地址）
				funcFoa,          // 函数FOA（文件偏移）
				sectionName,      // 所在节名称
				funcName,         // 函数名称（无名称则为None）
				status,           // 状态（正常/转发/无效）
				forwardTarget     // 转发目标（仅转发函数有效）
				);
		}

		DisplayLine(120);
	}

	// --------------------------------------------------
	// 输出重定位表的所有分页情况
	// --------------------------------------------------
	void ShowFixRelocPage()
	{
		IsOpenFile();

		// 1. 获取基础信息
		DWORD base = NtHeader->OptionalHeader.ImageBase;                   // 原始映像基地址
		PIMAGE_DATA_DIRECTORY relocDir = &NtHeader->OptionalHeader.DataDirectory[5];  // 重定位表数据目录
		DWORD RelocRVA = relocDir->VirtualAddress;                         // 重定位表RVA
		DWORD RelocSize = relocDir->Size;                                  // 重定位表大小

		// 检查重定位表是否存在
		if (RelocRVA == 0 || RelocSize == 0)
		{
			printf("[-] 未找到有效重定位表\n");
			return;
		}

		// 2. 计算重定位表的FOA和文件中地址
		DWORD RelocFOA = RVAtoFOA(RelocRVA);
		auto Reloc = (PIMAGE_BASE_RELOCATION)(GlobalFileBase + RelocFOA);

		// 模拟新基地址（用于计算重定位后地址，实际中由加载器决定）
		DWORD newBase = base + 0x10000;  // 示例:原基地址+0x10000

		// ---------------------- 输出重定位表全局信息 ----------------------
		DisplayLine(120);
		printf("重定位表全局信息\n");
		printf("原始映像基地址: 0x%08X\n", base);
		printf("模拟新基地址(示例): 0x%08X\n", newBase);
		printf("重定位表数据目录RVA: 0x%08X, FOA: 0x%08X\n", RelocRVA, RelocFOA);
		printf("重定位表总大小: 0x%08X 字节\n", RelocSize);
		DisplayLine(120);

		// ---------------------- 输出重定位块表头 ----------------------
		printf("块序号 \t 块起始RVA \t 块FOA \t 块内存起始VA \t 块长度 \t 重定位项数 \n");
		DisplayLine(120);

		DWORD blockIndex = 0;  // 重定位块序号

		// 3. 遍历所有重定位块（以SizeOfBlock=0结束）
		while (Reloc->SizeOfBlock != 0)
		{
			blockIndex++;

			// 计算当前块的FOA（文件偏移）
			DWORD blockFOA = (DWORD)Reloc - GlobalFileBase;

			// 计算块的内存起始VA（VirtualAddress是RVA，需加原始基地址）
			DWORD blockVA = base + Reloc->VirtualAddress;

			// 计算重定位项个数（块大小减去块头大小，再除以每个项的大小2字节）
			DWORD entryCount = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;

			// 输出当前块的基本信息
			printf("%d \t 0x%08X \t 0x%08X \t 0x%08X \t 0x%04X \t %d \n",
				blockIndex,
				Reloc->VirtualAddress,
				blockFOA,
				blockVA,
				Reloc->SizeOfBlock,
				entryCount);

			// 4. 解析当前块中的所有重定位项
			if (entryCount > 0)
			{
				// 重定位项起始地址（块头后面的第一个项）
				auto relocEntries = (TypeOffset*)(Reloc + 1);

				// 输出重定位项表头
				printf("  ├─ 项序号 \t 类型 \t 类型描述 \t 项偏移 \t 完整RVA \t 原始地址 \t 重定位后地址 \n");

				for (DWORD i = 0; i < entryCount; i++)
				{
					// 重定位项类型（高4位）和偏移（低12位）
					WORD type = relocEntries[i].Type;
					WORD offset = relocEntries[i].Offset;

					// 计算完整RVA（块起始RVA + 项偏移）
					DWORD entryRVA = Reloc->VirtualAddress + offset;

					// 计算项的FOA和文件中地址
					DWORD entryFOA = RVAtoFOA(entryRVA);
					DWORD* entryAddrInFile = (DWORD*)(GlobalFileBase + entryFOA);  // 文件中存储的原始地址

					// 计算重定位后地址:原始地址 - 原基地址 + 新基地址
					DWORD relocatedAddr = (*entryAddrInFile) - base + newBase;

					// 转换类型为可读字符串
					const char* typeDesc = "未知";
					switch (type)
					{
					case IMAGE_REL_BASED_ABSOLUTE:    typeDesc = "ABSOLUTE（无意义）"; break;
					case IMAGE_REL_BASED_HIGH:        typeDesc = "HIGH（高16位）"; break;
					case IMAGE_REL_BASED_LOW:         typeDesc = "LOW（低16位）"; break;
					case IMAGE_REL_BASED_HIGHLOW:     typeDesc = "HIGHLOW（32位完整地址）"; break;
					case IMAGE_REL_BASED_REL32:       typeDesc = "REL32（相对32位）"; break;
						// 可根据需要补充其他类型（如IMAGE_REL_BASED_DIR64等）
					}

					// 输出当前重定位项信息
					printf("  ├─ %d \t %d \t %-15s \t 0x%04X \t 0x%08X \t 0x%08X \t 0x%08X \n",
						i + 1,
						type,
						typeDesc,
						offset,
						entryRVA,
						*entryAddrInFile,
						relocatedAddr);
				}
				printf("  └─ （块结束）\n");
			}

			// 移动到下一个重定位块
			Reloc = (PIMAGE_BASE_RELOCATION)((DWORD)Reloc + Reloc->SizeOfBlock);
		}

		DisplayLine(120);
		printf("重定位表遍历完成，共%d个重定位块\n", blockIndex);
		DisplayLine(120);
	}

	// --------------------------------------------------
	// 遍历全部重定位表数据/或指定RVA参数遍历指定选项
	// --------------------------------------------------

	void ShowFixReloc(char GetRva[])
	{
		IsOpenFile();
		DWORD oldBase = NtHeader->OptionalHeader.ImageBase;  // 原始映像基地址
		DWORD newBase = oldBase + 0x10000;                   // 模拟新基地址（示例:原基地址+0x10000）

		// 1. 获取重定位表基础信息
		PIMAGE_DATA_DIRECTORY relocDir = &NtHeader->OptionalHeader.DataDirectory[5];
		DWORD RelocRVA = relocDir->VirtualAddress;
		DWORD RelocSize = relocDir->Size;

		// 检查重定位表是否存在
		if (RelocRVA == 0 || RelocSize == 0)
		{
			printf("[-] 未找到有效重定位表（数据目录为空）\n");
			return;
		}

		// 计算重定位表FOA及文件中地址
		DWORD RelocFOA = RVAtoFOA(RelocRVA);
		auto Reloc = (PIMAGE_BASE_RELOCATION)(GlobalFileBase + RelocFOA);

		// 2. 输出重定位表全局信息
		DisplayLine(120);
		printf("重定位表全局信息\n");
		printf("原始映像基地址: 0x%08X\n", oldBase);
		printf("模拟新基地址(示例): 0x%08X\n", newBase);
		printf("重定位表RVA: 0x%08X, FOA: 0x%08X, 总大小: 0x%08X 字节\n", RelocRVA, RelocFOA, RelocSize);
		DisplayLine(120);

		// 3. 输出表头（区分块和项的层次）
		printf("块序号 | 块起始RVA  | 块FOA     | 块VA      | 块大小  | 项数量 | 项序号 | 类型 | 类型描述       | 项偏移 | 项RVA    | 项FOA    | 原始VA   | 重定位后VA \n");
		DisplayLine(120);

		DWORD blockIndex = 0;  // 重定位块序号

		// 4. 遍历所有重定位块（以SizeOfBlock=0结束）
		while (Reloc->SizeOfBlock != 0)
		{
			blockIndex++;

			// 计算当前块的基础信息
			DWORD blockFOA = (DWORD)Reloc - GlobalFileBase;  // 块在文件中的偏移
			DWORD blockVA = oldBase + Reloc->VirtualAddress;  // 块的内存起始VA
			DWORD entryCount = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;  // 项数量

			// 5. 遍历当前块中的所有重定位项
			auto Offset = (TypeOffset*)(Reloc + 1);  // 重定位项起始地址
			for (DWORD i = 0; i < entryCount; ++i)
			{
				// 解析重定位项类型和偏移
				DWORD type = Offset[i].Type;
				DWORD offset = Offset[i].Offset;

				// 计算项的完整RVA、FOA和文件中地址
				DWORD entryRVA = Reloc->VirtualAddress + offset;
				DWORD entryFOA = RVAtoFOA(entryRVA);
				DWORD* entryFileAddr = (DWORD*)(GlobalFileBase + entryFOA);  // 文件中存储的原始地址

				// 计算重定位相关地址
				DWORD originalVA = *entryFileAddr;                // 原始VA（文件中存储的地址）
				DWORD relocatedVA = originalVA - oldBase + newBase;  // 重定位后VA（基于新基地址）

				// 转换类型为可读描述
				const char* typeDesc = "未知";
				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:    typeDesc = "ABSOLUTE（填充）"; break;
				case IMAGE_REL_BASED_HIGH:        typeDesc = "HIGH（高16位）"; break;
				case IMAGE_REL_BASED_LOW:         typeDesc = "LOW（低16位）"; break;
				case IMAGE_REL_BASED_HIGHLOW:     typeDesc = "HIGHLOW（32位完整）"; break;
				case IMAGE_REL_BASED_REL32:       typeDesc = "REL32（32位相对）"; break;
				case IMAGE_REL_BASED_DIR64:       typeDesc = "DIR64（64位）"; break;
				}

				// 根据输入参数过滤输出（指定RVA或"all"）
				bool needPrint = false;
				if (strcmp(GetRva, "all") == 0)
				{
					needPrint = true;  // 输出所有项
				}
				else
				{
					DWORD targetRVA = HexStringToDec(GetRva);
					if (Reloc->VirtualAddress == targetRVA)
					{
						needPrint = true;  // 输出指定块的项
					}
				}

				// 输出项信息（块信息仅在同块的第一项打印，后续项留空）
				if (needPrint)
				{
					printf(
						"%-6d | 0x%08X | 0x%08X | 0x%08X | 0x%04X | %-6d | %-6d | %-4d | %-14s | 0x%04X | 0x%08X | 0x%08X | 0x%08X | 0x%08X \n",
						(i == 0) ? blockIndex : 0,          // 块序号（同块仅首项显示）
						(i == 0) ? Reloc->VirtualAddress : 0, // 块起始RVA（同块仅首项显示）
						(i == 0) ? blockFOA : 0,             // 块FOA（同块仅首项显示）
						(i == 0) ? blockVA : 0,              // 块VA（同块仅首项显示）
						(i == 0) ? Reloc->SizeOfBlock : 0,   // 块大小（同块仅首项显示）
						(i == 0) ? entryCount : 0,           // 项数量（同块仅首项显示）
						i + 1,                               // 项在块内的序号
						type,                                // 类型
						typeDesc,                            // 类型描述
						offset,                              // 项偏移（相对于块起始RVA）
						entryRVA,                            // 项完整RVA
						entryFOA,                            // 项FOA
						originalVA,                          // 原始VA（文件中存储的值）
						relocatedVA                          // 重定位后VA（基于新基地址）
						);
				}
			}

			// 移动到下一个重定位块
			Reloc = (PIMAGE_BASE_RELOCATION)((DWORD)Reloc + Reloc->SizeOfBlock);
		}

		// 输出统计信息
		DisplayLine(120);
		printf("重定位表遍历完成，共%d个有效重定位块\n", blockIndex);
		DisplayLine(120);
	}

	// --------------------------------------------------
	// 递归解析资源目录（处理三级目录结构）
	// --------------------------------------------------
	void ParseResourceDirectory(
		PIMAGE_RESOURCE_DIRECTORY pResDir,
		DWORD resBaseFOA,  // 资源表在文件中的基地址FOA
		int level,         // 目录级别:1=类型级，2=名称/ID级，3=语言级
		const char* parentInfo  // 父目录信息（用于打印层次）
		)
	{
		if (pResDir == nullptr) return;

		// 计算当前目录的RVA和FOA
		DWORD dirFOA = (DWORD)pResDir - GlobalFileBase;  // 目录在文件中的偏移
		DWORD dirRVA = FOAtoRVA(dirFOA);                 // 目录的RVA

		// 输出当前目录的基本信息（按级别区分）
		const char* levelName[] = { "", "类型目录", "名称/ID目录", "语言目录" };
		printf("\n%s[ %s ] 信息:\n", parentInfo, levelName[level]);
		printf("%s- 目录RVA: 0x%08X, FOA: 0x%08X\n", parentInfo, dirRVA, dirFOA);
		printf("%s- 命名条目数: %d, ID条目数: %d, 总条目数: %d\n",
			parentInfo,
			pResDir->NumberOfNamedEntries,
			pResDir->NumberOfIdEntries,
			pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries);

		// 获取目录条目数组
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDir + 1);
		DWORD entryCount = pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries;

		// 遍历所有条目
		for (DWORD i = 0; i < entryCount; ++i)
		{
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry = &pEntries[i];
			char entryInfo[256] = { 0 };
			char childParentInfo[256] = { 0 };
			sprintf(childParentInfo, "%s  |- ", parentInfo);  // 子目录前缀（层次缩进）

			// 1. 解析条目名称（命名条目/ID条目）
			if (pEntry->NameIsString)
			{
				// 命名条目:解析字符串名称（宽字符串）
				PIMAGE_RESOURCE_DIR_STRING_U pStr = (PIMAGE_RESOURCE_DIR_STRING_U)(resBaseFOA + pEntry->NameOffset + GlobalFileBase);
				WCHAR wName[MAX_PATH] = { 0 };
				memcpy_s(wName, sizeof(wName), pStr->NameString, pStr->Length * sizeof(WCHAR));
				char aName[MAX_PATH] = { 0 };
				WideCharToMultiByte(CP_ACP, 0, wName, -1, aName, sizeof(aName), NULL, NULL);
				sprintf(entryInfo, "命名条目 (名称: %s)", aName);
			}
			else
			{
				// ID条目:根据级别解析ID含义
				if (level == 1)
				{
					// 类型级ID:使用预设的资源类型名称
					const char* typeName = (pEntry->Id < 0x11) ? szResName[pEntry->Id] : "未知类型";
					sprintf(entryInfo, "ID条目 (类型ID: 0x%04X, 类型: %s)", pEntry->Id, typeName);
				}
				else if (level == 2)
				{
					// 名称/ID级ID:直接显示ID
					sprintf(entryInfo, "ID条目 (资源ID: 0x%04X)", pEntry->Id);
				}
				else if (level == 3)
				{
					// 语言级ID:解析语言代码（参考Windows语言ID定义）
					sprintf(entryInfo, "ID条目 (语言ID: 0x%04X)", pEntry->Id);
				}
			}

			// 2. 输出当前条目的基本信息
			printf("\n%s[条目 %d] %s:\n", childParentInfo, i + 1, entryInfo);
			printf("%s- 条目偏移: 0x%08X (相对资源基地址)\n", childParentInfo, pEntry->OffsetToDirectory);

			// 3. 判断条目是目录还是数据
			if (pEntry->DataIsDirectory)
			{
				// 目录条目:递归解析下一级目录
				PIMAGE_RESOURCE_DIRECTORY pChildDir = (PIMAGE_RESOURCE_DIRECTORY)(resBaseFOA + pEntry->OffsetToDirectory + GlobalFileBase);
				printf("%s- 条目类型: 目录 (指向%s)\n", childParentInfo, levelName[level + 1]);
				ParseResourceDirectory(pChildDir, resBaseFOA, level + 1, childParentInfo);
			}
			else
			{
				// 数据条目:解析资源数据信息（仅第三级目录有数据条目）
				if (level != 3)
				{
					printf("%s- 警告: 非语言级目录出现数据条目（不符合PE规范）\n", childParentInfo);
					continue;
				}

				// 解析资源数据项
				PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(resBaseFOA + pEntry->OffsetToData + GlobalFileBase);
				DWORD dataRVA = pDataEntry->OffsetToData;
				DWORD dataFOA = RVAtoFOA(dataRVA);
				DWORD dataSize = pDataEntry->Size;
				DWORD codePage = pDataEntry->CodePage;

				printf("%s- 条目类型: 资源数据\n", childParentInfo);
				printf("%s- 数据RVA: 0x%08X, FOA: 0x%08X\n", childParentInfo, dataRVA, dataFOA);
				printf("%s- 数据大小: %d 字节 (0x%08X)\n", childParentInfo, dataSize, dataSize);
				printf("%s- 代码页: 0x%04X (用于本地化编码)\n", childParentInfo, codePage);
			}
		}
	}

	// 显示资源表完整信息
	void ShowResource()
	{
		IsOpenFile();

		// 1. 获取资源目录表数据目录信息
		PIMAGE_DATA_DIRECTORY pResDirEntry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		if (pResDirEntry->VirtualAddress == 0 || pResDirEntry->Size == 0)
		{
			printf("[-] 无有效资源表（数据目录为空）\n");
			return;
		}

		// 2. 计算资源表基础地址
		DWORD resRVA = pResDirEntry->VirtualAddress;
		DWORD resFOA = RVAtoFOA(resRVA);
		DWORD resSize = pResDirEntry->Size;
		PIMAGE_RESOURCE_DIRECTORY pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)(GlobalFileBase + resFOA);

		// 3. 输出资源表全局信息
		DisplayLine(120);
		printf("资源表全局信息\n");
		printf("资源表数据目录RVA: 0x%08X, FOA: 0x%08X\n", resRVA, resFOA);
		printf("资源表总大小: %d 字节 (0x%08X)\n", resSize, resSize);
		printf("资源表在文件中的基地址: 0x%08X (GlobalFileBase + FOA)\n", (DWORD)pRootResDir);
		DisplayLine(120);

		// 4. 递归解析三级资源目录（类型级->名称/ID级->语言级）
		ParseResourceDirectory(pRootResDir, resFOA, 1, "");

		DisplayLine(120);
		printf("资源表解析完成\n");
		DisplayLine(120);
	}

	// --------------------------------------------------
	// 将 VA(虚拟地址) --> 转换为 FOA(文件偏移)
	// 增强版:完善逻辑校验与信息输出
	// --------------------------------------------------
	void VA_To_FOA(DWORD dwVA)
	{
		IsOpenFile(); // 确保文件已打开

		// 基本参数校验:VA不能小于ImageBase（无效虚拟地址）
		DWORD dwImageBase = NtHeader->OptionalHeader.ImageBase;
		if (dwVA < dwImageBase)
		{
			DisplayLine(80);
			printf("[-] 无效的VA地址:0x%08X（小于基地址0x%08X）\n", dwVA, dwImageBase);
			DisplayLine(80);
			return;
		}

		DWORD NumberOfSectionsCount = NtHeader->FileHeader.NumberOfSections; // 修正变量名拼写错误
		bool bFound = false; // 标记是否找到对应节区

		DisplayLine(80);
		printf("[*] VA转FOA转换开始:\n");
		printf("[*] 目标VA地址:0x%08X\n", dwVA);
		printf("[*] 模块基地址（ImageBase）:0x%08X\n", dwImageBase);
		printf("[*] 节区总数:%d\n", NumberOfSectionsCount);
		DisplayLine(80);

		// 遍历所有节区查找VA所属范围
		for (DWORD i = 0; i < NumberOfSectionsCount; i++)
		{
			PIMAGE_SECTION_HEADER pCurSection = &pSection[i];

			// 计算当前节区的虚拟地址范围（内存中）
			DWORD dwSectionVAStart = dwImageBase + pCurSection->VirtualAddress; // 节区VA起始
			// 节区VA结束:使用VirtualSize（内存中实际大小），左闭右开
			DWORD dwSectionVAEnd = dwSectionVAStart + pCurSection->Misc.VirtualSize;

			// 打印当前节区信息（辅助定位）
			printf("[节区 %d] 名称:%s | VA范围:0x%08X - 0x%08X | 节区RVA起始:0x%08X | 内存大小:0x%08X\n",
				i + 1,
				pCurSection->Name,
				dwSectionVAStart,
				dwSectionVAEnd - 1, // 显示有效结束地址（闭区间）
				pCurSection->VirtualAddress,
				pCurSection->Misc.VirtualSize);

			// 检查VA是否在当前节区的虚拟地址范围内（左闭右开）
			if (dwVA >= dwSectionVAStart && dwVA < dwSectionVAEnd)
			{
				bFound = true;

				// 计算转换结果
				DWORD dwRVA = dwVA - dwImageBase; // RVA = VA - 基地址
				DWORD dwFOA = pCurSection->PointerToRawData + (dwRVA - pCurSection->VirtualAddress); // FOA = 节区文件偏移 + (RVA - 节区RVA起始)

				// 输出详细转换信息
				DisplayLine(80);
				printf("[+] 找到VA所属节区:\n");
				printf("    节区名称:%s\n", pCurSection->Name);
				printf("    节区VA范围:0x%08X - 0x%08X（有效范围）\n", dwSectionVAStart, dwSectionVAEnd - 1);
				printf("    节区RVA起始:0x%08X | 节区文件偏移:0x%08X | 内存大小:0x%08X\n",
					pCurSection->VirtualAddress,
					pCurSection->PointerToRawData,
					pCurSection->Misc.VirtualSize);
				DisplayLine(60);
				printf("    转换过程:\n");
				printf("    RVA = VA - 基地址\n");
				printf("    RVA = 0x%08X - 0x%08X = 0x%08X\n", dwVA, dwImageBase, dwRVA);
				printf("    FOA = 节区文件偏移 + (RVA - 节区RVA起始)\n");
				printf("    FOA = 0x%08X + (0x%08X - 0x%08X) = 0x%08X\n",
					pCurSection->PointerToRawData,
					dwRVA,
					pCurSection->VirtualAddress,
					dwFOA);
				DisplayLine(60);
				printf("    最终结果:\n");
				printf("    VA:0x%08X --> RVA:0x%08X --> FOA:0x%08X\n", dwVA, dwRVA, dwFOA);
				DisplayLine(80);
				break; // 找到后退出循环
			}
		}

		// 未找到对应节区的处理
		if (!bFound)
		{
			DisplayLine(80);
			printf("[-] 转换失败:VA 0x%08X 不在任何节区的虚拟地址范围内\n", dwVA);
			printf("[-] 可能原因:VA属于未分配的内存区域或超出模块镜像大小（0x%08X）\n", NtHeader->OptionalHeader.SizeOfImage);
			DisplayLine(80);
		}
	}

	// --------------------------------------------------
	// 将 RVA(虚拟地址) --> 转换为 FOA(文件偏移)
	// 将 RVA(相对虚拟地址) 转换为 FOA(文件偏移地址)
	// 增强版:完善错误处理、输出详细节区信息及转换过程
	void RVA_To_FOA(DWORD dwRVA)
	{
		IsOpenFile(); // 确保文件已打开

		// 基本参数校验
		if (dwRVA == 0)
		{
			DisplayLine(80);
			printf("[-] 无效的RVA地址:0x00000000（RVA不能为0）\n");
			DisplayLine(80);
			return;
		}

		DWORD dwImageBase = NtHeader->OptionalHeader.ImageBase;
		DWORD dwSectionCount = NtHeader->FileHeader.NumberOfSections;
		bool bFound = false; // 标记是否找到对应节区

		DisplayLine(80);
		printf("[*] RVA转FOA转换开始:\n");
		printf("[*] 目标RVA地址:0x%08X\n", dwRVA);
		printf("[*] 模块基地址（ImageBase）:0x%08X\n", dwImageBase);
		printf("[*] 节区总数:%d\n", dwSectionCount);
		DisplayLine(80);

		// 遍历所有节区查找RVA所属范围
		for (DWORD i = 0; i < dwSectionCount; i++)
		{
			PIMAGE_SECTION_HEADER pCurSection = &pSection[i];

			// 计算当前节区的RVA范围
			DWORD dwSectionRVAStart = pCurSection->VirtualAddress;
			// 节区有效RVA结束地址:取VirtualSize与SizeOfRawData的较小值（避免越界）
			DWORD dwSectionRVAEnd = dwSectionRVAStart + min(pCurSection->Misc.VirtualSize, pCurSection->SizeOfRawData);

			// 打印当前节区信息（辅助调试）
			printf("[节区 %d] 名称:%s | RVA范围:0x%08X - 0x%08X | 节区文件偏移:0x%08X\n",
				i + 1,
				pCurSection->Name,
				dwSectionRVAStart,
				dwSectionRVAEnd,
				pCurSection->PointerToRawData);

			// 检查RVA是否在当前节区内
			if (dwRVA >= dwSectionRVAStart && dwRVA <= dwSectionRVAEnd)
			{
				bFound = true;

				// 计算转换结果
				DWORD dwVA = dwImageBase + dwRVA; // 虚拟地址（VA）
				DWORD dwFOA = pCurSection->PointerToRawData + (dwRVA - dwSectionRVAStart); // 文件偏移（FOA）

				// 输出详细转换信息
				DisplayLine(80);
				printf("[+] 找到RVA所属节区:\n");
				printf("    节区名称:%s\n", pCurSection->Name);
				printf("    节区RVA起始:0x%08X | 节区RVA结束:0x%08X\n", dwSectionRVAStart, dwSectionRVAEnd);
				printf("    节区文件偏移:0x%08X | 节区虚拟大小:0x%08X | 节区文件大小:0x%08X\n",
					pCurSection->PointerToRawData,
					pCurSection->Misc.VirtualSize,
					pCurSection->SizeOfRawData);
				DisplayLine(60);
				printf("    转换过程:\n");
				printf("    FOA = 节区文件偏移 + (RVA - 节区RVA起始)\n");
				printf("    FOA = 0x%08X + (0x%08X - 0x%08X) = 0x%08X\n",
					pCurSection->PointerToRawData,
					dwRVA,
					dwSectionRVAStart,
					dwFOA);
				DisplayLine(60);
				printf("    最终结果:\n");
				printf("    RVA:0x%08X --> VA:0x%08X --> FOA:0x%08X\n", dwRVA, dwVA, dwFOA);
				DisplayLine(80);
				break; // 找到后退出循环
			}
		}

		// 未找到对应节区的处理
		if (!bFound)
		{
			DisplayLine(80);
			printf("[-] 转换失败:RVA 0x%08X 不在任何节区范围内\n", dwRVA);
			printf("[-] 请检查RVA是否有效（可能超出所有节区的RVA范围）\n");
			DisplayLine(80);
		}
	}

	// --------------------------------------------------
	// 将 FOA(文件偏移) --> 转换为 VA(虚拟地址)
	// 增强版:完善错误处理、输出详情及转换逻辑
	// --------------------------------------------------
	void FOA_To_VA(DWORD dwFOA)
	{
		IsOpenFile(); // 确保文件已打开

		// 基本参数校验:FOA不能超过文件总大小（无效偏移）
		if (dwFOA >= GlobalFileSize)
		{
			DisplayLine(80);
			printf("[-] 无效的FOA地址:0x%08X（超过文件总大小0x%08X）\n", dwFOA, GlobalFileSize);
			DisplayLine(80);
			return;
		}

		DWORD dwImageBase = NtHeader->OptionalHeader.ImageBase;
		DWORD NumberOfSectionsCount = NtHeader->FileHeader.NumberOfSections; // 修正变量名拼写错误
		bool bFound = false; // 标记是否找到对应节区

		DisplayLine(80);
		printf("[*] FOA转VA转换开始:\n");
		printf("[*] 目标FOA地址:0x%08X\n", dwFOA);
		printf("[*] 模块基地址（ImageBase）:0x%08X\n", dwImageBase);
		printf("[*] 节区总数:%d\n", NumberOfSectionsCount);
		DisplayLine(80);

		// 遍历所有节区查找FOA所属范围
		for (DWORD i = 0; i < NumberOfSectionsCount; i++)
		{
			PIMAGE_SECTION_HEADER pCurSection = &pSection[i];

			// 计算当前节区的文件偏移范围（左闭右开，避免越界）
			DWORD dwSectionFOAStart = pCurSection->PointerToRawData;
			DWORD dwSectionFOAEnd = dwSectionFOAStart + pCurSection->SizeOfRawData; // 结束位置为开区间

			// 打印当前节区信息（辅助定位）
			printf("[节区 %d] 名称:%s | 文件偏移范围:0x%08X - 0x%08X | 节区虚拟地址:0x%08X\n",
				i + 1,
				pCurSection->Name,
				dwSectionFOAStart,
				dwSectionFOAEnd - 1, // 显示实际有效结束偏移（闭区间）
				pCurSection->VirtualAddress);

			// 检查FOA是否在当前节区的文件偏移范围内（左闭右开）
			if (dwFOA >= dwSectionFOAStart && dwFOA < dwSectionFOAEnd)
			{
				bFound = true;

				// 计算转换结果
				DWORD dwRVA = pCurSection->VirtualAddress + (dwFOA - dwSectionFOAStart); // RVA = 节区虚拟地址 + (FOA - 节区文件偏移)
				DWORD dwVA = dwImageBase + dwRVA; // VA = 基地址 + RVA

				// 输出详细转换信息
				DisplayLine(80);
				printf("[+] 找到FOA所属节区:\n");
				printf("    节区名称:%s\n", pCurSection->Name);
				printf("    节区文件偏移范围:0x%08X - 0x%08X（有效范围）\n", dwSectionFOAStart, dwSectionFOAEnd - 1);
				printf("    节区虚拟地址（RVA起始）:0x%08X | 节区文件大小:0x%08X\n",
					pCurSection->VirtualAddress,
					pCurSection->SizeOfRawData);
				DisplayLine(60);
				printf("    转换过程:\n");
				printf("    RVA = 节区虚拟地址 + (FOA - 节区文件偏移起始)\n");
				printf("    RVA = 0x%08X + (0x%08X - 0x%08X) = 0x%08X\n",
					pCurSection->VirtualAddress,
					dwFOA,
					dwSectionFOAStart,
					dwRVA);
				printf("    VA = 基地址 + RVA\n");
				printf("    VA = 0x%08X + 0x%08X = 0x%08X\n",
					dwImageBase,
					dwRVA,
					dwVA);
				DisplayLine(60);
				printf("    最终结果:\n");
				printf("    FOA:0x%08X --> RVA:0x%08X --> VA:0x%08X\n", dwFOA, dwRVA, dwVA);
				DisplayLine(80);
				break; // 找到后退出循环
			}
		}

		// 未找到对应节区的处理
		if (!bFound)
		{
			DisplayLine(80);
			printf("[-] 转换失败:FOA 0x%08X 不在任何节区的文件偏移范围内\n", dwFOA);
			printf("[-] 可能原因:FOA属于未分配的文件区域（如节区对齐间隙）\n");
			DisplayLine(80);
		}
	}

	// --------------------------------------------------
	// 将 VA(虚拟地址) --> 转换为 RVA(相对虚拟地址)
	// 增强版:完善校验与转换过程可视化
	// --------------------------------------------------
	void VA_To_RVA(DWORD dwVA)
	{
		IsOpenFile(); // 确保文件已打开

		DWORD dwImageBase = NtHeader->OptionalHeader.ImageBase;
		DWORD dwSizeOfImage = NtHeader->OptionalHeader.SizeOfImage;

		// 基本参数校验
		if (dwVA < dwImageBase)
		{
			DisplayLine(80);
			printf("[-] 无效的VA地址:0x%08X（小于基地址0x%08X）\n", dwVA, dwImageBase);
			DisplayLine(80);
			return;
		}

		// 计算RVA
		DWORD dwRVA = dwVA - dwImageBase;

		// 校验RVA是否在模块有效范围内
		if (dwRVA >= dwSizeOfImage)
		{
			DisplayLine(80);
			printf("[-] VA转换RVA超出模块范围:\n");
			printf("    VA:0x%08X | 基地址:0x%08X | 计算得到RVA:0x%08X\n", dwVA, dwImageBase, dwRVA);
			printf("    模块总大小（SizeOfImage）:0x%08X，RVA超出有效范围\n", dwSizeOfImage);
			DisplayLine(80);
			return;
		}

		// 输出转换详情
		DisplayLine(80);
		printf("[*] VA转RVA转换开始:\n");
		printf("[*] 目标VA地址:0x%08X\n", dwVA);
		printf("[*] 模块基地址（ImageBase）:0x%08X\n", dwImageBase);
		printf("[*] 模块总大小（SizeOfImage）:0x%08X\n", dwSizeOfImage);
		DisplayLine(60);
		printf("    转换过程:\n");
		printf("    RVA = VA - 基地址\n");
		printf("    RVA = 0x%08X - 0x%08X = 0x%08X\n", dwVA, dwImageBase, dwRVA);
		DisplayLine(60);
		printf("    最终结果:\n");
		printf("    VA:0x%08X --> RVA:0x%08X（有效，在模块范围内）\n", dwVA, dwRVA);
		DisplayLine(80);
	}

	// --------------------------------------------------
	// 将 RVA(相对虚拟地址) --> 转换为 VA(虚拟地址)
	// 增强版:完善校验与节区范围验证
	// --------------------------------------------------
	void RVA_To_VA(DWORD dwRVA)
	{
		IsOpenFile(); // 确保文件已打开

		DWORD dwImageBase = NtHeader->OptionalHeader.ImageBase;
		DWORD dwSizeOfImage = NtHeader->OptionalHeader.SizeOfImage;
		DWORD dwSectionCount = NtHeader->FileHeader.NumberOfSections;
		bool bInValidSection = false; // 标记RVA是否在有效节区内

		// 基本参数校验
		if (dwRVA >= dwSizeOfImage)
		{
			DisplayLine(80);
			printf("[-] 无效的RVA地址:0x%08X（超过模块总大小0x%08X）\n", dwRVA, dwSizeOfImage);
			DisplayLine(80);
			return;
		}

		// 计算VA
		DWORD dwVA = dwImageBase + dwRVA;

		// 验证RVA是否在某个节区内（增强校验）
		for (DWORD i = 0; i < dwSectionCount; i++)
		{
			PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
			DWORD dwSectionRVAStart = pCurSection->VirtualAddress;
			DWORD dwSectionRVAEnd = dwSectionRVAStart + min(pCurSection->Misc.VirtualSize, pCurSection->SizeOfRawData);

			if (dwRVA >= dwSectionRVAStart && dwRVA <= dwSectionRVAEnd)
			{
				bInValidSection = true;
				break;
			}
		}

		// 输出转换详情
		DisplayLine(80);
		printf("[*] RVA转VA转换开始:\n");
		printf("[*] 目标RVA地址:0x%08X\n", dwRVA);
		printf("[*] 模块基地址（ImageBase）:0x%08X\n", dwImageBase);
		printf("[*] 模块总大小（SizeOfImage）:0x%08X\n", dwSizeOfImage);
		DisplayLine(60);
		printf("    转换过程:\n");
		printf("    VA = 基地址 + RVA\n");
		printf("    VA = 0x%08X + 0x%08X = 0x%08X\n", dwImageBase, dwRVA, dwVA);
		DisplayLine(60);
		printf("    校验结果:\n");
		if (bInValidSection)
		{
			printf("    RVA在有效节区内，VA有效\n");
		}
		else
		{
			printf("    RVA不在任何节区内（可能属于未分配内存区域）\n");
		}
		printf("    最终结果:\n");
		printf("    RVA:0x%08X --> VA:0x%08X\n", dwRVA, dwVA);
		DisplayLine(80);
	}

	// --------------------------------------------------
	// 获取传入文件长度（增强版:支持大文件，增加错误提示）
	// --------------------------------------------------
	long long HexGetFileSize(const char* FileName)
	{
		if (FileName == nullptr || *FileName == '\0')
		{
			printf("[-] 错误:文件路径为空\n");
			return -1;
		}

		FILE* fp = nullptr;
		// 使用fopen_s提高安全性
		errno_t err = fopen_s(&fp, FileName, "rb");
		if (err != 0 || fp == nullptr)
		{
			printf("[-] 打开文件失败:%s（错误码:%d）\n", FileName, err);
			return -1;
		}

		// 移动到文件末尾获取大小（支持大文件）
		if (fseek(fp, 0, SEEK_END) != 0)
		{
			printf("[-] 获取文件大小失败（fseek错误）\n");
			fclose(fp);
			return -1;
		}

		long long len = ftell(fp);  // 用long long支持超过2GB的文件
		fclose(fp);

		if (len < 0)
		{
			printf("[-] 获取文件大小失败（ftell错误）\n");
			return -1;
		}
		return len;
	}

	// --------------------------------------------------
	// 获取十六进制字符集（增强版:显示更多信息，优化格式）
	// --------------------------------------------------
	void GetHexASCII(long long StartAddr, long long AddrLen)
	{
		IsOpenFile();

		// 1. 基础参数校验
		if (StartAddr < 0)
		{
			printf("[-] 错误:起始偏移不能为负数（输入:%lld）\n", StartAddr);
			return;
		}
		if (AddrLen <= 0)
		{
			printf("[-] 错误:读取长度必须大于0（输入:%lld）\n", AddrLen);
			return;
		}

		// 2. 获取文件信息
		long long file_size = HexGetFileSize(GlobalFilePath);
		if (file_size <= 0)
		{
			printf("[-] 无法获取文件大小，终止操作\n");
			return;
		}

		// 3. 计算实际读取范围（处理超出文件大小的情况）
		long long end_addr = StartAddr + AddrLen;
		if (StartAddr >= file_size)
		{
			printf("[-] 错误:起始偏移（%lld）超出文件总大小（%lld）\n", StartAddr, file_size);
			return;
		}
		// 若结束偏移超出文件大小，自动截断
		if (end_addr > file_size)
		{
			AddrLen = file_size - StartAddr;
			end_addr = file_size;
			printf("[!] 警告:读取范围超出文件大小，自动截断为从 %lld 到文件末尾（总长度:%lld）\n", StartAddr, AddrLen);
		}

		// 4. 打开文件准备读取
		FILE* pointer = nullptr;
		errno_t err = fopen_s(&pointer, GlobalFilePath, "rb");
		if (err != 0 || pointer == nullptr)
		{
			printf("[-] 无法打开文件:%s（错误码:%d）\n", GlobalFilePath, err);
			return;
		}

		// 5. 输出文件元信息
		DisplayLine(120);
		//printf("文件路径:%s\n", GlobalFilePath);
		printf("文件总大小:%lld 字节（0x%016llX）\n", file_size, file_size);
		printf("读取范围:起始偏移 = %lld（0x%016llX），结束偏移 = %lld（0x%016llX），读取长度 = %lld 字节\n",
			StartAddr, StartAddr, end_addr - 1, end_addr - 1, AddrLen);
		DisplayLine(120);

		// 6. 输出十六进制/ASCII表格头部
		printf("------------------------------------------------------------------------------------------------\n");
		printf("偏移        00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  |  ASCII\n");
		printf("------------------------------------------------------------------------------------------------\n");

		// 7. 读取并打印数据
		unsigned char buffer[16];  // 每次读取16字节
		long long total_read = 0;  // 已读取总字节数
		long long line_count = 0;  // 总行数统计

		// 定位到起始偏移
		if (fseek(pointer, StartAddr, SEEK_SET) != 0)
		{
			printf("[-] 无法定位到起始偏移（%lld）\n", StartAddr);
			fclose(pointer);
			return;
		}

		while (total_read < AddrLen)
		{
			// 计算当前行需要读取的字节数（最后一行可能不足16字节）
			size_t read_size = (AddrLen - total_read) < 16 ? (size_t)(AddrLen - total_read) : 16;
			size_t bytes_read = fread(buffer, 1, read_size, pointer);
			if (bytes_read == 0) break;

			// 打印当前行偏移（十六进制，8位对齐）
			printf("0x%08llX | ", StartAddr + total_read);

			// 打印十六进制部分（8字节一组，用空格分隔）
			for (size_t i = 0; i < 16; ++i)
			{
				if (i < bytes_read)
				{
					printf("%02X ", buffer[i]);
				}
				else
				{
					printf("   ");  // 不足16字节时补空格对齐
				}
				// 8字节处加一个空格分组
				if (i == 7) printf(" ");
			}

			// 打印ASCII部分（不可打印字符用.代替）
			printf(" | ");
			for (size_t i = 0; i < bytes_read; ++i)
			{
				if (isprint(buffer[i]))  // 判断是否为可打印字符
				{
					printf("%c", buffer[i]);
				}
				else
				{
					printf(".");
				}
			}
			printf("\n");

			total_read += bytes_read;
			line_count++;
		}

		// 8. 输出统计信息
		DisplayLine(120);
		printf("读取完成:共读取 %lld 字节，输出 %lld 行\n", total_read, line_count);
		DisplayLine(120);

		fclose(pointer);
	}

	// --------------------------------------------------
	// 特征码搜索功能:在指定区域搜索带通配符的特征码
	// 参数:
	//   StartAddr:搜索起始偏移
	//   SearchLen:搜索长度
	//   sig_str:特征码字符串（格式如"55 8B ?? EC"）
	// --------------------------------------------------
	void SearchSignature(long long StartAddr, long long SearchLen, const std::string& sig_str)
	{
		IsOpenFile();

		// 1. 基础参数校验
		if (StartAddr < 0)
		{
			printf("[-] 错误:起始偏移不能为负数（输入:%lld）\n", StartAddr);
			return;
		}
		if (SearchLen <= 0)
		{
			printf("[-] 错误:搜索长度必须大于0（输入:%lld）\n", SearchLen);
			return;
		}
		if (sig_str.empty())
		{
			printf("[-] 错误:特征码不能为空\n");
			return;
		}

		// 2. 解析特征码
		std::vector<unsigned char> signature = ParseSignature(sig_str);
		if (signature.empty())
		{
			printf("[-] 错误:特征码格式无效（正确格式:\"55 8B ?? EC\"，支持十六进制和??通配符）\n");
			return;
		}
		size_t sig_len = signature.size();
		if (sig_len > SearchLen)
		{
			printf("[-] 错误:特征码长度（%llu字节）大于搜索范围（%lld字节）\n",
				(unsigned long long)sig_len, SearchLen);
			return;
		}

		// 3. 获取文件信息并校验搜索范围
		long long file_size = HexGetFileSize(GlobalFilePath);
		if (file_size <= 0)
		{
			printf("[-] 无法获取文件大小，终止操作\n");
			return;
		}
		long long end_addr = StartAddr + SearchLen;
		if (StartAddr >= file_size)
		{
			printf("[-] 错误:起始偏移（%lld）超出文件总大小（%lld）\n", StartAddr, file_size);
			return;
		}
		// 截断超出文件范围的搜索长度
		if (end_addr > file_size)
		{
			SearchLen = file_size - StartAddr;
			end_addr = file_size;
			printf("[!] 警告:搜索范围超出文件大小，自动截断为从 %lld 到文件末尾（总长度:%lld）\n",
				StartAddr, SearchLen);
		}
		if (sig_len > SearchLen)
		{
			printf("[-] 错误:截断后搜索范围（%lld字节）仍小于特征码长度（%llu字节）\n",
				SearchLen, (unsigned long long)sig_len);
			return;
		}

		// 4. 打开文件并读取搜索区域数据到缓冲区
		FILE* pointer = nullptr;
		errno_t err = fopen_s(&pointer, GlobalFilePath, "rb");
		if (err != 0 || pointer == nullptr)
		{
			printf("[-] 无法打开文件:%s（错误码:%d）\n", GlobalFilePath, err);
			return;
		}
		// 定位到起始偏移
		if (fseek(pointer, StartAddr, SEEK_SET) != 0)
		{
			printf("[-] 无法定位到起始偏移（%lld）\n", StartAddr);
			fclose(pointer);
			return;
		}
		// 分配缓冲区并读取数据
		unsigned char* buffer = new unsigned char[SearchLen];
		size_t bytes_read = fread(buffer, 1, SearchLen, pointer);
		if (bytes_read != SearchLen)
		{
			printf("[-] 读取数据失败，实际读取 %llu 字节（预期 %lld 字节）\n",
				(unsigned long long)bytes_read, SearchLen);
			delete[] buffer;
			fclose(pointer);
			return;
		}
		fclose(pointer);

		// 5. 搜索特征码（核心匹配逻辑）
		std::vector<long long> match_offsets; // 存储所有匹配的偏移
		for (long long i = 0; i <= SearchLen - (long long)sig_len; ++i)
		{
			bool matched = true;
			for (size_t j = 0; j < sig_len; ++j)
			{
				// 通配符??直接跳过匹配
				if (signature[j] == 0xFF)
				{
					continue;
				}
				// 非通配符必须严格匹配
				if (buffer[i + j] != signature[j])
				{
					matched = false;
					break;
				}
			}
			if (matched)
			{
				// 记录匹配的绝对偏移（文件中的实际偏移）
				match_offsets.push_back(StartAddr + i);
			}
		}

		// 6. 输出搜索结果
		DisplayLine(120);
		//printf("文件路径:%s\n", GlobalFilePath);
		printf("搜索范围:起始偏移 = %lld（0x%016llX），搜索长度 = %lld 字节\n",
			StartAddr, StartAddr, SearchLen);
		printf("特征码:%s（长度:%llu字节，包含通配符）\n", sig_str.c_str(), (unsigned long long)sig_len);
		DisplayLine(120);

		if (match_offsets.empty())
		{
			printf("未找到匹配的特征码\n");
		}
		else
		{
			printf("找到 %llu 个匹配结果:\n", (unsigned long long)match_offsets.size());
			printf("------------------------------------------------------------------------------------------------\n");
			printf("偏移（十进制）         偏移（十六进制）         匹配位置的十六进制数据\n");
			printf("------------------------------------------------------------------------------------------------\n");
			for (long long offset : match_offsets)
			{
				// 打印偏移信息
				printf("%-20lld 0x%016llX  ", offset, offset);
				// 打印匹配位置的前16字节数据（方便确认）
				for (size_t k = 0; k < 16; ++k)
				{
					// 计算在缓冲区中的索引
					long long buf_idx = (offset - StartAddr) + k;
					if (buf_idx < SearchLen)
					{
						printf("%02X ", buffer[buf_idx]);
					}
					else
					{
						printf("   ");
					}
				}
				printf("\n");
			}
		}

		DisplayLine(120);
		printf("搜索完成\n");
		DisplayLine(120);

		// 释放缓冲区
		delete[] buffer;
	}

	// --------------------------------------------------
	// 字符串搜索功能:在指定区域搜索特定字符串
	// 参数:
	//   StartAddr:搜索起始偏移（FOA）
	//   SearchLen:搜索长度（字节）
	//   target_str:目标字符串（ASCII）
	// --------------------------------------------------
	void SearchString(long long StartAddr, long long SearchLen, const std::string& target_str)
	{
		IsOpenFile();

		// 1. 基础参数校验
		if (StartAddr < 0)
		{
			printf("[-] 错误:起始偏移不能为负数（输入:%lld）\n", StartAddr);
			return;
		}
		if (SearchLen <= 0)
		{
			printf("[-] 错误:搜索长度必须大于0（输入:%lld）\n", SearchLen);
			return;
		}
		if (target_str.empty())
		{
			printf("[-] 错误:目标字符串不能为空\n");
			return;
		}
		size_t str_len = target_str.size();
		if (str_len == 0)
		{
			printf("[-] 错误:目标字符串长度不能为0\n");
			return;
		}

		// 2. 获取文件信息并校验搜索范围
		long long file_size = HexGetFileSize(GlobalFilePath);
		if (file_size <= 0)
		{
			printf("[-] 无法获取文件大小，终止操作\n");
			return;
		}
		long long end_addr = StartAddr + SearchLen;
		if (StartAddr >= file_size)
		{
			printf("[-] 错误:起始偏移（%lld）超出文件总大小（%lld）\n", StartAddr, file_size);
			return;
		}
		// 截断超出文件范围的搜索长度
		if (end_addr > file_size)
		{
			SearchLen = file_size - StartAddr;
			end_addr = file_size;
			printf("[!] 警告:搜索范围超出文件大小，自动截断为从 %lld 到文件末尾（总长度:%lld）\n",
				StartAddr, SearchLen);
		}
		if (str_len > SearchLen)
		{
			printf("[-] 错误:目标字符串长度（%llu字节）大于搜索范围（%lld字节）\n",
				(unsigned long long)str_len, SearchLen);
			return;
		}

		// 3. 打开文件并读取搜索区域数据到缓冲区
		FILE* pointer = nullptr;
		errno_t err = fopen_s(&pointer, GlobalFilePath, "rb");
		if (err != 0 || pointer == nullptr)
		{
			printf("[-] 无法打开文件:%s（错误码:%d）\n", GlobalFilePath, err);
			return;
		}
		// 定位到起始偏移
		if (fseek(pointer, StartAddr, SEEK_SET) != 0)
		{
			printf("[-] 无法定位到起始偏移（%lld）\n", StartAddr);
			fclose(pointer);
			return;
		}
		// 分配缓冲区并读取数据
		unsigned char* buffer = new unsigned char[SearchLen];
		size_t bytes_read = fread(buffer, 1, SearchLen, pointer);
		if (bytes_read != SearchLen)
		{
			printf("[-] 读取数据失败，实际读取 %llu 字节（预期 %lld 字节）\n",
				(unsigned long long)bytes_read, SearchLen);
			delete[] buffer;
			fclose(pointer);
			return;
		}
		fclose(pointer);

		// 4. 搜索字符串（核心匹配逻辑）
		std::vector<long long> match_offsets; // 存储所有匹配的偏移
		for (long long i = 0; i <= SearchLen - (long long)str_len; ++i)
		{
			bool matched = true;
			for (size_t j = 0; j < str_len; ++j)
			{
				// 严格匹配每个字符（ASCII）
				if (buffer[i + j] != (unsigned char)target_str[j])
				{
					matched = false;
					break;
				}
			}
			if (matched)
			{
				// 记录匹配的绝对偏移（文件中的实际偏移）
				match_offsets.push_back(StartAddr + i);
			}
		}

		// 5. 输出搜索结果
		DisplayLine(120);
		// printf("文件路径:%s\n", GlobalFilePath);
		printf("搜索范围:起始偏移 = %lld（0x%016llX），搜索长度 = %lld 字节\n",
			StartAddr, StartAddr, SearchLen);
		printf("目标字符串:\"%s\"（长度:%llu字节，ASCII）\n", target_str.c_str(), (unsigned long long)str_len);
		DisplayLine(120);

		if (match_offsets.empty())
		{
			printf("未找到匹配的字符串\n");
		}
		else {
			printf("找到 %llu 个匹配结果:\n", (unsigned long long)match_offsets.size());
			printf("------------------------------------------------------------------------------------------------\n");
			printf("偏移（十进制）         偏移（十六进制）         VA地址（十六进制）         匹配内容\n");
			printf("------------------------------------------------------------------------------------------------\n");
			for (long long offset : match_offsets)
			{
				// 计算VA地址（FOA->RVA->VA）
				DWORD va = 0;
				if (offset <= 0xFFFFFFFF)
				{ // 确保FOA在32位范围内
					DWORD rva = FOAtoRVA((DWORD)offset);
					va = rva + NtHeader->OptionalHeader.ImageBase;
				}

				// 打印偏移信息
				printf("%-20lld 0x%016llX  0x%016X  ", offset, offset, va);

				// 打印匹配的字符串内容
				printf("\"");
				for (size_t k = 0; k < str_len; ++k)
				{
					printf("%c", target_str[k]);
				}
				printf("\"\n");
			}
		}

		DisplayLine(120);
		printf("搜索完成\n");
		DisplayLine(120);

		// 释放缓冲区
		delete[] buffer;
	}

	// --------------------------------------------------
	// 检查自身进程开启的保护方式
	// --------------------------------------------------
	void ModuleStatus()
	{
		IsOpenFile();
		WORD dllCharac = NtHeader->OptionalHeader.DllCharacteristics;  // DLL特性标志
		DWORD secDirSize = NtHeader->OptionalHeader.DataDirectory[4].Size;  // 安全目录（证书）大小
		DWORD dbgDirSize = NtHeader->OptionalHeader.DataDirectory[6].Size;  // 调试目录大小
		WORD fileCharac = NtHeader->FileHeader.Characteristics;  // 文件特性标志
		WORD subsystem = NtHeader->OptionalHeader.Subsystem;      // 子系统类型
		WORD machine = NtHeader->FileHeader.Machine;              // 机器架构


		DisplayLine(80);
		printf("[模块基本属性]\n");
		DisplayLine(80);

		// 1. 是否为DLL
		if (fileCharac & IMAGE_FILE_DLL)
			printf("文件类型:       DLL文件\n");
		else
			printf("文件类型:       可执行文件(EXE)\n");

		// 2. 机器架构
		printf("机器架构:       ");
		switch (machine)
		{
		case IMAGE_FILE_MACHINE_I386:    printf("x86 (32位)\n"); break;
		case IMAGE_FILE_MACHINE_AMD64:   printf("x64 (64位)\n"); break;
		case IMAGE_FILE_MACHINE_ARM:     printf("ARM\n"); break;
		case IMAGE_FILE_MACHINE_ARM64:   printf("ARM64\n"); break;  // 已补充定义
		default:                         printf("未知 (0x%04X)\n", machine);
		}

		// 3. 子系统类型
		printf("子系统类型:     ");
		switch (subsystem)
		{
		case IMAGE_SUBSYSTEM_WINDOWS_CUI:        printf("控制台应用程序 (CUI)\n"); break;  // 值为3
		case IMAGE_SUBSYSTEM_WINDOWS_GUI:        printf("图形界面应用程序 (GUI)\n"); break;  // 值为2
		case IMAGE_SUBSYSTEM_WINDOWS_DRIVER:     printf("Windows驱动程序 (EFI)\n"); break;  // 修正后值为0x000B，无冲突
		case IMAGE_SUBSYSTEM_WINDOWS_NATIVE:     printf("Windows原生应用\n"); break;  // 修正后值为0x0001，无冲突
		case IMAGE_SUBSYSTEM_POSIX_CUI:          printf("POSIX控制台应用\n"); break;  // 值为7
		default:                                 printf("未知 (0x%04X)\n", subsystem);
		}

		// 4. 链接器版本（修正结构体成员访问）
		printf("链接器版本:     %d.%d\n",
			NtHeader->OptionalHeader.MajorImageVersion,  // 原MajorLinkerVersion修正
			NtHeader->OptionalHeader.MinorImageVersion);  // 原MinorLinkerVersion修正

		DisplayLine(80);
		printf("[安全特性]\n");
		DisplayLine(80);

		// 5. 基址随机化 (ASLR)
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
			printf("基址随机化(ASLR):  启用\n");
		else
			printf("基址随机化(ASLR):  禁用\n");

		// 6. 强制高熵ASLR
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)
			printf("高熵ASLR:          启用 (地址空间熵更高)\n");
		else
			printf("高熵ASLR:          禁用\n");

		// 7. DEP兼容 (NX保护)
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
			printf("DEP/NX保护:        兼容 (数据页不可执行)\n");
		else
			printf("DEP/NX保护:        不兼容 (可能允许数据执行)\n");

		// 8. 控制流保护 (CFG)
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
			printf("控制流保护(CFG):   启用 (阻止非法间接调用)\n");
		else
			printf("控制流保护(CFG):   禁用\n");

		// 9. 强制完整性
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
			printf("强制完整性:        启用 (必须通过完整性校验)\n");
		else
			printf("强制完整性:        禁用\n");

		// 10. SEH异常保护
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_NO_SEH)
			printf("SEH异常处理:       禁用 (不允许结构化异常处理)\n");
		else
			printf("SEH异常处理:       允许 (支持结构化异常处理)\n");

		// 11. 证书签名
		if (secDirSize != 0)
			printf("数字证书:          存在 (可能已签名)\n");
		else
			printf("数字证书:          不存在\n");

		DisplayLine(80);
		printf("[其他特性]\n");
		DisplayLine(80);

		// 12. 终端服务感知
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE)
			printf("终端服务感知:      是 (兼容终端服务环境)\n");
		else
			printf("终端服务感知:      否\n");

		// 13. UAC虚拟化（使用补充定义的常量）
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_NO_UAC_DLL)
			printf("UAC虚拟化:         禁用 (不虚拟化文件系统/注册表)\n");
		else
			printf("UAC虚拟化:         启用\n");

		// 14. 隔离特性（使用补充定义的常量）
		if (dllCharac & IMAGE_DLLCHARACTERISTICS_ISOLATION)
			printf("隔离特性:          启用 (需在AppContainer中运行)\n");
		else
			printf("隔离特性:          禁用\n");

		// 15. 调试信息
		if (dbgDirSize != 0)
			printf("调试信息:          存在 (包含调试符号目录)\n");
		else
			printf("调试信息:          不存在\n");

		DisplayLine(80);
	}
}

// PE文件反汇编
namespace PEDisassemble
{
	// 存放反汇编数据
	typedef struct
	{
		int OpCodeSize;               // 机器码长度
		int OpStringSize;             // 反汇编长度
		unsigned long long Address;   // 相对地址
		unsigned char OpCode[16];     // 机器码
		char OpString[256];           // 反汇编
	}MyStruct;

	// 辅助函数:将字符串转换为数值（支持十进制和十六进制，如"100"或"0x100"）
	unsigned long long str_to_ulonglong(const std::string& s)
	{
		if (s.empty()) return 0;
		char* endptr = nullptr;
		unsigned long long val = 0;
		// 检查是否为十六进制格式（0x前缀）
		if (s.size() >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')))
		{
			val = strtoull(s.c_str() + 2, &endptr, 16); // 十六进制解析
		}
		else
		{
			val = strtoull(s.c_str(), &endptr, 10); // 十进制解析
		}
		// 若解析失败（存在非数字字符），返回0
		return (endptr && *endptr == '\0') ? val : 0;
	}

	// 在文件偏移位置读入数据
	BOOL ReadPEFileOffset(IN LPSTR file_path, IN DWORD Offset, IN DWORD Size, OUT LPVOID* pFileBuffer)
	{
		FILE* fp = NULL;

		fopen_s(&fp, file_path, "rb");
		if (fp == NULL)
		{
			return FALSE;
		}
		else
		{
			// 开辟指定大小的内存
			LPVOID ptr = malloc(sizeof(char)*Size);
			if (ptr == NULL)
			{
				fclose(fp);
				return FALSE;
			}

			// 设置标志
			fseek(fp, Offset, SEEK_SET);

			// 将文件数据拷贝到缓冲区
			size_t nsize = fread(ptr, sizeof(char), Size, fp);
			if (!nsize)
			{
				free(ptr);
				fclose(fp);
				return FALSE;
			}
			*pFileBuffer = ptr;
			ptr = NULL;

			fclose(fp);
		}

		return TRUE;
	}

	// 反汇编字符串
	std::vector<MyStruct> DisassembleCode(unsigned char *start_offset, int size)
	{
		PEView::IsOpenFile();

		std::vector<MyStruct> ptr = {};

		csh handle;
		cs_insn *insn;
		size_t count;

		// 打开句柄
		if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		{
			return{};
		}

		// 反汇编代码,地址从0x1000开始,返回总条数
		count = cs_disasm(handle, (unsigned char *)start_offset, size, 0x0, 0, &insn);

		if (count > 0)
		{
			size_t index;

			// 循环反汇编代码
			for (index = 0; index < count; index++)
			{
				// 清空
				MyStruct location;
				memset(&location, 0, sizeof(MyStruct));

				// 循环拷贝机器码
				for (int x = 0; x < insn[index].size; x++)
				{
					location.OpCode[x] = insn[index].bytes[x];
				}

				// 拷贝地址长度
				location.Address = insn[index].address;
				location.OpCodeSize = insn[index].size;

				// 拷贝反汇编指令
				strcpy_s(location.OpString, insn[index].mnemonic);
				strcat_s(location.OpString, " ");
				strcat_s(location.OpString, insn[index].op_str);

				// 得到反汇编长度
				location.OpStringSize = strlen(location.OpString);

				ptr.push_back(location);
			}
			cs_free(insn, count);
		}
		else
		{
			return{};
		}
		cs_close(&handle);
		return ptr;
	}
}

void Help()
{
	fprintf(stderr,
		"\n 可选参数:\n\n"
		" \t Open              打开PE文件 \n"
		" \t Info              显示文件基本信息 \n"
		" \t Dos               显示文件DOS头结构 \n"
		" \t Nt                显示文件NT头结构 \n"
		" \t DataDirectory     显示数据目录结构 \n"
		" \t Section           显示文件节表信息 \n"
		" \t Import            显示所有导入表信息 \n"
		" \t ImportDll         显示所有导入的DLL库 \n"
		" \t ImportByName      查询指定导入表中导入过的函数 \n"
		" \t ImportByFunction  查询指定函数是否存在于导入表中 \n"
		" \t Export            显示所有导出表信息 \n"
		" \t FixRelocPage      显示重定位表分页情况 \n"
		" \t FixReloc          显示所有重定位表定位项 \n"
		" \t FixRelocRVA       显示指定RVA中的重定位表 \n"
		" \t Resource          显示当前PE文件资源列表 \n"
		" \t HexAscii          获取指定文本中的十六进制格式 \n"
		" \t Disassembly       反汇编文件偏移内的数据\n"
		" \t SearchSig         搜索十六进制机器码特征值 \n"
		" \t SearchString      搜索特定区域的ASCII字符串 \n"
		" \t Add               内置十六进制加法计算器 \n"
		" \t Sub               内置十六进制减法计算器 \n"
		" \t VaToFoa           将VA地址转为FOA地址\n"
		" \t FoaToVa           将FOA地址转为VA地址\n"
		" \t RvaToFoa          将RVA地址转为FOA地址\n"
		" \t VaToRva           将VA地址转为RVA地址\n"
		" \t RvaToVa           将RVA地址转为VA地址\n"
		" \t Protection        检查自身开启的保护方式或验证签名 \n"
		" \t GetProcAddr       获取DLL中特定函数的内存地址 \n"
		"\n\n"
		);
}

void Loading()
{
	printf("__ __       _____      _     _     __      _____    _      _   \n");
	printf(" /_/\\__/\\   /\\_____\\    /_/\\ /\\_\\   /\\_\\   /\\_____\\  /_/\\  /\\_\\  \n");
	printf(" ) ) ) ) ) ( (_____/    ) ) ) ( (   \\/_/  ( (_____/  ) ) )( ( (  \n");
	printf("_/_/ /_/ /   \\ \\__\\     /_/ / \\ \\_\\   /\\_\\  \\ \\__\\   /_/ //\\\\ \\_\\ \n");
	printf("\\ \\ \\_\\/    / /__/_    \\ \\ \\_/ / /  / / /  / /__/_  \\ \\ /  \\ / / \n");
	printf(" )_) )     ( (_____\\    \\ \\   / /  ( (_(  ( (_____\\  )_) /\\ (_(  \n");
	printf(" \\_\\/       \\/_____/     \\_\\_/_/    \\/_/   \\/_____/  \\_\\/  \\/_/  \n");
	printf("                                                                 \n");
	printf("[编译日期] %s \n", __DATE__);
	printf("[解析格式] Windows x86 (PE32)\n");
	printf("[当前版本] 4.0.0 \n");
	printf("[官方网站] peview.lyshark.com \n\n");
}

int main(int argc, char* argv[])
{
	std::string command;
	Loading();
	while (1)
	{
		std::cout << "[PEVIEW] # ";
		std::getline(std::cin, command);

		if (command.length() == 0)
		{
			continue;
		}
		else if (command == "help")
		{
			Help();
		}
		else
		{
			// 定义分词器: 定义分割符号为[逗号,空格]
			boost::char_separator<char> sep(", --");
			typedef boost::tokenizer<boost::char_separator<char>> CustonTokenizer;
			CustonTokenizer tok(command, sep);

			// 将分词结果放入vector链表
			std::vector<std::string> vecSegTag;
			for (CustonTokenizer::iterator beg = tok.begin(); beg != tok.end(); ++beg)
			{
				vecSegTag.push_back(*beg);
			}

			// ----------------------------------------------------------------------
			// 解析三个参数
			// ----------------------------------------------------------------------

			// 输出基本信息
			if (vecSegTag.size() == 1 && vecSegTag[0] == "Info")
			{
				PEView::ShowFileBasicInfo();
			}

			// 验证指定DLL中指定函数内存地址
			else if (vecSegTag.size() == 5 && vecSegTag[0] == "GetProcAddr")
			{
				// GetProcAddress --dll user32.dll --function MessageBoxA
				if (vecSegTag[1] == "dll" && vecSegTag[3] == "function")
				{
					std::string dll = vecSegTag[2];
					std::string function = vecSegTag[4];
					PEView::GetProcessAddress((char*)dll.c_str(), (char *)function.c_str());
				}
			}

			// 内置加法计算器
			else if (vecSegTag.size() == 5 && vecSegTag[0] == "Add")
			{
				// Add --x 0x1a --y 0x2b
				if (vecSegTag[1] == "x" && vecSegTag[3] == "y")
				{
					std::string x = vecSegTag[2];
					std::string y = vecSegTag[4];

					DWORD ref = 0;
					char bin[10];
					ref = PEView::HexToDex((char *)x.c_str()) + PEView::HexToDex((char *)y.c_str());
					printf("%s + %s =>\n"
						"\tHEX= %08X\n"
						"\tDEC= %d\n"
						"\tOCT= %o\n"
						"\tBIN= %s\n",
						(char*)x.c_str(), (char*)y.c_str(),
						ref, ref, ref,
						itoa(ref, bin, 2));
				}
			}

			// 内置减法计算器
			else if (vecSegTag.size() == 5 && vecSegTag[0] == "Sub")
			{
				// Sub --x 0x1a --y 0x2b
				if (vecSegTag[1] == "x" && vecSegTag[3] == "y")
				{
					std::string x = vecSegTag[2];
					std::string y = vecSegTag[4];

					DWORD ref = 0;
					char bin[10];
					ref = PEView::HexToDex((char*)x.c_str()) - PEView::HexToDex((char*)y.c_str());
					printf("%s - %s =>\n"
						"\tHEX= %08X\n"
						"\tDEC= %d\n"
						"\tOCT= %o\n"
						"\tBIN= %s\n",
						(char*)x.c_str(), (char*)y.c_str(),
						ref, ref, ref,
						itoa(ref, bin, 2));
				}
			}

			// 输出指定位置的十六进制机器码
			else if (vecSegTag.size() == 5 && vecSegTag[0] == "HexAscii")
			{
				// 支持十进制（如100）和十六进制（如0x64）输入解析
				if (vecSegTag[1] == "offset" && vecSegTag[3] == "len")
				{
					std::string offsetStr = vecSegTag[2];
					std::string lenStr = vecSegTag[4];
					long offset = 0, len = 0;
					bool isValid = true;

					// 解析数字（支持十进制和十六进制）
					auto parseNumber = [&](const std::string& str, long& result) -> bool
					{
						char* endptr;
						// 检查是否为十六进制（0x或0X前缀）
						if (str.size() >= 2 && (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')))
						{
							result = strtol(str.c_str(), &endptr, 16); // 十六进制解析
						}
						else
						{
							result = strtol(str.c_str(), &endptr, 10); // 十进制解析
						}
						// 检查是否完全解析（无无效字符）且结果非负
						if (*endptr != '\0' || result < 0)
						{
							return false;
						}
						return true;
					};

					// 解析offset
					if (!parseNumber(offsetStr, offset))
					{
						printf("[-] 无效的offset值: %s（支持十进制或十六进制，如100或0x64）\n", offsetStr.c_str());
						isValid = false;
					}

					// 解析len
					if (!parseNumber(lenStr, len))
					{
						printf("[-] 无效的len值: %s（支持十进制或十六进制，如100或0x64）\n", lenStr.c_str());
						isValid = false;
					}

					// 检查长度是否为正数
					if (isValid && len <= 0)
					{
						printf("[-] len值必须为正数: %ld\n", len);
						isValid = false;
					}

					// 执行转换
					if (isValid)
					{
						PEView::GetHexASCII(offset, len);
					}
				}
			}

			else if (vecSegTag.size() == 5 && vecSegTag[0] == "Disassembly")
			{
				// 实现反汇编指定位置
				// DasmFoa --offset 100 --len 100
				// 处理"DasmFoa --offset 100 --len 100"命令的升级版本
				if (vecSegTag[1] == "offset" && vecSegTag[3] == "len")
				{
					std::string offset_str = vecSegTag[2];
					std::string len_str = vecSegTag[4];

					// 解析偏移和长度（支持十六进制）
					unsigned long long offset_val = PEDisassemble::str_to_ulonglong(offset_str);
					unsigned long long len_val = PEDisassemble::str_to_ulonglong(len_str);

					// 基本参数校验
					if (len_val == 0)
					{
						PEView::DisplayLine(80);
						printf("错误:长度不能为0\n");
						PEView::DisplayLine(80);

					}
					if (offset_val == 0 && offset_str != "0" && offset_str != "0x0")
					{
						PEView::DisplayLine(80);
						printf("错误:偏移格式无效（支持十进制或十六进制，如100或0x100）\n");
						PEView::DisplayLine(80);

					}

					LPVOID pFileBuffer = NULL;
					// 读取文件指定偏移的数据（修复返回值判断错误）
					BOOL read_success = PEDisassemble::ReadPEFileOffset(
						GlobalFilePath,
						(DWORD)offset_val,
						(DWORD)len_val,
						&pFileBuffer
						);
					if (!read_success)
					{
						PEView::DisplayLine(80);
						printf("错误:无法读取文件偏移 0x%llX 处的 %llu 字节数据\n", offset_val, len_val);
						PEView::DisplayLine(80);

					}

					// 反汇编指定数据
					std::vector<PEDisassemble::MyStruct> FileDissassemble =
						PEDisassemble::DisassembleCode((unsigned char*)pFileBuffer, (int)len_val);

					// 输出结果
					PEView::DisplayLine(80);
					// 表头:偏移（8字节） | 机器码（最多16字节，占48字符） | 反汇编指令
					printf("文件偏移\t\t机器码\t\t\t\t反汇编指令集\n");
					PEView::DisplayLine(80);

					if (FileDissassemble.empty())
					{
						printf("提示:未反汇编到任何指令（可能是无效的机器码）\n");
					}
					else {
						for (size_t i = 0; i < FileDissassemble.size(); i++)
						{
							const auto& item = FileDissassemble[i];
							// 计算显示的实际文件偏移（原始偏移 + 指令在缓冲区中的偏移）
							unsigned long long display_offset = offset_val + item.Address;

							// 1. 打印文件偏移（8位十六进制）
							printf("0x%08llX | ", display_offset);

							// 2. 打印机器码（十六进制，空格分隔，如"55 8B EC"）
							char op_code_str[16 * 3 + 1] = { 0 }; // 16字节最多占48字符（每个字节"XX "）
							for (int x = 0; x < item.OpCodeSize; x++)
							{
								char temp[4];
								sprintf_s(temp, "%02X ", item.OpCode[x]); // 每个字节转为两位十六进制
								strcat_s(op_code_str, temp);
							}
							printf("%-30s | ", op_code_str); // 左对齐，预留48字符宽度

							// 3. 打印反汇编指令
							printf("%s\n", item.OpString);
						}
					}

					PEView::DisplayLine(80);
					// 释放动态分配的内存（修复内存泄漏）
					free(pFileBuffer);
				}
			}

			// -------------------------- 新增:特征码搜索命令处理分支 --------------------------
			// 新逻辑:允许 --sig 后有多个参数（特征码拆分的结果），只需前6个参数结构正确
			else if (vecSegTag.size() >= 7 && vecSegTag[0] == "SearchSig")
			{
				// 检查前6个参数是否符合格式:SearchSig --offset [值] --len [值] --sig
				if (vecSegTag[1] == "offset" && vecSegTag[3] == "len" && vecSegTag[5] == "sig")
				{
					// 1. 提取偏移和长度（前6个参数中正常解析）
					std::string offset_str = vecSegTag[2];
					std::string len_str = vecSegTag[4];

					// 2. 合并 --sig 后的所有参数作为特征码（用空格连接拆分的部分）
					std::string sig_str;
					for (size_t i = 6; i < vecSegTag.size(); ++i)
					{
						if (i > 6) sig_str += " "; // 多个部分之间用空格分隔
						sig_str += vecSegTag[i];
					}

					// 后续参数解析和校验逻辑不变
					long long offset_val = PEDisassemble::str_to_ulonglong(offset_str);
					long long len_val = PEDisassemble::str_to_ulonglong(len_str);

					bool param_valid = true;
					if (offset_val < 0 || (offset_str != "0" && offset_val == 0))
					{
						printf("[-] 错误:偏移值无效\n");
						param_valid = false;
					}
					if (len_val <= 0)
					{
						printf("[-] 错误:搜索长度必须大于0\n");
						param_valid = false;
					}
					if (sig_str.empty())
					{
						printf("[-] 错误:特征码不能为空\n");
						param_valid = false;
					}

					if (param_valid)
					{
						PEView::SearchSignature(offset_val, len_val, sig_str);
					}
				}
			}

			// -------------------------- 新增:字符串搜索命令处理分支 --------------------------
			else if (vecSegTag.size() >= 7 && vecSegTag[0] == "SearchString")
			{
				// 检查前6个参数是否符合格式:SearchString --offset [值] --len [值] --str
				if (vecSegTag[1] == "offset" && vecSegTag[3] == "len" && vecSegTag[5] == "str")
				{
					// 1. 提取偏移和长度（前6个参数中正常解析）
					std::string offset_str = vecSegTag[2];
					std::string len_str = vecSegTag[4];

					// 2. 合并 --str 后的所有参数作为目标字符串（用空格连接拆分的部分，支持含空格的字符串）
					std::string target_str;
					for (size_t i = 6; i < vecSegTag.size(); ++i)
					{
						if (i > 6) target_str += " "; // 多个部分之间用空格分隔，还原原始字符串中的空格
						target_str += vecSegTag[i];
					}

					// 3. 参数解析和校验
					long long offset_val = PEDisassemble::str_to_ulonglong(offset_str);
					long long len_val = PEDisassemble::str_to_ulonglong(len_str);

					bool param_valid = true;
					if (offset_val < 0 || (offset_str != "0" && offset_val == 0))
					{
						printf("[-] 错误:偏移值无效\n");
						param_valid = false;
					}
					if (len_val <= 0)
					{
						printf("[-] 错误:搜索长度必须大于0\n");
						param_valid = false;
					}
					if (target_str.empty())
					{
						printf("[-] 错误:目标字符串不能为空\n");
						param_valid = false;
					}

					// 4. 执行搜索
					if (param_valid)
					{
						PEView::SearchString(offset_val, len_val, target_str);
					}
				}
			}

			// ----------------------------------------------------------------------
			// 解析两个参数
			// ----------------------------------------------------------------------
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "Open")
			{
				// 打开文件操作
				// Open --path d://test.exe
				if (vecSegTag[1] == "path")
				{
					std::string path = vecSegTag[2];
					PEView::OpenPeFile((LPCSTR)path.c_str());
				}
			}
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "ImportByName")
			{
				// 显示指定DLL中的导入函数
				// ImportByName --dll kernel32.dll
				if (vecSegTag[1] == "dll")
				{
					PEView::ShowImportByName((char *)vecSegTag[2].c_str());
				}
			}
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "ImportByFunction")
			{
				// 显示指定DLL中的导入函数
				// ImportByFunction --function MessageBoxA
				if (vecSegTag[1] == "function")
				{
					PEView::ShowImportByFunction((char*)vecSegTag[2].c_str());
				}
			}
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "FixRelocRVA")
			{
				// 显示指定DLL中的导入函数
				// FixRelocRVA --rva 0x1000
				if (vecSegTag[1] == "rva")
				{
					PEView::ShowFixReloc((char*)vecSegTag[2].c_str());
				}
			}
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "VaToFoa")
			{
				// 将VA转为FOA
				// VaToFoa --va 0x10011
				if (vecSegTag[1] == "va")
				{
					DWORD dec = 0;
					// 将传入十六进制转为十进制
					dec = PEView::HexStringToDec((char*)vecSegTag[2].c_str());
					PEView::VA_To_FOA(dec);
				}
			}
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "FoaToVa")
			{
				// 将FOA转为VA
				// VaToFoa --foa 0x10011
				if (vecSegTag[1] == "foa")
				{
					DWORD dec = 0;
					// 将传入十六进制转为十进制
					dec = PEView::HexStringToDec((char*)vecSegTag[2].c_str());
					PEView::FOA_To_VA(dec);
				}
			}
			else if (vecSegTag.size() == 3 && vecSegTag[0] == "RvaToFoa")
			{
				// 将RVA转为FOA
				// VaToFoa --rva 0x10011
				if (vecSegTag[1] == "rva")
				{
					DWORD dec = 0;
					// 将传入十六进制转为十进制
					dec = PEView::HexStringToDec((char*)vecSegTag[2].c_str());
					PEView::RVA_To_FOA(dec);
				}
			}

			else if (vecSegTag.size() == 3 && vecSegTag[0] == "VaToRva")
			{
				// VaToFoa --va 0x10011
				if (vecSegTag[1] == "va")
				{
					DWORD dec = 0;
					// 将传入十六进制转为十进制
					dec = PEView::HexStringToDec((char*)vecSegTag[2].c_str());
					PEView::VA_To_RVA(dec);
				}
			}

			else if (vecSegTag.size() == 3 && vecSegTag[0] == "RvaToVa")
			{
				if (vecSegTag[1] == "rva")
				{
					DWORD dec = 0;
					// 将传入十六进制转为十进制
					dec = PEView::HexStringToDec((char*)vecSegTag[2].c_str());
					PEView::RVA_To_VA(dec);
				}
			}

			// ----------------------------------------------------------------------
			// 解析一个参数
			// ----------------------------------------------------------------------
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Dos")
			{
				PEView::ShowDosHead();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Nt")
			{
				PEView::ShowNtHead();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "DataDirectory")
			{
				PEView::ShowOptionalDataDirectoryInfo();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Section")
			{
				PEView::ShowSection();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Import")
			{
				PEView::ShowImportAll();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "ImportDll")
			{
				PEView::ShowImportByDll();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Export")
			{
				PEView::ShowExport();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "FixRelocPage")
			{
				PEView::ShowFixRelocPage();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "FixReloc")
			{
				PEView::ShowFixReloc((char*)"all");
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Resource")
			{
				PEView::ShowResource();
			}
			else if (vecSegTag.size() == 1 && vecSegTag[0] == "Protection")
			{
				PEView::ModuleStatus();
			}

			else
			{
				Help();
			}
		}
	}
	return 0;
}