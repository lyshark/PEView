#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE
#define MG_WIN32 1

#include <windows.h>
#include <winsock2.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <atlconv.h>
#include <time.h> 
#include <sstream>
#include <cstdio>   
#include <cstdint> 
#include <inttypes.h>
#include <algorithm>
#include <signal.h>
#include <process.h>
#include <capstone/capstone.h>
#include "mongoose.h"
#include "cJSON.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib,"capstone64.lib")

// --------------------------------------------------
// 全局变量声明（包含文件映射资源句柄）
// --------------------------------------------------
CHAR GlobalFilePath[2048] = { 0 };
DWORD64 GlobalFileSize = 0;
DWORD64 GlobalFileBase = 0;
BOOL IsOpen = 0;

// 文件映射资源句柄（新增，用于管理生命周期）
HANDLE Global_hFile = INVALID_HANDLE_VALUE;
HANDLE Global_hMapFile = NULL;
HANDLE Global_lpMapAddress = NULL;

// PE结构指针
PIMAGE_DOS_HEADER DosHeader = nullptr;
PIMAGE_NT_HEADERS64 NtHeader = nullptr;
PIMAGE_FILE_HEADER FileHead = nullptr;
PIMAGE_SECTION_HEADER pSection = nullptr;

// --------------------------------------------------
// 常量定义
// --------------------------------------------------
#define IMAGE_REL_BASED_ABSOLUTE    0x00
#define IMAGE_REL_BASED_HIGH        0x01
#define IMAGE_REL_BASED_LOW         0x02
#define IMAGE_REL_BASED_HIGHLOW     0x03
#define IMAGE_REL_BASED_REL32       0x04
#define IMAGE_REL_BASED_DIR64       0x0A
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#define IMAGE_SUBSYSTEM_WINDOWS_DRIVER 0x000B
#define IMAGE_SUBSYSTEM_WINDOWS_NATIVE 0x0001
#define IMAGE_DLLCHARACTERISTICS_NO_UAC_DLL 0x0040
#define IMAGE_DLLCHARACTERISTICS_ISOLATION 0x0020

struct TypeOffset
{
	WORD Offset : 12;
	WORD Type : 4;
};

static char* szResName[0x11] = {
	0, (char*)"Mouse Pointer", (char*)"Bitmap", (char*)"Icon", (char*)"Menu",
	(char*)"Dialog Box", (char*)"String Table", (char*)"Font Directory", (char*)"Font",
	(char*)"Accelerator", (char*)"Unformatted Resource", (char*)"Message Table", (char*)"Mouse Pointer Group",
	(char*)"Plug and Play Resource", (char*)"Icon Group", (char*)"Reserved/Custom Type", (char*)"Version Information"
};

// 存放反汇编数据
typedef struct
{
	int OpCodeSize;               // 机器码长度
	int OpStringSize;             // 反汇编长度
	unsigned long long Address;   // 相对地址
	unsigned char OpCode[16];     // 机器码
	char OpString[256];           // 反汇编
}MyStruct;

// --------------------------------------------------
// 请求类型及数据结构
// --------------------------------------------------
enum class RequestType
{
	Unknown,
	PEView_Open,
	PEView_ShowFileBasicInfo,
	PEView_ShowDosHead,
	PEView_ShowNtHead,
	PEView_ShowSection,
	PEView_ShowOptionalDataDirectory,
	PEView_ShowImportByDll,
	PEView_ShowImportByName,
	PEView_ShowImportByFunction,
	PEView_ShowImportAll,
	PEView_ShowExport,
	PEView_ShowFixRelocPage,
	PEView_ShowFixReloc,
	PEView_ShowResource,
	PEView_VA_To_FOA,
	PEView_RVA_To_FOA,
	PEView_FOA_To_VA,
	PEView_VA_To_RVA,
	PEView_RVA_To_VA,
	PEView_GetHexASCII,
	PEView_SearchSignature,
	PEView_SearchString,
	PEView_ModuleStatus,
	PEView_GetProcessAddress,
	PEView_DisassembleCode,
	PEView_AddCalculator,
	PEView_SubCalculator,
	PEView_Close
};

// 辅助函数：将字符串转换为long long（支持十进制/十六进制）
static long long str_to_ll(const std::string& s, bool& success)
{
	success = false;
	if (s.empty()) return 0;

	char* endptr = nullptr;
	errno = 0;
	long long val = 0;
	// 处理十六进制（0x前缀）
	if (s.substr(0, 2) == "0x" || s.substr(0, 2) == "0X")
	{
		val = _strtoi64(s.c_str() + 2, &endptr, 16);
	}
	else
	{
		val = _strtoi64(s.c_str(), &endptr, 10);
	}
	// 校验转换结果（无无效字符、无溢出）
	if (*endptr == '\0' && errno == 0)
	{
		success = true;
		return val;
	}
	return 0;
}

// 优化辅助函数：字符串转long long（支持十进制/十六进制，适配大偏移）
static long long str_to_longlong(const std::string& s, bool& success)
{
	success = false;
	if (s.empty()) return 0;

	char* endptr = nullptr;
	errno = 0;
	long long val = 0;
	// 十六进制（0x/0X前缀）
	if (s.size() >= 2 && ((s[0] == '0' && s[1] == 'x') || (s[0] == '0' && s[1] == 'X')))
	{
		val = _strtoi64(s.c_str() + 2, &endptr, 16);
	}
	// 十进制
	else
	{
		val = _strtoi64(s.c_str(), &endptr, 10);
	}
	// 校验：无无效字符且无溢出
	if (*endptr == '\0' && errno == 0)
	{
		success = true;
		return val;
	}
	return 0;
}

// 辅助1：将DWORD64转为二进制字符串（无符号，仅输出有效位，如5→"101"）
std::string DWORD64_to_bin(DWORD64 val)
{
	if (val == 0) return "0"; // 特殊处理0值
	char buf[33] = { 0 }; // DWORD64最多32位，加终止符
	int idx = 31;
	while (val > 0 && idx >= 0)
	{
		buf[idx--] = (val & 1) ? '1' : '0';
		val >>= 1;
	}
	return buf + idx + 1; // 返回有效位起始地址
}

// 辅助2：将DWORD64转为八进制字符串（使用sprintf_s确保安全）
std::string DWORD64_to_oct(DWORD64 val)
{
	char buf[12] = { 0 }; // DWORD64最大0xFFFFFFFF→八进制37777777777（11位）
	sprintf_s(buf, "%o", val);
	return buf;
}

// 辅助：校验字符串是否为合法十六进制（支持0x前缀）
static bool is_valid_hex(const std::string& s)
{
	if (s.empty()) return false;
	size_t start = 0;
	// 跳过0x/0X前缀
	if (s.size() >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')))
	{
		start = 2;
		if (start >= s.size()) return false; // 仅"0x"无效
	}
	// 校验剩余字符是否为十六进制（0-9/a-f/A-F）
	for (size_t i = start; i < s.size(); i++)
	{
		char c = s[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
		{
			return false;
		}
	}
	return true;
}

struct RequestData
{
	RequestType type;
	std::vector<std::string> params;
};

struct CJsonDeleter
{
	void operator()(cJSON* ptr) const { if (ptr != nullptr) cJSON_Delete(ptr); }
};
using CJsonPtr = std::unique_ptr<cJSON, CJsonDeleter>;

struct ResponseData
{
	bool success;
	CJsonPtr result;

	ResponseData() : success(false), result(cJSON_CreateObject()) {}
	ResponseData(ResponseData&& other) : success(other.success), result(std::move(other.result)) { other.success = false; }
	ResponseData(const ResponseData&) = delete;
	ResponseData& operator=(const ResponseData&) = delete;
	ResponseData& operator=(ResponseData&& other)
	{
		if (this != &other) { success = other.success; result = std::move(other.result); other.success = false; }
		return *this;
	}
};

// --------------------------------------------------
// 线程工具类
// --------------------------------------------------
class ThreadUtils
{
public:
	using ThreadHandle = HANDLE;
	using MutexHandle = HANDLE;

	static ThreadHandle create_thread(LPTHREAD_START_ROUTINE func)
	{
		return CreateThread(nullptr, 0, func, nullptr, 0, nullptr);
	}

	static void join_thread(ThreadHandle handle)
	{
		if (handle != nullptr) { WaitForSingleObject(handle, INFINITE); CloseHandle(handle); }
	}

	static MutexHandle create_mutex() { return CreateMutex(nullptr, FALSE, nullptr); }
	static void destroy_mutex(MutexHandle mutex) { CloseHandle(mutex); }
};

// --------------------------------------------------
// 服务器上下文类
// --------------------------------------------------
class ServerContext
{
public:
	mg_mgr mgr;
	std::atomic<bool> running;
	ThreadUtils::ThreadHandle thread;
	ThreadUtils::MutexHandle mutex;
	std::string listen_addr;
	class RequestHandler* handler;

	ServerContext() : running(false), handler(nullptr)
	{
		//mg_log_set(-1);
		mutex = ThreadUtils::create_mutex();
		mg_mgr_init(&mgr);
	}

	~ServerContext()
	{
		ThreadUtils::destroy_mutex(mutex);
		mg_mgr_free(&mgr);
	}
};

// --------------------------------------------------
// 提前声明g_server
// --------------------------------------------------
extern std::unique_ptr<ServerContext> g_server;

// --------------------------------------------------
// 请求解析器
// --------------------------------------------------
class RequestParser
{
public:
	static RequestData parse(cJSON* req_json)
	{
		RequestData data;
		data.type = RequestType::Unknown;

		cJSON* class_name = cJSON_GetObjectItemCaseSensitive(req_json, "class");
		cJSON* interface_list = cJSON_GetObjectItemCaseSensitive(req_json, "interface");
		cJSON* param_list = cJSON_GetObjectItemCaseSensitive(req_json, "params");

		if (!cJSON_IsString(class_name) || !class_name->valuestring ||
			!cJSON_IsString(interface_list) || !interface_list->valuestring ||
			!cJSON_IsArray(param_list)) {
			return data;
		}

		for (int i = 0; i < cJSON_GetArraySize(param_list); i++)
		{
			cJSON* param = cJSON_GetArrayItem(param_list, i);
			if (cJSON_IsString(param) && param->valuestring)
			{
				data.params.push_back(param->valuestring);
			}
		}

		std::string cls = class_name->valuestring;
		std::string iface = interface_list->valuestring;

		if (cls == "PE")
		{
			if (iface == "Open") data.type = RequestType::PEView_Open;
			if (iface == "FileBasicInfo") data.type = RequestType::PEView_ShowFileBasicInfo;
			if (iface == "DosHead") data.type = RequestType::PEView_ShowDosHead;
			if (iface == "NtHead") data.type = RequestType::PEView_ShowNtHead;
			if (iface == "Section") data.type = RequestType::PEView_ShowSection;
			if (iface == "OptionalDataDirectory") data.type = RequestType::PEView_ShowOptionalDataDirectory;
			if (iface == "ImportByDll") data.type = RequestType::PEView_ShowImportByDll;
			if (iface == "ImportByName") data.type = RequestType::PEView_ShowImportByName;
			if (iface == "ImportByFunction")
			{
				data.type = RequestType::PEView_ShowImportByFunction;
				// 补充：确保params至少包含函数名/序号，缺失的布尔参数用默认值
				// params[0]：函数名/序号（必填）
				// params[1]：caseSensitive（可选，默认"false"）
				// params[2]：checkOrdinal（可选，默认"true"）
			}

			if (iface == "ImportAll")
			{
				data.type = RequestType::PEView_ShowImportAll;
				// 无需参数，忽略params（即使传入也不处理）
			}
			// ... 原有类型解析 ...
			if (iface == "Export")
			{
				data.type = RequestType::PEView_ShowExport;
				// 无需参数，忽略params（即使传入也不处理）
			}
			// ... 原有类型解析 ...
			if (iface == "FixRelocPage")
			{
				data.type = RequestType::PEView_ShowFixRelocPage;
				// 无需参数，忽略params（即使传入也不处理）
			}

			if (iface == "FixReloc")
			{
				data.type = RequestType::PEView_ShowFixReloc;
				// 校验参数：需1个参数（"all"或十六进制RVA）
				if (data.params.size() != 1 || data.params[0].empty())
				{
					data.type = RequestType::Unknown;  // 标记为无效请求，后续返回Parameter error
					data.params.clear();
					data.params.push_back("Parameter error: 1 parameter needs to be passed in ( all or hexadecimal RVA, such as  0x1000)");
				}
				else
				{
					std::string param = data.params[0];
					// 校验参数格式：要么是"all"，要么是合法十六进制（支持带/不带0x）
					bool isAll = (param == "all" || param == "ALL");
					bool isHexRva = false;
					if (!isAll)
					{
						// 尝试转换为十进制，验证是否为合法十六进制
						char* endptr = nullptr;
						strtoul(param.c_str(), &endptr, 16);
						isHexRva = (*endptr == '\0');  // 无无效字符则为合法
					}
					if (!isAll && !isHexRva)
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Parameter error: 1 parameter needs to be passed in ( all or hexadecimal RVA, such as  0x1000)");
					}
				}
			}

			if (iface == "Resource")
			{
				data.type = RequestType::PEView_ShowResource;
				// 无需参数，忽略多余params
			}


			if (iface == "VAToFOA")
			{
				data.type = RequestType::PEView_VA_To_FOA;
				// 校验参数：需1个有效VA（十进制或十六进制）
				if (data.params.size() != 1 || data.params[0].empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: A target VA (decimal value such as 100 or hexadecimal value such as 0x64) is required to be inputted");
				}
				else
				{
					std::string vaStr = data.params[0];
					// 尝试转换为DWORD64，验证合法性
					char* endptr = nullptr;
					DWORD64 va = 0;
					if (vaStr.substr(0, 2) == "0x" || vaStr.substr(0, 2) == "0X")
					{
						va = strtoul(vaStr.c_str() + 2, &endptr, 16); // 十六进制
					}
					else
					{
						va = strtoul(vaStr.c_str(), &endptr, 10); // 十进制
					}
					// 若转换后有无效字符，标记Parameter error
					if (*endptr != '\0' || va == 0 && vaStr != "0" && vaStr != "0x0")
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Parameter format error: VA must be a valid decimal or hexadecimal value (such as \"100\" or \"0x64\")");
					}
				}
			}

			if (iface == "RVAToFOA")
			{
				data.type = RequestType::PEView_RVA_To_FOA;
				// 校验参数：需1个有效RVA（非0，十进制/十六进制）
				if (data.params.size() != 1 || data.params[0].empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: One target RVA (decimal, such as 4096, or hexadecimal, such as 0x1000) is required to be inputted");
				}
				else
				{
					std::string rvaStr = data.params[0];
					char* endptr = nullptr;
					DWORD64 rva = 0;
					// 转换RVA（支持十进制/十六进制）
					if (rvaStr.substr(0, 2) == "0x" || rvaStr.substr(0, 2) == "0X")
					{
						rva = strtoul(rvaStr.c_str() + 2, &endptr, 16);
					}
					else
					{
						rva = strtoul(rvaStr.c_str(), &endptr, 10);
					}
					// 校验：转换后无无效字符 + RVA≠0
					if (*endptr != '\0')
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Parameter format error: RVA should be a valid decimal or hexadecimal value (such as \"4096\" or \"0x1000\")");
					}
					else if (rva == 0)
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Invalid parameter: RVA cannot be 0 (does not comply with PE specification)");
					}
				}
			}

			if (iface == "FOAToVA")
			{
				data.type = RequestType::PEView_FOA_To_VA;
				// 校验参数：需1个有效FOA（十进制/十六进制，非负）
				if (data.params.size() != 1 || data.params[0].empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: A target FOA (decimal, such as 1024, or hexadecimal, such as 0x400) is required to be inputted");
				}
				else
				{
					std::string foaStr = data.params[0];
					char* endptr = nullptr;
					DWORD64 foa = 0;
					// 转换FOA（支持十进制/十六进制）
					if (foaStr.substr(0, 2) == "0x" || foaStr.substr(0, 2) == "0X")
					{
						foa = strtoul(foaStr.c_str() + 2, &endptr, 16);
					}
					else
					{
						foa = strtoul(foaStr.c_str(), &endptr, 10);
					}
					// 校验：转换后无无效字符（排除字母、符号等）
					if (*endptr != '\0')
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Parameter format error: FOA should be legal decimal or hexadecimal (such as \"1024\" or \"0x400\")");
					}
				}
			}

			if (iface == "VAToRVA")
			{
				data.type = RequestType::PEView_VA_To_RVA;
				// 校验参数：需1个有效VA（十进制/十六进制，非负）
				if (data.params.size() != 1 || data.params[0].empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: 1 target VA needs to be passed in (decimal such as \"4198404\" or hexadecimal such as \"0x401004\")");
				}
				else
				{
					std::string vaStr = data.params[0];
					char* endptr = nullptr;
					DWORD64 va = 0;
					// 转换VA（支持十进制/十六进制）
					if (vaStr.substr(0, 2) == "0x" || vaStr.substr(0, 2) == "0X")
					{
						va = strtoul(vaStr.c_str() + 2, &endptr, 16);
					}
					else
					{
						va = strtoul(vaStr.c_str(), &endptr, 10);
					}
					// 校验：转换后无无效字符（排除字母、符号等）
					if (*endptr != '\0')
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Parameter format error: VA must be legal decimal or hexadecimal (such as \"4198404\" or \"0x401004\")");
					}
				}
			}


			if (iface == "RVAToVA")
			{
				data.type = RequestType::PEView_RVA_To_VA;
				// 校验参数：需1个有效RVA（十进制/十六进制，非负）
				if (data.params.size() != 1 || data.params[0].empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: 1 target RVA needs to be passed in (decimal such as \"4100\" or hexadecimal such as \"0x1004\")");
				}
				else
				{
					std::string rvaStr = data.params[0];
					char* endptr = nullptr;
					DWORD64 rva = 0;
					// 转换RVA（支持十进制/十六进制）
					if (rvaStr.substr(0, 2) == "0x" || rvaStr.substr(0, 2) == "0X")
					{
						rva = strtoul(rvaStr.c_str() + 2, &endptr, 16);
					}
					else
					{
						rva = strtoul(rvaStr.c_str(), &endptr, 10);
					}
					// 校验：转换后无无效字符（排除字母、符号等）
					if (*endptr != '\0')
					{
						data.type = RequestType::Unknown;
						data.params.clear();
						data.params.push_back("Parameter format error: RVA should be legal decimal or hexadecimal (such as \"4100\" or \"0x1004\")");
					}
				}
			}

			if (iface == "HexASCII")
			{
				data.type = RequestType::PEView_GetHexASCII;
				// 校验参数：需2个参数（StartAddr 和 AddrLen）
				if (data.params.size() != 2)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: two parameters need to be passed in (startaddr and addrlen, such as [\"0x0\", \"100\"])");
					return data;
				}

				// 转换并校验StartAddr（≥0）
				bool addrOk = false;
				long long startAddr = str_to_ll(data.params[0], addrOk);
				if (!addrOk || startAddr < 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: startaddr should be non negative decimal/hexadecimal (such as \"0\" or \"0x0\")");
					return data;
				}

				// 转换并校验AddrLen（>0）
				bool lenOk = false;
				long long addrLen = str_to_ll(data.params[1], lenOk);
				if (!lenOk || addrLen <= 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: addrlen should be positive decimal/hexadecimal (such as \"100\" or \"0x64\")");
					return data;
				}

				// 保留转换后的参数（转为字符串，后续业务函数再解析）
				data.params[0] = std::to_string(startAddr);
				data.params[1] = std::to_string(addrLen);
			}


			if (iface == "SearchSignature")
			{
				data.type = RequestType::PEView_SearchSignature;
				// 校验参数数量：需3个（StartAddr, SearchLen, sig_str）
				if (data.params.size() != 3)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: three parameters need to be passed in (startaddr, searchlen, Sigu STR)");
					return data;
				}

				// 校验StartAddr（非负）
				bool addrOk = false;
				long long startAddr = str_to_ll(data.params[0], addrOk);
				if (!addrOk || startAddr < 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: startaddr should be non negative decimal/hexadecimal (such as \"0\" or \"0x0\")");
					return data;
				}

				// 校验SearchLen（>0）
				bool lenOk = false;
				long long searchLen = str_to_ll(data.params[1], lenOk);
				if (!lenOk || searchLen <= 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: searchlen needs to be positive decimal/hexadecimal (such as \"1000\" or \"0x3e8\")");
					return data;
				}

				// 校验sig_str（非空，基础格式：空格分隔的2字符token）
				std::string sigStr = data.params[2];
				if (sigStr.empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: signature string cannot be empty");
					return data;
				}

				// 保留转换后的参数（StartAddr和SearchLen转为十进制字符串，sig_str保留原格式）
				data.params[0] = std::to_string(startAddr);
				data.params[1] = std::to_string(searchLen);
			}

			if (iface == "SearchString")
			{
				data.type = RequestType::PEView_SearchString;
				// 校验参数数量：需3个（StartAddr, SearchLen, target_str）
				if (data.params.size() != 3)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: three parameters need to be passed in（StartAddr, SearchLen, target_str）");
					return data;
				}

				// 1. 校验StartAddr（FOA，非负）
				bool addrOk = false;
				long long startAddr = str_to_ll(data.params[0], addrOk);
				if (!addrOk || startAddr < 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: startaddr (FOA) must be non negative decimal/hexadecimal");
					return data;
				}

				// 2. 校验SearchLen（正整数）
				bool lenOk = false;
				long long searchLen = str_to_ll(data.params[1], lenOk);
				if (!lenOk || searchLen <= 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: searchlen needs to be positive decimal/hexadecimal");
					return data;
				}

				// 3. 校验target_str（非空ASCII字符串）
				std::string targetStr = data.params[2];
				if (targetStr.empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: the target string (target_str) cannot be empty (only ASCII is supported)");
					return data;
				}

				// 保留转换后的参数（StartAddr和SearchLen转十进制字符串，target_str保留原格式）
				data.params[0] = std::to_string(startAddr);
				data.params[1] = std::to_string(searchLen);
			}

			if (iface == "ModuleStatus")
			{
				data.type = RequestType::PEView_ModuleStatus;
				// 允许params为空，无需额外参数
				if (!data.params.empty())
				{
					// printf("[!] 提示：ModuleStatus接口无需参数，传入的参数将被忽略\n");
				}
			}

			if (iface == "GetProcessAddress")
			{
				data.type = RequestType::PEView_GetProcessAddress;
				// 校验参数：需2个非空参数（DllName, Function）
				if (data.params.size() != 2)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: two parameters need to be passed in (dllname, function");
					return data;
				}
				// 校验参数非空
				std::string dllName = data.params[0];
				std::string funcName = data.params[1];
				if (dllName.empty() || funcName.empty())
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: DLL name or function name cannot be empty");
					return data;
				}
				// 保留原始参数（无需转换，直接传递给业务函数）
			}

			if (iface == "DisassembleCode")
			{
				data.type = RequestType::PEView_DisassembleCode;
				// 校验参数：需2个参数（StartFOA, DisasmLen）
				if (data.params.size() != 2)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: two parameters need to be passed in (startfoa, disasmlen)");
					return data;
				}

				// 校验StartFOA（非负）
				bool foaOk = false;
				long long startFOA = str_to_longlong(data.params[0], foaOk);
				if (!foaOk || startFOA < 0)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: startfoa must be non negative decimal/hexadecimal");
					return data;
				}

				// 校验DisasmLen（正整数）
				bool lenOk = false;
				long long disasmLen = str_to_longlong(data.params[1], lenOk);
				if (!lenOk || disasmLen <= 0 || disasmLen > 0x100000) // 限制最大反汇编长度（1MB），避免内存溢出
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Parameter error: disasmlen should be 1~1048576 (1MB) decimal/hexadecimal");
					return data;
				}

				// 保留转换后的参数（转为字符串，业务函数再解析）
				data.params[0] = std::to_string(startFOA);
				data.params[1] = std::to_string(disasmLen);
			}


			// 加法计算器参数解析
			if (iface == "AddCalculator")
			{
				data.type = RequestType::PEView_AddCalculator;
				// 校验参数：需2个非空合法十六进制
				if (data.params.size() != 2)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Addition calculator parameter error: two hexadecimal parameters need to be passed in");
					return data;
				}
				std::string x = data.params[0], y = data.params[1];
				if (!is_valid_hex(x))
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Addition calculator parameter error: X (" + x + ") is not a legal hex");
					return data;
				}
				if (!is_valid_hex(y))
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Addition calculator parameter error: Y (" + y + ") is not a legal hex");
					return data;
				}
			}
			// 减法计算器参数解析
			if (iface == "SubCalculator")
			{
				data.type = RequestType::PEView_SubCalculator;
				// 校验逻辑与加法完全一致
				if (data.params.size() != 2)
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Subtraction calculator parameter error: two hexadecimal parameters need to be passed in");
					return data;
				}
				std::string x = data.params[0], y = data.params[1];
				if (!is_valid_hex(x))
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Subtraction calculator parameter error: X (" + x + ") is not a legal hex");
					return data;
				}
				if (!is_valid_hex(y))
				{
					data.type = RequestType::Unknown;
					data.params.clear();
					data.params.push_back("Subtraction calculator parameter error: Y (" + y + ") is not a legal hex");
					return data;
				}
			}

			if (iface == "Close") data.type = RequestType::PEView_Close;
		}

		return data;
	}
};

// --------------------------------------------------
// PE视图处理器
// --------------------------------------------------
class PEViewHandler
{
public:
	// 打开PE文件
	static ResponseData handle_open(const std::vector<std::string>& params)
	{
		ResponseData response;

		// 加锁保护全局变量
		WaitForSingleObject(g_server->mutex, INFINITE);

		// 先释放可能残留的资源
		release_resources();

		// 参数校验
		if (params.size() != 1)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Parameter error: A PE file path is required to be inputted");
			response.success = false;
			ReleaseMutex(g_server->mutex);
			return response;
		}
		const std::string& filePath = params[0];
		LPCSTR FileName = filePath.c_str();

		// 打开文件
		Global_hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (Global_hFile == INVALID_HANDLE_VALUE)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to open the file");
			response.success = false;
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 获取文件大小
		GlobalFileSize = GetFileSize(Global_hFile, NULL);
		if (GlobalFileSize == INVALID_FILE_SIZE)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to obtain the file size");
			response.success = false;
			CloseHandle(Global_hFile);
			Global_hFile = INVALID_HANDLE_VALUE;
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 创建文件映射
		Global_hMapFile = CreateFileMapping(Global_hFile, NULL, PAGE_READONLY, 0, GlobalFileSize, NULL);
		if (Global_hMapFile == NULL)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to create mapping object");
			response.success = false;
			CloseHandle(Global_hFile);
			Global_hFile = INVALID_HANDLE_VALUE;
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 映射文件视图（关键：不立即释放，保存到全局变量）
		Global_lpMapAddress = MapViewOfFile(Global_hMapFile, FILE_MAP_READ, 0, 0, GlobalFileSize);
		if (Global_lpMapAddress == NULL)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to map file view");
			response.success = false;
			CloseHandle(Global_hMapFile);
			Global_hMapFile = NULL;
			CloseHandle(Global_hFile);
			Global_hFile = INVALID_HANDLE_VALUE;
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 解析PE结构
		GlobalFileBase = (DWORD64)Global_lpMapAddress;
		DosHeader = (PIMAGE_DOS_HEADER)GlobalFileBase;

		if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The file does not adhere to the DOS structure");
			response.success = false;
			release_resources(); // 错误时释放资源
			ReleaseMutex(g_server->mutex);
			return response;
		}

		NtHeader = (PIMAGE_NT_HEADERS64)(GlobalFileBase + DosHeader->e_lfanew);
		if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The file does not belong to PE structure");
			response.success = false;
			release_resources();
			ReleaseMutex(g_server->mutex);
			return response;
		}

		if (NtHeader->OptionalHeader.Magic != 0x020B)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unable to debug non-32-bit/32+bit PE files");
			response.success = false;
			release_resources();
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 初始化成功，标记文件为打开状态
		FileHead = &NtHeader->FileHeader;
		pSection = IMAGE_FIRST_SECTION(NtHeader);
		IsOpen = 1;
		strcpy_s(GlobalFilePath, _countof(GlobalFilePath), FileName);

		// 构建成功响应
		response.success = true;
		cJSON_AddStringToObject(response.result.get(), "message", "The PE file has been successfully opened");
		cJSON_AddStringToObject(response.result.get(), "file_path", GlobalFilePath);
		cJSON_AddNumberToObject(response.result.get(), "file_size", GlobalFileSize);

		ReleaseMutex(g_server->mutex);
		return response;
	}

	// 新增：处理“获取文件基本信息”请求
	static ResponseData handle_show_file_basic_info(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 校验前置条件（文件已打开、PE结构指针有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The PE file has not been opened. Please call Open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (DosHeader == nullptr || NtHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "The PE structure pointer is invalid, and the file may be corrupted");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 构建JSON根对象（按原逻辑拆分为3个模块：文件基本信息、PE结构标识、可选头信息）
			// 2.1 模块1：文件基本信息（路径、大小、属性、时间、映射基址）
			cJSON* file_basic_info = cJSON_CreateObject();
			if (file_basic_info == nullptr) throw std::bad_alloc();

			// 2.1.1 文件路径与大小
			cJSON_AddStringToObject(file_basic_info, "file_path", GlobalFilePath);
			double fileSizeKB = (double)GlobalFileSize / 1024;
			double fileSizeMB = fileSizeKB / 1024;
			cJSON_AddNumberToObject(file_basic_info, "file_size_bytes", GlobalFileSize);
			cJSON_AddNumberToObject(file_basic_info, "file_size_kb", fileSizeKB);
			cJSON_AddNumberToObject(file_basic_info, "file_size_mb", fileSizeMB);

			// 2.1.2 文件属性（只读/隐藏/系统/归档）
			DWORD64 fileAttr = GetFileAttributesA(GlobalFilePath);
			std::string attrStr;
			if (fileAttr & FILE_ATTRIBUTE_READONLY) attrStr += "read-only; ";
			if (fileAttr & FILE_ATTRIBUTE_HIDDEN) attrStr += "hide; ";
			if (fileAttr & FILE_ATTRIBUTE_SYSTEM) attrStr += "system; ";
			if (fileAttr & FILE_ATTRIBUTE_ARCHIVE) attrStr += "file; ";
			if (attrStr.empty()) attrStr = "normal";
			cJSON_AddStringToObject(file_basic_info, "file_attributes", attrStr.c_str());

			// 2.1.3 文件时间（创建时间、修改时间）
			HANDLE hFile = CreateFileA(GlobalFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				cJSON_AddStringToObject(file_basic_info, "create_time", "Get failed");
				cJSON_AddStringToObject(file_basic_info, "modify_time", "Get failed");
			}
			else
			{
				FILETIME createTime, modifyTime, accessTime;
				SYSTEMTIME localCreateTime, localModifyTime;
				GetFileTime(hFile, &createTime, &accessTime, &modifyTime);
				FileTimeToLocalFileTime(&createTime, &createTime);
				FileTimeToSystemTime(&createTime, &localCreateTime);
				FileTimeToLocalFileTime(&modifyTime, &modifyTime);
				FileTimeToSystemTime(&modifyTime, &localModifyTime);

				// 格式化时间为 "YYYY-MM-DD HH:MM:SS"
				char createTimeStr[32] = { 0 };
				sprintf_s(createTimeStr, "%04d-%02d-%02d %02d:%02d:%02d",
					localCreateTime.wYear, localCreateTime.wMonth, localCreateTime.wDay,
					localCreateTime.wHour, localCreateTime.wMinute, localCreateTime.wSecond);
				cJSON_AddStringToObject(file_basic_info, "create_time", createTimeStr);

				char modifyTimeStr[32] = { 0 };
				sprintf_s(modifyTimeStr, "%04d-%02d-%02d %02d:%02d:%02d",
					localModifyTime.wYear, localModifyTime.wMonth, localModifyTime.wDay,
					localModifyTime.wHour, localModifyTime.wMinute, localModifyTime.wSecond);
				cJSON_AddStringToObject(file_basic_info, "modify_time", modifyTimeStr);

				CloseHandle(hFile);  // 及时释放文件句柄
			}

			// 2.1.4 映射基址
			cJSON_AddStringToObject(file_basic_info, "map_base_address", DexToHex(GlobalFileBase).c_str());
			cJSON_AddNumberToObject(file_basic_info, "map_base_address_dec", GlobalFileBase);


			// 2.2 模块2：PE结构标识（DOS头、NT头基础信息）
			cJSON* pe_identifier = cJSON_CreateObject();
			if (pe_identifier == nullptr) throw std::bad_alloc();

			// 2.2.1 DOS头关键信息
			cJSON_AddStringToObject(pe_identifier, "dos_signature_hex", DexToHex(DosHeader->e_magic).c_str());
			cJSON_AddNumberToObject(pe_identifier, "dos_signature_dec", DosHeader->e_magic);
			cJSON_AddStringToObject(pe_identifier, "dos_signature_desc",
				DosHeader->e_magic == IMAGE_DOS_SIGNATURE ? "Valid DOS signature (MZ)" : "Invalid DOS signature");
			cJSON_AddStringToObject(pe_identifier, "pe_header_offset_hex", DexToHex(DosHeader->e_lfanew).c_str());
			cJSON_AddNumberToObject(pe_identifier, "pe_header_offset_dec", DosHeader->e_lfanew);

			// 2.2.2 NT头基础信息
			cJSON_AddStringToObject(pe_identifier, "nt_signature_hex", DexToHex(NtHeader->Signature).c_str());
			cJSON_AddNumberToObject(pe_identifier, "nt_signature_dec", NtHeader->Signature);
			cJSON_AddStringToObject(pe_identifier, "nt_signature_desc",
				NtHeader->Signature == IMAGE_NT_SIGNATURE ? "Valid PE signature (pe00)" : "Invalid PE signature");

			// 机器类型（x86/x64/ARM/未知）
			const char* machineDesc = "Unknown schema";
			switch (NtHeader->FileHeader.Machine)
			{
			case IMAGE_FILE_MACHINE_I386:  machineDesc = "x86 (32bit)"; break;
			case IMAGE_FILE_MACHINE_AMD64: machineDesc = "x64 (64bit)"; break;
			case IMAGE_FILE_MACHINE_ARM:   machineDesc = "Arm architecture"; break;
			}
			cJSON_AddStringToObject(pe_identifier, "machine_type_hex", DexToHex(NtHeader->FileHeader.Machine).c_str());
			cJSON_AddNumberToObject(pe_identifier, "machine_type_dec", NtHeader->FileHeader.Machine);
			cJSON_AddStringToObject(pe_identifier, "machine_type_desc", machineDesc);

			// 节区数量
			cJSON_AddNumberToObject(pe_identifier, "section_count", NtHeader->FileHeader.NumberOfSections);

			// NT头时间戳（转换为可读时间）
			SYSTEMTIME timestampSysTime;
			FILETIME timestampFileTime;
			ULARGE_INTEGER uli;
			uli.LowPart = NtHeader->FileHeader.TimeDateStamp;
			uli.HighPart = 0;
			timestampFileTime.dwLowDateTime = uli.LowPart;
			timestampFileTime.dwHighDateTime = uli.HighPart;
			FileTimeToLocalFileTime(&timestampFileTime, &timestampFileTime);
			FileTimeToSystemTime(&timestampFileTime, &timestampSysTime);
			char timestampStr[32] = { 0 };
			sprintf_s(timestampStr, "%04d-%02d-%02d %02d:%02d:%02d",
				timestampSysTime.wYear, timestampSysTime.wMonth, timestampSysTime.wDay,
				timestampSysTime.wHour, timestampSysTime.wMinute, timestampSysTime.wSecond);
			cJSON_AddStringToObject(pe_identifier, "nt_timestamp_hex", DexToHex(NtHeader->FileHeader.TimeDateStamp).c_str());
			cJSON_AddNumberToObject(pe_identifier, "nt_timestamp_dec", NtHeader->FileHeader.TimeDateStamp);
			cJSON_AddStringToObject(pe_identifier, "nt_timestamp_desc", timestampStr);

			// NT头特性标记（可执行/DLL/系统文件/移除调试信息）
			std::string characDesc;
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) characDesc += "Executable; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) characDesc += "DLL File; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) characDesc += "System files; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) characDesc += "Remove debug information; ";
			if (characDesc.empty()) characDesc = "No special features";
			cJSON_AddStringToObject(pe_identifier, "nt_characteristics_hex", DexToHex(NtHeader->FileHeader.Characteristics).c_str());
			cJSON_AddNumberToObject(pe_identifier, "nt_characteristics_dec", NtHeader->FileHeader.Characteristics);
			cJSON_AddStringToObject(pe_identifier, "nt_characteristics_desc", characDesc.c_str());


			// 2.3 模块3：可选头关键信息
			cJSON* optional_header = cJSON_CreateObject();
			if (optional_header == nullptr) throw std::bad_alloc();

			// 入口点RVA、镜像基址、图像大小
			cJSON_AddStringToObject(optional_header, "entry_point_rva_hex", DexToHex(NtHeader->OptionalHeader.AddressOfEntryPoint).c_str());
			cJSON_AddNumberToObject(optional_header, "entry_point_rva_dec", NtHeader->OptionalHeader.AddressOfEntryPoint);
			cJSON_AddStringToObject(optional_header, "image_base_hex", DexToHex(NtHeader->OptionalHeader.ImageBase).c_str());
			cJSON_AddNumberToObject(optional_header, "image_base_dec", NtHeader->OptionalHeader.ImageBase);
			cJSON_AddStringToObject(optional_header, "image_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfImage).c_str());
			cJSON_AddNumberToObject(optional_header, "image_size_dec", NtHeader->OptionalHeader.SizeOfImage);

			// 节区对齐、文件对齐
			cJSON_AddStringToObject(optional_header, "section_alignment_hex", DexToHex(NtHeader->OptionalHeader.SectionAlignment).c_str());
			cJSON_AddNumberToObject(optional_header, "section_alignment_dec", NtHeader->OptionalHeader.SectionAlignment);
			cJSON_AddStringToObject(optional_header, "file_alignment_hex", DexToHex(NtHeader->OptionalHeader.FileAlignment).c_str());
			cJSON_AddNumberToObject(optional_header, "file_alignment_dec", NtHeader->OptionalHeader.FileAlignment);

			// 子系统（GUI/CUI/Native/未知）
			const char* subsystemDesc = "未知子系统";
			switch (NtHeader->OptionalHeader.Subsystem)
			{
			case IMAGE_SUBSYSTEM_WINDOWS_GUI:   subsystemDesc = "Windows GUI (Graphical interface)"; break;
			case IMAGE_SUBSYSTEM_WINDOWS_CUI:   subsystemDesc = "Windows CUI (Console Application )"; break;
			case IMAGE_SUBSYSTEM_NATIVE:        subsystemDesc = "Native (System kernel mode)"; break;
			}
			cJSON_AddStringToObject(optional_header, "subsystem_hex", DexToHex(NtHeader->OptionalHeader.Subsystem).c_str());
			cJSON_AddNumberToObject(optional_header, "subsystem_dec", NtHeader->OptionalHeader.Subsystem);
			cJSON_AddStringToObject(optional_header, "subsystem_desc", subsystemDesc);

			// DLL特性（ASLR/DEP/不使用SEH）
			std::string dllCharacDesc;
			if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) dllCharacDesc += "ASLR support; ";
			if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) dllCharacDesc += "DEP support; ";
			if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) dllCharacDesc += "Not used SEH; ";
			if (dllCharacDesc.empty()) dllCharacDesc = "No special features";
			cJSON_AddStringToObject(optional_header, "dll_characteristics_hex", DexToHex(NtHeader->OptionalHeader.DllCharacteristics).c_str());
			cJSON_AddNumberToObject(optional_header, "dll_characteristics_dec", NtHeader->OptionalHeader.DllCharacteristics);
			cJSON_AddStringToObject(optional_header, "dll_characteristics_desc", dllCharacDesc.c_str());

			// 栈大小、堆大小（保留/提交）
			cJSON_AddStringToObject(optional_header, "stack_reserve_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfStackReserve).c_str());
			cJSON_AddNumberToObject(optional_header, "stack_reserve_size_dec", NtHeader->OptionalHeader.SizeOfStackReserve);
			cJSON_AddStringToObject(optional_header, "stack_commit_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfStackCommit).c_str());
			cJSON_AddNumberToObject(optional_header, "stack_commit_size_dec", NtHeader->OptionalHeader.SizeOfStackCommit);
			cJSON_AddStringToObject(optional_header, "heap_reserve_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfHeapReserve).c_str());
			cJSON_AddNumberToObject(optional_header, "heap_reserve_size_dec", NtHeader->OptionalHeader.SizeOfHeapReserve);
			cJSON_AddStringToObject(optional_header, "heap_commit_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfHeapCommit).c_str());
			cJSON_AddNumberToObject(optional_header, "heap_commit_size_dec", NtHeader->OptionalHeader.SizeOfHeapCommit);


			// 3. 组装JSON响应
			cJSON_AddItemToObject(response.result.get(), "file_basic_info", file_basic_info);
			cJSON_AddItemToObject(response.result.get(), "pe_identifier", pe_identifier);
			cJSON_AddItemToObject(response.result.get(), "optional_header_info", optional_header);
			cJSON_AddStringToObject(response.result.get(), "message", "PE File basic information parsing succeeded");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build response data");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 显示DOS头信息
	static ResponseData handle_show_dos_head(const std::vector<std::string>& params)
	{
		ResponseData response;

		WaitForSingleObject(g_server->mutex, INFINITE);

		// 校验文件状态
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (DosHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "DOS header pointer is invalid, file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 创建DOS头JSON对象
		cJSON* dos_head = cJSON_CreateObject();
		if (dos_head == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Failed to create DOS header JSON object (out of memory)");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 添加字段的lambda函数
		auto add_field = [&](const char* key, DWORD64 value) {
			cJSON* field = cJSON_CreateObject();
			if (field == nullptr) throw std::bad_alloc();
			char hex_str[32] = { 0 };
			sprintf_s(hex_str, "0x%016llX", value);
			cJSON_AddStringToObject(field, "hex", hex_str);
			cJSON_AddNumberToObject(field, "dec", value);
			cJSON_AddItemToObject(dos_head, key, field);
		};

		try
		{
			// 基本字段
			add_field("e_magic", DosHeader->e_magic);
			add_field("e_cblp", DosHeader->e_cblp);
			add_field("e_cp", DosHeader->e_cp);
			add_field("e_crlc", DosHeader->e_crlc);
			add_field("e_cparhdr", DosHeader->e_cparhdr);
			add_field("e_minalloc", DosHeader->e_minalloc);
			add_field("e_maxalloc", DosHeader->e_maxalloc);
			add_field("e_ss", DosHeader->e_ss);
			add_field("e_sp", DosHeader->e_sp);
			add_field("e_csum", DosHeader->e_csum);
			add_field("e_ip", DosHeader->e_ip);
			add_field("e_cs", DosHeader->e_cs);
			add_field("e_lfarlc", DosHeader->e_lfarlc);
			add_field("e_ovno", DosHeader->e_ovno);

			// e_res数组
			cJSON* e_res = cJSON_CreateArray();
			if (e_res == nullptr) throw std::bad_alloc();
			for (int i = 0; i < 4; i++)
			{
				cJSON* item = cJSON_CreateObject();
				if (item == nullptr) { cJSON_Delete(e_res); cJSON_Delete(dos_head); throw std::bad_alloc(); }
				char hex_str[32] = { 0 };
				sprintf_s(hex_str, "0x%016llX", DosHeader->e_res[i]);
				cJSON_AddStringToObject(item, "hex", hex_str);
				cJSON_AddNumberToObject(item, "dec", DosHeader->e_res[i]);
				cJSON_AddItemToArray(e_res, item);
			}
			cJSON_AddItemToObject(dos_head, "e_res", e_res);

			// OEM字段
			add_field("e_oemid", DosHeader->e_oemid);
			add_field("e_oeminfo", DosHeader->e_oeminfo);

			// e_res2数组
			cJSON* e_res2 = cJSON_CreateArray();
			if (e_res2 == nullptr) throw std::bad_alloc();
			for (int i = 0; i < 10; i++)
			{
				cJSON* item = cJSON_CreateObject();
				if (item == nullptr) { cJSON_Delete(e_res2); cJSON_Delete(dos_head); throw std::bad_alloc(); }
				char hex_str[32] = { 0 };
				sprintf_s(hex_str, "0x%016llX", DosHeader->e_res2[i]);
				cJSON_AddStringToObject(item, "hex", hex_str);
				cJSON_AddNumberToObject(item, "dec", DosHeader->e_res2[i]);
				cJSON_AddItemToArray(e_res2, item);
			}
			cJSON_AddItemToObject(dos_head, "e_res2", e_res2);

			// PE头偏移
			add_field("e_lfanew", DosHeader->e_lfanew);

			// 构建成功响应
			response.success = true;
			cJSON_AddItemToObject(response.result.get(), "dos_header", dos_head);
			cJSON_AddStringToObject(response.result.get(), "message", "DOS header parsing succeeded");
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to parse DOS header");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);
		return response;
	}

	// 新增：处理“获取NT头信息”请求
	static ResponseData handle_show_nt_head(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 校验前置条件（文件已打开、NtHeader指针有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid NT header pointer, file may be corrupted");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 构建JSON根对象（按原逻辑分3个模块：NT签名、文件头、可选头）
			cJSON* nt_head_root = cJSON_CreateObject();
			if (nt_head_root == nullptr) throw std::bad_alloc();


			// ---------------------------- 模块1：NT签名 ----------------------------
			cJSON* nt_signature = cJSON_CreateObject();
			if (nt_signature == nullptr) throw std::bad_alloc();

			cJSON_AddStringToObject(nt_signature, "nt_signature_hex", DexToHex(NtHeader->Signature).c_str());
			cJSON_AddNumberToObject(nt_signature, "nt_signature_dec", NtHeader->Signature);
			cJSON_AddStringToObject(nt_signature, "nt_signature_desc",
				(NtHeader->Signature == IMAGE_NT_SIGNATURE) ? "Valid PE signature(PE00)" : "Invalid PE signature");

			cJSON_AddItemToObject(nt_head_root, "nt_signature", nt_signature);


			// ---------------------------- 模块2：文件头（IMAGE_FILE_HEADER） ----------------------------
			cJSON* image_file_header = cJSON_CreateObject();
			if (image_file_header == nullptr) throw std::bad_alloc();

			// 2.1 运行平台（Machine）
			const char* machineDesc = "Unknown platform";
			switch (NtHeader->FileHeader.Machine)
			{
			case IMAGE_FILE_MACHINE_I386:  machineDesc = "x86 (32bit)"; break;
			case IMAGE_FILE_MACHINE_AMD64: machineDesc = "x64 (64bit)"; break;
			case IMAGE_FILE_MACHINE_ARM:   machineDesc = "ARM architecture"; break;
			}
			cJSON_AddStringToObject(image_file_header, "machine_hex", DexToHex(NtHeader->FileHeader.Machine).c_str());
			cJSON_AddNumberToObject(image_file_header, "machine_dec", NtHeader->FileHeader.Machine);
			cJSON_AddStringToObject(image_file_header, "machine_desc", machineDesc);

			// 2.2 区段数目
			cJSON_AddStringToObject(image_file_header, "section_count_hex", DexToHex(NtHeader->FileHeader.NumberOfSections).c_str());
			cJSON_AddNumberToObject(image_file_header, "section_count_dec", NtHeader->FileHeader.NumberOfSections);
			cJSON_AddStringToObject(image_file_header, "section_count_desc", "Number of sections contained in PE file");

			// 2.3 时间日期标志（转换为可读时间，处理可能的空指针）
			char timeStr[26] = "Invalid timestamp";
			time_t timestamp = NtHeader->FileHeader.TimeDateStamp;
			struct tm* tm_info = localtime(&timestamp);
			if (tm_info != nullptr)
			{
				asctime_s(timeStr, sizeof(timeStr), tm_info);
				timeStr[strcspn(timeStr, "\n")] = '\0';  // 移除asctime_s自带的换行符
			}
			cJSON_AddStringToObject(image_file_header, "timestamp_hex", DexToHex(NtHeader->FileHeader.TimeDateStamp).c_str());
			cJSON_AddNumberToObject(image_file_header, "timestamp_dec", NtHeader->FileHeader.TimeDateStamp);
			cJSON_AddStringToObject(image_file_header, "timestamp_desc", timeStr);

			// 2.4 特征值（Characteristics）
			std::string characDesc;
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)      characDesc += "Remove relocation; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)     characDesc += "Executable file; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED)   characDesc += "Remove line number; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED)  characDesc += "Remove local symbol; ";
			if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)                  characDesc += "DLL file; ";
			if (characDesc.empty()) characDesc = "No special features";
			cJSON_AddStringToObject(image_file_header, "characteristics_hex", DexToHex(NtHeader->FileHeader.Characteristics).c_str());
			cJSON_AddNumberToObject(image_file_header, "characteristics_dec", NtHeader->FileHeader.Characteristics);
			cJSON_AddStringToObject(image_file_header, "characteristics_desc", characDesc.c_str());

			// 2.5 可选头部大小
			cJSON_AddStringToObject(image_file_header, "size_of_optional_header_hex", DexToHex(NtHeader->FileHeader.SizeOfOptionalHeader).c_str());
			cJSON_AddNumberToObject(image_file_header, "size_of_optional_header_dec", NtHeader->FileHeader.SizeOfOptionalHeader);
			cJSON_AddStringToObject(image_file_header, "size_of_optional_header_desc", "Byte size of optional header");

			// 2.6 符号数量与符号表指针
			cJSON_AddStringToObject(image_file_header, "number_of_symbols_hex", DexToHex(NtHeader->FileHeader.NumberOfSymbols).c_str());
			cJSON_AddNumberToObject(image_file_header, "number_of_symbols_dec", NtHeader->FileHeader.NumberOfSymbols);
			cJSON_AddStringToObject(image_file_header, "number_of_symbols_desc", "Number of symbols in the symbol table");

			cJSON_AddStringToObject(image_file_header, "pointer_to_symbol_table_hex", DexToHex(NtHeader->FileHeader.PointerToSymbolTable).c_str());
			cJSON_AddNumberToObject(image_file_header, "pointer_to_symbol_table_dec", NtHeader->FileHeader.PointerToSymbolTable);
			cJSON_AddStringToObject(image_file_header, "pointer_to_symbol_table_desc", "Offset of symbol table in file");

			cJSON_AddItemToObject(nt_head_root, "image_file_header", image_file_header);


			// ---------------------------- 模块3：可选头（PIMAGE_OPTIONAL_HEADER64） ----------------------------
			cJSON* image_optional_header = cJSON_CreateObject();
			if (image_optional_header == nullptr) throw std::bad_alloc();

			// 3.1 入口点（RVA + 计算VA）
			DWORD64 entryVA = NtHeader->OptionalHeader.ImageBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
			cJSON_AddStringToObject(image_optional_header, "entry_point_rva_hex", DexToHex(NtHeader->OptionalHeader.AddressOfEntryPoint).c_str());
			cJSON_AddNumberToObject(image_optional_header, "entry_point_rva_dec", NtHeader->OptionalHeader.AddressOfEntryPoint);
			cJSON_AddStringToObject(image_optional_header, "entry_point_va_hex", DexToHex(entryVA).c_str());
			cJSON_AddNumberToObject(image_optional_header, "entry_point_va_dec", entryVA);
			cJSON_AddStringToObject(image_optional_header, "entry_point_desc", "Virtual address of entry point (VA=mirror base address+RVA)");

			// 3.2 镜像基址与镜像大小
			cJSON_AddStringToObject(image_optional_header, "image_base_hex", DexToHex(NtHeader->OptionalHeader.ImageBase).c_str());
			cJSON_AddNumberToObject(image_optional_header, "image_base_dec", NtHeader->OptionalHeader.ImageBase);
			cJSON_AddStringToObject(image_optional_header, "image_base_desc", "Preferred base address to load into memory");

			cJSON_AddStringToObject(image_optional_header, "size_of_image_hex", DexToHex(NtHeader->OptionalHeader.SizeOfImage).c_str());
			cJSON_AddNumberToObject(image_optional_header, "size_of_image_dec", NtHeader->OptionalHeader.SizeOfImage);
			cJSON_AddStringToObject(image_optional_header, "size_of_image_desc", "Size of the entire image in memory (bytes)");

			// 3.3 代码/数据基址与大小
			cJSON_AddStringToObject(image_optional_header, "base_of_code_hex", DexToHex(NtHeader->OptionalHeader.BaseOfCode).c_str());
			cJSON_AddNumberToObject(image_optional_header, "base_of_code_dec", NtHeader->OptionalHeader.BaseOfCode);
			cJSON_AddStringToObject(image_optional_header, "base_of_code_desc", "Start relative virtual address of code segment");

			//cJSON_AddStringToObject(image_optional_header, "base_of_data_hex", DexToHex(NtHeader->OptionalHeader.BaseOfData).c_str());
			//cJSON_AddNumberToObject(image_optional_header, "base_of_data_dec", NtHeader->OptionalHeader.BaseOfData);
			//cJSON_AddStringToObject(image_optional_header, "base_of_data_desc", "Start relative virtual address of data segment");

			cJSON_AddStringToObject(image_optional_header, "size_of_code_hex", DexToHex(NtHeader->OptionalHeader.SizeOfCode).c_str());
			cJSON_AddNumberToObject(image_optional_header, "size_of_code_dec", NtHeader->OptionalHeader.SizeOfCode);
			cJSON_AddStringToObject(image_optional_header, "size_of_code_desc", "Total size of code snippet (bytes)");

			cJSON_AddStringToObject(image_optional_header, "size_of_initialized_data_hex", DexToHex(NtHeader->OptionalHeader.SizeOfInitializedData).c_str());
			cJSON_AddNumberToObject(image_optional_header, "size_of_initialized_data_dec", NtHeader->OptionalHeader.SizeOfInitializedData);
			cJSON_AddStringToObject(image_optional_header, "size_of_initialized_data_desc", "Size of initialized data segment (bytes)");

			cJSON_AddStringToObject(image_optional_header, "size_of_uninitialized_data_hex", DexToHex(NtHeader->OptionalHeader.SizeOfUninitializedData).c_str());
			cJSON_AddNumberToObject(image_optional_header, "size_of_uninitialized_data_dec", NtHeader->OptionalHeader.SizeOfUninitializedData);
			cJSON_AddStringToObject(image_optional_header, "size_of_uninitialized_data_desc", "Size of uninitialized data segment (bytes)");

			// 3.4 内存对齐与文件对齐
			cJSON_AddStringToObject(image_optional_header, "section_alignment_hex", DexToHex(NtHeader->OptionalHeader.SectionAlignment).c_str());
			cJSON_AddNumberToObject(image_optional_header, "section_alignment_dec", NtHeader->OptionalHeader.SectionAlignment);
			cJSON_AddStringToObject(image_optional_header, "section_alignment_desc", "Alignment granularity of blocks in memory (bytes)");

			cJSON_AddStringToObject(image_optional_header, "file_alignment_hex", DexToHex(NtHeader->OptionalHeader.FileAlignment).c_str());
			cJSON_AddNumberToObject(image_optional_header, "file_alignment_dec", NtHeader->OptionalHeader.FileAlignment);
			cJSON_AddStringToObject(image_optional_header, "file_alignment_desc", "Alignment granularity of blocks in file (bytes)");

			// 3.5 子系统
			const char* subsystemDesc = "Unknown subsystem";
			switch (NtHeader->OptionalHeader.Subsystem)
			{
			case IMAGE_SUBSYSTEM_WINDOWS_GUI:  subsystemDesc = "Windows GUI(Graphical interface)"; break;
			case IMAGE_SUBSYSTEM_WINDOWS_CUI:  subsystemDesc = "Windows CUI(console)"; break;
			case IMAGE_SUBSYSTEM_NATIVE:       subsystemDesc = "Native system program"; break;
			}
			cJSON_AddStringToObject(image_optional_header, "subsystem_hex", DexToHex(NtHeader->OptionalHeader.Subsystem).c_str());
			cJSON_AddNumberToObject(image_optional_header, "subsystem_dec", NtHeader->OptionalHeader.Subsystem);
			cJSON_AddStringToObject(image_optional_header, "subsystem_desc", subsystemDesc);

			// 3.6 首部大小与校验和
			cJSON_AddStringToObject(image_optional_header, "size_of_headers_hex", DexToHex(NtHeader->OptionalHeader.SizeOfHeaders).c_str());
			cJSON_AddNumberToObject(image_optional_header, "size_of_headers_dec", NtHeader->OptionalHeader.SizeOfHeaders);
			cJSON_AddStringToObject(image_optional_header, "size_of_headers_desc", "Total size of DOS header+nt header+section table");

			cJSON_AddStringToObject(image_optional_header, "check_sum_hex", DexToHex(NtHeader->OptionalHeader.CheckSum).c_str());
			cJSON_AddNumberToObject(image_optional_header, "check_sum_dec", NtHeader->OptionalHeader.CheckSum);
			cJSON_AddStringToObject(image_optional_header, "check_sum_desc", "Used to verify file integrity (usually 0)");

			// 3.7 数据目录数量
			cJSON_AddStringToObject(image_optional_header, "number_of_rva_and_sizes_hex", DexToHex(NtHeader->OptionalHeader.NumberOfRvaAndSizes).c_str());
			cJSON_AddNumberToObject(image_optional_header, "number_of_rva_and_sizes_dec", NtHeader->OptionalHeader.NumberOfRvaAndSizes);
			cJSON_AddStringToObject(image_optional_header, "number_of_rva_and_sizes_desc", "Number of data catalog entries (typically 16)");

			// 3.8 链接器版本
			cJSON_AddStringToObject(image_optional_header, "major_linker_version_hex", DexToHex(NtHeader->OptionalHeader.MajorLinkerVersion).c_str());
			cJSON_AddNumberToObject(image_optional_header, "major_linker_version_dec", NtHeader->OptionalHeader.MajorLinkerVersion);
			cJSON_AddStringToObject(image_optional_header, "major_linker_version_desc", "Linker major version");

			cJSON_AddStringToObject(image_optional_header, "minor_linker_version_hex", DexToHex(NtHeader->OptionalHeader.MinorLinkerVersion).c_str());
			cJSON_AddNumberToObject(image_optional_header, "minor_linker_version_dec", NtHeader->OptionalHeader.MinorLinkerVersion);
			cJSON_AddStringToObject(image_optional_header, "minor_linker_version_desc", "Linker minor version");

			// 3.9 版本信息（操作系统/映像/子系统）
			cJSON* version_info = cJSON_CreateObject();
			if (version_info == nullptr) throw std::bad_alloc();

			// 操作系统版本
			char osVersion[32] = { 0 };
			sprintf_s(osVersion, "%lld.%lld",
				NtHeader->OptionalHeader.MajorOperatingSystemVersion,
				NtHeader->OptionalHeader.MinorOperatingSystemVersion);
			cJSON_AddStringToObject(version_info, "operating_system_version", osVersion);
			cJSON_AddStringToObject(version_info, "operating_system_version_desc",
				std::string("Major version." + std::to_string(NtHeader->OptionalHeader.MajorOperatingSystemVersion) +
				".Minor version." + std::to_string(NtHeader->OptionalHeader.MinorOperatingSystemVersion)).c_str());

			// 映像版本
			char imageVersion[32] = { 0 };
			sprintf_s(imageVersion, "%lld.%lld",
				NtHeader->OptionalHeader.MajorImageVersion,
				NtHeader->OptionalHeader.MinorImageVersion);
			cJSON_AddStringToObject(version_info, "image_version", imageVersion);
			cJSON_AddStringToObject(version_info, "image_version_desc",
				std::string("Major version." + std::to_string(NtHeader->OptionalHeader.MajorImageVersion) +
				".Minor version." + std::to_string(NtHeader->OptionalHeader.MinorImageVersion)).c_str());

			// 子系统版本
			char subsystemVersion[32] = { 0 };
			sprintf_s(subsystemVersion, "%lld.%lld",
				NtHeader->OptionalHeader.MajorSubsystemVersion,
				NtHeader->OptionalHeader.MinorSubsystemVersion);
			cJSON_AddStringToObject(version_info, "subsystem_version", subsystemVersion);
			cJSON_AddStringToObject(version_info, "subsystem_version_desc",
				std::string("Major version." + std::to_string(NtHeader->OptionalHeader.MajorSubsystemVersion) +
				".Minor version." + std::to_string(NtHeader->OptionalHeader.MinorSubsystemVersion)).c_str());

			cJSON_AddItemToObject(image_optional_header, "version_info", version_info);

			// 3.10 Win32版本值
			cJSON_AddStringToObject(image_optional_header, "win32_version_value_hex", DexToHex(NtHeader->OptionalHeader.Win32VersionValue).c_str());
			cJSON_AddNumberToObject(image_optional_header, "win32_version_value_dec", NtHeader->OptionalHeader.Win32VersionValue);
			cJSON_AddStringToObject(image_optional_header, "win32_version_value_desc", "Normally 0 (reserved)");

			// 3.11 DLL特征（ASLR/DEP/SEH）
			std::string dllCharacDesc;
			if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)  dllCharacDesc += "support ASLR; ";
			if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)     dllCharacDesc += "support DEP; ";
			if (NtHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)        dllCharacDesc += "Not used SEH; ";
			if (dllCharacDesc.empty()) dllCharacDesc = "No special features";
			cJSON_AddStringToObject(image_optional_header, "dll_characteristics_hex", DexToHex(NtHeader->OptionalHeader.DllCharacteristics).c_str());
			cJSON_AddNumberToObject(image_optional_header, "dll_characteristics_dec", NtHeader->OptionalHeader.DllCharacteristics);
			cJSON_AddStringToObject(image_optional_header, "dll_characteristics_desc", dllCharacDesc.c_str());

			// 3.12 栈和堆相关（保留/提交大小）
			cJSON* stack_heap_info = cJSON_CreateObject();
			if (stack_heap_info == nullptr) throw std::bad_alloc();

			// 栈信息
			cJSON_AddStringToObject(stack_heap_info, "stack_reserve_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfStackReserve).c_str());
			cJSON_AddNumberToObject(stack_heap_info, "stack_reserve_size_dec", NtHeader->OptionalHeader.SizeOfStackReserve);
			cJSON_AddStringToObject(stack_heap_info, "stack_reserve_size_desc", "Reserved size of process stack");

			cJSON_AddStringToObject(stack_heap_info, "stack_commit_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfStackCommit).c_str());
			cJSON_AddNumberToObject(stack_heap_info, "stack_commit_size_dec", NtHeader->OptionalHeader.SizeOfStackCommit);
			cJSON_AddStringToObject(stack_heap_info, "stack_commit_size_desc", "Initial commit size of process stack");

			// 堆信息
			cJSON_AddStringToObject(stack_heap_info, "heap_reserve_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfHeapReserve).c_str());
			cJSON_AddNumberToObject(stack_heap_info, "heap_reserve_size_dec", NtHeader->OptionalHeader.SizeOfHeapReserve);
			cJSON_AddStringToObject(stack_heap_info, "heap_reserve_size_desc", "Reserved size of process heap");

			cJSON_AddStringToObject(stack_heap_info, "heap_commit_size_hex", DexToHex(NtHeader->OptionalHeader.SizeOfHeapCommit).c_str());
			cJSON_AddNumberToObject(stack_heap_info, "heap_commit_size_dec", NtHeader->OptionalHeader.SizeOfHeapCommit);
			cJSON_AddStringToObject(stack_heap_info, "heap_commit_size_desc", "Initial commit size of process heap");

			cJSON_AddItemToObject(image_optional_header, "stack_heap_info", stack_heap_info);

			// 3.13 加载器标志
			cJSON_AddStringToObject(image_optional_header, "loader_flags_hex", DexToHex(NtHeader->OptionalHeader.LoaderFlags).c_str());
			cJSON_AddNumberToObject(image_optional_header, "loader_flags_dec", NtHeader->OptionalHeader.LoaderFlags);
			cJSON_AddStringToObject(image_optional_header, "loader_flags_desc", "Obsolete (usually 0)");

			cJSON_AddItemToObject(nt_head_root, "image_optional_header", image_optional_header);


			// 3. 组装最终响应
			cJSON_AddItemToObject(response.result.get(), "nt_head_info", nt_head_root);
			cJSON_AddStringToObject(response.result.get(), "message", "NT Header parsing succeeded");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build NT header response data");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, parsing NT header failed");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}


	// 新增：处理“获取节区信息”请求
	static ResponseData handle_show_section(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 校验前置条件（文件已打开、NtHeader指针有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid NT header pointer, file may be corrupted");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 初始化节区遍历参数（用局部指针避免修改全局pSection）
			DWORD64 sectionCount = NtHeader->FileHeader.NumberOfSections;
			PIMAGE_SECTION_HEADER pLocalSection = IMAGE_FIRST_SECTION(NtHeader);
			if (pLocalSection == nullptr && sectionCount > 0)
			{
				throw std::runtime_error("Invalid section table pointer");
			}

			// 3. 构建JSON根对象（包含节区总数和节区数组）
			cJSON* section_root = cJSON_CreateObject();
			if (section_root == nullptr) throw std::bad_alloc();

			// 3.1 节区总数
			cJSON_AddNumberToObject(section_root, "section_count", sectionCount);
			cJSON_AddStringToObject(section_root, "section_count_desc", "PE Total number of sections contained in the file");

			// 3.2 节区数组（存储每个节区的详情）
			cJSON* section_array = cJSON_CreateArray();
			if (section_array == nullptr) throw std::bad_alloc();

			// 4. 遍历每个节区，构建单节区JSON对象
			for (DWORD64 each = 0; each < sectionCount; each++, pLocalSection++)
			{
				cJSON* section_item = cJSON_CreateObject();
				if (section_item == nullptr) throw std::bad_alloc();

				// 4.1 基础信息（编号、节区名称）
				cJSON_AddNumberToObject(section_item, "section_index", each + 1);  // 编号（从1开始）
				// 节区名称：IMAGE_SECTION_HEADER.Name是8字节CHAR数组，需转为字符串（自动处理'\0'结尾）
				std::string sectionName(reinterpret_cast<char*>(pLocalSection->Name));
				cJSON_AddStringToObject(section_item, "section_name", sectionName.c_str());

				// 4.2 地址与大小信息（RVA/FOA/虚拟大小/实际大小）
				// 虚拟偏移（RVA）
				cJSON_AddStringToObject(section_item, "virtual_address_rva_hex", DexToHex(pLocalSection->VirtualAddress).c_str());
				cJSON_AddNumberToObject(section_item, "virtual_address_rva_dec", pLocalSection->VirtualAddress);
				cJSON_AddStringToObject(section_item, "virtual_address_rva_desc", "Relative virtual address of the section in memory");

				// 虚拟大小（内存中占用大小）
				cJSON_AddStringToObject(section_item, "virtual_size_hex", DexToHex(pLocalSection->Misc.VirtualSize).c_str());
				cJSON_AddNumberToObject(section_item, "virtual_size_dec", pLocalSection->Misc.VirtualSize);
				cJSON_AddStringToObject(section_item, "virtual_size_desc", "Total size of the section in memory (bytes)");

				// 实际偏移（FOA，文件中的偏移）
				cJSON_AddStringToObject(section_item, "raw_data_offset_foa_hex", DexToHex(pLocalSection->PointerToRawData).c_str());
				cJSON_AddNumberToObject(section_item, "raw_data_offset_foa_dec", pLocalSection->PointerToRawData);
				cJSON_AddStringToObject(section_item, "raw_data_offset_foa_desc", "Actual offset of the section in the file");

				// 实际大小（文件中存储大小）
				cJSON_AddStringToObject(section_item, "raw_data_size_hex", DexToHex(pLocalSection->SizeOfRawData).c_str());
				cJSON_AddNumberToObject(section_item, "raw_data_size_dec", pLocalSection->SizeOfRawData);
				cJSON_AddStringToObject(section_item, "raw_data_size_desc", "Storage size of the section in the file (bytes)");

				// 4.3 重定位信息
				cJSON_AddStringToObject(section_item, "relocation_offset_foa_hex", DexToHex(pLocalSection->PointerToRelocations).c_str());
				cJSON_AddNumberToObject(section_item, "relocation_offset_foa_dec", pLocalSection->PointerToRelocations);
				cJSON_AddStringToObject(section_item, "relocation_offset_foa_desc", "Offset of section relocation information in the file (0 means none)");

				cJSON_AddNumberToObject(section_item, "relocation_count", pLocalSection->NumberOfRelocations);
				cJSON_AddStringToObject(section_item, "relocation_count_desc", "The number of relocation items contained in the section (0 means none)");

				// 4.4 行号信息
				cJSON_AddStringToObject(section_item, "linenumber_offset_foa_hex", DexToHex(pLocalSection->PointerToLinenumbers).c_str());
				cJSON_AddNumberToObject(section_item, "linenumber_offset_foa_dec", pLocalSection->PointerToLinenumbers);
				cJSON_AddStringToObject(section_item, "linenumber_offset_foa_desc", "Offset of section line number information in the file (0 means none)");

				cJSON_AddNumberToObject(section_item, "linenumber_count", pLocalSection->NumberOfLinenumbers);
				cJSON_AddStringToObject(section_item, "linenumber_count_desc", "Number of line number items contained in the section (0 means none)");

				// 4.5 节区属性（Characteristics解析，与原函数逻辑完全一致）
				std::string attrDesc;
				if (pLocalSection->Characteristics & IMAGE_SCN_CNT_CODE)
					attrDesc += "Code section; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
					attrDesc += "Initialized data; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
					attrDesc += "Uninitialized data; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
					attrDesc += "Executable; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_MEM_READ)
					attrDesc += "readable; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_MEM_WRITE)
					attrDesc += "Writable; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL)
					attrDesc += "Relocation overflow; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_1BYTES)
					attrDesc += "1 byte alignment; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_2BYTES)
					attrDesc += "2 byte alignment; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_4BYTES)
					attrDesc += "4 byte alignment; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_8BYTES)
					attrDesc += "8 byte alignment; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_16BYTES)
					attrDesc += "16 byte alignment; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_32BYTES)
					attrDesc += "32 byte alignment; ";
				if (pLocalSection->Characteristics & IMAGE_SCN_ALIGN_64BYTES)
					attrDesc += "64 byte alignment; ";
				if (attrDesc.empty())
					attrDesc = "No special properties";

				cJSON_AddStringToObject(section_item, "characteristics_hex", DexToHex(pLocalSection->Characteristics).c_str());
				cJSON_AddNumberToObject(section_item, "characteristics_dec", pLocalSection->Characteristics);
				cJSON_AddStringToObject(section_item, "characteristics_desc", attrDesc.c_str());

				// 4.6 将单节区对象添加到数组
				cJSON_AddItemToArray(section_array, section_item);
			}

			// 5. 组装最终JSON结构
			cJSON_AddItemToObject(section_root, "sections", section_array);
			cJSON_AddItemToObject(response.result.get(), "section_info", section_root);
			cJSON_AddStringToObject(response.result.get(), "message", "Section information parsing succeeded");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build section response data");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse section information");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“获取数据目录表信息”请求
	static ResponseData handle_show_optional_data_directory(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 校验前置条件（文件已打开、NtHeader指针有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Invalid NT header pointer, file may be corrupted");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 初始化数据目录核心参数（与原函数完全一致）
			int dataDirCount = NtHeader->OptionalHeader.NumberOfRvaAndSizes;  // 数据目录总数
			DWORD64 imageBase = NtHeader->OptionalHeader.ImageBase;            // 镜像基址（用于计算VA）

			// 2.1 标准数据目录名称数组（对应IMAGE_DIRECTORY_ENTRY_0到15）
			const char* dirNames[16] = {
				"Export Table", "Import Table", "Resource Table", "Exception Table",
				"Security Table", "Base Relocation Table", "Debug Table", "Architecture",
				"Global Pointer", "TLS Table", "Load Configuration Table", "Bound Import Table",
				"Import Address Table", "Delay Import Descriptor", "COM Descriptor", "Reserved"
			};

			// 2.2 标准数据目录详细描述数组
			const char* dirDescriptions[16] = {
				"Contains exported functions and symbol information for calling by other modules",
				"Contains information about imported DLLs and functions, which needs to be resolved during loading",
				"Contains index information of program resources (such as icons, strings, dialog boxes, etc.)",
				"Contains exception handling-related structures for exception catching and handling",
				"Contains security information such as digital signatures for verifying file integrity",
				"Contains base address relocation information, used to correct when the module loading address is different from the default",
				"Contains debugging information (such as debug symbol path, type, etc.)",
				"Copyright information string (usually in Unicode format)",
				"Global pointers (used for accessing global variables in certain architectures)",
				"Thread Local Storage (TLS) information, used for thread-private data",
				"Load configuration information (such as security cookies, SEH verification, etc.)",
				"Bound import table, pre-resolved imported function addresses to accelerate loading",
				"Import Address Table (IAT), which stores the memory addresses of actual imported functions",
				"Delay Import Descriptor, used for delayed loading of DLLs (loaded at runtime)",
				"COM component description information (such as CLSID, interface information, etc.)",
				"Reserved and unused"
			};

			// 3. 构建JSON根对象（包含目录总数和目录数组）
			cJSON* data_dir_root = cJSON_CreateObject();
			if (data_dir_root == nullptr) throw std::bad_alloc();

			// 3.1 数据目录总数
			cJSON_AddNumberToObject(data_dir_root, "data_directory_count", dataDirCount);
			cJSON_AddStringToObject(data_dir_root, "data_directory_count_desc", "Total number of data directory entries defined in PE optional header (usually 16)");

			// 3.2 数据目录数组（存储每个目录项的详情）
			cJSON* data_dir_array = cJSON_CreateArray();
			if (data_dir_array == nullptr) throw std::bad_alloc();

			// 4. 遍历每个数据目录项，构建单目录JSON对象
			for (int x = 0; x < dataDirCount; x++)
			{
				// 获取当前目录项（IMAGE_DATA_DIRECTORY）
				IMAGE_DATA_DIRECTORY dir = NtHeader->OptionalHeader.DataDirectory[x];
				DWORD64 rva = dir.VirtualAddress;       // 目录RVA
				DWORD64 size = dir.Size;                 // 目录大小
				DWORD64 foa = RVAtoFOA(rva);             // 目录FOA（调用私有函数转换）
				DWORD64 va = (rva != 0) ? (imageBase + rva) : 0;  // 目录VA（虚拟地址）
				bool is_valid = (rva != 0 && size != 0);       // 有效性判断（RVA和Size均非0）

				// 创建单目录项JSON对象
				cJSON* dir_item = cJSON_CreateObject();
				if (dir_item == nullptr) throw std::bad_alloc();

				// 4.1 基础信息（编号、标准名称、详细描述）
				cJSON_AddNumberToObject(dir_item, "directory_index", x + 1);  // 编号（从1开始）
				// 标准名称：索引≤15用预定义名称，否则为Unknown
				const char* dirName = (x < 16) ? dirNames[x] : "Unknown";
				cJSON_AddStringToObject(dir_item, "standard_name", dirName);
				// 详细描述：索引≤15用预定义描述，否则提示超出范围
				const char* dirDesc = (x < 16) ? dirDescriptions[x] : "Beyond the range of standard data directory (index ≥ 16)";
				cJSON_AddStringToObject(dir_item, "description", dirDesc);

				// 4.2 地址信息（RVA/VA/FOA，均含十六进制和十进制）
				// RVA（相对虚拟地址）
				cJSON_AddStringToObject(dir_item, "virtual_address_rva_hex", DexToHex(rva).c_str());
				cJSON_AddNumberToObject(dir_item, "virtual_address_rva_dec", rva);
				cJSON_AddStringToObject(dir_item, "virtual_address_rva_desc", "Relative virtual address of the directory in memory");

				// VA（虚拟地址 = 镜像基址 + RVA）
				cJSON_AddStringToObject(dir_item, "virtual_address_va_hex", DexToHex(va).c_str());
				cJSON_AddNumberToObject(dir_item, "virtual_address_va_dec", va);
				cJSON_AddStringToObject(dir_item, "virtual_address_va_desc", "Absolute virtual address of the directory in memory (mirror base address+rva)");

				// FOA（文件偏移地址，调用RVAtoFOA转换）
				cJSON_AddStringToObject(dir_item, "file_offset_foa_hex", DexToHex(foa).c_str());
				cJSON_AddNumberToObject(dir_item, "file_offset_foa_dec", foa);
				cJSON_AddStringToObject(dir_item, "file_offset_foa_desc", "The actual offset address of the directory in the file (converted from RVA)");

				// 4.3 大小信息（十进制和十六进制）
				cJSON_AddNumberToObject(dir_item, "size_dec", size);
				cJSON_AddStringToObject(dir_item, "size_hex", DexToHex(size).c_str());
				cJSON_AddStringToObject(dir_item, "size_desc", "Size of bytes occupied by the directory (0 means no actual data)");

				// 4.4 有效性标识（true=有效，false=无效）
				cJSON_AddBoolToObject(dir_item, "is_valid", is_valid);
				cJSON_AddStringToObject(dir_item, "is_valid_desc", is_valid ? "Valid (RVA and size are not 0)" : "Valid (RVA and size are not 0)");

				// 4.5 将单目录项添加到数组
				cJSON_AddItemToArray(data_dir_array, dir_item);
			}

			// 5. 组装最终JSON结构
			cJSON_AddItemToObject(data_dir_root, "data_directories", data_dir_array);
			cJSON_AddItemToObject(response.result.get(), "optional_data_directory_info", data_dir_root);
			cJSON_AddStringToObject(response.result.get(), "message", "Data directory table information parsing succeeded");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build data directory response data");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse data directory table information");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“获取导入DLL列表”请求
	static ResponseData handle_show_import_by_dll(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 校验前置条件（文件已打开、NtHeader/GlobalFileBase有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 定位导入表（从数据目录表获取，索引1对应导入表）
			DWORD64 importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
			if (importDirRva == 0)
			{
				throw std::runtime_error("The import table RVA is invalid (the import table entry in the data directory table is empty)");
			}
			// 转换导入表FOA并获取指针（RVA->FOA + 全局映射基址）
			DWORD64 importTableFoa = RVAtoFOA(importDirRva);
			PIMAGE_IMPORT_DESCRIPTOR ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(importTableFoa + GlobalFileBase);
			if (ImportTable == nullptr)
			{
				throw std::runtime_error("Import table pointer is null, unable to traverse import DLL");
			}

			// 3. 初始化核心参数
			DWORD64 imageBase = NtHeader->OptionalHeader.ImageBase;  // 镜像基址（用于计算VA）
			int dllCount = 0;                                      // 导入DLL总数

			// 4. 构建JSON根对象（包含DLL总数和DLL数组）
			cJSON* import_root = cJSON_CreateObject();
			if (import_root == nullptr) throw std::bad_alloc();

			// 4.1 导入DLL数组（存储每个DLL的详情）
			cJSON* import_dll_array = cJSON_CreateArray();
			if (import_dll_array == nullptr) throw std::bad_alloc();

			// 5. 遍历导入表（以全0的IMAGE_IMPORT_DESCRIPTOR结束）
			while (ImportTable->Name != 0)
			{
				dllCount++;
				cJSON* dll_item = cJSON_CreateObject();
				if (dll_item == nullptr) throw std::bad_alloc();

				// 5.1 基础信息（序号、DLL名称）
				cJSON_AddNumberToObject(dll_item, "dll_index", dllCount);  // 序号（从1开始）
				// 解析DLL名称：Name字段是RVA，需转换为文件偏移后读取
				DWORD64 dllNameRva = ImportTable->Name;
				DWORD64 dllNameFoa = RVAtoFOA(dllNameRva);
				CHAR* dllNameRaw = (CHAR*)(dllNameFoa + GlobalFileBase);
				std::string dllName(dllNameRaw ? dllNameRaw : "");  // 处理空指针
				cJSON_AddStringToObject(dll_item, "dll_name", dllName.c_str());

				// 5.2 INT（导入名称表）地址信息（RVA/FOA/VA）
				DWORD64 intRva = ImportTable->OriginalFirstThunk;
				DWORD64 intFoa = (intRva != 0) ? RVAtoFOA(intRva) : 0;
				DWORD64 intVa = (intRva != 0) ? (imageBase + intRva) : 0;
				// INT RVA
				cJSON_AddStringToObject(dll_item, "int_rva_hex", DexToHex(intRva).c_str());
				cJSON_AddNumberToObject(dll_item, "int_rva_dec", intRva);
				cJSON_AddStringToObject(dll_item, "int_rva_desc", "Relative virtual address of import name table (int)");
				// INT FOA
				cJSON_AddStringToObject(dll_item, "int_foa_hex", DexToHex(intFoa).c_str());
				cJSON_AddNumberToObject(dll_item, "int_foa_dec", intFoa);
				cJSON_AddStringToObject(dll_item, "int_foa_desc", "File offset address of import name table (int)");
				// INT VA
				cJSON_AddStringToObject(dll_item, "int_va_hex", DexToHex(intVa).c_str());
				cJSON_AddNumberToObject(dll_item, "int_va_dec", intVa);
				cJSON_AddStringToObject(dll_item, "int_va_desc", "Memory virtual address of import name table (int) (image base address+rva)");

				// 5.3 IAT（导入地址表）地址信息（RVA/FOA/VA）
				DWORD64 iatRva = ImportTable->FirstThunk;
				DWORD64 iatFoa = (iatRva != 0) ? RVAtoFOA(iatRva) : 0;
				DWORD64 iatVa = (iatRva != 0) ? (imageBase + iatRva) : 0;
				// IAT RVA
				cJSON_AddStringToObject(dll_item, "iat_rva_hex", DexToHex(iatRva).c_str());
				cJSON_AddNumberToObject(dll_item, "iat_rva_dec", iatRva);
				cJSON_AddStringToObject(dll_item, "iat_rva_desc", "Import the relative virtual address of the address table (IAT)");
				// IAT FOA
				cJSON_AddStringToObject(dll_item, "iat_foa_hex", DexToHex(iatFoa).c_str());
				cJSON_AddNumberToObject(dll_item, "iat_foa_dec", iatFoa);
				cJSON_AddStringToObject(dll_item, "iat_foa_desc", "File offset address of import address table (IAT)");
				// IAT VA
				cJSON_AddStringToObject(dll_item, "iat_va_hex", DexToHex(iatVa).c_str());
				cJSON_AddNumberToObject(dll_item, "iat_va_dec", iatVa);
				cJSON_AddStringToObject(dll_item, "iat_va_desc", "Import the memory virtual address of the address table (IAT) (image base address+rva)");

				// 5.4 时间戳信息（原始值+UTC字符串）
				DWORD64 timeStamp = ImportTable->TimeDateStamp;
				char timeStr[32] = "Unbound (0)";  // 0表示未绑定
				if (timeStamp != 0)
				{
					time_t t = (time_t)timeStamp;
					struct tm* utcTime = gmtime(&t);  // 转UTC时间（与原函数一致）
					if (utcTime != nullptr)
					{
						strftime(timeStr, sizeof(timeStr), "%Y-%m-%lld %H:%M:%S", utcTime);
					}
					else
					{
						strcpy_s(timeStr, "Invalid timestamp");
					}
				}
				cJSON_AddStringToObject(dll_item, "timestamp_hex", DexToHex(timeStamp).c_str());
				cJSON_AddNumberToObject(dll_item, "timestamp_dec", timeStamp);
				cJSON_AddStringToObject(dll_item, "timestamp_utc", timeStr);
				cJSON_AddStringToObject(dll_item, "timestamp_desc", timeStamp == 0 ? "Unbound (dynamically resolved on load)" : "Bound (pre resolved import address)");

				// 5.5 转发链信息（原始值+描述）
				DWORD64 forwarderChain = ImportTable->ForwarderChain;
				const char* forwardDesc = nullptr;
				if (forwarderChain == 0xFFFFFFFF)
					forwardDesc = "No forwarding(-1)";
				else if (forwarderChain == 0)
					forwardDesc = "Not set(0)";
				else
					forwardDesc = "Forward (to other import functions)";
				cJSON_AddStringToObject(dll_item, "forwarder_chain_hex", DexToHex(forwarderChain).c_str());
				cJSON_AddNumberToObject(dll_item, "forwarder_chain_dec", forwarderChain);
				cJSON_AddStringToObject(dll_item, "forwarder_chain_desc", forwardDesc);

				// 5.6 DLL名称的RVA/FOA（补充原函数字段）
				cJSON_AddStringToObject(dll_item, "dll_name_rva_hex", DexToHex(dllNameRva).c_str());
				cJSON_AddNumberToObject(dll_item, "dll_name_rva_dec", dllNameRva);
				cJSON_AddStringToObject(dll_item, "dll_name_foa_hex", DexToHex(dllNameFoa).c_str());
				cJSON_AddNumberToObject(dll_item, "dll_name_foa_dec", dllNameFoa);
				cJSON_AddStringToObject(dll_item, "dll_name_addr_desc", "Address information of DLL name string in file");

				// 5.7 将单DLL对象添加到数组
				cJSON_AddItemToArray(import_dll_array, dll_item);

				// 移动到下一个导入描述符
				ImportTable++;
			}

			// 6. 组装最终JSON结构（补充DLL总数）
			cJSON_AddNumberToObject(import_root, "import_dll_count", dllCount);
			cJSON_AddStringToObject(import_root, "import_dll_count_desc", "Total number of DLLs imported from PE file");
			cJSON_AddItemToObject(import_root, "import_dlls", import_dll_array);
			cJSON_AddItemToObject(response.result.get(), "import_by_dll_info", import_root);
			cJSON_AddStringToObject(response.result.get(), "message", "Import DLL list resolved successfully");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build import DLL response data");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse import DLL list");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}


	// 新增：处理“获取指定DLL的导入函数”请求
	static ResponseData handle_show_import_by_name(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：文件已打开 + 参数有效（需1个DLL名称参数）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (params.size() != 1 || params[0].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Parameter error: 1 DLL name needs to be passed in");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		const std::string targetDll = params[0];  // 用户指定的DLL名称


		try
		{
			// 2. 定位导入表（数据目录表索引1对应导入表）
			DWORD64 importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
			if (importDirRva == 0)
			{
				throw std::runtime_error("The import table RVA is invalid (the import table entry in the data directory table is empty)");
			}
			DWORD64 importTableFoa = RVAtoFOA(importDirRva);
			PIMAGE_IMPORT_DESCRIPTOR ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(importTableFoa + GlobalFileBase);
			if (ImportTable == nullptr)
			{
				throw std::runtime_error("The import table pointer is null, unable to traverse the import function");
			}

			// 3. 初始化核心参数
			DWORD64 imageBase = NtHeader->OptionalHeader.ImageBase;  // 镜像基址（计算VA）
			bool dllFound = false;                                // 是否找到指定DLL
			int funcCount = 0;                                     // 导入函数总数
			cJSON* import_func_array = cJSON_CreateArray();        // 导入函数数组
			if (import_func_array == nullptr) throw std::bad_alloc();


			// 4. 遍历导入表，匹配指定DLL
			while (ImportTable->Name != 0)
			{
				// 解析当前导入描述符的DLL名称
				DWORD64 dllNameRva = ImportTable->Name;
				DWORD64 dllNameFoa = RVAtoFOA(dllNameRva);
				CHAR* currentDllName = (CHAR*)(dllNameFoa + GlobalFileBase);
				if (currentDllName == nullptr)
				{
					ImportTable++;
					continue;
				}

				// 匹配目标DLL（区分大小写，与原函数strcmp逻辑一致）
				if (strcmp(currentDllName, targetDll.c_str()) != 0)
				{
					ImportTable++;
					continue;
				}

				// 找到目标DLL，标记并解析其导入函数
				dllFound = true;
				DWORD64 intRva = ImportTable->OriginalFirstThunk;  // INT（导入名称表）RVA
				DWORD64 iatRva = ImportTable->FirstThunk;          // IAT（导入地址表）RVA
				DWORD64 currentIntRva = intRva;                    // 当前INT表项RVA（用于累加）
				DWORD64 currentIatRva = iatRva;                    // 当前IAT表项RVA（用于累加）

				// 初始化INT/IAT指针（修复原函数空指针问题）
				PIMAGE_THUNK_DATA Int = nullptr;
				if (intRva != 0)
				{
					DWORD64 intFoa = RVAtoFOA(intRva);
					Int = (PIMAGE_THUNK_DATA)(LPVOID)(intFoa + GlobalFileBase);
				}
				PIMAGE_THUNK_DATA Iat = nullptr;
				if (iatRva != 0)
				{
					DWORD64 iatFoa = RVAtoFOA(iatRva);
					Iat = (PIMAGE_THUNK_DATA)(LPVOID)(iatFoa + GlobalFileBase);
				}

				// 校验INT/IAT指针有效性
				if (Int == nullptr || Iat == nullptr)
				{
					throw std::runtime_error("Invalid int or IAT pointer, unable to parse import function");
				}

				// 5. 遍历INT/IAT表项，解析每个导入函数
				while (Int->u1.Ordinal != 0 && Iat->u1.Ordinal != 0)
				{
					funcCount++;
					cJSON* func_item = cJSON_CreateObject();
					if (func_item == nullptr) throw std::bad_alloc();

					// 5.1 导入类型（序号导入/名称导入）
					bool isOrdinal = (Int->u1.Ordinal & 0x80000000) != 0;
					const char* importType = isOrdinal ? "Sn import" : "Name import";
					cJSON_AddStringToObject(func_item, "import_type", importType);

					// 5.2 函数序号/名称 + Hint值
					WORD hint = 0;
					std::string funcInfo = "unknown";
					if (isOrdinal)
					{
						// 序号导入：提取低16位序号
						WORD ordinal = (WORD)(Int->u1.Ordinal & 0x7FFF);
						funcInfo = "Ordinal: " + std::to_string(ordinal);
					}
					else
					{
						// 名称导入：解析IMAGE_IMPORT_BY_NAME获取Hint和函数名
						DWORD64 nameDataRva = Int->u1.AddressOfData;
						DWORD64 nameDataFoa = RVAtoFOA(nameDataRva);
						PIMAGE_IMPORT_BY_NAME nameData = (PIMAGE_IMPORT_BY_NAME)(nameDataFoa + GlobalFileBase);
						if (nameData != nullptr)
						{
							hint = nameData->Hint;
							funcInfo = nameData->Name;
						}
					}
					cJSON_AddNumberToObject(func_item, "hint_value", hint);
					cJSON_AddStringToObject(func_item, "function_info", funcInfo.c_str());
					cJSON_AddNumberToObject(func_item, "function_index", funcCount);  // 函数序号

					// 5.3 INT（导入名称表）地址信息（RVA/FOA/VA）
					DWORD64 intFoa = RVAtoFOA(currentIntRva);
					DWORD64 intVa = currentIntRva != 0 ? (imageBase + currentIntRva) : 0;
					cJSON_AddStringToObject(func_item, "int_rva_hex", DexToHex(currentIntRva).c_str());
					cJSON_AddNumberToObject(func_item, "int_rva_dec", currentIntRva);
					cJSON_AddStringToObject(func_item, "int_foa_hex", DexToHex(intFoa).c_str());
					cJSON_AddNumberToObject(func_item, "int_foa_dec", intFoa);
					cJSON_AddStringToObject(func_item, "int_va_hex", DexToHex(intVa).c_str());
					cJSON_AddNumberToObject(func_item, "int_va_dec", intVa);

					// 5.4 IAT（导入地址表）地址信息（RVA/FOA/VA）
					DWORD64 iatFoa = RVAtoFOA(currentIatRva);
					DWORD64 iatVa = currentIatRva != 0 ? (imageBase + currentIatRva) : 0;
					cJSON_AddStringToObject(func_item, "iat_rva_hex", DexToHex(currentIatRva).c_str());
					cJSON_AddNumberToObject(func_item, "iat_rva_dec", currentIatRva);
					cJSON_AddStringToObject(func_item, "iat_foa_hex", DexToHex(iatFoa).c_str());
					cJSON_AddNumberToObject(func_item, "iat_foa_dec", iatFoa);
					cJSON_AddStringToObject(func_item, "iat_va_hex", DexToHex(iatVa).c_str());
					cJSON_AddNumberToObject(func_item, "iat_va_dec", iatVa);

					// 5.5 将函数项添加到数组
					cJSON_AddItemToArray(import_func_array, func_item);

					// 移动到下一个INT/IAT表项（IMAGE_THUNK_DATA占4字节）
					Int++;
					Iat++;
					currentIntRva += sizeof(IMAGE_THUNK_DATA);
					currentIatRva += sizeof(IMAGE_THUNK_DATA);
				}

				// 找到目标DLL后无需继续遍历其他DLL
				break;
			}


			// 6. 构建最终JSON响应
			cJSON* import_root = cJSON_CreateObject();
			if (import_root == nullptr) throw std::bad_alloc();
			cJSON_AddStringToObject(import_root, "target_dll", targetDll.c_str());
			cJSON_AddBoolToObject(import_root, "dll_found", dllFound);

			if (dllFound)
			{
				cJSON_AddNumberToObject(import_root, "import_function_count", funcCount);
				cJSON_AddStringToObject(import_root, "import_function_count_desc", "Total number of import functions for the specified DLL");
				cJSON_AddItemToObject(import_root, "import_functions", import_func_array);
				cJSON_AddStringToObject(response.result.get(), "message", "The import function of the specified DLL resolved successfully");
			}
			else
			{
				cJSON_AddStringToObject(import_root, "reason", "The specified DLL was not found in the import table of the PE file");
				cJSON_Delete(import_func_array);  // 未找到DLL，释放空数组
				cJSON_AddStringToObject(response.result.get(), "message", "The import function for the specified DLL was not found");
			}

			cJSON_AddItemToObject(response.result.get(), "import_by_name_info", import_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build import function response data");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse the import function of the specified DLL");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“按函数名/序号匹配导入函数”请求
	static ResponseData handle_show_import_by_function(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：文件状态 + 参数合法性
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		// 参数1：函数名/序号（必填）
		if (params.empty() || params[0].empty())
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Parameter error: the first parameter needs to be passed in");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		const std::string targetFunc = params[0];

		// 解析参数2：caseSensitive（可选，默认FALSE）
		BOOL caseSensitive = FALSE;
		if (params.size() >= 2 && !params[1].empty())
		{
			std::string csStr = params[1];
			std::transform(csStr.begin(), csStr.end(), csStr.begin(), ::tolower);
			caseSensitive = (csStr == "true" || csStr == "1") ? TRUE : FALSE;
		}

		// 解析参数3：checkOrdinal（可选，默认TRUE）
		BOOL checkOrdinal = TRUE;
		if (params.size() >= 3 && !params[2].empty())
		{
			std::string coStr = params[2];
			std::transform(coStr.begin(), coStr.end(), coStr.begin(), ::tolower);
			checkOrdinal = (coStr == "true" || coStr == "1") ? TRUE : FALSE;
		}


		try
		{
			// 2. 定位导入表（数据目录表索引1）
			DWORD64 importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
			if (importDirRva == 0)
			{
				throw std::runtime_error("The import table RVA is invalid (the import table entry in the data directory table is empty)");
			}
			DWORD64 importTableFoa = RVAtoFOA(importDirRva);
			PIMAGE_IMPORT_DESCRIPTOR ImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(importTableFoa + GlobalFileBase);
			if (ImportTable == nullptr)
			{
				throw std::runtime_error("The import table pointer is null, unable to traverse the import function");
			}

			// 3. 初始化核心变量（复用原函数逻辑）
			DWORD64 imageBase = NtHeader->OptionalHeader.ImageBase;  // 镜像基址
			int matchCount = 0;                                   // 匹配到的函数总数
			DWORD64 funcOrdinal = 0;                                // 转换后的函数序号（仅checkOrdinal有效）
			cJSON* match_array = cJSON_CreateArray();              // 匹配结果数组
			if (match_array == nullptr) throw std::bad_alloc();

			// 3.1 尝试将目标函数转为序号（仅当checkOrdinal为TRUE时）
			if (checkOrdinal)
			{
				char* endptr = nullptr;
				funcOrdinal = strtoul(targetFunc.c_str(), &endptr, 10);
				// 若转换后仍有非数字字符，说明不是有效序号
				if (*endptr != '\0') funcOrdinal = 0;
			}


			// 4. 遍历导入表，匹配函数
			while (ImportTable->Name != 0)
			{
				// 4.1 获取当前DLL名称
				DWORD64 dllNameRva = ImportTable->Name;
				DWORD64 dllNameFoa = RVAtoFOA(dllNameRva);
				CHAR* currentDll = (CHAR*)(dllNameFoa + GlobalFileBase);
				if (currentDll == nullptr)
				{
					ImportTable++;
					continue;
				}

				// 4.2 初始化INT/IAT指针（安全处理空指针）
				DWORD64 intRva = ImportTable->OriginalFirstThunk;
				DWORD64 iatRva = ImportTable->FirstThunk;
				DWORD64 currentIntRva = intRva;  // 当前INT表项RVA（累加用）
				DWORD64 currentIatRva = iatRva;  // 当前IAT表项RVA（累加用）

				PIMAGE_THUNK_DATA Int = nullptr;
				if (intRva != 0)
				{
					DWORD64 intFoa = RVAtoFOA(intRva);
					Int = (PIMAGE_THUNK_DATA)(intFoa + GlobalFileBase);
				}
				PIMAGE_THUNK_DATA Iat = nullptr;
				if (iatRva != 0)
				{
					DWORD64 iatFoa = RVAtoFOA(iatRva);
					Iat = (PIMAGE_THUNK_DATA)(iatFoa + GlobalFileBase);
				}
				if (Int == nullptr || Iat == nullptr)
				{
					ImportTable++;
					continue;
				}


				// 4.3 遍历INT/IAT表项，检查匹配
				while (Int->u1.Ordinal != 0 && Iat->u1.Ordinal != 0)
				{
					BOOL isMatch = FALSE;
					const char* importType = "unknown";
					WORD hint = 0;
					std::string funcInfo = "unknown";

					// 4.3.1 序号导入匹配（仅checkOrdinal为TRUE且序号有效）
					if (Int->u1.Ordinal & 0x80000000)
					{
						importType = "Sn import";
						WORD ordinal = (WORD)(Int->u1.Ordinal & 0x7FFF);  // 提取低16位序号
						funcInfo = "Ordinal: " + std::to_string(ordinal);

						// 若开启序号检查且目标是有效序号，判断是否匹配
						if (checkOrdinal && funcOrdinal != 0 && ordinal == funcOrdinal)
						{
							isMatch = TRUE;
						}
					}
					// 4.3.2 名称导入匹配（区分/不区分大小写）
					else
					{
						importType = "Name import";
						DWORD64 nameDataRva = Int->u1.AddressOfData;
						DWORD64 nameDataFoa = RVAtoFOA(nameDataRva);
						PIMAGE_IMPORT_BY_NAME nameData = (PIMAGE_IMPORT_BY_NAME)(nameDataFoa + GlobalFileBase);
						if (nameData != nullptr)
						{
							hint = nameData->Hint;
							funcInfo = nameData->Name;

							// 按名称匹配（根据caseSensitive选择比较函数）
							if (caseSensitive)
							{
								isMatch = (strcmp(targetFunc.c_str(), nameData->Name) == 0) ? TRUE : FALSE;
							}
							else
							{
								isMatch = (_stricmp(targetFunc.c_str(), nameData->Name) == 0) ? TRUE : FALSE;
							}
						}
					}


					// 4.3.3 匹配成功：构建函数信息JSON
					if (isMatch)
					{
						matchCount++;
						cJSON* func_item = cJSON_CreateObject();
						if (func_item == nullptr) throw std::bad_alloc();

						// 基本匹配信息
						cJSON_AddNumberToObject(func_item, "match_index", matchCount);
						cJSON_AddStringToObject(func_item, "import_type", importType);
						cJSON_AddNumberToObject(func_item, "hint_value", hint);
						cJSON_AddStringToObject(func_item, "function_info", funcInfo.c_str());
						cJSON_AddStringToObject(func_item, "dll_name", currentDll);

						// INT地址信息（RVA/FOA/VA）
						DWORD64 intFoa = RVAtoFOA(currentIntRva);
						DWORD64 intVa = currentIntRva + imageBase;
						cJSON_AddStringToObject(func_item, "int_rva_hex", DexToHex(currentIntRva).c_str());
						cJSON_AddNumberToObject(func_item, "int_rva_dec", currentIntRva);
						cJSON_AddStringToObject(func_item, "int_foa_hex", DexToHex(intFoa).c_str());
						cJSON_AddNumberToObject(func_item, "int_foa_dec", intFoa);
						cJSON_AddStringToObject(func_item, "int_va_hex", DexToHex(intVa).c_str());
						cJSON_AddNumberToObject(func_item, "int_va_dec", intVa);

						// IAT地址信息（RVA/FOA/VA）
						DWORD64 iatFoa = RVAtoFOA(currentIatRva);
						DWORD64 iatVa = currentIatRva + imageBase;
						cJSON_AddStringToObject(func_item, "iat_rva_hex", DexToHex(currentIatRva).c_str());
						cJSON_AddNumberToObject(func_item, "iat_rva_dec", currentIatRva);
						cJSON_AddStringToObject(func_item, "iat_foa_hex", DexToHex(iatFoa).c_str());
						cJSON_AddNumberToObject(func_item, "iat_foa_dec", iatFoa);
						cJSON_AddStringToObject(func_item, "iat_va_hex", DexToHex(iatVa).c_str());
						cJSON_AddNumberToObject(func_item, "iat_va_dec", iatVa);

						cJSON_AddItemToArray(match_array, func_item);
					}


					// 移动到下一个表项（IMAGE_THUNK_DATA占4字节）
					Int++;
					Iat++;
					currentIntRva += sizeof(IMAGE_THUNK_DATA);
					currentIatRva += sizeof(IMAGE_THUNK_DATA);
				}

				ImportTable++;
			}


			// 5. 构建最终JSON响应
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			// 匹配配置信息
			cJSON_AddStringToObject(result_root, "target_function", targetFunc.c_str());
			cJSON_AddBoolToObject(result_root, "case_sensitive", caseSensitive);
			cJSON_AddBoolToObject(result_root, "check_ordinal", checkOrdinal);
			cJSON_AddNumberToObject(result_root, "match_count", matchCount);
			// 匹配结果数组
			cJSON_AddItemToObject(result_root, "matched_functions", match_array);
			// 补充说明
			if (matchCount == 0)
			{
				cJSON_AddStringToObject(result_root, "reason", "No matching function was found in the import table (check function name/sequence number or matching configuration)");
				cJSON_AddStringToObject(response.result.get(), "message", "No matching import function found");
			}
			else
			{
				cJSON_AddStringToObject(response.result.get(), "message", "Successfully matched import function");
			}

			cJSON_AddItemToObject(response.result.get(), "import_by_function_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build matching results");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, matching import function failed");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“遍历所有导入模块和函数”请求
	static ResponseData handle_show_import_all(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：文件状态 + PE结构有效性
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "");
			ReleaseMutex(g_server->mutex);
			return response;
		}


		try
		{
			// 2. 定位导入表（数据目录表索引1）
			DWORD64 importDirRva = NtHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
			if (importDirRva == 0)
			{
				// 无导入表，返回特殊响应（非错误）
				cJSON* result_root = cJSON_CreateObject();
				cJSON_AddStringToObject(result_root, "reason", "Import table data not found (RVA of import table entry in data directory table is 0)");
				cJSON_AddNumberToObject(result_root, "import_module_count", 0);
				cJSON_AddItemToObject(response.result.get(), "import_all_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "Import table data not found");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 3. 计算导入表基础地址（复用原函数逻辑）
			DWORD64 importTableFoa = RVAtoFOA(importDirRva);
			PIMAGE_IMPORT_DESCRIPTOR importTableBase = (PIMAGE_IMPORT_DESCRIPTOR)(importTableFoa + GlobalFileBase);
			if (importTableBase == nullptr)
			{
				throw std::runtime_error("Import table base pointer is null, unable to traverse the import module");
			}
			DWORD64 imageBase = NtHeader->OptionalHeader.ImageBase;  // 模块加载基地址
			int dllIndex = 0;                                    // 导入模块计数器
			cJSON* result_root = cJSON_CreateObject();            // 根对象
			if (result_root == nullptr) throw std::bad_alloc();


			// 4. 构建【导入表全局信息】（对应原函数的“导入表全局信息”打印）
			cJSON* global_info = cJSON_CreateObject();
			if (global_info == nullptr) throw std::bad_alloc();
			// 导入表数据目录RVA/FOA
			cJSON_AddStringToObject(global_info, "import_dir_rva_hex", DexToHex(importDirRva).c_str());
			cJSON_AddNumberToObject(global_info, "import_dir_rva_dec", importDirRva);
			cJSON_AddStringToObject(global_info, "import_dir_foa_hex", DexToHex(importTableFoa).c_str());
			cJSON_AddNumberToObject(global_info, "import_dir_foa_dec", importTableFoa);
			// 模块加载基地址
			cJSON_AddStringToObject(global_info, "image_base_hex", DexToHex(imageBase).c_str());
			cJSON_AddNumberToObject(global_info, "image_base_dec", imageBase);
			cJSON_AddItemToObject(result_root, "import_table_global", global_info);


			// 5. 构建【导入模块数组】（遍历所有导入模块）
			cJSON* module_array = cJSON_CreateArray();
			if (module_array == nullptr) throw std::bad_alloc();
			PIMAGE_IMPORT_DESCRIPTOR ImportTable = importTableBase;

			while (ImportTable->Name != 0)
			{
				dllIndex++;
				cJSON* module_item = cJSON_CreateObject();
				if (module_item == nullptr) throw std::bad_alloc();

				// 5.1 模块基础信息（DLL名称、描述符RVA/FOA）
				// DLL名称
				DWORD64 dllNameRva = ImportTable->Name;
				DWORD64 dllNameFoa = RVAtoFOA(dllNameRva);
				CHAR* dllName = (CHAR*)(dllNameFoa + GlobalFileBase);
				cJSON_AddStringToObject(module_item, "dll_name", dllName ? dllName : "Unknown DLL name");
				cJSON_AddNumberToObject(module_item, "dll_index", dllIndex);

				// 导入描述符自身RVA/FOA（原函数的descRva计算逻辑，完全复用）
				DWORD64 descRva = (DWORD64)((BYTE*)ImportTable - (BYTE*)GlobalFileBase) +
					FOAtoRVA((DWORD64)((BYTE*)ImportTable - (BYTE*)GlobalFileBase) - GlobalFileBase);
				DWORD64 descFoa = RVAtoFOA(descRva);
				cJSON_AddStringToObject(module_item, "descriptor_rva_hex", DexToHex(descRva).c_str());
				cJSON_AddNumberToObject(module_item, "descriptor_rva_dec", descRva);
				cJSON_AddStringToObject(module_item, "descriptor_foa_hex", DexToHex(descFoa).c_str());
				cJSON_AddNumberToObject(module_item, "descriptor_foa_dec", descFoa);

				// 5.2 模块描述符详情（TimeDateStamp、ForwarderChain、INT/IAT RVA/FOA）
				// TimeDateStamp（未绑定/已绑定）
				DWORD64 timeStamp = ImportTable->TimeDateStamp;
				cJSON_AddStringToObject(module_item, "timestamp_hex", DexToHex(timeStamp).c_str());
				cJSON_AddNumberToObject(module_item, "timestamp_dec", timeStamp);
				cJSON_AddStringToObject(module_item, "timestamp_desc", timeStamp == 0 ? "Unbound" : "Bound");

				// ForwarderChain（无转发/存在转发）
				DWORD64 forwarderChain = ImportTable->ForwarderChain;
				cJSON_AddStringToObject(module_item, "forwarder_chain_hex", DexToHex(forwarderChain).c_str());
				cJSON_AddNumberToObject(module_item, "forwarder_chain_dec", forwarderChain);
				cJSON_AddStringToObject(module_item, "forwarder_chain_desc",
					forwarderChain == 0xFFFFFFFF ? "No forwarding (-1)" : "Presence forwarding");

				// INT/IAT的RVA/FOA
				DWORD64 intRva = ImportTable->OriginalFirstThunk;
				DWORD64 iatRva = ImportTable->FirstThunk;
				DWORD64 intFoa = RVAtoFOA(intRva);
				DWORD64 iatFoa = RVAtoFOA(iatRva);
				// INT信息
				cJSON_AddStringToObject(module_item, "int_rva_hex", DexToHex(intRva).c_str());
				cJSON_AddNumberToObject(module_item, "int_rva_dec", intRva);
				cJSON_AddStringToObject(module_item, "int_foa_hex", DexToHex(intFoa).c_str());
				cJSON_AddNumberToObject(module_item, "int_foa_dec", intFoa);
				// IAT信息
				cJSON_AddStringToObject(module_item, "iat_rva_hex", DexToHex(iatRva).c_str());
				cJSON_AddNumberToObject(module_item, "iat_rva_dec", iatRva);
				cJSON_AddStringToObject(module_item, "iat_foa_hex", DexToHex(iatFoa).c_str());
				cJSON_AddNumberToObject(module_item, "iat_foa_dec", iatFoa);


				// 5.3 模块内【导入函数数组】（遍历INT/IAT表项）
				cJSON* func_array = cJSON_CreateArray();
				if (func_array == nullptr) throw std::bad_alloc();
				int funcIndex = 0;
				DWORD64 currentIntRva = intRva;  // 当前INT表项RVA（累加用）
				DWORD64 currentIatRva = iatRva;  // 当前IAT表项RVA（累加用）

				// 初始化INT/IAT指针（处理空表）
				PIMAGE_THUNK_DATA Int = nullptr;
				if (intRva != 0) Int = (PIMAGE_THUNK_DATA)(intFoa + GlobalFileBase);
				PIMAGE_THUNK_DATA Iat = nullptr;
				if (iatRva != 0) Iat = (PIMAGE_THUNK_DATA)(iatFoa + GlobalFileBase);

				// 遍历函数表项（复用原函数的空指针判断逻辑）
				while ((Int != nullptr || Iat != nullptr) &&
					(Int == nullptr || Int->u1.Ordinal != 0) &&
					(Iat == nullptr || Iat->u1.Ordinal != 0))
				{
					funcIndex++;
					cJSON* func_item = cJSON_CreateObject();
					if (func_item == nullptr) throw std::bad_alloc();

					// 函数基础信息（序号、导入类型、Hint值、函数信息）
					cJSON_AddNumberToObject(func_item, "function_index", funcIndex);
					const char* importType = "unknown";
					const char* status = "normal";
					WORD hint = 0;
					std::string funcInfo = "unknown";
					DWORD64 intRawData = 0;
					DWORD64 iatRawData = 0;
					DWORD64 intVa = 0;
					DWORD64 iatVa = 0;

					// 处理INT表项（原始数据、VA）
					if (Int != nullptr)
					{
						intRawData = Int->u1.Ordinal;
						intVa = currentIntRva + imageBase;
					}
					// 处理IAT表项（原始数据、VA）
					if (Iat != nullptr)
					{
						iatRawData = Iat->u1.Ordinal;
						iatVa = currentIatRva + imageBase;
					}

					// 判断导入类型（优先INT，INT为空则用IAT）
					PIMAGE_THUNK_DATA thunk = (Int != nullptr) ? Int : Iat;
					if (thunk != nullptr)
					{
						if (thunk->u1.Ordinal & 0x80000000)
						{
							// 序号导入
							importType = "Sn import";
							WORD ordinal = (WORD)(thunk->u1.Ordinal & 0x7FFF);
							funcInfo = std::to_string(ordinal);
						}
						else
						{
							// 名称导入
							importType = "Name import";
							DWORD64 nameDataRva = thunk->u1.AddressOfData;
							DWORD64 nameDataFoa = RVAtoFOA(nameDataRva);
							PIMAGE_IMPORT_BY_NAME nameData = (PIMAGE_IMPORT_BY_NAME)(nameDataFoa + GlobalFileBase);
							if (nameData != nullptr)
							{
								hint = nameData->Hint;
								funcInfo = nameData->Name;
							}
						}
					}

					// 判断函数状态（INT缺失、存在转发）
					if (intRva == 0)
					{
						status = "Int missing (IAT also acts as int)";
					}
					else if (forwarderChain != 0xFFFFFFFF)
					{
						status = "Existing function forwarding";
					}

					// 填充函数JSON字段
					cJSON_AddStringToObject(func_item, "import_type", importType);
					cJSON_AddNumberToObject(func_item, "hint_value", hint);
					cJSON_AddStringToObject(func_item, "function_info", funcInfo.c_str());
					cJSON_AddStringToObject(func_item, "status", status);
					// INT原始数据/VA
					cJSON_AddStringToObject(func_item, "int_raw_data_hex", DexToHex(intRawData).c_str());
					cJSON_AddNumberToObject(func_item, "int_raw_data_dec", intRawData);
					cJSON_AddStringToObject(func_item, "int_va_hex", DexToHex(intVa).c_str());
					cJSON_AddNumberToObject(func_item, "int_va_dec", intVa);
					// IAT原始数据/VA
					cJSON_AddStringToObject(func_item, "iat_raw_data_hex", DexToHex(iatRawData).c_str());
					cJSON_AddNumberToObject(func_item, "iat_raw_data_dec", iatRawData);
					cJSON_AddStringToObject(func_item, "iat_va_hex", DexToHex(iatVa).c_str());
					cJSON_AddNumberToObject(func_item, "iat_va_dec", iatVa);

					cJSON_AddItemToArray(func_array, func_item);

					// 移动到下一个表项
					if (Int != nullptr) Int++;
					if (Iat != nullptr) Iat++;
					currentIntRva += sizeof(IMAGE_THUNK_DATA);
					currentIatRva += sizeof(IMAGE_THUNK_DATA);
				}

				// 处理“模块无函数”场景
				cJSON_AddNumberToObject(module_item, "function_count", funcIndex);
				if (funcIndex == 0)
				{
					cJSON_AddStringToObject(module_item, "function_reason", "The module has no valid import function");
				}
				cJSON_AddItemToObject(module_item, "import_functions", func_array);
				cJSON_AddItemToArray(module_array, module_item);

				ImportTable++;  // 下一个导入模块
			}


			// 6. 组装最终响应（处理“无导入模块”场景）
			cJSON_AddNumberToObject(result_root, "import_module_count", dllIndex);
			if (dllIndex == 0)
			{
				cJSON_AddStringToObject(result_root, "module_reason", "No import module found (import table is empty)");
				cJSON_AddStringToObject(response.result.get(), "message", "No import modules found");
			}
			else
			{
				cJSON_AddItemToObject(result_root, "import_modules", module_array);
				cJSON_AddStringToObject(response.result.get(), "message", "Successfully traverse all import modules and functions");
			}

			cJSON_AddItemToObject(response.result.get(), "import_all_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build import global response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to traverse the import module and function");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}


	// 新增：处理“显示所有导出表数据”请求
	static ResponseData handle_show_export(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：文件状态 + PE结构有效性
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 定位导出表（数据目录表0号项：导出表）
			DWORD64 exportDirRva = NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
			if (exportDirRva == 0)
			{
				// 无导出表，返回特殊响应（非错误）
				cJSON* result_root = cJSON_CreateObject();
				cJSON_AddStringToObject(result_root, "reason", "Export table data not found (RVA of export table entry in data directory table is 0)");
				cJSON_AddNumberToObject(result_root, "export_function_count", 0);
				cJSON_AddItemToObject(response.result.get(), "export_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "Export table data not found");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 3. 计算导出表基础地址（RVA→FOA + 全局映射基址）
			DWORD64 exportDirFoa = RVAtoFOA(exportDirRva);
			PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)(exportDirFoa + GlobalFileBase);
			if (ExportTable == nullptr)
			{
				throw std::runtime_error("Export table pointer is null, unable to parse export data");
			}
			DWORD64 imageBase = NtHeader->OptionalHeader.ImageBase;  // 镜像基址（计算VA）
			cJSON* result_root = cJSON_CreateObject();            // 响应根对象
			if (result_root == nullptr) throw std::bad_alloc();


			// 4. 构建【导出表全局信息】（对应原函数的“导出表全局信息”打印）
			cJSON* global_info = cJSON_CreateObject();
			if (global_info == nullptr) throw std::bad_alloc();

			// 4.1 导出表地址信息（RVA/FOA）
			cJSON_AddStringToObject(global_info, "export_dir_rva_hex", DexToHex(exportDirRva).c_str());
			cJSON_AddNumberToObject(global_info, "export_dir_rva_dec", exportDirRva);
			cJSON_AddStringToObject(global_info, "export_dir_foa_hex", DexToHex(exportDirFoa).c_str());
			cJSON_AddNumberToObject(global_info, "export_dir_foa_dec", exportDirFoa);

			// 4.2 特征值（Characteristics）
			cJSON_AddStringToObject(global_info, "characteristics_hex", DexToHex(ExportTable->Characteristics).c_str());
			cJSON_AddNumberToObject(global_info, "characteristics_dec", ExportTable->Characteristics);

			// 4.3 时间戳（转换为本地时间，复用原函数逻辑）
			FILETIME ft;
			SYSTEMTIME stLocal;
			ft.dwLowDateTime = ExportTable->TimeDateStamp;
			ft.dwHighDateTime = 0;  // 32位时间戳，高32位补0
			FileTimeToLocalFileTime(&ft, &ft);
			FileTimeToSystemTime(&ft, &stLocal);
			char timeStr[32] = { 0 };
			sprintf_s(timeStr, "%04d-%02d-%02d %02d:%02d:%02d",
				stLocal.wYear, stLocal.wMonth, stLocal.wDay,
				stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
			cJSON_AddStringToObject(global_info, "timestamp_hex", DexToHex(ExportTable->TimeDateStamp).c_str());
			cJSON_AddNumberToObject(global_info, "timestamp_dec", ExportTable->TimeDateStamp);
			cJSON_AddStringToObject(global_info, "timestamp_local", timeStr);

			// 4.4 版本号、模块名、序号与函数计数
			cJSON_AddNumberToObject(global_info, "major_version", ExportTable->MajorVersion);
			cJSON_AddNumberToObject(global_info, "minor_version", ExportTable->MinorVersion);
			// 模块名（RVA→FOA→字符串）
			DWORD64 moduleNameRva = ExportTable->Name;
			DWORD64 moduleNameFoa = RVAtoFOA(moduleNameRva);
			CHAR* moduleName = (CHAR*)(moduleNameFoa + GlobalFileBase);
			cJSON_AddStringToObject(global_info, "module_name", moduleName ? moduleName : "Unknown module name");
			// 起始序号、函数总数、命名函数数
			cJSON_AddStringToObject(global_info, "base_ordinal_hex", DexToHex(ExportTable->Base).c_str());
			cJSON_AddNumberToObject(global_info, "base_ordinal_dec", ExportTable->Base);
			cJSON_AddNumberToObject(global_info, "total_function_count", ExportTable->NumberOfFunctions);
			cJSON_AddNumberToObject(global_info, "named_function_count", ExportTable->NumberOfNames);

			cJSON_AddItemToObject(result_root, "export_table_global", global_info);


			// 5. 获取导出表三张核心表（地址表、名称表、序号表）
			DWORD64* addrTable = (DWORD64*)(RVAtoFOA(ExportTable->AddressOfFunctions) + GlobalFileBase);
			DWORD64* nameTable = (DWORD64*)(RVAtoFOA(ExportTable->AddressOfNames) + GlobalFileBase);
			WORD* idTable = (WORD*)(RVAtoFOA(ExportTable->AddressOfNameOrdinals) + GlobalFileBase);
			if (addrTable == nullptr)
			{
				throw std::runtime_error("The pointer of the exported function address table is null");
			}

			// 6. 构建【导出函数数组】（遍历地址表）
			DWORD64 funcCount = ExportTable->NumberOfFunctions;
			DWORD64 nameCount = ExportTable->NumberOfNames;
			cJSON* func_array = cJSON_CreateArray();
			if (func_array == nullptr) throw std::bad_alloc();

			for (DWORD64 i = 0; i < funcCount; ++i)
			{
				cJSON* func_item = cJSON_CreateObject();
				if (func_item == nullptr) throw std::bad_alloc();

				// 6.1 函数基础地址信息（RVA/VA/FOA）
				DWORD64 funcRva = addrTable[i];
				DWORD64 funcFoa = RVAtoFOA(funcRva);
				DWORD64 funcVa = imageBase + funcRva;
				// RVA
				cJSON_AddStringToObject(func_item, "function_rva_hex", DexToHex(funcRva).c_str());
				cJSON_AddNumberToObject(func_item, "function_rva_dec", funcRva);
				// VA
				cJSON_AddStringToObject(func_item, "function_va_hex", DexToHex(funcVa).c_str());
				cJSON_AddNumberToObject(func_item, "function_va_dec", funcVa);
				// FOA
				cJSON_AddStringToObject(func_item, "function_foa_hex", DexToHex(funcFoa).c_str());
				cJSON_AddNumberToObject(func_item, "function_foa_dec", funcFoa);

				// 6.2 导出序号（起始序号 + 索引）
				DWORD64 exportOrdinal = ExportTable->Base + i;
				cJSON_AddNumberToObject(func_item, "export_ordinal", exportOrdinal);

				// 6.3 函数名称（通过序号表关联名称表，复用原函数逻辑）
				bool hasName = false;
				std::string funcName = "None";
				for (DWORD64 j = 0; j < nameCount; ++j)
				{
					if (i == idTable[j])  // Id_Table[j]是函数在地址表中的索引
					{
						hasName = true;
						DWORD64 funcNameRva = nameTable[j];
						DWORD64 funcNameFoa = RVAtoFOA(funcNameRva);
						CHAR* rawName = (CHAR*)(funcNameFoa + GlobalFileBase);
						if (rawName != nullptr) funcName = rawName;
						break;
					}
				}
				cJSON_AddStringToObject(func_item, "function_name", funcName.c_str());
				cJSON_AddBoolToObject(func_item, "has_named", hasName);

				// 6.4 函数所在节（遍历节表匹配RVA范围）
				const char* sectionName = "unknown";
				PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(NtHeader);
				WORD sectionCount = NtHeader->FileHeader.NumberOfSections;
				for (WORD s = 0; s < sectionCount; ++s)
				{
					DWORD64 secStartRva = sections[s].VirtualAddress;
					DWORD64 secEndRva = secStartRva + sections[s].Misc.VirtualSize;
					if (funcRva >= secStartRva && funcRva < secEndRva)
					{
						sectionName = reinterpret_cast<char*>(sections[s].Name);
						break;
					}
				}
				cJSON_AddStringToObject(func_item, "section_name", sectionName);

				// 6.5 函数状态与转发目标（复用原函数判断逻辑）
				const char* status = "normal";
				const char* forwardTarget = "nothing";
				if (funcRva == 0)
				{
					status = "Invalid address";
				}
				else
				{
					// 检查是否为转发函数（字符串含"!"，格式 DLLName!FunctionName）
					BYTE* forwardStr = (BYTE*)(funcFoa + GlobalFileBase);
					if (forwardStr != nullptr)
					{
						bool isForward = false;
						for (int c = 0; c < 256; ++c)  // 限制长度，避免越界
						{
							if (forwardStr[c] == '\0') break;
							if (forwardStr[c] == '!')
							{
								isForward = true;
								break;
							}
						}
						if (isForward)
						{
							status = "Forwarding function";
							forwardTarget = reinterpret_cast<char*>(forwardStr);
						}
					}
				}
				cJSON_AddStringToObject(func_item, "status", status);
				cJSON_AddStringToObject(func_item, "forward_target", forwardTarget);

				cJSON_AddItemToArray(func_array, func_item);
			}

			// 7. 组装函数数组到根对象
			cJSON_AddNumberToObject(result_root, "export_function_count", funcCount);
			cJSON_AddItemToObject(result_root, "export_functions", func_array);
			cJSON_AddStringToObject(response.result.get(), "message", "Export table data parsing succeeded");
			cJSON_AddItemToObject(response.result.get(), "export_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build export table response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse export table data");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}


	// 新增：处理“显示重定位表分页情况”请求
	static ResponseData handle_show_fix_reloc_page(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：文件状态 + PE结构有效性
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}


		try
		{
			// 2. 定位重定位表（数据目录表5号项：基址重定位表）
			PIMAGE_DATA_DIRECTORY relocDir = &NtHeader->OptionalHeader.DataDirectory[5];
			DWORD64 relocRva = relocDir->VirtualAddress;
			DWORD64 relocSize = relocDir->Size;

			// 处理“无重定位表”场景
			if (relocRva == 0 || relocSize == 0)
			{
				cJSON* result_root = cJSON_CreateObject();
				cJSON_AddStringToObject(result_root, "reason", "No valid relocation table was found (relocation table entry RVA or size 0 in data directory table)");
				cJSON_AddNumberToObject(result_root, "reloc_block_count", 0);
				cJSON_AddItemToObject(response.result.get(), "fix_reloc_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "No valid relocation table found");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 3. 计算重定位表基础地址与核心参数
			DWORD64 relocFoa = RVAtoFOA(relocRva);
			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(GlobalFileBase + relocFoa);
			if (reloc == nullptr)
			{
				throw std::runtime_error("The relocation table pointer is null and cannot traverse the relocation block");
			}
			DWORD64 originalBase = NtHeader->OptionalHeader.ImageBase;  // 原始映像基址
			DWORD64 newBase = originalBase + 0x10000;                  // 模拟新基址（与原函数一致）
			DWORD64 blockIndex = 0;                                   // 重定位块计数器
			cJSON* result_root = cJSON_CreateObject();               // 响应根对象
			if (result_root == nullptr) throw std::bad_alloc();


			// 4. 构建【重定位表全局信息】（对应原函数的“重定位表全局信息”打印）
			cJSON* global_info = cJSON_CreateObject();
			if (global_info == nullptr) throw std::bad_alloc();
			// 基地址信息
			cJSON_AddStringToObject(global_info, "original_image_base_hex", DexToHex(originalBase).c_str());
			cJSON_AddNumberToObject(global_info, "original_image_base_dec", originalBase);
			cJSON_AddStringToObject(global_info, "simulated_new_base_hex", DexToHex(newBase).c_str());
			cJSON_AddNumberToObject(global_info, "simulated_new_base_dec", newBase);
			// 重定位表地址与大小
			cJSON_AddStringToObject(global_info, "reloc_dir_rva_hex", DexToHex(relocRva).c_str());
			cJSON_AddNumberToObject(global_info, "reloc_dir_rva_dec", relocRva);
			cJSON_AddStringToObject(global_info, "reloc_dir_foa_hex", DexToHex(relocFoa).c_str());
			cJSON_AddNumberToObject(global_info, "reloc_dir_foa_dec", relocFoa);
			cJSON_AddStringToObject(global_info, "reloc_dir_size_hex", DexToHex(relocSize).c_str());
			cJSON_AddNumberToObject(global_info, "reloc_dir_size_dec", relocSize);

			cJSON_AddItemToObject(result_root, "reloc_global_info", global_info);


			// 5. 构建【重定位块数组】（遍历所有重定位块）
			cJSON* block_array = cJSON_CreateArray();
			if (block_array == nullptr) throw std::bad_alloc();

			while (reloc->SizeOfBlock != 0)
			{
				blockIndex++;
				cJSON* block_item = cJSON_CreateObject();
				if (block_item == nullptr) throw std::bad_alloc();

				// 5.1 重定位块基础信息（序号、起始RVA/FOA/VA、长度、项数）
				cJSON_AddNumberToObject(block_item, "block_index", blockIndex);
				// 块起始RVA（VirtualAddress）
				DWORD64 blockStartRva = reloc->VirtualAddress;
				cJSON_AddStringToObject(block_item, "block_start_rva_hex", DexToHex(blockStartRva).c_str());
				cJSON_AddNumberToObject(block_item, "block_start_rva_dec", blockStartRva);
				// 块FOA（文件偏移 = 块指针 - 全局映射基址）
				DWORD64 blockFoa = (DWORD64)reloc - GlobalFileBase;
				cJSON_AddStringToObject(block_item, "block_foa_hex", DexToHex(blockFoa).c_str());
				cJSON_AddNumberToObject(block_item, "block_foa_dec", blockFoa);
				// 块内存起始VA（原始基址 + 块起始RVA）
				DWORD64 blockVa = originalBase + blockStartRva;
				cJSON_AddStringToObject(block_item, "block_mem_start_va_hex", DexToHex(blockVa).c_str());
				cJSON_AddNumberToObject(block_item, "block_mem_start_va_dec", blockVa);
				// 块长度与重定位项数
				DWORD64 blockSize = reloc->SizeOfBlock;
				DWORD64 entryCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;  // 每项2字节
				cJSON_AddStringToObject(block_item, "block_size_hex", DexToHex(blockSize).c_str());
				cJSON_AddNumberToObject(block_item, "block_size_dec", blockSize);
				cJSON_AddNumberToObject(block_item, "reloc_entry_count", entryCount);


				// 5.2 构建【块内重定位项数组】（遍历当前块的所有项）
				cJSON* entry_array = cJSON_CreateArray();
				if (entry_array == nullptr) throw std::bad_alloc();
				// 重定位项起始地址（块头后第一个项）
				TypeOffset* relocEntries = (TypeOffset*)(reloc + 1);

				for (DWORD64 i = 0; i < entryCount; ++i)
				{
					cJSON* entry_item = cJSON_CreateObject();
					if (entry_item == nullptr) throw std::bad_alloc();

					// 项基础信息（序号、类型、类型描述、偏移）
					cJSON_AddNumberToObject(entry_item, "entry_index", i + 1);
					WORD entryType = relocEntries[i].Type;
					WORD entryOffset = relocEntries[i].Offset;
					cJSON_AddNumberToObject(entry_item, "entry_type", entryType);
					// 类型描述（与原函数一致的映射）
					const char* typeDesc = "unknown";
					switch (entryType)
					{
					case IMAGE_REL_BASED_ABSOLUTE:    typeDesc = "ABSOLUTE（Meaningless）"; break;
					case IMAGE_REL_BASED_HIGH:        typeDesc = "HIGH（High 16 bits）"; break;
					case IMAGE_REL_BASED_LOW:         typeDesc = "LOW（Lower 16 bits）"; break;
					case IMAGE_REL_BASED_HIGHLOW:     typeDesc = "HIGHLOW（32-bit full address）"; break;
					case IMAGE_REL_BASED_REL32:       typeDesc = "REL32（Relative 32 bits）"; break;
					}
					cJSON_AddStringToObject(entry_item, "entry_type_desc", typeDesc);
					cJSON_AddStringToObject(entry_item, "entry_offset_hex", DexToHex(entryOffset).c_str());
					cJSON_AddNumberToObject(entry_item, "entry_offset_dec", entryOffset);

					// 完整RVA（块起始RVA + 项偏移）
					DWORD64 entryFullRva = blockStartRva + entryOffset;
					cJSON_AddStringToObject(entry_item, "entry_full_rva_hex", DexToHex(entryFullRva).c_str());
					cJSON_AddNumberToObject(entry_item, "entry_full_rva_dec", entryFullRva);

					// 原始地址与重定位后地址（复用原函数计算逻辑）
					DWORD64 entryFoa = RVAtoFOA(entryFullRva);
					DWORD64* entryRawAddr = (DWORD64*)(GlobalFileBase + entryFoa);  // 文件中存储的原始地址
					DWORD64 relocatedAddr = (*entryRawAddr) - originalBase + newBase;  // 重定位后地址
					cJSON_AddStringToObject(entry_item, "entry_raw_addr_hex", DexToHex(*entryRawAddr).c_str());
					cJSON_AddNumberToObject(entry_item, "entry_raw_addr_dec", *entryRawAddr);
					cJSON_AddStringToObject(entry_item, "relocated_addr_hex", DexToHex(relocatedAddr).c_str());
					cJSON_AddNumberToObject(entry_item, "relocated_addr_dec", relocatedAddr);

					cJSON_AddItemToArray(entry_array, entry_item);
				}

				// 组装项数组到块对象
				cJSON_AddItemToObject(block_item, "reloc_entries", entry_array);
				cJSON_AddItemToArray(block_array, block_item);

				// 移动到下一个重定位块（按块大小偏移）
				reloc = (PIMAGE_BASE_RELOCATION)((DWORD64)reloc + blockSize);
			}


			// 6. 组装最终响应
			cJSON_AddNumberToObject(result_root, "reloc_block_count", blockIndex);
			if (blockIndex > 0)
			{
				cJSON_AddItemToObject(result_root, "reloc_blocks", block_array);
				cJSON_AddStringToObject(response.result.get(), "message", "Successfully resolved the paging status of the relocation table");
			}
			else
			{
				cJSON_AddStringToObject(result_root, "reason", "The relocation table exists, but no relocation blocks were found (may be invalid tables)");
				cJSON_Delete(block_array);  // 无块时释放空数组
				cJSON_AddStringToObject(response.result.get(), "message", "Relocation table exists, but no relocation block was found");
			}
			cJSON_AddItemToObject(response.result.get(), "fix_reloc_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build relocation table response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse the paging condition of the relocation table");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}


	// 新增：处理“遍历全部/指定RVA重定位表”请求
	static ResponseData handle_show_fix_reloc(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：参数合法性（由RequestParser预处理，此处二次确认）
		if (params.empty() || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}
		std::string getRva = params[0];
		bool isAll = (getRva == "all" || getRva == "ALL");
		DWORD64 targetRVA = 0;
		if (!isAll)
		{
			targetRVA = HexStringToDec(const_cast<char*>(getRva.c_str()));  // 复用原函数的十六进制转换
		}

		// 2. 基础文件与PE结构校验
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}


		try
		{
			// 3. 定位重定位表（数据目录表5号项）
			PIMAGE_DATA_DIRECTORY relocDir = &NtHeader->OptionalHeader.DataDirectory[5];
			DWORD64 relocRva = relocDir->VirtualAddress;
			DWORD64 relocSize = relocDir->Size;

			// 处理“无重定位表”场景
			if (relocRva == 0 || relocSize == 0)
			{
				cJSON* result_root = cJSON_CreateObject();
				cJSON_AddStringToObject(result_root, "reason", "No valid relocation table was found (relocation table entry RVA or size 0 in data directory table)");
				cJSON_AddStringToObject(result_root, "requested_param", getRva.c_str());
				cJSON_AddNumberToObject(result_root, "matched_block_count", 0);
				cJSON_AddItemToObject(response.result.get(), "fix_reloc_filtered_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "No valid relocation table found");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 4. 计算重定位表基础地址与核心参数
			DWORD64 relocFoa = RVAtoFOA(relocRva);
			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(GlobalFileBase + relocFoa);
			if (reloc == nullptr)
			{
				throw std::runtime_error("The relocation table pointer is null, unable to traverse the relocation data");
			}
			DWORD64 oldBase = NtHeader->OptionalHeader.ImageBase;  // 原始基址
			DWORD64 newBase = oldBase + 0x10000;                  // 模拟新基址（与原函数一致）
			DWORD64 totalBlockCount = 0;                         // 总重定位块数
			DWORD64 matchedBlockCount = 0;                       // 匹配的块数
			cJSON* result_root = cJSON_CreateObject();          // 响应根对象
			if (result_root == nullptr) throw std::bad_alloc();


			// 5. 构建【重定位表全局信息】（含请求参数信息）
			cJSON* global_info = cJSON_CreateObject();
			if (global_info == nullptr) throw std::bad_alloc();
			// 基地址与请求参数
			cJSON_AddStringToObject(global_info, "original_image_base_hex", DexToHex(oldBase).c_str());
			cJSON_AddNumberToObject(global_info, "original_image_base_dec", oldBase);
			cJSON_AddStringToObject(global_info, "simulated_new_base_hex", DexToHex(newBase).c_str());
			cJSON_AddNumberToObject(global_info, "simulated_new_base_dec", newBase);
			cJSON_AddStringToObject(global_info, "requested_param", getRva.c_str());
			cJSON_AddStringToObject(global_info, "param_desc", isAll ? "Traverse all relocation data" : "Traverse the relocation block corresponding to the specified rva");
			// 重定位表地址与大小
			cJSON_AddStringToObject(global_info, "reloc_dir_rva_hex", DexToHex(relocRva).c_str());
			cJSON_AddNumberToObject(global_info, "reloc_dir_rva_dec", relocRva);
			cJSON_AddStringToObject(global_info, "reloc_dir_foa_hex", DexToHex(relocFoa).c_str());
			cJSON_AddNumberToObject(global_info, "reloc_dir_foa_dec", relocFoa);
			cJSON_AddStringToObject(global_info, "reloc_dir_size_hex", DexToHex(relocSize).c_str());
			cJSON_AddNumberToObject(global_info, "reloc_dir_size_dec", relocSize);

			cJSON_AddItemToObject(result_root, "reloc_global_info", global_info);


			// 6. 构建【过滤后的重定位块数组】（按参数匹配块）
			cJSON* matched_blocks = cJSON_CreateArray();
			if (matched_blocks == nullptr) throw std::bad_alloc();

			while (reloc->SizeOfBlock != 0)
			{
				totalBlockCount++;
				// 计算当前块基础信息（复用原函数逻辑）
				DWORD64 blockStartRva = reloc->VirtualAddress;
				DWORD64 blockFOA = (DWORD64)reloc - GlobalFileBase;
				DWORD64 blockVA = oldBase + blockStartRva;
				DWORD64 blockSize = reloc->SizeOfBlock;
				DWORD64 entryCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;  // 每项2字节

				// 按参数过滤：是否匹配当前块
				bool blockMatched = false;
				if (isAll)
				{
					blockMatched = true;
				}
				else
				{
					blockMatched = (blockStartRva == targetRVA);  // 匹配块的起始RVA
				}

				if (blockMatched)
				{
					matchedBlockCount++;
					cJSON* block_item = cJSON_CreateObject();
					if (block_item == nullptr) throw std::bad_alloc();

					// 6.1 块信息（同原函数首项显示的内容）
					cJSON_AddNumberToObject(block_item, "block_index", totalBlockCount);
					cJSON_AddStringToObject(block_item, "block_start_rva_hex", DexToHex(blockStartRva).c_str());
					cJSON_AddNumberToObject(block_item, "block_start_rva_dec", blockStartRva);
					cJSON_AddStringToObject(block_item, "block_foa_hex", DexToHex(blockFOA).c_str());
					cJSON_AddNumberToObject(block_item, "block_foa_dec", blockFOA);
					cJSON_AddStringToObject(block_item, "block_va_hex", DexToHex(blockVA).c_str());
					cJSON_AddNumberToObject(block_item, "block_va_dec", blockVA);
					cJSON_AddStringToObject(block_item, "block_size_hex", DexToHex(blockSize).c_str());
					cJSON_AddNumberToObject(block_item, "block_size_dec", blockSize);
					cJSON_AddNumberToObject(block_item, "reloc_entry_count", entryCount);

					// 6.2 块内重定位项数组（遍历当前块的项）
					cJSON* entry_array = cJSON_CreateArray();
					if (entry_array == nullptr) throw std::bad_alloc();
					TypeOffset* offsetEntries = (TypeOffset*)(reloc + 1);  // 项起始地址

					for (DWORD64 i = 0; i < entryCount; ++i)
					{
						cJSON* entry_item = cJSON_CreateObject();
						if (entry_item == nullptr) throw std::bad_alloc();

						// 项基础信息（类型、偏移、RVA/FOA）
						DWORD64 entryType = offsetEntries[i].Type;
						DWORD64 entryOffset = offsetEntries[i].Offset;
						DWORD64 entryFullRva = blockStartRva + entryOffset;
						DWORD64 entryFOA = RVAtoFOA(entryFullRva);
						DWORD64* entryRawAddr = (DWORD64*)(GlobalFileBase + entryFOA);  // 原始地址
						DWORD64 relocatedVA = (*entryRawAddr) - oldBase + newBase;    // 重定位后地址

						// 类型描述（复用原函数的switch映射）
						const char* typeDesc = "unknown";
						switch (entryType)
						{
						case IMAGE_REL_BASED_ABSOLUTE:    typeDesc = "ABSOLUTE（filling）"; break;
						case IMAGE_REL_BASED_HIGH:        typeDesc = "HIGH（High 16 bits）"; break;
						case IMAGE_REL_BASED_LOW:         typeDesc = "LOW（Lower 16 bits）"; break;
						case IMAGE_REL_BASED_HIGHLOW:     typeDesc = "HIGHLOW（32-bit complete）"; break;
						case IMAGE_REL_BASED_REL32:       typeDesc = "REL32（32-bit relative）"; break;
						case IMAGE_REL_BASED_DIR64:       typeDesc = "DIR64（64 bit）"; break;
						}

						// 填充项JSON字段
						cJSON_AddNumberToObject(entry_item, "entry_index_in_block", i + 1);  // 块内项序号
						cJSON_AddNumberToObject(entry_item, "entry_type", entryType);
						cJSON_AddStringToObject(entry_item, "entry_type_desc", typeDesc);
						cJSON_AddStringToObject(entry_item, "entry_offset_hex", DexToHex(entryOffset).c_str());
						cJSON_AddNumberToObject(entry_item, "entry_offset_dec", entryOffset);
						cJSON_AddStringToObject(entry_item, "entry_full_rva_hex", DexToHex(entryFullRva).c_str());
						cJSON_AddNumberToObject(entry_item, "entry_full_rva_dec", entryFullRva);
						cJSON_AddStringToObject(entry_item, "entry_foa_hex", DexToHex(entryFOA).c_str());
						cJSON_AddNumberToObject(entry_item, "entry_foa_dec", entryFOA);
						cJSON_AddStringToObject(entry_item, "entry_raw_va_hex", DexToHex(*entryRawAddr).c_str());
						cJSON_AddNumberToObject(entry_item, "entry_raw_va_dec", *entryRawAddr);
						cJSON_AddStringToObject(entry_item, "relocated_va_hex", DexToHex(relocatedVA).c_str());
						cJSON_AddNumberToObject(entry_item, "relocated_va_dec", relocatedVA);

						cJSON_AddItemToArray(entry_array, entry_item);
					}

					// 组装项数组到块对象
					cJSON_AddItemToObject(block_item, "reloc_entries_in_block", entry_array);
					cJSON_AddItemToArray(matched_blocks, block_item);
				}

				// 移动到下一个块
				reloc = (PIMAGE_BASE_RELOCATION)((DWORD64)reloc + blockSize);
			}

			// 7. 组装最终响应（补充统计信息）
			cJSON_AddNumberToObject(result_root, "total_block_count", totalBlockCount);
			cJSON_AddNumberToObject(result_root, "matched_block_count", matchedBlockCount);
			if (matchedBlockCount > 0)
			{
				cJSON_AddItemToObject(result_root, "matched_reloc_blocks", matched_blocks);
				cJSON_AddStringToObject(response.result.get(), "message", isAll ? "Complete traversal of all relocation data" : "The relocation data traversal of the specified RVA is completed");
			}
			else
			{
				cJSON_AddStringToObject(result_root, "reason", isAll ? "No relocation blocks found" : "No relocation block matching the specified RVA was found");
				cJSON_Delete(matched_blocks);  // 无匹配块时释放空数组
				cJSON_AddStringToObject(response.result.get(), "message", isAll ? "No relocation blocks found" : "No relocation block matching the specified RVA was found");
			}
			cJSON_AddItemToObject(response.result.get(), "fix_reloc_filtered_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build relocation table response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse relocation table data");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“显示资源表完整信息”请求
	static ResponseData handle_show_resource(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：文件状态与PE结构有效性
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || GlobalFileBase == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer or file mapping base address is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 定位资源表（数据目录表2号项：IMAGE_DIRECTORY_ENTRY_RESOURCE）
			PIMAGE_DATA_DIRECTORY pResDirEntry = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
			DWORD64 resRVA = pResDirEntry->VirtualAddress;
			DWORD64 resSize = pResDirEntry->Size;

			// 处理“无资源表”场景
			if (resRVA == 0 || resSize == 0)
			{
				cJSON* result_root = cJSON_CreateObject();
				cJSON_AddStringToObject(result_root, "reason", "No valid resource table (resource table entry RVA or size 0 in data directory table)");
				cJSON_AddItemToObject(response.result.get(), "resource_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "No valid resource table");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 3. 计算资源表基础地址
			DWORD64 resFOA = RVAtoFOA(resRVA);
			PIMAGE_RESOURCE_DIRECTORY pRootResDir = (PIMAGE_RESOURCE_DIRECTORY)(GlobalFileBase + resFOA);
			if (pRootResDir == nullptr)
			{
				throw std::runtime_error("The resource table root directory pointer is null, unable to parse the resource data");
			}

			// 4. 构建【资源表全局信息】
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();

			cJSON* global_info = cJSON_CreateObject();
			if (global_info == nullptr) throw std::bad_alloc();
			cJSON_AddStringToObject(global_info, "resource_dir_rva_hex", DexToHex(resRVA).c_str());
			cJSON_AddNumberToObject(global_info, "resource_dir_rva_dec", resRVA);
			cJSON_AddStringToObject(global_info, "resource_dir_foa_hex", DexToHex(resFOA).c_str());
			cJSON_AddNumberToObject(global_info, "resource_dir_foa_dec", resFOA);
			cJSON_AddStringToObject(global_info, "resource_dir_size_hex", DexToHex(resSize).c_str());
			cJSON_AddNumberToObject(global_info, "resource_dir_size_dec", resSize);
			cJSON_AddStringToObject(global_info, "root_dir_base_hex", DexToHex((DWORD64)pRootResDir).c_str());
			cJSON_AddNumberToObject(global_info, "root_dir_base_dec", (DWORD64)pRootResDir);
			cJSON_AddStringToObject(global_info, "directory_structure_desc", "Level 3 Directory: type directory → name/id directory → language directory (resource data under language directory)");

			cJSON_AddItemToObject(result_root, "resource_global_info", global_info);

			// 5. 递归解析根目录（类型级，level=1）
			cJSON* root_dir_json = parse_resource_dir_to_json(pRootResDir, resFOA, 1, GlobalFileBase);
			if (root_dir_json != nullptr)
			{
				cJSON_AddItemToObject(result_root, "root_resource_directory", root_dir_json);
			}
			else
			{
				cJSON_AddStringToObject(result_root, "warning", "Resource table root parsing failed (null pointer or out of memory)");
			}

			// 6. 组装响应
			cJSON_AddStringToObject(response.result.get(), "message", "The complete information of the resource table was successfully parsed");
			cJSON_AddItemToObject(response.result.get(), "resource_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build resource table response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse resource table information");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“VA转换为FOA”请求
	static ResponseData handle_va_to_foa(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：参数合法性（由RequestParser预处理，二次确认）
		if (params.empty() || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}
		// 解析VA参数（十进制/十六进制）
		std::string vaStr = params[0];
		char* endptr = nullptr;
		DWORD64 dwVA = 0;
		if (vaStr.substr(0, 2) == "0x" || vaStr.substr(0, 2) == "0X")
		{
			dwVA = strtoul(vaStr.c_str() + 2, &endptr, 16);
		}
		else
		{
			dwVA = strtoul(vaStr.c_str(), &endptr, 10);
		}

		// 2. 基础文件与PE结构校验
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || pSection == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer (ntheader/section table) is invalid, and the file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 3. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			// 全局信息：目标VA、镜像基址
			DWORD64 dwImageBase = NtHeader->OptionalHeader.ImageBase;
			cJSON_AddStringToObject(result_root, "target_va_hex", DexToHex(dwVA).c_str());
			cJSON_AddNumberToObject(result_root, "target_va_dec", dwVA);
			cJSON_AddStringToObject(result_root, "image_base_hex", DexToHex(dwImageBase).c_str());
			cJSON_AddNumberToObject(result_root, "image_base_dec", dwImageBase);
			cJSON_AddNumberToObject(result_root, "section_total_count", NtHeader->FileHeader.NumberOfSections);

			// 4. 原函数核心校验：VA不能小于镜像基址
			if (dwVA < dwImageBase)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "VA invalid");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target VA（0x" + DexToHex(dwVA) + "）Less than mirror base address（0x" + DexToHex(dwImageBase) + "），Non compliance with PE specification").c_str());
				cJSON_AddItemToObject(response.result.get(), "va_to_foa_result", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "VA conversion FOA failed");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 5. 遍历节区：记录扫描过程，查找VA所属节区
			bool bFound = false;
			DWORD64 NumberOfSectionsCount = NtHeader->FileHeader.NumberOfSections;
			cJSON* section_scan_array = cJSON_CreateArray(); // 节区扫描日志
			PIMAGE_SECTION_HEADER pFoundSection = nullptr;   // 找到的目标节区
			DWORD64 dwRVA = 0, dwFOA = 0;                      // 转换结果

			for (DWORD64 i = 0; i < NumberOfSectionsCount; i++)
			{
				PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
				// 计算当前节区的VA范围（左闭右开）
				DWORD64 dwSectionVAStart = dwImageBase + pCurSection->VirtualAddress;
				DWORD64 dwSectionVAEnd = dwSectionVAStart + pCurSection->Misc.VirtualSize;

				// 记录当前节区扫描信息
				cJSON* section_log = cJSON_CreateObject();
				cJSON_AddNumberToObject(section_log, "section_index", i + 1);
				cJSON_AddStringToObject(section_log, "section_name", reinterpret_cast<char*>(pCurSection->Name));
				cJSON_AddStringToObject(section_log, "section_va_start_hex", DexToHex(dwSectionVAStart).c_str());
				cJSON_AddNumberToObject(section_log, "section_va_start_dec", dwSectionVAStart);
				cJSON_AddStringToObject(section_log, "section_va_end_hex", DexToHex(dwSectionVAEnd - 1).c_str()); // 闭区间显示
				cJSON_AddNumberToObject(section_log, "section_va_end_dec", dwSectionVAEnd - 1);
				cJSON_AddStringToObject(section_log, "section_rva_start_hex", DexToHex(pCurSection->VirtualAddress).c_str());
				cJSON_AddNumberToObject(section_log, "section_rva_start_dec", pCurSection->VirtualAddress);
				cJSON_AddStringToObject(section_log, "section_virtual_size_hex", DexToHex(pCurSection->Misc.VirtualSize).c_str());
				cJSON_AddNumberToObject(section_log, "section_virtual_size_dec", pCurSection->Misc.VirtualSize);
				cJSON_AddBoolToObject(section_log, "is_target_section", false); // 标记是否为目标节区
				cJSON_AddItemToArray(section_scan_array, section_log);

				// 检查VA是否在当前节区范围内
				if (dwVA >= dwSectionVAStart && dwVA < dwSectionVAEnd)
				{
					bFound = true;
					pFoundSection = pCurSection;
					// 计算RVA和FOA（原函数公式）
					dwRVA = dwVA - dwImageBase;
					dwFOA = pCurSection->PointerToRawData + (dwRVA - pCurSection->VirtualAddress);
					// 标记当前节区为目标节区
					cJSON_AddBoolToObject(section_log, "is_target_section", true);
					break;
				}
			}

			// 添加节区扫描日志到响应
			cJSON_AddItemToObject(result_root, "section_scan_info", section_scan_array);

			// 6. 处理“找到节区”与“未找到节区”场景
			if (bFound && pFoundSection != nullptr)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", true);

				// 目标节区详情
				cJSON* target_section = cJSON_CreateObject();
				cJSON_AddStringToObject(target_section, "section_name", reinterpret_cast<char*>(pFoundSection->Name));
				cJSON_AddStringToObject(target_section, "section_rva_start_hex", DexToHex(pFoundSection->VirtualAddress).c_str());
				cJSON_AddNumberToObject(target_section, "section_rva_start_dec", pFoundSection->VirtualAddress);
				cJSON_AddStringToObject(target_section, "section_foa_start_hex", DexToHex(pFoundSection->PointerToRawData).c_str());
				cJSON_AddNumberToObject(target_section, "section_foa_start_dec", pFoundSection->PointerToRawData);
				cJSON_AddStringToObject(target_section, "section_virtual_size_hex", DexToHex(pFoundSection->Misc.VirtualSize).c_str());
				cJSON_AddNumberToObject(target_section, "section_virtual_size_dec", pFoundSection->Misc.VirtualSize);
				cJSON_AddItemToObject(result_root, "target_section_info", target_section);

				// 转换步骤（清晰呈现计算过程）
				cJSON* conversion_steps = cJSON_CreateArray();
				// 步骤1：计算RVA
				cJSON* step1 = cJSON_CreateObject();
				cJSON_AddNumberToObject(step1, "step", 1);
				cJSON_AddStringToObject(step1, "description", "Calculate RVA (relative virtual address)");
				cJSON_AddStringToObject(step1, "formula", "RVA = VA - Mirror base address");
				cJSON_AddStringToObject(step1, "calculation",
					std::string("RVA = 0x" + DexToHex(dwVA) + " - 0x" + DexToHex(dwImageBase) + " = 0x" + DexToHex(dwRVA)).c_str());
				cJSON_AddItemToArray(conversion_steps, step1);
				// 步骤2：计算FOA
				cJSON* step2 = cJSON_CreateObject();
				cJSON_AddNumberToObject(step2, "step", 2);
				cJSON_AddStringToObject(step2, "description", "Calculate FOA (file offset address)");
				cJSON_AddStringToObject(step2, "formula", "FOA=start of nodal FOA+(RVA - start of nodal RVA)");
				cJSON_AddStringToObject(step2, "calculation",
					std::string("FOA = 0x" + DexToHex(pFoundSection->PointerToRawData) + " + (0x" + DexToHex(dwRVA) + " - 0x" + DexToHex(pFoundSection->VirtualAddress) + ") = 0x" + DexToHex(dwFOA)).c_str());
				cJSON_AddItemToArray(conversion_steps, step2);
				cJSON_AddItemToObject(result_root, "conversion_steps", conversion_steps);

				// 最终结果
				cJSON* final_result = cJSON_CreateObject();
				cJSON_AddStringToObject(final_result, "rva_hex", DexToHex(dwRVA).c_str());
				cJSON_AddNumberToObject(final_result, "rva_dec", dwRVA);
				cJSON_AddStringToObject(final_result, "foa_hex", DexToHex(dwFOA).c_str());
				cJSON_AddNumberToObject(final_result, "foa_dec", dwFOA);
				cJSON_AddItemToObject(result_root, "final_result", final_result);

				cJSON_AddStringToObject(response.result.get(), "message", "VA converted FOA successfully");
			}
			else
			{
				// 未找到节区：补充镜像大小信息
				DWORD64 imageSize = NtHeader->OptionalHeader.SizeOfImage;
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "VA unmatched section");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target VA（0x" + DexToHex(dwVA) + "）Not within the VA range of any section, which may belong to unallocated memory or exceed the image size（0x" + DexToHex(imageSize) + "）").c_str());
				cJSON_AddStringToObject(result_root, "image_total_size_hex", DexToHex(imageSize).c_str());
				cJSON_AddNumberToObject(result_root, "image_total_size_dec", imageSize);
				cJSON_AddStringToObject(response.result.get(), "message", "VA conversion FOA failed");
			}

			// 7. 组装响应
			cJSON_AddItemToObject(response.result.get(), "va_to_foa_result", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build VA to FOA response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, VA conversion FOA process exception");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“RVA转换为FOA”请求
	static ResponseData handle_rva_to_foa(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：参数合法性（由RequestParser预处理，二次确认）
		if (params.empty() || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}
		// 解析目标RVA（十进制/十六进制）
		std::string rvaStr = params[0];
		char* endptr = nullptr;
		DWORD64 dwRVA = 0;
		if (rvaStr.substr(0, 2) == "0x" || rvaStr.substr(0, 2) == "0X")
		{
			dwRVA = strtoul(rvaStr.c_str() + 2, &endptr, 16);
		}
		else
		{
			dwRVA = strtoul(rvaStr.c_str(), &endptr, 10);
		}

		// 2. 基础文件与PE结构校验
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || pSection == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer (ntheader/section table) is invalid, and the file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 3. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			// 全局信息：目标RVA、镜像基址、节区总数
			DWORD64 dwImageBase = NtHeader->OptionalHeader.ImageBase;
			DWORD64 dwSectionCount = NtHeader->FileHeader.NumberOfSections;
			cJSON_AddStringToObject(result_root, "target_rva_hex", DexToHex(dwRVA).c_str());
			cJSON_AddNumberToObject(result_root, "target_rva_dec", dwRVA);
			cJSON_AddStringToObject(result_root, "image_base_hex", DexToHex(dwImageBase).c_str());
			cJSON_AddNumberToObject(result_root, "image_base_dec", dwImageBase);
			cJSON_AddNumberToObject(result_root, "section_total_count", dwSectionCount);

			// 4. 遍历节区：记录扫描过程，查找RVA所属节区
			bool bFound = false;
			PIMAGE_SECTION_HEADER pFoundSection = nullptr;
			DWORD64 dwVA = 0, dwFOA = 0;  // 转换结果（VA=基址+RVA，FOA=目标地址）
			cJSON* section_scan_array = cJSON_CreateArray();  // 节区扫描日志

			for (DWORD64 i = 0; i < dwSectionCount; i++)
			{
				PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
				// 计算当前节区的RVA范围（原函数核心逻辑：避免越界）
				DWORD64 dwSectionRVAStart = pCurSection->VirtualAddress;
				DWORD64 dwSectionRVAEnd = dwSectionRVAStart + min(pCurSection->Misc.VirtualSize, pCurSection->SizeOfRawData);

				// 记录当前节区扫描信息
				cJSON* section_log = cJSON_CreateObject();
				cJSON_AddNumberToObject(section_log, "section_index", i + 1);
				cJSON_AddStringToObject(section_log, "section_name", reinterpret_cast<char*>(pCurSection->Name));
				cJSON_AddStringToObject(section_log, "section_rva_start_hex", DexToHex(dwSectionRVAStart).c_str());
				cJSON_AddNumberToObject(section_log, "section_rva_start_dec", dwSectionRVAStart);
				cJSON_AddStringToObject(section_log, "section_rva_end_hex", DexToHex(dwSectionRVAEnd).c_str());
				cJSON_AddNumberToObject(section_log, "section_rva_end_dec", dwSectionRVAEnd);
				cJSON_AddStringToObject(section_log, "section_foa_start_hex", DexToHex(pCurSection->PointerToRawData).c_str());
				cJSON_AddNumberToObject(section_log, "section_foa_start_dec", pCurSection->PointerToRawData);
				cJSON_AddBoolToObject(section_log, "is_target_section", false);  // 标记是否为目标节区
				cJSON_AddItemToArray(section_scan_array, section_log);

				// 检查RVA是否在当前节区范围内（原函数判断逻辑）
				if (dwRVA >= dwSectionRVAStart && dwRVA <= dwSectionRVAEnd)
				{
					bFound = true;
					pFoundSection = pCurSection;
					// 计算VA和FOA（严格复用原函数公式）
					dwVA = dwImageBase + dwRVA;
					dwFOA = pCurSection->PointerToRawData + (dwRVA - dwSectionRVAStart);
					// 标记当前节区为目标节区
					cJSON_AddBoolToObject(section_log, "is_target_section", true);
					break;
				}
			}

			// 添加节区扫描日志到响应
			cJSON_AddItemToObject(result_root, "section_scan_info", section_scan_array);

			// 5. 处理“找到节区”与“未找到节区”场景
			if (bFound && pFoundSection != nullptr)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", true);

				// 5.1 目标节区详情
				cJSON* target_section = cJSON_CreateObject();
				cJSON_AddStringToObject(target_section, "section_name", reinterpret_cast<char*>(pFoundSection->Name));
				cJSON_AddStringToObject(target_section, "section_rva_start_hex", DexToHex(pFoundSection->VirtualAddress).c_str());
				cJSON_AddNumberToObject(target_section, "section_rva_start_dec", pFoundSection->VirtualAddress);
				cJSON_AddStringToObject(target_section, "section_rva_end_hex", DexToHex(pFoundSection->VirtualAddress + min(pFoundSection->Misc.VirtualSize, pFoundSection->SizeOfRawData)).c_str());
				cJSON_AddNumberToObject(target_section, "section_rva_end_dec", pFoundSection->VirtualAddress + min(pFoundSection->Misc.VirtualSize, pFoundSection->SizeOfRawData));
				cJSON_AddStringToObject(target_section, "section_foa_start_hex", DexToHex(pFoundSection->PointerToRawData).c_str());
				cJSON_AddNumberToObject(target_section, "section_foa_start_dec", pFoundSection->PointerToRawData);
				cJSON_AddStringToObject(target_section, "section_virtual_size_hex", DexToHex(pFoundSection->Misc.VirtualSize).c_str());
				cJSON_AddNumberToObject(target_section, "section_virtual_size_dec", pFoundSection->Misc.VirtualSize);
				cJSON_AddStringToObject(target_section, "section_file_size_hex", DexToHex(pFoundSection->SizeOfRawData).c_str());
				cJSON_AddNumberToObject(target_section, "section_file_size_dec", pFoundSection->SizeOfRawData);
				cJSON_AddItemToObject(result_root, "target_section_info", target_section);

				// 5.2 转换步骤（清晰呈现计算过程）
				cJSON* conversion_steps = cJSON_CreateArray();
				// 步骤1：计算VA（原函数新增的辅助信息，保留）
				cJSON* step1 = cJSON_CreateObject();
				cJSON_AddNumberToObject(step1, "step", 1);
				cJSON_AddStringToObject(step1, "description", "Calculate VA (virtual address, auxiliary information)");
				cJSON_AddStringToObject(step1, "formula", "");
				cJSON_AddStringToObject(step1, "calculation",
					std::string("VA = 0x" + DexToHex(dwImageBase) + " + 0x" + DexToHex(dwRVA) + " = 0x" + DexToHex(dwVA)).c_str());
				cJSON_AddItemToArray(conversion_steps, step1);
				// 步骤2：计算FOA（核心转换）
				cJSON* step2 = cJSON_CreateObject();
				cJSON_AddNumberToObject(step2, "step", 2);
				cJSON_AddStringToObject(step2, "description", "Calculate FOA (file offset address, core result)");
				cJSON_AddStringToObject(step2, "formula", "FOA=start of nodal FOA+(RVA - start of nodal RVA)");
				cJSON_AddStringToObject(step2, "calculation",
					std::string("FOA = 0x" + DexToHex(pFoundSection->PointerToRawData) + " + (0x" + DexToHex(dwRVA) + " - 0x" + DexToHex(pFoundSection->VirtualAddress) + ") = 0x" + DexToHex(dwFOA)).c_str());
				cJSON_AddItemToArray(conversion_steps, step2);
				cJSON_AddItemToObject(result_root, "conversion_steps", conversion_steps);

				// 5.3 最终结果（VA和FOA）
				cJSON* final_result = cJSON_CreateObject();
				cJSON_AddStringToObject(final_result, "va_hex", DexToHex(dwVA).c_str());
				cJSON_AddNumberToObject(final_result, "va_dec", dwVA);
				cJSON_AddStringToObject(final_result, "foa_hex", DexToHex(dwFOA).c_str());
				cJSON_AddNumberToObject(final_result, "foa_dec", dwFOA);
				cJSON_AddItemToObject(result_root, "final_result", final_result);

				cJSON_AddStringToObject(response.result.get(), "message", "RVA converted FOA successfully");
			}
			else
			{
				// 未找到节区：补充所有节区的RVA范围汇总
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "RVA unmatched segment");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target rva（0x" + DexToHex(dwRVA) + "）Not within the RVA scope of any section, please check the validity of rva").c_str());
				// 汇总所有节区的RVA范围（辅助用户排查）
				std::string sectionRangeSummary = "RVA range of all sections：";
				for (DWORD64 i = 0; i < dwSectionCount; i++)
				{
					PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
					DWORD64 start = pCurSection->VirtualAddress;
					DWORD64 end = start + min(pCurSection->Misc.VirtualSize, pCurSection->SizeOfRawData);
					sectionRangeSummary += "["
						+ std::string(reinterpret_cast<char*>(pCurSection->Name))  // 先转为string
						+ ": 0x" + DexToHex(start)
						+ "-0x" + DexToHex(end)
						+ "], ";
				}
				sectionRangeSummary = sectionRangeSummary.substr(0, sectionRangeSummary.size() - 2); // 移除末尾逗号
				cJSON_AddStringToObject(result_root, "all_section_rva_summary", sectionRangeSummary.c_str());
				cJSON_AddStringToObject(response.result.get(), "message", "RVA failed to convert FOA");
			}

			// 6. 组装最终响应
			cJSON_AddItemToObject(response.result.get(), "rva_to_foa_result", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build RVA to FOA response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, RVA conversion FOA process exception");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“FOA转换为VA”请求
	static ResponseData handle_foa_to_va(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：参数合法性（由RequestParser预处理，二次确认）
		if (params.empty() || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}
		// 解析目标FOA（十进制/十六进制）
		std::string foaStr = params[0];
		char* endptr = nullptr;
		DWORD64 dwFOA = 0;
		if (foaStr.substr(0, 2) == "0x" || foaStr.substr(0, 2) == "0X")
		{
			dwFOA = strtoul(foaStr.c_str() + 2, &endptr, 16);
		}
		else
		{
			dwFOA = strtoul(foaStr.c_str(), &endptr, 10);
		}

		// 2. 基础文件与PE结构校验（确保文件已打开，结构有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || pSection == nullptr || GlobalFileSize == 0)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer (ntheader/section table) or file size is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 3. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			// 全局信息：目标FOA、镜像基址、文件大小、节区总数
			DWORD64 dwImageBase = NtHeader->OptionalHeader.ImageBase;
			DWORD64 dwSectionCount = NtHeader->FileHeader.NumberOfSections;
			cJSON_AddStringToObject(result_root, "target_foa_hex", DexToHex(dwFOA).c_str());
			cJSON_AddNumberToObject(result_root, "target_foa_dec", dwFOA);
			cJSON_AddStringToObject(result_root, "image_base_hex", DexToHex(dwImageBase).c_str());
			cJSON_AddNumberToObject(result_root, "image_base_dec", dwImageBase);
			cJSON_AddStringToObject(result_root, "file_total_size_hex", DexToHex(GlobalFileSize).c_str());
			cJSON_AddNumberToObject(result_root, "file_total_size_dec", GlobalFileSize);
			cJSON_AddNumberToObject(result_root, "section_total_count", dwSectionCount);

			// 4. 原函数核心校验：FOA不能超过文件总大小
			if (dwFOA >= GlobalFileSize)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "FOA exceeds file size");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target FOA（0x" + DexToHex(dwFOA) + "）Exceeds total file size（0x" + DexToHex(GlobalFileSize) + "），Invalid file offset").c_str());
				cJSON_AddItemToObject(response.result.get(), "foa_to_va_result", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "FOA conversion VA failed");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 5. 遍历节区：记录扫描过程，查找FOA所属节区
			bool bFound = false;
			PIMAGE_SECTION_HEADER pFoundSection = nullptr;
			DWORD64 dwRVA = 0, dwVA = 0;  // 转换结果（RVA=节区RVA+偏移，VA=基址+RVA）
			cJSON* section_scan_array = cJSON_CreateArray();  // 节区扫描日志

			for (DWORD64 i = 0; i < dwSectionCount; i++)
			{
				PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
				// 计算当前节区的FOA范围（左闭右开，原函数逻辑）
				DWORD64 dwSectionFOAStart = pCurSection->PointerToRawData;
				DWORD64 dwSectionFOAEnd = dwSectionFOAStart + pCurSection->SizeOfRawData;

				// 记录当前节区扫描信息
				cJSON* section_log = cJSON_CreateObject();
				cJSON_AddNumberToObject(section_log, "section_index", i + 1);
				cJSON_AddStringToObject(section_log, "section_name", reinterpret_cast<char*>(pCurSection->Name));
				cJSON_AddStringToObject(section_log, "section_foa_start_hex", DexToHex(dwSectionFOAStart).c_str());
				cJSON_AddNumberToObject(section_log, "section_foa_start_dec", dwSectionFOAStart);
				cJSON_AddStringToObject(section_log, "section_foa_end_hex", DexToHex(dwSectionFOAEnd - 1).c_str()); // 显示为闭区间
				cJSON_AddNumberToObject(section_log, "section_foa_end_dec", dwSectionFOAEnd - 1);
				cJSON_AddStringToObject(section_log, "section_rva_start_hex", DexToHex(pCurSection->VirtualAddress).c_str());
				cJSON_AddNumberToObject(section_log, "section_rva_start_dec", pCurSection->VirtualAddress);
				cJSON_AddBoolToObject(section_log, "is_target_section", false);  // 标记是否为目标节区
				cJSON_AddItemToArray(section_scan_array, section_log);

				// 检查FOA是否在当前节区范围内（左闭右开，原函数判断逻辑）
				if (dwFOA >= dwSectionFOAStart && dwFOA < dwSectionFOAEnd)
				{
					bFound = true;
					pFoundSection = pCurSection;
					// 计算RVA和VA（严格复用原函数公式）
					dwRVA = pCurSection->VirtualAddress + (dwFOA - dwSectionFOAStart);
					dwVA = dwImageBase + dwRVA;
					// 标记当前节区为目标节区
					cJSON_AddBoolToObject(section_log, "is_target_section", true);
					break;
				}
			}

			// 添加节区扫描日志到响应
			cJSON_AddItemToObject(result_root, "section_scan_info", section_scan_array);

			// 6. 处理“找到节区”与“未找到节区”场景
			if (bFound && pFoundSection != nullptr)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", true);

				// 6.1 目标节区详情
				cJSON* target_section = cJSON_CreateObject();
				cJSON_AddStringToObject(target_section, "section_name", reinterpret_cast<char*>(pFoundSection->Name));
				cJSON_AddStringToObject(target_section, "section_foa_start_hex", DexToHex(pFoundSection->PointerToRawData).c_str());
				cJSON_AddNumberToObject(target_section, "section_foa_start_dec", pFoundSection->PointerToRawData);
				cJSON_AddStringToObject(target_section, "section_foa_end_hex", DexToHex(pFoundSection->PointerToRawData + pFoundSection->SizeOfRawData - 1).c_str());
				cJSON_AddNumberToObject(target_section, "section_foa_end_dec", pFoundSection->PointerToRawData + pFoundSection->SizeOfRawData - 1);
				cJSON_AddStringToObject(target_section, "section_rva_start_hex", DexToHex(pFoundSection->VirtualAddress).c_str());
				cJSON_AddNumberToObject(target_section, "section_rva_start_dec", pFoundSection->VirtualAddress);
				cJSON_AddStringToObject(target_section, "section_file_size_hex", DexToHex(pFoundSection->SizeOfRawData).c_str());
				cJSON_AddNumberToObject(target_section, "section_file_size_dec", pFoundSection->SizeOfRawData);
				cJSON_AddItemToObject(result_root, "target_section_info", target_section);

				// 6.2 转换步骤（清晰呈现计算过程）
				cJSON* conversion_steps = cJSON_CreateArray();
				// 步骤1：计算RVA（核心中间结果）
				cJSON* step1 = cJSON_CreateObject();
				cJSON_AddNumberToObject(step1, "step", 1);
				cJSON_AddStringToObject(step1, "description", "Calculate RVA (relative virtual address)");
				cJSON_AddStringToObject(step1, "formula", "RVA=start of RVA+(FOA - start of FOA)");
				cJSON_AddStringToObject(step1, "calculation",
					std::string("RVA = 0x" + DexToHex(pFoundSection->VirtualAddress) + " + (0x" + DexToHex(dwFOA) + " - 0x" + DexToHex(pFoundSection->PointerToRawData) + ") = 0x" + DexToHex(dwRVA)).c_str());
				cJSON_AddItemToArray(conversion_steps, step1);
				// 步骤2：计算VA（最终虚拟地址）
				cJSON* step2 = cJSON_CreateObject();
				cJSON_AddNumberToObject(step2, "step", 2);
				cJSON_AddStringToObject(step2, "description", "Calculate VA (virtual address, core result)");
				cJSON_AddStringToObject(step2, "formula", "VA=mirror base address+rva");
				cJSON_AddStringToObject(step2, "calculation",
					std::string("VA = 0x" + DexToHex(dwImageBase) + " + 0x" + DexToHex(dwRVA) + " = 0x" + DexToHex(dwVA)).c_str());
				cJSON_AddItemToArray(conversion_steps, step2);
				cJSON_AddItemToObject(result_root, "conversion_steps", conversion_steps);

				// 6.3 最终结果（RVA和VA）
				cJSON* final_result = cJSON_CreateObject();
				cJSON_AddStringToObject(final_result, "rva_hex", DexToHex(dwRVA).c_str());
				cJSON_AddNumberToObject(final_result, "rva_dec", dwRVA);
				cJSON_AddStringToObject(final_result, "va_hex", DexToHex(dwVA).c_str());
				cJSON_AddNumberToObject(final_result, "va_dec", dwVA);
				cJSON_AddItemToObject(result_root, "final_result", final_result);

				cJSON_AddStringToObject(response.result.get(), "message", "FOA converted VA successfully");
			}
			else
			{
				// 未找到节区：提示可能为节区对齐间隙（原函数错误原因）
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "FOA unmatched section");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target FOA（0x" + DexToHex(dwFOA) + "）Not within the file offset range of any section, which may belong to section alignment gap or unallocated file area").c_str());
				// 汇总所有节区的FOA范围（辅助用户排查）
				std::string sectionRangeSummary = "FOA scope of all sections：";
				for (DWORD64 i = 0; i < dwSectionCount; i++)
				{
					PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
					DWORD64 start = pCurSection->PointerToRawData;
					DWORD64 end = start + pCurSection->SizeOfRawData - 1;
					sectionRangeSummary += "["  // 字符串字面量会被隐式转换为std::string参与拼接
						+ std::string(reinterpret_cast<char*>(pCurSection->Name))  // 将节区名转为std::string
						+ ": 0x" + DexToHex(start)
						+ "-0x" + DexToHex(end)
						+ "], ";
				}
				sectionRangeSummary = sectionRangeSummary.substr(0, sectionRangeSummary.size() - 2); // 移除末尾逗号
				cJSON_AddStringToObject(result_root, "all_section_foa_summary", sectionRangeSummary.c_str());
				cJSON_AddStringToObject(response.result.get(), "message", "FOA conversion VA failed");
			}

			// 7. 组装最终响应
			cJSON_AddItemToObject(response.result.get(), "foa_to_va_result", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build FOA to VA response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, FOA conversion VA process exception");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“VA转换为RVA”请求
	static ResponseData handle_va_to_rva(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：参数合法性（由RequestParser预处理，二次确认）
		if (params.empty() || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}
		// 解析目标VA（十进制/十六进制）
		std::string vaStr = params[0];
		char* endptr = nullptr;
		DWORD64 dwVA = 0;
		if (vaStr.substr(0, 2) == "0x" || vaStr.substr(0, 2) == "0X")
		{
			dwVA = strtoul(vaStr.c_str() + 2, &endptr, 16);
		}
		else
		{
			dwVA = strtoul(vaStr.c_str(), &endptr, 10);
		}

		// 2. 基础文件与PE结构校验（确保文件已打开、结构有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer (ntheader) is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 3. 构建响应根对象，获取PE核心参数
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			DWORD64 dwImageBase = NtHeader->OptionalHeader.ImageBase;    // 镜像基址
			DWORD64 dwSizeOfImage = NtHeader->OptionalHeader.SizeOfImage;// 模块总大小
			// 全局信息：目标VA、基址、模块大小
			cJSON_AddStringToObject(result_root, "target_va_hex", DexToHex(dwVA).c_str());
			cJSON_AddNumberToObject(result_root, "target_va_dec", dwVA);
			cJSON_AddStringToObject(result_root, "image_base_hex", DexToHex(dwImageBase).c_str());
			cJSON_AddNumberToObject(result_root, "image_base_dec", dwImageBase);
			cJSON_AddStringToObject(result_root, "module_total_size_hex", DexToHex(dwSizeOfImage).c_str());
			cJSON_AddNumberToObject(result_root, "module_total_size_dec", dwSizeOfImage);


			// 4. 原函数核心逻辑：双重校验 + 转换计算
			// 校验1：VA是否≥镜像基址
			if (dwVA < dwImageBase)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "VA invalid (less than mirror base address)");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target VA（0x" + DexToHex(dwVA) + "）Less than mirror base address（0x" + DexToHex(dwImageBase) + "），Does not conform to PE virtual address specification").c_str());
				cJSON_AddItemToObject(response.result.get(), "va_to_rva_result", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "VA conversion RVA failed");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 计算RVA（核心公式：RVA = VA - 镜像基址）
			DWORD64 dwRVA = dwVA - dwImageBase;

			// 校验2：RVA是否在模块有效范围内
			if (dwRVA >= dwSizeOfImage)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "RVA out of module range");
				// 构建详细错误信息，包含计算过程
				std::string errorDetail =
					"VA → RVA calculation result exceeds the valid range of the module：\n"
					"  VA: 0x" + DexToHex(dwVA) + " | Mirror base address: 0x" + DexToHex(dwImageBase) + "\n"
					"  Calculated rva: 0x" + DexToHex(dwRVA) + "\n"
					"  Total module size（SizeOfImage）: 0x" + DexToHex(dwSizeOfImage) + "，RVA should be less than this value";
				cJSON_AddStringToObject(result_root, "error_reason", errorDetail.c_str());
				cJSON_AddStringToObject(result_root, "calculated_rva_hex", DexToHex(dwRVA).c_str());
				cJSON_AddNumberToObject(result_root, "calculated_rva_dec", dwRVA);
				cJSON_AddItemToObject(response.result.get(), "va_to_rva_result", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "VA conversion RVA failed");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}


			// 5. 转换成功：构建步骤与结果
			cJSON_AddBoolToObject(result_root, "conversion_success", true);

			// 5.1 转换步骤（简化但清晰，突出减法公式）
			cJSON* conversion_steps = cJSON_CreateArray();
			cJSON* step1 = cJSON_CreateObject();
			cJSON_AddNumberToObject(step1, "step", 1);
			cJSON_AddStringToObject(step1, "description", "Core conversion: calculate RVA (relative virtual address)");
			cJSON_AddStringToObject(step1, "formula", "RVA = VA - Mirror base address");
			cJSON_AddStringToObject(step1, "calculation",
				std::string("RVA = 0x" + DexToHex(dwVA) + " - 0x" + DexToHex(dwImageBase) + " = 0x" + DexToHex(dwRVA)).c_str());
			cJSON_AddItemToArray(conversion_steps, step1);
			cJSON_AddItemToObject(result_root, "conversion_steps", conversion_steps);

			// 5.2 最终结果（含有效性标识）
			cJSON* final_result = cJSON_CreateObject();
			cJSON_AddStringToObject(final_result, "rva_hex", DexToHex(dwRVA).c_str());
			cJSON_AddNumberToObject(final_result, "rva_dec", dwRVA);
			cJSON_AddBoolToObject(final_result, "rva_valid", true);
			cJSON_AddStringToObject(final_result, "validity_desc", "RVA is within the effective range of the module (<total module size)");
			cJSON_AddItemToObject(result_root, "final_result", final_result);

			cJSON_AddStringToObject(response.result.get(), "message", "VA successfully converted rva");
			cJSON_AddItemToObject(response.result.get(), "va_to_rva_result", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build VA to RVA response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, VA conversion RVA process exception");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“RVA转换为VA”请求
	static ResponseData handle_rva_to_va(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局变量

		// 1. 前置校验：参数合法性（由RequestParser预处理，二次确认）
		if (params.empty() || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}
		// 解析目标RVA（十进制/十六进制）
		std::string rvaStr = params[0];
		char* endptr = nullptr;
		DWORD64 dwRVA = 0;
		if (rvaStr.substr(0, 2) == "0x" || rvaStr.substr(0, 2) == "0X")
		{
			dwRVA = strtoul(rvaStr.c_str() + 2, &endptr, 16);
		}
		else
		{
			dwRVA = strtoul(rvaStr.c_str(), &endptr, 10);
		}

		// 2. 基础文件与PE结构校验（确保文件已打开、结构有效）
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr || pSection == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer (ntheader/section table) is invalid, and the file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 3. 构建响应根对象，获取PE核心参数
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			DWORD64 dwImageBase = NtHeader->OptionalHeader.ImageBase;    // 镜像基址
			DWORD64 dwSizeOfImage = NtHeader->OptionalHeader.SizeOfImage;// 模块总大小
			DWORD64 dwSectionCount = NtHeader->FileHeader.NumberOfSections; // 节区总数
			// 全局信息：目标RVA、基址、模块大小、节区总数
			cJSON_AddStringToObject(result_root, "target_rva_hex", DexToHex(dwRVA).c_str());
			cJSON_AddNumberToObject(result_root, "target_rva_dec", dwRVA);
			cJSON_AddStringToObject(result_root, "image_base_hex", DexToHex(dwImageBase).c_str());
			cJSON_AddNumberToObject(result_root, "image_base_dec", dwImageBase);
			cJSON_AddStringToObject(result_root, "module_total_size_hex", DexToHex(dwSizeOfImage).c_str());
			cJSON_AddNumberToObject(result_root, "module_total_size_dec", dwSizeOfImage);
			cJSON_AddNumberToObject(result_root, "section_total_count", dwSectionCount);


			// 4. 原函数核心逻辑1：基础校验（RVA是否≤模块大小）
			if (dwRVA >= dwSizeOfImage)
			{
				cJSON_AddBoolToObject(result_root, "conversion_success", false);
				cJSON_AddStringToObject(result_root, "error_type", "RVA invalid (over module size)");
				cJSON_AddStringToObject(result_root, "error_reason",
					std::string("Target rva（0x" + DexToHex(dwRVA) + "）Exceeds total module size（0x" + DexToHex(dwSizeOfImage) + "），Non compliance with PE specification").c_str());
				cJSON_AddItemToObject(response.result.get(), "rva_to_va_result", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "RVA failed to convert VA");
				response.success = true;
				ReleaseMutex(g_server->mutex);
				return response;
			}

			// 5. 计算VA（核心公式：VA = 镜像基址 + RVA）
			DWORD64 dwVA = dwImageBase + dwRVA;

			// 6. 原函数核心逻辑2：增强校验（RVA是否在有效节区内）
			bool bInValidSection = false;
			PIMAGE_SECTION_HEADER pFoundSection = nullptr;
			cJSON* section_check_array = cJSON_CreateArray();  // 节区校验日志

			for (DWORD64 i = 0; i < dwSectionCount; i++)
			{
				PIMAGE_SECTION_HEADER pCurSection = &pSection[i];
				// 计算节区RVA范围（原函数逻辑：避免越界）
				DWORD64 dwSectionRVAStart = pCurSection->VirtualAddress;
				DWORD64 dwSectionRVAEnd = dwSectionRVAStart + min(pCurSection->Misc.VirtualSize, pCurSection->SizeOfRawData);

				// 记录节区校验日志
				cJSON* section_log = cJSON_CreateObject();
				cJSON_AddNumberToObject(section_log, "section_index", i + 1);
				cJSON_AddStringToObject(section_log, "section_name", reinterpret_cast<char*>(pCurSection->Name));
				cJSON_AddStringToObject(section_log, "section_rva_start_hex", DexToHex(dwSectionRVAStart).c_str());
				cJSON_AddNumberToObject(section_log, "section_rva_start_dec", dwSectionRVAStart);
				cJSON_AddStringToObject(section_log, "section_rva_end_hex", DexToHex(dwSectionRVAEnd).c_str());
				cJSON_AddNumberToObject(section_log, "section_rva_end_dec", dwSectionRVAEnd);
				bool isMatch = (dwRVA >= dwSectionRVAStart && dwRVA <= dwSectionRVAEnd);
				cJSON_AddBoolToObject(section_log, "is_rva_in_section", isMatch);
				cJSON_AddItemToArray(section_check_array, section_log);

				// 标记RVA是否在当前节区内
				if (isMatch)
				{
					bInValidSection = true;
					pFoundSection = pCurSection;
					break;  // 找到后退出循环（原函数逻辑）
				}
			}

			// 添加节区校验日志到响应
			cJSON_AddItemToObject(result_root, "section_check_info", section_check_array);


			// 7. 转换成功：构建步骤、校验结果与最终VA
			cJSON_AddBoolToObject(result_root, "conversion_success", true);

			// 7.1 转换步骤（突出核心加法公式）
			cJSON* conversion_steps = cJSON_CreateArray();
			cJSON* step1 = cJSON_CreateObject();
			cJSON_AddNumberToObject(step1, "step", 1);
			cJSON_AddStringToObject(step1, "description", "Core conversion: calculate VA (virtual address)");
			cJSON_AddStringToObject(step1, "formula", "VA = Mirror base address + RVA");
			cJSON_AddStringToObject(step1, "calculation",
				std::string("VA = 0x" + DexToHex(dwImageBase) + " + 0x" + DexToHex(dwRVA) + " = 0x" + DexToHex(dwVA)).c_str());
			cJSON_AddItemToArray(conversion_steps, step1);
			cJSON_AddItemToObject(result_root, "conversion_steps", conversion_steps);

			// 7.2 增强校验结果（是否在有效节区）
			cJSON* section_check_result = cJSON_CreateObject();
			cJSON_AddBoolToObject(section_check_result, "is_rva_in_valid_section", bInValidSection);
			if (bInValidSection && pFoundSection != nullptr)
			{
				cJSON_AddStringToObject(section_check_result, "valid_section_name", reinterpret_cast<char*>(pFoundSection->Name));
				cJSON_AddStringToObject(section_check_result, "check_desc", "RVA is within the valid section, and VA address is valid");
			}
			else
			{
				cJSON_AddStringToObject(section_check_result, "valid_section_name", "None");
				cJSON_AddStringToObject(section_check_result, "check_desc", "RVA is not in any section and may belong to unallocated memory area");
			}
			cJSON_AddItemToObject(result_root, "section_check_result", section_check_result);

			// 7.3 最终结果（VA及有效性说明）
			cJSON* final_result = cJSON_CreateObject();
			cJSON_AddStringToObject(final_result, "va_hex", DexToHex(dwVA).c_str());
			cJSON_AddNumberToObject(final_result, "va_dec", dwVA);
			cJSON_AddStringToObject(final_result, "va_validity_desc",
				bInValidSection ? "VA valid (RVA is within the valid section)" : "VA syntax is valid but RVA is not in the section (possibly unallocated memory)");
			cJSON_AddItemToObject(result_root, "final_result", final_result);

			cJSON_AddStringToObject(response.result.get(), "message", "RVA converted VA successfully");
			cJSON_AddItemToObject(response.result.get(), "rva_to_va_result", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to build RVA to VA response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, RVA conversion VA process is abnormal");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“读取文件十六进制/ASCII”请求
	static ResponseData handle_get_hex_ascii(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局资源

		// 1. 前置校验：参数合法性（由RequestParser预处理，二次确认）
		if (params.empty() || params.size() != 2 || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params.empty() ? "Parameter is empty" : params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 解析参数（已由RequestParser转为十进制字符串）
		long long StartAddr = std::stoll(params[0]);
		long long AddrLen = std::stoll(params[1]);

		// 2. 基础校验：文件已打开、GlobalFilePath有效
		if (!IsOpen || GlobalFilePath[0] == '\0')
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 3. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			cJSON_AddStringToObject(result_root, "file_path", GlobalFilePath);

			// 4. 步骤1：获取文件大小（调用内部辅助函数）
			std::string fileSizeErr;
			long long fileSize = hex_get_file_size(GlobalFilePath, fileSizeErr);
			if (fileSize < 0)
			{
				throw std::runtime_error("Failed to get file size: " + fileSizeErr);
			}
			cJSON_AddStringToObject(result_root, "file_total_size_hex", DexToHex(fileSize).c_str());
			cJSON_AddNumberToObject(result_root, "file_total_size_dec", fileSize);

			// 5. 步骤2：校验并计算实际读取范围（复用原函数逻辑）
			long long endAddr = StartAddr + AddrLen;
			long long actualStart = StartAddr;
			long long actualLen = AddrLen;
			std::string warning;

			// 校验起始地址是否超出文件大小
			if (actualStart >= fileSize)
			{
				throw std::runtime_error(
					"Start offset (" + std::to_string(actualStart) + ") exceeds total file size (" + std::to_string(fileSize) + ")"
					);
			}
			// 自动截断超出文件大小的部分
			if (endAddr > fileSize)
			{
				actualLen = fileSize - actualStart;
				endAddr = fileSize;
				warning = "Read range exceeds file size, automatically truncated to: start=" + std::to_string(actualStart) +
					", end=" + std::to_string(endAddr - 1) + ", length=" + std::to_string(actualLen);
			}

			// 添加读取范围信息到响应
			cJSON* read_range = cJSON_CreateObject();
			cJSON_AddStringToObject(read_range, "requested_start_hex", DexToHex(StartAddr).c_str());
			cJSON_AddNumberToObject(read_range, "requested_start_dec", StartAddr);
			cJSON_AddStringToObject(read_range, "requested_len_hex", DexToHex(AddrLen).c_str());
			cJSON_AddNumberToObject(read_range, "requested_len_dec", AddrLen);
			cJSON_AddStringToObject(read_range, "actual_start_hex", DexToHex(actualStart).c_str());
			cJSON_AddNumberToObject(read_range, "actual_start_dec", actualStart);
			cJSON_AddStringToObject(read_range, "actual_end_hex", DexToHex(endAddr - 1).c_str());
			cJSON_AddNumberToObject(read_range, "actual_end_dec", endAddr - 1);
			cJSON_AddStringToObject(read_range, "actual_len_hex", DexToHex(actualLen).c_str());
			cJSON_AddNumberToObject(read_range, "actual_len_dec", actualLen);
			if (!warning.empty())
			{
				cJSON_AddStringToObject(read_range, "warning", warning.c_str());
			}
			cJSON_AddItemToObject(result_root, "read_range", read_range);

			// 6. 步骤3：打开文件并读取数据
			FILE* fp = nullptr;
			errno_t err = fopen_s(&fp, GlobalFilePath, "rb");
			if (err != 0 || fp == nullptr)
			{
				throw std::runtime_error("Failed to open file (error code: " + std::to_string(err) + ")");
			}

			// 定位到实际起始偏移
			if (fseek(fp, actualStart, SEEK_SET) != 0)
			{
				fclose(fp);
				throw std::runtime_error("Failed to seek to start offset (" + std::to_string(actualStart) + ")");
			}

			// 7. 步骤4：读取并处理数据（16字节/行）
			unsigned char buffer[16];
			long long totalRead = 0;
			long long lineCount = 0;
			cJSON* hex_data = cJSON_CreateArray();  // 存储所有行数据

			while (totalRead < actualLen)
			{
				// 计算当前行读取字节数（最后一行可能不足16字节）
				size_t readSize = (actualLen - totalRead) < 16 ? (size_t)(actualLen - totalRead) : 16;
				size_t bytesRead = fread(buffer, 1, readSize, fp);
				if (bytesRead == 0) break;

				// 构建当前行的JSON对象
				cJSON* line_item = cJSON_CreateObject();
				long long lineOffset = actualStart + totalRead;
				// 行起始偏移
				cJSON_AddStringToObject(line_item, "line_offset_hex", DexToHex(lineOffset).c_str());
				cJSON_AddNumberToObject(line_item, "line_offset_dec", lineOffset);

				// 十六进制数组（16个元素，不足补空字符串）
				cJSON* hex_array = cJSON_CreateArray();
				for (size_t i = 0; i < 16; ++i)
				{
					if (i < bytesRead)
					{
						char hex[4] = { 0 };
						sprintf_s(hex, "%02X", buffer[i]);
						cJSON_AddItemToArray(hex_array, cJSON_CreateString(hex));
					}
					else
					{
						cJSON_AddItemToArray(hex_array, cJSON_CreateString(""));  // 不足补空
					}
				}
				cJSON_AddItemToObject(line_item, "hex_array", hex_array);

				// ASCII字符串（不可打印字符用.代替）
				std::string asciiStr;
				for (size_t i = 0; i < bytesRead; ++i)
				{
					asciiStr += isprint(buffer[i]) ? (char)buffer[i] : '.';
				}
				cJSON_AddStringToObject(line_item, "ascii_str", asciiStr.c_str());

				// 添加当前行到数据数组
				cJSON_AddItemToArray(hex_data, line_item);

				totalRead += bytesRead;
				lineCount++;
			}

			fclose(fp);

			// 8. 步骤5：添加统计信息和数据到响应
			cJSON* stats = cJSON_CreateObject();
			cJSON_AddNumberToObject(stats, "total_read_bytes", totalRead);
			cJSON_AddNumberToObject(stats, "total_lines", lineCount);
			cJSON_AddItemToObject(result_root, "statistics", stats);
			cJSON_AddItemToObject(result_root, "hex_ascii_data", hex_data);

			// 9. 组装成功响应
			cJSON_AddStringToObject(response.result.get(), "message", "Successfully read file hex/ASCII");
			cJSON_AddItemToObject(response.result.get(), "hex_ascii_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to read file data");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“特征码搜索”请求
	static ResponseData handle_search_signature(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局资源

		// 1. 前置校验：参数合法性（由RequestParser预处理）
		if (params.empty() || params.size() != 3 || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params.empty() ? "Parameter is empty" : params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 解析参数（StartAddr和SearchLen已转为十进制字符串）
		long long StartAddr = std::stoll(params[0]);
		long long SearchLen = std::stoll(params[1]);
		std::string sigStr = params[2];
		unsigned char* buffer = nullptr; // 文件缓冲区，最后需释放

		try
		{
			// 2. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (result_root == nullptr) throw std::bad_alloc();
			cJSON_AddStringToObject(result_root, "file_path", GlobalFilePath);

			// 3. 步骤1：解析特征码
			std::vector<unsigned char> signature = parse_signature(sigStr);
			if (signature.empty())
			{
				throw std::runtime_error("Invalid signature format (correct format: \"55 8B ?? EC\", only supports space-separated 2-digit hexadecimal or \"??\" wildcard)");
			}
			size_t sigLen = signature.size();
			// 添加特征码配置到响应
			cJSON* sigConfig = cJSON_CreateObject();
			cJSON_AddStringToObject(sigConfig, "signature_str", sigStr.c_str());
			cJSON_AddNumberToObject(sigConfig, "signature_len_bytes", sigLen);
			cJSON_AddItemToObject(result_root, "signature_config", sigConfig);

			// 4. 步骤2：获取文件大小并校验搜索范围
			std::string fileSizeErr;
			long long fileSize = hex_get_file_size(GlobalFilePath, fileSizeErr);
			if (fileSize < 0)
			{
				throw std::runtime_error("Failed to get file size: " + fileSizeErr);
			}
			cJSON_AddStringToObject(result_root, "file_total_size_hex", DexToHex(fileSize).c_str());
			cJSON_AddNumberToObject(result_root, "file_total_size_dec", fileSize);

			// 计算实际搜索范围（截断超出文件的部分）
			long long endAddr = StartAddr + SearchLen;
			long long actualStart = StartAddr;
			long long actualLen = SearchLen;
			std::string warning;

			// 校验起始地址是否超出文件
			if (actualStart >= fileSize)
			{
				throw std::runtime_error(
					"Start offset (" + std::to_string(actualStart) + ") exceeds total file size (" + std::to_string(fileSize) + ")"
					);
			}
			// 截断搜索范围
			if (endAddr > fileSize)
			{
				actualLen = fileSize - actualStart;
				endAddr = fileSize;
				warning = "Search range exceeds file size, automatically truncated to: start=" + std::to_string(actualStart) +
					", end=" + std::to_string(endAddr - 1) + ", length=" + std::to_string(actualLen);
			}
			// 校验截断后搜索长度是否大于特征码长度
			if (actualLen < (long long)sigLen)
			{
				throw std::runtime_error(
					"Search length (" + std::to_string(actualLen) + " bytes) is less than signature length (" + std::to_string(sigLen) + " bytes)"
					);
			}

			// 添加搜索范围信息到响应
			cJSON* searchRange = cJSON_CreateObject();
			cJSON_AddStringToObject(searchRange, "requested_start_hex", DexToHex(StartAddr).c_str());
			cJSON_AddNumberToObject(searchRange, "requested_start_dec", StartAddr);
			cJSON_AddStringToObject(searchRange, "requested_len_hex", DexToHex(SearchLen).c_str());
			cJSON_AddNumberToObject(searchRange, "requested_len_dec", SearchLen);
			cJSON_AddStringToObject(searchRange, "actual_start_hex", DexToHex(actualStart).c_str());
			cJSON_AddNumberToObject(searchRange, "actual_start_dec", actualStart);
			cJSON_AddStringToObject(searchRange, "actual_end_hex", DexToHex(endAddr - 1).c_str());
			cJSON_AddNumberToObject(searchRange, "actual_end_dec", endAddr - 1);
			cJSON_AddStringToObject(searchRange, "actual_len_hex", DexToHex(actualLen).c_str());
			cJSON_AddNumberToObject(searchRange, "actual_len_dec", actualLen);
			if (!warning.empty())
			{
				cJSON_AddStringToObject(searchRange, "warning", warning.c_str());
			}
			cJSON_AddItemToObject(result_root, "search_range", searchRange);

			// 5. 步骤3：打开文件并读取搜索区域到缓冲区
			FILE* fp = nullptr;
			errno_t err = fopen_s(&fp, GlobalFilePath, "rb");
			if (err != 0 || fp == nullptr)
			{
				throw std::runtime_error("Failed to open file (error code: " + std::to_string(err) + ")");
			}
			// 定位到起始偏移
			if (fseek(fp, actualStart, SEEK_SET) != 0)
			{
				fclose(fp);
				throw std::runtime_error("Failed to seek to start offset (" + std::to_string(actualStart) + ")");
			}
			// 分配缓冲区并读取数据
			buffer = new unsigned char[actualLen];
			size_t bytesRead = fread(buffer, 1, actualLen, fp);
			if (bytesRead != actualLen)
			{
				fclose(fp);
				delete[] buffer;
				throw std::runtime_error(
					"Failed to read data: actually read " + std::to_string(bytesRead) + " bytes, expected " + std::to_string(actualLen) + " bytes"
					);
			}
			fclose(fp);

			// 6. 步骤4：特征码匹配（核心逻辑）
			std::vector<long long> matchOffsets;
			for (long long i = 0; i <= actualLen - (long long)sigLen; ++i)
			{
				bool matched = true;
				for (size_t j = 0; j < sigLen; ++j)
				{
					// 通配符（0xFF）跳过匹配
					if (signature[j] == 0xFF)
					{
						continue;
					}
					// 非通配符严格匹配
					if (buffer[i + j] != signature[j])
					{
						matched = false;
						break;
					}
				}
				if (matched)
				{
					// 记录文件中的绝对偏移
					matchOffsets.push_back(actualStart + i);
				}
			}

			// 7. 步骤5：构建匹配结果
			cJSON* matchResult = cJSON_CreateObject();
			cJSON_AddNumberToObject(matchResult, "match_count", matchOffsets.size());
			cJSON* matchList = cJSON_CreateArray();

			for (long long offset : matchOffsets)
			{
				cJSON* matchItem = cJSON_CreateObject();
				// 匹配偏移（十进制+十六进制）
				cJSON_AddNumberToObject(matchItem, "offset_dec", offset);
				cJSON_AddStringToObject(matchItem, "offset_hex", DexToHex(offset).c_str());
				// 匹配位置前16字节数据（格式：空格分隔的十六进制）
				std::string first16Bytes;
				long long bufIdx = offset - actualStart; // 缓冲区中的索引
				for (size_t k = 0; k < 16; ++k)
				{
					if (bufIdx + k < actualLen)
					{
						char hex[4] = { 0 };
						sprintf_s(hex, "%02X ", buffer[bufIdx + k]);
						first16Bytes += hex;
					}
					else
					{
						first16Bytes += "   "; // 不足16字节补空格
					}
				}
				// 移除末尾多余空格
				if (!first16Bytes.empty())
				{
					first16Bytes.pop_back();
				}
				cJSON_AddStringToObject(matchItem, "first_16_bytes_hex", first16Bytes.c_str());
				cJSON_AddItemToArray(matchList, matchItem);
			}

			cJSON_AddItemToObject(matchResult, "matches", matchList);
			cJSON_AddItemToObject(result_root, "match_result", matchResult);

			// 8. 步骤6：添加统计信息
			cJSON* stats = cJSON_CreateObject();
			cJSON_AddNumberToObject(stats, "total_searched_bytes", actualLen);
			cJSON_AddNumberToObject(stats, "total_matches", matchOffsets.size());
			cJSON_AddItemToObject(result_root, "statistics", stats);

			// 9. 组装成功响应
			const char* msg = matchOffsets.empty() ? "Signature search completed, no matching results found" : "Signature search completed, matching results found";
			cJSON_AddStringToObject(response.result.get(), "message", msg);
			cJSON_AddItemToObject(response.result.get(), "signature_search_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, signature search failed");
			response.success = false;
		}

		// 释放缓冲区（避免内存泄漏）
		if (buffer != nullptr)
		{
			delete[] buffer;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“ASCII字符串搜索”请求
	static ResponseData handle_search_string(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局资源

		// 1. 前置校验：参数合法性（由RequestParser预处理）
		if (params.empty() || params.size() != 3 || params[0].find("Parameter error") != std::string::npos)
		{
			cJSON_AddStringToObject(response.result.get(), "error", params.empty() ? "Parameter is empty" : params[0].c_str());
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 解析参数（StartAddr和SearchLen已转为十进制字符串）
		long long StartAddr = std::stoll(params[0]);
		long long SearchLen = std::stoll(params[1]);
		std::string targetStr = params[2];
		size_t targetLen = targetStr.size();
		unsigned char* buffer = nullptr;  // 文件缓冲区，需手动释放

		try
		{
			// 2. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (!result_root) throw std::bad_alloc();
			cJSON_AddStringToObject(result_root, "file_path", GlobalFilePath);

			// 3. 步骤1：添加搜索配置信息
			cJSON* searchConfig = cJSON_CreateObject();
			cJSON_AddStringToObject(searchConfig, "target_string", targetStr.c_str());
			cJSON_AddNumberToObject(searchConfig, "target_string_len_bytes", targetLen);
			cJSON_AddStringToObject(searchConfig, "requested_start_foa_hex", DexToHex(StartAddr).c_str());
			cJSON_AddNumberToObject(searchConfig, "requested_start_foa_dec", StartAddr);
			cJSON_AddStringToObject(searchConfig, "requested_search_len_hex", DexToHex(SearchLen).c_str());
			cJSON_AddNumberToObject(searchConfig, "requested_search_len_dec", SearchLen);
			cJSON_AddItemToObject(result_root, "search_config", searchConfig);

			// 4. 步骤2：获取文件大小并校验搜索范围
			std::string fileErr;
			long long fileSize = hex_get_file_size(GlobalFilePath, fileErr);
			if (fileSize < 0) throw std::runtime_error("Failed to get file size: " + fileErr);
			cJSON_AddStringToObject(result_root, "file_total_size_hex", DexToHex(fileSize).c_str());
			cJSON_AddNumberToObject(result_root, "file_total_size_dec", fileSize);

			// 截断超出文件的搜索范围（原函数逻辑）
			long long endAddr = StartAddr + SearchLen;
			long long actualStart = StartAddr;
			long long actualLen = SearchLen;
			std::string warning;

			// 校验起始偏移是否超文件
			if (actualStart >= fileSize)
				throw std::runtime_error("Start FOA (" + std::to_string(actualStart) + ") exceeds file size (" + std::to_string(fileSize) + ")");
			// 截断搜索长度
			if (endAddr > fileSize)
			{
				actualLen = fileSize - actualStart;
				endAddr = fileSize;
				warning = "Search range exceeds file size, automatically truncated to: start FOA=" + std::to_string(actualStart) +
					", end FOA=" + std::to_string(endAddr - 1) + ", actual search length=" + std::to_string(actualLen);
			}
			// 校验目标字符串长度是否超搜索长度
			if (targetLen > actualLen)
				throw std::runtime_error("Target string length (" + std::to_string(targetLen) + " bytes) > actual search length (" + std::to_string(actualLen) + " bytes)");

			// 添加实际搜索范围到响应
			cJSON* actualRange = cJSON_CreateObject();
			cJSON_AddStringToObject(actualRange, "actual_start_foa_hex", DexToHex(actualStart).c_str());
			cJSON_AddNumberToObject(actualRange, "actual_start_foa_dec", actualStart);
			cJSON_AddStringToObject(actualRange, "actual_end_foa_hex", DexToHex(endAddr - 1).c_str());
			cJSON_AddNumberToObject(actualRange, "actual_end_foa_dec", endAddr - 1);
			cJSON_AddStringToObject(actualRange, "actual_search_len_hex", DexToHex(actualLen).c_str());
			cJSON_AddNumberToObject(actualRange, "actual_search_len_dec", actualLen);
			if (!warning.empty()) cJSON_AddStringToObject(actualRange, "warning", warning.c_str());
			cJSON_AddItemToObject(result_root, "actual_search_range", actualRange);

			// 5. 步骤3：打开文件并读取搜索区域到缓冲区
			FILE* fp = nullptr;
			errno_t err = fopen_s(&fp, GlobalFilePath, "rb");
			if (err != 0 || !fp) throw std::runtime_error("Failed to open file (error code: " + std::to_string(err) + ")");

			// 定位到实际起始FOA
			if (fseek(fp, actualStart, SEEK_SET) != 0)
			{
				fclose(fp);
				throw std::runtime_error("Failed to seek to start FOA (" + std::to_string(actualStart) + ")");
			}

			// 分配缓冲区并读取数据
			buffer = new unsigned char[actualLen];
			size_t bytesRead = fread(buffer, 1, actualLen, fp);
			fclose(fp);
			if (bytesRead != actualLen)
			{
				delete[] buffer;
				throw std::runtime_error("Failed to read data: actually " + std::to_string(bytesRead) + " bytes, expected " + std::to_string(actualLen) + " bytes");
			}

			// 6. 步骤4：ASCII字符串匹配（核心逻辑，逐字节比较）
			std::vector<long long> matchFOAs;
			for (long long i = 0; i <= actualLen - (long long)targetLen; ++i)
			{
				bool matched = true;
				for (size_t j = 0; j < targetLen; ++j)
				{
					// 严格匹配ASCII字符（原函数逻辑）
					if (buffer[i + j] != (unsigned char)targetStr[j])
					{
						matched = false;
						break;
					}
				}
				if (matched)
				{
					matchFOAs.push_back(actualStart + i);  // 记录文件绝对FOA
				}
			}

			// 7. 步骤5：构建匹配结果（含VA计算）
			cJSON* matchResult = cJSON_CreateObject();
			cJSON_AddNumberToObject(matchResult, "match_count", matchFOAs.size());
			cJSON* matchList = cJSON_CreateArray();

			for (long long foa : matchFOAs)
			{
				cJSON* matchItem = cJSON_CreateObject();
				// 1. 匹配FOA偏移
				cJSON_AddNumberToObject(matchItem, "match_foa_dec", foa);
				cJSON_AddStringToObject(matchItem, "match_foa_hex", DexToHex(foa).c_str());
				// 2. 匹配VA地址（原函数逻辑：FOA≤32位才计算）
				DWORD64 va = foa_to_va(foa, NtHeader);
				cJSON_AddStringToObject(matchItem, "match_va_hex", DexToHex(va).c_str());
				cJSON_AddNumberToObject(matchItem, "match_va_dec", va);
				// 3. 匹配内容（目标字符串）
				cJSON_AddStringToObject(matchItem, "matched_content", targetStr.c_str());
				cJSON_AddItemToArray(matchList, matchItem);
			}

			cJSON_AddItemToObject(matchResult, "match_details", matchList);
			cJSON_AddItemToObject(result_root, "match_result", matchResult);

			// 8. 步骤6：添加统计信息
			cJSON* stats = cJSON_CreateObject();
			cJSON_AddNumberToObject(stats, "total_searched_bytes", actualLen);
			cJSON_AddNumberToObject(stats, "total_matches", matchFOAs.size());
			cJSON_AddItemToObject(result_root, "statistics", stats);

			// 9. 组装成功响应
			const char* msg = matchFOAs.empty() ? "String search completed, no matching results found" : "String search completed, matching results found";
			cJSON_AddStringToObject(response.result.get(), "message", msg);
			cJSON_AddItemToObject(response.result.get(), "string_search_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct response");
			response.success = false;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, string search failed");
			response.success = false;
		}

		// 释放缓冲区（避免内存泄漏）
		if (buffer) delete[] buffer;

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“检查模块保护方式”请求
	static ResponseData handle_module_status(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 加锁保护全局资源

		// 1. 前置校验：文件已打开且NtHeader有效
		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file is not opened, please call open first");
			ReleaseMutex(g_server->mutex);
			return response;
		}
		if (NtHeader == nullptr)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE structure pointer (ntheader) is invalid. The file may be damaged");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		try
		{
			// 2. 提取PE核心字段（与原函数一致）
			WORD dllCharac = NtHeader->OptionalHeader.DllCharacteristics;       // DLL特性标志
			DWORD64 secDirSize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;  // 安全目录（证书）
			DWORD64 dbgDirSize = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;    // 调试目录
			WORD fileCharac = NtHeader->FileHeader.Characteristics;           // 文件特性标志
			WORD subsystem = NtHeader->OptionalHeader.Subsystem;              // 子系统类型
			WORD machine = NtHeader->FileHeader.Machine;                      // 机器架构
			// 链接器版本（按原函数注释修正后的成员，若原函数有误需同步调整）
			BYTE majorLinkerVer = NtHeader->OptionalHeader.MajorImageVersion;  // 原MajorLinkerVersion修正
			BYTE minorLinkerVer = NtHeader->OptionalHeader.MinorImageVersion;  // 原MinorLinkerVersion修正

			// 3. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (!result_root) throw std::bad_alloc();
			cJSON_AddStringToObject(result_root, "file_path", GlobalFilePath);

			// 4. 构建【模块基本属性】JSON（对应原函数第一部分）
			cJSON* basic_props = cJSON_CreateObject();
			// 4.1 文件类型（EXE/DLL）
			const char* fileType = (fileCharac & IMAGE_FILE_DLL) ? "DLL file" : "Executable file (EXE)";
			cJSON_AddStringToObject(basic_props, "file_type", fileType);
			// 4.2 机器架构
			const char* machineArch = "Unknown";
			switch (machine)
			{
			case IMAGE_FILE_MACHINE_I386:    machineArch = "x86 (32-bit)"; break;
			case IMAGE_FILE_MACHINE_AMD64:   machineArch = "x64 (64-bit)"; break;
			case IMAGE_FILE_MACHINE_ARM:     machineArch = "ARM"; break;
			case IMAGE_FILE_MACHINE_ARM64:   machineArch = "ARM64"; break;
			default:                         sprintf_s(const_cast<char*>(machineArch), 32, "Unknown (0x%04X)", machine);
			}
			cJSON_AddStringToObject(basic_props, "machine_architecture", machineArch);
			// 4.3 子系统类型
			const char* subsystemType = "Unknown";
			switch (subsystem)
			{
			case IMAGE_SUBSYSTEM_WINDOWS_CUI:        subsystemType = "Console application (CUI)"; break;
			case IMAGE_SUBSYSTEM_WINDOWS_GUI:        subsystemType = "Graphical user interface application (GUI)"; break;
			case IMAGE_SUBSYSTEM_WINDOWS_DRIVER:     subsystemType = "Windows driver (EFI)"; break;
			case IMAGE_SUBSYSTEM_WINDOWS_NATIVE:     subsystemType = "Windows native application"; break;
			case IMAGE_SUBSYSTEM_POSIX_CUI:          subsystemType = "POSIX console application"; break;
			default:                                 sprintf_s(const_cast<char*>(subsystemType), 64, "Unknown (0x%04X)", subsystem);
			}
			cJSON_AddStringToObject(basic_props, "subsystem_type", subsystemType);
			// 4.4 链接器版本
			char linkerVer[16] = { 0 };
			sprintf_s(linkerVer, "%lld.%lld", majorLinkerVer, minorLinkerVer);
			cJSON_AddStringToObject(basic_props, "linker_version", linkerVer);
			cJSON_AddItemToObject(result_root, "basic_properties", basic_props);

			// 5. 构建【安全特性】JSON（对应原函数第二部分）
			cJSON* security_features = cJSON_CreateObject();
			// 5.1 基址随机化（ASLR）
			bool aslrEnabled = (dllCharac & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
			cJSON_AddBoolToObject(security_features, "aslr_enabled", aslrEnabled);
			cJSON_AddStringToObject(security_features, "aslr_description", aslrEnabled ? "Enabled" : "Disabled");
			// 5.2 高熵ASLR
			bool highEntropyAslr = (dllCharac & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
			cJSON_AddBoolToObject(security_features, "high_entropy_aslr_enabled", highEntropyAslr);
			cJSON_AddStringToObject(security_features, "high_entropy_aslr_description", highEntropyAslr ? "Enabled (higher address space entropy)" : "Disabled");
			// 5.3 DEP/NX保护
			bool depEnabled = (dllCharac & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
			cJSON_AddBoolToObject(security_features, "dep_enabled", depEnabled);
			cJSON_AddStringToObject(security_features, "dep_description", depEnabled ? "Compatible (data pages non-executable)" : "Incompatible (may allow data execution)");
			// 5.4 控制流保护（CFG）
			bool cfgEnabled = (dllCharac & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
			cJSON_AddBoolToObject(security_features, "cfg_enabled", cfgEnabled);
			cJSON_AddStringToObject(security_features, "cfg_description", cfgEnabled ? "Enabled (blocks illegal indirect calls)" : "Disabled");
			// 5.5 强制完整性
			bool forceIntegrity = (dllCharac & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;
			cJSON_AddBoolToObject(security_features, "force_integrity_enabled", forceIntegrity);
			cJSON_AddStringToObject(security_features, "force_integrity_description", forceIntegrity ? "Enabled (must pass integrity verification)" : "Disabled");
			// 5.6 SEH异常保护（原函数判断“是否禁用”，需取反）
			bool sehEnabled = !(dllCharac & IMAGE_DLLCHARACTERISTICS_NO_SEH);
			cJSON_AddBoolToObject(security_features, "seh_enabled", sehEnabled);
			cJSON_AddStringToObject(security_features, "seh_description", sehEnabled ? "Allowed (supports structured exception handling)" : "Disabled (does not allow structured exception handling)");
			// 5.7 数字证书
			bool hasCert = (secDirSize != 0);
			cJSON_AddBoolToObject(security_features, "has_digital_certificate", hasCert);
			cJSON_AddStringToObject(security_features, "cert_description", hasCert ? "Exists (may be signed)" : "Does not exist");
			cJSON_AddItemToObject(result_root, "security_features", security_features);

			// 6. 构建【其他特性】JSON（对应原函数第三部分）
			cJSON* other_features = cJSON_CreateObject();
			// 6.1 终端服务感知
			bool tsAware = (dllCharac & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) != 0;
			cJSON_AddBoolToObject(other_features, "terminal_server_aware", tsAware);
			cJSON_AddStringToObject(other_features, "ts_aware_description", tsAware ? "Yes (compatible with terminal services environment)" : "No");
			// 6.2 UAC虚拟化（原函数判断“是否禁用”，需取反）
			bool uacVirtualization = !(dllCharac & IMAGE_DLLCHARACTERISTICS_NO_UAC_DLL);
			cJSON_AddBoolToObject(other_features, "uac_virtualization_enabled", uacVirtualization);
			cJSON_AddStringToObject(other_features, "uac_virtualization_description", uacVirtualization ? "Enabled" : "Disabled (does not virtualize file system/registry)");
			// 6.3 隔离特性
			bool isolationEnabled = (dllCharac & IMAGE_DLLCHARACTERISTICS_ISOLATION) != 0;
			cJSON_AddBoolToObject(other_features, "isolation_enabled", isolationEnabled);
			cJSON_AddStringToObject(other_features, "isolation_description", isolationEnabled ? "Enabled (must run in AppContainer)" : "Disabled");
			// 6.4 调试信息
			bool hasDebugInfo = (dbgDirSize != 0);
			cJSON_AddBoolToObject(other_features, "has_debug_info", hasDebugInfo);
			cJSON_AddStringToObject(other_features, "debug_info_description", hasDebugInfo ? "Exists (contains debug symbol directory)" : "Does not exist");
			cJSON_AddItemToObject(result_root, "other_features", other_features);

			// 7. 组装成功响应
			cJSON_AddStringToObject(response.result.get(), "message", "Successfully parsed module properties and protection methods");
			cJSON_AddItemToObject(response.result.get(), "module_status_info", result_root);
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct module status response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, failed to parse module status");
			response.success = false;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：处理“获取DLL函数地址”请求
	static ResponseData handle_get_process_address(const std::vector<std::string>& params)
	{
		ResponseData response;
		// 无需全局互斥锁（Windows API线程安全，且不访问共享全局变量）

		// 1. 提取参数（已由RequestParser校验非空）
		std::string dllName = params[0];
		std::string funcName = params[1];
		HMODULE hDll = NULL;  // DLL句柄，需确保最终释放
		bool dllLoaded = false;  // 标记DLL是否成功加载

		try
		{
			// 2. 构建响应根对象
			cJSON* result_root = cJSON_CreateObject();
			if (!result_root) throw std::bad_alloc();
			// 添加请求参数信息
			cJSON_AddStringToObject(result_root, "requested_dll_name", dllName.c_str());
			cJSON_AddStringToObject(result_root, "requested_function_name", funcName.c_str());

			// 3. 步骤1：加载DLL（复用原函数LoadLibraryA）
			hDll = LoadLibraryA(dllName.c_str());
			if (hDll == NULL)
			{
				DWORD64 errCode = GetLastError();
				// 构建错误信息
				cJSON* errorInfo = cJSON_CreateObject();
				cJSON_AddStringToObject(errorInfo, "error_type", "DLL loading failed");
				cJSON_AddNumberToObject(errorInfo, "error_code_dec", errCode);
				cJSON_AddStringToObject(errorInfo, "error_code_hex", DexToHex(errCode).c_str());
				cJSON_AddStringToObject(errorInfo, "error_reason",
					"The DLL does not exist, path is incorrect, dependencies are missing, or permissions are insufficient (common error codes: 126=DLL not found, 127=function not found)");
				cJSON_AddItemToObject(result_root, "error", errorInfo);
				// 组装失败响应
				cJSON_AddBoolToObject(result_root, "success", false);
				cJSON_AddItemToObject(response.result.get(), "get_process_address_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "Failed to get DLL function address (DLL loading failed)");
				response.success = true;  // HTTP响应成功，业务逻辑失败
				return response;
			}
			dllLoaded = true;  // 标记DLL已加载，后续需释放

			// 4. 步骤2：获取函数地址（复用原函数GetProcAddress）
			FARPROC pFunc = GetProcAddress(hDll, funcName.c_str());
			if (pFunc == NULL)
			{
				DWORD64 errCode = GetLastError();
				// 构建错误信息
				cJSON* errorInfo = cJSON_CreateObject();
				cJSON_AddStringToObject(errorInfo, "error_type", "Function address retrieval failed");
				cJSON_AddNumberToObject(errorInfo, "error_code_dec", errCode);
				cJSON_AddStringToObject(errorInfo, "error_code_hex", DexToHex(errCode).c_str());
				cJSON_AddStringToObject(errorInfo, "error_reason",
					"The function does not exist, is a non-exported function (check export table required), or has an incorrect function name spelling (case-sensitive)");
				cJSON_AddItemToObject(result_root, "error", errorInfo);
				// 组装失败响应
				cJSON_AddBoolToObject(result_root, "success", false);
				cJSON_AddItemToObject(response.result.get(), "get_process_address_info", result_root);
				cJSON_AddStringToObject(response.result.get(), "message", "Failed to get DLL function address (function not found)");
				response.success = true;
				return response;
			}

			// 5. 步骤3：计算地址信息（复用原函数公式）
			DWORD64 dllBaseVA = (DWORD64)hDll;          // DLL加载基址（VA）
			DWORD64 funcVA = (DWORD64)pFunc;            // 函数绝对地址（VA）
			DWORD64 funcRVA = funcVA - dllBaseVA;     // 函数相对偏移（RVA）

			// 构建成功数据
			cJSON* successData = cJSON_CreateObject();
			// DLL信息
			cJSON* dllInfo = cJSON_CreateObject();
			cJSON_AddStringToObject(dllInfo, "dll_name", dllName.c_str());
			cJSON_AddStringToObject(dllInfo, "dll_base_va_hex", DexToHex(dllBaseVA).c_str());
			cJSON_AddNumberToObject(dllInfo, "dll_base_va_dec", dllBaseVA);
			cJSON_AddItemToObject(successData, "dll_info", dllInfo);
			// 函数信息
			cJSON* funcInfo = cJSON_CreateObject();
			cJSON_AddStringToObject(funcInfo, "function_name", funcName.c_str());
			cJSON_AddStringToObject(funcInfo, "function_va_hex", DexToHex(funcVA).c_str());
			cJSON_AddNumberToObject(funcInfo, "function_va_dec", funcVA);
			cJSON_AddStringToObject(funcInfo, "function_rva_hex", DexToHex(funcRVA).c_str());
			cJSON_AddNumberToObject(funcInfo, "function_rva_dec", funcRVA);
			cJSON_AddItemToObject(successData, "function_info", funcInfo);
			// 添加成功标记
			cJSON_AddBoolToObject(result_root, "success", true);
			cJSON_AddItemToObject(result_root, "success_data", successData);

			// 6. 步骤4：释放DLL（复用原函数FreeLibrary）
			std::string releaseWarning = "";
			if (!FreeLibrary(hDll))
			{
				DWORD64 errCode = GetLastError();
				releaseWarning = std::string("DLL release failed, error code: ") + std::to_string(errCode) +
					" (0x" + DexToHex(errCode) + "), potential resource leak may occur";
				// 添加释放警告（非致命错误，不影响业务结果）
				cJSON_AddStringToObject(result_root, "release_warning", releaseWarning.c_str());
			}
			dllLoaded = false;  // 标记DLL已释放

			// 7. 组装成功响应
			cJSON_AddItemToObject(response.result.get(), "get_process_address_info", result_root);
			cJSON_AddStringToObject(response.result.get(), "message",
				releaseWarning.empty() ? "Successfully got DLL function address" : ("Successfully got DLL function address, but DLL release failed: " + releaseWarning).c_str());
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			// 内存分配失败，需先释放DLL
			if (dllLoaded && hDll != NULL)
			{
				FreeLibrary(hDll);
			}
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct response");
			response.success = false;
		}
		catch (...)
		{
			// 未知异常，需先释放DLL
			if (dllLoaded && hDll != NULL)
			{
				FreeLibrary(hDll);
			}
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, exception occurred while getting DLL function address");
			response.success = false;
		}

		// 兜底：若异常未释放DLL，此处补充释放
		if (dllLoaded && hDll != NULL)
		{
			FreeLibrary(hDll);
		}

		return response;
	}

	// 新增：处理“反汇编指定区域”请求
	static ResponseData handle_disassemble_code(const std::vector<std::string>& params)
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);  // 保护全局资源

		// 1. 解析参数（已由RequestParser校验）
		long long StartFOA = std::stoll(params[0]);
		DWORD64 DisasmLen = (DWORD64)std::stoll(params[1]);
		LPVOID fileBuffer = nullptr;  // ReadPEFileOffset分配的缓冲区
		std::vector<MyStruct> disasmResult;

		try
		{
			// 2. 前置校验：文件已打开
			if (!IsOpen || GlobalFilePath[0] == '\0')
			{
				throw std::runtime_error("PE file is not opened, please call open first");
			}

			// 3. 校验搜索范围：不超出文件大小
			std::string fileErr;
			long long fileSize = get_file_size_64(GlobalFilePath, fileErr);
			if (fileSize < 0)
			{
				throw std::runtime_error("Failed to get file size: " + fileErr);
			}
			if (StartFOA + DisasmLen > fileSize)
			{
				throw std::runtime_error(
					"Disassembly range exceeds file size (file size: " + std::to_string(fileSize) +
					" bytes, requested range: " + std::to_string(StartFOA) + "~" + std::to_string(StartFOA + DisasmLen) + " bytes)"
					);
			}

			// 4. 读取文件指定区域到缓冲区
			if (!ReadPEFileOffset(GlobalFilePath, StartFOA, DisasmLen, &fileBuffer) || !fileBuffer)
			{
				throw std::runtime_error("Failed to read specified file region (start FOA: " + std::to_string(StartFOA) + ", length: " + std::to_string(DisasmLen) + " bytes)");
			}

			// 5. 调用DisassembleCode反汇编（复用原函数逻辑）
			disasmResult = DisassembleCode((unsigned char*)fileBuffer, DisasmLen);
			if (disasmResult.empty())
			{
				// 非致命错误：可能无有效指令，仍返回空结果
				printf("[!] Disassembly did not get any instructions (may be a data region or engine initialization failure)\n");
			}

			// 6. 构建JSON响应根对象
			cJSON* resultRoot = cJSON_CreateObject();
			if (!resultRoot) throw std::bad_alloc();
			// 6.1 反汇编配置信息
			cJSON* config = cJSON_CreateObject();
			cJSON_AddStringToObject(config, "file_path", GlobalFilePath);
			cJSON_AddStringToObject(config, "start_foa_hex", DexToHex(StartFOA).c_str());
			cJSON_AddNumberToObject(config, "start_foa_dec", StartFOA);
			cJSON_AddStringToObject(config, "disasm_len_hex", DexToHex(DisasmLen).c_str());
			cJSON_AddNumberToObject(config, "disasm_len_dec", DisasmLen);
			cJSON_AddStringToObject(config, "capstone_info", "Architecture: x86, Mode: 32-bit");
			cJSON_AddItemToObject(resultRoot, "disasm_config", config);

			// 6.2 反汇编结果列表
			cJSON* insnList = cJSON_CreateArray();
			for (const auto& ms : disasmResult)
			{
				cJSON* insnObj = mystruct_to_json(ms, StartFOA);
				if (insnObj) cJSON_AddItemToArray(insnList, insnObj);
			}
			cJSON_AddItemToObject(resultRoot, "disasm_instructions", insnList);

			// 6.3 统计信息
			cJSON* stats = cJSON_CreateObject();
			cJSON_AddNumberToObject(stats, "total_instructions", disasmResult.size());
			cJSON_AddNumberToObject(stats, "total_bytes_disassembled", DisasmLen);
			cJSON_AddItemToObject(resultRoot, "statistics", stats);

			// 6.4 组装成功响应
			const char* msg = disasmResult.empty() ? "Disassembly completed, no valid instructions identified" : "Disassembly completed, instructions successfully identified";
			cJSON_AddStringToObject(response.result.get(), "message", msg);
			cJSON_AddItemToObject(response.result.get(), "disasm_result", resultRoot);
			response.success = true;
		}
		catch (const std::runtime_error& e)
		{
			cJSON_AddStringToObject(response.result.get(), "error", e.what());
			response.success = false;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, exception occurred during disassembly");
			response.success = false;
		}

		// 7. 释放资源（关键：避免内存泄漏）
		if (fileBuffer)
		{
			free(fileBuffer);
			fileBuffer = nullptr;
		}

		ReleaseMutex(g_server->mutex);  // 解锁
		return response;
	}

	// 新增：加法计算器处理函数
	static ResponseData handle_add_calculator(const std::vector<std::string>& params)
	{
		ResponseData response;
		std::string x = params[0], y = params[1];

		try
		{
			// 1. 十六进制转DWORD64（复用原逻辑HexToDex）
			DWORD64 xVal = HexToDex(const_cast<char*>(x.c_str()));
			DWORD64 yVal = HexToDex(const_cast<char*>(y.c_str()));

			// 2. 无符号加法计算（溢出自动模2^32）
			DWORD64 result = xVal + yVal;

			// 3. 构建JSON响应
			cJSON* root = cJSON_CreateObject();
			if (!root) throw std::bad_alloc();

			// 3.1 输入参数信息
			cJSON* input = cJSON_CreateObject();
			cJSON_AddStringToObject(input, "x_hex", x.c_str());
			cJSON_AddNumberToObject(input, "x_dec", xVal);
			cJSON_AddStringToObject(input, "y_hex", y.c_str());
			cJSON_AddNumberToObject(input, "y_dec", yVal);
			cJSON_AddItemToObject(root, "input_params", input);

			// 3.2 计算结果（四进制）
			cJSON* resultObj = build_result_json(xVal, yVal, result, "+");
			if (!resultObj) throw std::bad_alloc();
			cJSON_AddItemToObject(root, "calculation_result", resultObj);

			// 3.3 组装成功响应
			cJSON_AddItemToObject(response.result.get(), "add_calculator", root);
			cJSON_AddStringToObject(response.result.get(), "message", "Addition calculation successful");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct addition response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, addition calculation failed");
			response.success = false;
		}

		return response;
	}

	// 新增：减法计算器处理函数
	static ResponseData handle_sub_calculator(const std::vector<std::string>& params)
	{
		ResponseData response;
		std::string x = params[0], y = params[1];

		try
		{
			// 1. 十六进制转DWORD64（复用原逻辑HexToDex）
			DWORD64 xVal = HexToDex(const_cast<char*>(x.c_str()));
			DWORD64 yVal = HexToDex(const_cast<char*>(y.c_str()));

			// 2. 无符号减法计算（负数自动模2^32，如0x1a-0x2b=0xFFFFFFED）
			DWORD64 result = xVal - yVal;

			// 3. 构建JSON响应
			cJSON* root = cJSON_CreateObject();
			if (!root) throw std::bad_alloc();

			// 3.1 输入参数信息
			cJSON* input = cJSON_CreateObject();
			cJSON_AddStringToObject(input, "x_hex", x.c_str());
			cJSON_AddNumberToObject(input, "x_dec", xVal);
			cJSON_AddStringToObject(input, "y_hex", y.c_str());
			cJSON_AddNumberToObject(input, "y_dec", yVal);
			cJSON_AddItemToObject(root, "input_params", input);

			// 3.2 计算结果（四进制）
			cJSON* resultObj = build_result_json(xVal, yVal, result, "-");
			if (!resultObj) throw std::bad_alloc();
			// 补充减法无符号提示（避免用户误解负数）
			cJSON_AddStringToObject(resultObj, "note", "Subtraction is based on DWORD64 unsigned calculation; negative numbers are automatically converted to modulo 2^32 values");
			cJSON_AddItemToObject(root, "calculation_result", resultObj);

			// 3.3 组装成功响应
			cJSON_AddItemToObject(response.result.get(), "sub_calculator", root);
			cJSON_AddStringToObject(response.result.get(), "message", "Subtraction calculation successful");
			response.success = true;
		}
		catch (const std::bad_alloc&)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Memory allocation failed, unable to construct subtraction response");
			response.success = false;
		}
		catch (...)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown error, subtraction calculation failed");
			response.success = false;
		}

		return response;
	}

	// 关闭文件并释放资源
	static ResponseData handle_close()
	{
		ResponseData response;
		WaitForSingleObject(g_server->mutex, INFINITE);

		if (!IsOpen)
		{
			cJSON_AddStringToObject(response.result.get(), "error", "PE file not opened, no need to close");
			ReleaseMutex(g_server->mutex);
			return response;
		}

		// 释放所有资源
		release_resources();

		response.success = true;
		cJSON_AddStringToObject(response.result.get(), "message", "PE file closed, resource released");
		ReleaseMutex(g_server->mutex);
		return response;
	}

private:
	// 内部工具函数：释放所有映射资源并重置状态
	static void release_resources()
	{
		// 释放映射视图（关键：此时才释放内存）
		if (Global_lpMapAddress != NULL)
		{
			UnmapViewOfFile(Global_lpMapAddress);
			Global_lpMapAddress = NULL;
		}
		// 释放映射对象
		if (Global_hMapFile != NULL)
		{
			CloseHandle(Global_hMapFile);
			Global_hMapFile = NULL;
		}
		// 释放文件句柄
		if (Global_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(Global_hFile);
			Global_hFile = INVALID_HANDLE_VALUE;
		}

		// 重置全局状态
		GlobalFileBase = 0;
		GlobalFileSize = 0;
		IsOpen = 0;
		DosHeader = nullptr;
		NtHeader = nullptr;
		FileHead = nullptr;
		pSection = nullptr;
		GlobalFilePath[0] = '\0';
	}

	// --------------------------------------------------
	// 临时将RVA转换为FOA的函数
	// --------------------------------------------------
	static DWORD64 RVAtoFOA(DWORD64 rva)
	{
		if (!IsOpen)
		{
			return -1; // 未打开文件时返回无效值
		}
		auto SectionTables = IMAGE_FIRST_SECTION(NtHeader);    // 获取区段表
		WORD Count = NtHeader->FileHeader.NumberOfSections;    // 获取区段数量

		for (int i = 0; i < Count; ++i)
		{
			// 判断是否存在于区段中
			DWORD64 Section_Start = SectionTables[i].VirtualAddress;
			DWORD64 Section_Ends = SectionTables[i].VirtualAddress + SectionTables[i].SizeOfRawData;
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
	static DWORD64 FOAtoRVA(DWORD64 dwFOA)
	{
		if (!IsOpen)
		{
			return 0; // 未打开文件时返回无效值
		}
		DWORD64 NumberOfSectinsCount = NtHeader->FileHeader.NumberOfSections;

		for (DWORD64 each = 0; each < NumberOfSectinsCount; each++)
		{
			DWORD64 PointerRawStart = pSection[each].PointerToRawData;
			DWORD64 PointerRawEnds = pSection[each].PointerToRawData + pSection[each].SizeOfRawData;

			if (dwFOA >= PointerRawStart && dwFOA <= PointerRawEnds)
			{
				DWORD64 RVA = pSection[each].VirtualAddress + (dwFOA - pSection[each].PointerToRawData);
				return RVA;
			}
		}
		return 0;
	}

	// 辅助2：FOA转VA（复用原函数逻辑，FOA>32位时返回0）
	static DWORD64 foa_to_va(long long foa, PIMAGE_NT_HEADERS64 ntHeader)
	{
		if (foa > 0xFFFFFFFF || !ntHeader) return 0;
		DWORD64 rva = FOAtoRVA((DWORD64)foa);  // 复用原有FOAtoRVA函数
		return rva + ntHeader->OptionalHeader.ImageBase;
	}

	// --------------------------------------------------
	// 传入一个十六进制字符串，将其自动转化为十进制格式:例如传入40158b转为4199819
	// --------------------------------------------------
	static int HexStringToDec(char hexStr[])
	{
		if (hexStr == nullptr) return 0;

		int i, m, n, temp = 0;
		m = strlen(hexStr);
		for (i = 0; i < m; i++)
		{
			if (hexStr[i] >= 'A' && hexStr[i] <= 'F')
				n = hexStr[i] - 'A' + 10;
			else if (hexStr[i] >= 'a' && hexStr[i] <= 'f')
				n = hexStr[i] - 'a' + 10;
			else n = hexStr[i] - '0';
			temp = temp * 16 + n;
		}
		return temp;
	}

	// --------------------------------------------------
	// 将十进制整数转为十六进制字符串（修复局部变量指针返回问题）
	// --------------------------------------------------
	static std::string DexToHex(int dex)
	{
		char hex[9] = { 0 };
		char ref[16] = { 0 }; // 足够存储"0x" + 8位十六进制数
		if (dex >= 0)
		{
			_ltoa(dex, hex, 16);
			sprintf_s(ref, "0x%08s", hex);
			return std::string(ref);
		}
		return "0x00000000";
	}

	// --------------------------------------------------
	// 将十六进制字符串转为整数
	// --------------------------------------------------
	static int HexToDex(char* Hex)
	{
		int ref = 0;
		if (Hex)
		{
			sscanf_s(Hex, "%x", &ref);
		}
		return ref;
	}

	// 辅助函数：字符串转long long（支持十进制/十六进制）
	static long long str_to_ll(const std::string& s, bool& success)
	{
		success = false;
		if (s.empty()) return 0;

		char* endptr = nullptr;
		errno = 0;
		long long val = 0;
		if (s.substr(0, 2) == "0x" || s.substr(0, 2) == "0X")
		{
			val = _strtoi64(s.c_str() + 2, &endptr, 16);
		}
		else
		{
			val = _strtoi64(s.c_str(), &endptr, 10);
		}
		if (*endptr == '\0' && errno == 0)
		{
			success = true;
			return val;
		}
		return 0;
	}

	// --------------------------------------------------
	// 解析特征码字符串（支持格式如"55 8B ?? EC"）
	// --------------------------------------------------
	static std::vector<unsigned char> ParseSignature(const std::string& sig_str)
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
				sig.push_back(0xFF); // 用0xFF标记通配符
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
			// 无效格式
			else
			{
				return{};
			}
		}
		return sig;
	}

	// 辅助函数：递归解析资源目录，构建JSON（对应原ParseResourceDirectory）
	static cJSON* parse_resource_dir_to_json(
		PIMAGE_RESOURCE_DIRECTORY pResDir,
		DWORD64 resBaseFOA,  // 资源表在文件中的基地址FOA
		int level,         // 目录级别：1=类型，2=名称/ID，3=语言
		DWORD64 globalFileBase  // 全局文件映射基址（避免访问全局变量）
		)
	{
		if (pResDir == nullptr) return nullptr;

		// 1. 创建当前目录的JSON对象
		cJSON* dir_json = cJSON_CreateObject();
		if (dir_json == nullptr) return nullptr;

		// 2. 目录基础信息（RVA/FOA、级别、条目数）
		DWORD64 dirFOA = (DWORD64)pResDir - globalFileBase;
		DWORD64 dirRVA = FOAtoRVA(dirFOA);  // 复用原FOAtoRVA函数
		const char* levelName[] = { "", "Type Directory", "Name/ID Directory", "Language Directory" };
		cJSON_AddStringToObject(dir_json, "directory_type", levelName[level]);
		cJSON_AddNumberToObject(dir_json, "level", level);
		cJSON_AddStringToObject(dir_json, "dir_rva_hex", DexToHex(dirRVA).c_str());
		cJSON_AddNumberToObject(dir_json, "dir_rva_dec", dirRVA);
		cJSON_AddStringToObject(dir_json, "dir_foa_hex", DexToHex(dirFOA).c_str());
		cJSON_AddNumberToObject(dir_json, "dir_foa_dec", dirFOA);
		cJSON_AddNumberToObject(dir_json, "named_entry_count", pResDir->NumberOfNamedEntries);
		cJSON_AddNumberToObject(dir_json, "id_entry_count", pResDir->NumberOfIdEntries);
		DWORD64 totalEntryCount = pResDir->NumberOfNamedEntries + pResDir->NumberOfIdEntries;
		cJSON_AddNumberToObject(dir_json, "total_entry_count", totalEntryCount);

		// 3. 处理目录条目（创建条目数组）
		cJSON* entries_json = cJSON_CreateArray();
		if (entries_json == nullptr)
		{
			cJSON_Delete(dir_json);
			return nullptr;
		}
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntries = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDir + 1);

		for (DWORD64 i = 0; i < totalEntryCount; ++i)
		{
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pEntry = &pEntries[i];
			cJSON* entry_json = cJSON_CreateObject();
			if (entry_json == nullptr) continue;

			// 3.1 条目基础信息（索引、偏移）
			cJSON_AddNumberToObject(entry_json, "entry_index", i + 1);
			cJSON_AddStringToObject(entry_json, "offset_to_dir_or_data_hex", DexToHex(pEntry->OffsetToDirectory).c_str());
			cJSON_AddNumberToObject(entry_json, "offset_to_dir_or_data_dec", pEntry->OffsetToDirectory);

			// 3.2 解析条目类型（命名条目/ID条目）
			if (pEntry->NameIsString)
			{
				// 命名条目：解析宽字符串名称
				cJSON_AddStringToObject(entry_json, "entry_type", "Named Entry");
				PIMAGE_RESOURCE_DIR_STRING_U pStr = (PIMAGE_RESOURCE_DIR_STRING_U)(resBaseFOA + pEntry->NameOffset + globalFileBase);
				WCHAR wName[MAX_PATH] = { 0 };
				char aName[MAX_PATH] = { 0 };
				memcpy_s(wName, sizeof(wName), pStr->NameString, pStr->Length * sizeof(WCHAR));
				WideCharToMultiByte(CP_ACP, 0, wName, -1, aName, sizeof(aName), NULL, NULL);
				cJSON_AddStringToObject(entry_json, "entry_name", aName);
				cJSON_AddNumberToObject(entry_json, "name_length", pStr->Length);
			}
			else
			{
				// ID条目：根据级别解析ID含义
				cJSON_AddStringToObject(entry_json, "entry_type", "ID Entry");
				cJSON_AddStringToObject(entry_json, "entry_id_hex", DexToHex(pEntry->Id).c_str());
				cJSON_AddNumberToObject(entry_json, "entry_id_dec", pEntry->Id);

				const char* idDesc = "Unknown";
				if (level == 1)
				{
					// 类型级ID：映射到资源类型名称
					idDesc = (pEntry->Id < sizeof(szResName) / sizeof(szResName[0])) ? szResName[pEntry->Id] : "Unknown Type";
				}
				else if (level == 2)
				{
					idDesc = "Resource ID";
				}
				else if (level == 3)
				{
					idDesc = "Language ID";
				}
				cJSON_AddStringToObject(entry_json, "entry_id_desc", idDesc);
			}

			// 3.3 条目内容：子目录 或 数据条目
			if (pEntry->DataIsDirectory)
			{
				// 子目录：递归解析下一级目录
				cJSON_AddStringToObject(entry_json, "content_type", "Child Directory");
				PIMAGE_RESOURCE_DIRECTORY pChildDir = (PIMAGE_RESOURCE_DIRECTORY)(resBaseFOA + pEntry->OffsetToDirectory + globalFileBase);
				cJSON* child_dir_json = parse_resource_dir_to_json(pChildDir, resBaseFOA, level + 1, globalFileBase);
				if (child_dir_json != nullptr)
				{
					cJSON_AddItemToObject(entry_json, "child_directory", child_dir_json);
				}
				else
				{
					cJSON_AddStringToObject(entry_json, "warning", "Failed to parse child directory (null pointer or insufficient memory)");
				}
			}
			else
			{
				// 数据条目：仅语言级（level=3）有效
				if (level != 3)
				{
					cJSON_AddStringToObject(entry_json, "content_type", "Invalid Data Entry");
					cJSON_AddStringToObject(entry_json, "warning", "Data entry appears in non-language-level directory (does not comply with PE specification)");
				}
				else
				{
					// 解析资源数据信息
					cJSON_AddStringToObject(entry_json, "content_type", "Resource Data");
					PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = (PIMAGE_RESOURCE_DATA_ENTRY)(resBaseFOA + pEntry->OffsetToDirectory + globalFileBase);
					DWORD64 dataRVA = pDataEntry->OffsetToData;
					DWORD64 dataFOA = RVAtoFOA(dataRVA);
					DWORD64 dataSize = pDataEntry->Size;
					DWORD64 codePage = pDataEntry->CodePage;

					cJSON_AddStringToObject(entry_json, "data_rva_hex", DexToHex(dataRVA).c_str());
					cJSON_AddNumberToObject(entry_json, "data_rva_dec", dataRVA);
					cJSON_AddStringToObject(entry_json, "data_foa_hex", DexToHex(dataFOA).c_str());
					cJSON_AddNumberToObject(entry_json, "data_foa_dec", dataFOA);
					cJSON_AddStringToObject(entry_json, "data_size_hex", DexToHex(dataSize).c_str());
					cJSON_AddNumberToObject(entry_json, "data_size_dec", dataSize);
					cJSON_AddStringToObject(entry_json, "code_page_hex", DexToHex(codePage).c_str());
					cJSON_AddNumberToObject(entry_json, "code_page_dec", codePage);
					cJSON_AddStringToObject(entry_json, "code_page_desc", "Used for resource localization encoding (e.g., 936 corresponds to GB2312)");
				}
			}

			cJSON_AddItemToArray(entries_json, entry_json);
		}

		// 4. 将条目数组添加到目录JSON
		cJSON_AddItemToObject(dir_json, "entries", entries_json);
		return dir_json;
	}

	// 内部辅助函数：复用HexGetFileSize逻辑，返回文件大小（long long），错误返回-1
	static long long hex_get_file_size(const char* fileName, std::string& errorMsg)
	{
		errorMsg.clear();
		if (fileName == nullptr || *fileName == '\0')
		{
			errorMsg = "File path is empty";
			return -1;
		}

		FILE* fp = nullptr;
		errno_t err = fopen_s(&fp, fileName, "rb");
		if (err != 0 || fp == nullptr)
		{
			errorMsg = std::string("Failed to open file (error code：") + std::to_string(err) + "）";
			return -1;
		}

		if (fseek(fp, 0, SEEK_END) != 0)
		{
			errorMsg = "Fseek failed to locate the end of the file";
			fclose(fp);
			return -1;
		}

		long long len = ftell(fp);
		fclose(fp);

		if (len < 0)
		{
			errorMsg = "FTell failed to get file size";
			return -1;
		}
		return len;
	}

	// 辅助函数：解析特征码字符串为字节数组（??→0xFF，十六进制→unsigned char）
	static std::vector<unsigned char> parse_signature(const std::string& sig_str)
	{
		std::vector<unsigned char> sig;
		std::stringstream ss(sig_str);
		std::string token;

		while (ss >> token)
		{
			if (token == "??")
			{
				// 通配符：用0xFF标记
				sig.push_back(0xFF);
			}
			else if (token.size() == 2)
			{
				// 十六进制：转为unsigned char
				char* endptr = nullptr;
				unsigned char byte = (unsigned char)strtoul(token.c_str(), &endptr, 16);
				if (*endptr != '\0')
				{
					sig.clear(); // 无效十六进制字符
					break;
				}
				sig.push_back(byte);
			}
			else
			{
				sig.clear(); // token长度不是2，无效
				break;
			}
		}

		return sig;
	}

	// 辅助：MyStruct转JSON对象
	static cJSON* mystruct_to_json(const MyStruct& ms, long long baseFOA)
	{
		cJSON* obj = cJSON_CreateObject();
		if (!obj) return nullptr;

		// 1. 机器码长度
		cJSON_AddNumberToObject(obj, "opcode_size_bytes", ms.OpCodeSize);
		// 2. 反汇编字符串长度
		cJSON_AddNumberToObject(obj, "opstring_size_chars", ms.OpStringSize);
		// 3. 真实文件偏移（baseFOA + 反汇编内部地址）
		long long realFOA = baseFOA + ms.Address;
		cJSON_AddStringToObject(obj, "real_foa_hex", DexToHex(realFOA).c_str());
		cJSON_AddNumberToObject(obj, "real_foa_dec", realFOA);
		// 4. 机器码（转为十六进制字符串数组）
		cJSON* opcodeArr = cJSON_CreateArray();
		for (int i = 0; i < ms.OpCodeSize; i++)
		{
			char hex[4] = { 0 };
			sprintf_s(hex, "%02X", ms.OpCode[i]);
			cJSON_AddItemToArray(opcodeArr, cJSON_CreateString(hex));
		}
		cJSON_AddItemToObject(obj, "opcode_hex_array", opcodeArr);
		// 5. 反汇编指令
		cJSON_AddStringToObject(obj, "disassembled_instruction", ms.OpString);

		return obj;
	}

	// 辅助函数:将字符串转换为数值（支持十进制和十六进制，如"100"或"0x100"）
	static unsigned long long str_to_ulonglong(const std::string& s)
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

	// 辅助：获取文件大小（64位，支持大文件）
	static long long get_file_size_64(const char* filePath, std::string& errorMsg)
	{
		errorMsg.clear();
		FILE* fp = nullptr;
		if (fopen_s(&fp, filePath, "rb") != 0 || !fp)
		{
			errorMsg = "fail to open file";
			return -1;
		}
		if (_fseeki64(fp, 0, SEEK_END) != 0)
		{
			errorMsg = "Failed to navigate to the end of the file";
			fclose(fp);
			return -1;
		}
		long long size = _ftelli64(fp);
		fclose(fp);
		return size < 0 ? -1 : size;
	}

	// 在文件偏移位置读入数据
	static BOOL ReadPEFileOffset(IN LPSTR file_path, IN DWORD64 Offset, IN DWORD64 Size, OUT LPVOID* pFileBuffer)
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
	static std::vector<MyStruct> DisassembleCode(unsigned char *start_offset, int size)
	{
		std::vector<MyStruct> ptr = {};

		csh handle;
		cs_insn *insn;
		size_t count;

		// 打开句柄
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
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

	// 辅助：统一处理计算结果的四进制转换（返回JSON对象）
	static cJSON* build_result_json(DWORD64 xVal, DWORD64 yVal, DWORD64 result, const std::string& op)
	{
		cJSON* resultObj = cJSON_CreateObject();
		if (!resultObj) return nullptr;

		// 1. 计算结果：HEX（8位补零）
		char hexBuf[16] = { 0 };
		sprintf_s(hexBuf, "0x%016llX", result);
		cJSON_AddStringToObject(resultObj, "hex", hexBuf);

		// 2. 计算结果：DEC（十进制）
		cJSON_AddNumberToObject(resultObj, "dec", result);

		// 3. 计算结果：OCT（八进制，调用辅助函数）
		std::string octStr = DWORD64_to_oct(result);
		cJSON_AddStringToObject(resultObj, "oct", octStr.c_str());

		// 4. 计算结果：BIN（二进制，调用辅助函数）
		std::string binStr = DWORD64_to_bin(result);
		cJSON_AddStringToObject(resultObj, "bin", binStr.c_str());

		// 5. 补充计算表达式（便于理解）
		char exprBuf[64] = { 0 };
		sprintf_s(exprBuf, "0x%016llX %s 0x%016llX = 0x%016llX", xVal, op.c_str(), yVal, result);
		cJSON_AddStringToObject(resultObj, "expression", exprBuf);

		return resultObj;
	}
};

// --------------------------------------------------
// 请求处理器
// --------------------------------------------------
class RequestHandler
{
public:
	ResponseData handle_request(const RequestData& data)
	{
		switch (data.type)
		{
		case RequestType::PEView_Open:
			return PEViewHandler::handle_open(data.params);
		case RequestType::PEView_ShowFileBasicInfo:  // 新增路由
			return PEViewHandler::handle_show_file_basic_info(data.params);
		case RequestType::PEView_ShowDosHead:
			return PEViewHandler::handle_show_dos_head(data.params);
		case RequestType::PEView_ShowNtHead:  // 新增路由
			return PEViewHandler::handle_show_nt_head(data.params);
		case RequestType::PEView_ShowSection:  // 新增路由
			return PEViewHandler::handle_show_section(data.params);
		case RequestType::PEView_ShowOptionalDataDirectory:  // 新增路由
			return PEViewHandler::handle_show_optional_data_directory(data.params);
		case RequestType::PEView_ShowImportByDll:  // 新增路由
			return PEViewHandler::handle_show_import_by_dll(data.params);
		case RequestType::PEView_ShowImportByName:  // 新增路由
			return PEViewHandler::handle_show_import_by_name(data.params);
		case RequestType::PEView_ShowImportByFunction:  // 新增路由
			return PEViewHandler::handle_show_import_by_function(data.params);
		case RequestType::PEView_ShowImportAll:  // 新增路由
			return PEViewHandler::handle_show_import_all(data.params);
		case RequestType::PEView_ShowExport:  // 新增路由
			return PEViewHandler::handle_show_export(data.params);
		case RequestType::PEView_ShowFixRelocPage:  // 新增路由
			return PEViewHandler::handle_show_fix_reloc_page(data.params);
		case RequestType::PEView_ShowFixReloc:  // 新增路由
			return PEViewHandler::handle_show_fix_reloc(data.params);
		case RequestType::PEView_ShowResource:  // 新增路由
			return PEViewHandler::handle_show_resource(data.params);
		case RequestType::PEView_VA_To_FOA:  // 新增路由
			return PEViewHandler::handle_va_to_foa(data.params);
		case RequestType::PEView_RVA_To_FOA:  // 新增RVA转FOA路由
			return PEViewHandler::handle_rva_to_foa(data.params);
		case RequestType::PEView_FOA_To_VA:  // 新增FOA转VA路由
			return PEViewHandler::handle_foa_to_va(data.params);
		case RequestType::PEView_VA_To_RVA:  // 新增VA转RVA路由
			return PEViewHandler::handle_va_to_rva(data.params);
		case RequestType::PEView_RVA_To_VA:  // 新增RVA转VA路由
			return PEViewHandler::handle_rva_to_va(data.params);
		case RequestType::PEView_GetHexASCII:  // 新增路由
			return PEViewHandler::handle_get_hex_ascii(data.params);
		case RequestType::PEView_SearchSignature:  // 新增特征码搜索路由
			return PEViewHandler::handle_search_signature(data.params);
		case RequestType::PEView_SearchString:  // 新增字符串搜索路由
			return PEViewHandler::handle_search_string(data.params);
		case RequestType::PEView_ModuleStatus:  // 新增模块保护方式检查路由
			return PEViewHandler::handle_module_status(data.params);
		case RequestType::PEView_GetProcessAddress:  // 新增DLL函数地址获取路由
			return PEViewHandler::handle_get_process_address(data.params);
		case RequestType::PEView_DisassembleCode:  // 新增反汇编路由
			return PEViewHandler::handle_disassemble_code(data.params);
		case RequestType::PEView_AddCalculator:  // 加法计算器路由
			return PEViewHandler::handle_add_calculator(data.params);
		case RequestType::PEView_SubCalculator:  // 减法计算器路由
			return PEViewHandler::handle_sub_calculator(data.params);
		case RequestType::PEView_Close:  // 新增路由
			return PEViewHandler::handle_close();
		default:
			ResponseData response;
			cJSON_AddStringToObject(response.result.get(), "error", "Unknown request type");
			return response;
		}
	}
};

// --------------------------------------------------
// g_server的实际定义
// --------------------------------------------------
static std::unique_ptr<ServerContext> g_server;

// --------------------------------------------------
// 服务器线程函数
// --------------------------------------------------
static DWORD WINAPI server_thread_func(LPVOID param)
{
	while (g_server->running)
	{
		mg_mgr_poll(&g_server->mgr, 100);
	}
	return 0;
}

// --------------------------------------------------
// 处理POST请求
// --------------------------------------------------
static void handle_post_request(struct mg_http_message* http_msg, struct mg_connection* connection)
{
	CJsonPtr req_json(cJSON_ParseWithLength(http_msg->body.buf, http_msg->body.len));
	if (!req_json)
	{
		mg_http_reply(connection, 400, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"error\":\"Invalid JSON\"}");
		return;
	}

	RequestData req_data = RequestParser::parse(req_json.get());
	if (req_data.type == RequestType::Unknown)
	{
		mg_http_reply(connection, 400, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"error\":\"Invalid parameters\"}");
		return;
	}

	ResponseData resp_data = g_server->handler->handle_request(req_data);
	CJsonPtr resp_json(cJSON_CreateObject());
	cJSON_AddStringToObject(resp_json.get(), "status", resp_data.success ? "success" : "error");
	cJSON_AddItemToObject(resp_json.get(), "result", resp_data.result.release());
	cJSON_AddNumberToObject(resp_json.get(), "timestamp", static_cast<double>(mg_millis()));

	char* resp_str = cJSON_PrintUnformatted(resp_json.get());
	if (resp_str)
	{
		mg_http_reply(connection, resp_data.success ? 200 : 400,
			"Content-Type: application/json\r\n", "%s", resp_str);
		free(resp_str);
	}
	else
	{
		mg_http_reply(connection, 500, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"error\":\"Failed to generate response\"}");
	}
}

// --------------------------------------------------
// 事件处理器
// --------------------------------------------------
static void ev_handler(struct mg_connection* connection, int ev, void* ev_data)
{
	if (ev == MG_EV_HTTP_MSG)
	{
		struct mg_http_message* http_msg = static_cast<struct mg_http_message*>(ev_data);

		if (mg_strcmp(http_msg->method, mg_str("GET")) != 0 &&
			mg_strcmp(http_msg->method, mg_str("POST")) != 0)
		{
			mg_http_reply(connection, 405, "Content-Type: application/json\r\nAllow: GET,POST\r\n",
				"{\"status\":\"error\",\"error\":\"Method not allowed\"}");
			return;
		}

		if (mg_strcmp(http_msg->method, mg_str("GET")) == 0 &&
			mg_strcmp(http_msg->uri, mg_str("/")) == 0)
		{
			mg_http_reply(connection, 200, "Content-Type: application/json\r\n",
				"{"
				"\"status\":\"success\","
				"\"plugin_info\":{\"version\":\"1.0.0\",\"author\":\"WangRui\",\"description\":\"Windows HTTP Debugging Interface\",\"compile_date\":\"%s\",\"compile_time\":\"%s\"}"
				"}", __DATE__, __TIME__);
			return;
		}

		if (mg_strcmp(http_msg->method, mg_str("POST")) == 0 &&
			mg_strcmp(http_msg->uri, mg_str("/")) == 0)
		{
			/*
			printf("[POST]\n");
			// 打印请求方法（POST）：使用mg_str的s成员（字符串指针）和len成员（长度）
			printf("请求方法: %.*s\n", (int)http_msg->method.len, http_msg->method.buf);
			// 打印请求URI（/）
			printf("请求路径: %.*s\n", (int)http_msg->uri.len, http_msg->uri.buf);
			// 打印请求体长度
			printf("请求体长度: %lld 字节\n", (int)http_msg->body.len);
			// 打印请求体内容（JSON）
			if (http_msg->body.len > 0)
			{
				printf("请求体内容:\n%.*s\n", (int)http_msg->body.len, http_msg->body.buf);
			}
			else
			{
				printf("请求体内容: 空\n");
			}
			*/
			// 调用函数执行
			handle_post_request(http_msg, connection);
			return;
		}

		mg_http_reply(connection, 404, "Content-Type: application/json\r\n",
			"{\"status\":\"error\",\"error\":\"Resource not found\"}");
	}
}

// --------------------------------------------------
// 主函数（退出时确保资源释放）
// --------------------------------------------------
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
	printf("[解析格式] Windows x64 Server (PE32+)\n");
	printf("[当前版本] 4.0.0 \n");
	printf("[官方网站] peview.lyshark.com \n");
}

// --------------------------------------------------
// 信号处理函数：捕获Ctrl+C（SIGINT），触发服务器停止
// --------------------------------------------------
void OnSigInt(int sig)
{
	if (sig == SIGINT && g_server != nullptr)
	{
		g_server->running = false;
	}
}

// --------------------------------------------------
// 主函数（退出时确保资源释放，仅Ctrl+C终止）
// --------------------------------------------------
int main(int argc, char *argv[])
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
		return 1;

	// 1. 初始化服务器上下文
	g_server = std::make_unique<ServerContext>();
	g_server->listen_addr = "http://0.0.0.0:8000";
	g_server->handler = new RequestHandler();
	bool server_started = false;

	// 2. 启动HTTP监听
	struct mg_connection* listener = mg_http_listen(
		&g_server->mgr,
		g_server->listen_addr.c_str(),
		ev_handler,
		nullptr
		);
	if (listener)
	{
		g_server->running = true;
		// 注册Ctrl+C信号处理函数（捕获SIGINT，触发停止逻辑）
		signal(SIGINT, OnSigInt);
		// 创建服务器工作线程
		g_server->thread = ThreadUtils::create_thread(server_thread_func);
		if (g_server->thread != nullptr)
		{
			server_started = true;
			Loading();
			printf("[监听地址] %s\n\n", g_server->listen_addr.c_str());
		}
		else
		{
			g_server->running = false;
			//printf("创建服务器线程失败\n");
		}
	}
	else
	{
		//printf("启动HTTP监听失败（端口可能被占用）\n");
		// 6. 释放PE文件资源+全局资源
		PEViewHandler::handle_close();
		delete g_server->handler;
		g_server.reset();
		WSACleanup();
	}

	// 3. 启动失败：释放资源并退出
	if (!server_started)
	{
		delete g_server->handler;
		g_server.reset();
		WSACleanup();
		return 1;
	}

	// 4. 核心：仅Ctrl+C终止，否则持续运行（低CPU占用循环）
	while (g_server->running)
	{
		Sleep(100); // 休眠100ms，避免CPU空转
	}

	// 5. Ctrl+C触发后：停止服务器并释放资源
	if (g_server->thread != nullptr)
	{
		ThreadUtils::join_thread(g_server->thread); // 等待工作线程退出
	}

	// 6. 释放PE文件资源+全局资源
	PEViewHandler::handle_close();
	delete g_server->handler;
	g_server.reset();
	WSACleanup();
	return 0;
}