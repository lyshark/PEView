import asyncio
import json
import os
import shlex
import sys
import platform
from datetime import datetime
from typing import TypeAlias, Union, Optional, Dict, Any, List
from mcp.server.fastmcp import FastMCP
from peview_client import Config, PE

# -------------------------- 1. 核心配置：统一管理服务参数 --------------------------
class ServerConfig:
    def __init__(self):
        # MCP 服务基础配置
        self.mcp_service_id = "custom_mcp_server_cherry"
        self.mcp_host = "0.0.0.0"  # 允许所有网络访问
        self.mcp_port = 8001  # 服务端口（可修改为未占用端口）
        self.mcp_transport = "streamable-http"
        self.log_level = "INFO"  # 日志级别：DEBUG/INFO/WARNING/ERROR

        # 客户端适配配置
        self.auto_approve_tools = True  # 自动批准工具调用
        self.timeout = 1800  # 超时时间（秒）

        # 全局系统提示词（补充 PE 工具说明，指导正确调用）
        self.system_prompt = """
        你是一个具备工具调用能力的服务助手，具备针对Windows PE/PE32+文件的分析能力，可使用以下工具完成任务：
        1. 系统工具：get_date()、get_time()、get_system_info()
        2. PE文件工具：
           - open_pe_file(file_path): 打开PE文件（所有PE操作的前置步骤）
           - close_pe_file(): 关闭PE文件并释放资源
           - get_pe_basic_info(): 获取PE文件基础信息
           - show_dos_head(): 查询DOS头完整信息
           - show_nt_head(): 查询NT头完整信息
           - show_section(): 查询所有节区信息
           - show_optional_data_directory(): 查询可选头数据目录表
           - 导入表相关：show_import_by_dll()、show_import_by_name(dll_name)、show_import_by_function(target_func, ...)、show_import_all()
           - 导出表相关：show_export()
           - 重定位表相关：show_fix_reloc_page()、show_fix_reloc(target_rva)
           - 资源表相关：show_resource()
           - 地址转换：va_to_foa(va)、rva_to_foa(rva)、foa_to_va(foa)、va_to_rva(va)、rva_to_va(rva)
           - 数据操作：get_hex_ascii(start_addr, addr_len)、search_signature(...)、search_string(...)
           - 高级功能：get_module_status()、get_process_address(dll_name, func_name)、disassemble_code(...)
           - 计算器：add_calculator(x, y)、sub_calculator(x, y)

        调用工具时请严格传入必填参数，工具返回结果会自动整理为JSON格式供你使用。
        注意：调用PE相关工具前，必须先通过 open_pe_file 成功打开目标文件。
        输出语言：必须使用简体中文。
        """

# -------------------------- 2. 响应格式化工具 --------------------------
class ResponseFormatter:
    @staticmethod
    def success(result: Any) -> str:
        """格式化成功响应"""
        return json.dumps({
            "status": "success",
            "result": result
        }, ensure_ascii=False, indent=2)

    @staticmethod
    def error(message: str, details: Optional[Any] = None) -> str:
        """格式化错误响应（补充错误详情，便于调试）"""
        response = {
            "status": "error",
            "message": f"{message}（详情：{str(details)}）" if details else message
        }
        return json.dumps(response, ensure_ascii=False, indent=2)

# -------------------------- 3. 工具实现（修复异步阻塞问题） --------------------------
Number: TypeAlias = Union[int, float]

class InfoTools:
    def __init__(self, config: ServerConfig):
        self.config = config

    async def get_date(self) -> str:
        """
        功能：获取当前系统日期
        用途：需要日期信息时调用（如日志记录、日期判断等）
        调用示例：get_date()
        返回格式：YYYY-MM-DD
        """
        try:
            current_date = datetime.now().strftime("%Y-%m-%d")
            return ResponseFormatter.success(current_date)
        except Exception as e:
            return ResponseFormatter.error("获取日期失败", e)

    async def get_time(self) -> str:
        """
        功能：获取当前系统时间
        用途：需要时间戳或时间判断时调用
        调用示例：get_time()
        返回格式：HH:MM:SS
        """
        try:
            current_time = datetime.now().strftime("%H:%M:%S")
            return ResponseFormatter.success(current_time)
        except Exception as e:
            return ResponseFormatter.error("获取时间失败", e)

    async def get_system_info(self) -> str:
        """
        功能：获取系统基础信息
        用途：调试环境或获取运行上下文时使用
        调用示例：get_system_info()
        返回内容：操作系统、Python版本、服务端口等
        """
        try:
            info = {
                "os": platform.system(),  # 操作系统（Windows/Linux/macOS）
                "os_version": platform.version(),
                "python_version": platform.python_version(),
                "service_port": self.config.mcp_port,
                "service_id": self.config.mcp_service_id
            }
            return ResponseFormatter.success(info)
        except Exception as e:
            return ResponseFormatter.error("获取系统信息失败", e)

class PeTools:
    def __init__(self, config: ServerConfig):
        # 区分 ServerConfig 和 peview_client 的 Config，避免变量名混淆
        self.server_config = config
        # 初始化 PE 客户端
        self.pe_config = Config(address="127.0.0.1", port=8000)
        self.pe = PE(self.pe_config)

    async def open_pe_file(self, file_path: str) -> str:
        """
        功能：打开PE文件（所有PE操作的前置步骤）
        用途：后续PE分析、解析操作需先调用此方法
        调用示例：open_pe_file("d://win32.exe") 或 open_pe_file("/home/test/test.exe")
        参数说明：file_path - PE文件的完整路径（需包含文件名和后缀）
        """
        try:
            # 用 asyncio.to_thread 包装同步方法，避免阻塞异步事件循环
            result = await asyncio.to_thread(self.pe.open_file, file_path)
            return ResponseFormatter.success(f"PE文件打开成功（路径：{file_path}），结果：{str(result)}")
        except Exception as e:
            return ResponseFormatter.error(f"打开PE文件失败（路径：{file_path}）", e)

    async def close_pe_file(self) -> str:
        """
        功能：关闭PE文件并释放服务端资源
        用途：PE文件操作完成后建议调用
        调用示例：close_pe_file()
        """
        try:
            result = await asyncio.to_thread(self.pe.close_file)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("关闭PE文件失败", e)

    async def get_pe_basic_info(self) -> str:
        """
        功能：查询PE文件基础信息
        用途：获取文件属性、DOS/NT头标识、可选头关键信息
        调用示例：get_pe_basic_info()
        """
        try:
            result = await asyncio.to_thread(self.pe.get_basic_info)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询PE基础信息失败", {"error_detail": str(e)})

    async def show_dos_head(self) -> str:
        """
        功能：查询DOS头完整信息（IMAGE_DOS_HEADER）
        用途：获取MZ标识、PE头偏移等DOS头字段信息
        调用示例：show_dos_head()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_dos_head)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询DOS头信息失败", e)

    async def show_nt_head(self) -> str:
        """
        功能：查询NT头完整信息
        用途：获取NT签名、文件头、可选头（32位）等信息
        调用示例：show_nt_head()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_nt_head)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询NT头信息失败", e)

    async def show_section(self) -> str:
        """
        功能：查询所有节区信息（IMAGE_SECTION_HEADER）
        用途：获取节区数量、每个节区的RVA/FOA/属性等信息
        调用示例：show_section()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_section)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询节区信息失败", e)

    async def show_optional_data_directory(self) -> str:
        """
        功能：查询可选头数据目录表
        用途：获取16个标准目录项（导出表、导入表等）的地址信息
        调用示例：show_optional_data_directory()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_optional_data_directory)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询可选头数据目录失败", e)

    async def show_import_by_dll(self) -> str:
        """
        功能：查询所有导入DLL列表
        用途：获取每个DLL的INT/IAT地址、时间戳等信息
        调用示例：show_import_by_dll()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_import_by_dll)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询导入DLL列表失败", e)

    async def show_import_by_name(self, dll_name: str) -> str:
        """
        功能：查询指定DLL的导入函数列表
        用途：获取特定DLL的序号导入/名称导入函数信息
        调用示例：show_import_by_name("KERNEL32.dll")
        参数说明：dll_name - 目标DLL名称（区分大小写）
        """
        try:
            result = await asyncio.to_thread(self.pe.show_import_by_name, dll_name)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"查询{dll_name}导入函数失败", e)

    async def show_import_by_function(
            self,
            target_func: str,
            case_sensitive: bool = False,
            check_ordinal: bool = True
    ) -> str:
        """
        功能：按函数名/序号匹配导入函数（支持模糊匹配）
        用途：查找特定函数名或序号的导入函数信息
        调用示例：show_import_by_function("CreateFileA")
        参数说明：
            target_func - 目标函数名或序号（例："CreateFileA"或"123"）
            case_sensitive - 是否区分大小写（默认False）
            check_ordinal - 是否按序号匹配（默认True，target_func为数字时生效）
        """
        try:
            result = await asyncio.to_thread(
                self.pe.show_import_by_function,
                target_func,
                case_sensitive,
                check_ordinal
            )
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"查询目标函数{target_func}失败", e)

    async def show_import_all(self) -> str:
        """
        功能：遍历所有导入模块和函数（全局导入表完整信息）
        用途：获取导入表全局信息及每个DLL的导入函数详情
        调用示例：show_import_all()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_import_all)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询全局导入表失败", e)

    async def show_export(self) -> str:
        """
        功能：查询导出表完整信息
        用途：获取导出函数、序号、转发函数等信息
        调用示例：show_export()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_export)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询导出表信息失败", e)

    async def show_fix_reloc_page(self) -> str:
        """
        功能：查询重定位表分页情况
        用途：获取所有重定位块的基础信息（起始RVA/FOA/项数）
        调用示例：show_fix_reloc_page()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_fix_reloc_page)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询重定位表分页失败", e)

    async def show_fix_reloc(self, target_rva: Union[str, int]) -> str:
        """
        功能：遍历指定RVA的重定位数据或所有重定位数据
        用途：获取特定RVA或全部重定位块及重定位项详情
        调用示例：show_fix_reloc("0x1000") 或 show_fix_reloc("all")
        参数说明：target_rva - 目标RVA（十六进制/十进制）或"all"（遍历所有）
        """
        try:
            result = await asyncio.to_thread(self.pe.show_fix_reloc, target_rva)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"查询目标RVA{target_rva}重定位数据失败", e)

    async def show_resource(self) -> str:
        """
        功能：查询资源表完整信息
        用途：获取资源类型（图标、菜单等）、数据地址、大小等信息（3级目录结构）
        调用示例：show_resource()
        """
        try:
            result = await asyncio.to_thread(self.pe.show_resource)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询资源表信息失败", e)

    async def va_to_foa(self, va: Union[str, int]) -> str:
        """
        功能：VA（虚拟地址）转换为FOA（文件偏移地址）
        用途：地址转换工具，辅助定位文件中的数据
        调用示例：va_to_foa("0x401000") 或 va_to_foa(4198400)
        参数说明：va - 目标虚拟地址（十六进制字符串或十进制整数）
        """
        try:
            result = await asyncio.to_thread(self.pe.va_to_foa, va)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"VA{va}转换为FOA失败", e)

    async def rva_to_foa(self, rva: Union[str, int]) -> str:
        """
        功能：RVA（相对虚拟地址）转换为FOA（文件偏移地址）
        用途：地址转换工具，辅助定位文件中的数据
        调用示例：rva_to_foa("0x1000") 或 rva_to_foa(4096)
        参数说明：rva - 目标相对虚拟地址（十六进制字符串或十进制整数）
        """
        try:
            result = await asyncio.to_thread(self.pe.rva_to_foa, rva)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"RVA{rva}转换为FOA失败", e)

    async def foa_to_va(self, foa: Union[str, int]) -> str:
        """
        功能：FOA（文件偏移地址）转换为VA（虚拟地址）
        用途：地址转换工具，辅助内存地址计算
        调用示例：foa_to_va("0x800") 或 foa_to_va(2048)
        参数说明：foa - 目标文件偏移地址（十六进制字符串或十进制整数）
        """
        try:
            result = await asyncio.to_thread(self.pe.foa_to_va, foa)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"FOA{foa}转换为VA失败", e)

    async def va_to_rva(self, va: Union[str, int]) -> str:
        """
        功能：VA（虚拟地址）转换为RVA（相对虚拟地址）
        用途：地址转换工具，辅助PE结构分析
        调用示例：va_to_rva("0x401000") 或 va_to_rva(4198400)
        参数说明：va - 目标虚拟地址（十六进制字符串或十进制整数）
        """
        try:
            result = await asyncio.to_thread(self.pe.va_to_rva, va)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"VA{va}转换为RVA失败", e)

    async def rva_to_va(self, rva: Union[str, int]) -> str:
        """
        功能：RVA（相对虚拟地址）转换为VA（虚拟地址）
        用途：地址转换工具，辅助内存地址计算
        调用示例：rva_to_va("0x1000") 或 rva_to_va(4096)
        参数说明：rva - 目标相对虚拟地址（十六进制字符串或十进制整数）
        """
        try:
            result = await asyncio.to_thread(self.pe.rva_to_va, rva)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"RVA{rva}转换为VA失败", e)

    async def get_hex_ascii(self, start_addr: Union[str, int], addr_len: Union[str, int]) -> str:
        """
        功能：读取文件指定范围的十六进制和ASCII数据
        用途：查看文件原始数据，按16字节/行格式化显示
        调用示例：get_hex_ascii("0x0", "0x100")
        参数说明：
            start_addr - 起始地址（FOA，十六进制或十进制）
            addr_len - 读取长度（正整数，十六进制或十进制）
        """
        try:
            result = await asyncio.to_thread(self.pe.get_hex_ascii, start_addr, addr_len)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"读取地址范围[{start_addr}:{addr_len}]数据失败", e)

    async def search_signature(self, start_addr: Union[str, int], search_len: Union[str, int], sig_str: str) -> str:
        """
        功能：特征码搜索（支持通配符??）
        用途：查找文件中匹配特定特征码的位置
        调用示例：search_signature("0x1000", "0x1000", "55 8B ?? EC")
        参数说明：
            start_addr - 起始地址（FOA，十六进制或十进制）
            search_len - 搜索长度（十六进制或十进制）
            sig_str - 特征码字符串（空格分隔，??为通配符）
        """
        try:
            result = await asyncio.to_thread(
                self.pe.search_signature,
                start_addr,
                search_len,
                sig_str
            )
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"搜索特征码{sig_str}失败", e)

    async def search_string(self, start_addr: Union[str, int], search_len: Union[str, int], target_str: str) -> str:
        """
        功能：ASCII字符串搜索（严格匹配）
        用途：查找文件中特定的ASCII字符串
        调用示例：search_string("0x2000", "0x500", "CreateFileA")
        参数说明：
            start_addr - 起始地址（FOA，十六进制或十进制）
            search_len - 搜索长度（十六进制或十进制）
            target_str - 目标ASCII字符串
        """
        try:
            result = await asyncio.to_thread(
                self.pe.search_string,
                start_addr,
                search_len,
                target_str
            )
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"搜索字符串{target_str}失败", e)

    async def get_module_status(self) -> str:
        """
        功能：查询模块保护方式（安全特性）
        用途：获取ASLR/DEP/CFG等安全机制信息
        调用示例：get_module_status()
        """
        try:
            result = await asyncio.to_thread(self.pe.get_module_status)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error("查询模块安全特性失败", e)

    async def get_process_address(self, dll_name: str, func_name: str) -> str:
        """
        功能：获取指定DLL的导出函数地址（模拟LoadLibrary+GetProcAddress）
        用途：查询特定函数的内存地址信息
        调用示例：get_process_address("KERNEL32.dll", "CreateFileA")
        参数说明：
            dll_name - DLL名称（例："KERNEL32.dll"）
            func_name - 函数名称（区分大小写）
        """
        try:
            result = await asyncio.to_thread(self.pe.get_process_address, dll_name, func_name)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"获取{dll_name}:{func_name}地址失败", e)

    async def disassemble_code(self, start_foa: Union[str, int], disasm_len: Union[str, int]) -> str:
        """
        功能：反汇编指定文件范围（基于Capstone引擎，x86-32架构）
        用途：查看指定地址范围的汇编指令
        调用示例：disassemble_code("0x1000", "0x200")
        参数说明：
            start_foa - 起始FOA（十六进制或十进制）
            disasm_len - 反汇编长度（最大0x100000）
        """
        try:
            result = await asyncio.to_thread(self.pe.disassemble_code, start_foa, disasm_len)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"反汇编地址范围[{start_foa}:{disasm_len}]失败", e)

    async def add_calculator(self, x: Union[str, int], y: Union[str, int]) -> str:
        """
        功能：十六进制加法计算器（DWORD无符号运算）
        用途：PE地址计算辅助工具
        调用示例：add_calculator("0x1A", 26)
        参数说明：
            x - 被加数（十六进制字符串或十进制整数）
            y - 加数（同上）
        """
        try:
            result = await asyncio.to_thread(self.pe.add_calculator, x, y)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"{x} + {y} 加法计算失败", e)

    async def sub_calculator(self, x: Union[str, int], y: Union[str, int]) -> str:
        """
        功能：十六进制减法计算器（DWORD无符号运算）
        用途：PE地址计算辅助工具
        调用示例：sub_calculator("0x20", "0xA")
        参数说明：
            x - 被减数（十六进制字符串或十进制整数）
            y - 减数（同上）
        """
        try:
            result = await asyncio.to_thread(self.pe.sub_calculator, x, y)
            return ResponseFormatter.success(result)
        except Exception as e:
            return ResponseFormatter.error(f"{x} - {y} 减法计算失败", e)

# -------------------------- 4. 客户端适配逻辑（补充PE工具到自动允许列表） --------------------------
def generate_cherry_config(config: ServerConfig) -> Dict[str, Any]:
    """生成客户端适配配置"""
    # 处理Python可执行路径（跨平台兼容）
    python_exec = sys.executable
    if os.name == "nt":
        python_exec = python_exec.replace("\\", "/")
        if " " in python_exec:
            python_exec = f'"{python_exec}"'
    else:
        python_exec = shlex.quote(python_exec)

    # 处理当前脚本路径（支持符号链接）
    current_script = os.path.abspath(__file__)
    if os.path.islink(current_script):
        current_script = os.path.realpath(current_script)
    if os.name == "nt" and " " in current_script:
        current_script = f'"{current_script}"'
    else:
        current_script = shlex.quote(current_script)

    # 所有PE工具方法名列表
    pe_tool_names = [
        "open_pe_file", "close_pe_file", "get_pe_basic_info", "show_dos_head",
        "show_nt_head", "show_section", "show_optional_data_directory",
        "show_import_by_dll", "show_import_by_name", "show_import_by_function",
        "show_import_all", "show_export", "show_fix_reloc_page", "show_fix_reloc",
        "show_resource", "va_to_foa", "rva_to_foa", "foa_to_va", "va_to_rva",
        "rva_to_va", "get_hex_ascii", "search_signature", "search_string",
        "get_module_status", "get_process_address", "disassemble_code",
        "add_calculator", "sub_calculator"
    ]

    return {
        "mcpServers": {
            config.mcp_service_id: {
                "command": python_exec,
                "args": [current_script, "--run-server"],
                "timeout": config.timeout,
                "disabled": False,
                "autoApprove": config.auto_approve_tools,
                # 自动允许的工具列表（系统工具+PE工具）
                "alwaysAllow": ["get_date", "get_time", "get_system_info"] + pe_tool_names,
                "host": config.mcp_host,
                "port": config.mcp_port,
                "transport": config.mcp_transport,
                "systemPrompt": config.system_prompt.strip()
            }
        },
        "version": "1.0",
        "compatibility": {
            "minimumStudioVersion": "1.0.0",
            "features": ["tool_auto_approve", "transport_multiplexing"]
        },
        # 环境变量配置（确保编码兼容，避免中文路径乱码）
        "env": {
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8"
        } if os.name == "nt" else {
            "LC_ALL": "en_US.UTF-8",
            "LANG": "en_US.UTF-8"
        }
    }

def print_cherry_guide(config: ServerConfig):
    """打印服务配置和使用指南（补充PE工具说明）"""
    cherry_config = generate_cherry_config(config)
    print("MCP服务配置")
    print(json.dumps(cherry_config, indent=2, ensure_ascii=False))
    print("\n服务访问地址")
    print(f"http://{config.mcp_host}:{config.mcp_port}/mcp")
    print(config.system_prompt.strip())

def register_tools(mcp: FastMCP, config: ServerConfig):
    """注册所有可用工具（确保PE工具正确注册）"""
    # 注册系统信息工具
    info_tools = InfoTools(config)
    mcp.tool()(info_tools.get_date)
    mcp.tool()(info_tools.get_time)
    mcp.tool()(info_tools.get_system_info)

    # 注册PE文件工具
    pe_tools = PeTools(config)
    mcp.tool()(pe_tools.open_pe_file)
    mcp.tool()(pe_tools.close_pe_file)
    mcp.tool()(pe_tools.get_pe_basic_info)
    mcp.tool()(pe_tools.show_dos_head)
    mcp.tool()(pe_tools.show_nt_head)
    mcp.tool()(pe_tools.show_section)
    mcp.tool()(pe_tools.show_optional_data_directory)
    mcp.tool()(pe_tools.show_import_by_dll)
    mcp.tool()(pe_tools.show_import_by_name)
    mcp.tool()(pe_tools.show_import_by_function)
    mcp.tool()(pe_tools.show_import_all)
    mcp.tool()(pe_tools.show_export)
    mcp.tool()(pe_tools.show_fix_reloc_page)
    mcp.tool()(pe_tools.show_fix_reloc)
    mcp.tool()(pe_tools.show_resource)
    mcp.tool()(pe_tools.va_to_foa)
    mcp.tool()(pe_tools.rva_to_foa)
    mcp.tool()(pe_tools.foa_to_va)
    mcp.tool()(pe_tools.va_to_rva)
    mcp.tool()(pe_tools.rva_to_va)
    mcp.tool()(pe_tools.get_hex_ascii)
    mcp.tool()(pe_tools.search_signature)
    mcp.tool()(pe_tools.search_string)
    mcp.tool()(pe_tools.get_module_status)
    mcp.tool()(pe_tools.get_process_address)
    mcp.tool()(pe_tools.disassemble_code)
    mcp.tool()(pe_tools.add_calculator)
    mcp.tool()(pe_tools.sub_calculator)

# -------------------------- 5. 服务启动逻辑（修复日志显示问题） --------------------------
if __name__ == "__main__":
    config = ServerConfig()

    # 处理命令行参数（增加参数合法性校验）
    if len(sys.argv) > 1:
        if sys.argv[1] == "--generate-config":
            print_cherry_guide(config)
            sys.exit(1)
        elif sys.argv[1] == "--run-server":
            pass
        else:
            sys.exit(1)
    else:
        sys.exit(1)

    # 启动MCP服务（增强错误捕获粒度）
    try:
        mcp = FastMCP(
            name=config.mcp_service_id,
            host=config.mcp_host,
            port=config.mcp_port,
            log_level=config.log_level
        )
        print(f"[*] 成功初始化MCP服务（ID：{config.mcp_service_id}）")
    except OSError as e:
        print(f"[-] 服务初始化失败：端口「{config.mcp_port}」相关错误", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] 服务初始化失败：未知错误", file=sys.stderr)
        sys.exit(1)

    # 注册工具（补充PE工具注册日志）
    try:
        register_tools(mcp, config)
        print("[*] 工具注册完成：系统工具（3个）+ PE工具（27个）")
    except Exception as e:
        print(f"[-] 工具注册失败", file=sys.stderr)
        sys.exit(1)

    # 运行服务（优化异步循环处理）
    try:
        # 检查是否已有运行中的事件循环（如Jupyter环境）
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # 无运行中的循环，使用asyncio.run创建新循环
        asyncio.run(mcp.run(transport=config.mcp_transport))
    else:
        # 已有运行中的循环，添加任务并保持运行
        if not loop.is_running():
            loop.run_until_complete(mcp.run(transport=config.mcp_transport))
        else:
            loop.create_task(mcp.run(transport=config.mcp_transport))
            loop.run_forever()