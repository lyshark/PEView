import http.client
import json
import socket
from urllib.parse import urlparse
from typing import Optional, Dict, Any, Union, List

class Config:
    """配置类，用于存储和共享共享连接连接参数"""

    def __init__(self, address="127.0.0.1", port=8000):
        self.address = address
        self.port = port
        self.ida_server_addr = f"http://{address}:{port}"

    def is_server_available(self, timeout=2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((self.address, self.port))
                return result == 0
        except socket.error as e:
            print(f"检测服务器时发生错误: {str(e)}")
            return False

class BaseHttpClient:
    """HTTP请求基类，提取公共请求逻辑，避免代码重复"""

    def __init__(self, config: Config):
        self.config = config
        parsed_url = urlparse(self.config.ida_server_addr)
        self.address = parsed_url.hostname
        self.port = parsed_url.port
        self.scheme = parsed_url.scheme
        self.path = parsed_url.path or '/'  # 缓存请求路径，避免重复解析

    def custom_post(self, json_data: Optional[Dict] = None, headers: Optional[Dict] = None, timeout=5) -> Dict[
        str, Any]:
        """通用POST请求发送方法，与服务端通信格式严格匹配"""
        # 处理默认请求头
        if not headers:
            headers = {}
        if json_data and 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'

        # 处理请求体（确保空数据时不传递body）
        body = json.dumps(json_data).encode('utf-8') if json_data else None

        try:
            # 根据协议选择HTTP/HTTPS连接
            conn = http.client.HTTPSConnection(self.address, self.port, timeout=timeout) if self.scheme == 'https' \
                else http.client.HTTPConnection(self.address, self.port, timeout=timeout)

            conn.request("POST", self.path, body=body, headers=headers)
            response = conn.getresponse()

            # 构建统一的响应结果结构
            result = {
                'status_code': response.status,
                'reason': response.reason,
                'text': response.read().decode('utf-8'),
                'headers': response.getheaders()
            }

            # 尝试解析JSON响应（服务端返回标准JSON格式）
            try:
                result['json'] = json.loads(result['text']) if result['text'] else None
            except json.JSONDecodeError:
                result['json'] = None

            conn.close()
            return result

        except socket.timeout:
            raise Exception(f"请求超时 (超过{timeout}秒)")
        except Exception as e:
            raise Exception(f"请求失败: {str(e)}")

    def _validate_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """统一响应验证逻辑，匹配服务端错误处理流程"""
        # 1. 验证HTTP状态码
        if response['status_code'] != 200:
            raise Exception(f"服务器返回错误: {response['status_code']} {response['reason']}")

        # 2. 验证JSON格式
        response_json = response['json']
        if not response_json:
            raise Exception("无法解析响应数据（非JSON格式）")

        # 3. 验证服务端业务状态（服务端返回格式：{'status': 'success', 'result': {...}}）
        if response_json.get('status') != 'success':
            error_msg = response_json.get('result', {}).get('error', '未知业务错误')
            raise Exception(f"操作失败: {error_msg}")

        # 返回业务结果数据
        return response_json.get('result', {})

class PE(BaseHttpClient):
    """
    PE文件操作接口客户端类，与服务端`PEViewHandler`完全对齐
    所有操作需先调用`open_file`打开PE文件，否则会抛出"文件未打开"异常
    """

    def __init__(self, config: Optional[Config] = None):
        super().__init__(config or Config())

    # --------------------------------------------------
    # 基础文件操作接口
    # --------------------------------------------------
    def open_file(self, file_path: str) -> Dict[str, Any]:
        """
        打开PE文件（所有其他操作的前置必选步骤）
        :param file_path: PE文件绝对路径（例："C:\\Windows\\notepad.exe" 或 "/usr/bin/ls"）
        :return: 成功响应示例：
            {
                "message": "The PE file has been successfully opened",
                "file_path": "C:\\Windows\\notepad.exe",
                "file_size": 242688
            }
        """
        request_data = {
            "class": "PE",
            "interface": "Open",
            "params": [file_path]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def close_file(self) -> Dict[str, Any]:
        """
        关闭PE文件并释放服务端资源（建议操作完成后调用）
        :return: 成功响应示例：{"message": "PE file closed, resource released"}
        """
        request_data = {
            "class": "PE",
            "interface": "Close",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def get_basic_info(self) -> Dict[str, Any]:
        """
        查询PE文件基础信息（包含文件属性、DOS/NT头标识、可选头关键信息）
        :return: 分层结构化数据，示例：
            {
                "file_basic_info": {
                    "file_path": "C:\\Windows\\notepad.exe",
                    "file_size_bytes": 242688,
                    "create_time": "2023-10-05 14:32:18",
                    ...
                },
                "pe_identifier": {
                    "dos_signature_desc": "Valid DOS signature (MZ)",
                    "nt_signature_desc": "Valid PE signature (pe00)",
                    ...
                },
                "optional_header_info": {
                    "entry_point_rva_hex": "0x1000",
                    "subsystem_desc": "Windows CUI (Console Application )",
                    ...
                }
            }
        """
        request_data = {
            "class": "PE",
            "interface": "FileBasicInfo",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # PE结构解析接口
    # --------------------------------------------------
    def show_dos_head(self) -> Dict[str, Any]:
        """
        查询DOS头完整信息（IMAGE_DOS_HEADER）
        :return: 包含所有DOS头字段的结构化数据，示例：
            {
                "dos_header": {
                    "e_magic": {"hex": "0x5A4D", "dec": 23117},  # MZ标识
                    "e_lfanew": {"hex": "0x80", "dec": 128},     # PE头偏移
                    "e_res": [{"hex": "0x0", "dec": 0}, ...],    # 保留字段数组
                    ...
                },
                "message": "DOS header parsing succeeded"
            }
        """
        request_data = {
            "class": "PE",
            "interface": "DosHead",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_nt_head(self) -> Dict[str, Any]:
        """
        查询NT头完整信息（包含NT签名、IMAGE_FILE_HEADER、IMAGE_OPTIONAL_HEADER32）
        :return: 分层结构化数据，涵盖机器类型、节区数、入口点、镜像基址等
        """
        request_data = {
            "class": "PE",
            "interface": "NtHead",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_section(self) -> Dict[str, Any]:
        """
        查询所有节区信息（IMAGE_SECTION_HEADER）
        :return: 包含节区总数、每个节区的RVA/FOA/属性等，示例：
            {
                "section_info": {
                    "section_count": 4,
                    "sections": [
                        {
                            "section_index": 1,
                            "section_name": ".text",
                            "virtual_address_rva_hex": "0x1000",
                            "characteristics_desc": "Code section; Executable; readable;",
                            ...
                        },
                        ...
                    ]
                },
                "message": "Section information parsing succeeded"
            }
        """
        request_data = {
            "class": "PE",
            "interface": "Section",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_optional_data_directory(self) -> Dict[str, Any]:
        """
        查询可选头数据目录表（16个标准目录项，如导出表、导入表、资源表）
        :return: 包含每个目录项的RVA/VA/FOA/有效性标识
        """
        request_data = {
            "class": "PE",
            "interface": "OptionalDataDirectory",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 导入表解析接口
    # --------------------------------------------------
    def show_import_by_dll(self) -> Dict[str, Any]:
        """
        查询所有导入DLL列表（含每个DLL的INT/IAT地址、时间戳等）
        :return: 示例：
            {
                "import_by_dll_info": {
                    "import_dll_count": 2,
                    "import_dlls": [
                        {
                            "dll_index": 1,
                            "dll_name": "KERNEL32.dll",
                            "int_rva_hex": "0x2000",
                            "iat_va_hex": "0x402000",
                            ...
                        },
                        ...
                    ]
                }
            }
        """
        request_data = {
            "class": "PE",
            "interface": "ImportByDll",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_import_by_name(self, dll_name: str) -> Dict[str, Any]:
        """
        查询指定DLL的导入函数列表（区分序号导入/名称导入）
        :param dll_name: 目标DLL名称（例："KERNEL32.dll"，区分大小写）
        :return: 包含该DLL的所有导入函数信息
        """
        request_data = {
            "class": "PE",
            "interface": "ImportByName",
            "params": [dll_name]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_import_by_function(
            self,
            target_func: str,
            case_sensitive: bool = False,
            check_ordinal: bool = True
    ) -> Dict[str, Any]:
        """
        按函数名/序号匹配导入函数（支持模糊匹配）
        :param target_func: 目标函数名（例："CreateFileA"）或序号（例："123"）
        :param case_sensitive: 是否区分大小写（默认False）
        :param check_ordinal: 是否按序号匹配（默认True，target_func为数字时生效）
        :return: 所有匹配的函数信息（含所属DLL、INT/IAT地址）
        """
        request_data = {
            "class": "PE",
            "interface": "ImportByFunction",
            "params": [target_func, str(case_sensitive).lower(), str(check_ordinal).lower()]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_import_all(self) -> Dict[str, Any]:
        """
        遍历所有导入模块和函数（全局导入表完整信息）
        :return: 包含导入表全局信息、每个DLL的导入函数详情
        """
        request_data = {
            "class": "PE",
            "interface": "ImportAll",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 导出表解析接口
    # --------------------------------------------------
    def show_export(self) -> Dict[str, Any]:
        """
        查询导出表完整信息（含导出函数、序号、转发函数等）
        :return: 示例：
            {
                "export_info": {
                    "export_table_global": {
                        "module_name": "notepad.exe",
                        "total_function_count": 5,
                        "named_function_count": 3,
                        ...
                    },
                    "export_functions": [
                        {
                            "function_name": "ExportedFunc1",
                            "function_rva_hex": "0x1200",
                            "export_ordinal": 1,
                            "status": "normal",
                            ...
                        },
                        ...
                    ]
                }
            }
        """
        request_data = {
            "class": "PE",
            "interface": "Export",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 重定位表解析接口
    # --------------------------------------------------
    def show_fix_reloc_page(self) -> Dict[str, Any]:
        """
        查询重定位表分页情况（所有重定位块的基础信息）
        :return: 包含重定位块总数、每个块的起始RVA/FOA/项数
        """
        request_data = {
            "class": "PE",
            "interface": "FixRelocPage",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def show_fix_reloc(self, target_rva: Union[str, int]) -> Dict[str, Any]:
        """
        遍历指定RVA的重定位数据或所有重定位数据
        :param target_rva: 目标RVA（例："0x1000" 或 4096）或 "all"（遍历所有）
        :return: 匹配的重定位块及块内重定位项详情
        """
        # 统一转换为字符串参数（支持十六进制/十进制/"all"）
        param = target_rva if isinstance(target_rva, str) else hex(target_rva)
        request_data = {
            "class": "PE",
            "interface": "FixReloc",
            "params": [param]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 资源表解析接口
    # --------------------------------------------------
    def show_resource(self) -> Dict[str, Any]:
        """
        查询资源表完整信息（3级目录结构：类型目录→名称/ID目录→语言目录）
        :return: 包含资源类型（图标、菜单、字符串等）、数据地址、大小等
        """
        request_data = {
            "class": "PE",
            "interface": "Resource",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 地址转换接口（VA/RVA/FOA互转）
    # --------------------------------------------------
    def va_to_foa(self, va: Union[str, int]) -> Dict[str, Any]:
        """
        VA（虚拟地址）转换为FOA（文件偏移地址）
        :param va: 目标VA（例："0x401000" 或 4198400）
        :return: 转换结果含步骤说明、所属节区信息
        """
        param = va if isinstance(va, str) else hex(va)
        request_data = {
            "class": "PE",
            "interface": "VAToFOA",
            "params": [param]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def rva_to_foa(self, rva: Union[str, int]) -> Dict[str, Any]:
        """
        RVA（相对虚拟地址）转换为FOA（文件偏移地址）
        :param rva: 目标RVA（例："0x1000" 或 4096，不可为0）
        :return: 转换结果含VA辅助信息、节区扫描日志
        """
        param = rva if isinstance(rva, str) else hex(rva)
        request_data = {
            "class": "PE",
            "interface": "RVAToFOA",
            "params": [param]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def foa_to_va(self, foa: Union[str, int]) -> Dict[str, Any]:
        """
        FOA（文件偏移地址）转换为VA（虚拟地址）
        :param foa: 目标FOA（例："0x800" 或 2048）
        :return: 转换结果含RVA中间值、节区匹配日志
        """
        param = foa if isinstance(foa, str) else hex(foa)
        request_data = {
            "class": "PE",
            "interface": "FOAToVA",
            "params": [param]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def va_to_rva(self, va: Union[str, int]) -> Dict[str, Any]:
        """
        VA（虚拟地址）转换为RVA（相对虚拟地址）
        :param va: 目标VA（例："0x401000" 或 4198400）
        :return: 转换结果含有效性校验（是否在模块范围内）
        """
        param = va if isinstance(va, str) else hex(va)
        request_data = {
            "class": "PE",
            "interface": "VAToRVA",
            "params": [param]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def rva_to_va(self, rva: Union[str, int]) -> Dict[str, Any]:
        """
        RVA（相对虚拟地址）转换为VA（虚拟地址）
        :param rva: 目标RVA（例："0x1000" 或 4096）
        :return: 转换结果含节区有效性校验（是否在有效节区内）
        """
        param = rva if isinstance(rva, str) else hex(rva)
        request_data = {
            "class": "PE",
            "interface": "RVAToVA",
            "params": [param]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 数据读取与搜索接口
    # --------------------------------------------------
    def get_hex_ascii(self, start_addr: Union[str, int], addr_len: Union[str, int]) -> Dict[str, Any]:
        """
        读取文件指定范围的十六进制和ASCII数据（16字节/行格式化）
        :param start_addr: 起始地址（FOA，例："0x0" 或 0）
        :param addr_len: 读取长度（例："0x100" 或 256，需为正整数）
        :return: 每行的偏移、十六进制数组、ASCII字符串
        """
        param_start = start_addr if isinstance(start_addr, str) else hex(start_addr)
        param_len = addr_len if isinstance(addr_len, str) else hex(addr_len)
        request_data = {
            "class": "PE",
            "interface": "HexASCII",
            "params": [param_start, param_len]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def search_signature(self, start_addr: Union[str, int], search_len: Union[str, int], sig_str: str) -> Dict[
        str, Any]:
        """
        特征码搜索（支持通配符??）
        :param start_addr: 起始地址（FOA，例："0x1000"）
        :param search_len: 搜索长度（例："0x1000" 或 4096）
        :param sig_str: 特征码字符串（例："55 8B ?? EC"，空格分隔，??为通配符）
        :return: 所有匹配结果（含匹配偏移、前16字节数据）
        """
        param_start = start_addr if isinstance(start_addr, str) else hex(start_addr)
        param_len = search_len if isinstance(search_len, str) else hex(search_len)
        request_data = {
            "class": "PE",
            "interface": "SearchSignature",
            "params": [param_start, param_len, sig_str]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def search_string(self, start_addr: Union[str, int], search_len: Union[str, int], target_str: str) -> Dict[
        str, Any]:
        """
        ASCII字符串搜索（严格匹配）
        :param start_addr: 起始地址（FOA，例："0x2000"）
        :param search_len: 搜索长度（例："0x500" 或 1280）
        :param target_str: 目标字符串（例："CreateFileA"，仅支持ASCII）
        :return: 所有匹配结果（含FOA/VA偏移）
        """
        param_start = start_addr if isinstance(start_addr, str) else hex(start_addr)
        param_len = search_len if isinstance(search_len, str) else hex(search_len)
        request_data = {
            "class": "PE",
            "interface": "SearchString",
            "params": [param_start, param_len, target_str]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 高级功能接口
    # --------------------------------------------------
    def get_module_status(self) -> Dict[str, Any]:
        """
        查询模块保护方式（ASLR/DEP/CFG等安全特性）
        :return: 包含基础属性、安全特性、其他特性三层数据
        """
        request_data = {
            "class": "PE",
            "interface": "ModuleStatus",
            "params": []
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def get_process_address(self, dll_name: str, func_name: str) -> Dict[str, Any]:
        """
        获取指定DLL的导出函数地址（模拟LoadLibrary+GetProcAddress）
        :param dll_name: DLL名称（例："KERNEL32.dll"）
        :param func_name: 函数名称（例："CreateFileA"，区分大小写）
        :return: 包含DLL加载基址、函数VA/RVA的结构化数据
        """
        request_data = {
            "class": "PE",
            "interface": "GetProcessAddress",
            "params": [dll_name, func_name]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def disassemble_code(self, start_foa: Union[str, int], disasm_len: Union[str, int]) -> Dict[str, Any]:
        """
        反汇编指定文件范围（基于Capstone引擎，x86-32架构）
        :param start_foa: 起始FOA（例："0x1000" 或 4096）
        :param disasm_len: 反汇编长度（例："0x200" 或 512，最大0x100000）
        :return: 每条指令的机器码、反汇编字符串、地址等信息
        """
        param_foa = start_foa if isinstance(start_foa, str) else hex(start_foa)
        param_len = disasm_len if isinstance(disasm_len, str) else hex(disasm_len)
        request_data = {
            "class": "PE",
            "interface": "DisassembleCode",
            "params": [param_foa, param_len]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    # --------------------------------------------------
    # 工具计算器接口
    # --------------------------------------------------
    def add_calculator(self, x: Union[str, int], y: Union[str, int]) -> Dict[str, Any]:
        """
        十六进制加法计算器（DWORD无符号运算）
        :param x: 被加数（十六进制字符串例："0x1A"，十进制例：26）
        :param y: 加数（格式同上）
        :return: 结果含HEX/DEC/OCT/BIN四种格式
        """
        # 统一转换为十六进制字符串参数
        param_x = x if isinstance(x, str) and (x.startswith("0x") or x.startswith("0X")) else hex(x)
        param_y = y if isinstance(y, str) and (y.startswith("0x") or y.startswith("0X")) else hex(y)
        request_data = {
            "class": "PE",
            "interface": "AddCalculator",
            "params": [param_x, param_y]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)

    def sub_calculator(self, x: Union[str, int], y: Union[str, int]) -> Dict[str, Any]:
        """
        十六进制减法计算器（DWORD无符号运算，负数自动模2^32）
        :param x: 被减数（格式同add_calculator）
        :param y: 减数（格式同add_calculator）
        :return: 结果含HEX/DEC/OCT/BIN四种格式及无符号提示
        """
        param_x = x if isinstance(x, str) and (x.startswith("0x") or x.startswith("0X")) else hex(x)
        param_y = y if isinstance(y, str) and (y.startswith("0x") or y.startswith("0X")) else hex(y)
        request_data = {
            "class": "PE",
            "interface": "SubCalculator",
            "params": [param_x, param_y]
        }
        response = self.custom_post(json_data=request_data)
        return self._validate_response(response)