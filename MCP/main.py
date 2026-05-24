from peview_client import *

if __name__ == "__main__":
    # 初始化配置
    config = Config(address="127.0.0.1", port=8000)

    # 验证服务器是否可用
    if not config.is_server_available():
        print("服务器未启动或端口不可达，请检查服务状态")
    else:
        print("服务器连接正常，可执行后续操作")

    # 创建PE接口实例
    pe = PE(config)

    # 1. 打开本地PE文件
    open_result = pe.open_file("e:\\win32.exe")
    print("文件打开结果：", open_result)

    # 2. 查询文件基础信息（需在open成功后调用）
    basic_info = pe.get_basic_info()
    print("\n文件基础信息：")
    print("文件路径：", basic_info["file_basic_info"]["file_path"])
    print("PE签名：", basic_info["pe_identifier"]["nt_signature_desc"])
    print("入口点RVA：", basic_info["optional_header_info"]["entry_point_rva_hex"])

    dasm = pe.disassemble_code("0x400","100")

    print(dasm)



    pe.close_file()