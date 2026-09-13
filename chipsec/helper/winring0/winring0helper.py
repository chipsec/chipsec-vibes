# CHIPSEC: Platform Security Assessment Framework
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
CHIPSEC helper using WinRing0-compatible kernel driver for hardware access on Windows.

Communicates directly with the AsusNBRing0x64.sys driver via DeviceIoControl IOCTLs,
without requiring the WinRing0 userspace DLL.

Supported operations:
    - MSR read/write (with per-thread affinity)
    - CPUID (including ECX sub-leaf input via native shellcode)
    - I/O port read/write (byte, word, dword)
    - PCI configuration space read/write (including extended config space)
    - Physical memory read/write
    - MMIO via physical memory access
    - EFI variables (via Windows API)
    - ACPI tables (via Windows API)

Limitations:
    - Physical memory alloc/free and virtual-to-physical translation are not available.
    - CR register access, descriptor tables, SW SMI, hypercall, microcode update,
      and IOSF message bus are not supported through WinRing0.
"""

import ctypes
import errno
import os
import platform
import struct
import sys
import threading

import pywintypes
import winerror
import win32api
import win32file
import win32process
import win32security
import win32service
import win32serviceutil
from collections import namedtuple
from ctypes import windll, CFUNCTYPE, POINTER
from ctypes import c_int, c_uint32, c_ulong, c_ushort, c_ubyte
from ctypes import c_void_p, c_wchar_p, c_char_p, c_size_t
from ctypes import addressof, sizeof, create_string_buffer, WinError
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from win32file import OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE

if TYPE_CHECKING:
    from chipsec.library.types import EfiVariableType
    from ctypes import Array
    from pywintypes import PyHANDLE

from chipsec.helper.basehelper import Helper
from chipsec.library.exceptions import OsHelperError, HWAccessViolationError, UnimplementedAPIError
from chipsec.library.logger import logger
from chipsec.library.uefi.common import EFI_GUID_STR
import chipsec.library.file

# ============================================================================
# Driver and device constants
# ============================================================================

DRIVER_FILE_NAME = 'AsusNBRing0x64.sys'
SERVICE_NAME = 'AsusNBRing0'
DISPLAY_NAME = 'CHIPSEC WinRing0 Helper'
DEVICE_FILE = '\\\\.\\WinRing0_1_2_0'

# ============================================================================
# WinRing0 IOCTL codes
# CTL_CODE(OLS_TYPE=0x9C40, Function, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
# = (0x9C40 << 16) | (Function << 2)
# ============================================================================

_OLS_TYPE = 0x9C40
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2


def _CTL_CODE(function: int, access: int = FILE_ANY_ACCESS) -> int:
    return (_OLS_TYPE << 16) | (access << 14) | (function << 2)


IOCTL_OLS_GET_DRIVER_VERSION = _CTL_CODE(0x800)
IOCTL_OLS_GET_REFCOUNT = _CTL_CODE(0x801)
IOCTL_OLS_READ_MSR = _CTL_CODE(0x821)
IOCTL_OLS_WRITE_MSR = _CTL_CODE(0x822)
IOCTL_OLS_READ_IO_PORT_BYTE = _CTL_CODE(0x833, FILE_READ_ACCESS)
IOCTL_OLS_READ_IO_PORT_WORD = _CTL_CODE(0x834, FILE_READ_ACCESS)
IOCTL_OLS_READ_IO_PORT_DWORD = _CTL_CODE(0x835, FILE_READ_ACCESS)
IOCTL_OLS_WRITE_IO_PORT_BYTE = _CTL_CODE(0x836, FILE_WRITE_ACCESS)
IOCTL_OLS_WRITE_IO_PORT_WORD = _CTL_CODE(0x837, FILE_WRITE_ACCESS)
IOCTL_OLS_WRITE_IO_PORT_DWORD = _CTL_CODE(0x838, FILE_WRITE_ACCESS)
IOCTL_OLS_READ_MEMORY = _CTL_CODE(0x841, FILE_READ_ACCESS)
IOCTL_OLS_WRITE_MEMORY = _CTL_CODE(0x842, FILE_WRITE_ACCESS)

# ============================================================================
# Win32 constants
# ============================================================================

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
STATUS_PRIVILEGED_INSTRUCTION = 0xC0000096

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40

EFI_VAR_MAX_BUFFER_SIZE = 1024 * 1024
FirmwareTableProviderSignature_ACPI = 0x41435049

# ============================================================================
# CPUID native shellcode (x86-64, Windows x64 calling convention)
# RCX = eax_in, RDX = ecx_in, R8 = pointer to uint32[4] output
# ============================================================================

_CPUID_CODE = bytes([
    0x53,                               # push rbx  (callee-saved)
    0x89, 0xC8,                         # mov eax, ecx
    0x89, 0xD1,                         # mov ecx, edx
    0x0F, 0xA2,                         # cpuid
    0x41, 0x89, 0x00,                   # mov [r8], eax
    0x41, 0x89, 0x58, 0x04,             # mov [r8+4], ebx
    0x41, 0x89, 0x48, 0x08,             # mov [r8+8], ecx
    0x41, 0x89, 0x50, 0x0C,             # mov [r8+12], edx
    0x5B,                               # pop rbx
    0xC3,                               # ret
])

_CpuidFuncType = CFUNCTYPE(None, c_uint32, c_uint32, POINTER(c_uint32 * 4))

# ============================================================================
# Module-level helpers
# ============================================================================

kernel32 = windll.kernel32


def _handle_winerror(fn: str, msg: str, hr: int) -> None:
    _handle_error(f'{fn} failed: {msg} ({hr:d})', hr)


def _handle_error(err: str, hr: int = 0) -> None:
    if logger().DEBUG:
        logger().log_error(err)
    raise OsHelperError(err, hr)


# ============================================================================
# WinRing0Helper
# ============================================================================

class WinRing0Helper(Helper):

    def __init__(self):
        super(WinRing0Helper, self).__init__()

        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.name = 'WinRing0Helper'
        self.driverpath = ''

        self.driver_handle = None
        self.use_existing_service = False
        self._cpuid_fn = None
        self._cpuid_mem = None

        self._cf8_lock = threading.Lock()

        self._driver_search_paths = [
            os.path.dirname(os.path.abspath(__file__)),
            os.path.join(chipsec.library.file.get_main_dir(), 'chipsec', 'helper', 'winring0'),
        ]

        # Enable SeSystemEnvironmentPrivilege
        privilege = win32security.LookupPrivilegeValue(None, 'SeSystemEnvironmentPrivilege')
        token = win32security.OpenProcessToken(
            win32process.GetCurrentProcess(),
            win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES
        )
        win32security.AdjustTokenPrivileges(token, False, [(privilege, win32security.SE_PRIVILEGE_ENABLED)])
        win32api.CloseHandle(token)

        # Enable SeLoadDriverPrivilege
        try:
            privilege_ld = win32security.LookupPrivilegeValue(None, 'SeLoadDriverPrivilege')
            token_ld = win32security.OpenProcessToken(
                win32process.GetCurrentProcess(),
                win32security.TOKEN_READ | win32security.TOKEN_ADJUST_PRIVILEGES
            )
            win32security.AdjustTokenPrivileges(token_ld, False, [(privilege_ld, win32security.SE_PRIVILEGE_ENABLED)])
            win32api.CloseHandle(token_ld)
        except Exception:
            logger().log_debug('[winring0] Could not enable SeLoadDriverPrivilege')

        # Windows API function references for EFI/ACPI
        self.GetFirmwareEnvironmentVariable = None
        self.SetFirmwareEnvironmentVariable = None
        self.GetFirmwareEnvironmentVariableEx = None
        self.SetFirmwareEnvironmentVariableEx = None
        self.NtEnumerateSystemEnvironmentValuesEx = None
        self.GetSystemFirmwareTbl = None
        self.EnumSystemFirmwareTbls = None
        self.NtQuerySystemInformation = None

        try:
            self.GetFirmwareEnvironmentVariable = kernel32.GetFirmwareEnvironmentVariableW
            self.GetFirmwareEnvironmentVariable.restype = c_int
            self.GetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
            self.SetFirmwareEnvironmentVariable = kernel32.SetFirmwareEnvironmentVariableW
            self.SetFirmwareEnvironmentVariable.restype = c_int
            self.SetFirmwareEnvironmentVariable.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int]
        except AttributeError:
            logger().log_debug('[winring0] GetFirmwareEnvironmentVariableW not available')

        try:
            c_int_p = POINTER(c_int)
            self.GetFirmwareEnvironmentVariableEx = kernel32.GetFirmwareEnvironmentVariableExW
            self.GetFirmwareEnvironmentVariableEx.restype = c_int
            self.GetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int_p]
            self.SetFirmwareEnvironmentVariableEx = kernel32.SetFirmwareEnvironmentVariableExW
            self.SetFirmwareEnvironmentVariableEx.restype = c_int
            self.SetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int]
        except AttributeError:
            logger().log_debug('[winring0] GetFirmwareEnvironmentVariableExW not available')

        try:
            self.NtEnumerateSystemEnvironmentValuesEx = windll.ntdll.NtEnumerateSystemEnvironmentValuesEx
            self.NtEnumerateSystemEnvironmentValuesEx.restype = c_int
            self.NtEnumerateSystemEnvironmentValuesEx.argtypes = [c_int, c_void_p, c_void_p]
        except AttributeError:
            logger().log_debug('[winring0] NtEnumerateSystemEnvironmentValuesEx not available')

        try:
            self.GetSystemFirmwareTbl = kernel32.GetSystemFirmwareTable
            self.GetSystemFirmwareTbl.restype = c_int
            self.GetSystemFirmwareTbl.argtypes = [c_int, c_int, c_void_p, c_int]
        except AttributeError:
            logger().log_debug('[winring0] GetSystemFirmwareTable not available')

        try:
            self.EnumSystemFirmwareTbls = kernel32.EnumSystemFirmwareTables
            self.EnumSystemFirmwareTbls.restype = c_int
            self.EnumSystemFirmwareTbls.argtypes = [c_int, c_void_p, c_int]
        except AttributeError:
            logger().log_debug('[winring0] EnumSystemFirmwareTables not available')

        try:
            c_uint32_p = POINTER(c_uint32)
            self.NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
            self.NtQuerySystemInformation.restype = c_int
            self.NtQuerySystemInformation.argtypes = [c_uint32, c_void_p, c_uint32, c_uint32_p]
        except AttributeError:
            logger().log_debug('[winring0] NtQuerySystemInformation not available')

        # Set up thread affinity functions for per-CPU MSR access
        kernel32.SetThreadAffinityMask.restype = c_size_t
        kernel32.SetThreadAffinityMask.argtypes = [c_void_p, c_size_t]
        kernel32.GetCurrentThread.restype = c_void_p
        kernel32.GetCurrentThread.argtypes = []

        # Set up CPUID native function
        self._init_cpuid()

    def __del__(self):
        if self.driver_handle is not None and self.driver_handle != INVALID_HANDLE_VALUE:
            try:
                win32api.CloseHandle(self.driver_handle)
            except Exception:
                pass
            self.driver_handle = None
        if self._cpuid_mem is not None:
            try:
                kernel32.VirtualFree(self._cpuid_mem, 0, MEM_RELEASE)
            except Exception:
                pass
            self._cpuid_mem = None

    def _init_cpuid(self) -> None:
        kernel32.VirtualAlloc.restype = c_void_p
        kernel32.VirtualAlloc.argtypes = [c_void_p, c_size_t, c_ulong, c_ulong]
        kernel32.VirtualFree.restype = c_int
        kernel32.VirtualFree.argtypes = [c_void_p, c_size_t, c_ulong]

        self._cpuid_mem = kernel32.VirtualAlloc(
            None, len(_CPUID_CODE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
        )
        if not self._cpuid_mem:
            logger().log_debug('[winring0] Failed to allocate executable memory for CPUID')
            return

        ctypes.memmove(self._cpuid_mem, _CPUID_CODE, len(_CPUID_CODE))
        self._cpuid_fn = _CpuidFuncType(self._cpuid_mem)

    # =========================================================================
    # Device handle management
    # =========================================================================

    def _open_device(self) -> 'PyHANDLE':
        if self.driver_handle is not None and self.driver_handle != INVALID_HANDLE_VALUE:
            return self.driver_handle

        self.driver_handle = win32file.CreateFile(
            DEVICE_FILE,
            GENERIC_READ | GENERIC_WRITE,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            None
        )
        if self.driver_handle is None or self.driver_handle == INVALID_HANDLE_VALUE:
            _handle_error(
                f'Cannot open WinRing0 device {DEVICE_FILE}. '
                'Make sure the driver is installed and started.',
                errno.ENXIO
            )
        logger().log_debug(
            f'[winring0] Opened device {DEVICE_FILE} (handle: {int(self.driver_handle):08X})'
        )
        return self.driver_handle

    def _ioctl(self, ioctl_code: int, in_buf: bytes, out_length: int) -> bytes:
        if not self.driver_loaded:
            _handle_error('WinRing0 driver is not loaded')

        self._open_device()
        try:
            out_buf = win32file.DeviceIoControl(
                self.driver_handle, ioctl_code, in_buf, out_length, None
            )
        except pywintypes.error as _err:
            err_status = _err.args[0] + 0x100000000
            if STATUS_PRIVILEGED_INSTRUCTION == err_status:
                err_msg = (
                    f'HW Access Violation: DeviceIoControl returned '
                    f'STATUS_PRIVILEGED_INSTRUCTION (0x{err_status:X})'
                )
                if logger().DEBUG:
                    logger().log_error(err_msg)
                raise HWAccessViolationError(err_msg, err_status)
            else:
                _handle_error(
                    f'HW Access Error: DeviceIoControl returned status '
                    f'0x{err_status:X} ({_err.args[2]})',
                    err_status
                )
        return out_buf

    # =========================================================================
    # Driver / service management via Windows SCM
    # =========================================================================

    def _find_driver(self) -> Optional[str]:
        for search_dir in self._driver_search_paths:
            driver_path = os.path.join(search_dir, DRIVER_FILE_NAME)
            if os.path.isfile(driver_path):
                return driver_path
        return None

    def show_warning(self) -> None:
        logger().log('')
        logger().log_warning('*******************************************************************')
        logger().log_warning('Chipsec should only be used on test systems!')
        logger().log_warning('It should not be installed/deployed on production end-user systems.')
        logger().log_warning('See WARNING.txt')
        logger().log_warning('*******************************************************************')
        logger().log('')

    def create(self) -> bool:
        self.driver_path = self._find_driver()
        if self.driver_path is None:
            raise OsHelperError(
                f'WinRing0 driver ({DRIVER_FILE_NAME}) not found. '
                f'Searched: {", ".join(self._driver_search_paths)}',
                errno.ENOENT
            )

        self.show_warning()
        logger().log_debug(f'[winring0] Found driver at {self.driver_path}')

        try:
            hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        except win32service.error as err:
            _handle_winerror(err.args[1], err.args[2], err.args[0])

        logger().log_debug(f'[winring0] Service control manager opened (handle = {hscm})')
        logger().log_debug(f'[winring0] Driver path: {os.path.abspath(self.driver_path)}')

        hs = None
        try:
            hs = win32service.CreateService(
                hscm,
                SERVICE_NAME,
                DISPLAY_NAME,
                (win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START |
                 win32service.SERVICE_STOP),
                win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START,
                win32service.SERVICE_ERROR_NORMAL,
                os.path.abspath(self.driver_path),
                None, 0, u'', None, None
            )
            if hs:
                logger().log_debug(
                    f'[winring0] Service \'{SERVICE_NAME}\' created (handle = 0x{int(hs):08X})'
                )
        except win32service.error as err:
            if winerror.ERROR_SERVICE_EXISTS == err.args[0]:
                logger().log_debug(
                    f'[winring0] Service \'{SERVICE_NAME}\' already exists: '
                    f'{err.args[2]} ({err.args[0]:d})'
                )
                try:
                    hs = win32service.OpenService(
                        hscm, SERVICE_NAME,
                        (win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_START |
                         win32service.SERVICE_STOP)
                    )
                except win32service.error as _err:
                    _handle_winerror(_err.args[1], _err.args[2], _err.args[0])
            else:
                _handle_winerror(err.args[1], err.args[2], err.args[0])
        finally:
            if hs:
                win32service.CloseServiceHandle(hs)
            win32service.CloseServiceHandle(hscm)

        return True

    def start(self) -> bool:
        self.use_existing_service = (
            win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] == win32service.SERVICE_RUNNING
        )

        if self.use_existing_service:
            self.driver_loaded = True
            logger().log_debug(f'[winring0] Service \'{SERVICE_NAME}\' already running')
        else:
            try:
                win32serviceutil.StartService(SERVICE_NAME)
                win32serviceutil.WaitForServiceStatus(
                    SERVICE_NAME, win32service.SERVICE_RUNNING, 1
                )
                self.driver_loaded = True
                logger().log_debug(f'[winring0] Service \'{SERVICE_NAME}\' started')
            except pywintypes.error as err:
                _handle_error(
                    f'Service \'{SERVICE_NAME}\' did not start: '
                    f'{err.args[2]} ({err.args[0]:d})',
                    err.args[0]
                )

        self.driverpath = os.path.abspath(self._find_driver() or '')

        # Open the device handle
        self._open_device()

        # Query driver version
        try:
            out_buf = self._ioctl(IOCTL_OLS_GET_DRIVER_VERSION, b'', 4)
            if len(out_buf) >= 4:
                version = struct.unpack('<I', out_buf[:4])[0]
                major = (version >> 8) & 0xFF
                minor = version & 0xFF
                logger().log_debug(f'[winring0] Driver version: {major}.{minor}')
        except Exception:
            logger().log_debug('[winring0] Could not query driver version')

        return True

    def stop(self) -> bool:
        if self.driver_handle is not None and self.driver_handle != INVALID_HANDLE_VALUE:
            try:
                win32api.CloseHandle(self.driver_handle)
            except Exception:
                pass
            self.driver_handle = None

        if self.use_existing_service:
            self.driver_loaded = False
            return True

        logger().log_debug(f'[winring0] Stopping service \'{SERVICE_NAME}\'...')
        try:
            win32serviceutil.StopService(SERVICE_NAME)
        except pywintypes.error as err:
            if logger().DEBUG:
                logger().log_error(f'StopService failed: {err.args[2]} ({err.args[0]:d})')
            return False
        finally:
            self.driver_loaded = False

        try:
            win32serviceutil.WaitForServiceStatus(
                SERVICE_NAME, win32service.SERVICE_STOPPED, 1
            )
            logger().log_debug(f'[winring0] Service \'{SERVICE_NAME}\' stopped')
        except pywintypes.error as err:
            if logger().DEBUG:
                logger().log_warning(
                    f'Service \'{SERVICE_NAME}\' did not stop: '
                    f'{err.args[2]} ({err.args[0]:d})'
                )
            return False

        return True

    def delete(self) -> bool:
        if self.use_existing_service:
            return True

        if win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1] != win32service.SERVICE_STOPPED:
            logger().log_warning(f'Cannot delete service \'{SERVICE_NAME}\' (not stopped)')
            return False

        logger().log_debug(f'[winring0] Deleting service \'{SERVICE_NAME}\'...')
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
            logger().log_debug(f'[winring0] Service \'{SERVICE_NAME}\' deleted')
        except win32service.error as err:
            if logger().DEBUG:
                logger().log_warning(f'RemoveService failed: {err.args[2]} ({err.args[0]:d})')
            return False

        return True

    def get_info(self) -> Tuple[str, str]:
        return self.name, self.driverpath

    def get_threads_count(self) -> int:
        proc_group_count = kernel32.GetActiveProcessorGroupCount() & 0xFFFF
        total = 0
        for grp in range(proc_group_count):
            total += kernel32.GetActiveProcessorCount(grp)
        return total

    # =========================================================================
    # MSR (with per-thread affinity)
    # =========================================================================

    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        thread_handle = kernel32.GetCurrentThread()
        old_affinity = kernel32.SetThreadAffinityMask(thread_handle, 1 << cpu_thread_id)
        if old_affinity == 0:
            raise HWAccessViolationError(
                f'SetThreadAffinityMask failed for thread {cpu_thread_id}', 0
            )
        try:
            in_buf = struct.pack('<I', msr_addr)
            out_buf = self._ioctl(IOCTL_OLS_READ_MSR, in_buf, 8)
            eax, edx = struct.unpack('<II', out_buf[:8])
            return (eax, edx)
        finally:
            kernel32.SetThreadAffinityMask(thread_handle, old_affinity)

    def write_msr(self, cpu_thread_id: int, msr_addr: int, eax: int, edx: int) -> int:
        thread_handle = kernel32.GetCurrentThread()
        old_affinity = kernel32.SetThreadAffinityMask(thread_handle, 1 << cpu_thread_id)
        if old_affinity == 0:
            raise HWAccessViolationError(
                f'SetThreadAffinityMask failed for thread {cpu_thread_id}', 0
            )
        try:
            in_buf = struct.pack('<III', msr_addr, eax, edx)
            self._ioctl(IOCTL_OLS_WRITE_MSR, in_buf, 0)
            return True
        finally:
            kernel32.SetThreadAffinityMask(thread_handle, old_affinity)

    # =========================================================================
    # CPUID (via native x86-64 shellcode — supports ECX sub-leaf)
    # =========================================================================

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        if self._cpuid_fn is None:
            raise UnimplementedAPIError('cpuid')
        output = (c_uint32 * 4)()
        self._cpuid_fn(c_uint32(eax), c_uint32(ecx), output)
        return (output[0], output[1], output[2], output[3])

    # =========================================================================
    # I/O port access
    # =========================================================================

    def read_io_port(self, io_port: int, size: int) -> int:
        in_buf = struct.pack('<I', io_port)
        if size == 1:
            out_buf = self._ioctl(IOCTL_OLS_READ_IO_PORT_BYTE, in_buf, 4)
        elif size == 2:
            out_buf = self._ioctl(IOCTL_OLS_READ_IO_PORT_WORD, in_buf, 4)
        elif size == 4:
            out_buf = self._ioctl(IOCTL_OLS_READ_IO_PORT_DWORD, in_buf, 4)
        else:
            raise OsHelperError(f'Unsupported I/O port read size: {size}', 0)
        value = struct.unpack('<I', out_buf[:4])[0]
        if size == 1:
            return value & 0xFF
        elif size == 2:
            return value & 0xFFFF
        return value

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        in_buf = struct.pack('<II', io_port, value)
        if size == 1:
            self._ioctl(IOCTL_OLS_WRITE_IO_PORT_BYTE, in_buf, 0)
        elif size == 2:
            self._ioctl(IOCTL_OLS_WRITE_IO_PORT_WORD, in_buf, 0)
        elif size == 4:
            self._ioctl(IOCTL_OLS_WRITE_IO_PORT_DWORD, in_buf, 0)
        else:
            raise OsHelperError(f'Unsupported I/O port write size: {size}', 0)
        return True

    # =========================================================================
    # PCI configuration space (via CF8/CFC I/O ports)
    #
    # CF8/CFC access is inherently non-atomic: the address write (CF8) and
    # data read/write (CFC) are two separate I/O port operations.  Another
    # thread, process, or kernel driver touching CF8 between them will
    # redirect the CFC access to the wrong device/register.  _cf8_lock
    # serializes within this process; cross-process races remain possible.
    # =========================================================================

    def _check_pci_cfg_args(self, address: int, size: int) -> None:
        if address >= 0x100:
            raise OsHelperError(
                f'PCI extended config space (offset 0x{address:X}) not supported via CF8/CFC', 0
            )
        if size not in (1, 2, 4):
            raise OsHelperError(f'Unsupported PCI config access size: {size}', 0)
        if address & (size - 1):
            raise OsHelperError(
                f'Misaligned PCI config access: offset 0x{address:X} size {size}', 0
            )

    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        self._check_pci_cfg_args(address, size)
        cf8 = (1 << 31) | ((bus & 0xFF) << 16) | ((device & 0x1F) << 11) | \
              ((function & 0x07) << 8) | (address & 0xFC)
        byte_offset = address & 3
        with self._cf8_lock:
            self.write_io_port(0xCF8, cf8, 4)
            value = self.read_io_port(0xCFC, 4)
        if size == 1:
            return (value >> (byte_offset * 8)) & 0xFF
        elif size == 2:
            return (value >> (byte_offset * 8)) & 0xFFFF
        return value

    def write_pci_reg(self, bus: int, device: int, function: int, address: int, value: int, size: int) -> int:
        self._check_pci_cfg_args(address, size)
        cf8 = (1 << 31) | ((bus & 0xFF) << 16) | ((device & 0x1F) << 11) | \
              ((function & 0x07) << 8) | (address & 0xFC)
        byte_offset = address & 3
        with self._cf8_lock:
            self.write_io_port(0xCF8, cf8, 4)
            if size == 1:
                self.write_io_port(0xCFC + byte_offset, value & 0xFF, 1)
            elif size == 2:
                self.write_io_port(0xCFC + byte_offset, value & 0xFFFF, 2)
            else:
                self.write_io_port(0xCFC, value & 0xFFFFFFFF, 4)
        return True

    # =========================================================================
    # Physical memory
    # =========================================================================

    _PHYS_ADDR_MAX = (1 << 46) - 1   # 64 TB — covers current x86-64 implementations
    _PHYS_LEN_MAX = 4 * 1024 * 1024  # 4 MB per operation

    def _check_phys_args(self, phys_address: int, length: int) -> None:
        if length <= 0 or length > self._PHYS_LEN_MAX:
            raise OsHelperError(
                f'Physical memory length out of range: 0x{length:X}', 0)
        if phys_address < 0 or phys_address > self._PHYS_ADDR_MAX:
            raise OsHelperError(
                f'Physical address out of range: 0x{phys_address:X}', 0)
        if phys_address + length - 1 > self._PHYS_ADDR_MAX:
            raise OsHelperError(
                f'Physical memory access exceeds address space: '
                f'0x{phys_address:X}+0x{length:X}', 0)

    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        self._check_phys_args(phys_address, length)
        in_buf = struct.pack('<QII', phys_address, 1, length)
        out_buf = self._ioctl(IOCTL_OLS_READ_MEMORY, in_buf, length)
        return bytes(out_buf[:length])

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        self._check_phys_args(phys_address, length)
        in_buf = struct.pack('<QII', phys_address, 1, length) + buf[:length]
        self._ioctl(IOCTL_OLS_WRITE_MEMORY, in_buf, 0)
        return length

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        self._check_phys_args(phys_address, size)
        data = self.read_phys_mem(phys_address, size)
        if size == 8:
            return struct.unpack('<Q', data)[0]
        elif size == 4:
            return struct.unpack('<I', data)[0]
        elif size == 2:
            return struct.unpack('<H', data)[0]
        elif size == 1:
            return struct.unpack('<B', data)[0]
        return 0

    def write_mmio_reg(self, phys_address: int, size: int, value: int) -> int:
        self._check_phys_args(phys_address, size)
        if size == 8:
            buf = struct.pack('<Q', value)
        elif size == 4:
            buf = struct.pack('<I', value & 0xFFFFFFFF)
        elif size == 2:
            buf = struct.pack('<H', value & 0xFFFF)
        elif size == 1:
            buf = struct.pack('<B', value & 0xFF)
        else:
            raise OsHelperError(f'Unsupported MMIO write size: {size}', 0)
        return self.write_phys_mem(phys_address, size, buf)

    # =========================================================================
    # Operations NOT supported by WinRing0
    # =========================================================================

    def alloc_phys_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        raise UnimplementedAPIError('alloc_phys_mem')

    def free_phys_mem(self, phys_address: int):
        raise UnimplementedAPIError('free_phys_mem')

    def va2pa(self, va: int) -> Tuple[int, int]:
        raise UnimplementedAPIError('va2pa')

    def map_io_space(self, phys_address: int, size: int, cache_type: int) -> int:
        raise UnimplementedAPIError('map_io_space')

    def read_cr(self, cpu_thread_id: int, cr_number: int) -> int:
        raise UnimplementedAPIError('read_cr')

    def write_cr(self, cpu_thread_id: int, cr_number: int, value: int) -> int:
        raise UnimplementedAPIError('write_cr')

    def load_ucode_update(self, cpu_thread_id: int, ucode_update_buf: bytes) -> bool:
        raise UnimplementedAPIError('load_ucode_update')

    def get_descriptor_table(self, cpu_thread_id: int, desc_table_code: int) -> Optional[Tuple[int, int, int]]:
        raise UnimplementedAPIError('get_descriptor_table')

    def send_sw_smi(self, cpu_thread_id: int, SMI_code_data: int, _rax: int, _rbx: int, _rcx: int, _rdx: int, _rsi: int, _rdi: int) -> Optional[int]:
        raise UnimplementedAPIError('send_sw_smi')

    def hypercall(self, rcx: int, rdx: int, r8: int, r9: int, r10: int, r11: int, rax: int, rbx: int, rdi: int, rsi: int, xmm_buffer: int) -> int:
        raise UnimplementedAPIError('hypercall')

    def msgbus_send_read_message(self, mcr: int, mcrx: int) -> Optional[int]:
        raise UnimplementedAPIError('msgbus_send_read_message')

    def msgbus_send_write_message(self, mcr: int, mcrx: int, mdr: int) -> None:
        raise UnimplementedAPIError('msgbus_send_write_message')

    def msgbus_send_message(self, mcr: int, mcrx: int, mdr: Optional[int]) -> Optional[int]:
        raise UnimplementedAPIError('msgbus_send_message')

    # =========================================================================
    # EFI variables (via Windows API)
    # =========================================================================

    def EFI_supported(self) -> bool:
        if self.GetFirmwareEnvironmentVariable is not None:
            self.GetFirmwareEnvironmentVariable(
                '', '{00000000-0000-0000-0000-000000000000}', 0, 0
            )
            return windll.kernel32.GetLastError() != 1
        elif self.GetFirmwareEnvironmentVariableEx is not None:
            self.GetFirmwareEnvironmentVariableEx(
                '', '{00000000-0000-0000-0000-000000000000}', 0, 0
            )
            return windll.kernel32.GetLastError() != 1
        return False

    def get_EFI_variable(self, name: str, guid: str, attrs: Optional[int] = None) -> Optional[bytes]:
        efi_var = create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
        length = 0
        if attrs is None:
            if self.GetFirmwareEnvironmentVariable is not None:
                length = self.GetFirmwareEnvironmentVariable(
                    name, f'{{{guid}}}', efi_var, EFI_VAR_MAX_BUFFER_SIZE
                )
        else:
            if self.GetFirmwareEnvironmentVariableEx is not None:
                pattrs = c_int(attrs)
                length = self.GetFirmwareEnvironmentVariableEx(
                    name, f'{{{guid}}}', efi_var, EFI_VAR_MAX_BUFFER_SIZE, pattrs
                )
        if length == 0 or efi_var is None:
            if logger().DEBUG:
                logger().log_error(f'GetFirmwareEnvironmentVariable failed: {WinError()}')
            return None
        return bytes(efi_var[:length])

    def set_EFI_variable(self, name: str, guid: str, buffer: bytes, buffer_size: Optional[int], attrs: Optional[int]) -> int:
        var = bytes(0) if buffer is None else buffer
        var_len = len(var) if buffer_size is None else buffer_size
        ntsts = 0
        if attrs is None:
            if self.SetFirmwareEnvironmentVariable is not None:
                ntsts = self.SetFirmwareEnvironmentVariable(name, f'{{{guid}}}', var, var_len)
        else:
            if self.SetFirmwareEnvironmentVariableEx is not None:
                ntsts = self.SetFirmwareEnvironmentVariableEx(
                    name, f'{{{guid}}}', var, var_len, attrs
                )
        if ntsts != 0:
            return 0
        status = windll.kernel32.GetLastError()
        if logger().DEBUG:
            logger().log_error(f'SetFirmwareEnvironmentVariable failed: {WinError()}')
        return status

    def delete_EFI_variable(self, name: str, guid: str) -> int:
        return self.set_EFI_variable(name, guid, None, buffer_size=0, attrs=None)

    def list_EFI_variables(self, infcls: int = 2) -> Optional[Dict[str, List['EfiVariableType']]]:
        if self.NtEnumerateSystemEnvironmentValuesEx is None:
            return None

        efi_vars = create_string_buffer(EFI_VAR_MAX_BUFFER_SIZE)
        length_bytes = struct.pack('<I', EFI_VAR_MAX_BUFFER_SIZE)
        length_buf = create_string_buffer(length_bytes, 4)

        status = self.NtEnumerateSystemEnvironmentValuesEx(infcls, efi_vars, length_buf)
        status = ((1 << 32) - 1) & status
        if status == 0xC0000023:
            retlength = struct.unpack('<I', bytes(length_buf))[0]
            efi_vars = create_string_buffer(retlength)
            status = self.NtEnumerateSystemEnvironmentValuesEx(infcls, efi_vars, length_buf)
            status = ((1 << 32) - 1) & status
        elif status == 0xC0000002:
            logger().log_debug(
                '[winring0] NtEnumerateSystemEnvironmentValuesEx not found '
                '(NTSTATUS = 0xC0000002)'
            )
            return None

        if status != 0:
            if logger().DEBUG:
                logger().log_error(
                    f'NtEnumerateSystemEnvironmentValuesEx failed '
                    f'(NTSTATUS=0x{status:08X})'
                )
            return None

        return _parse_efi_variables(bytes(efi_vars))

    # =========================================================================
    # ACPI (via Windows API)
    # =========================================================================

    def enum_ACPI_tables(self) -> Optional['Array']:
        if self.EnumSystemFirmwareTbls is None:
            raise UnimplementedAPIError('enum_ACPI_tables')
        table_size = 36
        tBuffer = create_string_buffer(table_size)
        retVal = self.EnumSystemFirmwareTbls(
            FirmwareTableProviderSignature_ACPI, tBuffer, table_size
        )
        if retVal == 0:
            if logger().DEBUG:
                logger().log_error(f'EnumSystemFirmwareTables failed: {WinError()}')
            return None
        if retVal > table_size:
            table_size = retVal
            tBuffer = create_string_buffer(table_size)
            retVal = self.EnumSystemFirmwareTbls(
                FirmwareTableProviderSignature_ACPI, tBuffer, table_size
            )
        return [tBuffer[i:i + 4] for i in range(0, retVal, 4)]

    def get_ACPI_table(self, table_name: str) -> Optional['Array']:
        if self.GetSystemFirmwareTbl is None:
            raise UnimplementedAPIError('get_ACPI_table')
        table_size = 36
        tBuffer = create_string_buffer(table_size)
        tbl = struct.unpack('<I', bytes(table_name, 'ascii'))[0]
        retVal = self.GetSystemFirmwareTbl(
            FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size
        )
        if retVal == 0:
            if logger().DEBUG:
                logger().log_error(
                    f'GetSystemFirmwareTable({table_name}) failed: {WinError()}'
                )
            return None
        if retVal > table_size:
            table_size = retVal
            tBuffer = create_string_buffer(table_size)
            retVal = self.GetSystemFirmwareTbl(
                FirmwareTableProviderSignature_ACPI, tbl, tBuffer, table_size
            )
        return tBuffer[:retVal]

    # =========================================================================
    # Affinity
    # =========================================================================

    def get_affinity(self) -> Optional[int]:
        pHandle = win32process.GetCurrentProcess()
        try:
            return win32process.GetProcessAffinityMask(pHandle)[0]
        except win32process.error as e:
            raise OsHelperError(f'Unable to get process affinity: {e}', 0)

    def set_affinity(self, value: int) -> Optional[int]:
        pHandle = win32process.GetCurrentProcess()
        current = win32process.GetProcessAffinityMask(pHandle)[0]
        try:
            win32process.SetProcessAffinityMask(pHandle, 1 << value)
        except win32process.error as e:
            raise OsHelperError(f'Unable to set process affinity: {e}', 0)
        return current

    # =========================================================================
    # Speculation control (via Windows API)
    # =========================================================================

    def retpoline_enabled(self) -> bool:
        if self.NtQuerySystemInformation is None:
            raise UnimplementedAPIError('retpoline_enabled')
        speculation_control = c_uint32(0)
        SystemSpeculationControlInformation = 0xC9
        SpecCtrlRetpolineEnabled = 0x4000
        self.NtQuerySystemInformation(
            SystemSpeculationControlInformation,
            addressof(speculation_control),
            sizeof(speculation_control),
            None
        )
        return bool(speculation_control.value & SpecCtrlRetpolineEnabled)


# ============================================================================
# EFI variable parsing
# ============================================================================

def _parse_efi_variables(buffer: bytes) -> Dict[str, list]:
    EFI_HDR = namedtuple('EFI_HDR', 'Size DataOffset DataSize Attributes guid')
    header_fmt = '<IIII16s'
    header_size = struct.calcsize(header_fmt)

    variables: Dict[str, list] = {}
    off = 0
    bsize = len(buffer)

    while (off + header_size) < bsize:
        hdr = EFI_HDR(*struct.unpack_from(header_fmt, buffer[off:off + header_size]))
        if hdr.Size == 0:
            break

        next_off = off + hdr.Size
        var_buf = buffer[off:next_off]
        var_data = buffer[off + hdr.DataOffset:off + hdr.DataOffset + hdr.DataSize]

        name_bytes = buffer[off + header_size:off + hdr.DataOffset]
        var_name = name_bytes.decode('utf-16-le', errors='replace').split('\x00')[0]

        if var_name not in variables:
            variables[var_name] = []
        variables[var_name].append(
            (off, var_buf, hdr, var_data, EFI_GUID_STR(hdr.guid), hdr.Attributes)
        )

        off = next_off

    return variables


def get_helper() -> WinRing0Helper:
    return WinRing0Helper()
