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
CHIPSEC helper using ASUS ATSZIO64.sys kernel driver for hardware access on Windows.

Communicates directly with the ATSZIO64.sys driver via DeviceIoControl IOCTLs.

Supported operations:
    - MSR read/write (with per-thread affinity)
    - CPUID (via native shellcode)
    - I/O port read/write (byte, word, dword)
    - PCI configuration space read/write (via HalGet/SetBusDataByOffset)
    - Physical memory read/write (via map/unmap of physical memory sections)
    - MMIO via physical memory access
    - Contiguous physical memory alloc/free
    - EFI variables (via Windows API)
    - ACPI tables (via Windows API)
"""

import ctypes
import errno
import os
import platform
import struct
import sys

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

DRIVER_FILE_NAME = 'ATSZIO64.sys'
SERVICE_NAME = 'ATSZIO'
DISPLAY_NAME = 'CHIPSEC ATSZIO Helper'
DEVICE_FILE = '\\\\.\\ATSZIO'

# ============================================================================
# ATSZIO IOCTL codes
# Device type 0x8807, FILE_ANY_ACCESS (0), METHOD_BUFFERED (0)
# CTL_CODE = (0x8807 << 16) | (Function << 2)
# ============================================================================

_ATSZIO_TYPE = 0x8807


def _CTL_CODE(function: int) -> int:
    return (_ATSZIO_TYPE << 16) | (function << 2)


# Low-range IOCTLs (jump table dispatch)
IOCTL_PCI_CF8_READ = _CTL_CODE(0x3D6)        # 0x88070F58
IOCTL_PCI_CF8_WRITE = _CTL_CODE(0x3D7)       # 0x88070F5C
IOCTL_IO_PORT_READ = _CTL_CODE(0x3D8)        # 0x88070F60
IOCTL_IO_PORT_WRITE = _CTL_CODE(0x3D9)       # 0x88070F64
IOCTL_INDEXED_IO_READ = _CTL_CODE(0x3DA)     # 0x88070F68
IOCTL_INDEXED_IO_WRITE = _CTL_CODE(0x3DB)    # 0x88070F6C
IOCTL_BATCH_PCI_READ = _CTL_CODE(0x3DC)      # 0x88070F70
IOCTL_BATCH_IO_READ = _CTL_CODE(0x3DD)       # 0x88070F74
IOCTL_BATCH_INDEXED_READ = _CTL_CODE(0x3DE)  # 0x88070F78
IOCTL_PHYS_MEM_READ = _CTL_CODE(0x3DF)       # 0x88070F7C
IOCTL_PHYS_MEM_WRITE = _CTL_CODE(0x3E0)      # 0x88070F80
IOCTL_PHYS_MEM_READ_PAGE = _CTL_CODE(0x3E1)  # 0x88070F84
IOCTL_MSR_READ = _CTL_CODE(0x3E2)            # 0x88070F88
IOCTL_MSR_WRITE = _CTL_CODE(0x3E3)           # 0x88070F8C
IOCTL_ALLOC_CONTIGUOUS = _CTL_CODE(0x3E4)    # 0x88070F90
IOCTL_FREE_CONTIGUOUS = _CTL_CODE(0x3E5)     # 0x88070F94

# High-range IOCTLs (explicit CMP dispatch)
IOCTL_HAL_PCI_READ = _CTL_CODE(0x800)        # 0x88072000
IOCTL_HAL_PCI_WRITE = _CTL_CODE(0x801)       # 0x88072004
IOCTL_MAP_PHYS_MEM = _CTL_CODE(0x803)        # 0x8807200C
IOCTL_UNMAP_PHYS_MEM = _CTL_CODE(0x804)      # 0x88072010
IOCTL_IO_PORT_WRITE_V2 = _CTL_CODE(0x805)    # 0x88072014
IOCTL_IO_PORT_READ_V2 = _CTL_CODE(0x806)     # 0x88072018

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

PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE - 1)

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
# ATSZIOHelper
# ============================================================================

class ATSZIOHelper(Helper):

    def __init__(self):
        super(ATSZIOHelper, self).__init__()

        self.os_system = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.os_machine = platform.machine()
        self.name = 'ATSZIOHelper'
        self.driverpath = ''

        self.driver_handle = None
        self.use_existing_service = False
        self._cpuid_fn = None
        self._cpuid_mem = None

        self._driver_search_paths = [
            os.path.dirname(os.path.abspath(__file__)),
            os.path.join(chipsec.library.file.get_main_dir(), 'chipsec', 'helper', 'atszio'),
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
            logger().log_debug('[atszio] Could not enable SeLoadDriverPrivilege')

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
            logger().log_debug('[atszio] GetFirmwareEnvironmentVariableW not available')

        try:
            c_int_p = POINTER(c_int)
            self.GetFirmwareEnvironmentVariableEx = kernel32.GetFirmwareEnvironmentVariableExW
            self.GetFirmwareEnvironmentVariableEx.restype = c_int
            self.GetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int_p]
            self.SetFirmwareEnvironmentVariableEx = kernel32.SetFirmwareEnvironmentVariableExW
            self.SetFirmwareEnvironmentVariableEx.restype = c_int
            self.SetFirmwareEnvironmentVariableEx.argtypes = [c_wchar_p, c_wchar_p, c_void_p, c_int, c_int]
        except AttributeError:
            logger().log_debug('[atszio] GetFirmwareEnvironmentVariableExW not available')

        try:
            self.NtEnumerateSystemEnvironmentValuesEx = windll.ntdll.NtEnumerateSystemEnvironmentValuesEx
            self.NtEnumerateSystemEnvironmentValuesEx.restype = c_int
            self.NtEnumerateSystemEnvironmentValuesEx.argtypes = [c_int, c_void_p, c_void_p]
        except AttributeError:
            logger().log_debug('[atszio] NtEnumerateSystemEnvironmentValuesEx not available')

        try:
            self.GetSystemFirmwareTbl = kernel32.GetSystemFirmwareTable
            self.GetSystemFirmwareTbl.restype = c_int
            self.GetSystemFirmwareTbl.argtypes = [c_int, c_int, c_void_p, c_int]
        except AttributeError:
            logger().log_debug('[atszio] GetSystemFirmwareTable not available')

        try:
            self.EnumSystemFirmwareTbls = kernel32.EnumSystemFirmwareTables
            self.EnumSystemFirmwareTbls.restype = c_int
            self.EnumSystemFirmwareTbls.argtypes = [c_int, c_void_p, c_int]
        except AttributeError:
            logger().log_debug('[atszio] EnumSystemFirmwareTables not available')

        try:
            c_uint32_p = POINTER(c_uint32)
            self.NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
            self.NtQuerySystemInformation.restype = c_int
            self.NtQuerySystemInformation.argtypes = [c_uint32, c_void_p, c_uint32, c_uint32_p]
        except AttributeError:
            logger().log_debug('[atszio] NtQuerySystemInformation not available')

        # Thread affinity for per-CPU MSR access
        kernel32.SetThreadAffinityMask.restype = c_size_t
        kernel32.SetThreadAffinityMask.argtypes = [c_void_p, c_size_t]
        kernel32.GetCurrentThread.restype = c_void_p
        kernel32.GetCurrentThread.argtypes = []

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
            logger().log_debug('[atszio] Failed to allocate executable memory for CPUID')
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
                f'Cannot open ATSZIO device {DEVICE_FILE}. '
                'Make sure the driver is installed and started.',
                errno.ENXIO
            )
        logger().log_debug(
            f'[atszio] Opened device {DEVICE_FILE} (handle: {int(self.driver_handle):08X})'
        )
        return self.driver_handle

    def _ioctl(self, ioctl_code: int, in_buf: bytes, out_length: int) -> bytes:
        if not self.driver_loaded:
            _handle_error('ATSZIO driver is not loaded')

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
                f'ATSZIO driver ({DRIVER_FILE_NAME}) not found. '
                f'Searched: {", ".join(self._driver_search_paths)}',
                errno.ENOENT
            )

        self.show_warning()
        logger().log_debug(f'[atszio] Found driver at {self.driver_path}')

        try:
            hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
        except win32service.error as err:
            _handle_winerror(err.args[1], err.args[2], err.args[0])

        logger().log_debug(f'[atszio] Service control manager opened (handle = {hscm})')
        logger().log_debug(f'[atszio] Driver path: {os.path.abspath(self.driver_path)}')

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
                    f'[atszio] Service \'{SERVICE_NAME}\' created (handle = 0x{int(hs):08X})'
                )
        except win32service.error as err:
            if winerror.ERROR_SERVICE_EXISTS == err.args[0]:
                logger().log_debug(
                    f'[atszio] Service \'{SERVICE_NAME}\' already exists: '
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
            logger().log_debug(f'[atszio] Service \'{SERVICE_NAME}\' already running')
        else:
            try:
                win32serviceutil.StartService(SERVICE_NAME)
                win32serviceutil.WaitForServiceStatus(
                    SERVICE_NAME, win32service.SERVICE_RUNNING, 1
                )
                self.driver_loaded = True
                logger().log_debug(f'[atszio] Service \'{SERVICE_NAME}\' started')
            except pywintypes.error as err:
                _handle_error(
                    f'Service \'{SERVICE_NAME}\' did not start: '
                    f'{err.args[2]} ({err.args[0]:d})',
                    err.args[0]
                )

        self.driverpath = os.path.abspath(self._find_driver() or '')
        self._open_device()

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

        logger().log_debug(f'[atszio] Stopping service \'{SERVICE_NAME}\'...')
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
            logger().log_debug(f'[atszio] Service \'{SERVICE_NAME}\' stopped')
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

        logger().log_debug(f'[atszio] Deleting service \'{SERVICE_NAME}\'...')
        try:
            win32serviceutil.RemoveService(SERVICE_NAME)
            logger().log_debug(f'[atszio] Service \'{SERVICE_NAME}\' deleted')
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
    # Buffer: buf[0]=MSR reg (dword), buf[8]=64-bit value (qword)
    # =========================================================================

    def read_msr(self, cpu_thread_id: int, msr_addr: int) -> Tuple[int, int]:
        thread_handle = kernel32.GetCurrentThread()
        old_affinity = kernel32.SetThreadAffinityMask(thread_handle, 1 << cpu_thread_id)
        if old_affinity == 0:
            raise HWAccessViolationError(
                f'SetThreadAffinityMask failed for thread {cpu_thread_id}', 0
            )
        try:
            in_buf = struct.pack('<I4xQ', msr_addr, 0)
            out_buf = self._ioctl(IOCTL_MSR_READ, in_buf, 16)
            val = struct.unpack_from('<Q', out_buf, 8)[0]
            eax = val & 0xFFFFFFFF
            edx = (val >> 32) & 0xFFFFFFFF
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
            val = (edx << 32) | (eax & 0xFFFFFFFF)
            in_buf = struct.pack('<I4xQ', msr_addr, val)
            self._ioctl(IOCTL_MSR_WRITE, in_buf, 0)
            return True
        finally:
            kernel32.SetThreadAffinityMask(thread_handle, old_affinity)

    # =========================================================================
    # CPUID (via native x86-64 shellcode)
    # =========================================================================

    def cpuid(self, eax: int, ecx: int) -> Tuple[int, int, int, int]:
        if self._cpuid_fn is None:
            raise UnimplementedAPIError('cpuid')
        output = (c_uint32 * 4)()
        self._cpuid_fn(c_uint32(eax), c_uint32(ecx), output)
        return (output[0], output[1], output[2], output[3])

    # =========================================================================
    # I/O port access
    # Buffer: buf[0]=size (qword), buf[8]=port (word),
    #         result/value at buf[0x12](byte)/buf[0x10](word)/buf[0x0C](dword)
    # =========================================================================

    def read_io_port(self, io_port: int, size: int) -> int:
        in_buf = bytearray(0x14)
        struct.pack_into('<Q', in_buf, 0, size)
        struct.pack_into('<H', in_buf, 8, io_port & 0xFFFF)
        out_buf = self._ioctl(IOCTL_IO_PORT_READ, bytes(in_buf), 0x14)
        if size == 1:
            return struct.unpack_from('<B', out_buf, 0x12)[0]
        elif size == 2:
            return struct.unpack_from('<H', out_buf, 0x10)[0]
        elif size == 4:
            return struct.unpack_from('<I', out_buf, 0x0C)[0]
        else:
            raise OsHelperError(f'Unsupported I/O port read size: {size}', 0)

    def write_io_port(self, io_port: int, value: int, size: int) -> int:
        in_buf = bytearray(0x14)
        struct.pack_into('<Q', in_buf, 0, size)
        struct.pack_into('<H', in_buf, 8, io_port & 0xFFFF)
        if size == 1:
            struct.pack_into('<B', in_buf, 0x12, value & 0xFF)
        elif size == 2:
            struct.pack_into('<H', in_buf, 0x10, value & 0xFFFF)
        elif size == 4:
            struct.pack_into('<I', in_buf, 0x0C, value & 0xFFFFFFFF)
        else:
            raise OsHelperError(f'Unsupported I/O port write size: {size}', 0)
        self._ioctl(IOCTL_IO_PORT_WRITE, bytes(in_buf), 0)
        return True

    # =========================================================================
    # PCI configuration space (via HalGet/SetBusDataByOffset)
    # Buffer: buf[0]=length, buf[4]=reg_offset, buf[5]=(dev<<3)|func,
    #         buf[6]=bus, result/value at buf[0x12]/buf[0x10]/buf[0x0C]
    #
    # The offset field is a single byte, so only standard config space
    # (0x00-0xFF) is reachable.  Extended config space (>= 0x100) must
    # use MMCFG via read_mmio_reg / the MMCFG HAL layer.
    # =========================================================================

    def _check_pci_cfg_args(self, address: int, size: int) -> None:
        if address >= 0x100:
            raise OsHelperError(
                f'PCI extended config space (offset 0x{address:X}) not supported '
                f'via HalGetBusDataByOffset (use MMCFG)', 0
            )
        if size not in (1, 2, 4):
            raise OsHelperError(f'Unsupported PCI config access size: {size}', 0)
        if address & (size - 1):
            raise OsHelperError(
                f'Misaligned PCI config access: offset 0x{address:X} size {size}', 0
            )

    def read_pci_reg(self, bus: int, device: int, function: int, address: int, size: int) -> int:
        self._check_pci_cfg_args(address, size)
        in_buf = bytearray(0x14)
        struct.pack_into('<B', in_buf, 0, size)
        struct.pack_into('<B', in_buf, 4, address & 0xFF)
        struct.pack_into('<B', in_buf, 5, ((device & 0x1F) << 3) | (function & 0x07))
        struct.pack_into('<B', in_buf, 6, bus & 0xFF)
        out_buf = self._ioctl(IOCTL_HAL_PCI_READ, bytes(in_buf), 0x14)
        if size == 1:
            return struct.unpack_from('<B', out_buf, 0x12)[0]
        elif size == 2:
            return struct.unpack_from('<H', out_buf, 0x10)[0]
        return struct.unpack_from('<I', out_buf, 0x0C)[0]

    def write_pci_reg(self, bus: int, device: int, function: int, address: int, value: int, size: int) -> int:
        self._check_pci_cfg_args(address, size)
        in_buf = bytearray(0x14)
        struct.pack_into('<B', in_buf, 0, size)
        struct.pack_into('<B', in_buf, 4, address & 0xFF)
        struct.pack_into('<B', in_buf, 5, ((device & 0x1F) << 3) | (function & 0x07))
        struct.pack_into('<B', in_buf, 6, bus & 0xFF)
        if size == 1:
            struct.pack_into('<B', in_buf, 0x12, value & 0xFF)
        elif size == 2:
            struct.pack_into('<H', in_buf, 0x10, value & 0xFFFF)
        else:
            struct.pack_into('<I', in_buf, 0x0C, value & 0xFFFFFFFF)
        self._ioctl(IOCTL_HAL_PCI_WRITE, bytes(in_buf), 0)
        return True

    # =========================================================================
    # Physical memory access
    #
    # IOCTL_PHYS_MEM_READ (0x88070F7C) - kernel-mode read of 1/2/4 bytes
    #   Input:  buf[0]=size(1/2/4), buf[0x18]=phys_addr (QWORD, full addr w/ page offset)
    #   Output: buf[1]=byte, buf[2..3]=word, buf[4..7]=dword
    #
    # IOCTL_PHYS_MEM_WRITE (0x88070F80) - kernel-mode write of 1/2/4 bytes
    #   Input:  buf[0]=size(1/2/4), buf[0x18]=phys_addr (QWORD)
    #           buf[1]=byte, buf[2..3]=word, buf[4..7]=dword
    #
    # IOCTL_PHYS_MEM_READ_PAGE (0x88070F84) - kernel-mode read of 4K page
    #   Input (0x1028 bytes):  buf[0x18]=phys_addr (QWORD, page-aligned by driver)
    #   Output (0x1028 bytes): buf[0x28..0x1027]=4K page data
    #
    # The Map/Unmap IOCTLs (0x8807200C/0x88072010) map into KERNEL space,
    # so user-mode ctypes.memmove cannot access them. All physical memory
    # access must go through the read/write/page IOCTLs above.
    # =========================================================================

    _PHYS_ADDR_MAX = (1 << 46) - 1
    _PHYS_LEN_MAX = 4 * 1024 * 1024

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

    def _read_phys_small(self, phys_address: int, size: int) -> bytes:
        in_buf = bytearray(0x20)
        in_buf[0] = size
        struct.pack_into('<Q', in_buf, 0x18, phys_address)
        out_buf = self._ioctl(IOCTL_PHYS_MEM_READ, bytes(in_buf), 0x20)
        if size == 1:
            return bytes([out_buf[1]])
        elif size == 2:
            return out_buf[2:4]
        else:
            return out_buf[4:8]

    def _read_phys_page(self, phys_address: int) -> bytes:
        in_buf = bytearray(0x1028)
        struct.pack_into('<Q', in_buf, 0x18, phys_address)
        out_buf = self._ioctl(IOCTL_PHYS_MEM_READ_PAGE, bytes(in_buf), 0x1028)
        return out_buf[0x28:0x1028]

    def _write_phys_small(self, phys_address: int, size: int, data: bytes) -> None:
        in_buf = bytearray(0x20)
        in_buf[0] = size
        struct.pack_into('<Q', in_buf, 0x18, phys_address)
        if size == 1:
            in_buf[1] = data[0]
        elif size == 2:
            in_buf[2:4] = data[:2]
        else:
            in_buf[4:8] = data[:4]
        self._ioctl(IOCTL_PHYS_MEM_WRITE, bytes(in_buf), 0)

    def read_phys_mem(self, phys_address: int, length: int) -> bytes:
        self._check_phys_args(phys_address, length)

        result = bytearray()
        addr = phys_address
        remaining = length

        while remaining > 0:
            page_offset = addr & (PAGE_SIZE - 1)
            bytes_in_page = PAGE_SIZE - page_offset

            if remaining <= 4 and remaining in (1, 2, 4):
                result.extend(self._read_phys_small(addr, remaining))
                break

            if page_offset == 0 and remaining >= PAGE_SIZE:
                result.extend(self._read_phys_page(addr))
                addr += PAGE_SIZE
                remaining -= PAGE_SIZE
                continue

            if page_offset == 0 and remaining < PAGE_SIZE:
                page_data = self._read_phys_page(addr)
                result.extend(page_data[:remaining])
                break

            page_base = addr & PAGE_MASK
            page_data = self._read_phys_page(page_base)
            chunk = min(remaining, bytes_in_page)
            result.extend(page_data[page_offset:page_offset + chunk])
            addr += chunk
            remaining -= chunk

        return bytes(result)

    def write_phys_mem(self, phys_address: int, length: int, buf: bytes) -> int:
        self._check_phys_args(phys_address, length)

        offset = 0
        addr = phys_address
        remaining = length

        while remaining > 0:
            if remaining >= 4:
                write_size = 4
            elif remaining >= 2:
                write_size = 2
            else:
                write_size = 1

            self._write_phys_small(addr, write_size, buf[offset:offset + write_size])
            addr += write_size
            offset += write_size
            remaining -= write_size

        return length

    def read_mmio_reg(self, phys_address: int, size: int) -> int:
        self._check_phys_args(phys_address, size)
        if size in (1, 2, 4):
            data = self._read_phys_small(phys_address, size)
        elif size == 8:
            lo = self._read_phys_small(phys_address, 4)
            hi = self._read_phys_small(phys_address + 4, 4)
            data = lo + hi
        else:
            raise OsHelperError(f'Unsupported MMIO read size: {size}', 0)
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
            self._write_phys_small(phys_address, 4, struct.pack('<I', value & 0xFFFFFFFF))
            self._write_phys_small(phys_address + 4, 4, struct.pack('<I', (value >> 32) & 0xFFFFFFFF))
        elif size == 4:
            self._write_phys_small(phys_address, 4, struct.pack('<I', value & 0xFFFFFFFF))
        elif size == 2:
            self._write_phys_small(phys_address, 2, struct.pack('<H', value & 0xFFFF))
        elif size == 1:
            self._write_phys_small(phys_address, 1, struct.pack('<B', value & 0xFF))
        else:
            raise OsHelperError(f'Unsupported MMIO write size: {size}', 0)
        return size

    # =========================================================================
    # Contiguous physical memory alloc/free
    # =========================================================================

    def alloc_phys_mem(self, length: int, max_phys_address: int) -> Tuple[int, int]:
        in_buf = bytearray(0x20)
        struct.pack_into('<I', in_buf, 0x10, length)
        out_buf = self._ioctl(IOCTL_ALLOC_CONTIGUOUS, bytes(in_buf), 0x20)
        virt_addr = struct.unpack_from('<Q', out_buf, 0x00)[0]
        phys_addr = struct.unpack_from('<Q', out_buf, 0x08)[0]
        if virt_addr == 0:
            raise OsHelperError(f'Failed to allocate {length} bytes of contiguous memory', 0)
        return (virt_addr, phys_addr)

    def free_phys_mem(self, phys_address: int):
        in_buf = bytearray(0x10)
        struct.pack_into('<Q', in_buf, 0x00, phys_address)
        self._ioctl(IOCTL_FREE_CONTIGUOUS, bytes(in_buf), 0)

    def va2pa(self, va: int) -> Tuple[int, int]:
        raise UnimplementedAPIError('va2pa')

    def map_io_space(self, phys_address: int, size: int, cache_type: int) -> int:
        raise UnimplementedAPIError('map_io_space')

    # =========================================================================
    # Operations NOT supported by ATSZIO
    # =========================================================================

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
                '[atszio] NtEnumerateSystemEnvironmentValuesEx not found '
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


def get_helper() -> ATSZIOHelper:
    return ATSZIOHelper()
