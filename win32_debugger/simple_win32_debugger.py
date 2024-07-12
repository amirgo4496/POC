import sys
import os
import time
import ctypes
import msvcrt
import pefile
import struct
import hexdump

from dbglib import win32types
from dbglib import win32process
from dbglib import win32memory
from dbglib import win32debug
from dbglib import win32stack

# Globals for easy access to target information
target_process_handle = None
target_path = None
target_dlls = {}
target_threads = []
target_main_thread_id = None
target_image_base = None

exports = []
sw_break_points = {}
hw_break_points = []


events = {"CREATE_PROCESS_DEBUG_EVENT" : 3,
          "CREATE_THREAD_DEBUG_EVENT" : 2,
          "EXCEPTION_DEBUG_EVENT" : 1,
          "EXIT_PROCESS_DEBUG_EVENT" : 5,
          "EXIT_THREAD_DEBUG_EVENT" : 4,
          "LOAD_DLL_DEBUG_EVENT" : 6,
          "OUTPUT_DEBUG_STRING_EVENT" : 8,
          "RIP_EVENT" : 9,
          "UNLOAD_DLL_DEBUG_EVENT" :7}

commands = ["reg info" ,"stack trace" ,"continue" ,"sw break" ,"hw break","search import" ,"info dlls" ,"write mem" ,"search string"]

def SetHardwareBreakpoint(bp_address):
    global target_process_handle
    global target_main_thread_id
    global hw_break_points
    # ** This function only sets the breakpoint on the main thread (could be extended to all threads)
    # ** Only using DR0 (could be extended to use DR0 - DR3)

    thread_id = target_main_thread_id
    print(f"Set hw breakpoint on main thread {thread_id}")
    hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, thread_id)             
    context = win32process.GetThreadContext(hThread)
    # Set debug regsiter DR0 with address of breakpoint
    context.Dr0 = bp_address

    #############################
    # Bits 0, 2, 4, 6 corresponding to on/off for DR0, … , DR3. 
    # Additionally, bits 16-17, 20-21, 24-25, and 28-29 function as a bitmask for DR0, … , DR3 
    # for when these breakpoints will trigger, with 00 being on execution, 01 on read, and 11 on write
    #############################
    breakpoint_bitmask = 0b00000000000000000000000000000001
    context.Dr7 = context.Dr7 | breakpoint_bitmask
    set_context_status = win32process.SetThreadContext(hThread, context)
    win32process.CloseHandle(hThread)
    return set_context_status


def ReleaseHardwareBreakpoint():
    global target_process_handle
    global target_main_thread_id
    # Only removing a single execution breakpoint from DR0
    thread_id = target_main_thread_id
    hThread = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, thread_id)
    context = win32process.GetThreadContext(hThread)
    # Clear bp address from DR0
    context.Dr0 = 0
    # Setup DR7 bitmask inversion to clear DR0 breakpoint
    breakpoint_bitmask = 0b00000000000000000000000000000001
    breakpoint_bitmask_clear = (~breakpoint_bitmask) & 0xffffffff
    # Clear the bitmask in DR7 with an AND
    context.Dr7 = context.Dr7 & breakpoint_bitmask_clear
    set_context_status = win32process.SetThreadContext(hThread, context)
    win32process.CloseHandle(hThread)
    return set_context_status



def _WriteToMemory(addr_to_write ,bytes_to_write ,process_handle):
    # First parse the given input
    addr_to_write = int(addr_to_write.split('0x')[1] ,16)
    bytes_to_write = [int(b ,16).to_bytes(1 ,'little') for b in bytes_to_write.split('\\x')[1:]]
    bytes_to_write = b''.join(bytes_to_write)

    bytes_written = win32memory.write(process_handle, addr_to_write, bytes_to_write)
    return bytes_written

def _ImportSearch(name_to_search):
    global exports
    for exp in exports:
        if exp['name'] ==  bytes(name_to_search, 'ascii'):
            return exp['address']
    return None

def _StringSearch(str_to_search):
    global target_image_base
    global target_path
    target_pe = pefile.PE(target_path, fast_load=True)
    rdata_address = None
    rdata_size = None
    for section in target_pe.sections:
        if b'rdata' in section.Name:
            rdata_address = section.VirtualAddress + target_image_base
            rdata_size = section.Misc_VirtualSize

    if rdata_address is None:
        print(f"Cannot find rdata section in PE: {target_path}")
        # Because we handled the event return a status of DBG_CONTINUE
        return win32types.DBG_CONTINUE
    
    radata_data = win32memory.read(target_process_handle, rdata_address, rdata_size)
    # Search for the input string
    string_offset = radata_data.find(bytes(str_to_search, 'ascii'))
    if string_offset == -1:
        print(f"Cannot find 'Hello World' string")
        return None
    string_address = string_offset + rdata_address

    return string_address

def _ReleaseSoftwareBreakpoint(exception_address ,target_thread_handle):
    global sw_break_points
    byte_to_restore = sw_break_points[exception_address]
    bytes_written = win32memory.write(target_process_handle, exception_address, byte_to_restore)
    context = win32process.GetThreadContext(target_thread_handle)
    context.Eip = context.Eip - 1
    set_context_status = win32process.SetThreadContext(target_thread_handle, context)
    sw_break_points.pop(exception_address)
    


def HandleSoftwareBreakpoint(pEvent):
    global target_process_handle
    global target_path

    global sw_break_points
    print(f"\nEXCEPTION_BREAKPOINT") 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    exception_info  = pEvent.u.Exception.ExceptionRecord
    exception_address = exception_info.ExceptionAddress
    dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    global commands

    print(f"Breakpoint hit at {hex(exception_address)}")
    target_thread_handle = win32process.OpenThread(win32types.THREAD_ALL_ACCESS, False, target_thread_id)
    while True:
        command = input("Enter command:\n")
        if not command in commands:
            print("Not a valid command..")
            [print(c) for c in commands]
        elif command == "reg info":
            context = win32process.GetThreadContext(target_thread_handle)
            PrintRegInfo(context)
        elif command == "stack trace":
            PrintStackTrace(target_thread_handle)
        elif command == "sw break":
            break_address = int(input("Enter address for software breakpoint (format 0x<adress>):\n") ,16)
            sw_break_points[break_address] = SetSoftwareBreakpoint(target_process_handle ,break_address)
        elif command == "hw break":
            break_address = int(input("Enter address for hardware breakpoint (format 0x<adress>):\n") ,16)
            hw_break_points.append(break_address)
            SetHardwareBreakpoint(break_address)
        elif command == "info dlls":
            PrintInfoDll()
        elif command == "write mem":
            bytes_to_write = input("Enter bytes to write in the form of \\x...\n")
            addr_to_write = input("Enter address to write to in the form of 0x...\n")
            bytes_written = _WriteToMemory(addr_to_write ,bytes_to_write ,target_process_handle)
            print(f"\n Wrote {bytes_written} bytes")
        elif command == "search import":
            name_to_search =input("Enter import name to search:\n")
            if addr_found:=_ImportSearch(name_to_search):
                print("Found " + name_to_search + ": " + hex(addr_found))
            else:
                print("Couldnt find " + name_to_search)
        elif command == "search string":
            str_to_search =input("Enter string to search:\n")
            if addr_found:=_StringSearch(str_to_search):
                print("Found at: " , hex(addr_found))
            else:  
                print(f"Couldnt find \"{str_to_search}\"")
        elif command == "continue":
            if exception_address in sw_break_points:
                _ReleaseSoftwareBreakpoint(exception_address ,target_thread_handle)
                dwStatus = win32types.DBG_CONTINUE

                # if exception_address == nt_write_file:
                #     print("NtWriteFile entry hit!")
                #     print("ESP is: " ,hex(context.Esp))
                #     ebp = context.Ebp
                #     esp = context.Esp
                #     buffer_length = win32memory.read(target_process_handle, (ebp + 16), 4)
                #     buffer_addr = win32memory.read(target_process_handle, (ebp + 12), 4)
                #     print("Buffer size: ",hex(struct.unpack('<L', buffer_length)[0]))
                #     print("Buffer address: " ,hex(struct.unpack('<L', buffer_addr)[0]))
                #     buffer = win32memory.read(target_process_handle, struct.unpack('<L', buffer_addr)[0], struct.unpack('<L', buffer_length)[0])
                #     print("XXXXXXX " ,buffer)
            else:
                print(f"Deafult breakpoint")
                dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
            win32process.CloseHandle(target_thread_handle)
            break

    return dwStatus

def HandleHardwareBreakpoint(pEvent):
    global target_process_handle
    global hw_break_points
    print(f"\nEXCEPTION_SINGLE_STEP")
    # Get debug event info 
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    # The event also contains an EXCEPTION_RECORD struct
    exception_info  = pEvent.u.Exception.ExceptionRecord
    # Get address of breakpoint from exception
    exception_address = exception_info.ExceptionAddress
    # Check if exception is our hw breakpoint
    if exception_address in hw_break_points:
        # Notify the user that our hw breakpoint was hit
        print(f"Hardware breakpoint exection at {hex(exception_address)}")
        ReleaseHardwareBreakpoint()
        hw_break_points.remove(exception_address)
        dwStatus = win32types.DBG_CONTINUE
    else:
        # Alert the user that an exception was raised but
        # that it was not our hw breakpoint
        print(f"Exception single-step at {hex(exception_address)} - not our hw breakpoint!")
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED
    return dwStatus

def HandleEventExitThread(pEvent):
    global target_threads
    print(f"\nEXIT_THREAD_DEBUG_EVENT")
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    print(f"Thread ID: {target_thread_id}")
    target_threads.remove(target_thread_id)
    return win32types.DBG_CONTINUE

#This function sets a software breakpoint and returns the overwritten byte
def SetSoftwareBreakpoint(target_process_handle ,break_point_address):
    breakpoint_byte = win32memory.read(target_process_handle, break_point_address, 1)
    # Write the INT3 opcode 0xcc to the entry point
    bytes_written = win32memory.write(target_process_handle, break_point_address, b'\xcc')
    print(f"Wrote {bytes_written} bytes to {hex(break_point_address)}")
    return breakpoint_byte



def PrintStackTrace(target_thread_handle):
    global target_process_handle

    MAX_FRAMES = 16
    machine_type = win32types.IMAGE_FILE_MACHINE_I386
    target_thread_context = win32process.GetThreadContext(target_thread_handle)

    stack_frame = win32types.STACKFRAME64()
    stack_frame.AddrPC    = win32types.ADDRESS64(target_thread_context.Eip)
    stack_frame.AddrFrame = win32types.ADDRESS64(target_thread_context.Ebp)
    stack_frame.AddrStack = win32types.ADDRESS64(target_thread_context.Esp)

    print(f"\nStack trace")
    frame_count = 0
    while win32stack.StackWalk64(machine_type, target_process_handle, target_thread_handle, stack_frame, target_thread_context):
        print(f"\n\t Frame {frame_count}")
        print(f"\t PC address: {hex(stack_frame.AddrPC.Offset)}")
        print(f"\t Stack address: {hex(stack_frame.AddrStack.Offset)}")
        print(f"\t PFrame address: {hex(stack_frame.AddrFrame.Offset)}")

        if frame_count >= MAX_FRAMES:
            break
        else:
            frame_count += 1

def HandleEventCreateThread(pEvent):
    global target_threads
    print(f"\nCREATE_THREAD_DEBUG_EVENT")
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    print(f"Thread ID: {target_thread_id}")
    target_threads.append(target_thread_id)
    return win32types.DBG_CONTINUE

def PrintRegInfo(target_thread_context):
    print(f"\t Dr0: {hex(target_thread_context.Dr0)}")    
    print(f"\t Dr1: {hex(target_thread_context.Dr1)}")    
    print(f"\t Dr2: {hex(target_thread_context.Dr2)}")    
    print(f"\t Dr3: {hex(target_thread_context.Dr3)}")    
    print(f"\t Dr6: {hex(target_thread_context.Dr6)}")    
    print(f"\t Dr7: {hex(target_thread_context.Dr7)}")    
    print(f"\t Edi: {hex(target_thread_context.Edi)}")    
    print(f"\t Esi: {hex(target_thread_context.Esi)}")    
    print(f"\t Ebx: {hex(target_thread_context.Ebx)}")    
    print(f"\t Edx: {hex(target_thread_context.Edx)}")    
    print(f"\t Ecx: {hex(target_thread_context.Ecx)}")    
    print(f"\t Eax: {hex(target_thread_context.Eax)}")    
    print(f"\t Ebp: {hex(target_thread_context.Ebp)}")    
    print(f"\t Eip: {hex(target_thread_context.Eip)}")    
    print(f"\t SegCs: {hex(target_thread_context.SegCs)}")    
    print(f"\t EFlags: {hex(target_thread_context.EFlags)}")    
    print(f"\t Esp: {hex(target_thread_context.Esp)}")    
    print(f"\t SegSs: {hex(target_thread_context.SegSs)}")

def HandleEventCreateProcess(pEvent):
    global target_process_handle
    global target_path
    global target_image_base

    global sw_break_points

    print(f"\nCREATE_PROCESS_DEBUG_EVENT")

    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId
    print(f"\nThread ID: {hex(target_thread_id)}")
    target_process_info = pEvent.u.CreateProcessInfo
    target_file_handle = target_process_info.hFile
    # target_process_handle = target_process_info.hProcess
    target_image_base = target_process_info.lpBaseOfImage
    target_start_address = target_process_info.lpStartAddress
    print(f"Target loaded at {hex(target_image_base)}")
    print(f"Target Entry Point at {hex(target_start_address)}")

    target_thread_handle = target_process_info.hThread
    target_thread_context = win32process.GetThreadContext(target_thread_handle)
    HandleEventCreateThread(pEvent)


    #set breakpoint to the start address
    entry_point_breakpoint_address = target_start_address
    sw_break_points[target_start_address] = SetSoftwareBreakpoint(target_process_handle ,target_start_address)

    return win32types.DBG_CONTINUE

def HandleEventExitProcess(pEvent):
    print(f"\nEXIT_PROCESS_DEBUG_EVENT")
    target_exit_code = pEvent.u.ExitProcess.dwExitCode
    print(f"Exit code: {hex(target_exit_code)}")
    return win32types.DBG_CONTINUE

def HandleEventUnloadDll(pEvent):
    print(f"\nUNLOAD_DLL_DEBUG_EVENT")
    return win32types.DBG_CONTINUE

def PrintInfoDll():
    global target_dlls
    for dll in target_dlls:
        print("*******************************************")
        print(f"DLL Loaded: {target_dlls[dll]['name']}")
        print(f"Base: {hex(target_dlls[dll]['base'])}")
        print(f"End: {hex(target_dlls[dll]['end_address'])}")
        print(f"Size: {target_dlls[dll]['virtual_size']}")
        print(f"Entry Point: {hex(target_dlls[dll]['entrypoint'])}")
        print("*******************************************")


def HandleEventLoadDll(pEvent):
    global target_dlls
    global target_process_handle

    print(f"\nLOAD_DLL_DEBUG_EVENT")
    target_process_id = pEvent.dwProcessId
    target_thread_id = pEvent.dwThreadId

    dll_event_info = pEvent.u.LoadDll
    dll_file_handle = dll_event_info.hFile
    dll_based_address = dll_event_info.lpBaseOfDll

    # Because the LOAD_DLL_DEBUG_INFO.lpImageName member is not correctly
    # populated at the time the LOAD_DLL_DEBUG_EVENT event is raised 
    # we must use the dll_file_handle to locate the DLL file on disk and
    # parse the file directly for more information about the DLL

    file_path_buffer_size = win32types.MAX_PATH
    file_path_buffer = ctypes.create_unicode_buffer(u"", win32types.MAX_PATH + 1)

    # Use the file handle to get the DLL file path
    path_status = ctypes.windll.kernel32.GetFinalPathNameByHandleW( pEvent.u.LoadDll.hFile, 
                                                                    file_path_buffer, 
                                                                    file_path_buffer_size, 
                                                                    win32types.FILE_NAME_NORMALIZED )
    if not path_status:
        print(f"GetFinalPathNameByHandleW failed: {ctypes.WinError().strerror}")
        return win32types.DBG_CONTINUE

    dll_file_path = file_path_buffer.value
    pe = pefile.PE(dll_file_path, fast_load=True)

    # Calculate DLL entry point by adding entrypoint RVA to DLL base address
    dll_entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint + dll_based_address
    # Calculate DLL end address by adding DLL base address and DLL virtual size calculated
    # by adding the size and virtual address(relativ to the base address) of the DLL's last PE section
    dll_end_address = pe.sections[-1].Misc_VirtualSize + pe.sections[-1].VirtualAddress + dll_based_address
    # Calcuate the DLL virtual size by subtracting the DLL base address from the DLL end address
    dll_virtual_size = dll_end_address - dll_based_address
    # Extract the DLL name from the DLL file path
    dll_name = os.path.basename(dll_file_path)

    # Parse the exports from DLL and save these for later use
    # Tell pefile to parse the export directory since we are using the fast_load option
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

    global exports
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        # The export address is the RVA so it must ba added to the DLL base address to
        # calculate the virtual address of the export
        export_address = dll_based_address + exp.address
        export_name = exp.name
        export_ord = exp.ordinal
        exports.append({'name':export_name, 'ord':export_ord, 'address':export_address})

    target_dlls[dll_based_address] = { 'name':dll_name, 
                                        'path':dll_file_path, 
                                        'base':dll_based_address, 
                                        'end_address':dll_end_address,
                                        'size':dll_virtual_size,
                                        'entrypoint':dll_entrypoint,
                                        'virtual_size':dll_virtual_size,
                                        'exports':exports }

    return win32types.DBG_CONTINUE

def main():
    global target_process_handle
    global target_path
    global target_main_thread_id
    # Get path to target exe
    try:
        target_path = sys.argv[1]
    except:
        print("Please enter PATH to debug process")
        sys.exit()
    print(f"Debugging target:{target_path}")

    # Create target process
    pStartupInfo = win32types.STARTUPINFO()
    pProcessInfo = win32types.PROCESS_INFORMATION()
    proc_status = ctypes.windll.kernel32.CreateProcessW(target_path,
                                                        None,
                                                        None,
                                                        None,
                                                        False,
                                                        # DEBUG_PROCESS flags tell the kernel 
                                                        win32types.DEBUG_PROCESS,
                                                        None,
                                                        None,
                                                        ctypes.byref(pStartupInfo),
                                                        ctypes.byref(pProcessInfo))

    if not proc_status:
        print(f"Cannot create target process:{ctypes.WinError().strerror}")
        sys.exit(1)

    target_process_handle = pProcessInfo.hProcess
    target_pid = pProcessInfo.dwProcessId
    target_main_thread_id = pProcessInfo.dwThreadId

    print(f"Target process created (PID:{pProcessInfo.dwProcessId})")

    print(f"Press ENTER to quit debug loop...")
    while True:
        # Create a DEBUG_EVENT struct to be populated with event information
        pEvent = win32types.DEBUG_EVENT()
        # Set the default debug status to DBG_EXCEPTION_NOT_HANDLED
        # This will be passed to ContinueDebugEvent() if the event is not handled 
        dwStatus = win32types.DBG_EXCEPTION_NOT_HANDLED

        if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(pEvent), 100):
            if pEvent.dwDebugEventCode == win32types.CREATE_PROCESS_DEBUG_EVENT:
                dwStatus = HandleEventCreateProcess(pEvent)
            elif pEvent.dwDebugEventCode == win32types.CREATE_THREAD_DEBUG_EVENT:
                dwStatus = HandleEventCreateThread(pEvent)
            elif pEvent.dwDebugEventCode == win32types.EXIT_THREAD_DEBUG_EVENT:
                dwStatus = HandleEventExitThread(pEvent)
            elif pEvent.dwDebugEventCode == win32types.LOAD_DLL_DEBUG_EVENT:
                dwStatus = HandleEventLoadDll(pEvent)
            elif pEvent.dwDebugEventCode == win32types.UNLOAD_DLL_DEBUG_EVENT:
                dwStatus = HandleEventUnloadDll(pEvent)
            elif pEvent.dwDebugEventCode == win32types.EXIT_PROCESS_DEBUG_EVENT:
                dwStatus = HandleEventExitProcess(pEvent)

            elif pEvent.dwDebugEventCode == win32types.EXCEPTION_DEBUG_EVENT: 
                exception_code = pEvent.u.Exception.ExceptionRecord.ExceptionCode
                exception_address = pEvent.u.Exception.ExceptionRecord.ExceptionAddress

                # software breakpoint exception event
                if exception_code == win32types.EXCEPTION_BREAKPOINT: 
                    dwStatus = HandleSoftwareBreakpoint(pEvent)
                # hardware breakpoint exception event
                elif exception_code == win32types.EXCEPTION_SINGLE_STEP:
                    dwStatus = HandleHardwareBreakpoint(pEvent)

            # Continue target process
            ctypes.windll.kernel32.ContinueDebugEvent(pEvent.dwProcessId, pEvent.dwThreadId, dwStatus)

        if msvcrt.kbhit():
            if msvcrt.getwche() == '\r':
                break





if __name__ == '__main__':
    main()
