```
The specified ResourceManager made no changes or updates to the resource under this transaction.
    RESOURCEMANAGER_READ_ONLY = 0x00000202,
    /// An operation is blocked and waiting for an oplock.
    WAIT_FOR_OPLOCK = 0x00000367,
    /// Debugger handled the exception.
    DBG_EXCEPTION_HANDLED = 0x00010001,
    /// The debugger continued.
    DBG_CONTINUE = 0x00010002,
    /// The IO was completed by a filter.
    FLT_IO_COMPLETE = 0x001C0001,
    /// The file is temporarily unavailable.
    FILE_NOT_AVAILABLE = 0xC0000467,
    /// The share is temporarily unavailable.
    SHARE_UNAVAILABLE = 0xC0000480,
    /// A threadpool worker thread entered a callback at thread affinity %p and exited at affinity %p.
    /// This is unexpected, indicating that the callback missed restoring the priority.
    CALLBACK_RETURNED_THREAD_AFFINITY = 0xC0000721,
    /// {Object Exists} An attempt was made to create an object but the object name already exists.
    OBJECT_NAME_EXISTS = 0x40000000,
    /// {Thread Suspended} A thread termination occurred while the thread was suspended. The thread resumed, and termination proceeded.
    THREAD_WAS_SUSPENDED = 0x40000001,
    /// {Working Set Range Error} An attempt was made to set the working set minimum or maximum to values that are outside the allowable range.
    WORKING_SET_LIMIT_RANGE = 0x40000002,
    /// {Image Relocated} An image file could not be mapped at the address that is specified in the image file. Local fixes must be performed on this image.
    IMAGE_NOT_AT_BASE = 0x40000003,
    /// This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created.
    RXACT_STATE_CREATED = 0x40000004,
    /// {Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image.
    /// An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments.
    SEGMENT_NOTIFICATION = 0x40000005,
    /// {Local Session Key} A user session key was requested for a local remote procedure call (RPC) connection.
    /// The session key that is returned is a constant value and not unique to this connection.
    LOCAL_USER_SESSION_KEY = 0x40000006,
    /// {Invalid Current Directory} The process cannot switch to the startup current directory %hs.
    /// Select OK to set the current directory to %hs, or select CANCEL to exit.
    BAD_CURRENT_DIRECTORY = 0x40000007,
    /// {Serial IOCTL Complete} A serial I/O operation was completed by another write to a serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)
    SERIAL_MORE_WRITES = 0x40000008,
    /// {Registry Recovery} One of the files that contains the system registry data had to be recovered by using a log or alternate copy. The recovery was successful.
    REGISTRY_RECOVERED = 0x40000009,
    /// {Redundant Read} To satisfy a read request, the Windows NT operating system fault-tolerant file system successfully read the requested data from a redundant copy.
    /// This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.
    FT_READ_RECOVERY_FROM_BACKUP = 0x4000000A,
    /// {Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information.
    /// This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device.
    FT_WRITE_RECOVERY = 0x4000000B,
    /// {Serial IOCTL Timeout} A serial I/O operation completed because the time-out period expired.
    /// (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)
    SERIAL_COUNTER_TIMEOUT = 0x4000000C,
    /// {Password Too Complex} The Windows password is too complex to be converted to a LAN Manager password.
    /// The LAN Manager password that returned is a NULL string.
    NULL_LM_PASSWORD = 0x4000000D,
    /// {Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine.
    /// Select OK to continue, or CANCEL to fail the DLL load.
    IMAGE_MACHINE_TYPE_MISMATCH = 0x4000000E,
    /// {Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.
    RECEIVE_PARTIAL = 0x4000000F,
    /// {Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.
    RECEIVE_EXPEDITED = 0x40000010,
    /// {Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.
    RECEIVE_PARTIAL_EXPEDITED = 0x40000011,
    /// {TDI Event Done} The TDI indication has completed successfully.
    EVENT_DONE = 0x40000012,
    /// {TDI Event Pending} The TDI indication has entered the pending state.
    EVENT_PENDING = 0x40000013,
    /// Checking file system on %wZ.
    CHECKING_FILE_SYSTEM = 0x40000014,
    /// {Fatal Application Exit} %hs
    FATAL_APP_EXIT = 0x40000015,
    /// The specified registry key is referenced by a predefined handle.
    PREDEFINED_HANDLE = 0x40000016,
    /// {Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.
    WAS_UNLOCKED = 0x40000017,
    /// %hs
    SERVICE_NOTIFICATION = 0x40000018,
    /// {Page Locked} One of the pages to lock was already locked.
    WAS_LOCKED = 0x40000019,
    /// Application popup: %1 : %2
    LOG_HARD_ERROR = 0x4000001A,
    /// A Win32 process already exists.
    ALREADY_WIN32 = 0x4000001B,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_UNSIMULATE = 0x4000001C,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_CONTINUE = 0x4000001D,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_SINGLE_STEP = 0x4000001E,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_BREAKPOINT = 0x4000001F,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_EXCEPTION_CONTINUE = 0x40000020,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_EXCEPTION_LASTCHANCE = 0x40000021,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_EXCEPTION_CHAIN = 0x40000022,
    /// {Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine.
    IMAGE_MACHINE_TYPE_MISMATCH_EXE = 0x40000023,
    /// A yield execution was performed and no thread was available to run.
    NO_YIELD_PERFORMED = 0x40000024,
    /// The resume flag to a timer API was ignored.
    TIMER_RESUME_IGNORED = 0x40000025,
    /// The arbiter has deferred arbitration of these resources to its parent.
    ARBITRATION_UNHANDLED = 0x40000026,
    /// The device has detected a CardBus card in its slot.
    CARDBUS_NOT_SUPPORTED = 0x40000027,
    /// An exception status code that is used by the Win32 x86 emulation subsystem.
    WX86_CREATEWX86TIB = 0x40000028,
    /// The CPUs in this multiprocessor system are not all the same revision level.
    /// To use all processors, the operating system restricts itself to the features of the least capable processor in the system.
    /// If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.
    MP_PROCESSOR_MISMATCH = 0x40000029,
    /// The system was put into hibernation.
    HIBERNATED = 0x4000002A,
    /// The system was resumed from hibernation.
    RESUME_HIBERNATION = 0x4000002B,
    /// Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3].
    FIRMWARE_UPDATED = 0x4000002C,
    /// A device driver is leaking locked I/O pages and is causing system degradation.
    /// The system has automatically enabled the tracking code to try and catch the culprit.
    DRIVERS_LEAKING_LOCKED_PAGES = 0x4000002D,
    /// The ALPC message being canceled has already been retrieved from the queue on the other side.
    MESSAGE_RETRIEVED = 0x4000002E,
    /// The system power state is transitioning from %2 to %3.
    SYSTEM_POWERSTATE_TRANSITION = 0x4000002F,
    /// The receive operation was successful.
    /// Check the ALPC completion list for the received message.
    ALPC_CHECK_COMPLETION_LIST = 0x40000030,
    /// The system power state is transitioning from %2 to %3 but could enter %4.
    SYSTEM_POWERSTATE_COMPLEX_TRANSITION = 0x40000031,
    /// Access to %1 is monitored by policy rule %2.
    ACCESS_AUDIT_BY_POLICY = 0x40000032,
    /// A valid hibernation file has been invalidated and should be abandoned.
    ABANDON_HIBERFILE = 0x40000033,
    /// Business rule scripts are disabled for the calling application.
    BIZRULES_NOT_ENABLED = 0x40000034,
    /// The system has awoken.
    WAKE_SYSTEM = 0x40000294,
    /// The directory service is shutting down.
    DS_SHUTTING_DOWN = 0x40000370,
    /// Debugger will reply later.
    DBG_REPLY_LATER = 0x40010001,
    /// Debugger cannot provide a handle.
    DBG_UNABLE_TO_PROVIDE_HANDLE = 0x40010002,
    /// Debugger terminated the thread.
    DBG_TERMINATE_THREAD = 0x40010003,
    /// Debugger terminated the process.
    DBG_TERMINATE_PROCESS = 0x40010004,
    /// Debugger obtained control of C.
    DBG_CONTROL_C = 0x40010005,
    /// Debugger printed an exception on control C.
    DBG_PRINTEXCEPTION_C = 0x40010006,
    /// Debugger received a RIP exception.
    DBG_RIPEXCEPTION = 0x40010007,
    /// Debugger received a control break.
    DBG_CONTROL_BREAK = 0x40010008,
    /// Debugger command communication exception.
    DBG_COMMAND_EXCEPTION = 0x40010009,
    /// A UUID that is valid only on this computer has been allocated.
    RPC_NT_UUID_LOCAL_ONLY = 0x40020056,
    /// Some data remains to be sent in the request buffer.
    RPC_NT_SEND_INCOMPLETE = 0x400200AF,
    /// The Client Drive Mapping Service has connected on Terminal Connection.
    CTX_CDM_CONNECT = 0x400A0004,
    /// The Client Drive Mapping Service has disconnected on Terminal Connection.
    CTX_CDM_DISCONNECT = 0x400A0005,
    /// A kernel mode component is releasing a reference on an activation context.
    SXS_RELEASE_ACTIVATION_CONTEXT = 0x4015000D,
    /// The transactional resource manager is already consistent. Recovery is not needed.
    RECOVERY_NOT_NEEDED = 0x40190034,
    /// The transactional resource manager has already been started.
    RM_ALREADY_STARTED = 0x40190035,
    /// The log service encountered a log stream with no restart area.
    LOG_NO_RESTART = 0x401A000C,
    /// {Display Driver Recovered From Failure} The %hs display driver has detected a failure and recovered from it. Some graphical operations might have failed.
    /// The next time you restart the machine, a dialog box appears, giving you an opportunity to upload data about this failure to Microsoft.
    VIDEO_DRIVER_DEBUG_REPORT_REQUEST = 0x401B00EC,
    /// The specified buffer is not big enough to contain the entire requested dataset.
    /// Partial data is populated up to the size of the buffer.
    /// The caller needs to provide a buffer of the size as specified in the partially populated buffer's content (interface specific).
    GRAPHICS_PARTIAL_DATA_POPULATED = 0x401E000A,
    /// The kernel driver detected a version mismatch between it and the user mode driver.
    GRAPHICS_DRIVER_MISMATCH = 0x401E0117,
    /// No mode is pinned on the specified VidPN source/target.
    GRAPHICS_MODE_NOT_PINNED = 0x401E0307,
    /// The specified mode set does not specify a preference for one of its modes.
    GRAPHICS_NO_PREFERRED_MODE = 0x401E031E,
    /// The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) is empty.
    GRAPHICS_DATASET_IS_EMPTY = 0x401E034B,
    /// The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) does not contain any more elements.
    GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET = 0x401E034C,
    /// The specified content transformation is not pinned on the specified VidPN present path.
    GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED = 0x401E0351,
    /// The child device presence was not reliably detected.
    GRAPHICS_UNKNOWN_CHILD_STATUS = 0x401E042F,
    /// Starting the lead adapter in a linked configuration has been temporarily deferred.
    GRAPHICS_LEADLINK_START_DEFERRED = 0x401E0437,
    /// The display adapter is being polled for children too frequently at the same polling level.
    GRAPHICS_POLLING_TOO_FREQUENTLY = 0x401E0439,
    /// Starting the adapter has been temporarily deferred.
    GRAPHICS_START_DEFERRED = 0x401E043A,
    /// The request will be completed later by an NDIS status indication.
    NDIS_INDICATION_REQUIRED = 0x40230001,
    /// {EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed.
    GUARD_PAGE_VIOLATION = 0x80000001,
    /// {EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction.
    DATATYPE_MISALIGNMENT = 0x80000002,
    /// {EXCEPTION} Breakpoint A breakpoint has been reached.
    BREAKPOINT = 0x80000003,
    /// {EXCEPTION} Single Step A single step or trace operation has just been completed.
    SINGLE_STEP = 0x80000004,
    /// {Buffer Overflow} The data was too large to fit into the specified buffer.
    BUFFER_OVERFLOW = 0x80000005,
    /// {No More Files} No more files were found which match the file specification.
    NO_MORE_FILES = 0x80000006,
    /// {Kernel Debugger Awakened} The system debugger was awakened by an interrupt.
    WAKE_SYSTEM_DEBUGGER = 0x80000007,
    /// {Handles Closed} Handles to objects have been automatically closed because of the requested operation.
    HANDLES_CLOSED = 0x8000000A,
    /// {Non-Inheritable ACL} An access control list (ACL) contains no components that can be inherited.
    NO_INHERITANCE = 0x8000000B,
    /// {GUID Substitution} During the translation of a globally unique identifier (GUID) to a Windows security ID (SID), no administratively defined GUID prefix was found.
    /// A substitute prefix was used, which will not compromise system security.
    /// However, this might provide a more restrictive access than intended.
    GUID_SUBSTITUTION_MADE = 0x8000000C,
    /// Because of protection conflicts, not all the requested bytes could be copied.
    PARTIAL_COPY = 0x8000000D,
    /// {Out of Paper} The printer is out of paper.
    DEVICE_PAPER_EMPTY = 0x8000000E,
    /// {Device Power Is Off} The printer power has been turned off.
    DEVICE_POWERED_OFF = 0x8000000F,
    /// {Device Offline} The printer has been taken offline.
    DEVICE_OFF_LINE = 0x80000010,
    /// {Device Busy} The device is currently busy.
    DEVICE_BUSY = 0x80000011,
    /// {No More EAs} No more extended attributes (EAs) were found for the file.
    NO_MORE_EAS = 0x80000012,
    /// {Illegal EA} The specified extended attribute (EA) name contains at least one illegal character.
    INVALID_EA_NAME = 0x80000013,
    /// {Inconsistent EA List} The extended attribute (EA) list is inconsistent.
    EA_LIST_INCONSISTENT = 0x80000014,
    /// {Invalid EA Flag} An invalid extended attribute (EA) flag was set.
    INVALID_EA_FLAG = 0x80000015,
    /// {Verifying Disk} The media has changed and a verify operation is in progress; therefore, no reads or writes can be performed to the device, except those that are used in the verify operation.
    VERIFY_REQUIRED = 0x80000016,
    /// {Too Much Information} The specified access control list (ACL) contained more information than was expected.
    EXTRANEOUS_INFORMATION = 0x80000017,
    /// This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted.
    /// The commit has NOT been completed but has not been rolled back either; therefore, it can still be committed, if needed.
    RXACT_COMMIT_NECESSARY = 0x80000018,
    /// {No More Entries} No more entries are available from an enumeration operation.
    NO_MORE_ENTRIES = 0x8000001A,
    /// {Filemark Found} A filemark was detected.
    FILEMARK_DETECTED = 0x8000001B,
    /// {Media Changed} The media has changed.
    MEDIA_CHANGED = 0x8000001C,
    /// {I/O Bus Reset} An I/O bus reset was detected.
    BUS_RESET = 0x8000001D,
    /// {End of Media} The end of the media was encountered.
    END_OF_MEDIA = 0x8000001E,
    /// The beginning of a tape or partition has been detected.
    BEGINNING_OF_MEDIA = 0x8000001F,
    /// {Media Changed} The media might have changed.
    MEDIA_CHECK = 0x80000020,
    /// A tape access reached a set mark.
    SETMARK_DETECTED = 0x80000021,
    /// During a tape access, the end of the data written is reached.
    NO_DATA_DETECTED = 0x80000022,
    /// The redirector is in use and cannot be unloaded.
    REDIRECTOR_HAS_OPEN_HANDLES = 0x80000023,
    /// The server is in use and cannot be unloaded.
    SERVER_HAS_OPEN_HANDLES = 0x80000024,
    /// The specified connection has already been disconnected.
    ALREADY_DISCONNECTED = 0x80000025,
    /// A long jump has been executed.
    LONGJUMP = 0x80000026,
    /// A cleaner cartridge is present in the tape library.
    CLEANER_CARTRIDGE_INSTALLED = 0x80000027,
    /// The Plug and Play query operation was not successful.
    PLUGPLAY_QUERY_VETOED = 0x80000028,
    /// A frame consolidation has been executed.
    UNWIND_CONSOLIDATE = 0x80000029,
    /// {Registry Hive Recovered} The registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.
    REGISTRY_HIVE_RECOVERED = 0x8000002A,
    /// The application is attempting to run executable code from the module %hs. This might be insecure.
    /// An alternative, %hs, is available. Should the application use the secure module %hs?
    DLL_MIGHT_BE_INSECURE = 0x8000002B,
    /// The application is loading executable code from the module %hs.
    /// This is secure but might be incompatible with previous releases of the operating system.
    /// An alternative, %hs, is available. Should the application use the secure module %hs?
    DLL_MIGHT_BE_INCOMPATIBLE = 0x8000002C,
    /// The create operation stopped after reaching a symbolic link.
    STOPPED_ON_SYMLINK = 0x8000002D,
    /// The device has indicated that cleaning is necessary.
    DEVICE_REQUIRES_CLEANING = 0x80000288,
    /// The device has indicated that its door is open. Further operations require it closed and secured.
    DEVICE_DOOR_OPEN = 0x80000289,
    /// Windows discovered a corruption in the file %hs. This file has now been repaired.
    /// Check if any data in the file was lost because of the corruption.
    DATA_LOST_REPAIR = 0x80000803,
    /// Debugger did not handle the exception.
    DBG_EXCEPTION_NOT_HANDLED = 0x80010001,
    /// The cluster node is already up.
    CLUSTER_NODE_ALREADY_UP = 0x80130001,
    /// The cluster node is already down.
    CLUSTER_NODE_ALREADY_DOWN = 0x80130002,
    /// The cluster network is already online.
    CLUSTER_NETWORK_ALREADY_ONLINE = 0x80130003,
    /// The cluster network is already offline.
    CLUSTER_NETWORK_ALREADY_OFFLINE = 0x80130004,
    /// The cluster node is already a member of the cluster.
    CLUSTER_NODE_ALREADY_MEMBER = 0x80130005,
    /// The log could not be set to the requested size.
    COULD_NOT_RESIZE_LOG = 0x80190009,
    /// There is no transaction metadata on the file.
    NO_TXF_METADATA = 0x80190029,
    /// The file cannot be recovered because there is a handle still open on it.
    CANT_RECOVER_WITH_HANDLE_OPEN = 0x80190031,
    /// Transaction metadata is already present on this file and cannot be superseded.
    TXF_METADATA_ALREADY_PRESENT = 0x80190041,
    /// A transaction scope could not be entered because the scope handler has not been initialized.
    TRANSACTION_SCOPE_CALLBACKS_NOT_SET = 0x80190042,
    /// {Display Driver Stopped Responding and recovered} The %hs display driver has stopped working normally. The recovery had been performed.
    VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED = 0x801B00EB,
    /// {Buffer too small} The buffer is too small to contain the entry. No information has been written to the buffer.
    FLT_BUFFER_TOO_SMALL = 0x801C0001,
    /// Volume metadata read or write is incomplete.
    FVE_PARTIAL_METADATA = 0x80210001,
    /// BitLocker encryption keys were ignored because the volume was in a transient state.
    FVE_TRANSIENT_STATE = 0x80210002,
    /// {Operation Failed} The requested operation was unsuccessful.
    UNSUCCESSFUL = 0xC0000001,
    /// {Not Implemented} The requested operation is not implemented.
    NOT_IMPLEMENTED = 0xC0000002,
    /// {Invalid Parameter} The specified information class is not a valid information class for the specified object.
    INVALID_INFO_CLASS = 0xC0000003,
    /// The specified information record length does not match the length that is required for the specified information class.
    INFO_LENGTH_MISMATCH = 0xC0000004,
    /// The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s.
    ACCESS_VIOLATION = 0xC0000005,
    /// The instruction at 0x%08lx referenced memory at 0x%08lx.
    /// The required data was not placed into memory because of an I/O error status of 0x%08lx.
    IN_PAGE_ERROR = 0xC0000006,
    /// The page file quota for the process has been exhausted.
    PAGEFILE_QUOTA = 0xC0000007,
    /// An invalid HANDLE was specified.
    INVALID_HANDLE = 0xC0000008,
    /// An invalid initial stack was specified in a call to NtCreateThread.
    BAD_INITIAL_STACK = 0xC0000009,
    /// An invalid initial start address was specified in a call to NtCreateThread.
    BAD_INITIAL_PC = 0xC000000A,
    /// An invalid client ID was specified.
    INVALID_CID = 0xC000000B,
    /// An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine.
    TIMER_NOT_CANCELED = 0xC000000C,
    /// An invalid parameter was passed to a service or function.
    INVALID_PARAMETER = 0xC000000D,
    /// A device that does not exist was specified.
    NO_SUCH_DEVICE = 0xC000000E,
    /// {File Not Found} The file %hs does not exist.
    NO_SUCH_FILE = 0xC000000F,
    /// The specified request is not a valid operation for the target device.
    INVALID_DEVICE_REQUEST = 0xC0000010,
    /// The end-of-file marker has been reached.
    /// There is no valid data in the file beyond this marker.
    END_OF_FILE = 0xC0000011,
    /// {Wrong Volume} The wrong volume is in the drive. Insert volume %hs into drive %hs.
    WRONG_VOLUME = 0xC0000012,
    /// {No Disk} There is no disk in the drive. Insert a disk into drive %hs.
    NO_MEDIA_IN_DEVICE = 0xC0000013,
    /// {Unknown Disk Format} The disk in drive %hs is not formatted properly.
    /// Check the disk, and reformat it, if needed.
    UNRECOGNIZED_MEDIA = 0xC0000014,
    /// {Sector Not Found} The specified sector does not exist.
    NONEXISTENT_SECTOR = 0xC0000015,
    /// {Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete.
    MORE_PROCESSING_REQUIRED = 0xC0000016,
    /// {Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation.
    NO_MEMORY = 0xC0000017,
    /// {Conflicting Address Range} The specified address range conflicts with the address space.
    CONFLICTING_ADDRESSES = 0xC0000018,
    /// The address range to unmap is not a mapped view.
    NOT_MAPPED_VIEW = 0xC0000019,
    /// The virtual memory cannot be freed.
    UNABLE_TO_FREE_VM = 0xC000001A,
    /// The specified section cannot be deleted.
    UNABLE_TO_DELETE_SECTION = 0xC000001B,
    /// An invalid system service was specified in a system service call.
    INVALID_SYSTEM_SERVICE = 0xC000001C,
    /// {EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction.
    ILLEGAL_INSTRUCTION = 0xC000001D,
    /// {Invalid Lock Sequence} An attempt was made to execute an invalid lock sequence.
    INVALID_LOCK_SEQUENCE = 0xC000001E,
    /// {Invalid Mapping} An attempt was made to create a view for a section that is bigger than the section.
    INVALID_VIEW_SIZE = 0xC000001F,
    /// {Bad File} The attributes of the specified mapping file for a section of memory cannot be read.
    INVALID_FILE_FOR_SECTION = 0xC0000020,
    /// {Already Committed} The specified address range is already committed.
    ALREADY_COMMITTED = 0xC0000021,
    /// {Access Denied} A process has requested access to an object but has not been granted those access rights.
    ACCESS_DENIED = 0xC0000022,
    /// {Buffer Too Small} The buffer is too small to contain the entry. No information has been written to the buffer.
    BUFFER_TOO_SMALL = 0xC0000023,
    /// {Wrong Type} There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request.
    OBJECT_TYPE_MISMATCH = 0xC0000024,
    /// {EXCEPTION} Cannot Continue Windows cannot continue from this exception.
    NONCONTINUABLE_EXCEPTION = 0xC0000025,
    /// An invalid exception disposition was returned by an exception handler.
    INVALID_DISPOSITION = 0xC0000026,
    /// Unwind exception code.
    UNWIND = 0xC0000027,
    /// An invalid or unaligned stack was encountered during an unwind operation.
    BAD_STACK = 0xC0000028,
    /// An invalid unwind target was encountered during an unwind operation.
    INVALID_UNWIND_TARGET = 0xC0000029,
    /// An attempt was made to unlock a page of memory that was not locked.
    NOT_LOCKED = 0xC000002A,
    /// A device parity error on an I/O operation.
    PARITY_ERROR = 0xC000002B,
    /// An attempt was made to decommit uncommitted virtual memory.
    UNABLE_TO_DECOMMIT_VM = 0xC000002C,
    /// An attempt was made to change the attributes on memory that has not been committed.
    NOT_COMMITTED = 0xC000002D,
    /// Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort.
    INVALID_PORT_ATTRIBUTES = 0xC000002E,
    /// The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port.
    PORT_MESSAGE_TOO_LONG = 0xC000002F,
    /// An invalid combination of parameters was specified.
    INVALID_PARAMETER_MIX = 0xC0000030,
    /// An attempt was made to lower a quota limit below the current usage.
    INVALID_QUOTA_LOWER = 0xC0000031,
    /// {Corrupt Disk} The file system structure on the disk is corrupt and unusable. Run the Chkdsk utility on the volume %hs.
    DISK_CORRUPT_ERROR = 0xC0000032,
    /// The object name is invalid.
    OBJECT_NAME_INVALID = 0xC0000033,
    /// The object name is not found.
    OBJECT_NAME_NOT_FOUND = 0xC0000034,
    /// The object name already exists.
    OBJECT_NAME_COLLISION = 0xC0000035,
    /// An attempt was made to send a message to a disconnected communication port.
    PORT_DISCONNECTED = 0xC0000037,
    /// An attempt was made to attach to a device that was already attached to another device.
    DEVICE_ALREADY_ATTACHED = 0xC0000038,
    /// The object path component was not a directory object.
    OBJECT_PATH_INVALID = 0xC0000039,
    /// {Path Not Found} The path %hs does not exist.
    OBJECT_PATH_NOT_FOUND = 0xC000003A,
    /// The object path component was not a directory object.
    OBJECT_PATH_SYNTAX_BAD = 0xC000003B,
    /// {Data Overrun} A data overrun error occurred.
    DATA_OVERRUN = 0xC000003C,
    /// {Data Late} A data late error occurred.
    DATA_LATE_ERROR = 0xC000003D,
    /// {Data Error} An error occurred in reading or writing data.
    DATA_ERROR = 0xC000003E,
    /// {Bad CRC} A cyclic redundancy check (CRC) checksum error occurred.
    CRC_ERROR = 0xC000003F,
    /// {Section Too Large} The specified section is too big to map the file.
    SECTION_TOO_BIG = 0xC0000040,
    /// The NtConnectPort request is refused.
    PORT_CONNECTION_REFUSED = 0xC0000041,
    /// The type of port handle is invalid for the operation that is requested.
    INVALID_PORT_HANDLE = 0xC0000042,
    /// A file cannot be opened because the share access flags are incompatible.
    SHARING_VIOLATION = 0xC0000043,
    /// Insufficient quota exists to complete the operation.
    QUOTA_EXCEEDED = 0xC0000044,
    /// The specified page protection was not valid.
    INVALID_PAGE_PROTECTION = 0xC0000045,
    /// An attempt to release a mutant object was made by a thread that was not the owner of the mutant object.
    MUTANT_NOT_OWNED = 0xC0000046,
    /// An attempt was made to release a semaphore such that its maximum count would have been exceeded.
    SEMAPHORE_LIMIT_EXCEEDED = 0xC0000047,
    /// An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set.
    PORT_ALREADY_SET = 0xC0000048,
    /// An attempt was made to query image information on a section that does not map an image.
    SECTION_NOT_IMAGE = 0xC0000049,
    /// An attempt was made to suspend a thread whose suspend count was at its maximum.
    SUSPEND_COUNT_EXCEEDED = 0xC000004A,
    /// An attempt was made to suspend a thread that has begun termination.
    THREAD_IS_TERMINATING = 0xC000004B,
    /// An attempt was made to set the working set limit to an invalid value (for example, the minimum greater than maximum).
    BAD_WORKING_SET_LIMIT = 0xC000004C,
    /// A section was created to map a file that is not compatible with an already existing section that maps the same file.
    INCOMPATIBLE_FILE_MAP = 0xC000004D,
    /// A view to a section specifies a protection that is incompatible with the protection of the initial view.
    SECTION_PROTECTION = 0xC000004E,
    /// An operation involving EAs failed because the file system does not support EAs.
    EAS_NOT_SUPPORTED = 0xC000004F,
    /// An EA operation failed because the EA set is too large.
    EA_TOO_LARGE = 0xC0000050,
    /// An EA operation failed because the name or EA index is invalid.
    NONEXISTENT_EA_ENTRY = 0xC0000051,
    /// The file for which EAs were requested has no EAs.
    NO_EAS_ON_FILE = 0xC0000052,
    /// The EA is corrupt and cannot be read.
    EA_CORRUPT_ERROR = 0xC0000053,
    /// A requested read/write cannot be granted due to a conflicting file lock.
    FILE_LOCK_CONFLICT = 0xC0000054,
    /// A requested file lock cannot be granted due to other existing locks.
    LOCK_NOT_GRANTED = 0xC0000055,
    /// A non-close operation has been requested of a file object that has a delete pending.
    DELETE_PENDING = 0xC0000056,
    /// An attempt was made to set the control attribute on a file.
    /// This attribute is not supported in the destination file system.
    CTL_FILE_NOT_SUPPORTED = 0xC0000057,
    /// Indicates a revision number that was encountered or specified is not one that is known by the service.
    /// It might be a more recent revision than the service is aware of.
    UNKNOWN_REVISION = 0xC0000058,
    /// Indicates that two revision levels are incompatible.
    REVISION_MISMATCH = 0xC0000059,
    /// Indicates a particular security ID cannot be assigned as the owner of an object.
    INVALID_OWNER = 0xC000005A,
    /// Indicates a particular security ID cannot be assigned as the primary group of an object.
    INVALID_PRIMARY_GROUP = 0xC000005B,
    /// An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.
    NO_IMPERSONATION_TOKEN = 0xC000005C,
    /// A mandatory group cannot be disabled.
    CANT_DISABLE_MANDATORY = 0xC000005D,
    /// No logon servers are currently available to service the logon request.
    NO_LOGON_SERVERS = 0xC000005E,
    /// A specified logon session does not exist. It might already have been terminated.
    NO_SUCH_LOGON_SESSION = 0xC000005F,
    /// A specified privilege does not exist.
    NO_SUCH_PRIVILEGE = 0xC0000060,
    /// A required privilege is not held by the client.
    PRIVILEGE_NOT_HELD = 0xC0000061,
    /// The name provided is not a properly formed account name.
    INVALID_ACCOUNT_NAME = 0xC0000062,
    /// The specified account already exists.
    USER_EXISTS = 0xC0000063,
    /// The specified account does not exist.
    NO_SUCH_USER = 0xC0000064,
    /// The specified group already exists.
    GROUP_EXISTS = 0xC0000065,
    /// The specified group does not exist.
    NO_SUCH_GROUP = 0xC0000066,
    /// The specified user account is already in the specified group account.
    /// Also used to indicate a group cannot be deleted because it contains a member.
    MEMBER_IN_GROUP = 0xC0000067,
    /// The specified user account is not a member of the specified group account.
    MEMBER_NOT_IN_GROUP = 0xC0000068,
    /// Indicates the requested operation would disable or delete the last remaining administration account.
    /// This is not allowed to prevent creating a situation in which the system cannot be administrated.
    LAST_ADMIN = 0xC0000069,
    /// When trying to update a password, this return status indicates that the value provided as the current password is not correct.
    WRONG_PASSWORD = 0xC000006A,
    /// When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords.
    ILL_FORMED_PASSWORD = 0xC000006B,
    /// When trying to update a password, this status indicates that some password update rule has been violated.
    /// For example, the password might not meet length criteria.
    PASSWORD_RESTRICTION = 0xC000006C,
    /// The attempted logon is invalid.
    /// This is either due to a bad username or authentication information.
    LOGON_FAILURE = 0xC000006D,
    /// Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions).
    ACCOUNT_RESTRICTION = 0xC000006E,
    /// The user account has time restrictions and cannot be logged onto at this time.
    INVALID_LOGON_HOURS = 0xC000006F,
    /// The user account is restricted so that it cannot be used to log on from the source workstation.
    INVALID_WORKSTATION = 0xC0000070,
    /// The user account password has expired.
    PASSWORD_EXPIRED = 0xC0000071,
    /// The referenced account is currently disabled and cannot be logged on to.
    ACCOUNT_DISABLED = 0xC0000072,
    /// None of the information to be translated has been translated.
    NONE_MAPPED = 0xC0000073,
    /// The number of LUIDs requested cannot be allocated with a single allocation.
    TOO_MANY_LUIDS_REQUESTED = 0xC0000074,
    /// Indicates there are no more LUIDs to allocate.
    LUIDS_EXHAUSTED = 0xC0000075,
    /// Indicates the sub-authority value is invalid for the particular use.
    INVALID_SUB_AUTHORITY = 0xC0000076,
    /// Indicates the ACL structure is not valid.
    INVALID_ACL = 0xC0000077,
    /// Indicates the SID structure is not valid.
    INVALID_SID = 0xC0000078,
    /// Indicates the SECURITY_DESCRIPTOR structure is not valid.
    INVALID_SECURITY_DESCR = 0xC0000079,
    /// Indicates the specified procedure address cannot be found in the DLL.
    PROCEDURE_NOT_FOUND = 0xC000007A,
    /// {Bad Image} %hs is either not designed to run on Windows or it contains an error.
    /// Try installing the program again using the original installation media or contact your system administrator or the software vendor for support.
    INVALID_IMAGE_FORMAT = 0xC000007B,
    /// An attempt was made to reference a token that does not exist.
    /// This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client.
    NO_TOKEN = 0xC000007C,
    /// Indicates that an attempt to build either an inherited ACL or ACE was not successful. This can be caused by a number of things.
    /// One of the more probable causes is the replacement of a CreatorId with a SID that did not fit into the ACE or ACL.
    BAD_INHERITANCE_ACL = 0xC000007D,
    /// The range specified in NtUnlockFile was not locked.
    RANGE_NOT_LOCKED = 0xC000007E,
    /// An operation failed because the disk was full.
    DISK_FULL = 0xC000007F,
    /// The GUID allocation server is disabled at the moment.
    SERVER_DISABLED = 0xC0000080,
    /// The GUID allocation server is enabled at the moment.
    SERVER_NOT_DISABLED = 0xC0000081,
    /// Too many GUIDs were requested from the allocation server at once.
    TOO_MANY_GUIDS_REQUESTED = 0xC0000082,
    /// The GUIDs could not be allocated because the Authority Agent was exhausted.
    GUIDS_EXHAUSTED = 0xC0000083,
    /// The value provided was an invalid value for an identifier authority.
    INVALID_ID_AUTHORITY = 0xC0000084,
    /// No more authority agent values are available for the particular identifier authority value.
    AGENTS_EXHAUSTED = 0xC0000085,
    /// An invalid volume label has been specified.
    INVALID_VOLUME_LABEL = 0xC0000086,
    /// A mapped section could not be extended.
    SECTION_NOT_EXTENDED = 0xC0000087,
    /// Specified section to flush does not map a data file.
    NOT_MAPPED_DATA = 0xC0000088,
    /// Indicates the specified image file did not contain a resource section.
    RESOURCE_DATA_NOT_FOUND = 0xC0000089,
    /// Indicates the specified resource type cannot be found in the image file.
    RESOURCE_TYPE_NOT_FOUND = 0xC000008A,
    /// Indicates the specified resource name cannot be found in the image file.
    RESOURCE_NAME_NOT_FOUND = 0xC000008B,
    /// {EXCEPTION} Array bounds exceeded.
    ARRAY_BOUNDS_EXCEEDED = 0xC000008C,
    /// {EXCEPTION} Floating-point denormal operand.
    FLOAT_DENORMAL_OPERAND = 0xC000008D,
    /// {EXCEPTION} Floating-point division by zero.
    FLOAT_DIVIDE_BY_ZERO = 0xC000008E,
    /// {EXCEPTION} Floating-point inexact result.
    FLOAT_INEXACT_RESULT = 0xC000008F,
    /// {EXCEPTION} Floating-point invalid operation.
    FLOAT_INVALID_OPERATION = 0xC0000090,
    /// {EXCEPTION} Floating-point overflow.
    FLOAT_OVERFLOW = 0xC0000091,
    /// {EXCEPTION} Floating-point stack check.
    FLOAT_STACK_CHECK = 0xC0000092,
    /// {EXCEPTION} Floating-point underflow.
    FLOAT_UNDERFLOW = 0xC0000093,
    /// {EXCEPTION} Integer division by zero.
    INTEGER_DIVIDE_BY_ZERO = 0xC0000094,
    /// {EXCEPTION} Integer overflow.
    INTEGER_OVERFLOW = 0xC0000095,
    /// {EXCEPTION} Privileged instruction.
    PRIVILEGED_INSTRUCTION = 0xC0000096,
    /// An attempt was made to install more paging files than the system supports.
    TOO_MANY_PAGING_FILES = 0xC0000097,
    /// The volume for a file has been externally altered such that the opened file is no longer valid.
    FILE_INVALID = 0xC0000098,
    /// When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates might exceed the amount of memory originally allotted.
    /// Because a quota might already have been charged to several processes that have handles to the object, it is not reasonable to alter the size of the allocated memory.
    /// Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTTED_SPACE_EXCEEDED error returned.
    ALLOTTED_SPACE_EXCEEDED = 0xC0000099,
    /// Insufficient system resources exist to complete the API.
    INSUFFICIENT_RESOURCES = 0xC000009A,
    /// An attempt has been made to open a DFS exit path control file.
    DFS_EXIT_PATH_FOUND = 0xC000009B,
    /// There are bad blocks (sectors) on the hard disk.
    DEVICE_DATA_ERROR = 0xC000009C,
    /// There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk.
    DEVICE_NOT_CONNECTED = 0xC000009D,
    /// Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified.
    FREE_VM_NOT_AT_BASE = 0xC000009F,
    /// An attempt was made to free virtual memory that is not allocated.
    MEMORY_NOT_ALLOCATED = 0xC00000A0,
    /// The working set is not big enough to allow the requested pages to be locked.
    WORKING_SET_QUOTA = 0xC00000A1,
    /// {Write Protect Error} The disk cannot be written to because it is write-protected.
    /// Remove the write protection from the volume %hs in drive %hs.
    MEDIA_WRITE_PROTECTED = 0xC00000A2,
    /// {Drive Not Ready} The drive is not ready for use; its door might be open.
    /// Check drive %hs and make sure that a disk is inserted and that the drive door is closed.
    DEVICE_NOT_READY = 0xC00000A3,
    /// The specified attributes are invalid or are incompatible with the attributes for the group as a whole.
    INVALID_GROUP_ATTRIBUTES = 0xC00000A4,
    /// A specified impersonation level is invalid.
    /// Also used to indicate that a required impersonation level was not provided.
    BAD_IMPERSONATION_LEVEL = 0xC00000A5,
    /// An attempt was made to open an anonymous-level token. Anonymous tokens cannot be opened.
    CANT_OPEN_ANONYMOUS = 0xC00000A6,
    /// The validation information class requested was invalid.
    BAD_VALIDATION_CLASS = 0xC00000A7,
    /// The type of a token object is inappropriate for its attempted use.
    BAD_TOKEN_TYPE = 0xC00000A8,
    /// The type of a token object is inappropriate for its attempted use.
    BAD_MASTER_BOOT_RECORD = 0xC00000A9,
    /// An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references.
    INSTRUCTION_MISALIGNMENT = 0xC00000AA,
    /// The maximum named pipe instance count has been reached.
    INSTANCE_NOT_AVAILABLE = 0xC00000AB,
    /// An instance of a named pipe cannot be found in the listening state.
    PIPE_NOT_AVAILABLE = 0xC00000AC,
    /// The named pipe is not in the connected or closing state.
    INVALID_PIPE_STATE = 0xC00000AD,
    /// The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations.
    PIPE_BUSY = 0xC00000AE,
    /// The specified handle is not open to the server end of the named pipe.
    ILLEGAL_FUNCTION = 0xC00000AF,
    /// The specified named pipe is in the disconnected state.
    PIPE_DISCONNECTED = 0xC00000B0,
    /// The specified named pipe is in the closing state.
    PIPE_CLOSING = 0xC00000B1,
    /// The specified named pipe is in the connected state.
    PIPE_CONNECTED = 0xC00000B2,
    /// The specified named pipe is in the listening state.
    PIPE_LISTENING = 0xC00000B3,
    /// The specified named pipe is not in message mode.
    INVALID_READ_MODE = 0xC00000B4,
    /// {Device Timeout} The specified I/O operation on %hs was not completed before the time-out period expired.
    IO_TIMEOUT = 0xC00000B5,
    /// The specified file has been closed by another process.
    FILE_FORCED_CLOSED = 0xC00000B6,
    /// Profiling is not started.
    PROFILING_NOT_STARTED = 0xC00000B7,
    /// Profiling is not stopped.
    PROFILING_NOT_STOPPED = 0xC00000B8,
    /// The passed ACL did not contain the minimum required information.
    COULD_NOT_INTERPRET = 0xC00000B9,
    /// The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory.
    FILE_IS_A_DIRECTORY = 0xC00000BA,
    /// The request is not supported.
    NOT_SUPPORTED = 0xC00000BB,
    /// This remote computer is not listening.
    REMOTE_NOT_LISTENING = 0xC00000BC,
    /// A duplicate name exists on the network.
    DUPLICATE_NAME = 0xC00000BD,
    /// The network path cannot be located.
    BAD_NETWORK_PATH = 0xC00000BE,
    /// The network is busy.
    NETWORK_BUSY = 0xC00000BF,
    /// This device does not exist.
    DEVICE_DOES_NOT_EXIST = 0xC00000C0,
    /// The network BIOS command limit has been reached.
    TOO_MANY_COMMANDS = 0xC00000C1,
    /// An I/O adapter hardware error has occurred.
    ADAPTER_HARDWARE_ERROR = 0xC00000C2,
    /// The network responded incorrectly.
    INVALID_NETWORK_RESPONSE = 0xC00000C3,
    /// An unexpected network error occurred.
    UNEXPECTED_NETWORK_ERROR = 0xC00000C4,
    /// The remote adapter is not compatible.
    BAD_REMOTE_ADAPTER = 0xC00000C5,
    /// The print queue is full.
    PRINT_QUEUE_FULL = 0xC00000C6,
    /// Space to store the file that is waiting to be printed is not available on the server.
    NO_SPOOL_SPACE = 0xC00000C7,
    /// The requested print file has been canceled.
    PRINT_CANCELLED = 0xC00000C8,
    /// The network name was deleted.
    NETWORK_NAME_DELETED = 0xC00000C9,
    /// Network access is denied.
    NETWORK_ACCESS_DENIED = 0xC00000CA,
    /// {Incorrect Network Resource Type} The specified device type (LPT, for example) conflicts with the actual device type on the remote resource.
    BAD_DEVICE_TYPE = 0xC00000CB,
    /// {Network Name Not Found} The specified share name cannot be found on the remote server.
    BAD_NETWORK_NAME = 0xC00000CC,
    /// The name limit for the network adapter card of the local computer was exceeded.
    TOO_MANY_NAMES = 0xC00000CD,
    /// The network BIOS session limit was exceeded.
    TOO_MANY_SESSIONS = 0xC00000CE,
    /// File sharing has been temporarily paused.
    SHARING_PAUSED = 0xC00000CF,
    /// No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections.
    REQUEST_NOT_ACCEPTED = 0xC00000D0,
    /// Print or disk redirection is temporarily paused.
    REDIRECTOR_PAUSED = 0xC00000D1,
    /// A network data fault occurred.
    NET_WRITE_FAULT = 0xC00000D2,
    /// The number of active profiling objects is at the maximum and no more can be started.
    PROFILING_AT_LIMIT = 0xC00000D3,
    /// {Incorrect Volume} The destination file of a rename request is located on a different device than the source of the rename request.
    NOT_SAME_DEVICE = 0xC00000D4,
    /// The specified file has been renamed and thus cannot be modified.
    FILE_RENAMED = 0xC00000D5,
    /// {Network Request Timeout} The session with a remote server has been disconnected because the time-out interval for a request has expired.
    VIRTUAL_CIRCUIT_CLOSED = 0xC00000D6,
    /// Indicates an attempt was made to operate on the security of an object that does not have security associated with it.
    NO_SECURITY_ON_OBJECT = 0xC00000D7,
    /// Used to indicate that an operation cannot continue without blocking for I/O.
    CANT_WAIT = 0xC00000D8,
    /// Used to indicate that a read operation was done on an empty pipe.
    PIPE_EMPTY = 0xC00000D9,
    /// Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied.
    CANT_ACCESS_DOMAIN_INFO = 0xC00000DA,
    /// Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.
    CANT_TERMINATE_SELF = 0xC00000DB,
    /// Indicates the Sam Server was in the wrong state to perform the desired operation.
    INVALID_SERVER_STATE = 0xC00000DC,
    /// Indicates the domain was in the wrong state to perform the desired operation.
    INVALID_DOMAIN_STATE = 0xC00000DD,
    /// This operation is only allowed for the primary domain controller of the domain.
    INVALID_DOMAIN_ROLE = 0xC00000DE,
    /// The specified domain did not exist.
    NO_SUCH_DOMAIN = 0xC00000DF,
    /// The specified domain already exists.
    DOMAIN_EXISTS = 0xC00000E0,
    /// An attempt was made to exceed the limit on the number of domains per server for this release.
    DOMAIN_LIMIT_EXCEEDED = 0xC00000E1,
    /// An error status returned when the opportunistic lock (oplock) request is denied.
    OPLOCK_NOT_GRANTED = 0xC00000E2,
    /// An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system.
    INVALID_OPLOCK_PROTOCOL = 0xC00000E3,
    /// This error indicates that the requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption.
    INTERNAL_DB_CORRUPTION = 0xC00000E4,
    /// An internal error occurred.
    INTERNAL_ERROR = 0xC00000E5,
    /// Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types.
    GENERIC_NOT_MAPPED = 0xC00000E6,
    /// Indicates a security descriptor is not in the necessary format (absolute or self-relative).
    BAD_DESCRIPTOR_FORMAT = 0xC00000E7,
    /// An access to a user buffer failed at an expected point in time.
    /// This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter.
    INVALID_USER_BUFFER = 0xC00000E8,
    /// If an I/O error that is not defined in the standard FsRtl filter is returned, it is converted to the following error, which is guaranteed to be in the filter.
    /// In this case, information is lost; however, the filter correctly handles the exception.
    UNEXPECTED_IO_ERROR = 0xC00000E9,
    /// If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter.
    /// In this case, information is lost; however, the filter correctly handles the exception.
    UNEXPECTED_MM_CREATE_ERR = 0xC00000EA,
    /// If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter.
    /// In this case, information is lost; however, the filter correctly handles the exception.
    UNEXPECTED_MM_MAP_ERROR = 0xC00000EB,
    /// If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter.
    /// In this case, information is lost; however, the filter correctly handles the exception.
    UNEXPECTED_MM_EXTEND_ERR = 0xC00000EC,
    /// The requested action is restricted for use by logon processes only.
    /// The calling process has not registered as a logon process.
    NOT_LOGON_PROCESS = 0xC00000ED,
    /// An attempt has been made to start a new session manager or LSA logon session by using an ID that is already in use.
    LOGON_SESSION_EXISTS = 0xC00000EE,
    /// An invalid parameter was passed to a service or function as the first argument.
    INVALID_PARAMETER_1 = 0xC00000EF,
    /// An invalid parameter was passed to a service or function as the second argument.
    INVALID_PARAMETER_2 = 0xC00000F0,
    /// An invalid parameter was passed to a service or function as the third argument.
    INVALID_PARAMETER_3 = 0xC00000F1,
    /// An invalid parameter was passed to a service or function as the fourth argument.
    INVALID_PARAMETER_4 = 0xC00000F2,
    /// An invalid parameter was passed to a service or function as the fifth argument.
    INVALID_PARAMETER_5 = 0xC00000F3,
    /// An invalid parameter was passed to a service or function as the sixth argument.
    INVALID_PARAMETER_6 = 0xC00000F4,
    /// An invalid parameter was passed to a service or function as the seventh argument.
    INVALID_PARAMETER_7 = 0xC00000F5,
    /// An invalid parameter was passed to a service or function as the eighth argument.
    INVALID_PARAMETER_8 = 0xC00000F6,
    /// An invalid parameter was passed to a service or function as the ninth argument.
    INVALID_PARAMETER_9 = 0xC00000F7,
    /// An invalid parameter was passed to a service or function as the tenth argument.
    INVALID_PARAMETER_10 = 0xC00000F8,
    /// An invalid parameter was passed to a service or function as the eleventh argument.
    INVALID_PARAMETER_11 = 0xC00000F9,
    /// An invalid parameter was passed to a service or function as the twelfth argument.
    INVALID_PARAMETER_12 = 0xC00000FA,
    /// An attempt was made to access a network file, but the network software was not yet started.
    REDIRECTOR_NOT_STARTED = 0xC00000FB,
    /// An attempt was made to start the redirector, but the redirector has already been started.
    REDIRECTOR_STARTED = 0xC00000FC,
    /// A new guard page for the stack cannot be created.
    STACK_OVERFLOW = 0xC00000FD,
    /// A specified authentication package is unknown.
    NO_SUCH_PACKAGE = 0xC00000FE,
    /// A malformed function table was encountered during an unwind operation.
    BAD_FUNCTION_TABLE = 0xC00000FF,
    /// Indicates the specified environment variable name was not found in the specified environment block.
    VARIABLE_NOT_FOUND = 0xC0000100,
    /// Indicates that the directory trying to be deleted is not empty.
    DIRECTORY_NOT_EMPTY = 0xC0000101,
    /// {Corrupt File} The file or directory %hs is corrupt and unreadable. Run the Chkdsk utility.
    FILE_CORRUPT_ERROR = 0xC0000102,
    /// A requested opened file is not a directory.
    NOT_A_DIRECTORY = 0xC0000103,
    /// The logon session is not in a state that is consistent with the requested operation.
    BAD_LOGON_SESSION_STATE = 0xC0000104,
    /// An internal LSA error has occurred.
    /// An authentication package has requested the creation of a logon session but the ID of an already existing logon session has been specified.
    LOGON_SESSION_COLLISION = 0xC0000105,
    /// A specified name string is too long for its intended use.
    NAME_TOO_LONG = 0xC0000106,
    /// The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force.
    FILES_OPEN = 0xC0000107,
    /// The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force.
    CONNECTION_IN_USE = 0xC0000108,
    /// RtlFindMessage could not locate the requested message ID in the message table resource.
    MESSAGE_NOT_FOUND = 0xC0000109,
    /// An attempt was made to duplicate an object handle into or out of an exiting process.
    PROCESS_IS_TERMINATING = 0xC000010A,
    /// Indicates an invalid value has been provided for the LogonType requested.
    INVALID_LOGON_TYPE = 0xC000010B,
    /// Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system.
    /// This causes the protection attempt to fail, which might cause a file creation attempt to fail.
    NO_GUID_TRANSLATION = 0xC000010C,
    /// Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from.
    CANNOT_IMPERSONATE = 0xC000010D,
    /// Indicates that the specified image is already loaded.
    IMAGE_ALREADY_LOADED = 0xC000010E,
    /// Indicates that an attempt was made to change the size of the LDT for a process that has no LDT.
    NO_LDT = 0xC0000117,
    /// Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors.
    INVALID_LDT_SIZE = 0xC0000118,
    /// Indicates that the starting value for the LDT information was not an integral multiple of the selector size.
    INVALID_LDT_OFFSET = 0xC0000119,
    /// Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors.
    INVALID_LDT_DESCRIPTOR = 0xC000011A,
    /// The specified image file did not have the correct format. It appears to be NE format.
    INVALID_IMAGE_NE_FORMAT = 0xC000011B,
    /// Indicates that the transaction state of a registry subtree is incompatible with the requested operation.
    /// For example, a request has been made to start a new transaction with one already in progress, or a request has been made to apply a transaction when one is not currently in progress.
    RXACT_INVALID_STATE = 0xC000011C,
    /// Indicates an error has occurred during a registry transaction commit.
    /// The database has been left in an unknown, but probably inconsistent, state.
    /// The state of the registry transaction is left as COMMITTING.
    RXACT_COMMIT_FAILURE = 0xC000011D,
    /// An attempt was made to map a file of size zero with the maximum size specified as zero.
    MAPPED_FILE_SIZE_ZERO = 0xC000011E,
    /// Too many files are opened on a remote server.
    /// This error should only be returned by the Windows redirector on a remote drive.
    TOO_MANY_OPENED_FILES = 0xC000011F,
    /// The I/O request was canceled.
    CANCELLED = 0xC0000120,
    /// An attempt has been made to remove a file or directory that cannot be deleted.
    CANNOT_DELETE = 0xC0000121,
    /// Indicates a name that was specified as a remote computer name is syntactically invalid.
    INVALID_COMPUTER_NAME = 0xC0000122,
    /// An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose.
    FILE_DELETED = 0xC0000123,
    /// Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted.
    SPECIAL_ACCOUNT = 0xC0000124,
    /// The operation requested cannot be performed on the specified group because it is a built-in special group.
    SPECIAL_GROUP = 0xC0000125,
    /// The operation requested cannot be performed on the specified user because it is a built-in special user.
    SPECIAL_USER = 0xC0000126,
    /// Indicates a member cannot be removed from a group because the group is currently the member's primary group.
    MEMBERS_PRIMARY_GROUP = 0xC0000127,
    /// An I/O request other than close and several other special case operations was attempted using a file object that had already been closed.
    FILE_CLOSED = 0xC0000128,
    /// Indicates a process has too many threads to perform the requested action.
    /// For example, assignment of a primary token can be performed only when a process has zero or one threads.
    TOO_MANY_THREADS = 0xC0000129,
    /// An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process.
    THREAD_NOT_IN_PROCESS = 0xC000012A,
    /// An attempt was made to establish a token for use as a primary token but the token is already in use.
    /// A token can only be the primary token of one process at a time.
    TOKEN_ALREADY_IN_USE = 0xC000012B,
    /// The page file quota was exceeded.
    PAGEFILE_QUOTA_EXCEEDED = 0xC000012C,
    /// {Out of Virtual Memory} Your system is low on virtual memory.
    /// To ensure that Windows runs correctly, increase the size of your virtual memory paging file. For more information, see Help.
    COMMITMENT_LIMIT = 0xC000012D,
    /// The specified image file did not have the correct format: it appears to be LE format.
    INVALID_IMAGE_LE_FORMAT = 0xC000012E,
    /// The specified image file did not have the correct format: it did not have an initial MZ.
    INVALID_IMAGE_NOT_MZ = 0xC000012F,
    /// The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header.
    INVALID_IMAGE_PROTECT = 0xC0000130,
    /// The specified image file did not have the correct format: it appears to be a 16-bit Windows image.
    INVALID_IMAGE_WIN_16 = 0xC0000131,
    /// The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.
    LOGON_SERVER_CONFLICT = 0xC0000132,
    /// The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount.
    TIME_DIFFERENCE_AT_DC = 0xC0000133,
    /// On applicable Windows Server releases, the SAM database is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required.
    SYNCHRONIZATION_REQUIRED = 0xC0000134,
    /// {Unable To Locate Component} This application has failed to start because %hs was not found.
    /// Reinstalling the application might fix this problem.
    DLL_NOT_FOUND = 0xC0000135,
    /// The NtCreateFile API failed. This error should never be returned to an application; it is a place holder for the Windows LAN Manager Redirector to use in its internal error-mapping routines.
    OPEN_FAILED = 0xC0000136,
    /// {Privilege Failed} The I/O permissions for the process could not be changed.
    IO_PRIVILEGE_FAILED = 0xC0000137,
    /// {Ordinal Not Found} The ordinal %ld could not be located in the dynamic link library %hs.
    ORDINAL_NOT_FOUND = 0xC0000138,
    /// {Entry Point Not Found} The procedure entry point %hs could not be located in the dynamic link library %hs.
    ENTRYPOINT_NOT_FOUND = 0xC0000139,
    /// {Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.
    CONTROL_C_EXIT = 0xC000013A,
    /// {Virtual Circuit Closed} The network transport on your computer has closed a network connection.
    /// There might or might not be I/O requests outstanding.
    LOCAL_DISCONNECT = 0xC000013B,
    /// {Virtual Circuit Closed} The network transport on a remote computer has closed a network connection.
    /// There might or might not be I/O requests outstanding.
    REMOTE_DISCONNECT = 0xC000013C,
    /// {Insufficient Resources on Remote Computer} The remote computer has insufficient resources to complete the network request.
    /// For example, the remote computer might not have enough available memory to carry out the request at this time.
    REMOTE_RESOURCES = 0xC000013D,
    /// {Virtual Circuit Closed} An existing connection (virtual circuit) has been broken at the remote computer.
    /// There is probably something wrong with the network software protocol or the network hardware on the remote computer.
    LINK_FAILED = 0xC000013E,
    /// {Virtual Circuit Closed} The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer.
    LINK_TIMEOUT = 0xC000013F,
    /// The connection handle that was given to the transport was invalid.
    INVALID_CONNECTION = 0xC0000140,
    /// The address handle that was given to the transport was invalid.
    INVALID_ADDRESS = 0xC0000141,
    /// {DLL Initialization Failed} Initialization of the dynamic link library %hs failed. The process is terminating abnormally.
    DLL_INIT_FAILED = 0xC0000142,
    /// {Missing System File} The required system file %hs is bad or missing.
    MISSING_SYSTEMFILE = 0xC0000143,
    /// {Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.
    UNHANDLED_EXCEPTION = 0xC0000144,
    /// {Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application.
    APP_INIT_FAILURE = 0xC0000145,
    /// {Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.
    PAGEFILE_CREATE_FAILED = 0xC0000146,
    /// {No Paging File Specified} No paging file was specified in the system configuration.
    NO_PAGEFILE = 0xC0000147,
    /// {Incorrect System Call Level} An invalid level was passed into the specified system call.
    INVALID_LEVEL = 0xC0000148,
    /// {Incorrect Password to LAN Manager Server} You specified an incorrect password to a LAN Manager 2.x or MS-NET server.
    WRONG_PASSWORD_CORE = 0xC0000149,
    /// {EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present.
    ILLEGAL_FLOAT_CONTEXT = 0xC000014A,
    /// The pipe operation has failed because the other end of the pipe has been closed.
    PIPE_BROKEN = 0xC000014B,
    /// {The Registry Is Corrupt} The structure of one of the files that contains registry data is corrupt; the image of the file in memory is corrupt; or the file could not be recovered because the alternate copy or log was absent or corrupt.
    REGISTRY_CORRUPT = 0xC000014C,
    /// An I/O operation initiated by the Registry failed and cannot be recovered.
    /// The registry could not read in, write out, or flush one of the files that contain the system's image of the registry.
    REGISTRY_IO_FAILED = 0xC000014D,
    /// An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread.
    NO_EVENT_PAIR = 0xC000014E,
    /// The volume does not contain a recognized file system.
    /// Be sure that all required file system drivers are loaded and that the volume is not corrupt.
    UNRECOGNIZED_VOLUME = 0xC000014F,
    /// No serial device was successfully initialized. The serial driver will unload.
    SERIAL_NO_DEVICE_INITED = 0xC0000150,
    /// The specified local group does not exist.
    NO_SUCH_ALIAS = 0xC0000151,
    /// The specified account name is not a member of the group.
    MEMBER_NOT_IN_ALIAS = 0xC0000152,
    /// The specified account name is already a member of the group.
    MEMBER_IN_ALIAS = 0xC0000153,
    /// The specified local group already exists.
    ALIAS_EXISTS = 0xC0000154,
    /// A requested type of logon (for example, interactive, network, and service) is not granted by the local security policy of the target system.
    /// Ask the system administrator to grant the necessary form of logon.
    LOGON_NOT_GRANTED = 0xC0000155,
    /// The maximum number of secrets that can be stored in a single system was exceeded.
    /// The length and number of secrets is limited to satisfy U.S. State Department export restrictions.
    TOO_MANY_SECRETS = 0xC0000156,
    /// The length of a secret exceeds the maximum allowable length.
    /// The length and number of secrets is limited to satisfy U.S. State Department export restrictions.
    SECRET_TOO_LONG = 0xC0000157,
    /// The local security authority (LSA) database contains an internal inconsistency.
    INTERNAL_DB_ERROR = 0xC0000158,
    /// The requested operation cannot be performed in full-screen mode.
    FULLSCREEN_MODE = 0xC0000159,
    /// During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation.
    /// Remove the user from some global or local groups to reduce the number of security IDs to incorporate into the security context.
    TOO_MANY_CONTEXT_IDS = 0xC000015A,
    /// A user has requested a type of logon (for example, interactive or network) that has not been granted.
    /// An administrator has control over who can logon interactively and through the network.
    LOGON_TYPE_NOT_GRANTED = 0xC000015B,
    /// The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file.
    NOT_REGISTRY_FILE = 0xC000015C,
    /// An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password.
    NT_CROSS_ENCRYPTION_REQUIRED = 0xC000015D,
    /// A domain server has an incorrect configuration.
    DOMAIN_CTRLR_CONFIG_ERROR = 0xC000015E,
    /// An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system.
    FT_MISSING_MEMBER = 0xC000015F,
    /// A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries.
    ILL_FORMED_SERVICE_ENTRY = 0xC0000160,
    /// An illegal character was encountered.
    /// For a multibyte character set, this includes a lead byte without a succeeding trail byte.
    /// For the Unicode character set this includes the characters 0xFFFF and 0xFFFE.
    ILLEGAL_CHARACTER = 0xC0000161,
    /// No mapping for the Unicode character exists in the target multibyte code page.
    UNMAPPABLE_CHARACTER = 0xC0000162,
    /// The Unicode character is not defined in the Unicode character set that is installed on the system.
    UNDEFINED_CHARACTER = 0xC0000163,
    /// The paging file cannot be created on a floppy disk.
    FLOPPY_VOLUME = 0xC0000164,
    /// {Floppy Disk Error} While accessing a floppy disk, an ID address mark was not found.
    FLOPPY_ID_MARK_NOT_FOUND = 0xC0000165,
    /// {Floppy Disk Error} While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller.
    FLOPPY_WRONG_CYLINDER = 0xC0000166,
    /// {Floppy Disk Error} The floppy disk controller reported an error that is not recognized by the floppy disk driver.
    FLOPPY_UNKNOWN_ERROR = 0xC0000167,
    /// {Floppy Disk Error} While accessing a floppy-disk, the controller returned inconsistent results via its registers.
    FLOPPY_BAD_REGISTERS = 0xC0000168,
    /// {Hard Disk Error} While accessing the hard disk, a recalibrate operation failed, even after retries.
    DISK_RECALIBRATE_FAILED = 0xC0000169,
    /// {Hard Disk Error} While accessing the hard disk, a disk operation failed even after retries.
    DISK_OPERATION_FAILED = 0xC000016A,
    /// {Hard Disk Error} While accessing the hard disk, a disk controller reset was needed, but even that failed.
    DISK_RESET_FAILED = 0xC000016B,
    /// An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices.
    /// At least one other device that uses that IRQ was already opened.
    /// Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use.
    SHARED_IRQ_BUSY = 0xC000016C,
    /// {FT Orphaning} A disk that is part of a fault-tolerant volume can no longer be accessed.
    FT_ORPHANING = 0xC000016D,
    /// The basic input/output system (BIOS) failed to connect a system interrupt to the device or bus for which the device is connected.
    BIOS_FAILED_TO_CONNECT_INTERRUPT = 0xC000016E,
    /// The tape could not be partitioned.
    PARTITION_FAILURE = 0xC0000172,
    /// When accessing a new tape of a multi-volume partition, the current blocksize is incorrect.
    INVALID_BLOCK_LENGTH = 0xC0000173,
    /// The tape partition information could not be found when loading a tape.
    DEVICE_NOT_PARTITIONED = 0xC0000174,
    /// An attempt to lock the eject media mechanism failed.
    UNABLE_TO_LOCK_MEDIA = 0xC0000175,
    /// An attempt to unload media failed.
    UNABLE_TO_UNLOAD_MEDIA = 0xC0000176,
    /// The physical end of tape was detected.
    EOM_OVERFLOW = 0xC0000177,
    /// {No Media} There is no media in the drive. Insert media into drive %hs.
    NO_MEDIA = 0xC0000178,
    /// A member could not be added to or removed from the local group because the member does not exist.
    NO_SUCH_MEMBER = 0xC000017A,
    /// A new member could not be added to a local group because the member has the wrong account type.
    INVALID_MEMBER = 0xC000017B,
    /// An illegal operation was attempted on a registry key that has been marked for deletion.
    KEY_DELETED = 0xC000017C,
    /// The system could not allocate the required space in a registry log.
    NO_LOG_SPACE = 0xC000017D,
    /// Too many SIDs have been specified.
    TOO_MANY_SIDS = 0xC000017E,
    /// An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password.
    LM_CROSS_ENCRYPTION_REQUIRED = 0xC000017F,
    /// An attempt was made to create a symbolic link in a registry key that already has subkeys or values.
    KEY_HAS_CHILDREN = 0xC0000180,
    /// An attempt was made to create a stable subkey under a volatile parent key.
    CHILD_MUST_BE_VOLATILE = 0xC0000181,
    /// The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect.
    DEVICE_CONFIGURATION_ERROR = 0xC0000182,
    /// An error was detected between two drivers or within an I/O driver.
    DRIVER_INTERNAL_ERROR = 0xC0000183,
    /// The device is not in a valid state to perform this request.
    INVALID_DEVICE_STATE = 0xC0000184,
    /// The I/O device reported an I/O error.
    IO_DEVICE_ERROR = 0xC0000185,
    /// A protocol error was detected between the driver and the device.
    DEVICE_PROTOCOL_ERROR = 0xC0000186,
    /// This operation is only allowed for the primary domain controller of the domain.
    BACKUP_CONTROLLER = 0xC0000187,
    /// The log file space is insufficient to support this operation.
    LOG_FILE_FULL = 0xC0000188,
    /// A write operation was attempted to a volume after it was dismounted.
    TOO_LATE = 0xC0000189,
    /// The workstation does not have a trust secret for the primary domain in the local LSA database.
    NO_TRUST_LSA_SECRET = 0xC000018A,
    /// On applicable Windows Server releases, the SAM database does not have a computer account for this workstation trust relationship.
    NO_TRUST_SAM_ACCOUNT = 0xC000018B,
    /// The logon request failed because the trust relationship between the primary domain and the trusted domain failed.
    TRUSTED_DOMAIN_FAILURE = 0xC000018C,
    /// The logon request failed because the trust relationship between this workstation and the primary domain failed.
    TRUSTED_RELATIONSHIP_FAILURE = 0xC000018D,
    /// The Eventlog log file is corrupt.
    EVENTLOG_FILE_CORRUPT = 0xC000018E,
    /// No Eventlog log file could be opened. The Eventlog service did not start.
    EVENTLOG_CANT_START = 0xC000018F,
    /// The network logon failed. This might be because the validation authority cannot be reached.
    TRUST_FAILURE = 0xC0000190,
    /// An attempt was made to acquire a mutant such that its maximum count would have been exceeded.
    MUTANT_LIMIT_EXCEEDED = 0xC0000191,
    /// An attempt was made to logon, but the NetLogon service was not started.
    NETLOGON_NOT_STARTED = 0xC0000192,
    /// The user account has expired.
    ACCOUNT_EXPIRED = 0xC0000193,
    /// {EXCEPTION} Possible deadlock condition.
    POSSIBLE_DEADLOCK = 0xC0000194,
    /// Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed.
    /// Disconnect all previous connections to the server or shared resource and try again.
    NETWORK_CREDENTIAL_CONFLICT = 0xC0000195,
    /// An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.
    REMOTE_SESSION_LIMIT = 0xC0000196,
    /// The log file has changed between reads.
    EVENTLOG_FILE_CHANGED = 0xC0000197,
    /// The account used is an interdomain trust account.
    /// Use your global user account or local user account to access this server.
    NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 0xC0000198,
    /// The account used is a computer account.
    /// Use your global user account or local user account to access this server.
    NOLOGON_WORKSTATION_TRUST_ACCOUNT = 0xC0000199,
    /// The account used is a server trust account.
    /// Use your global user account or local user account to access this server.
    NOLOGON_SERVER_TRUST_ACCOUNT = 0xC000019A,
    /// The name or SID of the specified domain is inconsistent with the trust information for that domain.
    DOMAIN_TRUST_INCONSISTENT = 0xC000019B,
    /// A volume has been accessed for which a file system driver is required that has not yet been loaded.
    FS_DRIVER_REQUIRED = 0xC000019C,
    /// Indicates that the specified image is already loaded as a DLL.
    IMAGE_ALREADY_LOADED_AS_DLL = 0xC000019D,
    /// Short name settings cannot be changed on this volume due to the global registry setting.
    INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING = 0xC000019E,
    /// Short names are not enabled on this volume.
    SHORT_NAMES_NOT_ENABLED_ON_VOLUME = 0xC000019F,
    /// The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume.
    SECURITY_STREAM_IS_INCONSISTENT = 0xC00001A0,
    /// A requested file lock operation cannot be processed due to an invalid byte range.
    INVALID_LOCK_RANGE = 0xC00001A1,
    /// The specified access control entry (ACE) contains an invalid condition.
    INVALID_ACE_CONDITION = 0xC00001A2,
    /// The subsystem needed to support the image type is not present.
    IMAGE_SUBSYSTEM_NOT_PRESENT = 0xC00001A3,
    /// The specified file already has a notification GUID associated with it.
    NOTIFICATION_GUID_ALREADY_DEFINED = 0xC00001A4,
    /// A remote open failed because the network open restrictions were not satisfied.
    NETWORK_OPEN_RESTRICTION = 0xC0000201,
    /// There is no user session key for the specified logon session.
    NO_USER_SESSION_KEY = 0xC0000202,
    /// The remote user session has been deleted.
    USER_SESSION_DELETED = 0xC0000203,
    /// Indicates the specified resource language ID cannot be found in the image file.
    RESOURCE_LANG_NOT_FOUND = 0xC0000204,
    /// Insufficient server resources exist to complete the request.
    INSUFF_SERVER_RESOURCES = 0xC0000205,
    /// The size of the buffer is invalid for the specified operation.
    INVALID_BUFFER_SIZE = 0xC0000206,
    /// The transport rejected the specified network address as invalid.
    INVALID_ADDRESS_COMPONENT = 0xC0000207,
    /// The transport rejected the specified network address due to invalid use of a wildcard.
    INVALID_ADDRESS_WILDCARD = 0xC0000208,
    /// The transport address could not be opened because all the available addresses are in use.
    TOO_MANY_ADDRESSES = 0xC0000209,
    /// The transport address could not be opened because it already exists.
    ADDRESS_ALREADY_EXISTS = 0xC000020A,
    /// The transport address is now closed.
    ADDRESS_CLOSED = 0xC000020B,
    /// The transport connection is now disconnected.
    CONNECTION_DISCONNECTED = 0xC000020C,
    /// The transport connection has been reset.
    CONNECTION_RESET = 0xC000020D,
    /// The transport cannot dynamically acquire any more nodes.
    TOO_MANY_NODES = 0xC000020E,
    /// The transport aborted a pending transaction.
    TRANSACTION_ABORTED = 0xC000020F,
    /// The transport timed out a request that is waiting for a response.
    TRANSACTION_TIMED_OUT = 0xC0000210,
    /// The transport did not receive a release for a pending response.
    TRANSACTION_NO_RELEASE = 0xC0000211,
    /// The transport did not find a transaction that matches the specific token.
    TRANSACTION_NO_MATCH = 0xC0000212,
    /// The transport had previously responded to a transaction request.
    TRANSACTION_RESPONDED = 0xC0000213,
    /// The transport does not recognize the specified transaction request ID.
    TRANSACTION_INVALID_ID = 0xC0000214,
    /// The transport does not recognize the specified transaction request type.
    TRANSACTION_INVALID_TYPE = 0xC0000215,
    /// The transport can only process the specified request on the server side of a session.
    NOT_SERVER_SESSION = 0xC0000216,
    /// The transport can only process the specified request on the client side of a session.
    NOT_CLIENT_SESSION = 0xC0000217,
    /// {Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.
    CANNOT_LOAD_REGISTRY_FILE = 0xC0000218,
    /// {Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request.
    /// Choosing OK will terminate the process, and choosing Cancel will ignore the error.
    DEBUG_ATTACH_FAILED = 0xC0000219,
    /// {Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.
    SYSTEM_PROCESS_TERMINATED = 0xC000021A,
    /// {Data Not Accepted} The TDI client could not handle the data received during an indication.
    DATA_NOT_ACCEPTED = 0xC000021B,
    /// {Unable to Retrieve Browser Server List} The list of servers for this workgroup is not currently available.
    NO_BROWSER_SERVERS_FOUND = 0xC000021C,
    /// NTVDM encountered a hard error.
    VDM_HARD_ERROR = 0xC000021D,
    /// {Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time.
    DRIVER_CANCEL_TIMEOUT = 0xC000021E,
    /// {Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message.
    REPLY_MESSAGE_MISMATCH = 0xC000021F,
    /// {Mapped View Alignment Incorrect} An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity.
    MAPPED_ALIGNMENT = 0xC0000220,
    /// {Bad Image Checksum} The image %hs is possibly corrupt.
    /// The header checksum does not match the computed checksum.
    IMAGE_CHECKSUM_MISMATCH = 0xC0000221,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost.
    /// This error might be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere.
    LOST_WRITEBEHIND_DATA = 0xC0000222,
    /// The parameters passed to the server in the client/server shared memory window were invalid.
    /// Too much data might have been put in the shared memory window.
    CLIENT_SERVER_PARAMETERS_INVALID = 0xC0000223,
    /// The user password must be changed before logging on the first time.
    PASSWORD_MUST_CHANGE = 0xC0000224,
    /// The object was not found.
    NOT_FOUND = 0xC0000225,
    /// The stream is not a tiny stream.
    NOT_TINY_STREAM = 0xC0000226,
    /// A transaction recovery failed.
    RECOVERY_FAILURE = 0xC0000227,
    /// The request must be handled by the stack overflow code.
    STACK_OVERFLOW_READ = 0xC0000228,
    /// A consistency check failed.
    FAIL_CHECK = 0xC0000229,
    /// The attempt to insert the ID in the index failed because the ID is already in the index.
    DUPLICATE_OBJECTID = 0xC000022A,
    /// The attempt to set the object ID failed because the object already has an ID.
    OBJECTID_EXISTS = 0xC000022B,
    /// Internal OFS status codes indicating how an allocation operation is handled.
    /// Either it is retried after the containing oNode is moved or the extent stream is converted to a large stream.
    CONVERT_TO_LARGE = 0xC000022C,
    /// The request needs to be retried.
    RETRY = 0xC000022D,
    /// The attempt to find the object found an object on the volume that matches by ID; however, it is out of the scope of the handle that is used for the operation.
    FOUND_OUT_OF_SCOPE = 0xC000022E,
    /// The bucket array must be grown. Retry the transaction after doing so.
    ALLOCATE_BUCKET = 0xC000022F,
    /// The specified property set does not exist on the object.
    PROPSET_NOT_FOUND = 0xC0000230,
    /// The user/kernel marshaling buffer has overflowed.
    MARSHALL_OVERFLOW = 0xC0000231,
    /// The supplied variant structure contains invalid data.
    INVALID_VARIANT = 0xC0000232,
    /// A domain controller for this domain was not found.
    DOMAIN_CONTROLLER_NOT_FOUND = 0xC0000233,
    /// The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested.
    ACCOUNT_LOCKED_OUT = 0xC0000234,
    /// NtClose was called on a handle that was protected from close via NtSetInformationObject.
    HANDLE_NOT_CLOSABLE = 0xC0000235,
    /// The transport-connection attempt was refused by the remote system.
    CONNECTION_REFUSED = 0xC0000236,
    /// The transport connection was gracefully closed.
    GRACEFUL_DISCONNECT = 0xC0000237,
    /// The transport endpoint already has an address associated with it.
    ADDRESS_ALREADY_ASSOCIATED = 0xC0000238,
    /// An address has not yet been associated with the transport endpoint.
    ADDRESS_NOT_ASSOCIATED = 0xC0000239,
    /// An operation was attempted on a nonexistent transport connection.
    CONNECTION_INVALID = 0xC000023A,
    /// An invalid operation was attempted on an active transport connection.
    CONNECTION_ACTIVE = 0xC000023B,
    /// The remote network is not reachable by the transport.
    NETWORK_UNREACHABLE = 0xC000023C,
    /// The remote system is not reachable by the transport.
    HOST_UNREACHABLE = 0xC000023D,
    /// The remote system does not support the transport protocol.
    PROTOCOL_UNREACHABLE = 0xC000023E,
    /// No service is operating at the destination port of the transport on the remote system.
    PORT_UNREACHABLE = 0xC000023F,
    /// The request was aborted.
    REQUEST_ABORTED = 0xC0000240,
    /// The transport connection was aborted by the local system.
    CONNECTION_ABORTED = 0xC0000241,
    /// The specified buffer contains ill-formed data.
    BAD_COMPRESSION_BUFFER = 0xC0000242,
    /// The requested operation cannot be performed on a file with a user mapped section open.
    USER_MAPPED_FILE = 0xC0000243,
    /// {Audit Failed} An attempt to generate a security audit failed.
    AUDIT_FAILED = 0xC0000244,
    /// The timer resolution was not previously set by the current process.
    TIMER_RESOLUTION_NOT_SET = 0xC0000245,
    /// A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.
    CONNECTION_COUNT_LIMIT = 0xC0000246,
    /// Attempting to log on during an unauthorized time of day for this account.
    LOGIN_TIME_RESTRICTION = 0xC0000247,
    /// The account is not authorized to log on from this station.
    LOGIN_WKSTA_RESTRICTION = 0xC0000248,
    /// {UP/MP Image Mismatch} The image %hs has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine. Reinstall the image file.
    IMAGE_MP_UP_MISMATCH = 0xC0000249,
    /// There is insufficient account information to log you on.
    INSUFFICIENT_LOGON_INFO = 0xC0000250,
    /// {Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly.
    /// The stack pointer has been left in an inconsistent state.
    /// The entry point should be declared as WINAPI or STDCALL.
    /// Select YES to fail the DLL load. Select NO to continue execution.
    /// Selecting NO might cause the application to operate incorrectly.
    BAD_DLL_ENTRYPOINT = 0xC0000251,
    /// {Invalid Service Callback Entrypoint} The %hs service is not written correctly.
    /// The stack pointer has been left in an inconsistent state.
    /// The callback entry point should be declared as WINAPI or STDCALL.
    /// Selecting OK will cause the service to continue operation.
    /// However, the service process might operate incorrectly.
    BAD_SERVICE_ENTRYPOINT = 0xC0000252,
    /// The server received the messages but did not send a reply.
    LPC_REPLY_LOST = 0xC0000253,
    /// There is an IP address conflict with another system on the network.
    IP_ADDRESS_CONFLICT1 = 0xC0000254,
    /// There is an IP address conflict with another system on the network.
    IP_ADDRESS_CONFLICT2 = 0xC0000255,
    /// {Low On Registry Space} The system has reached the maximum size that is allowed for the system part of the registry. Additional storage requests will be ignored.
    REGISTRY_QUOTA_LIMIT = 0xC0000256,
    /// The contacted server does not support the indicated part of the DFS namespace.
    PATH_NOT_COVERED = 0xC0000257,
    /// A callback return system service cannot be executed when no callback is active.
    NO_CALLBACK_ACTIVE = 0xC0000258,
    /// The service being accessed is licensed for a particular number of connections.
    /// No more connections can be made to the service at this time because the service has already accepted the maximum number of connections.
    LICENSE_QUOTA_EXCEEDED = 0xC0000259,
    /// The password provided is too short to meet the policy of your user account. Choose a longer password.
    PWD_TOO_SHORT = 0xC000025A,
    /// The policy of your user account does not allow you to change passwords too frequently.
    /// This is done to prevent users from changing back to a familiar, but potentially discovered, password.
    /// If you feel your password has been compromised, contact your administrator immediately to have a new one assigned.
    PWD_TOO_RECENT = 0xC000025B,
    /// You have attempted to change your password to one that you have used in the past.
    /// The policy of your user account does not allow this.
    /// Select a password that you have not previously used.
    PWD_HISTORY_CONFLICT = 0xC000025C,
    /// You have attempted to load a legacy device driver while its device instance had been disabled.
    PLUGPLAY_NO_DEVICE = 0xC000025E,
    /// The specified compression format is unsupported.
    UNSUPPORTED_COMPRESSION = 0xC000025F,
    /// The specified hardware profile configuration is invalid.
    INVALID_HW_PROFILE = 0xC0000260,
    /// The specified Plug and Play registry device path is invalid.
    INVALID_PLUGPLAY_DEVICE_PATH = 0xC0000261,
    /// {Driver Entry Point Not Found} The %hs device driver could not locate the ordinal %ld in driver %hs.
    DRIVER_ORDINAL_NOT_FOUND = 0xC0000262,
    /// {Driver Entry Point Not Found} The %hs device driver could not locate the entry point %hs in driver %hs.
    DRIVER_ENTRYPOINT_NOT_FOUND = 0xC0000263,
    /// {Application Error} The application attempted to release a resource it did not own. Click OK to terminate the application.
    RESOURCE_NOT_OWNED = 0xC0000264,
    /// An attempt was made to create more links on a file than the file system supports.
    TOO_MANY_LINKS = 0xC0000265,
    /// The specified quota list is internally inconsistent with its descriptor.
    QUOTA_LIST_INCONSISTENT = 0xC0000266,
    /// The specified file has been relocated to offline storage.
    FILE_IS_OFFLINE = 0xC0000267,
    /// {Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour.
    /// To restore access to this installation of Windows, upgrade this installation by using a licensed distribution of this product.
    EVALUATION_EXPIRATION = 0xC0000268,
    /// {Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly.
    /// The relocation occurred because the DLL %hs occupied an address range that is reserved for Windows system DLLs.
    /// The vendor supplying the DLL should be contacted for a new DLL.
    ILLEGAL_DLL_RELOCATION = 0xC0000269,
    /// {License Violation} The system has detected tampering with your registered product type.
    /// This is a violation of your software license. Tampering with the product type is not permitted.
    LICENSE_VIOLATION = 0xC000026A,
    /// {DLL Initialization Failed} The application failed to initialize because the window station is shutting down.
    DLL_INIT_FAILED_LOGOFF = 0xC000026B,
    /// {Unable to Load Device Driver} %hs device driver could not be loaded. Error Status was 0x%x.
    DRIVER_UNABLE_TO_LOAD = 0xC000026C,
    /// DFS is unavailable on the contacted server.
    DFS_UNAVAILABLE = 0xC000026D,
    /// An operation was attempted to a volume after it was dismounted.
    VOLUME_DISMOUNTED = 0xC000026E,
    /// An internal error occurred in the Win32 x86 emulation subsystem.
    WX86_INTERNAL_ERROR = 0xC000026F,
    /// Win32 x86 emulation subsystem floating-point stack check.
    WX86_FLOAT_STACK_CHECK = 0xC0000270,
    /// The validation process needs to continue on to the next step.
    VALIDATE_CONTINUE = 0xC0000271,
    /// There was no match for the specified key in the index.
    NO_MATCH = 0xC0000272,
    /// There are no more matches for the current index enumeration.
    NO_MORE_MATCHES = 0xC0000273,
    /// The NTFS file or directory is not a reparse point.
    NOT_A_REPARSE_POINT = 0xC0000275,
    /// The Windows I/O reparse tag passed for the NTFS reparse point is invalid.
    IO_REPARSE_TAG_INVALID = 0xC0000276,
    /// The Windows I/O reparse tag does not match the one that is in the NTFS reparse point.
    IO_REPARSE_TAG_MISMATCH = 0xC0000277,
    /// The user data passed for the NTFS reparse point is invalid.
    IO_REPARSE_DATA_INVALID = 0xC0000278,
    /// The layered file system driver for this I/O tag did not handle it when needed.
    IO_REPARSE_TAG_NOT_HANDLED = 0xC0000279,
    /// The NTFS symbolic link could not be resolved even though the initial file name is valid.
    REPARSE_POINT_NOT_RESOLVED = 0xC0000280,
    /// The NTFS directory is a reparse point.
    DIRECTORY_IS_A_REPARSE_POINT = 0xC0000281,
    /// The range could not be added to the range list because of a conflict.
    RANGE_LIST_CONFLICT = 0xC0000282,
    /// The specified medium changer source element contains no media.
    SOURCE_ELEMENT_EMPTY = 0xC0000283,
    /// The specified medium changer destination element already contains media.
    DESTINATION_ELEMENT_FULL = 0xC0000284,
    /// The specified medium changer element does not exist.
    ILLEGAL_ELEMENT_ADDRESS = 0xC0000285,
    /// The specified element is contained in a magazine that is no longer present.
    MAGAZINE_NOT_PRESENT = 0xC0000286,
    /// The device requires re-initialization due to hardware errors.
    REINITIALIZATION_NEEDED = 0xC0000287,
    /// The file encryption attempt failed.
    ENCRYPTION_FAILED = 0xC000028A,
    /// The file decryption attempt failed.
    DECRYPTION_FAILED = 0xC000028B,
    /// The specified range could not be found in the range list.
    RANGE_NOT_FOUND = 0xC000028C,
    /// There is no encryption recovery policy configured for this system.
    NO_RECOVERY_POLICY = 0xC000028D,
    /// The required encryption driver is not loaded for this system.
    NO_EFS = 0xC000028E,
    /// The file was encrypted with a different encryption driver than is currently loaded.
    WRONG_EFS = 0xC000028F,
    /// There are no EFS keys defined for the user.
    NO_USER_KEYS = 0xC0000290,
    /// The specified file is not encrypted.
    FILE_NOT_ENCRYPTED = 0xC0000291,
    /// The specified file is not in the defined EFS export format.
    NOT_EXPORT_FORMAT = 0xC0000292,
    /// The specified file is encrypted and the user does not have the ability to decrypt it.
    FILE_ENCRYPTED = 0xC0000293,
    /// The GUID passed was not recognized as valid by a WMI data provider.
    WMI_GUID_NOT_FOUND = 0xC0000295,
    /// The instance name passed was not recognized as valid by a WMI data provider.
    WMI_INSTANCE_NOT_FOUND = 0xC0000296,
    /// The data item ID passed was not recognized as valid by a WMI data provider.
    WMI_ITEMID_NOT_FOUND = 0xC0000297,
    /// The WMI request could not be completed and should be retried.
    WMI_TRY_AGAIN = 0xC0000298,
    /// The policy object is shared and can only be modified at the root.
    SHARED_POLICY = 0xC0000299,
    /// The policy object does not exist when it should.
    POLICY_OBJECT_NOT_FOUND = 0xC000029A,
    /// The requested policy information only lives in the Ds.
    POLICY_ONLY_IN_DS = 0xC000029B,
    /// The volume must be upgraded to enable this feature.
    VOLUME_NOT_UPGRADED = 0xC000029C,
    /// The remote storage service is not operational at this time.
    REMOTE_STORAGE_NOT_ACTIVE = 0xC000029D,
    /// The remote storage service encountered a media error.
    REMOTE_STORAGE_MEDIA_ERROR = 0xC000029E,
    /// The tracking (workstation) service is not running.
    NO_TRACKING_SERVICE = 0xC000029F,
    /// The server process is running under a SID that is different from the SID that is required by client.
    SERVER_SID_MISMATCH = 0xC00002A0,
    /// The specified directory service attribute or value does not exist.
    DS_NO_ATTRIBUTE_OR_VALUE = 0xC00002A1,
    /// The attribute syntax specified to the directory service is invalid.
    DS_INVALID_ATTRIBUTE_SYNTAX = 0xC00002A2,
    /// The attribute type specified to the directory service is not defined.
    DS_ATTRIBUTE_TYPE_UNDEFINED = 0xC00002A3,
    /// The specified directory service attribute or value already exists.
    DS_ATTRIBUTE_OR_VALUE_EXISTS = 0xC00002A4,
    /// The directory service is busy.
    DS_BUSY = 0xC00002A5,
    /// The directory service is unavailable.
    DS_UNAVAILABLE = 0xC00002A6,
    /// The directory service was unable to allocate a relative identifier.
    DS_NO_RIDS_ALLOCATED = 0xC00002A7,
    /// The directory service has exhausted the pool of relative identifiers.
    DS_NO_MORE_RIDS = 0xC00002A8,
    /// The requested operation could not be performed because the directory service is not the master for that type of operation.
    DS_INCORRECT_ROLE_OWNER = 0xC00002A9,
    /// The directory service was unable to initialize the subsystem that allocates relative identifiers.
    DS_RIDMGR_INIT_ERROR = 0xC00002AA,
    /// The requested operation did not satisfy one or more constraints that are associated with the class of the object.
    DS_OBJ_CLASS_VIOLATION = 0xC00002AB,
    /// The directory service can perform the requested operation only on a leaf object.
    DS_CANT_ON_NON_LEAF = 0xC00002AC,
    /// The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object.
    DS_CANT_ON_RDN = 0xC00002AD,
    /// The directory service detected an attempt to modify the object class of an object.
    DS_CANT_MOD_OBJ_CLASS = 0xC00002AE,
    /// An error occurred while performing a cross domain move operation.
    DS_CROSS_DOM_MOVE_FAILED = 0xC00002AF,
    /// Unable to contact the global catalog server.
    DS_GC_NOT_AVAILABLE = 0xC00002B0,
    /// The requested operation requires a directory service, and none was available.
    DIRECTORY_SERVICE_REQUIRED = 0xC00002B1,
    /// The reparse attribute cannot be set because it is incompatible with an existing attribute.
    REPARSE_ATTRIBUTE_CONFLICT = 0xC00002B2,
    /// A group marked "use for deny only" cannot be enabled.
    CANT_ENABLE_DENY_ONLY = 0xC00002B3,
    /// {EXCEPTION} Multiple floating-point faults.
    FLOAT_MULTIPLE_FAULTS = 0xC00002B4,
    /// {EXCEPTION} Multiple floating-point traps.
    FLOAT_MULTIPLE_TRAPS = 0xC00002B5,
    /// The device has been removed.
    DEVICE_REMOVED = 0xC00002B6,
    /// The volume change journal is being deleted.
    JOURNAL_DELETE_IN_PROGRESS = 0xC00002B7,
    /// The volume change journal is not active.
    JOURNAL_NOT_ACTIVE = 0xC00002B8,
    /// The requested interface is not supported.
    NOINTERFACE = 0xC00002B9,
    /// A directory service resource limit has been exceeded.
    DS_ADMIN_LIMIT_EXCEEDED = 0xC00002C1,
    /// {System Standby Failed} The driver %hs does not support standby mode.
    /// Updating this driver allows the system to go to standby mode.
    DRIVER_FAILED_SLEEP = 0xC00002C2,
    /// Mutual Authentication failed. The server password is out of date at the domain controller.
    MUTUAL_AUTHENTICATION_FAILED = 0xC00002C3,
    /// The system file %1 has become corrupt and has been replaced.
    CORRUPT_SYSTEM_FILE = 0xC00002C4,
    /// {EXCEPTION} Alignment Error A data type misalignment error was detected in a load or store instruction.
    DATATYPE_MISALIGNMENT_ERROR = 0xC00002C5,
    /// The WMI data item or data block is read-only.
    WMI_READ_ONLY = 0xC00002C6,
    /// The WMI data item or data block could not be changed.
    WMI_SET_FAILU```
