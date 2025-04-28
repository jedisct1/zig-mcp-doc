```
pped at the address specified in the image file. Local fixups must be performed on this image.
    IMAGE_NOT_AT_BASE = 700,
    /// This informational level status indicates that a specified registry sub-tree transaction state did not yet exist and had to be created.
    RXACT_STATE_CREATED = 701,
    /// {Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image.
    /// An exception is raised so a debugger can load, unload or track symbols and breakpoints within these 16-bit segments.
    SEGMENT_NOTIFICATION = 702,
    /// {Invalid Current Directory} The process cannot switch to the startup current directory %hs.
    /// Select OK to set current directory to %hs, or select CANCEL to exit.
    BAD_CURRENT_DIRECTORY = 703,
    /// {Redundant Read} To satisfy a read request, the NT fault-tolerant file system successfully read the requested data from a redundant copy.
    /// This was done because the file system encountered a failure on a member of the fault-tolerant volume, but was unable to reassign the failing area of the device.
    FT_READ_RECOVERY_FROM_BACKUP = 704,
    /// {Redundant Write} To satisfy a write request, the NT fault-tolerant file system successfully wrote a redundant copy of the information.
    /// This was done because the file system encountered a failure on a member of the fault-tolerant volume, but was not able to reassign the failing area of the device.
    FT_WRITE_RECOVERY = 705,
    /// {Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine.
    /// Select OK to continue, or CANCEL to fail the DLL load.
    IMAGE_MACHINE_TYPE_MISMATCH = 706,
    /// {Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later.
    RECEIVE_PARTIAL = 707,
    /// {Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system.
    RECEIVE_EXPEDITED = 708,
    /// {Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later.
    RECEIVE_PARTIAL_EXPEDITED = 709,
    /// {TDI Event Done} The TDI indication has completed successfully.
    EVENT_DONE = 710,
    /// {TDI Event Pending} The TDI indication has entered the pending state.
    EVENT_PENDING = 711,
    /// Checking file system on %wZ.
    CHECKING_FILE_SYSTEM = 712,
    /// {Fatal Application Exit} %hs.
    FATAL_APP_EXIT = 713,
    /// The specified registry key is referenced by a predefined handle.
    PREDEFINED_HANDLE = 714,
    /// {Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process.
    WAS_UNLOCKED = 715,
    /// %hs
    SERVICE_NOTIFICATION = 716,
    /// {Page Locked} One of the pages to lock was already locked.
    WAS_LOCKED = 717,
    /// Application popup: %1 : %2
    LOG_HARD_ERROR = 718,
    /// ERROR_ALREADY_WIN32
    ALREADY_WIN32 = 719,
    /// {Machine Type Mismatch} The image file %hs is valid, but is for a machine type other than the current machine.
    IMAGE_MACHINE_TYPE_MISMATCH_EXE = 720,
    /// A yield execution was performed and no thread was available to run.
    NO_YIELD_PERFORMED = 721,
    /// The resumable flag to a timer API was ignored.
    TIMER_RESUME_IGNORED = 722,
    /// The arbiter has deferred arbitration of these resources to its parent.
    ARBITRATION_UNHANDLED = 723,
    /// The inserted CardBus device cannot be started because of a configuration error on "%hs".
    CARDBUS_NOT_SUPPORTED = 724,
    /// The CPUs in this multiprocessor system are not all the same revision level.
    /// To use all processors the operating system restricts itself to the features of the least capable processor in the system.
    /// Should problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported.
    MP_PROCESSOR_MISMATCH = 725,
    /// The system was put into hibernation.
    HIBERNATED = 726,
    /// The system was resumed from hibernation.
    RESUME_HIBERNATION = 727,
    /// Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3].
    FIRMWARE_UPDATED = 728,
    /// A device driver is leaking locked I/O pages causing system degradation.
    /// The system has automatically enabled tracking code in order to try and catch the culprit.
    DRIVERS_LEAKING_LOCKED_PAGES = 729,
    /// The system has awoken.
    WAKE_SYSTEM = 730,
    /// ERROR_WAIT_1
    WAIT_1 = 731,
    /// ERROR_WAIT_2
    WAIT_2 = 732,
    /// ERROR_WAIT_3
    WAIT_3 = 733,
    /// ERROR_WAIT_63
    WAIT_63 = 734,
    /// ERROR_ABANDONED_WAIT_0
    ABANDONED_WAIT_0 = 735,
    /// ERROR_ABANDONED_WAIT_63
    ABANDONED_WAIT_63 = 736,
    /// ERROR_USER_APC
    USER_APC = 737,
    /// ERROR_KERNEL_APC
    KERNEL_APC = 738,
    /// ERROR_ALERTED
    ALERTED = 739,
    /// The requested operation requires elevation.
    ELEVATION_REQUIRED = 740,
    /// A reparse should be performed by the Object Manager since the name of the file resulted in a symbolic link.
    REPARSE = 741,
    /// An open/create operation completed while an oplock break is underway.
    OPLOCK_BREAK_IN_PROGRESS = 742,
    /// A new volume has been mounted by a file system.
    VOLUME_MOUNTED = 743,
    /// This success level status indicates that the transaction state already exists for the registry sub-tree, but that a transaction commit was previously aborted. The commit has now been completed.
    RXACT_COMMITTED = 744,
    /// This indicates that a notify change request has been completed due to closing the handle which made the notify change request.
    NOTIFY_CLEANUP = 745,
    /// {Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed.
    /// The computer WAS able to connect on a secondary transport.
    PRIMARY_TRANSPORT_CONNECT_FAILED = 746,
    /// Page fault was a transition fault.
    PAGE_FAULT_TRANSITION = 747,
    /// Page fault was a demand zero fault.
    PAGE_FAULT_DEMAND_ZERO = 748,
    /// Page fault was a demand zero fault.
    PAGE_FAULT_COPY_ON_WRITE = 749,
    /// Page fault was a demand zero fault.
    PAGE_FAULT_GUARD_PAGE = 750,
    /// Page fault was satisfied by reading from a secondary storage device.
    PAGE_FAULT_PAGING_FILE = 751,
    /// Cached page was locked during operation.
    CACHE_PAGE_LOCKED = 752,
    /// Crash dump exists in paging file.
    CRASH_DUMP = 753,
    /// Specified buffer contains all zeros.
    BUFFER_ALL_ZEROS = 754,
    /// A reparse should be performed by the Object Manager since the name of the file resulted in a symbolic link.
    REPARSE_OBJECT = 755,
    /// The device has succeeded a query-stop and its resource requirements have changed.
    RESOURCE_REQUIREMENTS_CHANGED = 756,
    /// The translator has translated these resources into the global space and no further translations should be performed.
    TRANSLATION_COMPLETE = 757,
    /// A process being terminated has no threads to terminate.
    NOTHING_TO_TERMINATE = 758,
    /// The specified process is not part of a job.
    PROCESS_NOT_IN_JOB = 759,
    /// The specified process is part of a job.
    PROCESS_IN_JOB = 760,
    /// {Volume Shadow Copy Service} The system is now ready for hibernation.
    VOLSNAP_HIBERNATE_READY = 761,
    /// A file system or file system filter driver has successfully completed an FsFilter operation.
    FSFILTER_OP_COMPLETED_SUCCESSFULLY = 762,
    /// The specified interrupt vector was already connected.
    INTERRUPT_VECTOR_ALREADY_CONNECTED = 763,
    /// The specified interrupt vector is still connected.
    INTERRUPT_STILL_CONNECTED = 764,
    /// An operation is blocked waiting for an oplock.
    WAIT_FOR_OPLOCK = 765,
    /// Debugger handled exception.
    DBG_EXCEPTION_HANDLED = 766,
    /// Debugger continued.
    DBG_CONTINUE = 767,
    /// An exception occurred in a user mode callback and the kernel callback frame should be removed.
    CALLBACK_POP_STACK = 768,
    /// Compression is disabled for this volume.
    COMPRESSION_DISABLED = 769,
    /// The data provider cannot fetch backwards through a result set.
    CANTFETCHBACKWARDS = 770,
    /// The data provider cannot scroll backwards through a result set.
    CANTSCROLLBACKWARDS = 771,
    /// The data provider requires that previously fetched data is released before asking for more data.
    ROWSNOTRELEASED = 772,
    /// The data provider was not able to interpret the flags set for a column binding in an accessor.
    BAD_ACCESSOR_FLAGS = 773,
    /// One or more errors occurred while processing the request.
    ERRORS_ENCOUNTERED = 774,
    /// The implementation is not capable of performing the request.
    NOT_CAPABLE = 775,
    /// The client of a component requested an operation which is not valid given the state of the component instance.
    REQUEST_OUT_OF_SEQUENCE = 776,
    /// A version number could not be parsed.
    VERSION_PARSE_ERROR = 777,
    /// The iterator's start position is invalid.
    BADSTARTPOSITION = 778,
    /// The hardware has reported an uncorrectable memory error.
    MEMORY_HARDWARE = 779,
    /// The attempted operation required self healing to be enabled.
    DISK_REPAIR_DISABLED = 780,
    /// The Desktop heap encountered an error while allocating session memory.
    /// There is more information in the system event log.
    INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE = 781,
    /// The system power state is transitioning from %2 to %3.
    SYSTEM_POWERSTATE_TRANSITION = 782,
    /// The system power state is transitioning from %2 to %3 but could enter %4.
    SYSTEM_POWERSTATE_COMPLEX_TRANSITION = 783,
    /// A thread is getting dispatched with MCA EXCEPTION because of MCA.
    MCA_EXCEPTION = 784,
    /// Access to %1 is monitored by policy rule %2.
    ACCESS_AUDIT_BY_POLICY = 785,
    /// Access to %1 has been restricted by your Administrator by policy rule %2.
    ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY = 786,
    /// A valid hibernation file has been invalidated and should be abandoned.
    ABANDON_HIBERFILE = 787,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost.
    /// This error may be caused by network connectivity issues. Please try to save this file elsewhere.
    LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED = 788,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost.
    /// This error was returned by the server on which the file exists. Please try to save this file elsewhere.
    LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR = 789,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost.
    /// This error may be caused if the device has been removed or the media is write-protected.
    LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR = 790,
    /// The resources required for this device conflict with the MCFG table.
    BAD_MCFG_TABLE = 791,
    /// The volume repair could not be performed while it is online.
    /// Please schedule to take the volume offline so that it can be repaired.
    DISK_REPAIR_REDIRECTED = 792,
    /// The volume repair was not successful.
    DISK_REPAIR_UNSUCCESSFUL = 793,
    /// One of the volume corruption logs is full.
    /// Further corruptions that may be detected won't be logged.
    CORRUPT_LOG_OVERFULL = 794,
    /// One of the volume corruption logs is internally corrupted and needs to be recreated.
    /// The volume may contain undetected corruptions and must be scanned.
    CORRUPT_LOG_CORRUPTED = 795,
    /// One of the volume corruption logs is unavailable for being operated on.
    CORRUPT_LOG_UNAVAILABLE = 796,
    /// One of the volume corruption logs was deleted while still having corruption records in them.
    /// The volume contains detected corruptions and must be scanned.
    CORRUPT_LOG_DELETED_FULL = 797,
    /// One of the volume corruption logs was cleared by chkdsk and no longer contains real corruptions.
    CORRUPT_LOG_CLEARED = 798,
    /// Orphaned files exist on the volume but could not be recovered because no more new names could be created in the recovery directory. Files must be moved from the recovery directory.
    ORPHAN_NAME_EXHAUSTED = 799,
    /// The oplock that was associated with this handle is now associated with a different handle.
    OPLOCK_SWITCHED_TO_NEW_HANDLE = 800,
    /// An oplock of the requested level cannot be granted. An oplock of a lower level may be available.
    CANNOT_GRANT_REQUESTED_OPLOCK = 801,
    /// The operation did not complete successfully because it would cause an oplock to be broken.
    /// The caller has requested that existing oplocks not be broken.
    CANNOT_BREAK_OPLOCK = 802,
    /// The handle with which this oplock was associated has been closed. The oplock is now broken.
    OPLOCK_HANDLE_CLOSED = 803,
    /// The specified access control entry (ACE) does not contain a condition.
    NO_ACE_CONDITION = 804,
    /// The specified access control entry (ACE) contains an invalid condition.
    INVALID_ACE_CONDITION = 805,
    /// Access to the specified file handle has been revoked.
    FILE_HANDLE_REVOKED = 806,
    /// An image file was mapped at a different address from the one specified in the image file but fixups will still be automatically performed on the image.
    IMAGE_AT_DIFFERENT_BASE = 807,
    /// Access to the extended attribute was denied.
    EA_ACCESS_DENIED = 994,
    /// The I/O operation has been aborted because of either a thread exit or an application request.
    OPERATION_ABORTED = 995,
    /// Overlapped I/O event is not in a signaled state.
    IO_INCOMPLETE = 996,
    /// Overlapped I/O operation is in progress.
    IO_PENDING = 997,
    /// Invalid access to memory location.
    NOACCESS = 998,
    /// Error performing inpage operation.
    SWAPERROR = 999,
    /// Recursion too deep; the stack overflowed.
    STACK_OVERFLOW = 1001,
    /// The window cannot act on the sent message.
    INVALID_MESSAGE = 1002,
    /// Cannot complete this function.
    CAN_NOT_COMPLETE = 1003,
    /// Invalid flags.
    INVALID_FLAGS = 1004,
    /// The volume does not contain a recognized file system.
    /// Please make sure that all required file system drivers are loaded and that the volume is not corrupted.
    UNRECOGNIZED_VOLUME = 1005,
    /// The volume for a file has been externally altered so that the opened file is no longer valid.
    FILE_INVALID = 1006,
    /// The requested operation cannot be performed in full-screen mode.
    FULLSCREEN_MODE = 1007,
    /// An attempt was made to reference a token that does not exist.
    NO_TOKEN = 1008,
    /// The configuration registry database is corrupt.
    BADDB = 1009,
    /// The configuration registry key is invalid.
    BADKEY = 1010,
    /// The configuration registry key could not be opened.
    CANTOPEN = 1011,
    /// The configuration registry key could not be read.
    CANTREAD = 1012,
    /// The configuration registry key could not be written.
    CANTWRITE = 1013,
    /// One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful.
    REGISTRY_RECOVERED = 1014,
    /// The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted.
    REGISTRY_CORRUPT = 1015,
    /// An I/O operation initiated by the registry failed unrecoverably.
    /// The registry could not read in, or write out, or flush, one of the files that contain the system's image of the registry.
    REGISTRY_IO_FAILED = 1016,
    /// The system has attempted to load or restore a file into the registry, but the specified file is not in a registry file format.
    NOT_REGISTRY_FILE = 1017,
    /// Illegal operation attempted on a registry key that has been marked for deletion.
    KEY_DELETED = 1018,
    /// System could not allocate the required space in a registry log.
    NO_LOG_SPACE = 1019,
    /// Cannot create a symbolic link in a registry key that already has subkeys or values.
    KEY_HAS_CHILDREN = 1020,
    /// Cannot create a stable subkey under a volatile parent key.
    CHILD_MUST_BE_VOLATILE = 1021,
    /// A notify change request is being completed and the information is not being returned in the caller's buffer.
    /// The caller now needs to enumerate the files to find the changes.
    NOTIFY_ENUM_DIR = 1022,
    /// A stop control has been sent to a service that other running services are dependent on.
    DEPENDENT_SERVICES_RUNNING = 1051,
    /// The requested control is not valid for this service.
    INVALID_SERVICE_CONTROL = 1052,
    /// The service did not respond to the start or control request in a timely fashion.
    SERVICE_REQUEST_TIMEOUT = 1053,
    /// A thread could not be created for the service.
    SERVICE_NO_THREAD = 1054,
    /// The service database is locked.
    SERVICE_DATABASE_LOCKED = 1055,
    /// An instance of the service is already running.
    SERVICE_ALREADY_RUNNING = 1056,
    /// The account name is invalid or does not exist, or the password is invalid for the account name specified.
    INVALID_SERVICE_ACCOUNT = 1057,
    /// The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
    SERVICE_DISABLED = 1058,
    /// Circular service dependency was specified.
    CIRCULAR_DEPENDENCY = 1059,
    /// The specified service does not exist as an installed service.
    SERVICE_DOES_NOT_EXIST = 1060,
    /// The service cannot accept control messages at this time.
    SERVICE_CANNOT_ACCEPT_CTRL = 1061,
    /// The service has not been started.
    SERVICE_NOT_ACTIVE = 1062,
    /// The service process could not connect to the service controller.
    FAILED_SERVICE_CONTROLLER_CONNECT = 1063,
    /// An exception occurred in the service when handling the control request.
    EXCEPTION_IN_SERVICE = 1064,
    /// The database specified does not exist.
    DATABASE_DOES_NOT_EXIST = 1065,
    /// The service has returned a service-specific error code.
    SERVICE_SPECIFIC_ERROR = 1066,
    /// The process terminated unexpectedly.
    PROCESS_ABORTED = 1067,
    /// The dependency service or group failed to start.
    SERVICE_DEPENDENCY_FAIL = 1068,
    /// The service did not start due to a logon failure.
    SERVICE_LOGON_FAILED = 1069,
    /// After starting, the service hung in a start-pending state.
    SERVICE_START_HANG = 1070,
    /// The specified service database lock is invalid.
    INVALID_SERVICE_LOCK = 1071,
    /// The specified service has been marked for deletion.
    SERVICE_MARKED_FOR_DELETE = 1072,
    /// The specified service already exists.
    SERVICE_EXISTS = 1073,
    /// The system is currently running with the last-known-good configuration.
    ALREADY_RUNNING_LKG = 1074,
    /// The dependency service does not exist or has been marked for deletion.
    SERVICE_DEPENDENCY_DELETED = 1075,
    /// The current boot has already been accepted for use as the last-known-good control set.
    BOOT_ALREADY_ACCEPTED = 1076,
    /// No attempts to start the service have been made since the last boot.
    SERVICE_NEVER_STARTED = 1077,
    /// The name is already in use as either a service name or a service display name.
    DUPLICATE_SERVICE_NAME = 1078,
    /// The account specified for this service is different from the account specified for other services running in the same process.
    DIFFERENT_SERVICE_ACCOUNT = 1079,
    /// Failure actions can only be set for Win32 services, not for drivers.
    CANNOT_DETECT_DRIVER_FAILURE = 1080,
    /// This service runs in the same process as the service control manager.
    /// Therefore, the service control manager cannot take action if this service's process terminates unexpectedly.
    CANNOT_DETECT_PROCESS_ABORT = 1081,
    /// No recovery program has been configured for this service.
    NO_RECOVERY_PROGRAM = 1082,
    /// The executable program that this service is configured to run in does not implement the service.
    SERVICE_NOT_IN_EXE = 1083,
    /// This service cannot be started in Safe Mode.
    NOT_SAFEBOOT_SERVICE = 1084,
    /// The physical end of the tape has been reached.
    END_OF_MEDIA = 1100,
    /// A tape access reached a filemark.
    FILEMARK_DETECTED = 1101,
    /// The beginning of the tape or a partition was encountered.
    BEGINNING_OF_MEDIA = 1102,
    /// A tape access reached the end of a set of files.
    SETMARK_DETECTED = 1103,
    /// No more data is on the tape.
    NO_DATA_DETECTED = 1104,
    /// Tape could not be partitioned.
    PARTITION_FAILURE = 1105,
    /// When accessing a new tape of a multivolume partition, the current block size is incorrect.
    INVALID_BLOCK_LENGTH = 1106,
    /// Tape partition information could not be found when loading a tape.
    DEVICE_NOT_PARTITIONED = 1107,
    /// Unable to lock the media eject mechanism.
    UNABLE_TO_LOCK_MEDIA = 1108,
    /// Unable to unload the media.
    UNABLE_TO_UNLOAD_MEDIA = 1109,
    /// The media in the drive may have changed.
    MEDIA_CHANGED = 1110,
    /// The I/O bus was reset.
    BUS_RESET = 1111,
    /// No media in drive.
    NO_MEDIA_IN_DRIVE = 1112,
    /// No mapping for the Unicode character exists in the target multi-byte code page.
    NO_UNICODE_TRANSLATION = 1113,
    /// A dynamic link library (DLL) initialization routine failed.
    DLL_INIT_FAILED = 1114,
    /// A system shutdown is in progress.
    SHUTDOWN_IN_PROGRESS = 1115,
    /// Unable to abort the system shutdown because no shutdown was in progress.
    NO_SHUTDOWN_IN_PROGRESS = 1116,
    /// The request could not be performed because of an I/O device error.
    IO_DEVICE = 1117,
    /// No serial device was successfully initialized. The serial driver will unload.
    SERIAL_NO_DEVICE = 1118,
    /// Unable to open a device that was sharing an interrupt request (IRQ) with other devices.
    /// At least one other device that uses that IRQ was already opened.
    IRQ_BUSY = 1119,
    /// A serial I/O operation was completed by another write to the serial port. The IOCTL_SERIAL_XOFF_COUNTER reached zero.)
    MORE_WRITES = 1120,
    /// A serial I/O operation completed because the timeout period expired.
    /// The IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)
    COUNTER_TIMEOUT = 1121,
    /// No ID address mark was found on the floppy disk.
    FLOPPY_ID_MARK_NOT_FOUND = 1122,
    /// Mismatch between the floppy disk sector ID field and the floppy disk controller track address.
    FLOPPY_WRONG_CYLINDER = 1123,
    /// The floppy disk controller reported an error that is not recognized by the floppy disk driver.
    FLOPPY_UNKNOWN_ERROR = 1124,
    /// The floppy disk controller returned inconsistent results in its registers.
    FLOPPY_BAD_REGISTERS = 1125,
    /// While accessing the hard disk, a recalibrate operation failed, even after retries.
    DISK_RECALIBRATE_FAILED = 1126,
    /// While accessing the hard disk, a disk operation failed even after retries.
    DISK_OPERATION_FAILED = 1127,
    /// While accessing the hard disk, a disk controller reset was needed, but even that failed.
    DISK_RESET_FAILED = 1128,
    /// Physical end of tape encountered.
    EOM_OVERFLOW = 1129,
    /// Not enough server storage is available to process this command.
    NOT_ENOUGH_SERVER_MEMORY = 1130,
    /// A potential deadlock condition has been detected.
    POSSIBLE_DEADLOCK = 1131,
    /// The base address or the file offset specified does not have the proper alignment.
    MAPPED_ALIGNMENT = 1132,
    /// An attempt to change the system power state was vetoed by another application or driver.
    SET_POWER_STATE_VETOED = 1140,
    /// The system BIOS failed an attempt to change the system power state.
    SET_POWER_STATE_FAILED = 1141,
    /// An attempt was made to create more links on a file than the file system supports.
    TOO_MANY_LINKS = 1142,
    /// The specified program requires a newer version of Windows.
    OLD_WIN_VERSION = 1150,
    /// The specified program is not a Windows or MS-DOS program.
    APP_WRONG_OS = 1151,
    /// Cannot start more than one instance of the specified program.
    SINGLE_INSTANCE_APP = 1152,
    /// The specified program was written for an earlier version of Windows.
    RMODE_APP = 1153,
    /// One of the library files needed to run this application is damaged.
    INVALID_DLL = 1154,
    /// No application is associated with the specified file for this operation.
    NO_ASSOCIATION = 1155,
    /// An error occurred in sending the command to the application.
    DDE_FAIL = 1156,
    /// One of the library files needed to run this application cannot be found.
    DLL_NOT_FOUND = 1157,
    /// The current process has used all of its system allowance of handles for Window Manager objects.
    NO_MORE_USER_HANDLES = 1158,
    /// The message can be used only with synchronous operations.
    MESSAGE_SYNC_ONLY = 1159,
    /// The indicated source element has no media.
    SOURCE_ELEMENT_EMPTY = 1160,
    /// The indicated destination element already contains media.
    DESTINATION_ELEMENT_FULL = 1161,
    /// The indicated element does not exist.
    ILLEGAL_ELEMENT_ADDRESS = 1162,
    /// The indicated element is part of a magazine that is not present.
    MAGAZINE_NOT_PRESENT = 1163,
    /// The indicated device requires reinitialization due to hardware errors.
    DEVICE_REINITIALIZATION_NEEDED = 1164,
    /// The device has indicated that cleaning is required before further operations are attempted.
    DEVICE_REQUIRES_CLEANING = 1165,
    /// The device has indicated that its door is open.
    DEVICE_DOOR_OPEN = 1166,
    /// The device is not connected.
    DEVICE_NOT_CONNECTED = 1167,
    /// Element not found.
    NOT_FOUND = 1168,
    /// There was no match for the specified key in the index.
    NO_MATCH = 1169,
    /// The property set specified does not exist on the object.
    SET_NOT_FOUND = 1170,
    /// The point passed to GetMouseMovePoints is not in the buffer.
    POINT_NOT_FOUND = 1171,
    /// The tracking (workstation) service is not running.
    NO_TRACKING_SERVICE = 1172,
    /// The Volume ID could not be found.
    NO_VOLUME_ID = 1173,
    /// Unable to remove the file to be replaced.
    UNABLE_TO_REMOVE_REPLACED = 1175,
    /// Unable to move the replacement file to the file to be replaced.
    /// The file to be replaced has retained its original name.
    UNABLE_TO_MOVE_REPLACEMENT = 1176,
    /// Unable to move the replacement file to the file to be replaced.
    /// The file to be replaced has been renamed using the backup name.
    UNABLE_TO_MOVE_REPLACEMENT_2 = 1177,
    /// The volume change journal is being deleted.
    JOURNAL_DELETE_IN_PROGRESS = 1178,
    /// The volume change journal is not active.
    JOURNAL_NOT_ACTIVE = 1179,
    /// A file was found, but it may not be the correct file.
    POTENTIAL_FILE_FOUND = 1180,
    /// The journal entry has been deleted from the journal.
    JOURNAL_ENTRY_DELETED = 1181,
    /// A system shutdown has already been scheduled.
    SHUTDOWN_IS_SCHEDULED = 1190,
    /// The system shutdown cannot be initiated because there are other users logged on to the computer.
    SHUTDOWN_USERS_LOGGED_ON = 1191,
    /// The specified device name is invalid.
    BAD_DEVICE = 1200,
    /// The device is not currently connected but it is a remembered connection.
    CONNECTION_UNAVAIL = 1201,
    /// The local device name has a remembered connection to another network resource.
    DEVICE_ALREADY_REMEMBERED = 1202,
    /// The network path was either typed incorrectly, does not exist, or the network provider is not currently available.
    /// Please try retyping the path or contact your network administrator.
    NO_NET_OR_BAD_PATH = 1203,
    /// The specified network provider name is invalid.
    BAD_PROVIDER = 1204,
    /// Unable to open the network connection profile.
    CANNOT_OPEN_PROFILE = 1205,
    /// The network connection profile is corrupted.
    BAD_PROFILE = 1206,
    /// Cannot enumerate a noncontainer.
    NOT_CONTAINER = 1207,
    /// An extended error has occurred.
    EXTENDED_ERROR = 1208,
    /// The format of the specified group name is invalid.
    INVALID_GROUPNAME = 1209,
    /// The format of the specified computer name is invalid.
    INVALID_COMPUTERNAME = 1210,
    /// The format of the specified event name is invalid.
    INVALID_EVENTNAME = 1211,
    /// The format of the specified domain name is invalid.
    INVALID_DOMAINNAME = 1212,
    /// The format of the specified service name is invalid.
    INVALID_SERVICENAME = 1213,
    /// The format of the specified network name is invalid.
    INVALID_NETNAME = 1214,
    /// The format of the specified share name is invalid.
    INVALID_SHARENAME = 1215,
    /// The format of the specified password is invalid.
    INVALID_PASSWORDNAME = 1216,
    /// The format of the specified message name is invalid.
    INVALID_MESSAGENAME = 1217,
    /// The format of the specified message destination is invalid.
    INVALID_MESSAGEDEST = 1218,
    /// Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed.
    /// Disconnect all previous connections to the server or shared resource and try again.
    SESSION_CREDENTIAL_CONFLICT = 1219,
    /// An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.
    REMOTE_SESSION_LIMIT_EXCEEDED = 1220,
    /// The workgroup or domain name is already in use by another computer on the network.
    DUP_DOMAINNAME = 1221,
    /// The network is not present or not started.
    NO_NETWORK = 1222,
    /// The operation was canceled by the user.
    CANCELLED = 1223,
    /// The requested operation cannot be performed on a file with a user-mapped section open.
    USER_MAPPED_FILE = 1224,
    /// The remote computer refused the network connection.
    CONNECTION_REFUSED = 1225,
    /// The network connection was gracefully closed.
    GRACEFUL_DISCONNECT = 1226,
    /// The network transport endpoint already has an address associated with it.
    ADDRESS_ALREADY_ASSOCIATED = 1227,
    /// An address has not yet been associated with the network endpoint.
    ADDRESS_NOT_ASSOCIATED = 1228,
    /// An operation was attempted on a nonexistent network connection.
    CONNECTION_INVALID = 1229,
    /// An invalid operation was attempted on an active network connection.
    CONNECTION_ACTIVE = 1230,
    /// The network location cannot be reached.
    /// For information about network troubleshooting, see Windows Help.
    NETWORK_UNREACHABLE = 1231,
    /// The network location cannot be reached.
    /// For information about network troubleshooting, see Windows Help.
    HOST_UNREACHABLE = 1232,
    /// The network location cannot be reached.
    /// For information about network troubleshooting, see Windows Help.
    PROTOCOL_UNREACHABLE = 1233,
    /// No service is operating at the destination network endpoint on the remote system.
    PORT_UNREACHABLE = 1234,
    /// The request was aborted.
    REQUEST_ABORTED = 1235,
    /// The network connection was aborted by the local system.
    CONNECTION_ABORTED = 1236,
    /// The operation could not be completed. A retry should be performed.
    RETRY = 1237,
    /// A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.
    CONNECTION_COUNT_LIMIT = 1238,
    /// Attempting to log in during an unauthorized time of day for this account.
    LOGIN_TIME_RESTRICTION = 1239,
    /// The account is not authorized to log in from this station.
    LOGIN_WKSTA_RESTRICTION = 1240,
    /// The network address could not be used for the operation requested.
    INCORRECT_ADDRESS = 1241,
    /// The service is already registered.
    ALREADY_REGISTERED = 1242,
    /// The specified service does not exist.
    SERVICE_NOT_FOUND = 1243,
    /// The operation being requested was not performed because the user has not been authenticated.
    NOT_AUTHENTICATED = 1244,
    /// The operation being requested was not performed because the user has not logged on to the network. The specified service does not exist.
    NOT_LOGGED_ON = 1245,
    /// Continue with work in progress.
    CONTINUE = 1246,
    /// An attempt was made to perform an initialization operation when initialization has already been completed.
    ALREADY_INITIALIZED = 1247,
    /// No more local devices.
    NO_MORE_DEVICES = 1248,
    /// The specified site does not exist.
    NO_SUCH_SITE = 1249,
    /// A domain controller with the specified name already exists.
    DOMAIN_CONTROLLER_EXISTS = 1250,
    /// This operation is supported only when you are connected to the server.
    ONLY_IF_CONNECTED = 1251,
    /// The group policy framework should call the extension even if there are no changes.
    OVERRIDE_NOCHANGES = 1252,
    /// The specified user does not have a valid profile.
    BAD_USER_PROFILE = 1253,
    /// This operation is not supported on a computer running Windows Server 2003 for Small Business Server.
    NOT_SUPPORTED_ON_SBS = 1254,
    /// The server machine is shutting down.
    SERVER_SHUTDOWN_IN_PROGRESS = 1255,
    /// The remote system is not available.
    /// For information about network troubleshooting, see Windows Help.
    HOST_DOWN = 1256,
    /// The security identifier provided is not from an account domain.
    NON_ACCOUNT_SID = 1257,
    /// The security identifier provided does not have a domain component.
    NON_DOMAIN_SID = 1258,
    /// AppHelp dialog canceled thus preventing the application from starting.
    APPHELP_BLOCK = 1259,
    /// This program is blocked by group policy.
    /// For more information, contact your system administrator.
    ACCESS_DISABLED_BY_POLICY = 1260,
    /// A program attempt to use an invalid register value.
    /// Normally caused by an uninitialized register. This error is Itanium specific.
    REG_NAT_CONSUMPTION = 1261,
    /// The share is currently offline or does not exist.
    CSCSHARE_OFFLINE = 1262,
    /// The Kerberos protocol encountered an error while validating the KDC certificate during smartcard logon.
    /// There is more information in the system event log.
    PKINIT_FAILURE = 1263,
    /// The Kerberos protocol encountered an error while attempting to utilize the smartcard subsystem.
    SMARTCARD_SUBSYSTEM_FAILURE = 1264,
    /// The system cannot contact a domain controller to service the authentication request. Please try again later.
    DOWNGRADE_DETECTED = 1265,
    /// The machine is locked and cannot be shut down without the force option.
    MACHINE_LOCKED = 1271,
    /// An application-defined callback gave invalid data when called.
    CALLBACK_SUPPLIED_INVALID_DATA = 1273,
    /// The group policy framework should call the extension in the synchronous foreground policy refresh.
    SYNC_FOREGROUND_REFRESH_REQUIRED = 1274,
    /// This driver has been blocked from loading.
    DRIVER_BLOCKED = 1275,
    /// A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.
    INVALID_IMPORT_OF_NON_DLL = 1276,
    /// Windows cannot open this program since it has been disabled.
    ACCESS_DISABLED_WEBBLADE = 1277,
    /// Windows cannot open this program because the license enforcement system has been tampered with or become corrupted.
    ACCESS_DISABLED_WEBBLADE_TAMPER = 1278,
    /// A transaction recover failed.
    RECOVERY_FAILURE = 1279,
    /// The current thread has already been converted to a fiber.
    ALREADY_FIBER = 1280,
    /// The current thread has already been converted from a fiber.
    ALREADY_THREAD = 1281,
    /// The system detected an overrun of a stack-based buffer in this application.
    /// This overrun could potentially allow a malicious user to gain control of this application.
    STACK_BUFFER_OVERRUN = 1282,
    /// Data present in one of the parameters is more than the function can operate on.
    PARAMETER_QUOTA_EXCEEDED = 1283,
    /// An attempt to do an operation on a debug object failed because the object is in the process of being deleted.
    DEBUGGER_INACTIVE = 1284,
    /// An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.
    DELAY_LOAD_FAILED = 1285,
    /// %1 is a 16-bit application. You do not have permissions to execute 16-bit applications.
    /// Check your permissions with your system administrator.
    VDM_DISALLOWED = 1286,
    /// Insufficient information exists to identify the cause of failure.
    UNIDENTIFIED_ERROR = 1287,
    /// The parameter passed to a C runtime function is incorrect.
    INVALID_CRUNTIME_PARAMETER = 1288,
    /// The operation occurred beyond the valid data length of the file.
    BEYOND_VDL = 1289,
    /// The service start failed since one or more services in the same process have an incompatible service SID type setting.
    /// A service with restricted service SID type can only coexist in the same process with other services with a restricted SID type.
    /// If the service SID type for this service was just configured, the hosting process must be restarted in order to start this service.
    /// On Windows Server 2003 and Windows XP, an unrestricted service cannot coexist in the same process with other services.
    /// The service with the unrestricted service SID type must be moved to an owned process in order to start this service.
    INCOMPATIBLE_SERVICE_SID_TYPE = 1290,
    /// The process hosting the driver for this device has been terminated.
    DRIVER_PROCESS_TERMINATED = 1291,
    /// An operation attempted to exceed an implementation-defined limit.
    IMPLEMENTATION_LIMIT = 1292,
    /// Either the target process, or the target thread's containing process, is a protected process.
    PROCESS_IS_PROTECTED = 1293,
    /// The service notification client is lagging too far behind the current state of services in the machine.
    SERVICE_NOTIFY_CLIENT_LAGGING = 1294,
    /// The requested file operation failed because the storage quota was exceeded.
    /// To free up disk space, move files to a different location or delete unnecessary files.
    /// For more information, contact your system administrator.
    DISK_QUOTA_EXCEEDED = 1295,
    /// The requested file operation failed because the storage policy blocks that type of file.
    /// For more information, contact your system administrator.
    CONTENT_BLOCKED = 1296,
    /// A privilege that the service requires to function properly does not exist in the service account configuration.
    /// You may use the Services Microsoft Management Console (MMC) snap-in (services.msc) and the Local Security Settings MMC snap-in (secpol.msc) to view the service configuration and the account configuration.
    INCOMPATIBLE_SERVICE_PRIVILEGE = 1297,
    /// A thread involved in this operation appears to be unresponsive.
    APP_HANG = 1298,
    /// Indicates a particular Security ID may not be assigned as the label of an object.
    INVALID_LABEL = 1299,
    /// Not all privileges or groups referenced are assigned to the caller.
    NOT_ALL_ASSIGNED = 1300,
    /// Some mapping between account names and security IDs was not done.
    SOME_NOT_MAPPED = 1301,
    /// No system quota limits are specifically set for this account.
    NO_QUOTAS_FOR_ACCOUNT = 1302,
    /// No encryption key is available. A well-known encryption key was returned.
    LOCAL_USER_SESSION_KEY = 1303,
    /// The password is too complex to be converted to a LAN Manager password.
    /// The LAN Manager password returned is a NULL string.
    NULL_LM_PASSWORD = 1304,
    /// The revision level is unknown.
    UNKNOWN_REVISION = 1305,
    /// Indicates two revision levels are incompatible.
    REVISION_MISMATCH = 1306,
    /// This security ID may not be assigned as the owner of this object.
    INVALID_OWNER = 1307,
    /// This security ID may not be assigned as the primary group of an object.
    INVALID_PRIMARY_GROUP = 1308,
    /// An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.
    NO_IMPERSONATION_TOKEN = 1309,
    /// The group may not be disabled.
    CANT_DISABLE_MANDATORY = 1310,
    /// There are currently no logon servers available to service the logon request.
    NO_LOGON_SERVERS = 1311,
    /// A specified logon session does not exist. It may already have been terminated.
    NO_SUCH_LOGON_SESSION = 1312,
    /// A specified privilege does not exist.
    NO_SUCH_PRIVILEGE = 1313,
    /// A required privilege is not held by the client.
    PRIVILEGE_NOT_HELD = 1314,
    /// The name provided is not a properly formed account name.
    INVALID_ACCOUNT_NAME = 1315,
    /// The specified account already exists.
    USER_EXISTS = 1316,
    /// The specified account does not exist.
    NO_SUCH_USER = 1317,
    /// The specified group already exists.
    GROUP_EXISTS = 1318,
    /// The specified group does not exist.
    NO_SUCH_GROUP = 1319,
    /// Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member.
    MEMBER_IN_GROUP = 1320,
    /// The specified user account is not a member of the specified group account.
    MEMBER_NOT_IN_GROUP = 1321,
    /// This operation is disallowed as it could result in an administration account being disabled, deleted or unable to log on.
    LAST_ADMIN = 1322,
    /// Unable to update the password. The value provided as the current password is incorrect.
    WRONG_PASSWORD = 1323,
    /// Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.
    ILL_FORMED_PASSWORD = 1324,
    /// Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.
    PASSWORD_RESTRICTION = 1325,
    /// The user name or password is incorrect.
    LOGON_FAILURE = 1326,
    /// Account restrictions are preventing this user from signing in.
    /// For example: blank passwords aren't allowed, sign-in times are limited, or a policy restriction has been enforced.
    ACCOUNT_RESTRICTION = 1327,
    /// Your account has time restrictions that keep you from signing in right now.
    INVALID_LOGON_HOURS = 1328,
    /// This user isn't allowed to sign in to this computer.
    INVALID_WORKSTATION = 1329,
    /// The password for this account has expired.
    PASSWORD_EXPIRED = 1330,
    /// This user can't sign in because this account is currently disabled.
    ACCOUNT_DISABLED = 1331,
    /// No mapping between account names and security IDs was done.
    NONE_MAPPED = 1332,
    /// Too many local user identifiers (LUIDs) were requested at one time.
    TOO_MANY_LUIDS_REQUESTED = 1333,
    /// No more local user identifiers (LUIDs) are available.
    LUIDS_EXHAUSTED = 1334,
    /// The subauthority part of a security ID is invalid for this particular use.
    INVALID_SUB_AUTHORITY = 1335,
    /// The access control list (ACL) structure is invalid.
    INVALID_ACL = 1336,
    /// The security ID structure is invalid.
    INVALID_SID = 1337,
    /// The security descriptor structure is invalid.
    INVALID_SECURITY_DESCR = 1338,
    /// The inherited access control list (ACL) or access control entry (ACE) could not be built.
    BAD_INHERITANCE_ACL = 1340,
    /// The server is currently disabled.
    SERVER_DISABLED = 1341,
    /// The server is currently enabled.
    SERVER_NOT_DISABLED = 1342,
    /// The value provided was an invalid value for an identifier authority.
    INVALID_ID_AUTHORITY = 1343,
    /// No more memory is available for security information updates.
    ALLOTTED_SPACE_EXCEEDED = 1344,
    /// The specified attributes are invalid, or incompatible with the attributes for the group as a whole.
    INVALID_GROUP_ATTRIBUTES = 1345,
    /// Either a required impersonation level was not provided, or the provided impersonation level is invalid.
    BAD_IMPERSONATION_LEVEL = 1346,
    /// Cannot open an anonymous level security token.
    CANT_OPEN_ANONYMOUS = 1347,
    /// The validation information class requested was invalid.
    BAD_VALIDATION_CLASS = 1348,
    /// The type of the token is inappropriate for its attempted use.
    BAD_TOKEN_TYPE = 1349,
    /// Unable to perform a security operation on an object that has no associated security.
    NO_SECURITY_ON_OBJECT = 1350,
    /// Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.
    CANT_ACCESS_DOMAIN_INFO = 1351,
    /// The security account manager (SAM) or local security authority (LSA) server was in the wrong state to perform the security operation.
    INVALID_SERVER_STATE = 1352,
    /// The domain was in the wrong state to perform the security operation.
    INVALID_DOMAIN_STATE = 1353,
    /// This operation is only allowed for the Primary Domain Controller of the domain.
    INVALID_DOMAIN_ROLE = 1354,
    /// The specified domain either does not exist or could not be contacted.
    NO_SUCH_DOMAIN = 1355,
    /// The specified domain already exists.
    DOMAIN_EXISTS = 1356,
    /// An attempt was made to exceed the limit on the number of domains per server.
    DOMAIN_LIMIT_EXCEEDED = 1357,
    /// Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk.
    INTERNAL_DB_CORRUPTION = 1358,
    /// An internal error occurred.
    INTERNAL_ERROR = 1359,
    /// Generic access types were contained in an access mask which should already be mapped to nongeneric types.
    GENERIC_NOT_MAPPED = 1360,
    /// A security descriptor is not in the right format (absolute or self-relative).
    BAD_DESCRIPTOR_FORMAT = 1361,
    /// The requested action is restricted for use by logon processes only.
    /// The calling process has not registered as a logon process.
    NOT_LOGON_PROCESS = 1362,
    /// Cannot start a new logon session with an ID that is already in use.
    LOGON_SESSION_EXISTS = 1363,
    /// A specified authentication package is unknown.
    NO_SUCH_PACKAGE = 1364,
    /// The logon session is not in a state that is consistent with the requested operation.
    BAD_LOGON_SESSION_STATE = 1365,
    /// The logon session ID is already in use.
    LOGON_SESSION_COLLISION = 1366,
    /// A logon request contained an invalid logon type value.
    INVALID_LOGON_TYPE = 1367,
    /// Unable to impersonate using a named pipe until data has been read from that pipe.
    CANNOT_IMPERSONATE = 1368,
    /// The transaction state of a registry subtree is incompatible with the requested operation.
    RXACT_INVALID_STATE = 1369,
    /// An internal security database corruption has been encountered.
    RXACT_COMMIT_FAILURE = 1370,
    /// Cannot perform this operation on built-in accounts.
    SPECIAL_ACCOUNT = 1371,
    /// Cannot perform this operation on this built-in special group.
    SPECIAL_GROUP = 1372,
    /// Cannot perform this operation on this built-in special user.
    SPECIAL_USER = 1373,
    /// The user cannot be removed from a group because the group is currently the user's primary group.
    MEMBERS_PRIMARY_GROUP = 1374,
    /// The token is already in use as a primary token.
    TOKEN_ALREADY_IN_USE = 1375,
    /// The specified local group does not exist.
    NO_SUCH_ALIAS = 1376,
    /// The specified account name is not a member of the group.
    MEMBER_NOT_IN_ALIAS = 1377,
    /// The specified account name is already a member of the group.
    MEMBER_IN_ALIAS = 1378,
    /// The specified local group already exists.
    ALIAS_EXISTS = 1379,
    /// Logon failure: the user has not been granted the requested logon type at this computer.
    LOGON_NOT_GRANTED = 1380,
    /// The maximum number of secrets that may be stored in a single system has been exceeded.
    TOO_MANY_SECRETS = 1381,
    /// The length of a secret exceeds the maximum length allowed.
    SECRET_TOO_LONG = 1382,
    /// The local security authority database contains an internal inconsistency.
    INTERNAL_DB_ERROR = 1383,
    /// During a logon attempt, the user's security context accumulated too many security IDs.
    TOO_MANY_CONTEXT_IDS = 1384,
    /// Logon failure: the user has not been granted the requested logon type at this computer.
    LOGON_TYPE_NOT_GRANTED = 1385,
    /// A cross-encrypted password is necessary to change a user password.
    NT_CROSS_ENCRYPTION_REQUIRED = 1386,
    /// A member could not be added to or removed from the local group because the member does not exist.
    NO_SUCH_MEMBER = 1387,
    /// A new member could not be added to a local group because the member has the wrong account type.
    INVALID_MEMBER = 1388,
    /// Too many security IDs have been specified.
    TOO_MANY_SIDS = 1389,
    /// A cross-encrypted password is necessary to change this user password.
    LM_CROSS_ENCRYPTION_REQUIRED = 1390,
    /// Indicates an ACL contains no inheritable components.
    NO_INHERITANCE = 1391,
    /// The file or directory is corrupted and unreadable.
    FILE_CORRUPT = 1392,
    /// The disk structure is corrupted and unreadable.
    DISK_CORRUPT = 1393,
    /// There is no user session key for the specified logon session.
    NO_USER_SESSION_KEY = 1394,
    /// The service being accessed is licensed for a particular number of connections.
    /// No more connections can be made to the service at this time because there are already as many connections as the service can accept.
    LICENSE_QUOTA_EXCEEDED = 1395,
    /// The target account name is incorrect.
    WRONG_TARGET_NAME = 1396,
    /// Mutual Authentication failed. The server's password is out of date at the domain controller.
    MUTUAL_AUTH_FAILED = 1397,
    /// There is a time and/or date difference between the client and server.
    TIME_SKEW = 1398,
    /// This operation cannot be performed on the current domain.
    CURRENT_DOMAIN_NOT_ALLOWED = 1399,
    /// Invalid window handle.
    INVALID_WINDOW_HANDLE = 1400,
    /// Invalid menu handle.
    INVALID_MENU_HANDLE = 1401,
    /// Invalid cursor handle.
    INVALID_CURSOR_HANDLE = 1402,
    /// Invalid accelerator table handle.
    INVALID_ACCEL_HANDLE = 1403,
    /// Invalid hook handle.
    INVALID_HOOK_HANDLE = 1404,
    /// Invalid handle to a multiple-window position structure.
    INVALID_DWP_HANDLE = 1405,
    /// Cannot create a top-level child window.
    TLW_WITH_WSCHILD = 1406,
    /// Cannot find window class.
    CANNOT_FIND_WND_CLASS = 1407,
    /// Invalid window; it belongs to other thread.
    WINDOW_OF_OTHER_THREAD = 1408,
    /// Hot key is already registered.
    HOTKEY_ALREADY_REGISTERED = 1409,
    /// Class already exists.
    CLASS_ALREADY_EXISTS = 1410,
    /// Class does not exist.
    CLASS_DOES_NOT_EXIST = 1411,
    /// Class still has open windows.
    CLASS_HAS_WINDOWS = 1412,
    /// Invalid index.
    INVALID_INDEX = 1413,
    /// Invalid icon handle.
    INVALID_ICON_HANDLE = 1414,
    /// Using private DIALOG window words.
    PRIVATE_DIALOG_INDEX = 1415,
    /// The list box identifier was not found.
    LISTBOX_ID_NOT_FOUND = 1416,
    /// No wildcards were found.
    NO_WILDCARD_CHARACTERS = 1417,
    /// Thread does not have a clipboard open.
    CLIPBOARD_NOT_OPEN = 1418,
    /// Hot key is not registered.
    HOTKEY_NOT_REGISTERED = 1419,
    /// The window is not a valid dialog window.
    WINDOW_NOT_DIALOG = 1420,
    /// Control ID not found.
    CONTROL_ID_NOT_FOUND = 1421,
    /// Invalid message for a combo box because it does not have an edit control.
    INVALID_COMBOBOX_MESSAGE = 1422,
    /// The window is not a combo box.
    WINDOW_NOT_COMBOBOX = 1423,
    /// Height must be less than 256.
    INVALID_EDIT_HEIGHT = 1424,
    /// Invalid device context (DC) handle.
    DC_NOT_FOUND = 1425,
    /// Invalid hook procedure type.
    INVALID_HOOK_FILTER = 1426,
    /// Invalid hook procedure.
    INVALID_FILTER_PROC = 1427,
    /// Cannot set nonlocal hook without a module handle.
    HOOK_NEEDS_HMOD = 1428,
    /// This hook procedure can only be set globally.
    GLOBAL_ONLY_HOOK = 1429,
    /// The journal hook procedure is already installed.
    JOURNAL_HOOK_SET = 1430,
    /// The hook procedure is not installed.
    HOOK_NOT_INSTALLED = 1431,
    /// Invalid message for single-selection list box.
    INVALID_LB_MESSAGE = 1432,
    /// LB_SETCOUNT sent to non-lazy list box.
    SETCOUNT_ON_BAD_LB = 1433,
    /// This list box does not support tab stops.
    LB_WITHOUT_TABSTOPS = 1434,
    /// Cannot destroy object created by another thread.
    DESTROY_OBJECT_OF_OTHER_THREAD = 1435,
    /// Child windows cannot have menus.
    CHILD_WINDOW_MENU = 1436,
    /// The window does not have a system menu.
    NO_SYSTEM_MENU = 1437,
    /// Invalid message box style.
    INVALID_MSGBOX_STYLE = 1438,
    /// Invalid system-wide (SPI_*) parameter.
    INVALID_SPI_VALUE = 1439,
    /// Screen already locked.
    SCREEN_ALREADY_LOCKED = 1440,
    /// All handles to windows in a multiple-window position structure must have the same parent.
    HWNDS_HAVE_DIFF_PARENT = 1441,
    /// The window is not a child window.
    NOT_CHILD_WINDOW = 1442,
    /// Invalid GW_* command.
    INVALID_GW_COMMAND = 1443,
    /// Invalid thread identifier.
    INVALID_THREAD_ID = 1444,
    /// Cannot process a message from a window that is not a multiple document interface (MDI) window.
    NON_MDICHILD_WINDOW = 1445,
    /// Popup menu already active.
    POPUP_ALREADY_ACTIVE = 1446,
    /// The window does not have scroll bars.
    NO_SCROLLBARS = 1447,
    /// Scroll bar range cannot be greater than MAXLONG.
    INVALID_SCROLLBAR_RANGE = 1448,
    /// Cannot show or remove the window in the way specified.
    INVALID_SHOWWIN_COMMAND = 1449,
    /// Insufficient system resources exist to complete the requested service.
    NO_SYSTEM_RESOURCES = 1450,
    /// Insufficient system resources exist to complete the requested service.
    NONPAGED_SYSTEM_RESOURCES = 1451,
    /// Insufficient system resources exist to complete the requested service.
    PAGED_SYSTEM_RESOURCES = 1452,
    /// Insufficient quota to complete the requested service.
    WORKING_SET_QUOTA = 1453,
    /// Insufficient quota to complete the requested service.
    PAGEFILE_QUOTA = 1454,
    /// The paging file is too small for this operation to complete.
    COMMITMENT_LIMIT = 1455,
    /// A menu item was not found.
    MENU_ITEM_NOT_FOUND = 1456,
    /// Invalid keyboard layout handle.
    INVALID_KEYBOARD_HANDLE = 1457,
    /// Hook type not allowed.
    HOOK_TYPE_NOT_ALLOWED = 1458,
    /// This operation requires an interactive window station.
    REQUIRES_INTERACTIVE_WINDOWSTATION = 1459,
    /// This operation returned because the timeout period expired.
    TIMEOUT = 1460,
    /// Invalid monitor handle.
    INVALID_MONITOR_HANDLE = 1461,
    /// Incorrect size argument.
    INCORRECT_SIZE = 1462,
    /// The symbolic link cannot be followed because its type is disabled.
    SYMLINK_CLASS_DISABLED = 1463,
    /// This application does not support the current operation on symbolic links.
    SYMLINK_NOT_SUPPORTED = 1464,
    /// Windows was unable to parse the requested XML data.
    XML_PARSE_ERROR = 1465,
    /// An error was encountered while processing an XML digital signature.
    XMLDSIG_ERROR = 1466,
    /// This application must be restarted.
    RESTART_APPLICATION = 1467,
    /// The caller made the connection request in the wrong routing compartment.
    WRONG_COMPARTMENT = 1468,
    /// There was an AuthIP failure when attempting to connect to the remote host.
    AUTHIP_FAILURE = 1469,
    /// Insufficient NVRAM resources exist to complete the requested service. A reboot might be required.
    NO_NVRAM_RESOURCES = 1470,
    /// Unable to finish the requested operation because the specified process is not a GUI process.
    NOT_GUI_PROCESS = 1471,
    /// The event log file is corrupted.
    EVENTLOG_FILE_CORRUPT = 1500,
    /// No event log file could be opened, so the event logging service did not start.
    EVENTLOG_CANT_START = 1501,
    /// The event log file is full.
    LOG_FILE_FULL = 1502,
    /// The event log file has changed between read operations.
    EVENTLOG_FILE_CHANGED = 1503,
    /// The specified task name is invalid.
    INVALID_TASK_NAME = 1550,
    /// The specified task index is invalid.
    INVALID_TASK_INDEX = 1551,
    /// The specified thread is already joining a task.
    THREAD_ALREADY_IN_TASK = 1552,
    /// The Windows Installer Service could not be accessed.
    /// This can occur if the Windows Installer is not correctly installed. Contact your support personnel for assistance.
    INSTALL_SERVICE_FAILURE = 1601,
    /// User cancelled installation.
    INSTALL_USEREXIT = 1602,
    /// Fatal error during installation.
    INSTALL_FAILURE = 1603,
    /// Installation suspended, incomplete.
    INSTALL_SUSPEND = 1604,
    /// This action is only valid for products that are currently installed.
    UNKNOWN_PRODUCT = 1605,
    /// Feature ID not registered.
    UNKNOWN_FEATURE = 1606,
    /// Component ID not registered.
    UNKNOWN_COMPONENT = 1607,
    /// Unknown property.
    UNKNOWN_PROPERTY = 1608,
    /// Handle is in an invalid state.
    INVALID_HANDLE_STATE = 1609,
    /// The configuration data for this product is corrupt. Contact your support personnel.
    BAD_CONFIGURATION = 1610,
    /// Component qualifier not present.
    INDEX_ABSENT = 1611,
    /// The installation source for this product is not available.
    /// Verify that the source exists and that you can access it.
    INSTALL_SOURCE_ABSENT = 1612,
    /// This installation package cannot be installed by the Windows Installer service.
    /// You must install a Windows service pack that contains a newer version of the Windows Installer service.
    INSTALL_PACKAGE_VERSION = 1613,
    /// Product is uninstalled.
    PRODUCT_UNINSTALLED = 1614,
    /// SQL query syntax invalid or unsupported.
    BAD_QUERY_SYNTAX = 1615,
    /// Record field does not exist.
    INVALID_FIELD = 1616,
    /// The device has been removed.
    DEVICE_REMOVED = 1617,
    /// Another installation is already in progress.
    /// Complete that installation before proceeding with this install.
    INSTALL_ALREADY_RUNNING = 1618,
    /// This installation package could not be opened.
    /// Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.
    INSTALL_PACKAGE_OPEN_FAILED = 1619,
    /// This installation package could not be opened.
    /// Contact the application vendor to verify that this is a valid Windows Installer package.
    INSTALL_PACKAGE_INVALID = 1620,
    /// There was an error starting the Windows Installer service user interface. Contact your support personnel.
    INSTALL_UI_FAILURE = 1621,
    /// Error opening installation log file.
    /// Verify that the specified log file location exists and that you can write to it.
    INSTALL_LOG_FAILURE = 1622,
    /// The language of this installation package is not supported by your system.
    INSTALL_LANGUAGE_UNSUPPORTED = 1623,
    /// Error applying transforms. Verify that the specified transform paths are valid.
    INSTALL_TRANSFORM_FAILURE = 1624,
    /// This installation is forbidden by system policy. Contact your system administrator.
    INSTALL_PACKAGE_REJECTED = 1625,
    /// Function could not be executed.
    FUNCTION_NOT_CALLED = 1626,
    /// Function failed during execution.
    FUNCTION_FAILED = 1627,
    /// Invalid or unknown table specified.
    INVALID_TABLE = 1628,
    /// Data supplied is of wrong type.
    DATATYPE_MISMATCH = 1629,
    /// Data of this type is not supported.
    UNSUPPORTED_TYPE = 1630,
    /// The Windows Installer service failed to start. Contact your support personnel.
    CREATE_FAILED = 1631,
    /// The Temp folder is on a drive that is full or is inaccessible.
    /// Free up space on the drive or verify that you have write permission on the Temp folder.
    INSTALL_TEMP_UNWRITABLE = 1632,
    /// This installation package is not supported by this processor type. Contact your product vendor.
    INSTALL_PLATFORM_UNSUPPORTED = 1633,
    /// Component not used on this computer.
    INSTALL_NOTUSED = 1634,
    /// This update package could not be opened.
    /// Verify that the update package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer update package.
    PATCH_PACKAGE_OPEN_FAILED = 1635,
    /// This update package could not be opened.
    /// Contact the application vendor to verify that this is a valid Windows Installer update package.
    PATCH_PACKAGE_INVALID = 1636,
    /// This update package cannot be processed by the Windows Installer service.
    /// You must install a Windows service pack that contains a newer version of the Windows Installer service.
    PATCH_PACKAGE_UNSUPPORTED = 1637,
    /// Another version of this product is already installed. Installation of this version cannot continue.
    /// To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel.
    PRODUCT_VERSION = 1638,
    /// Invalid command line argument. Consult the Windows Installer SDK for detailed command line help.
    INVALID_COMMAND_LINE = 1639,
    /// Only administrators have permission to add, remove, or configure server software during a Terminal services remote session.
    /// If you want to install or configure software on the server, contact your network administrator.
    INSTALL_REMOTE_DISALLOWED = 1640,
    /// The requested operation completed successfully.
    /// The system will be restarted so the changes can take effect.
    SUCCESS_REBOOT_INITIATED = 1641,
    /// The upgrade cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade may update a different version of the program.
    /// Verify that the program to be upgraded exists on your computer and that you have the correct upgrade.
    PATCH_TARGET_NOT_FOUND = 1642,
    /// The update package is not permitted by software restriction policy.
    PATCH_PACKAGE_REJECTED = 1643,
    /// One or more customizations are not permitted by software restriction policy.
    INSTALL_TRANSFORM_REJECTED = 1644,
    /// The Windows Installer does not permit installation from a Remote Desktop Connection.
    INSTALL_REMOTE_PROHIBITED = 1645,
    /// Uninstallation of the update package is not supported.
    PATCH_REMOVAL_UNSUPPORTED = 1646,
    /// The update is not applied to this product.
    UNKNOWN_PATCH = 1647,
    /// No valid sequence could be found for the set of updates.
    PATCH_NO_SEQUENCE = 1648,
    /// Update removal was disallowed by policy.
    PATCH_REMOVAL_DISALLOWED = 1649,
    /// The XML update data is invalid.
    INVALID_PATCH_XML = 1650,
    /// Windows Installer does not permit updating of managed advertised products.
    /// At least one feature of the product must be installed before applying the update.
    PATCH_MANAGED_ADVERTISED_PRODUCT = 1651,
    /// The Windows Installer service is not accessible in Safe Mode.
    /// Please try again when your computer is not in Safe Mode or you can use System Restore to return your machine to a previous good state.
    INSTALL_SERVICE_SAFEBOOT = 1652,
    /// A fail fast exception occurred.
    /// Exception handlers will not be invoked and the process will be terminated immediately.
    FAIL_FAST_EXCEPTION = 1653,
    /// The app that you are trying to run is not supported on this version of Windows.
    INSTALL_REJECTED = 1654,
    /// The string binding is invalid.
    RPC_S_INVALID_STRING_BINDING = 1700,
    /// The binding handle is not the correct type.
    RPC_S_WRONG_KIND_OF_BINDING = 1701,
    /// The binding handle is invalid.
    RPC_S_INVALID_BINDING = 1702,
    /// The RPC protocol sequence is not supported.
    RPC_S_PROTSEQ_NOT_SUPPORTED = 1703,
    /// The RPC protocol sequence is invalid.
    RPC_S_INVALID_RPC_PROTSEQ = 1704,
    /// The string universal unique identifier (UUID) is invalid.
    RPC_S_INVALID_STRING_UUID = 1705,
    /// The endpoint format is invalid.
    RPC_S_INVALID_ENDPOINT_FORMAT = 1706,
    /// The network address is invalid.
    RPC_S_INVALID_NET_ADDR = 1707,
    /// No endpoint was found.
    RPC_S_NO_ENDPOINT_FOUND = 1708,
    /// The timeout value is invalid.
    RPC_S_INVALID_TIMEOUT = 1709,
    /// The object universal unique identifier (UUID) was not found.
    RPC_S_OBJECT_NOT_FOUND = 1710,
    /// The object universal unique identifier (UUID) has already been registered.
    RPC_S_ALREADY_REGISTERED = 1711,
    /// The type universal unique identifier (UUID) has already been registered.
    RPC_S_TYPE_ALREADY_REGISTERED = 1712,
    /// The RPC server is already listening.
    RPC_S_ALREADY_LISTENING = 1713,
    /// No protocol sequences have been registered.
    RPC_S_NO_PROTSEQS_REGISTERED = 1714,
    /// The RPC server is not listening.
    RPC_S_NOT_LISTENING = 1715,
    /// The manager type is unknown.
    RPC_S_UNKNOWN_MGR_TYPE = 1716,
    /// The interface is unknown.
    RPC_S_UNKNOWN_IF = 1717,
    /// There are no bindings.
    RPC_S_NO_BINDINGS = 1718,
    /// There are no protocol sequences.
    RPC_S_NO_PROTSEQS = 1719,
    /// The endpoint cannot be created.
    RPC_S_CANT_CREATE_ENDPOINT = 1720,
    /// Not enough resources are available to complete this operation.
    RPC_S_OUT_OF_RESOURCES = 1721,
    /// The RPC server is unavailable.
    RPC_S_SERVER_UNAVAILABLE = 1722,
    /// The RPC server is too busy to complete this operation.
    RPC_S_SERVER_TOO_BUSY = 1723,
    /// The network options are invalid.
    RPC_S_INVALID_NETWORK_OPTIONS = 1724,
    /// There are no remote procedure calls active on this thread.
    RPC_S_NO_CALL_ACTIVE = 1725,
    /// The remote procedure call failed.
    RPC_S_CALL_FAILED = 1726,
    /// The remote procedure call failed and did not execute.
    RPC_S_CALL_FAILED_DNE = 1727,
    /// A remote procedure call (RPC) protocol error occurred.
    RPC_S_PROTOCOL_ERROR = 1728,
    /// Access to the HTTP proxy is denied.
    RPC_S_PROXY_ACCESS_DENIED = 1729,
    /// The transfer syntax is not supported by the RPC server.
    RPC_S_UNSUPPORTED_TRANS_SYN = 1730,
    /// The universal unique identifier (UUID) type is not supported.
    RPC_S_UNSUPPORTED_TYPE = 1732,
    /// The tag is invalid.
    RPC_S_INVALID_TAG = 1733,
    /// The array bounds are invalid.
    RPC_S_INVALID_BOUND = 1734,
    /// The binding does not contain an entry name.
    RPC_S_NO_ENTRY_NAME = 1735,
    /// The name syntax is invalid.
    RPC_S_INVALID_NAME_SYNTAX = 1736,
    /// The name syntax is not supported.
    RPC_S_UNSUPPORTED_NAME_SYNTAX = 1737,
    /// No network address is available to use to construct a universal unique identifier (UUID).
    RPC_S_UUID_NO_ADDRESS = 1739,
    /// The endpoint is a duplicate.
    RPC_S_DUPLICATE_ENDPOINT = 1740,
    /// The authentication type is unknown.
    RPC_S_UNKNOWN_AUTHN_TYPE = 1741,
    /// The maximum number of calls is too small.
    RPC_S_MAX_CALLS_TOO_SMALL = 1742,
    /// The string is too long.
    RPC_S_STRING_TOO_LONG = 1743,
    /// The RPC protocol sequence was not found.
    RPC_S_PROTSEQ_NOT_FOUND = 1744,
    /// The procedure number is out of range.
    RPC_S_PROCNUM_OUT_OF_RANGE = 1745,
    /// The binding does not contain any authentication information.
    RPC_S_BINDING_HAS_NO_AUTH = 1746,
    /// The authentication service is unknown.
    RPC_S_UNKNOWN_AUTHN_SERVICE = 1747,
    /// The authentication level is unknown.
    RPC_S_UNKNOWN_AUTHN_LEVEL = 1748,
    /// The security context is invalid.
    RPC_S_INVALID_AUTH_IDENTITY = 1749,
    /// The authorization service is unknown.
    RPC_S_UNKNOWN_AUTHZ_SERVICE = 1750,
    /// The entry is invalid.
    EPT_S_INVALID_ENTRY = 1751,
    /// The server endpoint cannot perform the operation.
    EPT_S_CANT_PERFORM_OP = 1752,
    /// There are no more endpoints available from the endpoint mapper.
    EPT_S_NOT_REGISTERED = 1753,
    /// No interfaces have been exported.
    RPC_S_NOTHING_TO_EXPORT = 1754,
    /// The entry name is incomplete.
    RPC_S_INCOMPLETE_NAME = 1755,
    /// The version option is invalid.
    RPC_S_INVALID_VERS_OPTION = 1756,
    /// There are no more members.
    RPC_S_NO_MORE_MEMBERS = 1757,
    /// There is nothing to unexport.
    RPC_S_NOT_ALL_OBJS_UNEXPORTED = 1758,
    /// The interface was not found.
    RPC_S_INTERFACE_NOT_FOUND = 1759,
    /// The entry already exists.
    RPC_S_ENTRY_ALREADY_EXISTS = 1760,
    /// The entry is not found.
    RPC_S_ENTRY_NOT_FOUND = 1761,
    /// The name service is unavailable.
    RPC_S_NAME_SERVICE_UNAVAILABLE = 1762,
    /// The network address family is invalid.
    RPC_S_INVALID_NAF_ID = 1763,
    /// The requested operation is not supported.
    RPC_S_CANNOT_SUPPORT = 1764,
    /// No security context is available to allow impersonation.
    RPC_S_NO_CONTEXT_AVAILABLE = 1765,
    /// An internal error occurred in a remote procedure call (RPC).
    RPC_S_INTERNAL_ERROR = 1766,
    /// The RPC server attempted an integer division by zero.
    RPC_S_ZERO_DIVIDE = 1767,
    /// An addressing error occurred in the RPC server.
    RPC_S_ADDRESS_ERROR = 1768,
    /// A floating-point operation at the RPC server caused a division by zero.
    RPC_S_FP_DIV_ZERO = 1769,
    /// A floating-point underflow occurred at the RPC server.
    RPC_S_FP_UNDERFLOW = 1770,
    /// A floating-point overflow occurred at the RPC server.
    RPC_S_FP_OVERFLOW = 1771,
    /// The list of RPC servers available for the binding of auto handles has been exhausted.
    RPC_X_NO_MORE_ENTRIES = 1772,
    /// Unable to open the character translation table file.
    RPC_X_SS_CHAR_TRANS_OPEN_FAIL = 1773,
    /// The file containing the character translation table has fewer than 512 bytes.
    RPC_X_SS_CHAR_TRANS_SHORT_FILE = 1774,
    /// A null context handle was passed from the client to the host during a remote procedure call.
    RPC_X_SS_IN_NULL_CONTEXT = 1775,
    /// The context handle changed during a remote procedure call.
    RPC_X_SS_CONTEXT_DAMAGED = 1777,
    /// The binding handles passed to a remote procedure call do not match.
    RPC_X_SS_HANDLES_MISMATCH = 1778,
    /// The stub is unable to get the remote procedure call handle.
    RPC_X_SS_CANNOT_GET_CALL_HANDLE = 1779,
    /// A null reference pointer was passed to the stub.
    RPC_X_NULL_REF_POINTER = 1780,
    /// The enumeration value is out of range.
    RPC_X_ENUM_VALUE_OUT_OF_RANGE = 1781,
    /// The byte count is too small.
    RPC_X_BYTE_COUNT_TOO_SMALL = 1782,
    /// The stub received bad data.
    RPC_X_BAD_STUB_DATA = 1783,
    /// The supplied user buffer is not valid for the requested operation.
    INVALID_USER_BUFFER = 1784,
    /// The disk media is not recognized. It may not be formatted.
    UNRECOGNIZED_MEDIA = 1785,
    /// The workstation does not have a trust secret.
    NO_TRUST_LSA_SECRET = 1786,
    /// The security database on the server does not have a computer account for this workstation trust relationship.
    NO_TRUST_SAM_ACCOUNT = 1787,
    /// The trust relationship between the primary domain and the trusted domain failed.
    TRUSTED_DOMAIN_FAILURE = 1788,
    /// The trust relationship between this workstation and the primary domain failed.
    TRUSTED_RELATIONSHIP_FAILURE = 1789,
    /// The network logon failed.
    TRUST_FAILURE = 1790,
    /// A remote procedure call is already in progress for this thread.
    RPC_S_CALL_IN_PROGRESS = 1791,
    /// An attempt was made to logon, but the network logon service was not started.
    NETLOGON_NOT_STARTED = 1792,
    /// The user's account has expired.
    ACCOUNT_EXPIRED = 1793,
    /// The redirector is in use and cannot be unloaded.
    REDIRECTOR_HAS_OPEN_HANDLES = 1794,
    /// The specified printer driver is already installed.
    PRINTER_DRIVER_ALREADY_INSTALLED = 1795,
    /// The specified port is unknown.
    UNKNOWN_PORT = 1796,
    /// The printer driver is unknown.
    UNKNOWN_PRINTER_DRIVER = 1797,
    /// The print processor is unknown.
    UNKNOWN_PRINTPROCESSOR = 1798,
    /// The specified separator file is invalid.
    INVALID_SEPARATOR_FILE = 1799,
    /// The specified priority is invalid.
    INVALID_PRIORITY = 1800,
    /// The printer name is invalid.
    INVALID_PRINTER_NAME = 1801,
    /// The printer already exists.
    PRINTER_ALREADY_EXISTS = 1802,
    /// The printer command is invalid.
    INVALID_PRINTER_COMMAND = 1803,
    /// The specified datatype is invalid.
    INVALID_DATATYPE = 1804,
    /// The environment specified is invalid.
    INVALID_ENVIRONMENT = 1805,
    /// There are no more bindings.
    RPC_S_NO_MORE_BINDINGS = 1806,
    /// The account used is an interdomain trust account.
    /// Use your global user account or local user account to access this server.
    NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 1807,
    /// The account used is a computer account.
    /// Use your global user account or local user account to access this server.
    NOLOGON_WORKSTATION_TRUST_ACCOUNT = 1808,
    /// The account used is a server trust account.
    /// Use your global user account or local user account to access this server.
    NOLOGON_SERVER_TRUST_ACCOUNT = 1809,
    /// The name or security ID (SID) of the domain specified is inconsistent with the trust information for that domain.
    DOMAIN_TRUST_INCONSISTENT = 1810,
    /// The server is in use and cannot be unloaded.
    SERVER_HAS_OPEN_HANDLES = 1811,
    /// The specified image file did not contain a resource section.
    RESOURCE_DATA_NOT_FOUND = 1812,
    /// The specified resource type cannot be found in the image file.
    RESOURCE_TYPE_NOT_FOUND = 1813,
    /// The specified resource name cannot be found in the image file.
    RESOURCE_NAME_NOT_FOUND = 1814,
    /// The specified resource language ID cannot be found in the image file.
    RESOURCE_LANG_NOT_FOUND = 1815,
    /// Not enough quota is available to process this command.
    NOT_ENOUGH_QUOTA = 1816,
    /// No interfaces have been registered.
    RPC_S_NO_INTERFACES = 1817,
    /// The remote procedure call was cancelled.
    RPC_S_CALL_CANCELLED = 1818,
    /// The binding handle does not contain all required information.
    RPC_S_BINDING_INCOMPLETE = 1819,
    /// A communications failure occurred during a remote procedure call.
    RPC_S_COMM_FAILURE = 1820,
    /// The requested authentication level is not supported.
    RPC_S_UNSUPPORTED_AUTHN_LEVEL = 1821,
    /// No principal name registered.
    RPC_S_NO_PRINC_NAME = 1822,
    /// The error specified is not a valid Windows RPC error code.
    RPC_S_NOT_RPC_ERROR = 1823,
    /// A UUID that is valid only on this computer has been allocated.
    RPC_S_UUID_LOCAL_ONLY = 1824,
    /// A security package specific error occurred.
    RPC_S_SEC_PKG_ERROR = 1825,
    /// Thread is not canceled.
    RPC_S_NOT_CANCELLED = 1826,
    /// Invalid operation on the encoding/decoding handle.
    RPC_X_INVALID_ES_ACTION = 1827,
    /// Incompatible version of the serializing package.
    RPC_X_WRONG_ES_VERSION = 1828,
    /// Incompatible version of the RPC stub.
    RPC_X_WRONG_STUB_VERSION = 1829,
    /// The RPC pipe object is invalid or corrupted.
    RPC_X_INVALID_PIPE_OBJECT = 1830,
    /// An invalid operation was attempted on an RPC pipe object.
    RPC_X_WRONG_PIPE_ORDER = 1831,
    /// Unsupported RPC pipe version.
    RPC_X_WRONG_PIPE_VERSION = 1832,
    /// HTTP proxy server rejected the connection because the cookie authentication failed.
    RPC_S_COOKIE_AUTH_FAILED = 1833,
    /// The group member was not found.
    RPC_S_GROUP_MEMBER_NOT_FOUND = 1898,
    /// The endpoint mapper database entry could not be created.
    EPT_S_CANT_CREATE = 1899,
    /// The object universal unique identifier (UUID) is the nil UUID.
    RPC_S_INVALID_OBJECT = 1900,
    /// The specified time is invalid.
    INVALID_TIME = 1901,
    /// The specified form name is invalid.
    INVALID_FORM_NAME = 1902,
    /// The specified form size is invalid.
    INVALID_FORM_SIZE = 1903,
    /// The specified printer handle is already being waited on.
    ALREADY_WAITING = 1904,
    /// The specified printer has been deleted.
    PRINTER_DELETED = 1905,
    /// The state of the printer is invalid.
    INVALID_PRINTER_STATE = 1906,
    /// The user's password must be changed before signing in.
    PASSWORD_MUST_CHANGE = 1907,
    /// Could not find the domain controller for this domain.
    DOMAIN_CONTROLLER_NOT_FOUND = 1908,
    /// The referenced account is currently locked out and may not be logged on to.
    ACCOUNT_LOCKED_OUT = 1909,
    /// The object exporter specified was not found.
    OR_INVALID_OXID = 1910,
    /// The object specified was not found.
    OR_INVALID_OID = 1911,
    /// The object resolver set specified was not found.
    OR_INVALID_SET = 1912,
    /// Some data remains to be sent in the request buffer.
    RPC_S_SEND_INCOMPLETE = 1913,
    /// Invalid asynchronous remote procedure call handle.
    RPC_S_INVALID_ASYNC_HANDLE = 1914,
    /// Invalid asynchronous RPC call handle for this operation.
    RPC_S_INVALID_ASYNC_CALL = 1915,
    /// The RPC pipe object has already been closed.
    RPC_X_PIPE_CLOSED = 1916,
    /// The RPC call completed before all pipes were processed.
    RPC_X_PIPE_DISCIPLINE_ERROR = 1917,
    /// No more data is available from the RPC pipe.
    RPC_X_PIPE_EMPTY = 1918,
    /// No site name is available for this machine.
    NO_SITENAME = 1919,
    /// The file cannot be accessed by the system.
    CANT_ACCESS_FILE = 1920,
    /// The name of the file cannot be resolved by the system.
    CANT_RESOLVE_FILENAME = 1921,
    /// The entry is not of the expected type.
    RPC_S_ENTRY_TYPE_MISMATCH = 1922,
    /// Not all object UUIDs could be exported to the specified entry.
    RPC_S_NOT_ALL_OBJS_EXPORTED = 1923,
    /// Interface could not be exported to the specified entry.
    RPC_S_INTERFACE_NOT_EXPORTED = 1924,
    /// The specified profile entry could not be added.
    RPC_S_PROFILE_NOT_ADDED = 1925,
    /// The specified profile element could not be added.
    RPC_S_PRF_ELT_NOT_ADDED = 1926,
    /// The specified profile element could not be removed.
    RPC_S_PRF_ELT_NOT_REMOVED = 1927,
    /// The group element could not be added.
    RPC_S_GRP_ELT_NOT_ADDED = 1928,
    /// The group element could not be removed.
    RPC_S_GRP_ELT_NOT_REMOVED = 1929,
    /// The printer driver is not compatible with a policy enabled on your computer that blocks NT 4.0 drivers.
    KM_DRIVER_BLOCKED = 1930,
    /// The context has expired and can no longer be used.
    CONTEXT_EXPIRED = 1931,
    /// The current user's delegated trust creation quota has been exceeded.
    PER_USER_TRUST_QUOTA_EXCEEDED = 1932,
    /// The total delegated trust creation quota has been exceeded.
    ALL_USER_TRUST_QUOTA_EXCEEDED = 1933,
    /// The current user's delegated trust deletion quota has been exceeded.
    USER_DELETE_TRUST_QUOTA_EXCEEDED = 1934,
    /// The computer you are signing into is protected by an authentication firewall.
    /// The specified account is not allowed to authenticate to the computer.
    AUTHENTICATION_FIREWALL_FAILED = 1935,
    /// Remote connections to the Print Spooler are blocked by a policy set on your machine.
    REMOTE_PRINT_CONNECTIONS_BLOCKED = 1936,
    /// Authentication failed because NTLM authentication has been disabled.
    NTLM_BLOCKED = 1937,
    /// Logon Failure: EAS policy requires that the user change their password before this operation can be performed.
    PASSWORD_CHANGE_REQUIRED = 1938,
    /// The pixel format is invalid.
    INVALID_PIXEL_FORMAT = 2000,
    /// The specified driver is invalid.
    BAD_DRIVER = 2001,
    /// The window style or class attribute is invalid for this operation.
    INVALID_WINDOW_STYLE = 2002,
    /// The requested metafile operation is not supported.
    METAFILE_NOT_SUPPORTED = 2003,
    /// The requested transformation operation is not supported.
    TRANSFORM_NOT_SUPPORTED = 2004,
    /// The requested clipping operation is not supported.
    CLIPPING_NOT_SUPPORTED = 2005,
    /// The specified color management module is invalid.
    INVALID_CMM = 2010,
    /// The specified color profile is invalid.
    INVALID_PROFILE = 2011,
    /// The specified tag was not found.
    TAG_NOT_FOUND = 2012,
    /// A required tag is not present.
    TAG_NOT_PRESENT = 2013,
    /// The specified tag is already present.
    DUPLICATE_TAG = 2014,
    /// The specified color profile is not associated with the specified device.
    PROFILE_NOT_ASSOCIATED_WITH_DEVICE = 2015,
    /// The specified color profile was not found.
    PROFILE_NOT_FOUND = 2016,
    /// The specified color space is invalid.
    INVALID_COLORSPACE = 2017,
    /// Image Color Management is not enabled.
    ICM_NOT_ENABLED = 2018,
    /// There was an error while deleting the color transform.
    DELETING_ICM_XFORM = 2019,
    /// The specified color transform is invalid.
    INVALID_TRANSFORM = 2020,
    /// The specified transform does not match the bitmap's color space.
    COLORSPACE_MISMATCH = 2021,
    /// The specified named color index is not present in the profile.
    INVALID_COLORINDEX = 2022,
    /// The specified profile is intended for a device of a different type than the specified device.
    PROFILE_DOES_NOT_MATCH_DEVICE = 2023,
    /// The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified.
    CONNECTED_OTHER_PASSWORD = 2108,
    /// The network connection was made successfully using default credentials.
    CONNECTED_OTHER_PASSWORD_DEFAULT = 2109,
    /// The specified username is invalid.
    BAD_USERNAME = 2202,
    /// This network connection does not exist.
    NOT_CONNECTED = 2250,
    /// This network connection has files open or requests pending.
    OPEN_FILES = 2401,
    /// Active connections still exist.
    ACTIVE_CONNECTIONS = 2402,
    /// The device is in use by an active process and cannot be disconnected.
    DEVICE_IN_USE = 2404,
    /// The specified print monitor is unknown.
    UNKNOWN_PRINT_MONITOR = 3000,
    /// The specified printer driver is currently in use.
    PRINTER_DRIVER_IN_USE = 3001,
    /// The spool file was not found.
    SPOOL_FILE_NOT_FOUND = 3002,
    /// A StartDocPrinter call was not issued.
    SPL_NO_STARTDOC = 3003,
    /// An AddJob call was not issued.
    SPL_NO_ADDJOB = 3004,
    /// The specified print processor has already been installed.
    PRINT_PROCESSOR_ALREADY_INSTALLED = 3005,
    /// The specified print monitor has already been installed.
    PRINT_MONITOR_ALREADY_INSTALLED = 3006,
    /// The specified print monitor does not have the required functions.
    INVALID_PRINT_MONITOR = 3007,
    /// The specified print monitor is currently in use.
    PRINT_MONITOR_IN_USE = 3008,
    /// The requested operation is not allowed when there are jobs queued to the printer.
    PRINTER_HAS_JOBS_QUEUED = 3009,
    /// The requested operation is successful.
    /// Changes will not be effective until the system is rebooted.
    SUCCESS_REBOOT_REQUIRED = 3010,
    /// The requested operation is successful.
    /// Changes will not be effective until the service is restarted.
    SUCCESS_RESTART_REQUIRED = 3011,
    /// No printers were found.
    PRINTER_NOT_FOUND = 3012,
    /// The printer driver is known to be unreliable.
    PRINTER_DRIVER_WARNED = 3013,
    /// The printer driver is known to harm the system.
    PRINTER_DRIVER_BLOCKED = 3014,
    /// The specified printer driver package is currently in use.
    PRINTER_DRIVER_PACKAGE_IN_USE = 3015,
    /// Unable to find a core driver package that is required by the printer driver package.
    CORE_DRIVER_PACKAGE_NOT_FOUND = 3016,
    /// The requested operation failed.
    /// A system reboot is required to roll back changes made.
    FAIL_REBOOT_REQUIRED = 3017,
    /// The requested operation failed.
    /// A system reboot has been initiated to roll back changes made.
    FAIL_REBOOT_INITIATED = 3018,
    /// The specified printer driver was not found on the system and needs to be downloaded.
    PRINTER_DRIVER_DOWNLOAD_NEEDED = 3019,
    /// The requested print job has failed to print.
    /// A print system update requires the job to be resubmitted.
    PRINT_JOB_RESTART_REQUIRED = 3020,
    /// The printer driver does not contain a valid manifest, or contains too many manifests.
    INVALID_PRINTER_DRIVER_MANIFEST = 3021,
    /// The specified printer cannot be shared.
    PRINTER_NOT_SHAREABLE = 3022,
    /// The operation was paused.
    REQUEST_PAUSED = 3050,
    /// Reissue the given operation as a cached IO operation.
    IO_REISSUE_AS_CACHED = 3950,
    _,
};
const std = @import("../../std.zig");
const assert = std.debug.assert;
const windows = std.os.windows;

const OVERLAPPED = windows.OVERLAPPED;
const WORD = windows.WORD;
const DWORD = windows.DWORD;
const GUID = windows.GUID;
const USHORT = windows.USHORT;
const WCHAR = windows.WCHAR;
const BOOL = windows.BOOL;
const HANDLE = windows.HANDLE;
const HWND = windows.HWND;
const INT = windows.INT;
const SHORT = windows.SHORT;
const CHAR = windows.CHAR;
const LONG = windows.LONG;
const ULONG = windows.ULONG;
const LPARAM = windows.LPARAM;
const FARPROC = windows.FARPROC;

pub const SOCKET = *opaque {};
pub const INVALID_SOCKET = @as(SOCKET, @ptrFromInt(~@as(usize, 0)));

pub const GROUP = u32;
pub const ADDRESS_FAMILY = u16;
pub const WSAEVENT = HANDLE;

// Microsoft use the signed c_int for this, but it should never be negative
pub const socklen_t = u32;

pub const LM_HB_Extension = 128;
pub const LM_HB1_PnP = 1;
pub const LM_HB1_PDA_Palmtop = 2;
pub const LM_HB1_Computer = 4;
pub const LM_HB1_Printer = 8;
pub const LM_HB1_Modem = 16;
pub const LM_HB1_Fax = 32;
pub const LM_HB1_LANAccess = 64;
pub const LM_HB2_Telephony = 1;
pub const LM_HB2_FileServer = 2;
pub const ATMPROTO_AALUSER = 0;
pub const ATMPROTO_AAL1 = 1;
pub const ATMPROTO_AAL2 = 2;
pub const ATMPROTO_AAL34 = 3;
pub const ATMPROTO_AAL5 = 5;
pub const SAP_FIELD_ABSENT = 4294967294;
pub const SAP_FIELD_ANY = 4294967295;
pub const SAP_FIELD_ANY_AESA_SEL = 4294967290;
pub const SAP_FIELD_ANY_AESA_REST = 4294967291;
pub const ATM_E164 = 1;
pub const ATM_NSAP = 2;
pub const ATM_AESA = 2;
pub const ATM_ADDR_SIZE = 20;
pub const BLLI_L2_ISO_1745 = 1;
pub const BLLI_L2_Q921 = 2;
pub const BLLI_L2_X25L = 6;
pub const BLLI_L2_X25M = 7;
pub const BLLI_L2_ELAPB = 8;
pub const BLLI_L2_HDLC_ARM = 9;
pub const BLLI_L2_HDLC_NRM = 10;
pub const BLLI_L2_HDLC_ABM = 11;
pub const BLLI_L2_LLC = 12;
pub const BLLI_L2_X75 = 13;
pub const BLLI_L2_Q922 = 14;
pub const BLLI_L2_USER_SPECIFIED = 16;
pub const BLLI_L2_ISO_7776 = 17;
pub const BLLI_L3_X25 = 6;
pub const BLLI_L3_ISO_8208 = 7;
pub const BLLI_L3_X223 = 8;
pub const BLLI_L3_SIO_8473 = 9;
pub const BLLI_L3_T70 = 10;
pub const BLLI_L3_ISO_TR9577 = 11;
pub const BLLI_L3_USER_SPECIFIED = 16;
pub const BLLI_L3_IPI_SNAP = 128;
pub const BLLI_L3_IPI_IP = 204;
pub const BHLI_ISO = 0;
pub const BHLI_UserSpecific = 1;
pub const BHLI_HighLayerProfile = 2;
pub const BHLI_VendorSpecificAppId = 3;
pub const AAL5_MODE_MESSAGE = 1;
pub const AAL5_MODE_STREAMING = 2;
pub const AAL5_SSCS_NULL = 0;
pub const AAL5_SSCS_SSCOP_ASSURED = 1;
pub const AAL5_SSCS_SSCOP_NON_ASSURED = 2;
pub const AAL5_SSCS_FRAME_RELAY = 4;
pub const BCOB_A = 1;
pub const BCOB_C = 3;
pub const BCOB_X = 16;
pub const TT_NOIND = 0;
pub const TT_CBR = 4;
pub const TT_VBR = 8;
pub const TR_NOIND = 0;
pub const TR_END_TO_END = 1;
pub const TR_NO_END_TO_END = 2;
pub const CLIP_NOT = 0;
pub const CLIP_SUS = 32;
pub const UP_P2P = 0;
pub const UP_P2MP = 1;
pub const BLLI_L2_MODE_NORMAL = 64;
pub const BLLI_L2_MODE_EXT = 128;
pub const BLLI_L3_MODE_NORMAL = 64;
pub const BLLI_L3_MODE_EXT = 128;
pub const BLLI_L3_PACKET_16 = 4;
pub const BLLI_L3_PACKET_32 = 5;
pub const BLLI_L3_PACKET_64 = 6;
pub const BLLI_L3_PACKET_128 = 7;
pub const BLLI_L3_PACKET_256 = 8;
pub const BLLI_L3_PACKET_512 = 9;
pub const BLLI_L3_PACKET_1024 = 10;
pub const BLLI_L3_PACKET_2048 = 11;
pub const BLLI_L3_PACKET_4096 = 12;
pub const PI_ALLOWED = 0;
pub const PI_RESTRICTED = 64;
pub const PI_NUMBER_NOT_AVAILABLE = 128;
pub const SI_USER_NOT_SCREENED = 0;
pub const SI_USER_PASSED = 1;
pub const SI_USER_FAILED = 2;
pub const SI_NETWORK = 3;
pub const CAUSE_LOC_USER = 0;
pub const CAUSE_LOC_PRIVATE_LOCAL = 1;
pub const CAUSE_LOC_PUBLIC_LOCAL = 2;
pub const CAUSE_LOC_TRANSIT_NETWORK = 3;
pub const CAUSE_LOC_PUBLIC_REMOTE = 4;
pub const CAUSE_LOC_PRIVATE_REMOTE = 5;
pub const CAUSE_LOC_INTERNATIONAL_NETWORK = 7;
pub const CAUSE_LOC_BEYOND_INTERWORKING = 10;
pub const CAUSE_UNALLOCATED_NUMBER = 1;
pub const CAUSE_NO_ROUTE_TO_TRANSIT_NETWORK = 2;
pub const CAUSE_NO_ROUTE_TO_DESTINATION = 3;
pub const CAUSE_VPI_VCI_UNACCEPTABLE = 10;
pub const CAUSE_NORMAL_CALL_CLEARING = 16;
pub const CAUSE_USER_BUSY = 17;
pub const CAUSE_NO_USER_RESPONDING = 18;
pub const CAUSE_CALL_REJECTED = 21;
pub const CAUSE_NUMBER_CHANGED = 22;
pub const CAUSE_USER_REJECTS_CLIR = 23;
pub const CAUSE_DESTINATION_OUT_OF_ORDER = 27;
pub const CAUSE_INVALID_NUMBER_FORMAT = 28;
pub const CAUSE_STATUS_ENQUIRY_RESPONSE = 30;
pub const CAUSE_NORMAL_UNSPECIFIED = 31;
pub const CAUSE_VPI_VCI_UNAVAILABLE = 35;
pub const CAUSE_NETWORK_OUT_OF_ORDER = 38;
pub const CAUSE_TEMPORARY_FAILURE = 41;
pub const CAUSE_ACCESS_INFORMAION_DISCARDED = 43;
pub const CAUSE_NO_VPI_VCI_AVAILABLE = 45;
pub const CAUSE_RESOURCE_UNAVAILABLE = 47;
pub const CAUSE_QOS_UNAVAILABLE = 49;
pub const CAUSE_USER_CELL_RATE_UNAVAILABLE = 51;
pub const CAUSE_BEARER_CAPABILITY_UNAUTHORIZED = 57;
pub const CAUSE_BEARER_CAPABILITY_UNAVAILABLE = 58;
pub const CAUSE_OPTION_UNAVAILABLE = 63;
pub const CAUSE_BEARER_CAPABILITY_UNIMPLEMENTED = 65;
pub const CAUSE_UNSUPPORTED_TRAFFIC_PARAMETERS = 73;
pub const CAUSE_INVALID_CALL_REFERENCE = 81;
pub const CAUSE_CHANNEL_NONEXISTENT = 82;
pub const CAUSE_INCOMPATIBLE_DESTINATION = 88;
pub const CAUSE_INVALID_ENDPOINT_REFERENCE = 89;
pub const CAUSE_INVALID_TRANSIT_NETWORK_SELECTION = 91;
pub const CAUSE_TOO_MANY_PENDING_ADD_PARTY = 92;
pub const CAUSE_AAL_PARAMETERS_UNSUPPORTED = 93;
pub const CAUSE_MANDATORY_IE_MISSING = 96;
pub const CAUSE_UNIMPLEMENTED_MESSAGE_TYPE = 97;
pub const CAUSE_UNIMPLEMENTED_IE = 99;
pub const CAUSE_INVALID_IE_CONTENTS = 100;
pub const CAUSE_INVALID_STATE_FOR_MESSAGE = 101;
pub const CAUSE_RECOVERY_ON_TIMEOUT = 102;
pub const CAUSE_INCORRECT_MESSAGE_LENGTH = 104;
pub const CAUSE_PROTOCOL_ERROR = 111;
pub const CAUSE_COND_UNKNOWN = 0;
pub const CAUSE_COND_PERMANENT = 1;
pub const CAUSE_COND_TRANSIENT = 2;
pub const CAUSE_REASON_USER = 0;
pub const CAUSE_REASON_IE_MISSING = 4;
pub const CAUSE_REASON_IE_INSUFFICIENT = 8;
pub const CAUSE_PU_PROVIDER = 0;
pub const CAUSE_PU_USER = 8;
pub const CAUSE_NA_NORMAL = 0;
pub const CAUSE_NA_ABNORMAL = 4;
pub const QOS_CLASS0 = 0;
pub const QOS_CLASS1 = 1;
pub const QOS_CLASS2 = 2;
pub const QOS_CLASS3 = 3;
pub const QOS_CLASS4 = 4;
pub const TNS_TYPE_NATIONAL = 64;
pub const TNS_PLAN_CARRIER_ID_CODE = 1;
pub const SIO_GET_NUMBER_OF_ATM_DEVICES = 1343619073;
pub const SIO_GET_ATM_ADDRESS = 3491102722;
pub const SIO_ASSOCIATE_PVC = 2417360899;
pub const SIO_GET_ATM_CONNECTION_ID = 1343619076;
pub const RIO_MSG_DONT_NOTIFY = 1;
pub const RIO_MSG_DEFER = 2;
pub const RIO_MSG_WAITALL = 4;
pub const RIO_MSG_COMMIT_ONLY = 8;
pub const RIO_MAX_CQ_SIZE = 134217728;
pub const RIO_CORRUPT_CQ = 4294967295;
pub const WINDOWS_AF_IRDA = 26;
pub const WCE_AF_IRDA = 22;
pub const IRDA_PROTO_SOCK_STREAM = 1;
pub const IRLMP_ENUMDEVICES = 16;
pub const IRLMP_IAS_SET = 17;
pub const IRLMP_IAS_QUERY = 18;
pub const IRLMP_SEND_PDU_LEN = 19;
pub const IRLMP_EXCLUSIVE_MODE = 20;
pub const IRLMP_IRLPT_MODE = 21;
pub const IRLMP_9WIRE_MODE = 22;
pub const IRLMP_TINYTP_MODE = 23;
pub const IRLMP_PARAMETERS = 24;
pub const IRLMP_DISCOVERY_MODE = 25;
pub const IRLMP_SHARP_MODE = 32;
pub const IAS_ATTRIB_NO_CLASS = 16;
pub const IAS_ATTRIB_NO_ATTRIB = 0;
pub const IAS_ATTRIB_INT = 1;
pub const IAS_ATTRIB_OCTETSEQ = 2;
pub const IAS_ATTRIB_STR = 3;
pub const IAS_MAX_USER_STRING = 256;
pub const IAS_MAX_OCTET_STRING = 1024;
pub const IAS_MAX_CLASSNAME = 64;
pub const IAS_MAX_ATTRIBNAME = 256;
pub const LmCharSetASCII = 0;
pub const LmCharSetISO_8859_1 = 1;
pub const LmCharSetISO_8859_2 = 2;
pub const LmCharSetISO_8859_3 = 3;
pub const LmCharSetISO_8859_4 = 4;
pub const LmCharSetISO_8859_5 = 5;
pub const LmCharSetISO_8859_6 = 6;
pub const LmCharSetISO_8859_7 = 7;
pub const LmCharSetISO_8859_8 = 8;
pub const LmCharSetISO_8859_9 = 9;
pub const LmCharSetUNICODE = 255;
pub const LM_BAUD_1200 = 1200;
pub const LM_BAUD_2400 = 2400;
pub const LM_BAUD_9600 = 9600;
pub const LM_BAUD_19200 = 19200;
pub const LM_BAUD_38400 = 38400;
pub const LM_BAUD_57600 = 57600;
pub const LM_BAUD_115200 = 115200;
pub const LM_BAUD_576K = 576000;
pub const LM_BAUD_1152K = 1152000;
pub const LM_BAUD_4M = 4000000;
pub const LM_BAUD_16M = 16000000;
pub const IPX_PTYPE = 16384;
pub const IPX_FILTERPTYPE = 16385;
pub const IPX_STOPFILTERPTYPE = 16387;
pub const IPX_DSTYPE = 16386;
pub const IPX_EXTENDED_ADDRESS = 16388;
pub const IPX_RECVHDR = 16389;
pub const IPX_MAXSIZE = 16390;
pub const IPX_ADDRESS = 16391;
pub const IPX_GETNETINFO = 16392;
pub const IPX_GETNETINFO_NORIP = 16393;
pub const IPX_SPXGETCONNECTIONSTATUS = 16395;
pub const IPX_ADDRESS_NOTIFY = 16396;
pub const IPX_MAX_ADAPTER_NUM = 16397;
pub const IPX_RERIPNETNUMBER = 16398;
pub const IPX_RECEIVE_BROADCAST = 16399;
pub const IPX_IMMEDIATESPXACK = 16400;
pub const MAX_MCAST_TTL = 255;
pub const RM_OPTIONSBASE = 1000;
pub const RM_RATE_WINDOW_SIZE = 1001;
pub const RM_SET_MESSAGE_BOUNDARY = 1002;
pub const RM_FLUSHCACHE = 1003;
pub const RM_SENDER_WINDOW_ADVANCE_METHOD = 1004;
pub const RM_SENDER_STATISTICS = 1005;
pub const RM_LATEJOIN = 1006;
pub const RM_SET_SEND_IF = 1007;
pub const RM_ADD_RECEIVE_IF = 1008;
pub const RM_DEL_RECEIVE_IF = 1009;
pub const RM_SEND_WINDOW_ADV_RATE = 1010;
pub const RM_USE_FEC = 1011;
pub const RM_SET_MCAST_TTL = 1012;
pub const RM_RECEIVER_STATISTICS = 1013;
pub const RM_HIGH_SPEED_INTRANET_OPT = 1014;
pub const SENDER_DEFAULT_RATE_KBITS_PER_SEC = 56;
pub const SENDER_DEFAULT_WINDOW_ADV_PERCENTAGE = 15;
pub const MAX_WINDOW_INCREMENT_PERCENTAGE = 25;
pub const SENDER_DEFAULT_LATE_JOINER_PERCENTAGE = 0;
pub const SENDER_MAX_LATE_JOINER_PERCENTAGE = 75;
pub const BITS_PER_BYTE = 8;
pub const LOG2_BITS_PER_BYTE = 3;

pub const SOCKET_DEFAULT2_QM_POLICY = GUID.parse("{aec2ef9c-3a4d-4d3e-8842-239942e39a47}");
pub const REAL_TIME_NOTIFICATION_CAPABILITY = GUID.parse("{6b59819a-5cae-492d-a901-2a3c2c50164f}");
pub const REAL_TIME_NOTIFICATION_CAPABILITY_EX = GUID.parse("{6843da03-154a-4616-a508-44371295f96b}");
pub const ASSOCIATE_NAMERES_CONTEXT = GUID.parse("{59a38b67-d4fe-46e1-ba3c-87ea74ca3049}");

pub const WSAID_CONNECTEX = GUID{
    .Data1 = 0x25a207b9,
    .Data2 = 0xddf3,
    .Data3 = 0x4660,
    .Data4 = [8]u8{ 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e },
};

pub const WSAID_ACCEPTEX = GUID{
    .Data1 = 0xb5367df1,
    .Data2 = 0xcbac,
    .Data3 = 0x11cf,
    .Data4 = [8]u8{ 0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92 },
};

pub const WSAID_GETACCEPTEXSOCKADDRS = GUID{
    .Data1 = 0xb5367df2,
    .Data2 = 0xcbac,
    .Data3 = 0x11cf,
    .Data4 = [8]u8{ 0x95, 0xca, 0x00, 0x80, 0x5f, 0x48, 0xa1, 0x92 },
};

pub const WSAID_WSARECVMSG = GUID{
    .Data1 = 0xf689d7c8,
    .Data2 = 0x6f1f,
    .Data3 = 0x436b,
    .Data4 = [8]u8{ 0x8a, 0x53, 0xe5, 0x4f, 0xe3, 0x51, 0xc3, 0x22 },
};

pub const WSAID_WSAPOLL = GUID{
    .Data1 = 0x18C76F85,
    .Data2 = 0xDC66,
    .Data3 = 0x4964,
    .Data4 = [8]u8{ 0x97, 0x2E, 0x23, 0xC2, 0x72, 0x38, 0x31, 0x2B },
};

pub const WSAID_WSASENDMSG = GUID{
    .Data1 = 0xa441e712,
    .Data2 = 0x754f,
    .Data3 = 0x43ca,
    .Data4 = [8]u8{ 0x84, 0xa7, 0x0d, 0xee, 0x44, 0xcf, 0x60, 0x6d },
};

pub const TCP_INITIAL_RTO_DEFAULT_RTT = 0;
pub const TCP_INITIAL_RTO_DEFAULT_MAX_SYN_RETRANSMISSIONS = 0;
pub const SOCKET_SETTINGS_GUARANTEE_ENCRYPTION = 1;
pub const SOCKET_SETTINGS_ALLOW_INSECURE = 2;
pub const SOCKET_SETTINGS_IPSEC_SKIP_FILTER_INSTANTIATION = 1;
pub const SOCKET_SETTINGS_IPSEC_OPTIONAL_PEER_NAME_VERIFICATION = 2;
pub const SOCKET_SETTINGS_IPSEC_ALLOW_FIRST_INBOUND_PKT_UNENCRYPTED = 4;
pub const SOCKET_SETTINGS_IPSEC_PEER_NAME_IS_RAW_FORMAT = 8;
pub const SOCKET_QUERY_IPSEC2_ABORT_CONNECTION_ON_FIELD_CHANGE = 1;
pub const SOCKET_QUERY_IPSEC2_FIELD_MASK_MM_SA_ID = 1;
pub const SOCKET_QUERY_IPSEC2_FIELD_MASK_QM_SA_ID = 2;
pub const SOCKET_INFO_CONNECTION_SECURED = 1;
pub const SOCKET_INFO_CONNECTION_ENCRYPTED = 2;
pub const SOCKET_INFO_CONNECTION_IMPERSONATED = 4;
pub const IN4ADDR_LOOPBACK = 16777343;
pub const IN4ADDR_LOOPBACKPREFIX_LENGTH = 8;
pub const IN4ADDR_LINKLOCALPREFIX_LENGTH = 16;
pub const IN4ADDR_MULTICASTPREFIX_LENGTH = 4;
pub const IFF_UP = 1;
pub const IFF_BROADCAST = 2;
pub const IFF_LOOPBACK = 4;
pub const IFF_POINTTOPOINT = 8;
pub const IFF_MULTICAST = 16;
pub const IP_OPTIONS = 1;
pub const IP_HDRINCL = 2;
pub const IP_TOS = 3;
pub const IP_TTL = 4;
pub const IP_MULTICAST_IF = 9;
pub const IP_MULTICAST_TTL = 10;
pub const IP_MULTICAST_LOOP = 11;
pub const IP_ADD_MEMBERSHIP = 12;
pub const IP_DROP_MEMBERSHIP = 13;
pub const IP_DONTFRAGMENT = 14;
pub const IP_ADD_SOURCE_MEMBERSHIP = 15;
pub const IP_DROP_SOURCE_MEMBERSHIP = 16;
pub const IP_BLOCK_SOURCE = 17;
pub const IP_UNBLOCK_SOURCE = 18;
pub const IP_PKTINFO = 19;
pub const IP_HOPLIMIT = 21;
pub const IP_RECVTTL = 21;
pub const IP_RECEIVE_BROADCAST = 22;
pub const IP_RECVIF = 24;
pub const IP_RECVDSTADDR = 25;
pub const IP_IFLIST = 28;
pub const IP_ADD_IFLIST = 29;
pub const IP_DEL_IFLIST = 30;
pub const IP_UNICAST_IF = 31;
pub const IP_RTHDR = 32;
pub const IP_GET_IFLIST = 33;
pub const IP_RECVRTHDR = 38;
pub const IP_TCLASS = 39;
pub const IP_RECVTCLASS = 40;
pub const IP_RECVTOS = 40;
pub const IP_ORIGINAL_ARRIVAL_IF = 47;
pub const IP_ECN = 50;
pub const IP_PKTINFO_EX = 51;
pub const IP_WFP_REDIRECT_RECORDS = 60;
pub const IP_WFP_REDIRECT_CONTEXT = 70;
pub const IP_MTU_DISCOVER = 71;
pub const IP_MTU = 73;
pub const IP_NRT_INTERFACE = 74;
pub const IP_RECVERR = 75;
pub const IP_USER_MTU = 76;
pub const IP_UNSPECIFIED_TYPE_OF_SERVICE = -1;
pub const IN6ADDR_LINKLOCALPREFIX_LENGTH = 64;
pub const IN6ADDR_MULTICASTPREFIX_LENGTH = 8;
pub const IN6ADDR_SOLICITEDNODEMULTICASTPREFIX_LENGTH = 104;
pub const IN6ADDR_V4MAPPEDPREFIX_LENGTH = 96;
pub const IN6ADDR_6TO4PREFIX_LENGTH = 16;
pub const IN6ADDR_TEREDOPREFIX_LENGTH = 32;
pub const MCAST_JOIN_GROUP = 41;
pub const MCAST_LEAVE_GROUP = 42;
pub const MCAST_BLOCK_SOURCE = 43;
pub const MCAST_UNBLOCK_SOURCE = 44;
pub const MCAST_JOIN_SOURCE_GROUP = 45;
pub const MCAST_LEAVE_SOURCE_GROUP = 46;
pub const IPV6_HOPOPTS = 1;
pub const IPV6_HDRINCL = 2;
pub const IPV6_UNICAST_HOPS = 4;
pub const IPV6_MULTICAST_IF = 9;
pub const IPV6_MULTICAST_HOPS = 10;
pub const IPV6_MULTICA```
