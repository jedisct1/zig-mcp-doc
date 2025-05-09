```
RE = 0xC00002C7,
    /// {Virtual Memory Minimum Too Low} Your system is low on virtual memory.
    /// Windows is increasing the size of your virtual memory paging file.
    /// During this process, memory requests for some applications might be denied. For more information, see Help.
    COMMITMENT_MINIMUM = 0xC00002C8,
    /// {EXCEPTION} Register NaT consumption faults.
    /// A NaT value is consumed on a non-speculative instruction.
    REG_NAT_CONSUMPTION = 0xC00002C9,
    /// The transport element of the medium changer contains media, which is causing the operation to fail.
    TRANSPORT_FULL = 0xC00002CA,
    /// Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x.
    /// Click OK to shut down this system and restart in Directory Services Restore Mode.
    /// Check the event log for more detailed information.
    DS_SAM_INIT_FAILURE = 0xC00002CB,
    /// This operation is supported only when you are connected to the server.
    ONLY_IF_CONNECTED = 0xC00002CC,
    /// Only an administrator can modify the membership list of an administrative group.
    DS_SENSITIVE_GROUP_VIOLATION = 0xC00002CD,
    /// A device was removed so enumeration must be restarted.
    PNP_RESTART_ENUMERATION = 0xC00002CE,
    /// The journal entry has been deleted from the journal.
    JOURNAL_ENTRY_DELETED = 0xC00002CF,
    /// Cannot change the primary group ID of a domain controller account.
    DS_CANT_MOD_PRIMARYGROUPID = 0xC00002D0,
    /// {Fatal System Error} The system image %s is not properly signed.
    /// The file has been replaced with the signed file. The system has been shut down.
    SYSTEM_IMAGE_BAD_SIGNATURE = 0xC00002D1,
    /// The device will not start without a reboot.
    PNP_REBOOT_REQUIRED = 0xC00002D2,
    /// The power state of the current device cannot support this request.
    POWER_STATE_INVALID = 0xC00002D3,
    /// The specified group type is invalid.
    DS_INVALID_GROUP_TYPE = 0xC00002D4,
    /// In a mixed domain, no nesting of a global group if the group is security enabled.
    DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN = 0xC00002D5,
    /// In a mixed domain, cannot nest local groups with other local groups, if the group is security enabled.
    DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN = 0xC00002D6,
    /// A global group cannot have a local group as a member.
    DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER = 0xC00002D7,
    /// A global group cannot have a universal group as a member.
    DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER = 0xC00002D8,
    /// A universal group cannot have a local group as a member.
    DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER = 0xC00002D9,
    /// A global group cannot have a cross-domain member.
    DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER = 0xC00002DA,
    /// A local group cannot have another cross-domain local group as a member.
    DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER = 0xC00002DB,
    /// Cannot change to a security-disabled group because primary members are in this group.
    DS_HAVE_PRIMARY_MEMBERS = 0xC00002DC,
    /// The WMI operation is not supported by the data block or method.
    WMI_NOT_SUPPORTED = 0xC00002DD,
    /// There is not enough power to complete the requested operation.
    INSUFFICIENT_POWER = 0xC00002DE,
    /// The Security Accounts Manager needs to get the boot password.
    SAM_NEED_BOOTKEY_PASSWORD = 0xC00002DF,
    /// The Security Accounts Manager needs to get the boot key from the floppy disk.
    SAM_NEED_BOOTKEY_FLOPPY = 0xC00002E0,
    /// The directory service cannot start.
    DS_CANT_START = 0xC00002E1,
    /// The directory service could not start because of the following error: %hs Error Status: 0x%x.
    /// Click OK to shut down this system and restart in Directory Services Restore Mode.
    /// Check the event log for more detailed information.
    DS_INIT_FAILURE = 0xC00002E2,
    /// The Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x.
    /// Click OK to shut down this system and restart in Safe Mode.
    /// Check the event log for more detailed information.
    SAM_INIT_FAILURE = 0xC00002E3,
    /// The requested operation can be performed only on a global catalog server.
    DS_GC_REQUIRED = 0xC00002E4,
    /// A local group can only be a member of other local groups in the same domain.
    DS_LOCAL_MEMBER_OF_LOCAL_ONLY = 0xC00002E5,
    /// Foreign security principals cannot be members of universal groups.
    DS_NO_FPO_IN_UNIVERSAL_GROUPS = 0xC00002E6,
    /// Your computer could not be joined to the domain.
    /// You have exceeded the maximum number of computer accounts you are allowed to create in this domain.
    /// Contact your system administrator to have this limit reset or increased.
    DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED = 0xC00002E7,
    /// This operation cannot be performed on the current domain.
    CURRENT_DOMAIN_NOT_ALLOWED = 0xC00002E9,
    /// The directory or file cannot be created.
    CANNOT_MAKE = 0xC00002EA,
    /// The system is in the process of shutting down.
    SYSTEM_SHUTDOWN = 0xC00002EB,
    /// Directory Services could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system.
    /// You can use the recovery console to diagnose the system further.
    DS_INIT_FAILURE_CONSOLE = 0xC00002EC,
    /// Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system.
    /// You can use the recovery console to diagnose the system further.
    DS_SAM_INIT_FAILURE_CONSOLE = 0xC00002ED,
    /// A security context was deleted before the context was completed. This is considered a logon failure.
    UNFINISHED_CONTEXT_DELETED = 0xC00002EE,
    /// The client is trying to negotiate a context and the server requires user-to-user but did not send a TGT reply.
    NO_TGT_REPLY = 0xC00002EF,
    /// An object ID was not found in the file.
    OBJECTID_NOT_FOUND = 0xC00002F0,
    /// Unable to accomplish the requested task because the local machine does not have any IP addresses.
    NO_IP_ADDRESSES = 0xC00002F1,
    /// The supplied credential handle does not match the credential that is associated with the security context.
    WRONG_CREDENTIAL_HANDLE = 0xC00002F2,
    /// The crypto system or checksum function is invalid because a required function is unavailable.
    CRYPTO_SYSTEM_INVALID = 0xC00002F3,
    /// The number of maximum ticket referrals has been exceeded.
    MAX_REFERRALS_EXCEEDED = 0xC00002F4,
    /// The local machine must be a Kerberos KDC (domain controller) and it is not.
    MUST_BE_KDC = 0xC00002F5,
    /// The other end of the security negotiation requires strong crypto but it is not supported on the local machine.
    STRONG_CRYPTO_NOT_SUPPORTED = 0xC00002F6,
    /// The KDC reply contained more than one principal name.
    TOO_MANY_PRINCIPALS = 0xC00002F7,
    /// Expected to find PA data for a hint of what etype to use, but it was not found.
    NO_PA_DATA = 0xC00002F8,
    /// The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Contact your administrator.
    PKINIT_NAME_MISMATCH = 0xC00002F9,
    /// Smart card logon is required and was not used.
    SMARTCARD_LOGON_REQUIRED = 0xC00002FA,
    /// An invalid request was sent to the KDC.
    KDC_INVALID_REQUEST = 0xC00002FB,
    /// The KDC was unable to generate a referral for the service requested.
    KDC_UNABLE_TO_REFER = 0xC00002FC,
    /// The encryption type requested is not supported by the KDC.
    KDC_UNKNOWN_ETYPE = 0xC00002FD,
    /// A system shutdown is in progress.
    SHUTDOWN_IN_PROGRESS = 0xC00002FE,
    /// The server machine is shutting down.
    SERVER_SHUTDOWN_IN_PROGRESS = 0xC00002FF,
    /// This operation is not supported on a computer running Windows Server 2003 operating system for Small Business Server.
    NOT_SUPPORTED_ON_SBS = 0xC0000300,
    /// The WMI GUID is no longer available.
    WMI_GUID_DISCONNECTED = 0xC0000301,
    /// Collection or events for the WMI GUID is already disabled.
    WMI_ALREADY_DISABLED = 0xC0000302,
    /// Collection or events for the WMI GUID is already enabled.
    WMI_ALREADY_ENABLED = 0xC0000303,
    /// The master file table on the volume is too fragmented to complete this operation.
    MFT_TOO_FRAGMENTED = 0xC0000304,
    /// Copy protection failure.
    COPY_PROTECTION_FAILURE = 0xC0000305,
    /// Copy protection error—DVD CSS Authentication failed.
    CSS_AUTHENTICATION_FAILURE = 0xC0000306,
    /// Copy protection error—The specified sector does not contain a valid key.
    CSS_KEY_NOT_PRESENT = 0xC0000307,
    /// Copy protection error—DVD session key not established.
    CSS_KEY_NOT_ESTABLISHED = 0xC0000308,
    /// Copy protection error—The read failed because the sector is encrypted.
    CSS_SCRAMBLED_SECTOR = 0xC0000309,
    /// Copy protection error—The region of the specified DVD does not correspond to the region setting of the drive.
    CSS_REGION_MISMATCH = 0xC000030A,
    /// Copy protection error—The region setting of the drive might be permanent.
    CSS_RESETS_EXHAUSTED = 0xC000030B,
    /// The Kerberos protocol encountered an error while validating the KDC certificate during smart card logon.
    /// There is more information in the system event log.
    PKINIT_FAILURE = 0xC0000320,
    /// The Kerberos protocol encountered an error while attempting to use the smart card subsystem.
    SMARTCARD_SUBSYSTEM_FAILURE = 0xC0000321,
    /// The target server does not have acceptable Kerberos credentials.
    NO_KERB_KEY = 0xC0000322,
    /// The transport determined that the remote system is down.
    HOST_DOWN = 0xC0000350,
    /// An unsupported pre-authentication mechanism was presented to the Kerberos package.
    UNSUPPORTED_PREAUTH = 0xC0000351,
    /// The encryption algorithm that is used on the source file needs a bigger key buffer than the one that is used on the destination file.
    EFS_ALG_BLOB_TOO_BIG = 0xC0000352,
    /// An attempt to remove a processes DebugPort was made, but a port was not already associated with the process.
    PORT_NOT_SET = 0xC0000353,
    /// An attempt to do an operation on a debug port failed because the port is in the process of being deleted.
    DEBUGGER_INACTIVE = 0xC0000354,
    /// This version of Windows is not compatible with the behavior version of the directory forest, domain, or domain controller.
    DS_VERSION_CHECK_FAILURE = 0xC0000355,
    /// The specified event is currently not being audited.
    AUDITING_DISABLED = 0xC0000356,
    /// The machine account was created prior to Windows NT 4.0 operating system. The account needs to be recreated.
    PRENT4_MACHINE_ACCOUNT = 0xC0000357,
    /// An account group cannot have a universal group as a member.
    DS_AG_CANT_HAVE_UNIVERSAL_MEMBER = 0xC0000358,
    /// The specified image file did not have the correct format; it appears to be a 32-bit Windows image.
    INVALID_IMAGE_WIN_32 = 0xC0000359,
    /// The specified image file did not have the correct format; it appears to be a 64-bit Windows image.
    INVALID_IMAGE_WIN_64 = 0xC000035A,
    /// The client's supplied SSPI channel bindings were incorrect.
    BAD_BINDINGS = 0xC000035B,
    /// The client session has expired; so the client must re-authenticate to continue accessing the remote resources.
    NETWORK_SESSION_EXPIRED = 0xC000035C,
    /// The AppHelp dialog box canceled; thus preventing the application from starting.
    APPHELP_BLOCK = 0xC000035D,
    /// The SID filtering operation removed all SIDs.
    ALL_SIDS_FILTERED = 0xC000035E,
    /// The driver was not loaded because the system is starting in safe mode.
    NOT_SAFE_MODE_DRIVER = 0xC000035F,
    /// Access to %1 has been restricted by your Administrator by the default software restriction policy level.
    ACCESS_DISABLED_BY_POLICY_DEFAULT = 0xC0000361,
    /// Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3.
    ACCESS_DISABLED_BY_POLICY_PATH = 0xC0000362,
    /// Access to %1 has been restricted by your Administrator by software publisher policy.
    ACCESS_DISABLED_BY_POLICY_PUBLISHER = 0xC0000363,
    /// Access to %1 has been restricted by your Administrator by policy rule %2.
    ACCESS_DISABLED_BY_POLICY_OTHER = 0xC0000364,
    /// The driver was not loaded because it failed its initialization call.
    FAILED_DRIVER_ENTRY = 0xC0000365,
    /// The device encountered an error while applying power or reading the device configuration.
    /// This might be caused by a failure of your hardware or by a poor connection.
    DEVICE_ENUMERATION_ERROR = 0xC0000366,
    /// The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached.
    MOUNT_POINT_NOT_RESOLVED = 0xC0000368,
    /// The device object parameter is either not a valid device object or is not attached to the volume that is specified by the file name.
    INVALID_DEVICE_OBJECT_PARAMETER = 0xC0000369,
    /// A machine check error has occurred.
    /// Check the system event log for additional information.
    MCA_OCCURED = 0xC000036A,
    /// Driver %2 has been blocked from loading.
    DRIVER_BLOCKED_CRITICAL = 0xC000036B,
    /// Driver %2 has been blocked from loading.
    DRIVER_BLOCKED = 0xC000036C,
    /// There was error [%2] processing the driver database.
    DRIVER_DATABASE_ERROR = 0xC000036D,
    /// System hive size has exceeded its limit.
    SYSTEM_HIVE_TOO_LARGE = 0xC000036E,
    /// A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.
    INVALID_IMPORT_OF_NON_DLL = 0xC000036F,
    /// The local account store does not contain secret material for the specified account.
    NO_SECRETS = 0xC0000371,
    /// Access to %1 has been restricted by your Administrator by policy rule %2.
    ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY = 0xC0000372,
    /// The system was not able to allocate enough memory to perform a stack switch.
    FAILED_STACK_SWITCH = 0xC0000373,
    /// A heap has been corrupted.
    HEAP_CORRUPTION = 0xC0000374,
    /// An incorrect PIN was presented to the smart card.
    SMARTCARD_WRONG_PIN = 0xC0000380,
    /// The smart card is blocked.
    SMARTCARD_CARD_BLOCKED = 0xC0000381,
    /// No PIN was presented to the smart card.
    SMARTCARD_CARD_NOT_AUTHENTICATED = 0xC0000382,
    /// No smart card is available.
    SMARTCARD_NO_CARD = 0xC0000383,
    /// The requested key container does not exist on the smart card.
    SMARTCARD_NO_KEY_CONTAINER = 0xC0000384,
    /// The requested certificate does not exist on the smart card.
    SMARTCARD_NO_CERTIFICATE = 0xC0000385,
    /// The requested keyset does not exist.
    SMARTCARD_NO_KEYSET = 0xC0000386,
    /// A communication error with the smart card has been detected.
    SMARTCARD_IO_ERROR = 0xC0000387,
    /// The system detected a possible attempt to compromise security.
    /// Ensure that you can contact the server that authenticated you.
    DOWNGRADE_DETECTED = 0xC0000388,
    /// The smart card certificate used for authentication has been revoked. Contact your system administrator.
    /// There might be additional information in the event log.
    SMARTCARD_CERT_REVOKED = 0xC0000389,
    /// An untrusted certificate authority was detected while processing the smart card certificate that is used for authentication. Contact your system administrator.
    ISSUING_CA_UNTRUSTED = 0xC000038A,
    /// The revocation status of the smart card certificate that is used for authentication could not be determined. Contact your system administrator.
    REVOCATION_OFFLINE_C = 0xC000038B,
    /// The smart card certificate used for authentication was not trusted. Contact your system administrator.
    PKINIT_CLIENT_FAILURE = 0xC000038C,
    /// The smart card certificate used for authentication has expired. Contact your system administrator.
    SMARTCARD_CERT_EXPIRED = 0xC000038D,
    /// The driver could not be loaded because a previous version of the driver is still in memory.
    DRIVER_FAILED_PRIOR_UNLOAD = 0xC000038E,
    /// The smart card provider could not perform the action because the context was acquired as silent.
    SMARTCARD_SILENT_CONTEXT = 0xC000038F,
    /// The delegated trust creation quota of the current user has been exceeded.
    PER_USER_TRUST_QUOTA_EXCEEDED = 0xC0000401,
    /// The total delegated trust creation quota has been exceeded.
    ALL_USER_TRUST_QUOTA_EXCEEDED = 0xC0000402,
    /// The delegated trust deletion quota of the current user has been exceeded.
    USER_DELETE_TRUST_QUOTA_EXCEEDED = 0xC0000403,
    /// The requested name already exists as a unique identifier.
    DS_NAME_NOT_UNIQUE = 0xC0000404,
    /// The requested object has a non-unique identifier and cannot be retrieved.
    DS_DUPLICATE_ID_FOUND = 0xC0000405,
    /// The group cannot be converted due to attribute restrictions on the requested group type.
    DS_GROUP_CONVERSION_ERROR = 0xC0000406,
    /// {Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.
    VOLSNAP_PREPARE_HIBERNATE = 0xC0000407,
    /// Kerberos sub-protocol User2User is required.
    USER2USER_REQUIRED = 0xC0000408,
    /// The system detected an overrun of a stack-based buffer in this application.
    /// This overrun could potentially allow a malicious user to gain control of this application.
    STACK_BUFFER_OVERRUN = 0xC0000409,
    /// The Kerberos subsystem encountered an error.
    /// A service for user protocol request was made against a domain controller which does not support service for user.
    NO_S4U_PROT_SUPPORT = 0xC000040A,
    /// An attempt was made by this server to make a Kerberos constrained delegation request for a target that is outside the server realm.
    /// This action is not supported and the resulting error indicates a misconfiguration on the allowed-to-delegate-to list for this server. Contact your administrator.
    CROSSREALM_DELEGATION_FAILURE = 0xC000040B,
    /// The revocation status of the domain controller certificate used for smart card authentication could not be determined.
    /// There is additional information in the system event log. Contact your system administrator.
    REVOCATION_OFFLINE_KDC = 0xC000040C,
    /// An untrusted certificate authority was detected while processing the domain controller certificate used for authentication.
    /// There is additional information in the system event log. Contact your system administrator.
    ISSUING_CA_UNTRUSTED_KDC = 0xC000040D,
    /// The domain controller certificate used for smart card logon has expired.
    /// Contact your system administrator with the contents of your system event log.
    KDC_CERT_EXPIRED = 0xC000040E,
    /// The domain controller certificate used for smart card logon has been revoked.
    /// Contact your system administrator with the contents of your system event log.
    KDC_CERT_REVOKED = 0xC000040F,
    /// Data present in one of the parameters is more than the function can operate on.
    PARAMETER_QUOTA_EXCEEDED = 0xC0000410,
    /// The system has failed to hibernate (The error code is %hs).
    /// Hibernation will be disabled until the system is restarted.
    HIBERNATION_FAILURE = 0xC0000411,
    /// An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed.
    DELAY_LOAD_FAILED = 0xC0000412,
    /// Logon Failure: The machine you are logging onto is protected by an authentication firewall.
    /// The specified account is not allowed to authenticate to the machine.
    AUTHENTICATION_FIREWALL_FAILED = 0xC0000413,
    /// %hs is a 16-bit application. You do not have permissions to execute 16-bit applications.
    /// Check your permissions with your system administrator.
    VDM_DISALLOWED = 0xC0000414,
    /// {Display Driver Stopped Responding} The %hs display driver has stopped working normally.
    /// Save your work and reboot the system to restore full display functionality.
    /// The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft.
    HUNG_DISPLAY_DRIVER_THREAD = 0xC0000415,
    /// The Desktop heap encountered an error while allocating session memory.
    /// There is more information in the system event log.
    INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE = 0xC0000416,
    /// An invalid parameter was passed to a C runtime function.
    INVALID_CRUNTIME_PARAMETER = 0xC0000417,
    /// The authentication failed because NTLM was blocked.
    NTLM_BLOCKED = 0xC0000418,
    /// The source object's SID already exists in destination forest.
    DS_SRC_SID_EXISTS_IN_FOREST = 0xC0000419,
    /// The domain name of the trusted domain already exists in the forest.
    DS_DOMAIN_NAME_EXISTS_IN_FOREST = 0xC000041A,
    /// The flat name of the trusted domain already exists in the forest.
    DS_FLAT_NAME_EXISTS_IN_FOREST = 0xC000041B,
    /// The User Principal Name (UPN) is invalid.
    INVALID_USER_PRINCIPAL_NAME = 0xC000041C,
    /// There has been an assertion failure.
    ASSERTION_FAILURE = 0xC0000420,
    /// Application verifier has found an error in the current process.
    VERIFIER_STOP = 0xC0000421,
    /// A user mode unwind is in progress.
    CALLBACK_POP_STACK = 0xC0000423,
    /// %2 has been blocked from loading due to incompatibility with this system.
    /// Contact your software vendor for a compatible version of the driver.
    INCOMPATIBLE_DRIVER_BLOCKED = 0xC0000424,
    /// Illegal operation attempted on a registry key which has already been unloaded.
    HIVE_UNLOADED = 0xC0000425,
    /// Compression is disabled for this volume.
    COMPRESSION_DISABLED = 0xC0000426,
    /// The requested operation could not be completed due to a file system limitation.
    FILE_SYSTEM_LIMITATION = 0xC0000427,
    /// The hash for image %hs cannot be found in the system catalogs.
    /// The image is likely corrupt or the victim of tampering.
    INVALID_IMAGE_HASH = 0xC0000428,
    /// The implementation is not capable of performing the request.
    NOT_CAPABLE = 0xC0000429,
    /// The requested operation is out of order with respect to other operations.
    REQUEST_OUT_OF_SEQUENCE = 0xC000042A,
    /// An operation attempted to exceed an implementation-defined limit.
    IMPLEMENTATION_LIMIT = 0xC000042B,
    /// The requested operation requires elevation.
    ELEVATION_REQUIRED = 0xC000042C,
    /// The required security context does not exist.
    NO_SECURITY_CONTEXT = 0xC000042D,
    /// The PKU2U protocol encountered an error while attempting to utilize the associated certificates.
    PKU2U_CERT_FAILURE = 0xC000042E,
    /// The operation was attempted beyond the valid data length of the file.
    BEYOND_VDL = 0xC0000432,
    /// The attempted write operation encountered a write already in progress for some portion of the range.
    ENCOUNTERED_WRITE_IN_PROGRESS = 0xC0000433,
    /// The page fault mappings changed in the middle of processing a fault so the operation must be retried.
    PTE_CHANGED = 0xC0000434,
    /// The attempt to purge this file from memory failed to purge some or all the data from memory.
    PURGE_FAILED = 0xC0000435,
    /// The requested credential requires confirmation.
    CRED_REQUIRES_CONFIRMATION = 0xC0000440,
    /// The remote server sent an invalid response for a file being opened with Client Side Encryption.
    CS_ENCRYPTION_INVALID_SERVER_RESPONSE = 0xC0000441,
    /// Client Side Encryption is not supported by the remote server even though it claims to support it.
    CS_ENCRYPTION_UNSUPPORTED_SERVER = 0xC0000442,
    /// File is encrypted and should be opened in Client Side Encryption mode.
    CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE = 0xC0000443,
    /// A new encrypted file is being created and a $EFS needs to be provided.
    CS_ENCRYPTION_NEW_ENCRYPTED_FILE = 0xC0000444,
    /// The SMB client requested a CSE FSCTL on a non-CSE file.
    CS_ENCRYPTION_FILE_NOT_CSE = 0xC0000445,
    /// Indicates a particular Security ID cannot be assigned as the label of an object.
    INVALID_LABEL = 0xC0000446,
    /// The process hosting the driver for this device has terminated.
    DRIVER_PROCESS_TERMINATED = 0xC0000450,
    /// The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria.
    AMBIGUOUS_SYSTEM_DEVICE = 0xC0000451,
    /// The requested system device cannot be found.
    SYSTEM_DEVICE_NOT_FOUND = 0xC0000452,
    /// This boot application must be restarted.
    RESTART_BOOT_APPLICATION = 0xC0000453,
    /// Insufficient NVRAM resources exist to complete the API.  A reboot might be required.
    INSUFFICIENT_NVRAM_RESOURCES = 0xC0000454,
    /// No ranges for the specified operation were able to be processed.
    NO_RANGES_PROCESSED = 0xC0000460,
    /// The storage device does not support Offload Write.
    DEVICE_FEATURE_NOT_SUPPORTED = 0xC0000463,
    /// Data cannot be moved because the source device cannot communicate with the destination device.
    DEVICE_UNREACHABLE = 0xC0000464,
    /// The token representing the data is invalid or expired.
    INVALID_TOKEN = 0xC0000465,
    /// The file server is temporarily unavailable.
    SERVER_UNAVAILABLE = 0xC0000466,
    /// The specified task name is invalid.
    INVALID_TASK_NAME = 0xC0000500,
    /// The specified task index is invalid.
    INVALID_TASK_INDEX = 0xC0000501,
    /// The specified thread is already joining a task.
    THREAD_ALREADY_IN_TASK = 0xC0000502,
    /// A callback has requested to bypass native code.
    CALLBACK_BYPASS = 0xC0000503,
    /// A fail fast exception occurred.
    /// Exception handlers will not be invoked and the process will be terminated immediately.
    FAIL_FAST_EXCEPTION = 0xC0000602,
    /// Windows cannot verify the digital signature for this file.
    /// The signing certificate for this file has been revoked.
    IMAGE_CERT_REVOKED = 0xC0000603,
    /// The ALPC port is closed.
    PORT_CLOSED = 0xC0000700,
    /// The ALPC message requested is no longer available.
    MESSAGE_LOST = 0xC0000701,
    /// The ALPC message supplied is invalid.
    INVALID_MESSAGE = 0xC0000702,
    /// The ALPC message has been canceled.
    REQUEST_CANCELED = 0xC0000703,
    /// Invalid recursive dispatch attempt.
    RECURSIVE_DISPATCH = 0xC0000704,
    /// No receive buffer has been supplied in a synchronous request.
    LPC_RECEIVE_BUFFER_EXPECTED = 0xC0000705,
    /// The connection port is used in an invalid context.
    LPC_INVALID_CONNECTION_USAGE = 0xC0000706,
    /// The ALPC port does not accept new request messages.
    LPC_REQUESTS_NOT_ALLOWED = 0xC0000707,
    /// The resource requested is already in use.
    RESOURCE_IN_USE = 0xC0000708,
    /// The hardware has reported an uncorrectable memory error.
    HARDWARE_MEMORY_ERROR = 0xC0000709,
    /// Status 0x%08x was returned, waiting on handle 0x%x for wait 0x%p, in waiter 0x%p.
    THREADPOOL_HANDLE_EXCEPTION = 0xC000070A,
    /// After a callback to 0x%p(0x%p), a completion call to Set event(0x%p) failed with status 0x%08x.
    THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED = 0xC000070B,
    /// After a callback to 0x%p(0x%p), a completion call to ReleaseSemaphore(0x%p, %d) failed with status 0x%08x.
    THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED = 0xC000070C,
    /// After a callback to 0x%p(0x%p), a completion call to ReleaseMutex(%p) failed with status 0x%08x.
    THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED = 0xC000070D,
    /// After a callback to 0x%p(0x%p), a completion call to FreeLibrary(%p) failed with status 0x%08x.
    THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED = 0xC000070E,
    /// The thread pool 0x%p was released while a thread was posting a callback to 0x%p(0x%p) to it.
    THREADPOOL_RELEASED_DURING_OPERATION = 0xC000070F,
    /// A thread pool worker thread is impersonating a client, after a callback to 0x%p(0x%p).
    /// This is unexpected, indicating that the callback is missing a call to revert the impersonation.
    CALLBACK_RETURNED_WHILE_IMPERSONATING = 0xC0000710,
    /// A thread pool worker thread is impersonating a client, after executing an APC.
    /// This is unexpected, indicating that the APC is missing a call to revert the impersonation.
    APC_RETURNED_WHILE_IMPERSONATING = 0xC0000711,
    /// Either the target process, or the target thread's containing process, is a protected process.
    PROCESS_IS_PROTECTED = 0xC0000712,
    /// A thread is getting dispatched with MCA EXCEPTION because of MCA.
    MCA_EXCEPTION = 0xC0000713,
    /// The client certificate account mapping is not unique.
    CERTIFICATE_MAPPING_NOT_UNIQUE = 0xC0000714,
    /// The symbolic link cannot be followed because its type is disabled.
    SYMLINK_CLASS_DISABLED = 0xC0000715,
    /// Indicates that the specified string is not valid for IDN normalization.
    INVALID_IDN_NORMALIZATION = 0xC0000716,
    /// No mapping for the Unicode character exists in the target multi-byte code page.
    NO_UNICODE_TRANSLATION = 0xC0000717,
    /// The provided callback is already registered.
    ALREADY_REGISTERED = 0xC0000718,
    /// The provided context did not match the target.
    CONTEXT_MISMATCH = 0xC0000719,
    /// The specified port already has a completion list.
    PORT_ALREADY_HAS_COMPLETION_LIST = 0xC000071A,
    /// A threadpool worker thread entered a callback at thread base priority 0x%x and exited at priority 0x%x.
    /// This is unexpected, indicating that the callback missed restoring the priority.
    CALLBACK_RETURNED_THREAD_PRIORITY = 0xC000071B,
    /// An invalid thread, handle %p, is specified for this operation.
    /// Possibly, a threadpool worker thread was specified.
    INVALID_THREAD = 0xC000071C,
    /// A threadpool worker thread entered a callback, which left transaction state.
    /// This is unexpected, indicating that the callback missed clearing the transaction.
    CALLBACK_RETURNED_TRANSACTION = 0xC000071D,
    /// A threadpool worker thread entered a callback, which left the loader lock held.
    /// This is unexpected, indicating that the callback missed releasing the lock.
    CALLBACK_RETURNED_LDR_LOCK = 0xC000071E,
    /// A threadpool worker thread entered a callback, which left with preferred languages set.
    /// This is unexpected, indicating that the callback missed clearing them.
    CALLBACK_RETURNED_LANG = 0xC000071F,
    /// A threadpool worker thread entered a callback, which left with background priorities set.
    /// This is unexpected, indicating that the callback missed restoring the original priorities.
    CALLBACK_RETURNED_PRI_BACK = 0xC0000720,
    /// The attempted operation required self healing to be enabled.
    DISK_REPAIR_DISABLED = 0xC0000800,
    /// The directory service cannot perform the requested operation because a domain rename operation is in progress.
    DS_DOMAIN_RENAME_IN_PROGRESS = 0xC0000801,
    /// An operation failed because the storage quota was exceeded.
    DISK_QUOTA_EXCEEDED = 0xC0000802,
    /// An operation failed because the content was blocked.
    CONTENT_BLOCKED = 0xC0000804,
    /// The operation could not be completed due to bad clusters on disk.
    BAD_CLUSTERS = 0xC0000805,
    /// The operation could not be completed because the volume is dirty. Please run the Chkdsk utility and try again.
    VOLUME_DIRTY = 0xC0000806,
    /// This file is checked out or locked for editing by another user.
    FILE_CHECKED_OUT = 0xC0000901,
    /// The file must be checked out before saving changes.
    CHECKOUT_REQUIRED = 0xC0000902,
    /// The file type being saved or retrieved has been blocked.
    BAD_FILE_TYPE = 0xC0000903,
    /// The file size exceeds the limit allowed and cannot be saved.
    FILE_TOO_LARGE = 0xC0000904,
    /// Access Denied. Before opening files in this location, you must first browse to the e.g.
    /// site and select the option to log on automatically.
    FORMS_AUTH_REQUIRED = 0xC0000905,
    /// The operation did not complete successfully because the file contains a virus.
    VIRUS_INFECTED = 0xC0000906,
    /// This file contains a virus and cannot be opened.
    /// Due to the nature of this virus, the file has been removed from this location.
    VIRUS_DELETED = 0xC0000907,
    /// The resources required for this device conflict with the MCFG table.
    BAD_MCFG_TABLE = 0xC0000908,
    /// The operation did not complete successfully because it would cause an oplock to be broken.
    /// The caller has requested that existing oplocks not be broken.
    CANNOT_BREAK_OPLOCK = 0xC0000909,
    /// WOW Assertion Error.
    WOW_ASSERTION = 0xC0009898,
    /// The cryptographic signature is invalid.
    INVALID_SIGNATURE = 0xC000A000,
    /// The cryptographic provider does not support HMAC.
    HMAC_NOT_SUPPORTED = 0xC000A001,
    /// The IPsec queue overflowed.
    IPSEC_QUEUE_OVERFLOW = 0xC000A010,
    /// The neighbor discovery queue overflowed.
    ND_QUEUE_OVERFLOW = 0xC000A011,
    /// An Internet Control Message Protocol (ICMP) hop limit exceeded error was received.
    HOPLIMIT_EXCEEDED = 0xC000A012,
    /// The protocol is not installed on the local machine.
    PROTOCOL_NOT_SUPPORTED = 0xC000A013,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost.
    /// This error might be caused by network connectivity issues. Try to save this file elsewhere.
    LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED = 0xC000A080,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost.
    /// This error was returned by the server on which the file exists. Try to save this file elsewhere.
    LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR = 0xC000A081,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost.
    /// This error might be caused if the device has been removed or the media is write-protected.
    LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR = 0xC000A082,
    /// Windows was unable to parse the requested XML data.
    XML_PARSE_ERROR = 0xC000A083,
    /// An error was encountered while processing an XML digital signature.
    XMLDSIG_ERROR = 0xC000A084,
    /// This indicates that the caller made the connection request in the wrong routing compartment.
    WRONG_COMPARTMENT = 0xC000A085,
    /// This indicates that there was an AuthIP failure when attempting to connect to the remote host.
    AUTHIP_FAILURE = 0xC000A086,
    /// OID mapped groups cannot have members.
    DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS = 0xC000A087,
    /// The specified OID cannot be found.
    DS_OID_NOT_FOUND = 0xC000A088,
    /// Hash generation for the specified version and hash type is not enabled on server.
    HASH_NOT_SUPPORTED = 0xC000A100,
    /// The hash requests is not present or not up to date with the current file contents.
    HASH_NOT_PRESENT = 0xC000A101,
    /// A file system filter on the server has not opted in for Offload Read support.
    OFFLOAD_READ_FLT_NOT_SUPPORTED = 0xC000A2A1,
    /// A file system filter on the server has not opted in for Offload Write support.
    OFFLOAD_WRITE_FLT_NOT_SUPPORTED = 0xC000A2A2,
    /// Offload read operations cannot be performed on:
    ///   - Compressed files
    ///   - Sparse files
    ///   - Encrypted files
    ///   - File system metadata files
    OFFLOAD_READ_FILE_NOT_SUPPORTED = 0xC000A2A3,
    /// Offload write operations cannot be performed on:
    ///  - Compressed files
    ///  - Sparse files
    ///  - Encrypted files
    ///  - File system metadata files
    OFFLOAD_WRITE_FILE_NOT_SUPPORTED = 0xC000A2A4,
    /// The debugger did not perform a state change.
    DBG_NO_STATE_CHANGE = 0xC0010001,
    /// The debugger found that the application is not idle.
    DBG_APP_NOT_IDLE = 0xC0010002,
    /// The string binding is invalid.
    RPC_NT_INVALID_STRING_BINDING = 0xC0020001,
    /// The binding handle is not the correct type.
    RPC_NT_WRONG_KIND_OF_BINDING = 0xC0020002,
    /// The binding handle is invalid.
    RPC_NT_INVALID_BINDING = 0xC0020003,
    /// The RPC protocol sequence is not supported.
    RPC_NT_PROTSEQ_NOT_SUPPORTED = 0xC0020004,
    /// The RPC protocol sequence is invalid.
    RPC_NT_INVALID_RPC_PROTSEQ = 0xC0020005,
    /// The string UUID is invalid.
    RPC_NT_INVALID_STRING_UUID = 0xC0020006,
    /// The endpoint format is invalid.
    RPC_NT_INVALID_ENDPOINT_FORMAT = 0xC0020007,
    /// The network address is invalid.
    RPC_NT_INVALID_NET_ADDR = 0xC0020008,
    /// No endpoint was found.
    RPC_NT_NO_ENDPOINT_FOUND = 0xC0020009,
    /// The time-out value is invalid.
    RPC_NT_INVALID_TIMEOUT = 0xC002000A,
    /// The object UUID was not found.
    RPC_NT_OBJECT_NOT_FOUND = 0xC002000B,
    /// The object UUID has already been registered.
    RPC_NT_ALREADY_REGISTERED = 0xC002000C,
    /// The type UUID has already been registered.
    RPC_NT_TYPE_ALREADY_REGISTERED = 0xC002000D,
    /// The RPC server is already listening.
    RPC_NT_ALREADY_LISTENING = 0xC002000E,
    /// No protocol sequences have been registered.
    RPC_NT_NO_PROTSEQS_REGISTERED = 0xC002000F,
    /// The RPC server is not listening.
    RPC_NT_NOT_LISTENING = 0xC0020010,
    /// The manager type is unknown.
    RPC_NT_UNKNOWN_MGR_TYPE = 0xC0020011,
    /// The interface is unknown.
    RPC_NT_UNKNOWN_IF = 0xC0020012,
    /// There are no bindings.
    RPC_NT_NO_BINDINGS = 0xC0020013,
    /// There are no protocol sequences.
    RPC_NT_NO_PROTSEQS = 0xC0020014,
    /// The endpoint cannot be created.
    RPC_NT_CANT_CREATE_ENDPOINT = 0xC0020015,
    /// Insufficient resources are available to complete this operation.
    RPC_NT_OUT_OF_RESOURCES = 0xC0020016,
    /// The RPC server is unavailable.
    RPC_NT_SERVER_UNAVAILABLE = 0xC0020017,
    /// The RPC server is too busy to complete this operation.
    RPC_NT_SERVER_TOO_BUSY = 0xC0020018,
    /// The network options are invalid.
    RPC_NT_INVALID_NETWORK_OPTIONS = 0xC0020019,
    /// No RPCs are active on this thread.
    RPC_NT_NO_CALL_ACTIVE = 0xC002001A,
    /// The RPC failed.
    RPC_NT_CALL_FAILED = 0xC002001B,
    /// The RPC failed and did not execute.
    RPC_NT_CALL_FAILED_DNE = 0xC002001C,
    /// An RPC protocol error occurred.
    RPC_NT_PROTOCOL_ERROR = 0xC002001D,
    /// The RPC server does not support the transfer syntax.
    RPC_NT_UNSUPPORTED_TRANS_SYN = 0xC002001F,
    /// The type UUID is not supported.
    RPC_NT_UNSUPPORTED_TYPE = 0xC0020021,
    /// The tag is invalid.
    RPC_NT_INVALID_TAG = 0xC0020022,
    /// The array bounds are invalid.
    RPC_NT_INVALID_BOUND = 0xC0020023,
    /// The binding does not contain an entry name.
    RPC_NT_NO_ENTRY_NAME = 0xC0020024,
    /// The name syntax is invalid.
    RPC_NT_INVALID_NAME_SYNTAX = 0xC0020025,
    /// The name syntax is not supported.
    RPC_NT_UNSUPPORTED_NAME_SYNTAX = 0xC0020026,
    /// No network address is available to construct a UUID.
    RPC_NT_UUID_NO_ADDRESS = 0xC0020028,
    /// The endpoint is a duplicate.
    RPC_NT_DUPLICATE_ENDPOINT = 0xC0020029,
    /// The authentication type is unknown.
    RPC_NT_UNKNOWN_AUTHN_TYPE = 0xC002002A,
    /// The maximum number of calls is too small.
    RPC_NT_MAX_CALLS_TOO_SMALL = 0xC002002B,
    /// The string is too long.
    RPC_NT_STRING_TOO_LONG = 0xC002002C,
    /// The RPC protocol sequence was not found.
    RPC_NT_PROTSEQ_NOT_FOUND = 0xC002002D,
    /// The procedure number is out of range.
    RPC_NT_PROCNUM_OUT_OF_RANGE = 0xC002002E,
    /// The binding does not contain any authentication information.
    RPC_NT_BINDING_HAS_NO_AUTH = 0xC002002F,
    /// The authentication service is unknown.
    RPC_NT_UNKNOWN_AUTHN_SERVICE = 0xC0020030,
    /// The authentication level is unknown.
    RPC_NT_UNKNOWN_AUTHN_LEVEL = 0xC0020031,
    /// The security context is invalid.
    RPC_NT_INVALID_AUTH_IDENTITY = 0xC0020032,
    /// The authorization service is unknown.
    RPC_NT_UNKNOWN_AUTHZ_SERVICE = 0xC0020033,
    /// The entry is invalid.
    EPT_NT_INVALID_ENTRY = 0xC0020034,
    /// The operation cannot be performed.
    EPT_NT_CANT_PERFORM_OP = 0xC0020035,
    /// No more endpoints are available from the endpoint mapper.
    EPT_NT_NOT_REGISTERED = 0xC0020036,
    /// No interfaces have been exported.
    RPC_NT_NOTHING_TO_EXPORT = 0xC0020037,
    /// The entry name is incomplete.
    RPC_NT_INCOMPLETE_NAME = 0xC0020038,
    /// The version option is invalid.
    RPC_NT_INVALID_VERS_OPTION = 0xC0020039,
    /// There are no more members.
    RPC_NT_NO_MORE_MEMBERS = 0xC002003A,
    /// There is nothing to unexport.
    RPC_NT_NOT_ALL_OBJS_UNEXPORTED = 0xC002003B,
    /// The interface was not found.
    RPC_NT_INTERFACE_NOT_FOUND = 0xC002003C,
    /// The entry already exists.
    RPC_NT_ENTRY_ALREADY_EXISTS = 0xC002003D,
    /// The entry was not found.
    RPC_NT_ENTRY_NOT_FOUND = 0xC002003E,
    /// The name service is unavailable.
    RPC_NT_NAME_SERVICE_UNAVAILABLE = 0xC002003F,
    /// The network address family is invalid.
    RPC_NT_INVALID_NAF_ID = 0xC0020040,
    /// The requested operation is not supported.
    RPC_NT_CANNOT_SUPPORT = 0xC0020041,
    /// No security context is available to allow impersonation.
    RPC_NT_NO_CONTEXT_AVAILABLE = 0xC0020042,
    /// An internal error occurred in the RPC.
    RPC_NT_INTERNAL_ERROR = 0xC0020043,
    /// The RPC server attempted to divide an integer by zero.
    RPC_NT_ZERO_DIVIDE = 0xC0020044,
    /// An addressing error occurred in the RPC server.
    RPC_NT_ADDRESS_ERROR = 0xC0020045,
    /// A floating point operation at the RPC server caused a divide by zero.
    RPC_NT_FP_DIV_ZERO = 0xC0020046,
    /// A floating point underflow occurred at the RPC server.
    RPC_NT_FP_UNDERFLOW = 0xC0020047,
    /// A floating point overflow occurred at the RPC server.
    RPC_NT_FP_OVERFLOW = 0xC0020048,
    /// An RPC is already in progress for this thread.
    RPC_NT_CALL_IN_PROGRESS = 0xC0020049,
    /// There are no more bindings.
    RPC_NT_NO_MORE_BINDINGS = 0xC002004A,
    /// The group member was not found.
    RPC_NT_GROUP_MEMBER_NOT_FOUND = 0xC002004B,
    /// The endpoint mapper database entry could not be created.
    EPT_NT_CANT_CREATE = 0xC002004C,
    /// The object UUID is the nil UUID.
    RPC_NT_INVALID_OBJECT = 0xC002004D,
    /// No interfaces have been registered.
    RPC_NT_NO_INTERFACES = 0xC002004F,
    /// The RPC was canceled.
    RPC_NT_CALL_CANCELLED = 0xC0020050,
    /// The binding handle does not contain all the required information.
    RPC_NT_BINDING_INCOMPLETE = 0xC0020051,
    /// A communications failure occurred during an RPC.
    RPC_NT_COMM_FAILURE = 0xC0020052,
    /// The requested authentication level is not supported.
    RPC_NT_UNSUPPORTED_AUTHN_LEVEL = 0xC0020053,
    /// No principal name was registered.
    RPC_NT_NO_PRINC_NAME = 0xC0020054,
    /// The error specified is not a valid Windows RPC error code.
    RPC_NT_NOT_RPC_ERROR = 0xC0020055,
    /// A security package-specific error occurred.
    RPC_NT_SEC_PKG_ERROR = 0xC0020057,
    /// The thread was not canceled.
    RPC_NT_NOT_CANCELLED = 0xC0020058,
    /// Invalid asynchronous RPC handle.
    RPC_NT_INVALID_ASYNC_HANDLE = 0xC0020062,
    /// Invalid asynchronous RPC call handle for this operation.
    RPC_NT_INVALID_ASYNC_CALL = 0xC0020063,
    /// Access to the HTTP proxy is denied.
    RPC_NT_PROXY_ACCESS_DENIED = 0xC0020064,
    /// The list of RPC servers available for auto-handle binding has been exhausted.
    RPC_NT_NO_MORE_ENTRIES = 0xC0030001,
    /// The file designated by DCERPCCHARTRANS cannot be opened.
    RPC_NT_SS_CHAR_TRANS_OPEN_FAIL = 0xC0030002,
    /// The file containing the character translation table has fewer than 512 bytes.
    RPC_NT_SS_CHAR_TRANS_SHORT_FILE = 0xC0030003,
    /// A null context handle is passed as an [in] parameter.
    RPC_NT_SS_IN_NULL_CONTEXT = 0xC0030004,
    /// The context handle does not match any known context handles.
    RPC_NT_SS_CONTEXT_MISMATCH = 0xC0030005,
    /// The context handle changed during a call.
    RPC_NT_SS_CONTEXT_DAMAGED = 0xC0030006,
    /// The binding handles passed to an RPC do not match.
    RPC_NT_SS_HANDLES_MISMATCH = 0xC0030007,
    /// The stub is unable to get the call handle.
    RPC_NT_SS_CANNOT_GET_CALL_HANDLE = 0xC0030008,
    /// A null reference pointer was passed to the stub.
    RPC_NT_NULL_REF_POINTER = 0xC0030009,
    /// The enumeration value is out of range.
    RPC_NT_ENUM_VALUE_OUT_OF_RANGE = 0xC003000A,
    /// The byte count is too small.
    RPC_NT_BYTE_COUNT_TOO_SMALL = 0xC003000B,
    /// The stub received bad data.
    RPC_NT_BAD_STUB_DATA = 0xC003000C,
    /// Invalid operation on the encoding/decoding handle.
    RPC_NT_INVALID_ES_ACTION = 0xC0030059,
    /// Incompatible version of the serializing package.
    RPC_NT_WRONG_ES_VERSION = 0xC003005A,
    /// Incompatible version of the RPC stub.
    RPC_NT_WRONG_STUB_VERSION = 0xC003005B,
    /// The RPC pipe object is invalid or corrupt.
    RPC_NT_INVALID_PIPE_OBJECT = 0xC003005C,
    /// An invalid operation was attempted on an RPC pipe object.
    RPC_NT_INVALID_PIPE_OPERATION = 0xC003005D,
    /// Unsupported RPC pipe version.
    RPC_NT_WRONG_PIPE_VERSION = 0xC003005E,
    /// The RPC pipe object has already been closed.
    RPC_NT_PIPE_CLOSED = 0xC003005F,
    /// The RPC call completed before all pipes were processed.
    RPC_NT_PIPE_DISCIPLINE_ERROR = 0xC0030060,
    /// No more data is available from the RPC pipe.
    RPC_NT_PIPE_EMPTY = 0xC0030061,
    /// A device is missing in the system BIOS MPS table. This device will not be used.
    /// Contact your system vendor for a system BIOS update.
    PNP_BAD_MPS_TABLE = 0xC0040035,
    /// A translator failed to translate resources.
    PNP_TRANSLATION_FAILED = 0xC0040036,
    /// An IRQ translator failed to translate resources.
    PNP_IRQ_TRANSLATION_FAILED = 0xC0040037,
    /// Driver %2 returned an invalid ID for a child device (%3).
    PNP_INVALID_ID = 0xC0040038,
    /// Reissue the given operation as a cached I/O operation
    IO_REISSUE_AS_CACHED = 0xC0040039,
    /// Session name %1 is invalid.
    CTX_WINSTATION_NAME_INVALID = 0xC00A0001,
    /// The protocol driver %1 is invalid.
    CTX_INVALID_PD = 0xC00A0002,
    /// The protocol driver %1 was not found in the system path.
    CTX_PD_NOT_FOUND = 0xC00A0003,
    /// A close operation is pending on the terminal connection.
    CTX_CLOSE_PENDING = 0xC00A0006,
    /// No free output buffers are available.
    CTX_NO_OUTBUF = 0xC00A0007,
    /// The MODEM.INF file was not found.
    CTX_MODEM_INF_NOT_FOUND = 0xC00A0008,
    /// The modem (%1) was not found in the MODEM.INF file.
    CTX_INVALID_MODEMNAME = 0xC00A0009,
    /// The modem did not accept the command sent to it.
    /// Verify that the configured modem name matches the attached modem.
    CTX_RESPONSE_ERROR = 0xC00A000A,
    /// The modem did not respond to the command sent to it.
    /// Verify that the modem cable is properly attached and the modem is turned on.
    CTX_MODEM_RESPONSE_TIMEOUT = 0xC00A000B,
    /// Carrier detection has failed or the carrier has been dropped due to disconnection.
    CTX_MODEM_RESPONSE_NO_CARRIER = 0xC00A000C,
    /// A dial tone was not detected within the required time.
    /// Verify that the phone cable is properly attached and functional.
    CTX_MODEM_RESPONSE_NO_DIALTONE = 0xC00A000D,
    /// A busy signal was detected at a remote site on callback.
    CTX_MODEM_RESPONSE_BUSY = 0xC00A000E,
    /// A voice was detected at a remote site on callback.
    CTX_MODEM_RESPONSE_VOICE = 0xC00A000F,
    /// Transport driver error.
    CTX_TD_ERROR = 0xC00A0010,
    /// The client you are using is not licensed to use this system. Your logon request is denied.
    CTX_LICENSE_CLIENT_INVALID = 0xC00A0012,
    /// The system has reached its licensed logon limit. Try again later.
    CTX_LICENSE_NOT_AVAILABLE = 0xC00A0013,
    /// The system license has expired. Your logon request is denied.
    CTX_LICENSE_EXPIRED = 0xC00A0014,
    /// The specified session cannot be found.
    CTX_WINSTATION_NOT_FOUND = 0xC00A0015,
    /// The specified session name is already in use.
    CTX_WINSTATION_NAME_COLLISION = 0xC00A0016,
    /// The requested operation cannot be completed because the terminal connection is currently processing a connect, disconnect, reset, or delete operation.
    CTX_WINSTATION_BUSY = 0xC00A0017,
    /// An attempt has been made to connect to a session whose video mode is not supported by the current client.
    CTX_BAD_VIDEO_MODE = 0xC00A0018,
    /// The application attempted to enable DOS graphics mode. DOS graphics mode is not supported.
    CTX_GRAPHICS_INVALID = 0xC00A0022,
    /// The requested operation can be performed only on the system console.
    /// This is most often the result of a driver or system DLL requiring direct console access.
    CTX_NOT_CONSOLE = 0xC00A0024,
    /// The client failed to respond to the server connect message.
    CTX_CLIENT_QUERY_TIMEOUT = 0xC00A0026,
    /// Disconnecting the console session is not supported.
    CTX_CONSOLE_DISCONNECT = 0xC00A0027,
    /// Reconnecting a disconnected session to the console is not supported.
    CTX_CONSOLE_CONNECT = 0xC00A0028,
    /// The request to control another session remotely was denied.
    CTX_SHADOW_DENIED = 0xC00A002A,
    /// A process has requested access to a session, but has not been granted those access rights.
    CTX_WINSTATION_ACCESS_DENIED = 0xC00A002B,
    /// The terminal connection driver %1 is invalid.
    CTX_INVALID_WD = 0xC00A002E,
    /// The terminal connection driver %1 was not found in the system path.
    CTX_WD_NOT_FOUND = 0xC00A002F,
    /// The requested session cannot be controlled remotely.
    /// You cannot control your own session, a session that is trying to control your session, a session that has no user logged on, or other sessions from the console.
    CTX_SHADOW_INVALID = 0xC00A0030,
    /// The requested session is not configured to allow remote control.
    CTX_SHADOW_DISABLED = 0xC00A0031,
    /// The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client.
    RDP_PROTOCOL_ERROR = 0xC00A0032,
    /// Your request to connect to this terminal server has been rejected.
    /// Your terminal server client license number has not been entered for this copy of the terminal client.
    /// Contact your system administrator for help in entering a valid, unique license number for this terminal server client. Click OK to continue.
    CTX_CLIENT_LICENSE_NOT_SET = 0xC00A0033,
    /// Your request to connect to this terminal server has been rejected.
    /// Your terminal server client license number is currently being used by another user.
    /// Contact your system administrator to obtain a new copy of the terminal server client with a valid, unique license number. Click OK to continue.
    CTX_CLIENT_LICENSE_IN_USE = 0xC00A0034,
    /// The remote control of the console was terminated because the display mode was changed.
    /// Changing the display mode in a remote control session is not supported.
    CTX_SHADOW_ENDED_BY_MODE_CHANGE = 0xC00A0035,
    /// Remote control could not be terminated because the specified session is not currently being remotely controlled.
    CTX_SHADOW_NOT_RUNNING = 0xC00A0036,
    /// Your interactive logon privilege has been disabled. Contact your system administrator.
    CTX_LOGON_DISABLED = 0xC00A0037,
    /// The terminal server security layer detected an error in the protocol stream and has disconnected the client.
    CTX_SECURITY_LAYER_ERROR = 0xC00A0038,
    /// The target session is incompatible with the current session.
    TS_INCOMPATIBLE_SESSIONS = 0xC00A0039,
    /// The resource loader failed to find an MUI file.
    MUI_FILE_NOT_FOUND = 0xC00B0001,
    /// The resource loader failed to load an MUI file because the file failed to pass validation.
    MUI_INVALID_FILE = 0xC00B0002,
    /// The RC manifest is corrupted with garbage data, is an unsupported version, or is missing a required item.
    MUI_INVALID_RC_CONFIG = 0xC00B0003,
    /// The RC manifest has an invalid culture name.
    MUI_INVALID_LOCALE_NAME = 0xC00B0004,
    /// The RC manifest has and invalid ultimate fallback name.
    MUI_INVALID_ULTIMATEFALLBACK_NAME = 0xC00B0005,
    /// The resource loader cache does not have a loaded MUI entry.
    MUI_FILE_NOT_LOADED = 0xC00B0006,
    /// The user stopped resource enumeration.
    RESOURCE_ENUM_USER_STOP = 0xC00B0007,
    /// The cluster node is not valid.
    CLUSTER_INVALID_NODE = 0xC0130001,
    /// The cluster node already exists.
    CLUSTER_NODE_EXISTS = 0xC0130002,
    /// A node is in the process of joining the cluster.
    CLUSTER_JOIN_IN_PROGRESS = 0xC0130003,
    /// The cluster node was not found.
    CLUSTER_NODE_NOT_FOUND = 0xC0130004,
    /// The cluster local node information was not found.
    CLUSTER_LOCAL_NODE_NOT_FOUND = 0xC0130005,
    /// The cluster network already exists.
    CLUSTER_NETWORK_EXISTS = 0xC0130006,
    /// The cluster network was not found.
    CLUSTER_NETWORK_NOT_FOUND = 0xC0130007,
    /// The cluster network interface already exists.
    CLUSTER_NETINTERFACE_EXISTS = 0xC0130008,
    /// The cluster network interface was not found.
    CLUSTER_NETINTERFACE_NOT_FOUND = 0xC0130009,
    /// The cluster request is not valid for this object.
    CLUSTER_INVALID_REQUEST = 0xC013000A,
    /// The cluster network provider is not valid.
    CLUSTER_INVALID_NETWORK_PROVIDER = 0xC013000B,
    /// The cluster node is down.
    CLUSTER_NODE_DOWN = 0xC013000C,
    /// The cluster node is not reachable.
    CLUSTER_NODE_UNREACHABLE = 0xC013000D,
    /// The cluster node is not a member of the cluster.
    CLUSTER_NODE_NOT_MEMBER = 0xC013000E,
    /// A cluster join operation is not in progress.
    CLUSTER_JOIN_NOT_IN_PROGRESS = 0xC013000F,
    /// The cluster network is not valid.
    CLUSTER_INVALID_NETWORK = 0xC0130010,
    /// No network adapters are available.
    CLUSTER_NO_NET_ADAPTERS = 0xC0130011,
    /// The cluster node is up.
    CLUSTER_NODE_UP = 0xC0130012,
    /// The cluster node is paused.
    CLUSTER_NODE_PAUSED = 0xC0130013,
    /// The cluster node is not paused.
    CLUSTER_NODE_NOT_PAUSED = 0xC0130014,
    /// No cluster security context is available.
    CLUSTER_NO_SECURITY_CONTEXT = 0xC0130015,
    /// The cluster network is not configured for internal cluster communication.
    CLUSTER_NETWORK_NOT_INTERNAL = 0xC0130016,
    /// The cluster node has been poisoned.
    CLUSTER_POISONED = 0xC0130017,
    /// An attempt was made to run an invalid AML opcode.
    ACPI_INVALID_OPCODE = 0xC0140001,
    /// The AML interpreter stack has overflowed.
    ACPI_STACK_OVERFLOW = 0xC0140002,
    /// An inconsistent state has occurred.
    ACPI_ASSERT_FAILED = 0xC0140003,
    /// An attempt was made to access an array outside its bounds.
    ACPI_INVALID_INDEX = 0xC0140004,
    /// A required argument was not specified.
    ACPI_INVALID_ARGUMENT = 0xC0140005,
    /// A fatal error has occurred.
    ACPI_FATAL = 0xC0140006,
    /// An invalid SuperName was specified.
    ACPI_INVALID_SUPERNAME = 0xC0140007,
    /// An argument with an incorrect type was specified.
    ACPI_INVALID_ARGTYPE = 0xC0140008,
    /// An object with an incorrect type was specified.
    ACPI_INVALID_OBJTYPE = 0xC0140009,
    /// A target with an incorrect type was specified.
    ACPI_INVALID_TARGETTYPE = 0xC014000A,
    /// An incorrect number of arguments was specified.
    ACPI_INCORRECT_ARGUMENT_COUNT = 0xC014000B,
    /// An address failed to translate.
    ACPI_ADDRESS_NOT_MAPPED = 0xC014000C,
    /// An incorrect event type was specified.
    ACPI_INVALID_EVENTTYPE = 0xC014000D,
    /// A handler for the target already exists.
    ACPI_HANDLER_COLLISION = 0xC014000E,
    /// Invalid data for the target was specified.
    ACPI_INVALID_DATA = 0xC014000F,
    /// An invalid region for the target was specified.
    ACPI_INVALID_REGION = 0xC0140010,
    /// An attempt was made to access a field outside the defined range.
    ACPI_INVALID_ACCESS_SIZE = 0xC0140011,
    /// The global system lock could not be acquired.
    ACPI_ACQUIRE_GLOBAL_LOCK = 0xC0140012,
    /// An attempt was made to reinitialize the ACPI subsystem.
    ACPI_ALREADY_INITIALIZED = 0xC0140013,
    /// The ACPI subsystem has not been initialized.
    ACPI_NOT_INITIALIZED = 0xC0140014,
    /// An incorrect mutex was specified.
    ACPI_INVALID_MUTEX_LEVEL = 0xC0140015,
    /// The mutex is not currently owned.
    ACPI_MUTEX_NOT_OWNED = 0xC0140016,
    /// An attempt was made to access the mutex by a process that was not the owner.
    ACPI_MUTEX_NOT_OWNER = 0xC0140017,
    /// An error occurred during an access to region space.
    ACPI_RS_ACCESS = 0xC0140018,
    /// An attempt was made to use an incorrect table.
    ACPI_INVALID_TABLE = 0xC0140019,
    /// The registration of an ACPI event failed.
    ACPI_REG_HANDLER_FAILED = 0xC0140020,
    /// An ACPI power object failed to transition state.
    ACPI_POWER_REQUEST_FAILED = 0xC0140021,
    /// The requested section is not present in the activation context.
    SXS_SECTION_NOT_FOUND = 0xC0150001,
    /// Windows was unble to process the application binding information.
    /// Refer to the system event log for further information.
    SXS_CANT_GEN_ACTCTX = 0xC0150002,
    /// The application binding data format is invalid.
    SXS_INVALID_ACTCTXDATA_FORMAT = 0xC0150003,
    /// The referenced assembly is not installed on the system.
    SXS_ASSEMBLY_NOT_FOUND = 0xC0150004,
    /// The manifest file does not begin with the required tag and format information.
    SXS_MANIFEST_FORMAT_ERROR = 0xC0150005,
    /// The manifest file contains one or more syntax errors.
    SXS_MANIFEST_PARSE_ERROR = 0xC0150006,
    /// The application attempted to activate a disabled activation context.
    SXS_ACTIVATION_CONTEXT_DISABLED = 0xC0150007,
    /// The requested lookup key was not found in any active activation context.
    SXS_KEY_NOT_FOUND = 0xC0150008,
    /// A component version required by the application conflicts with another component version that is already active.
    SXS_VERSION_CONFLICT = 0xC0150009,
    /// The type requested activation context section does not match the query API used.
    SXS_WRONG_SECTION_TYPE = 0xC015000A,
    /// Lack of system resources has required isolated activation to be disabled for the current thread of execution.
    SXS_THREAD_QUERIES_DISABLED = 0xC015000B,
    /// The referenced assembly could not be found.
    SXS_ASSEMBLY_MISSING = 0xC015000C,
    /// An attempt to set the process default activation context failed because the process default activation context was already set.
    SXS_PROCESS_DEFAULT_ALREADY_SET = 0xC015000E,
    /// The activation context being deactivated is not the most recently activated one.
    SXS_EARLY_DEACTIVATION = 0xC015000F,
    /// The activation context being deactivated is not active for the current thread of execution.
    SXS_INVALID_DEACTIVATION = 0xC0150010,
    /// The activation context being deactivated has already been deactivated.
    SXS_MULTIPLE_DEACTIVATION = 0xC0150011,
    /// The activation context of the system default assembly could not be generated.
    SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY = 0xC0150012,
    /// A component used by the isolation facility has requested that the process be terminated.
    SXS_PROCESS_TERMINATION_REQUESTED = 0xC0150013,
    /// The activation context activation stack for the running thread of execution is corrupt.
    SXS_CORRUPT_ACTIVATION_STACK = 0xC0150014,
    /// The application isolation metadata for this process or thread has become corrupt.
    SXS_CORRUPTION = 0xC0150015,
    /// The value of an attribute in an identity is not within the legal range.
    SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE = 0xC0150016,
    /// The name of an attribute in an identity is not within the legal range.
    SXS_INVALID_IDENTITY_ATTRIBUTE_NAME = 0xC0150017,
    /// An identity contains two definitions for the same attribute.
    SXS_IDENTITY_DUPLICATE_ATTRIBUTE = 0xC0150018,
    /// The identity string is malformed.
    /// This might be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value.
    SXS_IDENTITY_PARSE_ERROR = 0xC0150019,
    /// The component store has become corrupted.
    SXS_COMPONENT_STORE_CORRUPT = 0xC015001A,
    /// A component's file does not match the verification information present in the component manifest.
    SXS_FILE_HASH_MISMATCH = 0xC015001B,
    /// The identities of the manifests are identical, but their contents are different.
    SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT = 0xC015001C,
    /// The component identities are different.
    SXS_IDENTITIES_DIFFERENT = 0xC015001D,
    /// The assembly is not a deployment.
    SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT = 0xC015001E,
    /// The file is not a part of the assembly.
    SXS_FILE_NOT_PART_OF_ASSEMBLY = 0xC015001F,
    /// An advanced installer failed during setup or servicing.
    ADVANCED_INSTALLER_FAILED = 0xC0150020,
    /// The character encoding in the XML declaration did not match the encoding used in the document.
    XML_ENCODING_MISMATCH = 0xC0150021,
    /// The size of the manifest exceeds the maximum allowed.
    SXS_MANIFEST_TOO_BIG = 0xC0150022,
    /// The setting is not registered.
    SXS_SETTING_NOT_REGISTERED = 0xC0150023,
    /// One or more required transaction members are not present.
    SXS_TRANSACTION_CLOSURE_INCOMPLETE = 0xC0150024,
    /// The SMI primitive installer failed during setup or servicing.
    SMI_PRIMITIVE_INSTALLER_FAILED = 0xC0150025,
    /// A generic command executable returned a result that indicates failure.
    GENERIC_COMMAND_FAILED = 0xC0150026,
    /// A component is missing file verification information in its manifest.
    SXS_FILE_HASH_MISSING = 0xC0150027,
    /// The function attempted to use a name that is reserved for use by another transaction.
    TRANSACTIONAL_CONFLICT = 0xC0190001,
    /// The transaction handle associated with this operation is invalid.
    INVALID_TRANSACTION = 0xC0190002,
    /// The requested operation was made in the context of a transaction that is no longer active.
    TRANSACTION_NOT_ACTIVE = 0xC0190003,
    /// The transaction manager was unable to be successfully initialized. Transacted operations are not supported.
    TM_INITIALIZATION_FAILED = 0xC0190004,
    /// Transaction support within the specified file system resource manager was not started or was shut down due to an error.
    RM_NOT_ACTIVE = 0xC0190005,
    /// The metadata of the resource manager has been corrupted. The resource manager will not function.
    RM_METADATA_CORRUPT = 0xC0190006,
    /// The resource manager attempted to prepare a transaction that it has not successfully joined.
    TRANSACTION_NOT_JOINED = 0xC0190007,
    /// The specified directory does not contain a file system resource manager.
    DIRECTORY_NOT_RM = 0xC0190008,
    /// The remote server or share does not support transacted file operations.
    TRANSACTIONS_UNSUPPORTED_REMOTE = 0xC019000A,
    /// The requested log size for the file system resource manager is invalid.
    LOG_RESIZE_INVALID_SIZE = 0xC019000B,
    /// The remote server sent mismatching version number or Fid for a file opened with transactions.
    REMOTE_FILE_VERSION_MISMATCH = 0xC019000C,
    /// The resource manager tried to register a protocol that already exists.
    CRM_PROTOCOL_ALREADY_EXISTS = 0xC019000F,
    /// The attempt to propagate the transaction failed.
    TRANSACTION_PROPAGATION_FAILED = 0xC0190010,
    /// The requested propagation protocol was not registered as a CRM.
    CRM_PROTOCOL_NOT_FOUND = 0xC0190011,
    /// The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed.
    TRANSACTION_SUPERIOR_EXISTS = 0xC0190012,
    /// The requested operation is not valid on the transaction object in its current state.
    TRANSACTION_REQUEST_NOT_VALID = 0xC0190013,
    /// The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller.
    TRANSACTION_NOT_REQUESTED = 0xC0190014,
    /// It is too late to perform the requested operation, because the transaction has already been aborted.
    TRANSACTION_ALREADY_ABORTED = 0xC0190015,
    /// It is too late to perform the requested operation, because the transaction has already been committed.
    TRANSACTION_ALREADY_COMMITTED = 0xC0190016,
    /// The buffer passed in to NtPushTransaction or NtPullTransaction is not in a valid format.
    TRANSACTION_INVALID_MARSHALL_BUFFER = 0xC0190017,
    /// The current transaction context associated with the thread is not a valid handle to a transaction object.
    CURRENT_TRANSACTION_NOT_VALID = 0xC0190018,
    /// An attempt to create space in the transactional resource manager's log failed.
    /// The failure status has been recorded in the event log.
    LOG_GROWTH_FAILED = 0xC0190019,
    /// The object (file, stream, or link) that corresponds to the handle has been deleted by a transaction savepoint rollback.
    OBJECT_NO_LONGER_EXISTS = 0xC0190021,
    /// The specified file miniversion was not found for this transacted file open.
    STREAM_MINIVERSION_NOT_FOUND = 0xC0190022,
    /// The specified file miniversion was found but has been invalidated.
    /// The most likely cause is a transaction savepoint rollback.
    STREAM_MINIVERSION_NOT_VALID = 0xC0190023,
    /// A miniversion can be opened only in the context of the transaction that created it.
    MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION = 0xC0190024,
    /// It is not possible to open a miniversion with modify access.
    CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT = 0xC0190025,
    /// It is not possible to create any more miniversions for this stream.
    CANT_CREATE_MORE_STREAM_MINIVERSIONS = 0xC0190026,
    /// The handle has been invalidated by a transaction.
    /// The most likely cause is the presence of memory mapping on a file or an open handle when the transaction ended or rolled back to savepoint.
    HANDLE_NO_LONGER_VALID = 0xC0190028,
    /// The log data is corrupt.
    LOG_CORRUPTION_DETECTED = 0xC0190030,
    /// The transaction outcome is unavailable because the resource manager responsible for it is disconnected.
    RM_DISCONNECTED = 0xC0190032,
    /// The request was rejected because the enlistment in question is not a superior enlistment.
    ENLISTMENT_NOT_SUPERIOR = 0xC0190033,
    /// The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction.
    FILE_IDENTITY_NOT_PERSISTENT = 0xC0190036,
    /// The operation cannot be performed because another transaction is depending on this property not changing.
    CANT_BREAK_TRANSACTIONAL_DEPENDENCY = 0xC0190037,
    /// The operation would involve a single file with two transactional resource managers and is, therefore, not allowed.
    CANT_CROSS_RM_BOUNDARY = 0xC0190038,
    /// The $Txf directory must be empty for this operation to succeed.
    TXF_DIR_NOT_EMPTY = 0xC0190039,
    /// The operation would leave a transactional resource manager in an inconsistent state and is therefore not allowed.
    INDOUBT_TRANSACTIONS_EXIST = 0xC019003A,
    /// The operation could not be completed because the transaction manager does not have a log.
    TM_VOLATILE = 0xC019003B,
    /// A rollback could not be scheduled because a previously scheduled rollback has already executed or been queued for execution.
    ROLLBACK_TIMER_EXPIRED = 0xC019003C,
    /// The transactional metadata attribute on the file or directory %hs is corrupt and unreadable.
    TXF_ATTRIBUTE_CORRUPT = 0xC019003D,
    /// The encryption operation could not be completed because a transaction is active.
    EFS_NOT_ALLOWED_IN_TRANSACTION = 0xC019003E,
    /// This object is not allowed to be opened in a transaction.
    TRANSACTIONAL_OPEN_NOT_ALLOWED = 0xC019003F,
    /// Memory mapping (creating a mapped section) a remote file under a transaction is not supported.
    TRANSACTED_MAPPING_UNSUPPORTED_REMOTE = 0xC0190040,
    /// Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it.
    TRANSACTION_REQUIRED_PROMOTION = 0xC0190043,
    /// This file is open for modification in an unresolved transaction and can be opened for execute only by a transacted reader.
    CANNOT_EXECUTE_FILE_IN_TRANSACTION = 0xC0190044,
    /// The request to thaw frozen transactions was ignored because transactions were not previously frozen.
    TRANSACTIONS_NOT_FROZEN = 0xC0190045,
    /// Transactions cannot be frozen because a freeze is already in progress.
    TRANSACTION_FREEZE_IN_PROGRESS = 0xC0190046,
    /// The target volume is not a snapshot volume.
    /// This operation is valid only on a volume mounted as a snapshot.
    NOT_SNAPSHOT_VOLUME = 0xC0190047,
    /// The savepoint operation failed because files are open on the transaction, which is not permitted.
    NO_SAVEPOINT_WITH_OPEN_FILES = 0xC0190048,
    /// The sparse operation could not be completed because a transaction is active on the file.
    SPARSE_NOT_ALLOWED_IN_TRANSACTION = 0xC0190049,
    /// The call to create a transaction manager object failed because the Tm Identity that is stored in the log file does not match the Tm Identity that was passed in as an argument.
    TM_IDENTITY_MISMATCH = 0xC019004A,
    /// I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data.
    FLOATED_SECTION = 0xC019004B,
    /// The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources.
    CANNOT_ACCEPT_TRANSACTED_WORK = 0xC019004C,
    /// The transactional resource manager had too many transactions outstanding that could not be aborted.
    /// The transactional resource manager has been shut down.
    CANNOT_ABORT_TRANSACTIONS = 0xC019004D,
    /// The specified transaction was unable to be opened because it was not found.
    TRANSACTION_NOT_FOUND = 0xC019004E,
    /// The specified resource manager was unable to be opened because it was not found.
    RESOURCEMANAGER_NOT_FOUND = 0xC019004F,
    /// The specified enlistment was unable to be opened because it was not found.
    ENLISTMENT_NOT_FOUND = 0xC0190050,
    /// The specified transaction manager was unable to be opened because it was not found.
    TRANSACTIONMANAGER_NOT_FOUND = 0xC0190051,
    /// The specified resource manager was unable to create an enlistment because its associated transaction manager is not online.
    TRANSACTIONMANAGER_NOT_ONLINE = 0xC0190052,
    /// The specified transaction manager was unable to create the objects contained in its log file in the Ob namespace.
    /// Therefore, the transaction manager was unable to recover.
    TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION = 0xC0190053,
    /// The call to create a superior enlistment on this transaction object could not be completed because the transaction object specified for the enlistment is a subordinate branch of the transaction.
    /// Only the root of the transaction can be enlisted as a superior.
    TRANSACTION_NOT_ROOT = 0xC0190054,
    /// Because the associated transaction manager or resource manager has been closed, the handle is no longer valid.
    TRANSACTION_OBJECT_EXPIRED = 0xC0190055,
    /// The compression operation could not be completed because a transaction is active on the file.
    COMPRESSION_NOT_ALLOWED_IN_TRANSACTION = 0xC0190056,
    /// The specified operation could not be performed on this superior enlistment because the enlistment was not created with the corresponding completion response in the NotificationMask.
    TRANSACTION_RESPONSE_NOT_ENLISTED = 0xC0190057,
    /// The specified operation could not be performed because the record to be logged was too long.
    /// This can occur because either there are too many enlistments on this transaction or the combined RecoveryInformation being logged on behalf of those enlistments is too long.
    TRANSACTION_RECORD_TOO_LONG = 0xC0190058,
    /// The link-tracking operation could not be completed because a transaction is active.
    NO_LINK_TRACKING_IN_TRANSACTION = 0xC0190059,
    /// This operation cannot be performed in a transaction.
    OPERATION_NOT_SUPPORTED_IN_TRANSACTION = 0xC019005A,
    /// The kernel transaction manager had to abort or forget the transaction because it blocked forward progress.
    TRANSACTION_INTEGRITY_VIOLATED = 0xC019005B,
    /// The handle is no longer properly associated with its transaction.
    ///  It might have been opened in a transactional resource manager that was subsequently forced to restart.  Please close the handle and open a new one.
    EXPIRED_HANDLE = 0xC0190060,
    /// The specified operation could not be performed because the resource manager is not enlisted in the transaction.
    TRANSACTION_NOT_ENLISTED = 0xC0190061,
    /// The log service found an invalid log sector.
    LOG_SECTOR_INVALID = 0xC01A0001,
    /// The log service encountered a log sector with invalid block parity.
    LOG_SECTOR_PARITY_INVALID = 0xC01A0002,
    /// The log service encountered a remapped log sector.
    LOG_SECTOR_REMAPPED = 0xC01A0003,
    /// The log service encountered a partial or incomplete log block.
    LOG_BLOCK_INCOMPLETE = 0xC01A0004,
    /// The log service encountered an attempt to access data outside the active log range.
    LOG_INVALID_RANGE = 0xC01A0005,
    /// The log service user-log marshaling buffers are exhausted.
    LOG_BLOCKS_EXHAUSTED = 0xC01A0006,
    /// The log service encountered an attempt to read from a marshaling area with an invalid read context.
    LOG_READ_CONTEXT_INVALID = 0xC01A0007,
    /// The log service encountered an invalid log restart area.
    LOG_RESTART_INVALID = 0xC01A0008,
    /// The log service encountered an invalid log block version.
    LOG_BLOCK_VERSION = 0xC01A0009,
    /// The log service encountered an invalid log block.
    LOG_BLOCK_INVALID = 0xC01A000A,
    /// The log service encountered an attempt to read the log with an invalid read mode.
    LOG_READ_MODE_INVALID = 0xC01A000B,
    /// The log service encountered a corrupted metadata file.
    LOG_METADATA_CORRUPT = 0xC01A000D,
    /// The log service encountered a metadata file that could not be created by the log file system.
    LOG_METADATA_INVALID = 0xC01A000E,
    /// The log service encountered a metadata file with inconsistent data.
    LOG_METADATA_INCONSISTENT = 0xC01A000F,
    /// The log service encountered an attempt to erroneously allocate or dispose reservation space.
    LOG_RESERVATION_INVALID = 0xC01A0010,
    /// The log service cannot delete the log file or the file system container.
    LOG_CANT_DELETE = 0xC01A0011,
    /// The log service has reached the maximum allowable containers allocated to a log file.
    LOG_CONTAINER_LIMIT_EXCEEDED = 0xC01A0012,
    /// The log service has attempted to read or write backward past the start of the log.
    LOG_START_OF_LOG = 0xC01A0013,
    /// The log policy could not be installed because a policy of the same type is already present.
    LOG_POLICY_ALREADY_INSTALLED = 0xC01A0014,
    /// The log policy in question was not installed at the time of the request.
    LOG_POLICY_NOT_INSTALLED = 0xC01A0015,
    /// The installed set of policies on the log is invalid.
    LOG_POLICY_INVALID = 0xC01A0016,
    /// A policy on the log in question prevented the operation from completing.
    LOG_POLICY_CONFLICT = 0xC01A0017,
    /// The log space cannot be reclaimed because the log is pinned by the archive tail.
    LOG_PINNED_ARCHIVE_TAIL = 0xC01A0018,
    /// The log record is not a record in the log file.
    LOG_RECORD_NONEXISTENT = 0xC01A0019,
    /// The number of reserved log records or the adjustment of the number of reserved log records is invalid.
    LOG_RECORDS_RESERVED_INVALID = 0xC01A001A,
    /// The reserved log space or the adjustment of the log space is invalid.
    LOG_SPACE_RESERVED_INVALID = 0xC01A001B,
    /// A new or existing archive tail or the base of the active log is invalid.
    LOG_TAIL_INVALID = 0xC01A001C,
    /// The log space is exhausted.
    LOG_FULL = 0xC01A001D,
    /// The log is multiplexed; no direct writes to the physical log are allowed.
    LOG_MULTIPLEXED = 0xC01A001E,
    /// The operation failed because the log is dedicated.
    LOG_DEDICATED = 0xC01A001F,
    /// The operation requires an archive context.
    LOG_ARCHIVE_NOT_IN_PROGRESS = 0xC01A0020,
    /// Log archival is in progress.
    LOG_ARCHIVE_IN_PROGRESS = 0xC01A0021,
    /// The operation requires a nonephemeral log, but the log is ephemeral.
    LOG_EPHEMERAL = 0xC01A0022,
    /// The log must have at least two containers before it can be read from or written to.
    LOG_NOT_ENOUGH_CONTAINERS = 0xC01A0023,
    /// A log client has already registered on the stream.
    LOG_CLIENT_ALREADY_REGISTERED = 0xC01A0024,
    /// A log client has not been registered on the stream.
    LOG_CLIENT_NOT_REGISTERED = 0xC01A0025,
    /// A request has already been made to handle the log full condition.
    LOG_FULL_HANDLER_IN_PROGRESS = 0xC01A0026,
    /// The log service encountered an error when attempting to read from a log container.
    LOG_CONTAINER_READ_FAILED = 0xC01A0027,
    /// The log service encountered an error when attempting to write to a log container.
    LOG_CONTAINER_WRITE_FAILED = 0xC01A0028,
    /// The log service encountered an error when attempting to open a log container.
    LOG_CONTAINER_OPEN_FAILED = 0xC01A0029,
    /// The log service encountered an invalid container state when attempting a requested action.
    LOG_CONTAINER_STATE_INVALID = 0xC01A002A,
    /// The log service is not in the correct state to perform a requested action.
    LOG_STATE_INVALID = 0xC01A002B,
    /// The log space cannot be reclaimed because the log is pinned.
    LOG_PINNED = 0xC01A002C,
    /// The log metadata flush failed.
    LOG_METADATA_FLUSH_FAILED = 0xC01A002D,
    /// Security on the log and its containers is inconsistent.
    LOG_INCONSISTENT_SECURITY = 0xC01A002E,
    /// Records were appended to the log or reservation changes were made, but the log could not be flushed.
    LOG_APPENDED_FLUSH_FAILED = 0xC01A002F,
    /// The log is pinned due to reservation consuming most of the log space.
    /// Free some reserved records to make space available.
    LOG_PINNED_RESERVATION = 0xC01A0030,
    /// {Display Driver Stopped Responding} The %hs display driver has stopped working normally.
    /// Save your work and reboot the system to restore full display functionality.
    /// The next time you reboot the computer, a dialog box will allow you to upload data about this failure to Microsoft.
    VIDEO_HUNG_DISPLAY_DRIVER_THREAD = 0xC01B00EA,
    /// A handler was not defined by the filter for this operation.
    FLT_NO_HANDLER_DEFINED = 0xC01C0001,
    /// A context is already defined for this object.
    FLT_CONTEXT_ALREADY_DEFINED = 0xC01C0002,
    /// Asynchronous requests are not valid for this operation.
    FLT_INVALID_ASYNCHRONOUS_REQUEST = 0xC01C0003,
    /// This is an internal error code used by the filter manager to determine if a fast I/O operation should be forced down the input/output request packet (IRP) path. Minifilters should never return this value.
    FLT_DISALLOW_FAST_IO = 0xC01C0004,
    /// An invalid name request was made.
    /// The name requested cannot be retrieved at this time.
    FLT_INVALID_NAME_REQUEST = 0xC01C0005,
    /// Posting this operation to a worker thread for further processing is not safe at this time because it could lead to a system deadlock.
    FLT_NOT_SAFE_TO_POST_OPERATION = 0xC01C0006,
    /// The Filter Manager was not initialized when a filter tried to register.
    /// Make sure that the Filter Manager is loaded as a driver.
    FLT_NOT_INITIALIZED = 0xC01C0007,
    /// The filter is not ready for attachment to volumes because it has not finished initializing (FltStartFiltering has not been called).
    FLT_FILTER_NOT_READY = 0xC01C0008,
    /// The filter must clean up any operation-specific context at this time because it is being removed from the system before the operation is completed by the lower drivers.
    FLT_POST_OPERATION_CLEANUP = 0xC01C0009,
    /// The Filter Manager had an internal error from which it cannot recover; therefore, the operation has failed.
    /// This is usually the result of a filter returning an invalid value from a pre-operation callback.
    FLT_INTERNAL_ERROR = 0xC01C000A,
    /// The object specified for this action is in the process of being deleted; therefore, the action requested cannot be completed at this time.
    FLT_DELETING_OBJECT = 0xC01C000B,
    /// A nonpaged pool must be used for this type of context.
    FLT_MUST_BE_NONPAGED_POOL = 0xC01C000C,
    /// A duplicate handler definition has been provided for an operation.
    FLT_DUPLICATE_ENTRY = 0xC01C000D,
    /// The callback data queue has been disabled.
    FLT_CBDQ_DISABLED = 0xC01C000E,
    /// Do not attach the filter to the volume at this time.
    FLT_DO_NOT_ATTACH = 0xC01C000F,
    /// Do not detach the filter from the volume at this time.
    FLT_DO_NOT_DETACH = 0xC01C0010,
    /// An instance already exists at this altitude on the volume specified.
    FLT_INSTANCE_ALTITUDE_COLLISION = 0xC01C0011,
    /// An instance already exists with this name on the volume specified.
    FLT_INSTANCE_NAME_COLLISION = 0xC01C0012,
    /// The system could not find the filter specified.
    FLT_FILTER_NOT_FOUND = 0xC01C0013,
    /// The system could not find the volume specified.
    FLT_VOLUME_NOT_FOUND = 0xC01C0014,
    /// The system could not find the instance specified.
    FLT_INSTANCE_NOT_FOUND = 0xC01C0015,
    /// No registered context allocation definition was found for the given request.
    FLT_CONTEXT_ALLOCATION_NOT_FOUND = 0xC01C0016,
    /// An invalid parameter was specified during context registration.
    FLT_INVALID_CONTEXT_REGISTRATION = 0xC01C0017,
    /// The name requested was not found in the Filter Manager name cache and could not be retrieved from the file system.
    FLT_NAME_CACHE_MISS = 0xC01C0018,
    /// The requested device object does not exist for the given volume.
    FLT_NO_DEVICE_OBJECT = 0xC01C0019,
    /// The specified volume is already mounted.
    FLT_VOLUME_ALREADY_MOUNTED = 0xC01C001A,
    /// The specified transaction context is already enlisted in a transaction.
    FLT_ALREADY_ENLISTED = 0xC01C001B,
    /// The specified context is already attached to another object.
    FLT_CONTEXT_ALREADY_LINKED = 0xC01C001C,
    /// No waiter is present for the filter's reply to this message.
    FLT_NO_WAITER_FOR_REPLY = 0xC01C0020,
    /// A monitor descriptor could not be obtained.
    MONITOR_NO_DESCRIPTOR = 0xC01D0001,
    /// This release does not support the format of the obtained monitor descriptor.
    MONITOR_UNKNOWN_DESCRIPTOR_FORMAT = 0xC01D0002,
    /// The checksum of the obtained monitor descriptor is invalid.
    MONITOR_INVALID_DESCRIPTOR_CHECKSUM = 0xC01D0003,
    /// The monitor descriptor contains an invalid standard timing block.
    MONITOR_INVALID_STANDARD_TIMING_BLOCK = 0xC01D0004,
    /// WMI data-block registration failed for one of the MSMonitorClass WMI subclasses.
    MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED = 0xC01D0005,
    /// The provided monitor descriptor block is either corrupted or does not contain the monitor's detailed serial number.
    MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK = 0xC01D0006,
    /// The provided monitor descriptor block is either corrupted or does not contain the monitor's user-friendly name.
    MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK = 0xC01D0007,
    /// There is no monitor descriptor data at the specified (offset or size) region.
    MONITOR_NO_MORE_DESCRIPTOR_DATA = 0xC01D0008,
    /// The monitor descriptor contains an invalid detailed timing block.
    MONITOR_INVALID_DETAILED_TIMING_BLOCK = 0xC01D0009,
    /// Monitor descriptor contains invalid manufacture date.
    MONITOR_INVALID_MANUFACTURE_DATE = 0xC01D000A,
    /// Exclusive mode ownership is needed to create an unmanaged primary allocation.
    GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER = 0xC01E0000,
    /// The driver needs more DMA buffer space to complete the requested operation.
    GRAPHICS_INSUFFICIENT_DMA_BUFFER = 0xC01E0001,
    /// The specified display adapter handle is invalid.
    GRAPHICS_INVALID_DISPLAY_ADAPTER = 0xC01E0002,
    /// The specified display adapter and all of its state have been reset.
    GRAPHICS_ADAPTER_WAS_RESET = 0xC01E0003,
    /// The driver stack does not match the expected driver model.
    GRAPHICS_INVALID_DRIVER_MODEL = 0xC01E0004,
    /// Present happened but ended up into the changed desktop mode.
    GRAPHICS_PRESENT_MODE_CHANGED = 0xC01E0005,
    /// Nothing to present due to desktop occlusion.
    GRAPHICS_PRESENT_OCCLUDED = 0xC01E0006,
    /// Not able to present due to denial of desktop access.
    GRAPHICS_PRESENT_DENIED = 0xC01E0007,
    /// Not able to present with color conversion.
    GRAPHICS_CANNOTCOLORCONVERT = 0xC01E0008,
    /// Present redirection is disabled (desktop windowing management subsystem is off).
    GRAPHICS_PRESENT_REDIRECTION_DISABLED = 0xC01E000B,
    /// Previous exclusive VidPn source owner has released its ownership
    GRAPHICS_PRESENT_UNOCCLUDED = 0xC01E000C,
    /// Not enough video memory is available to complete the operation.
    GRAPHICS_NO_VIDEO_MEMORY = 0xC01E0100,
    /// Could not probe and lock the underlying memory of an allocation.
    GRAPHICS_CANT_LOCK_MEMORY = 0xC01E0101,
    /// The allocation is currently busy.
    GRAPHICS_ALLOCATION_BUSY = 0xC01E0102,
    /// An object being referenced has already reached the maximum reference count and cannot be referenced further.
    GRAPHICS_TOO_MANY_REFERENCES = 0xC01E0103,
    /// A problem could not be solved due to an existing condition. Try again later.
    GRAPHICS_TRY_AGAIN_LATER = 0xC01E0104,
    /// A problem could not be solved due to an existing condition. Try again now.
    GRAPHICS_TRY_AGAIN_NOW = 0xC01E0105,
    /// The allocation is invalid.
    GRAPHICS_ALLOCATION_INVALID = 0xC01E0106,
    /// No more unswizzling apertures are currently available.
    GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE = 0xC01E0107,
    /// The current allocation cannot be unswizzled by an aperture.
    GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED = 0xC01E0108,
    /// The request failed because a pinned allocation cannot be evicted.
    GRAPHICS_CANT_EVICT_PINNED_ALLOCATION = 0xC01E0109,
    /// The allocation cannot be used from its current segment location for the specified operation.
    GRAPHICS_INVALID_ALLOCATION_USAGE = 0xC01E0110,
    /// A locked allocation cannot be used in the current command buffer.
    GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION = 0xC01E0111,
    /// The allocation being referenced has been closed permanently.
    GRAPHICS_ALLOCATION_CLOSED = 0xC01E0112,
    /// An invalid allocation instance is being referenced.
    GRAPHICS_INVALID_ALLOCATION_INSTANCE = 0xC01E0113,
    /// An invalid allocation handle is being referenced.
    GRAPHICS_INVALID_ALLOCATION_HANDLE = 0xC01E0114,
    /// The allocation being referenced does not belong to the current device.
    GRAPHICS_WRONG_ALLOCATION_DEVICE = 0xC01E0115,
    /// The specified allocation lost its content.
    GRAPHICS_ALLOCATION_CONTENT_LOST = 0xC01E0116,
    /// A GPU exception was detected on the given device. The device cannot be scheduled.
    GRAPHICS_GPU_EXCEPTION_ON_DEVICE = 0xC01E0200,
    /// The specified VidPN topology is invalid.
    GRAPHICS_INVALID_VIDPN_TOPOLOGY = 0xC01E0300,
    /// The specified VidPN topology is valid but is not supported by this model of the display adapter.
    GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED = 0xC01E0301,
    /// The specified VidPN topology is valid but is not currently supported by the display adapter due to allocation of its resources.
    GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED = 0xC01E0302,
    /// The specified VidPN handle is invalid.
    GRAPHICS_INVALID_VIDPN = 0xC01E0303,
    /// The specified video present source is invalid.
    GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE = 0xC01E0304,
    /// The specified video present target is invalid.
    GRAPHICS_INVALID_VIDEO_PRESENT_TARGET = 0xC01E0305,
    /// The specified VidPN modality is not supported (for example, at least two of the pinned modes are not co-functional).
    GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED = 0xC01E0306,
    /// The specified VidPN source mode set is invalid.
    GRAPHICS_INVALID_VIDPN_SOURCEMODESET = 0xC01E0308,
    /// The specified VidPN target mode set is invalid.
    GRAPHICS_INVALID_VIDPN_TARGETMODESET = 0xC01E0309,
    /// The specified video signal frequency is invalid.
    GRAPHICS_INVALID_FREQUENCY = 0xC01E030A,
    /// The specified video signal active region is invalid.
    GRAPHICS_INVALID_ACTIVE_REGION = 0xC01E030B,
    /// The specified video signal total region is invalid.
    GRAPHICS_INVALID_TOTAL_REGION = 0xC01E030C,
    /// The specified video present source mode is invalid.
    GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE = 0xC01E0310,
    /// The specified video present target mode is invalid.
    GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE = 0xC01E0311,
    /// The pinned mode must remain in the set on the VidPN's co-functional modality enumeration.
    GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET = 0xC01E0312,
    /// The specified video present path is already in the VidPN's topology.
    GRAPHICS_PATH_ALREADY_IN_TOPOLOGY = 0xC01E0313,
    /// The specified mode is already in the mode set.
    GRAPHICS_MODE_ALREADY_IN_MODESET = 0xC01E0314,
    /// The specified video present source set is invalid.
    GRAPHICS_INVALID_VIDEOPRESENTSOURCESET = 0xC01E0315,
    /// The specified video present target set is invalid.
    GRAPHICS_INVALID_VIDEOPRESENTTARGETSET = 0xC01E0316,
    /// The specified video present source is already in the video present source set.
    GRAPHICS_SOURCE_ALREADY_IN_SET = 0xC01E0317,
    /// The specified video present target is already in the video present target set.
    GRAPHICS_TARGET_ALREADY_IN_SET = 0xC01E0318,
    /// The specified VidPN present path is invalid.
    GRAPHICS_INVALID_VIDPN_PRESENT_PATH = 0xC01E0319,
    /// The miniport has no recommendation for augmenting the specified VidPN's topology.
    GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY = 0xC01E031A,
    /// The specified monitor frequency range set is invalid.
    GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET = 0xC01E031B,
    /// The specified monitor frequency range is invalid.
    GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE = 0xC01E031C,
    /// The specified frequency range is not in the specified monitor frequency range set.
    GRAPHICS_FREQUENCYRANGE_NOT_IN_SET = 0xC01E031D,
    /// The specified frequency range is already in the specified monitor frequency range set.
    GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET = 0xC01E031F,
    /// The specified mode set is stale. Reacquire the new mode set.
    GRAPHICS_STALE_MODESET = 0xC01E0320,
    /// The specified monitor source mode set is invalid.
    GRAPHICS_INVALID_MONITOR_SOURCEMODESET = 0xC01E0321,
    /// The specified monitor source mode is invalid.
    GRAPHICS_INVALID_MONITOR_SOURCE_MODE = 0xC01E0322,
    /// The miniport does not have a recommendation regarding the request to provide a functional VidPN given the current display adapter configuration.
    GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN = 0xC01E0323,
    /// The ID of the specified mode is being used by another mode in the set.
    GRAPHICS_MODE_ID_MUST_BE_UNIQUE = 0xC01E0324,
    /// The system failed to determine a mode that is supported by both the display adapter and the monitor connected to it.
    GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION = 0xC01E0325,
    /// The number of video present targets must be greater than or equal to the number of video present sources.
    GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES = 0xC01E0326,
    /// The specified present path is not in the VidPN's topology.
    GRAPHICS_PATH_NOT_IN_TOPOLOGY = 0xC01E0327,
    /// The display adapter must have at least one video present source.
    GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE = 0xC01E0328,
    /// The display adapter must have at least one video present target.
    GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET = 0xC01E0329,
    /// The specified monitor descriptor set is invalid.
    GRAPHICS_INVALID_MONITORDESCRIPTORSET = 0xC01E032A,
    /// The specified monitor descriptor is invalid.
    GRAPHICS_INVALID_MONITORDESCRIPTOR = 0xC01E032B,
    /// The specified descriptor is not in the specified monitor descriptor set.
    GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET = 0xC01E032C,
    /// The specified descriptor is already in the specified monitor descriptor set.
    GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET = 0xC01E032D,
    /// The ID of the specified monitor descriptor is being used by another descriptor in the set.
    GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE = 0xC01E032E,
    /// The specified video present target subset type is invalid.
    GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE = 0xC01E032F,
    /// Two or more of the specified resources are not related to each other, as defined by the interface semantics.
    GRAPHICS_RESOURCES_NOT_RELATED = 0xC01E0330,
    /// The ID of the specified video present source is being used by another source in the set.
    GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE = 0xC01E0331,
    /// The ID of the specified video present target is being used by another target in the set.
    GRAPHICS_TARGET_ID_MUST_BE_UNIQUE = 0xC01E0332,
    /// The specified VidPN source cannot be used because there is no available VidPN target to connect it to.
    GRAPHICS_NO_AVAILABLE_VIDPN_TARGET = 0xC01E0333,
    /// The newly arrived monitor could not be associated with a display adapter.
    GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER = 0xC01E0334,
    /// The particular display adapter does not have an associated VidPN manager.
    GRAPHICS_NO_VIDPNMGR = 0xC01E0335,
    /// The VidPN manager of the particular display adapter does not have an active VidPN.
    GRAPHICS_NO_ACTIVE_VIDPN = 0xC01E0336,
    /// The specified VidPN topology is stale; obtain the new topology.
    GRAPHICS_STALE_VIDPN_TOPOLOGY = 0xC01E0337,
    /// No monitor is connected on the specified video present target.
    GRAPHICS_MONITOR_NOT_CONNECTED = 0xC01E0338,
    /// The specified source is not part of the specified VidPN's topology.
    GRAPHICS_SOURCE_NOT_IN_TOPOLOGY = 0xC01E0339,
    /// The specified primary surface size is invalid.
    GRAPHICS_INVALID_PRIMARYSURFACE_SIZE = 0xC01E033A,
    /// The specified visible region size is invalid.
    GRAPHICS_INVALID_VISIBLEREGION_SIZE = 0xC01E033B,
    /// The specified stride is invalid.
    GRAPHICS_INVALID_STRIDE = 0xC01E033C,
    /// The specified pixel format is invalid.
    GRAPHICS_INVALID_PIXELFORMAT = 0xC01E033D,
    /// The specified color basis is invalid.
    GRAPHICS_INVALID_COLORBASIS = 0xC01E033E,
    /// The specified pixel value access mode is invalid.
    GRAPHICS_INVALID_PIXELVALUEACCESSMODE = 0xC01E033F,
    /// The specified target is not part of the specified VidPN's topology.
    GRAPHICS_TARGET_NOT_IN_TOPOLOGY = 0xC01E0340,
    /// Failed to acquire the display mode management interface.
    GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT = 0xC01E0341,
    /// The specified VidPN source is already owned by a DMM client and cannot be used until that client releases it.
    GRAPHICS_VIDPN_SOURCE_IN_USE = 0xC01E0342,
    /// The specified VidPN is active and cannot be accessed.
    GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN = 0xC01E0343,
    /// The specified VidPN's present path importance ordinal is invalid.
    GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL = 0xC01E0344,
    /// The specified VidPN's present path content geometry transformation is invalid.
    GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION = 0xC01E0345,
    /// The specified content geometry transformation is not supported on the respective VidPN present path.
    GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED = 0xC01E0346,
    /// The specified gamma ramp is invalid.
    GRAPHICS_INVALID_GAMMA_RAMP = 0xC01E0347,
    /// The specified gamma ramp is not supported on the respective VidPN present path.
    GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED = 0xC01E0348,
    /// Multisampling is not supported on the respective VidPN present path.
    GRAPHICS_MULTISAMPLING_NOT_SUPPORTED = 0xC01E0349,
    /// The specified mode is not in the specified mode set.
    GRAPHICS_MODE_NOT_IN_MODESET = 0xC01E034A,
    /// The specified VidPN topology recommendation reason is invalid.
    GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON = 0xC01E034D,
    /// The specified VidPN present path content type is invalid.
    GRAPHICS_INVALID_PATH_CONTENT_TYPE = 0xC01E034E,
    /// The specified VidPN present path copy protection type is invalid.
    GRAPHICS_INVALID_COPYPROTECTION_TYPE = 0xC01E034F,
    /// Only one unassigned mode set can exist at any one time for a particular VidPN source or target.
    GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS = 0xC01E0350,
    /// The specified scan line ordering type is invalid.
    GRAPHICS_INVALID_SCANLINE_ORDERING = 0xC01E0352,
    /// The topology changes are not allowed for the specified VidPN.
    GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED = 0xC01E0353,
    /// All available importance ordinals are being used in the specified topology.
    GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS = 0xC01E0354,
    /// The specified primary surface has a different private-format attribute than the current primary surface.
    GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT = 0xC01E0355,
    /// The specified mode-pruning algorithm is invalid.
    GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM = 0xC01E0356,
    /// The specified monitor-capability origin is invalid.
    GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN = 0xC01E0357,
    /// The specified monitor-frequency range constraint is invalid.
    GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT = 0xC01E0358,
    /// The maximum supported number of present paths has been reached.
    GRAPHICS_MAX_NUM_PATHS_REACHED = 0xC01E0359,
    /// The miniport requested that augmentation be canceled for the specified source of the specified VidPN's topology.
    GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION = 0xC01E035A,
    /// The specified client type was not recognized.
    GRAPHICS_INVALID_CLIENT_TYPE = 0xC01E035B,
    /// The client VidPN is not set on this adapter (for example, no user mode-initiated mode changes have taken place on this adapter).
    GRAPHICS_CLIENTVIDPN_NOT_SET = 0xC01E035C,
    /// The specified display adapter child device already has an external device connected to it.
    GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED = 0xC01E0400,
    /// The display adapter child device does not support reporting a descriptor.
    GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED = 0xC01E0401,
    /// The display adapter is not linked to any other adapters.
    GRAPHICS_NOT_A_LINKED_ADAPTER = 0xC01E0430,
    /// The lead adapter in a linked configuration was not enumer```
