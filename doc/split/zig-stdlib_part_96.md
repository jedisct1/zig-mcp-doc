```
ated yet.
    GRAPHICS_LEADLINK_NOT_ENUMERATED = 0xC01E0431,
    /// Some chain adapters in a linked configuration have not yet been enumerated.
    GRAPHICS_CHAINLINKS_NOT_ENUMERATED = 0xC01E0432,
    /// The chain of linked adapters is not ready to start because of an unknown failure.
    GRAPHICS_ADAPTER_CHAIN_NOT_READY = 0xC01E0433,
    /// An attempt was made to start a lead link display adapter when the chain links had not yet started.
    GRAPHICS_CHAINLINKS_NOT_STARTED = 0xC01E0434,
    /// An attempt was made to turn on a lead link display adapter when the chain links were turned off.
    GRAPHICS_CHAINLINKS_NOT_POWERED_ON = 0xC01E0435,
    /// The adapter link was found in an inconsistent state.
    /// Not all adapters are in an expected PNP/power state.
    GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE = 0xC01E0436,
    /// The driver trying to start is not the same as the driver for the posted display adapter.
    GRAPHICS_NOT_POST_DEVICE_DRIVER = 0xC01E0438,
    /// An operation is being attempted that requires the display adapter to be in a quiescent state.
    GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED = 0xC01E043B,
    /// The driver does not support OPM.
    GRAPHICS_OPM_NOT_SUPPORTED = 0xC01E0500,
    /// The driver does not support COPP.
    GRAPHICS_COPP_NOT_SUPPORTED = 0xC01E0501,
    /// The driver does not support UAB.
    GRAPHICS_UAB_NOT_SUPPORTED = 0xC01E0502,
    /// The specified encrypted parameters are invalid.
    GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS = 0xC01E0503,
    /// An array passed to a function cannot hold all of the data that the function wants to put in it.
    GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL = 0xC01E0504,
    /// The GDI display device passed to this function does not have any active protected outputs.
    GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST = 0xC01E0505,
    /// The PVP cannot find an actual GDI display device that corresponds to the passed-in GDI display device name.
    GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME = 0xC01E0506,
    /// This function failed because the GDI display device passed to it was not attached to the Windows desktop.
    GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP = 0xC01E0507,
    /// The PVP does not support mirroring display devices because they do not have any protected outputs.
    GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED = 0xC01E0508,
    /// The function failed because an invalid pointer parameter was passed to it.
    /// A pointer parameter is invalid if it is null, is not correctly aligned, or it points to an invalid address or a kernel mode address.
    GRAPHICS_OPM_INVALID_POINTER = 0xC01E050A,
    /// An internal error caused an operation to fail.
    GRAPHICS_OPM_INTERNAL_ERROR = 0xC01E050B,
    /// The function failed because the caller passed in an invalid OPM user-mode handle.
    GRAPHICS_OPM_INVALID_HANDLE = 0xC01E050C,
    /// This function failed because the GDI device passed to it did not have any monitors associated with it.
    GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE = 0xC01E050D,
    /// A certificate could not be returned because the certificate buffer passed to the function was too small.
    GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH = 0xC01E050E,
    /// DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present yarget is in spanning mode.
    GRAPHICS_OPM_SPANNING_MODE_ENABLED = 0xC01E050F,
    /// DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present target is in theater mode.
    GRAPHICS_OPM_THEATER_MODE_ENABLED = 0xC01E0510,
    /// The function call failed because the display adapter's hardware functionality scan (HFS) failed to validate the graphics hardware.
    GRAPHICS_PVP_HFS_FAILED = 0xC01E0511,
    /// The HDCP SRM passed to this function did not comply with section 5 of the HDCP 1.1 specification.
    GRAPHICS_OPM_INVALID_SRM = 0xC01E0512,
    /// The protected output cannot enable the HDCP system because it does not support it.
    GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP = 0xC01E0513,
    /// The protected output cannot enable analog copy protection because it does not support it.
    GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP = 0xC01E0514,
    /// The protected output cannot enable the CGMS-A protection technology because it does not support it.
    GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA = 0xC01E0515,
    /// DxgkDdiOPMGetInformation() cannot return the version of the SRM being used because the application never successfully passed an SRM to the protected output.
    GRAPHICS_OPM_HDCP_SRM_NEVER_SET = 0xC01E0516,
    /// DxgkDdiOPMConfigureProtectedOutput() cannot enable the specified output protection technology because the output's screen resolution is too high.
    GRAPHICS_OPM_RESOLUTION_TOO_HIGH = 0xC01E0517,
    /// DxgkDdiOPMConfigureProtectedOutput() cannot enable HDCP because other physical outputs are using the display adapter's HDCP hardware.
    GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE = 0xC01E0518,
    /// The operating system asynchronously destroyed this OPM-protected output because the operating system state changed.
    /// This error typically occurs because the monitor PDO associated with this protected output was removed or stopped, the protected output's session became a nonconsole session, or the protected output's desktop became inactive.
    GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS = 0xC01E051A,
    /// OPM functions cannot be called when a session is changing its type.
    /// Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA).
    GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS = 0xC01E051B,
    /// The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed.
    /// This error is returned only if a protected output has OPM semantics.
    /// DxgkDdiOPMGetCOPPCompatibleInformation always returns this error if a protected output has OPM semantics.
    /// DxgkDdiOPMGetInformation returns this error code if the caller requested COPP-specific information.
    /// DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use a COPP-specific command.
    GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS = 0xC01E051C,
    /// The DxgkDdiOPMGetInformation and DxgkDdiOPMGetCOPPCompatibleInformation functions return this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid.
    GRAPHICS_OPM_INVALID_INFORMATION_REQUEST = 0xC01E051D,
    /// The function failed because an unexpected error occurred inside a display driver.
    GRAPHICS_OPM_DRIVER_INTERNAL_ERROR = 0xC01E051E,
    /// The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed.
    /// This error is returned only if a protected output has COPP semantics.
    /// DxgkDdiOPMGetCOPPCompatibleInformation returns this error code if the caller requested OPM-specific information.
    /// DxgkDdiOPMGetInformation always returns this error if a protected output has COPP semantics.
    /// DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use an OPM-specific command.
    GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS = 0xC01E051F,
    /// The DxgkDdiOPMGetCOPPCompatibleInformation and DxgkDdiOPMConfigureProtectedOutput functions return this error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXGKMDT_OPM_SET_ACP_AND_CGMSA_SIGNALING GUIDs.
    GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED = 0xC01E0520,
    /// The DxgkDdiOPMConfigureProtectedOutput function returns this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid.
    GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST = 0xC01E0521,
    /// The monitor connected to the specified video output does not have an I2C bus.
    GRAPHICS_I2C_NOT_SUPPORTED = 0xC01E0580,
    /// No device on the I2C bus has the specified address.
    GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST = 0xC01E0581,
    /// An error occurred while transmitting data to the device on the I2C bus.
    GRAPHICS_I2C_ERROR_TRANSMITTING_DATA = 0xC01E0582,
    /// An error occurred while receiving data from the device on the I2C bus.
    GRAPHICS_I2C_ERROR_RECEIVING_DATA = 0xC01E0583,
    /// The monitor does not support the specified VCP code.
    GRAPHICS_DDCCI_VCP_NOT_SUPPORTED = 0xC01E0584,
    /// The data received from the monitor is invalid.
    GRAPHICS_DDCCI_INVALID_DATA = 0xC01E0585,
    /// A function call failed because a monitor returned an invalid timing status byte when the operating system used the DDC/CI get timing report and timing message command to get a timing report from a monitor.
    GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE = 0xC01E0586,
    /// A monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification.
    GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING = 0xC01E0587,
    /// An internal error caused an operation to fail.
    GRAPHICS_MCA_INTERNAL_ERROR = 0xC01E0588,
    /// An operation failed because a DDC/CI message had an invalid value in its command field.
    GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND = 0xC01E0589,
    /// This error occurred because a DDC/CI message had an invalid value in its length field.
    GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH = 0xC01E058A,
    /// This error occurred because the value in a DDC/CI message's checksum field did not match the message's computed checksum value.
    /// This error implies that the data was corrupted while it was being transmitted from a monitor to a computer.
    GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM = 0xC01E058B,
    /// This function failed because an invalid monitor handle was passed to it.
    GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE = 0xC01E058C,
    /// The operating system asynchronously destroyed the monitor that corresponds to this handle because the operating system's state changed.
    /// This error typically occurs because the monitor PDO associated with this handle was removed or stopped, or a display mode change occurred.
    /// A display mode change occurs when Windows sends a WM_DISPLAYCHANGE message to applications.
    GRAPHICS_MONITOR_NO_LONGER_EXISTS = 0xC01E058D,
    /// This function can be used only if a program is running in the local console session.
    /// It cannot be used if a program is running on a remote desktop session or on a terminal server session.
    GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED = 0xC01E05E0,
    /// This function cannot find an actual GDI display device that corresponds to the specified GDI display device name.
    GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME = 0xC01E05E1,
    /// The function failed because the specified GDI display device was not attached to the Windows desktop.
    GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP = 0xC01E05E2,
    /// This function does not support GDI mirroring display devices because GDI mirroring display devices do not have any physical monitors associated with them.
    GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED = 0xC01E05E3,
    /// The function failed because an invalid pointer parameter was passed to it.
    /// A pointer parameter is invalid if it is null, is not correctly aligned, or points to an invalid address or to a kernel mode address.
    GRAPHICS_INVALID_POINTER = 0xC01E05E4,
    /// This function failed because the GDI device passed to it did not have a monitor associated with it.
    GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE = 0xC01E05E5,
    /// An array passed to the function cannot hold all of the data that the function must copy into the array.
    GRAPHICS_PARAMETER_ARRAY_TOO_SMALL = 0xC01E05E6,
    /// An internal error caused an operation to fail.
    GRAPHICS_INTERNAL_ERROR = 0xC01E05E7,
    /// The function failed because the current session is changing its type.
    /// This function cannot be called when the current session is changing its type.
    /// Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA).
    GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS = 0xC01E05E8,
    /// The volume must be unlocked before it can be used.
    FVE_LOCKED_VOLUME = 0xC0210000,
    /// The volume is fully decrypted and no key is available.
    FVE_NOT_ENCRYPTED = 0xC0210001,
    /// The control block for the encrypted volume is not valid.
    FVE_BAD_INFORMATION = 0xC0210002,
    /// Not enough free space remains on the volume to allow encryption.
    FVE_TOO_SMALL = 0xC0210003,
    /// The partition cannot be encrypted because the file system is not supported.
    FVE_FAILED_WRONG_FS = 0xC0210004,
    /// The file system is inconsistent. Run the Check Disk utility.
    FVE_FAILED_BAD_FS = 0xC0210005,
    /// The file system does not extend to the end of the volume.
    FVE_FS_NOT_EXTENDED = 0xC0210006,
    /// This operation cannot be performed while a file system is mounted on the volume.
    FVE_FS_MOUNTED = 0xC0210007,
    /// BitLocker Drive Encryption is not included with this version of Windows.
    FVE_NO_LICENSE = 0xC0210008,
    /// The requested action was denied by the FVE control engine.
    FVE_ACTION_NOT_ALLOWED = 0xC0210009,
    /// The data supplied is malformed.
    FVE_BAD_DATA = 0xC021000A,
    /// The volume is not bound to the system.
    FVE_VOLUME_NOT_BOUND = 0xC021000B,
    /// The volume specified is not a data volume.
    FVE_NOT_DATA_VOLUME = 0xC021000C,
    /// A read operation failed while converting the volume.
    FVE_CONV_READ_ERROR = 0xC021000D,
    /// A write operation failed while converting the volume.
    FVE_CONV_WRITE_ERROR = 0xC021000E,
    /// The control block for the encrypted volume was updated by another thread. Try again.
    FVE_OVERLAPPED_UPDATE = 0xC021000F,
    /// The volume encryption algorithm cannot be used on this sector size.
    FVE_FAILED_SECTOR_SIZE = 0xC0210010,
    /// BitLocker recovery authentication failed.
    FVE_FAILED_AUTHENTICATION = 0xC0210011,
    /// The volume specified is not the boot operating system volume.
    FVE_NOT_OS_VOLUME = 0xC0210012,
    /// The BitLocker startup key or recovery password could not be read from external media.
    FVE_KEYFILE_NOT_FOUND = 0xC0210013,
    /// The BitLocker startup key or recovery password file is corrupt or invalid.
    FVE_KEYFILE_INVALID = 0xC0210014,
    /// The BitLocker encryption key could not be obtained from the startup key or the recovery password.
    FVE_KEYFILE_NO_VMK = 0xC0210015,
    /// The TPM is disabled.
    FVE_TPM_DISABLED = 0xC0210016,
    /// The authorization data for the SRK of the TPM is not zero.
    FVE_TPM_SRK_AUTH_NOT_ZERO = 0xC0210017,
    /// The system boot information changed or the TPM locked out access to BitLocker encryption keys until the computer is restarted.
    FVE_TPM_INVALID_PCR = 0xC0210018,
    /// The BitLocker encryption key could not be obtained from the TPM.
    FVE_TPM_NO_VMK = 0xC0210019,
    /// The BitLocker encryption key could not be obtained from the TPM and PIN.
    FVE_PIN_INVALID = 0xC021001A,
    /// A boot application hash does not match the hash computed when BitLocker was turned on.
    FVE_AUTH_INVALID_APPLICATION = 0xC021001B,
    /// The Boot Configuration Data (BCD) settings are not supported or have changed because BitLocker was enabled.
    FVE_AUTH_INVALID_CONFIG = 0xC021001C,
    /// Boot debugging is enabled. Run Windows Boot Configuration Data Store Editor (bcdedit.exe) to turn it off.
    FVE_DEBUGGER_ENABLED = 0xC021001D,
    /// The BitLocker encryption key could not be obtained.
    FVE_DRY_RUN_FAILED = 0xC021001E,
    /// The metadata disk region pointer is incorrect.
    FVE_BAD_METADATA_POINTER = 0xC021001F,
    /// The backup copy of the metadata is out of date.
    FVE_OLD_METADATA_COPY = 0xC0210020,
    /// No action was taken because a system restart is required.
    FVE_REBOOT_REQUIRED = 0xC0210021,
    /// No action was taken because BitLocker Drive Encryption is in RAW access mode.
    FVE_RAW_ACCESS = 0xC0210022,
    /// BitLocker Drive Encryption cannot enter RAW access mode for this volume.
    FVE_RAW_BLOCKED = 0xC0210023,
    /// This feature of BitLocker Drive Encryption is not included with this version of Windows.
    FVE_NO_FEATURE_LICENSE = 0xC0210026,
    /// Group policy does not permit turning off BitLocker Drive Encryption on roaming data volumes.
    FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED = 0xC0210027,
    /// Bitlocker Drive Encryption failed to recover from aborted conversion.
    /// This could be due to either all conversion logs being corrupted or the media being write-protected.
    FVE_CONV_RECOVERY_FAILED = 0xC0210028,
    /// The requested virtualization size is too big.
    FVE_VIRTUALIZED_SPACE_TOO_BIG = 0xC0210029,
    /// The drive is too small to be protected using BitLocker Drive Encryption.
    FVE_VOLUME_TOO_SMALL = 0xC0210030,
    /// The callout does not exist.
    FWP_CALLOUT_NOT_FOUND = 0xC0220001,
    /// The filter condition does not exist.
    FWP_CONDITION_NOT_FOUND = 0xC0220002,
    /// The filter does not exist.
    FWP_FILTER_NOT_FOUND = 0xC0220003,
    /// The layer does not exist.
    FWP_LAYER_NOT_FOUND = 0xC0220004,
    /// The provider does not exist.
    FWP_PROVIDER_NOT_FOUND = 0xC0220005,
    /// The provider context does not exist.
    FWP_PROVIDER_CONTEXT_NOT_FOUND = 0xC0220006,
    /// The sublayer does not exist.
    FWP_SUBLAYER_NOT_FOUND = 0xC0220007,
    /// The object does not exist.
    FWP_NOT_FOUND = 0xC0220008,
    /// An object with that GUID or LUID already exists.
    FWP_ALREADY_EXISTS = 0xC0220009,
    /// The object is referenced by other objects and cannot be deleted.
    FWP_IN_USE = 0xC022000A,
    /// The call is not allowed from within a dynamic session.
    FWP_DYNAMIC_SESSION_IN_PROGRESS = 0xC022000B,
    /// The call was made from the wrong session and cannot be completed.
    FWP_WRONG_SESSION = 0xC022000C,
    /// The call must be made from within an explicit transaction.
    FWP_NO_TXN_IN_PROGRESS = 0xC022000D,
    /// The call is not allowed from within an explicit transaction.
    FWP_TXN_IN_PROGRESS = 0xC022000E,
    /// The explicit transaction has been forcibly canceled.
    FWP_TXN_ABORTED = 0xC022000F,
    /// The session has been canceled.
    FWP_SESSION_ABORTED = 0xC0220010,
    /// The call is not allowed from within a read-only transaction.
    FWP_INCOMPATIBLE_TXN = 0xC0220011,
    /// The call timed out while waiting to acquire the transaction lock.
    FWP_TIMEOUT = 0xC0220012,
    /// The collection of network diagnostic events is disabled.
    FWP_NET_EVENTS_DISABLED = 0xC0220013,
    /// The operation is not supported by the specified layer.
    FWP_INCOMPATIBLE_LAYER = 0xC0220014,
    /// The call is allowed for kernel-mode callers only.
    FWP_KM_CLIENTS_ONLY = 0xC0220015,
    /// The call tried to associate two objects with incompatible lifetimes.
    FWP_LIFETIME_MISMATCH = 0xC0220016,
    /// The object is built-in and cannot be deleted.
    FWP_BUILTIN_OBJECT = 0xC0220017,
    /// The maximum number of callouts has been reached.
    FWP_TOO_MANY_CALLOUTS = 0xC0220018,
    /// A notification could not be delivered because a message queue has reached maximum capacity.
    FWP_NOTIFICATION_DROPPED = 0xC0220019,
    /// The traffic parameters do not match those for the security association context.
    FWP_TRAFFIC_MISMATCH = 0xC022001A,
    /// The call is not allowed for the current security association state.
    FWP_INCOMPATIBLE_SA_STATE = 0xC022001B,
    /// A required pointer is null.
    FWP_NULL_POINTER = 0xC022001C,
    /// An enumerator is not valid.
    FWP_INVALID_ENUMERATOR = 0xC022001D,
    /// The flags field contains an invalid value.
    FWP_INVALID_FLAGS = 0xC022001E,
    /// A network mask is not valid.
    FWP_INVALID_NET_MASK = 0xC022001F,
    /// An FWP_RANGE is not valid.
    FWP_INVALID_RANGE = 0xC0220020,
    /// The time interval is not valid.
    FWP_INVALID_INTERVAL = 0xC0220021,
    /// An array that must contain at least one element has a zero length.
    FWP_ZERO_LENGTH_ARRAY = 0xC0220022,
    /// The displayData.name field cannot be null.
    FWP_NULL_DISPLAY_NAME = 0xC0220023,
    /// The action type is not one of the allowed action types for a filter.
    FWP_INVALID_ACTION_TYPE = 0xC0220024,
    /// The filter weight is not valid.
    FWP_INVALID_WEIGHT = 0xC0220025,
    /// A filter condition contains a match type that is not compatible with the operands.
    FWP_MATCH_TYPE_MISMATCH = 0xC0220026,
    /// An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type.
    FWP_TYPE_MISMATCH = 0xC0220027,
    /// An integer value is outside the allowed range.
    FWP_OUT_OF_BOUNDS = 0xC0220028,
    /// A reserved field is nonzero.
    FWP_RESERVED = 0xC0220029,
    /// A filter cannot contain multiple conditions operating on a single field.
    FWP_DUPLICATE_CONDITION = 0xC022002A,
    /// A policy cannot contain the same keying module more than once.
    FWP_DUPLICATE_KEYMOD = 0xC022002B,
    /// The action type is not compatible with the layer.
    FWP_ACTION_INCOMPATIBLE_WITH_LAYER = 0xC022002C,
    /// The action type is not compatible with the sublayer.
    FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER = 0xC022002D,
    /// The raw context or the provider context is not compatible with the layer.
    FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER = 0xC022002E,
    /// The raw context or the provider context is not compatible with the callout.
    FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT = 0xC022002F,
    /// The authentication method is not compatible with the policy type.
    FWP_INCOMPATIBLE_AUTH_METHOD = 0xC0220030,
    /// The Diffie-Hellman group is not compatible with the policy type.
    FWP_INCOMPATIBLE_DH_GROUP = 0xC0220031,
    /// An IKE policy cannot contain an Extended Mode policy.
    FWP_EM_NOT_SUPPORTED = 0xC0220032,
    /// The enumeration template or subscription will never match any objects.
    FWP_NEVER_MATCH = 0xC0220033,
    /// The provider context is of the wrong type.
    FWP_PROVIDER_CONTEXT_MISMATCH = 0xC0220034,
    /// The parameter is incorrect.
    FWP_INVALID_PARAMETER = 0xC0220035,
    /// The maximum number of sublayers has been reached.
    FWP_TOO_MANY_SUBLAYERS = 0xC0220036,
    /// The notification function for a callout returned an error.
    FWP_CALLOUT_NOTIFICATION_FAILED = 0xC0220037,
    /// The IPsec authentication configuration is not compatible with the authentication type.
    FWP_INCOMPATIBLE_AUTH_CONFIG = 0xC0220038,
    /// The IPsec cipher configuration is not compatible with the cipher type.
    FWP_INCOMPATIBLE_CIPHER_CONFIG = 0xC0220039,
    /// A policy cannot contain the same auth method more than once.
    FWP_DUPLICATE_AUTH_METHOD = 0xC022003C,
    /// The TCP/IP stack is not ready.
    FWP_TCPIP_NOT_READY = 0xC0220100,
    /// The injection handle is being closed by another thread.
    FWP_INJECT_HANDLE_CLOSING = 0xC0220101,
    /// The injection handle is stale.
    FWP_INJECT_HANDLE_STALE = 0xC0220102,
    /// The classify cannot be pended.
    FWP_CANNOT_PEND = 0xC0220103,
    /// The binding to the network interface is being closed.
    NDIS_CLOSING = 0xC0230002,
    /// An invalid version was specified.
    NDIS_BAD_VERSION = 0xC0230004,
    /// An invalid characteristics table was used.
    NDIS_BAD_CHARACTERISTICS = 0xC0230005,
    /// Failed to find the network interface or the network interface is not ready.
    NDIS_ADAPTER_NOT_FOUND = 0xC0230006,
    /// Failed to open the network interface.
    NDIS_OPEN_FAILED = 0xC0230007,
    /// The network interface has encountered an internal unrecoverable failure.
    NDIS_DEVICE_FAILED = 0xC0230008,
    /// The multicast list on the network interface is full.
    NDIS_MULTICAST_FULL = 0xC0230009,
    /// An attempt was made to add a duplicate multicast address to the list.
    NDIS_MULTICAST_EXISTS = 0xC023000A,
    /// At attempt was made to remove a multicast address that was never added.
    NDIS_MULTICAST_NOT_FOUND = 0xC023000B,
    /// The network interface aborted the request.
    NDIS_REQUEST_ABORTED = 0xC023000C,
    /// The network interface cannot process the request because it is being reset.
    NDIS_RESET_IN_PROGRESS = 0xC023000D,
    /// An attempt was made to send an invalid packet on a network interface.
    NDIS_INVALID_PACKET = 0xC023000F,
    /// The specified request is not a valid operation for the target device.
    NDIS_INVALID_DEVICE_REQUEST = 0xC0230010,
    /// The network interface is not ready to complete this operation.
    NDIS_ADAPTER_NOT_READY = 0xC0230011,
    /// The length of the buffer submitted for this operation is not valid.
    NDIS_INVALID_LENGTH = 0xC0230014,
    /// The data used for this operation is not valid.
    NDIS_INVALID_DATA = 0xC0230015,
    /// The length of the submitted buffer for this operation is too small.
    NDIS_BUFFER_TOO_SHORT = 0xC0230016,
    /// The network interface does not support this object identifier.
    NDIS_INVALID_OID = 0xC0230017,
    /// The network interface has been removed.
    NDIS_ADAPTER_REMOVED = 0xC0230018,
    /// The network interface does not support this media type.
    NDIS_UNSUPPORTED_MEDIA = 0xC0230019,
    /// An attempt was made to remove a token ring group address that is in use by other components.
    NDIS_GROUP_ADDRESS_IN_USE = 0xC023001A,
    /// An attempt was made to map a file that cannot be found.
    NDIS_FILE_NOT_FOUND = 0xC023001B,
    /// An error occurred while NDIS tried to map the file.
    NDIS_ERROR_READING_FILE = 0xC023001C,
    /// An attempt was made to map a file that is already mapped.
    NDIS_ALREADY_MAPPED = 0xC023001D,
    /// An attempt to allocate a hardware resource failed because the resource is used by another component.
    NDIS_RESOURCE_CONFLICT = 0xC023001E,
    /// The I/O operation failed because the network media is disconnected or the wireless access point is out of range.
    NDIS_MEDIA_DISCONNECTED = 0xC023001F,
    /// The network address used in the request is invalid.
    NDIS_INVALID_ADDRESS = 0xC0230022,
    /// The offload operation on the network interface has been paused.
    NDIS_PAUSED = 0xC023002A,
    /// The network interface was not found.
    NDIS_INTERFACE_NOT_FOUND = 0xC023002B,
    /// The revision number specified in the structure is not supported.
    NDIS_UNSUPPORTED_REVISION = 0xC023002C,
    /// The specified port does not exist on this network interface.
    NDIS_INVALID_PORT = 0xC023002D,
    /// The current state of the specified port on this network interface does not support the requested operation.
    NDIS_INVALID_PORT_STATE = 0xC023002E,
    /// The miniport adapter is in a lower power state.
    NDIS_LOW_POWER_STATE = 0xC023002F,
    /// The network interface does not support this request.
    NDIS_NOT_SUPPORTED = 0xC02300BB,
    /// The TCP connection is not offloadable because of a local policy setting.
    NDIS_OFFLOAD_POLICY = 0xC023100F,
    /// The TCP connection is not offloadable by the Chimney offload target.
    NDIS_OFFLOAD_CONNECTION_REJECTED = 0xC0231012,
    /// The IP Path object is not in an offloadable state.
    NDIS_OFFLOAD_PATH_REJECTED = 0xC0231013,
    /// The wireless LAN interface is in auto-configuration mode and does not support the requested parameter change operation.
    NDIS_DOT11_AUTO_CONFIG_ENABLED = 0xC0232000,
    /// The wireless LAN interface is busy and cannot perform the requested operation.
    NDIS_DOT11_MEDIA_IN_USE = 0xC0232001,
    /// The wireless LAN interface is power down and does not support the requested operation.
    NDIS_DOT11_POWER_STATE_INVALID = 0xC0232002,
    /// The list of wake on LAN patterns is full.
    NDIS_PM_WOL_PATTERN_LIST_FULL = 0xC0232003,
    /// The list of low power protocol offloads is full.
    NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL = 0xC0232004,
    /// The SPI in the packet does not match a valid IPsec SA.
    IPSEC_BAD_SPI = 0xC0360001,
    /// The packet was received on an IPsec SA whose lifetime has expired.
    IPSEC_SA_LIFETIME_EXPIRED = 0xC0360002,
    /// The packet was received on an IPsec SA that does not match the packet characteristics.
    IPSEC_WRONG_SA = 0xC0360003,
    /// The packet sequence number replay check failed.
    IPSEC_REPLAY_CHECK_FAILED = 0xC0360004,
    /// The IPsec header and/or trailer in the packet is invalid.
    IPSEC_INVALID_PACKET = 0xC0360005,
    /// The IPsec integrity check failed.
    IPSEC_INTEGRITY_CHECK_FAILED = 0xC0360006,
    /// IPsec dropped a clear text packet.
    IPSEC_CLEAR_TEXT_DROP = 0xC0360007,
    /// IPsec dropped an incoming ESP packet in authenticated firewall mode.  This drop is benign.
    IPSEC_AUTH_FIREWALL_DROP = 0xC0360008,
    /// IPsec dropped a packet due to DOS throttle.
    IPSEC_THROTTLE_DROP = 0xC0360009,
    /// IPsec Dos Protection matched an explicit block rule.
    IPSEC_DOSP_BLOCK = 0xC0368000,
    /// IPsec Dos Protection received an IPsec specific multicast packet which is not allowed.
    IPSEC_DOSP_RECEIVED_MULTICAST = 0xC0368001,
    /// IPsec Dos Protection received an incorrectly formatted packet.
    IPSEC_DOSP_INVALID_PACKET = 0xC0368002,
    /// IPsec Dos Protection failed to lookup state.
    IPSEC_DOSP_STATE_LOOKUP_FAILED = 0xC0368003,
    /// IPsec Dos Protection failed to create state because there are already maximum number of entries allowed by policy.
    IPSEC_DOSP_MAX_ENTRIES = 0xC0368004,
    /// IPsec Dos Protection received an IPsec negotiation packet for a keying module which is not allowed by policy.
    IPSEC_DOSP_KEYMOD_NOT_ALLOWED = 0xC0368005,
    /// IPsec Dos Protection failed to create per internal IP ratelimit queue because there is already maximum number of queues allowed by policy.
    IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES = 0xC0368006,
    /// The system does not support mirrored volumes.
    VOLMGR_MIRROR_NOT_SUPPORTED = 0xC038005B,
    /// The system does not support RAID-5 volumes.
    VOLMGR_RAID5_NOT_SUPPORTED = 0xC038005C,
    /// A virtual disk support provider for the specified file was not found.
    VIRTDISK_PROVIDER_NOT_FOUND = 0xC03A0014,
    /// The specified disk is not a virtual disk.
    VIRTDISK_NOT_VIRTUAL_DISK = 0xC03A0015,
    /// The chain of virtual hard disks is inaccessible.
    /// The process has not been granted access rights to the parent virtual hard disk for the differencing disk.
    VHD_PARENT_VHD_ACCESS_DENIED = 0xC03A0016,
    /// The chain of virtual hard disks is corrupted.
    /// There is a mismatch in the virtual sizes of the parent virtual hard disk and differencing disk.
    VHD_CHILD_PARENT_SIZE_MISMATCH = 0xC03A0017,
    /// The chain of virtual hard disks is corrupted.
    /// A differencing disk is indicated in its own parent chain.
    VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED = 0xC03A0018,
    /// The chain of virtual hard disks is inaccessible.
    /// There was an error opening a virtual hard disk further up the chain.
    VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT = 0xC03A0019,
    _,
};
pub const NEUTRAL = 0x00;
pub const DEFAULT = 0x01;
pub const SYS_DEFAULT = 0x02;
pub const CUSTOM_DEFAULT = 0x03;
pub const CUSTOM_UNSPECIFIED = 0x04;
pub const UI_CUSTOM_DEFAULT = 0x05;
pub const AFRIKAANS_SOUTH_AFRICA = 0x01;
pub const ALBANIAN_ALBANIA = 0x01;
pub const ALSATIAN_FRANCE = 0x01;
pub const AMHARIC_ETHIOPIA = 0x01;
pub const ARABIC_SAUDI_ARABIA = 0x01;
pub const ARABIC_IRAQ = 0x02;
pub const ARABIC_EGYPT = 0x03;
pub const ARABIC_LIBYA = 0x04;
pub const ARABIC_ALGERIA = 0x05;
pub const ARABIC_MOROCCO = 0x06;
pub const ARABIC_TUNISIA = 0x07;
pub const ARABIC_OMAN = 0x08;
pub const ARABIC_YEMEN = 0x09;
pub const ARABIC_SYRIA = 0x0a;
pub const ARABIC_JORDAN = 0x0b;
pub const ARABIC_LEBANON = 0x0c;
pub const ARABIC_KUWAIT = 0x0d;
pub const ARABIC_UAE = 0x0e;
pub const ARABIC_BAHRAIN = 0x0f;
pub const ARABIC_QATAR = 0x10;
pub const ARMENIAN_ARMENIA = 0x01;
pub const ASSAMESE_INDIA = 0x01;
pub const AZERI_LATIN = 0x01;
pub const AZERI_CYRILLIC = 0x02;
pub const AZERBAIJANI_AZERBAIJAN_LATIN = 0x01;
pub const AZERBAIJANI_AZERBAIJAN_CYRILLIC = 0x02;
pub const BANGLA_INDIA = 0x01;
pub const BANGLA_BANGLADESH = 0x02;
pub const BASHKIR_RUSSIA = 0x01;
pub const BASQUE_BASQUE = 0x01;
pub const BELARUSIAN_BELARUS = 0x01;
pub const BENGALI_INDIA = 0x01;
pub const BENGALI_BANGLADESH = 0x02;
pub const BOSNIAN_BOSNIA_HERZEGOVINA_LATIN = 0x05;
pub const BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC = 0x08;
pub const BRETON_FRANCE = 0x01;
pub const BULGARIAN_BULGARIA = 0x01;
pub const CATALAN_CATALAN = 0x01;
pub const CENTRAL_KURDISH_IRAQ = 0x01;
pub const CHEROKEE_CHEROKEE = 0x01;
pub const CHINESE_TRADITIONAL = 0x01;
pub const CHINESE_SIMPLIFIED = 0x02;
pub const CHINESE_HONGKONG = 0x03;
pub const CHINESE_SINGAPORE = 0x04;
pub const CHINESE_MACAU = 0x05;
pub const CORSICAN_FRANCE = 0x01;
pub const CZECH_CZECH_REPUBLIC = 0x01;
pub const CROATIAN_CROATIA = 0x01;
pub const CROATIAN_BOSNIA_HERZEGOVINA_LATIN = 0x04;
pub const DANISH_DENMARK = 0x01;
pub const DARI_AFGHANISTAN = 0x01;
pub const DIVEHI_MALDIVES = 0x01;
pub const DUTCH = 0x01;
pub const DUTCH_BELGIAN = 0x02;
pub const ENGLISH_US = 0x01;
pub const ENGLISH_UK = 0x02;
pub const ENGLISH_AUS = 0x03;
pub const ENGLISH_CAN = 0x04;
pub const ENGLISH_NZ = 0x05;
pub const ENGLISH_EIRE = 0x06;
pub const ENGLISH_SOUTH_AFRICA = 0x07;
pub const ENGLISH_JAMAICA = 0x08;
pub const ENGLISH_CARIBBEAN = 0x09;
pub const ENGLISH_BELIZE = 0x0a;
pub const ENGLISH_TRINIDAD = 0x0b;
pub const ENGLISH_ZIMBABWE = 0x0c;
pub const ENGLISH_PHILIPPINES = 0x0d;
pub const ENGLISH_INDIA = 0x10;
pub const ENGLISH_MALAYSIA = 0x11;
pub const ENGLISH_SINGAPORE = 0x12;
pub const ESTONIAN_ESTONIA = 0x01;
pub const FAEROESE_FAROE_ISLANDS = 0x01;
pub const FILIPINO_PHILIPPINES = 0x01;
pub const FINNISH_FINLAND = 0x01;
pub const FRENCH = 0x01;
pub const FRENCH_BELGIAN = 0x02;
pub const FRENCH_CANADIAN = 0x03;
pub const FRENCH_SWISS = 0x04;
pub const FRENCH_LUXEMBOURG = 0x05;
pub const FRENCH_MONACO = 0x06;
pub const FRISIAN_NETHERLANDS = 0x01;
pub const FULAH_SENEGAL = 0x02;
pub const GALICIAN_GALICIAN = 0x01;
pub const GEORGIAN_GEORGIA = 0x01;
pub const GERMAN = 0x01;
pub const GERMAN_SWISS = 0x02;
pub const GERMAN_AUSTRIAN = 0x03;
pub const GERMAN_LUXEMBOURG = 0x04;
pub const GERMAN_LIECHTENSTEIN = 0x05;
pub const GREEK_GREECE = 0x01;
pub const GREENLANDIC_GREENLAND = 0x01;
pub const GUJARATI_INDIA = 0x01;
pub const HAUSA_NIGERIA_LATIN = 0x01;
pub const HAWAIIAN_US = 0x01;
pub const HEBREW_ISRAEL = 0x01;
pub const HINDI_INDIA = 0x01;
pub const HUNGARIAN_HUNGARY = 0x01;
pub const ICELANDIC_ICELAND = 0x01;
pub const IGBO_NIGERIA = 0x01;
pub const INDONESIAN_INDONESIA = 0x01;
pub const INUKTITUT_CANADA = 0x01;
pub const INUKTITUT_CANADA_LATIN = 0x02;
pub const IRISH_IRELAND = 0x02;
pub const ITALIAN = 0x01;
pub const ITALIAN_SWISS = 0x02;
pub const JAPANESE_JAPAN = 0x01;
pub const KANNADA_INDIA = 0x01;
pub const KASHMIRI_SASIA = 0x02;
pub const KASHMIRI_INDIA = 0x02;
pub const KAZAK_KAZAKHSTAN = 0x01;
pub const KHMER_CAMBODIA = 0x01;
pub const KICHE_GUATEMALA = 0x01;
pub const KINYARWANDA_RWANDA = 0x01;
pub const KONKANI_INDIA = 0x01;
pub const KOREAN = 0x01;
pub const KYRGYZ_KYRGYZSTAN = 0x01;
pub const LAO_LAO = 0x01;
pub const LATVIAN_LATVIA = 0x01;
pub const LITHUANIAN = 0x01;
pub const LOWER_SORBIAN_GERMANY = 0x02;
pub const LUXEMBOURGISH_LUXEMBOURG = 0x01;
pub const MACEDONIAN_MACEDONIA = 0x01;
pub const MALAY_MALAYSIA = 0x01;
pub const MALAY_BRUNEI_DARUSSALAM = 0x02;
pub const MALAYALAM_INDIA = 0x01;
pub const MALTESE_MALTA = 0x01;
pub const MAORI_NEW_ZEALAND = 0x01;
pub const MAPUDUNGUN_CHILE = 0x01;
pub const MARATHI_INDIA = 0x01;
pub const MOHAWK_MOHAWK = 0x01;
pub const MONGOLIAN_CYRILLIC_MONGOLIA = 0x01;
pub const MONGOLIAN_PRC = 0x02;
pub const NEPALI_INDIA = 0x02;
pub const NEPALI_NEPAL = 0x01;
pub const NORWEGIAN_BOKMAL = 0x01;
pub const NORWEGIAN_NYNORSK = 0x02;
pub const OCCITAN_FRANCE = 0x01;
pub const ODIA_INDIA = 0x01;
pub const ORIYA_INDIA = 0x01;
pub const PASHTO_AFGHANISTAN = 0x01;
pub const PERSIAN_IRAN = 0x01;
pub const POLISH_POLAND = 0x01;
pub const PORTUGUESE = 0x02;
pub const PORTUGUESE_BRAZILIAN = 0x01;
pub const PULAR_SENEGAL = 0x02;
pub const PUNJABI_INDIA = 0x01;
pub const PUNJABI_PAKISTAN = 0x02;
pub const QUECHUA_BOLIVIA = 0x01;
pub const QUECHUA_ECUADOR = 0x02;
pub const QUECHUA_PERU = 0x03;
pub const ROMANIAN_ROMANIA = 0x01;
pub const ROMANSH_SWITZERLAND = 0x01;
pub const RUSSIAN_RUSSIA = 0x01;
pub const SAKHA_RUSSIA = 0x01;
pub const SAMI_NORTHERN_NORWAY = 0x01;
pub const SAMI_NORTHERN_SWEDEN = 0x02;
pub const SAMI_NORTHERN_FINLAND = 0x03;
pub const SAMI_LULE_NORWAY = 0x04;
pub const SAMI_LULE_SWEDEN = 0x05;
pub const SAMI_SOUTHERN_NORWAY = 0x06;
pub const SAMI_SOUTHERN_SWEDEN = 0x07;
pub const SAMI_SKOLT_FINLAND = 0x08;
pub const SAMI_INARI_FINLAND = 0x09;
pub const SANSKRIT_INDIA = 0x01;
pub const SCOTTISH_GAELIC = 0x01;
pub const SERBIAN_BOSNIA_HERZEGOVINA_LATIN = 0x06;
pub const SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC = 0x07;
pub const SERBIAN_MONTENEGRO_LATIN = 0x0b;
pub const SERBIAN_MONTENEGRO_CYRILLIC = 0x0c;
pub const SERBIAN_SERBIA_LATIN = 0x09;
pub const SERBIAN_SERBIA_CYRILLIC = 0x0a;
pub const SERBIAN_CROATIA = 0x01;
pub const SERBIAN_LATIN = 0x02;
pub const SERBIAN_CYRILLIC = 0x03;
pub const SINDHI_INDIA = 0x01;
pub const SINDHI_PAKISTAN = 0x02;
pub const SINDHI_AFGHANISTAN = 0x02;
pub const SINHALESE_SRI_LANKA = 0x01;
pub const SOTHO_NORTHERN_SOUTH_AFRICA = 0x01;
pub const SLOVAK_SLOVAKIA = 0x01;
pub const SLOVENIAN_SLOVENIA = 0x01;
pub const SPANISH = 0x01;
pub const SPANISH_MEXICAN = 0x02;
pub const SPANISH_MODERN = 0x03;
pub const SPANISH_GUATEMALA = 0x04;
pub const SPANISH_COSTA_RICA = 0x05;
pub const SPANISH_PANAMA = 0x06;
pub const SPANISH_DOMINICAN_REPUBLIC = 0x07;
pub const SPANISH_VENEZUELA = 0x08;
pub const SPANISH_COLOMBIA = 0x09;
pub const SPANISH_PERU = 0x0a;
pub const SPANISH_ARGENTINA = 0x0b;
pub const SPANISH_ECUADOR = 0x0c;
pub const SPANISH_CHILE = 0x0d;
pub const SPANISH_URUGUAY = 0x0e;
pub const SPANISH_PARAGUAY = 0x0f;
pub const SPANISH_BOLIVIA = 0x10;
pub const SPANISH_EL_SALVADOR = 0x11;
pub const SPANISH_HONDURAS = 0x12;
pub const SPANISH_NICARAGUA = 0x13;
pub const SPANISH_PUERTO_RICO = 0x14;
pub const SPANISH_US = 0x15;
pub const SWAHILI_KENYA = 0x01;
pub const SWEDISH = 0x01;
pub const SWEDISH_FINLAND = 0x02;
pub const SYRIAC_SYRIA = 0x01;
pub const TAJIK_TAJIKISTAN = 0x01;
pub const TAMAZIGHT_ALGERIA_LATIN = 0x02;
pub const TAMAZIGHT_MOROCCO_TIFINAGH = 0x04;
pub const TAMIL_INDIA = 0x01;
pub const TAMIL_SRI_LANKA = 0x02;
pub const TATAR_RUSSIA = 0x01;
pub const TELUGU_INDIA = 0x01;
pub const THAI_THAILAND = 0x01;
pub const TIBETAN_PRC = 0x01;
pub const TIGRIGNA_ERITREA = 0x02;
pub const TIGRINYA_ERITREA = 0x02;
pub const TIGRINYA_ETHIOPIA = 0x01;
pub const TSWANA_BOTSWANA = 0x02;
pub const TSWANA_SOUTH_AFRICA = 0x01;
pub const TURKISH_TURKEY = 0x01;
pub const TURKMEN_TURKMENISTAN = 0x01;
pub const UIGHUR_PRC = 0x01;
pub const UKRAINIAN_UKRAINE = 0x01;
pub const UPPER_SORBIAN_GERMANY = 0x01;
pub const URDU_PAKISTAN = 0x01;
pub const URDU_INDIA = 0x02;
pub const UZBEK_LATIN = 0x01;
pub const UZBEK_CYRILLIC = 0x02;
pub const VALENCIAN_VALENCIA = 0x02;
pub const VIETNAMESE_VIETNAM = 0x01;
pub const WELSH_UNITED_KINGDOM = 0x01;
pub const WOLOF_SENEGAL = 0x01;
pub const XHOSA_SOUTH_AFRICA = 0x01;
pub const YAKUT_RUSSIA = 0x01;
pub const YI_PRC = 0x01;
pub const YORUBA_NIGERIA = 0x01;
pub const ZULU_SOUTH_AFRICA = 0x01;
const std = @import("../../std.zig");
const builtin = @import("builtin");
const windows = std.os.windows;
const mem = std.mem;
const testing = std.testing;

/// Wrapper around RtlDosPathNameToNtPathName_U for use in comparing
/// the behavior of RtlDosPathNameToNtPathName_U with wToPrefixedFileW
/// Note: RtlDosPathNameToNtPathName_U is not used in the Zig implementation
//        because it allocates.
fn RtlDosPathNameToNtPathName_U(path: [:0]const u16) !windows.PathSpace {
    var out: windows.UNICODE_STRING = undefined;
    const rc = windows.ntdll.RtlDosPathNameToNtPathName_U(path, &out, null, null);
    if (rc != windows.TRUE) return error.BadPathName;
    defer windows.ntdll.RtlFreeUnicodeString(&out);

    var path_space: windows.PathSpace = undefined;
    const out_path = out.Buffer.?[0 .. out.Length / 2];
    @memcpy(path_space.data[0..out_path.len], out_path);
    path_space.len = out.Length / 2;
    path_space.data[path_space.len] = 0;

    return path_space;
}

/// Test that the Zig conversion matches the expected_path (for instances where
/// the Zig implementation intentionally diverges from what RtlDosPathNameToNtPathName_U does).
fn testToPrefixedFileNoOracle(comptime path: []const u8, comptime expected_path: []const u8) !void {
    const path_utf16 = std.unicode.utf8ToUtf16LeStringLiteral(path);
    const expected_path_utf16 = std.unicode.utf8ToUtf16LeStringLiteral(expected_path);
    const actual_path = try windows.wToPrefixedFileW(null, path_utf16);
    std.testing.expectEqualSlices(u16, expected_path_utf16, actual_path.span()) catch |e| {
        std.debug.print("got '{s}', expected '{s}'\n", .{ std.unicode.fmtUtf16Le(actual_path.span()), std.unicode.fmtUtf16Le(expected_path_utf16) });
        return e;
    };
}

/// Test that the Zig conversion matches the expected_path and that the
/// expected_path matches the conversion that RtlDosPathNameToNtPathName_U does.
fn testToPrefixedFileWithOracle(comptime path: []const u8, comptime expected_path: []const u8) !void {
    try testToPrefixedFileNoOracle(path, expected_path);
    try testToPrefixedFileOnlyOracle(path);
}

/// Test that the Zig conversion matches the conversion that RtlDosPathNameToNtPathName_U does.
fn testToPrefixedFileOnlyOracle(comptime path: []const u8) !void {
    const path_utf16 = std.unicode.utf8ToUtf16LeStringLiteral(path);
    const zig_result = try windows.wToPrefixedFileW(null, path_utf16);
    const win32_api_result = try RtlDosPathNameToNtPathName_U(path_utf16);
    std.testing.expectEqualSlices(u16, win32_api_result.span(), zig_result.span()) catch |e| {
        std.debug.print("got '{s}', expected '{s}'\n", .{ std.unicode.fmtUtf16Le(zig_result.span()), std.unicode.fmtUtf16Le(win32_api_result.span()) });
        return e;
    };
}

test "toPrefixedFileW" {
    if (builtin.os.tag != .windows)
        return;

    // Most test cases come from https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
    // Note that these tests do not actually touch the filesystem or care about whether or not
    // any of the paths actually exist or are otherwise valid.

    // Drive Absolute
    try testToPrefixedFileWithOracle("X:\\ABC\\DEF", "\\??\\X:\\ABC\\DEF");
    try testToPrefixedFileWithOracle("X:\\", "\\??\\X:\\");
    try testToPrefixedFileWithOracle("X:\\ABC\\", "\\??\\X:\\ABC\\");
    // Trailing . and space characters are stripped
    try testToPrefixedFileWithOracle("X:\\ABC\\DEF. .", "\\??\\X:\\ABC\\DEF");
    try testToPrefixedFileWithOracle("X:/ABC/DEF", "\\??\\X:\\ABC\\DEF");
    try testToPrefixedFileWithOracle("X:\\ABC\\..\\XYZ", "\\??\\X:\\XYZ");
    try testToPrefixedFileWithOracle("X:\\ABC\\..\\..\\..", "\\??\\X:\\");
    // Drive letter casing is unchanged
    try testToPrefixedFileWithOracle("x:\\", "\\??\\x:\\");

    // Drive Relative
    // These tests depend on the CWD of the specified drive letter which can vary,
    // so instead we just test that the Zig implementation matches the result of
    // RtlDosPathNameToNtPathName_U.
    // TODO: Setting the =X: environment variable didn't seem to affect
    //       RtlDosPathNameToNtPathName_U, not sure why that is but getting that
    //       to work could be an avenue to making these cases environment-independent.
    // All -> are examples of the result if the X drive's cwd was X:\ABC
    try testToPrefixedFileOnlyOracle("X:DEF\\GHI"); // -> \??\X:\ABC\DEF\GHI
    try testToPrefixedFileOnlyOracle("X:"); // -> \??\X:\ABC
    try testToPrefixedFileOnlyOracle("X:DEF. ."); // -> \??\X:\ABC\DEF
    try testToPrefixedFileOnlyOracle("X:ABC\\..\\XYZ"); // -> \??\X:\ABC\XYZ
    try testToPrefixedFileOnlyOracle("X:ABC\\..\\..\\.."); // -> \??\X:\
    try testToPrefixedFileOnlyOracle("x:"); // -> \??\X:\ABC

    // Rooted
    // These tests depend on the drive letter of the CWD which can vary, so
    // instead we just test that the Zig implementation matches the result of
    // RtlDosPathNameToNtPathName_U.
    // TODO: Getting the CWD path, getting the drive letter from it, and using it to
    //       construct the expected NT paths could be an avenue to making these cases
    //       environment-independent and therefore able to use testToPrefixedFileWithOracle.
    // All -> are examples of the result if the CWD's drive letter was X
    try testToPrefixedFileOnlyOracle("\\ABC\\DEF"); // -> \??\X:\ABC\DEF
    try testToPrefixedFileOnlyOracle("\\"); // -> \??\X:\
    try testToPrefixedFileOnlyOracle("\\ABC\\DEF. ."); // -> \??\X:\ABC\DEF
    try testToPrefixedFileOnlyOracle("/ABC/DEF"); // -> \??\X:\ABC\DEF
    try testToPrefixedFileOnlyOracle("\\ABC\\..\\XYZ"); // -> \??\X:\XYZ
    try testToPrefixedFileOnlyOracle("\\ABC\\..\\..\\.."); // -> \??\X:\

    // Relative
    // These cases differ in functionality to RtlDosPathNameToNtPathName_U.
    // Relative paths remain relative if they don't have enough .. components
    // to error with TooManyParentDirs
    try testToPrefixedFileNoOracle("ABC\\DEF", "ABC\\DEF");
    // TODO: enable this if trailing . and spaces are stripped from relative paths
    //try testToPrefixedFileNoOracle("ABC\\DEF. .", "ABC\\DEF");
    try testToPrefixedFileNoOracle("ABC/DEF", "ABC\\DEF");
    try testToPrefixedFileNoOracle("./ABC/.././DEF", "DEF");
    // TooManyParentDirs, so resolved relative to the CWD
    // All -> are examples of the result if the CWD was X:\ABC\DEF
    try testToPrefixedFileOnlyOracle("..\\GHI"); // -> \??\X:\ABC\GHI
    try testToPrefixedFileOnlyOracle("GHI\\..\\..\\.."); // -> \??\X:\

    // UNC Absolute
    try testToPrefixedFileWithOracle("\\\\server\\share\\ABC\\DEF", "\\??\\UNC\\server\\share\\ABC\\DEF");
    try testToPrefixedFileWithOracle("\\\\server", "\\??\\UNC\\server");
    try testToPrefixedFileWithOracle("\\\\server\\share", "\\??\\UNC\\server\\share");
    try testToPrefixedFileWithOracle("\\\\server\\share\\ABC. .", "\\??\\UNC\\server\\share\\ABC");
    try testToPrefixedFileWithOracle("//server/share/ABC/DEF", "\\??\\UNC\\server\\share\\ABC\\DEF");
    try testToPrefixedFileWithOracle("\\\\server\\share\\ABC\\..\\XYZ", "\\??\\UNC\\server\\share\\XYZ");
    try testToPrefixedFileWithOracle("\\\\server\\share\\ABC\\..\\..\\..", "\\??\\UNC\\server\\share");

    // Local Device
    try testToPrefixedFileWithOracle("\\\\.\\COM20", "\\??\\COM20");
    try testToPrefixedFileWithOracle("\\\\.\\pipe\\mypipe", "\\??\\pipe\\mypipe");
    try testToPrefixedFileWithOracle("\\\\.\\X:\\ABC\\DEF. .", "\\??\\X:\\ABC\\DEF");
    try testToPrefixedFileWithOracle("\\\\.\\X:/ABC/DEF", "\\??\\X:\\ABC\\DEF");
    try testToPrefixedFileWithOracle("\\\\.\\X:\\ABC\\..\\XYZ", "\\??\\X:\\XYZ");
    // Can replace the first component of the path (contrary to drive absolute and UNC absolute paths)
    try testToPrefixedFileWithOracle("\\\\.\\X:\\ABC\\..\\..\\C:\\", "\\??\\C:\\");
    try testToPrefixedFileWithOracle("\\\\.\\pipe\\mypipe\\..\\notmine", "\\??\\pipe\\notmine");

    // Special-case device names
    // TODO: Enable once these are supported
    //       more cases to test here: https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
    //try testToPrefixedFileWithOracle("COM1", "\\??\\COM1");
    // Sometimes the special-cased device names are not respected
    try testToPrefixedFileWithOracle("\\\\.\\X:\\COM1", "\\??\\X:\\COM1");
    try testToPrefixedFileWithOracle("\\\\abc\\xyz\\COM1", "\\??\\UNC\\abc\\xyz\\COM1");

    // Verbatim
    // Left untouched except \\?\ is replaced by \??\
    try testToPrefixedFileWithOracle("\\\\?\\X:", "\\??\\X:");
    try testToPrefixedFileWithOracle("\\\\?\\X:\\COM1", "\\??\\X:\\COM1");
    try testToPrefixedFileWithOracle("\\\\?\\X:/ABC/DEF. .", "\\??\\X:/ABC/DEF. .");
    try testToPrefixedFileWithOracle("\\\\?\\X:\\ABC\\..\\..\\..", "\\??\\X:\\ABC\\..\\..\\..");
    // NT Namespace
    // Fully unmodified
    try testToPrefixedFileWithOracle("\\??\\X:", "\\??\\X:");
    try testToPrefixedFileWithOracle("\\??\\X:\\COM1", "\\??\\X:\\COM1");
    try testToPrefixedFileWithOracle("\\??\\X:/ABC/DEF. .", "\\??\\X:/ABC/DEF. .");
    try testToPrefixedFileWithOracle("\\??\\X:\\ABC\\..\\..\\..", "\\??\\X:\\ABC\\..\\..\\..");

    // 'Fake' Verbatim
    // If the prefix looks like the verbatim prefix but not all path separators in the
    // prefix are backslashes, then it gets canonicalized and the prefix is dropped in favor
    // of the NT prefix.
    try testToPrefixedFileWithOracle("//?/C:/ABC", "\\??\\C:\\ABC");
    // 'Fake' NT
    // If the prefix looks like the NT prefix but not all path separators in the prefix
    // are backslashes, then it gets canonicalized and the /??/ is not dropped but
    // rather treated as part of the path. In other words, the path is treated
    // as a rooted path, so the final path is resolved relative to the CWD's
    // drive letter.
    // The -> shows an example of the result if the CWD's drive letter was X
    try testToPrefixedFileOnlyOracle("/??/C:/ABC"); // -> \??\X:\??\C:\ABC

    // Root Local Device
    // \\. and \\? always get converted to \??\
    try testToPrefixedFileWithOracle("\\\\.", "\\??\\");
    try testToPrefixedFileWithOracle("\\\\?", "\\??\\");
    try testToPrefixedFileWithOracle("//?", "\\??\\");
    try testToPrefixedFileWithOracle("//.", "\\??\\");
}

fn testRemoveDotDirs(str: []const u8, expected: []const u8) !void {
    const mutable = try testing.allocator.dupe(u8, str);
    defer testing.allocator.free(mutable);
    const actual = mutable[0..try windows.removeDotDirsSanitized(u8, mutable)];
    try testing.expect(mem.eql(u8, actual, expected));
}
fn testRemoveDotDirsError(err: anyerror, str: []const u8) !void {
    const mutable = try testing.allocator.dupe(u8, str);
    defer testing.allocator.free(mutable);
    try testing.expectError(err, windows.removeDotDirsSanitized(u8, mutable));
}
test "removeDotDirs" {
    try testRemoveDotDirs("", "");
    try testRemoveDotDirs(".", "");
    try testRemoveDotDirs(".\\", "");
    try testRemoveDotDirs(".\\.", "");
    try testRemoveDotDirs(".\\.\\", "");
    try testRemoveDotDirs(".\\.\\.", "");

    try testRemoveDotDirs("a", "a");
    try testRemoveDotDirs("a\\", "a\\");
    try testRemoveDotDirs("a\\b", "a\\b");
    try testRemoveDotDirs("a\\.", "a\\");
    try testRemoveDotDirs("a\\b\\.", "a\\b\\");
    try testRemoveDotDirs("a\\.\\b", "a\\b");

    try testRemoveDotDirs(".a", ".a");
    try testRemoveDotDirs(".a\\", ".a\\");
    try testRemoveDotDirs(".a\\.b", ".a\\.b");
    try testRemoveDotDirs(".a\\.", ".a\\");
    try testRemoveDotDirs(".a\\.\\.", ".a\\");
    try testRemoveDotDirs(".a\\.\\.\\.b", ".a\\.b");
    try testRemoveDotDirs(".a\\.\\.\\.b\\", ".a\\.b\\");

    try testRemoveDotDirsError(error.TooManyParentDirs, "..");
    try testRemoveDotDirsError(error.TooManyParentDirs, "..\\");
    try testRemoveDotDirsError(error.TooManyParentDirs, ".\\..\\");
    try testRemoveDotDirsError(error.TooManyParentDirs, ".\\.\\..\\");

    try testRemoveDotDirs("a\\..", "");
    try testRemoveDotDirs("a\\..\\", "");
    try testRemoveDotDirs("a\\..\\.", "");
    try testRemoveDotDirs("a\\..\\.\\", "");
    try testRemoveDotDirs("a\\..\\.\\.", "");
    try testRemoveDotDirsError(error.TooManyParentDirs, "a\\..\\.\\.\\..");

    try testRemoveDotDirs("a\\..\\.\\.\\b", "b");
    try testRemoveDotDirs("a\\..\\.\\.\\b\\", "b\\");
    try testRemoveDotDirs("a\\..\\.\\.\\b\\.", "b\\");
    try testRemoveDotDirs("a\\..\\.\\.\\b\\.\\", "b\\");
    try testRemoveDotDirs("a\\..\\.\\.\\b\\.\\..", "");
    try testRemoveDotDirs("a\\..\\.\\.\\b\\.\\..\\", "");
    try testRemoveDotDirs("a\\..\\.\\.\\b\\.\\..\\.", "");
    try testRemoveDotDirsError(error.TooManyParentDirs, "a\\..\\.\\.\\b\\.\\..\\.\\..");

    try testRemoveDotDirs("a\\b\\..\\", "a\\");
    try testRemoveDotDirs("a\\b\\..\\c", "a\\c");
}

test "loadWinsockExtensionFunction" {
    _ = try windows.WSAStartup(2, 2);
    defer windows.WSACleanup() catch unreachable;

    const LPFN_CONNECTEX = *const fn (
        Socket: windows.ws2_32.SOCKET,
        SockAddr: *const windows.ws2_32.sockaddr,
        SockLen: std.posix.socklen_t,
        SendBuf: ?*const anyopaque,
        SendBufLen: windows.DWORD,
        BytesSent: *windows.DWORD,
        Overlapped: *windows.OVERLAPPED,
    ) callconv(.winapi) windows.BOOL;

    _ = windows.loadWinsockExtensionFunction(
        LPFN_CONNECTEX,
        try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0),
        windows.ws2_32.WSAID_CONNECTEX,
    ) catch |err| switch (err) {
        error.OperationNotSupported => unreachable,
        error.ShortRead => unreachable,
        else => |e| return e,
    };
}
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;

export var _tls_index: u32 = std.os.windows.TLS_OUT_OF_INDEXES;
export var _tls_start: ?*anyopaque linksection(".tls") = null;
export var _tls_end: ?*anyopaque linksection(".tls$ZZZ") = null;
export var __xl_a: windows.PIMAGE_TLS_CALLBACK linksection(".CRT$XLA") = null;
export var __xl_z: windows.PIMAGE_TLS_CALLBACK linksection(".CRT$XLZ") = null;

comptime {
    if (builtin.cpu.arch == .x86 and !builtin.abi.isGnu() and builtin.zig_backend != .stage2_c) {
        // The __tls_array is the offset of the ThreadLocalStoragePointer field
        // in the TEB block whose base address held in the %fs segment.
        asm (
            \\ .global __tls_array
            \\ __tls_array = 0x2C
        );
    }
}

// TODO this is how I would like it to be expressed
//export const _tls_used linksection(".rdata$T") = std.os.windows.IMAGE_TLS_DIRECTORY {
//    .StartAddressOfRawData = @intFromPtr(&_tls_start),
//    .EndAddressOfRawData = @intFromPtr(&_tls_end),
//    .AddressOfIndex = @intFromPtr(&_tls_index),
//    .AddressOfCallBacks = @intFromPtr(__xl_a),
//    .SizeOfZeroFill = 0,
//    .Characteristics = 0,
//};
// This is the workaround because we can't do @intFromPtr at comptime like that.
pub const IMAGE_TLS_DIRECTORY = extern struct {
    StartAddressOfRawData: *?*anyopaque,
    EndAddressOfRawData: *?*anyopaque,
    AddressOfIndex: *u32,
    AddressOfCallBacks: [*:null]windows.PIMAGE_TLS_CALLBACK,
    SizeOfZeroFill: u32,
    Characteristics: u32,
};
export const _tls_used linksection(".rdata$T") = IMAGE_TLS_DIRECTORY{
    .StartAddressOfRawData = &_tls_start,
    .EndAddressOfRawData = &_tls_end,
    .AddressOfIndex = &_tls_index,
    // __xl_a is just a global variable containing a null pointer; the actual callbacks sit in
    // between __xl_a and __xl_z. So we need to skip over __xl_a here. If there are no callbacks,
    // this just means we point to __xl_z (the null terminator).
    .AddressOfCallBacks = @as([*:null]windows.PIMAGE_TLS_CALLBACK, @ptrCast(&__xl_a)) + 1,
    .SizeOfZeroFill = 0,
    .Characteristics = 0,
};
/// Codes are from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
pub const Win32Error = enum(u16) {
    /// The operation completed successfully.
    SUCCESS = 0,
    /// Incorrect function.
    INVALID_FUNCTION = 1,
    /// The system cannot find the file specified.
    FILE_NOT_FOUND = 2,
    /// The system cannot find the path specified.
    PATH_NOT_FOUND = 3,
    /// The system cannot open the file.
    TOO_MANY_OPEN_FILES = 4,
    /// Access is denied.
    ACCESS_DENIED = 5,
    /// The handle is invalid.
    INVALID_HANDLE = 6,
    /// The storage control blocks were destroyed.
    ARENA_TRASHED = 7,
    /// Not enough storage is available to process this command.
    NOT_ENOUGH_MEMORY = 8,
    /// The storage control block address is invalid.
    INVALID_BLOCK = 9,
    /// The environment is incorrect.
    BAD_ENVIRONMENT = 10,
    /// An attempt was made to load a program with an incorrect format.
    BAD_FORMAT = 11,
    /// The access code is invalid.
    INVALID_ACCESS = 12,
    /// The data is invalid.
    INVALID_DATA = 13,
    /// Not enough storage is available to complete this operation.
    OUTOFMEMORY = 14,
    /// The system cannot find the drive specified.
    INVALID_DRIVE = 15,
    /// The directory cannot be removed.
    CURRENT_DIRECTORY = 16,
    /// The system cannot move the file to a different disk drive.
    NOT_SAME_DEVICE = 17,
    /// There are no more files.
    NO_MORE_FILES = 18,
    /// The media is write protected.
    WRITE_PROTECT = 19,
    /// The system cannot find the device specified.
    BAD_UNIT = 20,
    /// The device is not ready.
    NOT_READY = 21,
    /// The device does not recognize the command.
    BAD_COMMAND = 22,
    /// Data error (cyclic redundancy check).
    CRC = 23,
    /// The program issued a command but the command length is incorrect.
    BAD_LENGTH = 24,
    /// The drive cannot locate a specific area or track on the disk.
    SEEK = 25,
    /// The specified disk or diskette cannot be accessed.
    NOT_DOS_DISK = 26,
    /// The drive cannot find the sector requested.
    SECTOR_NOT_FOUND = 27,
    /// The printer is out of paper.
    OUT_OF_PAPER = 28,
    /// The system cannot write to the specified device.
    WRITE_FAULT = 29,
    /// The system cannot read from the specified device.
    READ_FAULT = 30,
    /// A device attached to the system is not functioning.
    GEN_FAILURE = 31,
    /// The process cannot access the file because it is being used by another process.
    SHARING_VIOLATION = 32,
    /// The process cannot access the file because another process has locked a portion of the file.
    LOCK_VIOLATION = 33,
    /// The wrong diskette is in the drive.
    /// Insert %2 (Volume Serial Number: %3) into drive %1.
    WRONG_DISK = 34,
    /// Too many files opened for sharing.
    SHARING_BUFFER_EXCEEDED = 36,
    /// Reached the end of the file.
    HANDLE_EOF = 38,
    /// The disk is full.
    HANDLE_DISK_FULL = 39,
    /// The request is not supported.
    NOT_SUPPORTED = 50,
    /// Windows cannot find the network path.
    /// Verify that the network path is correct and the destination computer is not busy or turned off.
    /// If Windows still cannot find the network path, contact your network administrator.
    REM_NOT_LIST = 51,
    /// You were not connected because a duplicate name exists on the network.
    /// If joining a domain, go to System in Control Panel to change the computer name and try again.
    /// If joining a workgroup, choose another workgroup name.
    DUP_NAME = 52,
    /// The network path was not found.
    BAD_NETPATH = 53,
    /// The network is busy.
    NETWORK_BUSY = 54,
    /// The specified network resource or device is no longer available.
    DEV_NOT_EXIST = 55,
    /// The network BIOS command limit has been reached.
    TOO_MANY_CMDS = 56,
    /// A network adapter hardware error occurred.
    ADAP_HDW_ERR = 57,
    /// The specified server cannot perform the requested operation.
    BAD_NET_RESP = 58,
    /// An unexpected network error occurred.
    UNEXP_NET_ERR = 59,
    /// The remote adapter is not compatible.
    BAD_REM_ADAP = 60,
    /// The printer queue is full.
    PRINTQ_FULL = 61,
    /// Space to store the file waiting to be printed is not available on the server.
    NO_SPOOL_SPACE = 62,
    /// Your file waiting to be printed was deleted.
    PRINT_CANCELLED = 63,
    /// The specified network name is no longer available.
    NETNAME_DELETED = 64,
    /// Network access is denied.
    NETWORK_ACCESS_DENIED = 65,
    /// The network resource type is not correct.
    BAD_DEV_TYPE = 66,
    /// The network name cannot be found.
    BAD_NET_NAME = 67,
    /// The name limit for the local computer network adapter card was exceeded.
    TOO_MANY_NAMES = 68,
    /// The network BIOS session limit was exceeded.
    TOO_MANY_SESS = 69,
    /// The remote server has been paused or is in the process of being started.
    SHARING_PAUSED = 70,
    /// No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.
    REQ_NOT_ACCEP = 71,
    /// The specified printer or disk device has been paused.
    REDIR_PAUSED = 72,
    /// The file exists.
    FILE_EXISTS = 80,
    /// The directory or file cannot be created.
    CANNOT_MAKE = 82,
    /// Fail on INT 24.
    FAIL_I24 = 83,
    /// Storage to process this request is not available.
    OUT_OF_STRUCTURES = 84,
    /// The local device name is already in use.
    ALREADY_ASSIGNED = 85,
    /// The specified network password is not correct.
    INVALID_PASSWORD = 86,
    /// The parameter is incorrect.
    INVALID_PARAMETER = 87,
    /// A write fault occurred on the network.
    NET_WRITE_FAULT = 88,
    /// The system cannot start another process at this time.
    NO_PROC_SLOTS = 89,
    /// Cannot create another system semaphore.
    TOO_MANY_SEMAPHORES = 100,
    /// The exclusive semaphore is owned by another process.
    EXCL_SEM_ALREADY_OWNED = 101,
    /// The semaphore is set and cannot be closed.
    SEM_IS_SET = 102,
    /// The semaphore cannot be set again.
    TOO_MANY_SEM_REQUESTS = 103,
    /// Cannot request exclusive semaphores at interrupt time.
    INVALID_AT_INTERRUPT_TIME = 104,
    /// The previous ownership of this semaphore has ended.
    SEM_OWNER_DIED = 105,
    /// Insert the diskette for drive %1.
    SEM_USER_LIMIT = 106,
    /// The program stopped because an alternate diskette was not inserted.
    DISK_CHANGE = 107,
    /// The disk is in use or locked by another process.
    DRIVE_LOCKED = 108,
    /// The pipe has been ended.
    BROKEN_PIPE = 109,
    /// The system cannot open the device or file specified.
    OPEN_FAILED = 110,
    /// The file name is too long.
    BUFFER_OVERFLOW = 111,
    /// There is not enough space on the disk.
    DISK_FULL = 112,
    /// No more internal file identifiers available.
    NO_MORE_SEARCH_HANDLES = 113,
    /// The target internal file identifier is incorrect.
    INVALID_TARGET_HANDLE = 114,
    /// The IOCTL call made by the application program is not correct.
    INVALID_CATEGORY = 117,
    /// The verify-on-write switch parameter value is not correct.
    INVALID_VERIFY_SWITCH = 118,
    /// The system does not support the command requested.
    BAD_DRIVER_LEVEL = 119,
    /// This function is not supported on this system.
    CALL_NOT_IMPLEMENTED = 120,
    /// The semaphore timeout period has expired.
    SEM_TIMEOUT = 121,
    /// The data area passed to a system call is too small.
    INSUFFICIENT_BUFFER = 122,
    /// The filename, directory name, or volume label syntax is incorrect.
    INVALID_NAME = 123,
    /// The system call level is not correct.
    INVALID_LEVEL = 124,
    /// The disk has no volume label.
    NO_VOLUME_LABEL = 125,
    /// The specified module could not be found.
    MOD_NOT_FOUND = 126,
    /// The specified procedure could not be found.
    PROC_NOT_FOUND = 127,
    /// There are no child processes to wait for.
    WAIT_NO_CHILDREN = 128,
    /// The %1 application cannot be run in Win32 mode.
    CHILD_NOT_COMPLETE = 129,
    /// Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O.
    DIRECT_ACCESS_HANDLE = 130,
    /// An attempt was made to move the file pointer before the beginning of the file.
    NEGATIVE_SEEK = 131,
    /// The file pointer cannot be set on the specified device or file.
    SEEK_ON_DEVICE = 132,
    /// A JOIN or SUBST command cannot be used for a drive that contains previously joined drives.
    IS_JOIN_TARGET = 133,
    /// An attempt was made to use a JOIN or SUBST command on a drive that has already been joined.
    IS_JOINED = 134,
    /// An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted.
    IS_SUBSTED = 135,
    /// The system tried to delete the JOIN of a drive that is not joined.
    NOT_JOINED = 136,
    /// The system tried to delete the substitution of a drive that is not substituted.
    NOT_SUBSTED = 137,
    /// The system tried to join a drive to a directory on a joined drive.
    JOIN_TO_JOIN = 138,
    /// The system tried to substitute a drive to a directory on a substituted drive.
    SUBST_TO_SUBST = 139,
    /// The system tried to join a drive to a directory on a substituted drive.
    JOIN_TO_SUBST = 140,
    /// The system tried to SUBST a drive to a directory on a joined drive.
    SUBST_TO_JOIN = 141,
    /// The system cannot perform a JOIN or SUBST at this time.
    BUSY_DRIVE = 142,
    /// The system cannot join or substitute a drive to or for a directory on the same drive.
    SAME_DRIVE = 143,
    /// The directory is not a subdirectory of the root directory.
    DIR_NOT_ROOT = 144,
    /// The directory is not empty.
    DIR_NOT_EMPTY = 145,
    /// The path specified is being used in a substitute.
    IS_SUBST_PATH = 146,
    /// Not enough resources are available to process this command.
    IS_JOIN_PATH = 147,
    /// The path specified cannot be used at this time.
    PATH_BUSY = 148,
    /// An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute.
    IS_SUBST_TARGET = 149,
    /// System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed.
    SYSTEM_TRACE = 150,
    /// The number of specified semaphore events for DosMuxSemWait is not correct.
    INVALID_EVENT_COUNT = 151,
    /// DosMuxSemWait did not execute; too many semaphores are already set.
    TOO_MANY_MUXWAITERS = 152,
    /// The DosMuxSemWait list is not correct.
    INVALID_LIST_FORMAT = 153,
    /// The volume label you entered exceeds the label character limit of the target file system.
    LABEL_TOO_LONG = 154,
    /// Cannot create another thread.
    TOO_MANY_TCBS = 155,
    /// The recipient process has refused the signal.
    SIGNAL_REFUSED = 156,
    /// The segment is already discarded and cannot be locked.
    DISCARDED = 157,
    /// The segment is already unlocked.
    NOT_LOCKED = 158,
    /// The address for the thread ID is not correct.
    BAD_THREADID_ADDR = 159,
    /// One or more arguments are not correct.
    BAD_ARGUMENTS = 160,
    /// The specified path is invalid.
    BAD_PATHNAME = 161,
    /// A signal is already pending.
    SIGNAL_PENDING = 162,
    /// No more threads can be created in the system.
    MAX_THRDS_REACHED = 164,
    /// Unable to lock a region of a file.
    LOCK_FAILED = 167,
    /// The requested resource is in use.
    BUSY = 170,
    /// Device's command support detection is in progress.
    DEVICE_SUPPORT_IN_PROGRESS = 171,
    /// A lock request was not outstanding for the supplied cancel region.
    CANCEL_VIOLATION = 173,
    /// The file system does not support atomic changes to the lock type.
    ATOMIC_LOCKS_NOT_SUPPORTED = 174,
    /// The system detected a segment number that was not correct.
    INVALID_SEGMENT_NUMBER = 180,
    /// The operating system cannot run %1.
    INVALID_ORDINAL = 182,
    /// Cannot create a file when that file already exists.
    ALREADY_EXISTS = 183,
    /// The flag passed is not correct.
    INVALID_FLAG_NUMBER = 186,
    /// The specified system semaphore name was not found.
    SEM_NOT_FOUND = 187,
    /// The operating system cannot run %1.
    INVALID_STARTING_CODESEG = 188,
    /// The operating system cannot run %1.
    INVALID_STACKSEG = 189,
    /// The operating system cannot run %1.
    INVALID_MODULETYPE = 190,
    /// Cannot run %1 in Win32 mode.
    INVALID_EXE_SIGNATURE = 191,
    /// The operating system cannot run %1.
    EXE_MARKED_INVALID = 192,
    /// %1 is not a valid Win32 application.
    BAD_EXE_FORMAT = 193,
    /// The operating system cannot run %1.
    ITERATED_DATA_EXCEEDS_64k = 194,
    /// The operating system cannot run %1.
    INVALID_MINALLOCSIZE = 195,
    /// The operating system cannot run this application program.
    DYNLINK_FROM_INVALID_RING = 196,
    /// The operating system is not presently configured to run this application.
    IOPL_NOT_ENABLED = 197,
    /// The operating system cannot run %1.
    INVALID_SEGDPL = 198,
    /// The operating system cannot run this application program.
    AUTODATASEG_EXCEEDS_64k = 199,
    /// The code segment cannot be greater than or equal to 64K.
    RING2SEG_MUST_BE_MOVABLE = 200,
    /// The operating system cannot run %1.
    RELOC_CHAIN_XEEDS_SEGLIM = 201,
    /// The operating system cannot run %1.
    INFLOOP_IN_RELOC_CHAIN = 202,
    /// The system could not find the environment option that was entered.
    ENVVAR_NOT_FOUND = 203,
    /// No process in the command subtree has a signal handler.
    NO_SIGNAL_SENT = 205,
    /// The filename or extension is too long.
    FILENAME_EXCED_RANGE = 206,
    /// The ring 2 stack is in use.
    RING2_STACK_IN_USE = 207,
    /// The global filename characters, * or ?, are entered incorrectly or too many global filename characters are specified.
    META_EXPANSION_TOO_LONG = 208,
    /// The signal being posted is not correct.
    INVALID_SIGNAL_NUMBER = 209,
    /// The signal handler cannot be set.
    THREAD_1_INACTIVE = 210,
    /// The segment is locked and cannot be reallocated.
    LOCKED = 212,
    /// Too many dynamic-link modules are attached to this program or dynamic-link module.
    TOO_MANY_MODULES = 214,
    /// Cannot nest calls to LoadModule.
    NESTING_NOT_ALLOWED = 215,
    /// This version of %1 is not compatible with the version of Windows you're running.
    /// Check your computer's system information and then contact the software publisher.
    EXE_MACHINE_TYPE_MISMATCH = 216,
    /// The image file %1 is signed, unable to modify.
    EXE_CANNOT_MODIFY_SIGNED_BINARY = 217,
    /// The image file %1 is strong signed, unable to modify.
    EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY = 218,
    /// This file is checked out or locked for editing by another user.
    FILE_CHECKED_OUT = 220,
    /// The file must be checked out before saving changes.
    CHECKOUT_REQUIRED = 221,
    /// The file type being saved or retrieved has been blocked.
    BAD_FILE_TYPE = 222,
    /// The file size exceeds the limit allowed and cannot be saved.
    FILE_TOO_LARGE = 223,
    /// Access Denied. Before opening files in this location, you must first add the web site to your trusted sites list, browse to the web site, and select the option to login automatically.
    FORMS_AUTH_REQUIRED = 224,
    /// Operation did not complete successfully because the file contains a virus or potentially unwanted software.
    VIRUS_INFECTED = 225,
    /// This file contains a virus or potentially unwanted software and cannot be opened.
    /// Due to the nature of this virus or potentially unwanted software, the file has been removed from this location.
    VIRUS_DELETED = 226,
    /// The pipe is local.
    PIPE_LOCAL = 229,
    /// The pipe state is invalid.
    BAD_PIPE = 230,
    /// All pipe instances are busy.
    PIPE_BUSY = 231,
    /// The pipe is being closed.
    NO_DATA = 232,
    /// No process is on the other end of the pipe.
    PIPE_NOT_CONNECTED = 233,
    /// More data is available.
    MORE_DATA = 234,
    /// The session was canceled.
    VC_DISCONNECTED = 240,
    /// The specified extended attribute name was invalid.
    INVALID_EA_NAME = 254,
    /// The extended attributes are inconsistent.
    EA_LIST_INCONSISTENT = 255,
    /// The wait operation timed out.
    WAIT_TIMEOUT = 258,
    /// No more data is available.
    NO_MORE_ITEMS = 259,
    /// The copy functions cannot be used.
    CANNOT_COPY = 266,
    /// The directory name is invalid.
    DIRECTORY = 267,
    /// The extended attributes did not fit in the buffer.
    EAS_DIDNT_FIT = 275,
    /// The extended attribute file on the mounted file system is corrupt.
    EA_FILE_CORRUPT = 276,
    /// The extended attribute table file is full.
    EA_TABLE_FULL = 277,
    /// The specified extended attribute handle is invalid.
    INVALID_EA_HANDLE = 278,
    /// The mounted file system does not support extended attributes.
    EAS_NOT_SUPPORTED = 282,
    /// Attempt to release mutex not owned by caller.
    NOT_OWNER = 288,
    /// Too many posts were made to a semaphore.
    TOO_MANY_POSTS = 298,
    /// Only part of a ReadProcessMemory or WriteProcessMemory request was completed.
    PARTIAL_COPY = 299,
    /// The oplock request is denied.
    OPLOCK_NOT_GRANTED = 300,
    /// An invalid oplock acknowledgment was received by the system.
    INVALID_OPLOCK_PROTOCOL = 301,
    /// The volume is too fragmented to complete this operation.
    DISK_TOO_FRAGMENTED = 302,
    /// The file cannot be opened because it is in the process of being deleted.
    DELETE_PENDING = 303,
    /// Short name settings may not be changed on this volume due to the global registry setting.
    INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING = 304,
    /// Short names are not enabled on this volume.
    SHORT_NAMES_NOT_ENABLED_ON_VOLUME = 305,
    /// The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume.
    SECURITY_STREAM_IS_INCONSISTENT = 306,
    /// A requested file lock operation cannot be processed due to an invalid byte range.
    INVALID_LOCK_RANGE = 307,
    /// The subsystem needed to support the image type is not present.
    IMAGE_SUBSYSTEM_NOT_PRESENT = 308,
    /// The specified file already has a notification GUID associated with it.
    NOTIFICATION_GUID_ALREADY_DEFINED = 309,
    /// An invalid exception handler routine has been detected.
    INVALID_EXCEPTION_HANDLER = 310,
    /// Duplicate privileges were specified for the token.
    DUPLICATE_PRIVILEGES = 311,
    /// No ranges for the specified operation were able to be processed.
    NO_RANGES_PROCESSED = 312,
    /// Operation is not allowed on a file system internal file.
    NOT_ALLOWED_ON_SYSTEM_FILE = 313,
    /// The physical resources of this disk have been exhausted.
    DISK_RESOURCES_EXHAUSTED = 314,
    /// The token representing the data is invalid.
    INVALID_TOKEN = 315,
    /// The device does not support the command feature.
    DEVICE_FEATURE_NOT_SUPPORTED = 316,
    /// The system cannot find message text for message number 0x%1 in the message file for %2.
    MR_MID_NOT_FOUND = 317,
    /// The scope specified was not found.
    SCOPE_NOT_FOUND = 318,
    /// The Central Access Policy specified is not defined on the target machine.
    UNDEFINED_SCOPE = 319,
    /// The Central Access Policy obtained from Active Directory is invalid.
    INVALID_CAP = 320,
    /// The device is unreachable.
    DEVICE_UNREACHABLE = 321,
    /// The target device has insufficient resources to complete the operation.
    DEVICE_NO_RESOURCES = 322,
    /// A data integrity checksum error occurred. Data in the file stream is corrupt.
    DATA_CHECKSUM_ERROR = 323,
    /// An attempt was made to modify both a KERNEL and normal Extended Attribute (EA) in the same operation.
    INTERMIXED_KERNEL_EA_OPERATION = 324,
    /// Device does not support file-level TRIM.
    FILE_LEVEL_TRIM_NOT_SUPPORTED = 326,
    /// The command specified a data offset that does not align to the device's granularity/alignment.
    OFFSET_ALIGNMENT_VIOLATION = 327,
    /// The command specified an invalid field in its parameter list.
    INVALID_FIELD_IN_PARAMETER_LIST = 328,
    /// An operation is currently in progress with the device.
    OPERATION_IN_PROGRESS = 329,
    /// An attempt was made to send down the command via an invalid path to the target device.
    BAD_DEVICE_PATH = 330,
    /// The command specified a number of descriptors that exceeded the maximum supported by the device.
    TOO_MANY_DESCRIPTORS = 331,
    /// Scrub is disabled on the specified file.
    SCRUB_DATA_DISABLED = 332,
    /// The storage device does not provide redundancy.
    NOT_REDUNDANT_STORAGE = 333,
    /// An operation is not supported on a resident file.
    RESIDENT_FILE_NOT_SUPPORTED = 334,
    /// An operation is not supported on a compressed file.
    COMPRESSED_FILE_NOT_SUPPORTED = 335,
    /// An operation is not supported on a directory.
    DIRECTORY_NOT_SUPPORTED = 336,
    /// The specified copy of the requested data could not be read.
    NOT_READ_FROM_COPY = 337,
    /// No action was taken as a system reboot is required.
    FAIL_NOACTION_REBOOT = 350,
    /// The shutdown operation failed.
    FAIL_SHUTDOWN = 351,
    /// The restart operation failed.
    FAIL_RESTART = 352,
    /// The maximum number of sessions has been reached.
    MAX_SESSIONS_REACHED = 353,
    /// The thread is already in background processing mode.
    THREAD_MODE_ALREADY_BACKGROUND = 400,
    /// The thread is not in background processing mode.
    THREAD_MODE_NOT_BACKGROUND = 401,
    /// The process is already in background processing mode.
    PROCESS_MODE_ALREADY_BACKGROUND = 402,
    /// The process is not in background processing mode.
    PROCESS_MODE_NOT_BACKGROUND = 403,
    /// Attempt to access invalid address.
    INVALID_ADDRESS = 487,
    /// User profile cannot be loaded.
    USER_PROFILE_LOAD = 500,
    /// Arithmetic result exceeded 32 bits.
    ARITHMETIC_OVERFLOW = 534,
    /// There is a process on other end of the pipe.
    PIPE_CONNECTED = 535,
    /// Waiting for a process to open the other end of the pipe.
    PIPE_LISTENING = 536,
    /// Application verifier has found an error in the current process.
    VERIFIER_STOP = 537,
    /// An error occurred in the ABIOS subsystem.
    ABIOS_ERROR = 538,
    /// A warning occurred in the WX86 subsystem.
    WX86_WARNING = 539,
    /// An error occurred in the WX86 subsystem.
    WX86_ERROR = 540,
    /// An attempt was made to cancel or set a timer that has an associated APC and the subject thread is not the thread that originally set the timer with an associated APC routine.
    TIMER_NOT_CANCELED = 541,
    /// Unwind exception code.
    UNWIND = 542,
    /// An invalid or unaligned stack was encountered during an unwind operation.
    BAD_STACK = 543,
    /// An invalid unwind target was encountered during an unwind operation.
    INVALID_UNWIND_TARGET = 544,
    /// Invalid Object Attributes specified to NtCreatePort or invalid Port Attributes specified to NtConnectPort
    INVALID_PORT_ATTRIBUTES = 545,
    /// Length of message passed to NtRequestPort or NtRequestWaitReplyPort was longer than the maximum message allowed by the port.
    PORT_MESSAGE_TOO_LONG = 546,
    /// An attempt was made to lower a quota limit below the current usage.
    INVALID_QUOTA_LOWER = 547,
    /// An attempt was made to attach to a device that was already attached to another device.
    DEVICE_ALREADY_ATTACHED = 548,
    /// An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references.
    INSTRUCTION_MISALIGNMENT = 549,
    /// Profiling not started.
    PROFILING_NOT_STARTED = 550,
    /// Profiling not stopped.
    PROFILING_NOT_STOPPED = 551,
    /// The passed ACL did not contain the minimum required information.
    COULD_NOT_INTERPRET = 552,
    /// The number of active profiling objects is at the maximum and no more may be started.
    PROFILING_AT_LIMIT = 553,
    /// Used to indicate that an operation cannot continue without blocking for I/O.
    CANT_WAIT = 554,
    /// Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process.
    CANT_TERMINATE_SELF = 555,
    /// If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter.
    /// In this case information is lost, however, the filter correctly handles the exception.
    UNEXPECTED_MM_CREATE_ERR = 556,
    /// If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter.
    /// In this case information is lost, however, the filter correctly handles the exception.
    UNEXPECTED_MM_MAP_ERROR = 557,
    /// If an MM error is returned which is not defined in the standard FsRtl filter, it is converted to one of the following errors which is guaranteed to be in the filter.
    /// In this case information is lost, however, the filter correctly handles the exception.
    UNEXPECTED_MM_EXTEND_ERR = 558,
    /// A malformed function table was encountered during an unwind operation.
    BAD_FUNCTION_TABLE = 559,
    /// Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system.
    /// This causes the protection attempt to fail, which may cause a file creation attempt to fail.
    NO_GUID_TRANSLATION = 560,
    /// Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors.
    INVALID_LDT_SIZE = 561,
    /// Indicates that the starting value for the LDT information was not an integral multiple of the selector size.
    INVALID_LDT_OFFSET = 563,
    /// Indicates that the user supplied an invalid descriptor when trying to set up Ldt descriptors.
    INVALID_LDT_DESCRIPTOR = 564,
    /// Indicates a process has too many threads to perform the requested action.
    /// For example, assignment of a primary token may only be performed when a process has zero or one threads.
    TOO_MANY_THREADS = 565,
    /// An attempt was made to operate on a thread within a specific process, but the thread specified is not in the process specified.
    THREAD_NOT_IN_PROCESS = 566,
    /// Page file quota was exceeded.
    PAGEFILE_QUOTA_EXCEEDED = 567,
    /// The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role.
    LOGON_SERVER_CONFLICT = 568,
    /// The SAM database on a Windows Server is significantly out of synchronization with the copy on the Domain Controller. A complete synchronization is required.
    SYNCHRONIZATION_REQUIRED = 569,
    /// The NtCreateFile API failed. This error should never be returned to an application, it is a place holder for the Windows Lan Manager Redirector to use in its internal error mapping routines.
    NET_OPEN_FAILED = 570,
    /// {Privilege Failed} The I/O permissions for the process could not be changed.
    IO_PRIVILEGE_FAILED = 571,
    /// {Application Exit by CTRL+C} The application terminated as a result of a CTRL+C.
    CONTROL_C_EXIT = 572,
    /// {Missing System File} The required system file %hs is bad or missing.
    MISSING_SYSTEMFILE = 573,
    /// {Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx.
    UNHANDLED_EXCEPTION = 574,
    /// {Application Error} The application was unable to start correctly (0x%lx). Click OK to close the application.
    APP_INIT_FAILURE = 575,
    /// {Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld.
    PAGEFILE_CREATE_FAILED = 576,
    /// Windows cannot verify the digital signature for this file.
    /// A recent hardware or software change might have installed a file that is signed incorrectly or damaged, or that might be malicious software from an unknown source.
    INVALID_IMAGE_HASH = 577,
    /// {No Paging File Specified} No paging file was specified in the system configuration.
    NO_PAGEFILE = 578,
    /// {EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present.
    ILLEGAL_FLOAT_CONTEXT = 579,
    /// An event pair synchronization operation was performed using the thread specific client/server event pair object, but no event pair object was associated with the thread.
    NO_EVENT_PAIR = 580,
    /// A Windows Server has an incorrect configuration.
    DOMAIN_CTRLR_CONFIG_ERROR = 581,
    /// An illegal character was encountered.
    /// For a multi-byte character set this includes a lead byte without a succeeding trail byte.
    /// For the Unicode character set this includes the characters 0xFFFF and 0xFFFE.
    ILLEGAL_CHARACTER = 582,
    /// The Unicode character is not defined in the Unicode character set installed on the system.
    UNDEFINED_CHARACTER = 583,
    /// The paging file cannot be created on a floppy diskette.
    FLOPPY_VOLUME = 584,
    /// The system BIOS failed to connect a system interrupt to the device or bus for which the device is connected.
    BIOS_FAILED_TO_CONNECT_INTERRUPT = 585,
    /// This operation is only allowed for the Primary Domain Controller of the domain.
    BACKUP_CONTROLLER = 586,
    /// An attempt was made to acquire a mutant such that its maximum count would have been exceeded.
    MUTANT_LIMIT_EXCEEDED = 587,
    /// A volume has been accessed for which a file system driver is required that has not yet been loaded.
    FS_DRIVER_REQUIRED = 588,
    /// {Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable.
    CANNOT_LOAD_REGISTRY_FILE = 589,
    /// {Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request.
    /// You may choose OK to terminate the process, or Cancel to ignore the error.
    DEBUG_ATTACH_FAILED = 590,
    /// {Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down.
    SYSTEM_PROCESS_TERMINATED = 591,
    /// {Data Not Accepted} The TDI client could not handle the data received during an indication.
    DATA_NOT_ACCEPTED = 592,
    /// NTVDM encountered a hard error.
    VDM_HARD_ERROR = 593,
    /// {Cancel Timeout} The driver %hs failed to complete a cancelled I/O request in the allotted time.
    DRIVER_CANCEL_TIMEOUT = 594,
    /// {Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message.
    REPLY_MESSAGE_MISMATCH = 595,
    /// {Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost.
    /// This error may be caused by a failure of your computer hardware or network connection. Please try to save this file elsewhere.
    LOST_WRITEBEHIND_DATA = 596,
    /// The parameter(s) passed to the server in the client/server shared memory window were invalid.
    /// Too much data may have been put in the shared memory window.
    CLIENT_SERVER_PARAMETERS_INVALID = 597,
    /// The stream is not a tiny stream.
    NOT_TINY_STREAM = 598,
    /// The request must be handled by the stack overflow code.
    STACK_OVERFLOW_READ = 599,
    /// Internal OFS status codes indicating how an allocation operation is handled.
    /// Either it is retried after the containing onode is moved or the extent stream is converted to a large stream.
    CONVERT_TO_LARGE = 600,
    /// The attempt to find the object found an object matching by ID on the volume but it is out of the scope of the handle used for the operation.
    FOUND_OUT_OF_SCOPE = 601,
    /// The bucket array must be grown. Retry transaction after doing so.
    ALLOCATE_BUCKET = 602,
    /// The user/kernel marshalling buffer has overflowed.
    MARSHALL_OVERFLOW = 603,
    /// The supplied variant structure contains invalid data.
    INVALID_VARIANT = 604,
    /// The specified buffer contains ill-formed data.
    BAD_COMPRESSION_BUFFER = 605,
    /// {Audit Failed} An attempt to generate a security audit failed.
    AUDIT_FAILED = 606,
    /// The timer resolution was not previously set by the current process.
    TIMER_RESOLUTION_NOT_SET = 607,
    /// There is insufficient account information to log you on.
    INSUFFICIENT_LOGON_INFO = 608,
    /// {Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly.
    /// The stack pointer has been left in an inconsistent state.
    /// The entrypoint should be declared as WINAPI or STDCALL.
    /// Select YES to fail the DLL load. Select NO to continue execution.
    /// Selecting NO may cause the application to operate incorrectly.
    BAD_DLL_ENTRYPOINT = 609,
    /// {Invalid Service Callback Entrypoint} The %hs service is not written correctly.
    /// The stack pointer has been left in an inconsistent state.
    /// The callback entrypoint should be declared as WINAPI or STDCALL.
    /// Selecting OK will cause the service to continue operation.
    /// However, the service process may operate incorrectly.
    BAD_SERVICE_ENTRYPOINT = 610,
    /// There is an IP address conflict with another system on the network.
    IP_ADDRESS_CONFLICT1 = 611,
    /// There is an IP address conflict with another system on the network.
    IP_ADDRESS_CONFLICT2 = 612,
    /// {Low On Registry Space} The system has reached the maximum size allowed for the system part of the registry. Additional storage requests will be ignored.
    REGISTRY_QUOTA_LIMIT = 613,
    /// A callback return system service cannot be executed when no callback is active.
    NO_CALLBACK_ACTIVE = 614,
    /// The password provided is too short to meet the policy of your user account. Please choose a longer password.
    PWD_TOO_SHORT = 615,
    /// The policy of your user account does not allow you to change passwords too frequently.
    /// This is done to prevent users from changing back to a familiar, but potentially discovered, password.
    /// If you feel your password has been compromised then please contact your administrator immediately to have a new one assigned.
    PWD_TOO_RECENT = 616,
    /// You have attempted to change your password to one that you have used in the past.
    /// The policy of your user account does not allow this.
    /// Please select a password that you have not previously used.
    PWD_HISTORY_CONFLICT = 617,
    /// The specified compression format is unsupported.
    UNSUPPORTED_COMPRESSION = 618,
    /// The specified hardware profile configuration is invalid.
    INVALID_HW_PROFILE = 619,
    /// The specified Plug and Play registry device path is invalid.
    INVALID_PLUGPLAY_DEVICE_PATH = 620,
    /// The specified quota list is internally inconsistent with its descriptor.
    QUOTA_LIST_INCONSISTENT = 621,
    /// {Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour.
    /// To restore access to this installation of Windows, please upgrade this installation using a licensed distribution of this product.
    EVALUATION_EXPIRATION = 622,
    /// {Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly.
    /// The relocation occurred because the DLL %hs occupied an address range reserved for Windows system DLLs.
    /// The vendor supplying the DLL should be contacted for a new DLL.
    ILLEGAL_DLL_RELOCATION = 623,
    /// {DLL Initialization Failed} The application failed to initialize because the window station is shutting down.
    DLL_INIT_FAILED_LOGOFF = 624,
    /// The validation process needs to continue on to the next step.
    VALIDATE_CONTINUE = 625,
    /// There are no more matches for the current index enumeration.
    NO_MORE_MATCHES = 626,
    /// The range could not be added to the range list because of a conflict.
    RANGE_LIST_CONFLICT = 627,
    /// The server process is running under a SID different than that required by client.
    SERVER_SID_MISMATCH = 628,
    /// A group marked use for deny only cannot be enabled.
    CANT_ENABLE_DENY_ONLY = 629,
    /// {EXCEPTION} Multiple floating point faults.
    FLOAT_MULTIPLE_FAULTS = 630,
    /// {EXCEPTION} Multiple floating point traps.
    FLOAT_MULTIPLE_TRAPS = 631,
    /// The requested interface is not supported.
    NOINTERFACE = 632,
    /// {System Standby Failed} The driver %hs does not support standby mode.
    /// Updating this driver may allow the system to go to standby mode.
    DRIVER_FAILED_SLEEP = 633,
    /// The system file %1 has become corrupt and has been replaced.
    CORRUPT_SYSTEM_FILE = 634,
    /// {Virtual Memory Minimum Too Low} Your system is low on virtual memory.
    /// Windows is increasing the size of your virtual memory paging file.
    /// During this process, memory requests for some applications may be denied. For more information, see Help.
    COMMITMENT_MINIMUM = 635,
    /// A device was removed so enumeration must be restarted.
    PNP_RESTART_ENUMERATION = 636,
    /// {Fatal System Error} The system image %s is not properly signed.
    /// The file has been replaced with the signed file. The system has been shut down.
    SYSTEM_IMAGE_BAD_SIGNATURE = 637,
    /// Device will not start without a reboot.
    PNP_REBOOT_REQUIRED = 638,
    /// There is not enough power to complete the requested operation.
    INSUFFICIENT_POWER = 639,
    /// ERROR_MULTIPLE_FAULT_VIOLATION
    MULTIPLE_FAULT_VIOLATION = 640,
    /// The system is in the process of shutting down.
    SYSTEM_SHUTDOWN = 641,
    /// An attempt to remove a processes DebugPort was made, but a port was not already associated with the process.
    PORT_NOT_SET = 642,
    /// This version of Windows is not compatible with the behavior version of directory forest, domain or domain controller.
    DS_VERSION_CHECK_FAILURE = 643,
    /// The specified range could not be found in the range list.
    RANGE_NOT_FOUND = 644,
    /// The driver was not loaded because the system is booting into safe mode.
    NOT_SAFE_MODE_DRIVER = 646,
    /// The driver was not loaded because it failed its initialization call.
    FAILED_DRIVER_ENTRY = 647,
    /// The "%hs" encountered an error while applying power or reading the device configuration.
    /// This may be caused by a failure of your hardware or by a poor connection.
    DEVICE_ENUMERATION_ERROR = 648,
    /// The create operation failed because the name contained at least one mount point which resolves to a volume to which the specified device object is not attached.
    MOUNT_POINT_NOT_RESOLVED = 649,
    /// The device object parameter is either not a valid device object or is not attached to the volume specified by the file name.
    INVALID_DEVICE_OBJECT_PARAMETER = 650,
    /// A Machine Check Error has occurred.
    /// Please check the system eventlog for additional information.
    MCA_OCCURED = 651,
    /// There was error [%2] processing the driver database.
    DRIVER_DATABASE_ERROR = 652,
    /// System hive size has exceeded its limit.
    SYSTEM_HIVE_TOO_LARGE = 653,
    /// The driver could not be loaded because a previous version of the driver is still in memory.
    DRIVER_FAILED_PRIOR_UNLOAD = 654,
    /// {Volume Shadow Copy Service} Please wait while the Volume Shadow Copy Service prepares volume %hs for hibernation.
    VOLSNAP_PREPARE_HIBERNATE = 655,
    /// The system has failed to hibernate (The error code is %hs).
    /// Hibernation will be disabled until the system is restarted.
    HIBERNATION_FAILURE = 656,
    /// The password provided is too long to meet the policy of your user account. Please choose a shorter password.
    PWD_TOO_LONG = 657,
    /// The requested operation could not be completed due to a file system limitation.
    FILE_SYSTEM_LIMITATION = 665,
    /// An assertion failure has occurred.
    ASSERTION_FAILURE = 668,
    /// An error occurred in the ACPI subsystem.
    ACPI_ERROR = 669,
    /// WOW Assertion Error.
    WOW_ASSERTION = 670,
    /// A device is missing in the system BIOS MPS table. This device will not be used.
    /// Please contact your system vendor for system BIOS update.
    PNP_BAD_MPS_TABLE = 671,
    /// A translator failed to translate resources.
    PNP_TRANSLATION_FAILED = 672,
    /// A IRQ translator failed to translate resources.
    PNP_IRQ_TRANSLATION_FAILED = 673,
    /// Driver %2 returned invalid ID for a child device (%3).
    PNP_INVALID_ID = 674,
    /// {Kernel Debugger Awakened} the system debugger was awakened by an interrupt.
    WAKE_SYSTEM_DEBUGGER = 675,
    /// {Handles Closed} Handles to objects have been automatically closed as a result of the requested operation.
    HANDLES_CLOSED = 676,
    /// {Too Much Information} The specified access control list (ACL) contained more information than was expected.
    EXTRANEOUS_INFORMATION = 677,
    /// This warning level status indicates that the transaction state already exists for the registry sub-tree, but that a transaction commit was previously aborted.
    /// The commit has NOT been completed, but has not been rolled back either (so it may still be committed if desired).
    RXACT_COMMIT_NECESSARY = 678,
    /// {Media Changed} The media may have changed.
    MEDIA_CHECK = 679,
    /// {GUID Substitution} During the translation of a global identifier (GUID) to a Windows security ID (SID), no administratively-defined GUID prefix was found.
    /// A substitute prefix was used, which will not compromise system security.
    /// However, this may provide a more restrictive access than intended.
    GUID_SUBSTITUTION_MADE = 680,
    /// The create operation stopped after reaching a symbolic link.
    STOPPED_ON_SYMLINK = 681,
    /// A long jump has been executed.
    LONGJUMP = 682,
    /// The Plug and Play query operation was not successful.
    PLUGPLAY_QUERY_VETOED = 683,
    /// A frame consolidation has been executed.
    UNWIND_CONSOLIDATE = 684,
    /// {Registry Hive Recovered} Registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost.
    REGISTRY_HIVE_RECOVERED = 685,
    /// The application is attempting to run executable code from the module %hs. This may be insecure.
    /// An alternative, %hs, is available. Should the application use the secure module %hs?
    DLL_MIGHT_BE_INSECURE = 686,
    /// The application is loading executable code from the module %hs.
    /// This is secure, but may be incompatible with previous releases of the operating system.
    /// An alternative, %hs, is available. Should the application use the secure module %hs?
    DLL_MIGHT_BE_INCOMPATIBLE = 687,
    /// Debugger did not handle the exception.
    DBG_EXCEPTION_NOT_HANDLED = 688,
    /// Debugger will reply later.
    DBG_REPLY_LATER = 689,
    /// Debugger cannot provide handle.
    DBG_UNABLE_TO_PROVIDE_HANDLE = 690,
    /// Debugger terminated thread.
    DBG_TERMINATE_THREAD = 691,
    /// Debugger terminated process.
    DBG_TERMINATE_PROCESS = 692,
    /// Debugger got control C.
    DBG_CONTROL_C = 693,
    /// Debugger printed exception on control C.
    DBG_PRINTEXCEPTION_C = 694,
    /// Debugger received RIP exception.
    DBG_RIPEXCEPTION = 695,
    /// Debugger received control break.
    DBG_CONTROL_BREAK = 696,
    /// Debugger command communication exception.
    DBG_COMMAND_EXCEPTION = 697,
    /// {Object Exists} An attempt was made to create an object and the object name already existed.
    OBJECT_NAME_EXISTS = 698,
    /// {Thread Suspended} A thread termination occurred while the thread was suspended.
    /// The thread was resumed, and termination proceeded.
    THREAD_WAS_SUSPENDED = 699,
    /// {Image Relocated} An image file could not be ma```
