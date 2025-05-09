```
reError!void {
        switch (self._configure(self, ip6_config_data)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .no_mapping => return Error.NoMapping,
            .already_started => return Error.AlreadyStarted,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn disable(self: *Ip6) ConfigureError!void {
        switch (self._configure(self, null)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .no_mapping => return Error.NoMapping,
            .already_started => return Error.AlreadyStarted,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn leaveAllGroups(self: *Ip6) GroupsError!void {
        switch (self._groups(self, false, null)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .not_started => return Error.NotStarted,
            .out_of_resources => return Error.OutOfResources,
            .unsupported => return Error.Unsupported,
            .already_started => return Error.AlreadyStarted,
            .not_found => return Error.NotFound,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Joins and leaves multicast groups.
    ///
    /// To leave all groups, use `leaveAllGroups` instead.
    pub fn groups(
        self: *Ip6,
        join_flag: JoinFlag,
        group_address: *const Address,
    ) GroupsError!void {
        switch (self._groups(
            self,
            // set to TRUE to join the multicast group session and FALSE to leave
            join_flag == .join,
            group_address,
        )) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .not_started => return Error.NotStarted,
            .out_of_resources => return Error.OutOfResources,
            .unsupported => return Error.Unsupported,
            .already_started => return Error.AlreadyStarted,
            .not_found => return Error.NotFound,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Adds and deletes routing table entries.
    pub fn routes(
        self: *Ip6,
        delete_route: DeleteFlag,
        destination: ?*const Address,
        prefix_length: u8,
        gateway_address: ?*const Address,
    ) RoutesError!void {
        switch (self._routes(
            self,
            delete_route == .delete,
            destination,
            prefix_length,
            gateway_address,
        )) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .not_found => return Error.NotFound,
            .access_denied => return Error.AccessDenied,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Add or delete Neighbor cache entries.
    pub fn neighbors(
        self: *Ip6,
        delete_flag: DeleteFlag,
        target_ip6_address: *const Address,
        target_link_address: ?*const MacAddress,
        timeout: u32,
        override: bool,
    ) NeighborsError!void {
        switch (self._neighbors(
            self,
            // set to TRUE to delete this route from the routing table.
            // set to FALSE to add this route to the routing table.
            delete_flag == .delete,
            target_ip6_address,
            target_link_address,
            timeout,
            override,
        )) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .not_found => return Error.NotFound,
            .access_denied => return Error.AccessDenied,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Places outgoing data packets into the transmit queue.
    pub fn transmit(self: *Ip6, token: *CompletionToken) TransmitError!void {
        switch (self._transmit(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .no_mapping => return Error.NoMapping,
            .invalid_parameter => return Error.InvalidParameter,
            .access_denied => return Error.AccessDenied,
            .not_ready => return Error.NotReady,
            .not_found => return Error.NotFound,
            .out_of_resources => return Error.OutOfResources,
            .buffer_too_small => return Error.BufferTooSmall,
            .bad_buffer_size => return Error.BadBufferSize,
            .device_error => return Error.DeviceError,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Places a receiving request into the receiving queue.
    pub fn receive(self: *Ip6, token: *CompletionToken) ReceiveError!void {
        switch (self._receive(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .no_mapping => return Error.NoMapping,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .device_error => return Error.DeviceError,
            .access_denied => return Error.AccessDenied,
            .not_ready => return Error.NotReady,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Abort an asynchronous transmits or receive request.
    pub fn cancel(self: *Ip6, token: ?*CompletionToken) CancelError!void {
        switch (self._cancel(self, token)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .not_started => return Error.NotStarted,
            .not_found => return Error.NotFound,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Polls for incoming data packets and processes outgoing data packets.
    ///
    /// Returns true if a packet was received or processed.
    pub fn poll(self: *Ip6) PollError!bool {
        switch (self._poll(self)) {
            .success => return true,
            .not_ready => return false,
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .timeout => return Error.Timeout,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x2c8759d5,
        .time_mid = 0x5c2d,
        .time_high_and_version = 0x66ef,
        .clock_seq_high_and_reserved = 0x92,
        .clock_seq_low = 0x5f,
        .node = [_]u8{ 0xb6, 0x6c, 0x10, 0x19, 0x57, 0xe2 },
    };

    pub const DeleteFlag = enum {
        delete,
        add,
    };

    pub const JoinFlag = enum {
        join,
        leave,
    };

    pub const Mode = extern struct {
        is_started: bool,
        max_packet_size: u32,
        config_data: Config,
        is_configured: bool,
        address_count: u32,
        address_list: [*]AddressInfo,
        group_count: u32,
        group_table: [*]Address,
        route_count: u32,
        route_table: [*]RouteTable,
        neighbor_count: u32,
        neighbor_cache: [*]NeighborCache,
        prefix_count: u32,
        prefix_table: [*]AddressInfo,
        icmp_type_count: u32,
        icmp_type_list: [*]IcmpType,
    };

    pub const Config = extern struct {
        default_protocol: u8,
        accept_any_protocol: bool,
        accept_icmp_errors: bool,
        accept_promiscuous: bool,
        destination_address: Address,
        station_address: Address,
        traffic_class: u8,
        hop_limit: u8,
        flow_label: u32,
        receive_timeout: u32,
        transmit_timeout: u32,
    };

    pub const Address = [16]u8;

    pub const AddressInfo = extern struct {
        address: Address,
        prefix_length: u8,
    };

    pub const RouteTable = extern struct {
        gateway: Address,
        destination: Address,
        prefix_length: u8,
    };

    pub const NeighborState = enum(u32) {
        incomplete,
        reachable,
        stale,
        delay,
        probe,
    };

    pub const NeighborCache = extern struct {
        neighbor: Address,
        link_address: MacAddress,
        state: NeighborState,
    };

    pub const IcmpType = extern struct {
        type: u8,
        code: u8,
    };

    pub const CompletionToken = extern struct {
        event: Event,
        status: Status,
        packet: *anyopaque, // union TODO
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Handle = uefi.Handle;
const Status = uefi.Status;
const SystemTable = uefi.tables.SystemTable;
const MemoryType = uefi.tables.MemoryType;
const DevicePath = uefi.protocol.DevicePath;
const cc = uefi.cc;
const Error = Status.Error;

pub const LoadedImage = extern struct {
    revision: u32,
    parent_handle: Handle,
    system_table: *SystemTable,
    device_handle: ?Handle,
    file_path: *DevicePath,
    reserved: *anyopaque,
    load_options_size: u32,
    load_options: ?*anyopaque,
    image_base: [*]u8,
    image_size: u64,
    image_code_type: MemoryType,
    image_data_type: MemoryType,
    _unload: *const fn (*LoadedImage, Handle) callconv(cc) Status,

    pub const UnloadError = uefi.UnexpectedError || error{InvalidParameter};

    /// Unloads an image from memory.
    pub fn unload(self: *LoadedImage, handle: Handle) UnloadError!void {
        switch (self._unload(self, handle)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x5b1b31a1,
        .time_mid = 0x9562,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x3f,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };

    pub const device_path_guid align(8) = Guid{
        .time_low = 0xbc62157e,
        .time_mid = 0x3e33,
        .time_high_and_version = 0x4fec,
        .clock_seq_high_and_reserved = 0x99,
        .clock_seq_low = 0x20,
        .node = [_]u8{ 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf },
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Event = uefi.Event;
const Handle = uefi.Handle;
const Status = uefi.Status;
const Time = uefi.Time;
const SimpleNetwork = uefi.protocol.SimpleNetwork;
const MacAddress = uefi.MacAddress;
const cc = uefi.cc;
const Error = Status.Error;

pub const ManagedNetwork = extern struct {
    _get_mode_data: *const fn (*const ManagedNetwork, ?*Config, ?*SimpleNetwork) callconv(cc) Status,
    _configure: *const fn (*ManagedNetwork, ?*const Config) callconv(cc) Status,
    _mcast_ip_to_mac: *const fn (*ManagedNetwork, bool, *const anyopaque, *MacAddress) callconv(cc) Status,
    _groups: *const fn (*ManagedNetwork, bool, ?*const MacAddress) callconv(cc) Status,
    _transmit: *const fn (*ManagedNetwork, *CompletionToken) callconv(cc) Status,
    _receive: *const fn (*ManagedNetwork, *CompletionToken) callconv(cc) Status,
    _cancel: *const fn (*ManagedNetwork, ?*const CompletionToken) callconv(cc) Status,
    _poll: *const fn (*ManagedNetwork) callconv(cc) Status,

    pub const GetModeDataError = uefi.UnexpectedError || error{
        InvalidParameter,
        Unsupported,
        NotStarted,
    } || Error;
    pub const ConfigureError = uefi.UnexpectedError || error{
        InvalidParameter,
        OutOfResources,
        Unsupported,
        DeviceError,
    } || Error;
    pub const McastIpToMacError = uefi.UnexpectedError || error{
        InvalidParameter,
        NotStarted,
        Unsupported,
        DeviceError,
    } || Error;
    pub const GroupsError = uefi.UnexpectedError || error{
        InvalidParameter,
        NotStarted,
        AlreadyStarted,
        NotFound,
        DeviceError,
        Unsupported,
    } || Error;
    pub const TransmitError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        AccessDenied,
        OutOfResources,
        DeviceError,
        NotReady,
        NoMedia,
    };
    pub const ReceiveError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        OutOfResources,
        DeviceError,
        AccessDenied,
        NotReady,
        NoMedia,
    };
    pub const CancelError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        NotFound,
    };
    pub const PollError = uefi.UnexpectedError || error{
        NotStarted,
        DeviceError,
        NotReady,
        Timeout,
    };

    pub const GetModeDataData = struct {
        mnp_config: Config,
        snp_mode: SimpleNetwork,
    };

    /// Returns the operational parameters for the current MNP child driver.
    /// May also support returning the underlying SNP driver mode data.
    pub fn getModeData(self: *const ManagedNetwork) GetModeDataError!GetModeDataData {
        var data: GetModeDataData = undefined;
        switch (self._get_mode_data(self, &data.mnp_config, &data.snp_mode)) {
            .success => return data,
            else => |status| {
                try status.err();
                return uefi.unexpectedStatus(status);
            },
        }
    }

    /// Sets or clears the operational parameters for the MNP child driver.
    pub fn configure(self: *ManagedNetwork, mnp_config_data: ?*const Config) ConfigureError!void {
        switch (self._configure(self, mnp_config_data)) {
            .success => {},
            else => |status| {
                try status.err();
                return uefi.unexpectedStatus(status);
            },
        }
    }

    /// Translates an IP multicast address to a hardware (MAC) multicast address.
    /// This function may be unsupported in some MNP implementations.
    pub fn mcastIpToMac(
        self: *ManagedNetwork,
        ipv6flag: bool,
        ipaddress: *const uefi.IpAddress,
    ) McastIpToMacError!MacAddress {
        var result: MacAddress = undefined;
        switch (self._mcast_ip_to_mac(self, ipv6flag, ipaddress, &result)) {
            .success => return result,
            else => |status| {
                try status.err();
                return uefi.unexpectedStatus(status);
            },
        }
    }

    /// Enables and disables receive filters for multicast address.
    /// This function may be unsupported in some MNP implementations.
    pub fn groups(
        self: *ManagedNetwork,
        join_flag: bool,
        mac_address: ?*const MacAddress,
    ) GroupsError!void {
        switch (self._groups(self, join_flag, mac_address)) {
            .success => {},
            else => |status| {
                try status.err();
                return uefi.unexpectedStatus(status);
            },
        }
    }

    /// Places asynchronous outgoing data packets into the transmit queue.
    pub fn transmit(self: *ManagedNetwork, token: *CompletionToken) TransmitError!void {
        switch (self._transmit(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .access_denied => return Error.AccessDenied,
            .out_of_resources => return Error.OutOfResources,
            .device_error => return Error.DeviceError,
            .not_ready => return Error.NotReady,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Places an asynchronous receiving request into the receiving queue.
    pub fn receive(self: *ManagedNetwork, token: *CompletionToken) TransmitError!void {
        switch (self._receive(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .device_error => return Error.DeviceError,
            .access_denied => return Error.AccessDenied,
            .not_ready => return Error.NotReady,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Aborts an asynchronous transmit or receive request.
    pub fn cancel(self: *ManagedNetwork, token: ?*const CompletionToken) CancelError!void {
        switch (self._cancel(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Polls for incoming data packets and processes outgoing data packets.
    pub fn poll(self: *ManagedNetwork) PollError!void {
        switch (self._poll(self)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .device_error => return Error.DeviceError,
            .not_ready => return Error.NotReady,
            .timeout => return Error.Timeout,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x7ab33a91,
        .time_mid = 0xace5,
        .time_high_and_version = 0x4326,
        .clock_seq_high_and_reserved = 0xb5,
        .clock_seq_low = 0x72,
        .node = [_]u8{ 0xe7, 0xee, 0x33, 0xd3, 0x9f, 0x16 },
    };

    pub const ServiceBinding = extern struct {
        _create_child: *const fn (*const ServiceBinding, *?Handle) callconv(cc) Status,
        _destroy_child: *const fn (*const ServiceBinding, Handle) callconv(cc) Status,

        pub fn createChild(self: *const ServiceBinding, handle: *?Handle) Status {
            return self._create_child(self, handle);
        }

        pub fn destroyChild(self: *const ServiceBinding, handle: Handle) Status {
            return self._destroy_child(self, handle);
        }

        pub const guid align(8) = Guid{
            .time_low = 0xf36ff770,
            .time_mid = 0xa7e1,
            .time_high_and_version = 0x42cf,
            .clock_seq_high_and_reserved = 0x9e,
            .clock_seq_low = 0xd2,
            .node = [_]u8{ 0x56, 0xf0, 0xf2, 0x71, 0xf4, 0x4c },
        };
    };

    pub const Config = extern struct {
        received_queue_timeout_value: u32,
        transmit_queue_timeout_value: u32,
        protocol_type_filter: u16,
        enable_unicast_receive: bool,
        enable_multicast_receive: bool,
        enable_broadcast_receive: bool,
        enable_promiscuous_receive: bool,
        flush_queues_on_reset: bool,
        enable_receive_timestamps: bool,
        disable_background_polling: bool,
    };

    pub const CompletionToken = extern struct {
        event: Event,
        status: Status,
        packet: extern union {
            rx_data: *ReceiveData,
            tx_data: *TransmitData,
        },
    };

    pub const ReceiveData = extern struct {
        timestamp: Time,
        recycle_event: Event,
        packet_length: u32,
        header_length: u32,
        address_length: u32,
        data_length: u32,
        broadcast_flag: bool,
        multicast_flag: bool,
        promiscuous_flag: bool,
        protocol_type: u16,
        destination_address: [*]u8,
        source_address: [*]u8,
        media_header: [*]u8,
        packet_data: [*]u8,
    };

    pub const TransmitData = extern struct {
        destination_address: ?*MacAddress,
        source_address: ?*MacAddress,
        protocol_type: u16,
        data_length: u32,
        header_length: u16,
        fragment_count: u16,

        pub fn getFragments(self: *TransmitData) []Fragment {
            return @as([*]Fragment, @ptrCast(@alignCast(@as([*]u8, @ptrCast(self)) + @sizeOf(TransmitData))))[0..self.fragment_count];
        }
    };

    pub const Fragment = extern struct {
        fragment_length: u32,
        fragment_buffer: [*]u8,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// Random Number Generator protocol
pub const Rng = extern struct {
    _get_info: *const fn (*const Rng, *usize, [*]align(8) Guid) callconv(cc) Status,
    _get_rng: *const fn (*const Rng, ?*align(8) const Guid, usize, [*]u8) callconv(cc) Status,

    pub const GetInfoError = uefi.UnexpectedError || error{
        Unsupported,
        DeviceError,
        BufferTooSmall,
    };
    pub const GetRNGError = uefi.UnexpectedError || error{
        Unsupported,
        DeviceError,
        NotReady,
        InvalidParameter,
    };

    /// Returns information about the random number generation implementation.
    pub fn getInfo(self: *const Rng, list: []align(8) Guid) GetInfoError![]align(8) Guid {
        var len: usize = list.len;
        switch (self._get_info(self, &len, list.ptr)) {
            .success => return list[0..len],
            .unsupported => return Error.Unsupported,
            .device_error => return Error.DeviceError,
            .buffer_too_small => return Error.BufferTooSmall,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Produces and returns an RNG value using either the default or specified RNG algorithm.
    pub fn getRNG(self: *const Rng, algo: ?*align(8) const Guid, value: []u8) GetRNGError!void {
        switch (self._get_rng(self, algo, value.len, value.ptr)) {
            .success => {},
            .unsupported => return Error.Unsupported,
            .device_error => return Error.DeviceError,
            .not_ready => return Error.NotReady,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x3152bca5,
        .time_mid = 0xeade,
        .time_high_and_version = 0x433d,
        .clock_seq_high_and_reserved = 0x86,
        .clock_seq_low = 0x2e,
        .node = [_]u8{ 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44 },
    };
    pub const algorithm_sp800_90_hash_256 align(8) = Guid{
        .time_low = 0xa7af67cb,
        .time_mid = 0x603b,
        .time_high_and_version = 0x4d42,
        .clock_seq_high_and_reserved = 0xba,
        .clock_seq_low = 0x21,
        .node = [_]u8{ 0x70, 0xbf, 0xb6, 0x29, 0x3f, 0x96 },
    };
    pub const algorithm_sp800_90_hmac_256 align(8) = Guid{
        .time_low = 0xc5149b43,
        .time_mid = 0xae85,
        .time_high_and_version = 0x4f53,
        .clock_seq_high_and_reserved = 0x99,
        .clock_seq_low = 0x82,
        .node = [_]u8{ 0xb9, 0x43, 0x35, 0xd3, 0xa9, 0xe7 },
    };
    pub const algorithm_sp800_90_ctr_256 align(8) = Guid{
        .time_low = 0x44f0de6e,
        .time_mid = 0x4d8c,
        .time_high_and_version = 0x4045,
        .clock_seq_high_and_reserved = 0xa8,
        .clock_seq_low = 0xc7,
        .node = [_]u8{ 0x4d, 0xd1, 0x68, 0x85, 0x6b, 0x9e },
    };
    pub const algorithm_x9_31_3des align(8) = Guid{
        .time_low = 0x63c4785a,
        .time_mid = 0xca34,
        .time_high_and_version = 0x4012,
        .clock_seq_high_and_reserved = 0xa3,
        .clock_seq_low = 0xc8,
        .node = [_]u8{ 0x0b, 0x6a, 0x32, 0x4f, 0x55, 0x46 },
    };
    pub const algorithm_x9_31_aes align(8) = Guid{
        .time_low = 0xacd03321,
        .time_mid = 0x777e,
        .time_high_and_version = 0x4d3d,
        .clock_seq_high_and_reserved = 0xb1,
        .clock_seq_low = 0xc8,
        .node = [_]u8{ 0x20, 0xcf, 0xd8, 0x88, 0x20, 0xc9 },
    };
    pub const algorithm_raw align(8) = Guid{
        .time_low = 0xe43176d7,
        .time_mid = 0xb6e8,
        .time_high_and_version = 0x4827,
        .clock_seq_high_and_reserved = 0xb7,
        .clock_seq_low = 0x84,
        .node = [_]u8{ 0x7f, 0xfd, 0xc4, 0xb6, 0x85, 0x61 },
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

pub const SerialIo = extern struct {
    revision: u64,
    _reset: *const fn (*SerialIo) callconv(cc) Status,
    _set_attribute: *const fn (*SerialIo, u64, u32, u32, ParityType, u8, StopBitsType) callconv(cc) Status,
    _set_control: *const fn (*SerialIo, u32) callconv(cc) Status,
    _get_control: *const fn (*const SerialIo, *u32) callconv(cc) Status,
    _write: *const fn (*SerialIo, *usize, *const anyopaque) callconv(cc) Status,
    _read: *const fn (*SerialIo, *usize, *anyopaque) callconv(cc) Status,
    mode: *Mode,
    device_type_guid: ?*Guid,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const SetAttributeError = uefi.UnexpectedError || error{
        InvalidParameter,
        DeviceError,
    };
    pub const SetControlError = uefi.UnexpectedError || error{
        Unsupported,
        DeviceError,
    };
    pub const GetControlError = uefi.UnexpectedError || error{DeviceError};
    pub const WriteError = uefi.UnexpectedError || error{
        DeviceError,
        Timeout,
    };
    pub const ReadError = uefi.UnexpectedError || error{
        DeviceError,
        Timeout,
    };

    /// Resets the serial device.
    pub fn reset(self: *SerialIo) ResetError!void {
        switch (self._reset(self)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Sets the baud rate, receive FIFO depth, transmit/receive time out, parity, data bits, and stop bits on a serial device.
    pub fn setAttribute(
        self: *SerialIo,
        baud_rate: u64,
        receiver_fifo_depth: u32,
        timeout: u32,
        parity: ParityType,
        data_bits: u8,
        stop_bits: StopBitsType,
    ) SetAttributeError!void {
        switch (self._set_attribute(
            self,
            baud_rate,
            receiver_fifo_depth,
            timeout,
            parity,
            data_bits,
            stop_bits,
        )) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Sets the control bits on a serial device.
    pub fn setControl(self: *SerialIo, control: u32) SetControlError!void {
        switch (self._set_control(self, control)) {
            .success => {},
            .unsupported => return Error.Unsupported,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Retrieves the status of the control bits on a serial device.
    pub fn getControl(self: *SerialIo) GetControlError!u32 {
        var control: u32 = undefined;
        switch (self._get_control(self, &control)) {
            .success => return control,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Writes data to a serial device.
    pub fn write(self: *SerialIo, buffer: []const u8) WriteError!usize {
        var len: usize = buffer.len;
        switch (self._write(self, &len, buffer.ptr)) {
            .success => return len,
            .device_error => return Error.DeviceError,
            .timeout => return Error.Timeout,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Reads data from a serial device.
    pub fn read(self: *SerialIo, buffer: []u8) ReadError!usize {
        var len: usize = buffer.len;
        switch (self._read(self, &len, buffer.ptr)) {
            .success => return len,
            .device_error => return Error.DeviceError,
            .timeout => return Error.Timeout,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0xBB25CF6F,
        .time_mid = 0xF1D4,
        .time_high_and_version = 0x11D2,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x0c,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0xfd },
    };

    pub const ParityType = enum(u32) {
        default_parity,
        no_parity,
        even_parity,
        odd_parity,
        mark_parity,
        space_parity,
    };

    pub const StopBitsType = enum(u32) {
        default_stop_bits,
        one_stop_bit,
        one_five_stop_bits,
        two_stop_bits,
    };

    pub const Mode = extern struct {
        control_mask: u32,
        timeout: u32,
        baud_rate: u64,
        receive_fifo_depth: u32,
        data_bits: u32,
        parity: u32,
        stop_bits: u32,
    };
};
const std = @import("std");
const uefi = std.uefi;
const Guid = uefi.Guid;
const Handle = uefi.Handle;
const Status = uefi.Status;
const Error = Status.Error;
const cc = uefi.cc;

pub fn ServiceBinding(service_guid: Guid) type {
    return struct {
        const Self = @This();

        _create_child: *const fn (*Self, *?Handle) callconv(cc) Status,
        _destroy_child: *const fn (*Self, Handle) callconv(cc) Status,

        pub const CreateChildError = uefi.UnexpectedError || error{
            InvalidParameter,
            OutOfResources,
        } || Error;
        pub const DestroyChildError = uefi.UnexpectedError || error{
            Unsupported,
            InvalidParameter,
            AccessDenied,
        } || Error;

        /// To add this protocol to an existing handle, use `addToHandle` instead.
        pub fn createChild(self: *Self) CreateChildError!Handle {
            var handle: ?Handle = null;
            switch (self._create_child(self, &handle)) {
                .success => return handle orelse error.Unexpected,
                else => |status| {
                    try status.err();
                    return uefi.unexpectedStatus(status);
                },
            }
        }

        pub fn addToHandle(self: *Self, handle: Handle) CreateChildError!void {
            switch (self._create_child(self, @ptrCast(@constCast(&handle)))) {
                .success => {},
                else => |status| {
                    try status.err();
                    return uefi.unexpectedStatus(status);
                },
            }
        }

        pub fn destroyChild(self: *Self, handle: Handle) DestroyChildError!void {
            switch (self._destroy_child(self, handle)) {
                .success => {},
                else => |status| {
                    try status.err();
                    return uefi.unexpectedStatus(status);
                },
            }
        }

        pub const guid align(8) = service_guid;
    };
}
const uefi = @import("std").os.uefi;
const Guid = uefi.Guid;
const FileHandle = uefi.FileHandle;

pub const ShellParameters = extern struct {
    argv: [*][*:0]const u16,
    argc: usize,
    stdin: FileHandle,
    stdout: FileHandle,
    stderr: FileHandle,

    pub const guid align(8) = Guid{
        .time_low = 0x752f3136,
        .time_mid = 0x4e16,
        .time_high_and_version = 0x4fdc,
        .clock_seq_high_and_reserved = 0xa2,
        .clock_seq_low = 0x2a,
        .node = [_]u8{ 0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca },
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const File = uefi.protocol.File;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

pub const SimpleFileSystem = extern struct {
    revision: u64,
    _open_volume: *const fn (*const SimpleFileSystem, **File) callconv(cc) Status,

    pub const OpenVolumeError = uefi.UnexpectedError || error{
        Unsupported,
        NoMedia,
        DeviceError,
        VolumeCorrupted,
        AccessDenied,
        OutOfResources,
        MediaChanged,
    };

    pub fn openVolume(self: *const SimpleFileSystem) OpenVolumeError!*File {
        var root: *File = undefined;
        switch (self._open_volume(self, &root)) {
            .success => return root,
            .unsupported => return Error.Unsupported,
            .no_media => return Error.NoMedia,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            .access_denied => return Error.AccessDenied,
            .out_of_resources => return Error.OutOfResources,
            .media_changed => return Error.MediaChanged,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x0964e5b22,
        .time_mid = 0x6459,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x39,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Event = uefi.Event;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

pub const SimpleNetwork = extern struct {
    revision: u64,
    _start: *const fn (*SimpleNetwork) callconv(cc) Status,
    _stop: *const fn (*SimpleNetwork) callconv(cc) Status,
    _initialize: *const fn (*SimpleNetwork, usize, usize) callconv(cc) Status,
    _reset: *const fn (*SimpleNetwork, bool) callconv(cc) Status,
    _shutdown: *const fn (*SimpleNetwork) callconv(cc) Status,
    _receive_filters: *const fn (*SimpleNetwork, ReceiveFilter, ReceiveFilter, bool, usize, ?[*]const MacAddress) callconv(cc) Status,
    _station_address: *const fn (*SimpleNetwork, bool, ?*const MacAddress) callconv(cc) Status,
    _statistics: *const fn (*const SimpleNetwork, bool, ?*usize, ?*Statistics) callconv(cc) Status,
    _mcast_ip_to_mac: *const fn (*SimpleNetwork, bool, *const anyopaque, *MacAddress) callconv(cc) Status,
    _nvdata: *const fn (*SimpleNetwork, bool, usize, usize, [*]u8) callconv(cc) Status,
    _get_status: *const fn (*SimpleNetwork, ?*InterruptStatus, ?*?[*]u8) callconv(cc) Status,
    _transmit: *const fn (*SimpleNetwork, usize, usize, [*]const u8, ?*const MacAddress, ?*const MacAddress, ?*const u16) callconv(cc) Status,
    _receive: *const fn (*SimpleNetwork, ?*usize, *usize, [*]u8, ?*MacAddress, ?*MacAddress, ?*u16) callconv(cc) Status,
    wait_for_packet: Event,
    mode: *Mode,

    pub const StartError = uefi.UnexpectedError || error{
        AlreadyStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const StopError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const InitializeError = uefi.UnexpectedError || error{
        NotStarted,
        OutOfResources,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const ResetError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const ShutdownError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
    };
    pub const ReceiveFiltersError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const StationAddressError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const StatisticsError = uefi.UnexpectedError || error{
        NotStarted,
        BufferTooSmall,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const McastIpToMacError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const NvDataError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const GetStatusError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
    };
    pub const TransmitError = uefi.UnexpectedError || error{
        NotStarted,
        NotReady,
        BufferTooSmall,
        InvalidParameter,
        DeviceError,
        Unsupported,
    };
    pub const ReceiveError = uefi.UnexpectedError || error{
        NotStarted,
        NotReady,
        BufferTooSmall,
        InvalidParameter,
        DeviceError,
    };

    /// Changes the state of a network interface from "stopped" to "started".
    pub fn start(self: *SimpleNetwork) StartError!void {
        switch (self._start(self)) {
            .success => {},
            .already_started => return Error.AlreadyStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Changes the state of a network interface from "started" to "stopped".
    pub fn stop(self: *SimpleNetwork) StopError!void {
        switch (self._stop(self)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Resets a network adapter and allocates the transmit and receive buffers required by the network interface.
    pub fn initialize(
        self: *SimpleNetwork,
        extra_rx_buffer_size: usize,
        extra_tx_buffer_size: usize,
    ) InitializeError!void {
        switch (self._initialize(self, extra_rx_buffer_size, extra_tx_buffer_size)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .out_of_resources => return Error.OutOfResources,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Resets a network adapter and reinitializes it with the parameters that were provided in the previous call to initialize().
    pub fn reset(self: *SimpleNetwork, extended_verification: bool) ResetError!void {
        switch (self._reset(self, extended_verification)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Resets a network adapter and leaves it in a state that is safe for another driver to initialize.
    pub fn shutdown(self: *SimpleNetwork) ShutdownError!void {
        switch (self._shutdown(self)) {
            .success => {},
            .not_started => return ShutdownError.NotStarted,
            .invalid_parameter => return ShutdownError.InvalidParameter,
            .device_error => return ShutdownError.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Manages the multicast receive filters of a network interface.
    pub fn receiveFilters(
        self: *SimpleNetwork,
        enable: ReceiveFilter,
        disable: ReceiveFilter,
        reset_mcast_filter: bool,
        mcast_filter: ?[]const MacAddress,
    ) ReceiveFiltersError!void {
        const count: usize, const ptr: ?[*]const MacAddress =
            if (mcast_filter) |f|
                .{ f.len, f.ptr }
            else
                .{ 0, null };

        switch (self._receive_filters(self, enable, disable, reset_mcast_filter, count, ptr)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Modifies or resets the current station address, if supported.
    pub fn stationAddress(
        self: *SimpleNetwork,
        reset_flag: bool,
        new: ?*const MacAddress,
    ) StationAddressError!void {
        switch (self._station_address(self, reset_flag, new)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn resetStatistics(self: *SimpleNetwork) StatisticsError!void {
        switch (self._statistics(self, true, null, null)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Resets or collects the statistics on a network interface.
    pub fn statistics(self: *SimpleNetwork, reset_flag: bool) StatisticsError!Statistics {
        var stats: Statistics = undefined;
        var stats_size: usize = @sizeOf(Statistics);
        switch (self._statistics(self, reset_flag, &stats_size, &stats)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }

        if (stats_size != @sizeOf(Statistics))
            return error.Unexpected
        else
            return stats;
    }

    /// Converts a multicast IP address to a multicast HW MAC address.
    pub fn mcastIpToMac(
        self: *SimpleNetwork,
        ipv6: bool,
        ip: *const anyopaque,
    ) McastIpToMacError!MacAddress {
        var mac: MacAddress = undefined;
        switch (self._mcast_ip_to_mac(self, ipv6, ip, &mac)) {
            .success => return mac,
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Performs read and write operations on the NVRAM device attached to a network interface.
    pub fn nvData(
        self: *SimpleNetwork,
        read_write: NvDataOperation,
        offset: usize,
        buffer: []u8,
    ) NvDataError!void {
        switch (self._nvdata(
            self,
            // if ReadWrite is TRUE, a read operation is performed
            read_write == .read,
            offset,
            buffer.len,
            buffer.ptr,
        )) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Reads the current interrupt status and recycled transmit buffer status from a network interface.
    pub fn getStatus(
        self: *SimpleNetwork,
        interrupt_status: ?*InterruptStatus,
        recycled_tx_buf: ?*?[*]u8,
    ) GetStatusError!void {
        switch (self._get_status(self, interrupt_status, recycled_tx_buf)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Places a packet in the transmit queue of a network interface.
    pub fn transmit(
        self: *SimpleNetwork,
        header_size: usize,
        buffer: []const u8,
        src_addr: ?*const MacAddress,
        dest_addr: ?*const MacAddress,
        protocol: ?*const u16,
    ) TransmitError!void {
        switch (self._transmit(
            self,
            header_size,
            buffer.len,
            buffer.ptr,
            src_addr,
            dest_addr,
            protocol,
        )) {
            .success => {},
            .not_started => return Error.NotStarted,
            .not_ready => return Error.NotReady,
            .buffer_too_small => return Error.BufferTooSmall,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Receives a packet from a network interface.
    pub fn receive(self: *SimpleNetwork, buffer: []u8) ReceiveError!Packet {
        var packet: Packet = undefined;
        packet.buffer = buffer;

        switch (self._receive(
            self,
            &packet.header_size,
            &packet.buffer.len,
            packet.buffer.ptr,
            &packet.src_addr,
            &packet.dst_addr,
            &packet.protocol,
        )) {
            .success => return packet,
            .not_started => return Error.NotStarted,
            .not_ready => return Error.NotReady,
            .buffer_too_small => return Error.BufferTooSmall,
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0xa19832b9,
        .time_mid = 0xac25,
        .time_high_and_version = 0x11d3,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x2d,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
    };

    pub const NvDataOperation = enum {
        read,
        write,
    };

    pub const MacAddress = [32]u8;

    pub const Mode = extern struct {
        state: State,
        hw_address_size: u32,
        media_header_size: u32,
        max_packet_size: u32,
        nvram_size: u32,
        nvram_access_size: u32,
        receive_filter_mask: ReceiveFilter,
        receive_filter_setting: ReceiveFilter,
        max_mcast_filter_count: u32,
        mcast_filter_count: u32,
        mcast_filter: [16]MacAddress,
        current_address: MacAddress,
        broadcast_address: MacAddress,
        permanent_address: MacAddress,
        if_type: u8,
        mac_address_changeable: bool,
        multiple_tx_supported: bool,
        media_present_supported: bool,
        media_present: bool,
    };

    pub const ReceiveFilter = packed struct(u32) {
        receive_unicast: bool,
        receive_multicast: bool,
        receive_broadcast: bool,
        receive_promiscuous: bool,
        receive_promiscuous_multicast: bool,
        _pad: u27 = 0,
    };

    pub const State = enum(u32) {
        stopped,
        started,
        initialized,
    };

    pub const Statistics = extern struct {
        rx_total_frames: u64,
        rx_good_frames: u64,
        rx_undersize_frames: u64,
        rx_oversize_frames: u64,
        rx_dropped_frames: u64,
        rx_unicast_frames: u64,
        rx_broadcast_frames: u64,
        rx_multicast_frames: u64,
        rx_crc_error_frames: u64,
        rx_total_bytes: u64,
        tx_total_frames: u64,
        tx_good_frames: u64,
        tx_undersize_frames: u64,
        tx_oversize_frames: u64,
        tx_dropped_frames: u64,
        tx_unicast_frames: u64,
        tx_broadcast_frames: u64,
        tx_multicast_frames: u64,
        tx_crc_error_frames: u64,
        tx_total_bytes: u64,
        collisions: u64,
        unsupported_protocol: u64,
        rx_duplicated_frames: u64,
        rx_decryptError_frames: u64,
        tx_error_frames: u64,
        tx_retry_frames: u64,
    };

    pub const InterruptStatus = packed struct(u32) {
        receive_interrupt: bool,
        transmit_interrupt: bool,
        command_interrupt: bool,
        software_interrupt: bool,
        _pad: u28 = 0,
    };

    pub const Packet = struct {
        header_size: usize,
        buffer: []u8,
        src_addr: MacAddress,
        dst_addr: MacAddress,
        protocol: u16,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Event = uefi.Event;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// Protocol for mice.
pub const SimplePointer = struct {
    _reset: *const fn (*SimplePointer, bool) callconv(cc) Status,
    _get_state: *const fn (*const SimplePointer, *State) callconv(cc) Status,
    wait_for_input: Event,
    mode: *Mode,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const GetStateError = uefi.UnexpectedError || error{
        NotReady,
        DeviceError,
    };

    /// Resets the pointer device hardware.
    pub fn reset(self: *SimplePointer, verify: bool) ResetError!void {
        switch (self._reset(self, verify)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Retrieves the current state of a pointer device.
    pub fn getState(self: *const SimplePointer) GetStateError!State {
        var state: State = undefined;
        switch (self._get_state(self, &state)) {
            .success => return state,
            .not_ready => return Error.NotReady,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x31878c87,
        .time_mid = 0x0b75,
        .time_high_and_version = 0x11d5,
        .clock_seq_high_and_reserved = 0x9a,
        .clock_seq_low = 0x4f,
        .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
    };

    pub const Mode = struct {
        resolution_x: u64,
        resolution_y: u64,
        resolution_z: u64,
        left_button: bool,
        right_button: bool,
    };

    pub const State = struct {
        relative_movement_x: i32,
        relative_movement_y: i32,
        relative_movement_z: i32,
        left_button: bool,
        right_button: bool,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Event = uefi.Event;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// Character input devices, e.g. Keyboard
pub const SimpleTextInputEx = extern struct {
    _reset: *const fn (*SimpleTextInputEx, bool) callconv(cc) Status,
    _read_key_stroke_ex: *const fn (*SimpleTextInputEx, *Key) callconv(cc) Status,
    wait_for_key_ex: Event,
    _set_state: *const fn (*SimpleTextInputEx, *const u8) callconv(cc) Status,
    _register_key_notify: *const fn (*SimpleTextInputEx, *const Key, *const fn (*const Key) callconv(cc) Status, **anyopaque) callconv(cc) Status,
    _unregister_key_notify: *const fn (*SimpleTextInputEx, *const anyopaque) callconv(cc) Status,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const ReadKeyStrokeError = uefi.UnexpectedError || error{
        NotReady,
        DeviceError,
        Unsupported,
    };
    pub const SetStateError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const RegisterKeyNotifyError = uefi.UnexpectedError || error{OutOfResources};
    pub const UnregisterKeyNotifyError = uefi.UnexpectedError || error{InvalidParameter};

    /// Resets the input device hardware.
    pub fn reset(self: *SimpleTextInputEx, verify: bool) ResetError!void {
        switch (self._reset(self, verify)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Reads the next keystroke from the input device.
    pub fn readKeyStroke(self: *SimpleTextInputEx) ReadKeyStrokeError!Key {
        var key: Key = undefined;
        switch (self._read_key_stroke_ex(self, &key)) {
            .success => return key,
            .not_ready => return Error.NotReady,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Set certain state for the input device.
    pub fn setState(self: *SimpleTextInputEx, state: *const Key.State.Toggle) SetStateError!void {
        switch (self._set_state(self, @ptrCast(state))) {
            .success => {},
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Register a notification function for a particular keystroke for the input device.
    pub fn registerKeyNotify(
        self: *SimpleTextInputEx,
        key_data: *const Key,
        notify: *const fn (*const Key) callconv(cc) Status,
    ) RegisterKeyNotifyError!uefi.Handle {
        var handle: uefi.Handle = undefined;
        switch (self._register_key_notify(self, key_data, notify, &handle)) {
            .success => return handle,
            .out_of_resources => return Error.OutOfResources,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Remove the notification that was previously registered.
    pub fn unregisterKeyNotify(
        self: *SimpleTextInputEx,
        handle: uefi.Handle,
    ) UnregisterKeyNotifyError!void {
        switch (self._unregister_key_notify(self, handle)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0xdd9e7534,
        .time_mid = 0x7762,
        .time_high_and_version = 0x4698,
        .clock_seq_high_and_reserved = 0x8c,
        .clock_seq_low = 0x14,
        .node = [_]u8{ 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa },
    };

    pub const Key = extern struct {
        input: Input,
        state: State,

        pub const State = extern struct {
            shift: Shift,
            toggle: Toggle,

            pub const Shift = packed struct(u32) {
                right_shift_pressed: bool,
                left_shift_pressed: bool,
                right_control_pressed: bool,
                left_control_pressed: bool,
                right_alt_pressed: bool,
                left_alt_pressed: bool,
                right_logo_pressed: bool,
                left_logo_pressed: bool,
                menu_key_pressed: bool,
                sys_req_pressed: bool,
                _pad: u21 = 0,
                shift_state_valid: bool,
            };

            pub const Toggle = packed struct(u8) {
                scroll_lock_active: bool,
                num_lock_active: bool,
                caps_lock_active: bool,
                _pad: u3 = 0,
                key_state_exposed: bool,
                toggle_state_valid: bool,
            };
        };

        pub const Input = extern struct {
            scan_code: u16,
            unicode_char: u16,
        };
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Event = uefi.Event;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// Character input devices, e.g. Keyboard
pub const SimpleTextInput = extern struct {
    _reset: *const fn (*SimpleTextInput, bool) callconv(cc) Status,
    _read_key_stroke: *const fn (*SimpleTextInput, *Key.Input) callconv(cc) Status,
    wait_for_key: Event,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const ReadKeyStrokeError = uefi.UnexpectedError || error{
        NotReady,
        DeviceError,
        Unsupported,
    };

    /// Resets the input device hardware.
    pub fn reset(self: *SimpleTextInput, verify: bool) ResetError!void {
        switch (self._reset(self, verify)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Reads the next keystroke from the input device.
    pub fn readKeyStroke(self: *SimpleTextInput) ReadKeyStrokeError!Key.Input {
        var key: Key.Input = undefined;
        switch (self._read_key_stroke(self, &key)) {
            .success => return key,
            .not_ready => return Error.NotReady,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x387477c1,
        .time_mid = 0x69c7,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x39,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };

    pub const Key = uefi.protocol.SimpleTextInputEx.Key;
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// Character output devices
pub const SimpleTextOutput = extern struct {
    _reset: *const fn (*SimpleTextOutput, bool) callconv(cc) Status,
    _output_string: *const fn (*SimpleTextOutput, [*:0]const u16) callconv(cc) Status,
    _test_string: *const fn (*const SimpleTextOutput, [*:0]const u16) callconv(cc) Status,
    _query_mode: *const fn (*const SimpleTextOutput, usize, *usize, *usize) callconv(cc) Status,
    _set_mode: *const fn (*SimpleTextOutput, usize) callconv(cc) Status,
    _set_attribute: *const fn (*SimpleTextOutput, usize) callconv(cc) Status,
    _clear_screen: *const fn (*SimpleTextOutput) callconv(cc) Status,
    _set_cursor_position: *const fn (*SimpleTextOutput, usize, usize) callconv(cc) Status,
    _enable_cursor: *const fn (*SimpleTextOutput, bool) callconv(cc) Status,
    mode: *Mode,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const OutputStringError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const QueryModeError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const SetModeError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const SetAttributeError = uefi.UnexpectedError || error{DeviceError};
    pub const ClearScreenError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const SetCursorPositionError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const EnableCursorError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };

    /// Resets the text output device hardware.
    pub fn reset(self: *SimpleTextOutput, verify: bool) ResetError!void {
        switch (self._reset(self, verify)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Writes a string to the output device.
    ///
    /// Returns `true` if the string was successfully written, `false` if an unknown glyph was encountered.
    pub fn outputString(self: *SimpleTextOutput, msg: [*:0]const u16) OutputStringError!bool {
        switch (self._output_string(self, msg)) {
            .success => return true,
            .warn_unknown_glyph => return false,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Verifies that all characters in a string can be output to the target device.
    pub fn testString(self: *const SimpleTextOutput, msg: [*:0]const u16) uefi.UnexpectedError!bool {
        switch (self._test_string(self, msg)) {
            .success => return true,
            .unsupported => return false,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Returns information for an available text mode that the output device(s) supports.
    pub fn queryMode(self: *const SimpleTextOutput, mode_number: usize) QueryModeError!Geometry {
        var geo: Geometry = undefined;
        switch (self._query_mode(self, mode_number, &geo.columns, &geo.rows)) {
            .success => return geo,
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Sets the output device(s) to a specified mode.
    pub fn setMode(self: *SimpleTextOutput, mode_number: usize) SetModeError!void {
        switch (self._set_mode(self, mode_number)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Sets the background and foreground colors for the outputString() and clearScreen() functions.
    pub fn setAttribute(self: *SimpleTextOutput, attribute: Attribute) SetAttributeError!void {
        const attr_as_num: u8 = @bitCast(attribute);
        switch (self._set_attribute(self, @intCast(attr_as_num))) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Clears the output device(s) display to the currently selected background color.
    pub fn clearScreen(self: *SimpleTextOutput) ClearScreenError!void {
        switch (self._clear_screen(self)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Sets the current coordinates of the cursor position.
    pub fn setCursorPosition(
        self: *SimpleTextOutput,
        column: usize,
        row: usize,
    ) SetCursorPositionError!void {
        switch (self._set_cursor_position(self, column, row)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Makes the cursor visible or invisible.
    pub fn enableCursor(self: *SimpleTextOutput, visible: bool) EnableCursorError!void {
        switch (self._enable_cursor(self, visible)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x387477c2,
        .time_mid = 0x69c7,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x39,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };
    pub const boxdraw_horizontal: u16 = 0x2500;
    pub const boxdraw_vertical: u16 = 0x2502;
    pub const boxdraw_down_right: u16 = 0x250c;
    pub const boxdraw_down_left: u16 = 0x2510;
    pub const boxdraw_up_right: u16 = 0x2514;
    pub const boxdraw_up_left: u16 = 0x2518;
    pub const boxdraw_vertical_right: u16 = 0x251c;
    pub const boxdraw_vertical_left: u16 = 0x2524;
    pub const boxdraw_down_horizontal: u16 = 0x252c;
    pub const boxdraw_up_horizontal: u16 = 0x2534;
    pub const boxdraw_vertical_horizontal: u16 = 0x253c;
    pub const boxdraw_double_horizontal: u16 = 0x2550;
    pub const boxdraw_double_vertical: u16 = 0x2551;
    pub const boxdraw_down_right_double: u16 = 0x2552;
    pub const boxdraw_down_double_right: u16 = 0x2553;
    pub const boxdraw_double_down_right: u16 = 0x2554;
    pub const boxdraw_down_left_double: u16 = 0x2555;
    pub const boxdraw_down_double_left: u16 = 0x2556;
    pub const boxdraw_double_down_left: u16 = 0x2557;
    pub const boxdraw_up_right_double: u16 = 0x2558;
    pub const boxdraw_up_double_right: u16 = 0x2559;
    pub const boxdraw_double_up_right: u16 = 0x255a;
    pub const boxdraw_up_left_double: u16 = 0x255b;
    pub const boxdraw_up_double_left: u16 = 0x255c;
    pub const boxdraw_double_up_left: u16 = 0x255d;
    pub const boxdraw_vertical_right_double: u16 = 0x255e;
    pub const boxdraw_vertical_double_right: u16 = 0x255f;
    pub const boxdraw_double_vertical_right: u16 = 0x2560;
    pub const boxdraw_vertical_left_double: u16 = 0x2561;
    pub const boxdraw_vertical_double_left: u16 = 0x2562;
    pub const boxdraw_double_vertical_left: u16 = 0x2563;
    pub const boxdraw_down_horizontal_double: u16 = 0x2564;
    pub const boxdraw_down_double_horizontal: u16 = 0x2565;
    pub const boxdraw_double_down_horizontal: u16 = 0x2566;
    pub const boxdraw_up_horizontal_double: u16 = 0x2567;
    pub const boxdraw_up_double_horizontal: u16 = 0x2568;
    pub const boxdraw_double_up_horizontal: u16 = 0x2569;
    pub const boxdraw_vertical_horizontal_double: u16 = 0x256a;
    pub const boxdraw_vertical_double_horizontal: u16 = 0x256b;
    pub const boxdraw_double_vertical_horizontal: u16 = 0x256c;
    pub const blockelement_full_block: u16 = 0x2588;
    pub const blockelement_light_shade: u16 = 0x2591;
    pub const geometricshape_up_triangle: u16 = 0x25b2;
    pub const geometricshape_right_triangle: u16 = 0x25ba;
    pub const geometricshape_down_triangle: u16 = 0x25bc;
    pub const geometricshape_left_triangle: u16 = 0x25c4;
    pub const arrow_up: u16 = 0x2591;
    pub const arrow_down: u16 = 0x2593;

    pub const Attribute = packed struct(u8) {
        foreground: ForegroundColor = .white,
        background: BackgroundColor = .black,

        pub const ForegroundColor = enum(u4) {
            black,
            blue,
            green,
            cyan,
            red,
            magenta,
            brown,
            lightgray,
            darkgray,
            lightblue,
            lightgreen,
            lightcyan,
            lightred,
            lightmagenta,
            yellow,
            white,
        };

        pub const BackgroundColor = enum(u4) {
            black,
            blue,
            green,
            cyan,
            red,
            magenta,
            brown,
            lightgray,
        };
    };

    pub const Mode = extern struct {
        max_mode: u32, // specified as signed
        mode: u32, // specified as signed
        attribute: i32,
        cursor_column: i32,
        cursor_row: i32,
        cursor_visible: bool,
    };

    pub const Geometry = struct {
        columns: usize,
        rows: usize,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Event = uefi.Event;
const Status = uefi.Status;
const Time = uefi.Time;
const Ip6 = uefi.protocol.Ip6;
const ManagedNetworkConfigData = uefi.protocol.ManagedNetwork.Config;
const SimpleNetwork = uefi.protocol.SimpleNetwork;
const cc = uefi.cc;
const Error = Status.Error;

pub const Udp6 = extern struct {
    _get_mode_data: *const fn (*const Udp6, ?*Config, ?*Ip6.Mode, ?*ManagedNetworkConfigData, ?*SimpleNetwork) callconv(cc) Status,
    _configure: *const fn (*const Udp6, ?*const Config) callconv(cc) Status,
    _groups: *const fn (*const Udp6, bool, ?*const Ip6.Address) callconv(cc) Status,
    _transmit: *const fn (*const Udp6, *CompletionToken) callconv(cc) Status,
    _receive: *const fn (*const Udp6, *CompletionToken) callconv(cc) Status,
    _cancel: *const fn (*const Udp6, ?*CompletionToken) callconv(cc) Status,
    _poll: *const fn (*const Udp6) callconv(cc) Status,

    pub const GetModeDataError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
    };
    pub const ConfigureError = uefi.UnexpectedError || error{
        NoMapping,
        InvalidParameter,
        AlreadyStarted,
        AccessDenied,
        OutOfResources,
        DeviceError,
    };
    pub const GroupsError = uefi.UnexpectedError || error{
        NotStarted,
        OutOfResources,
        InvalidParameter,
        AlreadyStarted,
        NotFound,
        DeviceError,
    };
    pub const TransmitError = uefi.UnexpectedError || error{
        NotStarted,
        NoMapping,
        InvalidParameter,
        AccessDenied,
        NotReady,
        OutOfResources,
        NotFound,
        BadBufferSize,
        NoMedia,
    };
    pub const ReceiveError = uefi.UnexpectedError || error{
        NotStarted,
        NoMapping,
        InvalidParameter,
        OutOfResources,
        DeviceError,
        AccessDenied,
        NotReady,
        NoMedia,
    };
    pub const CancelError = uefi.UnexpectedError || error{
        InvalidParameter,
        NotStarted,
        NotFound,
    };
    pub const PollError = uefi.UnexpectedError || error{
        InvalidParameter,
        DeviceError,
        Timeout,
    };

    pub fn getModeData(self: *const Udp6) GetModeDataError!ModeData {
        var data: ModeData = undefined;
        switch (self._get_mode_data(
            self,
            &data.udp6_config_data,
            &data.ip6_mode_data,
            &data.mnp_config_data,
            &data.snp_mode_data,
        )) {
            .success => return data,
            .not_started => return Error.NotStarted,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn configure(self: *Udp6, udp6_config_data: ?*const Config) ConfigureError!void {
        switch (self._configure(self, udp6_config_data)) {
            .success => {},
            .no_mapping => return Error.NoMapping,
            .invalid_parameter => return Error.InvalidParameter,
            .already_started => return Error.AlreadyStarted,
            .access_denied => return Error.AccessDenied,
            .out_of_resources => return Error.OutOfResources,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn groups(
        self: *Udp6,
        join_flag: JoinFlag,
        multicast_address: ?*const Ip6.Address,
    ) GroupsError!void {
        switch (self._groups(
            self,
            // set to TRUE to join a multicast group
            join_flag == .join,
            multicast_address,
        )) {
            .success => {},
            .not_started => return Error.NotStarted,
            .out_of_resources => return Error.OutOfResources,
            .invalid_parameter => return Error.InvalidParameter,
            .already_started => return Error.AlreadyStarted,
            .not_found => return Error.NotFound,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn transmit(self: *Udp6, token: *CompletionToken) TransmitError!void {
        switch (self._transmit(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .no_mapping => return Error.NoMapping,
            .invalid_parameter => return Error.InvalidParameter,
            .access_denied => return Error.AccessDenied,
            .not_ready => return Error.NotReady,
            .out_of_resources => return Error.OutOfResources,
            .not_found => return Error.NotFound,
            .bad_buffer_size => return Error.BadBufferSize,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn receive(self: *Udp6, token: *CompletionToken) ReceiveError!void {
        switch (self._receive(self, token)) {
            .success => {},
            .not_started => return Error.NotStarted,
            .no_mapping => return Error.NoMapping,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            .device_error => return Error.DeviceError,
            .access_denied => return Error.AccessDenied,
            .not_ready => return Error.NotReady,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn cancel(self: *Udp6, token: ?*CompletionToken) CancelError!void {
        switch (self._cancel(self, token)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .not_started => return Error.NotStarted,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn poll(self: *Udp6) PollError!void {
        switch (self._poll(self)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .device_error => return Error.DeviceError,
            .timeout => return Error.Timeout,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = uefi.Guid{
        .time_low = 0x4f948815,
        .time_mid = 0xb4b9,
        .time_high_and_version = 0x43cb,
        .clock_seq_high_and_reserved = 0x8a,
        .clock_seq_low = 0x33,
        .node = [_]u8{ 0x90, 0xe0, 0x60, 0xb3, 0x49, 0x55 },
    };

    pub const JoinFlag = enum {
        join,
        leave,
    };

    pub const ModeData = struct {
        udp6_config_data: Config,
        ip6_mode_data: Ip6.Mode,
        mnp_config_data: ManagedNetworkConfigData,
        snp_mode_data: SimpleNetwork,
    };

    pub const Config = extern struct {
        accept_promiscuous: bool,
        accept_any_port: bool,
        allow_duplicate_port: bool,
        traffic_class: u8,
        hop_limit: u8,
        receive_timeout: u32,
        transmit_timeout: u32,
        station_address: Ip6.Address,
        station_port: u16,
        remote_address: Ip6.Address,
        remote_port: u16,
    };

    pub const CompletionToken = extern struct {
        event: Event,
        status: usize,
        packet: extern union {
            rx_data: *ReceiveData,
            tx_data: *TransmitData,
        },
    };

    pub const ReceiveData = extern struct {
        timestamp: Time,
        recycle_signal: Event,
        udp6_session: SessionData,
        data_length: u32,
        fragment_count: u32,

        pub fn getFragments(self: *ReceiveData) []Fragment {
            return @as([*]Fragment, @ptrCast(@alignCast(@as([*]u8, @ptrCast(self)) + @sizeOf(ReceiveData))))[0..self.fragment_count];
        }
    };

    pub const TransmitData = extern struct {
        udp6_session_data: ?*SessionData,
        data_length: u32,
        fragment_count: u32,

        pub fn getFragments(self: *TransmitData) []Fragment {
            return @as([*]Fragment, @ptrCast(@alignCast(@as([*]u8, @ptrCast(self)) + @sizeOf(TransmitData))))[0..self.fragment_count];
        }
    };

    pub const SessionData = extern struct {
        source_address: Ip6.Address,
        source_port: u16,
        destination_address: Ip6.Address,
        destination_port: u16,
    };

    pub const Fragment = extern struct {
        fragment_length: u32,
        fragment_buffer: [*]u8,
    };
};
const testing = @import("std").testing;

const high_bit = 1 << @typeInfo(usize).int.bits - 1;

pub const Status = enum(usize) {
    /// The operation completed successfully.
    success = 0,

    /// The image failed to load.
    load_error = high_bit | 1,

    /// A parameter was incorrect.
    invalid_parameter = high_bit | 2,

    /// The operation is not supported.
    unsupported = high_bit | 3,

    /// The buffer was not the proper size for the request.
    bad_buffer_size = high_bit | 4,

    /// The buffer is not large enough to hold the requested data. The required buffer size is returned in the appropriate parameter when this error occurs.
    buffer_too_small = high_bit | 5,

    /// There is no data pending upon return.
    not_ready = high_bit | 6,

    /// The physical device reported an error while attempting the operation.
    device_error = high_bit | 7,

    /// The device cannot be written to.
    write_protected = high_bit | 8,

    /// A resource has run out.
    out_of_resources = high_bit | 9,

    /// An inconstancy was detected on the file system causing the operating to fail.
    volume_corrupted = high_bit | 10,

    /// There is no more space on the file system.
    volume_full = high_bit | 11,

    /// The device does not contain any medium to perform the operation.
    no_media = high_bit | 12,

    /// The medium in the device has changed since the last access.
    media_changed = high_bit | 13,

    /// The item was not found.
    not_found = high_bit | 14,

    /// Access was denied.
    access_denied = high_bit | 15,

    /// The server was not found or did not respond to the request.
    no_response = high_bit | 16,

    /// A mapping to a device does not exist.
    no_mapping = high_bit | 17,

    /// The timeout time expired.
    timeout = high_bit | 18,

    /// The protocol has not been started.
    not_started = high_bit | 19,

    /// The protocol has already been started.
    already_started = high_bit | 20,

    /// The operation was aborted.
    aborted = high_bit | 21,

    /// An ICMP error occurred during the network operation.
    icmp_error = high_bit | 22,

    /// A TFTP error occurred during the network operation.
    tftp_error = high_bit | 23,

    /// A protocol error occurred during the network operation.
    protocol_error = high_bit | 24,

    /// The function encountered an internal version that was incompatible with a version requested by the caller.
    incompatible_version = high_bit | 25,

    /// The function was not performed due to a security violation.
    security_violation = high_bit | 26,

    /// A CRC error was detected.
    crc_error = high_bit | 27,

    /// Beginning or end of media was reached
    end_of_media = high_bit | 28,

    /// The end of the file was reached.
    end_of_file = high_bit | 31,

    /// The language specified was invalid.
    invalid_language = high_bit | 32,

    /// The security status of the data is unknown or compromised and the data must be updated or replaced to restore a valid security status.
    compromised_data = high_bit | 33,

    /// There is an address conflict address allocation
    ip_address_conflict = high_bit | 34,

    /// A HTTP error occurred during the network operation.
    http_error = high_bit | 35,

    network_unreachable = high_bit | 100,

    host_unreachable = high_bit | 101,

    protocol_unreachable = high_bit | 102,

    port_unreachable = high_bit | 103,

    connection_fin = high_bit | 104,

    connection_reset = high_bit | 105,

    connection_refused = high_bit | 106,

    /// The string contained one or more characters that the device could not render and were skipped.
    warn_unknown_glyph = 1,

    /// The handle was closed, but the file was not deleted.
    warn_delete_failure = 2,

    /// The handle was closed, but the data to the file was not flushed properly.
    warn_write_failure = 3,

    /// The resulting buffer was too small, and the data was truncated to the buffer size.
    warn_buffer_too_small = 4,

    /// The data has not been updated within the timeframe set by localpolicy for this type of data.
    warn_stale_data = 5,

    /// The resulting buffer contains UEFI-compliant file system.
    warn_file_system = 6,

    /// The operation will be processed across a system reset.
    warn_reset_required = 7,

    _,

    pub const Error = error{
        LoadError,
        InvalidParameter,
        Unsupported,
        BadBufferSize,
        BufferTooSmall,
        NotReady,
        DeviceError,
        WriteProtected,
        OutOfResources,
        VolumeCorrupted,
        VolumeFull,
        NoMedia,
        MediaChanged,
        NotFound,
        AccessDenied,
        NoResponse,
        NoMapping,
        Timeout,
        NotStarted,
        AlreadyStarted,
        Aborted,
        IcmpError,
        TftpError,
        ProtocolError,
        IncompatibleVersion,
        SecurityViolation,
        CrcError,
        EndOfMedia,
        EndOfFile,
        InvalidLanguage,
        CompromisedData,
        IpAddressConflict,
        HttpError,
        NetworkUnreachable,
        HostUnreachable,
        ProtocolUnreachable,
        PortUnreachable,
        ConnectionFin,
        ConnectionReset,
        ConnectionRefused,
    };

    pub fn err(self: Status) Error!void {
        switch (self) {
            .load_error => return error.LoadError,
            .invalid_parameter => return error.InvalidParameter,
            .unsupported => return error.Unsupported,
            .bad_buffer_size => return error.BadBufferSize,
            .buffer_too_small => return error.BufferTooSmall,
            .not_ready => return error.NotReady,
            .device_error => return error.DeviceError,
            .write_protected => return error.WriteProtected,
            .out_of_resources => return error.OutOfResources,
            .volume_corrupted => return error.VolumeCorrupted,
            .volume_full => return error.VolumeFull,
            .no_media => return error.NoMedia,
            .media_changed => return error.MediaChanged,
            .not_found => return error.NotFound,
            .access_denied => return error.AccessDenied,
            .no_response => return error.NoResponse,
            .no_mapping => return error.NoMapping,
            .timeout => return error.Timeout,
            .not_started => return error.NotStarted,
            .already_started => return error.AlreadyStarted,
            .aborted => return error.Aborted,
            .icmp_error => return error.IcmpError,
            .tftp_error => return error.TftpError,
            .protocol_error => return error.ProtocolError,
            .incompatible_version => return error.IncompatibleVersion,
            .security_violation => return error.SecurityViolation,
            .crc_error => return error.CrcError,
            .end_of_media => return error.EndOfMedia,
            .end_of_file => return error.EndOfFile,
            .invalid_language => return error.InvalidLanguage,
            .compromised_data => return error.CompromisedData,
            .ip_address_conflict => return error.IpAddressConflict,
            .http_error => return error.HttpError,
            .network_unreachable => return error.NetworkUnreachable,
            .host_unreachable => return error.HostUnreachable,
            .protocol_unreachable => return error.ProtocolUnreachable,
            .port_unreachable => return error.PortUnreachable,
            .connection_fin => return error.ConnectionFin,
            .connection_reset => return error.ConnectionReset,
            .connection_refused => return error.ConnectionRefused,
            // success, warn_*, _
            else => {},
        }
    }

    pub fn fromError(e: Error) Status {
        return switch (e) {
            Error.Aborted => .aborted,
            Error.AccessDenied => .access_denied,
            Error.AlreadyStarted => .already_started,
            Error.BadBufferSize => .bad_buffer_size,
            Error.BufferTooSmall => .buffer_too_small,
            Error.CompromisedData => .compromised_data,
            Error.ConnectionFin => .connection_fin,
            Error.ConnectionRefused => .connection_refused,
            Error.ConnectionReset => .connection_reset,
            Error.CrcError => .crc_error,
            Error.DeviceError => .device_error,
            Error.EndOfFile => .end_of_file,
            Error.EndOfMedia => .end_of_media,
            Error.HostUnreachable => .host_unreachable,
            Error.HttpError => .http_error,
            Error.IcmpError => .icmp_error,
            Error.IncompatibleVersion => .incompatible_version,
            Error.InvalidLanguage => .invalid_language,
            Error.InvalidParameter => .invalid_parameter,
            Error.IpAddressConflict => .ip_address_conflict,
            Error.LoadError => .load_error,
            Error.MediaChanged => .media_changed,
            Error.NetworkUnreachable => .network_unreachable,
            Error.NoMapping => .no_mapping,
            Error.NoMedia => .no_media,
            Error.NoResponse => .no_response,
            Error.NotFound => .not_found,
            Error.NotReady => .not_ready,
            Error.NotStarted => .not_started,
            Error.OutOfResources => .out_of_resources,
            Error.PortUnreachable => .port_unreachable,
            Error.ProtocolError => .protocol_error,
            Error.ProtocolUnreachable => .protocol_unreachable,
            Error.SecurityViolation => .security_violation,
            Error.TftpError => .tftp_error,
            Error.Timeout => .timeout,
            Error.Unsupported => .unsupported,
            Error.VolumeCorrupted => .volume_corrupted,
            Error.VolumeFull => .volume_full,
            Error.WriteProtected => .write_protected,
        };
    }
};

test "status" {
    var st: Status = .device_error;
    try testing.expectError(error.DeviceError, st.err());
    try testing.expectEqual(st, Status.fromError(st.err()));

    st = .success;
    try st.err();

    st = .warn_unknown_glyph;
    try st.err();
}
pub const BootServices = @import("tables/boot_services.zig").BootServices;
pub const RuntimeServices = @import("tables/runtime_services.zig").RuntimeServices;
pub const ConfigurationTable = @import("tables/configuration_table.zig").ConfigurationTable;
pub const SystemTable = @import("tables/system_table.zig").SystemTable;
pub const TableHeader = @import("tables/table_header.zig").TableHeader;

pub const EventNotify = *const fn (event: Event, ctx: *anyopaque) callconv(cc) void;

pub const TimerDelay = enum(u32) {
    timer_cancel,
    timer_periodic,
    timer_relative,
};

pub const MemoryType = enum(u32) {
    reserved_memory_type,
    loader_code,
    loader_data,
    boot_services_code,
    boot_services_data,
    runtime_services_code,
    runtime_services_data,
    conventional_memory,
    unusable_memory,
    acpi_reclaim_memory,
    acpi_memory_nvs,
    memory_mapped_io,
    memory_mapped_io_port_space,
    pal_code,
    persistent_memory,
    max_memory_type,
    _,
};

pub const MemoryDescriptorAttribute = packed struct(u64) {
    uc: bool,
    wc: bool,
    wt: bool,
    wb: bool,
    uce: bool,
    _pad1: u7 = 0,
    wp: bool,
    rp: bool,
    xp: bool,
    nv: bool,
    more_reliable: bool,
    ro: bool,
    sp: bool,
    cpu_crypto: bool,
    _pad2: u43 = 0,
    memory_runtime: bool,
};

pub const MemoryDescriptor = extern struct {
    type: MemoryType,
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: MemoryDescriptorAttribute,
};

pub const LocateSearchType = enum(u32) {
    all_handles,
    by_register_notify,
    by_protocol,
};

pub const OpenProtocolAttributes = packed struct(u32) {
    by_handle_protocol: bool = false,
    get_protocol: bool = false,
    test_protocol: bool = false,
    by_child_controller: bool = false,
    by_driver: bool = false,
    exclusive: bool = false,
    reserved: u26 = 0,
};

pub const ProtocolInformationEntry = extern struct {
    agent_handle: ?Handle,
    controller_handle: ?Handle,
    attributes: OpenProtocolAttributes,
    open_count: u32,
};

pub const InterfaceType = enum(u32) {
    efi_native_interface,
};

pub const AllocateType = enum(u32) {
    allocate_any_pages,
    allocate_max_address,
    allocate_address,
};

pub const PhysicalAddress = u64;

pub const CapsuleHeader = extern struct {
    capsule_guid: Guid align(8),
    header_size: u32,
    flags: u32,
    capsule_image_size: u32,
};

pub const UefiCapsuleBlockDescriptor = extern struct {
    length: u64,
    address: extern union {
        data_block: PhysicalAddress,
        continuation_pointer: PhysicalAddress,
    },
};

pub const ResetType = enum(u32) {
    reset_cold,
    reset_warm,
    reset_shutdown,
    reset_platform_specific,
};

pub const global_variable align(8) = Guid{
    .time_low = 0x8be4df61,
    .time_mid = 0x93ca,
    .time_high_and_version = 0x11d2,
    .clock_seq_high_and_reserved = 0xaa,
    .clock_seq_low = 0x0d,
    .node = [_]u8{ 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c },
};

test {
    std.testing.refAllDeclsRecursive(@This());
}

const std = @import("std");
const uefi = std.os.uefi;
const Handle = uefi.Handle;
const Event = uefi.Event;
const Guid = uefi.Guid;
const cc = uefi.cc;
const std = @import("std");
const uefi = std.os.uefi;
const Event = uefi.Event;
const Guid = uefi.Guid;
const Handle = uefi.Handle;
const Status = uefi.Status;
const TableHeader = uefi.tables.TableHeader;
const DevicePathProtocol = uefi.protocol.DevicePath;
const AllocateType = uefi.tables.AllocateType;
const MemoryType = uefi.tables.MemoryType;
const MemoryDescriptor = uefi.tables.MemoryDescriptor;
const TimerDelay = uefi.tables.TimerDelay;
const InterfaceType = uefi.tables.InterfaceType;
const LocateSearchType = uefi.tables.LocateSearchType;
const OpenProtocolAttributes = uefi.tables.OpenProtocolAttributes;
const ProtocolInformationEntry = uefi.tables.ProtocolInformationEntry;
const EventNotify = uefi.tables.EventNotify;
const cc = uefi.cc;

/// Boot services are services provided by the system's firmware until the operating system takes
/// over control over the hardware by calling exitBootServices.
///
/// Boot Services must not be used after exitBootServices has been called. The only exception is
/// getMemoryMap, which may be used after the first unsuccessful call to exitBootServices.
/// After successfully calling exitBootServices, system_table.console_in_handle, system_table.con_in,
/// system_table.console_out_handle, system_table.con_out, system_table.standard_error_handle,
/// system_table.std_err, and system_table.boot_services should be set to null. After setting these
/// attributes to null, system_table.hdr.crc32 must be recomputed.
///
/// As the boot_services table may grow with new UEFI versions, it is important to check hdr.header_size.
pub const BootServices = extern struct {
    hdr: TableHeader,

    /// Raises a task's priority level and returns its previous level.
    raiseTpl: *const fn (new_tpl: usize) callconv(cc) usize,

    /// Restores a task's priority level to its previous value.
    restoreTpl: *const fn (old_tpl: usize) callconv(cc) void,

    /// Allocates memory pages from the system.
    allocatePages: *const fn (alloc_type: AllocateType, mem_type: MemoryType, pages: usize, memory: *[*]align(4096) u8) callconv(cc) Status,

    /// Frees memory pages.
    freePages: *const fn (memory: [*]align(4096) u8, pages: usize) callconv(cc) Status,

    /// Returns the current memory map.
    getMemoryMap: *const fn (mmap_size: *usize, mmap: ?[*]MemoryDescriptor, map_key: *usize, descriptor_size: *usize, descriptor_version: *u32) callconv(cc) Status,

    /// Allocates pool memory.
    allocatePool: *const fn (pool_type: MemoryType, size: usize, buffer: *[*]align(8) u8) callconv(cc) Status,

    /// Returns pool memory to the system.
    freePool: *const fn (buffer: [*]align(8) u8) callconv(cc) Status,

    /// Creates an event.
    createEvent: *const fn (type: u32, notify_tpl: usize, notify_func: ?*const fn (Event, ?*anyopaque) callconv(cc) void, notify_ctx: ?*const anyopaque, event: *Event) callconv(cc) Status,

    /// Sets the type of timer and the trigger time for a timer event.
    setTimer: *const fn (event: Event, type: TimerDelay, trigger_time: u64) callconv(cc) Status,

    /// Stops execution until an event is signaled.
    waitForEvent: *const fn (event_len: usize, events: [*]const Event, index: *usize) callconv(cc) Status,

    /// Signals an event.
    signalEvent: *const fn (event: Event) callconv(cc) Status,

    /// Closes an event.
    closeEvent: *const fn (event: Event) callconv(cc) Status,

    /// Checks whether an event is in the signaled state.
    checkEvent: *const fn (event: Event) callconv(cc) Status,

    /// Installs a protocol interface on a device handle. If the handle does not exist, it is created
    /// and added to the list of handles in the system. installMultipleProtocolInterfaces()
    /// performs more error checking than installProtocolInterface(), so its use is recommended over this.
    installProtocolInterface: *const fn (handle: Handle, protocol: *align(8) const Guid, interface_type: InterfaceType, interface: *anyopaque) callconv(cc) Status,

    /// Reinstalls a protocol interface on a device handle
    reinstallProtocolInterface: *const fn (handle: Handle, protocol: *align(8) const Guid, old_interface: *anyopaque, new_interface: *anyopaque) callconv(cc) Status,

    /// Removes a protocol interface from a device handle. Usage of
    /// uninstallMultipleProtocolInterfaces is recommended over this.
    uninstallProtocolInterface: *const fn (handle: Handle, protocol: *align(8) const Guid, interface: *anyopaque) callconv(cc) Status,

    /// Queries a handle to determine if it supports a specified protocol.
    handleProtocol: *const fn (handle: Handle, protocol: *align(8) const Guid, interface: *?*anyopaque) callconv(cc) Status,

    reserved: *anyopaque,

    /// Creates an event that is to be signaled whenever an interface is installed for a specified protocol.
    registerProtocolNotify: *const fn (protocol: *align(8) const Guid, event: Event, registration: **anyopaque) callconv(cc) Status,

    /// Returns an array of handles that support a specified protocol.
    locateHandle: *const fn (search_type: LocateSearchType, protocol: ?*align(8) const Guid, search_key: ?*const anyopaque, buffer_size: *usize, buffer: [*]Handle) callconv(cc) Status,

    /// Locates the handle to a device on the device path that supports the specified protocol
    locateDevicePath: *const fn (protocols: *align(8) const Guid, device_path: **const DevicePathProtocol, device: *?Handle) callconv(cc) Status,

    /// Adds, updates, or removes a configuration table entry from the EFI System Table.
    installConfigurationTable: *const fn (guid: *align(8) const Guid, table: ?*anyopaque) callconv(cc) Status,

    /// Loads an EFI image into memory.
    loadImage: *const fn (boot_policy: bool, parent_image_handle: Handle, device_path: ?*const DevicePathProtocol, source_buffer: ?[*]const u8, source_size: usize, image_handle: *?Handle) callconv(cc) Status,

    /// Transfers control to a loaded image's entry point.
    startImage: *const fn (image_handle: Handle, exit_data_size: ?*usize, exit_data: ?*[*]u16) callconv(cc) Status,

    /// Terminates a loaded EFI image and returns control to boot services.
    exit: *const fn (image_handle: Handle, exit_status: Status, exit_data_size: usize, exit_data: ?*const anyopaque) callconv(cc) Status,

    /// Unloads an image.
    unloadImage: *const fn (image_handle: Handle) callconv(cc) Status,

    /// Terminates all boot services.
    exitBootServices: *const fn (image_handle: Handle, map_key: usize) callconv(cc) Status,

    /// Returns a monotonically increasing count for the platform.
    getNextMonotonicCount: *const fn (count: *u64) callconv(cc) Status,

    /// Induces a fine-grained stall.
    stall: *const fn (microseconds: usize) callconv(cc) Status,

    /// Sets the system's watchdog timer.
    setWatchdogTimer: *const fn (timeout: usize, watchdog_code: u64, data_size: usize, watchdog_data: ?[*]const u16) callconv(cc) Status,

    /// Connects one or more drives to a controller.
    connectController: *const fn (controller_handle: Handle, driver_image_handle: ?Handle, remaining_device_path: ?*DevicePathProtocol, recursive: bool) callconv(cc) Status,

    // Disconnects one or more drivers from a controller
    disconnectController: *const fn (controller_handle: Handle, driver_image_handle: ?Handle, child_handle: ?Handle) callconv(cc) Status,

    /// Queries a handle to determine if it supports a specified protocol.
    openProtocol: *const fn (handle: Handle, protocol: *align(8) const Guid, interface: *?*anyopaque, agent_handle: ?Handle, controller_handle: ?Handle, attributes: OpenProtocolAttributes) callconv(cc) Status,

    /// Closes a protocol on a handle that was opened using openProtocol().
    closeProtocol: *const fn (handle: Handle, protocol: *align(8) const Guid, agent_handle: Handle, controller_handle: ?Handle) callconv(cc) Status,

    /// Retrieves the list of agents that currently have a protocol interface opened.
    openProtocolInformation: *const fn (handle: Handle, protocol: *align(8) const Guid, entry_buffer: *[*]ProtocolInformationEntry, entry_count: *usize) callconv(cc) Status,

    /// Retrieves the list of protocol interface GUIDs that are installed on a handle in a buffer allocated from pool.
    protocolsPerHandle: *const fn (handle: Handle, protocol_buffer: *[*]*align(8) const Guid, protocol_buffer_count: *usize) callconv(cc) Status,

    /// Returns an array of handles that support the requested protocol in a buffer allocated from pool.
    locateHandleBuffer: *const fn (search_type: LocateSearchType, protocol: ?*align(8) const Guid, search_key: ?*const anyopaque, num_handles: *usize, buffer: *[*]Handle) callconv(cc) Status,

    /// Returns the first protocol instance that matches the given protocol.
    locateProtocol: *const fn (protocol: *align(8) const Guid, registration: ?*const anyopaque, interface: *?*anyopaque) callconv(cc) Status,

    /// Installs one or more protocol interfaces into the boot services environment
    // TODO: use callconv(cc) instead once that works
    installMultipleProtocolInterfaces: *const fn (handle: *Handle, ...) callconv(.c) Status,

    /// Removes one or more protocol interfaces into the boot services environment
    // TODO: use callconv(cc) instead once that works
    uninstallMultipleProtocolInterfaces: *const fn (handle: *Handle, ...) callconv(.c) Status,

    /// Computes and returns a 32-bit CRC for a data buffer.
    calculateCrc32: *const fn (data: [*]const u8, data_size: u```
