```
zig");
pub const DevicePath = @import("uefi/device_path.zig").DevicePath;
pub const hii = @import("uefi/hii.zig");

/// Status codes returned by EFI interfaces
pub const Status = @import("uefi/status.zig").Status;
pub const Error = UnexpectedError || Status.Error;
pub const tables = @import("uefi/tables.zig");

/// The memory type to allocate when using the pool.
/// Defaults to `.loader_data`, the default data allocation type
/// used by UEFI applications to allocate pool memory.
pub var efi_pool_memory_type: tables.MemoryType = .loader_data;
pub const pool_allocator = @import("uefi/pool_allocator.zig").pool_allocator;
pub const raw_pool_allocator = @import("uefi/pool_allocator.zig").raw_pool_allocator;

/// The EFI image's handle that is passed to its entry point.
pub var handle: Handle = undefined;

/// A pointer to the EFI System Table that is passed to the EFI image's entry point.
pub var system_table: *tables.SystemTable = undefined;

/// A handle to an event structure.
pub const Event = *opaque {};

/// The calling convention used for all external functions part of the UEFI API.
pub const cc: std.builtin.CallingConvention = switch (@import("builtin").target.cpu.arch) {
    .x86_64 => .{ .x86_64_win = .{} },
    else => .c,
};

pub const MacAddress = extern struct {
    address: [32]u8,
};

pub const Ipv4Address = extern struct {
    address: [4]u8,
};

pub const Ipv6Address = extern struct {
    address: [16]u8,
};

pub const IpAddress = extern union {
    v4: Ipv4Address,
    v6: Ipv6Address,
};

/// GUIDs are align(8) unless otherwise specified.
pub const Guid = extern struct {
    time_low: u32,
    time_mid: u16,
    time_high_and_version: u16,
    clock_seq_high_and_reserved: u8,
    clock_seq_low: u8,
    node: [6]u8,

    /// Format GUID into hexadecimal lowercase xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format
    pub fn format(
        self: @This(),
        comptime f: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        if (f.len == 0) {
            const fmt = std.fmt.fmtSliceHexLower;

            const time_low = @byteSwap(self.time_low);
            const time_mid = @byteSwap(self.time_mid);
            const time_high_and_version = @byteSwap(self.time_high_and_version);

            return std.fmt.format(writer, "{:0>8}-{:0>4}-{:0>4}-{:0>2}{:0>2}-{:0>12}", .{
                fmt(std.mem.asBytes(&time_low)),
                fmt(std.mem.asBytes(&time_mid)),
                fmt(std.mem.asBytes(&time_high_and_version)),
                fmt(std.mem.asBytes(&self.clock_seq_high_and_reserved)),
                fmt(std.mem.asBytes(&self.clock_seq_low)),
                fmt(std.mem.asBytes(&self.node)),
            });
        } else {
            std.fmt.invalidFmtError(f, self);
        }
    }

    pub fn eql(a: std.os.uefi.Guid, b: std.os.uefi.Guid) bool {
        return a.time_low == b.time_low and
            a.time_mid == b.time_mid and
            a.time_high_and_version == b.time_high_and_version and
            a.clock_seq_high_and_reserved == b.clock_seq_high_and_reserved and
            a.clock_seq_low == b.clock_seq_low and
            std.mem.eql(u8, &a.node, &b.node);
    }
};

/// An EFI Handle represents a collection of related interfaces.
pub const Handle = *opaque {};

/// This structure represents time information.
pub const Time = extern struct {
    /// 1900 - 9999
    year: u16,

    /// 1 - 12
    month: u8,

    /// 1 - 31
    day: u8,

    /// 0 - 23
    hour: u8,

    /// 0 - 59
    minute: u8,

    /// 0 - 59
    second: u8,

    _pad1: u8,

    /// 0 - 999999999
    nanosecond: u32,

    /// The time's offset in minutes from UTC.
    /// Allowed values are -1440 to 1440 or unspecified_timezone
    timezone: i16,
    daylight: packed struct(u8) {
        /// If true, the time has been adjusted for daylight savings time.
        in_daylight: bool,

        /// If true, the time is affected by daylight savings time.
        adjust_daylight: bool,

        _: u6,
    },

    _pad2: u8,

    comptime {
        std.debug.assert(@sizeOf(Time) == 16);
    }

    /// Time is to be interpreted as local time
    pub const unspecified_timezone: i16 = 0x7ff;

    fn daysInYear(year: u16, max_month: u4) u9 {
        var days: u9 = 0;
        var month: u4 = 0;
        while (month < max_month) : (month += 1) {
            days += std.time.epoch.getDaysInMonth(year, @enumFromInt(month + 1));
        }
        return days;
    }

    pub fn toEpoch(self: std.os.uefi.Time) u64 {
        var year: u16 = 0;
        var days: u32 = 0;

        while (year < (self.year - 1971)) : (year += 1) {
            days += daysInYear(year + 1970, 12);
        }

        days += daysInYear(self.year, @as(u4, @intCast(self.month)) - 1) + self.day;
        const hours: u64 = self.hour + (days * 24);
        const minutes: u64 = self.minute + (hours * 60);
        const seconds: u64 = self.second + (minutes * std.time.s_per_min);
        return self.nanosecond + (seconds * std.time.ns_per_s);
    }
};

/// Capabilities of the clock device
pub const TimeCapabilities = extern struct {
    /// Resolution in Hz
    resolution: u32,

    /// Accuracy in an error rate of 1e-6 parts per million.
    accuracy: u32,

    /// If true, a time set operation clears the device's time below the resolution level.
    sets_to_zero: bool,
};

/// File Handle as specified in the EFI Shell Spec
pub const FileHandle = *opaque {};

test "GUID formatting" {
    const bytes = [_]u8{ 137, 60, 203, 50, 128, 128, 124, 66, 186, 19, 80, 73, 135, 59, 194, 135 };
    const guid: Guid = @bitCast(bytes);

    const str = try std.fmt.allocPrint(std.testing.allocator, "{}", .{guid});
    defer std.testing.allocator.free(str);

    try std.testing.expect(std.mem.eql(u8, str, "32cb3c89-8080-427c-ba13-5049873bc287"));
}

test {
    _ = tables;
    _ = protocol;
}

pub const UnexpectedError = error{Unexpected};

pub fn unexpectedStatus(status: Status) UnexpectedError {
    // TODO: debug printing the encountered error? maybe handle warnings?
    _ = status;
    return error.Unexpected;
}
const std = @import("../../std.zig");
const assert = std.debug.assert;
const uefi = std.os.uefi;
const Guid = uefi.Guid;

pub const DevicePath = union(Type) {
    hardware: Hardware,
    acpi: Acpi,
    messaging: Messaging,
    media: Media,
    bios_boot_specification: BiosBootSpecification,
    end: End,

    pub const Type = enum(u8) {
        hardware = 0x01,
        acpi = 0x02,
        messaging = 0x03,
        media = 0x04,
        bios_boot_specification = 0x05,
        end = 0x7f,
        _,
    };

    pub const Hardware = union(Subtype) {
        pci: *const PciDevicePath,
        pc_card: *const PcCardDevicePath,
        memory_mapped: *const MemoryMappedDevicePath,
        vendor: *const VendorDevicePath,
        controller: *const ControllerDevicePath,
        bmc: *const BmcDevicePath,

        pub const Subtype = enum(u8) {
            pci = 1,
            pc_card = 2,
            memory_mapped = 3,
            vendor = 4,
            controller = 5,
            bmc = 6,
            _,
        };

        pub const PciDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            function: u8,
            device: u8,
        };

        comptime {
            assert(6 == @sizeOf(PciDevicePath));
            assert(1 == @alignOf(PciDevicePath));

            assert(0 == @offsetOf(PciDevicePath, "type"));
            assert(1 == @offsetOf(PciDevicePath, "subtype"));
            assert(2 == @offsetOf(PciDevicePath, "length"));
            assert(4 == @offsetOf(PciDevicePath, "function"));
            assert(5 == @offsetOf(PciDevicePath, "device"));
        }

        pub const PcCardDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            function_number: u8,
        };

        comptime {
            assert(5 == @sizeOf(PcCardDevicePath));
            assert(1 == @alignOf(PcCardDevicePath));

            assert(0 == @offsetOf(PcCardDevicePath, "type"));
            assert(1 == @offsetOf(PcCardDevicePath, "subtype"));
            assert(2 == @offsetOf(PcCardDevicePath, "length"));
            assert(4 == @offsetOf(PcCardDevicePath, "function_number"));
        }

        pub const MemoryMappedDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            memory_type: u32 align(1),
            start_address: u64 align(1),
            end_address: u64 align(1),
        };

        comptime {
            assert(24 == @sizeOf(MemoryMappedDevicePath));
            assert(1 == @alignOf(MemoryMappedDevicePath));

            assert(0 == @offsetOf(MemoryMappedDevicePath, "type"));
            assert(1 == @offsetOf(MemoryMappedDevicePath, "subtype"));
            assert(2 == @offsetOf(MemoryMappedDevicePath, "length"));
            assert(4 == @offsetOf(MemoryMappedDevicePath, "memory_type"));
            assert(8 == @offsetOf(MemoryMappedDevicePath, "start_address"));
            assert(16 == @offsetOf(MemoryMappedDevicePath, "end_address"));
        }

        pub const VendorDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeOf(VendorDevicePath));
            assert(1 == @alignOf(VendorDevicePath));

            assert(0 == @offsetOf(VendorDevicePath, "type"));
            assert(1 == @offsetOf(VendorDevicePath, "subtype"));
            assert(2 == @offsetOf(VendorDevicePath, "length"));
            assert(4 == @offsetOf(VendorDevicePath, "vendor_guid"));
        }

        pub const ControllerDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            controller_number: u32 align(1),
        };

        comptime {
            assert(8 == @sizeOf(ControllerDevicePath));
            assert(1 == @alignOf(ControllerDevicePath));

            assert(0 == @offsetOf(ControllerDevicePath, "type"));
            assert(1 == @offsetOf(ControllerDevicePath, "subtype"));
            assert(2 == @offsetOf(ControllerDevicePath, "length"));
            assert(4 == @offsetOf(ControllerDevicePath, "controller_number"));
        }

        pub const BmcDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            interface_type: u8,
            base_address: u64 align(1),
        };

        comptime {
            assert(13 == @sizeOf(BmcDevicePath));
            assert(1 == @alignOf(BmcDevicePath));

            assert(0 == @offsetOf(BmcDevicePath, "type"));
            assert(1 == @offsetOf(BmcDevicePath, "subtype"));
            assert(2 == @offsetOf(BmcDevicePath, "length"));
            assert(4 == @offsetOf(BmcDevicePath, "interface_type"));
            assert(5 == @offsetOf(BmcDevicePath, "base_address"));
        }
    };

    pub const Acpi = union(Subtype) {
        acpi: *const BaseAcpiDevicePath,
        expanded_acpi: *const ExpandedAcpiDevicePath,
        adr: *const AdrDevicePath,

        pub const Subtype = enum(u8) {
            acpi = 1,
            expanded_acpi = 2,
            adr = 3,
            _,
        };

        pub const BaseAcpiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            hid: u32 align(1),
            uid: u32 align(1),
        };

        comptime {
            assert(12 == @sizeOf(BaseAcpiDevicePath));
            assert(1 == @alignOf(BaseAcpiDevicePath));

            assert(0 == @offsetOf(BaseAcpiDevicePath, "type"));
            assert(1 == @offsetOf(BaseAcpiDevicePath, "subtype"));
            assert(2 == @offsetOf(BaseAcpiDevicePath, "length"));
            assert(4 == @offsetOf(BaseAcpiDevicePath, "hid"));
            assert(8 == @offsetOf(BaseAcpiDevicePath, "uid"));
        }

        pub const ExpandedAcpiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            hid: u32 align(1),
            uid: u32 align(1),
            cid: u32 align(1),
            // variable length u16[*:0] strings
            // hid_str, uid_str, cid_str
        };

        comptime {
            assert(16 == @sizeOf(ExpandedAcpiDevicePath));
            assert(1 == @alignOf(ExpandedAcpiDevicePath));

            assert(0 == @offsetOf(ExpandedAcpiDevicePath, "type"));
            assert(1 == @offsetOf(ExpandedAcpiDevicePath, "subtype"));
            assert(2 == @offsetOf(ExpandedAcpiDevicePath, "length"));
            assert(4 == @offsetOf(ExpandedAcpiDevicePath, "hid"));
            assert(8 == @offsetOf(ExpandedAcpiDevicePath, "uid"));
            assert(12 == @offsetOf(ExpandedAcpiDevicePath, "cid"));
        }

        pub const AdrDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            adr: u32 align(1),

            // multiple adr entries can optionally follow
            pub fn adrs(self: *const AdrDevicePath) []align(1) const u32 {
                // self.length is a minimum of 8 with one adr which is size 4.
                const entries = (self.length - 4) / @sizeOf(u32);
                return @as([*]align(1) const u32, @ptrCast(&self.adr))[0..entries];
            }
        };

        comptime {
            assert(8 == @sizeOf(AdrDevicePath));
            assert(1 == @alignOf(AdrDevicePath));

            assert(0 == @offsetOf(AdrDevicePath, "type"));
            assert(1 == @offsetOf(AdrDevicePath, "subtype"));
            assert(2 == @offsetOf(AdrDevicePath, "length"));
            assert(4 == @offsetOf(AdrDevicePath, "adr"));
        }
    };

    pub const Messaging = union(Subtype) {
        atapi: *const AtapiDevicePath,
        scsi: *const ScsiDevicePath,
        fibre_channel: *const FibreChannelDevicePath,
        fibre_channel_ex: *const FibreChannelExDevicePath,
        @"1394": *const F1394DevicePath,
        usb: *const UsbDevicePath,
        sata: *const SataDevicePath,
        usb_wwid: *const UsbWwidDevicePath,
        lun: *const DeviceLogicalUnitDevicePath,
        usb_class: *const UsbClassDevicePath,
        i2o: *const I2oDevicePath,
        mac_address: *const MacAddressDevicePath,
        ipv4: *const Ipv4DevicePath,
        ipv6: *const Ipv6DevicePath,
        vlan: *const VlanDevicePath,
        infini_band: *const InfiniBandDevicePath,
        uart: *const UartDevicePath,
        vendor: *const VendorDefinedDevicePath,

        pub const Subtype = enum(u8) {
            atapi = 1,
            scsi = 2,
            fibre_channel = 3,
            fibre_channel_ex = 21,
            @"1394" = 4,
            usb = 5,
            sata = 18,
            usb_wwid = 16,
            lun = 17,
            usb_class = 15,
            i2o = 6,
            mac_address = 11,
            ipv4 = 12,
            ipv6 = 13,
            vlan = 20,
            infini_band = 9,
            uart = 14,
            vendor = 10,
            _,
        };

        pub const AtapiDevicePath = extern struct {
            pub const Role = enum(u8) {
                master = 0,
                slave = 1,
            };

            pub const Rank = enum(u8) {
                primary = 0,
                secondary = 1,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            primary_secondary: Rank,
            slave_master: Role,
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(8 == @sizeOf(AtapiDevicePath));
            assert(1 == @alignOf(AtapiDevicePath));

            assert(0 == @offsetOf(AtapiDevicePath, "type"));
            assert(1 == @offsetOf(AtapiDevicePath, "subtype"));
            assert(2 == @offsetOf(AtapiDevicePath, "length"));
            assert(4 == @offsetOf(AtapiDevicePath, "primary_secondary"));
            assert(5 == @offsetOf(AtapiDevicePath, "slave_master"));
            assert(6 == @offsetOf(AtapiDevicePath, "logical_unit_number"));
        }

        pub const ScsiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            target_id: u16 align(1),
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(8 == @sizeOf(ScsiDevicePath));
            assert(1 == @alignOf(ScsiDevicePath));

            assert(0 == @offsetOf(ScsiDevicePath, "type"));
            assert(1 == @offsetOf(ScsiDevicePath, "subtype"));
            assert(2 == @offsetOf(ScsiDevicePath, "length"));
            assert(4 == @offsetOf(ScsiDevicePath, "target_id"));
            assert(6 == @offsetOf(ScsiDevicePath, "logical_unit_number"));
        }

        pub const FibreChannelDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            world_wide_name: u64 align(1),
            logical_unit_number: u64 align(1),
        };

        comptime {
            assert(24 == @sizeOf(FibreChannelDevicePath));
            assert(1 == @alignOf(FibreChannelDevicePath));

            assert(0 == @offsetOf(FibreChannelDevicePath, "type"));
            assert(1 == @offsetOf(FibreChannelDevicePath, "subtype"));
            assert(2 == @offsetOf(FibreChannelDevicePath, "length"));
            assert(4 == @offsetOf(FibreChannelDevicePath, "reserved"));
            assert(8 == @offsetOf(FibreChannelDevicePath, "world_wide_name"));
            assert(16 == @offsetOf(FibreChannelDevicePath, "logical_unit_number"));
        }

        pub const FibreChannelExDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            world_wide_name: u64 align(1),
            logical_unit_number: u64 align(1),
        };

        comptime {
            assert(24 == @sizeOf(FibreChannelExDevicePath));
            assert(1 == @alignOf(FibreChannelExDevicePath));

            assert(0 == @offsetOf(FibreChannelExDevicePath, "type"));
            assert(1 == @offsetOf(FibreChannelExDevicePath, "subtype"));
            assert(2 == @offsetOf(FibreChannelExDevicePath, "length"));
            assert(4 == @offsetOf(FibreChannelExDevicePath, "reserved"));
            assert(8 == @offsetOf(FibreChannelExDevicePath, "world_wide_name"));
            assert(16 == @offsetOf(FibreChannelExDevicePath, "logical_unit_number"));
        }

        pub const F1394DevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            guid: u64 align(1),
        };

        comptime {
            assert(16 == @sizeOf(F1394DevicePath));
            assert(1 == @alignOf(F1394DevicePath));

            assert(0 == @offsetOf(F1394DevicePath, "type"));
            assert(1 == @offsetOf(F1394DevicePath, "subtype"));
            assert(2 == @offsetOf(F1394DevicePath, "length"));
            assert(4 == @offsetOf(F1394DevicePath, "reserved"));
            assert(8 == @offsetOf(F1394DevicePath, "guid"));
        }

        pub const UsbDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            parent_port_number: u8,
            interface_number: u8,
        };

        comptime {
            assert(6 == @sizeOf(UsbDevicePath));
            assert(1 == @alignOf(UsbDevicePath));

            assert(0 == @offsetOf(UsbDevicePath, "type"));
            assert(1 == @offsetOf(UsbDevicePath, "subtype"));
            assert(2 == @offsetOf(UsbDevicePath, "length"));
            assert(4 == @offsetOf(UsbDevicePath, "parent_port_number"));
            assert(5 == @offsetOf(UsbDevicePath, "interface_number"));
        }

        pub const SataDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            hba_port_number: u16 align(1),
            port_multiplier_port_number: u16 align(1),
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(10 == @sizeOf(SataDevicePath));
            assert(1 == @alignOf(SataDevicePath));

            assert(0 == @offsetOf(SataDevicePath, "type"));
            assert(1 == @offsetOf(SataDevicePath, "subtype"));
            assert(2 == @offsetOf(SataDevicePath, "length"));
            assert(4 == @offsetOf(SataDevicePath, "hba_port_number"));
            assert(6 == @offsetOf(SataDevicePath, "port_multiplier_port_number"));
            assert(8 == @offsetOf(SataDevicePath, "logical_unit_number"));
        }

        pub const UsbWwidDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            interface_number: u16 align(1),
            device_vendor_id: u16 align(1),
            device_product_id: u16 align(1),

            pub fn serial_number(self: *const UsbWwidDevicePath) []align(1) const u16 {
                const serial_len = (self.length - @sizeOf(UsbWwidDevicePath)) / @sizeOf(u16);
                return @as([*]align(1) const u16, @ptrCast(@as([*]const u8, @ptrCast(self)) + @sizeOf(UsbWwidDevicePath)))[0..serial_len];
            }
        };

        comptime {
            assert(10 == @sizeOf(UsbWwidDevicePath));
            assert(1 == @alignOf(UsbWwidDevicePath));

            assert(0 == @offsetOf(UsbWwidDevicePath, "type"));
            assert(1 == @offsetOf(UsbWwidDevicePath, "subtype"));
            assert(2 == @offsetOf(UsbWwidDevicePath, "length"));
            assert(4 == @offsetOf(UsbWwidDevicePath, "interface_number"));
            assert(6 == @offsetOf(UsbWwidDevicePath, "device_vendor_id"));
            assert(8 == @offsetOf(UsbWwidDevicePath, "device_product_id"));
        }

        pub const DeviceLogicalUnitDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            lun: u8,
        };

        comptime {
            assert(5 == @sizeOf(DeviceLogicalUnitDevicePath));
            assert(1 == @alignOf(DeviceLogicalUnitDevicePath));

            assert(0 == @offsetOf(DeviceLogicalUnitDevicePath, "type"));
            assert(1 == @offsetOf(DeviceLogicalUnitDevicePath, "subtype"));
            assert(2 == @offsetOf(DeviceLogicalUnitDevicePath, "length"));
            assert(4 == @offsetOf(DeviceLogicalUnitDevicePath, "lun"));
        }

        pub const UsbClassDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_id: u16 align(1),
            product_id: u16 align(1),
            device_class: u8,
            device_subclass: u8,
            device_protocol: u8,
        };

        comptime {
            assert(11 == @sizeOf(UsbClassDevicePath));
            assert(1 == @alignOf(UsbClassDevicePath));

            assert(0 == @offsetOf(UsbClassDevicePath, "type"));
            assert(1 == @offsetOf(UsbClassDevicePath, "subtype"));
            assert(2 == @offsetOf(UsbClassDevicePath, "length"));
            assert(4 == @offsetOf(UsbClassDevicePath, "vendor_id"));
            assert(6 == @offsetOf(UsbClassDevicePath, "product_id"));
            assert(8 == @offsetOf(UsbClassDevicePath, "device_class"));
            assert(9 == @offsetOf(UsbClassDevicePath, "device_subclass"));
            assert(10 == @offsetOf(UsbClassDevicePath, "device_protocol"));
        }

        pub const I2oDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            tid: u32 align(1),
        };

        comptime {
            assert(8 == @sizeOf(I2oDevicePath));
            assert(1 == @alignOf(I2oDevicePath));

            assert(0 == @offsetOf(I2oDevicePath, "type"));
            assert(1 == @offsetOf(I2oDevicePath, "subtype"));
            assert(2 == @offsetOf(I2oDevicePath, "length"));
            assert(4 == @offsetOf(I2oDevicePath, "tid"));
        }

        pub const MacAddressDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            mac_address: uefi.MacAddress,
            if_type: u8,
        };

        comptime {
            assert(37 == @sizeOf(MacAddressDevicePath));
            assert(1 == @alignOf(MacAddressDevicePath));

            assert(0 == @offsetOf(MacAddressDevicePath, "type"));
            assert(1 == @offsetOf(MacAddressDevicePath, "subtype"));
            assert(2 == @offsetOf(MacAddressDevicePath, "length"));
            assert(4 == @offsetOf(MacAddressDevicePath, "mac_address"));
            assert(36 == @offsetOf(MacAddressDevicePath, "if_type"));
        }

        pub const Ipv4DevicePath = extern struct {
            pub const IpType = enum(u8) {
                dhcp = 0,
                static = 1,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            local_ip_address: uefi.Ipv4Address align(1),
            remote_ip_address: uefi.Ipv4Address align(1),
            local_port: u16 align(1),
            remote_port: u16 align(1),
            network_protocol: u16 align(1),
            static_ip_address: IpType,
            gateway_ip_address: u32 align(1),
            subnet_mask: u32 align(1),
        };

        comptime {
            assert(27 == @sizeOf(Ipv4DevicePath));
            assert(1 == @alignOf(Ipv4DevicePath));

            assert(0 == @offsetOf(Ipv4DevicePath, "type"));
            assert(1 == @offsetOf(Ipv4DevicePath, "subtype"));
            assert(2 == @offsetOf(Ipv4DevicePath, "length"));
            assert(4 == @offsetOf(Ipv4DevicePath, "local_ip_address"));
            assert(8 == @offsetOf(Ipv4DevicePath, "remote_ip_address"));
            assert(12 == @offsetOf(Ipv4DevicePath, "local_port"));
            assert(14 == @offsetOf(Ipv4DevicePath, "remote_port"));
            assert(16 == @offsetOf(Ipv4DevicePath, "network_protocol"));
            assert(18 == @offsetOf(Ipv4DevicePath, "static_ip_address"));
            assert(19 == @offsetOf(Ipv4DevicePath, "gateway_ip_address"));
            assert(23 == @offsetOf(Ipv4DevicePath, "subnet_mask"));
        }

        pub const Ipv6DevicePath = extern struct {
            pub const Origin = enum(u8) {
                manual = 0,
                assigned_stateless = 1,
                assigned_stateful = 2,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            local_ip_address: uefi.Ipv6Address,
            remote_ip_address: uefi.Ipv6Address,
            local_port: u16 align(1),
            remote_port: u16 align(1),
            protocol: u16 align(1),
            ip_address_origin: Origin,
            prefix_length: u8,
            gateway_ip_address: uefi.Ipv6Address,
        };

        comptime {
            assert(60 == @sizeOf(Ipv6DevicePath));
            assert(1 == @alignOf(Ipv6DevicePath));

            assert(0 == @offsetOf(Ipv6DevicePath, "type"));
            assert(1 == @offsetOf(Ipv6DevicePath, "subtype"));
            assert(2 == @offsetOf(Ipv6DevicePath, "length"));
            assert(4 == @offsetOf(Ipv6DevicePath, "local_ip_address"));
            assert(20 == @offsetOf(Ipv6DevicePath, "remote_ip_address"));
            assert(36 == @offsetOf(Ipv6DevicePath, "local_port"));
            assert(38 == @offsetOf(Ipv6DevicePath, "remote_port"));
            assert(40 == @offsetOf(Ipv6DevicePath, "protocol"));
            assert(42 == @offsetOf(Ipv6DevicePath, "ip_address_origin"));
            assert(43 == @offsetOf(Ipv6DevicePath, "prefix_length"));
            assert(44 == @offsetOf(Ipv6DevicePath, "gateway_ip_address"));
        }

        pub const VlanDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vlan_id: u16 align(1),
        };

        comptime {
            assert(6 == @sizeOf(VlanDevicePath));
            assert(1 == @alignOf(VlanDevicePath));

            assert(0 == @offsetOf(VlanDevicePath, "type"));
            assert(1 == @offsetOf(VlanDevicePath, "subtype"));
            assert(2 == @offsetOf(VlanDevicePath, "length"));
            assert(4 == @offsetOf(VlanDevicePath, "vlan_id"));
        }

        pub const InfiniBandDevicePath = extern struct {
            pub const ResourceFlags = packed struct(u32) {
                pub const ControllerType = enum(u1) {
                    ioc = 0,
                    service = 1,
                };

                ioc_or_service: ControllerType,
                extend_boot_environment: bool,
                console_protocol: bool,
                storage_protocol: bool,
                network_protocol: bool,

                // u1 + 4 * bool = 5 bits, we need a total of 32 bits
                reserved: u27,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            resource_flags: ResourceFlags align(1),
            port_gid: [16]u8,
            service_id: u64 align(1),
            target_port_id: u64 align(1),
            device_id: u64 align(1),
        };

        comptime {
            assert(48 == @sizeOf(InfiniBandDevicePath));
            assert(1 == @alignOf(InfiniBandDevicePath));

            assert(0 == @offsetOf(InfiniBandDevicePath, "type"));
            assert(1 == @offsetOf(InfiniBandDevicePath, "subtype"));
            assert(2 == @offsetOf(InfiniBandDevicePath, "length"));
            assert(4 == @offsetOf(InfiniBandDevicePath, "resource_flags"));
            assert(8 == @offsetOf(InfiniBandDevicePath, "port_gid"));
            assert(24 == @offsetOf(InfiniBandDevicePath, "service_id"));
            assert(32 == @offsetOf(InfiniBandDevicePath, "target_port_id"));
            assert(40 == @offsetOf(InfiniBandDevicePath, "device_id"));
        }

        pub const UartDevicePath = extern struct {
            pub const Parity = enum(u8) {
                default = 0,
                none = 1,
                even = 2,
                odd = 3,
                mark = 4,
                space = 5,
                _,
            };

            pub const StopBits = enum(u8) {
                default = 0,
                one = 1,
                one_and_a_half = 2,
                two = 3,
                _,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            baud_rate: u64 align(1),
            data_bits: u8,
            parity: Parity,
            stop_bits: StopBits,
        };

        comptime {
            assert(19 == @sizeOf(UartDevicePath));
            assert(1 == @alignOf(UartDevicePath));

            assert(0 == @offsetOf(UartDevicePath, "type"));
            assert(1 == @offsetOf(UartDevicePath, "subtype"));
            assert(2 == @offsetOf(UartDevicePath, "length"));
            assert(4 == @offsetOf(UartDevicePath, "reserved"));
            assert(8 == @offsetOf(UartDevicePath, "baud_rate"));
            assert(16 == @offsetOf(UartDevicePath, "data_bits"));
            assert(17 == @offsetOf(UartDevicePath, "parity"));
            assert(18 == @offsetOf(UartDevicePath, "stop_bits"));
        }

        pub const VendorDefinedDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeOf(VendorDefinedDevicePath));
            assert(1 == @alignOf(VendorDefinedDevicePath));

            assert(0 == @offsetOf(VendorDefinedDevicePath, "type"));
            assert(1 == @offsetOf(VendorDefinedDevicePath, "subtype"));
            assert(2 == @offsetOf(VendorDefinedDevicePath, "length"));
            assert(4 == @offsetOf(VendorDefinedDevicePath, "vendor_guid"));
        }
    };

    pub const Media = union(Subtype) {
        hard_drive: *const HardDriveDevicePath,
        cdrom: *const CdromDevicePath,
        vendor: *const VendorDevicePath,
        file_path: *const FilePathDevicePath,
        media_protocol: *const MediaProtocolDevicePath,
        piwg_firmware_file: *const PiwgFirmwareFileDevicePath,
        piwg_firmware_volume: *const PiwgFirmwareVolumeDevicePath,
        relative_offset_range: *const RelativeOffsetRangeDevicePath,
        ram_disk: *const RamDiskDevicePath,

        pub const Subtype = enum(u8) {
            hard_drive = 1,
            cdrom = 2,
            vendor = 3,
            file_path = 4,
            media_protocol = 5,
            piwg_firmware_file = 6,
            piwg_firmware_volume = 7,
            relative_offset_range = 8,
            ram_disk = 9,
            _,
        };

        pub const HardDriveDevicePath = extern struct {
            pub const Format = enum(u8) {
                legacy_mbr = 0x01,
                guid_partition_table = 0x02,
            };

            pub const SignatureType = enum(u8) {
                no_signature = 0x00,
                /// "32-bit signature from address 0x1b8 of the type 0x01 MBR"
                mbr_signature = 0x01,
                guid_signature = 0x02,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            partition_number: u32 align(1),
            partition_start: u64 align(1),
            partition_size: u64 align(1),
            partition_signature: [16]u8,
            partition_format: Format,
            signature_type: SignatureType,
        };

        comptime {
            assert(42 == @sizeOf(HardDriveDevicePath));
            assert(1 == @alignOf(HardDriveDevicePath));

            assert(0 == @offsetOf(HardDriveDevicePath, "type"));
            assert(1 == @offsetOf(HardDriveDevicePath, "subtype"));
            assert(2 == @offsetOf(HardDriveDevicePath, "length"));
            assert(4 == @offsetOf(HardDriveDevicePath, "partition_number"));
            assert(8 == @offsetOf(HardDriveDevicePath, "partition_start"));
            assert(16 == @offsetOf(HardDriveDevicePath, "partition_size"));
            assert(24 == @offsetOf(HardDriveDevicePath, "partition_signature"));
            assert(40 == @offsetOf(HardDriveDevicePath, "partition_format"));
            assert(41 == @offsetOf(HardDriveDevicePath, "signature_type"));
        }

        pub const CdromDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            boot_entry: u32 align(1),
            partition_start: u64 align(1),
            partition_size: u64 align(1),
        };

        comptime {
            assert(24 == @sizeOf(CdromDevicePath));
            assert(1 == @alignOf(CdromDevicePath));

            assert(0 == @offsetOf(CdromDevicePath, "type"));
            assert(1 == @offsetOf(CdromDevicePath, "subtype"));
            assert(2 == @offsetOf(CdromDevicePath, "length"));
            assert(4 == @offsetOf(CdromDevicePath, "boot_entry"));
            assert(8 == @offsetOf(CdromDevicePath, "partition_start"));
            assert(16 == @offsetOf(CdromDevicePath, "partition_size"));
        }

        pub const VendorDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeOf(VendorDevicePath));
            assert(1 == @alignOf(VendorDevicePath));

            assert(0 == @offsetOf(VendorDevicePath, "type"));
            assert(1 == @offsetOf(VendorDevicePath, "subtype"));
            assert(2 == @offsetOf(VendorDevicePath, "length"));
            assert(4 == @offsetOf(VendorDevicePath, "guid"));
        }

        pub const FilePathDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),

            pub fn getPath(self: *const FilePathDevicePath) [*:0]align(1) const u16 {
                return @as([*:0]align(1) const u16, @ptrCast(@as([*]const u8, @ptrCast(self)) + @sizeOf(FilePathDevicePath)));
            }
        };

        comptime {
            assert(4 == @sizeOf(FilePathDevicePath));
            assert(1 == @alignOf(FilePathDevicePath));

            assert(0 == @offsetOf(FilePathDevicePath, "type"));
            assert(1 == @offsetOf(FilePathDevicePath, "subtype"));
            assert(2 == @offsetOf(FilePathDevicePath, "length"));
        }

        pub const MediaProtocolDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeOf(MediaProtocolDevicePath));
            assert(1 == @alignOf(MediaProtocolDevicePath));

            assert(0 == @offsetOf(MediaProtocolDevicePath, "type"));
            assert(1 == @offsetOf(MediaProtocolDevicePath, "subtype"));
            assert(2 == @offsetOf(MediaProtocolDevicePath, "length"));
            assert(4 == @offsetOf(MediaProtocolDevicePath, "guid"));
        }

        pub const PiwgFirmwareFileDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            fv_filename: Guid align(1),
        };

        comptime {
            assert(20 == @sizeOf(PiwgFirmwareFileDevicePath));
            assert(1 == @alignOf(PiwgFirmwareFileDevicePath));

            assert(0 == @offsetOf(PiwgFirmwareFileDevicePath, "type"));
            assert(1 == @offsetOf(PiwgFirmwareFileDevicePath, "subtype"));
            assert(2 == @offsetOf(PiwgFirmwareFileDevicePath, "length"));
            assert(4 == @offsetOf(PiwgFirmwareFileDevicePath, "fv_filename"));
        }

        pub const PiwgFirmwareVolumeDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            fv_name: Guid align(1),
        };

        comptime {
            assert(20 == @sizeOf(PiwgFirmwareVolumeDevicePath));
            assert(1 == @alignOf(PiwgFirmwareVolumeDevicePath));

            assert(0 == @offsetOf(PiwgFirmwareVolumeDevicePath, "type"));
            assert(1 == @offsetOf(PiwgFirmwareVolumeDevicePath, "subtype"));
            assert(2 == @offsetOf(PiwgFirmwareVolumeDevicePath, "length"));
            assert(4 == @offsetOf(PiwgFirmwareVolumeDevicePath, "fv_name"));
        }

        pub const RelativeOffsetRangeDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            start: u64 align(1),
            end: u64 align(1),
        };

        comptime {
            assert(24 == @sizeOf(RelativeOffsetRangeDevicePath));
            assert(1 == @alignOf(RelativeOffsetRangeDevicePath));

            assert(0 == @offsetOf(RelativeOffsetRangeDevicePath, "type"));
            assert(1 == @offsetOf(RelativeOffsetRangeDevicePath, "subtype"));
            assert(2 == @offsetOf(RelativeOffsetRangeDevicePath, "length"));
            assert(4 == @offsetOf(RelativeOffsetRangeDevicePath, "reserved"));
            assert(8 == @offsetOf(RelativeOffsetRangeDevicePath, "start"));
            assert(16 == @offsetOf(RelativeOffsetRangeDevicePath, "end"));
        }

        pub const RamDiskDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            start: u64 align(1),
            end: u64 align(1),
            disk_type: Guid align(1),
            instance: u16 align(1),
        };

        comptime {
            assert(38 == @sizeOf(RamDiskDevicePath));
            assert(1 == @alignOf(RamDiskDevicePath));

            assert(0 == @offsetOf(RamDiskDevicePath, "type"));
            assert(1 == @offsetOf(RamDiskDevicePath, "subtype"));
            assert(2 == @offsetOf(RamDiskDevicePath, "length"));
            assert(4 == @offsetOf(RamDiskDevicePath, "start"));
            assert(12 == @offsetOf(RamDiskDevicePath, "end"));
            assert(20 == @offsetOf(RamDiskDevicePath, "disk_type"));
            assert(36 == @offsetOf(RamDiskDevicePath, "instance"));
        }
    };

    pub const BiosBootSpecification = union(Subtype) {
        bbs101: *const BBS101DevicePath,

        pub const Subtype = enum(u8) {
            bbs101 = 1,
            _,
        };

        pub const BBS101DevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            device_type: u16 align(1),
            status_flag: u16 align(1),

            pub fn getDescription(self: *const BBS101DevicePath) [*:0]const u8 {
                return @as([*:0]const u8, @ptrCast(self)) + @sizeOf(BBS101DevicePath);
            }
        };

        comptime {
            assert(8 == @sizeOf(BBS101DevicePath));
            assert(1 == @alignOf(BBS101DevicePath));

            assert(0 == @offsetOf(BBS101DevicePath, "type"));
            assert(1 == @offsetOf(BBS101DevicePath, "subtype"));
            assert(2 == @offsetOf(BBS101DevicePath, "length"));
            assert(4 == @offsetOf(BBS101DevicePath, "device_type"));
            assert(6 == @offsetOf(BBS101DevicePath, "status_flag"));
        }
    };

    pub const End = union(Subtype) {
        end_entire: *const EndEntireDevicePath,
        end_this_instance: *const EndThisInstanceDevicePath,

        pub const Subtype = enum(u8) {
            end_entire = 0xff,
            end_this_instance = 0x01,
            _,
        };

        pub const EndEntireDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
        };

        comptime {
            assert(4 == @sizeOf(EndEntireDevicePath));
            assert(1 == @alignOf(EndEntireDevicePath));

            assert(0 == @offsetOf(EndEntireDevicePath, "type"));
            assert(1 == @offsetOf(EndEntireDevicePath, "subtype"));
            assert(2 == @offsetOf(EndEntireDevicePath, "length"));
        }

        pub const EndThisInstanceDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
        };

        comptime {
            assert(4 == @sizeOf(EndEntireDevicePath));
            assert(1 == @alignOf(EndEntireDevicePath));

            assert(0 == @offsetOf(EndEntireDevicePath, "type"));
            assert(1 == @offsetOf(EndEntireDevicePath, "subtype"));
            assert(2 == @offsetOf(EndEntireDevicePath, "length"));
        }
    };
};
const uefi = @import("std").os.uefi;
const Guid = uefi.Guid;

pub const Handle = *opaque {};

/// The header found at the start of each package.
pub const PackageHeader = packed struct(u32) {
    length: u24,
    type: u8,

    pub const type_all: u8 = 0x0;
    pub const type_guid: u8 = 0x1;
    pub const forms: u8 = 0x2;
    pub const strings: u8 = 0x4;
    pub const fonts: u8 = 0x5;
    pub const images: u8 = 0x6;
    pub const simple_fonsts: u8 = 0x7;
    pub const device_path: u8 = 0x8;
    pub const keyboard_layout: u8 = 0x9;
    pub const animations: u8 = 0xa;
    pub const end: u8 = 0xdf;
    pub const type_system_begin: u8 = 0xe0;
    pub const type_system_end: u8 = 0xff;
};

/// The header found at the start of each package list.
pub const PackageList = extern struct {
    package_list_guid: Guid,

    /// The size of the package list (in bytes), including the header.
    package_list_length: u32,

    // TODO implement iterator
};

pub const SimplifiedFontPackage = extern struct {
    header: PackageHeader,
    number_of_narrow_glyphs: u16,
    number_of_wide_glyphs: u16,

    pub fn getNarrowGlyphs(self: *SimplifiedFontPackage) []NarrowGlyph {
        return @as([*]NarrowGlyph, @ptrCast(@alignCast(@as([*]u8, @ptrCast(self)) + @sizeOf(SimplifiedFontPackage))))[0..self.number_of_narrow_glyphs];
    }
};

pub const NarrowGlyphAttributes = packed struct(u8) {
    non_spacing: bool,
    wide: bool,
    _pad: u6 = 0,
};

pub const NarrowGlyph = extern struct {
    unicode_weight: u16,
    attributes: NarrowGlyphAttributes,
    glyph_col_1: [19]u8,
};

pub const WideGlyphAttributes = packed struct(u8) {
    non_spacing: bool,
    wide: bool,
    _pad: u6 = 0,
};

pub const WideGlyph = extern struct {
    unicode_weight: u16,
    attributes: WideGlyphAttributes,
    glyph_col_1: [19]u8,
    glyph_col_2: [19]u8,
    _pad: [3]u8 = [_]u8{0} ** 3,
};

pub const StringPackage = extern struct {
    header: PackageHeader,
    hdr_size: u32,
    string_info_offset: u32,
    language_window: [16]u16,
    language_name: u16,
    language: [3]u8,
};
const std = @import("std");

const mem = std.mem;
const uefi = std.os.uefi;

const assert = std.debug.assert;

const Allocator = mem.Allocator;

const UefiPoolAllocator = struct {
    fn getHeader(ptr: [*]u8) *[*]align(8) u8 {
        return @as(*[*]align(8) u8, @ptrFromInt(@intFromPtr(ptr) - @sizeOf(usize)));
    }

    fn alloc(
        _: *anyopaque,
        len: usize,
        alignment: mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ret_addr;

        assert(len > 0);

        const ptr_align = alignment.toByteUnits();

        const metadata_len = mem.alignForward(usize, @sizeOf(usize), ptr_align);

        const full_len = metadata_len + len;

        var unaligned_ptr: [*]align(8) u8 = undefined;
        if (uefi.system_table.boot_services.?.allocatePool(uefi.efi_pool_memory_type, full_len, &unaligned_ptr) != .success) return null;

        const unaligned_addr = @intFromPtr(unaligned_ptr);
        const aligned_addr = mem.alignForward(usize, unaligned_addr + @sizeOf(usize), ptr_align);

        const aligned_ptr = unaligned_ptr + (aligned_addr - unaligned_addr);
        getHeader(aligned_ptr).* = unaligned_ptr;

        return aligned_ptr;
    }

    fn resize(
        _: *anyopaque,
        buf: []u8,
        alignment: mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ret_addr;
        _ = alignment;

        if (new_len > buf.len) return false;
        return true;
    }

    fn remap(
        _: *anyopaque,
        buf: []u8,
        alignment: mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = alignment;
        _ = ret_addr;

        if (new_len > buf.len) return null;
        return buf.ptr;
    }

    fn free(
        _: *anyopaque,
        buf: []u8,
        alignment: mem.Alignment,
        ret_addr: usize,
    ) void {
        _ = alignment;
        _ = ret_addr;
        _ = uefi.system_table.boot_services.?.freePool(getHeader(buf.ptr).*);
    }
};

/// Supports the full Allocator interface, including alignment.
/// For a direct call of `allocatePool`, see `raw_pool_allocator`.
pub const pool_allocator = Allocator{
    .ptr = undefined,
    .vtable = &pool_allocator_vtable,
};

const pool_allocator_vtable = Allocator.VTable{
    .alloc = UefiPoolAllocator.alloc,
    .resize = UefiPoolAllocator.resize,
    .remap = UefiPoolAllocator.remap,
    .free = UefiPoolAllocator.free,
};

/// Asserts allocations are 8 byte aligned and calls `boot_services.allocatePool`.
pub const raw_pool_allocator = Allocator{
    .ptr = undefined,
    .vtable = &raw_pool_allocator_table,
};

const raw_pool_allocator_table = Allocator.VTable{
    .alloc = uefi_alloc,
    .resize = uefi_resize,
    .remap = uefi_remap,
    .free = uefi_free,
};

fn uefi_alloc(
    _: *anyopaque,
    len: usize,
    alignment: mem.Alignment,
    ret_addr: usize,
) ?[*]u8 {
    _ = ret_addr;

    std.debug.assert(@intFromEnum(alignment) <= 3);

    var ptr: [*]align(8) u8 = undefined;
    if (uefi.system_table.boot_services.?.allocatePool(uefi.efi_pool_memory_type, len, &ptr) != .success) return null;

    return ptr;
}

fn uefi_resize(
    _: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    _ = ret_addr;

    std.debug.assert(@intFromEnum(alignment) <= 3);

    if (new_len > buf.len) return false;
    return true;
}

fn uefi_remap(
    _: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) ?[*]u8 {
    _ = ret_addr;

    std.debug.assert(@intFromEnum(alignment) <= 3);

    if (new_len > buf.len) return null;
    return buf.ptr;
}

fn uefi_free(
    _: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    ret_addr: usize,
) void {
    _ = alignment;
    _ = ret_addr;
    _ = uefi.system_table.boot_services.?.freePool(@alignCast(buf.ptr));
}
const std = @import("std");
const uefi = std.os.uefi;

pub const ServiceBinding = @import("protocol/service_binding.zig").ServiceBinding;

pub const LoadedImage = @import("protocol/loaded_image.zig").LoadedImage;
pub const DevicePath = @import("protocol/device_path.zig").DevicePath;
pub const Rng = @import("protocol/rng.zig").Rng;
pub const ShellParameters = @import("protocol/shell_parameters.zig").ShellParameters;

pub const SimpleFileSystem = @import("protocol/simple_file_system.zig").SimpleFileSystem;
pub const File = @import("protocol/file.zig").File;
pub const BlockIo = @import("protocol/block_io.zig").BlockIo;

pub const SimpleTextInput = @import("protocol/simple_text_input.zig").SimpleTextInput;
pub const SimpleTextInputEx = @import("protocol/simple_text_input_ex.zig").SimpleTextInputEx;
pub const SimpleTextOutput = @import("protocol/simple_text_output.zig").SimpleTextOutput;

pub const SimplePointer = @import("protocol/simple_pointer.zig").SimplePointer;
pub const AbsolutePointer = @import("protocol/absolute_pointer.zig").AbsolutePointer;

pub const SerialIo = @import("protocol/serial_io.zig").SerialIo;

pub const GraphicsOutput = @import("protocol/graphics_output.zig").GraphicsOutput;

pub const edid = @import("protocol/edid.zig");

pub const SimpleNetwork = @import("protocol/simple_network.zig").SimpleNetwork;
pub const ManagedNetwork = @import("protocol/managed_network.zig").ManagedNetwork;

pub const Ip6ServiceBinding = ServiceBinding(.{
    .time_low = 0xec835dd3,
    .time_mid = 0xfe0f,
    .time_high_and_version = 0x617b,
    .clock_seq_high_and_reserved = 0xa6,
    .clock_seq_low = 0x21,
    .node = [_]u8{ 0xb3, 0x50, 0xc3, 0xe1, 0x33, 0x88 },
});
pub const Ip6 = @import("protocol/ip6.zig").Ip6;
pub const Ip6Config = @import("protocol/ip6_config.zig").Ip6Config;

pub const Udp6ServiceBinding = ServiceBinding(.{
    .time_low = 0x66ed4721,
    .time_mid = 0x3c98,
    .time_high_and_version = 0x4d3e,
    .clock_seq_high_and_reserved = 0x81,
    .clock_seq_low = 0xe3,
    .node = [_]u8{ 0xd0, 0x3d, 0xd3, 0x9a, 0x72, 0x54 },
});
pub const Udp6 = @import("protocol/udp6.zig").Udp6;

pub const HiiDatabase = @import("protocol/hii_database.zig").HiiDatabase;
pub const HiiPopup = @import("protocol/hii_popup.zig").HiiPopup;

test {
    @setEvalBranchQuota(2000);
    @import("std").testing.refAllDeclsRecursive(@This());
}
const std = @import("std");
const uefi = std.os.uefi;
const Event = uefi.Event;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// Protocol for touchscreens.
pub const AbsolutePointer = extern struct {
    _reset: *const fn (*AbsolutePointer, bool) callconv(cc) Status,
    _get_state: *const fn (*const AbsolutePointer, *State) callconv(cc) Status,
    wait_for_input: Event,
    mode: *Mode,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const GetStateError = uefi.UnexpectedError || error{ NotReady, DeviceError };

    /// Resets the pointer device hardware.
    pub fn reset(self: *AbsolutePointer, verify: bool) ResetError!void {
        switch (self._reset(self, verify)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Retrieves the current state of a pointer device.
    pub fn getState(self: *const AbsolutePointer) GetStateError!State {
        var state: State = undefined;
        switch (self._get_state(self, &state)) {
            .success => return state,
            .not_ready => return Error.NotReady,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x8d59d32b,
        .time_mid = 0xc655,
        .time_high_and_version = 0x4ae9,
        .clock_seq_high_and_reserved = 0x9b,
        .clock_seq_low = 0x15,
        .node = [_]u8{ 0xf2, 0x59, 0x04, 0x99, 0x2a, 0x43 },
    };

    pub const Mode = extern struct {
        absolute_min_x: u64,
        absolute_min_y: u64,
        absolute_min_z: u64,
        absolute_max_x: u64,
        absolute_max_y: u64,
        absolute_max_z: u64,
        attributes: Attributes,

        pub const Attributes = packed struct(u32) {
            supports_alt_active: bool,
            supports_pressure_as_z: bool,
            _pad: u30 = 0,
        };
    };

    pub const State = extern struct {
        current_x: u64,
        current_y: u64,
        current_z: u64,
        active_buttons: ActiveButtons,

        pub const ActiveButtons = packed struct(u32) {
            touch_active: bool,
            alt_active: bool,
            _pad: u30 = 0,
        };
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

pub const BlockIo = extern struct {
    const Self = @This();

    revision: u64,
    media: *BlockMedia,

    _reset: *const fn (*BlockIo, extended_verification: bool) callconv(cc) Status,
    _read_blocks: *const fn (*BlockIo, media_id: u32, lba: u64, buffer_size: usize, buf: [*]u8) callconv(cc) Status,
    _write_blocks: *const fn (*BlockIo, media_id: u32, lba: u64, buffer_size: usize, buf: [*]const u8) callconv(cc) Status,
    _flush_blocks: *const fn (*BlockIo) callconv(cc) Status,

    pub const ResetError = uefi.UnexpectedError || error{DeviceError};
    pub const ReadBlocksError = uefi.UnexpectedError || error{
        DeviceError,
        NoMedia,
        BadBufferSize,
        InvalidParameter,
    };
    pub const WriteBlocksError = uefi.UnexpectedError || error{
        WriteProtected,
        NoMedia,
        MediaChanged,
        DeviceError,
        BadBufferSize,
        InvalidParameter,
    };
    pub const FlushBlocksError = uefi.UnexpectedError || error{
        DeviceError,
        NoMedia,
    };

    /// Resets the block device hardware.
    pub fn reset(self: *Self, extended_verification: bool) ResetError!void {
        switch (self._reset(self, extended_verification)) {
            .success => {},
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Reads the number of requested blocks from the device.
    pub fn readBlocks(self: *Self, media_id: u32, lba: u64, buf: []u8) ReadBlocksError!void {
        switch (self._read_blocks(self, media_id, lba, buf.len, buf.ptr)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .no_media => return Error.NoMedia,
            .bad_buffer_size => return Error.BadBufferSize,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Writes a specified number of blocks to the device.
    pub fn writeBlocks(self: *Self, media_id: u32, lba: u64, buf: []const u8) WriteBlocksError!void {
        switch (self._write_blocks(self, media_id, lba, buf.len, buf.ptr)) {
            .success => {},
            .write_protected => return Error.WriteProtected,
            .no_media => return Error.NoMedia,
            .media_changed => return Error.MediaChanged,
            .device_error => return Error.DeviceError,
            .bad_buffer_size => return Error.BadBufferSize,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Flushes all modified data to a physical block device.
    pub fn flushBlocks(self: *Self) FlushBlocksError!void {
        switch (self._flush_blocks(self)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .no_media => return Error.NoMedia,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = uefi.Guid{
        .time_low = 0x964e5b21,
        .time_mid = 0x6459,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x39,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };

    pub const BlockMedia = extern struct {
        /// The current media ID. If the media changes, this value is changed.
        media_id: u32,

        /// `true` if the media is removable; otherwise, `false`.
        removable_media: bool,
        /// `true` if there is a media currently present in the device
        media_present: bool,
        /// `true` if the `BlockIo` was produced to abstract
        /// partition structures on the disk. `false` if the `BlockIo` was
        /// produced to abstract the logical blocks on a hardware device.
        logical_partition: bool,
        /// `true` if the media is marked read-only otherwise, `false`. This field
        /// shows the read-only status as of the most recent `WriteBlocks()`
        read_only: bool,
        /// `true` if the WriteBlocks() function caches write data.
        write_caching: bool,

        /// The intrinsic block size of the device. If the media changes, then this
        // field is updated. Returns the number of bytes per logical block.
        block_size: u32,
        /// Supplies the alignment requirement for any buffer used in a data
        /// transfer. IoAlign values of 0 and 1 mean that the buffer can be
        /// placed anywhere in memory. Otherwise, IoAlign must be a power of
        /// 2, and the requirement is that the start address of a buffer must be
        /// evenly divisible by IoAlign with no remainder.
        io_align: u32,
        /// The last LBA on the device. If the media changes, then this field is updated.
        last_block: u64,

        // Revision 2
        lowest_aligned_lba: u64,
        logical_blocks_per_physical_block: u32,
        optimal_transfer_length_granularity: u32,
    };
};
const std = @import("../../../std.zig");
const mem = std.mem;
const uefi = std.os.uefi;
const Allocator = mem.Allocator;
const Guid = uefi.Guid;
const assert = std.debug.assert;

// All Device Path Nodes are byte-packed and may appear on any byte boundary.
// All code references to device path nodes must assume all fields are unaligned.

pub const DevicePath = extern struct {
    type: uefi.DevicePath.Type,
    subtype: u8,
    length: u16 align(1),

    pub const CreateFileDevicePathError = Allocator.Error;

    pub const guid align(8) = Guid{
        .time_low = 0x09576e91,
        .time_mid = 0x6d3f,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x39,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };

    /// Returns the next DevicePath node in the sequence, if any.
    pub fn next(self: *const DevicePath) ?*const DevicePath {
        const bytes: [*]const u8 = @ptrCast(self);
        const next_node: *const DevicePath = @ptrCast(bytes + self.length);
        if (next_node.type == .end and @as(uefi.DevicePath.End.Subtype, @enumFromInt(self.subtype)) == .end_entire)
            return null;

        return next_node;
    }

    /// Calculates the total length of the device path structure in bytes, including the end of device path node.
    pub fn size(self: *const DevicePath) usize {
        var node = self;

        while (node.next()) |next_node| {
            node = next_node;
        }

        return (@intFromPtr(node) + node.length) - @intFromPtr(self);
    }

    /// Creates a file device path from the existing device path and a file path.
    pub fn createFileDevicePath(
        self: *const DevicePath,
        allocator: Allocator,
        path: []const u16,
    ) CreateFileDevicePathError!*const DevicePath {
        const path_size = self.size();

        // 2 * (path.len + 1) for the path and its null terminator, which are u16s
        // DevicePath for the extra node before the end
        var buf = try allocator.alloc(u8, path_size + 2 * (path.len + 1) + @sizeOf(DevicePath));

        @memcpy(buf[0..path_size], @as([*]const u8, @ptrCast(self))[0..path_size]);

        // Pointer to the copy of the end node of the current chain, which is - 4 from the buffer
        // as the end node itself is 4 bytes (type: u8 + subtype: u8 + length: u16).
        var new = @as(*uefi.DevicePath.Media.FilePathDevicePath, @ptrCast(buf.ptr + path_size - 4));

        new.type = .media;
        new.subtype = .file_path;
        new.length = @sizeOf(uefi.DevicePath.Media.FilePathDevicePath) + 2 * (@as(u16, @intCast(path.len)) + 1);

        // The same as new.getPath(), but not const as we're filling it in.
        var ptr = @as([*:0]align(1) u16, @ptrCast(@as([*]u8, @ptrCast(new)) + @sizeOf(uefi.DevicePath.Media.FilePathDevicePath)));

        for (path, 0..) |s, i|
            ptr[i] = s;

        ptr[path.len] = 0;

        var end = @as(*uefi.DevicePath.End.EndEntireDevicePath, @ptrCast(@constCast(@as(*DevicePath, @ptrCast(new)).next().?)));
        end.type = .end;
        end.subtype = .end_entire;
        end.length = @sizeOf(uefi.DevicePath.End.EndEntireDevicePath);

        return @as(*DevicePath, @ptrCast(buf.ptr));
    }

    pub fn getDevicePath(self: *const DevicePath) ?uefi.DevicePath {
        inline for (@typeInfo(uefi.DevicePath).@"union".fields) |ufield| {
            const enum_value = std.meta.stringToEnum(uefi.DevicePath.Type, ufield.name);

            // Got the associated union type for self.type, now
            // we need to initialize it and its subtype
            if (self.type == enum_value) {
                const subtype = self.initSubtype(ufield.type);
                if (subtype) |sb| {
                    // e.g. return .{ .hardware = .{ .pci = @ptrCast(...) } }
                    return @unionInit(uefi.DevicePath, ufield.name, sb);
                }
            }
        }

        return null;
    }

    pub fn initSubtype(self: *const DevicePath, comptime TUnion: type) ?TUnion {
        const type_info = @typeInfo(TUnion).@"union";
        const TTag = type_info.tag_type.?;

        inline for (type_info.fields) |subtype| {
            // The tag names match the union names, so just grab that off the enum
            const tag_val: u8 = @intFromEnum(@field(TTag, subtype.name));

            if (self.subtype == tag_val) {
                // e.g. expr = .{ .pci = @ptrCast(...) }
                return @unionInit(TUnion, subtype.name, @as(subtype.type, @ptrCast(self)));
            }
        }

        return null;
    }
};

comptime {
    assert(4 == @sizeOf(DevicePath));
    assert(1 == @alignOf(DevicePath));

    assert(0 == @offsetOf(DevicePath, "type"));
    assert(1 == @offsetOf(DevicePath, "subtype"));
    assert(2 == @offsetOf(DevicePath, "length"));
}
const std = @import("../../../std.zig");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Handle = uefi.Handle;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

/// EDID information for an active video output device
pub const Active = extern struct {
    size_of_edid: u32,
    edid: ?[*]u8,

    pub const guid align(8) = Guid{
        .time_low = 0xbd8c1056,
        .time_mid = 0x9f36,
        .time_high_and_version = 0x44ec,
        .clock_seq_high_and_reserved = 0x92,
        .clock_seq_low = 0xa8,
        .node = [_]u8{ 0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86 },
    };
};

/// EDID information for a video output device
pub const Discovered = extern struct {
    size_of_edid: u32,
    edid: ?[*]u8,

    pub const guid align(8) = Guid{
        .time_low = 0x1c0c34f6,
        .time_mid = 0xd380,
        .time_high_and_version = 0x41fa,
        .clock_seq_high_and_reserved = 0xa0,
        .clock_seq_low = 0x49,
        .node = [_]u8{ 0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa },
    };
};

/// Override EDID information
pub const Override = extern struct {
    _get_edid: *const fn (*const Override, *const Handle, *Attributes, *usize, *?[*]u8) callconv(cc) Status,

    pub const GetEdidError = uefi.UnexpectedError || error{
        Unsupported,
    };

    /// Returns policy information and potentially a replacement EDID for the specified video output device.
    pub fn getEdid(self: *const Override, handle: Handle) GetEdidError!Edid {
        var size: usize = undefined;
        var ptr: ?[*]u8 = undefined;
        var attributes: Attributes = undefined;
        switch (self._get_edid(self, &handle, &attributes, &size, &ptr)) {
            .success => {},
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }

        return .{
            .attributes = attributes,
            .edid = if (ptr) |p| p[0..size] else null,
        };
    }

    pub const guid align(8) = Guid{
        .time_low = 0x48ecb431,
        .time_mid = 0xfb72,
        .time_high_and_version = 0x45c0,
        .clock_seq_high_and_reserved = 0xa9,
        .clock_seq_low = 0x22,
        .node = [_]u8{ 0xf4, 0x58, 0xfe, 0x04, 0x0b, 0xd5 },
    };

    pub const Edid = struct {
        attributes: Attributes,
        edid: ?[]u8,
    };

    pub const Attributes = packed struct(u32) {
        dont_override: bool,
        enable_hot_plug: bool,
        _pad: u30 = 0,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const io = std.io;
const Guid = uefi.Guid;
const Time = uefi.Time;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

pub const File = extern struct {
    revision: u64,
    _open: *const fn (*const File, **File, [*:0]const u16, OpenMode, Attributes) callconv(cc) Status,
    _close: *const fn (*File) callconv(cc) Status,
    _delete: *const fn (*File) callconv(cc) Status,
    _read: *const fn (*File, *usize, [*]u8) callconv(cc) Status,
    _write: *const fn (*File, *usize, [*]const u8) callconv(cc) Status,
    _get_position: *const fn (*const File, *u64) callconv(cc) Status,
    _set_position: *const fn (*File, u64) callconv(cc) Status,
    _get_info: *const fn (*const File, *align(8) const Guid, *usize, ?[*]u8) callconv(cc) Status,
    _set_info: *const fn (*File, *align(8) const Guid, usize, [*]const u8) callconv(cc) Status,
    _flush: *const fn (*File) callconv(cc) Status,

    pub const OpenError = uefi.UnexpectedError || error{
        NotFound,
        NoMedia,
        MediaChanged,
        DeviceError,
        VolumeCorrupted,
        WriteProtected,
        AccessDenied,
        OutOfResources,
        VolumeFull,
        InvalidParameter,
    };
    pub const CloseError = uefi.UnexpectedError;
    pub const SeekError = uefi.UnexpectedError || error{
        Unsupported,
        DeviceError,
    };
    pub const ReadError = uefi.UnexpectedError || error{
        NoMedia,
        DeviceError,
        VolumeCorrupted,
        BufferTooSmall,
    };
    pub const WriteError = uefi.UnexpectedError || error{
        Unsupported,
        NoMedia,
        DeviceError,
        VolumeCorrupted,
        WriteProtected,
        AccessDenied,
        VolumeFull,
    };
    pub const GetInfoSizeError = uefi.UnexpectedError || error{
        Unsupported,
        NoMedia,
        DeviceError,
        VolumeCorrupted,
    };
    pub const GetInfoError = GetInfoSizeError || error{
        BufferTooSmall,
    };
    pub const SetInfoError = uefi.UnexpectedError || error{
        Unsupported,
        NoMedia,
        DeviceError,
        VolumeCorrupted,
        WriteProtected,
        AccessDenied,
        VolumeFull,
        BadBufferSize,
    };
    pub const FlushError = uefi.UnexpectedError || error{
        DeviceError,
        VolumeCorrupted,
        WriteProtected,
        AccessDenied,
        VolumeFull,
    };

    pub const SeekableStream = io.SeekableStream(
        *File,
        SeekError,
        SeekError,
        setPosition,
        seekBy,
        getPosition,
        getEndPos,
    );
    pub const Reader = io.Reader(*File, ReadError, read);
    pub const Writer = io.Writer(*File, WriteError, write);

    pub fn seekableStream(self: *File) SeekableStream {
        return .{ .context = self };
    }

    pub fn reader(self: *File) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *File) Writer {
        return .{ .context = self };
    }

    pub fn open(
        self: *const File,
        file_name: [*:0]const u16,
        mode: OpenMode,
        create_attributes: Attributes,
    ) OpenError!*File {
        var new: *File = undefined;
        switch (self._open(
            self,
            &new,
            file_name,
            mode,
            create_attributes,
        )) {
            .success => return new,
            .not_found => return Error.NotFound,
            .no_media => return Error.NoMedia,
            .media_changed => return Error.MediaChanged,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            .write_protected => return Error.WriteProtected,
            .access_denied => return Error.AccessDenied,
            .out_of_resources => return Error.OutOfResources,
            .volume_full => return Error.VolumeFull,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn close(self: *File) CloseError!void {
        switch (self._close(self)) {
            .success => {},
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Delete the file.
    ///
    /// Returns true if the file was deleted, false if the file was not deleted, which is a warning
    /// according to the UEFI specification.
    pub fn delete(self: *File) uefi.UnexpectedError!bool {
        switch (self._delete(self)) {
            .success => return true,
            .warn_delete_failure => return false,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn read(self: *File, buffer: []u8) ReadError!usize {
        var size: usize = buffer.len;
        switch (self._read(self, &size, buffer.ptr)) {
            .success => return size,
            .no_media => return Error.NoMedia,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            .buffer_too_small => return Error.BufferTooSmall,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn write(self: *File, buffer: []const u8) WriteError!usize {
        var size: usize = buffer.len;
        switch (self._write(self, &size, buffer.ptr)) {
            .success => return size,
            .unsupported => return Error.Unsupported,
            .no_media => return Error.NoMedia,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            .write_protected => return Error.WriteProtected,
            .access_denied => return Error.AccessDenied,
            .volume_full => return Error.VolumeFull,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn getPosition(self: *const File) SeekError!u64 {
        var position: u64 = undefined;
        switch (self._get_position(self, &position)) {
            .success => return position,
            .unsupported => return Error.Unsupported,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    fn getEndPos(self: *File) SeekError!u64 {
        const start_pos = try self.getPosition();
        // ignore error
        defer self.setPosition(start_pos) catch {};

        try self.setPosition(end_of_file);
        return self.getPosition();
    }

    pub fn setPosition(self: *File, position: u64) SeekError!void {
        switch (self._set_position(self, position)) {
            .success => {},
            .unsupported => return Error.Unsupported,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    fn seekBy(self: *File, offset: i64) SeekError!void {
        var pos = try self.getPosition();
        const seek_back = offset < 0;
        const amt = @abs(offset);
        if (seek_back) {
            pos += amt;
        } else {
            pos -= amt;
        }
        try self.setPosition(pos);
    }

    pub fn getInfoSize(self: *const File, comptime info: std.meta.Tag(Info)) GetInfoError!usize {
        const InfoType = @FieldType(Info, @tagName(info));

        var len: usize = 0;
        switch (self._get_info(self, &InfoType.guid, &len, null)) {
            .success, .buffer_too_small => return len,
            .unsupported => return Error.Unsupported,
            .no_media => return Error.NoMedia,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// If `buffer` is too small to contain all of the info, this function returns
    /// `Error.BufferTooSmall`. You should call `getInfoSize` first to determine
    /// how big the buffer should be to safely call this function.
    pub fn getInfo(
        self: *const File,
        comptime info: std.meta.Tag(Info),
        buffer: []u8,
    ) GetInfoError!*@FieldType(Info, @tagName(info)) {
        const InfoType = @FieldType(Info, @tagName(info));

        var len = buffer.len;
        switch (self._get_info(
            self,
            &InfoType.guid,
            &len,
            buffer.ptr,
        )) {
            .success => return @as(*InfoType, @ptrCast(buffer.ptr)),
            .buffer_too_small => return Error.BufferTooSmall,
            .unsupported => return Error.Unsupported,
            .no_media => return Error.NoMedia,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn setInfo(
        self: *File,
        comptime info: std.meta.Tag(Info),
        data: *const @FieldType(Info, @tagName(info)),
    ) SetInfoError!void {
        const InfoType = @FieldType(Info, @tagName(info));

        const attached_str: [*:0]const u16 = switch (info) {
            .file => data.getFileName(),
            .file_system, .volume_label => data.getVolumeLabel(),
        };
        const attached_str_len = std.mem.sliceTo(attached_str, 0).len;

        // add the length (not +1 for sentinel) because `@sizeOf(InfoType)`
        // already contains the first utf16 char
        const len = @sizeOf(InfoType) + (attached_str_len * 2);

        switch (self._set_info(self, &InfoType.guid, len, @ptrCast(data))) {
            .success => {},
            .unsupported => return Error.Unsupported,
            .no_media => return Error.NoMedia,
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            .write_protected => return Error.WriteProtected,
            .access_denied => return Error.AccessDenied,
            .volume_full => return Error.VolumeFull,
            .bad_buffer_size => return Error.BadBufferSize,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn flush(self: *File) FlushError!void {
        switch (self._flush(self)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .volume_corrupted => return Error.VolumeCorrupted,
            .write_protected => return Error.WriteProtected,
            .access_denied => return Error.AccessDenied,
            .volume_full => return Error.VolumeFull,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const OpenMode = enum(u64) {
        pub const Bits = packed struct(u64) {
            // 0x0000000000000001
            read: bool = false,
            // 0x0000000000000002
            write: bool = false,
            _pad: u61 = 0,
            // 0x8000000000000000
            create: bool = false,
        };

        read = @bitCast(Bits{ .read = true }),
        read_write = @bitCast(Bits{ .read = true, .write = true }),
        read_write_create = @bitCast(Bits{ .read = true, .write = true, .create = true }),
    };

    pub const Attributes = packed struct(u64) {
        // 0x0000000000000001
        read_only: bool = false,
        // 0x0000000000000002
        hidden: bool = false,
        // 0x0000000000000004
        system: bool = false,
        // 0x0000000000000008
        reserved: bool = false,
        // 0x0000000000000010
        directory: bool = false,
        // 0x0000000000000020
        archive: bool = false,
        _pad: u58 = 0,
    };

    pub const Info = union(enum) {
        file: Info.File,
        file_system: FileSystem,
        volume_label: VolumeLabel,

        pub const File = extern struct {
            size: u64,
            file_size: u64,
            physical_size: u64,
            create_time: Time,
            last_access_time: Time,
            modification_time: Time,
            attribute: Attributes,
            _file_name: u16,

            pub fn getFileName(self: *const Info.File) [*:0]const u16 {
                return @as([*:0]const u16, @ptrCast(&self._file_name));
            }

            pub const guid align(8) = Guid{
                .time_low = 0x09576e92,
                .time_mid = 0x6d3f,
                .time_high_and_version = 0x11d2,
                .clock_seq_high_and_reserved = 0x8e,
                .clock_seq_low = 0x39,
                .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
            };
        };

        pub const FileSystem = extern struct {
            size: u64,
            read_only: bool,
            volume_size: u64,
            free_space: u64,
            block_size: u32,
            _volume_label: u16,

            pub fn getVolumeLabel(self: *const FileSystem) [*:0]const u16 {
                return @as([*:0]const u16, @ptrCast(&self._volume_label));
            }

            pub const guid align(8) = Guid{
                .time_low = 0x09576e93,
                .time_mid = 0x6d3f,
                .time_high_and_version = 0x11d2,
                .clock_seq_high_and_reserved = 0x8e,
                .clock_seq_low = 0x39,
                .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
            };
        };

        pub const VolumeLabel = extern struct {
            _volume_label: u16,

            pub fn getVolumeLabel(self: *const VolumeLabel) [*:0]const u16 {
                return @as([*:0]const u16, @ptrCast(&self._volume_label));
            }

            pub const guid align(8) = Guid{
                .time_low = 0xdb47d7d3,
                .time_mid = 0xfe81,
                .time_high_and_version = 0x11d3,
                .clock_seq_high_and_reserved = 0x9a,
                .clock_seq_low = 0x35,
                .node = [_]u8{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d },
            };
        };
    };

    const end_of_file: u64 = 0xffffffffffffffff;
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;

pub const GraphicsOutput = extern struct {
    _query_mode: *const fn (*const GraphicsOutput, u32, *usize, **Mode.Info) callconv(cc) Status,
    _set_mode: *const fn (*GraphicsOutput, u32) callconv(cc) Status,
    _blt: *const fn (*GraphicsOutput, ?[*]BltPixel, BltOperation, usize, usize, usize, usize, usize, usize, usize) callconv(cc) Status,
    mode: *Mode,

    pub const QueryModeError = uefi.UnexpectedError || error{
        DeviceError,
        InvalidParameter,
    };
    pub const SetModeError = uefi.UnexpectedError || error{
        DeviceError,
        Unsupported,
    };
    pub const BltError = uefi.UnexpectedError || error{
        InvalidParameter,
        DeviceError,
    };

    /// Returns information for an available graphics mode that the graphics device and the set of active video output devices supports.
    pub fn queryMode(self: *const GraphicsOutput, mode_id: u32) QueryModeError!*Mode.Info {
        var size_of_info: usize = undefined;
        var info: *Mode.Info = undefined;
        switch (self._query_mode(self, mode_id, &size_of_info, &info)) {
            .success => return info,
            .device_error => return Error.DeviceError,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Set the video device into the specified mode and clears the visible portions of the output display to black.
    pub fn setMode(self: *GraphicsOutput, mode_id: u32) SetModeError!void {
        switch (self._set_mode(self, mode_id)) {
            .success => {},
            .device_error => return Error.DeviceError,
            .unsupported => return Error.Unsupported,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Blt a rectangle of pixels on the graphics screen. Blt stands for BLock Transfer.
    pub fn blt(
        self: *GraphicsOutput,
        blt_buffer: ?[*]BltPixel,
        blt_operation: BltOperation,
        source_x: usize,
        source_y: usize,
        destination_x: usize,
        destination_y: usize,
        width: usize,
        height: usize,
        delta: usize,
    ) BltError!void {
        switch (self._blt(
            self,
            blt_buffer,
            blt_operation,
            source_x,
            source_y,
            destination_x,
            destination_y,
            width,
            height,
            delta,
        )) {
            .success => {},
            .device_error => return Error.DeviceError,
            .invalid_parameter => return Error.InvalidParameter,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x9042a9de,
        .time_mid = 0x23dc,
        .time_high_and_version = 0x4a38,
        .clock_seq_high_and_reserved = 0x96,
        .clock_seq_low = 0xfb,
        .node = [_]u8{ 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a },
    };

    pub const Mode = extern struct {
        max_mode: u32,
        mode: u32,
        info: *Info,
        size_of_info: usize,
        frame_buffer_base: u64,
        frame_buffer_size: usize,

        pub const Info = extern struct {
            version: u32,
            horizontal_resolution: u32,
            vertical_resolution: u32,
            pixel_format: PixelFormat,
            pixel_information: PixelBitmask,
            pixels_per_scan_line: u32,
        };
    };

    pub const PixelFormat = enum(u32) {
        red_green_blue_reserved_8_bit_per_color,
        blue_green_red_reserved_8_bit_per_color,
        bit_mask,
        blt_only,
    };

    pub const PixelBitmask = extern struct {
        red_mask: u32,
        green_mask: u32,
        blue_mask: u32,
        reserved_mask: u32,
    };

    pub const BltPixel = extern struct {
        blue: u8,
        green: u8,
        red: u8,
        reserved: u8 = undefined,
    };

    pub const BltOperation = enum(u32) {
        blt_video_fill,
        blt_video_to_blt_buffer,
        blt_buffer_to_video,
        blt_video_to_video,
        graphics_output_blt_operation_max,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const hii = uefi.hii;
const cc = uefi.cc;
const Error = Status.Error;

/// Database manager for HII-related data structures.
pub const HiiDatabase = extern struct {
    _new_package_list: Status, // TODO
    _remove_package_list: *const fn (*HiiDatabase, hii.Handle) callconv(cc) Status,
    _update_package_list: *const fn (*HiiDatabase, hii.Handle, *const hii.PackageList) callconv(cc) Status,
    _list_package_lists: *const fn (*const HiiDatabase, u8, ?*const Guid, *usize, [*]hii.Handle) callconv(cc) Status,
    _export_package_lists: *const fn (*const HiiDatabase, ?hii.Handle, *usize, [*]hii.PackageList) callconv(cc) Status,
    _register_package_notify: Status, // TODO
    _unregister_package_notify: Status, // TODO
    _find_keyboard_layouts: Status, // TODO
    _get_keyboard_layout: Status, // TODO
    _set_keyboard_layout: Status, // TODO
    _get_package_list_handle: Status, // TODO

    pub const RemovePackageListError = uefi.UnexpectedError || error{NotFound};
    pub const UpdatePackageListError = uefi.UnexpectedError || error{
        OutOfResources,
        InvalidParameter,
        NotFound,
    };
    pub const ListPackageListsError = uefi.UnexpectedError || error{
        BufferTooSmall,
        InvalidParameter,
        NotFound,
    };
    pub const ExportPackageListError = uefi.UnexpectedError || error{
        BufferTooSmall,
        InvalidParameter,
        NotFound,
    };

    /// Removes a package list from the HII database.
    pub fn removePackageList(self: *HiiDatabase, handle: hii.Handle) !void {
        switch (self._remove_package_list(self, handle)) {
            .success => {},
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Update a package list in the HII database.
    pub fn updatePackageList(
        self: *HiiDatabase,
        handle: hii.Handle,
        buffer: *const hii.PackageList,
    ) UpdatePackageListError!void {
        switch (self._update_package_list(self, handle, buffer)) {
            .success => {},
            .out_of_resources => return Error.OutOfResources,
            .invalid_parameter => return Error.InvalidParameter,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Determines the handles that are currently active in the database.
    pub fn listPackageLists(
        self: *const HiiDatabase,
        package_type: u8,
        package_guid: ?*const Guid,
        handles: []hii.Handle,
    ) ListPackageListsError![]hii.Handle {
        var len: usize = handles.len;
        switch (self._list_package_lists(
            self,
            package_type,
            package_guid,
            &len,
            handles.ptr,
        )) {
            .success => return handles[0..len],
            .buffer_too_small => return Error.BufferTooSmall,
            .invalid_parameter => return Error.InvalidParameter,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Exports the contents of one or all package lists in the HII database into a buffer.
    pub fn exportPackageLists(
        self: *const HiiDatabase,
        handle: ?hii.Handle,
        buffer: []hii.PackageList,
    ) ExportPackageListError![]hii.PackageList {
        var len = buffer.len;
        switch (self._export_package_lists(self, handle, &len, buffer.ptr)) {
            .success => return buffer[0..len],
            .buffer_too_small => return Error.BufferTooSmall,
            .invalid_parameter => return Error.InvalidParameter,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0xef9fc172,
        .time_mid = 0xa1b2,
        .time_high_and_version = 0x4693,
        .clock_seq_high_and_reserved = 0xb3,
        .clock_seq_low = 0x27,
        .node = [_]u8{ 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42 },
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Status = uefi.Status;
const hii = uefi.hii;
const cc = uefi.cc;
const Error = Status.Error;

/// Display a popup window
pub const HiiPopup = extern struct {
    revision: u64,
    _create_popup: *const fn (*const HiiPopup, PopupStyle, PopupType, hii.Handle, u16, ?*PopupSelection) callconv(cc) Status,

    pub const CreatePopupError = uefi.UnexpectedError || error{
        InvalidParameter,
        OutOfResources,
    };

    /// Displays a popup window.
    pub fn createPopup(
        self: *const HiiPopup,
        style: PopupStyle,
        popup_type: PopupType,
        handle: hii.Handle,
        msg: u16,
    ) CreatePopupError!PopupSelection {
        var res: PopupSelection = undefined;
        switch (self._create_popup(self, style, popup_type, handle, msg, &res)) {
            .success => return res,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x4311edc0,
        .time_mid = 0x6054,
        .time_high_and_version = 0x46d4,
        .clock_seq_high_and_reserved = 0x9e,
        .clock_seq_low = 0x40,
        .node = [_]u8{ 0x89, 0x3e, 0xa9, 0x52, 0xfc, 0xcc },
    };

    pub const PopupStyle = enum(u32) {
        info,
        warning,
        @"error",
    };

    pub const PopupType = enum(u32) {
        ok,
        cancel,
        yes_no,
        yes_no_cancel,
    };

    pub const PopupSelection = enum(u32) {
        ok,
        cancel,
        yes,
        no,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Event = uefi.Event;
const Status = uefi.Status;
const cc = uefi.cc;
const Error = Status.Error;
const MacAddress = uefi.MacAddress;
const Ip6 = uefi.protocol.Ip6;

pub const Ip6Config = extern struct {
    _set_data: *const fn (*const Ip6Config, DataType, usize, *const anyopaque) callconv(cc) Status,
    _get_data: *const fn (*const Ip6Config, DataType, *usize, ?*const anyopaque) callconv(cc) Status,
    _register_data_notify: *const fn (*const Ip6Config, DataType, Event) callconv(cc) Status,
    _unregister_data_notify: *const fn (*const Ip6Config, DataType, Event) callconv(cc) Status,

    pub const SetDataError = uefi.UnexpectedError || error{
        InvalidParameter,
        WriteProtected,
        AccessDenied,
        NotReady,
        BadBufferSize,
        Unsupported,
        OutOfResources,
        DeviceError,
    };
    pub const GetDataError = uefi.UnexpectedError || error{
        InvalidParameter,
        BufferTooSmall,
        NotReady,
        NotFound,
    };
    pub const RegisterDataNotifyError = uefi.UnexpectedError || error{
        InvalidParameter,
        Unsupported,
        OutOfResources,
        AccessDenied,
    };
    pub const UnregisterDataNotifyError = uefi.UnexpectedError || error{
        InvalidParameter,
        NotFound,
    };

    pub fn setData(
        self: *const Ip6Config,
        comptime data_type: std.meta.Tag(DataType),
        payload: *const std.meta.TagPayload(DataType, data_type),
    ) SetDataError!void {
        const data_size = @sizeOf(@TypeOf(payload));
        switch (self._set_data(self, data_type, data_size, @ptrCast(payload))) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .write_protected => return Error.WriteProtected,
            .access_denied => return Error.AccessDenied,
            .not_ready => return Error.NotReady,
            .bad_buffer_size => return Error.BadBufferSize,
            .unsupported => return Error.Unsupported,
            .out_of_resources => return Error.OutOfResources,
            .device_error => return Error.DeviceError,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn getData(
        self: *const Ip6Config,
        comptime data_type: std.meta.Tag(DataType),
    ) GetDataError!std.meta.TagPayload(DataType, data_type) {
        const DataPayload = std.meta.TagPayload(DataType, data_type);

        var payload: DataPayload = undefined;
        var payload_size: usize = @sizeOf(DataPayload);

        switch (self._get_data(self, data_type, &payload_size, @ptrCast(&payload))) {
            .success => return payload,
            .invalid_parameter => return Error.InvalidParameter,
            .buffer_too_small => return Error.BufferTooSmall,
            .not_ready => return Error.NotReady,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn registerDataNotify(
        self: *const Ip6Config,
        data_type: DataType,
        event: Event,
    ) RegisterDataNotifyError!void {
        switch (self._register_data_notify(self, data_type, event)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .unsupported => return Error.Unsupported,
            .out_of_resources => return Error.OutOfResources,
            .access_denied => return Error.AccessDenied,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub fn unregisterDataNotify(
        self: *const Ip6Config,
        data_type: DataType,
        event: Event,
    ) UnregisterDataNotifyError!void {
        switch (self._unregister_data_notify(self, data_type, event)) {
            .success => {},
            .invalid_parameter => return Error.InvalidParameter,
            .not_found => return Error.NotFound,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    pub const guid align(8) = Guid{
        .time_low = 0x937fe521,
        .time_mid = 0x95ae,
        .time_high_and_version = 0x4d1a,
        .clock_seq_high_and_reserved = 0x89,
        .clock_seq_low = 0x29,
        .node = [_]u8{ 0x48, 0xbc, 0xd9, 0x0a, 0xd3, 0x1a },
    };

    pub const DataType = union(enum(u32)) {
        interface_info: InterfaceInfo,
        alt_interface_id: InterfaceId,
        policy: Policy,
        dup_addr_detect_transmits: DupAddrDetectTransmits,
        manual_address: [*]ManualAddress,
        gateway: [*]Ip6.Address,
        dns_server: [*]Ip6.Address,
    };

    pub const InterfaceInfo = extern struct {
        name: [32]u16,
        if_type: u8,
        hw_address_size: u32,
        hw_address: MacAddress,
        address_info_count: u32,
        address_info: [*]Ip6.AddressInfo,
        route_count: u32,
        route_table: Ip6.RouteTable,
    };

    pub const InterfaceId = extern struct {
        id: [8]u8,
    };

    pub const Policy = enum(u32) {
        manual,
        automatic,
    };

    pub const DupAddrDetectTransmits = extern struct {
        dup_addr_detect_transmits: u32,
    };

    pub const ManualAddress = extern struct {
        address: Ip6.Address,
        is_anycast: bool,
        prefix_length: u8,
    };
};
const std = @import("std");
const uefi = std.os.uefi;
const Guid = uefi.Guid;
const Event = uefi.Event;
const Status = uefi.Status;
const MacAddress = uefi.MacAddress;
const ManagedNetworkConfigData = uefi.protocol.ManagedNetwork.Config;
const SimpleNetwork = uefi.protocol.SimpleNetwork;
const cc = uefi.cc;
const Error = Status.Error;

pub const Ip6 = extern struct {
    _get_mode_data: *const fn (*const Ip6, ?*Mode, ?*ManagedNetworkConfigData, ?*SimpleNetwork) callconv(cc) Status,
    _configure: *const fn (*Ip6, ?*const Config) callconv(cc) Status,
    _groups: *const fn (*Ip6, bool, ?*const Address) callconv(cc) Status,
    _routes: *const fn (*Ip6, bool, ?*const Address, u8, ?*const Address) callconv(cc) Status,
    _neighbors: *const fn (*Ip6, bool, *const Address, ?*const MacAddress, u32, bool) callconv(cc) Status,
    _transmit: *const fn (*Ip6, *CompletionToken) callconv(cc) Status,
    _receive: *const fn (*Ip6, *CompletionToken) callconv(cc) Status,
    _cancel: *const fn (*Ip6, ?*CompletionToken) callconv(cc) Status,
    _poll: *const fn (*Ip6) callconv(cc) Status,

    pub const GetModeDataError = uefi.UnexpectedError || error{
        InvalidParameter,
        OutOfResources,
    };
    pub const ConfigureError = uefi.UnexpectedError || error{
        InvalidParameter,
        OutOfResources,
        NoMapping,
        AlreadyStarted,
        DeviceError,
        Unsupported,
    };
    pub const GroupsError = uefi.UnexpectedError || error{
        InvalidParameter,
        NotStarted,
        OutOfResources,
        Unsupported,
        AlreadyStarted,
        NotFound,
        DeviceError,
    };
    pub const RoutesError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        OutOfResources,
        NotFound,
        AccessDenied,
    };
    pub const NeighborsError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        OutOfResources,
        NotFound,
        AccessDenied,
    };
    pub const TransmitError = uefi.UnexpectedError || error{
        NotStarted,
        NoMapping,
        InvalidParameter,
        AccessDenied,
        NotReady,
        NotFound,
        OutOfResources,
        BufferTooSmall,
        BadBufferSize,
        DeviceError,
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
        DeviceError,
    };
    pub const PollError = uefi.UnexpectedError || error{
        NotStarted,
        InvalidParameter,
        DeviceError,
        Timeout,
    };

    pub const ModeData = struct {
        ip6_mode: Mode,
        mnp_config: ManagedNetworkConfigData,
        snp_mode: SimpleNetwork,
    };

    /// Gets the current operational settings for this instance of the EFI IPv6 Protocol driver.
    pub fn getModeData(self: *const Ip6) GetModeDataError!ModeData {
        var data: ModeData = undefined;
        switch (self._get_mode_data(self, &data.ip6_mode, &data.mnp_config, &data.snp_mode)) {
            .success => return data,
            .invalid_parameter => return Error.InvalidParameter,
            .out_of_resources => return Error.OutOfResources,
            else => |status| return uefi.unexpectedStatus(status),
        }
    }

    /// Assign IPv6 address and other configuration parameter to this EFI IPv6 Protocol driver instance.
    ///
    /// To reset the configuration, use `disable` instead.
    pub fn configure(self: *Ip6, ip6_config_data: *const Config) Configu```
