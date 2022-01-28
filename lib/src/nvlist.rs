// Copyright 2021 Oxide Computer Company

use std::os::raw::c_void;

#[allow(dead_code)]
#[derive(Debug)]
#[repr(C)]
pub struct NvList {
    pub version: i32,
    pub nvflags: u32,
    pub private: u64,
    pub flags: u32,
    pub pad: i32,
}

#[derive(Debug)]
#[repr(C)]
pub struct NvPair {
    pub size: i32,
    pub name_size: i16,
    pub reserve: i16,
    pub value_count: i32,
    pub typ: NvDataType,
    /* name string */
    /* aligned value */
}

#[derive(Debug)]
#[repr(C)]
pub struct NvHeader {
    pub encoding: Encoding,
    pub endian: Endian,
    pub reserved1: u8,
    pub reserved2: u8,
}

#[derive(Debug)]
#[repr(C)]
pub struct NvPriv {
    pub list: *mut Nvp,
    pub last: *mut Nvp,
    pub curr: *mut Nvp,
}

#[allow(dead_code)]
#[derive(Debug)]
#[repr(u8)]
pub enum Encoding {
    Native = 0,
    Xdr = 1,
}

#[allow(dead_code)]
#[derive(Debug)]
#[repr(u8)]
pub enum Endian {
    BigEndian = 0,
    LittleEndian = 1,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct NVP<'a> {
    pub name: &'a str,
    pub value: Value<'a>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Value<'a> {
    DontCare,
    Unknown,
    Boolean(bool),
    Byte(u8),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Str(&'a str),
    ByteArray(&'a [u8]),
    Int16Array(&'a [i16]),
    Uint16Array(&'a [u16]),
    Int32Array(&'a [i32]),
    Uint32Array(&'a [u32]),
    Int64Array(&'a [i64]),
    Uint64Array(&'a [u64]),
    StringArray(&'a [&'a str]),
    HRTime, //TODO
    NvList(Vec<NVP<'a>>),
    NvListArray, //TODO
    BooleanVal(bool),
    Int8(i8),
    Uint8(u8),
    BooleanArray(&'a [bool]),
    Int8Array(&'a [i8]),
    Uint8Array(&'a [u8]),
}

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
#[repr(i32)]
pub enum NvDataType {
    DontCare = -1,
    Unknown = 0,
    Boolean = 1,
    Byte = 2,
    Int16 = 3,
    Uint16 = 4,
    Int32 = 5,
    Uint32 = 6,
    Int64 = 7,
    Uint64 = 8,
    Str = 9,
    ByteArray = 10,
    Int16Array = 11,
    Uint16Array = 12,
    Int32Array = 13,
    Uint32Array = 14,
    Int64Array = 15,
    Uint64Array = 16,
    StringArray = 17,
    HRTime = 18,
    NvList = 19,
    NvListArray = 20,
    BooleanValue = 21,
    Int8 = 22,
    Uint8 = 23,
    BooleanArray = 24,
    Int8Array = 25,
    Uint8Array = 26,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Nvi {
    pub next: *mut Nvp,
    pub prev: *mut Nvp,
    pub hash_next: *mut Nvp,
}

#[repr(C)]
pub union NviU {
    pub align: u64,
    pub nvi: Nvi,
}

#[repr(C)]
pub struct Nvp {
    pub un: NviU,
    pub nvp: NvPair,
}

#[allow(dead_code)]
#[repr(C)]
pub struct NvAlloc {
    pub ops: *mut NvOps,
    pub arg: *mut c_void,
}

#[allow(dead_code)]
#[repr(C)]
pub struct NvOps {
    pub init: fn(*mut NvAlloc), //WARNING: no va_list here
    pub fini: fn(*mut NvAlloc),
    pub alloc: fn(*mut NvAlloc, usize),
    pub free: fn(*mut NvAlloc, *mut c_void, usize),
    pub reset: fn(*mut NvAlloc),
}
