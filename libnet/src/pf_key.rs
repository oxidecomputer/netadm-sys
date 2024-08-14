// Copyright 2024 Oxide Computer Company

use libc::IPPROTO_TCP;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::{mem::size_of, time::Duration};

const PF_KEY: i32 = 27;
const PF_KEY_V2: u8 = 2;
//const MAX_KEY_SIZE: usize = (u16::MAX >> 8) as usize;
const MAX_KEY_SIZE: usize = 80;

#[derive(Debug)]
#[repr(u8)]
pub enum MessageType {
    Reserved = 0,
    GetSpi = 1,
    Update = 2,
    Add = 3,
    Delete = 4,
    Get = 5,
    Acquire = 6,
    Register = 7,
    Expire = 8,
    Flush = 9,
    Dump = 10,
    Promisc = 11,
    InverseAcquire = 12,
    UpdatePair = 13,
    DelPair = 14,
    DelPairState = 15,
}

#[derive(Debug)]
#[repr(u8)]
pub enum SaType {
    Unspec = 0,
    Ah = 2,
    Esp = 3,
    TcpSig = 4,
    Rsvp = 5,
    OspvV2 = 6,
    RipV2 = 7,
    Mip = 8,
}

#[repr(u16)]
pub enum SaExtType {
    Sa = 1,
    LifetimeCurrent = 2,
    LifetimeHard = 3,
    LifetimeSoft = 4,
    AddressSrc = 5,
    AddressDst = 6,
    AddressProxy = 7,
    KeyAuth = 8,
    KeyEncrypt = 9,
    IdentitySrc = 10,
    IdentityDst = 11,
    Sensitivity = 12,
    Proposal = 13,
    SupportedAuth = 14,
    SupportedEncrypt = 15,
    SpiRange = 16,
    Ereg = 17,
    Eprop = 18,
    KmCookie = 19,
    AddressNattLoc = 20,
    AddressNattRem = 21,
    AddressInnerDst = 22,
    Pair = 23,
    ReplayValue = 24,
    Edump = 25,
    LifetimeIdle = 26,
    OuterSens = 27,
    StrAuth = 28,
}

#[repr(u8)]
pub enum SaAuthType {
    None,
    Md5,
    Md5Hmac,
    Sha1Hmac,
    Sha256Hmac,
    Sha384Hmac,
    Sha512Hmac,
}

#[repr(u8)]
pub enum SaEncryptType {
    None,
    DesCbc,
    DesCbc3,
    Blowfish,
    Null,
    Aes,
    AesCcm8,
    AesCcm12,
    AesCcm16,
    AesGcm8,
    AesGcm12,
    AesGcm16,
}

#[repr(u8)]
pub enum SaState {
    Larval,
    Mature,
    Dying,
    Dead,
}

#[repr(C, packed)]
pub struct Header {
    pub version: u8,
    pub typ: MessageType,
    pub errno: u8,
    pub sa_typ: SaType,
    pub len: u16,
    pub reserved: u16,
    pub seq: u32,
    pub pid: u32,
}

#[repr(C, packed)]
pub struct Association {
    pub len: u16,
    pub typ: SaExtType,
    pub spi: u32,
    pub replay: u8,
    pub state: SaState,
    pub auth: SaAuthType,
    pub encrypt: SaEncryptType,
    pub flags: u32,
}

#[repr(C, packed)]
pub struct Lifetime {
    pub len: u16,
    pub typ: SaExtType,
    pub alloc: u32,
    pub bytes: u64,
    pub addtime: u64,
    pub usetime: u64,
}

#[repr(C, packed)]
pub struct Address {
    pub len: u16,
    pub typ: SaExtType,
    pub proto: u8,
    pub prefix_len: u8,
    pub reserved: u16,
    pub sockaddr: SockAddr,
}

#[repr(C, packed)]
pub struct Key {
    pub len: u16,
    pub typ: SaExtType,
    pub bits: u16,
    pub reserved: u16,
    pub data: [u8; MAX_KEY_SIZE],
}

#[repr(C, packed)]
pub struct TcpMd5AddKeyRequest {
    pub header: Header,
    pub association: Association,
    pub lifetime: Lifetime,
    pub src: Address,
    pub dst: Address,
    pub key: Key,
}

#[repr(C, packed)]
pub struct TcpMd5DeleteKeyRequest {
    pub header: Header,
    pub association: Association,
    pub src: Address,
    pub dst: Address,
}

/// Add a TCP-MD5 security association for the provided souce and destination
/// address with `authstring` as the key that is valid for `valid_time` after
/// creation.
pub fn tcp_md5_key_add(
    src: SockAddr,
    dst: SockAddr,
    authstring: &str,
    valid_time: Duration,
) -> anyhow::Result<()> {
    let msg = TcpMd5AddKeyRequest::new(src, dst, authstring, valid_time);
    let mut sock = Socket::new(
        Domain::from(PF_KEY),
        Type::RAW,
        Some(Protocol::from(i32::from(PF_KEY_V2))),
    )?;
    let data = unsafe {
        std::slice::from_raw_parts(
            (&msg as *const TcpMd5AddKeyRequest) as *const u8,
            size_of::<TcpMd5AddKeyRequest>(),
        )
    };
    let n = sock.write(data)?;
    if n != data.len() {
        return Err(anyhow::anyhow!("short write {} != {}", n, data.len()));
    }

    let mut buf = [0u8; 1024];
    let _n = sock.read(&mut buf)?;
    let response = unsafe { &*(buf.as_ptr() as *const Header) };

    let diagnostic = response.reserved;

    println!(
        "{:?}/{:?}: {}/{}",
        response.typ, response.sa_typ, response.errno, diagnostic
    );

    Ok(())
}

impl TcpMd5AddKeyRequest {
    fn new(
        src: SockAddr,
        dst: SockAddr,
        authstring: &str,
        valid_time: Duration,
    ) -> Self {
        let header = Header {
            version: PF_KEY_V2,
            typ: MessageType::Add,
            errno: 0,
            sa_typ: SaType::TcpSig,
            len: u16::try_from(size_of::<Self>()).unwrap() >> 3,
            reserved: 0,
            seq: rand::random(),
            pid: std::process::id(),
        };

        let association = Association {
            len: u16::try_from(size_of::<Association>()).unwrap() >> 3,
            typ: SaExtType::Sa,
            spi: 0, // This is not for IPsec
            replay: 0,
            state: SaState::Mature,
            auth: SaAuthType::Md5,
            encrypt: SaEncryptType::None,
            flags: 0,
        };

        let lifetime = Lifetime {
            len: u16::try_from(size_of::<Lifetime>()).unwrap() >> 3,
            typ: SaExtType::LifetimeHard,
            alloc: 0, // no allocation limit
            bytes: 0, // no byte limit
            addtime: valid_time.as_secs(),
            usetime: valid_time.as_secs(),
        };

        let src = Address {
            len: u16::try_from(size_of::<Address>()).unwrap() >> 3,
            typ: SaExtType::AddressSrc,
            proto: IPPROTO_TCP as u8,
            prefix_len: 0,
            reserved: 0,
            sockaddr: src,
        };

        let dst = Address {
            len: u16::try_from(size_of::<Address>()).unwrap() >> 3,
            typ: SaExtType::AddressDst,
            proto: IPPROTO_TCP as u8,
            prefix_len: 0,
            reserved: 0,
            sockaddr: dst,
        };

        let mut key = Key {
            len: u16::try_from(size_of::<Key>()).unwrap() >> 3,
            typ: SaExtType::StrAuth,
            bits: u16::try_from(authstring.len() << 3).unwrap(),
            reserved: 0,
            data: [0; MAX_KEY_SIZE],
        };
        key.data[..authstring.len()].copy_from_slice(authstring.as_bytes());

        Self {
            header,
            association,
            lifetime,
            src,
            dst,
            key,
        }
    }
}

impl TcpMd5DeleteKeyRequest {
    fn new(src: SockAddr, dst: SockAddr) -> Self {
        let header = Header {
            version: PF_KEY_V2,
            typ: MessageType::Delete,
            errno: 0,
            sa_typ: SaType::TcpSig,
            len: u16::try_from(size_of::<Self>()).unwrap() >> 3,
            reserved: 0,
            seq: rand::random(),
            pid: std::process::id(),
        };

        let association = Association {
            len: u16::try_from(size_of::<Association>()).unwrap() >> 3,
            typ: SaExtType::Sa,
            spi: 0, // This is not for IPsec
            replay: 0,
            state: SaState::Mature,
            auth: SaAuthType::Md5,
            encrypt: SaEncryptType::None,
            flags: 0,
        };

        let src = Address {
            len: u16::try_from(size_of::<Address>()).unwrap() >> 3,
            typ: SaExtType::AddressSrc,
            proto: IPPROTO_TCP as u8,
            prefix_len: 0,
            reserved: 0,
            sockaddr: src,
        };

        let dst = Address {
            len: u16::try_from(size_of::<Address>()).unwrap() >> 3,
            typ: SaExtType::AddressDst,
            proto: IPPROTO_TCP as u8,
            prefix_len: 0,
            reserved: 0,
            sockaddr: dst,
        };

        Self {
            header,
            association,
            src,
            dst,
        }
    }
}

/// Delete the TCP-MD5 security association for the provided source and
/// destination.
pub fn tcp_md5_key_remove(src: SockAddr, dst: SockAddr) -> anyhow::Result<()> {
    let msg = TcpMd5DeleteKeyRequest::new(src, dst);
    let mut sock = Socket::new(
        Domain::from(PF_KEY),
        Type::RAW,
        Some(Protocol::from(i32::from(PF_KEY_V2))),
    )?;
    let data = unsafe {
        std::slice::from_raw_parts(
            (&msg as *const TcpMd5DeleteKeyRequest) as *const u8,
            size_of::<TcpMd5DeleteKeyRequest>(),
        )
    };
    let n = sock.write(data)?;
    if n != data.len() {
        return Err(anyhow::anyhow!("short write {} != {}", n, data.len()));
    }

    let mut buf = [0u8; 1024];
    let _n = sock.read(&mut buf)?;
    let response = unsafe { &*(buf.as_ptr() as *const Header) };

    let diagnostic = response.reserved;

    println!(
        "{:?}/{:?}: {}/{}",
        response.typ, response.sa_typ, response.errno, diagnostic
    );
    Ok(())
}
