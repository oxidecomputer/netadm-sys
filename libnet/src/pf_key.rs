// Copyright 2024 Oxide Computer Company

// This file implements the PF_KEY protocol as described in RFC 2367.

use libc::IPPROTO_TCP;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::{mem::size_of, time::Duration};
use winnow::binary::{le_u16, le_u32, le_u64, le_u8};
use winnow::combinator::repeat;
use winnow::error::{ContextError, ErrMode};
use winnow::token::take;
use winnow::{PResult, Parser};

/// The PF_KEY protocol family.
const PF_KEY: i32 = 27;
/// The PF_KEY protocol version.
const PF_KEY_V2: u8 = 2;
/// Maximum size of a StrAuth key.
const MAX_STR_AUTH_KEY_SIZE: usize = 80;

/// PF_KEY message types.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
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

/// PF_KEY security association types.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
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

/// PF_KEY security association extension types.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
#[repr(u16)]
pub enum SaExtType {
    Sa = 1,
    LifetimeCurrent = 2,
    LifetimeHard = 3,
    LifetimeSoft = 4,
    AddressSrc = 5,
    AddressDst = 6,
    //TODO AddressProxy = 7,
    //TODO KeyAuth = 8,
    //TODO KeyEncrypt = 9,
    //TODO IdentitySrc = 10,
    //TODO IdentityDst = 11,
    //TODO Sensitivity = 12,
    //TODO Proposal = 13,
    //TODO SupportedAuth = 14,
    //TODO SupportedEncrypt = 15,
    //TODO SpiRange = 16,
    //TODO Ereg = 17,
    //TODO Eprop = 18,
    //TODO KmCookie = 19,
    //TODO AddressNattLoc = 20,
    //TODO AddressNattRem = 21,
    //TODO AddressInnerDst = 22,
    //TODO Pair = 23,
    //TODO ReplayValue = 24,
    //TODO Edump = 25,
    //TODO LifetimeIdle = 26,
    //TODO OuterSens = 27,
    StrAuth = 28,
}

/// PF_KEY security association authentication types.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
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

/// PF_KEY security association encryption types.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
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

/// PF_KEY security association states.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum SaState {
    Larval,
    Mature,
    Dying,
    Dead,
}

/// A PF_KEY security association header.
#[derive(Debug)]
#[repr(C, packed)]
pub struct Header {
    /// Protocol version. Always PF_KEY_2.
    pub version: u8,
    /// The message type.
    pub typ: MessageType,
    /// Error returned by OS, if any.
    pub errno: u8,
    /// Security association type.
    pub sa_typ: SaType,
    /// Length of the message in 8-byte units.
    pub len: u16,
    /// Reserved when going to the kernel, diagnostic code when coming from the
    /// kernel.
    pub reserved: u16,
    /// Sequence id for this message.
    pub seq: u32,
    /// Process id of the sender.
    pub pid: u32,
}

impl Header {
    pub fn new(typ: MessageType, sa_typ: SaType, len: usize) -> Self {
        Header {
            version: PF_KEY_V2,
            typ,
            errno: 0,
            sa_typ,
            len: u16::try_from(len).unwrap() >> 3,
            reserved: 0,
            seq: rand::random(),
            pid: std::process::id(),
        }
    }
}

/// The extension enumeration contains all PF_KEY extensions supported by this
/// module.
#[derive(Debug)]
pub enum Extension {
    Association(Association),
    Lifetime(Lifetime),
    Address(Address),
    StrAuth(StrAuth),
}

/// Basic information about a security association.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Association {
    /// Length of this extension in 8-byte units.
    pub len: u16,
    /// The type of this extension.
    pub typ: SaExtType,
    /// Security parameters index.
    pub spi: u32,
    /// Replay window size.
    pub replay: u8,
    /// State of the association.
    pub state: SaState,
    /// Authentication type.
    pub auth: SaAuthType,
    /// Encryption type.
    pub encrypt: SaEncryptType,
    /// Optional flags.
    pub flags: u32,
}

impl Default for Association {
    fn default() -> Self {
        Association {
            len: u16::try_from(size_of::<Association>()).unwrap() >> 3,
            typ: SaExtType::Sa,
            spi: 0, // This is not for IPsec
            replay: 0,
            state: SaState::Mature,
            auth: SaAuthType::Md5,
            encrypt: SaEncryptType::None,
            flags: 0,
        }
    }
}

/// Lifetime information for a security association.
#[derive(Debug)]
#[repr(C, packed)]
pub struct Lifetime {
    /// Length of this extension in 8-byte units.
    pub len: u16,
    /// The type of this extension.
    pub typ: SaExtType,
    /// How many allocations this lifetime lasts for.
    pub alloc: u32,
    /// How many bytes this lifetime lasts for.
    pub bytes: u64,
    /// How long after creation this lifetime expires in seconds.
    pub addtime: u64,
    /// How long after first use this lifetime expires in seconds.
    pub usetime: u64,
}

impl Lifetime {
    /// Create a hard lifetime extension.
    pub fn hard(addtime: Duration, usetime: Duration) -> Self {
        Lifetime {
            len: u16::try_from(size_of::<Lifetime>()).unwrap() >> 3,
            typ: SaExtType::LifetimeHard,
            alloc: 0, // no allocation limit
            bytes: 0, // no byte limit
            addtime: addtime.as_secs(),
            usetime: usetime.as_secs(),
        }
    }
    /// Create a soft lifetime extension.
    pub fn soft(addtime: Duration, usetime: Duration) -> Self {
        Lifetime {
            len: u16::try_from(size_of::<Lifetime>()).unwrap() >> 3,
            typ: SaExtType::LifetimeSoft,
            alloc: 0, // no allocation limit
            bytes: 0, // no byte limit
            addtime: addtime.as_secs(),
            usetime: usetime.as_secs(),
        }
    }
}

/// Address information for a security association.
#[repr(C, packed)]
pub struct Address {
    /// Length of this extension in 8-byte units.
    pub len: u16,
    /// The type of this extension.
    pub typ: SaExtType,
    /// Protocol family identifier for this address.
    pub proto: u8,
    /// Prefix length associated with the address.
    pub prefix_len: u8,
    /// Reserved bits.
    pub reserved: u16,
    /// Address and port the security association binds to.
    pub sockaddr: SockAddr,
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = unsafe { (self as *const Address).read_unaligned() };
        let len = s.len;
        let typ = s.typ;
        let proto = s.proto;
        let plen = s.prefix_len;
        let res = s.reserved;
        let sa = s.sockaddr;
        let sa = sa.as_socket();
        f.debug_struct("Address")
            .field("len", &len)
            .field("typ", &typ)
            .field("proto", &proto)
            .field("prefix_len", &plen)
            .field("reserved", &res)
            .field("sockaddr", &sa)
            .finish()
    }
}

impl Address {
    /// Create a new source address extension.
    pub fn src(sockaddr: SockAddr, proto: u8) -> Self {
        Self::new(sockaddr, proto, SaExtType::AddressSrc)
    }

    /// Create a new destination address extension.
    pub fn dst(sockaddr: SockAddr, proto: u8) -> Self {
        Self::new(sockaddr, proto, SaExtType::AddressDst)
    }

    /// Create a new address extension.
    pub fn new(sockaddr: SockAddr, proto: u8, typ: SaExtType) -> Self {
        Address {
            len: u16::try_from(size_of::<Address>()).unwrap() >> 3,
            typ,
            proto,
            prefix_len: 0,
            reserved: 0,
            sockaddr,
        }
    }

    /// Get the socket address.
    pub fn get_sockaddr(&self) -> Option<SocketAddr> {
        let s = unsafe { (self as *const Address).read_unaligned() };
        let sa = s.sockaddr;
        sa.as_socket()
    }
}

/// String authentication information for this security association.
#[repr(C, packed)]
pub struct StrAuth {
    /// Length of this extension in 8-byte units.
    pub len: u16,
    /// The type of this extension.
    pub typ: SaExtType,
    /// Length of the key in bits.
    pub bits: u16,
    /// Reserved.
    pub reserved: u16,
    /// Key data.
    pub data: [u8; MAX_STR_AUTH_KEY_SIZE],
}

impl std::fmt::Debug for StrAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = unsafe { (self as *const StrAuth).read_unaligned() };
        let len = s.len;
        let typ = s.typ;
        let bits = s.bits;
        let res = s.reserved;
        let key = s.key();
        f.debug_struct("StrAuth")
            .field("len", &len)
            .field("typ", &typ)
            .field("bits", &bits)
            .field("reserved", &res)
            .field("data", &key)
            .finish()
    }
}

impl StrAuth {
    /// Create a new string authentication extension for a given key.
    pub fn new(authstring: &str) -> Self {
        let mut key = StrAuth {
            len: u16::try_from(size_of::<StrAuth>()).unwrap() >> 3,
            typ: SaExtType::StrAuth,
            bits: u16::try_from(authstring.len() << 3).unwrap(),
            reserved: 0,
            data: [0; MAX_STR_AUTH_KEY_SIZE],
        };
        key.data[..authstring.len()].copy_from_slice(authstring.as_bytes());
        key
    }

    /// Return the key in string form.
    pub fn key(&self) -> String {
        let s = unsafe { (self as *const StrAuth).read_unaligned() };
        let bits = s.bits;
        let bytelen = (bits >> 3) as usize;
        let data = s.data;
        String::from_utf8_lossy(&data[..bytelen]).to_string()
    }
}

/// A packet to add or update a TCP-MD5 security association.
#[repr(C, packed)]
pub struct TcpMd5SetKeyRequest {
    /// Packet header.
    pub header: Header,
    /// Association info.
    pub association: Association,
    /// Lifetime info.
    pub lifetime: Lifetime,
    /// Source socket address to bind to.
    pub src: Address,
    /// Destination socket address to bind to.
    pub dst: Address,
    /// String-based key.
    pub key: StrAuth,
}

impl TcpMd5SetKeyRequest {
    /// Create a new TCP-MD5 set key request.
    pub fn new(
        src: SockAddr,
        dst: SockAddr,
        authstring: &str,
        valid_time: Duration,
        update: bool,
    ) -> Self {
        let mtype = if update {
            MessageType::Update
        } else {
            MessageType::Add
        };

        Self {
            header: Header::new(mtype, SaType::TcpSig, size_of::<Self>()),
            association: Association::default(),
            lifetime: Lifetime::hard(valid_time, valid_time),
            src: Address::src(src, IPPROTO_TCP as u8),
            dst: Address::dst(dst, IPPROTO_TCP as u8),
            key: StrAuth::new(authstring),
        }
    }
}

/// A packet to delete a TCP-MD5 security association.
#[repr(C, packed)]
pub struct TcpMd5DeleteKeyRequest {
    /// Packet header.
    pub header: Header,
    /// Association info.
    pub association: Association,
    /// Source socket address to unbind.
    pub src: Address,
    /// Destination socket address to unbind.
    pub dst: Address,
}

impl TcpMd5DeleteKeyRequest {
    /// Create a new TCP-MD5 delete key request.
    pub fn new(src: SockAddr, dst: SockAddr) -> Self {
        Self {
            header: Header::new(
                MessageType::Delete,
                SaType::TcpSig,
                size_of::<Self>(),
            ),
            association: Association::default(),
            src: Address::src(src, IPPROTO_TCP as u8),
            dst: Address::dst(dst, IPPROTO_TCP as u8),
        }
    }
}

/// A packet to request info about a TCP-MD5 security association.
#[repr(C, packed)]
pub struct TcpMd5GetKeyRequest {
    /// Packet header.
    pub header: Header,
    /// Association info.
    pub association: Association,
    /// Source socket address predicate.
    pub src: Address,
    /// Destination socket address predicate.
    pub dst: Address,
}

impl TcpMd5GetKeyRequest {
    /// Create a new TCP-MD5 get key request.
    pub fn new(src: SockAddr, dst: SockAddr) -> Self {
        Self {
            header: Header::new(
                MessageType::Get,
                SaType::TcpSig,
                size_of::<Self>(),
            ),
            association: Association::default(),
            src: Address::src(src, IPPROTO_TCP as u8),
            dst: Address::dst(dst, IPPROTO_TCP as u8),
        }
    }
}

/// Response information returned from kernel from a key association request.
#[derive(Debug)]
pub struct GetAssociationResponse {
    pub header: Header,
    pub extensions: Vec<Extension>,
}

/// Add a TCP-MD5 security association for the provided source and destination
/// address with `authstring` as the key that is valid for `valid_time` after
/// creation.
pub fn tcp_md5_key_add(
    src: SockAddr,
    dst: SockAddr,
    authstring: &str,
    valid_time: Duration,
) -> Result<(), Error> {
    tcp_md5_key_set(src, dst, authstring, valid_time, false)
}

/// Update a TCP-MD5 security association for the provided source and destination
/// address with `authstring` as the key that is valid for `valid_time` after
/// creation.
pub fn tcp_md5_key_update(
    src: SockAddr,
    dst: SockAddr,
    authstring: &str,
    valid_time: Duration,
) -> Result<(), Error> {
    tcp_md5_key_set(src, dst, authstring, valid_time, true)
}

/// Set a TCP-MD5 security association for the provided source and destination
/// address with `authstring` as the key that is valid for `valid_time` after
/// creation. If update is true, this is treated as an update to an existing
/// association, otherwise a new association is created.
pub fn tcp_md5_key_set(
    src: SockAddr,
    dst: SockAddr,
    authstring: &str,
    valid_time: Duration,
    update: bool,
) -> Result<(), Error> {
    let msg =
        TcpMd5SetKeyRequest::new(src, dst, authstring, valid_time, update);
    let mut sock = Socket::new(
        Domain::from(PF_KEY),
        Type::RAW,
        Some(Protocol::from(i32::from(PF_KEY_V2))),
    )?;
    let data = unsafe {
        std::slice::from_raw_parts(
            (&msg as *const TcpMd5SetKeyRequest) as *const u8,
            size_of::<TcpMd5SetKeyRequest>(),
        )
    };
    let n = sock.write(data)?;
    if n != data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("short write {} != {}", n, data.len()),
        )
        .into());
    }

    let mut buf = [0u8; 1024];
    let _n = sock.read(&mut buf)?;
    let response = unsafe { &*(buf.as_ptr() as *const Header) };

    if response.errno != 0 {
        return Err(Error::PfKey {
            errno: response.errno,
            typ: response.typ,
            sa_typ: response.sa_typ,
            diagnostic: response.reserved,
        });
    }

    Ok(())
}

/// Get info on a TCP-MD5 security association for the provided source and
/// destination address with
pub fn tcp_md5_key_get(
    src: SockAddr,
    dst: SockAddr,
) -> Result<GetAssociationResponse, Error> {
    let msg = TcpMd5GetKeyRequest::new(src, dst);
    let mut sock = Socket::new(
        Domain::from(PF_KEY),
        Type::RAW,
        Some(Protocol::from(i32::from(PF_KEY_V2))),
    )?;
    let data = unsafe {
        std::slice::from_raw_parts(
            (&msg as *const TcpMd5GetKeyRequest) as *const u8,
            size_of::<TcpMd5GetKeyRequest>(),
        )
    };
    let n = sock.write(data)?;
    if n != data.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("short write {} != {}", n, data.len()),
        )
        .into());
    }

    let mut buf = [0u8; 1024];
    let _n = sock.read(&mut buf)?;
    let response = unsafe { &*(buf.as_ptr() as *const Header) };

    if response.errno != 0 {
        return Err(Error::PfKey {
            errno: response.errno,
            typ: response.typ,
            sa_typ: response.sa_typ,
            diagnostic: response.reserved,
        });
    }

    let cursor = &mut buf.as_slice();
    parse::association_response
        .parse_next(cursor)
        .map_err(|e| Error::PfKeyParse(format!("{e:?}")))
}

/// Delete the TCP-MD5 security association for the provided source and
/// destination.
pub fn tcp_md5_key_remove(src: SockAddr, dst: SockAddr) -> Result<(), Error> {
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
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("short write {} != {}", n, data.len()),
        )
        .into());
    }

    let mut buf = [0u8; 1024];
    let _n = sock.read(&mut buf)?;
    let response = unsafe { &*(buf.as_ptr() as *const Header) };

    if response.errno != 0 {
        return Err(Error::PfKey {
            errno: response.errno,
            typ: response.typ,
            sa_typ: response.sa_typ,
            diagnostic: response.reserved,
        });
    }

    Ok(())
}

/// Errors that can be returned from PF_KEY operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io error {0}")]
    Io(#[from] std::io::Error),

    #[error("pfkey {typ:?}/{sa_typ:?} {errno}/{diagnostic}")]
    PfKey {
        typ: MessageType,
        sa_typ: SaType,
        errno: u8,
        diagnostic: u16,
    },

    #[error("pfkey parse {0}")]
    PfKeyParse(String),
}

mod parse {
    use super::*;

    pub fn association_response(
        buf: &mut &[u8],
    ) -> PResult<GetAssociationResponse> {
        Ok(GetAssociationResponse {
            header: header.parse_next(buf)?,
            extensions: repeat(0.., extension).parse_next(buf)?,
        })
    }

    pub fn header(buf: &mut &[u8]) -> PResult<Header> {
        Ok(Header {
            version: le_u8.parse_next(buf)?,
            typ: message_type.parse_next(buf)?,
            errno: le_u8.parse_next(buf)?,
            sa_typ: sa_type.parse_next(buf)?,
            len: le_u16.parse_next(buf)?,
            reserved: le_u16.parse_next(buf)?,
            seq: le_u32.parse_next(buf)?,
            pid: le_u32.parse_next(buf)?,
        })
    }

    pub fn extension(buf: &mut &[u8]) -> PResult<Extension> {
        let len = le_u16.parse_next(buf)?;
        let typ = sa_ext_type.parse_next(buf)?;
        Ok(match typ {
            SaExtType::Sa => {
                Extension::Association(association(len).parse_next(buf)?)
            }
            SaExtType::LifetimeCurrent
            | SaExtType::LifetimeHard
            | SaExtType::LifetimeSoft => {
                Extension::Lifetime(lifetime(len, typ).parse_next(buf)?)
            }
            SaExtType::AddressSrc | SaExtType::AddressDst => {
                Extension::Address(address(len, typ).parse_next(buf)?)
            }
            SaExtType::StrAuth => {
                Extension::StrAuth(str_auth(len).parse_next(buf)?)
            }
        })
    }

    pub fn association(
        len: u16,
    ) -> impl FnMut(&mut &[u8]) -> PResult<Association> {
        move |buf: &mut &[u8]| -> PResult<Association> {
            Ok(Association {
                len,
                typ: SaExtType::Sa,
                spi: le_u32.parse_next(buf)?,
                replay: le_u8.parse_next(buf)?,
                state: sa_state.parse_next(buf)?,
                auth: sa_auth_type.parse_next(buf)?,
                encrypt: sa_encrypt_type.parse_next(buf)?,
                flags: le_u32.parse_next(buf)?,
            })
        }
    }

    pub fn lifetime(
        len: u16,
        typ: SaExtType,
    ) -> impl FnMut(&mut &[u8]) -> PResult<Lifetime> {
        move |buf: &mut &[u8]| -> PResult<Lifetime> {
            Ok(Lifetime {
                len,
                typ,
                alloc: le_u32.parse_next(buf)?,
                bytes: le_u64.parse_next(buf)?,
                addtime: le_u64.parse_next(buf)?,
                usetime: le_u64.parse_next(buf)?,
            })
        }
    }

    pub fn address(
        len: u16,
        typ: SaExtType,
    ) -> impl FnMut(&mut &[u8]) -> PResult<Address> {
        move |buf: &mut &[u8]| -> PResult<Address> {
            let sockaddr_len = ((len as usize) << 3)
                - (size_of::<Address>() - size_of::<SockAddr>());
            Ok(Address {
                len,
                typ,
                proto: le_u8.parse_next(buf)?,
                prefix_len: le_u8.parse_next(buf)?,
                reserved: le_u16.parse_next(buf)?,
                sockaddr: unsafe {
                    let x = take(sockaddr_len).parse_next(buf)?;
                    let mut buf = [0; size_of::<SockAddr>()];
                    buf[0..sockaddr_len].copy_from_slice(x);
                    (buf.as_ptr() as *const SockAddr).read_unaligned()
                },
            })
        }
    }

    pub fn str_auth(len: u16) -> impl FnMut(&mut &[u8]) -> PResult<StrAuth> {
        let data_len = ((len as usize) << 3)
            - (size_of::<StrAuth>() - MAX_STR_AUTH_KEY_SIZE);
        move |buf: &mut &[u8]| -> PResult<StrAuth> {
            Ok(StrAuth {
                len,
                typ: SaExtType::StrAuth,
                bits: le_u16.parse_next(buf)?,
                reserved: le_u16.parse_next(buf)?,
                data: {
                    let x = take(data_len).parse_next(buf)?;
                    let mut buf = [0; MAX_STR_AUTH_KEY_SIZE];
                    buf[0..data_len].copy_from_slice(x);
                    buf
                },
            })
        }
    }

    pub fn message_type(buf: &mut &[u8]) -> PResult<MessageType> {
        let value = le_u8.parse_next(buf)?;
        MessageType::try_from_primitive(value)
            .map_err(|_| ErrMode::Backtrack(ContextError::new()))
    }

    pub fn sa_type(buf: &mut &[u8]) -> PResult<SaType> {
        let value = le_u8.parse_next(buf)?;
        SaType::try_from_primitive(value)
            .map_err(|_| ErrMode::Backtrack(ContextError::new()))
    }

    fn sa_ext_type(buf: &mut &[u8]) -> PResult<SaExtType> {
        let value = le_u16.parse_next(buf)?;
        SaExtType::try_from_primitive(value)
            .map_err(|_| ErrMode::Backtrack(ContextError::new()))
    }

    fn sa_auth_type(buf: &mut &[u8]) -> PResult<SaAuthType> {
        let value = le_u8.parse_next(buf)?;
        SaAuthType::try_from_primitive(value)
            .map_err(|_| ErrMode::Backtrack(ContextError::new()))
    }

    fn sa_encrypt_type(buf: &mut &[u8]) -> PResult<SaEncryptType> {
        let value = le_u8.parse_next(buf)?;
        SaEncryptType::try_from_primitive(value)
            .map_err(|_| ErrMode::Backtrack(ContextError::new()))
    }

    fn sa_state(buf: &mut &[u8]) -> PResult<SaState> {
        let value = le_u8.parse_next(buf)?;
        SaState::try_from_primitive(value)
            .map_err(|_| ErrMode::Backtrack(ContextError::new()))
    }
}
