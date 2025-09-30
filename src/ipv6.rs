
use std::io::ErrorKind;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use dhcproto::v6::{DhcpOption, DhcpOptions, IAPrefix, OptionCode, Status, VendorClass, IAPD, StatusCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Socket, Domain, Type};

pub use dhcproto::v6::MessageType;

#[derive(Debug)]
pub struct Dhcp6Client {
    socket: std::net::UdpSocket,
    local_if_mac: [u8; 6],
    local_ll_addr: Ipv6Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdPrefix {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub t1: u32,
    pub t2: u32,
}

#[derive(Debug, Clone)]
pub struct Dhcp6Response {
    pub client_id: Vec<u8>,
    pub server_id: Vec<u8>,
    pub pd: Option<PdPrefix>,
    pub nameserver_addrs: Vec<Ipv6Addr>,
    pub domain_search_list: Vec<String>,
    pub sip_server_addrs: Vec<Ipv6Addr>,
    pub sntp_server_addrs: Vec<Ipv6Addr>,
}

pub fn ipv6_ll_to_mac(ll_addr: Ipv6Addr) -> [u8; 6] {
    if !ll_addr.is_unicast_link_local() {
        return [0; 6];
    }

    let addr: [u8; 16] = ll_addr.octets();
    let mut part1: [u8; 3] = addr[8..11].try_into().unwrap();
    part1[0] ^= 2;
    let part2: [u8; 3] = addr[13..16].try_into().unwrap();
    let mut mac: [u8; 6] = [0; 6];
    mac[0] = part1[0];
    mac[1] = part1[1];
    mac[2] = part1[2];
    mac[3] = part2[0];
    mac[4] = part2[1];
    mac[5] = part2[2];
    mac
}

impl Dhcp6Client {
    pub const CLIENT_PORT: u16 = 546;
    pub const SERVER_PORT: u16 = 547;
    pub const VENDOR_CODE_NTT: u32 = 210;

    pub fn new(local_ll_address: Ipv6Addr, local_if_mac: [u8; 6], if_name: &str) -> std::io::Result<Self> {
        if !local_ll_address.is_unicast_link_local() {
            return Err(std::io::Error::new(ErrorKind::InvalidInput, "Invalid IPv6 link-local address"));
        }

        let socket = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        socket.bind_device(Some(if_name.as_bytes()))?;
        socket.bind(&(SocketAddr::V6(SocketAddrV6::new(local_ll_address, Self::CLIENT_PORT, 0, 0)).into()))?;
        socket.set_nonblocking(false)?;
        let socket: std::net::UdpSocket = socket.into();
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        socket.set_write_timeout(Some(Duration::from_secs(15)))?;
        Ok(Self {
            socket,
            local_if_mac,
            local_ll_addr: local_ll_address,
        })
    }

    fn encode_send(&self, msg: dhcproto::v6::Message) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(1500);
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e).map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "DHCPv6 encoding failed"))?;
        self.socket.send_to(&buf, ("ff02::1:2", Self::SERVER_PORT))?;
        Ok(())
    }

    pub fn local_ll(&self) -> std::io::Result<Ipv6Addr> {
        let addr = self.local_ll_addr;
        assert!(addr.is_unicast_link_local(), "Local address is not link local");
        Ok(addr)
    }

    pub fn local_duid(&self) -> std::io::Result<Vec<u8>> {
        let mac = self.local_if_mac;
        let mut duid: Vec<u8> = vec![0x00, 0x03, 0x00, 0x01];
        duid.extend_from_slice(&mac);
        Ok(duid)
    }

    pub fn solicit_pd(&self, elapsed: Duration, ia_id: u32) -> std::io::Result<()> {
        let duid = self.local_duid()?;
        let mut msg = dhcproto::v6::Message::new(dhcproto::v6::MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::ClientId(duid));
        msg.opts_mut().insert(DhcpOption::ElapsedTime(elapsed.as_millis().try_into().unwrap_or(0)));
        msg.opts_mut().insert(DhcpOption::IAPD(IAPD {
            id: ia_id,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }));
        self.encode_send(msg)?;
        Ok(())
    }

    pub fn request_pd(&self, elapsed: Duration, ia_id: u32, server_id: Vec<u8>, pd: PdPrefix) -> std::io::Result<()> {
        let duid = self.local_duid()?;
        let mut msg = dhcproto::v6::Message::new(dhcproto::v6::MessageType::Request);
        msg.opts_mut().insert(DhcpOption::ClientId(duid));
        msg.opts_mut().insert(DhcpOption::ServerId(server_id));
        let mut oro = dhcproto::v6::ORO {
            opts: Vec::new(),
        };
        oro.opts.push(OptionCode::IAPD);
        oro.opts.push(OptionCode::SipServerA);
        oro.opts.push(OptionCode::SntpServers);
        oro.opts.push(OptionCode::DomainNameServers);
        oro.opts.push(OptionCode::DomainSearchList);
        msg.opts_mut().insert(DhcpOption::ORO(oro));
        msg.opts_mut().insert(DhcpOption::ElapsedTime(elapsed.as_millis().try_into().unwrap_or(0)));

        // let mut data1 = Vec::new();
        // data1.extend_from_slice(&u16::to_be_bytes(6));
        // data1.extend_from_slice(&self.local_if_mac);
        msg.opts_mut().insert(DhcpOption::VendorClass(VendorClass {
            num: Self::VENDOR_CODE_NTT,
            data: vec![self.local_if_mac.to_vec()], // MAC address
        }));

        let mut pd_options = DhcpOptions::new();
        let mut prefix_options = DhcpOptions::new();
        prefix_options.insert(DhcpOption::StatusCode(StatusCode {
            status: dhcproto::v6::Status::Success,
            msg: "".to_string(),
        }));
        pd_options.insert(DhcpOption::IAPrefix(IAPrefix {
            preferred_lifetime: pd.preferred_lifetime,
            valid_lifetime: pd.valid_lifetime,
            prefix_ip: pd.prefix,
            prefix_len: pd.prefix_len,
            opts: prefix_options,
        }));
        msg.opts_mut().insert(DhcpOption::IAPD(IAPD {
            id: ia_id,
            t1: 0,
            t2: 0,
            opts: pd_options,
        }));
        log::debug!("REQUEST: {:?}", &msg);
        self.encode_send(msg)?;
        Ok(())
    }

    fn recv_msg(&self) -> std::io::Result<dhcproto::v6::Message> {
        let mut buf = [0u8; 1500];
        let (nlen, _remote_addr) = self.socket.recv_from(&mut buf)?;
        let slice = &buf[..nlen];
        let msg = dhcproto::v6::Message::decode(&mut Decoder::new(slice))
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "DHCPv6 decoding failed"))?;
        Ok(msg)
    }

    pub fn recv(&self, expected_msg_type: MessageType) -> std::io::Result<Dhcp6Response> {
        let msg = self.recv_msg()?;
        let msg_type = msg.msg_type();
        if msg_type != expected_msg_type {
            return Err(std::io::Error::new(ErrorKind::InvalidData, "Unexpected message type"));
        }

        let mut domain_search_list = Vec::new();
        let mut nameserver_addrs = Vec::new();
        let mut sntp_server_addrs = Vec::new();
        let mut sip_server_addrs = Vec::new();
        let mut client_id = None;
        let mut server_id = None;
        let mut t1: u32 = 0;
        let mut t2: u32 = 0;
        let mut valid_lifetime: u32 = 0;
        let mut preferred_lifetime: u32 = 0;
        let mut prefix = None;
        let mut prefix_len = None;
        for opt in msg.opts().iter() {
            let opt = opt.to_owned();
            match opt {
                DhcpOption::ClientId(id) => {
                    let duid = self.local_duid()?;
                    if id != duid {
                        return Err(std::io::Error::new(ErrorKind::InvalidData, "client DUID mismatch"));
                    }
                    client_id = Some(id);
                },

                DhcpOption::ServerId(id) => {
                    server_id = Some(id);
                },

                DhcpOption::StatusCode(code) => {
                    match code.status {
                        Status::Success => {},
                        _ => {
                            return Err(std::io::Error::new(ErrorKind::ConnectionAborted, "DHCP error"));
                        },
                    }
                },

                DhcpOption::DomainNameServers(srv) => {
                    nameserver_addrs.extend_from_slice(&srv);
                },

                DhcpOption::DomainSearchList(l) => {
                    for name in l {
                        domain_search_list.push(name.to_ascii());
                    }
                },

                DhcpOption::IAPD(pd) => {
                    t1 = pd.t1;
                    t2 = pd.t2;

                    for opt in pd.opts.iter() {
                        let opt = opt.to_owned();
                        match opt {
                            DhcpOption::IAPrefix(pd_prefix) => {
                                valid_lifetime = pd_prefix.valid_lifetime;
                                preferred_lifetime = pd_prefix.preferred_lifetime;
                                prefix = Some(pd_prefix.prefix_ip);
                                prefix_len = Some(pd_prefix.prefix_len);
                            },
                            _ => {},
                        }
                    }
                },

                DhcpOption::Unknown(opt) => {
                    let code = opt.code();
                    let (_, data) = opt.into_parts();

                    match code {
                        OptionCode::SipServerA => {
                            for i in 0usize.. {
                                let start = i * 16;
                                let end = start + 16;
                                if end > data.len() {
                                    break;
                                }
                                let addr: [u8; 16] = data[start..end].try_into().unwrap();
                                let addr: Ipv6Addr = addr.into();
                                sip_server_addrs.push(addr);
                            }
                        },
                        OptionCode::SntpServers => {
                            for i in 0usize.. {
                                let start = i * 16;
                                let end = start + 16;
                                if end > data.len() {
                                    break;
                                }
                                let addr: [u8; 16] = data[start..end].try_into().unwrap();
                                let addr: Ipv6Addr = addr.into();
                                sntp_server_addrs.push(addr);
                            }
                        }
                        _ => {},
                    }
                },

                _ => {},
            }
        }

        let pd;
        if prefix.is_none() || prefix_len.is_none() {
            pd = None;
        } else {
            pd = Some(PdPrefix {
                prefix: prefix.unwrap(),
                prefix_len: prefix_len.unwrap(),
                preferred_lifetime,
                valid_lifetime,
                t1,
                t2,
            });
        }

        let res = Dhcp6Response {
            client_id: client_id.unwrap(),
            server_id: server_id.unwrap(),
            pd,
            nameserver_addrs,
            domain_search_list,
            sip_server_addrs,
            sntp_server_addrs,
        };
        Ok(res)
    }

}
