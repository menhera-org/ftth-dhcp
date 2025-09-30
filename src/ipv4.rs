
use std::ffi::CStr;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Flags, HType, Message, Opcode, OptionCode, UnknownOption, CLIENT_PORT};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use socket2::{Socket, Domain, Type};

pub use dhcproto::v4::MessageType;

#[derive(Debug)]
pub struct Dhcp4Client {
    socket: std::net::UdpSocket,
    local_if_mac: [u8; 6],
}

#[derive(Debug, Clone)]
pub struct Dhcp4Response {
    pub client_addr: Option<Ipv4Addr>,
    pub server_addr: Option<Ipv4Addr>,
    pub router_addrs: Vec<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub addr_time: u32,
    pub renewal_time: u32,
    pub rebind_time: u32,
    pub sip_server_addrs: Vec<Ipv4Addr>,
    pub sip_domain_name: Option<String>,
    pub sip_main_number: Option<String>,
    pub sip_add_numbers: Vec<String>,
    pub static_routes: Vec<Dhcp4Route>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp4Route {
    pub prefix_addr: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
}

#[derive(PartialEq, Eq)]
pub enum Dhcp4RequestType {
    Select,
    InitReboot,
    Renew,
    Rebind,
}

impl Dhcp4Client {
    pub const CLIENT_PORT: u16 = 68;
    pub const SERVER_PORT: u16 = 67;
    pub const VENDOR_CODE_NTT: u32 = 210;

    pub fn new(local_if_mac: [u8; 6], if_name: &str) -> std::io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        socket.bind_device(Some(if_name.as_bytes()))?;
        let bind = SocketAddr::from(("0.0.0.0".parse::<IpAddr>().unwrap(), CLIENT_PORT));
        socket.bind(&bind.into())?;
        socket.set_nonblocking(false)?;
        socket.set_broadcast(true)?;
        let socket: std::net::UdpSocket = socket.into();
        socket.set_read_timeout(Some(Duration::from_secs(15)))?;
        socket.set_write_timeout(Some(Duration::from_secs(15)))?;
        Ok(Self {
            socket,
            local_if_mac,
        })
    }

    fn encode_send(&self, msg: Message, server_ip: Option<Ipv4Addr>) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e).map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "DHCPv4 encoding failed"))?;
        match server_ip {
            None => {
                self.socket.send_to(&buf, ("255.255.255.255", Self::SERVER_PORT))?;
            },
            Some(ip) => {
                self.socket.send_to(&buf, (ip, Self::SERVER_PORT))?;
            },
        }
        Ok(())
    }

    fn recv_msg(&self) -> std::io::Result<Message> {
        let mut buf = [0u8; 1500];
        let (nlen, _remote_addr) = self.socket.recv_from(&mut buf)?;
        let slice = &buf[..nlen];
        let msg = Message::decode(&mut Decoder::new(slice))
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "DHCPv4 decoding failed"))?;
        Ok(msg)
    }

    pub fn discover(&self) -> std::io::Result<()> {
        let mut msg = Message::new(
            Ipv4Addr::from_bits(0),
            Ipv4Addr::from_bits(0),
            Ipv4Addr::from_bits(0),
            Ipv4Addr::from_bits(0),
            &self.local_if_mac
        );
        msg.set_opcode(Opcode::BootRequest);
        msg.set_htype(HType::Eth);

        let flags = Flags::default().set_broadcast();
        msg.set_flags(flags);
        msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));

        let req_list = vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
        ];
        msg.opts_mut().insert(DhcpOption::ParameterRequestList(req_list));
        msg.opts_mut().insert(DhcpOption::MaxMessageSize(1200));
        msg.opts_mut().insert(DhcpOption::ClientIdentifier(self.local_if_mac.to_vec()));
        self.encode_send(msg, None)?;
        Ok(())
    }

    pub fn request(&self, req_type: Dhcp4RequestType, req_ip: Ipv4Addr, server_id: Ipv4Addr) -> std::io::Result<()> {
        let mut msg = match req_type {
            Dhcp4RequestType::Select => {
                Message::new(
                    Ipv4Addr::from_bits(0),
                    Ipv4Addr::from_bits(0),
                    server_id,
                    Ipv4Addr::from_bits(0),
                    &self.local_if_mac
                )
            },
            Dhcp4RequestType::InitReboot => {
                Message::new(
                    Ipv4Addr::from_bits(0),
                    Ipv4Addr::from_bits(0),
                    Ipv4Addr::from_bits(0),
                    Ipv4Addr::from_bits(0),
                    &self.local_if_mac
                )
            },
            _ => {
                Message::new(
                    req_ip,
                    Ipv4Addr::from_bits(0),
                    Ipv4Addr::from_bits(0),
                    Ipv4Addr::from_bits(0),
                    &self.local_if_mac
                )
            },
        };
        msg.set_opcode(Opcode::BootRequest);
        msg.set_htype(HType::Eth);

        let flags = Flags::default().set_broadcast();
        msg.set_flags(flags);
        msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Request));

        if req_type == Dhcp4RequestType::Select || req_type == Dhcp4RequestType::InitReboot {
            msg.opts_mut().insert(DhcpOption::RequestedIpAddress(req_ip));
        }

        if req_type == Dhcp4RequestType::Select {
            msg.opts_mut().insert(DhcpOption::ServerIdentifier(server_id));
        }

        let req_list = vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::Unknown(120),
            OptionCode::ClasslessStaticRoute,
            OptionCode::Unknown(125),
        ];
        msg.opts_mut().insert(DhcpOption::ParameterRequestList(req_list));
        msg.opts_mut().insert(DhcpOption::MaxMessageSize(1200));
        msg.opts_mut().insert(DhcpOption::ClientIdentifier(self.local_if_mac.to_vec()));

        let mut opt_data: Vec<u8> = Vec::new();
        opt_data.extend_from_slice(&u32::to_be_bytes(210));
        opt_data.push(7);
        opt_data.push(6);
        opt_data.extend_from_slice(&self.local_if_mac);
        let vendor_opt = UnknownOption::new(OptionCode::Unknown(124), opt_data);
        msg.opts_mut().insert(DhcpOption::Unknown(vendor_opt));

        let server_ip;
        if req_type == Dhcp4RequestType::Renew {
            server_ip = Some(server_id);
        } else {
            server_ip = None;
        }
        self.encode_send(msg, server_ip)?;
        Ok(())
    }

    pub fn recv(&self, expected_msg_type: MessageType) -> std::io::Result<Dhcp4Response> {
        let msg = self.recv_msg()?;
        if msg.opcode() != Opcode::BootReply {
            return Err(std::io::Error::new(ErrorKind::InvalidData, "Unexpected BOOTP opcode"));
        }

        let yiaddr = msg.yiaddr();
        // let siaddr = msg.siaddr();

        let mut subnet_mask = None;
        let mut router_addrs = Vec::new();
        let mut addr_time = 0u32;
        let mut renewal_time = 0u32;
        let mut rebind_time = 0u32;
        let mut sip_server_addrs = Vec::new();
        let mut sip_domain_name = None;
        let mut sip_main_number = None;
        let mut sip_add_numbers = Vec::new();
        let mut server_addr = None;
        let mut static_routes = Vec::new();

        for (optcode, opt) in msg.opts().iter() {
            let optcode = *optcode;
            let opt = opt.to_owned();
            match opt {
                DhcpOption::SubnetMask(mask) => {
                    subnet_mask = Some(mask);
                },
                DhcpOption::Router(rtaddr) => {
                    router_addrs.extend_from_slice(&rtaddr);
                },
                DhcpOption::AddressLeaseTime(at) => {
                    addr_time = at;
                },
                DhcpOption::MessageType(msgtype) => {
                    if msgtype != expected_msg_type {
                        return Err(std::io::Error::new(ErrorKind::InvalidData, "Unexpected message type"));
                    }
                },
                DhcpOption::ServerIdentifier(srvid) => {
                    server_addr = Some(srvid);
                },
                DhcpOption::Renewal(t1) => {
                    renewal_time = t1;
                },
                DhcpOption::Rebinding(t2) => {
                    rebind_time = t2;
                },
                DhcpOption::ClasslessStaticRoute(csr) => {
                    for (net, gw) in csr {
                        let route = Dhcp4Route {
                            prefix_addr: net.network(),
                            prefix_len: net.prefix_len(),
                            gateway: gw,
                        };
                        static_routes.push(route);
                    }
                },
                DhcpOption::Unknown(inneropt) => {
                    let code: u8 = optcode.into();
                    log::debug!("DHCPv4 optcode: {}", code);
                    let data = inneropt.data();
                    match code {
                        120 => {
                            if data.len() < 1 {
                                continue;
                            }
                            let count = data[0] as usize;
                            for i in 0usize..count {
                                let start = 1 + i * 4;
                                let end = start + 4;
                                if end > data.len() {
                                    break;
                                }
                                let addr: [u8; 4] = data[start..end].try_into().unwrap();
                                let addr: Ipv4Addr = addr.into();
                                sip_server_addrs.push(addr);
                            }
                        },
                        125 => {
                            if data.len() < 5 {
                                continue;
                            }

                            let entnum: [u8; 4] = data[0..4].try_into().unwrap();
                            let entnum = u32::from_be_bytes(entnum);
                            if entnum != Self::VENDOR_CODE_NTT {
                                log::warn!("Nonrecognized vendor code");
                                continue;
                            }
                            let optlen = data[4] as usize;
                            if (optlen + 5) > data.len() {
                                log::warn!("Invalid NTT option length");
                            }
                            let mut pos = 5usize;
                            while (pos + 1) < data.len() {
                                let subopt_code = data[pos];
                                let subopt_len = data[pos + 1] as usize;
                                let startoffset = pos + 2;
                                if startoffset >= data.len() {
                                    break;
                                }
                                let endoffset = startoffset + subopt_len;
                                if endoffset > data.len() {
                                    break;
                                }
                                let subopt_data = &data[startoffset..endoffset];
                                match subopt_code {
                                    201 => {
                                        // MAC address check
                                    },
                                    202 => {
                                        let main = CStr::from_bytes_until_nul(subopt_data).unwrap_or_default();
                                        let main = main.to_str().unwrap_or("");
                                        if !main.is_empty() {
                                            sip_main_number = Some(main.to_string());
                                        }
                                    },
                                    203 => {
                                        let add = CStr::from_bytes_until_nul(subopt_data).unwrap_or_default();
                                        let add = add.to_str().unwrap_or("");
                                        if !add.is_empty() {
                                            sip_add_numbers.push(add.to_string());
                                        }
                                    },
                                    204 => {
                                        let mut i = 0usize;
                                        let mut labels = Vec::new();
                                        while i < subopt_data.len() {
                                            let label_len = subopt_data[i] as usize;
                                            if label_len == 0 {
                                                break;
                                            }
                                            let start_i = i + 1;
                                            if start_i >= subopt_data.len() {
                                                break;
                                            }
                                            let end_i = start_i + label_len;
                                            if end_i > subopt_data.len() {
                                                break;
                                            }
                                            let label = &subopt_data[start_i..end_i];
                                            labels.push(String::from_utf8_lossy(label).into_owned());
                                            i = end_i;
                                        }
                                        let domain = labels.join(".");
                                        sip_domain_name = Some(domain);
                                    },
                                    _ => {},
                                }
                                pos += 2 + (subopt_len as usize);
                            }
                        },
                        _ => {},
                    }
                },
                _ => {},
            }
        }

        let client_addr = if yiaddr == Ipv4Addr::from_bits(0) { None } else { Some(yiaddr) };

        Ok(Dhcp4Response {
            client_addr,
            server_addr,
            router_addrs,
            subnet_mask,
            addr_time,
            renewal_time,
            rebind_time,
            sip_server_addrs,
            sip_domain_name,
            sip_main_number,
            sip_add_numbers,
            static_routes,
        })
    }
}
