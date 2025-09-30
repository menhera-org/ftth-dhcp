
use std::time::Instant;

use ftth_dhcp::{ipv4, ipv6};
use ftth_rtnl::RtnlClient;

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let ifname = args.get(1);
    let ifname = if let Some(name) = ifname {
        name
    } else {
        println!("Usage: {} <interface_name>", args[0]);
        return Ok(())
    };

    let rtnl_client = RtnlClient::new();
    let link_client = rtnl_client.link();
    let addr_client = rtnl_client.address();

    let interface = link_client.interface_get_by_name(ifname)?;
    let if_id = interface.if_id;
    let mac_addr = link_client.mac_addr_get(if_id)?;
    if mac_addr.is_none() {
        eprintln!("No MAC address found for interface {ifname}");
        return Err(std::io::Error::other("Invalid address"));
    }
    let mac_addr = mac_addr.unwrap();
    let ipv6_addrs = addr_client.ipv6_addrs_get(Some(if_id))?;
    let mut ll_addr = ipv6_addrs.iter().filter(|a| a.is_unicast_link_local());
    let ll_addr = ll_addr.next();
    let ll_addr = if let Some(addr) = ll_addr {
        *addr
    } else {
        return Err(std::io::Error::other("IPv6 LL address not found"));
    };

    println!("Testing DHCPv4...");
    let e = {
        let v4_client = ipv4::Dhcp4Client::new(mac_addr.inner, ifname)?;
        v4_client.discover()?;
        let res = v4_client.recv(ipv4::MessageType::Offer)?;
        if res.client_addr.is_none() || res.server_addr.is_none() {
            Err(std::io::Error::other("No server/client address found"))?;
        }
        v4_client.request(ipv4::Dhcp4RequestType::Select, res.client_addr.unwrap(), res.server_addr.unwrap())?;
        let res = v4_client.recv(ipv4::MessageType::Ack)?;
        println!("IPv4 lease:\n{:?}", res);
        Ok::<(), std::io::Error>(())
    };
    if let Err(e) = e {
        eprintln!("DHCPv4 error: {}", e);
    }

    println!("Testing DHCPv6...");
    let e = {
        let init = Instant::now();
        let ia_id: u32 = rand::random();
        let v6_client = ipv6::Dhcp6Client::new(ll_addr, mac_addr.inner, ifname)?;
        v6_client.solicit_pd(init.elapsed(), ia_id)?;
        let res = v6_client.recv(ipv6::MessageType::Advertise)?;
        if res.pd.is_none() {
            Err(std::io::Error::other("PD prefix not received"))?;
        }
        v6_client.request_pd(init.elapsed(), ia_id, res.server_id, res.pd.unwrap())?;
        let res = v6_client.recv(ipv6::MessageType::Reply)?;
        println!("IPv6 lease:\n{:?}", res);
        Ok::<(), std::io::Error>(())
    };
    if let Err(e) = e {
        eprintln!("DHCPv6 error: {}", e);
    }

    Ok(())
}
