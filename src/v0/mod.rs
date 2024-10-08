use std::ffi::CString;

use chrono::Utc;
use clap::{Arg, Command};
use libc::{ARPOP_REQUEST, SIOCGIFINDEX};

pub fn run() {
    // 1. parse args
    let if_name = __parse_args();

    // 2. create a new raw socket for receiving arp packets
    let sock_fd = __create_raw_socket();

    // 3. create interface request and copy the input interface name into it
    let ifr = __setup_ifr(sock_fd, &if_name);

    // 4. set interface index into the interface request
    let sll = __create_sll(&ifr);

    // 5. bind the socket to the interface
    __bind_socket(sock_fd, &sll);

    // 6. handle the arp packets
    __process_arp_packets(sock_fd);
}

fn __parse_args() -> String {
    let matches = Command::new("arpdump")
        .version("1.0")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .num_args(1)
                .required(true)
                .help("usage: arpdump -i <interface>"),
        )
        .get_matches();

    matches.get_one::<String>("interface").unwrap().to_string()
}

fn __create_raw_socket() -> i32 {
    unsafe {
        let sock_fd = libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::ETH_P_ARP.to_be() as i32,
        );
        if sock_fd == -1 {
            eprintln!("Failed to create raw socket");
            libc::exit(libc::EXIT_FAILURE);
        }
        sock_fd
    }
}

fn __setup_ifr(sock_fd: i32, if_name: &str) -> libc::ifreq {
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let c_if_name = CString::new(if_name).unwrap();
        std::ptr::copy_nonoverlapping(
            c_if_name.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            if_name.len().min(libc::IFNAMSIZ - 1),
        );

        if libc::ioctl(sock_fd, libc::SIOCGIFINDEX as _, &mut ifr) < 0 {
            eprintln!("Failed to get interface index");
            libc::close(sock_fd);
            libc::exit(libc::EXIT_FAILURE);
        }

        ifr
    }
}

fn __create_sll(ifr: &libc::ifreq) -> libc::sockaddr_ll {
    unsafe {
        let mut sll: libc::sockaddr_ll = std::mem::zeroed();
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = ifr.ifr_ifru.ifru_ifindex;

        sll
    }
}

fn __bind_socket(sock_fd: i32, sll: &libc::sockaddr_ll) {
    unsafe {
        let sockaddr = sll as *const _ as *const libc::sockaddr;
        let sockaddr_len = std::mem::size_of::<libc::sockaddr_ll>() as u32;

        if libc::bind(sock_fd, sockaddr, sockaddr_len) < 0 {
            eprintln!("Failed to bind socket");
            libc::close(sock_fd);
            libc::exit(libc::EXIT_FAILURE);
        }
    }
}

fn __process_arp_packets(sock_fd: i32) {
    let mut buf = [0_u8; 1024];

    println!("start to process arp packets");
    loop {
        __handle_arp_packet(sock_fd, &mut buf);
    }
}

fn __handle_arp_packet(sock_fd: i32, buf: &mut [u8]) {
    unsafe {
        let read_bytes = libc::recvfrom(
            sock_fd,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        println!("read_bytes: {}", read_bytes);
        if read_bytes < 0 {
            eprintln!("Failed to read arp packet");
            return;
        }

        let ether_header = &*(buf.as_ptr() as *const EtherHeader);
        // let ether_header = buf.as_ptr() as *const EtherHeader;
        if !ether_header.is_arp_packet() {
            return;
        }
        println!("ether_header: {}", ether_header);
        let arp_header =
            &*(buf.as_ptr().add(std::mem::size_of::<EtherHeader>()) as *const ArpHeader);

        // let arp_header = ArpHeader::unsafe_from(
        //     &mut *(buf.as_mut_ptr().add(std::mem::size_of::<EtherHeader>()) as *mut ArpHeader),
        // );
        println!("{}", arp_header);
    }
}

#[repr(C, packed)]
struct EtherHeader {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ether_type: u16,
}

impl EtherHeader {
    fn unsafe_from(buf: &mut [u8]) -> &Self {
        unsafe {
            let ether_header = &mut *(buf.as_mut_ptr() as *mut Self);
            ether_header.ether_type = ether_header.ether_type.to_le();

            ether_header
        }
    }

    fn is_arp_packet(&self) -> bool {
        u16::from_be(self.ether_type) == libc::ETH_P_ARP as u16
    }
}

impl std::fmt::Display for EtherHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ether_type = match u16::from_be(self.ether_type.to_le()) as i32 {
            libc::ETH_P_ARP => "ARP_PACKET",
            libc::ETH_P_IP => "IP_PACKET",
            libc::ETH_P_IPV6 => "IPV6_PACKET",
            _ => "UNKNOWN_PACKET",
        };
        write!(
            f,
            "dst_mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, src_mac: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, ether_type: {}",
            self.dst_mac[0], self.dst_mac[1], self.dst_mac[2], self.dst_mac[3], self.dst_mac[4], self.dst_mac[5],
            self.src_mac[0], self.src_mac[1], self.src_mac[2], self.src_mac[3], self.src_mac[4], self.src_mac[5],
            ether_type
        )
    }
}

#[repr(C, packed)]
struct ArpHeader {
    hardware_type: u16,
    protocol_type: u16,
    hardware_size: u8,
    protocol_size: u8,
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_mac: [u8; 6],
    target_ip: [u8; 4],
}

impl ArpHeader {
    fn unsafe_from(buf: &mut [u8]) -> &Self {
        unsafe {
            let arp_header = &mut *(buf.as_mut_ptr() as *mut Self);
            arp_header.hardware_type = arp_header.hardware_type.to_le();
            arp_header.protocol_type = arp_header.protocol_type.to_le();
            arp_header.opcode = arp_header.opcode.to_le();

            arp_header
        }
    }

    // MAC 주소를 포맷팅하는 헬퍼 메소드
    fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    // IP 주소를 포맷팅하는 헬퍼 메소드
    fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }
}

impl std::fmt::Display for ArpHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let opcode_str = match u16::from_be(self.opcode) {
            libc::ARPOP_REQUEST => "ARP Request",
            libc::ARPOP_REPLY => "ARP Reply",
            _ => "Unknown",
        };

        write!(
            f,
            r#"
            -----------------------------------------------------
            {}
            hardware_type: {}
            protocol_type: {}
            hardware_size: {}
            protocol_size: {}
            mac: from [{}] to [{}]
            ip:  from [{}] to [{}]
            {}
            -----------------------------------------------------
            "#,
            opcode_str,
            self.hardware_type.to_le(),
            self.protocol_type.to_le(),
            self.hardware_size.to_le(),
            self.protocol_size.to_le(),
            ArpHeader::format_mac(&self.sender_mac),
            ArpHeader::format_mac(&self.target_mac),
            ArpHeader::format_ip(&self.sender_ip),
            ArpHeader::format_ip(&self.target_ip),
            Utc::now().to_rfc3339()
        )
    }
}
