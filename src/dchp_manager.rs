//! Axis Camera DHCP Server
//!
//! A custom DHCP server implementation specifically designed for handling
//! factory-new Axis cameras with identical default IP addresses.

use anyhow::Result;
use byteorder::{ BigEndian, ByteOrder };
use chrono::{ DateTime, Utc };
use log::{ debug, error, info, warn };
use network_interface::{ NetworkInterface as NetInterface, NetworkInterfaceConfig };
use rand::prelude::*;
use rand::rngs::StdRng; // This is Send-compatible
use socket2::{ Domain, Protocol, Socket, Type };
use std::collections::HashMap;
use std::net::{ Ipv4Addr, SocketAddr, SocketAddrV4 };
use std::sync::atomic::{ AtomicBool, Ordering };
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::RwLock; // Use tokio's RwLock
use tokio::time::timeout;

#[derive(Error, Debug)]
pub enum DhcpError {
    #[error("Network error: {0}")] Network(#[from] std::io::Error),
    #[error("Configuration error: {0}")] Config(String),
    #[error("Packet parsing error: {0}")] PacketParsing(String),
    #[error("Address error: {0}")] Address(String),
}

/// DHCP Message Types
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = DhcpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DhcpMessageType::Discover),
            2 => Ok(DhcpMessageType::Offer),
            3 => Ok(DhcpMessageType::Request),
            4 => Ok(DhcpMessageType::Decline),
            5 => Ok(DhcpMessageType::Ack),
            6 => Ok(DhcpMessageType::Nak),
            7 => Ok(DhcpMessageType::Release),
            _ => Err(DhcpError::PacketParsing(format!("Invalid DHCP message type: {}", value))),
        }
    }
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub mac: Option<[u8; 6]>,
}

/// DHCP Lease information
#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    pub lease_start: DateTime<Utc>,
    pub lease_end: DateTime<Utc>,
}

/// DHCP Packet structure
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op: u8, // Message op code
    pub htype: u8, // Hardware address type
    pub hlen: u8, // Hardware address length
    pub hops: u8, // Hops
    pub xid: u32, // Transaction ID
    pub secs: u16, // Seconds
    pub flags: u16, // Flags
    pub ciaddr: Ipv4Addr, // Client IP
    pub yiaddr: Ipv4Addr, // Your IP
    pub siaddr: Ipv4Addr, // Server IP
    pub giaddr: Ipv4Addr, // Relay agent IP
    pub chaddr: [u8; 16], // Client hardware address
    pub options: HashMap<u8, Vec<u8>>,
}

impl DhcpPacket {
    /// Parse a DHCP packet from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, DhcpError> {
        if data.len() < 240 {
            return Err(DhcpError::PacketParsing("Packet too short for DHCP".to_string()));
        }

        let mut packet = DhcpPacket {
            op: data[0],
            htype: data[1],
            hlen: data[2],
            hops: data[3],
            xid: BigEndian::read_u32(&data[4..8]),
            secs: BigEndian::read_u16(&data[8..10]),
            flags: BigEndian::read_u16(&data[10..12]),
            ciaddr: Ipv4Addr::from(BigEndian::read_u32(&data[12..16])),
            yiaddr: Ipv4Addr::from(BigEndian::read_u32(&data[16..20])),
            siaddr: Ipv4Addr::from(BigEndian::read_u32(&data[20..24])),
            giaddr: Ipv4Addr::from(BigEndian::read_u32(&data[24..28])),
            chaddr: [0u8; 16],
            options: HashMap::new(),
        };

        packet.chaddr.copy_from_slice(&data[28..44]);

        // Check for magic cookie at offset 236
        if data.len() > 240 && &data[236..240] == &[0x63, 0x82, 0x53, 0x63] {
            packet.options = Self::parse_options(&data[240..])?;
        }

        Ok(packet)
    }

    /// Parse DHCP options
    fn parse_options(data: &[u8]) -> Result<HashMap<u8, Vec<u8>>, DhcpError> {
        let mut options = HashMap::new();
        let mut i = 0;

        while i < data.len() {
            match data[i] {
                0 => {
                    // Padding
                    i += 1;
                }
                255 => {
                    // End of options
                    break;
                }
                option_code => {
                    if i + 1 >= data.len() {
                        break;
                    }
                    let length = data[i + 1] as usize;
                    if i + 2 + length > data.len() {
                        break;
                    }
                    let value = data[i + 2..i + 2 + length].to_vec();
                    options.insert(option_code, value);
                    i += 2 + length;
                }
            }
        }

        Ok(options)
    }

    /// Get the MAC address as a 6-byte array
    pub fn get_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    /// Get the DHCP message type from options
    pub fn get_message_type(&self) -> Option<DhcpMessageType> {
        self.options
            .get(&53)
            .and_then(|v| v.first())
            .and_then(|&t| DhcpMessageType::try_from(t).ok())
    }

    /// Create a DHCP response packet
    pub fn create_response(
        &self,
        message_type: DhcpMessageType,
        server_ip: Ipv4Addr,
        offered_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        lease_time: u32
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 240];

        // Basic packet structure
        packet[0] = 2; // BOOTREPLY
        packet[1] = 1; // Ethernet
        packet[2] = 6; // MAC address length
        packet[3] = 0; // Hops

        BigEndian::write_u32(&mut packet[4..8], self.xid);
        BigEndian::write_u16(&mut packet[8..10], 0); // secs
        BigEndian::write_u16(&mut packet[10..12], 0); // flags

        // IP addresses
        BigEndian::write_u32(&mut packet[12..16], 0); // ciaddr
        BigEndian::write_u32(&mut packet[16..20], u32::from(offered_ip)); // yiaddr
        BigEndian::write_u32(&mut packet[20..24], u32::from(server_ip)); // siaddr
        BigEndian::write_u32(&mut packet[24..28], 0); // giaddr

        // Client MAC address
        packet[28..34].copy_from_slice(&self.chaddr[..6]);

        // Magic cookie
        packet[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // DHCP options
        let mut options = Vec::new();

        // Option 53: DHCP Message Type
        options.extend_from_slice(&[53, 1, message_type as u8]);

        // Option 54: DHCP Server Identifier
        options.extend_from_slice(&[54, 4]);
        options.extend_from_slice(&server_ip.octets());

        // Option 51: IP Address Lease Time
        options.extend_from_slice(&[51, 4]);
        let mut lease_bytes = [0u8; 4];
        BigEndian::write_u32(&mut lease_bytes, lease_time);
        options.extend_from_slice(&lease_bytes);

        // Option 1: Subnet Mask
        options.extend_from_slice(&[1, 4]);
        options.extend_from_slice(&subnet_mask.octets());

        // Option 3: Router (Gateway)
        options.extend_from_slice(&[3, 4]);
        options.extend_from_slice(&server_ip.octets());

        // Option 6: Domain Name Server
        options.extend_from_slice(&[6, 4]);
        options.extend_from_slice(&server_ip.octets());

        // End option
        options.push(255);

        packet.extend_from_slice(&options);
        packet
    }
}

/// Main DHCP Manager
pub struct DhcpManager {
    server_ip: Option<Ipv4Addr>,
    start_ip: Option<Ipv4Addr>,
    end_ip: Option<Ipv4Addr>,
    subnet_mask: Ipv4Addr,
    lease_time: Duration,
    interface: Option<String>,

    leases: Arc<RwLock<HashMap<[u8; 6], DhcpLease>>>,
    available_ips: Arc<RwLock<Vec<Ipv4Addr>>>,
    is_running: Arc<AtomicBool>,
}

impl DhcpManager {
    /// Create a new DHCP Manager
    pub fn new() -> Self {
        Self {
            server_ip: None,
            start_ip: None,
            end_ip: None,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            lease_time: Duration::from_secs(3600), // 1 hour
            interface: None,
            leases: Arc::new(RwLock::new(HashMap::new())),
            available_ips: Arc::new(RwLock::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get available network interfaces
    pub fn get_network_interfaces() -> Result<Vec<NetworkInterface>, DhcpError> {
        let mut interfaces = Vec::new();

        let network_interfaces = NetInterface::show().map_err(|e| {
            DhcpError::Network(
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to enumerate network interfaces: {}", e)
                )
            )
        })?;

        for interface in network_interfaces {
            // Skip loopback and interfaces without addresses
            if interface.name.starts_with("lo") || interface.addr.is_empty() {
                continue;
            }

            // Extract IPv4 address
            let mut ipv4_addr = None;
            for addr in &interface.addr {
                if let std::net::IpAddr::V4(ip) = addr.ip() {
                    // Skip loopback IPs
                    if !ip.is_loopback() {
                        ipv4_addr = Some(ip);
                        break;
                    }
                }
            }

            // Extract MAC address
            let mac_addr = if let Some(mac_str) = &interface.mac_addr {
                Self::parse_mac_address(mac_str).ok()
            } else {
                None
            };

            if let Some(ipv4) = ipv4_addr {
                interfaces.push(NetworkInterface {
                    name: interface.name,
                    ipv4,
                    mac: mac_addr,
                });
            }
        }

        Ok(interfaces)
    }

    /// Parse MAC address from string format (e.g., "aa:bb:cc:dd:ee:ff")
    fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], DhcpError> {
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return Err(DhcpError::Address(format!("Invalid MAC address format: {}", mac_str)));
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8
                ::from_str_radix(part, 16)
                .map_err(|_| {
                    DhcpError::Address(format!("Invalid MAC address format: {}", mac_str))
                })?;
        }

        Ok(mac)
    }

    /// Configure the DHCP server
    pub async fn configure(
        &mut self,
        interface: String,
        server_ip: Ipv4Addr,
        start_ip: Ipv4Addr,
        end_ip: Ipv4Addr,
        lease_time: Duration
    ) -> Result<(), DhcpError> {
        if u32::from(start_ip) > u32::from(end_ip) {
            return Err(
                DhcpError::Config("Start IP must be less than or equal to end IP".to_string())
            );
        }

        self.interface = Some(interface);
        self.server_ip = Some(server_ip);
        self.start_ip = Some(start_ip);
        self.end_ip = Some(end_ip);
        self.lease_time = lease_time;

        self.generate_ip_pool().await?;

        info!("DHCP server configured successfully");
        Ok(())
    }

    /// Generate the IP address pool using Send-compatible RNG
    async fn generate_ip_pool(&self) -> Result<(), DhcpError> {
        let start = self.start_ip.ok_or_else(|| {
            DhcpError::Config("Start IP not configured".to_string())
        })?;
        let end = self.end_ip.ok_or_else(|| {
            DhcpError::Config("End IP not configured".to_string())
        })?;
        let server_ip = self.server_ip.ok_or_else(|| {
            DhcpError::Config("Server IP not configured".to_string())
        })?;

        let mut ips = Vec::new();
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        for ip_u32 in start_u32..=end_u32 {
            let ip = Ipv4Addr::from(ip_u32);
            if ip != server_ip {
                ips.push(ip);
            }
        }

        // Use Send-compatible RNG
        let mut rng = StdRng::from_os_rng();
        ips.shuffle(&mut rng);

        *self.available_ips.write().await = ips;

        info!(
            "Generated IP pool with {} available addresses",
            self.available_ips.read().await.len()
        );

        Ok(())
    }

    /// Start the DHCP server
    pub async fn start(&self, mut shutdown_rx: mpsc::Receiver<()>) -> Result<(), DhcpError> {
        if self.is_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        let _server_ip = self.server_ip.ok_or_else(|| {
            DhcpError::Config("Server not properly configured".to_string())
        })?;

        // Create UDP socket using socket2 for more control, then convert to tokio
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_broadcast(true)?;

        let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67);
        socket.bind(&bind_addr.into())?;

        // Convert to std socket, then to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(std_socket)?;

        self.is_running.store(true, Ordering::Relaxed);
        info!("DHCP server started on port 67");

        let mut buffer = vec![0u8; 4096];

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
                
                result = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)) => {
                    match result {
                        Ok(Ok((len, addr))) => {
                            if let Err(e) = self.process_dhcp_packet(&buffer[..len], addr, &socket).await {
                                error!("Error processing DHCP packet: {}", e);
                            }
                        }
                        Ok(Err(e)) => {
                            error!("Socket error: {}", e);
                        }
                        Err(_) => {
                            // Timeout - continue loop to check for shutdown
                            continue;
                        }
                    }
                }
            }
        }

        self.is_running.store(false, Ordering::Relaxed);
        info!("DHCP server stopped");
        Ok(())
    }

    /// Process a DHCP packet
    async fn process_dhcp_packet(
        &self,
        data: &[u8],
        _addr: SocketAddr,
        socket: &UdpSocket
    ) -> Result<(), DhcpError> {
        let packet = DhcpPacket::parse(data)?;

        match packet.get_message_type() {
            Some(DhcpMessageType::Discover) => {
                self.handle_dhcp_discover(&packet, socket).await?;
            }
            Some(DhcpMessageType::Request) => {
                self.handle_dhcp_request(&packet, socket).await?;
            }
            _ => {
                // Ignore other message types for now
                debug!("Ignoring DHCP message type: {:?}", packet.get_message_type());
            }
        }

        Ok(())
    }

    /// Handle DHCP DISCOVER message
    async fn handle_dhcp_discover(
        &self,
        packet: &DhcpPacket,
        socket: &UdpSocket
    ) -> Result<(), DhcpError> {
        let mac = packet.get_mac();
        let now = Utc::now();

        // Check for existing lease
        let offer_ip = {
            let leases = self.leases.read().await;
            if let Some(lease) = leases.get(&mac) {
                if lease.lease_end > now { Some(lease.ip) } else { None }
            } else {
                None
            }
        }; // Lock is dropped here

        let offer_ip = if let Some(ip) = offer_ip {
            ip
        } else {
            // Assign new IP
            let mut available_ips = self.available_ips.write().await;
            if available_ips.is_empty() {
                warn!("No available IPs for DHCP OFFER");
                return Ok(());
            }

            let new_ip = available_ips.remove(0);
            drop(available_ips); // Explicitly drop the lock

            // Create lease
            let lease = DhcpLease {
                ip: new_ip,
                mac,
                lease_start: now,
                lease_end: now + chrono::Duration::from_std(self.lease_time).unwrap(),
            };

            self.leases.write().await.insert(mac, lease);
            new_ip
        };

        self.send_dhcp_offer(packet, offer_ip, socket).await?;
        Ok(())
    }

    /// Handle DHCP REQUEST message
    async fn handle_dhcp_request(
        &self,
        packet: &DhcpPacket,
        socket: &UdpSocket
    ) -> Result<(), DhcpError> {
        let mac = packet.get_mac();
        let now = Utc::now();

        let mut leases = self.leases.write().await;
        if let Some(lease) = leases.get_mut(&mac) {
            // Update lease time
            lease.lease_end = now + chrono::Duration::from_std(self.lease_time).unwrap();
            let lease_ip = lease.ip; // Copy the IP before dropping the lock
            drop(leases); // Drop the lock before the await

            self.send_dhcp_ack(packet, lease_ip, socket).await?;

            info!(
                "DHCP lease renewed for MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, IP {}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5],
                lease_ip
            );
        }

        Ok(())
    }

    /// Send DHCP OFFER
    async fn send_dhcp_offer(
        &self,
        packet: &DhcpPacket,
        offer_ip: Ipv4Addr,
        socket: &UdpSocket
    ) -> Result<(), DhcpError> {
        let server_ip = self.server_ip.unwrap();
        let lease_time = self.lease_time.as_secs() as u32;

        let response = packet.create_response(
            DhcpMessageType::Offer,
            server_ip,
            offer_ip,
            self.subnet_mask,
            lease_time
        );

        let broadcast_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, 68);
        socket.send_to(&response, broadcast_addr).await?;

        let mac = packet.get_mac();
        info!(
            "Sent DHCP OFFER: {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            offer_ip,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        Ok(())
    }

    /// Send DHCP ACK
    async fn send_dhcp_ack(
        &self,
        packet: &DhcpPacket,
        ack_ip: Ipv4Addr,
        socket: &UdpSocket
    ) -> Result<(), DhcpError> {
        let server_ip = self.server_ip.unwrap();
        let lease_time = self.lease_time.as_secs() as u32;

        let response = packet.create_response(
            DhcpMessageType::Ack,
            server_ip,
            ack_ip,
            self.subnet_mask,
            lease_time
        );

        let broadcast_addr = SocketAddrV4::new(Ipv4Addr::BROADCAST, 68);
        socket.send_to(&response, broadcast_addr).await?;

        let mac = packet.get_mac();
        info!(
            "Sent DHCP ACK: {} to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            ack_ip,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        Ok(())
    }

    /// Get active leases
    pub async fn get_active_leases(&self) -> Vec<DhcpLease> {
        let now = Utc::now();
        let leases = self.leases.read().await;
        leases
            .values()
            .filter(|lease| lease.lease_end > now)
            .cloned()
            .collect()
    }

    /// Check if server is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }
}

impl Default for DhcpManager {
    fn default() -> Self {
        Self::new()
    }
}
