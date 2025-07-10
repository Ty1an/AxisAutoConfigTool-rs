//! Axis Camera Unified Setup & Configuration Tool
//! Network utilities for camera connectivity operations
//!
//! This module provides robust networking functionality for:
//! 1. Validating and verifying camera connectivity
//! 2. Waiting for cameras to become available after IP changes
//! 3. Checking network conditions and port accessibility
//! 4. Validating IP address and subnet configurations
//!
//! These utilities are critical to the camera configuration workflow,
//! particularly when transitioning cameras from temporary DHCP addresses
//!
//! to final static IP configurations.
//!
//! The implementation uses multiple connection verification methods
//! (ping, HTTP requests, port checks) for maximum reliability across
//! different network environments and camera firmware versions.

use anyhow::Result;
use ipnetwork::Ipv4Network;
use log::{ debug, error, info, warn };
use reqwest::{ Client, ClientBuilder };
use serde::{ Deserialize, Serialize };
use std::collections::HashMap;
use std::net::{ IpAddr, Ipv4Addr, SocketAddr };
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use surge_ping::ping;
use tokio::time::{ sleep, timeout, Instant };
use url::Url;

/// Custom error types for network operations
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection timeout after {timeout_secs} seconds")] Timeout {
        timeout_secs: u64,
    },

    #[error("Invalid IP address: {ip}")] InvalidIp {
        ip: String,
    },

    #[error("Authentication failed for {ip}")] AuthFailed {
        ip: String,
    },

    #[error("Network unreachable: {ip}")] NetworkUnreachable {
        ip: String,
    },

    #[error("Port {port} closed on {ip}")] PortClosed {
        ip: String,
        port: u16,
    },

    #[error("Invalid network format: {network}")] InvalidNetwork {
        network: String,
    },

    #[error("SSL/TLS error: {message}")] SslError {
        message: String,
    },

    #[error("HTTP error: {status_code}")] HttpError {
        status_code: u16,
    },

    #[error("IO error: {0}")] Io(#[from] std::io::Error),

    #[error("Request error: {0}")] Request(#[from] reqwest::Error),

    #[error("URL parse error: {0}")] UrlParse(#[from] url::ParseError),
}

/// Protocol types for camera communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
}

impl Protocol {
    pub fn port(&self) -> u16 {
        match self {
            Protocol::Http => 80,
            Protocol::Https => 443,
        }
    }

    pub fn scheme(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
    }
}

/// Network parameters calculated from IP and subnet mask
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkParameters {
    pub network_address: Ipv4Addr,
    pub broadcast_address: Ipv4Addr,
    pub first_usable: Option<Ipv4Addr>,
    pub last_usable: Option<Ipv4Addr>,
    pub cidr: String,
    pub prefix_length: u8,
    pub num_hosts: u32,
}

/// Connection attempt statistics for troubleshooting
#[derive(Debug, Default)]
struct ConnectionStats {
    ping_attempts: u32,
    port_attempts: u32,
    http_attempts: u32,
}

/// Wait for a camera to come online at the specified IP address
///
/// This function is critical when cameras change IP addresses (e.g., going from
/// DHCP to static IP). It implements a multi-layered verification approach:
///
/// 1. Initial ping check (fastest, network-level connectivity)
/// 2. Port availability check (TCP socket connection to HTTP/HTTPS port)
/// 3. API endpoint authentication (final verification of camera web services)
///
/// The progressive approach minimizes unnecessary authentication attempts
/// and provides detailed feedback about connectivity issues.
pub async fn wait_for_camera_online(
    ip: Ipv4Addr,
    username: &str,
    password: &str,
    protocol: Protocol,
    max_wait_time: Duration,
    check_interval: Duration
) -> Result<(bool, Duration), NetworkError> {
    info!(
        "Waiting for camera to become available at {} (timeout: {}s)",
        ip,
        max_wait_time.as_secs()
    );

    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true) // Handle self-signed certificates
        .build()
        .map_err(NetworkError::Request)?;

    let port = protocol.port();
    let start_time = Instant::now();
    let mut stats = ConnectionStats::default();

    while start_time.elapsed() < max_wait_time {
        // STEP 1: Try ping first (fastest method)
        stats.ping_attempts += 1;
        if ping_host(ip, 1, Duration::from_secs(2)).await? {
            info!("Host {} is responding to ping", ip);

            // STEP 2: Check if port is open
            stats.port_attempts += 1;
            if check_port_open(ip, port, Duration::from_secs(2)).await? {
                info!("Port {} is open on {}", port, ip);

                // STEP 3: Try HTTP connection to verify camera web interface is up
                stats.http_attempts += 1;
                match verify_camera_auth(&client, ip, username, password, protocol).await {
                    Ok(_) => {
                        let elapsed_time = start_time.elapsed();
                        info!(
                            "Camera at {} is online and accepting authentication (took {:.2}s)",
                            ip,
                            elapsed_time.as_secs_f64()
                        );
                        return Ok((true, elapsed_time));
                    }
                    Err(NetworkError::AuthFailed { .. }) => {
                        warn!("Authentication failed for {} - check credentials", ip);
                    }
                    Err(NetworkError::SslError { .. }) => {
                        // SSL error indicates server is responding but with invalid cert
                        warn!("SSL verification failed for {} - certificate may be self-signed", ip);
                        let elapsed_time = start_time.elapsed();
                        return Ok((true, elapsed_time));
                    }
                    Err(e) => {
                        debug!("HTTP connection attempt to {} failed: {}", ip, e);
                    }
                }
            } else {
                debug!("Port {} not responding on {}", port, ip);
            }
        }

        // Wait before next check
        sleep(check_interval).await;
        let elapsed = start_time.elapsed();

        // Provide progressive feedback during longer waits
        let elapsed_secs = elapsed.as_secs();
        let max_secs = max_wait_time.as_secs();

        if elapsed >= max_wait_time {
            warn!("Timeout waiting for camera at {} to come online after {}s", ip, max_secs);
            break;
        } else if elapsed_secs >= (max_secs * 3) / 4 {
            info!(
                "Still waiting for camera at {} to come online ({}s elapsed, 75% of timeout)",
                ip,
                elapsed_secs
            );
        } else if elapsed_secs >= max_secs / 2 {
            info!(
                "Still waiting for camera at {} to come online ({}s elapsed, 50% of timeout)",
                ip,
                elapsed_secs
            );
        }
    }

    // Log detailed connection attempt statistics for troubleshooting
    debug!(
        "Connection attempts for {}: ping={}, port={}, http={}",
        ip,
        stats.ping_attempts,
        stats.port_attempts,
        stats.http_attempts
    );

    Ok((false, start_time.elapsed()))
}

/// Ping a host to check if it's online using async surge-ping
pub async fn ping_host(
    ip: Ipv4Addr,
    count: u32,
    timeout_duration: Duration
) -> Result<bool, NetworkError> {
    let mut successful_pings = 0;

    for _i in 0..count {
        let result = timeout(timeout_duration, ping(IpAddr::V4(ip), &[])).await;

        match result {
            Ok(Ok(_)) => {
                successful_pings += 1;
            }
            Ok(Err(_)) => {} // Ping failed but no timeout
            Err(_) => {} // Timeout occurred
        }
    }

    // Consider successful if at least one ping succeeds
    Ok(successful_pings > 0)
}

/// Validate IP address format and provide detailed feedback
///
/// Uses the standard library for RFC-compliant validation of IPv4 addresses.
/// This function checks for:
/// - Proper format (4 octets of numbers 0-255 separated by dots)
/// - Reserved/special addresses (like 0.0.0.0, 127.0.0.1, etc.)
/// - Private network ranges
pub fn validate_ip_address(ip_str: &str) -> Result<(), NetworkError> {
    let ip: Ipv4Addr = ip_str.parse().map_err(|_| NetworkError::InvalidIp {
        ip: ip_str.to_string(),
    })?;

    if ip.is_loopback() {
        return Err(NetworkError::InvalidIp {
            ip: format!("Loopback address ({}) not allowed for camera configuration", ip),
        });
    }

    if ip.is_multicast() {
        return Err(NetworkError::InvalidIp {
            ip: format!("Multicast address ({}) not allowed for camera configuration", ip),
        });
    }

    if ip.is_unspecified() {
        return Err(NetworkError::InvalidIp {
            ip: "Unspecified address (0.0.0.0) not allowed".to_string(),
        });
    }

    // Check for broadcast (255.255.255.255)
    if ip.is_broadcast() {
        return Err(NetworkError::InvalidIp {
            ip: format!("Broadcast address ({}) not allowed", ip),
        });
    }

    // For informational purposes, log if the IP is in a private range
    if ip.is_private() {
        debug!("IP {} is in a private address range (recommended)", ip);
    }

    Ok(())
}

/// Check if an IP address is in a network range
///
/// This function verifies if a given IP address belongs to a specified
/// network range. It's useful for:
/// - Validating that static IPs are in the correct subnet
/// - Ensuring gateway and camera IPs are in the same network
/// - Detecting potential routing issues before they occur
pub fn is_ip_in_network(ip: Ipv4Addr, network_str: &str) -> Result<bool, NetworkError> {
    let network: Ipv4Network = network_str.parse().map_err(|e| NetworkError::InvalidNetwork {
        network: format!("{}: {}", network_str, e),
    })?;

    Ok(network.contains(ip))
}

/// Check if a specific TCP port is open on a host
///
/// This function performs a TCP socket connection test to determine
/// if a specific port is open and accepting connections. This is
/// particularly useful for verifying that a camera's web server is
/// functioning before attempting more complex API requests.
pub async fn check_port_open(
    ip: Ipv4Addr,
    port: u16,
    timeout_duration: Duration
) -> Result<bool, NetworkError> {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);

    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false), // Timeout
    }
}

/// Calculate network parameters from IP address and subnet mask
///
/// This utility function computes various useful network values:
/// - Network address (e.g., 192.168.1.0)
/// - Broadcast address (e.g., 192.168.1.255)
/// - CIDR notation (e.g., 192.168.1.0/24)
/// - Valid IP range (first usable to last usable)
/// - Prefix length (e.g., 24)
///
/// These values are useful for:
/// - Validating gateway addresses
/// - Computing proper IP ranges for DHCP
/// - Ensuring IPs are within valid ranges
/// - Network configuration validation
pub fn calculate_network_parameters(
    ip: Ipv4Addr,
    subnet_mask: Ipv4Addr
) -> Result<NetworkParameters, NetworkError> {
    // Convert subnet mask to prefix length
    let prefix_len = subnet_mask_to_prefix_length(subnet_mask)?;
    let network = Ipv4Network::new(ip, prefix_len).map_err(|e| NetworkError::InvalidNetwork {
        network: format!("Failed to create network from {}/{}: {}", ip, prefix_len, e),
    })?;

    // Get all host addresses
    let hosts: Vec<Ipv4Addr> = network.iter().collect();

    // First and last usable addresses (excluding network and broadcast)
    let (first_usable, last_usable) = if hosts.len() > 2 {
        (Some(hosts[1]), Some(hosts[hosts.len() - 2]))
    } else {
        (None, None)
    };

    Ok(NetworkParameters {
        network_address: network.network(),
        broadcast_address: network.broadcast(),
        first_usable,
        last_usable,
        cidr: network.to_string(),
        prefix_length: network.prefix(),
        num_hosts: network.size().saturating_sub(2), // Subtract network and broadcast addresses
    })
}

/// Convert subnet mask to prefix length
fn subnet_mask_to_prefix_length(mask: Ipv4Addr) -> Result<u8, NetworkError> {
    let mask_bits = u32::from(mask);
    let prefix_len = mask_bits.leading_ones() as u8;

    // Validate it's a proper subnet mask (contiguous 1s followed by contiguous 0s)
    let expected_mask = (0xffffffff_u32).checked_shl(32 - (prefix_len as u32)).unwrap_or(0);

    if mask_bits != expected_mask {
        return Err(NetworkError::InvalidNetwork {
            network: format!("Invalid subnet mask: {}", mask),
        });
    }

    Ok(prefix_len)
}

/// Verify camera authentication by making an HTTP request
pub async fn verify_camera_auth(
    client: &Client,
    ip: Ipv4Addr,
    username: &str,
    password: &str,
    protocol: Protocol
) -> Result<(), NetworkError> {
    let base_url = format!("{}://{}", protocol.scheme(), ip);
    let endpoint = "/axis-cgi/usergroup.cgi"; // Simple endpoint to check auth
    let url = Url::parse(&base_url)?.join(endpoint)?;

    // First attempt without auth to trigger authentication
    let response = client.get(url.clone()).send().await?;

    match response.status().as_u16() {
        200 => Ok(()), // Success
        401 => {
            // Try with digest authentication
            let auth_response = client.get(url).basic_auth(username, Some(password)).send().await?;

            match auth_response.status().as_u16() {
                200 => Ok(()),
                401 =>
                    Err(NetworkError::AuthFailed {
                        ip: ip.to_string(),
                    }),
                status =>
                    Err(NetworkError::HttpError {
                        status_code: status,
                    }),
            }
        }
        status => {
            if status >= 500 {
                // Server error, but camera is responding
                Ok(())
            } else {
                Err(NetworkError::HttpError {
                    status_code: status,
                })
            }
        }
    }
}

/// Utility function to create a default HTTP client for camera operations
pub fn create_camera_client() -> Result<Client, NetworkError> {
    ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .user_agent("Axis-Camera-Config-Tool/1.0")
        .build()
        .map_err(NetworkError::Request)
}

/// Batch validate multiple IP addresses
pub fn validate_ip_addresses(ips: &[&str]) -> HashMap<String, Result<(), NetworkError>> {
    ips.iter()
        .map(|&ip| (ip.to_string(), validate_ip_address(ip)))
        .collect()
}

/// Check if multiple IPs are in the same network
pub fn validate_ips_in_network(
    ips: &[Ipv4Addr],
    network: &str
) -> HashMap<String, Result<bool, NetworkError>> {
    ips.iter()
        .map(|&ip| (ip.to_string(), is_ip_in_network(ip, network)))
        .collect()
}
