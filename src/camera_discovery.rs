//! Axis Camera Unified Setup & Configuration Tool
//! Camera discovery module

use anyhow::Result;
use log::{debug, info, warn};
use reqwest::{Client, ClientBuilder, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;
use url::Url;

/// Custom error types for camera discovery operations
#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("Network timeout for {ip}")]
    Timeout { ip: String },
    
    #[error("Connection failed for {ip}: {reason}")]
    ConnectionFailed { ip: String, reason: String },
    
    #[error("HTTP error for {ip}: {status}")]
    HttpError { ip: String, status: u16 },
    
    #[error("Invalid IP address: {ip}")]
    InvalidIp { ip: String },
    
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

/// Device information returned by discovery operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub ip: String,
    pub status: String,
    pub device_type: Option<String>,
    pub server_header: Option<String>,
    pub authentication_type: Option<String>,
    pub response_time_ms: Option<u64>,
}

/// Camera discovery functionality for Axis cameras
#[derive(Debug)]
pub struct CameraDiscovery {
    /// Timeout for connection attempts (seconds)
    timeout: Duration,
    /// HTTP client for making requests
    client: Client,
}

impl CameraDiscovery {
    /// Initialize the Camera Discovery module
    pub fn new() -> Result<Self, DiscoveryError> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(2))
            .danger_accept_invalid_certs(true)
            .user_agent("Axis-Camera-Discovery/1.0")
            .build()
            .map_err(DiscoveryError::Request)?;

        Ok(Self {
            timeout: Duration::from_secs(2),
            client,
        })
    }

    /// Create a new instance with custom timeout
    pub fn with_timeout(timeout: Duration) -> Result<Self, DiscoveryError> {
        let client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .user_agent("Axis-Camera-Discovery/1.0")
            .build()
            .map_err(DiscoveryError::Request)?;

        Ok(Self { timeout, client })
    }

    /// Check if a device at the specified IP is potentially an Axis camera
    ///
    /// This performs multiple checks to identify Axis cameras:
    /// 1. Basic connectivity (ping)
    /// 2. HTTP port availability
    /// 3. Axis-specific response characteristics
    pub async fn check_device(&self, ip: Ipv4Addr) -> Result<bool, DiscoveryError> {
        let ip_str = ip.to_string();

        // First check basic connectivity
        let is_pingable = self.check_ping(ip).await?;
        if !is_pingable {
            debug!("Device at {} did not respond to ping", ip_str);
            // Continue with other checks even if ping fails (some cameras may have ping disabled)
        }

        // Check for Axis-specific HTTP characteristics
        if self.check_axis_specific(ip).await? {
            info!("Device at {} identified as an Axis camera", ip_str);
            return Ok(true);
        }

        // Try basic HTTP connectivity as a fallback
        if self.check_http_connection(ip).await? {
            info!("Device at {} has open HTTP port (possibly an Axis camera)", ip_str);
            return Ok(true);
        }

        // If device responded to ping but not to HTTP, it's likely not a camera
        if is_pingable {
            debug!("Device at {} responded to ping but doesn't appear to be an Axis camera", ip_str);
        }

        Ok(false)
    }

    /// Check for Axis-specific characteristics to identify cameras
    async fn check_axis_specific(&self, ip: Ipv4Addr) -> Result<bool, DiscoveryError> {
        let ip_str = ip.to_string();

        // Common Axis endpoints to check
        let endpoints = [
            "/axis-cgi/usergroup.cgi",
            "/axis-cgi/basicdeviceinfo.cgi",
            "/",
        ];

        // First try HEAD requests to common Axis endpoints
        for endpoint in &endpoints {
            match self.check_endpoint_with_head(ip, endpoint).await {
                Ok(true) => {
                    info!("Axis server characteristics detected at {} via {}", ip_str, endpoint);
                    return Ok(true);
                }
                Ok(false) => continue,
                Err(_) => continue, // Try next endpoint
            }
        }

        // Try a GET request to analyze the response body
        match self.check_content_for_axis_indicators(ip).await {
            Ok(true) => {
                info!("Axis-specific content detected at {}", ip_str);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(e) => {
                debug!("Error in Axis-specific check for {}: {}", ip_str, e);
                Ok(false)
            }
        }
    }

    /// Check a specific endpoint with HEAD request for Axis characteristics
    async fn check_endpoint_with_head(&self, ip: Ipv4Addr, endpoint: &str) -> Result<bool, DiscoveryError> {
        let url_str = format!("http://{}{}", ip, endpoint);
        let url = Url::parse(&url_str)?;

        let response = self
            .client
            .request(Method::HEAD, url)
            .send()
            .await?;

        let headers = response.headers();

        // Check for Axis-specific HTTP headers
        if let Some(server_header) = headers.get("server") {
            if let Ok(server_str) = server_header.to_str() {
                let server_lower = server_str.to_lowercase();
                if server_lower.contains("axis") {
                    info!("Axis server header detected at {}: {}", ip, server_str);
                    return Ok(true);
                }
            }
        }

        // Response code 401 (Unauthorized) is common for Axis cameras with default endpoints
        if response.status().as_u16() == 401 {
            if let Some(auth_header) = headers.get("www-authenticate") {
                if let Ok(auth_str) = auth_header.to_str() {
                    let auth_lower = auth_str.to_lowercase();
                    if auth_lower.contains("digest") && 
                       (auth_lower.contains("axis") || auth_lower.contains("realm")) {
                        info!("Axis digest authentication detected at {}", ip);
                        return Ok(true);
                    }
                }
            }
        }

        // Sometimes, an Axis camera redirects to the web interface
        let status = response.status().as_u16();
        if status == 302 || status == 301 {
            if let Some(location) = headers.get("location") {
                if let Ok(location_str) = location.to_str() {
                    let location_lower = location_str.to_lowercase();
                    if location_lower.contains("index.html") || location_lower.contains("axis") {
                        info!("Axis-like redirect detected at {}", ip);
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check response content for Axis indicators
    async fn check_content_for_axis_indicators(&self, ip: Ipv4Addr) -> Result<bool, DiscoveryError> {
        let url_str = format!("http://{}/", ip);
        let url = Url::parse(&url_str)?;

        let response = self.client.get(url).send().await?;
        let content = response.text().await?;
        let content_lower = content.to_lowercase();

        // Look for Axis indicators in the response content
        let axis_indicators = [
            "axis communications",
            "axis camera",
            "axis network camera",
        ];

        for indicator in &axis_indicators {
            if content_lower.contains(indicator) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a device responds to ping
    async fn check_ping(&self, ip: Ipv4Addr) -> Result<bool, DiscoveryError> {
        let ip_str = ip.to_string();

        let mut cmd = Command::new("ping");

        // Platform-specific ping command
        #[cfg(windows)]
        {
            cmd.args([
                "-n", "1",
                "-w", &(self.timeout.as_millis() as u64).to_string(),
                &ip_str,
            ]);
        }

        #[cfg(not(windows))]
        {
            cmd.args([
                "-c", "1",
                "-W", &self.timeout.as_secs().to_string(),
                &ip_str,
            ]);
        }

        // Run ping command with additional timeout margin
        let output = timeout(
            self.timeout + Duration::from_secs(1),
            cmd.output()
        )
        .await
        .map_err(|_| DiscoveryError::Timeout { ip: ip_str.clone() })?
        .map_err(|e| DiscoveryError::ConnectionFailed {
            ip: ip_str.clone(),
            reason: format!("Ping subprocess error: {}", e),
        })?;

        Ok(output.status.success())
    }

    /// Check if a device has an open HTTP port (80)
    async fn check_http_connection(&self, ip: Ipv4Addr) -> Result<bool, DiscoveryError> {
        let ip_str = ip.to_string();
        let addr = SocketAddr::new(IpAddr::V4(ip), 80);

        // Try to connect to HTTP port
        let tcp_result = timeout(self.timeout, TcpStream::connect(addr)).await;

        match tcp_result {
            Ok(Ok(_)) => {
                // HTTP port is open, try a simple HEAD request
                let url_str = format!("http://{}/", ip);
                match Url::parse(&url_str) {
                    Ok(url) => {
                        match self.client.head(url).send().await {
                            Ok(_) => {
                                // Any response (even 401 Unauthorized) suggests a web server is present
                                Ok(true)
                            }
                            Err(_) => {
                                // If the HTTP request fails, but the port was open,
                                // still consider it as potentially a camera
                                Ok(true)
                            }
                        }
                    }
                    Err(e) => {
                        debug!("URL parse error for {}: {}", ip_str, e);
                        Ok(false)
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("TCP connection failed for {}: {}", ip_str, e);
                Ok(false)
            }
            Err(_) => {
                debug!("TCP connection timeout for {}", ip_str);
                Ok(false)
            }
        }
    }

    /// Get basic device information
    ///
    /// This method retrieves minimal device information for discovery purposes
    pub async fn get_device_info(
        &self,
        ip: Ipv4Addr,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<DeviceInfo, DiscoveryError> {
        let ip_str = ip.to_string();
        let start_time = std::time::Instant::now();

        // Check if device is responsive
        let is_responsive = self.check_device(ip).await?;
        let response_time = start_time.elapsed().as_millis() as u64;

        let mut device_info = DeviceInfo {
            ip: ip_str,
            status: if is_responsive { "discovered".to_string() } else { "not_responsive".to_string() },
            device_type: None,
            server_header: None,
            authentication_type: None,
            response_time_ms: Some(response_time),
        };

        // If device is responsive, try to get more detailed information
        if is_responsive {
            if let Ok(details) = self.get_detailed_device_info(ip, username, password).await {
                device_info.device_type = details.device_type;
                device_info.server_header = details.server_header;
                device_info.authentication_type = details.authentication_type;
            }
        }

        Ok(device_info)
    }

    /// Get detailed device information with optional authentication
    async fn get_detailed_device_info(
        &self,
        ip: Ipv4Addr,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<DeviceInfo, DiscoveryError> {
        let ip_str = ip.to_string();
        let url_str = format!("http://{}/", ip);
        let url = Url::parse(&url_str)?;

        let mut request = self.client.head(url);

        // Add authentication if provided
        if let (Some(user), Some(pass)) = (username, password) {
            request = request.basic_auth(user, Some(pass));
        }

        let response = request.send().await?;
        let headers = response.headers();

        let server_header = headers
            .get("server")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let auth_type = headers
            .get("www-authenticate")
            .and_then(|h| h.to_str().ok())
            .map(|auth_str| {
                if auth_str.to_lowercase().contains("digest") {
                    "digest".to_string()
                } else if auth_str.to_lowercase().contains("basic") {
                    "basic".to_string()
                } else {
                    "unknown".to_string()
                }
            });

        let device_type = if server_header.as_ref().map_or(false, |s| s.to_lowercase().contains("axis")) {
            Some("axis_camera".to_string())
        } else {
            Some("unknown_device".to_string())
        };

        Ok(DeviceInfo {
            ip: ip_str,
            status: "discovered".to_string(),
            device_type,
            server_header,
            authentication_type: auth_type,
            response_time_ms: None,
        })
    }

    /// Batch check multiple IP addresses for Axis cameras
    pub async fn check_multiple_devices(&self, ips: &[Ipv4Addr]) -> HashMap<String, bool> {
        let mut results = HashMap::new();
        
        // Use tokio::spawn to check devices concurrently
        let mut handles = Vec::new();
        
        for &ip in ips {
            let discovery = CameraDiscovery::with_timeout(self.timeout).unwrap();
            let handle = tokio::spawn(async move {
                let result = discovery.check_device(ip).await.unwrap_or(false);
                (ip.to_string(), result)
            });
            handles.push(handle);
        }
        
        // Collect results
        for handle in handles {
            if let Ok((ip, result)) = handle.await {
                results.insert(ip, result);
            }
        }
        
        results
    }

    /// Scan a subnet for Axis cameras
    pub async fn scan_subnet(&self, network: &str) -> Result<Vec<DeviceInfo>, DiscoveryError> {
        use ipnetwork::Ipv4Network;
        use std::str::FromStr;

        let network: Ipv4Network = network.parse()
            .map_err(|_| DiscoveryError::InvalidIp { ip: network.to_string() })?;

        let mut discovered_devices = Vec::new();
        let mut handles = Vec::new();

        // Limit concurrent connections to avoid overwhelming the network
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(20));

        for ip in network.iter() {
            let discovery = CameraDiscovery::with_timeout(self.timeout)?;
            let sem = semaphore.clone();
            
            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                discovery.get_device_info(ip, None, None).await
            });
            
            handles.push(handle);
        }

        // Collect results
        for handle in handles {
            if let Ok(Ok(device_info)) = handle.await {
                if device_info.status == "discovered" {
                    discovered_devices.push(device_info);
                }
            }
        }

        info!("Subnet scan of {} completed. Found {} devices", network, discovered_devices.len());
        Ok(discovered_devices)
    }
}

impl Default for CameraDiscovery {
    fn default() -> Self {
        Self::new().expect("Failed to create default CameraDiscovery")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tokio::test;

    #[test]
    async fn test_camera_discovery_creation() {
        let discovery = CameraDiscovery::new();
        assert!(discovery.is_ok());
    }

    #[test]
    async fn test_camera_discovery_with_timeout() {
        let discovery = CameraDiscovery::with_timeout(Duration::from_secs(5));
        assert!(discovery.is_ok());
        assert_eq!(discovery.unwrap().timeout, Duration::from_secs(5));
    }

    #[test]
    async fn test_check_localhost() {
        let discovery = CameraDiscovery::new().unwrap();
        let ip = Ipv4Addr::from_str("127.0.0.1").unwrap();
        
        // This test might fail depending on the environment
        let result = discovery.check_device(ip).await;
        println!("Localhost check result: {:?}", result);
        // We don't assert the result because localhost behavior varies
    }

    #[test]
    async fn test_get_device_info() {
        let discovery = CameraDiscovery::new().unwrap();
        let ip = Ipv4Addr::from_str("127.0.0.1").unwrap();
        
        let result = discovery.get_device_info(ip, None, None).await;
        assert!(result.is_ok());
        
        let device_info = result.unwrap();
        assert_eq!(device_info.ip, "127.0.0.1");
        assert!(device_info.response_time_ms.is_some());
    }

    #[test]
    async fn test_batch_check() {
        let discovery = CameraDiscovery::new().unwrap();
        let ips = vec![
            Ipv4Addr::from_str("127.0.0.1").unwrap(),
            Ipv4Addr::from_str("192.168.1.1").unwrap(),
        ];
        
        let results = discovery.check_multiple_devices(&ips).await;
        assert_eq!(results.len(), 2);
        assert!(results.contains_key("127.0.0.1"));
        assert!(results.contains_key("192.168.1.1"));
    }
}
