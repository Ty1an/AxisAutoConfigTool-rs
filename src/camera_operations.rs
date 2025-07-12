//! Axis Camera Unified Setup & Configuration Tool
//! Camera operations module for VAPIX

use anyhow::Result;
use log::{ debug, error, info, warn };
use reqwest::{ multipart, Client, ClientBuilder, Response };
use serde::{ Deserialize, Serialize };
use serde_json::{ json, Value };
use url::Url;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::sync::Arc;
use thiserror::Error;
use diqwest::WithDigestAuth;
use reqwest::header::{ AUTHORIZATION, WWW_AUTHENTICATE };
use std::collections::HashMap;

/// Custom error types for camera operations
#[derive(Error, Debug)]
pub enum CameraError {
    #[error("Connection timeout for {ip}")] Timeout {
        ip: String,
    },

    #[error("Authentication failed for {ip}")] AuthFailed {
        ip: String,
    },

    #[error("HTTP error for {ip}: {status}")] HttpError {
        ip: String,
        status: u16,
    },

    #[error("Invalid IP address: {ip}")] InvalidIp {
        ip: String,
    },

    #[error("User already exists: {username}")] UserExists {
        username: String,
    },

    #[error("Camera not in factory state: {message}")] NotFactoryState {
        message: String,
    },

    #[error("Parameter not supported: {parameter}")] ParameterNotSupported {
        parameter: String,
    },

    #[error("Firmware upgrade failed: {message}")] FirmwareUpgradeFailed {
        message: String,
    },

    #[error(
        "Model incompatible: Camera model '{camera_model}' not compatible with firmware. Compatible models: {compatible_models}"
    )] ModelIncompatible {
        camera_model: String,
        compatible_models: String,
    },

    #[error("Invalid network configuration: {message}")] InvalidNetworkConfig {
        message: String,
    },

    #[error("Request error: {0}")] Request(#[from] reqwest::Error),

    #[error("Digest auth error: {0}")] DigestAuth(#[from] diqwest::error::Error),

    #[error("IO error: {0}")] Io(#[from] std::io::Error),

    #[error("JSON error: {0}")] Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")] UrlParse(#[from] url::ParseError),
}

/// Protocol types for camera communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
}

impl Protocol {
    pub fn scheme(&self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
    }
}

/// IP configuration for static network setup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpConfig {
    pub ip: String,
    pub subnet: String,
    pub gateway: String,
}

/// Firmware upgrade progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareStatus {
    pub active_firmware_version: String,
    pub inactive_firmware_version: Option<String>,
    pub is_committed: bool,
    pub time_to_rollback: Option<u32>,
    pub last_upgrade_at: Option<String>,
}

/// Firmware upgrade options
#[derive(Debug, Clone)]
pub struct FirmwareUpgradeOptions {
    pub auto_rollback_timeout: Option<u32>, // Seconds before auto-rollback
    pub commit_automatically: bool,
}

/// Firmware file information with model compatibility
#[derive(Debug, Clone)]
pub struct FirmwareFile {
    pub filename: String,
    pub file_path: Option<std::path::PathBuf>, // Store file path for lazy loading
    pub data: Option<Arc<Vec<u8>>>, // Lazy-loaded data
    pub compatible_models: Vec<String>, // List of compatible camera models
}

/// Model-to-firmware mapping for multi-model support
#[derive(Debug, Clone)]
pub struct ModelFirmwareMapping {
    pub firmware_files: Vec<FirmwareFile>,
}

impl ModelFirmwareMapping {
    pub fn new() -> Self {
        Self {
            firmware_files: Vec::new(),
        }
    }

    pub fn add_firmware(
        &mut self,
        filename: String,
        file_path: std::path::PathBuf,
        compatible_models: Vec<String>
    ) {
        self.firmware_files.push(FirmwareFile {
            filename,
            file_path: Some(file_path),
            data: None,
            compatible_models,
        });
    }

    pub fn add_firmware_data(
        &mut self,
        filename: String,
        data: Arc<Vec<u8>>,
        compatible_models: Vec<String>
    ) {
        self.firmware_files.push(FirmwareFile {
            filename,
            file_path: None,
            data: Some(data),
            compatible_models,
        });
    }

    // Match firmware files to camera models using both user-defined mappings and filename parsing
    pub fn find_firmware_for_model(&self, model_name: &str) -> Option<&FirmwareFile> {
        self.firmware_files.iter().find(|fw| {
            // First try exact matching with user-defined compatible models
            let user_model_match = fw.compatible_models
                .iter()
                .any(|compatible_model| {
                    model_name.to_lowercase().contains(&compatible_model.to_lowercase()) ||
                        compatible_model.to_lowercase().contains(&model_name.to_lowercase())
                });

            if user_model_match {
                return true;
            }

            // If no user-defined models match, try extracting model from firmware filename
            // Example: "P3219-PLE_11_11_148.bin" -> extract "P3219-PLE"
            if let Some(extracted_model) = Self::extract_model_from_firmware_filename(&fw.filename) {
                // Check if camera model contains the extracted firmware model prefix
                model_name.to_lowercase().contains(&extracted_model.to_lowercase()) ||
                    extracted_model.to_lowercase().contains(&model_name.to_lowercase())
            } else {
                false
            }
        })
    }

    /// Load firmware data on demand (lazy loading)
    pub fn load_firmware_data(
        &mut self,
        firmware_file: &mut FirmwareFile
    ) -> Result<Arc<Vec<u8>>, std::io::Error> {
        if let Some(data) = &firmware_file.data {
            return Ok(data.clone());
        }

        if let Some(file_path) = &firmware_file.file_path {
            let data = std::fs::read(file_path)?;
            let arc_data = Arc::new(data);
            firmware_file.data = Some(arc_data.clone());
            Ok(arc_data)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No data or file path available"))
        }
    }

    /// Extract model prefix from firmware filename
    /// Example: "P3219-PLE_11_11_148.bin" -> "P3219-PLE"
    pub fn extract_model_from_firmware_filename(filename: &str) -> Option<String> {
        let name_without_ext = filename.strip_suffix(".bin").unwrap_or(filename);

        if let Some(underscore_pos) = name_without_ext.find('_') {
            let model_part = &name_without_ext[..underscore_pos];
            if !model_part.is_empty() {
                return Some(model_part.to_string());
            }
        }

        if let Some(version_start) = name_without_ext.find(char::is_numeric) {
            let before_version = &name_without_ext[..version_start];
            if before_version.len() > 1 && before_version.ends_with('_') {
                let model_part = &before_version[..before_version.len() - 1];
                if !model_part.is_empty() {
                    return Some(model_part.to_string());
                }
            }
        }

        None
    }
}

impl Default for FirmwareUpgradeOptions {
    fn default() -> Self {
        Self {
            auto_rollback_timeout: None,
            commit_automatically: true,
        }
    }
}

/// VAPIX operations for Axis cameras
#[derive(Debug)]
pub struct CameraOperations {
    /// Number of retries for failed requests
    retry_count: u32,
    /// Seconds to wait between retries
    retry_delay: Duration,
    /// HTTP client for making requests
    client: Client,
}

impl CameraOperations {
    /// Initialize Camera Operations module
    pub fn new() -> Result<Self, CameraError> {
        let client = ClientBuilder::new()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent("Axis-Camera-Operations/1.0")
            .pool_max_idle_per_host(3) // Reduced from 10 to 3 idle connections per host
            .pool_idle_timeout(Duration::from_secs(30)) // Reduced from 90 to 30 seconds
            .tcp_keepalive(Duration::from_secs(30)) // Reduced from 60 to 30 seconds
            .build()
            .map_err(CameraError::Request)?;

        Ok(Self {
            retry_count: 3,
            retry_delay: Duration::from_secs(2),
            client,
        })
    }
    
    /// Find camera's new IP by MAC address in DHCP leases (much more efficient)
    pub fn find_camera_ip_by_mac_in_dhcp_leases(
        mac_address: &str,
        dhcp_leases: &[crate::dchp_manager::DhcpLease]
    ) -> Option<Ipv4Addr> {
        for lease in dhcp_leases {
            let lease_mac = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                lease.mac[0], lease.mac[1], lease.mac[2],
                lease.mac[3], lease.mac[4], lease.mac[5]
            );
            
            if lease_mac.to_lowercase() == mac_address.to_lowercase() {
                debug!("Found camera MAC {} at IP {} in DHCP leases", mac_address, lease.ip);
                return Some(lease.ip);
            }
        }
        
        debug!("Camera MAC {} not found in current DHCP leases", mac_address);
        None
    }

    /// Calculate MD5 hash for digest authentication
    fn calculate_md5(input: &str) -> String {
        format!("{:x}", md5::compute(input.as_bytes()))
    }

    /// Parse WWW-Authenticate header to extract digest parameters
    fn parse_digest_challenge(auth_header: &str) -> Result<HashMap<String, String>, CameraError> {
        let mut params = HashMap::new();

        // Remove "Digest " prefix
        let challenge = auth_header.strip_prefix("Digest ").unwrap_or(auth_header);

        // Parse key=value pairs
        for part in challenge.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                params.insert(key.to_string(), value.to_string());
            }
        }

        Ok(params)
    }

    /// Calculate digest response for authentication
    fn calculate_digest_response(
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        realm: &str,
        nonce: &str,
        qop: Option<&str>,
        nc: Option<&str>,
        cnonce: Option<&str>
    ) -> String {
        let ha1 = Self::calculate_md5(&format!("{}:{}:{}", username, realm, password));
        let ha2 = Self::calculate_md5(&format!("{}:{}", method, uri));

        if let (Some(qop), Some(nc), Some(cnonce)) = (qop, nc, cnonce) {
            Self::calculate_md5(&format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2))
        } else {
            Self::calculate_md5(&format!("{}:{}:{}", ha1, nonce, ha2))
        }
    }

    /// Perform digest authentication manually for multipart requests
    // Custom digest auth implementation for multipart uploads since reqwest doesn't support digest+multipart
    async fn send_multipart_with_digest_auth(
        &self,
        url: reqwest::Url,
        form: multipart::Form,
        username: &str,
        password: &str
    ) -> Result<Response, CameraError> {
        // Step 1: Make initial GET request to the same endpoint to get digest challenge
        // This is more standard than POST and avoids potential issues
        info!("Making initial request to {} to get digest challenge", url);
        let initial_response = self.client
            .get(url.clone())
            .timeout(Duration::from_secs(30))
            .send().await
            .map_err(|e| {
                error!("Failed to make initial request for digest challenge: {}", e);
                CameraError::Request(e)
            })?;

        info!("Initial response status: {}", initial_response.status());

        if initial_response.status() != 401 {
            // Try a POST request to trigger digest challenge
            info!("GET request didn't return 401, trying POST to trigger digest challenge");
            let post_response = self.client
                .post(url.clone())
                .timeout(Duration::from_secs(30))
                .send().await
                .map_err(CameraError::Request)?;

            info!("POST response status: {}", post_response.status());
            if post_response.status() != 401 {
                error!("Neither GET nor POST returned 401 Unauthorized for digest challenge");
                return Err(CameraError::HttpError {
                    ip: url.host_str().unwrap_or("unknown").to_string(),
                    status: post_response.status().as_u16(),
                });
            }
        }

        // Use the response that gave us 401
        let auth_response = if initial_response.status() == 401 {
            initial_response
        } else {
            self.client.post(url.clone()).send().await.map_err(CameraError::Request)?
        };

        // Step 2: Parse WWW-Authenticate header
        let auth_header = auth_response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| CameraError::AuthFailed {
                ip: url.host_str().unwrap_or("unknown").to_string(),
            })?;

        let digest_params = Self::parse_digest_challenge(auth_header)?;

        let realm = digest_params.get("realm").cloned().unwrap_or_default();
        let nonce = digest_params.get("nonce").cloned().unwrap_or_default();
        let qop = digest_params.get("qop");
        let algorithm = digest_params.get("algorithm");

        // Step 3: Generate client nonce and nc if qop is present
        let (cnonce, nc) = if qop.is_some() {
            let cnonce = format!(
                "{:x}",
                md5::compute(
                    format!(
                        "{}",
                        std::time::SystemTime
                            ::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_nanos()
                    )
                )
            );
            let nc = "00000001";
            (Some(cnonce), Some(nc))
        } else {
            (None, None)
        };

        // Step 4: Calculate digest response
        let uri = url.path();
        let response = Self::calculate_digest_response(
            username,
            password,
            "POST", // Method for firmware upload
            uri,
            &realm,
            &nonce,
            qop.as_deref().map(|x| x.as_str()),
            nc,
            cnonce.as_deref()
        );

        // Step 5: Build Authorization header
        let mut auth_value = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            username,
            realm,
            nonce,
            uri,
            response
        );

        if let Some(qop_val) = qop {
            if let (Some(cnonce), Some(nc)) = (&cnonce, &nc) {
                auth_value.push_str(
                    &format!(r#", qop={}, nc={}, cnonce="{}""#, qop_val, nc, cnonce)
                );
            }
        }

        if let Some(alg) = algorithm {
            auth_value.push_str(&format!(r#", algorithm={}"#, alg));
        }

        info!("Generated digest auth header for firmware upload");
        debug!("Digest auth header: {}", auth_value);

        // Step 6: Make the actual request with digest auth
        info!("Sending firmware multipart request to {}", url);
        let final_response = self.client
            .post(url)
            .header(AUTHORIZATION, auth_value)
            .multipart(form)
            .timeout(Duration::from_secs(300)) // Increase timeout for large firmware files
            .send().await
            .map_err(|e| {
                error!("Failed to send firmware upload request: {}", e);
                CameraError::Request(e)
            })?;

        Ok(final_response)
    }
    fn calculate_broadcast_address(
        &self,
        ip: &str,
        subnet_mask: &str
    ) -> Result<String, CameraError> {
        let ip_addr: std::net::Ipv4Addr = ip.parse().map_err(|_| CameraError::InvalidNetworkConfig {
            message: format!("Invalid IP address: {}", ip),
        })?;

        let mask_addr: std::net::Ipv4Addr = subnet_mask
            .parse()
            .map_err(|_| CameraError::InvalidNetworkConfig {
                message: format!("Invalid subnet mask: {}", subnet_mask),
            })?;

        let ip_u32 = u32::from(ip_addr);
        let mask_u32 = u32::from(mask_addr);
        let broadcast_u32 = ip_u32 | !mask_u32;
        let broadcast_addr = std::net::Ipv4Addr::from(broadcast_u32);

        Ok(broadcast_addr.to_string())
    }

    /// Create initial administrator user on a factory-new camera
    ///
    /// For AXIS OS version 10, username must be 'root' and role must be Administrator
    /// with PTZ control. This user can only be created once.
    pub async fn create_initial_admin(
        &self,
        temp_ip: Ipv4Addr,
        _new_admin_user: &str,
        new_admin_pass: &str,
        protocol: Protocol
    ) -> Result<String, CameraError> {
        let _admin_user = "root";
        let ip_str = temp_ip.to_string();

        info!("Creating initial admin user 'root' on camera at {}", ip_str);
        warn!("Provided admin username overridden with 'root' as required by Axis OS v10");

        let base_url = format!("{}://{}", protocol.scheme(), temp_ip);
        let endpoint = "/axis-cgi/pwdgrp.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let params = [
            ("action", "add"),
            ("user", "root"),
            ("pwd", new_admin_pass),
            ("grp", "root"),
            ("sgrp", "admin:operator:viewer:ptz"),
        ];

        for attempt in 1..=self.retry_count {
            let response = self.make_request_with_params(&url, &params, None).await?;
            let status = response.status();
            let status_code = status.as_u16();

            if status.is_success() {
                info!("Successfully created admin user 'root' on {}", ip_str);
                return Ok("Initial admin user 'root' created successfully".to_string());
            }

            let response_text = response.text().await.unwrap_or_default();

            if status_code == 401 || status_code == 403 {
                warn!("Authentication required for {} - camera may not be in factory-new state", ip_str);

                match
                    self.verify_admin_credentials(temp_ip, "root", new_admin_pass, protocol).await
                {
                    Ok(_) => {
                        info!("User 'root' already exists and credentials work on {}", ip_str);
                        return Ok(
                            "Admin user 'root' already exists with matching credentials".to_string()
                        );
                    }
                    Err(_) => {
                        return Err(CameraError::NotFactoryState {
                            message: "Camera is not in factory-new state and provided credentials invalid".to_string(),
                        });
                    }
                }
            }

            let error_message = format!(
                "Failed to create user (HTTP {}): {}",
                status_code,
                response_text
            );
            error!("{}", error_message);

            if attempt < self.retry_count {
                info!(
                    "Retrying in {} seconds... (attempt {}/{})",
                    self.retry_delay.as_secs(),
                    attempt,
                    self.retry_count
                );
                tokio::time::sleep(self.retry_delay).await;
            } else {
                return Err(CameraError::HttpError { ip: ip_str, status: status_code });
            }
        }

        unreachable!("Should have returned or errored before this point");
    }

    /// Set final static IP configuration on camera with MAC-based IP tracking
    pub async fn set_final_static_ip_with_mac_tracking(
        &self,
        current_camera_ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        ip_config: &IpConfig,
        protocol: Protocol,
        camera_mac: &str,
        dhcp_leases_provider: impl Fn() -> Vec<crate::dchp_manager::DhcpLease>
    ) -> Result<(String, Option<Ipv4Addr>), CameraError> {
        // Set the static IP configuration
        let result = self.set_final_static_ip(
            current_camera_ip,
            admin_user, 
            admin_pass,
            ip_config,
            protocol
        ).await;
        
        match result {
            Ok(message) => {
                info!("Static IP configuration sent, checking if camera moved to new DHCP IP...");
                
                // Wait a moment for the camera to potentially restart and get new DHCP lease
                tokio::time::sleep(Duration::from_secs(3)).await;
                
                // Get the most current DHCP leases and look up camera's new IP by MAC address
                let current_dhcp_leases = dhcp_leases_provider();
                if let Some(new_ip) = Self::find_camera_ip_by_mac_in_dhcp_leases(camera_mac, &current_dhcp_leases) {
                    if new_ip != current_camera_ip {
                        info!("Camera with MAC {} moved from {} to new DHCP IP: {}", camera_mac, current_camera_ip, new_ip);
                        
                        // Quickly verify the camera is accessible at the new IP
                        match self.verify_admin_credentials(new_ip, admin_user, admin_pass, protocol).await {
                            Ok(_) => {
                                info!("Verified camera is accessible at new IP: {}", new_ip);
                                return Ok((message, Some(new_ip)));
                            }
                            Err(e) => {
                                warn!("Camera found in DHCP at {} but not accessible: {}", new_ip, e);
                            }
                        }
                    } else {
                        debug!("Camera MAC {} still at same IP: {}", camera_mac, current_camera_ip);
                    }
                } else {
                    debug!("Camera MAC {} not found in current DHCP leases after configuration", camera_mac);
                }
                
                Ok((message, None))
            }
            Err(e) => Err(e)
        }
    }
    
    /// Set final static IP configuration on camera
    pub async fn set_final_static_ip(
        &self,
        current_camera_ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        ip_config: &IpConfig,
        protocol: Protocol
    ) -> Result<String, CameraError> {
        let current_ip_str = current_camera_ip.to_string();
        let final_ip = &ip_config.ip;
        let subnet = &ip_config.subnet;
        let gateway = &ip_config.gateway;

        if final_ip.is_empty() {
            return Err(CameraError::InvalidNetworkConfig {
                message: "No IP address provided in configuration".to_string(),
            });
        }

        info!("Setting static IP {} on camera currently at {}", final_ip, current_ip_str);

        let base_url = format!("{}://{}", protocol.scheme(), current_camera_ip);

        match
            self.set_ip_using_json_api(
                &base_url,
                admin_user,
                admin_pass,
                final_ip,
                subnet,
                gateway
            ).await
        {
            Ok(message) => Ok(message),
            Err(e) => {
                info!("JSON API failed, trying legacy param.cgi API: {}", e);
                self.set_ip_using_param_cgi(
                    &base_url,
                    admin_user,
                    admin_pass,
                    final_ip,
                    subnet,
                    gateway
                ).await
            }
        }
    }

    /// Upgrade firmware using model-to-firmware mapping for automatic model detection
    pub async fn upgrade_firmware_with_model_mapping(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        firmware_mapping: &ModelFirmwareMapping,
        protocol: Protocol,
        options: Option<FirmwareUpgradeOptions>
    ) -> Result<String, CameraError> {
        let ip_str = ip.to_string();

        info!("Retrieving device info for camera at {} to determine model", ip_str);
        let device_info = self.get_device_info(ip, admin_user, admin_pass, protocol).await?;

        let model_name = device_info
            .get("ProdNbr")
            .and_then(|v| v.as_str())
            .or_else(|| device_info.get("ProductName").and_then(|v| v.as_str()))
            .or_else(|| device_info.get("Brand").and_then(|v| v.as_str()))
            .unwrap_or("Unknown Model");

        info!("Detected camera model: '{}' for camera at {}", model_name, ip_str);

        let firmware_file = firmware_mapping
            .find_firmware_for_model(model_name)
            .ok_or_else(|| CameraError::ModelIncompatible {
                camera_model: model_name.to_string(),
                compatible_models: firmware_mapping.firmware_files
                    .iter()
                    .map(|fw| fw.compatible_models.join(", "))
                    .collect::<Vec<_>>()
                    .join("; "),
            })?;

        info!(
            "Found compatible firmware '{}' for model '{}' at {}",
            firmware_file.filename,
            model_name,
            ip_str
        );

        let firmware_data = if let Some(data) = &firmware_file.data {
            data.clone()
        } else if let Some(file_path) = &firmware_file.file_path {
            match std::fs::read(file_path) {
                Ok(data) => Arc::new(data),
                Err(e) => {
                    return Err(CameraError::FirmwareUpgradeFailed {
                        message: format!("Failed to load firmware file: {}", e),
                    });
                }
            }
        } else {
            return Err(CameraError::FirmwareUpgradeFailed {
                message: "No firmware data or file path available".to_string(),
            });
        };

        self.upgrade_firmware_with_data(
            ip,
            admin_user,
            admin_pass,
            firmware_data,
            firmware_file.filename.clone(),
            protocol,
            options
        ).await
    }

    /// Upgrade firmware using pre-loaded firmware data (more efficient for multiple cameras)
    pub async fn upgrade_firmware_with_data(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        firmware_data: Arc<Vec<u8>>,
        firmware_filename: String,
        protocol: Protocol,
        options: Option<FirmwareUpgradeOptions>
    ) -> Result<String, CameraError> {
        let ip_str = ip.to_string();
        let opts = options.unwrap_or_default();

        info!(
            "Starting firmware upgrade for camera at {} with pre-loaded data ({} bytes)",
            ip_str,
            firmware_data.len()
        );

        if firmware_data.is_empty() {
            return Err(CameraError::FirmwareUpgradeFailed {
                message: "Firmware data is empty".to_string(),
            });
        }

        if !firmware_filename.ends_with(".bin") {
            warn!("Firmware filename does not end with .bin: {}", firmware_filename);
        }

        let mut json_payload_value =
            json!({
            "apiVersion": "1.0",
            "context": "firmware_upgrade_tool",
            "method": "upgrade"
        });

        if let Some(timeout) = opts.auto_rollback_timeout {
            json_payload_value["params"] =
                json!({
                "autoRollback": timeout.to_string()
            });
            info!("Firmware upgrade with auto-rollback timeout set to {} seconds", timeout);
        } else {
            info!(
                "Firmware upgrade without auto-rollback timeout (will commit automatically upon boot)"
            );
        }

        let json_payload_str = serde_json::to_string(&json_payload_value)?;
        info!("JSON Payload for firmware upgrade: {}", json_payload_str);

        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        for attempt in 1..=self.retry_count {
            let upload_start = std::time::Instant::now();
            info!("🚀 Starting firmware upload to {} (Attempt {}/{}, {} bytes)", ip_str, attempt, self.retry_count, firmware_data.len());

            let json_part = multipart::Part
                ::text(json_payload_str.clone())
                .mime_str("application/json")
                .map_err(CameraError::Request)?;

            let file_part = multipart::Part
                ::bytes((*firmware_data).clone())
                .file_name(firmware_filename.clone())
                .mime_str("application/octet-stream")
                .map_err(CameraError::Request)?;

            let form = multipart::Form::new().part("payload", json_part).part("file", file_part);

            let response = match
                self.client
                    .post(url.clone())
                    .basic_auth(admin_user, Some(admin_pass))
                    .multipart(form)
                    .timeout(Duration::from_secs(300))
                    .send().await
            {
                Ok(resp) if resp.status().is_success() => resp,
                Ok(resp) if resp.status() == 401 => {
                    info!("Basic auth failed, trying digest auth for firmware upload");
                    let json_part = multipart::Part
                        ::text(json_payload_str.clone())
                        .mime_str("application/json")
                        .map_err(CameraError::Request)?;

                    let file_part = multipart::Part
                        ::bytes((*firmware_data).clone())
                        .file_name(firmware_filename.clone())
                        .mime_str("application/octet-stream")
                        .map_err(CameraError::Request)?;

                    let digest_form = multipart::Form
                        ::new()
                        .part("payload", json_part)
                        .part("file", file_part);

                    self.send_multipart_with_digest_auth(
                        url.clone(),
                        digest_form,
                        admin_user,
                        admin_pass
                    ).await?
                }
                Ok(resp) => resp,
                Err(e) => {
                    error!("Failed to send firmware upload request: {}", e);
                    return Err(CameraError::Request(e));
                }
            };

            let status = response.status();
            let status_code = status.as_u16();

            if status.is_success() {
                let upload_duration = upload_start.elapsed();
                let response_text = response.text().await.map_err(CameraError::Request)?;
                info!("📤 Firmware upload completed in {:.1}s (HTTP {}): {}", upload_duration.as_secs_f32(), status_code, response_text);

                match serde_json::from_str::<Value>(&response_text) {
                    Ok(json_response) => {
                        if let Some(error) = json_response.get("error") {
                            let error_code = error
                                .get("code")
                                .and_then(|c| c.as_i64())
                                .unwrap_or(-1);
                            let error_msg = error
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Unknown firmware upgrade error");

                            error!(
                                "Firmware upgrade API error (code {}): {}",
                                error_code,
                                error_msg
                            );
                            return Err(CameraError::FirmwareUpgradeFailed {
                                message: format!("API Error {}: {}", error_code, error_msg),
                            });
                        }

                        let new_version = if let Some(data) = json_response.get("data") {
                            let version = data
                                .get("firmwareVersion")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Unknown Version");

                            info!("Firmware upload successful. Camera reported new version: {}", version);
                            version.to_string()
                        } else {
                            info!(
                                "Firmware upload appears successful (no version info returned yet)"
                            );
                            "Unknown Version".to_string()
                        };

                        info!("Camera will reboot now. Waiting for it to come back online...");
                        tokio::time::sleep(Duration::from_secs(5)).await;

                        match
                            crate::network_utilities::wait_for_camera_online(
                                ip,
                                admin_user,
                                admin_pass,
                                crate::network_utilities::Protocol::Http,
                                Duration::from_secs(100), // Increased to 3 minutes for firmware completion
                                Duration::from_millis(500) // Check every 500ms for much more responsive detection
                            ).await
                        {
                            Ok((true, elapsed_time)) => {
                                info!(
                                    "Camera at {} is online again after firmware upgrade (took {:.1}s)",
                                    ip_str,
                                    elapsed_time.as_secs_f32()
                                );
                            }
                            Ok((false, _)) => {
                                warn!("Camera at {} authentication timeout, but checking basic connectivity...", ip_str);

                                if
                                    let Ok(true) = crate::network_utilities::ping_host(
                                        ip,
                                        1,
                                        Duration::from_secs(3)
                                    ).await
                                {
                                    info!("Camera at {} is responding to ping after firmware upgrade - considering success", ip_str);
                                } else {
                                    return Err(CameraError::FirmwareUpgradeFailed {
                                        message: "Camera did not reboot and come online after upgrade.".to_string(),
                                    });
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Error waiting for camera at {} after upgrade: {}",
                                    ip_str,
                                    e
                                );
                                if
                                    let Ok(true) = crate::network_utilities::ping_host(
                                        ip,
                                        1,
                                        Duration::from_secs(3)
                                    ).await
                                {
                                    info!("Camera at {} is responding to ping after firmware upgrade - considering success", ip_str);
                                } else {
                                    return Err(CameraError::FirmwareUpgradeFailed {
                                        message: format!("Error during post-upgrade reboot wait: {}", e),
                                    });
                                }
                            }
                        }

                        if opts.commit_automatically && opts.auto_rollback_timeout.is_some() {
                            info!("Attempting to commit firmware upgrade for {}", ip_str);
                            match
                                self.commit_firmware_upgrade(
                                    ip,
                                    admin_user,
                                    admin_pass,
                                    protocol
                                ).await
                            {
                                Ok(_) =>
                                    info!("Firmware upgrade committed successfully for {}", ip_str),
                                Err(e) =>
                                    warn!(
                                        "Failed to commit firmware upgrade for {}: {}",
                                        ip_str,
                                        e
                                    ),
                            }
                        }

                        return Ok(
                            format!("Firmware upgrade completed. New version: {}", new_version)
                        );
                    }
                    Err(e) => {
                        debug!(
                            "Failed to parse JSON response: {}. Raw response: {}",
                            e,
                            response_text
                        );
                        warn!(
                            "Firmware upgrade appears successful but response parsing failed. Assuming success."
                        );
                        return Ok(
                            "Firmware upgrade initiated successfully (response parsing error)".to_string()
                        );
                    }
                }
            } else {
                let error_text = response.text().await.unwrap_or_default();
                error!("Firmware upgrade failed (HTTP {}): {}", status_code, error_text);

                if attempt < self.retry_count {
                    info!("Retrying firmware upgrade in {} seconds...", self.retry_delay.as_secs());
                    tokio::time::sleep(self.retry_delay).await;
                } else {
                    return Err(CameraError::FirmwareUpgradeFailed {
                        message: format!("HTTP {}: {}", status_code, error_text),
                    });
                }
            }
        }
        unreachable!("Should have returned or errored before this point in firmware upgrade.");
    }

    pub async fn get_device_info(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        protocol: Protocol
    ) -> Result<serde_json::Value, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/basicdeviceinfo.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload =
            json!({
        "apiVersion": "1.0",
        "context": "get_device_info_tool",
        "method": "getAllProperties" // Or "getProperties" with specific list
    });

        let response = self.client
            .post(url)
            .json(&json_payload)
            .send_with_digest_auth(admin_user, admin_pass).await?; // Use your manual digest auth or diqwest if applicable

        let status = response.status();
        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            let json_response: Value = serde_json::from_str(&response_text)?;

            if let Some(error) = json_response.get("error") {
                let error_msg = error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                return Err(CameraError::FirmwareUpgradeFailed { // You might want a more specific error type here
                    message: format!("Device info API error: {}", error_msg),
                });
            }

            Ok(json_response["data"]["propertyList"].clone())
        } else {
            Err(CameraError::HttpError {
                ip: ip.to_string(),
                status: status.as_u16(),
            })
        }
    }

    /// Get network interface information including MAC address
    pub async fn get_network_interface_info(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        protocol: Protocol
    ) -> Result<Option<String>, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/network_settings.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload =
            json!({
            "apiVersion": "1.0",
            "context": "get_network_info",
            "method": "getNetworkInterfaces"
        });

        let response = self.client
            .post(url)
            .json(&json_payload)
            .send_with_digest_auth(admin_user, admin_pass).await?;

        let status = response.status();
        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            debug!("Network interface response: {}", response_text);

            match serde_json::from_str::<Value>(&response_text) {
                Ok(json_response) => {
                    if let Some(error) = json_response.get("error") {
                        let error_msg = error
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Unknown error");
                        warn!("Network interface API error: {}", error_msg);
                        return Ok(None);
                    }

                    if let Some(data) = json_response.get("data") {
                        if
                            let Some(interfaces) = data
                                .get("networkInterfaces")
                                .and_then(|n| n.as_array())
                        {
                            for interface in interfaces {
                                if
                                    let Some(mac) = interface
                                        .get("macAddress")
                                        .and_then(|m| m.as_str())
                                {
                                    info!("Found MAC address via VAPIX: {}", mac);
                                    return Ok(Some(mac.to_string()));
                                }
                            }
                        }
                    }
                    Ok(None)
                }
                Err(e) => {
                    debug!("Failed to parse network interface response: {}", e);
                    Ok(None)
                }
            }
        } else {
            debug!("Network interface request failed with status: {}", status);
            Ok(None)
        }
    }

    /// Commit firmware upgrade (prevents auto-rollback)
    pub async fn commit_firmware_upgrade(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        protocol: Protocol
    ) -> Result<String, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload =
            json!({
            "apiVersion": "1.0",
            "context": "commit_upgrade_tool",
            "method": "commit"
        });

        let response = self.client
            .post(url)
            .json(&json_payload)
            .send_with_digest_auth(admin_user, admin_pass).await?;

        let status = response.status();
        let status_code = status.as_u16();

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            let json_response: Value = serde_json::from_str(&response_text)?;

            if let Some(error) = json_response.get("error") {
                let error_msg = error
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                return Err(CameraError::FirmwareUpgradeFailed {
                    message: format!("Firmware commit API error: {}", error_msg),
                });
            }

            Ok("Firmware upgrade committed successfully".to_string())
        } else {
            Err(CameraError::HttpError {
                ip: ip.to_string(),
                status: status_code,
            })
        }
    }

    /// Make HTTP request with form parameters
    async fn make_request_with_params(
        &self,
        url: &Url,
        params: &[(&str, &str)],
        auth: Option<(&str, &str)>
    ) -> Result<Response, CameraError> {
        let mut request = self.client.get(url.clone());

        if let Some((username, password)) = auth {
            request = request.basic_auth(username, Some(password));
        }

        for (key, value) in params {
            request = request.query(&[(key, value)]);
        }

        request.send().await.map_err(CameraError::Request)
    }

    /// Verify admin credentials work (made public for IP scanning)
    pub async fn verify_admin_credentials(
        &self,
        ip: Ipv4Addr,
        username: &str,
        password: &str,
        protocol: Protocol
    ) -> Result<(), CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/usergroup.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let response = self.client
            .get(url)
            .basic_auth(username, Some(password))
            .timeout(Duration::from_secs(3)) // Shorter timeout for scanning
            .send().await
            .map_err(CameraError::Request)?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(CameraError::AuthFailed {
                ip: ip.to_string(),
            })
        }
    }

    /// Set static IP using modern JSON API
    async fn set_ip_using_json_api(
        &self,
        base_url: &str,
        admin_user: &str,
        admin_pass: &str,
        final_ip: &str,
        subnet: &str,
        gateway: &str
    ) -> Result<String, CameraError> {
        let endpoint = "/axis-cgi/network_settings.cgi";
        let url = Url::parse(base_url)?.join(endpoint)?;

        let prefix_length = self.subnet_mask_to_prefix_length(subnet)?;
        let broadcast = self.calculate_broadcast_address(final_ip, subnet).ok();

        let mut payload =
            json!({
        "apiVersion": "1.0",
        "context": "AxisAutoConfig",
        "method": "setIPv4AddressConfiguration",
        "params": {
            "deviceName": "eth0",
            "configurationMode": "static",
            "staticDefaultRouter": gateway,
            "staticAddressConfigurations": [{
                "address": final_ip,
                "prefixLength": prefix_length
            }]
        }
    });

        if let Some(broadcast_ip) = broadcast {
            payload["params"]["staticAddressConfigurations"][0]["broadcast"] = json!(broadcast_ip);
        }

        info!("Sending network configuration payload: {}", serde_json::to_string_pretty(&payload)?);

        let response = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send_with_digest_auth(admin_user, admin_pass).await?;

        let status = response.status();
        info!("Final response status after digest auth: {}", status);

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            info!("Network settings response: {}", response_text);

            if let Ok(json_response) = serde_json::from_str::<Value>(&response_text) {
                if let Some(error) = json_response.get("error") {
                    let error_msg = error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown API error");
                    return Err(CameraError::InvalidNetworkConfig {
                        message: format!("API error: {}", error_msg),
                    });
                }
            }
            Ok(format!("Static IP successfully set to {}", final_ip))
        } else {
            let error_text = response.text().await.unwrap_or_default();
            error!("Request failed with status {} and body: {}", status, error_text);
            Err(CameraError::HttpError {
                ip: final_ip.to_string(),
                status: status.as_u16(),
            })
        }
    }

    /// Set static IP using legacy param.cgi API
    async fn set_ip_using_param_cgi(
        &self,
        base_url: &str,
        admin_user: &str,
        admin_pass: &str,
        final_ip: &str,
        subnet: &str,
        gateway: &str
    ) -> Result<String, CameraError> {
        let endpoint = "/axis-cgi/param.cgi";
        let url = Url::parse(base_url)?.join(endpoint)?;

        let params = [
            ("action", "update"),
            ("Network.InterfaceName", "eth0"),
            ("Network.BootProto", "static"),
            ("Network.IPAddress", final_ip),
            ("Network.SubnetMask", subnet),
            ("Network.DefaultRouter", gateway),
        ];

        info!(
            "Using legacy param.cgi API to set static IP: {}, subnet: {}, gateway: {}",
            final_ip,
            subnet,
            gateway
        );

        let response = self.make_request_with_params(
            &url,
            &params,
            Some((admin_user, admin_pass))
        ).await?;

        let status = response.status();
        let status_code = status.as_u16();

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;

            if response_text.contains("Error") {
                return Err(CameraError::InvalidNetworkConfig {
                    message: format!("API error: {}", response_text),
                });
            }

            info!("Successfully set static IP {} using param.cgi API", final_ip);
            Ok(format!("Static IP successfully set to {}", final_ip))
        } else {
            Err(CameraError::HttpError {
                ip: final_ip.to_string(),
                status: status_code,
            })
        }
    }

    /// Convert subnet mask to prefix length
    fn subnet_mask_to_prefix_length(&self, subnet_mask: &str) -> Result<u8, CameraError> {
        use std::net::Ipv4Addr;

        let mask_addr = subnet_mask
            .parse::<Ipv4Addr>()
            .map_err(|_| CameraError::InvalidNetworkConfig {
                message: format!("Invalid subnet mask format: {}", subnet_mask),
            })?;

        let mask_bits = u32::from(mask_addr);
        let prefix_len = mask_bits.leading_ones() as u8;

        let expected_mask = (0xffffffff_u32).checked_shl(32 - (prefix_len as u32)).unwrap_or(0);

        if mask_bits != expected_mask {
            return Err(CameraError::InvalidNetworkConfig {
                message: format!("Invalid subnet mask: {}", subnet_mask),
            });
        }

        Ok(prefix_len)
    }
}

impl Default for CameraOperations {
    fn default() -> Self {
        Self::new().expect("Failed to create default CameraOperations")
    }
}