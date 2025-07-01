//! Axis Camera Unified Setup & Configuration Tool
//! Camera operations module for VAPIX

use anyhow::{ Context, Result };
use log::{ debug, error, info, warn };
use reqwest::{ multipart, Client, ClientBuilder, Response };
use serde::{ Deserialize, Serialize };
use serde_json::{ json, Value };
use url::Url;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use diqwest::WithDigestAuth;
use reqwest::header::{ HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE };
use std::collections::HashMap;
use md5;

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
    /// Default timeout for requests (seconds)
    timeout: Duration,
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
            .build()
            .map_err(CameraError::Request)?;

        Ok(Self {
            timeout: Duration::from_secs(10),
            retry_count: 3,
            retry_delay: Duration::from_secs(2),
            client,
        })
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

        let response = if let (Some(qop), Some(nc), Some(cnonce)) = (qop, nc, cnonce) {
            Self::calculate_md5(&format!("{}:{}:{}:{}:{}:{}", ha1, nonce, nc, cnonce, qop, ha2))
        } else {
            Self::calculate_md5(&format!("{}:{}:{}", ha1, nonce, ha2))
        };

        response
    }

    /// Perform digest authentication manually for multipart requests
    /// Perform digest authentication manually for multipart requests
    async fn send_multipart_with_digest_auth(
        &self,
        url: reqwest::Url,
        form: multipart::Form,
        username: &str,
        password: &str
    ) -> Result<Response, CameraError> {
        // Step 1: Make initial GET request to the same endpoint to get digest challenge
        // This is more standard than POST and avoids potential issues
        let initial_response = self.client
            .get(url.clone())
            .send().await
            .map_err(CameraError::Request)?;

        if initial_response.status() != 401 {
            // Try a POST request to trigger digest challenge
            let post_response = self.client
                .post(url.clone())
                .send().await
                .map_err(CameraError::Request)?;

            if post_response.status() != 401 {
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

        debug!("Digest auth header: {}", auth_value);

        // Step 6: Make the actual request with digest auth
        let final_response = self.client
            .post(url)
            .header(AUTHORIZATION, auth_value)
            .multipart(form)
            .timeout(Duration::from_secs(300)) // Increase timeout for large firmware files
            .send().await
            .map_err(CameraError::Request)?;

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

    /// Create a new instance with custom settings
    pub fn with_settings(
        timeout: Duration,
        retry_count: u32,
        retry_delay: Duration
    ) -> Result<Self, CameraError> {
        let client = ClientBuilder::new()
            .timeout(timeout)
            .danger_accept_invalid_certs(true)
            .user_agent("Axis-Camera-Operations/1.0")
            .build()
            .map_err(CameraError::Request)?;

        Ok(Self {
            timeout,
            retry_count,
            retry_delay,
            client,
        })
    }

    /// Create initial administrator user on a factory-new camera
    ///
    /// For AXIS OS version 10, username must be 'root' and role must be Administrator
    /// with PTZ control. This user can only be created once.
    pub async fn create_initial_admin(
        &self,
        temp_ip: Ipv4Addr,
        _new_admin_user: &str, // Ignored, will use 'root'
        new_admin_pass: &str,
        protocol: Protocol
    ) -> Result<String, CameraError> {
        // Force username to be 'root' for OS version 10
        let _admin_user = "root";
        let ip_str = temp_ip.to_string();

        info!("Creating initial admin user 'root' on camera at {}", ip_str);
        warn!("Provided admin username overridden with 'root' as required by Axis OS v10");

        let base_url = format!("{}://{}", protocol.scheme(), temp_ip);
        let endpoint = "/axis-cgi/pwdgrp.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        // Parameters for the request - ensure we use required groups for OS v10
        let params = [
            ("action", "add"),
            ("user", "root"),
            ("pwd", new_admin_pass),
            ("grp", "root"),
            ("sgrp", "admin:operator:viewer:ptz"), // Required security groups for OS v10
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

            // Check for specific error cases
            if status_code == 401 || status_code == 403 {
                // Camera might already have admin accounts set up
                warn!("Authentication required for {} - camera may not be in factory-new state", ip_str);

                // Try to check if user exists by attempting to authenticate
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

    /// Set final static IP configuration on camera
    pub async fn set_final_static_ip(
        &self,
        current_camera_ip: Ipv4Addr, // <-- This should be the CURRENT IP, not target IP
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

        // IMPORTANT: Use the CURRENT camera IP for the base URL, not the target IP
        let base_url = format!("{}://{}", protocol.scheme(), current_camera_ip);

        // Try modern JSON API first, then fall back to legacy param.cgi API
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

    /// This method performs the firmware upgrade by sending a multipart POST request
    /// containing a JSON payload and the binary firmware file.
    // Updated firmware upgrade method
    pub async fn upgrade_firmware(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        firmware_path: &Path,
        protocol: Protocol,
        options: Option<FirmwareUpgradeOptions>
    ) -> Result<String, CameraError> {
        let ip_str = ip.to_string();
        let opts = options.unwrap_or_default();

        info!("Starting firmware upgrade for camera at {}", ip_str);

        // 1. Read firmware file into memory
        let firmware_data = tokio::fs
            ::read(firmware_path).await
            .with_context(|| format!("Failed to read firmware file: {:?}", firmware_path))
            .map_err(|e| CameraError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e)))?;

        info!("Read {} bytes from firmware file: {}", firmware_data.len(), firmware_path.display());

        // 2. Prepare the JSON payload
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
        debug!("JSON Payload for firmware upgrade: {}", json_payload_str);

        // 3. Construct the multipart/form-data request
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        for attempt in 1..=self.retry_count {
            info!("Uploading firmware to {} (Attempt {}/{})", ip_str, attempt, self.retry_count);

            // Create the JSON part - this should be named "payload" for Axis cameras
            let json_part = multipart::Part
                ::text(json_payload_str.clone())
                .mime_str("application/json")
                .map_err(|e| CameraError::Request(e.into()))?;

            // Create the file part - this should be named "file" for Axis cameras
            let filename = firmware_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|s| s.to_owned())
                .unwrap_or_else(|| "firmware.bin".to_string());

            let file_part = multipart::Part
                ::bytes(firmware_data.clone())
                .file_name(filename)
                .mime_str("application/octet-stream")
                .map_err(|e| CameraError::Request(e.into()))?;

            // Create form using the exact field names expected by Axis API
            let form = multipart::Form
                ::new()
                .part("payload", json_part) // Must be named "payload"
                .part("file", file_part); // Must be named "file"

            // Send the request with manual digest auth
            let response = self.send_multipart_with_digest_auth(
                url.clone(),
                form,
                admin_user,
                admin_pass
            ).await?;

            let status = response.status();
            let status_code = status.as_u16();

            if status.is_success() {
                let response_text = response.text().await.map_err(CameraError::Request)?;
                info!("Firmware upload response (HTTP {}): {}", status_code, response_text);

                // Parse response and handle success (keep your existing logic here)
                match serde_json::from_str::<Value>(&response_text) {
                    Ok(json_response) => {
                        if let Some(error) = json_response.get("error") {
                            let error_msg = error
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Unknown firmware upgrade error");
                            return Err(CameraError::FirmwareUpgradeFailed {
                                message: error_msg.to_string(),
                            });
                        }

                        let new_version = json_response
                            .get("data")
                            .and_then(|d| d.get("firmwareVersion"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown Version");

                        info!("Firmware upload successful. Camera reported new version: {}", new_version);

                        // Wait for camera reboot and verification logic...
                        info!("Camera will reboot now. Waiting for it to come back online...");
                        tokio::time::sleep(Duration::from_secs(15)).await;

                        match
                            super::network_utilities::wait_for_camera_online(
                                ip,
                                admin_user,
                                admin_pass,
                                super::network_utilities::Protocol::Http,
                                Duration::from_secs(120),
                                Duration::from_secs(5)
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
                                warn!("Camera at {} did not come back online within timeout after firmware upgrade.", ip_str);
                                return Err(CameraError::FirmwareUpgradeFailed {
                                    message: "Camera did not reboot and come online after upgrade.".to_string(),
                                });
                            }
                            Err(e) => {
                                error!("Error while waiting for camera to come online after upgrade: {}", e);
                                return Err(CameraError::FirmwareUpgradeFailed {
                                    message: format!("Error during post-upgrade reboot wait: {}", e),
                                });
                            }
                        }

                        // Handle firmware commit logic if needed...
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
    /// Get current firmware status
    pub async fn get_firmware_status(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        protocol: Protocol
    ) -> Result<FirmwareStatus, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload =
            json!({
            "apiVersion": "1.0", // Use 1.0 as per docs
            "context": "status_check_tool",
            "method": "status"
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
                return Err(CameraError::FirmwareUpgradeFailed { // Re-use this error type or create a new StatusError
                    message: format!("Firmware status API error: {}", error_msg),
                });
            }

            if let Some(data) = json_response.get("data") {
                let status = FirmwareStatus {
                    active_firmware_version: data
                        .get("activeFirmwareVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    inactive_firmware_version: data
                        .get("inactiveFirmwareVersion")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    is_committed: data
                        .get("isCommited") // Note: Axis API uses "isCommited" (typo)
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    time_to_rollback: data
                        .get("timeToRollback")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    last_upgrade_at: data
                        .get("lastUpgradeAt")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                };

                return Ok(status);
            } else {
                return Err(CameraError::FirmwareUpgradeFailed {
                    message: "Firmware status data not found in response".to_string(),
                });
            }
        }

        Err(CameraError::HttpError {
            ip: ip.to_string(),
            status: status_code,
        })
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
            "apiVersion": "1.0", // Use 1.0 as per docs
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

    /// Rollback to previous firmware version
    pub async fn rollback_firmware(
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
            "apiVersion": "1.3",
            "context": "rollback",
            "method": "rollback"
        });

        let response = self.client
            .post(url)
            .basic_auth(admin_user, Some(admin_pass))
            .json(&json_payload)
            .send().await
            .map_err(CameraError::Request)?;

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
                    message: error_msg.to_string(),
                });
            }

            Ok("Firmware rollback initiated successfully".to_string())
        } else {
            Err(CameraError::HttpError {
                ip: ip.to_string(),
                status: status_code,
            })
        }
    }

    // Private helper methods

    /// Make HTTP request with form parameters
    async fn make_request_with_params(
        &self,
        url: &Url,
        params: &[(&str, &str)],
        auth: Option<(&str, &str)>
    ) -> Result<Response, CameraError> {
        let mut request = self.client.get(url.clone());

        // Add authentication if provided
        if let Some((username, password)) = auth {
            request = request.basic_auth(username, Some(password));
        }

        // Add parameters
        for (key, value) in params {
            request = request.query(&[(key, value)]);
        }

        request.send().await.map_err(CameraError::Request)
    }

    /// Verify admin credentials work
    async fn verify_admin_credentials(
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

        // diqwest handles the entire 401 challenge and response flow automatically!
        let response = self.client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send_with_digest_auth(admin_user, admin_pass).await?; // This is the magic line

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
            return Ok(format!("Static IP successfully set to {}", final_ip));
        } else {
            let error_text = response.text().await.unwrap_or_default();
            error!("Request failed with status {} and body: {}", status, error_text);
            return Err(CameraError::HttpError {
                ip: final_ip.to_string(),
                status: status.as_u16(),
            });
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

        // Validate it's a proper subnet mask (contiguous 1s followed by contiguous 0s)
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
