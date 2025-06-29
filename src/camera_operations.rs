//! Axis Camera Unified Setup & Configuration Tool
//! Camera operations module for VAPIX and ONVIF interactions

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use reqwest::{multipart, Client, ClientBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use url::Url;

/// Custom error types for camera operations
#[derive(Error, Debug)]
pub enum CameraError {
    #[error("Connection timeout for {ip}")]
    Timeout { ip: String },
    
    #[error("Authentication failed for {ip}")]
    AuthFailed { ip: String },
    
    #[error("HTTP error for {ip}: {status}")]
    HttpError { ip: String, status: u16 },
    
    #[error("Invalid IP address: {ip}")]
    InvalidIp { ip: String },
    
    #[error("User already exists: {username}")]
    UserExists { username: String },
    
    #[error("Camera not in factory state: {message}")]
    NotFactoryState { message: String },
    
    #[error("Parameter not supported: {parameter}")]
    ParameterNotSupported { parameter: String },
    
    #[error("Firmware upgrade failed: {message}")]
    FirmwareUpgradeFailed { message: String },
    
    #[error("Invalid network configuration: {message}")]
    InvalidNetworkConfig { message: String },
    
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
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

/// VAPIX and ONVIF operations for Axis cameras
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

    /// Create a new instance with custom settings
    pub fn with_settings(
        timeout: Duration,
        retry_count: u32,
        retry_delay: Duration,
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
        protocol: Protocol,
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
                match self.verify_admin_credentials(temp_ip, "root", new_admin_pass, protocol).await {
                    Ok(_) => {
                        info!("User 'root' already exists and credentials work on {}", ip_str);
                        return Ok("Admin user 'root' already exists with matching credentials".to_string());
                    }
                    Err(_) => {
                        return Err(CameraError::NotFactoryState {
                            message: "Camera is not in factory-new state and provided credentials invalid".to_string(),
                        });
                    }
                }
            }

            let error_message = format!("Failed to create user (HTTP {}): {}", status_code, response_text);
            error!("{}", error_message);

            if attempt < self.retry_count {
                info!("Retrying in {} seconds... (attempt {}/{})", 
                      self.retry_delay.as_secs(), attempt, self.retry_count);
                tokio::time::sleep(self.retry_delay).await;
            } else {
                return Err(CameraError::HttpError { ip: ip_str, status: status_code });
            }
        }

        unreachable!("Should have returned or errored before this point");
    }

    /// Create ONVIF user on camera
    ///
    /// This uses the VAPIX API to create a new ONVIF user with proper privileges
    pub async fn create_onvif_user(
        &self,
        temp_ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        onvif_user: &str,
        onvif_pass: &str,
        protocol: Protocol,
    ) -> Result<String, CameraError> {
        let ip_str = temp_ip.to_string();
        info!("Creating ONVIF user '{}' on camera at {}", onvif_user, ip_str);

        let base_url = format!("{}://{}", protocol.scheme(), temp_ip);
        let endpoint = "/axis-cgi/pwdgrp.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        // Parameters for the request - correct format for Axis OS 10.12
        let params = [
            ("action", "add"),
            ("user", onvif_user),
            ("pwd", onvif_pass),
            ("grp", "users"),
            ("sgrp", "onvif:admin:operator:viewer"), // ONVIF with proper privileges
            ("comment", "ONVIF user created by Axis Camera Unified Setup Tool"),
        ];

        for attempt in 1..=self.retry_count {
            let response = self.make_request_with_params(&url, &params, Some((admin_user, admin_pass))).await?;
            let status = response.status();
            let status_code = status.as_u16();
            
            if status.is_success() {
                let response_text = response.text().await.unwrap_or_default();
                
                // Handle specific success/warning cases
                if response_text.to_lowercase().contains("account already exist") {
                    warn!("ONVIF user '{}' already exists on {}", onvif_user, ip_str);
                    
                    // Try to update existing user with correct groups
                    match self.update_onvif_user(temp_ip, admin_user, admin_pass, onvif_user, onvif_pass, protocol).await {
                        Ok(msg) => return Ok(msg),
                        Err(_) => return Ok(format!("ONVIF user '{}' already exists, but could not update", onvif_user)),
                    }
                }

                info!("Successfully created ONVIF user '{}' on {} via VAPIX", onvif_user, ip_str);
                return Ok(format!("ONVIF user '{}' created successfully", onvif_user));
            }

            let response_text = response.text().await.unwrap_or_default();
            let error_message = format!("Failed to create ONVIF user (HTTP {}): {}", status_code, response_text);
            error!("{}", error_message);

            if attempt < self.retry_count {
                info!("Retrying in {} seconds... (attempt {}/{})", 
                      self.retry_delay.as_secs(), attempt, self.retry_count);
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
        temp_ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        ip_config: &IpConfig,
        protocol: Protocol,
    ) -> Result<String, CameraError> {
        let ip_str = temp_ip.to_string();
        let final_ip = &ip_config.ip;
        let subnet = &ip_config.subnet;
        let gateway = &ip_config.gateway;

        if final_ip.is_empty() {
            return Err(CameraError::InvalidNetworkConfig {
                message: "No IP address provided in configuration".to_string(),
            });
        }

        info!("Setting static IP {} on camera at {}", final_ip, ip_str);

        let base_url = format!("{}://{}", protocol.scheme(), temp_ip);

        // Try modern JSON API first, then fall back to legacy param.cgi API
        match self.set_ip_using_json_api(&base_url, admin_user, admin_pass, final_ip, subnet, gateway).await {
            Ok(message) => Ok(message),
            Err(e) => {
                info!("JSON API failed, trying legacy param.cgi API: {}", e);
                self.set_ip_using_param_cgi(&base_url, admin_user, admin_pass, final_ip, subnet, gateway).await
            }
        }
    }

    /// Upgrade camera firmware
    pub async fn upgrade_firmware(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        firmware_path: &Path,
        protocol: Protocol,
        options: Option<FirmwareUpgradeOptions>,
    ) -> Result<String, CameraError> {
        let ip_str = ip.to_string();
        let opts = options.unwrap_or_default();
        
        info!("Starting firmware upgrade for camera at {}", ip_str);
        
        // Step 1: Read firmware file once
        let mut firmware_data = Vec::new();
        let mut file = File::open(firmware_path).await
            .with_context(|| format!("Failed to open firmware file: {:?}", firmware_path))
            .map_err(|e| CameraError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, e)))?;
        
        file.read_to_end(&mut firmware_data).await
            .with_context(|| "Failed to read firmware file")
            .map_err(|e| CameraError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        info!("Read {} bytes from firmware file", firmware_data.len());

        // Step 2: Prepare the base JSON payload string (needed for each retry)
        let mut json_payload_value = json!({
            "apiVersion": "1.3",
            "context": "firmware_upgrade",
            "method": "upgrade"
        });

        // Add auto-rollback timeout if specified
        if let Some(timeout) = opts.auto_rollback_timeout {
            json_payload_value["params"] = json!({
                "autoRollback": timeout.to_string()
            });
        }
        let json_payload_str = serde_json::to_string(&json_payload_value)?;


        // Step 3: Upload firmware
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        info!("Uploading firmware to {}", ip_str);
        
        for attempt in 1..=self.retry_count {
            // Recreate multipart form for each attempt, cloning data as needed
            let firmware_part_inner = multipart::Part::bytes(firmware_data.clone()) // Clone Vec<u8>
                .file_name("firmware.bin")
                .mime_str("application/octet-stream")
                .map_err(CameraError::Request)?;

            let json_part_inner = multipart::Part::text(json_payload_str.clone()) // Clone String
                .mime_str("application/json")
                .map_err(CameraError::Request)?;

            let form = multipart::Form::new()
                .part("payload", json_part_inner)
                .part("file", firmware_part_inner);

            let response = self.client
                .post(url.clone())
                .basic_auth(admin_user, Some(admin_pass))
                .multipart(form) // Use the newly created form
                .send()
                .await
                .map_err(CameraError::Request)?;

            let status = response.status();
            let status_code = status.as_u16();

            if status.is_success() {
                let response_text = response.text().await.map_err(CameraError::Request)?;
                
                // Parse response to get firmware version
                match serde_json::from_str::<Value>(&response_text) {
                    Ok(json_response) => {
                        if let Some(error) = json_response.get("error") {
                            let error_msg = error.get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Unknown firmware upgrade error");
                            return Err(CameraError::FirmwareUpgradeFailed {
                                message: error_msg.to_string(),
                            });
                        }

                        if let Some(data) = json_response.get("data") {
                            if let Some(version) = data.get("firmwareVersion").and_then(|v| v.as_str()) {
                                info!("Firmware upload successful. New version: {}", version);
                                
                                // Step 4: Wait for reboot and verify
                                info!("Camera will reboot now. Waiting for it to come back online...");
                                tokio::time::sleep(Duration::from_secs(10)).await; // Give it time to start rebooting
                                
                                // Step 5: Optionally commit the upgrade
                                if opts.commit_automatically && opts.auto_rollback_timeout.is_some() {
                                    // Wait a bit more for the camera to fully boot
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                    
                                    match self.commit_firmware_upgrade(ip, admin_user, admin_pass, protocol).await {
                                        Ok(_) => info!("Firmware upgrade committed successfully"),
                                        Err(e) => warn!("Failed to commit firmware upgrade: {}", e),
                                    }
                                }

                                return Ok(format!("Firmware upgrade completed. New version: {}", version));
                            }
                        }

                        info!("Firmware upgrade initiated successfully");
                        return Ok("Firmware upgrade initiated successfully".to_string());
                    }
                    Err(e) => {
                        debug!("Failed to parse JSON response: {}. Raw response: {}", e, response_text);
                        // If we can't parse JSON but got 200, assume success
                        info!("Firmware upgrade appears successful (non-JSON response)");
                        return Ok("Firmware upgrade completed".to_string());
                    }
                }
            } else {
                let _error_text = response.text().await.unwrap_or_default(); // Store text before status
                error!("Firmware upgrade failed (HTTP {}): {}", status_code, _error_text);

                if attempt < self.retry_count {
                    info!("Retrying firmware upgrade in {} seconds... (attempt {}/{})", 
                          self.retry_delay.as_secs(), attempt, self.retry_count);
                    tokio::time::sleep(self.retry_delay).await;
                } else {
                    return Err(CameraError::FirmwareUpgradeFailed {
                        message: format!("HTTP {}: {}", status_code, _error_text),
                    });
                }
            }
        }

        unreachable!("Should have returned or errored before this point");
    }

    /// Get current firmware status
    pub async fn get_firmware_status(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        protocol: Protocol,
    ) -> Result<FirmwareStatus, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload = json!({
            "apiVersion": "1.3",
            "context": "status_check",
            "method": "status"
        });

        let response = self.client
            .post(url)
            .basic_auth(admin_user, Some(admin_pass))
            .json(&json_payload)
            .send()
            .await
            .map_err(CameraError::Request)?;

        let status = response.status();
        let status_code = status.as_u16();

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            let json_response: Value = serde_json::from_str(&response_text)?;

            if let Some(error) = json_response.get("error") {
                let error_msg = error.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                return Err(CameraError::FirmwareUpgradeFailed {
                    message: error_msg.to_string(),
                });
            }

            if let Some(data) = json_response.get("data") {
                let status = FirmwareStatus {
                    active_firmware_version: data.get("activeFirmwareVersion")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    inactive_firmware_version: data.get("inactiveFirmwareVersion")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    is_committed: data.get("isCommited") // Note: Axis API uses "isCommited" (typo)
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    time_to_rollback: data.get("timeToRollback")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    last_upgrade_at: data.get("lastUpgradeAt")
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

    /// Commit firmware upgrade (prevents auto-rollback)
    pub async fn commit_firmware_upgrade(
        &self,
        ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        protocol: Protocol,
    ) -> Result<String, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload = json!({
            "apiVersion": "1.3",
            "context": "commit_upgrade",
            "method": "commit"
        });

        let response = self.client
            .post(url)
            .basic_auth(admin_user, Some(admin_pass))
            .json(&json_payload)
            .send()
            .await
            .map_err(CameraError::Request)?;

        let status = response.status();
        let status_code = status.as_u16();

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            let json_response: Value = serde_json::from_str(&response_text)?;

            if let Some(error) = json_response.get("error") {
                let error_msg = error.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                return Err(CameraError::FirmwareUpgradeFailed {
                    message: error_msg.to_string(),
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
        protocol: Protocol,
    ) -> Result<String, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/firmwaremanagement.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let json_payload = json!({
            "apiVersion": "1.3",
            "context": "rollback",
            "method": "rollback"
        });

        let response = self.client
            .post(url)
            .basic_auth(admin_user, Some(admin_pass))
            .json(&json_payload)
            .send()
            .await
            .map_err(CameraError::Request)?;

        let status = response.status();
        let status_code = status.as_u16();

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            let json_response: Value = serde_json::from_str(&response_text)?;

            if let Some(error) = json_response.get("error") {
                let error_msg = error.get("message")
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
        auth: Option<(&str, &str)>,
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
        protocol: Protocol,
    ) -> Result<(), CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), ip);
        let endpoint = "/axis-cgi/usergroup.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let response = self.client
            .get(url)
            .basic_auth(username, Some(password))
            .send()
            .await
            .map_err(CameraError::Request)?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(CameraError::AuthFailed {
                ip: ip.to_string(),
            })
        }
    }

    /// Update existing ONVIF user
    async fn update_onvif_user(
        &self,
        temp_ip: Ipv4Addr,
        admin_user: &str,
        admin_pass: &str,
        onvif_user: &str,
        onvif_pass: &str,
        protocol: Protocol,
    ) -> Result<String, CameraError> {
        let base_url = format!("{}://{}", protocol.scheme(), temp_ip);
        let endpoint = "/axis-cgi/pwdgrp.cgi";
        let url = Url::parse(&base_url)?.join(endpoint)?;

        let params = [
            ("action", "update"),
            ("user", onvif_user),
            ("pwd", onvif_pass),
            ("grp", "users"),
            ("sgrp", "onvif:admin:operator:viewer"),
        ];

        let response = self.make_request_with_params(&url, &params, Some((admin_user, admin_pass))).await?;

        if response.status().is_success() {
            Ok(format!("ONVIF user '{}' updated successfully", onvif_user))
        } else {
            Err(CameraError::HttpError {
                ip: temp_ip.to_string(),
                status: response.status().as_u16(),
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
        gateway: &str,
    ) -> Result<String, CameraError> {
        // Convert subnet mask to prefix length
        let prefix_length = self.subnet_mask_to_prefix_length(subnet)?;
        info!("Calculated prefix length {} from subnet mask {}", prefix_length, subnet);

        let endpoint = "/axis-cgi/network_settings.cgi";
        let url = Url::parse(base_url)?.join(endpoint)?;

        let payload = json!({
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

        info!("Sending network configuration payload: {}", serde_json::to_string_pretty(&payload)?);

        let response = self.client
            .post(url)
            .basic_auth(admin_user, Some(admin_pass))
            .json(&payload)
            .send()
            .await
            .map_err(CameraError::Request)?;

        let status = response.status();
        let status_code = status.as_u16();

        info!("Network settings response status: {}", status);

        if status.is_success() {
            let response_text = response.text().await.map_err(CameraError::Request)?;
            info!("Network settings response: {}", response_text);

            // Check for JSON error response
            if let Ok(json_response) = serde_json::from_str::<Value>(&response_text) {
                if let Some(error) = json_response.get("error") {
                    let error_msg = error.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown API error");
                    return Err(CameraError::InvalidNetworkConfig {
                        message: format!("API error: {}", error_msg),
                    });
                }
            }

            Ok(format!("Static IP successfully set to {}", final_ip))
        } else {
            Err(CameraError::HttpError {
                ip: final_ip.to_string(),
                status: status_code,
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
        gateway: &str,
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

        info!("Using legacy param.cgi API to set static IP: {}, subnet: {}, gateway: {}", 
              final_ip, subnet, gateway);

        let response = self.make_request_with_params(&url, &params, Some((admin_user, admin_pass))).await?;

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

        let mask_addr = subnet_mask.parse::<Ipv4Addr>()
            .map_err(|_| CameraError::InvalidNetworkConfig {
                message: format!("Invalid subnet mask format: {}", subnet_mask),
            })?;

        let mask_bits = u32::from(mask_addr);
        let prefix_len = mask_bits.leading_ones() as u8;

        // Validate it's a proper subnet mask (contiguous 1s followed by contiguous 0s)
        let expected_mask = 0xFFFFFFFF_u32.checked_shl(32 - prefix_len as u32).unwrap_or(0);
        
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr; // Needed for `Ipv4Addr::from_str`

    #[tokio::test]
    async fn test_camera_operations_creation() {
        let ops = CameraOperations::new();
        assert!(ops.is_ok());
    }

    #[tokio::test]
    async fn test_camera_operations_with_settings() {
        let ops = CameraOperations::with_settings(
            Duration::from_secs(5),
            2,
            Duration::from_secs(1),
        );
        assert!(ops.is_ok());
        
        let ops = ops.unwrap();
        assert_eq!(ops.timeout, Duration::from_secs(5));
        assert_eq!(ops.retry_count, 2);
        assert_eq!(ops.retry_delay, Duration::from_secs(1));
    }

    #[test]
    fn test_subnet_mask_to_prefix_length() {
        let ops = CameraOperations::new().unwrap();
        
        assert_eq!(ops.subnet_mask_to_prefix_length("255.255.255.0").unwrap(), 24);
        assert_eq!(ops.subnet_mask_to_prefix_length("255.255.0.0").unwrap(), 16);
        assert_eq!(ops.subnet_mask_to_prefix_length("255.0.0.0").unwrap(), 8);
        
        // Invalid subnet mask
        assert!(ops.subnet_mask_to_prefix_length("255.255.255.1").is_err());
        assert!(ops.subnet_mask_to_prefix_length("invalid").is_err());
    }

    #[test]
    fn test_ip_config_serialization() {
        let config = IpConfig {
            ip: "192.168.1.100".to_string(),
            subnet: "255.255.255.0".to_string(),
            gateway: "192.168.1.1".to_string(),
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: IpConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.ip, deserialized.ip);
        assert_eq!(config.subnet, deserialized.subnet);
        assert_eq!(config.gateway, deserialized.gateway);
    }
}

// Usage examples
pub async fn example_usage() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let ops = CameraOperations::new()?;
    let ip = "192.168.1.100".parse::<Ipv4Addr>()?;
    
    // Create initial admin user
    let result = ops.create_initial_admin(
        ip,
        "admin", // Will be ignored, 'root' will be used
        "newpassword",
        Protocol::Http,
    ).await?;
    println!("Admin creation result: {}", result);
    
    // Create ONVIF user
    let result = ops.create_onvif_user(
        ip,
        "root",
        "newpassword",
        "onvif_user",
        "onvif_pass",
        Protocol::Http,
    ).await?;
    println!("ONVIF user creation result: {}", result);
    
    // Set static IP
    let ip_config = IpConfig {
        ip: "192.168.1.101".to_string(),
        subnet: "255.255.255.0".to_string(),
        gateway: "192.168.1.1".to_string(),
    };
    
    let result = ops.set_final_static_ip(
        ip,
        "root",
        "newpassword",
        &ip_config,
        Protocol::Http,
    ).await?;
    println!("Static IP result: {}", result);
    
    // Upgrade firmware
    let firmware_path = Path::new("firmware.bin");
    if firmware_path.exists() {
        let options = FirmwareUpgradeOptions {
            auto_rollback_timeout: Some(60), // 60 seconds
            commit_automatically: true,
        };
        
        let result = ops.upgrade_firmware(
            ip,
            "root",
            "newpassword",
            firmware_path,
            Protocol::Http,
            Some(options),
        ).await?;
        println!("Firmware upgrade result: {}", result);
    }
    
    // Get firmware status
    let status = ops.get_firmware_status(
        ip,
        "root",
        "newpassword",
        Protocol::Http,
    ).await?;
    println!("Firmware status: {:#?}", status);
    
    Ok(())
}