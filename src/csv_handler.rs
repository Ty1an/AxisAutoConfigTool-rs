//! Axis Camera Unified Setup & Configuration Tool
//! CSV Handler module for reading IP lists and generating reports
//!
//! This module provides functionality for:
//! 1. Validating and reading IP assignment lists from CSV files
//! 2. Generating inventory reports of configured cameras
//! 3. Creating sample CSV templates for users

use anyhow::{ Context, Result };
use chrono::{ DateTime, Utc };
use csv::{ Reader, ReaderBuilder, Writer, WriterBuilder };
use log::{ error, info, warn };
use serde::{ Deserialize, Serialize };
use std::collections::HashSet;
use std::fs::File;
use std::net::Ipv4Addr;
use std::path::Path;
use thiserror::Error;

/// Custom error types for CSV operations
#[derive(Error, Debug)]
pub enum CsvError {
    #[error("File not found: {path}")] FileNotFound {
        path: String,
    },

    #[error("Duplicate IP addresses found: {ips}")] DuplicateIps {
        ips: String,
    },

    #[error("Duplicate MAC addresses found: {macs}")] DuplicateMacs {
        macs: String,
    },

    #[error("Invalid IP address format: {ip}")] InvalidIp {
        ip: String,
    },

    #[error("Invalid MAC address format: {mac}")] InvalidMac {
        mac: String,
    },

    #[error("CSV parsing error: {message}")] ParseError {
        message: String,
    },

    #[error("Validation error: {message}")] ValidationError {
        message: String,
    },

    #[error("Invalid network configuration: {message}")] InvalidNetworkConfig {
        message: String,
    },

    #[error("CSV error: {0}")] Csv(#[from] csv::Error),

    #[error("IO error: {0}")] Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")] Serialization(#[from] serde_json::Error),
}

/// IP configuration for CSV input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAssignment {
    pub ip: String,
    pub mac: Option<String>,
}

/// Camera data structure for inventory reports
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CameraInventoryData {
    /// Final IP address assigned to camera
    pub final_ip: String,
    /// Temporary IP address used during setup
    pub temp_ip: Option<String>,
    /// MAC address of the camera
    pub mac: Option<String>,
    /// Verified MAC address (if different from discovered)
    pub verified_mac: Option<String>,
    /// Serial number of the camera
    pub serial: Option<String>,
    /// Camera name/hostname
    pub camera_name: Option<String>,
    /// Current firmware version
    pub firmware_version: Option<String>,
    /// Admin username
    pub admin_username: Option<String>,
    /// ONVIF username
    pub onvif_username: Option<String>,
    /// Overall status of camera configuration
    pub status: String,
    /// Individual operation results
    pub operations: OperationResults,
    /// Timestamp when this record was created
    pub report_generated: DateTime<Utc>,
    /// Tool version that generated this record
    pub tool_version: String,
}

/// Results from individual camera operations
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperationResults {
    pub create_admin: Option<OperationResult>,
    pub create_onvif_user: Option<OperationResult>,
    pub set_static_ip: Option<OperationResult>,
    pub upgrade_firmware: Option<OperationResult>,
}

/// Result of a single operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl OperationResult {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            success: true,
            message: message.into(),
            timestamp: Utc::now(),
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            message: message.into(),
            timestamp: Utc::now(),
        }
    }
}

/// CSV file operations for IP lists and inventory reports
///
/// Handles validation, parsing, and generation of CSV files for IP assignment
/// and configuration reporting. Special attention is given to validating
/// IP addresses and MAC addresses to prevent configuration errors.
pub struct CsvHandler {
    // No specific state needed for this handler
}

impl CsvHandler {
    /// Initialize CSV Handler module
    pub fn new() -> Self {
        Self {}
    }

    /// Read IP assignment list from CSV file with enhanced validation
    ///
    /// The CSV can be in one of two formats:
    /// 1. Sequential assignment: A single column of IP addresses
    ///    Example:
    ///    ```csv
    ///    IP
    ///    192.168.1.101
    ///    192.168.1.102
    ///    ```
    ///
    /// 2. MAC-specific assignment: Two columns with IP and MAC
    ///    Example:
    ///    ```csv
    ///    IP,MAC
    ///    192.168.1.101,00408C123456
    ///    192.168.1.102,00408CAABBCC
    ///    ```
    ///
    /// The function performs extensive validation:
    /// - Checks for duplicate IP addresses
    /// - Validates IP address format
    /// - In MAC-specific mode, validates MAC format and checks for duplicates
    /// - Verifies column headers match expected format
    pub fn read_ip_list<P: AsRef<Path>>(
        &self,
        file_path: P
    ) -> Result<Vec<IpAssignment>, CsvError> {
        let path_str = file_path.as_ref().to_string_lossy().to_string();

        if !file_path.as_ref().exists() {
            return Err(CsvError::FileNotFound { path: path_str });
        }

        let file = File::open(&file_path)?;
        let mut reader = ReaderBuilder::new().has_headers(true).flexible(true).from_reader(file);

        let headers = reader.headers()?.clone();
        let header_strings: Vec<String> = headers
            .iter()
            .map(|h| h.to_lowercase().trim().to_string())
            .collect();

        info!("CSV headers found: {:?}", header_strings);

        // Determine if this is MAC-specific format
        let has_mac =
            header_strings.contains(&"mac".to_string()) ||
            header_strings.contains(&"macaddress".to_string());

        // Validate required headers
        let has_ip =
            header_strings.contains(&"ip".to_string()) ||
            header_strings.contains(&"finalipaddress".to_string());

        if !has_ip {
            return Err(CsvError::ValidationError {
                message: "CSV file must contain an 'IP' column".to_string(),
            });
        }

        if
            has_mac &&
            !(
                header_strings.contains(&"mac".to_string()) ||
                header_strings.contains(&"macaddress".to_string())
            )
        {
            return Err(CsvError::ValidationError {
                message: "CSV file appears to be MAC-specific but is missing a 'MAC' column".to_string(),
            });
        }

        let mut results = Vec::new();
        let mut row_number = 2; // Start at 2 to account for header row

        for record_result in reader.records() {
            let record = match record_result {
                Ok(r) => r,
                Err(e) => {
                    warn!("Skipping row {}: CSV parsing error: {}", row_number, e);
                    row_number += 1;
                    continue;
                }
            };

            // Extract IP address
            let ip = self.extract_field(&record, &headers, &["ip", "finalipaddress"]);
            let ip = match ip {
                Some(ip_str) if !ip_str.trim().is_empty() => ip_str.trim().to_string(),
                _ => {
                    warn!("Skipping row {}: Missing IP address", row_number);
                    row_number += 1;
                    continue;
                }
            };

            // Validate IP address format
            if let Err(e) = ip.parse::<Ipv4Addr>() {
                warn!("Skipping row {}: Invalid IP address '{}': {}", row_number, ip, e);
                row_number += 1;
                continue;
            }

            // Extract MAC address if this is MAC-specific format
            let mac = if has_mac {
                let mac = self.extract_field(&record, &headers, &["mac", "macaddress"]);
                match mac {
                    Some(mac_str) if !mac_str.trim().is_empty() => {
                        let cleaned_mac = mac_str.trim().to_uppercase();
                        if !self.validate_mac_format(&cleaned_mac) {
                            warn!(
                                "Skipping row {}: Invalid MAC address format '{}'",
                                row_number,
                                cleaned_mac
                            );
                            row_number += 1;
                            continue;
                        }
                        Some(self.normalize_mac(&cleaned_mac))
                    }
                    _ => {
                        warn!("Skipping row {}: Missing MAC address", row_number);
                        row_number += 1;
                        continue;
                    }
                }
            } else {
                None
            };

            results.push(IpAssignment { ip, mac });
            row_number += 1;
        }

        if results.is_empty() {
            return Err(CsvError::ValidationError {
                message: "No valid IP assignments found in the CSV file".to_string(),
            });
        }

        // Perform comprehensive validation
        self.validate_assignments(&results)?;

        info!("Successfully validated and read {} IP assignments from {}", results.len(), path_str);

        Ok(results)
    }

    /// Read sequential IP assignment list from CSV file
    pub fn read_sequential_ip_list<P: AsRef<Path>>(
        &self,
        file_path: P
    ) -> Result<Vec<String>, CsvError> {
        let assignments = self.read_ip_list(file_path)?;

        if let Some(first) = assignments.first() {
            if first.mac.is_some() {
                warn!(
                    "CSV appears to be in MAC-specific format, but sequential was requested. Using IP addresses only."
                );
            }
        }

        Ok(
            assignments
                .into_iter()
                .map(|a| a.ip)
                .collect()
        )
    }

    /// Read MAC-specific IP assignment list from CSV file
    pub fn read_mac_specific_ip_list<P: AsRef<Path>>(
        &self,
        file_path: P
    ) -> Result<std::collections::HashMap<String, String>, CsvError> {
        let assignments = self.read_ip_list(file_path)?;

        // Verify this is actually MAC-specific format
        if assignments.iter().any(|a| a.mac.is_none()) {
            return Err(CsvError::ValidationError {
                message: "CSV file is not in MAC-specific format (missing MAC address column)".to_string(),
            });
        }

        let mut mac_to_ip = std::collections::HashMap::new();
        for assignment in assignments {
            if let Some(mac) = assignment.mac {
                mac_to_ip.insert(mac, assignment.ip);
            }
        }

        Ok(mac_to_ip)
    }

    /// Write comprehensive inventory report to CSV file
    ///
    /// Creates a detailed report containing:
    /// - Camera identification (IPs, MACs, serials, names)
    /// - Configuration status for each operation performed
    /// - Firmware version information
    /// - Login credentials used
    /// - Timestamp information for tracking purposes
    /// - Tool version information for record-keeping
    pub fn write_inventory_report<P: AsRef<Path>>(
        &self,
        file_path: P,
        camera_data: &[CameraInventoryData]
    ) -> Result<(), CsvError> {
        if camera_data.is_empty() {
            return Err(CsvError::ValidationError {
                message: "No camera data provided for inventory report".to_string(),
            });
        }

        let file = File::create(&file_path)?;
        let mut writer = WriterBuilder::new().has_headers(true).from_writer(file);

        // Write header
        writer.write_record(
            &[
                "final_ip",
                "temp_ip",
                "mac",
                "verified_mac",
                "serial",
                "camera_name",
                "firmware_version",
                "admin_username",
                "onvif_username",
                "status",
                "create_admin_success",
                "create_admin_message",
                "create_admin_timestamp",
                "create_onvif_user_success",
                "create_onvif_user_message",
                "create_onvif_user_timestamp",
                "set_static_ip_success",
                "set_static_ip_message",
                "set_static_ip_timestamp",
                "upgrade_firmware_success",
                "upgrade_firmware_message",
                "upgrade_firmware_timestamp",
                "report_generated",
                "tool_version",
            ]
        )?;

        // Write data rows
        for camera in camera_data {
            let ops = &camera.operations;

            // Create string values for all fields to avoid reference issues
            let temp_ip_str = camera.temp_ip.as_deref().unwrap_or("").to_string();
            let mac_str = camera.mac.as_deref().unwrap_or("").to_string();
            let verified_mac_str = camera.verified_mac.as_deref().unwrap_or("").to_string();
            let serial_str = camera.serial.as_deref().unwrap_or("").to_string();
            let camera_name_str = camera.camera_name.as_deref().unwrap_or("").to_string();
            let firmware_version_str = camera.firmware_version.as_deref().unwrap_or("").to_string();
            let admin_username_str = camera.admin_username.as_deref().unwrap_or("").to_string();
            let onvif_username_str = camera.onvif_username.as_deref().unwrap_or("").to_string();

            // Create operation result strings
            let create_admin_success = ops.create_admin
                .as_ref()
                .map(|op| op.success.to_string())
                .unwrap_or_default();
            let create_admin_message = ops.create_admin
                .as_ref()
                .map(|op| op.message.clone())
                .unwrap_or_default();
            let create_admin_timestamp = ops.create_admin
                .as_ref()
                .map(|op| op.timestamp.to_rfc3339())
                .unwrap_or_default();

            let create_onvif_user_success = ops.create_onvif_user
                .as_ref()
                .map(|op| op.success.to_string())
                .unwrap_or_default();
            let create_onvif_user_message = ops.create_onvif_user
                .as_ref()
                .map(|op| op.message.clone())
                .unwrap_or_default();
            let create_onvif_user_timestamp = ops.create_onvif_user
                .as_ref()
                .map(|op| op.timestamp.to_rfc3339())
                .unwrap_or_default();

            let set_static_ip_success = ops.set_static_ip
                .as_ref()
                .map(|op| op.success.to_string())
                .unwrap_or_default();
            let set_static_ip_message = ops.set_static_ip
                .as_ref()
                .map(|op| op.message.clone())
                .unwrap_or_default();
            let set_static_ip_timestamp = ops.set_static_ip
                .as_ref()
                .map(|op| op.timestamp.to_rfc3339())
                .unwrap_or_default();

            let upgrade_firmware_success = ops.upgrade_firmware
                .as_ref()
                .map(|op| op.success.to_string())
                .unwrap_or_default();
            let upgrade_firmware_message = ops.upgrade_firmware
                .as_ref()
                .map(|op| op.message.clone())
                .unwrap_or_default();
            let upgrade_firmware_timestamp = ops.upgrade_firmware
                .as_ref()
                .map(|op| op.timestamp.to_rfc3339())
                .unwrap_or_default();

            writer.write_record(
                &[
                    &camera.final_ip,
                    &temp_ip_str,
                    &mac_str,
                    &verified_mac_str,
                    &serial_str,
                    &camera_name_str,
                    &firmware_version_str,
                    &admin_username_str,
                    &onvif_username_str,
                    &camera.status,
                    &create_admin_success,
                    &create_admin_message,
                    &create_admin_timestamp,
                    &create_onvif_user_success,
                    &create_onvif_user_message,
                    &create_onvif_user_timestamp,
                    &set_static_ip_success,
                    &set_static_ip_message,
                    &set_static_ip_timestamp,
                    &upgrade_firmware_success,
                    &upgrade_firmware_message,
                    &upgrade_firmware_timestamp,
                    &camera.report_generated.to_rfc3339(),
                    &camera.tool_version,
                ]
            )?;
        }

        writer.flush()?;

        info!(
            "Wrote inventory report for {} cameras to {}",
            camera_data.len(),
            file_path.as_ref().to_string_lossy()
        );

        Ok(())
    }

    // Private helper methods

    /// Extract field value from CSV record
    fn extract_field(
        &self,
        record: &csv::StringRecord,
        headers: &csv::StringRecord,
        field_names: &[&str]
    ) -> Option<String> {
        for field_name in field_names {
            for (i, header) in headers.iter().enumerate() {
                if header.to_lowercase().trim() == field_name.to_lowercase() {
                    if let Some(value) = record.get(i) {
                        if !value.trim().is_empty() {
                            return Some(value.to_string());
                        }
                    }
                }
            }
        }
        None
    }

    /// Validate all assignments for duplicates and format issues
    fn validate_assignments(&self, assignments: &[IpAssignment]) -> Result<(), CsvError> {
        // Check for duplicate IPs
        let mut seen_ips = HashSet::new();
        let mut duplicate_ips = Vec::new();

        for assignment in assignments {
            if !seen_ips.insert(&assignment.ip) {
                duplicate_ips.push(assignment.ip.clone());
            }
        }

        if !duplicate_ips.is_empty() {
            return Err(CsvError::DuplicateIps {
                ips: duplicate_ips.join(", "),
            });
        }

        // Check for duplicate MACs if MAC-specific
        let macs: Vec<_> = assignments
            .iter()
            .filter_map(|a| a.mac.as_ref())
            .collect();

        if !macs.is_empty() {
            let mut seen_macs = HashSet::new();
            let mut duplicate_macs = Vec::new();

            for mac in &macs {
                if !seen_macs.insert(mac) {
                    duplicate_macs.push((*mac).clone());
                }
            }

            if !duplicate_macs.is_empty() {
                return Err(CsvError::DuplicateMacs {
                    macs: duplicate_macs.join(", "),
                });
            }

            // Verify all MACs are properly formatted
            for (idx, assignment) in assignments.iter().enumerate() {
                if let Some(mac) = &assignment.mac {
                    if !self.is_valid_mac(mac) {
                        return Err(CsvError::InvalidMac {
                            mac: format!("Row {}: {}", idx + 2, mac),
                        });
                    }
                }
            }
        }

        // Verify IP subnet consistency
        if assignments.len() > 1 {
            let ips: Vec<_> = assignments
                .iter()
                .map(|a| &a.ip)
                .collect();
            if let Err(e) = self.verify_ip_subnet_consistency(&ips) {
                warn!("IP subnet consistency check failed: {}", e);
            }
        }

        Ok(())
    }

    /// Validate basic MAC address format
    fn validate_mac_format(&self, mac: &str) -> bool {
        let clean_mac = mac.replace(':', "").replace('-', "").replace('.', "");

        // Check length and hex characters
        clean_mac.len() == 12 && clean_mac.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Perform comprehensive MAC address validation
    fn is_valid_mac(&self, mac: &str) -> bool {
        let clean_mac = mac.replace(':', "").replace('-', "").replace('.', "");

        // Check length and hex characters
        if clean_mac.len() != 12 || !clean_mac.chars().all(|c| c.is_ascii_hexdigit()) {
            return false;
        }

        // Check for invalid patterns (all zeros, all FFs)
        if clean_mac == "000000000000" || clean_mac == "FFFFFFFFFFFF" {
            return false;
        }

        true
    }

    /// Normalize MAC address to consistent format (no delimiters, uppercase)
    fn normalize_mac(&self, mac: &str) -> String {
        mac.replace(':', "").replace('-', "").replace('.', "").to_uppercase()
    }

    /// Check if all IP addresses are in the same subnet
    fn verify_ip_subnet_consistency(&self, ip_addresses: &[&String]) -> Result<(), CsvError> {
        if ip_addresses.len() < 2 {
            return Ok(());
        }

        let first_ip = ip_addresses[0].parse::<Ipv4Addr>().map_err(|e| CsvError::InvalidIp {
            ip: format!("{}: {}", ip_addresses[0], e),
        })?;

        let first_network = u32::from(first_ip) & 0xffffff00; // /24 network

        for ip_str in &ip_addresses[1..] {
            let ip = ip_str.parse::<Ipv4Addr>().map_err(|e| CsvError::InvalidIp {
                ip: format!("{}: {}", ip_str, e),
            })?;

            let network = u32::from(ip) & 0xffffff00; // /24 network

            if network != first_network {
                warn!("IP addresses span multiple subnets - this might cause connectivity issues");
                break;
            }
        }

        Ok(())
    }
}

impl Default for CsvHandler {
    fn default() -> Self {
        Self::new()
    }
}
