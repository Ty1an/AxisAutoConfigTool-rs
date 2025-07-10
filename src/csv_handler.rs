
use anyhow::Result;
use calamine::{ open_workbook, Reader, Xlsx, Data };
use chrono::{ DateTime, Utc };
use csv::{ ReaderBuilder, WriterBuilder };
use log::{ error, info, warn };
use rust_xlsxwriter::{ Workbook, Format };
use serde::{ Deserialize, Serialize };
use std::collections::HashMap;
use std::fs::File;
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

    #[error("Excel error: {0}")] Excel(#[from] calamine::Error),

    #[error("Excel writer error: {0}")] ExcelWriter(#[from] rust_xlsxwriter::XlsxError),
}


/// Camera data structure for inventory reports
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CameraInventoryData {
    /// Item Name
    pub item_name: Option<String>,
    /// Current firmware version
    pub firmware_version: Option<String>,
    /// MAC address of the camera
    pub mac_address: Option<String>,
    /// Serial number of the camera
    pub serial: Option<String>,
    /// Final IP address assigned to camera
    pub ip_address: String,
    /// Subnet mask
    pub subnet: String,
    /// Gateway address
    pub gateway: String,
    /// User Name
    pub user_name: String,
    /// Password
    pub password: String,
    /// Device Map #
    pub device_map: Option<String>,
    /// Timestamp when configuration was completed (internal use)
    pub completion_time: DateTime<Utc>,
    /// Overall status of camera configuration (internal use)
    pub status: String,
    /// Individual operation results (internal use)
    pub operations: OperationResults,
    /// Tool version that generated this record (internal use)
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

    /// Import existing CSV file with camera inventory data
    ///
    /// The CSV should have the following columns:
    /// - Item Name
    /// - Firmware Version
    /// - MAC Address
    /// - Serial #
    /// - IP Address
    /// - Subnet
    /// - Gateway
    /// - User Name
    /// - Password
    /// - Device Map #
    ///
    /// This function can import an existing CSV and allow editing/updating
    /// of configuration results.
    pub fn import_camera_inventory<P: AsRef<Path>>(
        &self,
        file_path: P
    ) -> Result<Vec<CameraInventoryData>, CsvError> {
        let path_str = file_path.as_ref().to_string_lossy().to_string();

        if !file_path.as_ref().exists() {
            return Err(CsvError::FileNotFound { path: path_str });
        }

        let file = File::open(&file_path)?;
        let mut reader = ReaderBuilder::new().has_headers(true).flexible(true).from_reader(file);

        let headers = reader.headers()?.clone();
        let header_index = Self::build_header_index(&headers);

        info!("CSV headers found: {:?}", headers);

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

            // Extract all fields
            let item_name = self.extract_field_with_index(&record, &header_index, &["item name", "camera model name", "model_name", "model"]);
            let firmware_version = self.extract_field_with_index(&record, &header_index, &["firmware version", "firmware"]);
            let mac_address = self.extract_field_with_index(&record, &header_index, &["mac address", "mac"]);
            let serial = self.extract_field_with_index(&record, &header_index, &["serial #", "s/n", "serial", "serial number"]);
            let ip_address = self.extract_field_with_index(&record, &header_index, &["ip address", "ip"]);
            let subnet = self.extract_field_with_index(&record, &header_index, &["subnet", "subnet mask"]);
            let gateway = self.extract_field_with_index(&record, &header_index, &["gateway", "gateway address"]);
            let user_name = self.extract_field_with_index(&record, &header_index, &["user name", "admin user name(root)", "admin username", "username"]);
            let password = self.extract_field_with_index(&record, &header_index, &["password", "admin(root) password", "admin password"]);
            let device_map = self.extract_field_with_index(&record, &header_index, &["device map #", "device map"]);
            let completion_time_str = self.extract_field_with_index(&record, &header_index, &["current time/date it was finish configuring", "completion time", "timestamp"]);

            // Skip rows without required fields
            let ip_address = match ip_address {
                Some(ip_str) if !ip_str.trim().is_empty() => ip_str.trim().to_string(),
                _ => {
                    warn!("Skipping row {}: Missing or empty IP address. Check columns: {}", 
                          row_number, 
                          headers.iter().collect::<Vec<_>>().join(", "));
                    row_number += 1;
                    continue;
                }
            };

            // Parse completion time or use current time
            let completion_time = if let Some(time_str) = completion_time_str {
                DateTime::parse_from_rfc3339(&time_str)
                    .or_else(|_| DateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S %z"))
                    .or_else(|_| DateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S"))
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now())
            } else {
                Utc::now()
            };

            let camera_data = CameraInventoryData {
                item_name,
                firmware_version,
                mac_address,
                serial,
                ip_address,
                subnet: subnet.unwrap_or_else(|| "255.255.255.0".to_string()),
                gateway: gateway.unwrap_or_else(|| "192.168.1.1".to_string()),
                user_name: user_name.unwrap_or_else(|| "root".to_string()),
                password: password.unwrap_or_default(),
                device_map,
                completion_time,
                status: "imported".to_string(),
                operations: OperationResults::default(),
                tool_version: "1.0".to_string(),
            };

            results.push(camera_data);
            row_number += 1;
        }

        if results.is_empty() {
            return Err(CsvError::ValidationError {
                message: format!(
                    "No valid camera inventory data found in the CSV file. Please ensure your file contains:\n\
                    • A header row with column names\n\
                    • At least one data row with an IP address\n\
                    • Supported column names: 'IP Address', 'IP', 'Item Name', 'MAC Address', 'Serial #', etc.\n\
                    • Found {} total rows (excluding header)", 
                    row_number - 2
                ),
            });
        }

        info!("Successfully imported {} camera inventory records from {}", results.len(), path_str);

        Ok(results)
    }


    /// Write comprehensive inventory report to CSV file
    ///
    /// Creates a detailed report with the required columns:
    /// - Item Name
    /// - Firmware Version
    /// - MAC Address
    /// - Serial #
    /// - IP Address
    /// - Subnet
    /// - Gateway
    /// - User Name
    /// - Password
    /// - Device Map #
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

        // Write header with the exact labels requested
        writer.write_record([
            "Item Name",
            "Firmware Version",
            "MAC Address",
            "Serial #",
            "IP Address",
            "Subnet",
            "Gateway",
            "User Name",
            "Password",
            "Device Map #",
        ])?;

        // Write data rows
        for camera in camera_data {
            let item_name_str = camera.item_name.as_deref().unwrap_or("").to_string();
            let firmware_version_str = camera.firmware_version.as_deref().unwrap_or("").to_string();
            let mac_address_str = camera.mac_address.as_deref().unwrap_or("").to_string();
            let serial_str = camera.serial.as_deref().unwrap_or("").to_string();
            let device_map_str = camera.device_map.as_deref().unwrap_or("").to_string();

            writer.write_record([
                &item_name_str,
                &firmware_version_str,
                &mac_address_str,
                &serial_str,
                &camera.ip_address,
                &camera.subnet,
                &camera.gateway,
                &camera.user_name,
                &camera.password,
                &device_map_str,
            ])?;
        }

        writer.flush()?;

        info!(
            "Wrote inventory report for {} cameras to {}",
            camera_data.len(),
            file_path.as_ref().to_string_lossy()
        );

        Ok(())
    }

    /// Update an existing CSV file with new camera configuration data
    ///
    /// This function can merge new configuration results with existing CSV data,
    /// updating entries that match by MAC address or IP address.
    pub fn update_inventory_csv<P: AsRef<Path>>(
        &self,
        file_path: P,
        new_camera_data: &[CameraInventoryData]
    ) -> Result<(), CsvError> {
        // First, try to read existing data
        let mut existing_data = match self.import_camera_inventory(&file_path) {
            Ok(data) => data,
            Err(_) => Vec::new(), // File doesn't exist or is empty, start fresh
        };

        // Update existing entries or add new ones
        for new_camera in new_camera_data {
            let mut updated = false;
            
            // Try to find existing entry by MAC address first, then by IP
            for existing_camera in &mut existing_data {
                if let (Some(existing_mac), Some(new_mac)) = (&existing_camera.mac_address, &new_camera.mac_address) {
                    if existing_mac == new_mac {
                        *existing_camera = new_camera.clone();
                        updated = true;
                        break;
                    }
                } else if existing_camera.ip_address == new_camera.ip_address {
                    *existing_camera = new_camera.clone();
                    updated = true;
                    break;
                }
            }
            
            // If not found, add as new entry
            if !updated {
                existing_data.push(new_camera.clone());
            }
        }

        // Write the updated data back to the file
        self.write_inventory_report(file_path, &existing_data)
    }

    /// Create a sample CSV template file
    pub fn create_sample_csv<P: AsRef<Path>>(&self, file_path: P) -> Result<(), CsvError> {
        let sample_data = vec![
            CameraInventoryData {
                item_name: Some("AXIS P1435-LE".to_string()),
                firmware_version: Some("10.12.182".to_string()),
                mac_address: Some("00408C123456".to_string()),
                serial: Some("ACCC8E123456".to_string()),
                ip_address: "192.168.1.101".to_string(),
                subnet: "255.255.255.0".to_string(),
                gateway: "192.168.1.1".to_string(),
                user_name: "root".to_string(),
                password: "password123".to_string(),
                device_map: Some("1".to_string()),
                completion_time: Utc::now(),
                status: "configured".to_string(),
                operations: OperationResults::default(),
                tool_version: "1.0".to_string(),
            },
            CameraInventoryData {
                item_name: Some("AXIS P3245-LVE".to_string()),
                firmware_version: Some("10.12.182".to_string()),
                mac_address: Some("00408CAABBCC".to_string()),
                serial: Some("ACCC8EAABBCC".to_string()),
                ip_address: "192.168.1.102".to_string(),
                subnet: "255.255.255.0".to_string(),
                gateway: "192.168.1.1".to_string(),
                user_name: "root".to_string(),
                password: "password123".to_string(),
                device_map: Some("2".to_string()),
                completion_time: Utc::now(),
                status: "configured".to_string(),
                operations: OperationResults::default(),
                tool_version: "1.0".to_string(),
            },
        ];

        self.write_inventory_report(file_path, &sample_data)
    }

    /// Import existing Excel (.xlsx) file with camera inventory data
    pub fn import_camera_inventory_excel<P: AsRef<Path>>(
        &self,
        file_path: P
    ) -> Result<Vec<CameraInventoryData>, CsvError> {
        let path_str = file_path.as_ref().to_string_lossy().to_string();

        if !file_path.as_ref().exists() {
            return Err(CsvError::FileNotFound { path: path_str });
        }

        let mut workbook: Xlsx<_> = open_workbook(&file_path).map_err(|e| CsvError::Excel(calamine::Error::Xlsx(e)))?;
        let worksheet_names = workbook.sheet_names();
        
        if worksheet_names.is_empty() {
            return Err(CsvError::ValidationError {
                message: "Excel file contains no worksheets".to_string(),
            });
        }

        // Use the first worksheet
        let worksheet_name = &worksheet_names[0];
        let range = workbook.worksheet_range(worksheet_name).map_err(|e| CsvError::Excel(calamine::Error::Xlsx(e)))?;

        let mut results = Vec::new();
        let mut header_map = HashMap::new();

        // Process the first row to build header mapping
        if let Some(first_row) = range.rows().next() {
            for (col_idx, cell) in first_row.iter().enumerate() {
                if let Data::String(header) = cell {
                    let normalized_header = header.to_lowercase().trim().to_string();
                    header_map.insert(normalized_header, col_idx);
                }
            }
        }

        // Process data rows (skip header row)
        for (row_idx, row) in range.rows().enumerate().skip(1) {
            let item_name = self.extract_excel_field(row, &header_map, &["item name", "camera model name", "model_name", "model"]);
            let firmware_version = self.extract_excel_field(row, &header_map, &["firmware version", "firmware"]);
            let mac_address = self.extract_excel_field(row, &header_map, &["mac address", "mac"]);
            let serial = self.extract_excel_field(row, &header_map, &["serial #", "s/n", "serial", "serial number"]);
            let ip_address = self.extract_excel_field(row, &header_map, &["ip address", "ip"]);
            let subnet = self.extract_excel_field(row, &header_map, &["subnet", "subnet mask"]);
            let gateway = self.extract_excel_field(row, &header_map, &["gateway", "gateway address"]);
            let user_name = self.extract_excel_field(row, &header_map, &["user name", "admin user name(root)", "admin username", "username"]);
            let password = self.extract_excel_field(row, &header_map, &["password", "admin(root) password", "admin password"]);
            let device_map = self.extract_excel_field(row, &header_map, &["device map #", "device map"]);
            let completion_time_str = self.extract_excel_field(row, &header_map, &["current time/date it was finish configuring", "completion time", "timestamp"]);

            // Skip rows without required fields
            let ip_address = match ip_address {
                Some(ip_str) if !ip_str.trim().is_empty() => ip_str.trim().to_string(),
                _ => {
                    let available_headers: Vec<String> = header_map.keys().cloned().collect();
                    warn!("Skipping row {}: Missing or empty IP address. Available columns: {}", 
                          row_idx + 1, 
                          available_headers.join(", "));
                    continue;
                }
            };

            // Parse completion time or use current time
            let completion_time = if let Some(time_str) = completion_time_str {
                DateTime::parse_from_rfc3339(&time_str)
                    .or_else(|_| DateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S %z"))
                    .or_else(|_| DateTime::parse_from_str(&time_str, "%Y-%m-%d %H:%M:%S"))
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now())
            } else {
                Utc::now()
            };

            let camera_data = CameraInventoryData {
                item_name,
                firmware_version,
                mac_address,
                serial,
                ip_address,
                subnet: subnet.unwrap_or_else(|| "255.255.255.0".to_string()),
                gateway: gateway.unwrap_or_else(|| "192.168.1.1".to_string()),
                user_name: user_name.unwrap_or_else(|| "root".to_string()),
                password: password.unwrap_or_default(),
                device_map,
                completion_time,
                status: "imported".to_string(),
                operations: OperationResults::default(),
                tool_version: "1.0".to_string(),
            };

            results.push(camera_data);
        }

        if results.is_empty() {
            let total_rows = range.rows().count().saturating_sub(1); // Subtract header row
            return Err(CsvError::ValidationError {
                message: format!(
                    "No valid camera inventory data found in the Excel file. Please ensure your file contains:\n\
                    • A header row with column names in the first row\n\
                    • At least one data row with an IP address\n\
                    • Supported column names: 'IP Address', 'IP', 'Item Name', 'MAC Address', 'Serial #', etc.\n\
                    • Found {} total rows (excluding header)", 
                    total_rows
                ),
            });
        }

        info!("Successfully imported {} camera inventory records from Excel file", results.len());
        Ok(results)
    }

    /// Extract field value from Excel row using header mapping
    fn extract_excel_field(
        &self,
        row: &[Data],
        header_map: &HashMap<String, usize>,
        field_names: &[&str]
    ) -> Option<String> {
        for field_name in field_names {
            let normalized_field = field_name.to_lowercase();
            if let Some(&col_idx) = header_map.get(&normalized_field) {
                if let Some(cell) = row.get(col_idx) {
                    match cell {
                        Data::String(s) if !s.trim().is_empty() => return Some(s.clone()),
                        Data::Float(f) => return Some(f.to_string()),
                        Data::Int(i) => return Some(i.to_string()),
                        Data::Bool(b) => return Some(b.to_string()),
                        _ => {}
                    }
                }
            }
        }
        None
    }

    /// Write comprehensive inventory report to Excel (.xlsx) file
    pub fn write_inventory_report_excel<P: AsRef<Path>>(
        &self,
        file_path: P,
        camera_data: &[CameraInventoryData]
    ) -> Result<(), CsvError> {
        if camera_data.is_empty() {
            return Err(CsvError::ValidationError {
                message: "No camera data provided for inventory report".to_string(),
            });
        }

        let mut workbook = Workbook::new();
        let worksheet = workbook.add_worksheet();

        // Create header format
        let header_format = Format::new()
            .set_bold()
            .set_background_color(rust_xlsxwriter::Color::RGB(0xD9E2F3));

        // Write headers
        let headers = [
            "Item Name",
            "Firmware Version", 
            "MAC Address",
            "Serial #",
            "IP Address",
            "Subnet",
            "Gateway",
            "User Name",
            "Password",
            "Device Map #",
        ];

        for (col, header) in headers.iter().enumerate() {
            worksheet.write_string_with_format(0, col as u16, *header, &header_format)?;
        }

        // Write data rows
        for (row_idx, camera) in camera_data.iter().enumerate() {
            let row = (row_idx + 1) as u32; // +1 to skip header row
            
            let item_name_str = camera.item_name.as_deref().unwrap_or("");
            let firmware_version_str = camera.firmware_version.as_deref().unwrap_or("");
            let mac_address_str = camera.mac_address.as_deref().unwrap_or("");
            let serial_str = camera.serial.as_deref().unwrap_or("");
            let device_map_str = camera.device_map.as_deref().unwrap_or("");

            worksheet.write_string(row, 0, item_name_str)?;
            worksheet.write_string(row, 1, firmware_version_str)?;
            worksheet.write_string(row, 2, mac_address_str)?;
            worksheet.write_string(row, 3, serial_str)?;
            worksheet.write_string(row, 4, &camera.ip_address)?;
            worksheet.write_string(row, 5, &camera.subnet)?;
            worksheet.write_string(row, 6, &camera.gateway)?;
            worksheet.write_string(row, 7, &camera.user_name)?;
            worksheet.write_string(row, 8, &camera.password)?;
            worksheet.write_string(row, 9, device_map_str)?;
        }

        // Auto-fit columns  
        worksheet.autofit();

        workbook.save(&file_path)?;

        info!(
            "Wrote Excel inventory report for {} cameras to {}",
            camera_data.len(),
            file_path.as_ref().to_string_lossy()
        );

        Ok(())
    }

    /// Update an existing Excel file with new camera configuration data
    pub fn update_inventory_excel<P: AsRef<Path>>(
        &self,
        file_path: P,
        new_camera_data: &[CameraInventoryData]
    ) -> Result<(), CsvError> {
        // First, try to read existing data
        let mut existing_data = match self.import_camera_inventory_excel(&file_path) {
            Ok(data) => data,
            Err(_) => Vec::new(), // File doesn't exist or is empty, start fresh
        };

        // Update existing entries or add new ones
        for new_camera in new_camera_data {
            let mut updated = false;
            
            // Try to find existing entry by MAC address first, then by IP
            for existing_camera in &mut existing_data {
                if let (Some(existing_mac), Some(new_mac)) = (&existing_camera.mac_address, &new_camera.mac_address) {
                    if existing_mac == new_mac {
                        *existing_camera = new_camera.clone();
                        updated = true;
                        break;
                    }
                } else if existing_camera.ip_address == new_camera.ip_address {
                    *existing_camera = new_camera.clone();
                    updated = true;
                    break;
                }
            }
            
            // If not found, add as new entry
            if !updated {
                existing_data.push(new_camera.clone());
            }
        }

        // Write the updated data back to the Excel file
        self.write_inventory_report_excel(file_path, &existing_data)
    }

    // Private helper methods

    /// Extract field value from CSV record
    /// Build a header index for O(1) lookups
    fn build_header_index(headers: &csv::StringRecord) -> HashMap<String, usize> {
        headers
            .iter()
            .enumerate()
            .map(|(i, header)| (header.to_lowercase().trim().to_string(), i))
            .collect()
    }

    fn extract_field_with_index(
        &self,
        record: &csv::StringRecord,
        header_index: &HashMap<String, usize>,
        field_names: &[&str]
    ) -> Option<String> {
        for field_name in field_names {
            let normalized_field = field_name.to_lowercase();
            if let Some(&index) = header_index.get(&normalized_field) {
                if let Some(value) = record.get(index) {
                    if !value.trim().is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
        None
    }

    fn extract_field(
        &self,
        record: &csv::StringRecord,
        headers: &csv::StringRecord,
        field_names: &[&str]
    ) -> Option<String> {
        // For backward compatibility, build index each time
        // In practice, you'd build this once and reuse it
        let header_index = Self::build_header_index(headers);
        self.extract_field_with_index(record, &header_index, field_names)
    }

}

impl Default for CsvHandler {
    fn default() -> Self {
        Self::new()
    }
}
