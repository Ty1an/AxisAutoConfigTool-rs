mod dchp_manager;
mod network_utilities;
mod camera_discovery;
mod camera_operations;
mod csv_handler;

use anyhow::Result;
use chrono::Utc;
use eframe::egui;
use log::{error, info, warn};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;

use camera_discovery::{CameraDiscovery, DeviceInfo};
use camera_operations::{CameraOperations, IpConfig, Protocol};
use csv_handler::{CsvHandler, IpAssignment, CameraInventoryData, OperationResult, OperationResults};
use dchp_manager::{DhcpManager, DhcpLease, NetworkInterface};
use network_utilities::wait_for_camera_online;

// Application state
#[derive(Default)]
pub struct AxisCameraApp {
    // Current screen
    current_screen: Screen,
    
    // DHCP Server state
    dhcp_manager: Option<Arc<Mutex<DhcpManager>>>,
    dhcp_interfaces: Vec<NetworkInterface>,
    selected_interface: Option<usize>,
    dhcp_running: bool,
    dhcp_leases: Vec<DhcpLease>,
    
    // Camera discovery state
    discovered_cameras: Vec<DeviceInfo>,
    discovery_in_progress: bool,
    last_scan_time: Option<Instant>,
    
    // Configuration state
    admin_password: String,
    onvif_password: String,
    ip_assignment_mode: IpAssignmentMode,
    csv_file_path: Option<PathBuf>,
    manual_ips: String,
    firmware_file_path: Option<PathBuf>,
    
    // Processing state
    processing_in_progress: bool,
    processing_logs: Vec<String>,
    processing_results: Vec<CameraInventoryData>,
    
    // Runtime handles
    rt: Option<tokio::runtime::Runtime>,
    dhcp_shutdown_tx: Option<mpsc::Sender<()>>,
}

#[derive(Default, PartialEq)]
enum Screen {
    #[default]
    Discovery,
    Configuration,
    Processing,
    Results,
}

#[derive(Default, PartialEq)]
enum IpAssignmentMode {
    #[default]
    Sequential,
    CsvFile,
    Manual,
}

impl AxisCameraApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Initialize logging
        env_logger::init();
        
        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
        
        let mut app = Self {
            rt: Some(rt),
            ..Default::default()
        };
        
        // Load network interfaces
        app.load_network_interfaces();
        
        app
    }
    
    fn load_network_interfaces(&mut self) {
        match DhcpManager::get_network_interfaces() {
            Ok(interfaces) => {
                self.dhcp_interfaces = interfaces;
                // Auto-select first non-loopback interface
                for (i, iface) in self.dhcp_interfaces.iter().enumerate() {
                    if !iface.name.starts_with("lo") && iface.ipv4.to_string() != "127.0.0.1" {
                        self.selected_interface = Some(i);
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Failed to load network interfaces: {}", e);
            }
        }
    }
}

impl eframe::App for AxisCameraApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Configure fonts and style
        self.configure_ui_style(ctx);
        
        // Main UI
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_screen {
                Screen::Discovery => self.show_discovery_screen(ui, ctx),
                Screen::Configuration => self.show_configuration_screen(ui, ctx),
                Screen::Processing => self.show_processing_screen(ui, ctx),
                Screen::Results => self.show_results_screen(ui, ctx),
            }
        });
        
        // Request repaint for live updates
        ctx.request_repaint_after(Duration::from_millis(500));
    }
}

impl AxisCameraApp {
    fn configure_ui_style(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.spacing.button_padding = egui::vec2(8.0, 4.0);
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        ctx.set_style(style);
    }
    
    fn show_discovery_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("🎯 Axis Camera Discovery & DHCP Server");
        ui.separator();
        
        // DHCP Server Configuration
        ui.group(|ui| {
            ui.strong("DHCP Server Configuration");
            
            // Interface selection
            ui.horizontal(|ui| {
                ui.label("Network Interface:");
                egui::ComboBox::from_label("")
                    .selected_text(
                        self.selected_interface
                            .and_then(|i| self.dhcp_interfaces.get(i))
                            .map(|iface| format!("{} ({})", iface.name, iface.ipv4))
                            .unwrap_or_else(|| "Select interface...".to_string())
                    )
                    .show_ui(ui, |ui| {
                        for (i, interface) in self.dhcp_interfaces.iter().enumerate() {
                            let text = format!("{} ({})", interface.name, interface.ipv4);
                            ui.selectable_value(&mut self.selected_interface, Some(i), text);
                        }
                    });
            });
            
            // DHCP Server controls
            ui.horizontal(|ui| {
                if !self.dhcp_running {
                    if ui.button("🚀 Start DHCP Server").clicked() {
                        self.start_dhcp_server();
                    }
                } else {
                    if ui.button("🛑 Stop DHCP Server").clicked() {
                        self.stop_dhcp_server();
                    }
                    ui.colored_label(egui::Color32::GREEN, "● DHCP Server Running");
                }
            });
            
            // DHCP Leases
            if !self.dhcp_leases.is_empty() {
                ui.strong("Active DHCP Leases:");
                egui::Grid::new("dhcp_leases")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("IP Address");
                        ui.strong("MAC Address");
                        ui.strong("Lease Time");
                        ui.end_row();
                        
                        for lease in &self.dhcp_leases {
                            ui.label(lease.ip.to_string());
                            ui.label(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                lease.mac[0], lease.mac[1], lease.mac[2],
                                lease.mac[3], lease.mac[4], lease.mac[5]));
                            ui.label(lease.lease_end.format("%H:%M:%S").to_string());
                            ui.end_row();
                        }
                    });
            }
        });
        
        ui.separator();
        
        // Camera Discovery
        ui.group(|ui| {
            ui.strong("Discovered Axis Cameras");
            
            ui.horizontal(|ui| {
                if ui.button("🔍 Scan for Cameras").clicked() && !self.discovery_in_progress {
                    self.start_camera_discovery();
                }
                
                if ui.button("🔄 Refresh").clicked() && !self.discovery_in_progress {
                    self.refresh_dhcp_leases();
                    self.start_camera_discovery();
                }
                
                if self.discovery_in_progress {
                    ui.spinner();
                    ui.label("Scanning...");
                }
                
                if let Some(last_scan) = self.last_scan_time {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(format!("Last scan: {:.1}s ago", last_scan.elapsed().as_secs_f32()));
                    });
                }
            });
            
            // Camera table
            if !self.discovered_cameras.is_empty() {
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .show(ui, |ui| {
                        egui::Grid::new("cameras")
                            .num_columns(5)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("IP Address");
                                ui.strong("Status");
                                ui.strong("Device Type");
                                ui.strong("Server");
                                ui.strong("Response Time");
                                ui.end_row();
                                
                                for camera in &self.discovered_cameras {
                                    ui.label(&camera.ip);
                                    
                                    let status_color = if camera.status == "discovered" {
                                        egui::Color32::GREEN
                                    } else {
                                        egui::Color32::RED
                                    };
                                    ui.colored_label(status_color, &camera.status);
                                    
                                    ui.label(camera.device_type.as_deref().unwrap_or("Unknown"));
                                    ui.label(camera.server_header.as_deref().unwrap_or("-"));
                                    ui.label(
                                        camera.response_time_ms
                                            .map(|ms| format!("{}ms", ms))
                                            .unwrap_or_else(|| "-".to_string())
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            } else {
                ui.label("No cameras discovered yet. Make sure cameras are connected and DHCP server is running.");
            }
        });
        
        ui.separator();
        
        // Continue button
        ui.horizontal(|ui| {
            let can_continue = self.dhcp_running && !self.discovered_cameras.is_empty();
            
            if ui.add_enabled(can_continue, egui::Button::new("✅ Continue to Configuration")).clicked() {
                self.current_screen = Screen::Configuration;
            }
            
            if !can_continue {
                ui.label("Start DHCP server and discover cameras to continue");
            }
        });
    }
    
    fn show_configuration_screen(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.heading("⚙️ Camera Configuration");
        ui.separator();
        
        // Password Configuration
        ui.group(|ui| {
            ui.strong("Authentication Settings");
            
            ui.horizontal(|ui| {
                ui.label("Admin Password:");
                ui.add(egui::TextEdit::singleline(&mut self.admin_password).password(true));
            });
            
            ui.horizontal(|ui| {
                ui.label("ONVIF Password:");
                ui.add(egui::TextEdit::singleline(&mut self.onvif_password).password(true));
            });
            
            if self.admin_password.is_empty() || self.onvif_password.is_empty() {
                ui.colored_label(egui::Color32::YELLOW, "⚠️ Passwords are required");
            }
        });
        
        ui.separator();
        
        // IP Assignment Configuration
        ui.group(|ui| {
            ui.strong("IP Address Assignment");
            
            ui.radio_value(&mut self.ip_assignment_mode, IpAssignmentMode::Sequential, "Sequential Assignment (auto-assign IPs)");
            ui.radio_value(&mut self.ip_assignment_mode, IpAssignmentMode::CsvFile, "CSV File (IP,MAC mapping)");
            ui.radio_value(&mut self.ip_assignment_mode, IpAssignmentMode::Manual, "Manual Entry");
            
            match self.ip_assignment_mode {
                IpAssignmentMode::Sequential => {
                    ui.label("Cameras will be assigned sequential IP addresses automatically");
                }
                IpAssignmentMode::CsvFile => {
                    ui.horizontal(|ui| {
                        ui.label("CSV File:");
                        if let Some(path) = &self.csv_file_path {
                            ui.label(path.file_name().unwrap().to_string_lossy());
                        } else {
                            ui.label("No file selected");
                        }
                        
                        if ui.button("📁 Browse").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("CSV files", &["csv"])
                                .pick_file()
                            {
                                self.csv_file_path = Some(path);
                            }
                        }
                    });
                }
                IpAssignmentMode::Manual => {
                    ui.label("Enter IP addresses (one per line):");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.manual_ips)
                            .desired_rows(5)
                            .hint_text("192.168.1.101\n192.168.1.102\n192.168.1.103")
                    );
                }
            }
        });
        
        ui.separator();
        
        // Firmware Upload
        ui.group(|ui| {
            ui.strong("Firmware Upgrade (Optional)");
            
            ui.horizontal(|ui| {
                ui.label("Firmware File:");
                if let Some(path) = &self.firmware_file_path {
                    ui.label(path.file_name().unwrap().to_string_lossy());
                } else {
                    ui.label("No file selected");
                }
                
                if ui.button("📁 Browse").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Firmware files", &["bin"])
                        .pick_file()
                    {
                        self.firmware_file_path = Some(path);
                    }
                }
                
                if self.firmware_file_path.is_some() {
                    if ui.button("🗑️ Remove").clicked() {
                        self.firmware_file_path = None;
                    }
                }
            });
        });
        
        ui.separator();
        
        // Navigation buttons
        ui.horizontal(|ui| {
            if ui.button("⬅️ Back").clicked() {
                self.current_screen = Screen::Discovery;
            }
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can_start = !self.admin_password.is_empty() && !self.onvif_password.is_empty();
                
                if ui.add_enabled(can_start, egui::Button::new("🚀 Start Configuration")).clicked() {
                    self.current_screen = Screen::Processing;
                    self.start_camera_configuration();
                }
                
                if !can_start {
                    ui.label("Fill in required fields to continue");
                }
            });
        });
    }
    
    fn show_processing_screen(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.heading("🔄 Processing Cameras");
        ui.separator();
        
        if self.processing_in_progress {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.strong("Configuration in progress...");
            });
        }
        
        // Processing logs
        ui.group(|ui| {
            ui.strong("Processing Log");
            
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log_entry in &self.processing_logs {
                        ui.label(log_entry);
                    }
                    
                    if self.processing_logs.is_empty() {
                        ui.label("Waiting for processing to start...");
                    }
                });
        });
        
        ui.separator();
        
        // Navigation
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.processing_in_progress, egui::Button::new("⬅️ Back")).clicked() {
                self.current_screen = Screen::Configuration;
            }
            
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(!self.processing_in_progress && !self.processing_results.is_empty(), 
                                  egui::Button::new("➡️ View Results")).clicked() {
                    self.current_screen = Screen::Results;
                }
            });
        });
    }
    
    fn show_results_screen(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        ui.heading("📊 Configuration Results");
        ui.separator();
        
        if !self.processing_results.is_empty() {
            // Summary
            let total = self.processing_results.len();
            let successful = self.processing_results.iter()
                .filter(|r| r.status == "Success")
                .count();
            
            ui.horizontal(|ui| {
                ui.strong(format!("Total Cameras: {}", total));
                ui.strong(format!("Successful: {}", successful));
                ui.strong(format!("Failed: {}", total - successful));
            });
            
            ui.separator();
            
            // Results table
            egui::ScrollArea::vertical()
                .show(ui, |ui| {
                    egui::Grid::new("results")
                        .num_columns(6)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Final IP");
                            ui.strong("MAC");
                            ui.strong("Status");
                            ui.strong("Admin User");
                            ui.strong("ONVIF User");
                            ui.strong("Firmware");
                            ui.end_row();
                            
                            for result in &self.processing_results {
                                ui.label(&result.final_ip);
                                ui.label(result.mac.as_deref().unwrap_or("-"));
                                
                                let status_color = if result.status == "Success" {
                                    egui::Color32::GREEN
                                } else {
                                    egui::Color32::RED
                                };
                                ui.colored_label(status_color, &result.status);
                                
                                ui.label(
                                    result.operations.create_admin
                                        .as_ref()
                                        .map(|op| if op.success { "✅" } else { "❌" })
                                        .unwrap_or("-")
                                );
                                
                                ui.label(
                                    result.operations.create_onvif_user
                                        .as_ref()
                                        .map(|op| if op.success { "✅" } else { "❌" })
                                        .unwrap_or("-")
                                );
                                
                                ui.label(
                                    result.operations.upgrade_firmware
                                        .as_ref()
                                        .map(|op| if op.success { "✅" } else { "❌" })
                                        .unwrap_or("-")
                                );
                                
                                ui.end_row();
                            }
                        });
                });
            
            ui.separator();
            
            // Export results
            ui.horizontal(|ui| {
                if ui.button("💾 Export Results to CSV").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("CSV files", &["csv"])
                        .set_file_name("camera_configuration_results.csv")
                        .save_file()
                    {
                        self.export_results_to_csv(path);
                    }
                }
            });
        }
        
        ui.separator();
        
        // Navigation
        ui.horizontal(|ui| {
            if ui.button("🔄 Start New Configuration").clicked() {
                self.reset_application();
                self.current_screen = Screen::Discovery;
            }
            
            if ui.button("⬅️ Back to Processing").clicked() {
                self.current_screen = Screen::Processing;
            }
        });
    }
    
    // Background operations
    
   fn start_dhcp_server(&mut self) {
    if let Some(interface_index) = self.selected_interface {
        if let Some(interface) = self.dhcp_interfaces.get(interface_index) {
            let interface_name = interface.name.clone();
            let server_ip = interface.ipv4;
            
            // Calculate IP range
            let server_u32 = u32::from(server_ip);
            let network_base = server_u32 & 0xFFFFFF00;
            let start_ip = std::net::Ipv4Addr::from(network_base | 50);
            let end_ip = std::net::Ipv4Addr::from(network_base | 200);
            
            if let Some(rt) = &self.rt {
                let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
                self.dhcp_shutdown_tx = Some(shutdown_tx);
                
                rt.spawn(async move {
                    let mut dhcp_manager = DhcpManager::new();
                    
                    // Configure the DHCP manager
                    match dhcp_manager.configure(
                        interface_name.clone(),
                        server_ip,
                        start_ip,
                        end_ip,
                        Duration::from_secs(3600),
                    ).await {
                        Ok(()) => {
                            info!("DHCP manager configured successfully on interface: {}", interface_name);
                            
                            // Start the DHCP server
                            if let Err(e) = dhcp_manager.start(shutdown_rx).await {
                                error!("DHCP server error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to configure DHCP manager: {}", e);
                        }
                    }
                });
                
                self.dhcp_running = true;
                info!("DHCP server starting on interface: {}", interface.name);
            }
        }
    }
}
    
    fn stop_dhcp_server(&mut self) {
        if let Some(shutdown_tx) = self.dhcp_shutdown_tx.take() {
            let _ = shutdown_tx.try_send(());
        }
        self.dhcp_running = false;
        self.dhcp_manager = None;
        info!("DHCP server stopped");
    }
    
    fn refresh_dhcp_leases(&mut self) {
    if let Some(dhcp_manager) = &self.dhcp_manager {
        if let Some(rt) = &self.rt {
            let manager = dhcp_manager.clone();
            rt.spawn(async move {
                let leases = {
                    let mgr = manager.lock().await;
                    mgr.get_active_leases().await
                };
                // Handle the leases result here
                info!("Retrieved {} active leases", leases.len());
            });
        }
    }
}
    
    fn start_camera_discovery(&mut self) {
        if self.discovery_in_progress {
            return;
        }
        
        self.discovery_in_progress = true;
        self.discovered_cameras.clear();
        
        if let Some(rt) = &self.rt {
            rt.spawn(async {
                let discovery = CameraDiscovery::new().unwrap();
                
                // Scan common IP ranges for cameras
                let networks = vec![
                    "192.168.1.0/24",
                    "192.168.0.0/24",
                    "10.0.0.0/24",
                    "169.254.0.0/16", // Link-local
                ];
                
                for network in networks {
                    if let Ok(cameras) = discovery.scan_subnet(network).await {
                        // In a real implementation, you'd send these results back
                        // to the main thread via a channel
                        info!("Found {} cameras in network {}", cameras.len(), network);
                    }
                }
            });
        }
        
        self.last_scan_time = Some(Instant::now());
        // Simulate discovery completion after 3 seconds
        // In real implementation, this would be handled by the async task
        if let Some(rt) = &self.rt {
            rt.spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                // Send completion signal
            });
        }
    }
    
    fn start_camera_configuration(&mut self) {
        self.processing_in_progress = true;
        self.processing_logs.clear();
        self.processing_results.clear();
        
        // Add initial log entry
        self.processing_logs.push(format!("[{}] Starting camera configuration...", 
                                         Utc::now().format("%H:%M:%S")));
        
        // In a real implementation, this would start the actual configuration process
        // For now, we'll simulate it
        if let Some(rt) = &self.rt {
            rt.spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                // Configuration would happen here
            });
        }
    }
    
    fn export_results_to_csv(&self, path: PathBuf) {
        let csv_handler = CsvHandler::new();
        if let Err(e) = csv_handler.write_inventory_report(&path, &self.processing_results) {
            error!("Failed to export results: {}", e);
        } else {
            info!("Results exported to: {}", path.display());
        }
    }
    
    fn reset_application(&mut self) {
        self.stop_dhcp_server();
        self.discovered_cameras.clear();
        self.processing_logs.clear();
        self.processing_results.clear();
        self.admin_password.clear();
        self.onvif_password.clear();
        self.csv_file_path = None;
        self.firmware_file_path = None;
        self.manual_ips.clear();
        self.processing_in_progress = false;
        self.discovery_in_progress = false;
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(eframe::icon_data::from_png_bytes(&[]).unwrap_or_default()),
        ..Default::default()
    };
    
    eframe::run_native(
        "Axis Camera Unified Setup Tool",
        options,
        Box::new(|cc| Ok(Box::new(AxisCameraApp::new(cc)))),
    )
}