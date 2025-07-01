#![windows_subsystem = "windows"]

mod dchp_manager;
mod network_utilities;
mod camera_discovery;
mod camera_operations;
mod csv_handler;

use anyhow::Result;
use chrono::Utc;
use eframe::egui::{ Align, Layout, RichText, Separator, TextStyle };
use eframe::epaint::Color32;
use egui_alignments::center_horizontal;
use log::{ debug, error, info, warn };
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{ mpsc, Mutex, Semaphore };
use tokio::time::Instant;
use futures::future::join_all;

use camera_discovery::{ CameraDiscovery, DeviceInfo };
use camera_operations::{ CameraOperations, IpConfig, Protocol };
use csv_handler::{
    CsvHandler,
    CameraInventoryData,
    OperationResult,
    OperationResults,
};
use dchp_manager::{ DhcpManager, DhcpLease, NetworkInterface };
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

    discovery_rx: Option<mpsc::UnboundedReceiver<Vec<DeviceInfo>>>,
    discovery_complete_rx: Option<mpsc::UnboundedReceiver<bool>>,

    // Camera configuration communication
    processing_log_rx: Option<mpsc::UnboundedReceiver<String>>,
    processing_result_rx: Option<mpsc::UnboundedReceiver<CameraInventoryData>>,
    processing_complete_rx: Option<mpsc::UnboundedReceiver<bool>>,

    // Network configuration
    camera_subnet_mask: String,
    camera_gateway: String,
}

#[derive(Default, PartialEq)]
enum Screen {
    #[default]
    Discovery,
    Configuration,
    Processing,
    Results,
}

#[derive(Default, PartialEq, Clone)]
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
        // Process async messages first
        self.process_discovery_messages();

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

        // Tweak spacing for a cleaner look
        style.spacing.button_padding = egui::vec2(10.0, 6.0); // Slightly larger buttons
        style.spacing.item_spacing = egui::vec2(8.0, 6.0); // Consistent spacing between items
        style.spacing.interact_size = egui::vec2(100.0, 30.0); // Minimum size for interactable widgets

        // Adjust text styles for better readability
        style.text_styles.insert(
            TextStyle::Heading,
            egui::FontId::new(24.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Body,
            egui::FontId::new(16.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Button,
            egui::FontId::new(16.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Monospace,
            egui::FontId::new(14.0, egui::FontFamily::Monospace)
        ); // For logs/IPs

        // Set colors for a sleeker look (optional, can be expanded)
        // style.visuals.widgets.active.bg_fill = Color32::from_rgb(0, 150, 136); // Teal for active
        // style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(0, 180, 160);
        // style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(50, 50, 50); // Darker gray for inactive
        // style.visuals.panel_fill = Color32::from_rgb(25, 25, 25); // Dark background
        // style.visuals.text_color = Color32::LIGHT_GRAY; // Lighter text

        ctx.set_style(style);
    }

    fn show_discovery_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
            ui.heading("Axis Camera DHCP Auto Config");
            ui.separator();

            ui.columns(2, |columns| {
                // Column 1: DHCP Server Configuration
                columns[0].with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                    ui.group(|ui| {
                        ui.strong("DHCP Server Configuration");

                        // Interface selection
                        ui.horizontal(|ui| {
                            ui.label("Network Interface:");
                            egui::ComboBox
                                ::from_label("")
                                .selected_text(
                                    self.selected_interface
                                        .and_then(|i| self.dhcp_interfaces.get(i))
                                        .map(|iface| format!("{} ({})", iface.name, iface.ipv4))
                                        .unwrap_or_else(|| "Select interface...".to_string())
                                )
                                .show_ui(ui, |ui| {
                                    for (i, interface) in self.dhcp_interfaces.iter().enumerate() {
                                        let text = format!(
                                            "{} ({})",
                                            interface.name,
                                            interface.ipv4
                                        );
                                        ui.selectable_value(
                                            &mut self.selected_interface,
                                            Some(i),
                                            text
                                        );
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
                            egui::Grid
                                ::new("dhcp_leases")
                                .num_columns(3)
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.strong("IP Address");
                                    ui.strong("MAC Address");
                                    ui.strong("Lease Time");
                                    ui.end_row();

                                    for lease in &self.dhcp_leases {
                                        ui.label(lease.ip.to_string());
                                        ui.label(
                                            format!(
                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                lease.mac[0],
                                                lease.mac[1],
                                                lease.mac[2],
                                                lease.mac[3],
                                                lease.mac[4],
                                                lease.mac[5]
                                            )
                                        );
                                        ui.label(lease.lease_end.format("%H:%M:%S").to_string());
                                        ui.end_row();
                                    }
                                });
                        }
                    });
                });

                // Column 2: Camera Discovery
                columns[1].with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                    ui.group(|ui| {
                        ui.strong("Discovered Axis Cameras");

                        ui.horizontal(|ui| {
                            if
                                ui.button("🔍 Scan for Cameras").clicked() &&
                                !self.discovery_in_progress
                            {
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
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            format!(
                                                "Last scan: {:.1}s ago",
                                                last_scan.elapsed().as_secs_f32()
                                            )
                                        );
                                    }
                                );
                            }
                        });

                        // Camera table
                        if !self.discovered_cameras.is_empty() {
                            egui::ScrollArea
                                ::vertical()
                                .max_height(300.0)
                                .show(ui, |ui| {
                                    egui::Grid
                                        ::new("cameras")
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

                                                ui.label(
                                                    camera.device_type
                                                        .as_deref()
                                                        .unwrap_or("Unknown")
                                                );
                                                ui.label(
                                                    camera.server_header.as_deref().unwrap_or("-")
                                                );
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
                            ui.label(
                                "No cameras discovered yet. Make sure cameras are connected and DHCP server is running."
                            );
                        }
                    });
                });
            });
        });

        ui.separator();

        // Continue button
        ui.horizontal(|ui| {
            let can_continue = self.dhcp_running && !self.discovered_cameras.is_empty();

            if ui.add_enabled(can_continue, egui::Button::new("✅ Continue")).clicked() {
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

            if self.admin_password.is_empty() {
                ui.colored_label(egui::Color32::YELLOW, "⚠️ Password required");
            }
        });

        ui.separator();

        // Network Configuration
        ui.group(|ui| {
            ui.strong("Network Configuration");

            // Auto-populate defaults based on selected interface
            if self.camera_subnet_mask.is_empty() || self.camera_gateway.is_empty() {
                if let Some(interface_index) = self.selected_interface {
                    if let Some(interface) = self.dhcp_interfaces.get(interface_index) {
                        if self.camera_subnet_mask.is_empty() {
                            self.camera_subnet_mask = "255.255.255.0".to_string();
                        }
                        if self.camera_gateway.is_empty() {
                            self.camera_gateway = interface.ipv4.to_string();
                        }
                    }
                }
            }

            ui.horizontal(|ui| {
                ui.label("Subnet Mask:");
                ui.add(
                    egui::TextEdit
                        ::singleline(&mut self.camera_subnet_mask)
                        .hint_text("255.255.255.0")
                );
            });

            ui.horizontal(|ui| {
                ui.label("Gateway:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.camera_gateway).hint_text("192.168.1.1")
                );
            });

            // Validation feedback
            let subnet_valid = self.camera_subnet_mask.parse::<std::net::Ipv4Addr>().is_ok();
            let gateway_valid = self.camera_gateway.parse::<std::net::Ipv4Addr>().is_ok();

            if !subnet_valid && !self.camera_subnet_mask.is_empty() {
                ui.colored_label(egui::Color32::RED, "⚠️ Invalid subnet mask format");
            }
            if !gateway_valid && !self.camera_gateway.is_empty() {
                ui.colored_label(egui::Color32::RED, "⚠️ Invalid gateway IP format");
            }

            // Helper buttons for common subnet masks
            ui.horizontal(|ui| {
                ui.label("Common subnet masks:");
                if ui.small_button("/24 (255.255.255.0)").clicked() {
                    self.camera_subnet_mask = "255.255.255.0".to_string();
                }
                if ui.small_button("/16 (255.255.0.0)").clicked() {
                    self.camera_subnet_mask = "255.255.0.0".to_string();
                }
                if ui.small_button("/8 (255.0.0.0)").clicked() {
                    self.camera_subnet_mask = "255.0.0.0".to_string();
                }
            });
        });

        ui.separator();
        // IP Assignment Configuration
        ui.group(|ui| {
            ui.strong("IP Address Assignment");

            ui.radio_value(
                &mut self.ip_assignment_mode,
                IpAssignmentMode::Sequential,
                "Sequential Assignment (auto-assign IPs)"
            );
            ui.radio_value(
                &mut self.ip_assignment_mode,
                IpAssignmentMode::CsvFile,
                "CSV File (IP,MAC mapping)"
            );
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
                            if
                                let Some(path) = rfd::FileDialog
                                    ::new()
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
                        egui::TextEdit
                            ::multiline(&mut self.manual_ips)
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
                    if
                        let Some(path) = rfd::FileDialog
                            ::new()
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
                let passwords_valid = !self.admin_password.is_empty();
                let network_valid =
                    !self.camera_subnet_mask.is_empty() &&
                    !self.camera_gateway.is_empty() &&
                    self.camera_subnet_mask.parse::<std::net::Ipv4Addr>().is_ok() &&
                    self.camera_gateway.parse::<std::net::Ipv4Addr>().is_ok();

                let can_start = passwords_valid && network_valid;

                if ui.add_enabled(can_start, egui::Button::new("🚀 Start Configuration")).clicked() {
                    self.current_screen = Screen::Processing;
                    self.start_camera_configuration();
                }

                if !can_start {
                    if !passwords_valid {
                        ui.label("Fill in passwords to continue");
                    } else if !network_valid {
                        ui.label("Configure valid network settings to continue");
                    }
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

            egui::ScrollArea
                ::vertical()
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
                if
                    ui
                        .add_enabled(
                            !self.processing_in_progress && !self.processing_results.is_empty(),
                            egui::Button::new("➡️ View Results")
                        )
                        .clicked()
                {
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
            let successful = self.processing_results
                .iter()
                .filter(|r| r.status == "Success")
                .count();

            ui.horizontal(|ui| {
                ui.strong(format!("Total Cameras: {}", total));
                ui.strong(format!("Successful: {}", successful));
                ui.strong(format!("Failed: {}", total - successful));
            });

            ui.separator();

            // Results table
            egui::ScrollArea::vertical().show(ui, |ui| {
                egui::Grid
                    ::new("results")
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
                    if
                        let Some(path) = rfd::FileDialog
                            ::new()
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
                let network_base = server_u32 & 0xffffff00;
                let start_ip = std::net::Ipv4Addr::from(network_base | 50);
                let end_ip = std::net::Ipv4Addr::from(network_base | 200);

                if let Some(rt) = &self.rt {
                    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
                    self.dhcp_shutdown_tx = Some(shutdown_tx);

                    rt.spawn(async move {
                        let mut dhcp_manager = DhcpManager::new();

                        // Configure the DHCP manager
                        match
                            dhcp_manager.configure(
                                interface_name.clone(),
                                server_ip,
                                start_ip,
                                end_ip,
                                Duration::from_secs(3600)
                            ).await
                        {
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

        // Create channels for communication
        let (discovery_tx, discovery_rx) = mpsc::unbounded_channel::<Vec<DeviceInfo>>();
        let (complete_tx, complete_rx) = mpsc::unbounded_channel::<bool>();

        self.discovery_rx = Some(discovery_rx);
        self.discovery_complete_rx = Some(complete_rx);

        // Get the DHCP server's network range
        let network_to_scan = if let Some(interface_index) = self.selected_interface {
            if let Some(interface) = self.dhcp_interfaces.get(interface_index) {
                let server_ip = interface.ipv4;
                let server_u32 = u32::from(server_ip);
                let network_base = server_u32 & 0xffffff00;
                let network_ip = std::net::Ipv4Addr::from(network_base);
                format!("{}/24", network_ip)
            } else {
                "192.168.1.0/24".to_string()
            }
        } else {
            "192.168.1.0/24".to_string()
        };

        if let Some(rt) = &self.rt {
            rt.spawn(async move {
                let discovery = CameraDiscovery::new().unwrap();

                info!("Starting fast scan of network: {}", network_to_scan);

                match discovery.fast_scan_subnet(&network_to_scan, Some(10)).await {
                    Ok(cameras) => {
                        info!("Fast scan found {} cameras", cameras.len());
                        let _ = discovery_tx.send(cameras);
                    }
                    Err(e) => {
                        error!("Error in fast scan: {}", e);
                        let _ = discovery_tx.send(Vec::new());
                    }
                }

                // Signal completion
                let _ = complete_tx.send(true);
            });
        }

        self.last_scan_time = Some(Instant::now());
    }

    fn process_discovery_messages(&mut self) {
        // Process discovery results
        if let Some(rx) = &mut self.discovery_rx {
            while let Ok(cameras) = rx.try_recv() {
                self.discovered_cameras = cameras;
            }
        }

        // Process discovery completion
        if let Some(rx) = &mut self.discovery_complete_rx {
            if let Ok(_) = rx.try_recv() {
                self.discovery_in_progress = false;
                self.discovery_rx = None;
                self.discovery_complete_rx = None;
                info!(
                    "Camera discovery completed. Found {} cameras",
                    self.discovered_cameras.len()
                );
            }
        }

        // Process configuration logs
        if let Some(rx) = &mut self.processing_log_rx {
            while let Ok(log_message) = rx.try_recv() {
                self.processing_logs.push(log_message);
            }
        }

        // Process configuration results
        if let Some(rx) = &mut self.processing_result_rx {
            while let Ok(result) = rx.try_recv() {
                self.processing_results.push(result);
            }
        }

        // Process configuration completion
        if let Some(rx) = &mut self.processing_complete_rx {
            if let Ok(_) = rx.try_recv() {
                self.processing_in_progress = false;
                self.processing_log_rx = None;
                self.processing_result_rx = None;
                self.processing_complete_rx = None;
                info!("Camera configuration completed!");
            }
        }
    }
    fn start_camera_configuration(&mut self) {
        self.processing_in_progress = true;
        self.processing_logs.clear();
        self.processing_results.clear();

        self.processing_logs.push(
            format!("[{}] Starting multi-camera configuration...", Utc::now().format("%H:%M:%S"))
        );

        let (log_tx, log_rx) = mpsc::unbounded_channel::<String>();
        let (result_tx, result_rx) = mpsc::unbounded_channel::<CameraInventoryData>();
        let (complete_tx, complete_rx) = mpsc::unbounded_channel::<bool>();

        self.processing_log_rx = Some(log_rx);
        self.processing_result_rx = Some(result_rx);
        self.processing_complete_rx = Some(complete_rx);

        // Clone all configuration data needed by the spawned tasks
        let discovered_cameras = self.discovered_cameras.clone();
        let admin_password = self.admin_password.clone();
        let onvif_password = self.onvif_password.clone(); // Keep for now, can remove if unused
        let ip_assignment_mode = self.ip_assignment_mode.clone();
        let manual_ips = self.manual_ips.clone();
        let firmware_file_path = self.firmware_file_path.clone();
        let camera_subnet_mask = self.camera_subnet_mask.clone();
        let camera_gateway = self.camera_gateway.clone();
        let selected_interface = self.selected_interface;
        let dhcp_interfaces = self.dhcp_interfaces.clone();

        if let Some(rt) = &self.rt {
            rt.spawn(async move {
                let _ = log_tx.send(
                    format!("[{}] Initializing camera operations...", Utc::now().format("%H:%M:%S"))
                );

                // Semaphore to limit concurrent camera configurations (e.g., 5 cameras at a time)
                let semaphore = Arc::new(Semaphore::new(5)); // Adjust this number as needed

                let mut handles = Vec::new();

                let total_cameras = discovered_cameras.len();

                for (index, camera) in discovered_cameras.into_iter().enumerate() {
                    let log_tx_clone = log_tx.clone();
                    let result_tx_clone = result_tx.clone();
                    let semaphore_clone = semaphore.clone();

                    // Clone all configs needed per task
                    let admin_password_clone = admin_password.clone();
                    let onvif_password_clone = onvif_password.clone(); // Clone for this task
                    let ip_assignment_mode_clone = ip_assignment_mode.clone();
                    let manual_ips_clone = manual_ips.clone();
                    let firmware_file_path_clone = firmware_file_path.clone();
                    let camera_subnet_mask_clone = camera_subnet_mask.clone();
                    let camera_gateway_clone = camera_gateway.clone();
                    let dhcp_interfaces_clone = dhcp_interfaces.clone();
                    let selected_interface_clone = selected_interface;

                    let handle = tokio::spawn(async move {
                        // Acquire a permit from the semaphore before starting this camera's configuration
                        let _permit = semaphore_clone
                            .acquire().await
                            .expect("Semaphore acquire failed");

                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] Starting configuration for camera {}/{} (IP: {})",
                                Utc::now().format("%H:%M:%S"),
                                index + 1,
                                total_cameras,
                                camera.ip
                            )
                        ); // Initial log for this specific camera

                        let camera_ops = match CameraOperations::new() {
                            Ok(ops) => ops,
                            Err(e) => {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Failed to initialize camera operations for {}: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera.ip,
                                        e
                                    )
                                );
                                // Send a failed result for this camera
                                let camera_data = CameraInventoryData {
                                    final_ip: camera.ip.clone(),
                                    status: "Failed - Init".to_string(),
                                    ..Default::default()
                                };
                                let _ = result_tx_clone.send(camera_data);
                                return; // Exit this spawned task
                            }
                        };

                        let camera_ip = match camera.ip.parse::<std::net::Ipv4Addr>() {
                            Ok(ip) => ip,
                            Err(e) => {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Invalid IP address {}: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera.ip,
                                        e
                                    )
                                );
                                let camera_data = CameraInventoryData {
                                    final_ip: camera.ip.clone(),
                                    temp_ip: Some(camera.ip.clone()),
                                    status: "Failed - Invalid IP".to_string(),
                                    ..Default::default()
                                };
                                let _ = result_tx_clone.send(camera_data);
                                return;
                            }
                        };

                        let mut camera_data = CameraInventoryData {
                            final_ip: camera.ip.clone(),
                            temp_ip: Some(camera.ip.clone()),
                            mac: None,
                            verified_mac: None,
                            serial: None,
                            camera_name: None,
                            firmware_version: None,
                            admin_username: Some("root".to_string()),
                            onvif_username: Some("onvif_user".to_string()), // Retaining ONVIF for now
                            status: "Processing".to_string(),
                            operations: OperationResults::default(),
                            report_generated: Utc::now(),
                            tool_version: "1.0.0".to_string(),
                        };

                        // *** STEP 1: CREATE ADMIN USER ***
                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] Creating admin user for {}",
                                Utc::now().format("%H:%M:%S"),
                                camera.ip
                            )
                        );

                        match
                            camera_ops.create_initial_admin(
                                camera_ip,
                                "root",
                                &admin_password_clone,
                                camera_operations::Protocol::Http
                            ).await
                        {
                            Ok(msg) => {
                                camera_data.operations.create_admin = Some(
                                    OperationResult::success(msg)
                                );
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] ✅ Admin user created for {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera.ip
                                    )
                                );
                            }
                            Err(e) => {
                                camera_data.operations.create_admin = Some(
                                    OperationResult::failure(e.to_string())
                                );
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] ❌ Failed to create admin user for {}: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera.ip,
                                        e
                                    )
                                );
                            }
                        }

                        // If admin user creation failed, no point in continuing with other steps
                        let admin_success = camera_data.operations.create_admin
                            .as_ref()
                            .map(|op| op.success)
                            .unwrap_or(false);

                        if !admin_success {
                            camera_data.status = "Failed - Admin User".to_string();
                            let _ = result_tx_clone.send(camera_data);
                            return; // Skip to next camera
                        }

                        // *** Step 1.5: Wait for user accounts to become active ***
                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] Waiting for user accounts to become active on {}...",
                                Utc::now().format("%H:%M:%S"),
                                camera.ip
                            )
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await; // Increased delay for stability

                        // *** Step 2: UPGRADE FIRMWARE (IF PATH PROVIDED) ***
                        if let Some(firmware_path_buf) = &firmware_file_path_clone {
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] Attempting firmware upgrade for {} using file: {}",
                                    Utc::now().format("%H:%M:%S"),
                                    camera.ip,
                                    firmware_path_buf.display()
                                )
                            );

                            match
                                camera_ops.upgrade_firmware(
                                    camera_ip,
                                    "root",
                                    &admin_password_clone,
                                    &firmware_path_buf,
                                    camera_operations::Protocol::Http,
                                    None // Use default options (auto-commit on reboot)
                                ).await
                            {
                                Ok(msg) => {
                                    camera_data.operations.upgrade_firmware = Some(
                                        OperationResult::success(msg)
                                    );
                                    let _ = log_tx_clone.send(
                                        format!(
                                            "[{}] ✅ Firmware upgrade initiated for {}",
                                            Utc::now().format("%H:%M:%S"),
                                            camera.ip
                                        )
                                    );
                                }
                                Err(e) => {
                                    camera_data.operations.upgrade_firmware = Some(
                                        OperationResult::failure(e.to_string())
                                    );
                                    let _ = log_tx_clone.send(
                                        format!(
                                            "[{}] ❌ Firmware upgrade failed for {}: {}",
                                            Utc::now().format("%H:%M:%S"),
                                            camera.ip,
                                            e
                                        )
                                    );
                                }
                            }
                        } else {
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] Skipping firmware upgrade for {} - no file provided.",
                                    Utc::now().format("%H:%M:%S"),
                                    camera.ip
                                )
                            );
                        }

                        // *** Step 3: SET STATIC IP ***
                        let target_ip_str = match ip_assignment_mode_clone {
                            IpAssignmentMode::Sequential => {
                                if let Some(interface_index) = selected_interface_clone {
                                    if
                                        let Some(interface) =
                                            dhcp_interfaces_clone.get(interface_index)
                                    {
                                        let server_ip = interface.ipv4;
                                        let server_u32 = u32::from(server_ip);
                                        let network_base = server_u32 & 0xffffff00;
                                        // Ensure calculated IP is valid (not 0 or 255 for last octet)
                                        let mut new_ip_val = 100 + (index as u32);
                                        if new_ip_val == 0 || new_ip_val == 255 {
                                            new_ip_val = 101; // Avoid network and broadcast
                                        }
                                        let new_ip = std::net::Ipv4Addr::from(
                                            network_base | new_ip_val
                                        );
                                        Some(new_ip.to_string())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                            IpAssignmentMode::Manual => {
                                let manual_ip_list: Vec<&str> = manual_ips_clone
                                    .lines()
                                    .map(|line| line.trim())
                                    .filter(|line| !line.is_empty())
                                    .collect();
                                manual_ip_list.get(index).map(|s| s.to_string())
                            }
                            IpAssignmentMode::CsvFile => {
                                // TODO: Implement CSV parsing here to get actual target IP
                                // For now, fall back to sequential for demonstration
                                if let Some(interface_index) = selected_interface_clone {
                                    if
                                        let Some(interface) =
                                            dhcp_interfaces_clone.get(interface_index)
                                    {
                                        let server_ip = interface.ipv4;
                                        let server_u32 = u32::from(server_ip);
                                        let network_base = server_u32 & 0xffffff00;
                                        let mut new_ip_val = 100 + (index as u32);
                                        if new_ip_val == 0 || new_ip_val == 255 {
                                            new_ip_val = 101;
                                        }
                                        let new_ip = std::net::Ipv4Addr::from(
                                            network_base | new_ip_val
                                        );
                                        Some(new_ip.to_string())
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            }
                        };

                        if let Some(new_ip_str) = target_ip_str {
                            // Convert new_ip_str to Ipv4Addr for wait_for_camera_online
                            let new_ip_addr = match new_ip_str.parse::<std::net::Ipv4Addr>() {
                                Ok(ip) => ip,
                                Err(e) => {
                                    let _ = log_tx_clone.send(
                                        format!(
                                            "[{}] ❌ Invalid target IP '{}' for {}: {}",
                                            Utc::now().format("%H:%M:%S"),
                                            new_ip_str,
                                            camera.ip,
                                            e
                                        )
                                    );
                                    camera_data.operations.set_static_ip = Some(
                                        OperationResult::failure(
                                            format!("Invalid target IP: {}", new_ip_str)
                                        )
                                    );
                                    if camera_data.status == "Processing".to_string() {
                                        camera_data.status =
                                            "Partial Success - IP Invalid".to_string();
                                    }
                                    let _ = result_tx_clone.send(camera_data);
                                    return;
                                }
                            };

                            if new_ip_str != camera.ip {
                                // Only change if different from current
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Setting static IP {} (subnet: {}, gateway: {}) for camera currently at {}",
                                        Utc::now().format("%H:%M:%S"),
                                        new_ip_str,
                                        camera_subnet_mask_clone,
                                        camera_gateway_clone,
                                        camera.ip
                                    )
                                );

                                let ip_config = IpConfig {
                                    ip: new_ip_str.clone(),
                                    subnet: camera_subnet_mask_clone.clone(),
                                    gateway: camera_gateway_clone.clone(),
                                };

                                match
                                    camera_ops.set_final_static_ip(
                                        camera_ip, // Still the current IP for the request
                                        "root",
                                        &admin_password_clone,
                                        &ip_config,
                                        camera_operations::Protocol::Http
                                    ).await
                                {
                                    Ok(msg) => {
                                        camera_data.operations.set_static_ip = Some(
                                            OperationResult::success(msg.clone())
                                        );
                                        camera_data.final_ip = new_ip_str.clone();
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] ✅ Static IP configuration sent to camera at {}, target IP: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                camera.ip,
                                                new_ip_str
                                            )
                                        );

                                        // Wait for camera to restart with new IP
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Waiting for camera to restart at new IP: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                new_ip_str
                                            )
                                        );

                                        match
                                            wait_for_camera_online(
                                                new_ip_addr, // Now wait for the NEW IP
                                                "root",
                                                &admin_password_clone,
                                                network_utilities::Protocol::Http,
                                                Duration::from_secs(90), // Increased wait time for IP change + reboot
                                                Duration::from_secs(3) // Check every 3 seconds
                                            ).await
                                        {
                                            Ok((true, elapsed)) => {
                                                let _ = log_tx_clone.send(
                                                    format!(
                                                        "[{}] ✅ Camera online at new IP {} after {:.1}s",
                                                        Utc::now().format("%H:%M:%S"),
                                                        new_ip_str,
                                                        elapsed.as_secs_f32()
                                                    )
                                                );
                                            }
                                            Ok((false, _)) => {
                                                let _ = log_tx_clone.send(
                                                    format!(
                                                        "[{}] ⚠️ Camera may not be responding at new IP: {}",
                                                        Utc::now().format("%H:%M:%S"),
                                                        new_ip_str
                                                    )
                                                );
                                            }
                                            Err(e) => {
                                                let _ = log_tx_clone.send(
                                                    format!(
                                                        "[{}] ❌ Error waiting for camera at new IP: {}",
                                                        Utc::now().format("%H:%M:%S"),
                                                        e
                                                    )
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        camera_data.operations.set_static_ip = Some(
                                            OperationResult::failure(e.to_string())
                                        );
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] ❌ Failed to set static IP: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                e
                                            )
                                        );
                                    }
                                }
                            } else {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Camera {} already has target IP, skipping IP change",
                                        Utc::now().format("%H:%M:%S"),
                                        camera.ip
                                    )
                                );
                            }
                        } else {
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] No target IP determined for camera {}, skipping IP change",
                                    Utc::now().format("%H:%M:%S"),
                                    camera.ip
                                )
                            );
                            camera_data.operations.set_static_ip = Some(
                                OperationResult::failure("No target IP determined".to_string())
                            );
                        }

                        // *** STEP 4: DETERMINE FINAL STATUS FOR THIS CAMERA ***
                        let ip_success = camera_data.operations.set_static_ip
                            .as_ref()
                            .map(|op| op.success)
                            .unwrap_or(false);
                        let firmware_success = camera_data.operations.upgrade_firmware
                            .as_ref()
                            .map(|op| op.success)
                            .unwrap_or(true); // True if no firmware attempted

                        camera_data.status = if admin_success && firmware_success && ip_success {
                            "Success".to_string()
                        } else if admin_success && firmware_success {
                            // IP config failed
                            "Partial Success - IP Setting Failed".to_string()
                        } else if admin_success && ip_success {
                            // Firmware failed
                            "Partial Success - Firmware Failed".to_string()
                        } else {
                            "Failed".to_string()
                        };

                        // Send final result for this camera back to the main thread
                        let _ = result_tx_clone.send(camera_data);
                    });
                    handles.push(handle);
                }

                // Wait for all individual camera configuration tasks to complete
                join_all(handles).await;

                let _ = log_tx.send(
                    format!(
                        "[{}] All camera configurations completed!",
                        Utc::now().format("%H:%M:%S")
                    )
                );
                let _ = complete_tx.send(true);

                // It's good practice to ensure the senders are dropped after all tasks complete
                // so the receivers know the stream has ended.
                drop(log_tx);
                drop(result_tx);
                drop(complete_tx);
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
        self.camera_subnet_mask.clear();
        self.camera_gateway.clear();
        self.manual_ips.clear();
        self.processing_in_progress = false;
        self.discovery_in_progress = false;
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder
            ::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(eframe::icon_data::from_png_bytes(&[]).unwrap_or_default()),
        ..Default::default()
    };

    eframe::run_native(
        "Axis Auto Config",
        options,
        Box::new(|cc| Ok(Box::new(AxisCameraApp::new(cc))))
    )
}
