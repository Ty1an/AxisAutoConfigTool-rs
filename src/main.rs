#![windows_subsystem = "windows"]

mod camera_discovery;
mod camera_operations;
mod csv_handler;
mod dchp_manager;
mod network_utilities;

use anyhow::Result;
use chrono::Utc;
use eframe::egui::TextStyle;
use futures::future::join_all;
use log::{ error, info };
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{ mpsc, Mutex, Semaphore };
use tokio::time::Instant;

// String constants to reduce allocations
const ROOT_USERNAME: &str = "root";
const TOOL_VERSION: &str = "1.0.0";
const PROCESSING_STATUS: &str = "Processing";
const FAILED_INIT_STATUS: &str = "Failed - Init";
const FAILED_INVALID_IP_STATUS: &str = "Failed - Invalid IP";
const SUCCESS_STATUS: &str = "Success";
const FAILED_STATUS: &str = "Failed";

use camera_discovery::{ CameraDiscovery, DeviceInfo };
use camera_operations::{ CameraOperations, IpConfig, ModelFirmwareMapping };
use csv_handler::{ CameraInventoryData, CsvHandler, OperationResult, OperationResults };
use dchp_manager::{ DhcpLease, DhcpManager, NetworkInterface };

#[derive(Clone, Debug)]
struct FirmwareEntry {
    file_path: Option<PathBuf>,
    compatible_models: String, // Comma-separated list of compatible models
    is_loaded: bool,
}

#[derive(Clone, Debug)]
struct ResponsiveDimensions {
    side_panel_width: f32,
    card_min_height: f32,
    button_height: f32,
    text_field_height: f32,
    base_spacing: f32,
    font_scale: f32,
}

// Shared configuration data to avoid excessive cloning
#[derive(Clone)]
struct ConfigData {
    admin_password: String,
    camera_subnet_mask: String,
    camera_gateway: String,
    firmware_mapping: ModelFirmwareMapping,
    target_ips: Arc<Vec<String>>,
}

// Structure to track camera by MAC address for IP change handling
#[derive(Clone, Debug)]
struct CameraTracker {
    pub mac_address: String,
    pub current_ip: String,
    pub target_ip: String,
    pub last_seen: std::time::Instant,
}

// Consolidated channel management to reduce Option overhead
struct ChannelManager {
    discovery_rx: Option<mpsc::UnboundedReceiver<Vec<DeviceInfo>>>,
    discovery_complete_rx: Option<mpsc::UnboundedReceiver<bool>>,
    processing_log_rx: Option<mpsc::UnboundedReceiver<String>>,
    processing_result_rx: Option<mpsc::UnboundedReceiver<CameraInventoryData>>,
    processing_complete_rx: Option<mpsc::UnboundedReceiver<bool>>,
    lease_refresh_rx: Option<mpsc::UnboundedReceiver<Vec<DhcpLease>>>,
    lease_update_tx: Option<mpsc::UnboundedSender<Vec<DhcpLease>>>,
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self {
            discovery_rx: None,
            discovery_complete_rx: None,
            processing_log_rx: None,
            processing_result_rx: None,
            processing_complete_rx: None,
            lease_refresh_rx: None,
            lease_update_tx: None,
        }
    }
}

pub struct AxisCameraApp {
    current_screen: Screen,

    dhcp_manager: Option<Arc<Mutex<DhcpManager>>>,
    dhcp_interfaces: Vec<NetworkInterface>,
    selected_interface: Option<usize>,
    dhcp_running: bool,
    dhcp_leases: Vec<DhcpLease>,

    discovered_cameras: Vec<DeviceInfo>,
    discovery_in_progress: bool,
    last_scan_time: Option<Instant>,

    admin_password: String,
    ip_range_input: String,
    firmware_mapping: ModelFirmwareMapping,
    firmware_entries: Vec<FirmwareEntry>,

    processing_in_progress: bool,
    processing_logs: Vec<String>,
    processing_results: Vec<CameraInventoryData>,

    rt: Option<tokio::runtime::Runtime>,
    dhcp_shutdown_tx: Option<mpsc::Sender<()>>,

    // Consolidated channel management
    channels: Option<ChannelManager>,

    camera_subnet_mask: String,
    camera_gateway: String,

    // CSV import functionality
    csv_import_file_path: String,
    imported_csv_data: Vec<CameraInventoryData>,
}

#[derive(Default, PartialEq)]
enum Screen {
    #[default]
    MainConfiguration, // Combined DHCP + Camera Discovery + Config
    Processing,
}

impl Default for AxisCameraApp {
    fn default() -> Self {
        Self {
            current_screen: Screen::default(),
            dhcp_manager: None,
            dhcp_interfaces: Vec::new(),
            selected_interface: None,
            dhcp_running: false,
            dhcp_leases: Vec::with_capacity(100),
            discovered_cameras: Vec::with_capacity(50),
            discovery_in_progress: false,
            last_scan_time: None,
            admin_password: String::new(),
            ip_range_input: String::new(),
            firmware_mapping: ModelFirmwareMapping::new(),
            firmware_entries: Vec::with_capacity(10),
            processing_in_progress: false,
            processing_logs: Vec::with_capacity(200),
            processing_results: Vec::with_capacity(75),
            rt: None,
            dhcp_shutdown_tx: None,
            channels: Some(ChannelManager::default()),
            camera_subnet_mask: "255.255.255.0".to_string(),
            camera_gateway: "192.168.1.1".to_string(),
            csv_import_file_path: String::new(),
            imported_csv_data: Vec::with_capacity(1000),
        }
    }
}

impl AxisCameraApp {
    fn create_button(text: &str, size: egui::Vec2) -> egui::Button {
        egui::Button::new(text).min_size(size)
    }
    
    // Responsive design helper functions
    fn get_responsive_dimensions(ui: &egui::Ui) -> ResponsiveDimensions {
        let available_width = ui.available_width();
        let available_height = ui.available_height();
        
        ResponsiveDimensions {
            side_panel_width: (available_width * 0.25).max(280.0).min(400.0),
            card_min_height: (available_height * 0.35).max(280.0),
            button_height: (available_height * 0.04).max(28.0).min(40.0),
            text_field_height: (available_height * 0.025).max(18.0).min(24.0),
            base_spacing: (available_width * 0.008).max(6.0).min(12.0),
            font_scale: Self::calculate_font_scale(available_width, available_height),
        }
    }
    
    fn calculate_font_scale(width: f32, height: f32) -> f32 {
        let base_area = 1400.0 * 900.0; // Original design area
        let current_area = width * height;
        (current_area / base_area).sqrt().clamp(0.8, 1.4)
    }

    fn toggle_switch(ui: &mut egui::Ui, on: &mut bool, size: egui::Vec2) -> egui::Response {
        let desired_size = size;
        let (rect, mut response) = ui.allocate_exact_size(desired_size, egui::Sense::click());

        if response.clicked() {
            *on = !*on;
            response.mark_changed();
        }

        if ui.is_rect_visible(rect) {
            let how_on = ui.ctx().animate_bool(response.id, *on);
            let visuals = ui.style().interact_selectable(&response, *on);
            let rect = rect.expand(visuals.expansion);
            let radius = 0.5 * rect.height();

            // Background with colors matching the Nordic UI theme
            let bg_color = if *on {
                egui::Color32::from_rgb(163, 190, 140) // NORD_GREEN to match the rest of the UI
            } else {
                egui::Color32::from_rgb(76, 86, 106) // NORD_POLAR_NIGHT[3] to match inactive elements
            };

            // Draw rounded rectangle background
            ui.painter().rect_filled(rect, egui::Rounding::same(radius as u8), bg_color);

            // Calculate circle position with smooth animation
            let circle_radius = radius - 3.0; // Slightly smaller for better iOS look
            let circle_x = egui::lerp(
                rect.min.x + circle_radius + 2.0..=rect.max.x - circle_radius - 2.0,
                how_on
            );
            let circle_center = egui::pos2(circle_x, rect.center().y);

            // Draw white circle with subtle shadow
            ui.painter().circle(
                circle_center + egui::vec2(0.5, 0.5),
                circle_radius,
                egui::Color32::from_rgba_premultiplied(0, 0, 0, 20), // Shadow
                egui::Stroke::NONE
            );
            ui.painter().circle(
                circle_center,
                circle_radius,
                egui::Color32::WHITE,
                egui::Stroke::new(0.5, egui::Color32::from_gray(200))
            );
        }

        response
    }

    fn load_firmware_files(&mut self) {
        self.firmware_mapping = ModelFirmwareMapping::new();

        for entry in &mut self.firmware_entries {
            if let Some(path) = &entry.file_path {
                if path.exists() {
                    let filename = path.file_name().unwrap().to_string_lossy().to_string();

                    // Load firmware data immediately into memory for fast access
                    match std::fs::read(path) {
                        Ok(firmware_data) => {

                            let compatible_models: Vec<String> = if
                                !entry.compatible_models.trim().is_empty()
                            {
                                entry.compatible_models
                                    .split(',')
                                    .map(|s| s.trim().to_string())
                                    .filter(|s| !s.is_empty())
                                    .collect()
                            } else if
                                let Some(extracted_model) =
                                    ModelFirmwareMapping::extract_model_from_firmware_filename(&filename)
                            {
                                vec![extracted_model]
                            } else {
                                vec!["auto-detect".to_string()]
                            };

                            if !compatible_models.is_empty() {
                                // Add firmware with pre-loaded data for immediate use
                                self.firmware_mapping.add_firmware_data(
                                    filename.clone(),
                                    std::sync::Arc::new(firmware_data),
                                    compatible_models.clone()
                                );
                                entry.is_loaded = true;

                                if
                                    entry.compatible_models.trim().is_empty() &&
                                    compatible_models.len() == 1 &&
                                    compatible_models[0] != "auto-detect"
                                {
                                    entry.compatible_models = compatible_models[0].clone();
                                }
                            } else {
                                entry.is_loaded = false;
                            }
                        }
                        Err(_) => {
                            entry.is_loaded = false;
                        }
                    }
                } else {
                    entry.is_loaded = false;
                }
            }
        }
    }

    /// Load and parse an existing Excel or CSV file for merging with new configuration results
    fn load_csv_file(&mut self) {
        if self.csv_import_file_path.is_empty() {
            return;
        }

        let csv_handler = CsvHandler::new();
        let path = std::path::Path::new(&self.csv_import_file_path);

        // Determine file type by extension
        let is_excel = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase() == "xlsx")
            .unwrap_or(false);

        let result = if is_excel {
            csv_handler.import_camera_inventory_excel(&self.csv_import_file_path)
        } else {
            csv_handler.import_camera_inventory(&self.csv_import_file_path)
        };

        match result {
            Ok(data) => {
                self.imported_csv_data = data;
                let file_type = if is_excel { "Excel" } else { "CSV" };
                info!(
                    "Successfully loaded {} entries from {} file",
                    self.imported_csv_data.len(),
                    file_type
                );
            }
            Err(e) => {
                error!("Failed to load file: {}", e);
                self.imported_csv_data.clear();
            }
        }
    }

    fn parse_ip_range(&self, range_str: &str) -> Result<Vec<String>, String> {
        let range_str = range_str.trim();

        if !range_str.contains('-') {
            match range_str.parse::<std::net::Ipv4Addr>() {
                Ok(_) => {
                    return Ok(vec![range_str.to_string()]);
                }
                Err(_) => {
                    return Err(
                        format!("Invalid IP address: {}. Use single IP (192.168.5.2) or range (192.168.5.2-10)", range_str)
                    );
                }
            }
        }

        let parts: Vec<&str> = range_str.split('-').collect();
        if parts.len() != 2 {
            return Err(
                "Invalid format. Use single IP (192.168.5.2) or range (192.168.5.2-10)".to_string()
            );
        }

        let start_ip = parts[0].trim();
        let end_num_str = parts[1].trim();

        let start_addr: std::net::Ipv4Addr = start_ip
            .parse()
            .map_err(|_| format!("Invalid start IP address: {}", start_ip))?;

        let end_num: u8 = end_num_str
            .parse()
            .map_err(|_| format!("Invalid end number: {}", end_num_str))?;

        let start_octets = start_addr.octets();
        let start_last_octet = start_octets[3];

        if end_num < start_last_octet {
            return Err(
                format!("End number {} must be >= start last octet {}", end_num, start_last_octet)
            );
        }

        let mut ip_list = Vec::new();
        for i in start_last_octet..=end_num {
            let ip = std::net::Ipv4Addr::new(start_octets[0], start_octets[1], start_octets[2], i);
            ip_list.push(ip.to_string());
        }

        Ok(ip_list)
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        env_logger::init();

        let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");

        if let Some(monitor) = cc.egui_ctx.input(|i| i.viewport().monitor_size) {
            let screen_width = monitor.x;
            let screen_height = monitor.y;

            let target_width = screen_width * 0.5;
            let target_height = screen_height * 0.9;

            cc.egui_ctx.send_viewport_cmd(
                egui::ViewportCommand::InnerSize(egui::Vec2::new(target_width, target_height))
            );

            let center_x = (screen_width - target_width) / 2.0;
            let center_y = (screen_height - target_height) / 2.0;
            cc.egui_ctx.send_viewport_cmd(
                egui::ViewportCommand::OuterPosition(egui::Pos2::new(center_x, center_y))
            );
        }

        let mut app = Self {
            rt: Some(rt),
            ..Default::default()
        };

        app.load_network_interfaces();

        app
    }

    fn load_network_interfaces(&mut self) {
        match DhcpManager::get_network_interfaces() {
            Ok(interfaces) => {
                self.dhcp_interfaces = interfaces;
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
        self.process_discovery_messages();

        if self.dhcp_running && !self.discovery_in_progress {
            let should_scan = if let Some(last_scan) = self.last_scan_time {
                last_scan.elapsed() >= Duration::from_secs(10)
            } else {
                true
            };

            // Continue scanning if we haven't found enough cameras to match DHCP leases
            let discovered_count = self.discovered_cameras.len();
            let dhcp_lease_count = self.dhcp_leases.len();
            let cameras_match_leases = discovered_count >= dhcp_lease_count && dhcp_lease_count > 0;

            if should_scan && !cameras_match_leases {
                self.start_camera_discovery();
            }
        }

        self.configure_ui_style(ctx);

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_screen {
                Screen::MainConfiguration => self.show_main_configuration_screen(ui, ctx),
                Screen::Processing => self.show_processing_screen(ui, ctx),
            }
        });

        let repaint_interval = if self.discovery_in_progress {
            Duration::from_millis(200)
        } else {
            Duration::from_millis(1000)
        };
        ctx.request_repaint_after(repaint_interval);
    }
}

impl AxisCameraApp {
    fn configure_ui_style(&self, ctx: &egui::Context) {
        const NORD_POLAR_NIGHT: [egui::Color32; 4] = [
            egui::Color32::from_rgb(46, 52, 64),
            egui::Color32::from_rgb(59, 66, 82),
            egui::Color32::from_rgb(67, 76, 94),
            egui::Color32::from_rgb(76, 86, 106),
        ];

        const NORD_SNOW_STORM: [egui::Color32; 3] = [
            egui::Color32::from_rgb(216, 222, 233),
            egui::Color32::from_rgb(229, 233, 240),
            egui::Color32::from_rgb(236, 239, 244),
        ];

        const NORD_FROST: [egui::Color32; 4] = [
            egui::Color32::from_rgb(143, 188, 187),
            egui::Color32::from_rgb(136, 192, 208),
            egui::Color32::from_rgb(129, 161, 193),
            egui::Color32::from_rgb(94, 129, 172),
        ];

        const NORD_AURORA: [egui::Color32; 5] = [
            egui::Color32::from_rgb(191, 97, 106),
            egui::Color32::from_rgb(208, 135, 112),
            egui::Color32::from_rgb(235, 203, 139),
            egui::Color32::from_rgb(163, 190, 140),
            egui::Color32::from_rgb(180, 142, 173),
        ];

        let mut style = (*ctx.style()).clone();
        let mut visuals = egui::Visuals::dark();

        visuals.window_fill = NORD_POLAR_NIGHT[0];
        visuals.panel_fill = NORD_POLAR_NIGHT[0];
        visuals.faint_bg_color = NORD_POLAR_NIGHT[1];
        visuals.extreme_bg_color = NORD_POLAR_NIGHT[0];
        visuals.code_bg_color = NORD_POLAR_NIGHT[1];

        visuals.override_text_color = Some(NORD_SNOW_STORM[2]);

        visuals.widgets.noninteractive.bg_fill = NORD_POLAR_NIGHT[1];
        visuals.widgets.noninteractive.weak_bg_fill = NORD_POLAR_NIGHT[0];
        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.5, NORD_POLAR_NIGHT[3]);
        visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.5, NORD_POLAR_NIGHT[2]);

        visuals.widgets.inactive.bg_fill = NORD_POLAR_NIGHT[2];
        visuals.widgets.inactive.weak_bg_fill = NORD_POLAR_NIGHT[1];
        visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.5, NORD_SNOW_STORM[1]);
        visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.5, NORD_POLAR_NIGHT[3]);

        visuals.widgets.hovered.bg_fill = NORD_POLAR_NIGHT[3];
        visuals.widgets.hovered.weak_bg_fill = NORD_FROST[3].gamma_multiply(0.4);
        visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, NORD_SNOW_STORM[2]);
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(2.0, NORD_FROST[3]);

        visuals.widgets.active.bg_fill = NORD_FROST[3].gamma_multiply(0.5);
        visuals.widgets.active.weak_bg_fill = NORD_FROST[3].gamma_multiply(0.6);
        visuals.widgets.active.fg_stroke = egui::Stroke::new(1.5, NORD_SNOW_STORM[2]);
        visuals.widgets.active.bg_stroke = egui::Stroke::new(2.5, NORD_FROST[3]);

        visuals.widgets.open.bg_fill = NORD_POLAR_NIGHT[2];
        visuals.widgets.open.weak_bg_fill = NORD_POLAR_NIGHT[1];
        visuals.widgets.open.fg_stroke = egui::Stroke::new(1.5, NORD_SNOW_STORM[1]);
        visuals.widgets.open.bg_stroke = egui::Stroke::new(1.5, NORD_FROST[3]);

        visuals.selection.bg_fill = NORD_FROST[3].gamma_multiply(0.5);
        visuals.selection.stroke = egui::Stroke::new(1.5, NORD_FROST[3]);

        visuals.hyperlink_color = NORD_FROST[1];

        visuals.error_fg_color = NORD_AURORA[0];
        visuals.warn_fg_color = NORD_AURORA[2];

        visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.5, NORD_POLAR_NIGHT[3]);

        style.spacing.button_padding = egui::vec2(8.0, 6.0);
        style.spacing.menu_margin = egui::Margin::same(8);
        style.spacing.indent = 16.0;
        style.spacing.item_spacing = egui::vec2(8.0, 4.0);
        style.spacing.window_margin = egui::Margin::same(12);
        style.spacing.combo_height = 32.0;
        style.spacing.text_edit_width = 200.0;
        style.spacing.tooltip_width = 600.0;
        style.spacing.interact_size = egui::vec2(120.0, 32.0);

        style.text_styles.insert(
            TextStyle::Heading,
            egui::FontId::new(30.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Body,
            egui::FontId::new(17.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Button,
            egui::FontId::new(15.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Monospace,
            egui::FontId::new(14.0, egui::FontFamily::Monospace)
        );
        style.text_styles.insert(
            TextStyle::Small,
            egui::FontId::new(11.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            egui::TextStyle::Name("ExtraSmall".into()),
            egui::FontId::new(15.0, egui::FontFamily::Proportional)
        );

        visuals.window_fill = visuals.window_fill.gamma_multiply(0.95);

        ctx.set_visuals(visuals);
        ctx.set_style(style);
    }

    fn show_main_configuration_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.show_unified_layout(ui, ctx);
    }

    fn show_unified_layout(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        egui::SidePanel
            ::left("control_panel")
            .exact_width(300.0)
            .resizable(false)
            .show_inside(ui, |ui| {
                self.show_compact_control_panel(ui, ctx);
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            let card_spacing = 8.0;

            ui.horizontal(|ui| {
                let half_width = (ui.available_width() - card_spacing) / 2.0;

                ui.vertical(|ui| {
                    ui.set_min_width(half_width);
                    ui.set_max_width(half_width);
                    ui.set_min_height(320.0);
                    ui.set_max_height(320.0);
                    self.show_discovery_card(ui);
                });

                ui.add_space(card_spacing);

                ui.vertical(|ui| {
                    ui.set_min_width(half_width);
                    ui.set_max_width(half_width);
                    ui.set_min_height(320.0);
                    ui.set_max_height(320.0);
                    self.show_console_card(ui);
                });
            });

            ui.add_space(card_spacing);

            ui.vertical(|ui| {
                let remaining_height = ui.available_height() - 8.0;
                ui.set_min_height(remaining_height);
                ui.set_max_height(remaining_height);
                self.show_results_card(ui);
            });
        });
    }

    fn show_compact_control_panel(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) {
        const NORD_GREEN: egui::Color32 = egui::Color32::from_rgb(163, 190, 140);
        const NORD_RED: egui::Color32 = egui::Color32::from_rgb(191, 97, 106);
        
        let dimensions = Self::get_responsive_dimensions(ui);

        egui::ScrollArea
            ::vertical()
            .id_salt("control_panel_scroll")
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                ui.vertical_centered(|ui| {
                    ui.add_space(1.0);
                    ui.label(
                        egui::RichText
                            ::new("Axis Auto Config")
                            .text_style(egui::TextStyle::Heading)
                            .size(20.0)
                    );
                    ui.add_space(1.0);
                });

                ui.separator();
                ui.add_space(3.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Interface:").size(14.0));
                    ui.add_space(2.0);
                    egui::ComboBox
                        ::from_label("")
                        .width(110.0)
                        .selected_text(
                            self.selected_interface
                                .and_then(|i| self.dhcp_interfaces.get(i))
                                .map(|iface| format!("{} ({})", iface.name, iface.ipv4))
                                .unwrap_or_else(|| "Select...".to_string())
                        )
                        .show_ui(ui, |ui| {
                            for (i, interface) in self.dhcp_interfaces.iter().enumerate() {
                                let text = format!("{} ({})", interface.name, interface.ipv4);
                                ui.selectable_value(&mut self.selected_interface, Some(i), text);
                            }
                        });
                });

                ui.add_space(1.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Start DHCP:").size(14.0));
                    ui.add_space(2.0);

                    let mut dhcp_enabled = self.dhcp_running;
                    if Self::toggle_switch(ui, &mut dhcp_enabled, egui::vec2(40.0, 20.0)).changed() {
                        if dhcp_enabled {
                            self.start_dhcp_server();
                        } else {
                            self.stop_dhcp_server();
                        }
                    }
                });

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(3.0);

                ui.label(egui::RichText::new("Configuration").size(15.0).strong());
                ui.add_space(1.0);

                ui.label(egui::RichText::new("IP Range:").size(15.0));
                ui.add_sized(
                    [ui.available_width(), 20.0],
                    egui::TextEdit
                        ::singleline(&mut self.ip_range_input)
                        .font(egui::TextStyle::Name("ExtraSmall".into()))
                );

                ui.add_space(1.0);

                ui.label(egui::RichText::new("Subnet:").size(15.0));
                ui.add_sized(
                    [ui.available_width(), 20.0],
                    egui::TextEdit
                        ::singleline(&mut self.camera_subnet_mask)
                        .font(egui::TextStyle::Name("ExtraSmall".into()))
                );

                ui.add_space(1.0);

                ui.label(egui::RichText::new("Gateway:").size(15.0));
                ui.add_sized(
                    [ui.available_width(), 20.0],
                    egui::TextEdit
                        ::singleline(&mut self.camera_gateway)
                        .font(egui::TextStyle::Name("ExtraSmall".into()))
                );

                ui.add_space(1.0);

                ui.label(egui::RichText::new("Password:").size(15.0));
                ui.add_sized(
                    [ui.available_width(), 20.0],
                    egui::TextEdit
                        ::singleline(&mut self.admin_password)
                        .password(true)
                        .font(egui::TextStyle::Name("ExtraSmall".into()))
                );

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(3.0);

                ui.label(egui::RichText::new("Firmware").size(15.0).strong());
                ui.add_space(1.0);

                if self.firmware_entries.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label("No firmware files");
                        if ui.small_button("➕").clicked() {
                            self.firmware_entries.push(FirmwareEntry {
                                file_path: None,
                                compatible_models: String::new(),
                                is_loaded: false,
                            });
                        }
                    });
                } else {
                    let mut should_reload = false;
                    let mut file_dialog_for_index = None;
                    let mut remove_index = None;

                    egui::ScrollArea
                        ::vertical()
                        .id_salt("firmware_files_scroll")
                        .auto_shrink([false; 2])
                        .max_height(120.0) // Show about 3 entries then scroll
                        .show(ui, |ui| {
                            for (i, entry) in self.firmware_entries.iter_mut().enumerate() {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        if let Some(path) = &entry.file_path {
                                            ui.label(
                                                path
                                                    .file_name()
                                                    .unwrap()
                                                    .to_string_lossy()
                                                    .chars()
                                                    .take(15)
                                                    .collect::<String>()
                                            );
                                            if entry.is_loaded {
                                                ui.colored_label(NORD_GREEN, "✅");
                                            } else {
                                                ui.colored_label(NORD_RED, "❌");
                                            }
                                        } else {
                                            ui.label("No file");
                                        }

                                        if ui.small_button("🔍").clicked() {
                                            file_dialog_for_index = Some(i);
                                        }

                                        if ui.small_button("➖").clicked() {
                                            remove_index = Some(i);
                                        }
                                    });

                                    ui.add_space(2.0);
                                });
                            }
                        });

                    // Handle removal
                    if let Some(index) = remove_index {
                        self.firmware_entries.remove(index);
                        should_reload = true;
                    }

                    if let Some(i) = file_dialog_for_index {
                        if
                            let Some(path) = rfd::FileDialog
                                ::new()
                                .add_filter("Firmware files", &["bin"])
                                .pick_file()
                        {
                            if let Some(entry) = self.firmware_entries.get_mut(i) {
                                // Load firmware immediately when selected
                                let filename = path.file_name().unwrap().to_string_lossy().to_string();
                                
                                match std::fs::read(&path) {
                                    Ok(firmware_data) => {

                                        // Determine compatible models
                                        let compatible_models: Vec<String> = if
                                            let Some(extracted_model) =
                                                ModelFirmwareMapping::extract_model_from_firmware_filename(&filename)
                                        {
                                            vec![extracted_model.clone()]
                                        } else {
                                            vec!["auto-detect".to_string()]
                                        };

                                        // Add to firmware mapping immediately
                                        self.firmware_mapping.add_firmware_data(
                                            filename.clone(),
                                            std::sync::Arc::new(firmware_data),
                                            compatible_models.clone()
                                        );

                                        // Update entry
                                        entry.file_path = Some(path);
                                        entry.is_loaded = true;
                                        
                                        // Auto-populate compatible models if empty
                                        if entry.compatible_models.trim().is_empty() && 
                                           compatible_models.len() == 1 && 
                                           compatible_models[0] != "auto-detect" {
                                            entry.compatible_models = compatible_models[0].clone();
                                        }
                                    }
                                    Err(_) => {
                                        entry.file_path = Some(path);
                                        entry.is_loaded = false;
                                    }
                                }
                            }
                        }
                    }

                    if should_reload {
                        self.load_firmware_files();
                    }

                    ui.add_space(4.0);
                    if ui.button("Add Firmware").clicked() {
                        self.firmware_entries.push(FirmwareEntry {
                            file_path: None,
                            compatible_models: String::new(),
                            is_loaded: false,
                        });
                    }
                }

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(3.0);

                // File Import Section
                ui.label(egui::RichText::new("CSV/Excel Import").size(15.0).strong());
                ui.add_space(1.0);

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("File:").size(15.0));
                        ui.add_space(2.0);
                        let available_width = ui.available_width() - 50.0; // Reserve space for Browse button
                        ui.add_sized(
                            [available_width.max(130.0), 20.0],
                            egui::TextEdit
                                ::singleline(&mut self.csv_import_file_path)
                                .font(egui::TextStyle::Name("ExtraSmall".into()))
                        );
                    });
                    ui.add_space(1.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔍").clicked() {
                            if
                                let Some(path) = rfd::FileDialog
                                    ::new()
                                    .add_filter("Excel files", &["xlsx"])
                                    .add_filter("CSV files", &["csv"])
                                    .add_filter("All supported", &["xlsx", "csv"])
                                    .pick_file()
                            {
                                self.csv_import_file_path = path.to_string_lossy().to_string();
                                self.load_csv_file();
                            }
                        }

                        if !self.csv_import_file_path.is_empty() {
                            ui.add_space(2.0);
                            if ui.button("Load").clicked() {
                                self.load_csv_file();
                            }
                        }
                    });
                });

                if !self.imported_csv_data.is_empty() {
                    ui.add_space(1.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(46, 204, 113),
                        format!("Loaded {} entries", self.imported_csv_data.len())
                    );
                }

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(3.0);

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(3.0);

                let passwords_valid = !self.admin_password.is_empty();
                let network_valid =
                    !self.camera_subnet_mask.is_empty() &&
                    !self.camera_gateway.is_empty() &&
                    self.camera_subnet_mask.parse::<std::net::Ipv4Addr>().is_ok() &&
                    self.camera_gateway.parse::<std::net::Ipv4Addr>().is_ok();
                let ip_range_valid = !self.ip_range_input.is_empty();

                let can_start =
                    passwords_valid && network_valid && ip_range_valid && self.dhcp_running;

                if
                    ui
                        .add_enabled(
                            can_start,
                            Self::create_button(
                                "Start Configuration",
                                egui::vec2(ui.available_width() - dimensions.base_spacing * 2.0, dimensions.button_height)
                            )
                        )
                        .clicked()
                {
                    self.current_screen = Screen::Processing;
                    self.start_camera_configuration();
                }

                if !can_start {
                    ui.add_space(2.0);
                    if !self.dhcp_running {
                        ui.colored_label(NORD_RED, "Start DHCP first");
                    } else if !passwords_valid {
                        ui.colored_label(NORD_RED, "Enter password");
                    } else if !network_valid {
                        ui.colored_label(NORD_RED, "Configure network");
                    } else if !ip_range_valid {
                        ui.colored_label(NORD_RED, "Enter IP range");
                    }
                }
            });
    }

    fn create_highlighted_card_frame(
        ui: &mut egui::Ui,
        title: &str,
        content: impl FnOnce(&mut egui::Ui)
    ) {
        let mut card_color = ui.visuals().window_fill;
        card_color = card_color.gamma_multiply(1.1);

        let card_frame = egui::Frame
            ::default()
            .fill(card_color)
            .stroke(egui::Stroke::new(1.0, ui.visuals().window_stroke.color))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::same(16)) // Reduced from 20 to 16 for more compact layout
            .outer_margin(egui::Margin::same(4)) // Reduced from 6 to 4 for uniform spacing
            .shadow(egui::epaint::Shadow {
                offset: [0, 2],
                blur: 6,
                spread: 0,
                color: egui::Color32::from_black_alpha(20),
            });
        card_frame.show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.strong(title);
                });
                ui.add_space(8.0);
                content(ui);
            });
        });
    }

    fn show_discovery_card(&mut self, ui: &mut egui::Ui) {
        const NORD_GREEN: egui::Color32 = egui::Color32::from_rgb(163, 190, 140);
        const NORD_RED: egui::Color32 = egui::Color32::from_rgb(191, 97, 106);

        Self::create_highlighted_card_frame(ui, "Discovery", |ui| {
            ui.horizontal(|ui| {
                ui.label("Status:");
                if self.discovery_in_progress {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Scanning...");
                    });
                } else {
                    ui.label("Idle");
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔄").clicked() && !self.discovery_in_progress {
                        self.start_camera_discovery();
                    }
                });
            });

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("Cameras:");
                ui.strong(format!("{} found", self.discovered_cameras.len()));
            });

            ui.add_space(8.0);

            ui.strong("Discovered Cameras:");
            ui.add_space(4.0);
            egui::ScrollArea
                ::vertical()
                .id_salt("discovery_cameras_scroll")
                .auto_shrink([false; 2])
                .max_height(190.0)
                .show(ui, |ui| {
                    if !self.discovered_cameras.is_empty() {
                        for camera in &self.discovered_cameras {
                            ui.horizontal(|ui| {
                                let status_color = if camera.status == "discovered" {
                                    NORD_GREEN
                                } else {
                                    NORD_RED
                                };
                                if camera.status == "discovered" {
                                    ui.colored_label(NORD_GREEN, "✅");
                                } else {
                                    ui.colored_label(NORD_RED, "❌");
                                }
                                ui.add_space(12.0);
                                ui.label(&camera.ip);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if let Some(model) = &camera.model_name {
                                            ui.label(model);
                                        } else {
                                            ui.colored_label(
                                                ui.visuals().weak_text_color(),
                                                "Detecting..."
                                            );
                                        }
                                    }
                                );
                            });
                        }
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(60.0);
                            ui.label("No cameras found");
                            ui.add_space(8.0);
                            ui.colored_label(
                                ui.visuals().weak_text_color(),
                                "Connect cameras and start DHCP"
                            );
                        });
                    }
                });
        });
    }

    fn show_console_card(&mut self, ui: &mut egui::Ui) {
        Self::create_highlighted_card_frame(ui, "Console", |ui| {
            egui::ScrollArea
                ::vertical()
                .id_salt("console_logs_scroll")
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .max_height(240.0)
                .show(ui, |ui| {
                    if !self.processing_logs.is_empty() {
                        for log in &self.processing_logs {
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::TOP).with_main_wrap(true),
                                |ui| {
                                    ui.label(
                                        egui::RichText::new(log).text_style(egui::TextStyle::Small)
                                    );
                                }
                            );
                            ui.add_space(1.0);
                        }
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(80.0);
                            ui.label("Console logs will appear here");
                            ui.add_space(4.0);
                            ui.colored_label(
                                ui.visuals().weak_text_color(),
                                "Start configuration to see progress"
                            );
                        });
                    }
                });
        });
    }

    fn show_results_card(&mut self, ui: &mut egui::Ui) {
        Self::create_highlighted_card_frame(ui, "Results", |ui| {
            ui.vertical(|ui| {
                // Header with export buttons
                ui.horizontal(|ui| {
                    ui.strong("Export Results:");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Export Excel").clicked() {
                            if
                                let Some(path) = rfd::FileDialog
                                    ::new()
                                    .add_filter("Excel files", &["xlsx"])
                                    .set_file_name("camera_configuration_results.xlsx")
                                    .save_file()
                            {
                                self.export_results_to_file(path);
                            }
                        }
                        ui.add_space(4.0);
                        if ui.button("Export CSV").clicked() {
                            if
                                let Some(path) = rfd::FileDialog
                                    ::new()
                                    .add_filter("CSV files", &["csv"])
                                    .set_file_name("camera_configuration_results.csv")
                                    .save_file()
                            {
                                self.export_results_to_file(path);
                            }
                        }
                    });
                });

                ui.add_space(8.0);

                // Main content area that fills available space
                let available_height = ui.available_height() - 50.0; // Reserve space for reset button

                egui::ScrollArea
                    ::vertical()
                    .id_salt("results_scroll")
                    .auto_shrink([false; 2])
                    .max_height(available_height)
                    .show(ui, |ui| {
                        if !self.processing_results.is_empty() {
                            egui::Grid
                                ::new("results_grid")
                                .num_columns(6)
                                .striped(true)
                                .spacing([8.0, 4.0])
                                .show(ui, |ui| {
                                    ui.strong("IP Address");
                                    ui.strong("MAC Address");
                                    ui.strong("Serial");
                                    ui.strong("Model");
                                    ui.strong("Firmware");
                                    ui.strong("Status");
                                    ui.end_row();

                                    for result in &self.processing_results {
                                        ui.label(&result.ip_address);
                                        ui.label(result.mac_address.as_deref().unwrap_or("-"));
                                        ui.label(result.serial.as_deref().unwrap_or("-"));
                                        ui.label(result.item_name.as_deref().unwrap_or("-"));
                                        ui.label(result.firmware_version.as_deref().unwrap_or("-"));
                                        ui.label(&result.status);
                                        ui.end_row();
                                    }
                                });
                        } else {
                            ui.vertical_centered(|ui| {
                                ui.add_space(60.0);
                                ui.label("Configuration results will appear here");
                                ui.add_space(8.0);
                                ui.colored_label(
                                    ui.visuals().weak_text_color(),
                                    "Complete camera configuration to see results"
                                );
                            });
                        }
                    });

                // Reset button at bottom right
                ui.add_space(8.0);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Reset & Clear Data").clicked() {
                        self.reset_all_data();
                    }
                });
            });
        });
    }

    fn show_processing_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.show_unified_layout(ui, ctx);
    }

    fn reset_all_data(&mut self) {
        // Clear all data from the last run
        self.processing_logs.clear();
        self.processing_results.clear();
        self.discovered_cameras.clear();
        self.dhcp_leases.clear();

        // Reset processing state
        self.processing_in_progress = false;
        self.discovery_in_progress = false;
        self.last_scan_time = None;

        // Reset screen to main configuration
        self.current_screen = Screen::MainConfiguration;

        // Clear any active channels
        if let Some(channels) = &mut self.channels {
            channels.discovery_rx = None;
            channels.discovery_complete_rx = None;
            channels.processing_log_rx = None;
            channels.processing_result_rx = None;
            channels.processing_complete_rx = None;
        }

        // Restart DHCP server to clear any cached state
        if self.dhcp_running {
            self.stop_dhcp_server();
            // Give a small delay before restarting
            if let Some(rt) = &self.rt {
                rt.spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                });

                // We'll restart DHCP immediately since we have the interface selected
                if self.selected_interface.is_some() {
                    self.start_dhcp_server();
                }
            }
        }

        info!("All data cleared and DHCP server restarted");
    }

    fn start_dhcp_server(&mut self) {
        if let Some(interface_index) = self.selected_interface {
            if let Some(interface) = self.dhcp_interfaces.get(interface_index) {
                let interface_name = interface.name.clone();
                let server_ip = interface.ipv4;

                let server_u32 = u32::from(server_ip);
                let network_base = server_u32 & 0xffffff00;
                // DHCP assigns IPs in range .50 to .200 to avoid conflicts with common static assignments
                let start_ip = std::net::Ipv4Addr::from(network_base | 50);
                let end_ip = std::net::Ipv4Addr::from(network_base | 200);

                if let Some(rt) = &self.rt {
                    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
                    self.dhcp_shutdown_tx = Some(shutdown_tx);

                    let (lease_tx, lease_rx) = mpsc::unbounded_channel::<Vec<DhcpLease>>();
                    if let Some(channels) = &mut self.channels {
                        channels.lease_refresh_rx = Some(lease_rx);
                        channels.lease_update_tx = Some(lease_tx.clone());
                    }

                    let dhcp_manager = Arc::new(Mutex::new(DhcpManager::new()));
                    self.dhcp_manager = Some(dhcp_manager.clone());

                    rt.spawn(async move {
                        let config_result = {
                            let mut mgr = dhcp_manager.lock().await;
                            mgr.configure(
                                interface_name.clone(),
                                server_ip,
                                start_ip,
                                end_ip,
                                Duration::from_secs(3600)
                            ).await
                        };

                        match config_result {
                            Ok(()) => {
                                info!("DHCP manager configured successfully on interface: {}", interface_name);

                                let mgr = dhcp_manager.lock().await;
                                if
                                    let Err(e) = mgr.start_with_lease_updates(
                                        shutdown_rx,
                                        Some(lease_tx)
                                    ).await
                                {
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
        if let Some(channels) = &mut self.channels {
            channels.lease_update_tx = None;
            channels.lease_refresh_rx = None;
        }
        info!("DHCP server stopped");
    }

    fn start_camera_discovery(&mut self) {
        if self.discovery_in_progress {
            return;
        }

        self.discovery_in_progress = true;
        self.discovered_cameras.clear();

        let (discovery_tx, discovery_rx) = mpsc::unbounded_channel::<Vec<DeviceInfo>>();
        let (complete_tx, complete_rx) = mpsc::unbounded_channel::<bool>();

        if let Some(channels) = &mut self.channels {
            channels.discovery_rx = Some(discovery_rx);
            channels.discovery_complete_rx = Some(complete_rx);
        }

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
        if let Some(channels) = &mut self.channels {
            if let Some(rx) = &mut channels.discovery_rx {
                while let Ok(mut cameras) = rx.try_recv() {
                for camera in &mut cameras {
                    for lease in &self.dhcp_leases {
                        if lease.ip.to_string() == camera.ip {
                            camera.mac_address = Some(
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
                            info!(
                                "Assigned MAC address to camera at {}: {}",
                                camera.ip,
                                camera.mac_address.as_ref().unwrap()
                            );
                            break;
                        }
                    }

                    if camera.mac_address.is_none() {
                        info!(
                            "No MAC address found in DHCP leases for camera at {}. Available leases: {}",
                            camera.ip,
                            self.dhcp_leases
                                .iter()
                                .map(|l| l.ip.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                    }
                }

                for new_camera in cameras {
                    if
                        let Some(existing_camera) = self.discovered_cameras
                            .iter_mut()
                            .find(|c| c.ip == new_camera.ip)
                    {
                        if
                            existing_camera.mac_address.is_none() &&
                            new_camera.mac_address.is_some()
                        {
                            existing_camera.mac_address = new_camera.mac_address.clone();
                        }
                        existing_camera.status = new_camera.status;
                        existing_camera.device_type = new_camera.device_type;
                        existing_camera.server_header = new_camera.server_header;
                        existing_camera.authentication_type = new_camera.authentication_type;
                        existing_camera.response_time_ms = new_camera.response_time_ms;
                        existing_camera.model_name = new_camera.model_name;
                    } else {
                        self.discovered_cameras.push(new_camera);
                    }
                }

                // Prevent memory bloat in large deployments by limiting camera list size
                // Use capacity management instead of truncation to avoid frequent reallocations
                if self.discovered_cameras.len() > 100 {
                    self.discovered_cameras.drain(0..25);
                    self.discovered_cameras.shrink_to_fit();
                }
            }
        }

            if let Some(rx) = &mut channels.discovery_complete_rx {
                if rx.try_recv().is_ok() {
                    self.discovery_in_progress = false;
                    channels.discovery_rx = None;
                    channels.discovery_complete_rx = None;
                info!(
                    "Camera discovery completed. Found {} cameras (DHCP leases: {})",
                    self.discovered_cameras.len(),
                    self.dhcp_leases.len()
                );
            }
        }

            if let Some(rx) = &mut channels.processing_log_rx {
                while let Ok(log_message) = rx.try_recv() {
                    self.processing_logs.push(log_message);
                    if self.processing_logs.len() > 200 {
                        self.processing_logs.drain(0..100);
                        self.processing_logs.shrink_to_fit();
                    }
                }
            }

            if let Some(rx) = &mut channels.processing_result_rx {
                while let Ok(result) = rx.try_recv() {
                    self.processing_results.push(result);
                    if self.processing_results.len() > 75 {
                        self.processing_results.drain(0..25);
                        self.processing_results.shrink_to_fit();
                    }
                }
            }

            if let Some(rx) = &mut channels.processing_complete_rx {
                if rx.try_recv().is_ok() {
                    self.processing_in_progress = false;
                    channels.processing_log_rx = None;
                    channels.processing_result_rx = None;
                    channels.processing_complete_rx = None;
                info!("Camera configuration completed!");
            }
        }

            if let Some(rx) = &mut channels.lease_refresh_rx {
                while let Ok(leases) = rx.try_recv() {
                    self.dhcp_leases = leases;
                    info!("DHCP leases updated: {} active leases", self.dhcp_leases.len());

                    for camera in &mut self.discovered_cameras {
                        if camera.mac_address.is_none() {
                            for lease in &self.dhcp_leases {
                                if lease.ip.to_string() == camera.ip {
                                    camera.mac_address = Some(
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
                                    info!(
                                        "Updated MAC address for camera at {}: {}",
                                        camera.ip,
                                        camera.mac_address.as_ref().unwrap()
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Create camera list ordered by DHCP lease assignment order
    fn create_dhcp_ordered_camera_list(&self) -> Vec<DeviceInfo> {
        let mut ordered_cameras = Vec::new();
        
        // First, create a map of MAC addresses to cameras
        let mut mac_to_camera: std::collections::HashMap<String, DeviceInfo> = std::collections::HashMap::new();
        for camera in &self.discovered_cameras {
            if let Some(mac) = &camera.mac_address {
                mac_to_camera.insert(mac.clone(), camera.clone());
            }
        }
        
        // Sort DHCP leases by lease start time to get the order cameras were plugged in
        let mut sorted_leases = self.dhcp_leases.clone();
        sorted_leases.sort_by(|a, b| a.lease_start.cmp(&b.lease_start));
        
        // Add cameras in DHCP lease order
        for lease in sorted_leases {
            let mac_str = format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                lease.mac[0], lease.mac[1], lease.mac[2], 
                lease.mac[3], lease.mac[4], lease.mac[5]
            );
            
            if let Some(camera) = mac_to_camera.remove(&mac_str) {
                ordered_cameras.push(camera);
            }
        }
        
        // Add any remaining cameras that don't have DHCP leases (shouldn't happen but safety net)
        for camera in &self.discovered_cameras {
            if let Some(mac) = &camera.mac_address {
                if mac_to_camera.contains_key(mac) {
                    ordered_cameras.push(camera.clone());
                }
            } else {
                // Camera without MAC address, add to end
                ordered_cameras.push(camera.clone());
            }
        }
        
        info!(
            "Ordered {} cameras by DHCP lease assignment order (original: {})",
            ordered_cameras.len(),
            self.discovered_cameras.len()
        );
        
        ordered_cameras
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

        if let Some(channels) = &mut self.channels {
            channels.processing_log_rx = Some(log_rx);
            channels.processing_result_rx = Some(result_rx);
            channels.processing_complete_rx = Some(complete_rx);
        }

        let target_ips = match self.parse_ip_range(&self.ip_range_input) {
            Ok(ips) => ips,
            Err(e) => {
                self.processing_logs.push(
                    format!("[{}] Error parsing IP range: {}", Utc::now().format("%H:%M:%S"), e)
                );
                self.processing_in_progress = false;
                return;
            }
        };

        // Create ordered camera list based on DHCP lease order
        let ordered_cameras = self.create_dhcp_ordered_camera_list();
        
        // Use Arc to share data instead of cloning
        let discovered_cameras = Arc::new(ordered_cameras);
        let dhcp_manager_ref = self.dhcp_manager.clone();
        let config_data = Arc::new(ConfigData {
            admin_password: self.admin_password.clone(),
            camera_subnet_mask: self.camera_subnet_mask.clone(),
            camera_gateway: self.camera_gateway.clone(),
            firmware_mapping: self.firmware_mapping.clone(),
            target_ips: Arc::new(target_ips),
        });

        if let Some(rt) = &self.rt {
            rt.spawn(async move {
                let _ = log_tx.send(
                    format!("[{}] Initializing camera operations...", Utc::now().format("%H:%M:%S"))
                );

                let has_firmware = !config_data.firmware_mapping.firmware_files.is_empty();
                if has_firmware {
                    let _ = log_tx.send(
                        format!(
                            "[{}] {} firmware file(s) loaded for model-based upgrades",
                            Utc::now().format("%H:%M:%S"),
                            config_data.firmware_mapping.firmware_files.len()
                        )
                    );
                }

                // Increase concurrent camera operations for faster processing
                let semaphore = Arc::new(Semaphore::new(15));

                let mut handles = Vec::new();

                let total_cameras = discovered_cameras.len();

                for (index, camera) in discovered_cameras.iter().enumerate() {
                    let log_tx_clone = log_tx.clone();
                    let result_tx_clone = result_tx.clone();
                    let semaphore_clone = Arc::clone(&semaphore);
                    let config_data_clone = Arc::clone(&config_data);
                    let dhcp_manager_clone = dhcp_manager_ref.clone();
                    let camera_clone = camera.clone();

                    let handle = tokio::spawn(async move {
                        let _permit = semaphore_clone
                            .acquire().await
                            .expect("Semaphore acquire failed");

                        let camera_start_time = std::time::Instant::now();
                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] 🚀 Starting configuration for camera {}/{} (IP: {})",
                                Utc::now().format("%H:%M:%S"),
                                index + 1,
                                total_cameras,
                                camera_clone.ip
                            )
                        );

                        let camera_ops = match CameraOperations::new() {
                            Ok(ops) => ops,
                            Err(e) => {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Failed to initialize camera operations for {}: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera_clone.ip,
                                        e
                                    )
                                );
                                let camera_data = CameraInventoryData {
                                    ip_address: camera_clone.ip.clone(),
                                    subnet: config_data_clone.camera_subnet_mask.clone(),
                                    gateway: config_data_clone.camera_gateway.clone(),
                                    user_name: ROOT_USERNAME.to_string(),
                                    password: config_data_clone.admin_password.clone(),
                                    completion_time: Utc::now(),
                                    status: FAILED_INIT_STATUS.to_string(),
                                    device_map: None,
                                    ..Default::default()
                                };
                                let _ = result_tx_clone.send(camera_data);
                                return;
                            }
                        };

                        let camera_ip = match camera_clone.ip.parse::<std::net::Ipv4Addr>() {
                            Ok(ip) => ip,
                            Err(e) => {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Invalid IP address {}: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera_clone.ip,
                                        e
                                    )
                                );
                                let camera_data = CameraInventoryData {
                                    ip_address: camera_clone.ip.clone(),
                                    subnet: config_data_clone.camera_subnet_mask.clone(),
                                    gateway: config_data_clone.camera_gateway.clone(),
                                    user_name: ROOT_USERNAME.to_string(),
                                    password: config_data_clone.admin_password.clone(),
                                    completion_time: Utc::now(),
                                    status: FAILED_INVALID_IP_STATUS.to_string(),
                                    device_map: None,
                                    ..Default::default()
                                };
                                let _ = result_tx_clone.send(camera_data);
                                return;
                            }
                        };

                        let mut camera_data = CameraInventoryData {
                            ip_address: camera_clone.ip.clone(),
                            subnet: config_data_clone.camera_subnet_mask.clone(),
                            gateway: config_data_clone.camera_gateway.clone(),
                            mac_address: camera_clone.mac_address.clone(),
                            serial: None,
                            firmware_version: None,
                            item_name: None,
                            user_name: "root".to_string(),
                            password: config_data_clone.admin_password.clone(),
                            device_map: None,
                            completion_time: Utc::now(),
                            status: PROCESSING_STATUS.to_owned(),
                            operations: OperationResults::default(),
                            tool_version: TOOL_VERSION.to_string(),
                        };

                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] Creating admin user for {}",
                                Utc::now().format("%H:%M:%S"),
                                camera_clone.ip
                            )
                        );

                        match
                            camera_ops.create_initial_admin(
                                camera_ip,
                                "root",
                                &config_data_clone.admin_password,
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
                                        camera_clone.ip
                                    )
                                );

                                match
                                    camera_ops.get_device_info(
                                        camera_ip,
                                        "root",
                                        &config_data_clone.admin_password,
                                        camera_operations::Protocol::Http
                                    ).await
                                {
                                    Ok(device_info) => {
                                        if let Some(model_obj) = device_info.get("ProdNbr") {
                                            if let Some(model_str) = model_obj.as_str() {
                                                camera_data.item_name = Some(model_str.to_string());
                                                let _ = log_tx_clone.send(
                                                    format!(
                                                        "[{}] Detected camera model: {} for {}",
                                                        Utc::now().format("%H:%M:%S"),
                                                        model_str,
                                                        camera_clone.ip
                                                    )
                                                );
                                            }
                                        }
                                        if let Some(fw_obj) = device_info.get("Version") {
                                            if let Some(fw_str) = fw_obj.as_str() {
                                                camera_data.firmware_version = Some(
                                                    fw_str.to_string()
                                                );
                                            }
                                        }
                                        if let Some(serial_obj) = device_info.get("SerialNumber") {
                                            if let Some(serial_str) = serial_obj.as_str() {
                                                camera_data.serial = Some(serial_str.to_string());
                                            }
                                        }
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Device info retrieved for {} (Model: {}, FW: {})",
                                                Utc::now().format("%H:%M:%S"),
                                                camera_clone.ip,
                                                camera_data.item_name
                                                    .as_deref()
                                                    .unwrap_or("Unknown"),
                                                camera_data.firmware_version
                                                    .as_deref()
                                                    .unwrap_or("Unknown")
                                            )
                                        );
                                    }
                                    Err(e) => {
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Could not get device info for {}: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                camera_clone.ip,
                                                e
                                            )
                                        );
                                    }
                                }

                                if camera_data.mac_address.is_none() {
                                    match
                                        camera_ops.get_network_interface_info(
                                            camera_ip,
                                            "root",
                                            &config_data_clone.admin_password,
                                            camera_operations::Protocol::Http
                                        ).await
                                    {
                                        Ok(Some(mac_addr)) => {
                                            camera_data.mac_address = Some(mac_addr);
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] MAC address retrieved via VAPIX for {}: {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera_clone.ip,
                                                    camera_data.mac_address
                                                        .as_deref()
                                                        .unwrap_or("Unknown")
                                                )
                                            );
                                        }
                                        Ok(None) => {
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] Could not retrieve MAC address via VAPIX for {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera_clone.ip
                                                )
                                            );
                                        }
                                        Err(e) => {
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] Error getting MAC address for {}: {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera_clone.ip,
                                                    e
                                                )
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                camera_data.operations.create_admin = Some(
                                    OperationResult::failure(e.to_string())
                                );
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] ❌ Failed to create admin user for {}: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        camera_clone.ip,
                                        e
                                    )
                                );
                            }
                        }

                        let admin_success = camera_data.operations.create_admin
                            .as_ref()
                            .map(|op| op.success)
                            .unwrap_or(false);

                        if !admin_success {
                            camera_data.status = "Failed - Admin User".to_string();
                            let _ = result_tx_clone.send(camera_data);
                            return;
                        }

                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] ⏱️ Admin user created, waiting 1s for activation on {}",
                                Utc::now().format("%H:%M:%S"),
                                camera_clone.ip
                            )
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;

                        if !config_data_clone.firmware_mapping.firmware_files.is_empty() {
                            let model_name = camera_data.item_name.as_deref().unwrap_or("Unknown");
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] 🔍 Checking firmware compatibility for {} (Model: {})...",
                                    Utc::now().format("%H:%M:%S"),
                                    camera_clone.ip,
                                    model_name
                                )
                            );

                            // Check if we have compatible firmware before attempting upgrade
                            if
                                let Some(firmware_file) =
                                    config_data_clone.firmware_mapping.find_firmware_for_model(model_name)
                            {
                                let firmware_start_time = std::time::Instant::now();
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] 🔄 Found compatible firmware '{}' for model '{}', starting upload to {}",
                                        Utc::now().format("%H:%M:%S"),
                                        firmware_file.filename,
                                        model_name,
                                        camera_clone.ip
                                    )
                                );

                                match
                                    camera_ops.upgrade_firmware_with_model_mapping(
                                        camera_ip,
                                        "root",
                                        &config_data_clone.admin_password,
                                        &config_data_clone.firmware_mapping,
                                        camera_operations::Protocol::Http,
                                        None
                                    ).await
                                {
                                    Ok(msg) => {
                                        let firmware_duration = firmware_start_time.elapsed();
                                        camera_data.operations.upgrade_firmware = Some(
                                            OperationResult::success(msg)
                                        );
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] ✅ Firmware upgrade completed for {} (took {:.1}s)",
                                                Utc::now().format("%H:%M:%S"),
                                                camera_clone.ip,
                                                firmware_duration.as_secs_f32()
                                            )
                                        );

                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Retrieving updated firmware version for {}...",
                                                Utc::now().format("%H:%M:%S"),
                                                camera_clone.ip
                                            )
                                        );

                                        match
                                            camera_ops.get_device_info(
                                                camera_ip,
                                                "root",
                                                &config_data_clone.admin_password,
                                                camera_operations::Protocol::Http
                                            ).await
                                        {
                                            Ok(device_info) => {
                                                if let Some(fw_obj) = device_info.get("Version") {
                                                    if let Some(fw_str) = fw_obj.as_str() {
                                                        camera_data.firmware_version = Some(
                                                            fw_str.to_string()
                                                        );
                                                        let _ = log_tx_clone.send(
                                                            format!(
                                                                "[{}] Updated firmware version for {}: {}",
                                                                Utc::now().format("%H:%M:%S"),
                                                                camera_clone.ip,
                                                                fw_str
                                                            )
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let _ = log_tx_clone.send(
                                                    format!(
                                                        "[{}] Could not get updated firmware version for {}: {}",
                                                        Utc::now().format("%H:%M:%S"),
                                                        camera_clone.ip,
                                                        e
                                                    )
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let error_string = e.to_string();
                                        camera_data.operations.upgrade_firmware = Some(
                                            OperationResult::failure(error_string.clone())
                                        );
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] ❌ Firmware upgrade failed for {}: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                camera_clone.ip,
                                                error_string
                                            )
                                        );
                                    }
                                }
                            } else {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] ⚠️ Skipping firmware upgrade for {} - no compatible firmware found for model '{}'",
                                        Utc::now().format("%H:%M:%S"),
                                        camera_clone.ip,
                                        model_name
                                    )
                                );
                                let available_models: Vec<String> =
                                    config_data_clone.firmware_mapping.firmware_files
                                        .iter()
                                        .flat_map(|fw| fw.compatible_models.iter())
                                        .cloned()
                                        .collect();
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Available firmware models: {}",
                                        Utc::now().format("%H:%M:%S"),
                                        available_models.join(", ")
                                    )
                                );
                            }
                        } else {
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] Skipping firmware upgrade for {} - no firmware files loaded",
                                    Utc::now().format("%H:%M:%S"),
                                    camera_clone.ip
                                )
                            );
                        }

                        // Get target IP based on the ordered index (DHCP lease order)
                        let target_ip_str = config_data_clone.target_ips.get(index).cloned();
                        
                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] Assigning target IP {} to camera {} (DHCP order: {})",
                                Utc::now().format("%H:%M:%S"),
                                target_ip_str.as_deref().unwrap_or("none"),
                                camera_clone.ip,
                                index + 1
                            )
                        );

                        if let Some(new_ip_str) = target_ip_str {
                            let _new_ip_addr = match new_ip_str.parse::<std::net::Ipv4Addr>() {
                                Ok(ip) => ip,
                                Err(e) => {
                                    let _ = log_tx_clone.send(
                                        format!(
                                            "[{}] ❌ Invalid target IP '{}' for {}: {}",
                                            Utc::now().format("%H:%M:%S"),
                                            new_ip_str,
                                            camera_clone.ip,
                                            e
                                        )
                                    );
                                    camera_data.operations.set_static_ip = Some(
                                        OperationResult::failure(
                                            format!("Invalid target IP: {}", new_ip_str)
                                        )
                                    );
                                    if camera_data.status == "Processing" {
                                        camera_data.status =
                                            "Partial Success - IP Invalid".to_string();
                                    }
                                    let _ = result_tx_clone.send(camera_data);
                                    return;
                                }
                            };

                            // Only configure static IP if different from current DHCP assignment
                            if new_ip_str != camera_clone.ip {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Setting static IP {} (subnet: {}, gateway: {}) for camera currently at {}",
                                        Utc::now().format("%H:%M:%S"),
                                        new_ip_str,
                                        config_data_clone.camera_subnet_mask,
                                        config_data_clone.camera_gateway,
                                        camera_clone.ip
                                    )
                                );

                                let ip_config = IpConfig {
                                    ip: new_ip_str.clone(),
                                    subnet: config_data_clone.camera_subnet_mask.clone(),
                                    gateway: config_data_clone.camera_gateway.clone(),
                                };

                                // Get camera MAC address for tracking
                                let camera_mac = camera_data.mac_address.as_deref().unwrap_or("unknown");
                                
                                // Create closure to get current DHCP leases
                                let dhcp_manager_for_closure = dhcp_manager_clone.clone();
                                let get_current_leases = move || {
                                    if let Some(manager) = dhcp_manager_for_closure.as_ref() {
                                        // Use tokio::task::block_in_place to run async code in sync context
                                        tokio::task::block_in_place(|| {
                                            tokio::runtime::Handle::current().block_on(async {
                                                manager.lock().await.get_active_leases().await
                                            })
                                        })
                                    } else {
                                        Vec::new()
                                    }
                                };

                                match
                                    camera_ops.set_final_static_ip_with_mac_tracking(
                                        camera_ip, // Current IP for the request
                                        "root",
                                        &config_data_clone.admin_password,
                                        &ip_config,
                                        camera_operations::Protocol::Http,
                                        camera_mac,
                                        get_current_leases
                                    ).await
                                {
                                    Ok((msg, new_dhcp_ip)) => {
                                        camera_data.operations.set_static_ip = Some(
                                            OperationResult::success(msg.clone())
                                        );
                                        camera_data.ip_address = new_ip_str.clone();
                                        
                                        if let Some(dhcp_ip) = new_dhcp_ip {
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] ✅ Camera moved to new DHCP IP {} after configuration (target static IP: {})",
                                                    Utc::now().format("%H:%M:%S"),
                                                    dhcp_ip,
                                                    new_ip_str
                                                )
                                            );
                                        } else {
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] ✅ Static IP configuration sent to camera at {}, target IP: {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera_clone.ip,
                                                    new_ip_str
                                                )
                                            );
                                        }

                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Configuration completed for camera (MAC: {})",
                                                Utc::now().format("%H:%M:%S"),
                                                camera_data.mac_address.as_deref().unwrap_or("unknown")
                                            )
                                        );
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
                                        camera_clone.ip
                                    )
                                );
                            }
                        } else {
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] No target IP determined for camera {}, skipping IP change",
                                    Utc::now().format("%H:%M:%S"),
                                    camera_clone.ip
                                )
                            );
                            camera_data.operations.set_static_ip = Some(
                                OperationResult::failure("No target IP determined".to_string())
                            );
                        }

                        let ip_success = camera_data.operations.set_static_ip
                            .as_ref()
                            .map(|op| op.success)
                            .unwrap_or(false);
                        let firmware_success = camera_data.operations.upgrade_firmware
                            .as_ref()
                            .map(|op| op.success)
                            .unwrap_or(true);

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

                        let total_duration = camera_start_time.elapsed();
                        let _ = log_tx_clone.send(
                            format!(
                                "[{}] ⚡ Camera {} configuration completed in {:.1}s",
                                Utc::now().format("%H:%M:%S"),
                                camera_clone.ip,
                                total_duration.as_secs_f32()
                            )
                        );

                        let _ = result_tx_clone.send(camera_data);
                    });
                    handles.push(handle);
                }

                join_all(handles).await;

                let _ = log_tx.send(
                    format!(
                        "[{}] All camera configurations completed!",
                        Utc::now().format("%H:%M:%S")
                    )
                );
                let _ = complete_tx.send(true);

                drop(log_tx);
                drop(result_tx);
                drop(complete_tx);
            });
        }
    }
    
    fn export_results_to_file(&self, path: PathBuf) {
        let csv_handler = CsvHandler::new();

        // Determine file type by extension
        let is_excel = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase() == "xlsx")
            .unwrap_or(false);

        // If we have imported data, merge new results with existing data
        if !self.imported_csv_data.is_empty() && !self.csv_import_file_path.is_empty() {
            info!("Merging new results with existing data from: {}", self.csv_import_file_path);

            // Update the original import file with new configuration data
            let import_path = std::path::Path::new(&self.csv_import_file_path);
            let import_is_excel = import_path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.to_lowercase() == "xlsx")
                .unwrap_or(false);

            let result = if import_is_excel {
                csv_handler.update_inventory_excel(&self.csv_import_file_path, &self.processing_results)
            } else {
                csv_handler.update_inventory_csv(&self.csv_import_file_path, &self.processing_results)
            };

            if let Err(e) = result {
                error!("Failed to update existing file: {}", e);
                // Fallback to creating new file
                let fallback_result = if is_excel {
                    csv_handler.write_inventory_report_excel(&path, &self.processing_results)
                } else {
                    csv_handler.write_inventory_report(&path, &self.processing_results)
                };

                if let Err(e2) = fallback_result {
                    error!("Failed to create new file: {}", e2);
                } else {
                    info!("Results exported to new file: {}", path.display());
                }
            } else {
                info!("Results merged and exported to: {}", path.display());
            }
        } else {
            // No imported data, create new file
            let result = if is_excel {
                csv_handler.write_inventory_report_excel(&path, &self.processing_results)
            } else {
                csv_handler.write_inventory_report(&path, &self.processing_results)
            };

            if let Err(e) = result {
                error!("Failed to export results: {}", e);
            } else {
                let file_type = if is_excel { "Excel" } else { "CSV" };
                info!("Results exported to {} file: {}", file_type, path.display());
            }
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder
            ::default()
            .with_title("Axis Camera Auto Configuration")
            .with_inner_size([1400.0, 900.0]) // Reasonable default size
            .with_min_inner_size([1000.0, 700.0]) // Minimum size for functionality
            .with_resizable(true)
            .with_clamp_size_to_monitor_size(true) // Cross-platform monitor clamping
            .with_icon(eframe::icon_data::from_png_bytes(&[]).unwrap_or_default()),
        ..Default::default()
    };

    eframe::run_native(
        "Axis Camera Auto Configuration",
        options,
        Box::new(|cc| Ok(Box::new(AxisCameraApp::new(cc))))
    )
}
