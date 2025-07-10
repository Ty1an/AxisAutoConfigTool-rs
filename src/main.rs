#![windows_subsystem = "windows"]

mod dchp_manager;
mod network_utilities;
mod camera_discovery;
mod camera_operations;
mod csv_handler;

use anyhow::Result;
use chrono::Utc;
use eframe::egui::TextStyle;
use log::{ error, info };
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{ mpsc, Mutex, Semaphore };
use tokio::time::Instant;
use futures::future::join_all;

use camera_discovery::{ CameraDiscovery, DeviceInfo };
use camera_operations::{ CameraOperations, IpConfig, ModelFirmwareMapping };
use csv_handler::{ CsvHandler, CameraInventoryData, OperationResult, OperationResults };
use dchp_manager::{ DhcpManager, DhcpLease, NetworkInterface };

#[derive(Clone, Debug)]
struct FirmwareEntry {
    file_path: Option<PathBuf>,
    compatible_models: String, // Comma-separated list of compatible models
    is_loaded: bool,
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

    discovery_rx: Option<mpsc::UnboundedReceiver<Vec<DeviceInfo>>>,
    discovery_complete_rx: Option<mpsc::UnboundedReceiver<bool>>,

    processing_log_rx: Option<mpsc::UnboundedReceiver<String>>,
    processing_result_rx: Option<mpsc::UnboundedReceiver<CameraInventoryData>>,
    processing_complete_rx: Option<mpsc::UnboundedReceiver<bool>>,

    lease_refresh_rx: Option<mpsc::UnboundedReceiver<Vec<DhcpLease>>>,
    lease_update_tx: Option<mpsc::UnboundedSender<Vec<DhcpLease>>>,

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
            dhcp_leases: Vec::new(),
            discovered_cameras: Vec::new(),
            discovery_in_progress: false,
            last_scan_time: None,
            admin_password: String::new(),
            ip_range_input: String::new(),
            firmware_mapping: ModelFirmwareMapping::new(),
            firmware_entries: Vec::new(),
            processing_in_progress: false,
            processing_logs: Vec::new(),
            processing_results: Vec::new(),
            rt: None,
            dhcp_shutdown_tx: None,
            discovery_rx: None,
            discovery_complete_rx: None,
            processing_log_rx: None,
            processing_result_rx: None,
            processing_complete_rx: None,
            lease_refresh_rx: None,
            lease_update_tx: None,
            camera_subnet_mask: "255.255.255.0".to_string(),
            camera_gateway: "192.168.1.1".to_string(),
            csv_import_file_path: String::new(),
            imported_csv_data: Vec::new(),
        }
    }
}

impl AxisCameraApp {
    fn create_button(text: &str, size: egui::Vec2) -> egui::Button {
        egui::Button::new(text).min_size(size)
    }

    fn load_firmware_files(&mut self) {
        self.firmware_mapping = ModelFirmwareMapping::new();

        for entry in &mut self.firmware_entries {
            if let Some(path) = &entry.file_path {
                match std::fs::read(path) {
                    Ok(_data) => {
                        let filename = path.file_name().unwrap().to_string_lossy().to_string();

                        let compatible_models: Vec<String> = if
                            !entry.compatible_models.trim().is_empty()
                        {
                            entry.compatible_models
                                .split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        } else {
                            if
                                let Some(extracted_model) =
                                    ModelFirmwareMapping::extract_model_from_firmware_filename(
                                        &filename
                                    )
                            {
                                vec![extracted_model]
                            } else {
                                vec!["auto-detect".to_string()]
                            }
                        };

                        if !compatible_models.is_empty() {
                            self.firmware_mapping.add_firmware_path(
                                filename.clone(),
                                path.clone(),
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
        let is_excel = path.extension()
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
                info!("Successfully loaded {} entries from {} file", self.imported_csv_data.len(), file_type);
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

        style.spacing.button_padding = egui::vec2(12.0, 8.0);
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
            egui::FontId::new(16.0, egui::FontFamily::Proportional)
        );
        style.text_styles.insert(
            TextStyle::Monospace,
            egui::FontId::new(14.0, egui::FontFamily::Monospace)
        );
        style.text_styles.insert(
            TextStyle::Small,
            egui::FontId::new(13.0, egui::FontFamily::Proportional)
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
            .default_width(240.0)
            .min_width(220.0)
            .max_width(280.0)
            .resizable(true)
            .show_inside(ui, |ui| {
                self.show_compact_control_panel(ui, ctx);
            });

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                let half_width = ui.available_width() / 2.0 - 2.0;

                ui.vertical(|ui| {
                    ui.set_min_width(half_width);
                    ui.set_max_width(half_width);
                    ui.set_min_height(320.0);
                    ui.set_max_height(320.0);
                    self.show_discovery_card(ui);
                });

                ui.add_space(4.0);

                ui.vertical(|ui| {
                    ui.set_min_width(half_width);
                    ui.set_max_width(half_width);
                    ui.set_min_height(320.0);
                    ui.set_max_height(320.0);
                    self.show_console_card(ui);
                });
            });

            ui.add_space(4.0);

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

        egui::ScrollArea
            ::vertical()
            .id_salt("control_panel_scroll")
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.set_width(ui.available_width());

                ui.vertical_centered(|ui| {
                    ui.add_space(2.0);
                    ui.strong("📷 Axis Auto Config");
                    ui.add_space(2.0);
                });

                ui.separator();
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    ui.label("Interface:");
                    ui.add_space(4.0);
                    egui::ComboBox
                        ::from_label("")
                        .width(120.0)
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

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("Start DHCP:");
                    ui.add_space(8.0);

                    let mut dhcp_enabled = self.dhcp_running;
                    let toggle_response = ui.allocate_response(
                        egui::Vec2::new(40.0, 20.0),
                        egui::Sense::click()
                    );

                    if toggle_response.clicked() {
                        dhcp_enabled = !dhcp_enabled;
                        if dhcp_enabled && !self.dhcp_running {
                            self.start_dhcp_server();
                        } else if !dhcp_enabled && self.dhcp_running {
                            self.stop_dhcp_server();
                        }
                    }

                    let rect = toggle_response.rect;
                    let how_on = ui
                        .ctx()
                        .animate_bool(toggle_response.id.with("toggle"), self.dhcp_running);
                    let visuals = ui
                        .style()
                        .interact_selectable(&toggle_response, self.dhcp_running);
                    let rect = rect.expand(visuals.expansion);
                    let radius = 0.5 * rect.height();
                    ui.painter().rect_filled(rect, radius, visuals.bg_fill);
                    let circle_x = egui::lerp(rect.left() + radius..=rect.right() - radius, how_on);
                    let center = egui::pos2(circle_x, rect.center().y);
                    let circle_color = if self.dhcp_running {
                        NORD_GREEN
                    } else {
                        ui.visuals().weak_text_color()
                    };
                    ui.painter().circle_filled(center, 0.75 * radius, circle_color);

                    ui.add_space(8.0);
                    if self.dhcp_running {
                        ui.colored_label(NORD_GREEN, "ON");
                    } else {
                        ui.colored_label(ui.visuals().weak_text_color(), "OFF");
                    }
                });

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                ui.strong("Configuration");
                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("IP Range:");
                    ui.add_space(4.0);
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::TextEdit
                            ::singleline(&mut self.ip_range_input)
                            .hint_text("192.168.5.2-10")
                    );
                });

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("Password:");
                    ui.add_space(4.0);
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::TextEdit
                            ::singleline(&mut self.admin_password)
                            .password(true)
                            .hint_text("admin")
                    );
                });

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("Subnet:");
                    ui.add_space(4.0);
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::TextEdit
                            ::singleline(&mut self.camera_subnet_mask)
                            .hint_text("255.255.255.0")
                    );
                });

                ui.add_space(2.0);

                ui.horizontal(|ui| {
                    ui.label("Gateway:");
                    ui.add_space(4.0);
                    ui.add_sized(
                        [120.0, 20.0],
                        egui::TextEdit
                            ::singleline(&mut self.camera_gateway)
                            .hint_text("192.168.1.1")
                    );
                });

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                ui.strong("Firmware (Optional)");
                ui.add_space(2.0);

                if self.firmware_entries.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label("No firmware files");
                        if ui.small_button("📁 Add").clicked() {
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
                                        ui.colored_label(NORD_GREEN, "✓");
                                    } else {
                                        ui.colored_label(NORD_RED, "✗");
                                    }
                                } else {
                                    ui.label("No file");
                                }

                                if ui.small_button("📁").clicked() {
                                    file_dialog_for_index = Some(i);
                                }
                                
                                if ui.small_button("🗑").clicked() {
                                    remove_index = Some(i);
                                }
                            });
                            
                            ui.horizontal(|ui| {
                                ui.label("Models:");
                                ui.add_sized(
                                    [120.0, 20.0],
                                    egui::TextEdit::singleline(&mut entry.compatible_models)
                                        .hint_text("P3219,M3206 or auto-detect")
                                );
                                if ui.small_button("↻").clicked() {
                                    should_reload = true;
                                }
                            });
                        });
                    }
                    
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
                                entry.file_path = Some(path);
                                entry.is_loaded = false;
                                should_reload = true;
                            }
                        }
                    }

                    if should_reload {
                        self.load_firmware_files();
                    }
                    
                    ui.add_space(4.0);
                    if ui.button("➕ Add Firmware").clicked() {
                        self.firmware_entries.push(FirmwareEntry {
                            file_path: None,
                            compatible_models: String::new(),
                            is_loaded: false,
                        });
                    }
                }

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                // File Import Section
                ui.strong("File Import (Optional)");
                ui.add_space(2.0);
                ui.label("Upload an existing Excel (.xlsx) or CSV file to merge with new configuration results:");
                
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("File:");
                        ui.add_space(4.0);
                        let available_width = ui.available_width() - 80.0; // Reserve space for Browse button
                        ui.add_sized(
                            [available_width.max(150.0), 20.0],
                            egui::TextEdit::singleline(&mut self.csv_import_file_path)
                                .hint_text("Select Excel or CSV file...")
                        );
                    });
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        if ui.button("📁 Browse").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
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
                            ui.add_space(4.0);
                            if ui.button("📤 Load File").clicked() {
                                self.load_csv_file();
                            }
                        }
                    });
                });

                if !self.imported_csv_data.is_empty() {
                    ui.add_space(2.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(46, 204, 113),
                        format!("✅ Loaded {} entries from CSV", self.imported_csv_data.len())
                    );
                    ui.label("New configuration results will be merged with this data.");
                }

                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

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
                                "🚀 Start Configuration",
                                egui::vec2(ui.available_width() - 16.0, 32.0)
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
                        ui.colored_label(NORD_RED, "❌ Start DHCP first");
                    } else if !passwords_valid {
                        ui.colored_label(NORD_RED, "❌ Enter password");
                    } else if !network_valid {
                        ui.colored_label(NORD_RED, "❌ Configure network");
                    } else if !ip_range_valid {
                        ui.colored_label(NORD_RED, "❌ Enter IP range");
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
            .inner_margin(egui::Margin::same(20))
            .outer_margin(egui::Margin::same(6))
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

        Self::create_highlighted_card_frame(ui, "📡 Discovery", |ui| {
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
                    if ui.button("🔄 Refresh").clicked() && !self.discovery_in_progress {
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
                                ui.colored_label(status_color, "●");
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
                            ui.label("💡 No cameras found");
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
        Self::create_highlighted_card_frame(ui, "📝 Console", |ui| {
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
                            ui.label("📋 Console logs will appear here");
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
        Self::create_highlighted_card_frame(ui, "📊 Results", |ui| {
            ui.horizontal(|ui| {
                ui.strong("Export Results:");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("💾 Export Excel").clicked() {
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
                    if ui.button("💾 Export CSV").clicked() {
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

            egui::ScrollArea
                ::vertical()
                .id_salt("results_scroll")
                .auto_shrink([false; 2])
                .max_height(180.0)
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
                            ui.label("📈 Configuration results will appear here");
                            ui.add_space(8.0);
                            ui.colored_label(
                                ui.visuals().weak_text_color(),
                                "Complete camera configuration to see results"
                            );
                        });
                    }
                });
        });
    }

    fn show_processing_screen(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.show_unified_layout(ui, ctx);
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
                    self.lease_refresh_rx = Some(lease_rx);
                    self.lease_update_tx = Some(lease_tx.clone());

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
        self.lease_update_tx = None;
        self.lease_refresh_rx = None;
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

        self.discovery_rx = Some(discovery_rx);
        self.discovery_complete_rx = Some(complete_rx);

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
        if let Some(rx) = &mut self.discovery_rx {
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
                if self.discovered_cameras.len() > 75 {
                    self.discovered_cameras.truncate(50);
                }
            }
        }

        if let Some(rx) = &mut self.discovery_complete_rx {
            if rx.try_recv().is_ok() {
                self.discovery_in_progress = false;
                self.discovery_rx = None;
                self.discovery_complete_rx = None;
                info!(
                    "Camera discovery completed. Found {} cameras (DHCP leases: {})",
                    self.discovered_cameras.len(),
                    self.dhcp_leases.len()
                );
            }
        }

        if let Some(rx) = &mut self.processing_log_rx {
            while let Ok(log_message) = rx.try_recv() {
                self.processing_logs.push(log_message);
                if self.processing_logs.len() > 200 {
                    self.processing_logs.drain(0..100);
                }
            }
        }

        if let Some(rx) = &mut self.processing_result_rx {
            while let Ok(result) = rx.try_recv() {
                self.processing_results.push(result);
                if self.processing_results.len() > 75 {
                    self.processing_results.drain(0..25);
                }
            }
        }

        if let Some(rx) = &mut self.processing_complete_rx {
            if rx.try_recv().is_ok() {
                self.processing_in_progress = false;
                self.processing_log_rx = None;
                self.processing_result_rx = None;
                self.processing_complete_rx = None;
                info!("Camera configuration completed!");
            }
        }

        if let Some(rx) = &mut self.lease_refresh_rx {
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

        let discovered_cameras = self.discovered_cameras.clone();
        let admin_password = self.admin_password.clone();
        let camera_subnet_mask = self.camera_subnet_mask.clone();
        let camera_gateway = self.camera_gateway.clone();
        let firmware_mapping = self.firmware_mapping.clone();

        if let Some(rt) = &self.rt {
            rt.spawn(async move {
                let _ = log_tx.send(
                    format!("[{}] Initializing camera operations...", Utc::now().format("%H:%M:%S"))
                );

                let has_firmware = !firmware_mapping.firmware_files.is_empty();
                if has_firmware {
                    let _ = log_tx.send(
                        format!(
                            "[{}] {} firmware file(s) loaded for model-based upgrades",
                            Utc::now().format("%H:%M:%S"),
                            firmware_mapping.firmware_files.len()
                        )
                    );
                }

                // Limit concurrent camera operations to prevent network/resource exhaustion
                let semaphore = Arc::new(Semaphore::new(10));

                let mut handles = Vec::new();

                let total_cameras = discovered_cameras.len();

                for (index, camera) in discovered_cameras.into_iter().enumerate() {
                    let log_tx_clone = log_tx.clone();
                    let result_tx_clone = result_tx.clone();
                    let semaphore_clone = semaphore.clone();

                    let admin_password_clone = admin_password.clone();
                    let firmware_mapping_clone = firmware_mapping.clone();
                    let camera_subnet_mask_clone = camera_subnet_mask.clone();
                    let camera_gateway_clone = camera_gateway.clone();
                    let target_ips_clone = target_ips.clone();

                    let handle = tokio::spawn(async move {
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
                        );

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
                                let camera_data = CameraInventoryData {
                                    ip_address: camera.ip.clone(),
                                    subnet: camera_subnet_mask_clone.clone(),
                                    gateway: camera_gateway_clone.clone(),
                                    user_name: "root".to_string(),
                                    password: admin_password_clone.clone(),
                                    completion_time: Utc::now(),
                                    status: "Failed - Init".to_string(),
                                    device_map: None,
                                    ..Default::default()
                                };
                                let _ = result_tx_clone.send(camera_data);
                                return;
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
                                    ip_address: camera.ip.clone(),
                                    subnet: camera_subnet_mask_clone.clone(),
                                    gateway: camera_gateway_clone.clone(),
                                    user_name: "root".to_string(),
                                    password: admin_password_clone.clone(),
                                    completion_time: Utc::now(),
                                    status: "Failed - Invalid IP".to_string(),
                                    device_map: None,
                                    ..Default::default()
                                };
                                let _ = result_tx_clone.send(camera_data);
                                return;
                            }
                        };

                        let mut camera_data = CameraInventoryData {
                            ip_address: camera.ip.clone(),
                            subnet: camera_subnet_mask_clone.clone(),
                            gateway: camera_gateway_clone.clone(),
                            mac_address: camera.mac_address.clone(),
                            serial: None,
                            firmware_version: None,
                            item_name: None,
                            user_name: "root".to_string(),
                            password: admin_password_clone.clone(),
                            device_map: None,
                            completion_time: Utc::now(),
                            status: "Processing".to_owned(),
                            operations: OperationResults::default(),
                            tool_version: "1.0.0".to_string(),
                        };

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

                                match
                                    camera_ops.get_device_info(
                                        camera_ip,
                                        "root",
                                        &admin_password_clone,
                                        camera_operations::Protocol::Http
                                    ).await
                                {
                                    Ok(device_info) => {
                                        if let Some(model_obj) = device_info.get("ProdNbr") {
                                            if let Some(model_str) = model_obj.as_str() {
                                                camera_data.item_name = Some(
                                                    model_str.to_string()
                                                );
                                                let _ = log_tx_clone.send(
                                                    format!(
                                                        "[{}] Detected camera model: {} for {}",
                                                        Utc::now().format("%H:%M:%S"),
                                                        model_str,
                                                        camera.ip
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
                                                camera.ip,
                                                camera_data.item_name.as_deref().unwrap_or("Unknown"),
                                                camera_data.firmware_version.as_deref().unwrap_or("Unknown")
                                            )
                                        );
                                    }
                                    Err(e) => {
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Could not get device info for {}: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                camera.ip,
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
                                            &admin_password_clone,
                                            camera_operations::Protocol::Http
                                        ).await
                                    {
                                        Ok(Some(mac_addr)) => {
                                            camera_data.mac_address = Some(mac_addr);
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] MAC address retrieved via VAPIX for {}: {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera.ip,
                                                    camera_data.mac_address.as_deref().unwrap_or("Unknown")
                                                )
                                            );
                                        }
                                        Ok(None) => {
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] Could not retrieve MAC address via VAPIX for {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera.ip
                                                )
                                            );
                                        }
                                        Err(e) => {
                                            let _ = log_tx_clone.send(
                                                format!(
                                                    "[{}] Error getting MAC address for {}: {}",
                                                    Utc::now().format("%H:%M:%S"),
                                                    camera.ip,
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
                                        camera.ip,
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
                                "[{}] Waiting for user accounts to become active on {}...",
                                Utc::now().format("%H:%M:%S"),
                                camera.ip
                            )
                        );
                        tokio::time::sleep(Duration::from_secs(2)).await;

                        if !firmware_mapping_clone.firmware_files.is_empty() {
                            let model_name = camera_data.item_name.as_deref().unwrap_or("Unknown");
                            let _ = log_tx_clone.send(
                                format!(
                                    "[{}] Checking firmware compatibility for {} (Model: {})...",
                                    Utc::now().format("%H:%M:%S"),
                                    camera.ip,
                                    model_name
                                )
                            );
                            
                            // Check if we have compatible firmware before attempting upgrade
                            if let Some(firmware_file) = firmware_mapping_clone.find_firmware_for_model(model_name) {
                                let _ = log_tx_clone.send(
                                    format!(
                                        "[{}] Found compatible firmware '{}' for model '{}' at {}",
                                        Utc::now().format("%H:%M:%S"),
                                        firmware_file.filename,
                                        model_name,
                                        camera.ip
                                    )
                                );

                                match
                                    camera_ops.upgrade_firmware_with_model_mapping(
                                        camera_ip,
                                        "root",
                                        &admin_password_clone,
                                        &firmware_mapping_clone,
                                        camera_operations::Protocol::Http,
                                        None
                                    ).await
                                {
                                Ok(msg) => {
                                    camera_data.operations.upgrade_firmware = Some(
                                        OperationResult::success(msg)
                                    );
                                    let _ = log_tx_clone.send(
                                        format!(
                                            "[{}] ✅ Firmware upgrade completed for {}",
                                            Utc::now().format("%H:%M:%S"),
                                            camera.ip
                                        )
                                    );

                                    let _ = log_tx_clone.send(
                                        format!(
                                            "[{}] Retrieving updated firmware version for {}...",
                                            Utc::now().format("%H:%M:%S"),
                                            camera.ip
                                        )
                                    );

                                    match
                                        camera_ops.get_device_info(
                                            camera_ip,
                                            "root",
                                            &admin_password_clone,
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
                                                            camera.ip,
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
                                                    camera.ip,
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
                                            camera.ip,
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
                                        camera.ip,
                                        model_name
                                    )
                                );
                                let available_models: Vec<String> = firmware_mapping_clone.firmware_files
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
                                    camera.ip
                                )
                            );
                        }

                        let target_ip_str = target_ips_clone.get(index).cloned();

                        if let Some(new_ip_str) = target_ip_str {
                            let _new_ip_addr = match new_ip_str.parse::<std::net::Ipv4Addr>() {
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
                                    if camera_data.status == "Processing" {
                                        camera_data.status =
                                            "Partial Success - IP Invalid".to_string();
                                    }
                                    let _ = result_tx_clone.send(camera_data);
                                    return;
                                }
                            };

                            // Only configure static IP if different from current DHCP assignment
                            if new_ip_str != camera.ip {
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
                                        camera_data.ip_address = new_ip_str.clone();
                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] ✅ Static IP configuration sent to camera at {}, target IP: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                camera.ip,
                                                new_ip_str
                                            )
                                        );

                                        let _ = log_tx_clone.send(
                                            format!(
                                                "[{}] Waiting for camera to restart at new IP: {}",
                                                Utc::now().format("%H:%M:%S"),
                                                new_ip_str
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
        let is_excel = path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase() == "xlsx")
            .unwrap_or(false);

        // If we have imported data, merge new results with existing data
        if !self.imported_csv_data.is_empty() && !self.csv_import_file_path.is_empty() {
            info!("Merging new results with existing data from: {}", self.csv_import_file_path);
            
            let result = if is_excel {
                csv_handler.update_inventory_excel(&path, &self.processing_results)
            } else {
                csv_handler.update_inventory_csv(&path, &self.processing_results)
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
