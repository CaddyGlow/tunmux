//! Accounts, provider tools and settings windows.

use std::time::SystemTime;

use egui::{Color32, RichText, Ui};
use tunmux::api::{AirAction, SystemStatus, WgProfile};

use crate::app::{Action, LoginForm, Tool, TunmuxApp};
use crate::model::{LoginState, Mode, Provider, TrayState};
use crate::prefs::LOG_LEVELS;
use crate::tray;
use crate::worker::Job;

impl TunmuxApp {
    pub fn accounts_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_accounts;
        egui::Window::new("Accounts")
            .open(&mut open)
            .default_size([520.0, 300.0])
            .collapsible(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| {
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(130.0);
                        for p in Provider::ALL {
                            let logged = self.backend.is_logged_in(p);
                            ui.horizontal(|ui| {
                                let state = if logged {
                                    TrayState::Direct
                                } else {
                                    TrayState::Disconnected
                                };
                                tray::paint_icon(ui, state, 10.0);
                                if ui
                                    .selectable_label(self.accounts_tab == p, p.label())
                                    .clicked()
                                    && self.accounts_tab != p
                                {
                                    self.accounts_tab = p;
                                    self.login = LoginForm::default();
                                }
                            });
                        }
                    });
                    ui.separator();
                    ui.vertical(|ui| self.account_panel(ui, self.accounts_tab));
                });
            });
        self.show_accounts = open;
    }

    fn account_panel(&mut self, ui: &mut Ui, p: Provider) {
        ui.heading(p.label());
        if !p.needs_account() {
            ui.label("WireGuard config files need no account.");
            match (&self.live, &self.backend.account(p).state) {
                (Some(_), LoginState::LoggedIn { detail, .. }) => {
                    ui.label(format!("{detail}."));
                }
                _ => {
                    let n = self.backend.wg_profiles.as_ref().map_or(0, Vec::len);
                    ui.label(format!("{n} saved profiles."));
                }
            }
            if ui.button("Manage profiles...").clicked() {
                self.show_tools = true;
            }
            return;
        }
        let account = self.backend.account(p).clone();
        match account.state {
            LoginState::LoggedIn {
                account: name,
                detail,
            } => {
                egui::Grid::new("acct").num_columns(2).show(ui, |ui| {
                    ui.weak("Account");
                    ui.label(&name);
                    ui.end_row();
                    ui.weak("Plan");
                    ui.label(&detail);
                    ui.end_row();
                    ui.weak("Servers");
                    ui.label(format!("{} cached", account.servers_cached));
                    ui.end_row();
                    ui.weak("Stored in");
                    ui.monospace(credential_location(p, &self.settings.credential_store));
                    ui.end_row();
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Refresh server list").clicked() {
                        if self.live.is_some() {
                            self.request_servers(p);
                        } else {
                            self.toast(format!("{} server list refreshed", p.label()));
                        }
                    }
                    let tunnels = self
                        .backend
                        .connections
                        .iter()
                        .filter(|c| c.provider == p)
                        .count();
                    let logout = ui.button("Log out");
                    let logout = if tunnels > 0 {
                        logout.on_hover_text(format!("Also disconnects {tunnels} tunnel(s)"))
                    } else {
                        logout
                    };
                    if logout.clicked() {
                        if self.live.is_some() {
                            self.send(Job::Logout(p.into()));
                        } else {
                            self.backend.logout(p);
                            self.toast(format!("Logged out of {}", p.label()));
                        }
                    }
                });
            }
            LoginState::LoggedOut => self.login_form(ui, p),
            LoginState::NeedsTwoFactor => self.two_factor_form(ui, p),
        }
    }

    fn login_form(&mut self, ui: &mut Ui, p: Provider) {
        let (user_label, secret_label) = match p {
            Provider::Proton => ("Username", Some("Password")),
            Provider::AirVpn => ("Username", Some("Password")),
            Provider::Mullvad => ("Account number", None),
            Provider::Ivpn => ("Account ID", None),
            Provider::WgConf => unreachable!("wgconf has no login"),
        };
        let mut submit = false;
        egui::Grid::new("login").num_columns(2).show(ui, |ui| {
            ui.label(user_label);
            let r = ui.add(egui::TextEdit::singleline(&mut self.login.user).desired_width(200.0));
            submit |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.end_row();
            if let Some(label) = secret_label {
                ui.label(label);
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.login.secret)
                        .password(true)
                        .desired_width(200.0),
                );
                submit |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                ui.end_row();
            }
        });
        if let Some(err) = &self.login.error {
            ui.colored_label(Color32::from_rgb(220, 80, 60), err);
        }
        if p == Provider::Mullvad && self.live.is_some() {
            ui.checkbox(&mut self.login.replace, "Replace a different saved account");
        }
        ui.horizontal(|ui| {
            submit |= ui
                .add_enabled(!self.is_busy(), egui::Button::new("Log in"))
                .clicked();
            if self.is_busy() {
                ui.spinner();
            }
            if p == Provider::Mullvad
                && self.live.is_none()
                && ui.button("Create account").clicked()
            {
                self.login.user = "7342 9921 0458 1167".into();
                self.toast("New Mullvad account created; add time before connecting");
            }
        });
        match p {
            Provider::Proton => ui.weak("A 2FA code is asked next when enabled."),
            Provider::AirVpn => ui.weak("Password is kept: the AirVPN API needs it on each call."),
            Provider::Mullvad => ui.weak("Account numbers are 16 digits."),
            Provider::Ivpn => ui.weak("Format i-XXXX-XXXX-XXXX."),
            Provider::WgConf => unreachable!(),
        };
        if submit && self.live.is_some() {
            self.login.error = None;
            let credentials = tunmux::api::Credentials {
                account: self.login.user.trim().to_string(),
                password: self.login.secret.clone(),
                two_factor: None,
                replace_saved_account: self.login.replace,
            };
            self.send(Job::Login(p.into(), credentials));
        } else if submit {
            let (user, secret) = (self.login.user.clone(), self.login.secret.clone());
            match self.backend.login(p, &user, &secret) {
                Ok(needs_2fa) => {
                    self.login.secret.clear();
                    self.login.error = None;
                    if !needs_2fa {
                        self.toast(format!("Logged in to {}", p.label()));
                    }
                }
                Err(e) => self.login.error = Some(e),
            }
        }
    }

    fn two_factor_form(&mut self, ui: &mut Ui, p: Provider) {
        ui.label(format!("Enter the 2FA code for {}.", self.login.user));
        let r = ui.add(
            egui::TextEdit::singleline(&mut self.login.code)
                .hint_text("123456")
                .desired_width(90.0),
        );
        let mut submit = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if let Some(err) = &self.login.error {
            ui.colored_label(Color32::from_rgb(220, 80, 60), err);
        }
        ui.horizontal(|ui| {
            submit |= ui.button("Verify").clicked();
            if ui.button("Cancel").clicked() {
                self.backend.cancel_login(p);
                self.login = LoginForm::default();
            }
        });
        if submit && self.live.is_some() {
            // The library logs in again with the code; the password is kept
            // in the form until then.
            self.login.error = None;
            let credentials = tunmux::api::Credentials {
                account: self.login.user.trim().to_string(),
                password: self.login.secret.clone(),
                two_factor: Some(self.login.code.trim().to_string()),
                replace_saved_account: self.login.replace,
            };
            self.send(Job::Login(p.into(), credentials));
        } else if submit {
            let (user, code) = (self.login.user.clone(), self.login.code.clone());
            match self.backend.submit_two_factor(p, &user, &code) {
                Ok(()) => {
                    self.login = LoginForm::default();
                    self.toast(format!("Logged in to {}", p.label()));
                }
                Err(e) => self.login.error = Some(e),
            }
        }
    }

    pub fn tools_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_tools;
        egui::Window::new("Provider tools")
            .open(&mut open)
            .default_size([560.0, 340.0])
            .collapsible(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| {
                let id = ui.scope_id().with("tools_tab");
                let mut tab = ui.data(|d| d.get_temp(id)).unwrap_or(Tool::AirVpn);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut tab, Tool::AirVpn, "AirVPN");
                    ui.selectable_value(&mut tab, Tool::Proton, "Proton");
                    ui.selectable_value(&mut tab, Tool::WgConf, "WG config");
                    if self.live.is_some() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button("Reload").clicked() {
                                self.request_tool(tab, true);
                            }
                        });
                    }
                });
                ui.data_mut(|d| d.insert_temp(id, tab));
                ui.separator();
                if let Some(error) = self.tool_errors.get(&tab).cloned() {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(ERROR, error);
                        if ui.small_button("Retry").clicked() {
                            self.request_tool(tab, true);
                        }
                    });
                }
                egui::ScrollArea::vertical().show(ui, |ui| match tab {
                    Tool::AirVpn => self.airvpn_tools(ui),
                    Tool::Proton => self.proton_tools(ui),
                    Tool::WgConf => self.wgconf_tools(ui),
                });
            });
        self.show_tools = open;
    }

    fn require_login(&mut self, ui: &mut Ui, p: Provider) -> bool {
        if self.backend.is_logged_in(p) {
            return true;
        }
        ui.label(format!("Log in to {} to use these tools.", p.label()));
        if ui.button("Open accounts").clicked() {
            self.actions.push(Action::OpenAccounts(p));
        }
        false
    }

    /// Spinner while a tool tab's data loads; `false` until it is there.
    fn loaded(&mut self, ui: &mut Ui, tool: Tool, present: bool, what: &str) -> bool {
        if present {
            return true;
        }
        self.request_tool(tool, false);
        if !self.tool_errors.contains_key(&tool) {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak(format!("Loading {what}..."));
            });
        }
        false
    }

    fn air(&mut self, action: AirAction) {
        if self.live.is_some() {
            self.send(Job::Air(action));
        } else {
            self.backend.air_apply(&action);
        }
    }

    fn airvpn_tools(&mut self, ui: &mut Ui) {
        if !self.require_login(ui, Provider::AirVpn) {
            return;
        }
        let present = self.backend.air.is_some();
        if !self.loaded(ui, Tool::AirVpn, present, "the AirVPN client area") {
            return;
        }
        let air = self.backend.air.clone().unwrap_or_default();
        let busy = self.is_busy();
        let mut actions = Vec::new();

        ui.strong("Forwarded ports");
        if air.ports.is_empty() {
            ui.weak("No forwarded ports.");
        } else {
            egui::Grid::new("air_ports")
                .striped(true)
                .num_columns(6)
                .show(ui, |ui| {
                    for h in ["Port", "Protocol", "Local", "Device", "Enabled", ""] {
                        ui.weak(h);
                    }
                    ui.end_row();
                    for port in &air.ports {
                        ui.monospace(port.port.to_string());
                        let mut protocol = port.protocol.clone();
                        egui::ComboBox::from_id_salt(("air_proto", port.port))
                            .selected_text(&protocol)
                            .width(70.0)
                            .show_ui(ui, |ui| {
                                for p in ["tcp", "udp", "both"] {
                                    ui.selectable_value(&mut protocol, p.to_string(), p);
                                }
                            });
                        if protocol != port.protocol {
                            actions.push(AirAction::SetProtocol(port.port, protocol));
                        }
                        ui.monospace(if port.local_port == 0 {
                            "same".to_string()
                        } else {
                            port.local_port.to_string()
                        });
                        ui.label(&port.device);
                        ui.label(if port.enabled { "yes" } else { "no" });
                        if confirm_button(ui, ("air_port_rm", port.port), "remove") {
                            actions.push(AirAction::RemovePort(port.port));
                        }
                        ui.end_row();
                    }
                });
        }
        ui.horizontal(|ui| {
            let id = ui.scope_id().with("air_new_port");
            let mut text: String = ui.data(|d| d.get_temp(id)).unwrap_or_default();
            ui.add(
                egui::TextEdit::singleline(&mut text)
                    .hint_text("random")
                    .desired_width(70.0),
            );
            let port = text.trim().parse::<u16>().ok();
            let valid = text.trim().is_empty() || port.is_some();
            if ui
                .add_enabled(valid && !busy, egui::Button::new("Add port"))
                .clicked()
            {
                actions.push(AirAction::AddPort(port.unwrap_or(0)));
                text.clear();
            }
            ui.data_mut(|d| d.insert_temp(id, text));
        });

        ui.add_space(8.0);
        ui.strong("Devices");
        egui::Grid::new("air_devices")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for device in &air.devices {
                    let id = ui.scope_id().with(("air_dev_name", &device.id));
                    let mut name: String = ui
                        .data(|d| d.get_temp(id))
                        .unwrap_or_else(|| device.name.clone());
                    ui.add(egui::TextEdit::singleline(&mut name).desired_width(140.0));
                    ui.monospace(&device.wg_ipv4);
                    let renamed = !name.trim().is_empty() && name != device.name;
                    if ui
                        .add_enabled(renamed && !busy, egui::Button::new("rename").small())
                        .clicked()
                    {
                        actions.push(AirAction::RenameDevice {
                            id: device.id.clone(),
                            name: name.trim().to_string(),
                        });
                    }
                    if confirm_button(ui, ("air_dev_rm", &device.id), "delete") {
                        actions.push(AirAction::DeleteDevice(device.id.clone()));
                    }
                    ui.data_mut(|d| d.insert_temp(id, name));
                    ui.end_row();
                }
            });
        if ui
            .add_enabled(!busy, egui::Button::new("Add device"))
            .on_hover_text("Creates a device named \"New device\" with its own WireGuard key")
            .clicked()
        {
            actions.push(AirAction::AddDevice);
        }

        ui.add_space(8.0);
        ui.strong("API keys");
        if air.api_keys.is_empty() {
            ui.weak("No API keys.");
        }
        egui::Grid::new("air_keys")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                for key in &air.api_keys {
                    ui.label(&key.name);
                    ui.monospace(&key.secret_short);
                    if confirm_button(ui, ("air_key_rm", &key.id), "delete") {
                        actions.push(AirAction::DeleteApiKey(key.id.clone()));
                    }
                    ui.end_row();
                }
            });
        if ui
            .add_enabled(!busy, egui::Button::new("Add API key"))
            .clicked()
        {
            actions.push(AirAction::AddApiKey);
        }
        for action in actions {
            self.air(action);
        }
    }

    fn proton_tools(&mut self, ui: &mut Ui) {
        if !self.require_login(ui, Provider::Proton) {
            return;
        }
        let present = self.backend.proton.is_some();
        if !self.loaded(ui, Tool::Proton, present, "port forwarding state") {
            return;
        }
        let ports = self.backend.proton.clone().unwrap_or_default();
        let busy = self.is_busy();
        let has_tunnel = self
            .connections()
            .iter()
            .any(|c| c.provider == Provider::Proton && c.is_direct());

        ui.strong("Port forwarding (NAT-PMP)");
        if ports.forwards.is_empty() {
            ui.weak("No forwarded ports.");
        }
        egui::Grid::new("pf")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for f in &ports.forwards {
                    ui.monospace(&f.instance);
                    ui.label(&f.protocol);
                    ui.monospace(f.public_port.to_string());
                    ui.weak(fmt_until(f.expires_at));
                    if ui.small_button("copy").clicked() {
                        self.actions
                            .push(Action::Copy(f.public_port.to_string(), "port"));
                    }
                    ui.end_row();
                }
            });
        ui.weak(if ports.daemon_running {
            "Renewed in the background."
        } else {
            "Not renewed: mappings lapse when their lease ends."
        });
        ui.horizontal(|ui| {
            let request = ui
                .add_enabled(has_tunnel && !busy, egui::Button::new("Request port"))
                .on_disabled_hover_text("Needs a direct Proton tunnel on a P2P server");
            if request.clicked() {
                if self.live.is_some() {
                    self.send(Job::ProtonRequestPort);
                } else {
                    self.backend.proton_forward();
                }
            }
            let release = !ports.forwards.is_empty() || ports.daemon_running;
            if ui
                .add_enabled(release && has_tunnel && !busy, egui::Button::new("Release"))
                .clicked()
            {
                if self.live.is_some() {
                    self.send(Job::ProtonReleasePorts);
                } else {
                    self.backend.proton_release();
                }
            }
        });

        ui.add_space(8.0);
        ui.strong("Certificate");
        ui.horizontal(|ui| {
            match ports.certificate_expires {
                Some(at) => ui.label(format!("Valid for {}", fmt_until(at))),
                None => ui.weak("No certificate saved."),
            };
            if ui
                .add_enabled(!busy, egui::Button::new("Renew now"))
                .clicked()
            {
                if self.live.is_some() {
                    self.send(Job::ProtonRenewCertificate);
                } else {
                    self.toast("Proton certificate renewed");
                }
            }
        });
    }

    fn wgconf_tools(&mut self, ui: &mut Ui) {
        let present = self.backend.wg_profiles.is_some();
        if !self.loaded(ui, Tool::WgConf, present, "saved profiles") {
            return;
        }
        let profiles = self.backend.wg_profiles.clone().unwrap_or_default();
        let busy = self.is_busy();
        ui.strong("Saved profiles");
        if profiles.is_empty() {
            ui.weak("No saved profiles.");
        }
        let mut remove = None;
        egui::Grid::new("wg_profiles")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                for p in &profiles {
                    ui.label(RichText::new(&p.name).strong());
                    ui.monospace(p.endpoint.as_deref().unwrap_or("-"));
                    if confirm_button(ui, ("wg_rm", &p.name), "remove") {
                        remove = Some(p.name.clone());
                    }
                    ui.end_row();
                }
            });
        if let Some(name) = remove {
            if self.live.is_some() {
                self.send(Job::WgRemove(name));
            } else if let Some(list) = &mut self.backend.wg_profiles {
                list.retain(|p| p.name != name);
            }
        }

        ui.add_space(8.0);
        ui.strong("Import a .conf file");
        let id = ui.scope_id().with("wg_import");
        let (mut path, mut name): (String, String) =
            ui.data(|d| d.get_temp(id)).unwrap_or_default();
        egui::Grid::new("wg_import_form")
            .num_columns(2)
            .show(ui, |ui| {
                ui.label("File");
                ui.add(
                    egui::TextEdit::singleline(&mut path)
                        .hint_text("/path/to/tunnel.conf")
                        .desired_width(300.0),
                );
                ui.end_row();
                ui.label("Name");
                let stem = std::path::Path::new(path.trim())
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                ui.add(
                    egui::TextEdit::singleline(&mut name)
                        .hint_text(stem)
                        .desired_width(160.0),
                );
                ui.end_row();
            });
        let chosen = if name.trim().is_empty() {
            std::path::Path::new(path.trim())
                .file_stem()
                .map(|s| s.to_string_lossy().to_lowercase())
                .unwrap_or_default()
        } else {
            name.trim().to_string()
        };
        let ready = !path.trim().is_empty() && !chosen.is_empty();
        if ui
            .add_enabled(ready && !busy, egui::Button::new("Import"))
            .on_hover_text("Lowercase letters, digits, '.', '_' and '-' only")
            .clicked()
        {
            if self.live.is_some() {
                self.send(Job::WgImport(path.trim().into(), chosen));
            } else if let Some(list) = &mut self.backend.wg_profiles {
                list.push(WgProfile {
                    name: chosen,
                    endpoint: Some("198.51.100.4:51820".into()),
                });
                self.toast("Profile imported");
            }
            path.clear();
            name.clear();
        }
        ui.data_mut(|d| d.insert_temp(id, (path, name)));
    }

    pub fn settings_window(&mut self, ctx: &egui::Context) {
        if !self.show_settings {
            // Probe again the next time the window opens.
            self.settings.system = None;
            return;
        }
        if self.settings.system.is_none() {
            self.settings.system = Some(if self.live.is_some() {
                tunmux::api::system_status()
            } else {
                SystemStatus {
                    helper_socket: "/var/run/tunmux/ctl.sock".into(),
                    helper_running: false,
                    service_installed: Ok(false),
                }
            });
        }
        let mut open = self.show_settings;
        egui::Window::new("Settings")
            .open(&mut open)
            .default_size([460.0, 380.0])
            .collapsible(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| self.settings_body(ui));
        self.show_settings = open;
    }

    fn save_prefs(&mut self) {
        if self.live.is_none() {
            return;
        }
        if let Err(e) = self.settings.prefs.save() {
            self.toast_error(format!("Cannot save settings: {e:#}"));
        }
    }

    fn write_autostart(&mut self) {
        if self.live.is_none() {
            return;
        }
        let s = &self.settings;
        if let Err(e) = crate::prefs::set_start_at_login(s.start_at_login, s.prefs.start_in_tray) {
            self.toast_error(format!("Cannot update the login entry: {e:#}"));
            self.settings.start_at_login = crate::prefs::start_at_login();
        }
    }

    fn settings_body(&mut self, ui: &mut Ui) {
        let prefs_before = self.settings.prefs.clone();
        let general_before = self.settings.general.clone();
        let login_before = self.settings.start_at_login;
        let busy = self.is_busy();

        ui.strong("Connections");
        let s = &mut self.settings;
        egui::Grid::new("set_conn").num_columns(2).show(ui, |ui| {
            ui.label("Default mode");
            egui::ComboBox::from_id_salt("set_mode")
                .selected_text(s.prefs.default_mode.label())
                .show_ui(ui, |ui| {
                    for m in [Mode::Direct, Mode::NetnsProxy, Mode::LocalProxy] {
                        ui.selectable_value(&mut s.prefs.default_mode, m, m.label());
                    }
                });
            ui.end_row();
            ui.label("Direct backend");
            ui.add_enabled_ui(!busy, |ui| {
                egui::ComboBox::from_id_salt("set_backend")
                    .selected_text(&s.general.backend)
                    .show_ui(ui, |ui| {
                        for b in ["kernel", "wg-quick", "userspace"] {
                            ui.selectable_value(&mut s.general.backend, b.to_string(), b);
                        }
                    });
            });
            ui.end_row();
        });
        ui.add_enabled_ui(!busy, |ui| {
            ui.checkbox(
                &mut s.general.proxy_access_log,
                "Log proxy connections (access log)",
            );
        });
        ui.weak(format!(
            "Backend and access log are saved to {}.",
            tunmux::api::config_path().display()
        ));

        ui.add_space(6.0);
        ui.strong("Desktop");
        ui.checkbox(&mut s.start_at_login, "Start at login");
        ui.add_enabled_ui(s.start_at_login, |ui| {
            ui.checkbox(&mut s.prefs.start_in_tray, "Start hidden in the tray");
        });
        ui.checkbox(
            &mut s.prefs.close_to_tray,
            "Closing the window keeps tunmux in the tray",
        );

        ui.add_space(6.0);
        ui.strong("Storage and logs");
        egui::Grid::new("set_store").num_columns(2).show(ui, |ui| {
            ui.label("Credential store");
            ui.monospace(&s.credential_store).on_hover_text(
                "Set general.credential_store in config.toml. \
                 Saved logins are not moved when it changes.",
            );
            ui.end_row();
            ui.label("Log level");
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("set_log")
                    .selected_text(&s.prefs.log_level)
                    .show_ui(ui, |ui| {
                        for v in LOG_LEVELS {
                            ui.selectable_value(&mut s.prefs.log_level, v.to_string(), v);
                        }
                    });
                ui.weak("from the next start");
            });
            ui.end_row();
        });

        ui.add_space(6.0);
        ui.strong("System");
        let mut copy = None;
        if let Some(sys) = &s.system {
            egui::Grid::new("set_sys").num_columns(2).show(ui, |ui| {
                ui.label("Privileged helper");
                if sys.helper_running {
                    ui.colored_label(OK, "running");
                } else {
                    ui.weak("idle, started when needed");
                }
                ui.end_row();
                ui.label("Socket");
                ui.monospace(sys.helper_socket.display().to_string());
                ui.end_row();
                ui.label("System service");
                match &sys.service_installed {
                    Ok(true) => {
                        ui.colored_label(OK, "installed");
                    }
                    Ok(false) => {
                        ui.horizontal(|ui| {
                            ui.colored_label(WARN, "not installed").on_hover_text(
                                "Without it, each start of the helper asks for elevation",
                            );
                            if ui.small_button("copy install command").clicked() {
                                copy = Some("sudo tunmux service install".to_string());
                            }
                        });
                    }
                    Err(error) => {
                        ui.colored_label(WARN, error);
                    }
                }
                ui.end_row();
                ui.label("Autoconnect");
                ui.weak(if cfg!(target_os = "macos") {
                    "managed with tunmux autoconnect"
                } else {
                    "not available on this platform yet"
                });
                ui.end_row();
            });
        }
        if let Some(text) = copy {
            self.actions.push(Action::Copy(text, "install command"));
        }

        if self.settings.prefs != prefs_before {
            self.save_prefs();
            if self.settings.start_at_login
                && self.settings.prefs.start_in_tray != prefs_before.start_in_tray
            {
                self.write_autostart();
            }
        }
        if self.settings.start_at_login != login_before {
            self.write_autostart();
        }
        if self.settings.general != general_before && self.live.is_some() {
            self.send(Job::SaveGeneral(self.settings.general.clone()));
        }
    }
}

const OK: Color32 = Color32::from_rgb(60, 180, 100);
const WARN: Color32 = Color32::from_rgb(230, 170, 40);
const ERROR: Color32 = Color32::from_rgb(220, 80, 80);

/// A small button that asks once more before acting; true on the second click.
fn confirm_button(ui: &mut Ui, key: impl std::hash::Hash + std::fmt::Debug, label: &str) -> bool {
    let id = ui.scope_id().with(key);
    let armed = ui.data(|d| d.get_temp::<bool>(id)).unwrap_or(false);
    let text = if armed {
        RichText::new(format!("confirm {label}")).color(ERROR)
    } else {
        RichText::new(label)
    };
    let response = ui.small_button(text);
    if response.clicked() {
        ui.data_mut(|d| d.insert_temp(id, !armed));
        return armed;
    }
    if armed && response.clicked_elsewhere() {
        ui.data_mut(|d| d.insert_temp(id, false));
    }
    false
}

/// Time left until `at`, coarsely: "5 d", "3 h", "40 s", or "expired".
fn fmt_until(at: SystemTime) -> String {
    let Ok(left) = at.duration_since(SystemTime::now()) else {
        return "expired".into();
    };
    let secs = left.as_secs();
    match secs {
        0..=119 => format!("{secs} s"),
        120..=7199 => format!("{} min", secs / 60),
        7200..=172_799 => format!("{} h", secs / 3600),
        _ => format!("{} d", secs / 86_400),
    }
}

fn credential_location(p: Provider, store: &str) -> String {
    let dir = match p {
        Provider::Proton => "proton",
        Provider::AirVpn => "airvpn",
        Provider::Mullvad => "mullvad",
        Provider::Ivpn => "ivpn",
        Provider::WgConf => "wgconf",
    };
    match store {
        "keyring" => format!("keyring: tunmux/{dir}"),
        _ => format!("~/.config/tunmux/{dir}/session.json"),
    }
}
