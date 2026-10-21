//! Accounts, provider tools and settings windows.

use egui::{Color32, RichText, Ui};

use crate::app::{Action, LoginForm, TunmuxApp};
use crate::model::{Backend, LoginState, Mode, Provider, TrayState};
use crate::tray;
use crate::worker::Job;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ToolsTab {
    AirVpn,
    Proton,
    WgConf,
}

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
                    ui.label(format!(
                        "{} saved profiles.",
                        self.backend.wg_profiles.len()
                    ));
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
                    ui.monospace(credential_location(p, self.settings.credential_store));
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
            .default_size([520.0, 320.0])
            .collapsible(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| {
                let id = ui.scope_id().with("tools_tab");
                let mut tab = ui.data(|d| d.get_temp(id)).unwrap_or(ToolsTab::AirVpn);
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut tab, ToolsTab::AirVpn, "AirVPN");
                    ui.selectable_value(&mut tab, ToolsTab::Proton, "Proton");
                    ui.selectable_value(&mut tab, ToolsTab::WgConf, "WG config");
                });
                ui.data_mut(|d| d.insert_temp(id, tab));
                ui.separator();
                if self.live.is_some() {
                    ui.weak(
                        "Sample data: provider tools are wired to the library in a later step.",
                    );
                }
                match tab {
                    ToolsTab::AirVpn => self.airvpn_tools(ui),
                    ToolsTab::Proton => self.proton_tools(ui),
                    ToolsTab::WgConf => self.wgconf_tools(ui),
                }
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

    fn airvpn_tools(&mut self, ui: &mut Ui) {
        if !self.require_login(ui, Provider::AirVpn) {
            return;
        }
        ui.strong("Forwarded ports");
        let mut remove = None;
        egui::Grid::new("air_ports")
            .striped(true)
            .num_columns(5)
            .show(ui, |ui| {
                ui.weak("Port");
                ui.weak("Protocol");
                ui.weak("Device");
                ui.weak("Enabled");
                ui.label("");
                ui.end_row();
                for (i, port) in self.backend.air_ports.iter_mut().enumerate() {
                    ui.monospace(port.port.to_string());
                    ui.label(port.protocol);
                    ui.label(port.device);
                    ui.checkbox(&mut port.enabled, "");
                    if ui.small_button("remove").clicked() {
                        remove = Some(i);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = remove {
            self.backend.air_ports.remove(i);
        }
        if ui.button("Add port").clicked() {
            let port = 40000 + self.backend.air_ports.len() as u16 * 111;
            self.backend.air_ports.push(crate::mock::AirPort {
                port,
                protocol: "tcp+udp",
                device: "default",
                enabled: true,
            });
        }
        ui.add_space(8.0);
        ui.columns(2, |cols| {
            cols[0].strong("Devices");
            for d in &self.backend.air_devices {
                cols[0].label(*d);
            }
            cols[1].strong("API keys");
            for k in &self.backend.air_api_keys {
                cols[1].label(*k);
            }
        });
    }

    fn proton_tools(&mut self, ui: &mut Ui) {
        if !self.require_login(ui, Provider::Proton) {
            return;
        }
        ui.strong("Port forwarding (NAT-PMP)");
        let has_tunnel = self
            .backend
            .connections
            .iter()
            .any(|c| c.provider == Provider::Proton);
        if self.backend.proton_forwards.is_empty() {
            ui.weak("No active forwards.");
        }
        egui::Grid::new("pf").num_columns(3).show(ui, |ui| {
            for f in &self.backend.proton_forwards {
                ui.monospace(&f.instance);
                ui.monospace(f.port.to_string());
                ui.weak(format!("renews every {} s", f.expires_in.as_secs()));
                ui.end_row();
            }
        });
        let req = ui
            .add_enabled(has_tunnel, egui::Button::new("Request port"))
            .on_disabled_hover_text("Needs an active Proton tunnel on a P2P server");
        if req.clicked() {
            self.backend.proton_forward();
        }
        ui.add_space(8.0);
        ui.strong("Certificate");
        ui.horizontal(|ui| {
            ui.label("Valid for 6 more days");
            if ui.button("Renew now").clicked() {
                self.toast("Proton certificate renewed");
            }
        });
    }

    fn wgconf_tools(&mut self, ui: &mut Ui) {
        ui.strong("Saved profiles");
        let mut remove = None;
        egui::Grid::new("wg_profiles")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                for (i, p) in self.backend.wg_profiles.iter().enumerate() {
                    ui.label(RichText::new(&p.name).strong());
                    ui.monospace(&p.endpoint);
                    if ui.small_button("remove").clicked() {
                        remove = Some(i);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = remove {
            self.backend.wg_profiles.remove(i);
        }
        if ui.button("Import .conf file...").clicked() {
            let n = self.backend.wg_profiles.len() + 1;
            self.backend.wg_profiles.push(crate::mock::WgProfile {
                name: format!("imported-{n}"),
                endpoint: "198.51.100.4:51820".into(),
            });
            self.toast("Profile imported");
        }
    }

    pub fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_settings;
        egui::Window::new("Settings")
            .open(&mut open)
            .default_size([420.0, 360.0])
            .collapsible(false)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.content_rect().center())
            .show(ctx, |ui| self.settings_body(ui));
        self.show_settings = open;
    }

    fn settings_body(&mut self, ui: &mut Ui) {
        if self.live.is_some() {
            ui.weak("Sample settings: not saved to config.toml yet.");
        }
        let s = &mut self.settings;
        ui.strong("Connections");
        egui::Grid::new("set_conn").num_columns(2).show(ui, |ui| {
            ui.label("Default mode");
            egui::ComboBox::from_id_salt("set_mode")
                .selected_text(s.default_mode.label())
                .show_ui(ui, |ui| {
                    for m in [Mode::Direct, Mode::NetnsProxy, Mode::LocalProxy] {
                        ui.selectable_value(&mut s.default_mode, m, m.label());
                    }
                });
            ui.end_row();
            ui.label("Direct backend");
            egui::ComboBox::from_id_salt("set_backend")
                .selected_text(s.backend.label())
                .show_ui(ui, |ui| {
                    for b in Backend::ALL {
                        ui.selectable_value(&mut s.backend, b, b.label());
                    }
                });
            ui.end_row();
        });
        ui.checkbox(&mut s.autoconnect, "Autoconnect on network change")
            .on_hover_text("Reconnects the last direct tunnel (tunmux autoconnect)");

        ui.add_space(6.0);
        ui.strong("Desktop");
        ui.checkbox(&mut s.start_at_login, "Start at login");
        ui.checkbox(&mut s.start_in_tray, "Start hidden in the tray");
        ui.checkbox(
            &mut s.close_to_tray,
            "Closing the window keeps tunmux in the tray",
        );

        ui.add_space(6.0);
        ui.strong("Storage and logs");
        egui::Grid::new("set_store").num_columns(2).show(ui, |ui| {
            ui.label("Credential store");
            egui::ComboBox::from_id_salt("set_cred")
                .selected_text(s.credential_store)
                .show_ui(ui, |ui| {
                    for v in ["auto", "file", "keyring"] {
                        ui.selectable_value(&mut s.credential_store, v, v);
                    }
                });
            ui.end_row();
            ui.label("Log level");
            egui::ComboBox::from_id_salt("set_log")
                .selected_text(s.log_level)
                .show_ui(ui, |ui| {
                    for v in ["error", "warn", "info", "debug", "trace"] {
                        ui.selectable_value(&mut s.log_level, v, v);
                    }
                });
            ui.end_row();
        });

        ui.add_space(6.0);
        ui.strong("System");
        let ok = Color32::from_rgb(60, 180, 100);
        let warn = Color32::from_rgb(230, 170, 40);
        egui::Grid::new("set_sys").num_columns(2).show(ui, |ui| {
            ui.label("Privileged helper");
            ui.colored_label(ok, "socket /var/run/tunmux/ctl.sock, idle");
            ui.end_row();
            ui.label("Group tunmux");
            ui.colored_label(ok, "member");
            ui.end_row();
            ui.label("System service");
            if s.service_installed {
                ui.colored_label(ok, "installed");
            } else {
                ui.horizontal(|ui| {
                    ui.colored_label(warn, "not installed");
                    if ui.small_button("Install").clicked() {
                        s.service_installed = true;
                    }
                });
            }
            ui.end_row();
        });
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
