//! Main window: a single dashboard with the connection status on top, the
//! server browser below and dialogs for accounts, provider tools and settings.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use egui::{Align, Color32, Layout, RichText, Ui};

use crate::live::Live;
use crate::mock::{ConnectError, MockBackend};
use crate::model::{
    Backend, ConnectSpec, ConnectionView, Health, Mode, Provider, ServerView, SortKey, TrayState,
};
use crate::tray::{self, TrayAction, TrayModel};

const TOAST_TTL: Duration = Duration::from_secs(4);

pub enum Action {
    Connect(ServerView, bool),
    Disconnect(String),
    Recover(String),
    Copy(String, &'static str),
    OpenAccounts(Provider),
    ToggleFavorite(Provider, String),
    Tray(TrayAction),
}

struct Toast {
    text: String,
    error: bool,
    at: Instant,
}

#[derive(Default)]
pub struct LoginForm {
    pub user: String,
    pub secret: String,
    pub code: String,
    pub error: Option<String>,
}

pub struct Settings {
    pub default_mode: Mode,
    pub backend: Backend,
    pub autoconnect: bool,
    pub start_at_login: bool,
    pub start_in_tray: bool,
    pub close_to_tray: bool,
    pub credential_store: &'static str,
    pub log_level: &'static str,
    pub service_installed: bool,
}

pub struct TunmuxApp {
    pub backend: MockBackend,
    provider: Provider,
    country: Option<&'static str>,
    search: String,
    tag: Option<&'static str>,
    pub spec: ConnectSpec,
    sort: SortKey,
    sort_desc: bool,
    favorites: HashSet<(Provider, String)>,
    pub show_accounts: bool,
    pub show_tools: bool,
    pub show_settings: bool,
    show_tray_preview: bool,
    pub accounts_tab: Provider,
    pub login: LoginForm,
    pending_replace: Option<(ServerView, String)>,
    toasts: Vec<Toast>,
    pub settings: Settings,
    pub actions: Vec<Action>,
    /// Real connection status; `None` runs everything on mock data.
    pub live: Option<Live>,
    #[cfg(target_os = "linux")]
    pub systray: Option<crate::systray::Handle>,
    tray_signature: String,
    clipboard: Option<arboard::Clipboard>,
    /// Set by the tray "Quit" item.
    pub quit: bool,
}

impl TunmuxApp {
    pub fn new(live: Option<Live>) -> Self {
        let mut favorites = HashSet::new();
        favorites.insert((Provider::AirVpn, "Hydrus".to_string()));
        Self {
            backend: MockBackend::new(),
            provider: Provider::AirVpn,
            country: None,
            search: String::new(),
            tag: None,
            spec: ConnectSpec::default(),
            sort: SortKey::Load,
            sort_desc: false,
            favorites,
            show_accounts: false,
            show_tools: false,
            show_settings: false,
            show_tray_preview: false,
            accounts_tab: Provider::Proton,
            login: LoginForm::default(),
            pending_replace: None,
            toasts: Vec::new(),
            settings: Settings {
                default_mode: Mode::Direct,
                backend: Backend::Auto,
                autoconnect: false,
                start_at_login: true,
                start_in_tray: true,
                close_to_tray: true,
                credential_store: "auto",
                log_level: "info",
                service_installed: false,
            },
            actions: Vec::new(),
            live,
            #[cfg(target_os = "linux")]
            systray: None,
            tray_signature: String::new(),
            clipboard: None,
            quit: false,
        }
    }

    pub fn connections(&self) -> Vec<ConnectionView> {
        match &self.live {
            Some(live) => live.snapshot().connections,
            None => self.backend.connections.clone(),
        }
    }

    fn corrupt_states(&self) -> Vec<String> {
        match &self.live {
            Some(live) => live.snapshot().corrupt,
            None => self.backend.corrupt_states.clone(),
        }
    }

    pub fn tray_model(&self) -> TrayModel {
        match &self.live {
            // Connecting from the GUI is not wired to the library yet.
            Some(live) => TrayModel {
                conns: live.snapshot().connections,
                ..TrayModel::default()
            },
            None => TrayModel {
                conns: self.backend.connections.clone(),
                quick: Provider::ALL
                    .into_iter()
                    .filter(|p| p.needs_account() && self.backend.is_logged_in(*p))
                    .collect(),
                recent: self.backend.recent.clone(),
            },
        }
    }

    /// Push menu changes to the system tray. In live mode the status thread
    /// also does this, so the tray stays current with the window closed.
    pub fn sync_tray(&mut self) {
        let model = self.tray_model();
        let signature = model.signature();
        if signature == self.tray_signature {
            return;
        }
        self.tray_signature = signature;
        #[cfg(target_os = "linux")]
        if let Some(handle) = &self.systray {
            handle.update(|t| t.model = model);
        }
    }

    /// Per-frame bookkeeping that also runs while the window is hidden.
    pub fn tick(&mut self) {
        if self.live.is_none() {
            self.backend.tick();
        }
        let messages = self
            .live
            .as_ref()
            .map(Live::take_messages)
            .unwrap_or_default();
        for message in messages {
            match message {
                Ok(text) => self.toast(text),
                Err(text) => self.toast_error(text),
            }
        }
        self.sync_tray();
    }

    fn copy(&mut self, ctx: Option<&egui::Context>, text: String) -> Result<(), String> {
        if let Some(ctx) = ctx {
            ctx.copy_text(text);
            return Ok(());
        }
        // No window: keep one clipboard owner alive so the text stays served.
        if self.clipboard.is_none() {
            self.clipboard = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        self.clipboard
            .as_mut()
            .expect("clipboard initialised above")
            .set_text(text)
            .map_err(|e| e.to_string())
    }

    pub fn toast(&mut self, text: impl Into<String>) {
        self.toasts.push(Toast {
            text: text.into(),
            error: false,
            at: Instant::now(),
        });
    }

    pub fn toast_error(&mut self, text: impl Into<String>) {
        self.toasts.push(Toast {
            text: text.into(),
            error: true,
            at: Instant::now(),
        });
    }

    pub fn apply_actions(&mut self, ctx: Option<&egui::Context>) {
        for action in std::mem::take(&mut self.actions) {
            match action {
                Action::Connect(server, replace) => self.connect(server, replace),
                Action::Disconnect(instance) => match &self.live {
                    Some(live) => {
                        live.disconnect(Some(&instance));
                        self.toast(format!("Disconnecting {instance}"));
                    }
                    None => {
                        self.backend.disconnect(&instance);
                        self.toast(format!("Disconnected {instance}"));
                    }
                },
                Action::Recover(instance) => {
                    self.backend.recover(&instance);
                    self.toast(format!("Recovering {instance}"));
                }
                Action::Copy(text, what) => match self.copy(ctx, text) {
                    Ok(()) => self.toast(format!("Copied {what}")),
                    Err(e) => self.toast_error(format!("Cannot copy {what}: {e}")),
                },
                Action::OpenAccounts(p) => {
                    self.accounts_tab = p;
                    self.show_accounts = true;
                }
                Action::ToggleFavorite(p, name) => {
                    let key = (p, name);
                    if !self.favorites.remove(&key) {
                        self.favorites.insert(key);
                    }
                }
                Action::Tray(t) => self.apply_tray(ctx, t),
            }
        }
    }

    /// Handle a tray menu action; `ctx` is `None` while the window is closed.
    pub fn apply_tray(&mut self, ctx: Option<&egui::Context>, action: TrayAction) {
        match action {
            TrayAction::Disconnect(i) => self.actions.push(Action::Disconnect(i)),
            TrayAction::DisconnectAll => match &self.live {
                Some(live) => {
                    live.disconnect(None);
                    self.toast("Disconnecting all");
                }
                None => {
                    self.backend.disconnect_all();
                    self.toast("Disconnected all");
                }
            },
            TrayAction::CopyProxy(addr) => self.actions.push(Action::Copy(addr, "proxy address")),
            TrayAction::QuickConnect(p) => {
                if let Some(s) = self.best_server(p, None) {
                    self.actions.push(Action::Connect(s, false));
                }
            }
            TrayAction::Reconnect(i) => {
                if let Some((p, name, mode)) = self.backend.recent.get(i).cloned() {
                    if let Some(s) = self.backend.find_server(p, &name).cloned() {
                        self.spec.mode = mode;
                        self.actions.push(Action::Connect(s, false));
                    }
                }
            }
            TrayAction::OpenWindow => {
                self.show_tray_preview = false;
                if let Some(ctx) = ctx {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
            }
            TrayAction::Quit => {
                self.quit = true;
                if let Some(ctx) = ctx {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        // Tray actions queued follow-ups; run them this frame.
        if !self.actions.is_empty() {
            self.apply_actions(ctx);
        }
    }

    fn connect(&mut self, server: ServerView, replace: bool) {
        if self.live.is_some() {
            self.toast_error(format!(
                "Connecting from the window is not wired yet; run: tunmux connect {} {}",
                server.provider.label().to_lowercase(),
                server.name
            ));
            return;
        }
        let spec = self.spec.clone();
        match self.backend.connect(&server, &spec, replace) {
            Ok(instance) => self.toast(format!(
                "Connecting {} {} as {instance}",
                server.provider.label(),
                server.name
            )),
            Err(ConnectError::InstanceExists(instance)) => {
                self.pending_replace = Some((server, instance));
            }
            Err(ConnectError::NotLoggedIn(p)) => {
                self.toast_error(format!("Log in to {} first", p.label()));
                self.actions.push(Action::OpenAccounts(p));
            }
        }
    }

    fn filtered_servers(&self) -> Vec<ServerView> {
        let needle = self.search.to_lowercase();
        let mut rows: Vec<ServerView> = self
            .backend
            .servers
            .iter()
            .filter(|s| s.provider == self.provider)
            .filter(|s| self.country.is_none_or(|c| s.country_code == c))
            .filter(|s| self.tag.is_none_or(|t| s.tags.contains(&t)))
            .filter(|s| {
                needle.is_empty()
                    || s.name.to_lowercase().contains(&needle)
                    || s.city.to_lowercase().contains(&needle)
            })
            .cloned()
            .collect();
        let key = |s: &ServerView| -> (u64, String) {
            let n = match self.sort {
                SortKey::Name | SortKey::Country => 0,
                SortKey::Load => s.load.map_or(u64::MAX, |l| (l * 100.0) as u64),
                SortKey::Score => s.score.map_or(u64::MAX, |v| (v * 1000.0) as u64),
                SortKey::Ping => s.ping_ms.map_or(u64::MAX, u64::from),
            };
            let text = match self.sort {
                SortKey::Country => format!("{}{}", s.country_code, s.city),
                _ => s.name.clone(),
            };
            (n, text)
        };
        rows.sort_by_key(key);
        if self.sort_desc {
            rows.reverse();
        }
        // Favorites always float to the top.
        rows.sort_by_key(|s| !self.favorites.contains(&(s.provider, s.name.clone())));
        rows
    }

    fn best_server(&self, provider: Provider, country: Option<&str>) -> Option<ServerView> {
        self.backend
            .servers
            .iter()
            .filter(|s| s.provider == provider)
            .filter(|s| country.is_none_or(|c| s.country_code == c))
            .min_by_key(|s| {
                s.ping_ms
                    .map(u64::from)
                    .unwrap_or_else(|| s.load.map_or(50, |l| l as u64) + 1000)
            })
            .cloned()
    }

    // --- status card -------------------------------------------------------

    fn status_card(&mut self, ui: &mut Ui) {
        let conns = self.connections();
        let state = TrayState::from_connections(&conns);
        let direct = conns.iter().find(|c| c.is_direct());

        ui.horizontal(|ui| {
            tray::paint_icon(ui, state, 28.0).on_hover_text(tray::tooltip(&conns));
            ui.vertical(|ui| match direct {
                Some(c) => self.direct_row(ui, c),
                None => {
                    ui.label(RichText::new("No direct tunnel").strong().size(16.0));
                    ui.weak("Pick a server below, or use Quick connect.");
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !conns.is_empty() && ui.button("Disconnect all").clicked() {
                    self.actions.push(Action::Tray(TrayAction::DisconnectAll));
                }
            });
        });

        let proxies: Vec<_> = conns.iter().filter(|c| !c.is_direct()).collect();
        if !proxies.is_empty() {
            ui.add_space(4.0);
            let row = Layout::left_to_right(Align::Center).with_main_wrap(true);
            ui.with_layout(row, |ui| {
                ui.weak("Proxies");
                for c in proxies {
                    self.proxy_chip(ui, c);
                }
            });
        }
        for name in &self.corrupt_states() {
            ui.colored_label(
                Color32::from_rgb(220, 80, 60),
                format!("State file {name}.json is unreadable."),
            );
        }
    }

    fn direct_row(&mut self, ui: &mut Ui, c: &ConnectionView) {
        let state = TrayState::from_connections(std::slice::from_ref(c));
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(state.label())
                    .strong()
                    .size(16.0)
                    .color(tray::state_color(state)),
            );
            ui.label(RichText::new(format!("{}  {}", c.provider.label(), c.server)).size(16.0));
            ui.weak(location(c));
        });
        ui.horizontal(|ui| {
            match c.health {
                Health::Connecting => {
                    ui.spinner();
                    ui.weak("bringing up tunnel...");
                }
                Health::Active | Health::Unknown => {
                    ui.monospace(&c.virtual_ip);
                    ui.weak(&c.backend);
                    ui.weak(format!(
                        "up {}",
                        fmt_uptime(c.since.elapsed().unwrap_or_default())
                    ));
                    if let (Some(rx), Some(tx)) = (c.rx_bytes, c.tx_bytes) {
                        ui.weak(format!("rx {}  tx {}", fmt_bytes(rx), fmt_bytes(tx)));
                    }
                    if c.health == Health::Unknown {
                        // Unknown is not evidence of failure; say so plainly.
                        ui.colored_label(tray::state_color(TrayState::Connecting), "unverified")
                            .on_hover_text(c.health_reason.as_deref().unwrap_or("no details"));
                    }
                }
                Health::Inactive => {
                    ui.colored_label(
                        tray::state_color(TrayState::Degraded),
                        format!(
                            "inactive: {}",
                            c.health_reason.as_deref().unwrap_or("no details")
                        ),
                    );
                    if self.live.is_none() && ui.small_button("Recover").clicked() {
                        self.actions.push(Action::Recover(c.instance.clone()));
                    }
                }
            }
            let label = if c.health == Health::Connecting {
                "Cancel"
            } else {
                "Disconnect"
            };
            if ui.button(label).clicked() {
                self.actions.push(Action::Disconnect(c.instance.clone()));
            }
        });
    }

    fn proxy_chip(&mut self, ui: &mut Ui, c: &ConnectionView) {
        let state = TrayState::from_connections(std::slice::from_ref(c));
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                tray::paint_icon(ui, state, 12.0);
                ui.label(RichText::new(&c.instance).strong())
                    .on_hover_text(format!(
                        "{} {} {}\n{}, {}: {}",
                        c.provider.label(),
                        c.server,
                        location(c),
                        c.mode.label(),
                        c.health.label(),
                        c.health_reason.as_deref().unwrap_or("")
                    ));
                if c.health == Health::Unknown {
                    ui.colored_label(tray::state_color(TrayState::Connecting), "?")
                        .on_hover_text(format!(
                            "unverified: {}",
                            c.health_reason.as_deref().unwrap_or("no details")
                        ));
                }
                if let (Some(socks), Some(http)) = (c.socks_port, c.http_port) {
                    ui.monospace(format!(":{socks}/:{http}"));
                    if ui
                        .small_button("copy")
                        .on_hover_text("Copy SOCKS5 address")
                        .clicked()
                    {
                        self.actions.push(Action::Copy(
                            format!("socks5://127.0.0.1:{socks}"),
                            "SOCKS5 address",
                        ));
                    }
                }
                if ui.small_button("stop").clicked() {
                    self.actions.push(Action::Disconnect(c.instance.clone()));
                }
            });
        });
    }

    // --- filter bar --------------------------------------------------------

    fn filter_bar(&mut self, ui: &mut Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label("Provider");
            let before = self.provider;
            egui::ComboBox::from_id_salt("provider")
                .selected_text(self.provider.label())
                .show_ui(ui, |ui| {
                    for p in Provider::ALL {
                        let text = if p.needs_account() && !self.backend.is_logged_in(p) {
                            format!("{} (log in)", p.label())
                        } else {
                            p.label().to_string()
                        };
                        ui.selectable_value(&mut self.provider, p, text);
                    }
                });
            if before != self.provider {
                self.country = None;
                self.tag = None;
            }

            let mut countries: Vec<&'static str> = self
                .backend
                .servers
                .iter()
                .filter(|s| s.provider == self.provider)
                .map(|s| s.country_code)
                .collect();
            countries.sort_unstable();
            countries.dedup();
            ui.label("Country");
            egui::ComboBox::from_id_salt("country")
                .selected_text(self.country.unwrap_or("Any"))
                .width(60.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.country, None, "Any");
                    for c in countries {
                        ui.selectable_value(&mut self.country, Some(c), c);
                    }
                });

            let mut tags: Vec<&'static str> = self
                .backend
                .servers
                .iter()
                .filter(|s| s.provider == self.provider)
                .flat_map(|s| s.tags.iter().copied())
                .collect();
            tags.sort_unstable();
            tags.dedup();
            if !tags.is_empty() {
                ui.label("Feature");
                egui::ComboBox::from_id_salt("tag")
                    .selected_text(self.tag.unwrap_or("Any"))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.tag, None, "Any");
                        for t in tags {
                            ui.selectable_value(&mut self.tag, Some(t), t);
                        }
                    });
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search server or city")
                    .desired_width(160.0),
            );
        });

        ui.horizontal_wrapped(|ui| {
            ui.label("Mode");
            for m in [Mode::Direct, Mode::NetnsProxy, Mode::LocalProxy] {
                ui.radio_value(&mut self.spec.mode, m, m.label())
                    .on_hover_text(mode_help(m));
            }
            ui.menu_button("Advanced", |ui| self.advanced_options(ui));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let quick = egui::Button::new(RichText::new("Quick connect").strong());
                let target = self.best_server(self.provider, self.country);
                let resp = ui
                    .add_enabled(target.is_some(), quick)
                    .on_hover_text("Lowest ping, or lowest load if not probed yet");
                if resp.clicked() {
                    if let Some(s) = target {
                        self.actions.push(Action::Connect(s, false));
                    }
                }
                if ui
                    .button("Probe ping")
                    .on_hover_text("TCP probe of every listed endpoint")
                    .clicked()
                {
                    self.backend.probe_pings(self.provider);
                    self.sort = SortKey::Ping;
                    self.sort_desc = false;
                }
            });
        });
    }

    fn advanced_options(&mut self, ui: &mut Ui) {
        ui.set_min_width(240.0);
        egui::Grid::new("advanced").num_columns(2).show(ui, |ui| {
            ui.label("Backend");
            egui::ComboBox::from_id_salt("backend")
                .selected_text(self.spec.backend.label())
                .show_ui(ui, |ui| {
                    for b in Backend::ALL {
                        ui.selectable_value(&mut self.spec.backend, b, b.label());
                    }
                });
            ui.end_row();
            ui.label("MTU");
            optional_u16(ui, &mut self.spec.mtu, 1280, 576..=9000);
            ui.end_row();
            ui.label("SOCKS port");
            optional_u16(ui, &mut self.spec.socks_port, 1080, 1024..=65535);
            ui.end_row();
            ui.label("HTTP port");
            optional_u16(ui, &mut self.spec.http_port, 8118, 1024..=65535);
            ui.end_row();
        });
        ui.checkbox(&mut self.spec.disable_ipv6, "Disable IPv6");
        ui.checkbox(&mut self.spec.allow_lan, "Allow LAN access to proxy");
        ui.checkbox(&mut self.spec.access_log, "Proxy access log");
        if ui.button("Reset").clicked() {
            let mode = self.spec.mode;
            self.spec = ConnectSpec {
                mode,
                ..ConnectSpec::default()
            };
        }
    }

    // --- server table ------------------------------------------------------

    fn server_table(&mut self, ui: &mut Ui) {
        let provider = self.provider;
        if provider.needs_account() && !self.backend.is_logged_in(provider) {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading(format!("Not logged in to {}", provider.label()));
                ui.add_space(8.0);
                if ui
                    .button(format!("Log in to {}...", provider.label()))
                    .clicked()
                {
                    self.actions.push(Action::OpenAccounts(provider));
                }
            });
            return;
        }
        if self.live.is_some() {
            ui.weak("Sample server list: browsing and connecting are wired to the library next.");
        }
        let rows = self.filtered_servers();
        let connected: Vec<(String, String)> = self
            .connections()
            .iter()
            .filter(|c| c.provider == provider)
            .map(|c| (c.server.clone(), c.instance.clone()))
            .collect();

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("servers")
                .striped(true)
                .spacing([14.0, 6.0])
                .min_col_width(0.0)
                .show(ui, |ui| {
                    ui.label("");
                    self.sort_header(ui, "Server", SortKey::Name);
                    self.sort_header(ui, "Location", SortKey::Country);
                    if provider.has_load() {
                        self.sort_header(ui, "Load", SortKey::Load);
                    }
                    if provider.has_score() {
                        self.sort_header(ui, "Score", SortKey::Score)
                            .on_hover_text("Provider score, lower is better");
                    }
                    self.sort_header(ui, "Ping", SortKey::Ping);
                    ui.strong("Features");
                    ui.label("");
                    ui.end_row();

                    for s in &rows {
                        self.server_row(ui, s, &connected);
                        ui.end_row();
                    }
                });
            if rows.is_empty() {
                ui.add_space(20.0);
                ui.vertical_centered(|ui| ui.weak("No servers match the filters."));
            }
        });
    }

    fn sort_header(&mut self, ui: &mut Ui, text: &str, key: SortKey) -> egui::Response {
        let arrow = match (self.sort == key, self.sort_desc) {
            (true, false) => " ^",
            (true, true) => " v",
            _ => "",
        };
        let resp = ui
            .add(egui::Button::new(RichText::new(format!("{text}{arrow}")).strong()).frame(false));
        if resp.clicked() {
            if self.sort == key {
                self.sort_desc = !self.sort_desc;
            } else {
                self.sort = key;
                self.sort_desc = false;
            }
        }
        resp
    }

    fn server_row(&mut self, ui: &mut Ui, s: &ServerView, connected: &[(String, String)]) {
        let fav = self.favorites.contains(&(s.provider, s.name.clone()));
        let star = if fav {
            RichText::new("*")
                .strong()
                .color(Color32::from_rgb(230, 170, 40))
        } else {
            RichText::new("*").weak()
        };
        if ui
            .add(egui::Button::new(star).frame(false))
            .on_hover_text(if fav {
                "Remove favorite"
            } else {
                "Add favorite"
            })
            .clicked()
        {
            self.actions
                .push(Action::ToggleFavorite(s.provider, s.name.clone()));
        }

        let live = connected.iter().find(|(name, _)| *name == s.name);
        let name = RichText::new(&s.name);
        let name = if live.is_some() { name.strong() } else { name };
        let resp = ui
            .add(egui::Button::new(name).frame(false))
            .on_hover_text("Double click to connect, right click for more");
        if resp.double_clicked() {
            self.actions.push(Action::Connect(s.clone(), false));
        }
        resp.context_menu(|ui| {
            if ui.button("Connect direct").clicked() {
                self.spec.mode = Mode::Direct;
                self.actions.push(Action::Connect(s.clone(), false));
                ui.close();
            }
            if ui.button("Connect as local proxy").clicked() {
                self.spec.mode = Mode::LocalProxy;
                self.actions.push(Action::Connect(s.clone(), false));
                ui.close();
            }
            if ui.button("Copy name").clicked() {
                self.actions
                    .push(Action::Copy(s.name.clone(), "server name"));
                ui.close();
            }
        });

        ui.label(format!("{}  {}", s.country_code, s.city));
        if s.provider.has_load() {
            match s.load {
                Some(l) => {
                    ui.add(
                        egui::ProgressBar::new(l / 100.0)
                            .desired_width(70.0)
                            .text(format!("{l:.0}%")),
                    );
                }
                None => {
                    ui.weak("-");
                }
            }
        }
        if s.provider.has_score() {
            match s.score {
                Some(v) => ui.monospace(format!("{v:.2}")),
                None => ui.weak("-"),
            };
        }
        match s.ping_ms {
            Some(ms) => ui.monospace(format!("{ms} ms")),
            None => ui.weak("-"),
        };
        ui.weak(s.tags.join(", "));

        match live {
            Some((_, instance)) => {
                if ui.button("Disconnect").clicked() {
                    self.actions.push(Action::Disconnect(instance.clone()));
                }
            }
            None => {
                if ui
                    .button("Connect")
                    .on_hover_text(format!("Connect ({})", self.spec.mode.label()))
                    .clicked()
                {
                    self.actions.push(Action::Connect(s.clone(), false));
                }
            }
        }
    }

    // --- footer, overlays --------------------------------------------------

    fn footer(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.button("Accounts").clicked() {
                self.show_accounts = true;
            }
            if ui.button("Provider tools").clicked() {
                self.show_tools = true;
            }
            if ui.button("Settings").clicked() {
                self.show_settings = true;
            }
            ui.separator();
            let tray_btn = ui
                .button("Tray menu")
                .on_hover_text("Preview of the system tray menu");
            if tray_btn.clicked() {
                self.show_tray_preview = !self.show_tray_preview;
            }
            if self.live.is_none() {
                self.mock_menu(ui);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let accounts = self
                    .backend
                    .accounts
                    .iter()
                    .filter(|a| a.provider.needs_account() && self.backend.is_logged_in(a.provider))
                    .count();
                let source = if self.live.is_some() {
                    "live status, sample servers and accounts"
                } else {
                    "mock data"
                };
                ui.weak(format!(
                    "{} tunnel(s), {accounts} account(s) - {source}",
                    self.connections().len()
                ));
            });
        });
    }

    fn mock_menu(&mut self, ui: &mut Ui) {
        ui.menu_button("Mock", |ui| {
            if ui.button("Health unknown on first tunnel").clicked() {
                self.backend
                    .degrade_first(Health::Unknown, "privileged helper not reachable");
                ui.close();
            }
            if ui.button("Last proxy inactive").clicked() {
                self.backend
                    .degrade_last(Health::Inactive, "proxy daemon pid 4211 exited");
                ui.close();
            }
            if ui.button("Unreadable state file").clicked() {
                self.backend.corrupt_states.push("old-nl".into());
                ui.close();
            }
            if ui.button("Error toast").clicked() {
                self.toast_error("privileged helper: permission denied (not in group tunmux)");
                ui.close();
            }
        });
    }

    fn tray_preview(&mut self, ctx: &egui::Context) {
        if !self.show_tray_preview {
            return;
        }
        let model = self.tray_model();
        let items = tray::build_menu(&model);
        let state = TrayState::from_connections(&model.conns);
        let mut open = true;
        egui::Window::new("Tray menu preview")
            .open(&mut open)
            .resizable(false)
            .collapsible(false)
            .anchor(egui::Align2::RIGHT_TOP, [-12.0, 12.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    tray::paint_icon(ui, state, 18.0);
                    ui.weak(tray::tooltip(&model.conns));
                });
                ui.separator();
                if let Some(a) = tray::show_menu(ui, &items) {
                    self.actions.push(Action::Tray(a));
                }
                ui.separator();
                ui.weak("Icon states");
                ui.horizontal(|ui| {
                    for s in [
                        TrayState::Disconnected,
                        TrayState::Connecting,
                        TrayState::Direct,
                        TrayState::ProxiesOnly,
                        TrayState::Degraded,
                    ] {
                        tray::paint_icon(ui, s, 16.0).on_hover_text(s.label());
                    }
                });
            });
        self.show_tray_preview &= open;
    }

    fn replace_prompt(&mut self, ctx: &egui::Context) {
        let Some((server, instance)) = self.pending_replace.clone() else {
            return;
        };
        let resp = egui::Modal::new(egui::Id::unique("replace")).show(ctx, |ui| {
            ui.set_max_width(340.0);
            ui.heading("Instance already running");
            ui.label(format!(
                "'{instance}' is in use. Replace it with {} {}?",
                server.provider.label(),
                server.name
            ));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Replace").clicked() {
                    self.actions.push(Action::Connect(server.clone(), true));
                    self.pending_replace = None;
                }
                if ui.button("Cancel").clicked() {
                    self.pending_replace = None;
                }
            });
        });
        if resp.should_close() {
            self.pending_replace = None;
        }
    }

    fn toasts(&mut self, ctx: &egui::Context) {
        self.toasts.retain(|t| t.at.elapsed() < TOAST_TTL);
        if self.toasts.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::unique("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -40.0])
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                for t in &self.toasts {
                    let fill = if t.error {
                        Color32::from_rgb(120, 40, 35)
                    } else {
                        Color32::from_rgb(40, 60, 50)
                    };
                    egui::Frame::popup(ui.style()).fill(fill).show(ui, |ui| {
                        ui.colored_label(Color32::WHITE, &t.text);
                    });
                }
            });
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

impl TunmuxApp {
    /// Draw the whole window; `tick` has run for this frame already.
    pub fn show(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        // Uptime (and mock traffic) moves every second.
        ctx.request_repaint_after(if self.live.is_none() && self.backend.is_busy() {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        });

        egui::Panel::top("status")
            .frame(egui::Frame::side_top_panel(ui.style()).inner_margin(10.0))
            .show(ui, |ui| self.status_card(ui));
        egui::Panel::top("filters")
            .frame(egui::Frame::side_top_panel(ui.style()).inner_margin(8.0))
            .show(ui, |ui| self.filter_bar(ui));
        egui::Panel::bottom("footer")
            .frame(egui::Frame::side_top_panel(ui.style()).inner_margin(6.0))
            .show(ui, |ui| self.footer(ui));
        egui::CentralPanel::default_margins().show(ui, |ui| self.server_table(ui));

        self.accounts_window(&ctx);
        self.tools_window(&ctx);
        self.settings_window(&ctx);
        self.tray_preview(&ctx);
        self.replace_prompt(&ctx);
        self.toasts(&ctx);
        self.apply_actions(Some(&ctx));
    }
}

fn optional_u16(
    ui: &mut Ui,
    value: &mut Option<u16>,
    default: u16,
    range: std::ops::RangeInclusive<u16>,
) {
    ui.horizontal(|ui| {
        let mut set = value.is_some();
        if ui.checkbox(&mut set, "").changed() {
            *value = set.then_some(default);
        }
        match value {
            Some(v) => {
                ui.add(egui::DragValue::new(v).range(range));
            }
            None => {
                ui.weak("auto");
            }
        }
    });
}

fn mode_help(mode: Mode) -> &'static str {
    match mode {
        Mode::Direct => "Route all traffic through the tunnel (one at a time)",
        Mode::NetnsProxy => "Kernel WireGuard in a network namespace, exposed as SOCKS5/HTTP",
        Mode::LocalProxy => "Rootless userspace tunnel exposed as SOCKS5/HTTP",
    }
}

/// "CH, Zurich", skipping parts the source does not know.
fn location(c: &ConnectionView) -> String {
    [c.country_code.as_str(), c.city.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn fmt_uptime(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
