//! Tray menu model, shared by the system tray (`systray`) and the preview
//! popup inside the window.

use egui::{Color32, Pos2, Sense, Stroke, Ui, Vec2};

use crate::model::{ConnectionView, Health, Mode, Provider, TrayState};

/// Everything the tray menu shows.
#[derive(Debug, Clone, Default)]
pub struct TrayModel {
    pub conns: Vec<ConnectionView>,
    /// Logged-in providers offered under "Quick connect".
    pub quick: Vec<Provider>,
    pub recent: Vec<(Provider, String, Mode)>,
}

impl TrayModel {
    /// Changes that alter the menu or icon; traffic and uptime are ignored.
    pub fn signature(&self) -> String {
        let mut s = String::new();
        for c in &self.conns {
            s += &format!(
                "{}|{}|{:?}|{:?}|{:?};",
                c.instance, c.server, c.health, c.socks_port, c.http_port
            );
        }
        s += &format!("{:?}{:?}", self.quick, self.recent);
        s
    }
}

#[derive(Debug, Clone)]
pub enum TrayAction {
    Disconnect(String),
    DisconnectAll,
    CopyProxy(String),
    QuickConnect(Provider),
    Reconnect(usize),
    OpenWindow,
    Quit,
}

pub enum TrayItem {
    Label(String),
    Action(String, TrayAction),
    Submenu(String, Vec<TrayItem>),
    Separator,
}

pub fn tooltip(conns: &[ConnectionView]) -> String {
    let direct = conns.iter().find(|c| c.is_direct());
    let proxies = conns.iter().filter(|c| !c.is_direct()).count();
    let mut s = String::from("tunmux - ");
    match direct {
        Some(c) => s += &format!("{} {}", c.provider.label(), place(c)),
        None if proxies == 0 => s += "disconnected",
        None => s += "no direct tunnel",
    }
    if proxies > 0 {
        s += &format!(" +{proxies} prox{}", if proxies == 1 { "y" } else { "ies" });
    }
    s
}

/// "Hydrus (CH)" or just the server name when the country is unknown.
pub fn place(c: &ConnectionView) -> String {
    if c.country_code.is_empty() {
        c.server.clone()
    } else {
        format!("{} ({})", c.server, c.country_code)
    }
}

pub fn build_menu(model: &TrayModel) -> Vec<TrayItem> {
    let conns = &model.conns;
    let mut items = Vec::new();

    match conns.iter().find(|c| c.is_direct()) {
        Some(c) => {
            items.push(TrayItem::Label(format!(
                "{}: {} {}",
                TrayState::from_connections(std::slice::from_ref(c)).label(),
                c.provider.label(),
                place(c)
            )));
            items.push(TrayItem::Action(
                "Disconnect direct".into(),
                TrayAction::Disconnect(c.instance.clone()),
            ));
        }
        None => items.push(TrayItem::Label("Not connected".into())),
    }

    let proxies: Vec<_> = conns.iter().filter(|c| !c.is_direct()).collect();
    if !proxies.is_empty() {
        items.push(TrayItem::Separator);
        items.push(TrayItem::Label("Proxies".into()));
        for c in proxies {
            let socks = c.socks_port.unwrap_or_default();
            let http = c.http_port.unwrap_or_default();
            items.push(TrayItem::Submenu(
                format!(
                    "{}  SOCKS :{socks}  HTTP :{http}{}",
                    c.instance,
                    match c.health {
                        Health::Inactive => "  (inactive)",
                        Health::Connecting => "  (connecting)",
                        Health::Active | Health::Unknown => "",
                    }
                ),
                vec![
                    TrayItem::Action(
                        "Copy SOCKS address".into(),
                        TrayAction::CopyProxy(format!("socks5://127.0.0.1:{socks}")),
                    ),
                    TrayItem::Action(
                        "Disconnect".into(),
                        TrayAction::Disconnect(c.instance.clone()),
                    ),
                ],
            ));
        }
    }

    if !model.quick.is_empty() || !model.recent.is_empty() {
        items.push(TrayItem::Separator);
    }
    if !model.quick.is_empty() {
        let quick = model
            .quick
            .iter()
            .map(|p| {
                TrayItem::Action(
                    format!("{} - fastest", p.label()),
                    TrayAction::QuickConnect(*p),
                )
            })
            .collect();
        items.push(TrayItem::Submenu("Quick connect".into(), quick));
    }
    if !model.recent.is_empty() {
        let recent = model
            .recent
            .iter()
            .enumerate()
            .map(|(i, (p, s, m))| {
                TrayItem::Action(
                    format!("{} {} ({})", p.label(), s, m.label()),
                    TrayAction::Reconnect(i),
                )
            })
            .collect();
        items.push(TrayItem::Submenu("Recent".into(), recent));
    }
    items.push(TrayItem::Separator);
    if !conns.is_empty() {
        items.push(TrayItem::Action(
            "Disconnect all".into(),
            TrayAction::DisconnectAll,
        ));
    }
    items.push(TrayItem::Action(
        "Open tunmux...".into(),
        TrayAction::OpenWindow,
    ));
    items.push(TrayItem::Action("Quit".into(), TrayAction::Quit));
    items
}

/// Render the menu with egui menus, returning the clicked action.
pub fn show_menu(ui: &mut Ui, items: &[TrayItem]) -> Option<TrayAction> {
    let mut picked = None;
    for item in items {
        match item {
            TrayItem::Label(text) => {
                ui.add_enabled(false, egui::Button::new(text.as_str()).frame(false));
            }
            TrayItem::Action(text, action) => {
                if ui.button(text.as_str()).clicked() {
                    picked = Some(action.clone());
                }
            }
            TrayItem::Submenu(text, children) => {
                ui.menu_button(text.as_str(), |ui| {
                    if let Some(a) = show_menu(ui, children) {
                        picked = Some(a);
                    }
                });
            }
            TrayItem::Separator => {
                ui.separator();
            }
        }
    }
    picked
}

pub fn state_color(state: TrayState) -> Color32 {
    match state {
        TrayState::Disconnected => Color32::from_gray(140),
        TrayState::Connecting => Color32::from_rgb(230, 170, 40),
        TrayState::Direct | TrayState::ProxiesOnly => Color32::from_rgb(60, 180, 100),
        TrayState::Degraded => Color32::from_rgb(220, 80, 60),
    }
}

/// Draw the tray icon for `state` at `size` points. Used in the window too,
/// so the user learns the icon meanings.
pub fn paint_icon(ui: &mut Ui, state: TrayState, size: f32) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
    let painter = ui.painter_at(rect);
    let c = rect.center();
    let r = size * 0.42;
    let color = state_color(state);
    match state {
        TrayState::Disconnected => {
            painter.circle_stroke(c, r, Stroke::new(size * 0.1, color));
        }
        TrayState::Connecting => {
            painter.circle_stroke(c, r, Stroke::new(size * 0.1, color.gamma_multiply(0.4)));
            let t = ui.input(|i| i.time) as f32;
            let a = t * 4.0;
            let p = c + Vec2::angled(a) * r;
            painter.circle_filled(p, size * 0.12, color);
            ui.ctx().request_repaint();
        }
        TrayState::Direct => {
            painter.circle_filled(c, r, color);
        }
        TrayState::ProxiesOnly => {
            painter.circle_stroke(c, r, Stroke::new(size * 0.1, color));
            painter.circle_filled(c, r * 0.45, color);
        }
        TrayState::Degraded => {
            painter.circle_filled(c, r, color.gamma_multiply(0.35));
            let top = Pos2::new(c.x, c.y - r * 0.55);
            painter.line_segment(
                [top, Pos2::new(c.x, c.y + r * 0.15)],
                Stroke::new(size * 0.12, color),
            );
            painter.circle_filled(Pos2::new(c.x, c.y + r * 0.5), size * 0.07, color);
        }
    }
    response
}

/// Render the tray icon as ARGB32 pixels (network byte order), using the
/// same shapes as `paint_icon`, with 4x4 supersampling.
pub fn icon_argb(state: TrayState, size: usize) -> Vec<u8> {
    let color = state_color(state);
    let faint = color.gamma_multiply(0.35);
    let s = size as f32;
    let (c, r, w) = (s / 2.0, s * 0.42, s * 0.1);
    let sample = |x: f32, y: f32| -> Option<Color32> {
        let d = ((x - c).powi(2) + (y - c).powi(2)).sqrt();
        let ring = (d - (r - w / 2.0)).abs() <= w / 2.0;
        match state {
            TrayState::Disconnected | TrayState::Connecting => ring.then_some(color),
            TrayState::Direct => (d <= r).then_some(color),
            TrayState::ProxiesOnly => (ring || d <= r * 0.45).then_some(color),
            TrayState::Degraded => {
                let bar = (x - c).abs() <= s * 0.06 && y >= c - r * 0.55 && y <= c + r * 0.15;
                let dot = ((x - c).powi(2) + (y - (c + r * 0.5)).powi(2)).sqrt() <= s * 0.07;
                if bar || dot {
                    Some(Color32::WHITE)
                } else {
                    (d <= r).then_some(faint)
                }
            }
        }
    };
    let mut out = Vec::with_capacity(size * size * 4);
    for py in 0..size {
        for px in 0..size {
            let (mut a, mut rr, mut gg, mut bb) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..4 {
                for sx in 0..4 {
                    let x = px as f32 + (sx as f32 + 0.5) / 4.0;
                    let y = py as f32 + (sy as f32 + 0.5) / 4.0;
                    if let Some(col) = sample(x, y) {
                        let ca = col.a() as f32 / 255.0;
                        a += ca;
                        rr += col.r() as f32;
                        gg += col.g() as f32;
                        bb += col.b() as f32;
                    }
                }
            }
            // Color32 is premultiplied; average then un-premultiply.
            let alpha = a / 16.0;
            let un = |v: f32| {
                if alpha > 0.0 {
                    (v / 16.0 / alpha).min(255.0) as u8
                } else {
                    0
                }
            };
            out.extend_from_slice(&[(alpha * 255.0) as u8, un(rr), un(gg), un(bb)]);
        }
    }
    out
}
