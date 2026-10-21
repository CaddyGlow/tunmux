//! Tray menu model. The same item list will feed the real tray (tray-icon or
//! ksni); for now it is rendered as a preview popup inside the window.

use egui::{Color32, Pos2, Sense, Stroke, Ui, Vec2};

use crate::mock::MockBackend;
use crate::model::{ConnectionView, Provider, TrayState};

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
        Some(c) => s += &format!("{} {} ({})", c.provider.label(), c.server, c.country_code),
        None if proxies == 0 => s += "disconnected",
        None => s += "no direct tunnel",
    }
    if proxies > 0 {
        s += &format!(" +{proxies} prox{}", if proxies == 1 { "y" } else { "ies" });
    }
    s
}

pub fn build_menu(backend: &MockBackend) -> Vec<TrayItem> {
    let conns = &backend.connections;
    let mut items = Vec::new();

    match conns.iter().find(|c| c.is_direct()) {
        Some(c) => {
            items.push(TrayItem::Label(format!(
                "{}: {} {} ({})",
                TrayState::from_connections(std::slice::from_ref(c)).label(),
                c.provider.label(),
                c.server,
                c.country_code
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
                format!("{}  SOCKS :{socks}  HTTP :{http}", c.instance),
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

    items.push(TrayItem::Separator);
    let quick: Vec<_> = Provider::ALL
        .into_iter()
        .filter(|p| p.needs_account() && backend.is_logged_in(*p))
        .map(|p| {
            TrayItem::Action(
                format!("{} - fastest", p.label()),
                TrayAction::QuickConnect(p),
            )
        })
        .collect();
    if !quick.is_empty() {
        items.push(TrayItem::Submenu("Quick connect".into(), quick));
    }
    if !backend.recent.is_empty() {
        let recent = backend
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
