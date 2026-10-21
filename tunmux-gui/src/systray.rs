//! StatusNotifierItem tray (KDE, GNOME with AppIndicator, waybar, ...).

use std::sync::mpsc::Sender;

use ksni::blocking::TrayMethods;
use ksni::menu::{StandardItem, SubMenu};
use ksni::MenuItem;

use crate::live::Notify;
use crate::model::TrayState;
use crate::tray::{self, TrayAction, TrayItem, TrayModel};

pub type Handle = ksni::blocking::Handle<SysTray>;

pub struct SysTray {
    pub model: TrayModel,
    actions: Sender<TrayAction>,
    /// Wakes the window, if shown, so it handles the action promptly.
    notify: Notify,
    /// Runs when the menu opens, to refresh status.
    on_menu: Box<dyn Fn() + Send>,
}

impl SysTray {
    fn send(&self, action: TrayAction) {
        let _ = self.actions.send(action);
        (self.notify)();
    }
}

/// Start the tray, or `None` when no StatusNotifierWatcher is running.
pub fn spawn(
    actions: Sender<TrayAction>,
    notify: Notify,
    on_menu: impl Fn() + Send + 'static,
) -> Option<Handle> {
    let tray = SysTray {
        model: TrayModel::default(),
        actions,
        notify,
        on_menu: Box::new(on_menu),
    };
    tray.spawn()
        .inspect_err(|error| tracing::warn!(%error, "gui_tray_unavailable"))
        .ok()
}

impl ksni::Tray for SysTray {
    fn id(&self) -> String {
        "tunmux".into()
    }

    fn title(&self) -> String {
        "tunmux".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let state = TrayState::from_connections(&self.model.conns);
        [22usize, 32, 48]
            .into_iter()
            .map(|size| ksni::Icon {
                width: size as i32,
                height: size as i32,
                data: tray::icon_argb(state, size),
            })
            .collect()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: tray::tooltip(&self.model.conns),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayAction::OpenWindow);
    }

    fn menu_about_to_show(&mut self) {
        (self.on_menu)();
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        convert(tray::build_menu(&self.model))
    }
}

fn convert(items: Vec<TrayItem>) -> Vec<MenuItem<SysTray>> {
    items
        .into_iter()
        .map(|item| match item {
            TrayItem::Label(label) => StandardItem {
                label: escape(&label),
                enabled: false,
                ..Default::default()
            }
            .into(),
            TrayItem::Action(label, action) => StandardItem {
                label: escape(&label),
                activate: Box::new(move |t: &mut SysTray| t.send(action.clone())),
                ..Default::default()
            }
            .into(),
            TrayItem::Submenu(label, children) => SubMenu {
                label: escape(&label),
                submenu: convert(children),
                ..Default::default()
            }
            .into(),
            TrayItem::Separator => MenuItem::Separator,
        })
        .collect()
}

/// Menu labels treat `_` as an access-key marker; instance names use it.
fn escape(label: &str) -> String {
    label.replace('_', "__")
}
