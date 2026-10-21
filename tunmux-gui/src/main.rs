//! Desktop front-end for tunmux: a system tray that follows the saved
//! connections, and a window to manage them.
//!
//! The process lives in the tray. The window is opened from the tray and
//! closing it keeps the tray running; without a tray, closing it quits.
//!
//! Options: `--mock` runs on sample data only, `--hidden` starts in the tray.

mod app;
mod dialogs;
mod live;
mod mock;
mod model;
#[cfg(target_os = "linux")]
mod systray;
mod tray;

use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

use app::TunmuxApp;
use tray::TrayAction;

/// The egui context of the open window, if any.
type WindowCtx = Arc<Mutex<Option<egui::Context>>>;

fn main() -> eframe::Result {
    // Library code logs through `tracing`; keep the guard to flush on exit.
    let _logging = tunmux::logging::init_terminal(false)
        .inspect_err(|e| eprintln!("tunmux-gui: logging disabled: {e}"))
        .ok();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mock = args.iter().any(|a| a == "--mock");
    let hidden = args.iter().any(|a| a == "--hidden");

    let window_ctx: WindowCtx = Arc::default();
    let repaint: live::Notify = {
        let window_ctx = window_ctx.clone();
        Arc::new(move || {
            if let Some(ctx) = window_ctx.lock().ok().and_then(|c| c.clone()) {
                ctx.request_repaint();
            }
        })
    };
    let (actions_tx, actions) = mpsc::channel::<TrayAction>();

    #[cfg(target_os = "linux")]
    let (systray, live) = {
        // The tray menu refresh needs the watcher, and the watcher updates
        // the tray, so connect them through a late-bound waker.
        let waker: Arc<Mutex<Option<live::Waker>>> = Arc::default();
        let menu_waker = waker.clone();
        let systray = systray::spawn(actions_tx, repaint.clone(), move || {
            if let Some(w) = menu_waker.lock().ok().and_then(|w| w.clone()) {
                w.wake();
            }
        });
        let live = (!mock).then(|| {
            let handle = systray.clone();
            let repaint = repaint.clone();
            let live = live::Live::start(repaint.clone(), move |snap| {
                if let Some(h) = &handle {
                    let conns = snap.connections.clone();
                    h.update(|t| t.model.conns = conns);
                }
                repaint();
            });
            if let Ok(mut w) = waker.lock() {
                *w = Some(live.waker());
            }
            live
        });
        (systray, live)
    };
    #[cfg(not(target_os = "linux"))]
    let live = {
        drop(actions_tx);
        (!mock).then(|| {
            let repaint = repaint.clone();
            live::Live::start(repaint.clone(), move |_| repaint())
        })
    };

    let mut app = TunmuxApp::new(live);
    #[cfg(target_os = "linux")]
    let has_tray = systray.is_some();
    #[cfg(not(target_os = "linux"))]
    let has_tray = false;
    #[cfg(target_os = "linux")]
    {
        app.systray = systray;
    }
    app.sync_tray();

    let mut open = !(hidden && has_tray);
    loop {
        if open {
            run_window(&mut app, &actions, &window_ctx)?;
            if app.quit || !has_tray || !app.settings.close_to_tray {
                break;
            }
            open = false;
        }
        match actions.recv() {
            Ok(TrayAction::OpenWindow) => open = true,
            Ok(TrayAction::Quit) | Err(_) => break,
            Ok(action) => {
                app.apply_tray(None, action);
                app.tick();
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(handle) = app.systray.take() {
        handle.shutdown().wait();
    }
    Ok(())
}

fn run_window(
    app: &mut TunmuxApp,
    actions: &Receiver<TrayAction>,
    window_ctx: &WindowCtx,
) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("tunmux")
            .with_app_id("tunmux")
            .with_inner_size([860.0, 600.0])
            .with_min_inner_size([620.0, 420.0]),
        ..Default::default()
    };
    if let Some(live) = &app.live {
        live.set_window_open(true);
    }
    let result = eframe::run_native(
        "tunmux",
        options,
        Box::new(|cc| {
            if let Ok(mut slot) = window_ctx.lock() {
                *slot = Some(cc.egui_ctx.clone());
            }
            Ok(Box::new(Window {
                app: &mut *app,
                actions,
            }))
        }),
    );
    if let Ok(mut slot) = window_ctx.lock() {
        *slot = None;
    }
    if let Some(live) = &app.live {
        live.set_window_open(false);
    }
    result
}

/// Borrows the long-lived app for one window session.
struct Window<'a> {
    app: &'a mut TunmuxApp,
    actions: &'a Receiver<TrayAction>,
}

impl eframe::App for Window<'_> {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        for action in self.actions.try_iter() {
            self.app.apply_tray(Some(ctx), action);
        }
        self.app.tick();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.app.show(ui);
    }
}
