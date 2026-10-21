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
mod worker;

use std::path::PathBuf;
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
    if let Some(arg) = args
        .iter()
        .find(|a| !["--mock", "--hidden"].contains(&a.as_str()))
    {
        // Also stops a helper re-exec aimed at the wrong binary from
        // opening a second window.
        eprintln!("tunmux-gui: unknown argument {arg:?}; options: --mock, --hidden");
        std::process::exit(2);
    }
    let mock = args.iter().any(|a| a == "--mock");
    let hidden = args.iter().any(|a| a == "--hidden");
    let cli = (!mock).then(find_cli).flatten();
    if let Some(path) = &cli {
        tunmux::shared::executable::set_cli_executable(path.clone());
    }

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
            let live = live::Live::start(move |snap| {
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
            live::Live::start(move |_| repaint())
        })
    };

    let worker = live
        .is_some()
        .then(|| worker::Worker::start(repaint.clone()));
    let mut app = TunmuxApp::new(live, worker);
    if !mock && cli.is_none() {
        tracing::warn!("gui_cli_not_found");
        app.toast_error("tunmux not found next to tunmux-gui or on PATH; connecting needs it");
    }
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

/// The tunmux CLI, which the library spawns for the privileged helper and
/// proxy daemons: next to this binary first, so versions match, then PATH.
fn find_cli() -> Option<PathBuf> {
    let sibling = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("tunmux")));
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join("tunmux"));
    sibling.into_iter().chain(on_path).find(|p| p.is_file())
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
