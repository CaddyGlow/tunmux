//! Desktop front-end for tunmux. This first version runs on mock data so the
//! interface can be reviewed before it is wired to the library.

mod app;
mod dialogs;
mod mock;
mod model;
mod tray;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("tunmux")
            .with_app_id("tunmux")
            .with_inner_size([860.0, 600.0])
            .with_min_inner_size([620.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "tunmux",
        options,
        Box::new(|_cc| Ok(Box::new(app::TunmuxApp::new()))),
    )
}
