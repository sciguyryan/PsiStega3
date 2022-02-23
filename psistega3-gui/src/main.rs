#![crate_name = "psistega3_gui"]

#![windows_subsystem = "windows"]

use gtk4 as gtk;
use gtk::prelude::*;
use gtk::{Application, ApplicationWindow};

fn main() {
    let app = Application::builder()
        .application_id("org.sciguyryan.MainWindow")
        .build();

    app.connect_activate(|app| {
        // We create the main window.
        let window = ApplicationWindow::builder()
            .application(app)
            .default_width(800)
            .default_height(600)
            .title("PsiStega3 :: GUI")
            .build();

        // Show the window.
        window.show();
    });

    app.run();
}