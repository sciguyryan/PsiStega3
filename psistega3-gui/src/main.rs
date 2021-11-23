#![crate_name = "psistega3_gui"]

#![windows_subsystem = "windows"]

sixtyfps::include_modules!();

fn main() {
    MainWindow::new().run();
}
