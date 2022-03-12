#![crate_name = "psistega3_gui"]

#![windows_subsystem = "windows"]

use fltk::{app, prelude::*, window::Window, image};

fn main() {
    let app = app::App::default();
    let mut wind = Window::new(100, 100, 800, 600, "PsiStega 3 :: GUI");

    let icon = icon();
    wind.set_icon(Some(icon));

    wind.end();
    wind.show();
    app.run().unwrap();
}

fn icon() -> image::PngImage {
    let bytes = include_bytes!("../../assets/icon.png");
    let ico = image::PngImage::from_data(bytes);

    // TODO - error check this.
    ico.unwrap()
}
