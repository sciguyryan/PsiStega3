#![crate_name = "psistega3_gui"]

#![windows_subsystem = "windows"]

use fltk::{app, prelude::*, window::Window, image, group::{Tabs, Group}, button, input, output};
use fltk_theme::{ColorTheme, color_themes, WidgetTheme, ThemeType};

const WIDTH: i32 = 550;
const HEIGHT: i32 = 400;

fn main() {
    let app = app::App::default();

    //let theme = ColorTheme::new(color_themes::GRAY_THEME);
    //theme.apply();

    let widget_theme = WidgetTheme::new(ThemeType::Greybird);
    widget_theme.apply();

    build_window();

    app.run().unwrap();
}

fn build_window() {
    let mut wind = Window::new(100, 100, WIDTH, HEIGHT, "PsiStega 3 :: GUI");

    wind.set_icon(Some(icon()));

    add_widgets();

    wind.end();
    wind.show();
}

fn add_widgets() {
    let base_control_height = 25;

    let tab = Tabs::new(10, 10, WIDTH - 20, HEIGHT - 20, "");

    let grp1 = Group::new(10, 35, WIDTH - 20, HEIGHT - 45, "Encode\t\t");

    // Input file
    let mut y_pos = 50;
    let input_encode = output::Output::new(100, y_pos, 300, base_control_height, "").with_label("Input Path: ");
    let input_browse_encode = button::Button::new(WIDTH - 100, y_pos, 80, base_control_height, "...");

    y_pos += base_control_height + 10;
    let output_encode = output::Output::new(100, y_pos, 300, base_control_height, "").with_label("Output Path: ");
    let output_browse_encode = button::Button::new(WIDTH - 100, y_pos, 80, base_control_height, "...");

    y_pos += base_control_height + 10;
    let output_encode = output::Output::new(100, y_pos, 300, base_control_height, "").with_label("Key: ");
    let output_browse_encode = button::Button::new(WIDTH - 100, y_pos, 80, base_control_height, "...");

    grp1.end();

    let grp2 = Group::new(10, 35, WIDTH - 30, HEIGHT - 25, "Decode\t\t");
    grp2.end();
    tab.end();
}

fn icon() -> image::PngImage {
    let bytes = include_bytes!("../../assets/icon.png");
    let ico = image::PngImage::from_data(bytes);

    // TODO - error check this.
    ico.unwrap()
}
