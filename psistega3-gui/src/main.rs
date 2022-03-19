#![crate_name = "psistega3_gui"]

#![windows_subsystem = "windows"]

use fltk::{app, prelude::*, window::Window, image, group::{Tabs, Group}, button::Button, output::Output, menu::Choice, dialog::{FileDialog, FileDialogType, FileDialogOptions}};
use fltk_theme::{WidgetTheme, ThemeType};

const WIDTH: i32 = 550;
const HEIGHT: i32 = 300;

fn main() {
    let app = app::App::default();

    //let theme = ColorTheme::new(color_themes::GRAY_THEME);
    //theme.apply();

    let widget_theme = WidgetTheme::new(ThemeType::Metro);
    widget_theme.apply();

    build_window();

    app.run().unwrap();
}

fn build_window() {
    let mut wind = Window::new(100, 100, WIDTH, HEIGHT, "PsiStega 3 :: GUI")
        .center_screen();

    wind.set_icon(Some(icon()));

    add_widgets();

    wind.end();
    wind.show();
}

fn add_widgets() {
    let base_control_height = 22;
    let spacer = 10;

    let tab = Tabs::new(10, 10, WIDTH - 20, HEIGHT - 20, "");

    let grp1 = Group::new(10, 35, WIDTH - 20, HEIGHT - 45, "Encode\t\t");

    // Input path.
    let mut y_pos = 50;
    let mut input_encode = Output::new(100, y_pos, 370, base_control_height, "")
        .with_label("Input Path: ");
    let mut input_browse_encode = Button::new(WIDTH - 70, y_pos, 30, base_control_height, "...");
    input_browse_encode.set_callback(move |_| {
        let file_path = open_file_dialog();
        input_encode.set_value(&file_path);
    });

    // Output path.
    y_pos += base_control_height + spacer;
    let mut output_encode = Output::new(100, y_pos, 370, base_control_height, "")
        .with_label("Output Path: ");
    let mut output_browse_encode = Button::new(WIDTH - 70, y_pos, 30, base_control_height, "...");
    output_browse_encode.set_callback(move |_| {
        let file_path = save_file_dialog();
        output_encode.set_value(&file_path);
    });

    // Version.
    y_pos += base_control_height + spacer;
    let mut version_select_encode = Choice::new(100, y_pos, 100, base_control_height, None)
        .with_label("Version: ");
    version_select_encode.add_choice("1");

    // Set key.
    y_pos += base_control_height + spacer;
    let mut key = "";
    let mut set_key = Button::new(100, y_pos, 100, base_control_height, "Set Key");
    set_key.set_callback(move |_| { key = "banana" });

    // Encode.
    y_pos += base_control_height + spacer;
    let mut encode = Button::new(100, y_pos, 100, base_control_height, "Encode!");
    encode.set_callback(move |_| handle_encode());

    grp1.end();

    let grp2 = Group::new(10, 35, WIDTH - 30, HEIGHT - 25, "Decode\t\t");
    grp2.end();
    tab.end();
}

fn handle_encode() {
}

fn icon() -> image::PngImage {
    let bytes = include_bytes!("../../assets/icon.png");
    image::PngImage::from_data(bytes).expect("Error getting window icon data.")
}

fn open_file_dialog() -> String {
    let mut dlg = FileDialog::new(FileDialogType::BrowseFile);
    dlg.set_option(FileDialogOptions::NoOptions);
    dlg.set_filter("PNG Files\t*.png");
    dlg.show();

    dlg.filename().to_string_lossy().to_string()
}

fn save_file_dialog() -> String {
    let mut dlg = FileDialog::new(FileDialogType::BrowseSaveFile);
    dlg.set_option(FileDialogOptions::SaveAsConfirm);
    dlg.set_filter("PNG Files\t*.png");
    dlg.show();

    dlg.filename().to_string_lossy().to_string()
}
