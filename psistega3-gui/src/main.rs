#![crate_name = "psistega3_gui"]

#![windows_subsystem = "windows"]

use fltk::{app, prelude::*, window::Window, image, group::{Tabs, Group}, button::Button, input::MultilineInput, output::Output, menu::Choice, dialog::{FileDialog, FileDialogType, FileDialogOptions, self}};
use fltk_theme::{WidgetTheme, ThemeType};

const WIDTH: i32 = 580;
const HEIGHT: i32 = 500;
const CONTROL_HEIGHT: i32 = 22;
const SPACE: i32 = 10;

#[derive(PartialEq)]
enum FileType {
    All,
    PNG
}

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
    let tab = Tabs::new(10, 10, WIDTH - 20, HEIGHT - 20, "");

    add_encode_text_tab();

    let grp2 = Group::new(10, 35, WIDTH - 30, HEIGHT - 25, "Decode\t\t");
    grp2.end();
    tab.end();
}

fn add_encode_text_tab() {
    let mut y_pos = 50;

    let tab = Group::new(10, 35, WIDTH - 20, HEIGHT - 45, "Encode Text\t\t");

    // Input image path.
    let mut input_encode = Output::new(130, y_pos, 370, CONTROL_HEIGHT, "")
        .with_label("Input Image Path: ");
    let mut input_browse_encode = Button::new(WIDTH - 70, y_pos, 30, CONTROL_HEIGHT, "...");
    input_browse_encode.set_callback(move |_| {
        let file_path = open_file_dialog(FileType::PNG);
        input_encode.set_value(&file_path);
    });

    // Output path.
    y_pos += CONTROL_HEIGHT + SPACE;
    let mut output_encode = Output::new(130, y_pos, 370, CONTROL_HEIGHT, "")
        .with_label("Output Image Path: ");
    let mut output_browse_encode = Button::new(WIDTH - 70, y_pos, 30, CONTROL_HEIGHT, "...");
    output_browse_encode.set_callback(move |_| {
        let file_path = save_file_dialog();
        output_encode.set_value(&file_path);
    });

    // Text.
    y_pos += CONTROL_HEIGHT + SPACE;
    let mut text_encode = MultilineInput::new(130, y_pos, 370, 200, "")
        .with_label("Text: ");
    y_pos += 180;

    // Version.
    y_pos += CONTROL_HEIGHT + SPACE;
    let mut version_select_encode = Choice::new(130, y_pos, 100, CONTROL_HEIGHT, None)
        .with_label("Version: ");
    version_select_encode.add_choice("1");

    // Set key.
    y_pos += CONTROL_HEIGHT + SPACE;
    let mut key = "";
    let mut set_key = Button::new(130, y_pos, 100, CONTROL_HEIGHT, "Set Key");
    set_key.set_callback(move |_| {
        let p = password_dialog();
        key = "banana"
    });

    // Encode.
    y_pos += CONTROL_HEIGHT + SPACE;
    let mut encode = Button::new(130, y_pos, 100, CONTROL_HEIGHT, "Encode!");
    encode.set_callback(move |_| handle_encode());

    tab.end();
}

fn handle_encode() {
}

fn icon() -> image::PngImage {
    let bytes = include_bytes!("../../assets/icon.png");
    image::PngImage::from_data(bytes).expect("Error getting window icon data.")
}

fn open_file_dialog(filter_type: FileType) -> String {
    let mut dlg = FileDialog::new(FileDialogType::BrowseFile);
    dlg.set_option(FileDialogOptions::NoOptions);
    if filter_type == FileType::All {
        dlg.set_filter("All Files\t*.*");
    } else {
        dlg.set_filter("PNG Files\t*.png");
    }
    dlg.show();

    dlg.filename().to_string_lossy().to_string()
}

fn password_dialog() -> Option<String> {
    let center = center();

    let p1 = dialog::password(center.0, center.1, "Password", "");
    let p2 = dialog::password(center.0, center.1, "Confirm Password", "");

    if p1 != p2 {
        dialog::alert(center.0, center.1, "Password Mismatch");
        return None;
    }

    p1
}

fn save_file_dialog() -> String {
    let mut dlg = FileDialog::new(FileDialogType::BrowseSaveFile);
    dlg.set_option(FileDialogOptions::SaveAsConfirm);
    dlg.set_filter("PNG Files\t*.png");
    dlg.show();

    dlg.filename().to_string_lossy().to_string()
}

pub fn center() -> (i32, i32) {
    (
        (app::screen_size().0 / 2.0) as i32,
        (app::screen_size().1 / 2.0) as i32,
    )
}
