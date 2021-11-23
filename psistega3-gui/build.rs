#[cfg(windows)]
extern crate winres;

fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("..\\assets\\icon.ico");
        res.compile().unwrap();
    }

    sixtyfps_build::compile("ui\\main.60").unwrap();
}
