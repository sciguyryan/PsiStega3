#[cfg(windows)]
extern crate winres;

fn main() {
    #[cfg(windows)]
    windows_only();
}

#[cfg(windows)]
fn windows_only() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("..//assets//icon.ico");
    res.compile().unwrap();
}
