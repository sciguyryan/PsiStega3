extern crate image;

use image::GenericImageView;

fn main() {
    let img = image::open("D:\\GitHub\\PsiStega3\\test-images\\milky-way-2695569_1920.jpg").unwrap();

    println!("dimensions {:?}", img.dimensions());
}
