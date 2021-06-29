extern crate image;

use image::{GenericImage, GenericImageView}; 

fn main() { 
    let mut img = image::open("D:\\GitHub\\PsiStega3\\test-images\\mewtwo_by_kicktyan-d65s6xy2.jpg").unwrap();

    println!("dimensions {:?}", img.dimensions());

    let (width, height) =  img.dimensions();

    if width % 2 > 0 || height % 2 > 0 {
        println!("Image width and height (inn pixels) must be divisible by 2.");
        return;
    }

    // Each cell is 2 by 2 pixels in size.
    let total_cells = (width * height) / 4;
    println!("total_cells = {}", &total_cells);

    let pixel = img.get_pixel(0, 0);

    println!("rgba = {}, {}, {}, {}", pixel[0], pixel[1], pixel[2], pixel[3]);

    let new_pixel = image::Rgba([0, 0, 0, 0]);

    img.put_pixel(0, 0, new_pixel);

    let r = img.save("D:\\GitHub\\PsiStega3\\test-images\\2.png");

    println!("result = {:?}", r);
}