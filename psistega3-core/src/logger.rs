pub(crate) static mut VERBOSE: bool = false;

/// Write a log file to the console, if verbose mode is enabled.
///
/// # Arguments
///
/// * `string` - The string to be logged.
///
#[allow(dead_code)]
pub(crate) fn log(string: &str) {
    unsafe {
        if !VERBOSE {
            return;
        }
    }

    #[cfg(debug_assertions)]
    log::debug!("{}", string);

    #[cfg(not(debug_assertions))]
    println!("{}", string);
}

#[allow(dead_code)]
pub(crate) fn enable_verbose_mode() {
    unsafe {
        VERBOSE = true;
    }
}

#[allow(dead_code)]
#[allow(dead_code)]
pub(crate) fn disable_verbose_mode() {
    unsafe {
        VERBOSE = false;
    }
}
