pub(crate) struct Logger {
    pub(crate) verbose: bool,
}

impl Logger {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Write a log file to the console, if verbose mode is enabled.
    ///
    /// # Arguments
    ///
    /// * `string` - The string to be logged.
    ///
    #[allow(dead_code)]
    pub(crate) fn log(&self, string: &str) {
        if !self.verbose {
            return;
        }

        #[cfg(debug_assertions)]
        log::debug!("{string}");

        #[cfg(not(debug_assertions))]
        println!("{}", string);
    }

    #[allow(dead_code)]
    pub(crate) fn enable_verbose_mode(&mut self) {
        self.verbose = true;
    }

    #[allow(dead_code)]
    pub(crate) fn disable_verbose_mode(&mut self) {
        self.verbose = true;
    }
}
