/// Unwrap a result or return if unsuccessful.
macro_rules! unwrap_or_return {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return,
        }
    };
}

/// Unwrap a result or return an error if unsuccessful.
macro_rules! unwrap_or_return_err {
    ( $e:expr, $b:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Err($b),
        }
    };
}

/// Unwrap a result or return a value if unsuccessful.
macro_rules! unwrap_or_return_val {
    ( $e:expr, $b:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return $b,
        }
    };
}

pub(crate) use unwrap_or_return;
pub(crate) use unwrap_or_return_err;
pub(crate) use unwrap_or_return_val;
