/// Unwrap a result or return if unsuccessful.
macro_rules! unwrap_res_or_return {
    ( $e:expr, $b:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return $b,
        }
    };
    ( $e:expr ) => {
        unwrap_res_or_return!($e, {})
    };
}

pub(crate) use unwrap_res_or_return;
