macro_rules! unwrap_or_return {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return,
        }
    };
}

macro_rules! unwrap_or_return_err {
    ( $e:expr, $b:expr ) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Err($b),
        }
    };
}

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
