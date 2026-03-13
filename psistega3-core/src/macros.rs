#[cfg(feature = "bench")]
#[allow(unused)]
#[macro_export]
macro_rules! bench_visible {
    () => { pub };
}

#[cfg(not(feature = "bench"))]
#[allow(unused)]
#[macro_export]
macro_rules! bench_visible {
    () => {};
}

#[cfg(test)]
#[allow(unused)]
#[macro_export]
macro_rules! test_visible {
    () => { pub };
}

#[cfg(not(test))]
#[allow(unused)]
#[macro_export]
macro_rules! test_visible {
    () => {};
}
