#[cfg(feature = "bench")]
macro_rules! bench_visible {
    () => { pub };
}

#[cfg(not(feature = "bench"))]
#[allow(unused)]
macro_rules! bench_visible {
    () => {};
}
