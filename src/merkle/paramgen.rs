use super::Params;

pub fn paramgen(n: usize) -> Params {
    if n < 2 {
        panic!("n of {} is less than minimum of 2", n);
    }
    let mut max_depth = 0;
    let mut max_n = 1;
    while max_n < n {
        max_n *= 2;
        max_depth += 1;
    }
    let mut n_bytes: [u8; 8] = [0; 8];
    for i in 0..8 {
        n_bytes[i] = ((n >> (i * 8)) & 0xff) as u8;
    }
    Params {
        n,
        n_bytes,
        max_depth,
    }
}
