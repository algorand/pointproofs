use super::Params;

// TODO: the current implemenation requires n to be at least 2; we should check this
pub fn paramgen(n : usize) -> Params {
    let mut max_depth = 0;
    let mut max_n = 1;
    while max_n < n {
        max_n *= 2;
        max_depth += 1;
    }
    let mut n_bytes : [u8;8] = [0;8];
    for i in 0..8 {
        n_bytes[i] = ((n>>(i*8)) & 0xff) as u8;
    }
    let hash_len = 32;
    Params {n, n_bytes, max_depth, hash_len}
}
