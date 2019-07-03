extern crate cbindgen;

use std::env;
use std::path::PathBuf;

fn main() {
  let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
  let target_dir = get_target_dir(&crate_dir);
  let package_name = env::var("CARGO_PKG_NAME").unwrap();
  let output_file_buf = target_dir.join(format!("{}.h", package_name));
  let output_file = output_file_buf.to_str().unwrap();

  let hdrgen = cbindgen::generate(&crate_dir).unwrap();
  hdrgen.write_to_file(&output_file);
}

fn get_target_dir(crate_dir: &str) -> PathBuf {
  match env::var("CARGO_TARGET_DIR") {
    Ok(d) => PathBuf::from(d),
    Err(_) => PathBuf::from(crate_dir).join("target"),
  }
}
