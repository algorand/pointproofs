use std::io::prelude::*;
use std::io::BufReader;

#[allow(dead_code)]
fn process_processed_txt() {
    let fin = std::fs::File::open("../processed.txt").unwrap();
    let mut f_aggregate = std::fs::File::create("../aggregate.txt").unwrap();
    let mut f_verify = std::fs::File::create("../verify.txt").unwrap();
    let mut f = BufReader::new(fin);

    let tmp_str = ["1024,", "16,", "64,", "256,"];
    for e in tmp_str.iter() {
        let n = e.to_string();

        //    let mut n = "1024,".to_string();

        f_aggregate
            .write_all(format!("Aggregate, n = {}\n\n", n).as_ref())
            .unwrap();
        f_aggregate.write_all(format!("|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |\n").as_ref()).unwrap();
        f_aggregate
            .write_all(format!("|---|---:|---:|---:|---:|---:|").as_ref())
            .unwrap();

        f_verify
            .write_all(format!("Verify, n = {}\n\n", n).as_ref())
            .unwrap();
        f_verify.write_all(format!("|# commit  |1 proof per commit | 2 proof per commit  | 4 proof per commit | 8 proof per commit | 16 proof per commit |\n").as_ref()).unwrap();
        f_verify
            .write_all(format!("|---|---:|---:|---:|---:|---:|").as_ref())
            .unwrap();

        let mut c_pre = "".to_string();
        for _i in 0..9 * 5 {
            let mut line1: String = "".to_string();
            let mut line2: String = "".to_string();
            f.read_line(&mut line1).unwrap();
            f.read_line(&mut line2).unwrap();

            let v1: Vec<&str> = line1.split_whitespace().collect();
            let v2: Vec<&str> = line2.split_whitespace().collect();

            let mut line3: String = "".to_string();
            let mut line4: String = "".to_string();
            f.read_line(&mut line3).unwrap();
            f.read_line(&mut line4).unwrap();
            let v4: Vec<&str> = line4.split_whitespace().collect();

            let c = v1[7].to_string();
            let time_agg = v2[3];
            let time_agg_unit = v2[4];
            let time_ver = v4[3];
            let time_ver_unit = v4[4];

            if c != c_pre {
                c_pre = c.to_owned();
                let tmp: Vec<&str> = c.split(",").collect();
                f_aggregate
                    .write_all(format!("\n| {} |", tmp[0]).as_ref())
                    .unwrap();
                f_verify
                    .write_all(format!("\n| {} |", tmp[0]).as_ref())
                    .unwrap();
            }
            f_aggregate
                .write_all(format!(" {} {} |", time_agg, time_agg_unit).as_ref())
                .unwrap();
            f_verify
                .write_all(format!(" {} {} |", time_ver, time_ver_unit).as_ref())
                .unwrap();
        }
        f_aggregate.write_all(b"\n\n").unwrap();
        f_verify.write_all(b"\n\n").unwrap();
    }
}

#[allow(dead_code)]
fn process_data_txt() {
    let file_name = format!("../data.txt");
    let f = std::fs::File::open(file_name).unwrap();
    let mut f = BufReader::new(f);
    let mut fout = std::fs::File::create("../processed.txt").unwrap();
    while {
        let mut line: String = "".to_string();
        let line_len = f.read_line(&mut line).unwrap();
        match line.find("pairings/x-com aggregate:") {
            Some(p) => {
                if p == 0 {
                    fout.write(line.as_ref()).unwrap();
                }
            }
            None => (),
        };
        match line.find("pairings/x-com batch verify:") {
            Some(p) => {
                if p == 0 {
                    fout.write(line.as_ref()).unwrap();
                }
            }
            None => (),
        };

        match line.find("                        time:") {
            Some(_p) => fout.write(line.as_ref()).unwrap(),
            None => 0,
        };
        line_len != 0
    } {}
}

fn main() {
    //    process_data_txt();
    process_processed_txt();
    println!("Hello, world!");
}
