#![cfg_attr(feature = "clippy", deny(warnings))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
#![cfg_attr(feature = "clippy", allow(too_many_arguments))]

extern crate bs58;
extern crate byteorder;
extern crate clap;
extern crate crypto;
extern crate curve25519_dalek;
extern crate ocl_core as core;
extern crate rand;

mod address;
mod device;
mod pattern;
mod sha256;
mod util;

use clap::{App, Arg};
use core::{PlatformInfo, DeviceInfo, DeviceId, PlatformId};
use pattern::Pattern;
use rand::OsRng;
use std::{thread, time};
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic;
use std::sync::mpsc::{self, Sender, Receiver};

fn main() {
    let matches = App::new("Zcash Vanity Address Generator")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Generates Zcash shielded addresses (\"z-addrs\") that match given prefixes.")
        .arg(Arg::with_name("device")
             .short("d")
             .takes_value(true)
             .number_of_values(1)
             .multiple(true)
             .help("OpenCL device string: <platform>:<device>.\n\
                    Specify multiple times for multiple devices, e.g. -d 0:0 -d 0:1.\n\
                    If not specified, uses all available platforms and devices."))
        .arg(Arg::with_name("file")
             .short("f")
             .takes_value(true)
             .help("Load prefixes from file, one per line.\nCan be combined with --insensitive."))
        .arg(Arg::with_name("insensitive")
             .short("i")
             .help("Case-insensitive prefix search."))
        .arg(Arg::with_name("continue")
             .short("c")
             .help("Continue searching after a match is found."))
        .arg(Arg::with_name("pattern")
             .index(1)
             .help("Zcash address prefix to be matched."))
        .after_help("Matches will be printed to stdout; 3 lines per match (z-addr, spending key, incoming viewing key).\n\
                     You can import the spending key to your Zcash client using `zcash-cli z_importkey <key> <rescan>`.")
        .get_matches();

    let mut device_specifiers = if matches.is_present("device") {
        matches.values_of("device").unwrap().map(|s| {
            let mut values = s.split(':');
            (values.next().unwrap().parse::<usize>().unwrap(), values.next().unwrap().parse::<usize>().unwrap())
        }).collect()
    } else {
        vec![]
    };
    device_specifiers.sort();
    let mut device_specifiers_iter = device_specifiers.into_iter();

    let mut stderr = io::stderr();
    let mut devices = vec![];
    let mut device_specifier = device_specifiers_iter.next();
    let all_devices = device_specifier.is_none();
    for (i, &platform) in core::get_platform_ids().unwrap().iter().enumerate() {
        writeln!(&mut stderr, "Available devices on platform {}:", core::get_platform_info(&platform, PlatformInfo::Name)).unwrap();
        for (j, &device) in core::get_device_ids(&platform, None, None).unwrap().iter().enumerate() {
            writeln!(&mut stderr, "  {}:{} {}", i, j, core::get_device_info(device, DeviceInfo::Name)).unwrap();
            if all_devices || Some((i, j)) == device_specifier {
                devices.push((platform, device));
                device_specifier = device_specifiers_iter.next();
            }
        }
    }
    stderr.flush().unwrap();

    let mut patterns = if let Some(filename) = matches.value_of("file") {
        let mut file = File::open(&filename).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        contents.lines().map(|s| Pattern::new(s.to_string()).unwrap()).collect()
    } else {
        vec![Pattern::new(matches.value_of("pattern").unwrap_or("").to_string()).unwrap()]
    };

    if matches.is_present("insensitive") {
        patterns = patterns.iter().flat_map(|p| p.case_insensitive()).collect()
    }

    vanity(&devices, &patterns, !matches.is_present("continue"));
}

fn vanity(devices: &[(PlatformId, DeviceId)], patterns: &[Pattern], single_match: bool) {
    let mut pattern_prefixes: Vec<String> = patterns.into_iter().map(|p| p.prefix.to_owned()).collect();
    pattern_prefixes.sort();

    let mut pattern_ranges: Vec<(u64, u64)> = patterns.iter().map(|p| p.range).collect();
    pattern_ranges.sort_by_key(|r| r.0);

    // TODO: the pairs in pattern_words are guaranteed to be sorted, but only by virtue of
    // lexicographic ordering of the default base58 alphabet being equivalent to ordering of the
    // big-endian data.
    let mut pattern_words = vec![];
    let mut search_size = 0.0_f64;
    for (from, to) in pattern_ranges {
        pattern_words.push(from);
        pattern_words.push(to);
        search_size += 1.0_f64 + (to - from) as f64;
    }

    let (tx, rx): (Sender<u64>, Receiver<u64>) = mpsc::channel();
    let pattern_prefixes = Arc::new(pattern_prefixes);
    let pattern_words = Arc::new(pattern_words);
    let finished = Arc::new(atomic::AtomicBool::new(false));

    for &device_specifier in devices {
        let tx = tx.clone();
        let pattern_prefixes = pattern_prefixes.clone();
        let pattern_words = pattern_words.clone();
        let finished = finished.clone();
        thread::spawn(move || {
            let mut rng = OsRng::new().unwrap();
            device::vanity_device(&*finished, &mut rng, &tx, device_specifier.0, device_specifier.1, &*pattern_prefixes, &*pattern_words, single_match);
            finished.store(true, atomic::Ordering::Relaxed);
        });
    }
    drop(tx);

    let difficulty = 2.0_f64.powi(64) / search_size;
    let start = time::Instant::now();
    let mut cumulative_work = 0u64;
    let mut now = start;
    let mut stderr = io::stderr();

    while let Ok(work) = rx.recv() {
        cumulative_work += work;
        let now_elapsed = now.elapsed();

        if now_elapsed.as_secs() > 0 {
            let start_elapsed = start.elapsed();
            let start_elapsed_secs = start_elapsed.as_secs() as f64 + f64::from(start_elapsed.subsec_nanos()) / 1_000_000_000.0;
            let now_elapsed_secs = now_elapsed.as_secs() as f64 + f64::from(now_elapsed.subsec_nanos()) / 1_000_000_000.0;

            let rate = cumulative_work as f64 / now_elapsed_secs;
            let lambda = rate / difficulty;
            let probability = 1. - (-start_elapsed_secs * lambda).exp();

            write!(&mut stderr, "\rElapsed: {:.0}/{:.0}s Rate: {:.0}/s Prob: {:.2}%", start_elapsed_secs, 1. / lambda, rate, 100. * probability).unwrap();
            stderr.flush().unwrap();

            cumulative_work = 0;
            now += now_elapsed;
        }
    }
}
