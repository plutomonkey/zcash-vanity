extern crate bs58;
extern crate byteorder;
extern crate clap;
extern crate crypto;
extern crate curve25519_dalek;
extern crate ocl_core as core;
extern crate ring;

mod address;
mod device;
mod pattern;
mod sha256;
mod util;

use clap::{App, Arg};
use core::{PlatformInfo, DeviceInfo, DeviceId, PlatformId};
use device::VanityWork;
use pattern::Pattern;
use ring::rand::SystemRandom;
use std::{str, thread, time};
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::Arc;
use std::sync::atomic;
use std::sync::mpsc::{self, Sender, Receiver};

fn main() {
    let matches = App::new("Zcash Vanity Address Generator")
        .version("0.0.1")
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
        .after_help("Matches will be printed to stdout; each z-addr on its own line followed by its spending key on the next line.\n\
                     You can import the spending key to your Zcash client using `zcash-cli z_importkey <key> <rescan>`.")
        .get_matches();

    let mut device_values = if matches.is_present("device") {
        matches.values_of("device").unwrap().collect::<Vec<&str>>()
    } else {
        vec![]
    };
    device_values.sort();
    let mut device_specifiers = device_values.iter().map(|s| {
        let mut values = s.split(':');
        (values.next().unwrap().parse::<usize>().unwrap(), values.next().unwrap().parse::<usize>().unwrap())
    });

    let mut stderr = io::stderr();
    let mut devices = vec![];
    let mut device_specifier = device_specifiers.next();
    let all_devices = device_specifier.is_none();
    for (i, &platform) in core::get_platform_ids().unwrap().iter().enumerate() {
        writeln!(&mut stderr, "Available devices on platform {}:", core::get_platform_info(&platform, PlatformInfo::Name)).unwrap();
        for (j, &device) in core::get_device_ids(&platform, None, None).unwrap().iter().enumerate() {
            writeln!(&mut stderr, "  {}:{} {}", i, j, core::get_device_info(device, DeviceInfo::Name)).unwrap();
            if all_devices || Some((i, j)) == device_specifier {
                devices.push((platform, device));
                device_specifier = device_specifiers.next();
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
    let mut search_size = 0;
    for (from, to) in pattern_ranges {
        pattern_words.push(from);
        pattern_words.push(to);
        search_size += to - from;
    }

    let (tx, rx): (Sender<VanityWork>, Receiver<VanityWork>) = mpsc::channel();
    let pattern_prefixes = Arc::new(pattern_prefixes);
    let pattern_words = Arc::new(pattern_words);
    let rng = Arc::new(SystemRandom::new());
    let finished = Arc::new(atomic::AtomicBool::new(false));

    for (id, &device_specifier) in devices.iter().enumerate() {
        let tx = tx.clone();
        let pattern_prefixes = pattern_prefixes.clone();
        let pattern_words = pattern_words.clone();
        let rng = rng.clone();
        let finished = finished.clone();
        thread::spawn(move || {
            device::vanity_device(id, &*finished, &*rng, &tx, device_specifier.0, device_specifier.1, &*pattern_prefixes, &*pattern_words, single_match);
            finished.store(true, atomic::Ordering::Relaxed);
        });
    }
    drop(tx);

    let difficulty = (!0u64 as f64) / (search_size as f64);
    let thread_count = devices.len();
    let mut rate_samples = vec![0f64; thread_count];

    let start = time::Instant::now();
    let mut stderr = io::stderr();
    while let Ok(VanityWork { id, rate }) = rx.recv() {
        rate_samples[id] = rate;

        let rate = rate_samples.iter().sum::<f64>();

        let start_elapsed = start.elapsed();
        let start_elapsed_secs = (start_elapsed.as_secs() as f64) + (start_elapsed.subsec_nanos() as f64 / 1_000_000_000.0);

        let lambda = rate / difficulty;
        let probability = 1. - (-start_elapsed_secs * lambda).exp();
        write!(&mut stderr, "\rElapsed: {:.0}/{:.0}s Rate: {:.0}/s Prob: {:.2}%", start_elapsed_secs, 1. / lambda, rate, 100. * probability).unwrap();
        stderr.flush().unwrap();
    }
}
