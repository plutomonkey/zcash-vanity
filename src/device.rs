use address::{PAYMENT_ADDRESS_PREFIX, pseudorandom_function_a_pk, SpendingKey};

use bs58;
use byteorder::{BigEndian, ByteOrder};
use core;
use core::{KernelArg, KernelWorkGroupInfo, KernelWorkGroupInfoResult, CommandExecutionStatus, ContextProperties, Event, EventInfo, EventInfoResult, DeviceInfo, DeviceInfoResult, DeviceId, PlatformId};
use ring::rand::SecureRandom;
use std::{cmp, str, thread, time};
use std::io::{self, Write};
use std::sync::atomic;
use std::sync::mpsc::Sender;
use std::ffi::CString;

const MAX_DATA: usize = 1 + 1024;
const ITERATIONS_PER_THREAD: usize = 1024;

pub struct VanityWork {
    pub id: usize,
    pub rate: f64,
}

pub fn vanity_device(id: usize, finished: &atomic::AtomicBool, rng: &SecureRandom, tx: &Sender<VanityWork>, platform: PlatformId, device: DeviceId, patterns_sorted: &[String], pattern_words: &[u64], single_match: bool) {
    let pattern_count = patterns_sorted.len();
    let pattern_count_log2 = (32 - ((pattern_words.len()/2 - 1) as u32).leading_zeros()) as u32;

    let context_properties = ContextProperties::new().platform(platform);

    let context = core::create_context(Some(&context_properties), &[device], None, None).unwrap();
    let queue = core::create_command_queue(&context, &device, None).unwrap();
    let program = core::create_program_with_source(&context, &[
        CString::new(SRC
            .replace("ITERATIONS_PER_THREAD", &ITERATIONS_PER_THREAD.to_string())
            .replace("MAX_DATA", &MAX_DATA.to_string())
        ).unwrap()
    ]).unwrap();
    core::build_program(&program, None::<&[()]>, &CString::new("").unwrap(), None, None).unwrap();
    let compress = core::create_kernel(&program, "compress").unwrap();

    let mut seed = [0u8; 32];
    let mut data = [0u32; MAX_DATA];
    let mut dev_data = [0u32; MAX_DATA];

    let dev_seed = unsafe { core::create_buffer(&context, core::MEM_READ_ONLY, 32, None::<&[u8]>).unwrap() };
    let dev_patterns = unsafe { core::create_buffer(&context, core::MEM_READ_ONLY, pattern_words.len(), None::<&[u64]>).unwrap() };
    let dev_out = unsafe { core::create_buffer(&context, core::MEM_READ_WRITE, MAX_DATA, None::<&[u32]>).unwrap() };

    core::enqueue_write_buffer(&queue, &dev_out, false, 0, &dev_data, None::<Event>, None::<&mut Event>).unwrap();
    core::enqueue_write_buffer(&queue, &dev_patterns, false, 0, pattern_words, None::<Event>, None::<&mut Event>).unwrap();

    let local_size = match core::get_kernel_work_group_info(&compress, &device, KernelWorkGroupInfo::WorkGroupSize) {
        KernelWorkGroupInfoResult::WorkGroupSize(size) => [size, 0, 0],
        _ => panic!("Unable to determine work group size."),
    };

    let global_size = match core::get_device_info(&device, DeviceInfo::MaxComputeUnits) {
        DeviceInfoResult::MaxComputeUnits(compute_units) => [local_size[0] * compute_units as usize * 4, 1, 1],
        _ => panic!("Unable to determine number of compute units."),
    };
    assert!(global_size[0] < (1 << 28));

    let device_little_endian = match core::get_device_info(&device, DeviceInfo::EndianLittle) {
        DeviceInfoResult::EndianLittle(d) => d,
        _ => cfg!(target_endian = "little"),
    };

    let mut a_pk = [0u8; 32];
    let mut unencoded_data = [0u8; 2 + 32*2 + 4];
    unencoded_data[0] = PAYMENT_ADDRESS_PREFIX[0];
    unencoded_data[1] = PAYMENT_ADDRESS_PREFIX[1];

    let mut stderr = io::stderr();
    'outer: loop {
        let now = time::Instant::now();
        rng.fill(&mut seed).unwrap();
        if device_little_endian {
            seed[3] = 0xc0 | (seed[3] & 0x0f);
        } else {
            seed[0] = 0xc0 | (seed[0] & 0x0f);
        }

        core::enqueue_write_buffer(&queue, &dev_seed, false, 0, &seed, None::<Event>, None::<&mut Event>).unwrap();

        core::set_kernel_arg(&compress, 0, KernelArg::Mem::<u8>(&dev_seed)).unwrap();
        core::set_kernel_arg(&compress, 1, KernelArg::Mem::<u64>(&dev_patterns)).unwrap();
        core::set_kernel_arg(&compress, 2, KernelArg::Scalar(pattern_count as u32)).unwrap();
        core::set_kernel_arg(&compress, 3, KernelArg::Scalar(pattern_count_log2)).unwrap();
        core::set_kernel_arg(&compress, 4, KernelArg::Mem::<u32>(&dev_out)).unwrap();

        core::enqueue_kernel(&queue, &compress, 1, None, &global_size, Some(local_size), None::<Event>, None::<&mut Event>).unwrap();

        let mut event = Event::null();
        unsafe { core::enqueue_read_buffer(&queue, &dev_out, false, 0, &mut dev_data, None::<Event>, Some(&mut event)).unwrap(); }

        if finished.load(atomic::Ordering::Relaxed) {
            break;
        }

        if data[0] != 0 {
            'next_candidate: for chunk in data[1..cmp::min(MAX_DATA, 1 + 8 * data[0] as usize)].chunks(8) {
                BigEndian::write_u32_into(chunk, &mut seed);
                pseudorandom_function_a_pk(&mut a_pk, &seed);
                unencoded_data[2..34].copy_from_slice(&a_pk);
                let encoded_data = bs58::encode(unencoded_data.as_ref()).into_string();
                if match patterns_sorted.binary_search(&encoded_data) {
                    Ok(_) => false,
                    Err(d) => d == 0 || !encoded_data.starts_with(&patterns_sorted[d - 1]),
                } {
                    continue 'next_candidate;
                }

                let spending_key = SpendingKey::new(seed);
                write!(&mut stderr, "\r{}\r", " ".repeat(80)).unwrap();
                stderr.flush().unwrap();
                println!("{}", spending_key.address());
                println!("{}", spending_key);
                io::stdout().flush().unwrap();

                if single_match {
                    break 'outer;
                }
            }
        }

        // avoid CPU busy-wait on NVIDIA
        let one_millis = time::Duration::from_millis(1);
        core::flush(&queue).unwrap();
        loop {
            match core::get_event_info(&event, EventInfo::CommandExecutionStatus) {
                EventInfoResult::CommandExecutionStatus(CommandExecutionStatus::Complete) => break,
                EventInfoResult::CommandExecutionStatus(_) => thread::sleep(one_millis),
                _ => panic!("Unexpected EventInfoResult."),
            }
        }

        data.copy_from_slice(&dev_data);
        dev_data[0] = 0;
        let zero_count = [0u32];
        core::enqueue_write_buffer(&queue, &dev_out, false, 0, &zero_count, None::<Event>, None::<&mut Event>).unwrap();

        let elapsed = now.elapsed();
        let elapsed_secs = (elapsed.as_secs() as f64) + (elapsed.subsec_nanos() as f64 / 1_000_000_000.0);
        let rate = (ITERATIONS_PER_THREAD * global_size[0]) as f64 / elapsed_secs;
        tx.send(VanityWork { id: id, rate: rate }).unwrap();
    }

    core::finish(&queue).unwrap();
}

const SRC: &'static str = r#"
typedef unsigned char  uint8_t;
typedef unsigned int   uint32_t;
typedef unsigned long  uint64_t;

__constant uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__constant uint32_t H[8] = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

inline static uint32_t rotr(const uint32_t x, const uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

inline static uint32_t shr(const uint32_t x, const uint32_t n) {
  return x >> n;
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (z & (x ^ y)); }

uint32_t Sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
uint32_t Sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
uint32_t sigma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }
uint32_t sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

__kernel
void compress(
    __global uint8_t *restrict a_sk,
    __global uint64_t *restrict patterns,
    uint32_t pattern_count,
    uint32_t pattern_count_log2,
    __global uint32_t *restrict out) {

  uint32_t W[64];

  // Copy the random a_sk seed to W[0..8].
  for (size_t i = 0; i < 2; ++i) {
    ((uint4 *)W)[i] = ((__global uint4 *)a_sk)[i];
  }

  // Toggle bits to ensure each thread starts with a different a_sk.  The first 4 bits should not
  // be touched; this is enforced by ensuring the global work size is smaller than 1<<28, which is
  // done by an assert on the host.
  W[0] ^= get_global_id(0);

  // Set remainder of input words to zero (pk_enc) as we assume they won't affect our base-58
  // address prefix (and computing pk_enc is expensive).
  for (size_t i = 8; i < 16; ++i) {
    W[i] = 0;
  }

  for (size_t iteration = 0; iteration < ITERATIONS_PER_THREAD; ++iteration) {

    for (size_t i = 16; i < 64; ++i) {
      W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }

    uint32_t state[8];

    for (size_t i = 0; i < 8; ++i) {
      state[i] = H[i];
    }

    for (size_t i = 0; i < 64; ++i) {
      uint32_t T1 = state[7] + Sigma1(state[4]) + Ch(state[4], state[5], state[6]) + K[i] + W[i],
               T2 = Sigma0(state[0]) + Maj(state[0], state[1], state[2]);

      state[7] = state[6];
      state[6] = state[5];
      state[5] = state[4];
      state[4] = state[3] + T1;
      state[3] = state[2];
      state[2] = state[1];
      state[1] = state[0];
      state[0] = T1 + T2;
    }

    // We only need the first two words.
    for (size_t i = 0; i < 2; i++) {
      state[i] += H[i];
    }

    uint64_t word = ((uint64_t)state[0] << 32) | (uint64_t)state[1];

    size_t lo = 0, mid = 0, hi = pattern_count;
    for (size_t depth = 0; depth <= pattern_count_log2; ++depth) {
      mid = (lo + hi) >> 1;
      if (patterns[2*mid] <= word) {
        lo = mid + (lo == hi ? 0 : 1);
      } else {
        hi = mid;
      }
    }
    if (0 < lo && word <= patterns[2*(lo-1)+1]) {
      uint32_t offset = atomic_inc(out);
      if (1 + 8*(offset+1) <= MAX_DATA) {
        for (size_t i = 0; i < 8; ++i) {
          out[1 + 8*offset + i] = W[i];
        }
      }
    }

    ++W[1];
  }
}"#;
