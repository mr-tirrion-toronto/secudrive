//! secudrive_rust - compiled scan engine (recursive walk + SHA-256/MD-5 hashing).
//!
//! Python contract:
//! ```python
//! outcome = secudrive_rust.scan_directory(
//!     path, hash_algo="sha256+md5", max_hash_size=..., max_depth=0,
//!     follow_symlinks=False, exclude_dirs=[...], threads=0,
//!     progress_cb=None, cancel_cb=None)
//! # outcome.stats  -> ScanStats(files_seen, dirs_seen, bytes_scanned, errors)
//! # outcome.results-> [FileHashResult(path, size, sha256, md5, error)]
//! # outcome.lnk_dirs -> [parent dirs containing at least one *.lnk regular file]
//! ```
//!
//! The engine mirrors the semantics of the pure-Python hot loop in
//! `secudrive/scanner.py` (`_walk` / `_scan_file`):
//!   * files are only hashed when `0 < size <= max_hash_size`;
//!   * files larger than the cap (or 0 bytes) are still reported (no hash) so
//!     Python-side heuristics can run;
//!   * per-file I/O errors are converted into `error` records (never abort);
//!   * excluded directory/file names (lower-case comparison as in Python) are
//!     never entered / hashed / counted;
//!   * symlink cycles cannot hang the walk (walkdir loop detection when
//!     `follow_symlinks` is on; junction reparse-point sniffing when off).
//!
//! The GIL is released for the whole scan; progress/cancellation callbacks
//! re-acquire it on the calling thread only (never from rayon workers).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

use md5::Md5;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const HASH_BATCH: usize = 256;   // files per rayon batch (also the progress cadence)

// ----------------------------------------------------------------------- pyclass

#[derive(Clone)]
#[pyclass]
struct FileHashResult {
    #[pyo3(get)]
    path: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    sha256: Option<String>,
    #[pyo3(get)]
    md5: Option<String>,
    #[pyo3(get)]
    error: Option<String>,
}

#[pyclass]
struct ScanStats {
    #[pyo3(get)]
    files_seen: u64,
    #[pyo3(get)]
    dirs_seen: u64,
    #[pyo3(get)]
    bytes_scanned: u64,
    #[pyo3(get)]
    errors: u64,
}

#[pyclass]
struct ScanOutcome {
    #[pyo3(get)]
    results: Vec<FileHashResult>,
    #[pyo3(get)]
    stats: ScanStats,
    #[pyo3(get)]
    lnk_dirs: Vec<String>,
}

// ------------------------------------------------------------------ internals

struct Config {
    max_hash_size: u64,
    wd_max: Option<usize>,
    follow_symlinks: bool,
    want_sha256: bool,
    want_md5: bool,
    exclude: HashSet<String>,
}

impl Config {
    fn from_args(hash_algo: &str, max_hash_size: u64, max_depth: u64,
                 follow_symlinks: bool, exclude_dirs: &[String]) -> Config {
        let algo = hash_algo.to_lowercase();
        Config {
            max_hash_size,
            wd_max: if max_depth == 0 { None } else { Some(max_depth as usize + 1) },
            follow_symlinks,
            want_sha256: algo.contains("sha") || algo.contains("both"),
            want_md5: algo.contains("md5") || algo.contains("both"),
            exclude: exclude_dirs.iter().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect(),
        }
    }

    fn excluded(&self, name: &OsStr) -> bool {
        if self.exclude.is_empty() {
            return false;
        }
        self.exclude.contains(&name.to_string_lossy().to_lowercase())
    }

    fn must_hash(&self, size: u64) -> bool {
        size > 0 && size <= self.max_hash_size
    }
}

#[derive(Clone, Default)]
struct Counters {
    files_seen: u64,
    dirs_seen: u64,
    bytes_scanned: u64,
    errors: u64,
}

struct Job {
    path: String,
    size: u64,
}

/// Shared state feeding the (P)ython progress / cancel callbacks.
struct TickState {
    abort: bool,
    captured: Option<PyErr>,
}

impl TickState {
    fn new() -> Self {
        TickState { abort: false, captured: None }
    }
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    // SAFETY: `wide` is a null-terminated UTF-16 buffer valid for the duration
    // of the call; `GetFileAttributesW` only reads it.
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attrs != u32::MAX && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_path: &Path) -> bool {
    false
}

fn is_lnk(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".lnk")
}

/// Stream a file through the requested hashers with a small fixed buffer.
fn compute_hashes(path: &str, cfg: &Config) -> Result<(Option<String>, Option<String>), String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut sha = cfg.want_sha256.then(Sha256::new);
    let mut md5 = cfg.want_md5.then(Md5::new);
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if let Some(s) = sha.as_mut() {
            s.update(&buf[..n]);
        }
        if let Some(m) = md5.as_mut() {
            m.update(&buf[..n]);
        }
    }
    Ok((sha.map(|s| hex::encode(s.finalize())), md5.map(|m| hex::encode(m.finalize()))))
}

fn hash_one(job: &Job, cfg: &Config) -> FileHashResult {
    let base = FileHashResult {
        path: job.path.clone(),
        size: job.size,
        sha256: None,
        md5: None,
        error: None,
    };
    if !cfg.must_hash(job.size) {
        return base; // zero-sized / oversized: heuristics only, no hash
    }
    match compute_hashes(&job.path, cfg) {
        Ok((sha, md)) => FileHashResult {
            path: job.path.clone(),
            size: job.size,
            sha256: sha,
            md5: md,
            error: None,
        },
        Err(e) => FileHashResult {
            path: job.path.clone(),
            size: job.size,
            sha256: None,
            md5: None,
            error: Some(e),
        },
    }
}

/// Single-threaded recursive walk (mirrors `scanner._walk` + `_scan_file`
/// enumeration stage). Produces hash jobs and accumulates counters.
#[allow(clippy::too_many_arguments)]
fn walk(root: &Path, cfg: &Config, counters: &mut Counters,
        lnk_dirs: &mut HashSet<String>, tick: &mut TickState,
        progress_cb: &Option<PyObject>, cancel_cb: &Option<PyObject>) -> Vec<Job> {
    let mut jobs = Vec::new();
    let mut entries = 0u64;
    let walker = WalkDir::new(root)
        .follow_links(cfg.follow_symlinks)
        .max_depth(cfg.wd_max.unwrap_or(0));

    for entry in walker {
        if entries % HASH_BATCH as u64 == 0 {
            let _ = maybe_tick(tick, root, counters, progress_cb, cancel_cb);
            if tick.abort {
                break;
            }
        }
        entries += 1;

        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                // Unreadable dir (or a detected link loop): Python counts the
                // dir as seen, then records one error and stops descending.
                counters.dirs_seen += 1;
                counters.errors += 1;
                continue;
            }
        };

        if entry.file_type().is_dir() {
            // Junction / reparse-point dirs are treated as *non* directories
            // by Python's os.scandir(follow_symlinks=False); replicate that so
            // junctions never get descended into (avoids junction cycles).
            if !cfg.follow_symlinks && is_reparse_point(entry.path()) {
                continue;
            }
            if let Some(limit) = cfg.wd_max {
                // Directories sitting exactly at the depth cap are never
                // entered (Python's `if depth > max_depth: return`).
                if entry.depth() >= limit {
                    continue;
                }
            }
            if cfg.excluded(entry.file_name()) {
                continue;
            }
            counters.dirs_seen += 1;
        } else if cfg.excluded(entry.file_name()) {
            continue;
        } else {
            match std::fs::metadata(entry.path()) {
                Ok(md) if md.is_file() => {
                    let name = entry.file_name().to_string_lossy();
                    if is_lnk(&name) {
                        if let Some(parent) = entry.path().parent() {
                            lnk_dirs.insert(parent.to_string_lossy().into_owned());
                        }
                    }
                    counters.files_seen += 1;
                    jobs.push(Job {
                        path: entry.path().to_string_lossy().into_owned(),
                        size: md.len(),
                    });
                }
                Ok(_) => { /* not a regular file: skip silently (Python S_ISREG) */ }
                Err(_) => {
                    // stat failed: Python increments errors and moves on.
                    counters.errors += 1;
                }
            }
        }
    }
    jobs
}

/// Emit a progress/cancel tick (GIL re-acquired on the calling thread only).
/// Callers throttle: the walk ticks every `HASH_BATCH` entries, the hashing
/// phase ticks after every batch, so this runs at most once per ~256 files.
fn maybe_tick(tick: &mut TickState, path: &Path, counters: &Counters,
             progress_cb: &Option<PyObject>, cancel_cb: &Option<PyObject>) -> bool {
    if tick.abort {
        return true;
    }
    let (files, dirs, bytes, errs) =
        (counters.files_seen, counters.dirs_seen, counters.bytes_scanned, counters.errors);
    if let Some(cb) = cancel_cb {
        let res = Python::with_gil(|py| cb.bind(py).call0().map(|_| ()));
        if let Err(e) = res {
            tick.abort = true;
            tick.captured = Some(e);
            return true;
        }
    }
    if let Some(pb) = progress_cb {
        let _ = Python::with_gil(|py| {
            pb.bind(py)
                .call1((path.to_string_lossy().into_owned(), files, dirs, bytes, errs))
        });
    }
    tick.abort
}

// ----------------------------------------------------------------- module entry

#[pyfunction]
#[pyo3(signature = (path, hash_algo, max_hash_size, max_depth, follow_symlinks,
                    exclude_dirs, threads, progress_cb=None, cancel_cb=None))]
fn scan_directory(
    py: Python<'_>,
    path: &str,
    hash_algo: &str,
    max_hash_size: u64,
    max_depth: u64,
    follow_symlinks: bool,
    exclude_dirs: Vec<String>,
    threads: usize,
    progress_cb: Option<PyObject>,
    cancel_cb: Option<PyObject>,
) -> PyResult<ScanOutcome> {
    let root = Path::new(path);
    if !root.is_dir() {
        return Err(PyValueError::new_err(format!("not a directory: {path}")));
    }
    let cfg = Config::from_args(hash_algo, max_hash_size, max_depth,
                                follow_symlinks, &exclude_dirs);
    let nthreads = if threads > 0 {
        threads
    } else {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(nthreads)
        .build()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    // Release the GIL: the walk and every hashing batch run without it. Only
    // the per-batch ticks (on this thread) briefly re-acquire it.
    let outcome = py.allow_threads(|| {
        let mut tick = TickState::new();
        let mut counters = Counters::default();
        let mut lnk_dirs: HashSet<String> = HashSet::new();

        let jobs = walk(&root, &cfg, &mut counters, &mut lnk_dirs, &mut tick,
                        &progress_cb, &cancel_cb);
        if tick.abort {
            return Err(tick.captured.take()
                .unwrap_or_else(|| PyRuntimeError::new_err("scan aborted")));
        }

        let mut results: Vec<FileHashResult> = Vec::with_capacity(jobs.len());
        for chunk in jobs.chunks(HASH_BATCH) {
            if tick.abort {
                break;
            }
            let partial: Vec<FileHashResult> =
                pool.install(|| chunk.par_iter().map(|job| hash_one(job, &cfg)).collect());
            for r in &partial {
                if r.error.is_none() {
                    if r.sha256.is_some() || r.md5.is_some() {
                        counters.bytes_scanned += r.size;
                    }
                } else {
                    counters.errors += 1;
                }
            }
            results.extend(partial);
            let last = chunk.last().map(|j| Path::new(&j.path));
            if let Some(last_path) = last {
                let _ = maybe_tick(&mut tick, last_path, &counters,
                                   &progress_cb, &cancel_cb);
            }
        }

        if tick.abort {
            return Err(tick.captured.take()
                .unwrap_or_else(|| PyRuntimeError::new_err("scan aborted")));
        }

        let mut lnk_dirs: Vec<String> = lnk_dirs.into_iter().collect();
        lnk_dirs.sort();
        Ok(ScanOutcome {
            results,
            stats: ScanStats {
                files_seen: counters.files_seen,
                dirs_seen: counters.dirs_seen,
                bytes_scanned: counters.bytes_scanned,
                errors: counters.errors,
            },
            lnk_dirs,
        })
    });

    outcome
}

#[pymodule]
fn secudrive_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FileHashResult>()?;
    m.add_class::<ScanStats>()?;
    m.add_class::<ScanOutcome>()?;
    m.add_function(wrap_pyfunction!(scan_directory, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}