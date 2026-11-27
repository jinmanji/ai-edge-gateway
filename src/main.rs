#![forbid(unsafe_code)]

use std::{
    io,
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, mpsc},
    time::Duration,
};

use ai_edge_gateway::{Result, config::Snapshot, server};
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};
use tracing_subscriber::{Layer, filter::filter_fn, fmt::MakeWriter, layer::SubscriberExt};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

struct Args {
    file: PathBuf,
    check: bool,
    workers: usize,
}
const USAGE: &str = "Usage: ai-edge-gateway [--config PATH] [--workers N] [--check]\n                     [--help | --version]";

fn args() -> Result<Option<Args>> {
    let mut a = Args {
        file: "config.toml".into(),
        check: false,
        workers: std::thread::available_parallelism().map_or(2, |n| n.get().min(2)),
    };
    let mut values = std::env::args_os().skip(1);
    while let Some(value) = values.next() {
        match value.to_str() {
            Some("--config") => a.file = values.next().ok_or("--config requires a path")?.into(),
            Some("--check") => a.check = true,
            Some("--workers") => {
                a.workers = values
                    .next()
                    .and_then(|x| x.to_str()?.parse::<usize>().ok())
                    .filter(|&n| (1..=64).contains(&n))
                    .ok_or("--workers must be in 1..=64")?
            }
            Some("--help" | "-h") => {
                println!("{USAGE}");
                return Ok(None);
            }
            Some("--version" | "-V") => {
                println!("ai-edge-gateway {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            _ => return Err("unknown argument; see --help".into()),
        }
    }
    Ok(Some(a))
}

fn main() -> ExitCode {
    let run = || -> Result<()> {
        let Some(args) = args()? else { return Ok(()) };
        if !args.check {
            logging();
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.workers)
            .enable_all()
            .build()
            .map_err(|_| "cannot initialize Tokio runtime")?;
        let result = runtime.block_on(serve(args));
        // At a drain deadline, remaining asynchronous tasks are cancelled. A
        // just-started blocking reload must not indefinitely delay process exit.
        runtime.shutdown_timeout(Duration::from_millis(100));
        result
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ai-edge-gateway: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(args: Args) -> Result<()> {
    let path = args.file.clone();
    let snapshot = tokio::task::spawn_blocking(move || Snapshot::from_file(&path, None))
        .await
        .map_err(|_| "configuration loader failed")??;
    if args.check {
        println!("configuration valid");
        return Ok(());
    }
    let mut hup = signal(SignalKind::hangup()).map_err(|_| "cannot register SIGHUP")?;
    let mut term = signal(SignalKind::terminate()).map_err(|_| "cannot register SIGTERM")?;
    let mut int = signal(SignalKind::interrupt()).map_err(|_| "cannot register SIGINT")?;
    let h3 = snapshot.listen.h3;
    let https = snapshot.tls.is_some();
    let running = server::start(Arc::new(snapshot))?;
    tracing::info!(public = %running.public_addr, management = %running.management_addr, https, h3, "gateway listening");
    let app = running.app;
    let mut pending: Option<JoinHandle<Result<Snapshot>>> = None;
    let mut reap = interval(Duration::from_secs(10));
    reap.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = term.recv() => break,
            _ = int.recv() => break,
            result = async { pending.as_mut().expect("reload job available").await }, if pending.is_some() => {
                pending = None;
                match result {
                    Ok(Ok(new)) => {
                        let new = Arc::new(new);
                        app.config.store(new.clone());
                        new.schedule_endpoint_refresh(&app.tasks, &app.stop);
                        tracing::info!("configuration reloaded");
                    }
                    Ok(Err(e)) => tracing::warn!(reason = %e, "configuration rejected; keeping previous snapshot"),
                    Err(_) => tracing::warn!("configuration loader failed; keeping previous snapshot"),
                }
            }
            _ = hup.recv(), if pending.is_none() => {
                let path = args.file.clone();
                let old = app.config.load_full();
                pending = Some(tokio::task::spawn_blocking(move || Snapshot::from_file(&path, Some(&old))));
            }
            _ = reap.tick() => {
                let snapshot = app.config.load_full();
                snapshot.schedule_endpoint_refresh(&app.tasks, &app.stop);
                snapshot.maintain().await;
            }
        }
    }
    let drained = server::shutdown(&app).await;
    tracing::info!(drained, "gateway stopped");
    Ok(())
}

// A narrow target filter is security-relevant: HTTP/DNS/TLS library debug logs
// can contain a URI or credentials even if the application never logs them.
fn logging() {
    if cfg!(feature = "quiet") || std::env::var("AIEG_LOG").as_deref() == Ok("off") {
        return;
    }
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(64);
    if std::thread::Builder::new()
        .name("aieg-log".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            use std::io::Write;
            let stderr = io::stderr();
            while let Ok(line) = rx.recv() {
                let _ = stderr.lock().write_all(&line);
            }
        })
        .is_err()
    {
        return;
    }
    let ours = filter_fn(|m| {
        (m.target() == "ai_edge_gateway" || m.target().starts_with("ai_edge_gateway::"))
            && *m.level() <= tracing::Level::INFO
    });
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(false)
            .with_writer(LogWriter(tx))
            .with_filter(ours),
    );
    let _ = tracing::subscriber::set_global_default(subscriber);
}

struct LogWriter(mpsc::SyncSender<Vec<u8>>);
struct Line<'a>(&'a mpsc::SyncSender<Vec<u8>>, Vec<u8>);
impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = Line<'a>;
    fn make_writer(&'a self) -> Line<'a> {
        Line(&self.0, Vec::with_capacity(256))
    }
}
impl io::Write for Line<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.1.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Line<'_> {
    fn drop(&mut self) {
        if !self.1.is_empty() {
            let _ = self.0.try_send(std::mem::take(&mut self.1));
        }
    }
}
