#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use tokio::{sync::mpsc, task::JoinHandle};

mod event;
#[cfg(target_os = "linux")]
mod linux;

pub use event::DropEventLine;
#[cfg(target_os = "linux")]
pub use event::parse_drop_event;
#[cfg(target_os = "linux")]
use linux::{open_drop_config, open_reader, set_drop_config};

pub struct DropEventReader {
    receiver: mpsc::Receiver<DropEventLine>,
    task: Option<JoinHandle<()>>,
}

impl DropEventReader {
    pub async fn recv(&mut self) -> Option<DropEventLine> {
        self.receiver.recv().await
    }
}

impl Drop for DropEventReader {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn stream(
    events_path: std::path::PathBuf,
    config_path: Option<std::path::PathBuf>,
    json: bool,
) -> Result<()> {
    let mut config = if let Some(path) = config_path {
        Some(open_drop_config(&path)?)
    } else {
        None
    };
    if let Some(config) = config.as_mut() {
        set_drop_config(config, true)?;
    }
    let result = print_events(events_path, json).await;
    if let Some(config) = config.as_mut() {
        let _ = set_drop_config(config, false);
    }
    result
}

#[cfg(target_os = "linux")]
async fn print_events(path: std::path::PathBuf, json: bool) -> Result<()> {
    let mut reader = open_reader(path)?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;
    loop {
        tokio::select! {
            event = reader.recv() => {
                let Some(line) = event else {
                    return Ok(());
                };
                if json {
                    match serde_json::to_string(&line) {
                        Ok(value) => println!("{value}"),
                        Err(err) => eprintln!("failed to serialize drop event: {err}"),
                    }
                } else {
                    println!("{}", line.to_line());
                }
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                return Ok(());
            }
            _ = terminate.recv() => {
                return Ok(());
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub fn spawn_drop_event_reader(path: std::path::PathBuf) -> Result<DropEventReader> {
    open_reader(path)
}

#[cfg(not(target_os = "linux"))]
pub fn spawn_drop_event_reader(_path: std::path::PathBuf) -> Result<DropEventReader> {
    let (_tx, rx) = mpsc::channel(1);
    Ok(DropEventReader {
        receiver: rx,
        task: None,
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unused_async)]
pub async fn stream(
    events_path: std::path::PathBuf,
    config_path: Option<std::path::PathBuf>,
    json: bool,
) -> Result<()> {
    let _ = (events_path, config_path, json);
    bail!("monitor --drop is only supported on Linux")
}
