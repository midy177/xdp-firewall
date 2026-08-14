use super::{DropEventReader, parse_drop_event};
use anyhow::{Context, Result};
use aya::{
    maps::{
        Array as AyaArray, Map, MapData, PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    util::online_cpus,
};
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};

pub(super) fn open_reader(path: std::path::PathBuf) -> Result<DropEventReader> {
    let map_data = MapData::from_pin(&path).with_context(|| {
        format!(
            "failed to open pinned drop_events map '{}'; start a new agent first",
            path.display()
        )
    })?;
    let map = Map::from_map_data(map_data)
        .context("pinned drop_events path is not a supported BPF map")?;
    let mut events: PerfEventArray<MapData> = map
        .try_into()
        .context("pinned drop_events map has unexpected type")?;
    let cpus = online_cpus().map_err(|(_, err)| err)?;
    let mut buffers = Vec::new();
    for cpu in cpus {
        let buffer = events
            .open(cpu, Some(16))
            .with_context(|| format!("failed to open drop event perf buffer for CPU {cpu}"))?;
        buffers.push((cpu, buffer));
    }
    let (tx, rx) = mpsc::channel(1024);
    let task = tokio::spawn(async move {
        poll_drop_event_buffers(tx, buffers).await;
    });
    Ok(DropEventReader {
        receiver: rx,
        task: Some(task),
    })
}

async fn poll_drop_event_buffers(
    tx: mpsc::Sender<super::DropEventLine>,
    mut buffers: Vec<(u32, PerfEventArrayBuffer<MapData>)>,
) {
    loop {
        if tx.is_closed() {
            break;
        }
        let mut drained = false;
        for (cpu, buffer) in &mut buffers {
            if !buffer.readable() {
                continue;
            }
            drained = true;
            buffer.for_each(|event| match event {
                PerfEvent::Sample { head, tail } => {
                    let mut bytes = Vec::with_capacity(head.len() + tail.len());
                    bytes.extend_from_slice(head);
                    bytes.extend_from_slice(tail);
                    if let Some(line) = parse_drop_event(*cpu, &bytes) {
                        let _ = tx.try_send(line);
                    }
                }
                PerfEvent::Lost { count } => {
                    eprintln!("lost {count} drop events on CPU {cpu}");
                }
            });
        }
        if !drained {
            sleep(Duration::from_millis(100)).await;
        }
    }
}

pub(super) fn open_drop_config(path: &std::path::Path) -> Result<AyaArray<MapData, u8>> {
    let map_data = MapData::from_pin(path).with_context(|| {
        format!(
            "failed to open pinned drop_config map '{}'; start a new agent first",
            path.display()
        )
    })?;
    Map::from_map_data(map_data)
        .context("pinned drop_config path is not a supported BPF map")?
        .try_into()
        .context("pinned drop_config map has unexpected type")
}

pub(super) fn set_drop_config(config: &mut AyaArray<MapData, u8>, enabled: bool) -> Result<()> {
    config.set(0, u8::from(enabled), 0)?;
    Ok(())
}
