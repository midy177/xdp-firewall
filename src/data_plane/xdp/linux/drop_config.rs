use crate::data_plane::xdp::{DropConfigValue, Result};
use aya::maps::{Array as AyaArray, MapData};

pub(in crate::data_plane::xdp) fn set_drop_config(
    drop_config: &mut AyaArray<MapData, DropConfigValue>,
    enabled: bool,
) -> Result<()> {
    drop_config.set(
        0,
        DropConfigValue {
            value: u8::from(enabled),
        },
        0,
    )?;
    Ok(())
}
