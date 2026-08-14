use crate::{db::entities::geo_ip_prefix, intelligence::geo::GeoPrefix};
use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{
    Deserializer,
    de::{Error as DeError, SeqAccess, Visitor},
};
use std::{fmt, net::IpAddr};

#[must_use]
pub fn geo_prefix_to_cidr(prefix: &GeoPrefix) -> String {
    match prefix.addr {
        IpAddr::V4(addr) => format!("{addr}/{}", prefix.prefix),
        IpAddr::V6(addr) => format!("{addr}/{}", prefix.prefix),
    }
}

pub(in crate::intelligence::geo) fn cidrs_json_from_prefixes(prefixes: &[GeoPrefix]) -> String {
    let mut output = String::new();
    output.push('[');
    for (index, prefix) in prefixes.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push('"');
        output.push_str(&geo_prefix_to_cidr(prefix));
        output.push('"');
    }
    output.push(']');
    output
}

pub(in crate::intelligence::geo) fn persisted_cidrs(
    row: &geo_ip_prefix::Model,
) -> Result<Vec<IpNet>> {
    let mut cidrs = Vec::new();
    for_each_persisted_cidr(row, |cidr| {
        cidrs.push(cidr);
        Ok(())
    })?;
    Ok(cidrs)
}

pub(in crate::intelligence::geo) fn for_each_persisted_cidr<F>(
    row: &geo_ip_prefix::Model,
    on_cidr: F,
) -> Result<usize>
where
    F: FnMut(IpNet) -> Result<()>,
{
    let mut deserializer = serde_json::Deserializer::from_str(&row.cidrs_json);
    deserialize_cidr_array(&mut deserializer, on_cidr)
        .with_context(|| format!("invalid persisted geo CIDR JSON for {}", row.country))
}

fn deserialize_cidr_array<'de, D, F>(
    deserializer: D,
    on_cidr: F,
) -> std::result::Result<usize, D::Error>
where
    D: Deserializer<'de>,
    F: FnMut(IpNet) -> Result<()>,
{
    struct CidrArrayVisitor<F> {
        on_cidr: F,
    }

    impl<'de, F> Visitor<'de> for CidrArrayVisitor<F>
    where
        F: FnMut(IpNet) -> Result<()>,
    {
        type Value = usize;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an array of CIDR strings")
        }

        fn visit_seq<A>(mut self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut count = 0_usize;
            while let Some(cidr) = seq.next_element::<IpNet>()? {
                (self.on_cidr)(cidr).map_err(A::Error::custom)?;
                count += 1;
            }
            Ok(count)
        }
    }

    deserializer.deserialize_seq(CidrArrayVisitor { on_cidr })
}
