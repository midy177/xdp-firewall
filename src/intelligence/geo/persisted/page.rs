use super::{
    for_each_persisted_cidr, geo_prefix_from_net, load_geo_ip_prefix_row,
    warn_malformed_geo_ip_prefixes, warn_missing_geo_ip_prefixes,
};
use crate::intelligence::geo::{GeoPrefix, GeoPrefixPage, encode_country, normalize_country};
use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use sea_orm::DatabaseConnection;

pub async fn load_persisted_geo_prefix_page(
    db: &DatabaseConnection,
    countries: &[String],
    page_token: Option<&str>,
    page_size: usize,
) -> Result<GeoPrefixPage> {
    let page_size = page_size.max(1);
    let (start_country_index, start_prefix_offset) = parse_geo_prefix_page_token(page_token)?;
    let mut page = GeoPrefixPageBuilder::new(page_size);

    for (country_index, country) in countries.iter().enumerate().skip(start_country_index) {
        collect_country_page(
            db,
            &mut page,
            country,
            country_index,
            start_country_index,
            start_prefix_offset,
        )
        .await?;
        if page.has_next_page() {
            break;
        }
    }

    Ok(page.finish())
}

async fn collect_country_page(
    db: &DatabaseConnection,
    page: &mut GeoPrefixPageBuilder,
    country: &str,
    country_index: usize,
    start_country_index: usize,
    start_prefix_offset: usize,
) -> Result<()> {
    let country = normalize_country(country)?;
    let country_code = encode_country(&country)?;
    let Some(row) = load_geo_ip_prefix_row(db, &country).await? else {
        warn_missing_geo_ip_prefixes(&country);
        return Ok(());
    };
    let skip_until = if country_index == start_country_index {
        start_prefix_offset
    } else {
        0
    };
    match page.collect_country(&row, country_index, skip_until, country_code) {
        Ok(()) => {}
        Err(err) => warn_malformed_geo_ip_prefixes(&country, &err),
    }
    Ok(())
}

struct GeoPrefixPageBuilder {
    prefixes: Vec<GeoPrefix>,
    next_page_token: Option<String>,
    page_size: usize,
}

impl GeoPrefixPageBuilder {
    fn new(page_size: usize) -> Self {
        Self {
            prefixes: Vec::with_capacity(page_size),
            next_page_token: None,
            page_size,
        }
    }

    fn collect_country(
        &mut self,
        row: &crate::db::entities::geo_ip_prefix::Model,
        country_index: usize,
        skip_until: usize,
        country_code: u16,
    ) -> Result<()> {
        let mut offset = 0_usize;
        for_each_persisted_cidr(row, |net| {
            if offset >= skip_until {
                self.collect_prefix(net, country_index, offset, country_code);
            }
            offset += 1;
            Ok(())
        })?;
        Ok(())
    }

    fn collect_prefix(
        &mut self,
        net: IpNet,
        country_index: usize,
        prefix_offset: usize,
        country_code: u16,
    ) {
        if self.prefixes.len() < self.page_size {
            self.prefixes.push(geo_prefix_from_net(net, country_code));
        } else if self.next_page_token.is_none() {
            self.next_page_token = Some(format!("{country_index}:{prefix_offset}"));
        }
    }

    fn has_next_page(&self) -> bool {
        self.next_page_token.is_some()
    }

    fn finish(self) -> GeoPrefixPage {
        GeoPrefixPage {
            prefixes: self.prefixes,
            next_page_token: self.next_page_token,
        }
    }
}

fn parse_geo_prefix_page_token(page_token: Option<&str>) -> Result<(usize, usize)> {
    let Some(page_token) = page_token.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok((0, 0));
    };
    let Some((country_index, prefix_offset)) = page_token.split_once(':') else {
        bail!("invalid GeoIP page token");
    };
    Ok((
        country_index
            .parse::<usize>()
            .context("invalid GeoIP page token country index")?,
        prefix_offset
            .parse::<usize>()
            .context("invalid GeoIP page token prefix offset")?,
    ))
}
