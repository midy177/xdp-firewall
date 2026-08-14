use super::super::{
    GEO_PREFIX_PAGE_SIZE,
    proto::{FetchGeoPrefixesRequest, GeoPrefix},
};
use super::XdsClient;
use crate::{intelligence::geo, policy::model::GeoIpPrefixPolicy};
use anyhow::{Context, Result};

impl XdsClient {
    pub(super) async fn fetch_geo_prefixes(
        &mut self,
        version: i64,
    ) -> Result<Vec<GeoIpPrefixPolicy>> {
        let mut prefixes = Vec::new();
        let mut page_token = String::new();
        loop {
            let page = self.fetch_geo_prefix_page(version, page_token).await?;
            append_geo_prefixes(&mut prefixes, page.prefixes)?;
            if page.next_page_token.trim().is_empty() {
                break;
            }
            page_token = page.next_page_token;
        }
        Ok(prefixes)
    }

    async fn fetch_geo_prefix_page(
        &mut self,
        version: i64,
        page_token: String,
    ) -> Result<super::super::proto::FetchGeoPrefixesResponse> {
        let request = self.with_auth(FetchGeoPrefixesRequest {
            version,
            page_size: GEO_PREFIX_PAGE_SIZE,
            page_token,
        })?;
        Ok(self.inner.fetch_geo_prefixes(request).await?.into_inner())
    }
}

fn append_geo_prefixes(prefixes: &mut Vec<GeoIpPrefixPolicy>, page: Vec<GeoPrefix>) -> Result<()> {
    for prefix in page {
        prefixes.push(geo_prefix_policy(prefix)?);
    }
    Ok(())
}

fn geo_prefix_policy(prefix: GeoPrefix) -> Result<GeoIpPrefixPolicy> {
    Ok(GeoIpPrefixPolicy {
        cidr: prefix
            .cidr
            .parse()
            .with_context(|| format!("invalid xDS GeoIP CIDR '{}'", prefix.cidr))?,
        country: geo::normalize_country(&prefix.country)?,
    })
}
