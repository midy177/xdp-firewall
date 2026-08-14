use super::super::{
    GEO_PREFIX_PAGE_SIZE, XdsService, internal_status,
    proto::{FetchGeoPrefixesRequest, FetchGeoPrefixesResponse, GeoPrefix as ProtoGeoPrefix},
    state::{enabled_geo_countries, latest_version},
};
use crate::intelligence::geo;
use anyhow::{Context, Result};
use tonic::Status;

const MAX_GEO_PREFIX_PAGE_SIZE: u32 = 10_000;

pub(in crate::control_plane::xds) async fn fetch_geo_prefixes_response(
    service: &XdsService,
    request: FetchGeoPrefixesRequest,
) -> std::result::Result<FetchGeoPrefixesResponse, Status> {
    let version = latest_version(&service.db).await.map_err(internal_status)?;
    ensure_geo_prefix_version_current(request.version, version)?;
    let countries = enabled_geo_countries(&service.db)
        .await
        .map_err(internal_status)?;
    let page = geo::load_persisted_geo_prefix_page(
        &service.db,
        &countries,
        Some(&request.page_token),
        geo_prefix_page_size(request.page_size),
    )
    .await
    .map_err(internal_status)?;
    Ok(FetchGeoPrefixesResponse {
        version,
        prefixes: proto_geo_prefixes(&page.prefixes).map_err(internal_status)?,
        next_page_token: page.next_page_token.unwrap_or_default(),
    })
}

fn ensure_geo_prefix_version_current(requested: i64, current: i64) -> Result<(), Status> {
    if requested > 0 && requested != current {
        return Err(Status::failed_precondition(
            "GeoIP prefix version changed; refetch policy",
        ));
    }
    Ok(())
}

fn geo_prefix_page_size(requested: u32) -> usize {
    if requested == 0 {
        GEO_PREFIX_PAGE_SIZE as usize
    } else {
        requested.min(MAX_GEO_PREFIX_PAGE_SIZE) as usize
    }
}

fn proto_geo_prefixes(prefixes: &[geo::GeoPrefix]) -> Result<Vec<ProtoGeoPrefix>> {
    prefixes.iter().map(proto_geo_prefix).collect()
}

fn proto_geo_prefix(prefix: &geo::GeoPrefix) -> Result<ProtoGeoPrefix> {
    Ok(ProtoGeoPrefix {
        cidr: geo::geo_prefix_to_cidr(prefix),
        country: geo::decode_country(prefix.country)
            .with_context(|| "invalid persisted geo country code")?,
    })
}
