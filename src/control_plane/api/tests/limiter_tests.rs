use super::*;

#[test]
fn geo_refresh_limiter_returns_cached_result_for_concurrent_and_repeated_refreshes() {
    let limiter = GeoRefreshLimiter::default();
    let permit = match limiter.start_or_cached(Duration::from_mins(5)) {
        GeoRefreshDecision::Start { permit, previous } => {
            assert!(previous.is_none());
            permit
        }
        _ => panic!("first refresh should start"),
    };
    match limiter.start_or_cached(Duration::from_mins(5)) {
        GeoRefreshDecision::Running(None) => {}
        _ => panic!("concurrent refresh without cache should return running state"),
    }

    permit.finish_success(CachedGeoRefresh {
        version: 7,
        report: geo::GeoRefreshReport::empty("completed"),
    });

    drop(permit);
    match limiter.start_or_cached(Duration::from_mins(5)) {
        GeoRefreshDecision::RateLimited(Some(cached)) => assert_eq!(cached.version, 7),
        _ => panic!("repeated refresh should return cached result"),
    }
}

#[test]
fn threat_refresh_limiter_can_be_bypassed_for_missing_prefixes() {
    let limiter = ThreatRefreshLimiter::default();
    let ThreatRefreshDecision::Start { permit, .. } =
        limiter.start_or_cached(MANUAL_REFRESH_RATE_LIMIT)
    else {
        panic!("initial threat refresh should start");
    };
    permit.finish_success(CachedThreatRefresh {
        version: 1,
        report: threat::ThreatRefreshReport::empty("unchanged"),
    });
    drop(permit);

    assert!(matches!(
        limiter.start_or_cached(MANUAL_REFRESH_RATE_LIMIT),
        ThreatRefreshDecision::RateLimited(_)
    ));
    assert!(matches!(
        limiter.start_or_cached(Duration::ZERO),
        ThreatRefreshDecision::Start { .. }
    ));
}
