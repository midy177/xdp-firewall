use super::*;

#[test]
fn resized_map_sizes_doubles_and_rounds_changed_maps() {
    let current = XdpMapSizes {
        rule_entries: 100,
        geo_entries: 8,
        trusted_entries: 4,
        country_entries: 676,
        rate_entries: 16,
        custom_rate_limit_entries: 4,
        temp_ban_entries: 4,
    };
    let required = XdpMapSizes {
        rule_entries: 101,
        geo_entries: 8,
        trusted_entries: 9,
        country_entries: 676,
        rate_entries: 999,
        custom_rate_limit_entries: 5,
        temp_ban_entries: 4,
    };

    let resized = resized_map_sizes(current, required).unwrap().unwrap();
    assert_eq!(resized.rule_entries, 256);
    assert_eq!(resized.geo_entries, 8);
    assert_eq!(resized.trusted_entries, 16);
    assert_eq!(resized.country_entries, 676);
    assert_eq!(resized.rate_entries, 16);
    assert_eq!(resized.custom_rate_limit_entries, 8);
    assert_eq!(resized.temp_ban_entries, 4);
}

#[test]
fn resized_map_sizes_returns_none_when_current_capacity_is_enough() {
    let current = XdpMapSizes::default();
    let required = current;

    assert_eq!(resized_map_sizes(current, required).unwrap(), None);
}

#[test]
fn validate_map_capacity_reports_capacity_shortfall() {
    let current = XdpMapSizes {
        rule_entries: 1,
        ..XdpMapSizes::default()
    };
    let required = XdpMapSizes {
        rule_entries: 2,
        ..current
    };
    let err = validate_map_capacity(required, current).unwrap_err();
    assert!(err.to_string().contains("rule_cidrs needs 2 entries"));
}
