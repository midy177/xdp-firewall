use super::cidrs::ip_to_host_cidr;
use super::watch::watch_line_changed;
use super::*;

#[test]
fn skips_headless_service_cluster_ip() {
    assert!(ip_to_host_cidr("None").unwrap().is_none());
}

#[test]
fn converts_node_ip_to_host_cidr() {
    assert_eq!(
        ip_to_host_cidr("10.0.0.5").unwrap().unwrap().to_string(),
        "10.0.0.5/32"
    );
}

#[test]
fn watch_bookmark_is_not_a_change() {
    assert!(
        !watch_line_changed::<Node>(
            r#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"1"}}}"#,
            "nodes"
        )
        .unwrap()
    );
}

#[test]
fn watch_added_is_a_change_after_resource_version_anchor() {
    assert!(watch_line_changed::<Node>(r#"{"type":"ADDED","object":{}}"#, "nodes").unwrap());
}

#[test]
fn watch_error_is_not_reported_as_policy_change() {
    let err = watch_line_changed::<Node>(
        r#"{"type":"ERROR","object":{"message":"too old resource version"}}"#,
        "nodes",
    )
    .unwrap_err();
    assert!(err.to_string().contains("too old resource version"));
}
