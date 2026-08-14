use super::*;

#[test]
fn pin_component_allows_vlan_interface_names() {
    assert_eq!(sanitize_pin_component("eth0.10").unwrap(), "eth0.10");
}

#[test]
fn pin_component_rejects_path_components() {
    for value in ["", " ", ".", ".."] {
        assert!(sanitize_pin_component(value).is_err());
    }
}
