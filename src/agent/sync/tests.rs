use crate::{agent::offline::OfflinePolicyState, cli::AgentOfflineMode};

fn should_unload_rules(state: &OfflinePolicyState, failure_limit: u32) -> bool {
    state.should_unload_rules(AgentOfflineMode::UnloadRules, failure_limit)
}

#[test]
fn offline_mode_unloads_after_configured_failure_limit() {
    let mut state = OfflinePolicyState::default();

    for _ in 0..4 {
        state.record_control_plane_failure();
        assert!(!should_unload_rules(&state, 5));
    }
    state.record_control_plane_failure();

    assert!(should_unload_rules(&state, 5));
}

#[test]
fn keep_rules_offline_mode_never_unloads() {
    let mut state = OfflinePolicyState::default();

    state.record_control_plane_failure();

    assert!(!state.should_unload_rules(AgentOfflineMode::KeepRules, 1));
}

#[test]
fn policy_apply_resets_offline_state() {
    let mut state = OfflinePolicyState::default();

    state.record_control_plane_failure();
    assert!(should_unload_rules(&state, 1));
    state.rules_unloaded = true;
    state.record_policy_applied();

    assert_eq!(state.consecutive_failures, 0);
    assert!(!state.rules_unloaded);
    assert!(!should_unload_rules(&state, 1));
}

#[test]
fn transient_connection_success_does_not_reset_failures() {
    let mut state = OfflinePolicyState::default();

    state.record_control_plane_failure();

    assert_eq!(state.consecutive_failures, 1);
    assert!(!should_unload_rules(&state, 2));
}

#[test]
fn healthy_control_plane_resets_failures() {
    let mut state = OfflinePolicyState::default();

    state.record_control_plane_failure();
    state.record_control_plane_healthy();

    assert_eq!(state.consecutive_failures, 0);
    assert!(!should_unload_rules(&state, 2));
}
