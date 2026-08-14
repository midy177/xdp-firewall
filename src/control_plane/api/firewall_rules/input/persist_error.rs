use crate::control_plane::api::ApiError;

pub(super) fn rule_insert_error(value: sea_orm::DbErr) -> ApiError {
    let message = value.to_string();
    let normalized = message.to_ascii_lowercase();
    if is_rule_key_conflict(&normalized) {
        return ApiError::conflict("firewall rule_key already exists");
    }
    ApiError::from(value)
}

fn is_rule_key_conflict(normalized_error: &str) -> bool {
    normalized_error.contains("rule_key")
        || normalized_error.contains("idx_firewall_rules_policy_name_rule_key")
        || normalized_error.contains("idx_firewall_rules_rule_key")
}
