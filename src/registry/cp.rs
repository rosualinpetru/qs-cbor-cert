pub const CP_ANY_POLICY: i64 = 0;
pub const CP_DOMAIN_VALIDATION: i64 = 1; // DV
pub const CP_ORGANIZATION_VALIDATION: i64 = 2; // OV
pub const CP_INDIVIDUAL_VALIDATION: i64 = 3; // IV
pub const CP_EXTENDED_VALIDATION: i64 = 4; // EV
pub const CP_RESOURCE_PKI: i64 = 7; // RPKI
pub const CP_RESOURCE_PKI_ALT: i64 = 8;
pub const CP_RSP_ROLE_CI: i64 = 10; // Certificate Issuer
pub const CP_RSP_ROLE_EUICC: i64 = 11;
pub const CP_RSP_ROLE_EUM: i64 = 12; // eUICC Manufacturer
pub const CP_RSP_ROLE_DP_TLS: i64 = 13; // SM-DP+ TLS
pub const CP_RSP_ROLE_DP_AUTH: i64 = 14; // SM-DP+ Authentication
pub const CP_RSP_ROLE_DP_PB: i64 = 15; // SM-DP+ Profile Binding
pub const CP_RSP_ROLE_DS_TLS: i64 = 16; // SM-DS TLS
pub const CP_RSP_ROLE_DS_AUTH: i64 = 17; // SM-DS Authentication, 06 07 67 81 12 01 02 01 07
pub fn cp_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0E, ..] => match oid[7..] {
            [0x02] => Some(CP_RESOURCE_PKI),
            [0x03] => Some(CP_RESOURCE_PKI_ALT),
            _ => None,
        },
        [0x55, 0x1D, 0x20, 0x00] => Some(CP_ANY_POLICY),
        [0x67, 0x81, 0x0C, 0x01, ..] => match oid[4..] {
            [0x01] => Some(CP_EXTENDED_VALIDATION),
            [0x02, 0x01] => Some(CP_DOMAIN_VALIDATION),
            [0x02, 0x02] => Some(CP_ORGANIZATION_VALIDATION),
            [0x02, 0x03] => Some(CP_INDIVIDUAL_VALIDATION),
            _ => None,
        },
        [0x67, 0x81, 0x12, 0x01, 0x02, 0x01, ..] => match oid[6..] {
            [0x00] => Some(CP_RSP_ROLE_CI),
            [0x01] => Some(CP_RSP_ROLE_EUICC),
            [0x02] => Some(CP_RSP_ROLE_EUM),
            [0x03] => Some(CP_RSP_ROLE_DP_TLS),
            [0x04] => Some(CP_RSP_ROLE_DP_AUTH),
            [0x05] => Some(CP_RSP_ROLE_DP_PB),
            [0x06] => Some(CP_RSP_ROLE_DS_TLS),
            [0x07] => Some(CP_RSP_ROLE_DS_AUTH),
            _ => None,
        },
        _ => None,
    }
}