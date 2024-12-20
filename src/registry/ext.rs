pub const EXT_SUBJECT_KEY_ID: u16 = 1;
pub const EXT_KEY_USAGE: u16 = 2;
pub const EXT_SUBJECT_ALT_NAME: u16 = 3;
pub const EXT_BASIC_CONSTRAINTS: u16 = 4;
pub const EXT_CRL_DIST_POINTS: u16 = 5;
pub const EXT_CERT_POLICIES: u16 = 6;
pub const EXT_AUTH_KEY_ID: u16 = 7;
pub const EXT_EXT_KEY_USAGE: u16 = 8;
pub const EXT_AUTH_INFO: u16 = 9;
pub const EXT_SCT_LIST: u16 = 10;
pub const EXT_SUBJECT_DIRECTORY_ATTR: u16 = 24; //0x09
pub const EXT_ISSUER_ALT_NAME: u16 = 25; //0x12
pub const EXT_NAME_CONSTRAINTS: u16 = 26; //0x1E
pub const EXT_POLICY_MAPPINGS: u16 = 27; //21
pub const EXT_POLICY_CONSTRAINTS: u16 = 28; //24
pub const EXT_FRESHEST_CRL: u16 = 29; //2e
pub const EXT_INHIBIT_ANYPOLICY: u16 = 30; //36
pub const EXT_SUBJECT_INFO_ACCESS: u16 = 31; //5-0b
pub const EXT_IP_RESOURCES: u16 = 32; //5-07
pub const EXT_AS_RESOURCES: u16 = 33; //5-08
pub const EXT_IP_RESOURCES_V2: u16 = 34; //5-1c
pub const EXT_AS_RESOURCES_V2: u16 = 35; //5-1d
pub const EXT_BIOMETRIC_INFO: u16 = 36; //5-02
pub const EXT_PRECERT_SIGNING_CERT: u16 = 37; //4-04
pub const EXT_OCSP_NO_CHECK: u16 = 38; //2B 06 01 05 05 07 30 01 05
pub const EXT_QUALIFIED_CERT_STATEMENTS: u16 = 39; //5-03
pub const EXT_S_MIME_CAPABILITIES: u16 = 40; //2A 86 48 86 F7 0D 01 09 0F
pub const EXT_TLS_FEATURES: u16 = 41; //5-18
pub const EXT_CHALLENGE_PASSWORD: u16 = 255;
pub fn ext_map(oid: &[u8]) -> Option<u16> {
    match oid {
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, ..] => match oid[9] {
            0x02 => Some(EXT_SCT_LIST),
            0x04 => Some(EXT_PRECERT_SIGNING_CERT),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, ..] => match oid[7] {
            0x01 => Some(EXT_AUTH_INFO),
            0x02 => Some(EXT_BIOMETRIC_INFO),
            0x03 => Some(EXT_QUALIFIED_CERT_STATEMENTS),
            0x07 => Some(EXT_IP_RESOURCES),
            0x08 => Some(EXT_AS_RESOURCES),
            0x0B => Some(EXT_SUBJECT_INFO_ACCESS),
            0x18 => Some(EXT_TLS_FEATURES),
            0x1C => Some(EXT_IP_RESOURCES_V2),
            0x1D => Some(EXT_AS_RESOURCES_V2),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05] => Some(EXT_OCSP_NO_CHECK),
        [0x2B, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0F] => Some(EXT_S_MIME_CAPABILITIES),
        [0x55, 0x1D, ..] => match oid[2] {
            0x09 => Some(EXT_SUBJECT_DIRECTORY_ATTR),
            0x0E => Some(EXT_SUBJECT_KEY_ID),
            0x0F => Some(EXT_KEY_USAGE),
            0x11 => Some(EXT_SUBJECT_ALT_NAME),
            0x12 => Some(EXT_ISSUER_ALT_NAME),
            0x13 => Some(EXT_BASIC_CONSTRAINTS),
            0x1E => Some(EXT_NAME_CONSTRAINTS),
            0x1F => Some(EXT_CRL_DIST_POINTS),
            0x20 => Some(EXT_CERT_POLICIES),
            0x21 => Some(EXT_POLICY_MAPPINGS),
            0x23 => Some(EXT_AUTH_KEY_ID),
            0x24 => Some(EXT_POLICY_CONSTRAINTS),
            0x25 => Some(EXT_EXT_KEY_USAGE),
            0x2E => Some(EXT_FRESHEST_CRL),
            0x36 => Some(EXT_INHIBIT_ANYPOLICY),
            _ => None,
        },
        _ => None,
    }
}