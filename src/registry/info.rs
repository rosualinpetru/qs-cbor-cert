pub const INFO_OCSP: i64 = 1;
pub const INFO_CA_ISSUERS: i64 = 2;
pub const INFO_TIME_STAMPING: i64 = 3;
pub const INFO_CA_REPOSITORY: i64 = 5;
pub const INFO_RPKI_MANIFEST: i64 = 10;
pub const INFO_SIGNED_OBJECT: i64 = 11;
pub const INFO_RPKI_NOTIFY: i64 = 13;
pub fn info_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, ..] => match oid[7..] {
            [0x01] => Some(INFO_OCSP),
            [0x02] => Some(INFO_CA_ISSUERS),
            [0x03] => Some(INFO_TIME_STAMPING),
            [0x05] => Some(INFO_CA_REPOSITORY),
            [0x0A] => Some(INFO_RPKI_MANIFEST),
            [0x0B] => Some(INFO_SIGNED_OBJECT),
            [0x0D] => Some(INFO_RPKI_NOTIFY),
            _ => None,
        },
        _ => None,
    }
}
