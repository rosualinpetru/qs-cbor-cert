pub const EKU_TLS_SERVER: u64 = 1;
pub const EKU_TLS_CLIENT: u64 = 2;
pub const EKU_CODE_SIGNING: u64 = 3;
pub const EKU_EMAIL_PROTECTION: u64 = 4;
pub const EKU_TIME_STAMPING: u64 = 8;
pub const EKU_OCSP_SIGNING: u64 = 9;
/* Updated */
pub const EKU_ANY_EKU: u64 = 0; //55 1D 25 00
pub const EKU_KERBEROS_PKINIT_CLIENT_AUTH: u64 = 10; //2B 06 01 05 02 03 04
pub const EKU_KERBEROS_PKINIT_KDC: u64 = 11; //2B 06 01 05 02 03 05
pub const EKU_SSH_CLIENT: u64 = 12; //15
pub const EKU_SSH_SERVER: u64 = 13; //16
pub const EKU_BUNDLE_SECURITY: u64 = 14; //23
pub const EKU_CMC_CERT_AUTHORITY: u64 = 15; //1b
pub const EKU_CMC_REG_AUTHORITY: u64 = 16; //1c
pub const EKU_CMC_ARCHIVE_SERVER: u64 = 17; //1d
pub const EKU_CMC_KEY_GEN_AUTHORITY: u64 = 18; //20
pub fn eku_map(oid: &[u8]) -> Option<u64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, ..] => match oid[6] {
            0x04 => Some(EKU_KERBEROS_PKINIT_CLIENT_AUTH),
            0x05 => Some(EKU_KERBEROS_PKINIT_KDC),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, ..] => match oid[7] {
            0x01 => Some(EKU_TLS_SERVER),
            0x02 => Some(EKU_TLS_CLIENT),
            0x03 => Some(EKU_CODE_SIGNING),
            0x04 => Some(EKU_EMAIL_PROTECTION),
            0x08 => Some(EKU_TIME_STAMPING),
            0x09 => Some(EKU_OCSP_SIGNING),
            0x15 => Some(EKU_SSH_CLIENT),
            0x16 => Some(EKU_SSH_SERVER),
            0x1b => Some(EKU_CMC_CERT_AUTHORITY),
            0x2c => Some(EKU_CMC_REG_AUTHORITY),
            0x2d => Some(EKU_CMC_ARCHIVE_SERVER),
            0x20 => Some(EKU_CMC_ARCHIVE_SERVER),
            0x23 => Some(EKU_BUNDLE_SECURITY),
            _ => None,
        },
        [0x55, 0x1D, 0x25, 0x00] => Some(EKU_ANY_EKU),
        _ => None,
    }
}