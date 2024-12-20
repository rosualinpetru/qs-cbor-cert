pub const ATT_EMAIL: u32 = 0;
pub const ATT_COMMON_NAME: u32 = 1; // CN
pub const ATT_SUR_NAME: u32 = 2; // SN
pub const ATT_SERIAL_NUMBER: u32 = 3;
pub const ATT_COUNTRY: u32 = 4; // C
pub const ATT_LOCALITY: u32 = 5; // L
pub const ATT_STATE_OR_PROVINCE: u32 = 6; // ST
pub const ATT_STREET_ADDRESS: u32 = 7;
pub const ATT_ORGANIZATION: u32 = 8; // O
pub const ATT_ORGANIZATION_UNIT: u32 = 9; // OU
pub const ATT_TITLE: u32 = 10; // T
pub const ATT_BUSINESS: u32 = 11;
pub const ATT_POSTAL_CODE: u32 = 12; // PC
pub const ATT_GIVEN_NAME: u32 = 13;
pub const ATT_INITIALS: u32 = 14;
pub const ATT_GENERATION_QUALIFIER: u32 = 15;
pub const ATT_DN_QUALIFIER: u32 = 16;
pub const ATT_PSEUDONYM: u32 = 17;
pub const ATT_ORGANIZATION_IDENTIFIER: u32 = 18;
pub const ATT_INC_LOCALITY: u32 = 19;
pub const ATT_INC_STATE: u32 = 20;
pub const ATT_INC_COUNTRY: u32 = 21;
pub const ATT_DOMAIN_COMPONENT: u32 = 22; // DC
pub const ATT_POSTAL_ADDRESS: u32 = 24; //postalAddress,  55 04 10
pub const ATT_NAME: u32 = 25; //name,   55 04 29
pub const ATT_TELEPHONE_NUMBER: u32 = 26; //telephoneNumber 55 04 14
pub const ATT_DIR_MAN_DOMAIN_NAME: u32 = 27; //dmdName  55 04 36
pub const ATT_USER_ID: u32 = 28; //uid   09 92 26 89 93 F2 2C 64 01 01
pub const ATT_UNSTRUCTURED_NAME: u32 = 29; //unstructuredName   2A 86 48 86 F7 0D 01 09 02
pub const ATT_UNSTRUCTURED_ADDRESS: u32 = 30; //unstructuredAddress   2A 86 48 86 F7 0D 01 09 08 00
pub fn att_map(oid: &[u8]) -> Option<u32> {
    match oid {
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, ..] => match oid[9..] {
            [0x01] => Some(ATT_USER_ID),
            [0x19] => Some(ATT_DOMAIN_COMPONENT),
            _ => None,
        },
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, ..] => match oid[8..] {
            [0x01] => Some(ATT_EMAIL),
            [0x02] => Some(ATT_UNSTRUCTURED_NAME),
            [0x08, 0x00] => Some(ATT_UNSTRUCTURED_ADDRESS),
            _ => None,
        },
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, ..] => match oid[10..] {
            [0x01] => Some(ATT_INC_LOCALITY),
            [0x02] => Some(ATT_INC_STATE),
            [0x03] => Some(ATT_INC_COUNTRY),
            _ => None,
        },
        [0x55, 0x04, ..] => match oid[2..] {
            [0x03] => Some(ATT_COMMON_NAME),
            [0x04] => Some(ATT_SUR_NAME),
            [0x05] => Some(ATT_SERIAL_NUMBER),
            [0x06] => Some(ATT_COUNTRY),
            [0x07] => Some(ATT_LOCALITY),
            [0x08] => Some(ATT_STATE_OR_PROVINCE),
            [0x09] => Some(ATT_STREET_ADDRESS),
            [0x10] => Some(ATT_POSTAL_ADDRESS),
            [0x14] => Some(ATT_TELEPHONE_NUMBER),
            [0x0A] => Some(ATT_ORGANIZATION),
            [0x0B] => Some(ATT_ORGANIZATION_UNIT),
            [0x0C] => Some(ATT_TITLE),
            [0x0F] => Some(ATT_BUSINESS),
            [0x11] => Some(ATT_POSTAL_CODE),
            [0x29] => Some(ATT_NAME),
            [0x2A] => Some(ATT_GIVEN_NAME),
            [0x2B] => Some(ATT_INITIALS),
            [0x2C] => Some(ATT_GENERATION_QUALIFIER),
            [0x2E] => Some(ATT_DN_QUALIFIER),
            [0x36] => Some(ATT_DIR_MAN_DOMAIN_NAME),
            [0x41] => Some(ATT_PSEUDONYM),
            [0x61] => Some(ATT_ORGANIZATION_IDENTIFIER),
            _ => None,
        },
        _ => None,
    }
}