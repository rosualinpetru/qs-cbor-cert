pub const PQ_CPS: i64 = 1;
pub const PQ_UNOTICE: i64 = 2;
pub fn pq_map(oid: &[u8]) -> Option<i64> {
    match oid {
        [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, ..] => match oid[7..] {
            [0x01] => Some(PQ_CPS),
            [0x02] => Some(PQ_UNOTICE),
            _ => None,
        },
        _ => None,
    }
}