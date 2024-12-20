/******************************************************************************************************/
/******************************************************************************************************/
// Parse a DER encoded X509 and encode it as C509
fn parse_x509_cert(input: Vec<u8>) -> Cert {
    let mut output = Vec::new();
    // der Certificate
    let certificate = lder_vec_len(&input, ASN1_SEQ, 3);
    let tbs_certificate = lder_vec_len(certificate[0], ASN1_SEQ, 8);
    let version = lder(tbs_certificate[0], 0xa0);
    let serial_number = lder_uint(tbs_certificate[1]);
    let signature_algorithm = certificate[1];
    let signature = tbs_certificate[2];
    let issuer = tbs_certificate[3];
    let validity = lder_vec_len(tbs_certificate[4], ASN1_SEQ, 2);
    let not_before = validity[0];
    let not_after = validity[1];
    let subject = tbs_certificate[5];
    let subject_public_key_info = lder_vec_len(tbs_certificate[6], ASN1_SEQ, 2);
    let spki_algorithm = subject_public_key_info[0]; //TODO, update?
    let subject_public_key = lder(subject_public_key_info[1], ASN1_BIT_STR);
    let extensions = lder_vec(lder(tbs_certificate[7], 0xa3), ASN1_SEQ); //0xa3 = [3] EXPLICIT, mandatory start of ext.seq if present
    let signature_value = lder(certificate[2], ASN1_BIT_STR);
    // version
    assert!(lder(version, ASN1_INT)[0] == 2, "Expected v3!");
    output.push(lcbor_uint(C509_TYPE_X509_ENCODED as u64));
    // serial_number
    output.push(lcbor_bytes(serial_number));
    
    // signatureAlg.
    if let Some(sig_type) = sig_map(signature_algorithm) {
        output.push(lcbor_int(sig_type));
    } else {
        let oid = lder(lder_vec(signature_algorithm, ASN1_SEQ)[0], ASN1_OID);
        print_warning("No C509 int regisered for signature algorithm identifier, oid", &signature_algorithm, oid);
        output.push(cbor_alg_id(signature_algorithm));
    }
    
    // signature
    assert!(signature_algorithm == signature, "Expected signature_algorithm == signature!");
    // issuer
    output.push(cbor_name(issuer));
    // validity
    let c_not_before = cbor_time(not_before, 0);
    let c_not_after = cbor_time(not_after, 0);
    
    if c_not_after < c_not_before {
      warn!("Pre-2000 time bug, trying to circumvent");
      output.push(cbor_time(not_before, 1));
      
    } else {
      output.push(c_not_before);
    }
    output.push(c_not_after);
    // subject
    output.push(cbor_name(subject));
    // subjectPublicKeyInfo
    assert!(subject_public_key[0] == 0, "expected 0 unused bits");
    let subject_public_key = &subject_public_key[1..];
    if let Some(pk_type) = pk_map(spki_algorithm) {
        output.push(lcbor_int(pk_type));
        // Special handling for RSA
        if pk_type == PK_RSA_ENC {
            let rsa_pk = lder_vec_len(subject_public_key, ASN1_SEQ, 2);
            let n = lcbor_bytes(lder_uint(rsa_pk[0]));
            let e = lcbor_bytes(lder_uint(rsa_pk[1]));
            if e == [0x43, 0x01, 0x00, 0x01] {
                //check for exponent == 65537
                output.push(n);
            } else {
                output.push(lcbor_array(&[n, e]));
            }
        // Special handling for ECDSA
        /*
        Please note:
        For elliptic curve public keys in Weierstraß form (id-ecPublicKey), keys may be point compressed
        as defined in Section 2.3.3 of [SECG]. Native C509 certificates with Weierstraß form keys use the
        octets 0x02, 0x03, and 0x04 as defined in [SECG]. If a DER encoded certificate with a uncompressed
        public key of type id-ecPublicKey is CBOR encoded with point compression, the octets 0xfe and 0xfd
        are used instead of 0x02 and 0x03 in the CBOR encoding to represent even and odd y-coordinate,
        respectively.
        */
        } else if [PK_SECP256R, PK_SECP384R, PK_SECP521R, PK_BRAINPOOL256R1, PK_BRAINPOOL384R1, PK_BRAINPOOL512R1, PK_FRP256V1].contains(&pk_type) {
            assert!(subject_public_key.len() % 2 == 1, "Expected odd subject public key length!");
            let coord_size = (subject_public_key.len() - 1) / 2;
            let secg_byte = subject_public_key[0];
            let x = &subject_public_key[1..1 + coord_size];
            if secg_byte == SECG_UNCOMPRESSED {
                let y = &subject_public_key[1 + coord_size..];
                if y[coord_size - 1] & 1 == 0 {
                    output.push(lcbor_bytes(&[&[SECG_EVEN_COMPRESSED], x].concat()));
                } else {
                    output.push(lcbor_bytes(&[&[SECG_ODD_COMPRESSED], x].concat()));
                }
            } else if secg_byte == SECG_EVEN || secg_byte == SECG_ODD as u8 {
                output.push(lcbor_bytes(&[&[-(secg_byte as i8) as u8], x].concat()));
            } else {
                panic!("Expected SECG byte to be 2, 3, or 4!")
            }
        } else {
            output.push(lcbor_bytes(subject_public_key));
        }
    } else {
        let oid = lder(lder_vec(spki_algorithm, ASN1_SEQ)[0], ASN1_OID);
        print_warning("No C509 int registered for public key algorithm identifier, oid", &spki_algorithm, oid);
        output.push(cbor_alg_id(spki_algorithm));
        output.push(lcbor_bytes(subject_public_key));
    }
    // issuerUniqueID, subjectUniqueID -- not supported
    // extensions
    let mut vec = Vec::new();
    for e in &extensions {
        let extension = lder_vec(e, ASN1_SEQ);
        assert!(extension.len() < 4, "Expected length 2 or 3");
        let oid = lder(extension[0], ASN1_OID);
        let mut crit_sign = 1;
        if extension.len() == 3 {
            assert!(lder(extension[1], ASN1_BOOL) == [0xff], "Expected critical == true");
            crit_sign = -1;
        }
        let extn_value = lder(extension[extension.len() - 1], ASN1_OCTET_STR);
        if let Some(ext_type) = ext_map(oid) {
            //println!("Working on {}. extensions.len() = {}, crit status: {:?}", ext_type, extensions.len(), cbor_int(crit_sign * ext_type as i64));
            //Note: We need look-ahead for the keyUsage only case and surpress the crit.sign, as it will be respresented by a negative keyUsage value only
            if extensions.len() == 1 && ext_type == EXT_KEY_USAGE {
                vec.push(lcbor_int(ext_type as i64));
            } else {
                vec.push(lcbor_int(crit_sign * ext_type as i64));
            }
            vec.push(match ext_type {
                EXT_SUBJECT_KEY_ID => lcbor_bytes(lder(extn_value, ASN1_OCTET_STR)),
                EXT_KEY_USAGE => cbor_ext_key_use(extn_value, crit_sign * extensions.len() as i64),
                EXT_SUBJECT_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),
                EXT_BASIC_CONSTRAINTS => cbor_ext_bas_con(extn_value),
                EXT_CRL_DIST_POINTS => cbor_ext_crl_dist(extn_value),
                EXT_CERT_POLICIES => cbor_ext_cert_policies(extn_value),
                EXT_AUTH_KEY_ID => cbor_ext_auth_key_id(extn_value),
                EXT_EXT_KEY_USAGE => cbor_ext_eku(extn_value),
                EXT_AUTH_INFO => cbor_ext_info_access(extn_value),
                EXT_SCT_LIST => cbor_ext_sct(extn_value, not_before),
                EXT_SUBJECT_DIRECTORY_ATTR => cbor_store_only(extn_value, extension[0], oid), //cbor_ext_directory_attr(extn_value),
                EXT_ISSUER_ALT_NAME => cbor_general_names(extn_value, ASN1_SEQ, 2),           //Note: "Issuer Alternative Name (issuerAltName). extensionValue is encoded exactly like subjectAltName."
                EXT_NAME_CONSTRAINTS => cbor_store_only(extn_value, extension[0], oid),       //cbor_ext_name_constraints(extn_value),  //Sample certificates welcome
                EXT_POLICY_MAPPINGS => cbor_store_only(extn_value, extension[0], oid),        //cbor_ext_policy_mappings(extn_value),   //Sample certificates welcome
                EXT_POLICY_CONSTRAINTS => cbor_store_only(extn_value, extension[0], oid),     //cbor_ext_policy_constraints(extn_value),  //Sample certificates welcome
                EXT_FRESHEST_CRL => cbor_ext_crl_dist(extn_value),                            //Note: "Freshest CRL (freshestCRL). extensionValue is encoded exactly like cRLDistributionPoints"
                EXT_INHIBIT_ANYPOLICY => cbor_store_only(extn_value, extension[0], oid),      //cbor_ext_inhibit_anypolicy(extn_value),   //Sample certificates welcome
                EXT_SUBJECT_INFO_ACCESS => cbor_ext_info_access(extn_value),
                EXT_IP_RESOURCES => cbor_ext_ip_res(extn_value),
                EXT_AS_RESOURCES => cbor_ext_as_res(extn_value),
                EXT_IP_RESOURCES_V2 => cbor_ext_ip_res(extn_value),
                EXT_AS_RESOURCES_V2 => cbor_ext_as_res(extn_value),
                EXT_BIOMETRIC_INFO => lcbor_bytes(extn_value),            //Store only
                EXT_PRECERT_SIGNING_CERT => lcbor_bytes(extn_value),      //Store only
                EXT_OCSP_NO_CHECK => lcbor_bytes(extn_value),             //Store only
                EXT_QUALIFIED_CERT_STATEMENTS => lcbor_bytes(extn_value), //Store only
                EXT_S_MIME_CAPABILITIES => lcbor_bytes(extn_value),       //Store only
                EXT_TLS_FEATURES => lcbor_bytes(extn_value),              //Store only
                _ => panic!("Unexpected extension'"),
            });
        } else {
            print_warning("No C509 int registered for extension oid", extension[0], oid);
            vec.push(lcbor_bytes(oid));
            if crit_sign == -1 {
                vec.push(lcbor_simple(CBOR_TRUE));
            }
            vec.push(lcbor_bytes(extn_value));
        }
    }
    /*
    Optimisation: if only a keyUsage field is present, skip the array for extensions.
    This requires the minus sign of the EXT_KEY_USAGE value (2) to be surpressed above
    */
    output.push(cbor_opt_array(&vec, EXT_KEY_USAGE as u8));
    // now only signatureValue
    assert!(signature_value[0] == 0, "expected 0 unused bits");
    let signature_value = &signature_value[1..];
    if let Some(sig_type) = sig_map(signature_algorithm) {
        // Special handling for ECDSA
        if [SIG_ECDSA_SHA1, SIG_ECDSA_SHA256, SIG_ECDSA_SHA384, SIG_ECDSA_SHA512, SIG_ECDSA_SHAKE128, SIG_ECDSA_SHAKE256].contains(&sig_type) {
            output.push(cbor_ecdsa(signature_value));
        } else {
            output.push(lcbor_bytes(signature_value));
        }
    } else {
        output.push(lcbor_bytes(signature_value));
    }
    Cert { der: input, cbor: output }
}
/******************************************************************************************************/
// CBOR encode a DER encoded Name field
fn cbor_name(b: &[u8]) -> Vec<u8> {
    let name = lder_vec(b, ASN1_SEQ);
    let mut vec = Vec::new();
    for rdn in &name {
        let attributes = lder_vec_len(rdn, ASN1_SET, 1);
        for item in attributes {
            let attribute = lder_vec_len(item, ASN1_SEQ, 2);
            let oid = lder(attribute[0], ASN1_OID);
            let der_value = attribute[1];
            if let Some(att_type) = att_map(oid) {
                if att_type == ATT_EMAIL || att_type == ATT_DOMAIN_COMPONENT {
                    vec.push(lcbor_int(att_type as i64));
                    let att_value = lder(der_value, ASN1_IA5_SRT);
                    vec.push(lcbor_text(att_value));
                } else {
                    let (sign, att_value) = if der_value[0] == ASN1_PRINT_STR { (-1, lder(der_value, ASN1_PRINT_STR)) } else { (1, lder(der_value, ASN1_UTF8_STR)) };
                    vec.push(lcbor_int(sign * att_type as i64));
                    vec.push(lcbor_text(att_value));
                }
            } else {
                print_warning("No C509 int regisered for attribute oid", attribute[0], oid);
                vec.push(lcbor_bytes(oid));
                vec.push(lcbor_bytes(der_value));
            }
        }
    }
    /*
    If Name contains a single Attribute containing an utf8String encoded 'common name' it is encoded as follows:
    *If the text string has an even length {{{≥}}} 2 and contains only the symbols '0'–'9' or 'a'–'f',
     it is encoded as a CBOR byte string, prefixed with an initial byte set to '00'.
    *If the text string contains an EUI-64 of the form "HH-HH-HH-HH-HH-HH-HH-HH" where 'H' is one of
     the symbols '0'–'9' or 'A'–'F' it is encoded as a CBOR byte string prefixed with an initial byte set to
     '01', for a total length of 9. An EUI-64 mapped from a 48-bit MAC address (i.e., of the form
     "HH-HH-HH-FF-FE-HH-HH-HH) is encoded as a CBOR byte string prefixed with an initial byte set to '01',
     for a total length of 7.
    *Otherwise it is encoded as a CBOR text string.
    */
    let eui_64 = regex::Regex::new(r"^([A-F\d]{2}-){7}[A-F\d]{2}$").unwrap();
    let is_hex = regex::Regex::new(r"^(?:[A-Fa-f0-9]{2})*$").unwrap();
    if vec.len() == 2 && vec[0] == [ATT_COMMON_NAME as u8] {
        //let cn = from_utf8(&vec[0][1..]).unwrap();
        vec.remove(0);
        if eui_64.is_match(from_utf8(&vec[0][1..]).unwrap()) {
            vec[0].retain(|&x| x != b'-' && x != 0x77); // 0x77 = text string length 23
            if &vec[0][6..10] == b"FFFE" {
                vec[0].drain(6..10);
            }
            vec[0].insert(0, '1' as u8);
            vec[0].insert(0, '0' as u8);
            vec[0] = lcbor_bytes(&hex::decode(&vec[0]).unwrap());
        } else if is_hex.is_match(from_utf8(&vec[0][1..]).unwrap()) {
            vec[0][0] = '0' as u8; //overwrite the added utf8 text marker at the start
            vec[0].insert(0, '0' as u8);
            vec[0] = lcbor_bytes(&hex::decode(&vec[0]).unwrap());
        }
        return vec[0].clone();
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encode a DER encoded Time field (ruturns ~biguint)
fn cbor_time(b: &[u8], pre_y2k_flag: u8) -> Vec<u8> {
  
    let time_string = if pre_y2k_flag == 1 {
        if b[0] == ASN1_UTC_TIME as u8 { [b"19", lder(b, ASN1_UTC_TIME)].concat() } else { lder(b, ASN1_GEN_TIME).to_vec() }
    } else { //the normal case 
        if b[0] == ASN1_UTC_TIME as u8 { [b"20", lder(b, ASN1_UTC_TIME)].concat() } else { lder(b, ASN1_GEN_TIME).to_vec() }
    };
    
    let time_string = from_utf8(&time_string).unwrap();
    match time_string {
        ASN1_GEN_TIME_MAX => lcbor_simple(CBOR_NULL),
        _ => { let dummy = lcbor_uint(chrono::NaiveDateTime::parse_from_str(time_string, "%Y%m%d%H%M%SZ").unwrap().timestamp() as u64);
              trace!("time_string, res time: {:?}, {:?}", time_string, dummy);
              dummy
            },
    }
}
// CBOR encode a DER encoded Algorithm Identifier
fn cbor_alg_id(b: &[u8]) -> Vec<u8> {
    let ai = lder_vec(b, ASN1_SEQ);
    assert!(ai.len() < 3, "Expected length 1 or 2");
    let oid = lcbor_bytes(lder(ai[0], ASN1_OID));
    if ai.len() == 1 {
        oid
    } else {
        let par = lcbor_bytes(ai[1]);
        lcbor_array(&[oid, par])
    }
}
// CBOR encodes a DER encoded ECDSA signature value
fn cbor_ecdsa(b: &[u8]) -> Vec<u8> {
    let signature_seq = lder_vec(b, ASN1_SEQ);
    let r = lder_uint(signature_seq[0]).to_vec();
    let s = lder_uint(signature_seq[1]).to_vec();
    let max = std::cmp::max(r.len(), s.len());
    lcbor_bytes(&[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat())
}
fn cbor_opt_array(vec: &[Vec<u8>], t: u8) -> Vec<u8> {
    if vec.len() == 2 && vec[0] == [t] {
        vec[1].clone()
    } else {
        lcbor_array(&vec)
    }
}
/******************************************************************************************************/
/*
Below is a list of encoding functions for the supported extensions listed in C509 Extensions Registry
*/
/*
  Placeholder function to store the raw extension value as bytes
*/
fn cbor_store_only(b: &[u8], v: &[u8], oid: &[u8]) -> Vec<u8> {
    print_warning("Warning, currently storing raw data for extension with oid", v, oid);
    lcbor_bytes(b)
}
/*
CBOR encode GeneralNames
Used for and in:
EXT_SUBJECT_ALT_NAME
Authority Key Identifier extension
Note: no wrapping array if content is a single name of type opt
*/
fn cbor_general_names(b: &[u8], t: u8, opt: u8) -> Vec<u8> {
    let unwrap = opt;
    let names = lder_vec(b, t);
    let mut vec = Vec::new();
    for name in names {
        //println!("handling name: {:02x?}", name);
        let value = lder(name, name[0]);
        let context_tag = name[0] as u64 & 0x0f;
        //println!("Storing context tag: {}", context_tag); //debug
        //ongoing: special handling of otherName:
        if context_tag == 0 {
            let inner_value = &value[12..]; //TODO, check handling of long values
            match value {
                [0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x08, ..] => match value[9] {
                    0x0B => {
                        vec.push(lcbor_int(-3));
                        vec.push(lcbor_bytes(inner_value));
                    }
                    0x09 => {
                        vec.push(lcbor_int(-2));
                        vec.push(cbor_other_name_mail(inner_value));
                    }
                    0x04 => {
                        vec.push(lcbor_int(-1));
                        vec.push(cbor_other_name_hw(inner_value));
                    }
                    _ => {
                        vec.push(lcbor_int(0));
                        vec.push(cbor_other_name(value))
                    } //resort to generic otherName encoding, [ ~oid, bytes ]
                },
                _ => {
                    vec.push(lcbor_int(0));
                    vec.push(cbor_other_name(value))
                } //same as above
            }
        } else {
            vec.push(lcbor_uint(context_tag));
            vec.push(match context_tag {
                1 => lcbor_text(value),  // rfc822Name
                2 => lcbor_text(value),  // dNSName
                4 => cbor_name(value),   // Name (TODO a4?)
                6 => lcbor_text(value),  // uniformResourceIdentifier
                7 => lcbor_bytes(value), // iPAddress
                8 => lcbor_bytes(value), // registeredID : should be stored as ~oid
                _ => panic!("Unknown general name"),
            })
        }
    }
    cbor_opt_array(&vec, unwrap)
}
/******************************************************************************************************/
/*
CBOR encoding of the general otherName format
ASN.1 input description
-- AnotherName replaces OTHER-NAME ::= TYPE-IDENTIFIER, as
-- TYPE-IDENTIFIER is not supported in the '88 ASN.1 syntax
 AnotherName ::= SEQUENCE {
 type-id  OBJECT IDENTIFIER,
 value  [0] EXPLICIT ANY DEFINED BY type-id }
CDDL
[ ~oid, bytes ]
*/
fn cbor_other_name(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let (oid_raw, rest) = lder_split(b, false);
    let oid = lder(oid_raw, ASN1_OID);
    let raw_value = lder(rest, ASN1_INDEX_ZERO);
    //let (choice, value_raw) = der_split(rest, false);
    //Since the raw value can be of any type, we just store it as a byte string without parsing
    vec.push(lcbor_bytes(oid));
    vec.push(lcbor_bytes(raw_value));
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
Notes on the OtherNames with special encodings:
***********************************
otherName with BundleEID
 ASN.1
ID: -3
1.3.6.1.5.5.7.8.11
06 08 2B 06 01 05 05 07 08 0B
Value: eid-structure from RFC 9171
https://www.rfc-editor.org/rfc/rfc9171.html
 Each BP endpoint ID (EID) SHALL be represented as a CBOR array comprising two items.
The first item of the array SHALL be the code number identifying the endpoint ID's URI scheme,
as defined in the registry of URI scheme code numbers for the Bundle Protocol. Each URI scheme
code number SHALL be represented as a CBOR unsigned integer.
The second item of the array SHALL be the applicable CBOR encoding of the scheme-specific part
of the EID, defined as noted in the references(s) for the URI scheme code number registry entry
for the EID's URI scheme.
eid-structure = [
uri-code: uint,
SSP: any
]
SSP: [
nodenum: uint,
servicenum: uint
]
https://www.rfc-editor.org/rfc/rfc9174.html
 This non-normative example demonstrates an otherName with a name form of
BundleEID to encode the node ID "dtn://example/".
The hexadecimal form of the DER encoding of the otherName is as follows:
a01c06082b0601050507080ba010160e64746e3a2f2f6578616d706c652f
And the text decoding in Figure 28 is an output of Peter Gutmann's "dumpasn1" program.
0  28: [0] {
2   8:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 8 11'
12  16:   [0] {
14  14:   IA5String 'dtn://example/'
   :   }
   :   }
*/
fn _cbor_other_name_bundle(b: &[u8]) -> Vec<u8> {
    /*
    TODO: agree on a possibly more fine grained parsing of the structure contained in the value.
    For now just store the content as a byte string
    let mut vec = Vec::new();
    let mut value;
    match b[0] {
     ASN1_IA5_SRT => { value = der(b, ASN1_IA5_SRT)
     },
     ASN1_UTF8_STR => { value = der(b, ASN1_UTF8_STR)
     },
     _ => panic!("Unknown general value type"),
    }
    */
    let mut vec = Vec::new();
    vec.push(lcbor_bytes(b));
    lcbor_array(&vec)
}
/*
otherName with SmtpUTF8Mailbox
ID -2
1.3.6.1.5.5.7.8.9
06 08 2B 06 01 05 05 07 08 09
https://www.rfc-editor.org/rfc/rfc8398.html
SmtpUTF8Mailbox ::= UTF8String (SIZE (1..MAX))
This non-normative example demonstrates using SmtpUTF8Mailbox as an
otherName in GeneralName to encode the email address
"u+8001u+5E2B@example.com".
The hexadecimal DER encoding of the email address is:
A022060A 2B060105 05070012 0809A014 0C12E880 81E5B8AB 40657861
6D706C65 2E636F6D
The text decoding is:
  0  34: [0] {
  2  10:   OBJECT IDENTIFIER '1 3 6 1 5 5 7 0 18 8 9'
 14  20:   [0] {
 16  18:   UTF8String '..@example.com'
   :   }
   :   }
*WARNING* the OID in this example does not match the OID found in OID databases
*/
fn cbor_other_name_mail(b: &[u8]) -> Vec<u8> {
    // let mut vec = Vec::new();
    let value;
    value = lder(b, ASN1_UTF8_STR);
    lcbor_text(value)
    //cbor_array(&vec)
}
/*
otherName with hardwareModuleName
 Note: this is used in the DevID certificates
 ASN.1
 ID: -1
1.3.6.1.5.5.7.8.4
06 08 2B 06 01 05 05 07 08 04
Value: [ ~oid, bytes ]
https://www.rfc-editor.org/rfc/rfc4108.html
A HardwareModuleName is composed of an object identifier and an octet string:
HardwareModuleName ::= SEQUENCE {
hwType OBJECT IDENTIFIER,
hwSerialNum OCTET STRING }
*/
fn cbor_other_name_hw(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let another_name_vec = lder_vec(b, ASN1_SEQ);
    let type_id = lder(another_name_vec[0], ASN1_OID);
    let value = lder(another_name_vec[1], ASN1_OCTET_STR);
    vec.push(lcbor_bytes(type_id));
    vec.push(lcbor_bytes(value));
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encodes a Autonomous System Identifier extension
ASN.1 input
 id-pe-autonomousSysIds  OBJECT IDENTIFIER ::= { id-pe 8 }
ASIdentifiers   ::= SEQUENCE
{
asnum   [0] EXPLICIT ASIdentifierChoice OPTIONAL,
rdi   [1] EXPLICIT ASIdentifierChoice OPTIONAL
}
ASIdentifierChoice  ::= CHOICE
{
inherit   NULL, -- inherit from issuer --
asIdsOrRanges   SEQUENCE OF ASIdOrRange
}
ASIdOrRange   ::= CHOICE {
id  ASId,
range   ASRange
}
ASRange   ::= SEQUENCE {
min   ASId,
max   ASId
}
ASId  ::= INTEGER
-- see https://www.rfc-editor.org/rfc/rfc3779.html
   CDDL
 AsIdsOrRanges = uint / [uint, uint]
ASIdentifiers = [ + AsIdsOrRanges ] / null
 NOTE
If rdi is not present, the extension value can be CBOR encoded.
Each ASId is encoded as an uint. With the exception of the first
ASId, the ASid is encoded as the difference to the previous ASid.
*/
fn cbor_ext_as_res(b: &[u8]) -> Vec<u8> {
    let as_identifiers = lder(b, ASN1_SEQ);
    let asnum = lder(as_identifiers, ASN1_INDEX_ZERO);
    let mut vec = Vec::new();
    let mut last = 0u64;
    if asnum == [0x05, 0x00] {
        return lcbor_simple(CBOR_NULL);
    }
    for elem in lder_vec(asnum, ASN1_SEQ) {
        if elem[0] == ASN1_INT {
            let asid = be_bytes_to_u64(lder_uint(elem));
            vec.push(lcbor_uint(asid - last));
            last = asid;
        } else if elem[0] == ASN1_SEQ {
            let mut range = Vec::new();
            for elem2 in lder_vec_len(elem, ASN1_SEQ, 2) {
                let asid = be_bytes_to_u64(lder_uint(elem2));
                range.push(lcbor_uint(asid - last));
                last = asid;
            }
            vec.push(lcbor_array(&range));
        } else {
            panic!("Expected INT or SEQ");
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encodes a Authority Key Identifier extension
Description:
Authority Key Identifier (authorityKeyIdentifier). If the authority key identifier
contains all of keyIdentifier, certIssuer, and certSerialNumberm or if only keyIdentifier
is present the extension value can be CBOR encoded. If all three are present a CBOR array
is used, if only keyIdentifier is present, the array is omitted
CDDL
KeyIdentifierArray = [
 keyIdentifier: KeyIdentifier / null,
 authorityCertIssuer: GeneralNames,
 authorityCertSerialNumber: CertificateSerialNumber
]
AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier
*/
fn cbor_ext_auth_key_id(b: &[u8]) -> Vec<u8> {
    let aki = lder_vec(b, ASN1_SEQ);
    let ki = lcbor_bytes(lder(aki[0], 0x80));
    match aki.len() {
        1 => ki,
        3 => lcbor_array(&[ki, cbor_general_names(aki[1], 0xa1, 0xff), lcbor_bytes(lder(aki[2], 0x82))]),
        _ => panic!("Error parsing auth key id"),
    }
}
/******************************************************************************************************/
/*
CBOR encode a Basic Constraints extension
Description
Basic Constraints (basicConstraints). If 'cA' = false then extensionValue = -2, if 'cA' = true and
'pathLenConstraint' is not present then extensionValue = -1, and if 'cA' = true and 'pathLenConstraint'
is present then extensionValue = pathLenConstraint.
CDDL
 BasicConstraints = int
*/
fn cbor_ext_bas_con(b: &[u8]) -> Vec<u8> {
    let bc = lder_vec(b, ASN1_SEQ);
    //println!("match bc.len(): {}", bc.len());
    match bc.len() {
        0 => lcbor_int(-2),
        1 => {
            assert!(lder(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
            lcbor_int(-1)
        }
        2 => {
            assert!(lder(bc[0], ASN1_BOOL) == [0xff], "Expected cA == true");
            let path_len = lder_uint(bc[1]);
            assert!(path_len.len() == 1, "Expected path length < 256");
            lcbor_uint(path_len[0] as u64)
        }
        _ => panic!("Error parsing basic constraints"),
    }
}
/******************************************************************************************************/
/*
CBOR encodes a Certificate Policies extension
ASN.1 input
CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
PolicyInformation ::= SEQUENCE {
policyIdentifier   CertPolicyId,
policyQualifiers   SEQUENCE SIZE (1..MAX) OF
  PolicyQualifierInfo OPTIONAL }
CertPolicyId ::= OBJECT IDENTIFIER
CERT-POLICY-QUALIFIER ::= TYPE-IDENTIFIER
PolicyQualifierInfo ::= SEQUENCE {
  policyQualifierId  CERT-POLICY-QUALIFIER.
  &id({PolicyQualifierId}),
  qualifier   CERT-POLICY-QUALIFIER.
  &Type({PolicyQualifierId}{@policyQualifierId})}
PolicyQualifierId CERT-POLICY-QUALIFIER ::=
{ pqid-cps | pqid-unotice, ... }
 CDDL
 PolicyIdentifier = int / ~oid
PolicyQualifierInfo = (
policyQualifierId: int / ~oid,
qualifier: text,
)
CertificatePolicies = [
+ ( PolicyIdentifier, ? [ + PolicyQualifierInfo ] )
]
 NOTE
If noticeRef is not used and any explicitText are encoded as UTF8String, the extension value can be CBOR encoded.
OIDs registered in C509 are encoded as an int. The policyQualifierId is encoded as an CBOR int or an unwrapped
CBOR OID tag (RFC9090).
*/
fn cbor_ext_cert_policies(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for pi in lder_vec(b, ASN1_SEQ) {
        let pi = lder_vec(pi, ASN1_SEQ);
        assert!(pi.len() == 1 || pi.len() == 2, "expected length 1 or 2");
        let oid = lder(pi[0], ASN1_OID);
        if let Some(cp_type) = cp_map(oid) {
            vec.push(lcbor_int(cp_type));
        } else {
            print_warning("No C509 int registered for Certificate Policy OID", pi[0], oid);
            vec.push(lcbor_bytes(oid));
        }
        if pi.len() == 2 {
            let mut vec2 = Vec::new();
            for pqi in lder_vec(pi[1], ASN1_SEQ) {
                let pqi = lder_vec_len(pqi, ASN1_SEQ, 2);
                let oid = lder(pqi[0], ASN1_OID);
                if let Some(pq_type) = pq_map(oid) {
                    vec2.push(lcbor_int(pq_type));
                    if pq_type == PQ_CPS {
                        let text = lder(pqi[1], ASN1_IA5_SRT);
                        trace!("cbor_ext_cert_policies, encoded text {:02x?}", text);
                        vec2.push(lcbor_text(text));
                    } else if pq_type == PQ_UNOTICE {
                        let text = lder(lder(pqi[1], ASN1_SEQ), ASN1_UTF8_STR);
                        vec2.push(lcbor_text(text));
                    } else {
                        panic!("unexpected qualifier oid");
                    }
                } else {
                    print_warning("No C509 int registered for Policy Qualifier OID", pqi[0], oid);
                    vec2.push(lcbor_bytes(oid));
                }
            }
            vec.push(lcbor_array(&vec2));
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/**
CBOR encodes a CRL distribution list extension
CDDL
DistributionPointName = [ 2* text ] / text
CRLDistributionPoints = [ + DistributionPointName ]
 NOTE
CRL Distribution Points (cRLDistributionPoints). If the CRL Distribution Points is a sequence of
DistributionPointName, where each DistributionPointName only contains uniformResourceIdentifiers,
the extension value can be CBOR encoded. extensionValue is encoded as follows:
*/
fn cbor_ext_crl_dist(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for dists in lder_vec(b, ASN1_SEQ) {
        let dists = lder(dists, ASN1_SEQ);
        let dists = lder(dists, 0xa0);
        let mut vec2 = Vec::new();
        for dist in lder_vec(dists, 0xa0) {
            vec2.push(lcbor_text(lder(dist, 0x86)));
        }
        if vec2.len() > 1 {
            vec.push(lcbor_array(&vec2))
        } else {
            vec.push(vec2[0].clone())
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encodes a extended key usage extension
fn cbor_ext_eku(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for eku in lder_vec(b, ASN1_SEQ) {
        let oid = lder(eku, ASN1_OID);
        if let Some(eku_type) = eku_map(oid) {
            vec.push(lcbor_uint(eku_type));
        } else {
            print_warning("No C509 int registered for EKU OID", eku, oid);
            vec.push(lcbor_bytes(oid));
        }
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
// CBOR encodes a authority/subject Info Access extension
fn cbor_ext_info_access(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    for access_desc in lder_vec(b, ASN1_SEQ) {
        let access_desc = lder_vec_len(access_desc, ASN1_SEQ, 2);
        let oid = lder(access_desc[0], ASN1_OID);
        let access_location = lcbor_text(lder(access_desc[1], 0x86));
        if let Some(access_type) = info_map(oid) {
            vec.push(lcbor_int(access_type));
        } else {
            print_warning("No C509 int registered for Info Access OID", access_desc[0], oid);
            vec.push(lcbor_bytes(oid));
        }
        vec.push(access_location);
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/******************************************************************************************************/
// CBOR encodes a Range of IP Addresses
fn cbor_ext_ip_res(b: &[u8]) -> Vec<u8> {
    let mut vec = Vec::new();
    let mut last = Vec::new();
    for block in lder_vec(b, ASN1_SEQ) {
        let family = lder_vec_len(block, ASN1_SEQ, 2);
        let afi = lder(family[0], ASN1_OCTET_STR);
        assert!(afi.len() == 2, "expected afi and no safi");
        vec.push(lcbor_uint(be_bytes_to_u64(afi)));
        // NULL
        let mut fam = Vec::new();
        for aor in lder_vec(family[1], ASN1_SEQ) {
            if aor[0] == ASN1_BIT_STR {
                let ip = lder(aor, ASN1_BIT_STR);
                let unused_bits = ip[0];
                let ip_bytes = &ip[1..];
                if ip_bytes.len() == last.len() {
                    let diff = be_bytes_to_u64(ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                    fam.push(lcbor_int(diff));
                } else {
                    fam.push(lcbor_bytes(&ip_bytes));
                }
                last = ip_bytes.to_vec();
                fam.push(lcbor_uint(unused_bits as u64));
            } else if aor[0] == ASN1_SEQ {
                let mut range = Vec::new();
                let range_der = lder_vec_len(aor, ASN1_SEQ, 2);
                let ip = lder(range_der[0], ASN1_BIT_STR);
                let ip_bytes = &ip[1..];
                if ip_bytes.len() == last.len() {
                    let diff = be_bytes_to_u64(ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                    range.push(lcbor_int(diff));
                } else {
                    range.push(lcbor_bytes(&ip_bytes));
                }
                last = ip_bytes.to_vec();
                let ip = lder(range_der[1], ASN1_BIT_STR);
                let unused_bits = ip[0];
                let mut ip_bytes = ip[1..].to_vec();
                let l = ip_bytes.len();
                ip_bytes[l - 1] |= (2u16.pow(unused_bits as u32) - 1) as u8;
                if ip_bytes.len() == last.len() {
                    let diff = be_bytes_to_u64(&ip_bytes) as i64 - be_bytes_to_u64(&last) as i64;
                    range.push(lcbor_int(diff));
                } else {
                    range.push(lcbor_bytes(&ip_bytes));
                }
                last = ip_bytes.to_vec();
                fam.push(lcbor_array(&range));
            } else {
                panic!("Expected INT or SEQ");
            }
        }
        vec.push(lcbor_array(&fam));
    }
    lcbor_array(&vec)
}
/******************************************************************************************************/
/*
CBOR encode EXT_KEY_USAGE - 2 - Key Usage Extension
*/
fn cbor_ext_key_use(bs: &[u8], signed_nr_ext: i64) -> Vec<u8> {
    assert!(bs[0] == ASN1_BIT_STR, "Expected 0x03");
    let len = bs[1];
    assert!((2..4).contains(&len), "Expected key usage ASN.1 field len to be 2 or 3 bytes");
    //Note: at encoding time we don't need to handle bs[2] / the number of free bytes
    let v = bs[3].swap_bits();
    if len == 3 {
        assert!(bs[4] == 128, "Error in KeyUsage bitstring, more than 9 bits used");
        let w = (v as u64) + 256;
        if signed_nr_ext == -1 {
            return lcbor_int(-(w as i64));
        }
        return lcbor_uint(w as u64);
    }
    if signed_nr_ext == -1 {
        return lcbor_int(-(v as i64));
    }
    lcbor_uint(v as u64)
}
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// CBOR encodes a SCT extention
// https://letsencrypt.org/2018/04/04/sct-encoding.html
// refactor signature calculation
fn cbor_ext_sct(b: &[u8], not_before: &[u8]) -> Vec<u8> {
    let mut temp = &lder(b, ASN1_OCTET_STR)[2..];
    let mut scts = Vec::new();
    while !temp.is_empty() {
        let end = ((temp[0] as usize) << 8) + (temp[1] as usize);
        let (value, temp2) = (&temp[2..2 + end], &temp[2 + end..]);
        scts.push(value);
        temp = temp2;
    }
    let mut vec = Vec::new();
    for sct in scts {
        assert!(sct[0] == 0, "expected SCT version 1");
        vec.push(lcbor_bytes(&sct[1..33]));
        let ts = be_bytes_to_u64(&sct[33..41]) as i64;
        let not_before_ms = 1000 * be_bytes_to_u64(&cbor_time(not_before, 0)[1..]) as i64;
        vec.push(lcbor_int(ts - not_before_ms));
        assert!(sct[41..43] == [0, 0], "expected no SCT extentsions");
        assert!(sct[43..45] == [4, 3], "expected SCT SHA-256 ECDSA");
        vec.push(lcbor_int(SIG_ECDSA_SHA256 as i64));

        let signature_seq = lder_vec(&sct[47..], ASN1_SEQ);
        trace!("ENCODING EXT_SCT_LIST TO CBOR: working with signature_seq of len {}: {:02x?}", signature_seq.len(), signature_seq);
        let r = lder_uint(signature_seq[0]).to_vec();
        let s = lder_uint(signature_seq[1]).to_vec();
        let max = std::cmp::max(r.len(), s.len());
        let signature_ecdsa = &[vec![0; max - r.len()], r, vec![0; max - s.len()], s].concat();
        trace!("ENCODING EXT_SCT_LIST TO CBOR: pushing signature of len {}: {:02x?}", signature_ecdsa.len(), signature_ecdsa);
        vec.push(lcbor_bytes(signature_ecdsa));
    }
    lcbor_array(&vec)
}
/*
Above is the list of encoding functions for the supported extensions listed in C509 Extensions Registry
*/
/******************************************************************************************************/
/******************************************************************************************************/

pub mod lcbor {
    // CBOR encodes an unsigned interger
    pub fn lcbor_uint(u: u64) -> Vec<u8> {
        lcbor_type_arg(0, u)
    }
    // CBOR encodes an signed integer
    pub fn lcbor_int(i: i64) -> Vec<u8> {
        if i < 0 {
            lcbor_type_arg(1, -i as u64 - 1)
        } else {
            lcbor_uint(i as u64)
        }
    }
    // CBOR encodes a byte string
    pub fn lcbor_bytes(b: &[u8]) -> Vec<u8> {
        [&lcbor_type_arg(2, b.len() as u64), b].concat()
    }
    // CBOR encodes a text string
    pub fn lcbor_text(b: &[u8]) -> Vec<u8> {
        let s = std::str::from_utf8(b).unwrap(); // check that this is valid utf8
        [&lcbor_type_arg(3, s.len() as u64), s.as_bytes()].concat()
    }
    // CBOR encodes an array
    pub fn lcbor_array(v: &[Vec<u8>]) -> Vec<u8> {
        [lcbor_type_arg(4, v.len() as u64), v.concat()].concat()
    }
    pub const CBOR_FALSE: u8 = 20;
    pub const CBOR_TRUE: u8 = 21;
    pub const CBOR_NULL: u8 = 22;
    // CBOR encodes a simple value
    pub fn lcbor_simple(u: u8) -> Vec<u8> {
        lcbor_type_arg(7, u as u64)
    }
    // Internal CBOR encoding helper funtion
    fn lcbor_type_arg(t: u8, u: u64) -> Vec<u8> {
        let mut vec = vec![t << 5];
        if u < 24 {
            vec[0] |= u as u8;
        } else if u < u8::MAX as u64 {
            vec[0] |= 24;
            vec.extend(&(u as u8).to_be_bytes());
        } else if u < u16::MAX as u64 {
            vec[0] |= 25;
            vec.extend(&(u as u16).to_be_bytes());
        } else if u < u32::MAX as u64 {
            vec[0] |= 26;
            vec.extend(&(u as u32).to_be_bytes());
        } else {
            vec[0] |= 27;
            vec.extend(&u.to_be_bytes());
        }
        vec
    }
}