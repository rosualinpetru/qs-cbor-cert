
pub const SECG_EVEN: u8 = 0x02;
pub const SECG_ODD: u8 = 0x03;
pub const SECG_UNCOMPRESSED: u8 = 0x04;
pub const SECG_EVEN_COMPRESSED: u8 = 0xfe;
pub const SECG_ODD_COMPRESSED: u8 = 0xfd;
pub const C509_TYPE_NATIVE: u8 = 0x02; 
pub const C509_TYPE_X509_ENCODED: u8 = 0x03; 



/******************************************************************************************************/
/******************************************************************************************************/
/******************************************************************************************************/
// Parse a HEX encoded C509 and encode it as X.509
fn parse_c509_cert(input: Vec<u8>, is_str: bool) -> Cert {
    let bytes = {
        if is_str == true {
            match hex::decode(input) {
                Ok(b) => {
                    debug!("Decoded bytes: {:x?}", b);
                    b
                }
                Err(err) => {
                    eprintln!("Error decoding hex string: {}", err);
                    Vec::new()
                }
            }
        } else {
            input
        }
    };
    //let input = raw_input.insert(0, 0x8b);
    let empty_vec: Vec<Value> = Vec::new();
    let x509_certificate: Vec<u8>;
    let mut certificate_vec: Vec<Vec<u8>> = Vec::new();
    let mut tbs_cert_vec: Vec<Vec<u8>> = Vec::new();
    let dummy: Vec<Vec<u8>> = Vec::new();

    let cursor = Cursor::new(bytes);
    match serde_cbor::de::from_reader(cursor) {
        Ok(value) => {
            if let Value::Array(elements) = value {
                debug!("CBOR array contains {} elements", elements.len());
                //We expect the elements to follow the order given by the C509 CDDL format
                //The first value should be an integer, representing the type/version
                trace!("Element: {:?}", elements[0]);
                match elements[0] {
                    Value::Integer(version) => {
                        debug!("Type with CBOR integer value: {}", version); // {}", i);
                        if version != C509_TYPE_X509_ENCODED as i128 {
                            panic!("The version value can only handle certs of type {}", C509_TYPE_X509_ENCODED);
                        }
                        tbs_cert_vec.push(ASN1_X509_VERSION_3.to_vec());
                    }
                    _ => {
                        panic!("The version value is not an integer.");
                    }
                }
                //The second value should be a byte array, representing the serialNumber
                let serial_number = match &elements[1] {
                    Value::Bytes(b) => b,
                    _ => {
                        panic!("The value of the serial number is not a byte array.");
                    }
                };

                let bytes = &&(**serial_number); //TODO: reformat, eventually
                let parsed_serial_number = lder_to_pos_int(bytes.to_vec());
                debug!("Done parsing serial number;\n{:02x?}", parsed_serial_number);
                //std::process::exit(0);
                tbs_cert_vec.push(parsed_serial_number);

                //Please note that in the reconstructed X.509 the third element is the "signature AlgorithmIdentifier"
                let (sig_alg, sig_val) = parse_cbor_sig_info(&elements[2], &elements[10]);
                debug!("Done parsing sig_alg & sig_val: {:02x?}", sig_val);
                tbs_cert_vec.push(sig_alg.clone());

                //The fourth value in the cbor array should be the issuer
                let issuer = parse_cbor_name(&elements[3], &empty_vec);
                debug!("Done parsing issuer;\n{:02x?}", issuer);
                tbs_cert_vec.push(issuer);

                //The fifth and sixth values should be the val.period
                let (not_before, not_before_int) = parse_cbor_time(&elements[4]);
                let validity: Vec<u8> = lder_to_two_seq(not_before, parse_cbor_time(&elements[5]).0);
                debug!("Done parsing validity time:\n{:02x?}", validity);
                tbs_cert_vec.push(validity);

                //The seventh value should be the cbor encoded subject
                let subject = parse_cbor_name(&elements[6], &empty_vec);
                debug!("Done parsing subject: {:02x?}", subject);
                tbs_cert_vec.push(subject);

                //The eighth value should be the subjectPublicKeyAlgorithm -- which in the reconstructed X.509 is combined inside the subjectPublicKeyInfo
                let (subject_pka, subject_pka_oid) = map_pk_id_to_oid(&elements[7]);
                let spka = lder_to_generic(subject_pka_oid, ASN1_SEQ);
                debug!("Done parsing subject_pka:\n{:02x?}", spka);
                //The ninth value should be the subjectPublicKey
                let subject_pub_key_info = parse_cbor_pub_key(&elements[8], subject_pka.unwrap());
                debug!("Done parsing subject_pub_key_info: {:02x?}", subject_pub_key_info);
                tbs_cert_vec.push(subject_pub_key_info);

                //issuerUniqueID + subjectUniqueID. -- Not supported in current draft
                //The tenth value should be the extension / ext.array
                let extensions = parse_cbor_extensions(&elements[9], not_before_int);
                trace!("Done parsing extensions: {:02x?}", extensions);

                tbs_cert_vec.push(extensions);

                let ccopy = lder_to_seq(tbs_cert_vec);

                certificate_vec.push(ccopy);
                //time to add the sign.algorithm - again, but this time to the outer asn1.seq
                certificate_vec.push(sig_alg);
                //... and the actual reconstructed signature
                certificate_vec.push(sig_val);

            /*
            What to reverse for issuerSignatureValue:
            Encoding of issuerSignatureValue
            If the two INTEGER value fields have different lengths, the shorter INTEGER value field is padded with
            zeroes so that the two fields have the same length. The resulting byte string is encoded as a CBOR byte string.
            For ECDSA signatures, the SEQUENCE and INTEGER type and length fields as well as the any leading 0x00 byte
            (to indicate that the number is not negative) are omitted. If the two INTEGER value fields have different
            lengths, the shorter INTEGER value field is padded with zeroes so that the two fields have the same length.
            The resulting byte string is encoded as a CBOR byte string.
            */
            } else {
                panic!("The value is not a CBOR array.");
            }
        }
        Err(err) => {
            eprintln!("Error decoding CBOR data: {}", err);
        }
    }
    x509_certificate = lder_to_seq(certificate_vec);
    info!("Done reconstructing X.509! Size is {}", x509_certificate.len());

    Cert { der: x509_certificate, cbor: dummy }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//Comment, the OID-parsing could happen anywhere
pub fn map_pk_id_to_oid(input: &Value) -> (Option<i64>, Vec<u8>) {
    trace!("map_pk_id_to_oid, parsing {:?}", input);
    //  Some(42)
    match input {
        Value::Integer(alg_id) => match *alg_id as i64 {
            PK_RSA_ENC => (Some(PK_RSA_ENC), lder_to_generic(PK_RSA_ENC_OID.as_bytes().to_vec(), ASN1_OID).clone()),
            PK_SECP256R => (Some(PK_SECP256R), lder_to_generic(PK_SECP256R_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_SECP384R => (Some(PK_SECP384R), lder_to_generic(PK_SECP384R_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_SECP521R => (Some(PK_SECP521R), lder_to_generic(PK_SECP521R_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_X25519 => (Some(PK_X25519), lder_to_generic(PK_X25519_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_X448 => (Some(PK_X448), lder_to_generic(PK_X448_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_ED25519 => (Some(PK_ED25519), lder_to_generic(PK_ED25519_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_ED448 => (Some(PK_ED448), lder_to_generic(PK_ED448_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_HSS_LMS => (Some(PK_HSS_LMS), lder_to_generic(PK_HSS_LMS_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_XMSS => (Some(PK_XMSS), lder_to_generic(PK_XMSS_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_XMSS_MT => (Some(PK_XMSS_MT), lder_to_generic(PK_XMSS_MT_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_BRAINPOOL256R1 => (Some(PK_BRAINPOOL256R1), lder_to_generic(PK_BRAINPOOL256R1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_BRAINPOOL384R1 => (Some(PK_BRAINPOOL384R1), lder_to_generic(PK_BRAINPOOL384R1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_BRAINPOOL512R1 => (Some(PK_BRAINPOOL512R1), lder_to_generic(PK_BRAINPOOL512R1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_FRP256V1 => (Some(PK_FRP256V1), lder_to_generic(PK_FRP256V1_OID.as_bytes().to_vec(), ASN1_OID)),
            PK_SM2P256V1 => (Some(PK_SM2P256V1), lder_to_generic(PK_SM2P256V1_OID.as_bytes().to_vec(), ASN1_OID)),
            _ => panic!("Unknown pk type: {}", alg_id),
        },
        _ => panic!("Could not parse pk type"),
    }
    //(None, Vec::new())
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
static EUI_64_CHUNK: &str = "-FF-FE";
fn parse_cbor_eui64(cn: &[u8]) -> Vec<u8> {
    trace!("parse_cbor_eui64, input: {:x?}", cn);
    let mut my_string: String = String::from("");
    for i in 0..cn.len() {
        my_string.push_str(&format!("{:02X}", cn[i]));
        if i == 2 && cn.len() == 6 {
            my_string.push_str(EUI_64_CHUNK);
        }
        if i < cn.len() - 1 {
            my_string.push('-');
        }
    }
    debug!("parse_cbor_eui64: {:x?}", my_string);
    my_string.into_bytes()
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_name<'a>(input: &'a Value, _empty_vec: &'a Vec<Value>) -> Vec<u8> {
    trace!("parse_cbor_name, incoming value: {:x?}", input);
    let mut result_vec = Vec::new();

    match input {
        Value::Text(name) => {
            trace!("CBOR name: {:x?}", name);
            let cn = name.as_bytes();

            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(cn.to_vec(), ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Bytes(b) => {
            trace!("CBOR bytes: {:x?}", b);
            let cn = match b[0] {
                0x00 => parse_cbor_eui64(&b[1..b.len()]),
                0x01 => parse_cbor_eui64(&b[1..b.len()]),
                _ => panic!("Unknown Name format'"),
            };
            let attr_type_and_val = lder_to_two_seq(ATT_COMMON_NAME_OID.to_der_vec().unwrap(), lder_to_generic(cn, ASN1_UTF8_STR));
            result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
        }
        Value::Array(name_elements) => {
            for i in (0..name_elements.len()).step_by(2) {
                let attr_type_and_val = match name_elements[i] {
                    Value::Integer(attribute) => {
                        trace!("parse_cbor_name, CBOR int: {}", attribute);
                        let (oid, tag) = match attribute.abs() as u32 {
                            ATT_EMAIL => (ATT_EMAIL_OID, ASN1_IA5_SRT),
                            ATT_COMMON_NAME => (ATT_COMMON_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_SUR_NAME => (ATT_SUR_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_SERIAL_NUMBER => (ATT_SERIAL_NUMBER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_COUNTRY => (ATT_COUNTRY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_LOCALITY => (ATT_LOCALITY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_STATE_OR_PROVINCE => (ATT_STATE_OR_PROVINCE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_STREET_ADDRESS => (ATT_STREET_ADDRESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_ORGANIZATION => (ATT_ORGANIZATION_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_ORGANIZATION_UNIT => (ATT_ORGANIZATION_UNIT_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_TITLE => (ATT_TITLE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_BUSINESS => (ATT_BUSINESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_POSTAL_CODE => (ATT_POSTAL_CODE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_GIVEN_NAME => (ATT_GIVEN_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INITIALS => (ATT_INITIALS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_DN_QUALIFIER => (ATT_DN_QUALIFIER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_ORGANIZATION_IDENTIFIER => (ATT_ORGANIZATION_IDENTIFIER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INC_LOCALITY => (ATT_INC_LOCALITY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INC_STATE => (ATT_INC_STATE_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_INC_COUNTRY => (ATT_INC_COUNTRY_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_DOMAIN_COMPONENT => (ATT_DOMAIN_COMPONENT_OID, ASN1_IA5_SRT),
                            ATT_POSTAL_ADDRESS => (ATT_POSTAL_ADDRESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_NAME => (ATT_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_TELEPHONE_NUMBER => (ATT_TELEPHONE_NUMBER_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_DIR_MAN_DOMAIN_NAME => (ATT_DIR_MAN_DOMAIN_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_USER_ID => (ATT_USER_ID_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_UNSTRUCTURED_NAME => (ATT_UNSTRUCTURED_NAME_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),
                            ATT_UNSTRUCTURED_ADDRESS => (ATT_UNSTRUCTURED_ADDRESS_OID, if attribute < 0 { ASN1_PRINT_STR } else { ASN1_UTF8_STR }),

                            _ => panic!("Unknown attribute format: {}", attribute),
                        };
                        let value = match &name_elements[i + 1] {
                            Value::Text(text_value) => text_value.as_bytes(),
                            _ => panic!("Unknown attribute value format'"),
                        };
                        lder_to_two_seq(oid.to_der_vec().unwrap(), lder_to_generic(value.to_vec(), tag))

                    }
                    _ => panic!("Unknown attribute format'"),
                };

                result_vec.push(lder_to_generic(attr_type_and_val, ASN1_SET));
            }
        }
        _ => {
            panic!("Unknown RelativeDistinguishedName value.");
        }
    };
    lder_to_seq(result_vec)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
Warning, CURRENTLY KNOWN BUG:
*/
fn parse_cbor_time(input: &Value) -> (Vec<u8>, i64) {
    // Format DateTime as "%Y%m%d%H%M%SZ"
    //let formatted_date = dt.format("%Y%m%d%H%M%SZ").to_string();
    let mut type_flag = ASN1_UTC_TIME;
    let (formatted_date, time_val) = match input {
        Value::Integer(val) => {

            trace!("parse_cbor_time, incoming ts: {}", *val);
            let ts = chrono::TimeZone::timestamp(&chrono::Utc, *val as i64, 0);
            if ASN1_UTC_TIME_MAX < *val as i64 {
                type_flag = ASN1_GEN_TIME;
                //using four digit year format to match GEN time format
                (ts.format("%Y%m%d%H%M%SZ").to_string(), *val)
            } //else if (*val as i64) < ASN1_UTC_TIME_Y2K {            panic!("Unresolved pre 2000 date handling bug, aborting");            }
            else {
                //using two digit year format to match UTC time format
                (ts.format("%y%m%d%H%M%SZ").to_string(), *val)
            }
        }
        Value::Null => {
            debug!("parse_cbor_time, found CBOR NULL");
            type_flag = ASN1_GEN_TIME;
            (ASN1_GEN_TIME_MAX.to_string(), 0)
        }
        _ => {
            panic!("Unknown time value.");
        }
    };
    trace!("parse_cbor_time custom format: {}", formatted_date);
    (lder_to_time(formatted_date, type_flag), time_val as i64)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
pub fn parse_cbor_pub_key(pub_key: &Value, key_type: i64) -> Vec<u8> {
    //  Some(42)

    let mut pub_key_vec= Vec::new();
    let mut result = Vec::new();
    match pub_key {
        Value::Bytes(pub_key_array) => {
            pub_key_vec = pub_key_array.to_vec();
            //Good
        }
        _ => debug!("parse_cbor_pub_key received key in non-byte format {:?}", pub_key),
    }

    let dummy = {
        match key_type {
            PK_RSA_ENC => {
                result.push(lder_to_two_seq(lder_to_generic(PK_RSA_ENC_OID.as_bytes().to_vec(), ASN1_OID), ASN1_NULL.to_vec()));
                check_and_reconstruct_pub_key_rsa(pub_key, PK_RSA_ENC)
            }
            PK_SECP256R => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SECP256R_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SECP256R_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SECP256R)
            }
            PK_SECP384R => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SECP384R_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SECP384R_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SECP384R)
            }
            PK_SECP521R => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SECP521R_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SECP521R_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SECP521R)
            }
            PK_X25519 => {
                result.push(lder_to_generic(lder_to_generic(PK_X25519_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_X25519)
            }
            PK_X448 => {
                result.push(lder_to_generic(lder_to_generic(PK_X448_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_X448)
            }
            PK_ED25519 => {
                result.push(lder_to_generic(lder_to_generic(PK_ED25519_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_ED25519)
            }
            PK_ED448 => {
                result.push(lder_to_generic(lder_to_generic(PK_ED448_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_ED448)
            }
            PK_HSS_LMS => {
                result.push(lder_to_generic(lder_to_generic(PK_HSS_LMS_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_mac(pub_key_vec, PK_HSS_LMS)
            }
            PK_XMSS => {
                result.push(lder_to_generic(lder_to_generic(PK_XMSS_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_mac(pub_key_vec, PK_XMSS)
            }
            PK_XMSS_MT => {
                result.push(lder_to_generic(lder_to_generic(PK_XMSS_MT_OID.as_bytes().to_vec(), ASN1_OID), ASN1_SEQ));
                check_and_reconstruct_pub_key_mac(pub_key_vec, PK_XMSS_MT)
            }
            PK_BRAINPOOL256R1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_BRAINPOOL256R1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_BRAINPOOL256R1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_BRAINPOOL256R1)
            }
            PK_BRAINPOOL384R1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_BRAINPOOL384R1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_BRAINPOOL384R1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_BRAINPOOL384R1)
            }
            PK_BRAINPOOL512R1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_BRAINPOOL512R1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_BRAINPOOL512R1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_BRAINPOOL512R1)
            }
            PK_FRP256V1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_FRP256V1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_FRP256V1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_FRP256V1)
            }
            PK_SM2P256V1 => {
                result.push(lder_to_two_seq(lder_to_generic(PK_SM2P256V1_OID.as_bytes().to_vec(), ASN1_OID), lder_to_generic(PK_SM2P256V1_PARAM_OID.as_bytes().to_vec(), ASN1_OID)));
                check_and_reconstruct_pub_key_ecc(pub_key_vec, PK_SM2P256V1)
            }
            _ => {
                panic!("Could not parse public key");
            }
        }
    }; //end of let dummy
    result.push(dummy);
    lder_to_seq(result)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn check_and_reconstruct_pub_key_ecc(pub_key: Vec<u8>, ecc_type_id: i64) -> Vec<u8> {
    let mut result = Vec::new();

    match pub_key.get(0).unwrap() as &u8 {
        &SECG_EVEN_COMPRESSED => {
            result.push(SECG_UNCOMPRESSED);
            result.extend_from_slice(&pub_key[1..pub_key.len()]);
            result.extend(decompress_ecc_key(pub_key[1..pub_key.len()].to_vec(), true, ecc_type_id));
        }
        &SECG_ODD_COMPRESSED => {
            result.push(SECG_UNCOMPRESSED);
            result.extend_from_slice(&pub_key[1..pub_key.len()]);
            result.extend(decompress_ecc_key(pub_key[1..pub_key.len()].to_vec(), false, ecc_type_id));
        }
        &SECG_EVEN | &SECG_ODD => result = pub_key, //dontdostuff, just return the key input for now

        _ => panic!("Expected public key to start with a compression indicator, but it started with {:?}", pub_key.get(0)),
    }

    //  if <criteria> TODO  result.insert(0, 0x00);
    lder_to_bit_str(result)
}

//https://github.com/RustCrypto/elliptic-curves/
fn decompress_ecc_key(pub_key_x: Vec<u8>, is_even: bool, ecc_type_id: i64) -> Vec<u8> {
    //let public_key = PublicKey::from_slice(pub_key_input.as_slice()).expect("Can only handle public keys of len 33 or 65 bytes, serialized according to SEC 2");
    //public_key.serialize_uncompressed().to_vec()
    //P-256
    //y^2 ≡ x^3+ax+b
    // let ms = { if is_even == true { Sign::Plus } else { Sign::Minus } };
    let x = BigInt::from_bytes_be(Sign::Plus, &pub_key_x);
    let mc = {
        match ecc_type_id {
            PK_SECP256R => ECCCurve {
                p: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16).unwrap(),
                a: BigInt::parse_bytes(b"ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16).unwrap(),
                b: BigInt::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16).unwrap(),
                l: 32,
            },
            PK_SECP384R => {
                //https://neuromancer.sk/std/secg/secp384r1
                ECCCurve {
                    p: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16).unwrap(),
                    a: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16).unwrap(),
                    b: BigInt::parse_bytes(b"b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16).unwrap(),
                    l: 48,
                }
            }
            PK_SECP521R => {
                //https://neuromancer.sk/std/secg/secp384r1
                ECCCurve {
                    p: BigInt::parse_bytes(b"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
                    a: BigInt::parse_bytes(b"01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16).unwrap(),
                    b: BigInt::parse_bytes(b"0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16).unwrap(),
                    l: 64,
                }
            }
            _ => panic!("Cannot handle ECC curve of type {}", ecc_type_id),
        }
    };
    //let big_int = &&x;
    let y2 = (pow(x.clone(), 3) + &mc.a * &x.clone() + &mc.b) % &mc.p;
    let mut y = y2.modpow(&((&mc.p + BigInt::one()) / BigInt::from(4)), &mc.p);

    let y_is_even = y.clone() % 2 == BigInt::zero();
    //  let mut ys = y.clone();
    //let mut y_inv = y.clone();

    //  if (y[y.len() - 1] & 1 == 0 && is_even == false) || y[y.len() - 1] & 1 == 1 && is_even == true {
    if y_is_even != is_even {
        y = &mc.p - &y;
        trace!("decompress_ecc_key: inverting y!");
    }
    //let mut y_inv = &mc.p-&y;
    //let y_inv = &mc.p-&y;
    let (_, mut yb) = y.to_bytes_be();

    if yb.len() < mc.l { //TODO: currently assuming only one leading 0
        yb.insert(0, 0);
    } 
    trace!("decompress_ecc_key: resulting y:\n{:02x?}", yb);
    yb
    //std::process::exit(0);
}

//***************************************************************************************************************************************

fn check_and_reconstruct_pub_key_rsa(pub_key: &Value, _key_id: i64) -> Vec<u8> {
    let modulus;
    let exponent;

    match pub_key {
        Value::Array(pub_key_arr) => {
            assert!(pub_key_arr.len() == 2, "Public key must have two components");
            modulus = lder_to_pos_int(get_as_bytes(pub_key_arr.get(0).unwrap()));
            exponent = lder_to_pos_int(get_as_bytes(pub_key_arr.get(1).unwrap()));
        }
        Value::Bytes(pub_key_mod_only) => {
            //  let my_integer = Integer::from_bytes_be(pub_key_mod_only);
            modulus = lder_to_pos_int(pub_key_mod_only.to_vec());
            exponent = ASN1_65537.to_vec();
        }
        _ => {
            panic!("Could not decode rsa pub key: {:?}", pub_key);
        }
    }
    lder_to_bit_str(lder_to_two_seq(modulus, exponent))
}
fn check_and_reconstruct_pub_key_mac(_pub_key: Vec<u8>, _key_id: i64) -> Vec<u8> {
    panic!("Reconstruction of mac based pub keys not yet supported");
}

//***************************************************************************************************************************************
//***************************************************************************************************************************************

//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_extensions(input: &Value, ts_offset: i64) -> Vec<u8> {
    //let mut parsed_extensions = Vec::new();
    let mut parsed_extensions_arr = Vec::new();
    match input {
        Value::Integer(val) => {
            trace!("parse_cbor_extensions, received CBOR int: {:x?}", val);
            parsed_extensions_arr.push(parse_cbor_ext_key_usage(input, *val < 0));
        }
        Value::Array(extension_array) => {
            //trace!("CBOR array: {:x?}", extension_array);
            for i in (0..extension_array.len()).step_by(2) {
                //trace!("Current values: {} {:?} {:?}", i, extension_array[i], extension_array[i+1]);
                parsed_extensions_arr.push({
                    match &extension_array[i] {
                        Value::Integer(ext_type) => {
                            trace!("parse_cbor_extensions, found ext of int type {}", ext_type);
                            match (ext_type.abs()) as u16 {
                                EXT_SUBJECT_KEY_ID => {
                                    let dummy = parse_cbor_ext_subject_key_id(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_KEY_ID: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_KEY_USAGE => {
                                    let dummy = parse_cbor_ext_key_usage(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_KEY_USAGE: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SUBJECT_ALT_NAME => {
                                    let dummy = parse_cbor_ext_subject_alt_name(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_ALT_NAME size: {}", dummy.len());
                                    dummy
                                }
                                EXT_BASIC_CONSTRAINTS => {
                                    let dummy = parse_cbor_ext_basic_constraints(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_BASIC_CONSTRAINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_CRL_DIST_POINTS => {
                                    let dummy = parse_cbor_ext_crl_dist_points(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_CRL_DIST_POINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_CERT_POLICIES => {
                                    let dummy = parse_cbor_ext_cert_policies(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_CERT_POLICIES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AUTH_KEY_ID => {
                                    let dummy = parse_cbor_ext_auth_key_id(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AUTH_KEY_ID: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_EXT_KEY_USAGE => {
                                    let dummy = parse_cbor_ext_ext_key_usage(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_EXT_KEY_USAGE: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AUTH_INFO => {
                                    let dummy = parse_cbor_ext_auth_info(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AUTH_INFO: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SCT_LIST => {
                                    let dummy = parse_cbor_ext_sct_list(&extension_array[i + 1], *ext_type < 0, ts_offset);
                                    debug!("parse_cbor_extensions, EXT_SCT_LIST: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SUBJECT_DIRECTORY_ATTR => {
                                    let dummy = parse_cbor_ext_subject_directory_attr(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_DIRECTORY_ATTR: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_ISSUER_ALT_NAME => {
                                    let dummy = parse_cbor_ext_issuer_alt_name(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_ISSUER_ALT_NAME: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_NAME_CONSTRAINTS => {
                                    let dummy = parse_cbor_ext_name_constraints(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_NAME_CONSTRAINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_POLICY_MAPPINGS => {
                                    let dummy = parse_cbor_ext_policy_mappings(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_POLICY_MAPPINGS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_POLICY_CONSTRAINTS => {
                                    let dummy = parse_cbor_ext_policy_constraints(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_POLICY_CONSTRAINTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_FRESHEST_CRL => {
                                    let dummy = parse_cbor_ext_freshest_crl(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_FRESHEST_CRL: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_INHIBIT_ANYPOLICY => {
                                    let dummy = parse_cbor_ext_inhibit_anypolicy(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_INHIBIT_ANYPOLICY: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_SUBJECT_INFO_ACCESS => {
                                    let dummy = parse_cbor_ext_subject_info_access(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_SUBJECT_INFO_ACCESS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_IP_RESOURCES => {
                                    let dummy = parse_cbor_ext_ip_resources(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_IP_RESOURCES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AS_RESOURCES => {
                                    let dummy = parse_cbor_ext_as_resources(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AS_RESOURCES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_IP_RESOURCES_V2 => {
                                    let dummy = parse_cbor_ext_ip_resources_v2(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_IP_RESOURCES_V2: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_AS_RESOURCES_V2 => {
                                    let dummy = parse_cbor_ext_as_resources_v2(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_AS_RESOURCES_V2: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_BIOMETRIC_INFO => {
                                    let dummy = parse_cbor_ext_biometric_info(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_BIOMETRIC_INFO: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_PRECERT_SIGNING_CERT => {
                                    let dummy = parse_cbor_ext_precert_signing_cert(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_PRECERT_SIGNING_CERT: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_OCSP_NO_CHECK => {
                                    let dummy = parse_cbor_ext_ocsp_no_check(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_OCSP_NO_CHECK: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_QUALIFIED_CERT_STATEMENTS => {
                                    let dummy = parse_cbor_ext_qualified_cert_statements(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_QUALIFIED_CERT_STATEMENTS: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_S_MIME_CAPABILITIES => {
                                    let dummy = parse_cbor_ext_s_mime_capabilities(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_S_MIME_CAPABILITIES: {:02x?}", dummy);
                                    dummy
                                }
                                EXT_TLS_FEATURES => {
                                    let dummy = parse_cbor_ext_tls_features(&extension_array[i + 1], *ext_type < 0);
                                    debug!("parse_cbor_extensions, EXT_TLS_FEATURES: {:02x?}", dummy);
                                    dummy
                                }
                                _ => panic!("Ext type {} out of scope!", ext_type),
                            }
                        }
                        Value::Bytes(raw_ext_type_oid) => {
                            let this_oid = lder_to_generic(raw_ext_type_oid.to_vec(), ASN1_OID);
                            let ext_val = match &extension_array[i + 1] {
                            //assuming the ext.value = next item in the array is also byte encoded
                              Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
                                _ => panic!("Error parsing value: {:?}.", extension_array[i + 1]),
                              };
                            let dummy = lder_to_two_seq(this_oid, ext_val);
                            debug!("parse_cbor_extensions, EXT OF BYTE TYPE {:02x?}", dummy);
                            dummy
                        }
                        _ => panic!("Unknown ext type: {:?}.", extension_array[i]),
                    }
                });
            }
        }
        _ => {
            panic!("Unknown ext value: {:?}.", input);
        }
    }
    lder_to_generic(lder_to_seq(parsed_extensions_arr), ASN1_INDEX_THREE)
    //parsed_extensions
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
pub fn parse_cbor_sig_alg(sig_alg: &Value) -> (Vec<u8>, i32) {

  println!("sig alg input: {:x?}", sig_alg);
  match sig_alg {
  Value::Integer(alg_id) => {
  match alg_id {
    0 => ([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00].to_vec(), (*alg_id as i32)),
    1 => (vec![0;0], (*alg_id as i32)),
    _ => panic!("Unknown pk type: {}", alg_id),
  }
  },
  Value::Array(raw_oid) => {
  panic!("not now")
  },
  _ => panic!("Could not parse sig alg"),
  }
}
*/
//***************************************************************************************************************************************
//***************************************************************************************************************************************
pub fn parse_cbor_sig_info(sig_alg: &Value, sig_val: &Value) -> (Vec<u8>, Vec<u8>) {
    trace!("parse_cbor_sig_info input: {:x?}", sig_alg);
    //let mut result: Vec<Vec<u8>> = Vec::new();
    let mut oid;

    let sig_val_vec: Vec<u8> = match sig_val {
        Value::Bytes(sig_val_bytes) => sig_val_bytes.to_vec(),
        _ => panic!("Could not parse sig val"),
    };
    let parsed_sig_val ;
    let mut param = Vec::new();

    match sig_alg {
        Value::Integer(sign_alg_id) => {
            trace!("parse_cbor_sig_info, working with sign alg_id {}", sign_alg_id);
            match *sign_alg_id as i64 {
                SIG_RSA_V15_SHA1 => {
                    oid = SIG_RSA_V15_SHA1_OID.as_bytes().to_vec(); //TODO check param
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                }
                SIG_ECDSA_SHA1 => {
                    oid = SIG_ECDSA_SHA1_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                }
                SIG_ECDSA_SHA256 => {
                    oid = SIG_ECDSA_SHA256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                    //  panic!("not now");
                }
                SIG_ECDSA_SHA384 => {
                    oid = SIG_ECDSA_SHA384_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ECDSA_SHA512 => {
                    oid = SIG_ECDSA_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ECDSA_SHAKE128 => {
                    oid = SIG_ECDSA_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ECDSA_SHAKE256 => {
                    oid = SIG_ECDSA_SHAKE256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ED25519 => {
                    oid = SIG_ED25519_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_ED448 => {
                    oid = SIG_ED448_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_ecc_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                //MAC based
                SIG_SHA256_HMAC_SHA256 => {
                    oid = SIG_SHA256_HMAC_SHA256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_mac_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_SHA384_HMAC_SHA384 => {
                    oid = SIG_SHA384_HMAC_SHA384_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_mac_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_SHA512_HMAC_SHA512 => {
                    oid = SIG_SHA512_HMAC_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_mac_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                //RSA based
                SIG_RSA_V15_SHA256 => {
                    oid = SIG_RSA_V15_SHA256_OID.as_bytes().to_vec();
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_V15_SHA384 => {
                    oid = SIG_RSA_V15_SHA384_OID.as_bytes().to_vec();
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_V15_SHA512 => {
                    oid = SIG_RSA_V15_SHA512_OID.as_bytes().to_vec();
                    param = ASN1_NULL.to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHA256 => {
                    oid = SIG_RSA_PSS_SHA256_OID.as_bytes().to_vec();
                    //param = TODO
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHA384 => {
                    oid = SIG_RSA_PSS_SHA384_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHA512 => {
                    oid = SIG_RSA_PSS_SHA512_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHAKE128 => {
                    oid = SIG_RSA_PSS_SHAKE128_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                SIG_RSA_PSS_SHAKE256 => {
                    oid = SIG_RSA_PSS_SHAKE256_OID.as_bytes().to_vec();
                    parsed_sig_val = parse_cbor_rsa_sig_value(sig_val_vec.clone());
                    trace!("parse_cbor_sig_info, encoded sig val bytes: {:02x?}", parsed_sig_val);
                }
                //Some odd ones, not yet supported
                SIG_HSS_LMS => {
                    //oid = SIG_HSS_LMS_OID.as_bytes().to_vec();
                    panic!("SIG_HSS_LMS sig alg reconstruction not yet supported");
                }
                SIG_XMSS => {
                    //oid = SIG_XMSS_OID.as_bytes().to_vec();
                    panic!("SIG_XMSS sig alg reconstruction not yet supported");
                }
                SIG_XMSS_MT => {
                    //oid = SIG_XMSS_MT_OID.as_bytes().to_vec();
                    panic!("SIG_XMSS_MT sig alg reconstruction not yet supported");
                }
                _ => panic!("Unknown sign alg type: {}", sign_alg_id),
            }
        }
        Value::Array(_) => {
            panic!("sig alg array not supported")
        }
        _ => panic!("Could not parse sig alg"),
    };
    if param != Vec::new() {
        oid = lder_to_two_seq(lder_to_generic(oid, ASN1_OID), param);
    } else {
        oid = lder_to_generic(lder_to_generic(oid, ASN1_OID), ASN1_SEQ);
    }
    (oid, parsed_sig_val) //lder_to_seq(result))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//use asn1_rs::{BitString, Sequence, Integer, FromBer, ToDer};
//use asn1_rs::{BitString, Sequence, Integer};
pub fn parse_cbor_ecc_sig_value(sig_val_bytes: Vec<u8>) -> Vec<u8> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    //let mut writer = Vec::new();



    let start_r_index = if sig_val_bytes[0] == 0 { 1 } else { 0 };
    let r = sig_val_bytes[start_r_index..sig_val_bytes.len() / 2].to_vec();
    trace!("parse_cbor_ecc_sig_value, restored r: {:02?}", r);

    let midpoint = if sig_val_bytes[sig_val_bytes.len() / 2] == 0 { sig_val_bytes.len() / 2+1 } else { sig_val_bytes.len() / 2 };         
    let s = sig_val_bytes[midpoint..sig_val_bytes.len()].to_vec();
    trace!("parse_cbor_ecc_sig_value, restored s: {:02?}", s);
    
    result.push(lder_to_pos_int(r));
    result.push(lder_to_pos_int(s));

    lder_to_bit_str(lder_to_seq(result))
}
pub fn parse_cbor_rsa_sig_value(sig_val_bytes: Vec<u8>) -> Vec<u8> {
    lder_to_bit_str(sig_val_bytes)
}
pub fn parse_cbor_mac_sig_value(_: Vec<u8>) -> Vec<u8> {
    panic!("Reconstruction of MAC based signatures not yet supported");
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
pub fn cleanup(mut file_contents: Vec<u8>) -> Vec<u8> {
    // Remove the trailing newline if present
    if let Some(last_byte) = file_contents.last() {
        if *last_byte == b'\n' {
            file_contents.remove(file_contents.len() - 1);
            return file_contents;
        //return file_contents[..file_contents.len() - 1]
        } else {
            return file_contents;
        }
    } else {
        return file_contents;
    };
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//              Below are fuctions for parsing and re-encoding cbor encoded extensions back to ASN.1
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_SUBJECT_KEY_ID = 1
fn parse_cbor_ext_subject_key_id(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_KEY_ID_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_KEY_USAGE = 2
fn parse_cbor_ext_key_usage(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_KEY_USAGE_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }

    let mut ext_val_arr = Vec::new();
    match extension_val {
        Value::Integer(key_usage_bitmap) => {
            let key_usage = {
                if 255 < *key_usage_bitmap {
                    ext_val_arr.push(128);
                    ((key_usage_bitmap - 256) as u8).swap_bits()
                } else {
                    (*key_usage_bitmap as u8).swap_bits()
                }
            };
            ext_val_arr.insert(0, key_usage);
            //Calculate number of trailing zeroes
            ext_val_arr.insert(0, key_usage.trailing_zeros() as u8);
            ext_val_arr = lder_to_generic(ext_val_arr, ASN1_BIT_STR);
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
EXT_SUBJECT_ALT_NAME = 3
CDDL
GeneralName = ( GeneralNameType : int, GeneralNameValue : any )
   GeneralNames = [ + GeneralName ]
   SubjectAltName = GeneralNames / text

*/
fn parse_cbor_ext_subject_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_ALT_NAME_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    //  let ext_val_arr = parse_cbor_general_name(extension_val);
    let ext_val_arr = lder_to_generic(parse_cbor_general_name(extension_val), ASN1_OCTET_STR);
    //let ext_val_arr = parse_cbor_general_name(extension_val); //TODO, check if general name always gives the needed octet string wrapping

    lder_to_two_seq(oid, ext_val_arr)
}

fn parse_cbor_general_name(extension_val: &Value) -> Vec<u8> {
    let empty_vec = Vec::new();
    match extension_val {
        Value::Array(general_name) => {
            let mut general_name_arr = Vec::new();
            let mut unwrap = false;
            for i in (0..general_name.len()).step_by(2) {
                general_name_arr.push({
                    match general_name[i] {
                        Value::Integer(gn_field) => {

                            match gn_field {
                                -1 => parse_cbor_general_name_hw_module(&general_name[i + 1]),
                                0 => {
                                    //otherName == [ ~oid, bytes ] //TODO TEST
                                    trace!("parse_cbor_general_name, option 0");
                                    match &general_name[i + 1] {
                                        Value::Array(other_name_array) => {
                                            let oid = {
                                                match &other_name_array[0] {
                                                    Value::Bytes(oid_bytes) => lder_to_generic(oid_bytes.to_vec(), ASN1_OID),
                                                    _ => panic!("Error parsing value: {:?}.", other_name_array[0]),
                                                }
                                            };
                                            let value = {
                                                match &other_name_array[1] {
                                                    Value::Bytes(val_bytes) => val_bytes.to_vec(),
                                                    _ => panic!("Error parsing value: {:?}.", other_name_array[0]),
                                                }
                                            };
                                            lder_to_two_seq(oid, value)
                                        }
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                1 => {
                                    //rfc822Name == text
                                    trace!("parse_cbor_general_name, option 1");
                                    match &general_name[i + 1] {
                                        Value::Text(rfc_822_name) => lder_to_generic(rfc_822_name.as_bytes().to_vec(), ASN1_INDEX_ONE_EXT),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                2 => {
                                    //dnsName == text
                                    trace!("parse_cbor_general_name, option 2");
                                    match &general_name[i + 1] {
                                        Value::Text(dns_name) => lder_to_generic(dns_name.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                4 => {
                                    // directoryName == Name
                                    trace!("parse_cbor_general_name, option 4");
                                    unwrap = true;
                                    lder_to_generic(parse_cbor_name(&general_name[i + 1] as &Value, &empty_vec), ASN1_INDEX_FOUR)
                                    //todo test more
                                }
                                6 => {
                                    // uri == text
                                    trace!("parse_cbor_general_name, option 6");
                                    match &general_name[i + 1] {
                                        Value::Text(uri) => lder_to_generic(uri.as_bytes().to_vec(), ASN1_URL),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                7 => {
                                    //ipAddress == bytes
                                    trace!("parse_cbor_general_name, option 7, ipAddress");
                                    match &general_name[i + 1] {
                                        Value::Bytes(ip) => lder_to_generic(ip.to_vec(), ASN1_IP),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                8 => {
                                    //registeredID  == ~oid
                                    trace!("parse_cbor_general_name, option 8, oid");
                                    match &general_name[i + 1] {
                                        Value::Bytes(id) => lder_to_generic(id.to_vec(), ASN1_URL),
                                        _ => panic!("Error parsing value: {:?}.", general_name[i + 1]),
                                    }
                                }
                                _ => {
                                    panic!("Not implemented: {:?}.", general_name[i])
                                }
                            }
                        }
                        _ => panic!("Error parsing value: {:?}.", general_name[i]),
                    }
                });
            }
            if unwrap == true {
                trace!("parse_cbor_general_name, unwrapping");
                general_name_arr.get(0).unwrap().clone().to_vec()
            } else {
                //implicit else:
                trace!("parse_cbor_general_name, no unwrapping");
                lder_to_seq(general_name_arr)
            }
            //let general_name = lder_to_seq(general_name_arr);  lder_to_generic(general_name, ASN1_OCTET_STR)
        }
        /*
          If subjectAltName contains exactly one dNSName, the array and the int are omitted and
          extensionValue is the dNSName encoded as a CBOR text string.

          The original ASN.1 struct is a an OCT string wrapping a SEQ wrapping a [2] elem
        */
        //Value::Text(raw_val) => lder_to_generic(lder_to_generic(lder_to_generic(raw_val.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT), ASN1_SEQ), ASN1_OCTET_STR),
        Value::Text(raw_val) => lder_to_generic(lder_to_generic(raw_val.as_bytes().to_vec(), ASN1_INDEX_TWO_EXT), ASN1_SEQ),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_BASIC_CONSTRAINTS = 4
fn parse_cbor_ext_basic_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_BASIC_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical {
        trace!("parse_cbor_ext_basic_constraints: CRITICAL!");
        oid.extend(ASN1_X509_CRITICAL.to_vec());
        let second = {
            match extension_val {
                Value::Integer(path_len) => {
                    if -2 == *path_len {
                        ASN1_X509_BASIC_CONSTRAINT_FALSE.to_vec()
                    } else if -1 == *path_len {
                        lder_to_generic(lder_to_generic(ASN1_X509_CRITICAL.to_vec(), ASN1_SEQ), ASN1_OCTET_STR)
                    } else {
                        let path_len_vec = vec![*path_len as u8];
                        lder_to_generic(lder_to_two_seq(ASN1_X509_CRITICAL.to_vec(), lder_to_pos_int(path_len_vec)), ASN1_OCTET_STR)
                    }
                }
                _ => panic!("Illegal path len {:?}", extension_val),
            }
        }; //end let second
        lder_to_two_seq(oid, second) //TODO check if this also should be wrapped
    } else {
        trace!("parse_cbor_ext_basic_constraints: NOT CRITICAL!");
        let second = {
            match extension_val {
                Value::Integer(path_len) => {
                    if -2 == *path_len {
                        ASN1_X509_BASIC_CONSTRAINT_FALSE.to_vec()
                    } else if -1 == *path_len {
                        lder_to_generic(lder_to_generic(ASN1_X509_CRITICAL.to_vec(), ASN1_SEQ), ASN1_OCTET_STR)
                    } else {
                        let path_len_vec = vec![*path_len as u8];
                        lder_to_generic(lder_to_two_seq(ASN1_X509_CRITICAL.to_vec(), lder_to_pos_int(path_len_vec)), ASN1_OCTET_STR)
                    }
                }
                _ => panic!("Illegal path len {:?}", extension_val),
            }
        }; //end let second
        lder_to_two_seq(oid, second)
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_CRL_DIST_POINTS = 5
fn parse_cbor_ext_crl_dist_points(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut result_vec = Vec::new();
    let mut oid = EXT_CRL_DIST_POINTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    match extension_val {
        Value::Array(elements) => {
            for element in elements {
                match element {
                    Value::Text(url_string) => {
                        result_vec.push(lder_to_generic(lder_to_generic(lder_to_generic(lder_to_generic(url_string.as_bytes().to_vec(), ASN1_URL), ASN1_INDEX_ZERO), ASN1_INDEX_ZERO), ASN1_SEQ));
                    }
                    _ => {
                        panic!("Could not parse {:?}", element);
                        //Possible todo: this could be a nested array as well. fail grafully? (See elster.de, puma.com)
                    }
                }
            }
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_CERT_POLICIES = 6
/*
Qualifier ::= CHOICE {
  cPSuri   CPSuri,
  userNotice   UserNotice }
   CPSuri ::= IA5String
*/
fn parse_cbor_ext_cert_policies(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut result_vec = Vec::new();
    let mut oid = EXT_CERT_POLICIES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let mut can_specify = false;
    let mut text_type = ASN1_UTC_TIME; //must be overwritten

    match extension_val {
        Value::Array(elements) => {
            let mut wip = Vec::new();
            for element in elements {
                match element {
                    Value::Integer(pol_id) => {
                        if can_specify {
                            //prev oid didn't use any qualifier, and should be stored now
                            result_vec.push(lder_to_seq(wip));
                            wip = Vec::new();
                        }
                        //result_vec.push(lder_to_generic(lder_to_generic(lder_to_generic(lder_to_generic(url_string.as_bytes().to_vec(), ASN1_INDEX_SIX_EXT),ASN1_INDEX_ZERO),ASN1_INDEX_ZERO),ASN1_SEQ));
                        trace!("parse_cbor_ext_cert_policies, FOUND pol id: {:02x?}", map_cert_policy_id_to_oid(*pol_id as i64));
                        wip.push(map_cert_policy_id_to_oid(*pol_id as i64));
                        can_specify = true;
                    }
                    Value::Bytes(raw_oid) => {
                        if can_specify {
                            //prev oid didn't use any qualifier, and should be stored now
                            result_vec.push(lder_to_seq(wip));
                            wip = Vec::new();
                        }
                        wip.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                        trace!("parse_cbor_ext_cert_policies, handling raw bytes");
                        can_specify = true;
                    }
                    Value::Array(specifiers) => {
                        if !can_specify {
                            panic!("Did not expect specifiers here: {:?}", specifiers);
                        }
                        let mut wip_internal = Vec::new();
                        for i in (0..specifiers.len()).step_by(2) { //Specifiers should come in (cps or unotice) / text string pairs, 0 to many
                          let q_oid = {
                              match specifiers.get(i).unwrap() {
                                  Value::Bytes(raw_oid) => lder_to_generic(raw_oid.to_vec(), ASN1_OID),
                                  Value::Integer(pol_id) => {
                                      if PQ_CPS == *pol_id as i64 {
                                          trace!("parse_cbor_ext_cert_policies, handling cps {:02x?}", PQ_CPS_OID.to_der_vec().unwrap());
                                          text_type = ASN1_IA5_SRT;
                                          PQ_CPS_OID.to_der_vec().unwrap()
                                      } else if PQ_UNOTICE == *pol_id as i64 {
                                          trace!("parse_cbor_ext_cert_policies, handling unotice {:02x?}", PQ_UNOTICE_OID.to_der_vec().unwrap());
                                          text_type = ASN1_UTF8_STR;
                                          PQ_UNOTICE_OID.to_der_vec().unwrap()
                                      } else {
                                          panic!("Can't handle policy qualifier: {:?}", pol_id);
                                      }
                                  }
                                  _ => {
                                      panic!("Could not parse {:?}", specifiers.get(0));
                                  }
                              }
                          };
                          let q_text = {
                              match specifiers.get(i+1).unwrap() {
                                  Value::Text(qualifier) => {
                                      trace!("parse_cbor_ext_cert_policies, handling text {:02x?}", qualifier.as_bytes());
                                      //unotice has one extra level of sequence wrapping...!
                                      let t_text = lder_to_generic(qualifier.as_bytes().to_vec(), text_type);
                                      if text_type == ASN1_UTF8_STR {
                                        lder_to_generic(t_text, ASN1_SEQ)
                                      } else {
                                        t_text
                                      }
                                  }
                                  _ => {
                                      panic!("Could not parse {:?}", specifiers.get(1))
                                  }
                              }
                          };
                          //wip.push(lder_to_generic(lder_to_two_seq(q_oid, q_text), ASN1_SEQ));
                          trace!("parse_cbor_ext_cert_policies, storing next two two");
                          wip_internal.push(lder_to_two_seq(q_oid, q_text));

                      } //end of specifiers loop
                      //wip.push(lder_to_generic(lder_to_two_seq(q_oid, q_text), ASN1_SEQ));
                      wip.push(lder_to_seq(wip_internal));
                      trace!("parse_cbor_ext_cert_policies, storing WIP to res {:?}", wip);
                      result_vec.push(lder_to_seq(wip)); //TODO: check empty
                      wip = Vec::new();
                      can_specify = false;

                    }
                    _ => {
                        panic!("Could not parse {:?}", element);
                    }
                } //end of element
            } //end of big for loop
            if can_specify {
                //last oid didn't use any qualifier, and should be stored now
                result_vec.push(lder_to_seq(wip));
            }
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}

fn map_cert_policy_id_to_oid(cert_policy_id: i64) -> Vec<u8> {
    match cert_policy_id {
        CP_ANY_POLICY => CP_ANY_POLICY_OID.to_der_vec().unwrap(),
        CP_DOMAIN_VALIDATION => CP_DOMAIN_VALIDATION_OID.to_der_vec().unwrap(),
        CP_ORGANIZATION_VALIDATION => CP_ORGANIZATION_VALIDATION_OID.to_der_vec().unwrap(),
        CP_INDIVIDUAL_VALIDATION => CP_INDIVIDUAL_VALIDATION_OID.to_der_vec().unwrap(),
        CP_EXTENDED_VALIDATION => CP_EXTENDED_VALIDATION_OID.to_der_vec().unwrap(),
        CP_RESOURCE_PKI => CP_RESOURCE_PKI_OID.to_der_vec().unwrap(),
        CP_RESOURCE_PKI_ALT => CP_RESOURCE_PKI_ALT_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_CI => CP_RSP_ROLE_CI_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_EUICC => CP_RSP_ROLE_EUICC_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_EUM => CP_RSP_ROLE_EUM_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DP_TLS => CP_RSP_ROLE_DP_TLS_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DP_AUTH => CP_RSP_ROLE_DP_AUTH_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DP_PB => CP_RSP_ROLE_DP_PB_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DS_TLS => CP_RSP_ROLE_DS_TLS_OID.to_der_vec().unwrap(),
        CP_RSP_ROLE_DS_AUTH => CP_RSP_ROLE_DS_AUTH_OID.to_der_vec().unwrap(),
        _ => panic!("Found unknown cert policy code: {}", cert_policy_id),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_AUTH_KEY_ID = 7
/*
KeyIdentifierArray = [
   keyIdentifier: KeyIdentifier / null,
   authorityCertIssuer: GeneralNames,
   authorityCertSerialNumber: CertificateSerialNumber
   ]
   AuthorityKeyIdentifier = KeyIdentifierArray / KeyIdentifier
*/
fn parse_cbor_ext_auth_key_id(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AUTH_KEY_ID_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }

    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(lder_to_generic(raw_val.to_vec(), ASN1_INDEX_ZERO_EXT), ASN1_SEQ),
        Value::Array(array) => {
            let mut int_arr: Vec<Vec<u8>> = Vec::new();
            match array.get(0).unwrap() {
                //expecting key id bytes
                Value::Bytes(key_id) => {
                    trace!("parse_cbor_ext_auth_key_id, handle key_id: {:02x?}", key_id);
                    int_arr.push(lder_to_generic(key_id.to_vec(), ASN1_INDEX_ZERO_EXT));
                }
                _ => panic!("Error parsing value: {:?}.", array.get(0)),
            }
            match array.get(1).unwrap() {
                //expecting general names = array
                Value::Array(gen_names_arr) => {
                    trace!("parse_cbor_ext_auth_key_id, handle gen_names: {:02x?}", gen_names_arr);
                    int_arr.push(lder_to_generic(parse_cbor_general_name(array.get(1).unwrap()), ASN1_INDEX_ONE));
                }
                _ => panic!("Error parsing value: {:?}.", array.get(1)),
            }
            match array.get(2).unwrap() {
                //expecting authorityCertSerialNumber
                Value::Bytes(auth_serial) => {
                    trace!("parse_cbor_ext_auth_key_id, handle authority Cert Serial Number: {:02x?}", auth_serial);
                    int_arr.push(lder_to_generic(auth_serial.to_vec(), ASN1_INDEX_TWO_EXT));
                }
                _ => panic!("Error parsing value: {:?}.", array.get(0)),
            }
            lder_to_seq(int_arr)
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}

//***************************************************************************************************************************************
//***************************************************************************************************************************************
//EXT_EXT_KEY_USAGE = 8
fn parse_cbor_ext_ext_key_usage(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_EXT_KEY_USAGE_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let mut ext_val_arr = Vec::new();
    match extension_val {
        Value::Integer(key_purpose_id) => {
            ext_val_arr.push(map_key_purpose_id_to_oid(*key_purpose_id as u64));
        }
        Value::Array(elements) => {
            for element in elements {
                match element {
                    Value::Integer(key_purpose_id) => {
                        ext_val_arr.push(map_key_purpose_id_to_oid(*key_purpose_id as u64));
                    }
                    Value::Bytes(raw_val) => {
                        ext_val_arr.push(lder_to_generic(raw_val.to_vec(), ASN1_OID));
                        //todo, check handling of multiple OIDs
                    }
                    _ => panic!("Error parsing value: {:?}.", element),
                }
            }
        }
        Value::Bytes(raw_val) => {
            ext_val_arr.push(lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR));
        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    //lder_to_seq(ext_val_arr);
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(ext_val_arr), ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn map_key_purpose_id_to_oid(key_purpose_id: u64) -> Vec<u8> {
    match key_purpose_id {
        EKU_TLS_SERVER => EKU_TLS_SERVER_OID.to_der_vec().unwrap(),
        EKU_TLS_CLIENT => EKU_TLS_CLIENT_OID.to_der_vec().unwrap(),
        EKU_CODE_SIGNING => EKU_CODE_SIGNING_OID.to_der_vec().unwrap(),
        EKU_EMAIL_PROTECTION => EKU_EMAIL_PROTECTION_OID.to_der_vec().unwrap(),
        EKU_TIME_STAMPING => EKU_TIME_STAMPING_OID.to_der_vec().unwrap(),
        EKU_OCSP_SIGNING => EKU_OCSP_SIGNING_OID.to_der_vec().unwrap(),
        EKU_ANY_EKU => EKU_ANY_EKU_OID.to_der_vec().unwrap(),
        EKU_KERBEROS_PKINIT_CLIENT_AUTH => EKU_KERBEROS_PKINIT_CLIENT_AUTH_OID.to_der_vec().unwrap(),
        EKU_KERBEROS_PKINIT_KDC => EKU_KERBEROS_PKINIT_KDC_OID.to_der_vec().unwrap(),
        EKU_SSH_CLIENT => EKU_SSH_CLIENT_OID.to_der_vec().unwrap(),
        EKU_SSH_SERVER => EKU_SSH_SERVER_OID.to_der_vec().unwrap(),
        EKU_BUNDLE_SECURITY => EKU_BUNDLE_SECURITY_OID.to_der_vec().unwrap(),
        EKU_CMC_CERT_AUTHORITY => EKU_CMC_CERT_AUTHORITY_OID.to_der_vec().unwrap(),
        EKU_CMC_REG_AUTHORITY => EKU_CMC_REG_AUTHORITY_OID.to_der_vec().unwrap(),
        EKU_CMC_ARCHIVE_SERVER => EKU_CMC_ARCHIVE_SERVER_OID.to_der_vec().unwrap(),
        EKU_CMC_KEY_GEN_AUTHORITY => EKU_CMC_KEY_GEN_AUTHORITY_OID.to_der_vec().unwrap(),
        _ => panic!("Found unknown ext key usage code: {}", key_purpose_id),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
EXT_AUTH_INFO = 9
CDDL
AccessDescription = ( accessMethod: int / ~oid , uri: text )
AuthorityInfoAccessSyntax = [ + AccessDescription ]
*/

fn parse_cbor_ext_auth_info(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut result_vec = Vec::new();
    let mut oid = EXT_AUTH_INFO_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    match extension_val {
        Value::Array(elements) => {
            let mut wip = Vec::new();
            trace!("parse_cbor_ext_auth_info, handle {} and {}", elements.len(), elements.len() % 2);
            assert!(0 == (elements.len() % 2), "The AuthorityInfoAccessSyntax array must be of even length");
            for i in (0..elements.len()).step_by(2) {
                match elements.get(i).unwrap() {
                    Value::Integer(access_method) => {
                        //trace!("parse_cbor_ext_auth_info, access_method: {:02x?}", map_auth_info_id_to_oid(*access_method as i64));
                        wip.push(map_auth_info_id_to_oid(*access_method as i64));
                    }
                    Value::Bytes(raw_oid) => {
                        wip.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                        trace!("parse_cbor_ext_auth_info, handle raw bytes");
                    }
                    _ => {
                        panic!("Could not parse {:?}", elements.get(i));
                    }
                };
                match elements.get(i + 1).unwrap() {
                    Value::Text(qualifier) => {
                        trace!("parse_cbor_ext_auth_info, handle text {:02x?}", qualifier.as_bytes());
                        wip.push(lder_to_generic(qualifier.as_bytes().to_vec(), ASN1_URL));
                    }
                    _ => {
                        panic!("Could not parse {:?}", elements.get(i + 1))
                    }
                }
                result_vec.push(lder_to_seq(wip));
                wip = Vec::new();
            }
        }
        _ => {
            panic!("Could not parse {:?}", extension_val);
        }
    }
    lder_to_two_seq(oid, lder_to_generic(lder_to_seq(result_vec), ASN1_OCTET_STR))
}
fn map_auth_info_id_to_oid(access_method: i64) -> Vec<u8> {
    match access_method {
        INFO_OCSP => INFO_OCSP_OID.to_der_vec().unwrap(),
        INFO_CA_ISSUERS => INFO_CA_ISSUERS_OID.to_der_vec().unwrap(),
        INFO_TIME_STAMPING => INFO_TIME_STAMPING_OID.to_der_vec().unwrap(),
        INFO_CA_REPOSITORY => INFO_CA_REPOSITORY_OID.to_der_vec().unwrap(),
        INFO_RPKI_MANIFEST => INFO_RPKI_MANIFEST_OID.to_der_vec().unwrap(),
        INFO_SIGNED_OBJECT => INFO_SIGNED_OBJECT_OID.to_der_vec().unwrap(),
        INFO_RPKI_NOTIFY => INFO_RPKI_NOTIFY_OID.to_der_vec().unwrap(),
        _ => panic!("Found unknown access method code: {}", access_method),
    }
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
EXT_SCT_LIST = 10
https://letsencrypt.org/2018/04/04/sct-encoding.html
CDDL
SignedCerticateTimestamp = (
   logID: bytes,
   timestamp: int,
   sigAlg: AlgorithmIdentifier,
   sigValue: any,
   )
   SignedCertificateTimestamps = [ + SignedCerticateTimestamp ]

*/
fn parse_cbor_ext_sct_list(extension_val: &Value, critical: bool, ts_offset: i64) -> Vec<u8> {
    let mut ext_val_arr = Vec::new();
    let mut sct_size = 0;
    let mut total_tally = 0;
    let ts_os_ms = 1000 * ts_offset as i64;

    let mut oid = EXT_SCT_LIST_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }

    match extension_val {
        Value::Array(sct_array) => {
            //println!("CBOR array: {:02x?}", sct_array);

            for i in (0..sct_array.len()).step_by(4) {
                if 0 < i {
                    ext_val_arr.insert(total_tally, 0x00);
                    ext_val_arr.insert(total_tally + 1, sct_size as u8);
                    total_tally += sct_size + 2;
                    sct_size = 0;
                    trace!("parse_cbor_ext_sct_list, status after one loop {:02x?}", ext_val_arr);
                }
                match sct_array.get(i).unwrap() {
                    Value::Bytes(log_id) => {
                        trace!("parse_cbor_ext_sct_list, handle logID bytes {:02x?}", log_id);
                        ext_val_arr.push(0x00);
                        ext_val_arr.extend(log_id);
                        sct_size += 32 + 1; //same len assumption as in the encoding part
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i));
                    }
                }
                match sct_array.get(i + 1).unwrap() {
                    Value::Integer(ts) => {
                        trace!("parse_cbor_ext_sct_list, handle ts {} and notBefore {}", ts, ts_os_ms);
                        let o_ts = (*ts as i64) + ts_os_ms;
                        let b = o_ts.to_be_bytes();
                        ext_val_arr.extend(b);
                        sct_size += 8;
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i + 1));
                    }
                }
                match sct_array.get(i + 2).unwrap() {
                    Value::Integer(ai) => {
                        trace!("parse_cbor_ext_sct_list, handle sigAlg {}", ai);
                        if *ai as i64 != SIG_ECDSA_SHA256 {
                            panic!("Can only handle scts using SIG_ECDSA_SHA256");
                        }
                        ext_val_arr.extend(SCT_EXT_AID);
                        sct_size += 4;
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i + 2));
                    }
                }
                match sct_array.get(i + 3).unwrap() {
                    Value::Bytes(sig_val) => {
                        trace!("parse_cbor_ext_sct_list, reconstruct r+s, found sigVal bytes of len {}: {:02x?}", sig_val.len(), sig_val);
                        //let get = ;
                        let start_r_index = if sig_val[0] == 0 { 1 } else { 0 }; //TODO test more
                        let r = lder_to_pos_int(sig_val[start_r_index..sig_val.len() / 2].to_vec());
                        
                        let start_s_index = if sig_val[sig_val.len() / 2] == 0 { sig_val.len() / 2 + 1 } else { sig_val.len() / 2 }; 
                        let s_r = sig_val[start_s_index..sig_val.len()].to_vec();
                        let s = lder_to_pos_int(s_r.clone());

                        let seq = lder_to_two_seq(r, s);
                        trace!("parse_cbor_ext_sct_list, reconstruct r+s, after seq of len {}: {:02x?}", seq.len(), seq);
                        ext_val_arr.push(0x00);
                        ext_val_arr.push(seq.len() as u8); //TODO handle larger lens
                        ext_val_arr.extend(seq.clone());
                        sct_size += seq.len() + 2;
                    }
                    _ => {
                        panic!("Can't parse {:?}", sct_array.get(i + 3));
                    }
                }
            }
            ext_val_arr.insert(total_tally, 0x00); //the size field for the last 4-touple
            ext_val_arr.insert(total_tally + 1, sct_size as u8);

        }
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    ext_val_arr = lder_to_generic(lder_to_generic(sct_add_len(ext_val_arr), ASN1_OCTET_STR), ASN1_OCTET_STR);
    trace!("parse_cbor_ext_sct_list, reconstructed {:02x?}", ext_val_arr);

    lder_to_two_seq(oid, ext_val_arr)
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_subject_directory_attr(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_DIRECTORY_ATTR_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_subject_directory_attr not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
 EXT_ISSUER_ALT_NAME = 25; //0x12
*/
fn parse_cbor_ext_issuer_alt_name(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_ISSUER_ALT_NAME_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let empty_vec = Vec::new();
    let ext_val_arr = parse_cbor_name(&extension_val, &empty_vec);
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}

//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_name_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_NAME_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_name_constraints not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_policy_mappings(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_POLICY_MAPPINGS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_policy_mappings not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_policy_constraints(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_POLICY_CONSTRAINTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_policy_constraints not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_freshest_crl(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_FRESHEST_CRL_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_freshest_crl not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_inhibit_anypolicy(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_INHIBIT_ANYPOLICY_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_inhibit_anypolicy not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_subject_info_access(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_SUBJECT_INFO_ACCESS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_subject_info_access not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_ip_resources(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_IP_RESOURCES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_ip_resources not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_as_resources(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AS_RESOURCES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_as_resources not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_ip_resources_v2(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_IP_RESOURCES_V2_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_ip_resources_v2 not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_as_resources_v2(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_AS_RESOURCES_V2_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_as_resources_v2 not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_biometric_info(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_BIOMETRIC_INFO_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_biometric_info not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_precert_signing_cert(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_PRECERT_SIGNING_CERT_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_precert_signing_cert not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_ocsp_no_check(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_OCSP_NO_CHECK_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_ocsp_no_check not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_qualified_cert_statements(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_QUALIFIED_CERT_STATEMENTS_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_qualified_cert_statements not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_ext_s_mime_capabilities(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_S_MIME_CAPABILITIES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_s_mime_capabilities not implemented / tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
/*
 EXT_TLS_FEATURES = 41
 */
fn parse_cbor_ext_tls_features(extension_val: &Value, critical: bool) -> Vec<u8> {
    let mut oid = EXT_TLS_FEATURES_OID.to_der_vec().unwrap();
    if critical {
        oid.extend(ASN1_X509_CRITICAL.to_vec());
    }
    let  ext_val_arr = match extension_val {
        //Value::Bytes(raw_val) => lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR),
        Value::Bytes(raw_val) => raw_val.to_vec(), //TODO: check if always oct-wrapped
        _ => panic!("Error parsing value: {:?}.", extension_val),
    };
    print_str_warning("WARNING ext_tls_features not tested");
    lder_to_two_seq(oid, lder_to_generic(ext_val_arr, ASN1_OCTET_STR))
}
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//***************************************************************************************************************************************
//***************************************************************************************************************************************
fn parse_cbor_general_name_hw_module(hw_module: &Value) -> Vec<u8> {
    let mut outer_vec = Vec::new();
    outer_vec.push(OTHER_NAME_WITH_HW_MODULE_NAME_OID.to_der_vec().unwrap());

    let mut inner_vec = Vec::new();

    match hw_module {
        Value::Array(array) => {
            if let Value::Bytes(raw_oid) = &array[0] {
                inner_vec.push(lder_to_generic(raw_oid.to_vec(), ASN1_OID));
                if let Value::Bytes(raw_val) = &array[1] {
                    trace!("parse_cbor_general_name_hw_module, working with raw_val.to_vec() {:02x?}", raw_val.to_vec());
                    inner_vec.push(lder_to_generic(raw_val.to_vec(), ASN1_OCTET_STR));
                } else {
                    panic!("Error parsing inner value of: {:?}.", hw_module)
                }
            } else {
                panic!("Error parsing value: {:?}.", hw_module)
            }
            //TODO work is here
        }
        _ => panic!("Error parsing value: {:?}.", hw_module),
    };
    outer_vec.push(lder_to_generic(lder_to_seq(inner_vec), ASN1_INDEX_ZERO));
    lder_to_gen_seq(outer_vec, ASN1_INDEX_ZERO)
}