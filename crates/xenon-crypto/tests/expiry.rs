// e.g.
// cargo test --package xenon-crypto --test expiry -- test_expiry_no_expiration --exact --nocapture 


use xenon_crypto::Expiry;

#[test]
fn test_expiry_no_expiration() {
    assert_eq!(Expiry::new(), Expiry::NO_EXPIRATION);

    assert_eq!(
        Expiry::new(),
        Expiry::try_from("0000/00/00".to_string()).unwrap(),
    );

    assert_eq!(
        Expiry::try_from("0000/00/00".to_string()).unwrap(),
        Expiry::NO_EXPIRATION
    );
}

#[test]
fn test_expiry_is_expired() {
    // The test: run on 2023/12/10.

    // true
    assert_eq!(
        Expiry::try_from("2023/12/10".to_string())
            .unwrap()
            .is_expired(),
        true
    );

    // false
    assert_eq!(
        Expiry::try_from("2023/12/01".to_string())
            .unwrap()
            .is_expired(),
        false
    );
}

#[test]
fn test_expiry_to_string() {
    let expiry = Expiry::try_from("2021/12/31".to_string()).unwrap();
    assert_eq!(expiry.to_string(), "2021/12/31".to_string());
}
