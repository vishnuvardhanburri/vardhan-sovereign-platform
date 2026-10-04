use core_crypto::aer_kep_q::{AER_KEY_LEN, AerKepQ, EpochStatus};

#[test]
fn encapsulate_and_decapsulate_round_trip_with_context_binding() {
    let mut receiver = AerKepQ::new("bank-a", 7).expect("epoch creation");
    let descriptor = receiver.descriptor().expect("active descriptor");

    let (ciphertext, sender_key) = AerKepQ::encapsulate(
        &descriptor,
        42,
        b"payment:12345",
    )
    .expect("encapsulation");

    let receiver_key = receiver
        .decapsulate(&ciphertext, 42, b"payment:12345")
        .expect("decapsulation");

    assert_eq!(sender_key, receiver_key);
    assert_eq!(sender_key.len(), AER_KEY_LEN);
}

#[test]
fn context_binding_rejects_mismatched_context() {
    let mut receiver = AerKepQ::new("bank-a", 7).expect("epoch creation");
    let descriptor = receiver.descriptor().expect("active descriptor");
    let (ciphertext, _) = AerKepQ::encapsulate(&descriptor, 9, b"context-a").unwrap();

    let first = receiver.decapsulate(&ciphertext, 9, b"context-b");
    assert!(first.is_err());
}

#[test]
fn quarantined_epoch_rejects_new_encapsulation_and_decapsulation() {
    let mut receiver = AerKepQ::new("bank-a", 7).expect("epoch creation");
    let descriptor = receiver.descriptor().expect("active descriptor");
    let (ciphertext, _) = AerKepQ::encapsulate(&descriptor, 10, b"payload").unwrap();

    receiver.quarantine().expect("quarantine");

    assert_eq!(receiver.status(), EpochStatus::Quarantined);
    assert!(receiver.descriptor().is_err());
    assert!(AerKepQ::encapsulate(&descriptor, 11, b"new").is_err());
    assert!(receiver.decapsulate(&ciphertext, 10, b"payload").is_err());
}

#[test]
fn replay_of_accepted_message_is_rejected() {
    let mut receiver = AerKepQ::new("bank-a", 7).expect("epoch creation");
    let descriptor = receiver.descriptor().unwrap();
    let (ciphertext, _) = AerKepQ::encapsulate(&descriptor, 99, b"once").unwrap();

    receiver.decapsulate(&ciphertext, 99, b"once").unwrap();
    assert!(receiver.decapsulate(&ciphertext, 99, b"once").is_err());
}
