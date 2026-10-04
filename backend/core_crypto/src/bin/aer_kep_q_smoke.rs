#[path = "../aer_kep_q.rs"]
mod aer_kep_q;

fn main() {
    let receiver = aer_kep_q::AerKepQ::new("smoke", 1).expect("epoch");
    let descriptor = receiver.descriptor().expect("descriptor");
    let (ciphertext, sender_key) =
        aer_kep_q::AerKepQ::encapsulate(&descriptor, 1, b"smoke-context").expect("encapsulate");
    let mut receiver = receiver;
    let receiver_key = receiver
        .decapsulate(&ciphertext, 1, b"smoke-context")
        .expect("decapsulate");
    assert_eq!(sender_key, receiver_key);
}
