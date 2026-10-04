use core_crypto::QuantumNodeIdentity;

#[path = "../aer_kep_q.rs"]
mod aer_kep_q;

fn main() {
    let node_a = QuantumNodeIdentity::generate_node_identity().unwrap();
    let receiver = aer_kep_q::AerKepQ::new("smoke", 1).expect("epoch");
    let descriptor = receiver.descriptor(&node_a).expect("descriptor");
    let dsa_pub = node_a.dsa_public_key_bytes();
    
    let (ciphertext, sender_key) =
        aer_kep_q::AerKepQ::encapsulate(&descriptor, &dsa_pub, 1, b"smoke-context").expect("encapsulate");
    let mut receiver = receiver;
    let receiver_key = receiver
        .decapsulate(&ciphertext, 1, b"smoke-context")
        .expect("decapsulate");
    assert_eq!(sender_key, receiver_key);
}
