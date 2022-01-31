use crate::server::verify_packet_signature;
use crate::server::export_public_key_to_binary;
use crate::server::FennelServerPacket;
use crate::server::parse_packet;
use crate::rsa_tools::{generate_keypair, sign};

#[cfg(test)]
#[test]
fn target_parse_packet() {
    parse_packet([0; 3184]);
}

#[test]
fn test_verify_packet_signature() {
    let (private_key, public_key) = generate_keypair(8192);
    let signature = sign(private_key, [1; 1024].to_vec());
    let packet = FennelServerPacket {
        command: [0; 1],
        identity: [0; 32],
        fingerprint: [0; 32],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(public_key).unwrap(),
        recipient: [0; 32],
    };
    assert_eq!(verify_packet_signature(&packet), true);
}
