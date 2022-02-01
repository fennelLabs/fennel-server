use crate::get_identity_database_handle;
use crate::get_message_database_handle;
use crate::rsa_tools::{generate_keypair, sign};
use crate::server::export_public_key_to_binary;
use crate::server::get_messages;
use crate::server::parse_packet;
use crate::server::send_message;
use crate::server::submit_identity;
use crate::server::verify_packet_signature;
use crate::server::FennelServerPacket;
use std::sync::Arc;

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
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 32],
    };
    assert_eq!(verify_packet_signature(&packet), true);
}

#[tokio::test]
async fn test_submit_identity() {
    let (private_key, public_key) = generate_keypair(8192);
    let signature = sign(private_key, [1; 1024].to_vec());
    let db = get_identity_database_handle();
    let packet = FennelServerPacket {
        command: [0; 1],
        identity: [0; 32],
        fingerprint: [0; 32],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 32],
    };
    assert_eq!(submit_identity(db, packet).await, &[0]);
}

#[tokio::test]
async fn test_send_message() {
    let (private_key, public_key) = generate_keypair(8192);
    let signature = sign(private_key, [1; 1024].to_vec());
    let db = get_message_database_handle();
    let packet = FennelServerPacket {
        command: [0; 1],
        identity: [0; 32],
        fingerprint: [0; 32],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 32],
    };
    assert_eq!(send_message(db, packet).await, &[0]);
}

#[tokio::test]
async fn test_get_messages() {
    let (private_key, public_key) = generate_keypair(8192);
    let signature = sign(private_key, [1; 1024].to_vec());
    let db = get_message_database_handle();
    let id_db = get_identity_database_handle();
    let db_2 = Arc::clone(&db);
    let id_db_2 = Arc::clone(&id_db);
    let packet = FennelServerPacket {
        command: [0; 1],
        identity: [0; 32],
        fingerprint: [0; 32],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 32],
    };
    assert_eq!(submit_identity(id_db, packet).await, &[0]);
    assert_eq!(send_message(db, packet).await, &[0]);
    let result: Vec<[u8; 3169]> = get_messages(db_2, id_db_2, packet).await;
    assert_ne!(result.len(), 0);
}
