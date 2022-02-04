use fennel_lib::{
    export_public_key_to_binary, generate_keypair, get_identity_database_handle,
    get_message_database_handle, sign,
};

use crate::server::{
    get_messages, send_message, submit_identity, verify_packet_signature, FennelServerPacket,
};
use std::sync::Arc;

#[cfg(test)]
#[test]
fn test_verify_packet_signature() {
    use fennel_lib::{export_public_key_to_binary, generate_keypair, sign};

    let (private_key, public_key) = generate_keypair(8192);
    let signature = sign(private_key, [1; 1024].to_vec());
    let packet = FennelServerPacket {
        command: [0; 1],
        identity: [0; 4],
        fingerprint: [0; 16],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 4],
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
        identity: [0; 4],
        fingerprint: [0; 16],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 4],
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
        identity: [0; 4],
        fingerprint: [0; 16],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 4],
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
        identity: [0; 4],
        fingerprint: [0; 16],
        message: [1; 1024],
        signature: signature.try_into().unwrap(),
        public_key: export_public_key_to_binary(&public_key).unwrap(),
        recipient: [0; 4],
    };
    assert_eq!(submit_identity(id_db, packet).await, &[0]);
    assert_eq!(send_message(db, packet).await, &[0]);
    let result: Vec<Vec<u8>> = get_messages(db_2, id_db_2, packet).await;
    assert_ne!(result.len(), 0);
}
