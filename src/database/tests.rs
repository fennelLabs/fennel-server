use crate::database::*;
use std::sync::Arc;

use crate::{types::Bytes, get_identity_database_handle};

#[test]
fn test_identity_to_bytes() {
    let ident = Identity {
        id: [0; 32],
        fingerprint: [0; 32],
        public_key: [0; 1038],
    };
    let vec: Vec<u8> = (&ident).into();
}

#[test]
fn test_bytes_to_identity() {
    let id: Identity = Identity {
        id: [0; 32],
        fingerprint: [0; 32],
        public_key: [0; 1038],
    };
    let idn: Identity = Identity::from(Bytes::from(&id));
    assert_eq!(id.id, idn.id);
}

#[test]
fn test_message_to_bytes() {
    let msg: Message = Message {
        sender_id: [0; 32],
        fingerprint: [0; 32],
        message: [0; 1024],
        signature: [0; 1024],
        public_key: [0; 1038],
        recipient_id: [0; 32],
    };
    Bytes::from(&msg);
}

#[test]
fn test_bytes_to_message() {
    let msg: Message = Message {
        sender_id: [0; 32],
        fingerprint: [0; 32],
        message: [0; 1024],
        signature: [0; 1024],
        public_key: [0; 1038],
        recipient_id: [0; 32],
    };
    let msgn: Message = Message::from(Bytes::from(&msg));
    assert_eq!(msg.sender_id, msgn.sender_id);
}

#[test]
fn test_insert_and_retrieve_message() {
    let db = get_message_database_handle();
    let db_2 = Arc::clone(&db);
    insert_message(
        db,
        Message {
            sender_id: [0; 32],
            fingerprint: [0; 32],
            message: [0; 1024],
            signature: [0; 1024],
            public_key: [0; 1038],
            recipient_id: [0; 32],
        },
    )
    .expect("failed message insertion");
    let result: Vec<Message> = retrieve_messages(
        db_2,
        Identity {
            id: [0; 32],
            fingerprint: [0; 32],
            public_key: [0; 1038],
        },
    );
    assert_ne!(result.len(), 0);
}

#[test]
fn test_insert_and_retrieve_identity() {
    let db = get_identity_database_handle();
    let db_2 = Arc::clone(&db);
    let identity: Identity = Identity {
        id: [0; 32],
        fingerprint: [0; 32],
        public_key: [0; 1038],
    };
    insert_identity(db, &identity).expect("failed identity insertion");
    let result: Identity = retrieve_identity(db_2, [0; 32]);
    assert_eq!(identity.id, result.id);
    assert_eq!(identity.fingerprint, result.fingerprint);
    assert_eq!(identity.public_key, result.public_key);
}
