#[cfg(test)]
use crate::get_identity_database_handle;
use crate::database::insert_identity;
use crate::database::retrieve_identity;
use crate::database::bytes_to_identity;
use crate::database::bytes_to_message;
use crate::database::insert_message;
use crate::database::message_to_bytes;
use crate::database::retrieve_messages;
use crate::database::Message;
use crate::database::{get_message_database_handle, identity_to_bytes, Identity};
use std::sync::Arc;

#[test]
fn test_identity_to_bytes() {
    identity_to_bytes(
        &(Identity {
            identity_id: [0; 32],
            fingerprint: [0; 32],
            public_key: [0; 1038],
        }),
    );
}

#[test]
fn test_bytes_to_identity() {
    let id: Identity = Identity {
        identity_id: [0; 32],
        fingerprint: [0; 32],
        public_key: [0; 1038],
    };
    let idn: Identity = bytes_to_identity(identity_to_bytes(&id));
    assert_eq!(id.identity_id, idn.identity_id);
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
    message_to_bytes(&msg);
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
    let msgn: Message = bytes_to_message(message_to_bytes(&msg));
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
            identity_id: [0; 32],
            fingerprint: [0; 32],
            public_key: [0; 1038],
        },
    );
    assert_eq!(result.len(), 1)
}

#[test]
fn test_insert_and_retrieve_identity() {
    let db = get_identity_database_handle();
    let db_2 = Arc::clone(&db);
    let identity: Identity = Identity {
        identity_id: [0; 32],
        fingerprint: [0; 32],
        public_key: [0; 1038],
    };
    insert_identity(db, &identity).expect("failed identity insertion");
    let result: Identity = retrieve_identity(
        db_2,
        [0; 32]
    );
    assert_eq!(identity.identity_id, result.identity_id);
    assert_eq!(identity.fingerprint, result.fingerprint);
    assert_eq!(identity.public_key, result.public_key);
}
