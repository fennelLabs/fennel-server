mod tests;

use crate::rsa_tools::hash;
use rocksdb::Error;
use rocksdb::IteratorMode;
use rocksdb::DB;
use std::sync::Arc;
use std::sync::Mutex;

pub struct Identity {
    pub identity_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub public_key: [u8; 1038],
}

pub struct Message {
    pub sender_id: [u8; 32],
    pub fingerprint: [u8; 32],
    pub message: [u8; 1024],
    pub signature: [u8; 1024],
    pub public_key: [u8; 1038],
    pub recipient_id: [u8; 32],
}

pub fn identity_to_bytes(identity: &Identity) -> Vec<u8> {
    identity
        .identity_id
        .iter()
        .cloned()
        .chain(
            identity
                .fingerprint
                .iter()
                .cloned()
                .chain(identity.public_key.iter().cloned()),
        )
        .collect()
}

pub fn bytes_to_identity(identity_bytes: Vec<u8>) -> Identity {
    Identity {
        identity_id: identity_bytes[0..32].try_into().unwrap(),
        fingerprint: identity_bytes[32..64].try_into().unwrap(),
        public_key: identity_bytes[64..1102].try_into().unwrap(),
    }
}

pub fn message_to_bytes(message: &Message) -> Vec<u8> {
    message
        .sender_id
        .iter()
        .cloned()
        .chain(
            message.fingerprint.iter().cloned().chain(
                message.message.iter().cloned().chain(
                    message.signature.iter().cloned().chain(
                        message
                            .public_key
                            .iter()
                            .cloned()
                            .chain(message.recipient_id.iter().cloned()),
                    ),
                ),
            ),
        )
        .collect()
}

pub fn bytes_to_message(message_bytes: Vec<u8>) -> Message {
    Message {
        sender_id: message_bytes[0..32].try_into().unwrap(),
        fingerprint: message_bytes[32..64].try_into().unwrap(),
        message: message_bytes[64..1088].try_into().unwrap(),
        signature: message_bytes[1088..2112].try_into().unwrap(),
        public_key: message_bytes[2112..3150].try_into().unwrap(),
        recipient_id: message_bytes[3150..3182].try_into().unwrap(),
    }
}

pub fn get_message_database_handle() -> Arc<Mutex<DB>> {
    Arc::new(Mutex::new(DB::open_default("./message.db").unwrap()))
}

pub fn get_identity_database_handle() -> Arc<Mutex<DB>> {
    Arc::new(Mutex::new(DB::open_default("./identity.db").unwrap()))
}

pub fn insert_message(db_lock: Arc<Mutex<DB>>, message: Message) -> Result<(), Error> {
    let db = db_lock.lock().unwrap();
    let message_bytes = message_to_bytes(&message);
    let m: Vec<u8> = message
        .recipient_id
        .iter()
        .cloned()
        .chain(hash(&message_bytes))
        .collect();
    db.put(m, message_bytes).unwrap();
    Ok(())
}

/// Retrieve all messages for identity_id. This is INCREDIBLY inefficient. We'll need to retool this.
pub fn retrieve_messages(db_lock: Arc<Mutex<DB>>, identity: Identity) -> Vec<Message> {
    let db = db_lock.lock().unwrap();
    let mut message_list: Vec<Message> = Vec::new();
    for (key, value) in db.iterator(IteratorMode::Start) {
        if key[0..32] == identity.identity_id {
            message_list.push(bytes_to_message((*value).try_into().unwrap()));
        }
    }
    message_list
}

pub fn insert_identity(db_lock: Arc<Mutex<DB>>, identity: &Identity) -> Result<(), Error> {
    let db = db_lock.lock().unwrap();
    db.put(identity.identity_id, identity_to_bytes(identity))
        .unwrap();
    Ok(())
}

pub fn retrieve_identity(db_lock: Arc<Mutex<DB>>, identity_id: [u8; 32]) -> Identity {
    let db = db_lock.lock().unwrap();
    bytes_to_identity(
        db.get(identity_id)
            .expect("failed to retrieve identity")
            .unwrap(),
    )
}
