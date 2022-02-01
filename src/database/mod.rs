#[cfg(test)]
mod tests;

use crate::{rsa_tools::hash, types::Bytes};
use rocksdb::Error;
use rocksdb::IteratorMode;
use rocksdb::DB;
use std::sync::Arc;
use std::sync::Mutex;

pub struct Identity {
    pub id: [u8; 32],
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

impl From<&Identity> for Vec<u8> {
    fn from(identity: &Identity) -> Vec<u8> {
        [
            identity.id.as_slice(),
            identity.fingerprint.as_slice(),
            identity.public_key.as_slice(),
        ]
        .concat()
    }
}

// TODO: Maybe `TryFrom`?
impl From<Vec<u8>> for Identity {
    fn from(bytes: Vec<u8>) -> Identity {
        Identity {
            id: bytes[0..32].try_into().unwrap(),
            fingerprint: bytes[32..64].try_into().unwrap(),
            public_key: bytes[64..1102].try_into().unwrap(),
        }
    }
}

impl From<&Message> for Vec<u8> {
    fn from(msg: &Message) -> Vec<u8> {
        [
            msg.sender_id.as_slice(),
            msg.fingerprint.as_slice(),
            msg.message.as_slice(),
            msg.signature.as_slice(),
            msg.public_key.as_slice(),
            msg.recipient_id.as_slice(),
        ]
        .concat()
    }
}

// TODO: maybe `TryFrom`?
impl From<Vec<u8>> for Message {
    fn from(bytes: Vec<u8>) -> Message {
        Message {
            sender_id: bytes[0..32].try_into().unwrap(),
            fingerprint: bytes[32..64].try_into().unwrap(),
            message: bytes[64..1088].try_into().unwrap(),
            signature: bytes[1088..2112].try_into().unwrap(),
            public_key: bytes[2112..3150].try_into().unwrap(),
            recipient_id: bytes[3150..3182].try_into().unwrap(),
        }
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
    let message_bytes = Bytes::from(&message);
    let m: Vec<u8> = message
        .recipient_id
        .iter()
        .cloned()
        .chain(hash(&message_bytes))
        .collect();
    db.put(m, message_bytes).unwrap();
    Ok(())
}

/// Retrieve all messages for id. This is INCREDIBLY inefficient. We'll need to retool this.
pub fn retrieve_messages(db_lock: Arc<Mutex<DB>>, identity: Identity) -> Vec<Message> {
    let db = db_lock.lock().unwrap();
    let mut message_list: Vec<Message> = Vec::new();
    for (key, value) in db.iterator(IteratorMode::Start) {
        if key[0..32] == identity.id {
            message_list.push((*value).to_vec().try_into().unwrap());
        }
    }
    message_list
}

pub fn insert_identity(db_lock: Arc<Mutex<DB>>, identity: &Identity) -> Result<(), Error> {
    let db = db_lock.lock().unwrap();
    db.put::<_, Vec<_>>(identity.id, identity.into()).unwrap();
    Ok(())
}

pub fn retrieve_identity(db_lock: Arc<Mutex<DB>>, id: [u8; 32]) -> Identity {
    let db = db_lock.lock().unwrap();
    Identity::from(db.get(id).expect("failed to retrieve identity").unwrap())
}
