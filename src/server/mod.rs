#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use fennel_lib::{
    import_public_key_from_binary, insert_identity, insert_message, retrieve_identity,
    retrieve_messages, verify, FennelServerPacket, Identity, Message,
};
use rocksdb::DB;
use std::sync::{Arc, Mutex};
use tokio::{io::*, net::TcpStream};

pub async fn handle_connection(
    identity_db: Arc<Mutex<DB>>,
    message_db: Arc<Mutex<DB>>,
    mut stream: TcpStream,
) -> Result<()> {
    println!("begin handling new connection");
    let mut buffer = [0; 4137];
    stream.read_exact(&mut buffer).await.unwrap();
    println!("received a packet");
    let server_packet: FennelServerPacket = Decode::decode(&mut (buffer.as_slice())).unwrap();
    println!("packet decoded successfully");
    if !verify_packet_signature(&server_packet) {
        panic!("packet signature failed to verify");
    } else {
        println!("packet signature verified successfully");
    }
    if server_packet.command == [0] {
        let r = submit_identity(identity_db, server_packet).await;
        stream.write_all(r).await?;
        stream.write_all(&[0]).await?;
    } else if server_packet.command == [1] {
        let r = send_message(message_db, server_packet).await;
        stream.write_all(r).await?;
        stream.write_all(&[0]).await?;
    } else if server_packet.command == [2] {
        let r_list = get_messages(message_db, identity_db, server_packet).await;
        for r in r_list {
            stream.write_all(&[1]).await?;
            stream.write_all(&r).await?;
        }
        stream.write_all(&[0]).await?;
    } else {
        stream.write_all(&[0]).await?;
    }

    Ok(())
}

fn verify_packet_signature(packet: &FennelServerPacket) -> bool {
    let pub_key =
        import_public_key_from_binary(&packet.public_key).expect("public key failed to import");
    verify(pub_key, packet.message.to_vec(), packet.signature.to_vec())
}

async fn submit_identity(db: Arc<Mutex<DB>>, packet: FennelServerPacket) -> &'static [u8] {
    let r = insert_identity(
        db,
        &(Identity {
            id: packet.identity,
            fingerprint: packet.fingerprint,
            public_key: packet.public_key,
        }),
    );
    match r {
        Ok(_) => &[0],
        Err(_) => &[1],
    }
}

async fn send_message(db: Arc<Mutex<DB>>, packet: FennelServerPacket) -> &'static [u8] {
    let r = insert_message(
        db,
        Message {
            sender_id: packet.identity,
            fingerprint: packet.fingerprint,
            message: packet.message,
            signature: packet.signature,
            public_key: packet.public_key,
            recipient_id: packet.recipient,
        },
    );
    match r {
        Ok(_) => &[0],
        Err(_) => &[1],
    }
}

async fn get_messages(
    messages_db: Arc<Mutex<DB>>,
    identity_db: Arc<Mutex<DB>>,
    packet: FennelServerPacket,
) -> Vec<Vec<u8>> {
    let messages = retrieve_messages(messages_db, retrieve_identity(identity_db, packet.identity));
    let mut result: Vec<Vec<u8>> = Vec::new();
    for message in messages {
        result.push(message.encode());
    }
    result
}
