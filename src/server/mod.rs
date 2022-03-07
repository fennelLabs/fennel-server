#[cfg(test)]
mod tests;

use codec::{Decode, Encode};
use fennel_lib::{
    hash, import_public_key_from_binary, insert_identity, insert_message, retrieve_identity,
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
    let mut buffer = [0; 3111];
    stream.read_exact(&mut buffer).await.unwrap();
    println!("received a packet");
    let server_packet: FennelServerPacket = Decode::decode(&mut (buffer.as_slice())).unwrap();
    println!("packet decoded successfully");
    if !verify_packet_signature(&server_packet) {
        stream.write_all(&[9]).await?;
    } else {
        println!("packet signature verified successfully");
        if server_packet.command == [0] {
            let r = submit_identity(identity_db, server_packet).await;
            stream.write_all(r).await?;
        } else if server_packet.command == [1] {
            let r = send_message(message_db, server_packet).await;
            stream.write_all(r).await?;
        } else if server_packet.command == [2] {
            let r_list = get_messages(message_db, identity_db, server_packet).await;
            let mut length: u8 = r_list.len().try_into().unwrap();
            let mut it = r_list.into_iter().peekable();
            stream.write_all(&[length]).await?;
            while let Some(r) = it.next() {
                println!("{} messages remaining", length);
                length -= 1;
                if it.peek().is_none() {
                    stream.write_all(&[0]).await?;
                } else {
                    stream.write_all(&[length]).await?;
                }
                let mut client_hash: [u8; 64] = [0; 64];
                let server_hash: [u8; 64] = hash(&r).try_into().unwrap();
                stream.write_all(&server_hash).await?;
                stream.write_all(&r).await?;
                stream.read_exact(&mut client_hash).await?;
                if client_hash == server_hash {
                    stream.write_all(&[0]).await?;
                } else {
                    stream.write_all(&[1]).await?;
                }
            }
            stream.write_all(&[97]).await?;
            println!("messages sent successfully");
        } else {
            stream.write_all(&[0]).await?;
        }
    }

    println!("thread exited");

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
            shared_secret_key: [0; 32],
        }),
    );
    match r {
        Ok(_) => &[0],
        Err(_) => &[1],
    }
}

async fn send_message(db: Arc<Mutex<DB>>, packet: FennelServerPacket) -> &'static [u8] {
    if verify(
        import_public_key_from_binary(&packet.public_key).unwrap(),
        packet.message.to_vec(),
        packet.signature.to_vec(),
    ) {
        println!("message sender is valid");
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
    } else {
        println!("message sender signature failed to verify");
        &[1]
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
        if verify(
            import_public_key_from_binary(&message.public_key).unwrap(),
            message.message.to_vec(),
            message.signature.to_vec(),
        ) {
            result.push(message.encode());
        }
    }
    result
}
