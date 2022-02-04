#![feature(test)]

extern crate fennel_lib;

mod server;

use fennel_lib::{get_identity_database_handle, get_message_database_handle};
use server::*;
use std::sync::Arc;
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").await.unwrap();
    let identity_db = get_identity_database_handle();
    let message_db = get_message_database_handle();
    while let Ok((stream, _address)) = listener.accept().await {
        let clone_identity_db = Arc::clone(&identity_db);
        let clone_message_db = Arc::clone(&message_db);
        tokio::spawn(handle_connection(
            clone_identity_db,
            clone_message_db,
            stream,
        ));
    }
}
