mod database;
mod rsa_tools;
mod server;

use server::*;
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").await.unwrap();
    while let Ok((stream, _address)) = listener.accept().await {
        tokio::spawn(handle_connection(stream));
    }
}
