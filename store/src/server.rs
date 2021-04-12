
use sequoia_ipc::Server;

fn main() {
    let ctx = Server::context()
        .expect("Failed to create context");
    Server::new(sequoia_store::descriptor(&ctx))
        .expect("Failed to create server")
        .serve()
        .expect("Failed to start server");
}
