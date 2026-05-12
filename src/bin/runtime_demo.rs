#[tokio::main]
async fn main() {
    env_logger::init();

    tokio::spawn(async {
        loop {
            println!("runtime_demo: tick");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    });

    // Keep the process alive so we can see logs.
    // In a real app you would do more useful work here.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
