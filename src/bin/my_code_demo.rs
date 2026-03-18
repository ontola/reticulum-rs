use reticulum::my_code::demo_transport::DemoTransport;
use reticulum::my_code::runtime_tokio::TokioRuntime;

#[tokio::main]
async fn main()
{
    env_logger::init();

    let rt = TokioRuntime;

    // Start the demo transport; it will log a tick every second.
    let _demo = DemoTransport::new(rt);

    // Keep the process alive so we can see logs.
    // In a real app you would do more useful work here.
    loop
    {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

