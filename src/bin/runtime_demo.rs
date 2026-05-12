use core::time::Duration;

use reticulum::runtime::{Runtime, TokioRuntime};

struct DemoTransport<R: Runtime> {
    rt: R,
}

impl<R: Runtime> DemoTransport<R> {
    fn new(rt: R) -> Self {
        let this = Self { rt: rt.clone() };
        this.spawn_background();
        this
    }

    fn spawn_background(&self) {
        let rt = self.rt.clone();

        rt.clone().spawn(async move {
            let rt = rt;
            loop {
                println!("demo_transport: tick");
                rt.sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let rt = TokioRuntime;

    // Start the demo transport; it will log a tick every second.
    let _demo = DemoTransport::new(rt);

    // Keep the process alive so we can see logs.
    // In a real app you would do more useful work here.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}
