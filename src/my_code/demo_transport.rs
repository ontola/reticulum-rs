use core::time::Duration;

use crate::my_code::runtime::Runtime;

/// Very small demo transport that shows how to depend on a generic Runtime.
///
/// It just spawns a background task that prints a log line every second.
pub struct DemoTransport<R: Runtime>
{
    rt: R,
}

impl<R: Runtime> DemoTransport<R>
{
    pub fn new(rt: R) -> Self
    {
        let this = Self { rt: rt.clone() };
        this.spawn_background();
        this
    }

    fn spawn_background(&self)
    {
        let rt = self.rt.clone();

        rt.clone().spawn(async move
        {
            let rt = rt;
            loop
            {
                println!("demo_transport: tick");
                rt.sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

