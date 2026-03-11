use log::{info, LevelFilter};
use simple_logger::SimpleLogger;

fn initialize_logger () {

    /*
    Initialize the needed dependencies app.
    */

    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .expect("An error ocurred on the initialization of logging system.");

    info!("Logging system initialized correctly.");

}

fn main() {

    /*
    Initialization point for the CDK.
    */

    initialize_logger();

}