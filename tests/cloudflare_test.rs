use cloudflare::cloudflare::CloudflareSetup;
use mockito::Server;

#[tokio::test]
async fn test_create_cname() -> Result<(), Box<dyn std::error::Error>> {

    /*
    Test mocking Cloudflare API to verify CNAME record creation using fake server.
    */

    let mut server = Server::new_async().await;

    server
        .mock("GET", "/client/v4/zones?name=mock.com")
        .with_status(200)
        .with_body(r#"{"result":[{"id":"zone123"}]}"#)
        .create();

    let cf = CloudflareSetup::new(
        "fake_token".to_string(),
        "mock.com".to_string(),
        server.url(),
    );

    let result = cf.create_cname_records(&[("api", "target.com")]).await;

    assert!(result.is_ok());
    Ok(())

}