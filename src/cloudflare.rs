use serde_json::json;
use reqwest::Client;
use log::{info, error};

pub struct CloudflareSetup {

    /*
    Structure that contains the `CF_TOKEN` and cloudflare client.
    */

    token: String,
    client: Client,
    domain: String,
    base: String

}

impl CloudflareSetup {

    pub fn new(token: String, domain: String, base: String) -> Self {

        /*
        Create a implementation instance using the cloudflare setup structure.
        */

        Self { token, domain, base, client: Client::new() }

    }

    async fn get_json(&self, url: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        
        /*
        Get a JSON using a get method, `CF_TOKEN`, asynchronous and JSON format.
        */

        Ok(self.client.get(url).bearer_auth(&self.token).send().await?.json().await?)

    }

    async fn obtain_zone_id(&self) -> Result<String, Box<dyn std::error::Error>> {

        /*
        Obtain the zone id asigned by cloudflare to the domain.
        */

        let res = self.get_json(&format!("{}/client/v4/zones?name={}", &self.base, &self.domain)).await?;

        Ok(res["result"][0]["id"].as_str().ok_or("Zone not found")?.to_string())

    }

    pub async fn create_cname_records(&self, subdomains: &[(&str, &str)]) -> Result<(), Box<dyn std::error::Error>> {

        /*
        Create a CNAME proxied for each subdomain on config list.
        */

        let zone_id = self.obtain_zone_id().await?;

        for (sub, target) in subdomains {

            let full_name = format!("{sub}.{}", &self.domain);

            let body = json!({ "type" : "CNAME", "name" : full_name, "content" : target, "ttl" : 120, "proxied" : true });

            let url = format!("{}/client/v4/zones/{zone_id}/dns_records", &self.base);

            let res = self.client.post(&url).bearer_auth(&self.token).json(&body).send().await?;
            let status = res.status();

            if status.is_success() {

                info!("CNAME proxied created; {full_name} -> {target}.");

            } 
            
            else {

                error!("An error has occurred creating {full_name}: status {status}.");
            
            }

        }

        Ok(())
    
    }
}

/*
Docs:

use config::{DOMAIN, SUBDOMAINS};

let base = "https://api.cloudflare.com".to_string();

let token = std::env::var("CF_TOKEN")?;
CloudflareSetup::new(token, DOMAIN.to_string(), base).create_cname_records(SUBDOMAINS).await?;
*/