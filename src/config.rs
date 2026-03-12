/*
Config file for CDK setup.
*/

const DOMAIN: &str = "edgepython.com";

const BASE_DOMAIN: &str = "https://api.cloudflare.com";

const SUBDOMAINS: &[(&str, &str)] = &[
    ("infra", "github.com/dylan-sutton-chavez/edge-python_infrastructure/")
];

const CDN_SUBDOMAIN: &str = "cdn";