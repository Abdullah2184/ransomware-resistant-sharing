use std::{env, process::ExitCode, time::Duration};

const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:8080";

#[tokio::main]
async fn main() -> ExitCode {
    match run(env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rrds: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [command] if command == "health" => {
            let base_url = env::var("GATEWAY_URL").unwrap_or_else(|_| DEFAULT_GATEWAY_URL.into());
            check_gateway_health(&base_url).await
        }
        [command, base_url] if command == "health" => check_gateway_health(base_url).await,
        [command] if command == "--help" || command == "-h" => {
            print_help();
            Ok(())
        }
        [] => {
            print_help();
            Err("a command is required".into())
        }
        [command, ..] if command != "health" => {
            Err(format!("unknown command `{command}`; run `rrds --help`"))
        }
        _ => Err("usage: rrds health [gateway-url]".into()),
    }
}

async fn check_gateway_health(base_url: &str) -> Result<(), String> {
    let url = health_url(base_url)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "could not initialize the HTTP client".to_owned())?;
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|_| "could not reach the configured gateway health endpoint".to_owned())?;

    if response.status().is_success() {
        println!("gateway healthy ({})", response.status());
        Ok(())
    } else {
        Err(format!(
            "gateway health check returned {}",
            response.status()
        ))
    }
}

fn health_url(base_url: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(base_url)
        .map_err(|_| "gateway URL must be a valid absolute HTTP or HTTPS URL".to_owned())?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("gateway URL must include an HTTP or HTTPS host".into());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("gateway URL must not contain credentials, a query, or a fragment".into());
    }

    let path = format!("{}/healthz", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url.to_string())
}

fn print_help() {
    println!(
        "Usage:\n  rrds health [gateway-url]\n\nChecks the configured gateway health endpoint.\n\nEnvironment:\n  GATEWAY_URL  Gateway base URL (default: {DEFAULT_GATEWAY_URL})"
    );
}

#[cfg(test)]
mod tests {
    use super::health_url;

    #[test]
    fn builds_health_url_from_gateway_base_url() {
        assert_eq!(
            health_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080/healthz"
        );
    }

    #[test]
    fn rejects_gateway_urls_without_http_scheme_or_host() {
        assert!(health_url("127.0.0.1:8080").is_err());
        assert!(health_url("http://").is_err());
        assert!(health_url("https://").is_err());
        assert!(health_url("http://gateway/?secret=value").is_err());
        assert!(health_url("http://user:password@gateway").is_err());
    }
}
