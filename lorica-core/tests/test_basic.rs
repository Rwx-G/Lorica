// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod utils;

// Lorica: every reqwest client here is handed its TLS configuration by
// `lorica_tls::http_client`, which reqwest 0.13 needs (see FORK.md,
// "reqwest 0.13 on a preconfigured TLS configuration").

#[cfg(all(unix, feature = "any_tls"))]
use hyper_util::client::legacy::Client;
#[cfg(all(unix, feature = "any_tls"))]
use hyperlocal::{UnixClientExt, UnixConnector, Uri};

#[tokio::test]
async fn test_http() {
    utils::init();
    let res = lorica_tls::http_client::client_builder(
        lorica_tls::http_client::public().expect("trust roots"),
    )
    .build()
    .unwrap()
    .get("http://127.0.0.1:6145")
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[cfg(feature = "any_tls")]
#[tokio::test]
async fn test_https_http2() {
    utils::init();

    let client = lorica_tls::http_client::client_builder(lorica_tls::http_client::offering_http2(
        lorica_tls::http_client::unverified(),
    ))
    .build()
    .unwrap();

    let res = client.get("https://127.0.0.1:6146").send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(res.version(), reqwest::Version::HTTP_2);

    let client = lorica_tls::http_client::client_builder(lorica_tls::http_client::unverified())
        .http1_only()
        .build()
        .unwrap();

    let res = client.get("https://127.0.0.1:6146").send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(res.version(), reqwest::Version::HTTP_11);
}

#[cfg(unix)]
#[cfg(feature = "any_tls")]
#[tokio::test]
async fn test_uds() {
    utils::init();
    let url = Uri::new("/tmp/echo.sock", "/").into();
    let client: Client<UnixConnector, String> = Client::unix();

    let res = client.get(url).await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
}

#[cfg(feature = "any_tls")]
#[tokio::test]
async fn test_h1_tls_with_h2c_enabled() {
    utils::init();

    let client = lorica_tls::http_client::client_builder(lorica_tls::http_client::unverified())
        .http1_only()
        .build()
        .unwrap();

    let res = client.get("https://127.0.0.1:6161").send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(res.version(), reqwest::Version::HTTP_11);
}

#[cfg(feature = "any_tls")]
#[tokio::test]
async fn test_h2_tls_with_h2c_enabled() {
    utils::init();

    let client = lorica_tls::http_client::client_builder(lorica_tls::http_client::offering_http2(
        lorica_tls::http_client::unverified(),
    ))
    .build()
    .unwrap();

    let res = client.get("https://127.0.0.1:6161").send().await.unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(res.version(), reqwest::Version::HTTP_2);
}

#[tokio::test]
async fn test_h2c_tcp_still_works() {
    utils::init();

    let res = lorica_tls::http_client::client_builder(
        lorica_tls::http_client::public().expect("trust roots"),
    )
    .build()
    .unwrap()
    .get("http://127.0.0.1:6160")
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::OK);
    assert_eq!(res.version(), reqwest::Version::HTTP_11);
}
