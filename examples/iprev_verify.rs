use std::{net::IpAddr, str::FromStr, sync::Arc};

use mail_auth::{IprevResult, MessageAuthenticator, Parameters};

/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */
#[tokio::main]
async fn main() {
    // Create an authenticator using Cloudflare DNS
    let authenticator = MessageAuthenticator::new_cloudflare().unwrap();
    //Letsencrypt IP
    let ip = IpAddr::from_str("54.215.62.21").unwrap();
    // Verify IPREV identity
    let result = authenticator
        .verify_iprev(Parameters::new(ip))
        .await;
    assert_eq!(result.result,IprevResult::Pass);
    assert_eq!(result.ptr,Some(Arc::new(vec!["ec2-54-215-62-21.us-west-1.compute.amazonaws.com.".to_string()])));
    //Fake letsencrypt IP
    let ip = IpAddr::from_str("8.8.8.8").unwrap();
    // Verify IPREV identity
    let result = authenticator
        .verify_iprev(Parameters::new(ip))
        .await;
    assert_eq!(result.result,IprevResult::Pass);
    assert_ne!(result.ptr,Some(Arc::new(vec!["ec2-54-215-62-21.us-west-1.compute.amazonaws.com.".to_string()])));
        //Fake letsencrypt IP
    let ip = IpAddr::from_str("141.95.150.143").unwrap();
    // Verify IPREV identity
    let result = authenticator
        .verify_iprev(Parameters::new(ip))
        .await;
    assert_ne!(result.result,IprevResult::Pass);
}