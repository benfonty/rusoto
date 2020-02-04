
//! The Credentials provider from Cognito.

use futures::{
    Async, 
    Future, 
    Poll
};

use rusoto_core::{
    Region,
    RusotoFuture
};

use rusoto_core::credential::{
    AwsCredentials, 
    CredentialsError,
    ProvideAwsCredentials,
    StaticProvider
};

use crate::generated::{
    GetCredentialsForIdentityInput,
    CognitoIdentityClient,
    GetCredentialsForIdentityResponse,
    CognitoIdentity,
    GetCredentialsForIdentityError
};

use chrono::{
    offset::Utc,
    DateTime,
    NaiveDateTime
};

use std::collections::HashMap;

/// Provides AWS credentials from aws Cognito.
///
/// # Example TODO
///
/// ```rust
/// 
/// ```
#[derive(Debug, Clone)]
pub struct CognitoProvider {
    identity_id: String,
    region: Region,
    logins: Option<HashMap<String, String>>
}

#[derive(Default)]
pub struct CognitoProviderBuilder {
    identity_id: Option<String>,
    region: Option<Region>,
    logins: Option<HashMap<String, String>>
}

impl CognitoProviderBuilder {
    pub fn build(self) -> CognitoProvider { 
        CognitoProvider {
            identity_id: self.identity_id.expect("no identity id provided"),
            region: self.region.unwrap_or(Region::default()),
            logins: self.logins
        }
    }

    pub fn identity_id(mut self, identity_id: String)-> Self {
        self.identity_id = Some(identity_id);
        self
    }

    pub fn region(mut self, region: Region)-> Self {
        self.region = Some(region);
        self
    }

    pub fn login(mut self, provider: String, token: String)-> Self {
        if self.logins == None {
            self.logins = Some(HashMap::new());
        }
        self.logins.as_mut().unwrap().insert(provider, token);
        self
    }
}

impl CognitoProvider {

    pub fn builder() -> CognitoProviderBuilder {
        CognitoProviderBuilder::default()
    }

    fn credentials_from_cognito(&self) -> Result<RusotoFuture<GetCredentialsForIdentityResponse, GetCredentialsForIdentityError>, CredentialsError> {
        let client = CognitoIdentityClient::new_with(
            rusoto_core::request::HttpClient::new().map_err(|e| CredentialsError::new(format!("{:?}", e)))?,
            StaticProvider::from(AwsCredentials::default()),
            self.region.clone()
        );
        let input = GetCredentialsForIdentityInput {
            identity_id: self.identity_id.clone(),
            logins: self.logins.clone(),
            ..Default::default()
        };
        
        Ok(client.get_credentials_for_identity(input))
    }
}

/// Future returned from `CognitoProvider`.
pub struct CognitoProviderFuture {
    inner: CognitoProviderFutureInner,
}

enum CognitoProviderFutureInner {
    Result(Result<GetCredentialsForIdentityResponse, CredentialsError>),
    Future(RusotoFuture<GetCredentialsForIdentityResponse, GetCredentialsForIdentityError>),
}

impl Future for CognitoProviderFuture {
    type Item = AwsCredentials;
    type Error = CredentialsError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        println!("poll");
        match self.inner {
            CognitoProviderFutureInner::Result(ref mut result) => {
               match result {
                   Err(err) => Err(CredentialsError::new(format!(
                        "StsProvider get_session_token error: {:?}",
                        err
                    ))),
                    Ok(_) => panic!("not possible")
               }
            },
            CognitoProviderFutureInner::Future(ref mut future) => {
                println!("toto");
                match future.poll() {
                    Ok(Async::Ready(resp)) => {
                        println!("tot");
                        let creds = resp.credentials.ok_or(CredentialsError::new("no credentials were found in the response"))?;
        
                        Ok(Async::Ready(
                            AwsCredentials::new(
                                creds.access_key_id.ok_or(CredentialsError::new("no access key id was found in the response"))?, 
                                creds.secret_key.ok_or(CredentialsError::new("no secret key was found in the response"))?, 
                                creds.session_token, 
                                creds.expiration.map(|x| DateTime::from_utc(NaiveDateTime::from_timestamp(x as i64, 0), Utc)) 
                            )
                        ))
                    },
                    Ok(Async::NotReady) => {
                        println!("tota");
                        Ok(Async::NotReady)
                    },
                    Err(err) => {
                        println!("err");
                        Err(CredentialsError::new(format!("{:?}",err)))
                },
                }
            },
        }
        
    }
}

impl ProvideAwsCredentials for CognitoProvider {
    type Future = CognitoProviderFuture;

    fn credentials(&self) -> Self::Future {
        println!("call to credentuials");
        let inner = match self.credentials_from_cognito() {
            Ok(future) => CognitoProviderFutureInner::Future(future),
            Err(e) => CognitoProviderFutureInner::Result(Err(e)),
        };
        CognitoProviderFuture { inner }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
        
    #[test]
    #[should_panic(expected = "no identity id provided")]
    fn builder_empty() {
        CognitoProvider::builder().build();
    }

    #[test]
    #[should_panic(expected = "no identity id provided")]
    fn builder_no_identity_id() {
        CognitoProvider::builder()
        .login("provider".to_string(), "token".to_string())
        .build();
    }

    #[test]
    fn builder_simple() {
        let provider = CognitoProvider::builder().identity_id("id_id".to_string()).build();
        assert_eq!(provider.identity_id, "id_id");
        assert_eq!(provider.region, Region::default());
        assert_eq!(provider.logins, None);
    }

    #[test]
    fn builder_complete() {
        let provider = CognitoProvider::builder()
            .identity_id("id_id".to_string())
            .region(Region::EuCentral1)
            .login("provider".to_string(), "token".to_string())
            .build();
        assert_eq!(provider.identity_id, "id_id");
        assert_eq!(provider.region, Region::EuCentral1);
        assert!(provider.logins.is_some());
        let logins = provider.logins.unwrap();
        assert_eq!(logins.len(), 1);
        assert!(logins.get("provider").is_some());
        assert_eq!(logins.get("provider").unwrap(), "token");
    }

    #[test]
    fn builder_two_providers() {
        let provider = CognitoProvider::builder()
            .identity_id("id_id".to_string())
            .region(Region::EuCentral1)
            .login("provider1".to_string(), "token1".to_string())
            .login("provider2".to_string(), "token2".to_string())
            .build();
        assert_eq!(provider.identity_id, "id_id");
        assert_eq!(provider.region, Region::EuCentral1);
        assert!(provider.logins.is_some());
        let logins = provider.logins.unwrap();
        assert_eq!(logins.len(), 2);
        assert!(logins.get("provider1").is_some());
        assert_eq!(logins.get("provider1").unwrap(), "token1");
        assert!(logins.get("provider2").is_some());
        assert_eq!(logins.get("provider2").unwrap(), "token2");
    }
}

