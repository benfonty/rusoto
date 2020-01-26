
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
    ProvideAwsCredentials
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
/// extern crate rusoto_credential;
///
/// use std::time::Duration;
///
/// use rusoto_credential::ContainerProvider;
///
/// fn main() {
///   let mut provider = ContainerProvider::new();
///   // you can overwrite the default timeout like this:
///   provider.set_timeout(Duration::from_secs(60));
///
///   // ...
/// }
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
    pub fn build(&self) -> CognitoProvider { // TODO: builder should consume self
        CognitoProvider {
            identity_id: self.identity_id.clone().expect("no identity id provided"),
            region: self.region.clone().unwrap_or(Region::default()),
            logins: self.logins.clone()
        }
    }

    pub fn identity_id(&mut self, identity_id: &str)-> &mut Self {
        self.identity_id = Some(identity_id.into());
        self
    }

    pub fn region(&mut self, region: &Region)-> &mut Self {
        self.region = Some(region.clone());
        self
    }

    pub fn login(&mut self, provider: &str, token: &str)-> &mut Self {
        if self.logins == None {
            self.logins = Some(HashMap::new());
        }
        self.logins.as_mut().unwrap().insert(provider.into(), token.into());
        self
    }
}

impl CognitoProvider {

    pub fn builder() -> CognitoProviderBuilder {
        CognitoProviderBuilder::default()
    }

    fn credentials_from_cognito(&self) -> Result<RusotoFuture<GetCredentialsForIdentityResponse, GetCredentialsForIdentityError>, CredentialsError> {
        let client = CognitoIdentityClient::new(self.region.clone());
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
                        Err(CredentialsError::new(format!(
                        "StsProvider get_session_token error: {:?}",
                        err
                    )))
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

