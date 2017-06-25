/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
extern crate openssl;
extern crate hyper;
extern crate hyper_openssl;
extern crate antidote;
//use hyper::net::{HttpsConnector};
use hosts::replace_host;
use hyper::client::Pool;
use hyper::error::{Result as HyperResult, Error as HyperError};
use hyper::net::{NetworkConnector, HttpsStream, HttpStream, SslClient};
use hyper_openssl::OpensslClient;
use hyper_openssl::SslStream;
use openssl::ssl::{SSL_OP_NO_COMPRESSION, SSL_OP_NO_SSLV2, SSL_OP_NO_SSLV3,SSL_VERIFY_PEER};
use openssl::ssl::{SslConnectorBuilder, SslContextBuilder, SslMethod, SslContext, Ssl, HandshakeError};
use std::io;
use std::net::TcpStream;
use std::path::PathBuf;
use time;
use std::time::{Duration,Instant};
use servo_config::resource_files::resources_dir_path;
use std::fs::File;
use std::io::{Read, Write};
use std::io::BufReader;
use std::sync::Arc;
use openssl::x509::X509Ref;
use openssl::nid;
use self::antidote::Mutex;
use hyper::net::NetworkStream;

#[derive(Clone)]
pub struct HttpsConnector {
    ssl: ServoSslClient,
}

impl HttpsConnector {
    fn new(ssl: ServoSslClient) -> HttpsConnector {
        HttpsConnector {
            ssl: ssl,
        }
    }
}

impl NetworkConnector for HttpsConnector {
    type Stream = HttpsStream<<ServoSslClient as SslClient>::Stream>;

    fn connect(&self, host: &str, port: u16, scheme: &str) -> HyperResult<Self::Stream> {
        if scheme != "http" && scheme != "https" {
            return Err(HyperError::Io(io::Error::new(io::ErrorKind::InvalidInput,
                                                     "Invalid scheme for Http")));
        }

        // Perform host replacement when making the actual TCP connection.
        let addr = &(&*replace_host(host), port);
        let stream = HttpStream(try!(TcpStream::connect(addr)));

        if scheme == "http" {
            Ok(HttpsStream::Http(stream))
        } else {
            // Do not perform host replacement on the host that is used
            // for verifying any SSL certificate encountered.:
            println!("cert verification");
            self.ssl.wrap_client(stream, host).map(HttpsStream::Https)
        }
    }
}


pub type Connector = HttpsConnector;

pub fn create_ssl_client(ca_file: &PathBuf) -> ServoSslClient {
    println!("create_ssl_client");

    /*let mut ssl_connector_builder = SslConnectorBuilder::new(SslMethod::tls()).unwrap();
    {
        let context = ssl_connector_builder.builder_mut();
        let now = Instant::now();
        context.set_ca_file(ca_file).expect("could not set CA file");
        let dur = now.elapsed();
        println!("time for setting trust anchors {}", dur.subsec_nanos());
        context.set_cipher_list(DEFAULT_CIPHERS).expect("could not set ciphers");
        context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);
        let servo_connector = ServoSslConnector { 
            context: Arc::new(context.build()) 
        };
        let sslClient = ServosslClieant
        ServoSslClient::from(servo_connector) 
    }*/
    /*let ca_file = &resources_dir_path()
        .expect("Need certificate file to make network requests")
        .join(certificate_file);*/
    let mut context = SslContextBuilder::new(SslMethod::tls()).unwrap();
    context.set_ca_file(ca_file).expect("could not set CA file");
    context.set_cipher_list(DEFAULT_CIPHERS).unwrap();
    context.set_options(SSL_OP_NO_SSLV2 | SSL_OP_NO_SSLV3 | SSL_OP_NO_COMPRESSION);

    let servo_connector = ServoSslConnector { 
        context: Arc::new(context.build()) 
    };
    let sslClient = ServoSslClient {
        connector: Arc::new(servo_connector),
    };
    sslClient
}

pub fn create_http_connector(ssl_client: ServoSslClient) -> Pool<Connector> {
    let https_connector = HttpsConnector::new(ssl_client);
    Pool::with_connector(Default::default(), https_connector)
}
// when i create a servosslconnctor, there will be a context associated with it. when i  create a context and pass it to a connector. that context will be associated woth the conector.
#[derive(Clone)]
pub struct ServoSslConnector{
    context: Arc<SslContext>, 
}
impl ServoSslConnector {
    pub fn connect(&self, domain: &str, stream: HttpStream) -> HyperResult<openssl::ssl::SslStream<HttpStream>> {
        let mut ssl = Ssl::new(&self.context).unwrap();
        ssl.set_hostname(domain).unwrap(); //#Imp: Sets the host name to be used with SNI (Server Name Indication).
        let domain = domain.to_owned();

        // create a rustls root store 
        //let mut roots = RootCertStore::empty();
        let ca_file = &resources_dir_path()
            .expect("Need certificate file to make network requests")
            .join("certs");
        let ca_pem = File::open(ca_file).unwrap();
        let mut ca_pem = BufReader::new(ca_pem);
       /* let r = roots.add_pem_file(&mut ca_pem);
        */
        //ssl.set_verify_callback(SSL_VERIFY_PEER, move |p, x| {
        //    rustls_verify(&domain, &roots, p, x)
        //});
        ssl.set_verify_callback(SSL_VERIFY_PEER,
                move |p, x| verify::verify_callback(&domain, p, x));

        match ssl.connect(stream) {
            Ok(stream) => Ok(stream),
            Err(err) => Err(hyper::Error::Ssl(Box::new(err))),
        }
    }
}

#[derive(Clone)]
pub struct ServoSslClient{
    connector: Arc<ServoSslConnector>,
}

impl SslClient for ServoSslClient {
    //type Stream = HttpsStream<<ServoSslClient as SslClient>::Stream>;
    type Stream = hyper_openssl::SslStream<HttpStream>;
    fn wrap_client(&self, stream: HttpStream, host: &str) -> HyperResult<Self::Stream> {
        match self.connector.connect(host, stream) {
            Ok(stream) => Ok(hyper_openssl::SslStream(Arc::new(Mutex::new(stream)))),
            Err(err) => Err(err),
        }
    }
}

//For OpenSSL verification
mod verify {
    use std::net::IpAddr;
    use std::str;

    use openssl::nid;
    use openssl::x509::{X509StoreContextRef, X509Ref, X509NameRef, GeneralName};
    use openssl::stack::Stack;

    pub fn verify_callback(domain: &str,
                           preverify_ok: bool,
                           x509_ctx: &X509StoreContextRef)
                           -> bool {
        if !preverify_ok || x509_ctx.error_depth() != 0 {
            return preverify_ok;
        }

        match x509_ctx.current_cert() {
            Some(x509) => verify_hostname(domain, &x509),
            None => true,
        }
}

    fn verify_hostname(domain: &str, cert: &X509Ref) -> bool {
        match cert.subject_alt_names() {
            Some(names) => verify_subject_alt_names(domain, names),
            None => verify_subject_name(domain, &cert.subject_name()),
        }
    }
    fn verify_subject_alt_names(domain: &str, names: Stack<GeneralName>) -> bool {
        let ip = domain.parse();

        for name in &names {
            match ip {
                Ok(ip) => {
                    if let Some(actual) = name.ipaddress() {
                        if matches_ip(&ip, actual) {
                            return true;
                        }
                    }
                }
                Err(_) => {
                    if let Some(pattern) = name.dnsname() {
                        if matches_dns(pattern, domain, false) {
                            return true;
                        }
                    }
                }
            }
        }

        false
}

    fn verify_subject_name(domain: &str, subject_name: &X509NameRef) -> bool {
        if let Some(pattern) = subject_name.entries_by_nid(nid::COMMONNAME).next() {
            let pattern = match str::from_utf8(pattern.data().as_slice()) {
                Ok(pattern) => pattern,
                Err(_) => return false,
            };

            // Unlike with SANs, IP addresses in the subject name don't have a
            // different encoding. We need to pass this down to matches_dns to
            // disallow wildcard matches with bogus patterns like *.0.0.1
            let is_ip = domain.parse::<IpAddr>().is_ok();

            if matches_dns(&pattern, domain, is_ip) {
                return true;
            }
        }

        false
    }


    fn matches_dns(mut pattern: &str, mut hostname: &str, is_ip: bool) -> bool {
        // first strip trailing . off of pattern and hostname to normalize
        if pattern.ends_with('.') {
            pattern = &pattern[..pattern.len() - 1];
        }
        if hostname.ends_with('.') {
            hostname = &hostname[..hostname.len() - 1];
        }

        matches_wildcard(pattern, hostname, is_ip).unwrap_or_else(|| pattern == hostname)
}

    
    

    fn matches_wildcard(pattern: &str, hostname: &str, is_ip: bool) -> Option<bool> {
        // IP addresses and internationalized domains can't involved in wildcards
        if is_ip || pattern.starts_with("xn--") {
            return None;
        }

        let wildcard_location = match pattern.find('*') {
            Some(l) => l,
            None => return None,
        };

        let mut dot_idxs = pattern.match_indices('.').map(|(l, _)| l);
        let wildcard_end = match dot_idxs.next() {
            Some(l) => l,
            None => return None,
        };

        // Never match wildcards if the pattern has less than 2 '.'s (no *.com)
        //
        // This is a bit dubious, as it doesn't disallow other TLDs like *.co.uk.
        // Chrome has a black- and white-list for this, but Firefox (via NSS) does
        // the same thing we do here.
        //
        // The Public Suffix (https://www.publicsuffix.org/) list could
        // potentially be used here, but it's both huge and updated frequently
        // enough that management would be a PITA.
        if dot_idxs.next().is_none() {
            return None;
        }

        // Wildcards can only be in the first component
        if wildcard_location > wildcard_end {
            return None;
        }

        let hostname_label_end = match hostname.find('.') {
            Some(l) => l,
            None => return None,
        };

        // check that the non-wildcard parts are identical
        if pattern[wildcard_end..] != hostname[hostname_label_end..] {
            return Some(false);
        }

        let wildcard_prefix = &pattern[..wildcard_location];
        let wildcard_suffix = &pattern[wildcard_location + 1..wildcard_end];

        let hostname_label = &hostname[..hostname_label_end];

        // check the prefix of the first label
        if !hostname_label.starts_with(wildcard_prefix) {
            return Some(false);
        }

        // and the suffix
        if !hostname_label[wildcard_prefix.len()..].ends_with(wildcard_suffix) {
            return Some(false);
        }

        Some(true)
}


    fn matches_ip(expected: &IpAddr, actual: &[u8]) -> bool {
        match (expected, actual.len()) {
            (&IpAddr::V4(ref addr), 4) => actual == addr.octets(),
            (&IpAddr::V6(ref addr), 16) => {
                let segments = [((actual[0] as u16) << 8) | actual[1] as u16,
                                ((actual[2] as u16) << 8) | actual[3] as u16,
                                ((actual[4] as u16) << 8) | actual[5] as u16,
                                ((actual[6] as u16) << 8) | actual[7] as u16,
                                ((actual[8] as u16) << 8) | actual[9] as u16,
                                ((actual[10] as u16) << 8) | actual[11] as u16,
                                ((actual[12] as u16) << 8) | actual[13] as u16,
                                ((actual[14] as u16) << 8) | actual[15] as u16];
                segments == addr.segments()
            }
            _ => false,
        }
}

}
// The basic logic here is to prefer ciphers with ECDSA certificates, Forward
// Secrecy, AES GCM ciphers, AES ciphers, and finally 3DES ciphers.
// A complete discussion of the issues involved in TLS configuration can be found here:
// https://wiki.mozilla.org/Security/Server_Side_TLS
const DEFAULT_CIPHERS: &'static str = concat!(
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
    "DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:",
    "ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:",
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:",
    "ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:",
    "DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:",
    "ECDHE-ECDSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:",
    "AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA"
);