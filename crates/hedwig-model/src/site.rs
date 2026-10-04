//! What a remote asks the workstation's browser to open: the URL read once
//! where it arrives, the site it leads to, the loopback callback it carries,
//! and the sites a capability opens.

use std::fmt;

use crate::text::{Host, Port};

/// The longest URL a remote may ask to open, in bytes. Invariant: an
/// authorisation request with every parameter a traced tool sends is under
/// two thousand; this leaves room and bounds what the core reads.
pub const LONGEST: usize = 8192;

/// A URL's scheme: only the web's two. Every other scheme Windows hands to
/// whatever program registered it, which is not a browser and may run what
/// it is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scheme {
    Https,
    Http,
}

impl Scheme {
    pub fn default_port(self) -> u16 {
        match self {
            Scheme::Https => 443,
            Scheme::Http => 80,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Scheme::Https => "https",
            Scheme::Http => "http",
        }
    }
}

/// An absolute URL a remote asked to open, as read: where it leads, and the
/// rest as it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub scheme: Scheme,
    /// Lower case; an IPv6 address without its brackets.
    pub host: Host,
    pub port: Port,
    /// The path and query, from the first `/` or `?` on; `/` where there is
    /// none.
    pub target: String,
}

impl Url {
    /// Whether it leads to the remote's own loopback: `localhost`, an address
    /// in `127.0.0.0/8`, or `::1`.
    pub fn loopback(&self) -> bool {
        let host = self.host.as_str();
        host == "localhost"
            || host == "::1"
            || host.strip_prefix("127.").is_some_and(|rest| {
                rest.split('.').count() == 3
                    && rest.split('.').all(|part| part.parse::<u8>().is_ok())
            })
    }

    /// The value of the query's first parameter `name`, percent-decoded.
    pub fn parameter(&self, name: &str) -> Option<String> {
        let query = self.target.split_once('?')?.1;
        let query = query.split_once('#').map_or(query, |(query, _)| query);
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key)? == name).then(|| decode(value)).flatten()
        })
    }

    /// The path alone.
    pub fn path(&self) -> &str {
        self.target.split(['?', '#']).next().unwrap_or("/")
    }

    /// Whether what is sent to it crosses a network unencrypted: plain
    /// `http` to anywhere but the remote's own loopback.
    pub fn cleartext(&self) -> bool {
        self.scheme == Scheme::Http && !self.loopback()
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.host.as_str();
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        write!(
            f,
            "{}://{host}:{}{}",
            self.scheme.word(),
            self.port,
            self.target
        )
    }
}

/// `%XX` decoded, and `+` as a blank as a form writes one; `None` where the
/// result is not UTF-8 or an escape is cut.
fn decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        match byte {
            b'%' => {
                let digits = std::str::from_utf8(bytes.get(at + 1..at + 3)?).ok()?;
                out.push(u8::from_str_radix(digits, 16).ok()?);
                at += 3;
            }
            b'+' => {
                out.push(b' ');
                at += 1;
            }
            _ => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Why a remote's URL is not one the workstation's browser is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Unopenable {
    /// Longer than [`LONGEST`].
    TooLong,
    /// Not an absolute URL: no scheme and authority, or a blank or a control
    /// character in it.
    NotUrl,
    /// A scheme other than `https` or `http`.
    Scheme,
    /// A user name or password before the host, which makes the address the
    /// person reads differ from where it leads.
    Credentials,
    /// A host no browser reaches, or a port that is not one.
    Host,
}

impl fmt::Display for Unopenable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unopenable::TooLong => "it is longer than any sign-in Hedwig opens",
            Unopenable::NotUrl => "it is not a web address",
            Unopenable::Scheme => "it is not an https or http address",
            Unopenable::Credentials => {
                "it carries a name before its host, so it would not lead where it reads"
            }
            Unopenable::Host => "its host or port is not one a browser reaches",
        })
    }
}

impl std::error::Error for Unopenable {}

/// Reads `text` as an absolute `https` or `http` URL.
///
/// # Errors
///
/// [`Unopenable`], saying why.
pub fn url(text: &str) -> Result<Url, Unopenable> {
    if text.len() > LONGEST {
        return Err(Unopenable::TooLong);
    }
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(Unopenable::NotUrl);
    }
    let (scheme, rest) = text.split_once("://").ok_or(Unopenable::NotUrl)?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        _ => return Err(Unopenable::Scheme),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(end);
    if authority.contains('@') {
        return Err(Unopenable::Credentials);
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, after) = bracketed.split_once(']').ok_or(Unopenable::Host)?;
        (host, after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(digits) => digits
            .parse::<u16>()
            .ok()
            .and_then(|number| Port::try_from(number).ok())
            .ok_or(Unopenable::Host)?,
        None => Port::try_from(scheme.default_port()).map_err(|_| Unopenable::Host)?,
    };
    if host.is_empty() {
        return Err(Unopenable::Host);
    }
    let host = Host::try_from(host.to_ascii_lowercase().as_str()).map_err(|_| Unopenable::Host)?;
    let target = match target.chars().next() {
        Some('/') => target.to_owned(),
        Some(_) => format!("/{target}"),
        None => "/".to_owned(),
    };
    Ok(Url {
        scheme,
        host,
        port,
        target,
    })
}

/// The remote's loopback port a sign-in comes back to, carried from the
/// workstation for the flow's life.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    /// The host as the URL wrote it, which the remote's server listens at.
    pub host: Host,
    pub port: Port,
    /// The path the authorisation server sends the code to, where the URL
    /// says it: `None` when the URL opened is the remote's own page, which
    /// redirects on its own.
    pub path: Option<String>,
}

/// A URL a remote asked to open, and what opening it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    pub url: Url,
    pub callback: Option<Callback>,
}

impl Opening {
    /// What opening `url` carries: the URL's own loopback port where it leads
    /// to the remote's loopback, as kubelogin opens its own page; else the
    /// loopback port of its `redirect_uri`, as RFC 8252 section 7.3 writes
    /// one; else nothing, as a device code's page needs.
    pub fn of(url: Url) -> Opening {
        let callback = if url.loopback() {
            Some(Callback {
                host: url.host.clone(),
                port: url.port,
                path: None,
            })
        } else {
            url.parameter("redirect_uri")
                .and_then(|redirect| self::url(&redirect).ok())
                .filter(|redirect| redirect.scheme == Scheme::Http && redirect.loopback())
                .map(|redirect| Callback {
                    host: redirect.host.clone(),
                    port: redirect.port,
                    path: Some(redirect.path().to_owned()),
                })
        };
        Opening { url, callback }
    }
}

/// Which hosts a site names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hosts {
    Exactly(Host),
    /// The host and every name beneath it.
    Within(Host),
    /// The remote's own loopback, which the core carries for the flow.
    Loopback,
}

/// A site a capability opens in the workstation's browser. It is made only
/// by [`Site::of`] and by reading its written form, so one site has one value:
/// a named host never carries its scheme's own port, and the loopback is
/// never a named host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Site {
    scheme: Scheme,
    hosts: Hosts,
    port: Option<Port>,
}

impl Site {
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn hosts(&self) -> &Hosts {
        &self.hosts
    }

    /// `None`: the scheme's own port for a named host, any port on the
    /// loopback.
    pub fn port(&self) -> Option<Port> {
        self.port
    }

    /// Whether what is sent to it crosses a network unencrypted: plain
    /// `http` to anywhere but the remote's own loopback.
    pub fn cleartext(&self) -> bool {
        self.scheme == Scheme::Http && self.hosts != Hosts::Loopback
    }

    /// Whether this site admits `url`.
    pub fn admits(&self, url: &Url) -> bool {
        let host = url.host.as_str();
        let hosts = match &self.hosts {
            Hosts::Exactly(named) => !url.loopback() && host == named.as_str(),
            Hosts::Within(named) => {
                !url.loopback()
                    && (host == named.as_str()
                        || host
                            .strip_suffix(named.as_str())
                            .is_some_and(|label| label.ends_with('.')))
            }
            Hosts::Loopback => url.loopback(),
        };
        let port = match (self.port, &self.hosts) {
            (Some(port), _) => port == url.port,
            (None, Hosts::Loopback) => true,
            (None, _) => url.port.number() == self.scheme.default_port(),
        };
        self.scheme == url.scheme && hosts && port
    }

    /// The narrowest site that admits `url`: what a person adds to open it.
    pub fn of(url: &Url) -> Site {
        let default = url.port.number() == url.scheme.default_port();
        if url.loopback() {
            Site {
                scheme: url.scheme,
                hosts: Hosts::Loopback,
                port: None,
            }
        } else {
            Site {
                scheme: url.scheme,
                hosts: Hosts::Exactly(url.host.clone()),
                port: (!default).then_some(url.port),
            }
        }
    }
}

/// The site's written form, which its [`FromStr`](std::str::FromStr) reads back: the scheme
/// and the host, `*.` before a host for it and every name beneath it, a port
/// only where it is not the scheme's own, and `localhost` for the remote's own
/// loopback, any port there unless one is written. What a refusal names is
/// what the person types.
impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = self.scheme.word();
        match &self.hosts {
            Hosts::Exactly(host) if host.as_str().contains(':') => {
                write!(f, "{scheme}://[{host}]")?;
            }
            Hosts::Exactly(host) => write!(f, "{scheme}://{host}")?,
            Hosts::Within(host) => write!(f, "{scheme}://*.{host}")?,
            Hosts::Loopback => write!(f, "{scheme}://localhost")?,
        }
        match self.port {
            Some(port) => write!(f, ":{port}"),
            None => Ok(()),
        }
    }
}

/// Why a text is not a site's written form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SiteError {
    /// Not an address the workstation's browser is given.
    Unopenable(Unopenable),
    /// A path, query or fragment after the host.
    Path,
    /// `*.` before the remote's own loopback, which has no names beneath it.
    LoopbackWithin,
}

impl fmt::Display for SiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SiteError::Unopenable(why) => why.fmt(f),
            SiteError::Path => f.write_str("a site is a scheme and a host, with no path"),
            SiteError::LoopbackWithin => {
                f.write_str("the remote's own loopback is written localhost, with no `*.`")
            }
        }
    }
}

impl std::error::Error for SiteError {}

impl std::str::FromStr for Site {
    type Err = SiteError;

    /// Reads a site as [`Site`]'s `Display` writes it. The scheme's own port
    /// written after a named host is no port of the site's; any address of
    /// the loopback reads as `localhost`.
    fn from_str(text: &str) -> Result<Site, SiteError> {
        let (within, address) = match text.split_once("://") {
            Some((scheme, rest)) => match rest.strip_prefix("*.") {
                Some(rest) => (true, format!("{scheme}://{rest}")),
                None => (false, text.to_owned()),
            },
            None => (false, text.to_owned()),
        };
        let read = url(&address).map_err(SiteError::Unopenable)?;
        if read.target != "/" {
            return Err(SiteError::Path);
        }
        let authority = address
            .split_once("://")
            .map_or("", |(_, rest)| rest)
            .trim_end_matches('/');
        // A port is written after the last `:` outside an IPv6 address's
        // brackets.
        let written = !authority.ends_with(']')
            && authority
                .rsplit_once(':')
                .is_some_and(|(host, _)| !host.ends_with('['));
        let port = written.then_some(read.port);
        if read.loopback() {
            if within {
                return Err(SiteError::LoopbackWithin);
            }
            return Ok(Site {
                scheme: read.scheme,
                hosts: Hosts::Loopback,
                port,
            });
        }
        Ok(Site {
            scheme: read.scheme,
            hosts: if within {
                Hosts::Within(read.host)
            } else {
                Hosts::Exactly(read.host)
            },
            port: port.filter(|port| port.number() != read.scheme.default_port()),
        })
    }
}
