//! What a client certificate names its client by, for `verify_and_map`:
//! read from the DER as `nats-server` reads it, and tried against the
//! users in the order it tries them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::dn::Dn;

/// Attribute types `nats-server` names in a subject, by OID contents, in
/// the order Go writes its own names out (`pkix.Name.ToRDNSequence`),
/// then domain components, which only go-ldap names.
const TYPES: [(&[u8], &str); 10] = [
    (&[0x55, 4, 6], "C"),
    (&[0x55, 4, 8], "ST"),
    (&[0x55, 4, 7], "L"),
    (&[0x55, 4, 9], "STREET"),
    (&[0x55, 4, 17], "POSTALCODE"),
    (&[0x55, 4, 10], "O"),
    (&[0x55, 4, 11], "OU"),
    (&[0x55, 4, 3], "CN"),
    (&[0x55, 4, 5], "SERIALNUMBER"),
    (DC, "DC"),
];

/// `domainComponent`, 0.9.2342.19200300.100.1.25.
const DC: &[u8] = &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19];

/// `subjectAltName`, 2.5.29.17.
const SAN: &[u8] = &[0x55, 0x1d, 0x11];

/// What a certificate names a client by. Empty for one that cannot be
/// read: `nats-server` refuses those in the handshake.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Names {
    emails: Vec<String>,
    dns: Vec<String>,
    uris: Vec<String>,
    /// The RDNs of the subject, in certificate order.
    subject: Rdns,
}

/// RDNs: the OID contents and value of each attribute of each.
type Rdns = Vec<Vec<(Vec<u8>, String)>>;

impl Names {
    /// What certificate `der` names.
    pub(crate) fn of(der: &[u8]) -> Names {
        read(der).unwrap_or_default()
    }

    /// The user this certificate names, of those `known` takes and those
    /// of `dns` named by a DN, as `nats-server` finds it: by e-mail
    /// address, DNS name, URI, then the subject as a DN, in order or not,
    /// then the subject as text with its domain components, then without.
    pub(crate) fn user(
        &self,
        known: impl Fn(&str) -> bool,
        by_dn: &[(Dn, String)],
    ) -> Option<String> {
        let text = self.written();
        // As Go writes the whole subject out: with the types it has no
        // name for too.
        let has_subject = !text.is_empty()
            || self
                .subject
                .iter()
                .flatten()
                .any(|(o, _)| !TYPES[..9].iter().any(|(t, _)| t == o));
        if self.emails.is_empty() && self.dns.is_empty() && self.uris.is_empty() && !has_subject {
            return None;
        }
        let mut alt = self.emails.iter().chain(&self.dns).chain(&self.uris);
        if let Some(u) = alt.find(|u| !u.is_empty() && known(u)) {
            return Some(u.clone());
        }
        if let Some(dn) = self.dn() {
            let named = || by_dn.iter().filter(|(_, u)| known(u));
            let found = named()
                .find(|(d, _)| d.same(&dn))
                .or_else(|| named().find(|(d, _)| d.same_rdns(&dn)));
            if let Some((_, u)) = found {
                return Some(u.clone());
            }
        }
        let dcs = self.dcs();
        if !dcs.is_empty() {
            let u = format!("{text},{dcs}");
            if known(&u) {
                return Some(u);
            }
        }
        (!text.is_empty() && known(&text)).then_some(text)
    }

    /// The subject as Go writes it out from the names it knows
    /// (`pkix.Name.ToRDNSequence().String()`): one RDN per type, in
    /// reverse order of `TYPES`, values of a type joined by `+`, the last
    /// `CN` and `SERIALNUMBER` only.
    fn written(&self) -> String {
        let all = || self.subject.iter().flatten();
        let mut rdns: Vec<String> = Vec::new();
        for (oid, name) in &TYPES[..9] {
            let mut values: Vec<&str> = all()
                .filter(|(o, _)| o == oid)
                .map(|(_, v)| v.as_str())
                .collect();
            if matches!(*name, "CN" | "SERIALNUMBER") {
                values = values.pop().filter(|v| !v.is_empty()).into_iter().collect();
            }
            if !values.is_empty() {
                let rdn: Vec<String> = values
                    .iter()
                    .map(|v| format!("{name}={}", escape(v)))
                    .collect();
                rdns.push(rdn.join("+"));
            }
        }
        rdns.reverse();
        rdns.join(",")
    }

    /// The domain components of the subject, in certificate order, as
    /// `DC=value` joined by commas.
    fn dcs(&self) -> String {
        let dcs: Vec<String> = self
            .subject
            .iter()
            .flatten()
            .filter(|(o, _)| o == DC)
            .map(|(_, v)| format!("DC={v}"))
            .collect();
        dcs.join(",")
    }

    /// The subject as go-ldap reads it: RDNs and attributes in reverse
    /// order. `None` with a type it has no name for.
    fn dn(&self) -> Option<Dn> {
        let mut rdns = Vec::with_capacity(self.subject.len());
        for rdn in self.subject.iter().rev().filter(|r| !r.is_empty()) {
            let mut out = Vec::with_capacity(rdn.len());
            for (oid, value) in rdn.iter().rev() {
                let (_, name) = TYPES.iter().find(|(o, _)| o == oid)?;
                out.push(((*name).to_owned(), value.clone()));
            }
            rdns.push(out);
        }
        Some(Dn(rdns))
    }
}

/// `v` escaped as Go escapes a value of a subject it writes out.
fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for (k, c) in v.char_indices() {
        let special = match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => true,
            ' ' => k == 0 || k == v.len() - 1,
            '#' => k == 0,
            _ => false,
        };
        if special {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The names in certificate `der`; `None` if it is not one Go reads.
fn read(der: &[u8]) -> Option<Names> {
    let (_, raw, mut tbs) = parts(der)?;
    let mut names = Names {
        subject: subject(raw)?,
        ..Names::default()
    };
    expect(&mut tbs, 0x30)?;
    while !tbs.is_empty() {
        let (tag, mut body) = element(&mut tbs)?;
        if tag == 0xa3 {
            extensions(expect(&mut body, 0x30)?, &mut names)?;
        }
    }
    Some(names)
}

/// The contents of the issuer and the subject of certificate `der`, and
/// what follows them.
fn parts(mut der: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut cert = expect(&mut der, 0x30)?;
    let mut tbs = expect(&mut cert, 0x30)?;
    let (mut tag, _) = element(&mut tbs)?;
    if tag == 0xa0 {
        // The version, then the serial number.
        (tag, _) = element(&mut tbs)?;
    }
    if tag != 0x02 {
        return None;
    }
    expect(&mut tbs, 0x30)?;
    let issuer = expect(&mut tbs, 0x30)?;
    expect(&mut tbs, 0x30)?;
    let subject = expect(&mut tbs, 0x30)?;
    Some((issuer, subject, tbs))
}

/// The subject of certificate `der`, as Go writes it out of the names it
/// knows; empty for one it cannot read.
pub(crate) fn subject_text(der: &[u8]) -> String {
    Names::of(der).written()
}

/// The subject public key info of certificate `der`, its tag and length
/// with it.
pub(crate) fn spki(mut der: &[u8]) -> Option<&[u8]> {
    let mut cert = expect(&mut der, 0x30)?;
    let mut tbs = expect(&mut cert, 0x30)?;
    let (tag, _) = element(&mut tbs)?;
    if tag == 0xa0 {
        element(&mut tbs)?;
    }
    // The signature algorithm, issuer, validity and subject.
    for _ in 0..4 {
        expect(&mut tbs, 0x30)?;
    }
    let all = tbs;
    expect(&mut tbs, 0x30)?;
    Some(&all[..all.len() - tbs.len()])
}

/// When certificate `der` expires: the end of its validity.
pub(crate) fn not_after(mut der: &[u8]) -> Option<SystemTime> {
    let mut cert = expect(&mut der, 0x30)?;
    let mut tbs = expect(&mut cert, 0x30)?;
    let (mut tag, _) = element(&mut tbs)?;
    if tag == 0xa0 {
        (tag, _) = element(&mut tbs)?;
    }
    if tag != 0x02 {
        return None;
    }
    // The signature algorithm and the issuer, then the validity.
    expect(&mut tbs, 0x30)?;
    expect(&mut tbs, 0x30)?;
    let mut validity = expect(&mut tbs, 0x30)?;
    element(&mut validity)?;
    let (tag, at) = element(&mut validity)?;
    asn1_time(tag, at)
}

/// An ASN.1 `UTCTime` (`YYMMDDHHMMSSZ`) or `GeneralizedTime`
/// (`YYYYMMDDHHMMSSZ`).
fn asn1_time(tag: u8, at: &[u8]) -> Option<SystemTime> {
    let s = std::str::from_utf8(at).ok()?.strip_suffix('Z')?;
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match (tag, s.len()) {
        (0x17, 12) => {
            let yy: i64 = s[..2].parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &s[2..])
        }
        (0x18, 14) => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest[i..i + 2].parse::<i64>().ok();
    let days = crate::times::days(year, n(0)?, n(2)?);
    let secs = days * 86_400 + n(4)? * 3600 + n(6)? * 60 + n(8)?;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).ok()?))
}

/// Whether certificate `ca` issued certificate `cert`, by their names,
/// and `cert` is not `ca` itself.
pub(crate) fn issued_by(cert: &[u8], ca: &[u8]) -> bool {
    match (parts(cert), parts(ca)) {
        (Some((issuer, _, _)), Some((_, of_ca, _))) => issuer == of_ca && cert != ca,
        _ => false,
    }
}

/// The RDNs of a subject's contents.
fn subject(mut name: &[u8]) -> Option<Rdns> {
    let mut rdns = Vec::new();
    while !name.is_empty() {
        let mut set = expect(&mut name, 0x31)?;
        let mut rdn = Vec::new();
        while !set.is_empty() {
            let mut atv = expect(&mut set, 0x30)?;
            let oid = expect(&mut atv, 0x06)?;
            let (tag, value) = element(&mut atv)?;
            rdn.push((oid.to_vec(), string(tag, value)?));
        }
        rdns.push(rdn);
    }
    Some(rdns)
}

/// Takes the alternative names among the extensions `list`.
fn extensions(mut list: &[u8], names: &mut Names) -> Option<()> {
    while !list.is_empty() {
        let mut ext = expect(&mut list, 0x30)?;
        let oid = expect(&mut ext, 0x06)?;
        let (mut tag, mut value) = element(&mut ext)?;
        if tag == 0x01 {
            // Critical or not.
            (tag, value) = element(&mut ext)?;
        }
        if tag != 0x04 {
            return None;
        }
        if oid == SAN {
            let mut all = expect(&mut value, 0x30)?;
            while !all.is_empty() {
                let (tag, name) = element(&mut all)?;
                let to = match tag {
                    0x81 => &mut names.emails,
                    0x82 => &mut names.dns,
                    0x86 => &mut names.uris,
                    _ => continue,
                };
                // IA5 strings, as Go wants them.
                to.push(
                    std::str::from_utf8(name)
                        .ok()
                        .filter(|s| s.is_ascii())?
                        .to_owned(),
                );
            }
        }
    }
    Some(())
}

/// A string of ASN.1 type `tag`, decoded as Go decodes the ones it takes
/// in a subject.
fn string(tag: u8, v: &[u8]) -> Option<String> {
    let all = |ok: fn(&u8) -> bool| {
        v.iter()
            .all(ok)
            .then(|| String::from_utf8_lossy(v).into_owned())
    };
    match tag {
        // UTF8String.
        0x0c => std::str::from_utf8(v).ok().map(str::to_owned),
        // PrintableString, with the `*` and `&` Go lets in.
        0x13 => all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?*&".contains(b)),
        // IA5String.
        0x16 => all(u8::is_ascii),
        // NumericString.
        0x12 => all(|b| b.is_ascii_digit() || *b == b' '),
        // T61String, taken as Latin-1.
        0x14 => Some(v.iter().map(|&b| char::from(b)).collect()),
        // BMPString: UCS-2, maybe with a terminator.
        0x1e => {
            let v = v.strip_suffix(&[0, 0]).unwrap_or(v);
            if !v.len().is_multiple_of(2) {
                return None;
            }
            let units = v.as_chunks::<2>().0.iter().map(|&p| u16::from_be_bytes(p));
            units
                .map(|u| {
                    let bad = u >= 0xfffe || (0xfdd0..=0xfdef).contains(&u);
                    char::from_u32(u.into()).filter(|_| !bad)
                })
                .collect()
        }
        _ => None,
    }
}

/// The contents of the element off the front of `der`, if it has tag
/// `tag`.
fn expect<'a>(der: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    element(der).and_then(|(t, body)| (t == tag).then_some(body))
}

/// The tag and contents of the element off the front of `der`: DER, with
/// definite lengths and low tag numbers only.
fn element<'a>(der: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        (bytes.iter().fold(0, |l, &b| l << 8 | usize::from(b)), rest)
    };
    let (body, rest) = rest.split_at_checked(len)?;
    *der = rest;
    Some((tag, body))
}

#[cfg(test)]
mod tests;
