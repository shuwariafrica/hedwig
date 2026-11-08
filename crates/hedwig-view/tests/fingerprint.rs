//! An SSH key named as `ssh-keygen -l` names it, checked against what the
//! in-box `ssh-keygen` 9.5p2 printed for keys and certificates of every type
//! it makes, and SHA-256
//! against FIPS 180-4's own examples.

use hedwig_model::text::SshKey;
use hedwig_view::fingerprint;

fn hex(digest: [u8; 32]) -> String {
    use std::fmt::Write as _;
    digest.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[test]
fn sha256_gives_fips_180_4s_digests() {
    assert_eq!(
        hex(fingerprint::sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(fingerprint::sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(fingerprint::sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(
        hex(fingerprint::sha256(&vec![b'a'; 1_000_000])),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

/// Every length from 0 to 129 bytes - each side of every padding boundary
/// of one and two blocks - against Python's `hashlib`, as one digest of the
/// 130 digests.
#[test]
fn sha256_holds_across_every_padding_boundary() {
    let mut all = Vec::new();
    for length in 0..130_usize {
        let message: Vec<u8> = (0..length)
            .map(|at| u8::try_from(at * 7 % 256).unwrap_or_default())
            .collect();
        all.extend_from_slice(&fingerprint::sha256(&message));
    }
    assert_eq!(
        hex(fingerprint::sha256(&all)),
        "6331a2b10770f73d638be11da3c97f61f5f9dddebf3f274e4c36e5b91ae35d28"
    );
}

/// Each key as its `.pub` file writes it, the fingerprint and the type
/// `ssh-keygen -l` printed for that file.
const PRINTED: [(&str, &str, &str); 13] = [
    // ca.pub
    (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOXkW0o5BqBhZuy1XiS4+mMrCulJoradnsgZFKIlU6K/",
        "SHA256:3Qg6Dq0og+fW2YwAfa4o/4mp/DUNjB/fbufj3llpFw8",
        "ED25519",
    ),
    // ecdsa256-cert.pub
    (
        "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgXWU2810OhVX9H8UbY5yF7p9buHJFB6P3I+uKCkoMSCgAAAAIbmlzdHAyNTYAAABBBNwo9zNZ1p9OJMHFfawTucuCrkP+GumZ23WooozBOTggm9wkcD/mjb+3nAAyY655XW+KEaqiVzrtd3CsyDdVeX4AAAAAAAAAAAAAAAEAAAALaWQtZWNkc2EyNTYAAAALAAAAB3NvbWVvbmUAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg5eRbSjkGoGFm7LVeJLj6YysK6Umitp2eyBkUoiVTor8AAABTAAAAC3NzaC1lZDI1NTE5AAAAQDRkMzXrJ9opE8hbnUCWyslPqW+U+9ClogFvmvyFows4va6IkiE1Pxj1VnBD3h2wYOs2V3TIt0UNWYfG10sFggM=",
        "SHA256:X4mkNnFzELzfodwwfn4jjh4ZhRfFtBN7vYS3FjS/nR0",
        "ECDSA-CERT",
    ),
    // ecdsa256.pub
    (
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwo9zNZ1p9OJMHFfawTucuCrkP+GumZ23WooozBOTggm9wkcD/mjb+3nAAyY655XW+KEaqiVzrtd3CsyDdVeX4=",
        "SHA256:X4mkNnFzELzfodwwfn4jjh4ZhRfFtBN7vYS3FjS/nR0",
        "ECDSA",
    ),
    // ecdsa384-cert.pub
    (
        "ecdsa-sha2-nistp384-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAzODQtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgAqPoe2QJELL/YyUQzQ9gc5bSfxzRHlvq1DNeJY5nVbMAAAAIbmlzdHAzODQAAABhBIZQhgLqVEyYl0xBAfYS3od18C9sM/wTzGVVPYfUrKB5TkIiHG3eN5Ok5mttV9CDR00civtm/a1N2DeBz9unUIIoNB19gkmBdjXjvNFKc5B6iAB1Cby+BcvAfW3dqBCmCAAAAAAAAAAAAAAAAQAAAAtpZC1lY2RzYTM4NAAAAAsAAAAHc29tZW9uZQAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDl5FtKOQagYWbstV4kuPpjKwrpSaK2nZ7IGRSiJVOivwAAAFMAAAALc3NoLWVkMjU1MTkAAABApEFUbMFvfmuAgJK/ACdKN2EbWur7X4ZiBbay0JDjMoD1oRz7FBWwZPJ7bUqx0jeJDOvpnkI1OcD9gMbBORpjBw==",
        "SHA256:xw/r3uccnpH2Bsxy0dqyZqCLcfc8yOR0J42CmVkwkl8",
        "ECDSA-CERT",
    ),
    // ecdsa384.pub
    (
        "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIZQhgLqVEyYl0xBAfYS3od18C9sM/wTzGVVPYfUrKB5TkIiHG3eN5Ok5mttV9CDR00civtm/a1N2DeBz9unUIIoNB19gkmBdjXjvNFKc5B6iAB1Cby+BcvAfW3dqBCmCA==",
        "SHA256:xw/r3uccnpH2Bsxy0dqyZqCLcfc8yOR0J42CmVkwkl8",
        "ECDSA",
    ),
    // ecdsa521.pub
    (
        "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAB3Pe4mVVpj2MhSV+yesKpxJv0Ilyehig1FF0tC5RaY8I+1NHY+y1fttlLyLp5gER/7Enfmv/QFqgml7OM8SGcqtQFpJCG1Ist9Mc87sLti3sX1htMDx+HcjUkrswSNn6HVnTHnt2r0YvKQEflm2ufOSCUIuHkhoelt1ViE8ybHt2BWcA==",
        "SHA256:o3eDis9wfQEkpJAGT1P6xOFfoLKx1jgoTHGvSbYXBmA",
        "ECDSA",
    ),
    // ed25519-cert.pub
    (
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGFG7LAAlpPLspreFN4e9neBiJcDg4KhJt2Yh4CAX14eAAAAIItLZoUun7m4kwftUgE3qXUy3IrZuqIlD7BcOv+KMz1XAAAAAAAAAAAAAAABAAAACmlkLWVkMjU1MTkAAAALAAAAB3NvbWVvbmUAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg5eRbSjkGoGFm7LVeJLj6YysK6Umitp2eyBkUoiVTor8AAABTAAAAC3NzaC1lZDI1NTE5AAAAQHKGqM7+7CenTJOI1HH+GlqiQI5FwRvtImXt9s6Dv8TTQC6oXtGMMszDrK8UsBp54VehGBZv5Qjn6n3khp7ySgE=",
        "SHA256:vey71A1LmxIAaLPYhQZyjT4sAvzulhaLQh9DQrRaoyg",
        "ED25519-CERT",
    ),
    // ed25519.pub
    (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItLZoUun7m4kwftUgE3qXUy3IrZuqIlD7BcOv+KMz1X",
        "SHA256:vey71A1LmxIAaLPYhQZyjT4sAvzulhaLQh9DQrRaoyg",
        "ED25519",
    ),
    // rsa2048-cert.pub
    (
        "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgMA6dTB+Kjr5tPRBtXUuILBxqnaAfqWsNO9QFS3onBlQAAAADAQABAAABAQCu4/wzgi2F2NH+wZnIr8tUngq4Tu1mHiwGzVTAl6Igj7drMo0BWVq6AUa8yxhL0bl2OBaVNqyPOceSvpQdYXeCmxt4CmeXpsQukJn/FC8c8CuR9Nexf24sfCdYy+SynL7/TsvP/Kpho1t1dbyWv0uRChpwnRxPLUYMFayfktHBSyoqP8lNGS3AOYrCAmlnNbF+0PFPPfK5HCHWig2mrkNYOHM6IT7b0B8vYzFqrWKpL4naF1Ux4gJo0unpoPfLo0Wzp5cHpqDDQ3BkfDxk3O9K+RRTFBWijghXppFHMRnlAWdEBim3O3mv/VCUZldkj1juh3h5YzEoiqa7uq0dNusNAAAAAAAAAAAAAAABAAAACmlkLXJzYTIwNDgAAAALAAAAB3NvbWVvbmUAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg5eRbSjkGoGFm7LVeJLj6YysK6Umitp2eyBkUoiVTor8AAABTAAAAC3NzaC1lZDI1NTE5AAAAQJQmPTwgEqOeOilXsRsUesko2Ss4tFadBlwjqmk71TvbtmDqdOMla5ciAGN0HSIXR5lZ8F1vzNm++Dj46EA2yA4=",
        "SHA256:7WPUEouPQokBPnKiZ769wme13LhXguWwF5tV43mkkq4",
        "RSA-CERT",
    ),
    // rsa2048.pub
    (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCu4/wzgi2F2NH+wZnIr8tUngq4Tu1mHiwGzVTAl6Igj7drMo0BWVq6AUa8yxhL0bl2OBaVNqyPOceSvpQdYXeCmxt4CmeXpsQukJn/FC8c8CuR9Nexf24sfCdYy+SynL7/TsvP/Kpho1t1dbyWv0uRChpwnRxPLUYMFayfktHBSyoqP8lNGS3AOYrCAmlnNbF+0PFPPfK5HCHWig2mrkNYOHM6IT7b0B8vYzFqrWKpL4naF1Ux4gJo0unpoPfLo0Wzp5cHpqDDQ3BkfDxk3O9K+RRTFBWijghXppFHMRnlAWdEBim3O3mv/VCUZldkj1juh3h5YzEoiqa7uq0dNusN",
        "SHA256:7WPUEouPQokBPnKiZ769wme13LhXguWwF5tV43mkkq4",
        "RSA",
    ),
    // rsa3072.pub
    (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDqGUJnEx2vanT8v+Mf9GUL6WGOZ1grVmG5fm20Axf0SmKSUUMNgslNZ1S1Anl5YGqGlKCzrDLd/nueflcdMJyeytKtW//1LOULui261DtoM6Xspq5vWCLpmNHVx+7++mQ6HmGeXEVA4k3Y9C2cGnHIV067mOib+lmV1B59o+mB3MpHo7aT01uJvVVqABUkqGd+U4eM6I61hJqfQUzOCEerq1ih9HCFnt0GrZatgH0uelsl/xPY6xWApunpZSyOE1d6OsUjr5lomO/wzp1MEnWKvk27mBUisdj2fiTZE/nhCR0gjHSv3oRZiBw/OAmIYof8X5d0YX0s8baFysV/ff22E+8h313e5gJgolNrCKBeinE0ElmrDyQAHEoaRZe9wjjrmOKFrcFqGwlBeQAZoCRdZEYWLpdvvm7dzCreIkAy9LNONyI1aoAvB+lHTbHxkOUsqqdW79+IXmtUIeHT7L9a9wAX2s1dVv2fT83tBIDEhoVJxRVNjBba6JqdXLwWGE=",
        "SHA256:bYgqXbtb5emO11p4eE2RnZNl67CXgpXBu7LwQ0s3qoY",
        "RSA",
    ),
    // sk-cert.pub
    (
        "sk-ssh-ed25519-cert-v01@openssh.com AAAAI3NrLXNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIA19xUXv7tcTpB36mzJZyV6S3f1Oct1fCBAxzo0bvhm+AAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbW8QijeUmdqzOkiAAAABHNzaDoAAAAAAAAAAAAAAAEAAAAFaWQtc2sAAAALAAAAB3NvbWVvbmUAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg5eRbSjkGoGFm7LVeJLj6YysK6Umitp2eyBkUoiVTor8AAABTAAAAC3NzaC1lZDI1NTE5AAAAQPRA1qMkoSdvfA+HtFJ0CGHTcc6h5HMjB/UiwMXz79OMS4xf1vDzD+9GW/IOFhzhi3U0TBJ+uuZ4n/RbmoqaHAs=",
        "SHA256:Waob+Q0aMrFVZlh0quFilLFF7TWazTaDD2O79RknZPA",
        "ED25519-SK-CERT",
    ),
    // sk.pub
    (
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbW8QijeUmdqzOkiAAAABHNzaDo=",
        "SHA256:Waob+Q0aMrFVZlh0quFilLFF7TWazTaDD2O79RknZPA",
        "ED25519-SK",
    ),
];

#[test]
fn a_key_is_named_as_ssh_keygen_names_it() {
    for (written, printed, kind) in PRINTED {
        let key = SshKey::try_from(written).map_err(|error| format!("{written}: {error}"));
        let named = key.map(|key| fingerprint::of(&key));
        assert_eq!(
            named,
            Ok(Some((kind.to_owned(), printed.to_owned()))),
            "{written}"
        );
    }
}

/// The key a real remote signed a commit with, as `git verify-commit`
/// named it there.
#[test]
fn a_key_is_named_as_git_named_it_on_a_real_remote() {
    let key = SshKey::try_from(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/fZgxPr11UWZgHjQXEU/F65sUwfaohdFFly5gtgRRs",
    );
    assert_eq!(
        key.map(|key| fingerprint::of(&key)),
        Ok(Some((
            "ED25519".to_owned(),
            "SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE".to_owned()
        )))
    );
}

/// A type OpenSSH does not name has no fingerprint here: it is shown as the
/// key itself, never as a fingerprint of the wrong bytes.
#[test]
fn a_type_openssh_does_not_name_has_no_fingerprint() {
    // "unknown-type" and one byte, in an SSH string, as base64.
    let key = SshKey::try_from("unknown-type AAAADHVua25vd24tdHlwZQE=");
    assert_eq!(key.map(|key| fingerprint::of(&key)), Ok(None));
    // A certificate cut short after its nonce.
    let cut = SshKey::try_from(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAAQE=",
    );
    assert_eq!(cut.map(|key| fingerprint::of(&key)), Ok(None));
}

/// A host's key pasted as each tool prints it.
#[test]
fn a_hosts_key_is_read_from_each_form_a_tool_prints() {
    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    let expected = SshKey::try_from(KEY).ok();
    for line in [
        // ssh-keyscan, and a known_hosts line.
        format!("github.com {KEY}"),
        // A hashed known_hosts line.
        format!("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= {KEY}"),
        // A host's own .pub file, with its comment.
        format!("{KEY} root@build"),
        // Marked for a certificate authority, as known_hosts allows.
        format!("@cert-authority *.example.com {KEY}"),
        format!("  {KEY}  "),
    ] {
        assert_eq!(fingerprint::key_in(&line), expected, "{line}");
    }
    for line in ["", "github.com", "ssh-ed25519", "ssh-ed25519 not-base64!"] {
        assert_eq!(fingerprint::key_in(line), None, "{line}");
    }
}
