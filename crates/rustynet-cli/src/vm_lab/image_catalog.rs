//! Lab base-image catalog and the host/image architecture gate.
//!
//! The catalog names the base images a lab host may be provisioned from, and
//! pins each one to a SHA-256 digest. It exists so `add-guest` can be driven by
//! a catalog name instead of a hand-pasted URL, and so the architecture of an
//! image can be checked against the architecture of the host before anything is
//! written to that host's pool.
//!
//! # Why the arch gate exists
//!
//! `provision-guest` builds a copy-on-write overlay and boots it with
//! `virt-install --import`. If the base image is built for a different
//! architecture than the host, nothing rejects it: the domain defines, the guest
//! never reaches userspace, and the failure surfaces as an opaque SSH timeout
//! minutes later. The gate turns that into an immediate, named refusal.
//!
//! # Fail-closed posture
//!
//! Every failure mode in this module denies rather than defaults:
//! - a catalog that does not parse, has an unknown key, or omits a required
//!   field is an error — never a partially-populated entry;
//! - an architecture token outside the closed accept-list is an error — there is
//!   no `_ =>` fallback arm and no "assume the host's arch";
//! - a host architecture that cannot be probed is an error — a declared or
//!   guessed value never substitutes for a measured one;
//! - a digest is mandatory, and its provenance must be stated explicitly, so an
//!   unverifiable image cannot be introduced by omission.
//!
//! The comparison itself is only reachable through
//! [`assert_image_runnable_on`], which takes a parsed [`CatalogImage`] and a
//! [`ProbedHostArch`]. Neither can be constructed from an unvalidated string, so
//! "arch matched" is unreachable without both sides having been parsed from the
//! accept-list. That is a type-level property, not a convention.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{
    LabHost, LabHostKind, ensure_provision_image_name, ensure_script_safe_value,
    load_inventory_with_hosts, resolve_path, run_guest_script, workspace_root_path,
};

/// Repo-relative location of the tracked catalog.
const DEFAULT_IMAGE_CATALOG_PATH: &str = "documents/operations/active/lab_image_catalog.json";

/// Only schema version this binary understands.
///
/// An older binary must refuse a newer catalog rather than silently ignore
/// fields it does not know about. Do not "fix" a version mismatch by widening
/// this check — bump the constant when the schema actually changes.
const SUPPORTED_CATALOG_VERSION: u32 = 1;

/// Upper bound on catalog entries, so a malformed or hostile file cannot make
/// validation quadratic on the duplicate scan.
const MAX_CATALOG_IMAGES: usize = 512;

pub fn default_image_catalog_path() -> PathBuf {
    workspace_root_path().join(DEFAULT_IMAGE_CATALOG_PATH)
}

/// A machine architecture the lab can provision for.
///
/// Deliberately a closed two-variant enum rather than a string: the whole point
/// of the gate is that an unrecognised architecture cannot participate in a
/// comparison at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabArch {
    Amd64,
    Arm64,
}

impl LabArch {
    pub fn as_str(self) -> &'static str {
        match self {
            LabArch::Amd64 => "amd64",
            LabArch::Arm64 => "arm64",
        }
    }
}

impl fmt::Display for LabArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The architecture an image declares.
///
/// `ArchIndependent` is a *claim by the catalog author* that the payload has no
/// architecture — a driver ISO, for example. It disables the gate for that
/// entry, so it is restricted to `kind = "iso"` (see
/// [`CatalogImage::validate`]) and must stay rare. A bootable installer ISO is
/// architecture-specific and must declare `amd64` or `arm64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageArch {
    Fixed(LabArch),
    ArchIndependent,
}

/// Parse the `arch` field of a catalog entry.
///
/// Exact canonical spellings only — no trimming, no case folding. This value
/// lives in a tracked file that humans review, so `"AMD64"` and `" amd64 "` are
/// rejected to keep one architecture from acquiring several spellings. Probed
/// values from a live host are the lenient side; see [`parse_probed_arch`].
pub fn parse_catalog_arch(token: &str) -> Result<ImageArch, String> {
    match token {
        "amd64" => Ok(ImageArch::Fixed(LabArch::Amd64)),
        "arm64" => Ok(ImageArch::Fixed(LabArch::Arm64)),
        "arch_independent" => Ok(ImageArch::ArchIndependent),
        other => Err(format!(
            "catalog schema: arch must be exactly \"amd64\", \"arm64\" or \
             \"arch_independent\" (got {other:?}); canonical spelling is required in a \
             tracked file"
        )),
    }
}

/// Parse an architecture token measured from a live host.
///
/// Lenient on purpose, because the real world spells one architecture several
/// ways and every one of these is something the fleet actually produces:
/// Linux `uname -m` reports `x86_64` / `aarch64`, macOS `uname -m` reports
/// `arm64`, and Windows `%PROCESSOR_ARCHITECTURE%` reports `AMD64`. A naive
/// string comparison against the catalog's spelling would reject correct images.
///
/// Case folding uses [`str::to_ascii_lowercase`], NOT `to_lowercase`: Unicode
/// case folding maps U+212A KELVIN SIGN to `k` and applies Turkish dotted-I
/// rules, which would let a non-ASCII lookalike fold onto a real token. ASCII
/// folding leaves those as unrecognised, so they fail closed.
pub fn parse_probed_arch(token: &str) -> Result<LabArch, String> {
    let normalised = token.trim().to_ascii_lowercase();
    match normalised.as_str() {
        "x86_64" | "amd64" => Ok(LabArch::Amd64),
        "aarch64" | "arm64" => Ok(LabArch::Arm64),
        _ => Err(format!(
            "fail-closed: unrecognised host architecture {token:?} — expected one of \
             x86_64/amd64/aarch64/arm64. Refusing rather than assuming an architecture."
        )),
    }
}

/// A host architecture that was actually established, not assumed.
///
/// There is no public field and no `From<&str>`: the only ways to obtain one are
/// [`probe_host_arch`], which measures the host, and
/// [`ProbedHostArch::assumed_by_operator`], whose name is deliberately
/// unpleasant so that every unverified construction is greppable. Carrying the
/// provenance in the type is what lets [`assert_image_runnable_on`] state in its
/// output whether the gate ran against a measurement or an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbedHostArch {
    arch: LabArch,
    measured: bool,
    host_id: &'static str,
}

impl ProbedHostArch {
    /// An operator-supplied architecture. Weaker than a probe and labelled as
    /// such in every message the gate emits.
    pub fn assumed_by_operator(arch: LabArch) -> Self {
        Self {
            arch,
            measured: false,
            host_id: "<assumed>",
        }
    }

    /// Whether this architecture was measured from the host or asserted by an
    /// operator. Callers surface the difference; they must not silently equate
    /// the two.
    pub fn is_measured(self) -> bool {
        self.measured
    }

    fn provenance(self) -> &'static str {
        if self.measured {
            "measured"
        } else {
            "assumed (operator-supplied, not measured)"
        }
    }
}

/// What sort of artifact a catalog entry points at.
///
/// This is load-bearing rather than descriptive: `provision-guest` treats its
/// base image as a qcow2 backing file (`qemu-img create -F qcow2 -b …`), so
/// handing it an ISO fails at runtime instead of at validation. Recording the
/// kind lets `add-guest` refuse the combination up front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKind {
    /// A cloud image used as a copy-on-write backing file.
    CloudImageQcow2,
    /// An ISO — installer media or a driver disc. Not a valid backing file.
    Iso,
}

/// Where an entry's pinned digest came from.
///
/// Mandatory, and the reason there is no "unpinned" state anywhere in this
/// module. `SecurityMinimumBar` §6.B is explicit that TLS is not a trust
/// transfer: a digest the implementer computed from their own download
/// authenticates nothing beyond "these are the bytes I happened to receive". It
/// is still the best available pin for artifacts whose publisher ships no
/// digest, so it is representable — but it must be *labelled*, not laundered
/// into looking like a vendor attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestProvenance {
    /// The digest is published by the image's publisher.
    UpstreamPublished,
    /// No upstream digest exists; this is trust-on-first-use, recorded from a
    /// specific local fetch. Authenticates continuity, not origin.
    LocalTofu,
}

impl DigestProvenance {
    pub fn as_str(self) -> &'static str {
        match self {
            DigestProvenance::UpstreamPublished => "upstream_published",
            DigestProvenance::LocalTofu => "local_tofu",
        }
    }
}

/// One catalog entry, as it appears in the JSON file.
///
/// `deny_unknown_fields` matters more here than in a typical config: it is what
/// makes a typo loud. Without it `"achr"` or `"sha_256"` would deserialize into
/// a *valid-looking* entry with the real field defaulted or missing, quietly
/// removing the gate's input or the digest pin. It also makes `serde` reject a
/// duplicated JSON key, whereas walking a `serde_json::Value` silently keeps the
/// last one — on a digest field that is a supply-chain hazard, not a nitpick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogImage {
    /// Catalog key callers name, e.g. `debian-13-arm64`.
    pub name: String,
    /// Operating system family, for operator readability.
    pub os: String,
    /// OS release, for operator readability.
    pub os_version: String,
    /// Declared architecture. Parsed by [`parse_catalog_arch`].
    pub arch: String,
    pub kind: ImageKind,
    /// Filename this image is stored under in a host's pool.
    pub filename: String,
    /// `https://` source.
    pub url: String,
    /// Lowercase hex SHA-256 of the artifact.
    pub sha256: String,
    pub digest_provenance: DigestProvenance,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl CatalogImage {
    /// The parsed architecture. Errors rather than defaulting.
    pub fn image_arch(&self) -> Result<ImageArch, String> {
        parse_catalog_arch(self.arch.as_str())
    }

    /// Validate one entry in isolation. Cross-entry rules live in
    /// [`ImageCatalog::validate`].
    fn validate(&self) -> Result<(), String> {
        for (label, value) in [
            ("name", &self.name),
            ("os", &self.os),
            ("os_version", &self.os_version),
            ("arch", &self.arch),
            ("filename", &self.filename),
            ("url", &self.url),
            ("sha256", &self.sha256),
        ] {
            // Trim before the emptiness test: a field of spaces is as absent as
            // an empty string, and only `arch`/`sha256` would be caught later by
            // their own shape checks.
            if value.trim().is_empty() {
                return Err(format!(
                    "catalog schema: {label} must not be empty (image {:?})",
                    self.name
                ));
            }
        }

        ensure_catalog_name(self.name.as_str())?;

        // The filename is consumed by the host scripts, so it must satisfy the
        // consumer's own validator, not merely a local approximation. Calling the
        // real one keeps a catalog-valid entry from being rejected downstream.
        ensure_provision_image_name(self.filename.as_str()).map_err(|err| {
            format!(
                "catalog schema: image {:?} has an unusable filename: {err}",
                self.name
            )
        })?;
        // No `ensure_script_safe_value` on `filename`: `ensure_provision_image_name`
        // is a strict `[A-Za-z0-9._+-]` allowlist, which strictly SUBSUMES that
        // metacharacter deny-list (every character it refuses is already outside the
        // allowlist). A second call would read as an additional control while adding
        // nothing — the shape of redundancy that makes a reader unsure which check is
        // load-bearing.

        if !self.url.starts_with("https://") {
            return Err(format!(
                "catalog schema: image {:?} url must be https (got {:?}); an image is \
                 executable content and must not be fetched in the clear",
                self.name, self.url
            ));
        }
        // `ensure_script_safe_value` directly, rather than the composed
        // `ensure_single_quoted_script_value` its doc steers callers to, is deliberate
        // here: the catalog is not a shell sink. Shell safety for this value is
        // enforced where it is actually used — `shell_quote` at the SSH sink, and
        // `Binding::Literal` in `script_template` — so this check exists for catalog
        // hygiene, to stop a row being authored that a downstream consumer would then
        // reject. Adding the single-quote refusal would also bound URL length, which
        // is not a property a catalog URL should have to satisfy.
        ensure_script_safe_value("url", self.url.as_str())
            .map_err(|err| format!("catalog schema: image {:?}: {err}", self.name))?;

        ensure_catalog_sha256(self.name.as_str(), self.sha256.as_str())?;

        let arch = self.image_arch()?;
        if arch == ImageArch::ArchIndependent && self.kind != ImageKind::Iso {
            return Err(format!(
                "catalog schema: image {:?} declares arch_independent, which is only \
                 permitted for kind=\"iso\" (this entry is a cloud image, and a cloud \
                 image always has an architecture)",
                self.name
            ));
        }

        self.assert_declared_arch_matches_artifact_naming(arch)?;
        Ok(())
    }

    /// Cross-check the declared architecture against the artifact's own naming.
    ///
    /// Without this the gate trusts a hand-typed field that nothing corroborates:
    /// `"arch": "amd64"` on `debian-13-generic-arm64.qcow2` satisfies every other
    /// rule, parses cleanly, and then tells an amd64 host that an arm64 image is
    /// fine — defeating the exact failure the gate exists to prevent, while
    /// reporting success.
    ///
    /// Only the pool filename and the URL's final path segment are scanned.
    /// Scanning the whole URL would false-positive on mirror directory names that
    /// mention an architecture unrelated to the artifact.
    fn assert_declared_arch_matches_artifact_naming(
        &self,
        declared: ImageArch,
    ) -> Result<(), String> {
        let url_basename = self.url.rsplit('/').next().unwrap_or_default();
        for (label, haystack) in [("filename", self.filename.as_str()), ("url", url_basename)] {
            let found = arch_tokens_in(haystack);
            match declared {
                ImageArch::ArchIndependent => {
                    if let Some(found_arch) = found.first() {
                        return Err(format!(
                            "catalog schema: image {:?} declares arch_independent but its \
                             {label} names architecture {found_arch:?} ({haystack:?}) — one \
                             of the two is wrong",
                            self.name
                        ));
                    }
                }
                ImageArch::Fixed(expected) => {
                    for found_arch in &found {
                        if *found_arch != expected {
                            return Err(format!(
                                "catalog schema: image {:?} declares arch {} but its {label} \
                                 names architecture {} ({haystack:?}) — refusing a declared \
                                 architecture the artifact contradicts",
                                self.name,
                                expected.as_str(),
                                found_arch.as_str()
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Architectures named by tokens appearing in `haystack`.
///
/// Substring matching is adequate and safe here because the accept-list tokens
/// do not overlap each other and are not substrings of unrelated words that
/// appear in image names.
fn arch_tokens_in(haystack: &str) -> Vec<LabArch> {
    let lower = haystack.to_ascii_lowercase();
    let mut found = Vec::new();
    for (token, arch) in [
        ("x86_64", LabArch::Amd64),
        ("amd64", LabArch::Amd64),
        ("aarch64", LabArch::Arm64),
        ("arm64", LabArch::Arm64),
    ] {
        if lower.contains(token) && !found.contains(&arch) {
            found.push(arch);
        }
    }
    found
}

/// Catalog names become part of operator commands and log lines, so they are
/// held to the same ASCII-only shape as other lab identifiers.
fn ensure_catalog_name(name: &str) -> Result<(), String> {
    if name.len() > 64 {
        return Err(format!(
            "catalog schema: image name must be 1..=64 chars (got {}): {name:?}",
            name.len()
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
    {
        return Err(format!(
            "catalog schema: image name must be ASCII alphanumeric, '.', '_' or '-': {name:?}"
        ));
    }
    if name.starts_with('-') || name.starts_with('.') {
        return Err(format!(
            "catalog schema: image name must not start with '-' or '.': {name:?}"
        ));
    }
    Ok(())
}

/// Validate a catalog digest.
///
/// Mixed case is accepted and canonicalised to lowercase, matching
/// `normalise_pinned_sha256` in the parent module — vendors publish uppercase
/// digests, and rejecting them would push an operator to bypass the catalog and
/// pass `--sha256` by hand, which is the one outcome the catalog exists to
/// prevent. What is NOT accepted is a wrong length or a non-hex character.
fn ensure_catalog_sha256(image: &str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "catalog schema: image {image:?} sha256 must be 64 hex characters (got {} \
             chars: {trimmed:?})",
            trimmed.len()
        ));
    }
    Ok(())
}

/// The parsed catalog file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageCatalog {
    pub version: u32,
    pub images: Vec<CatalogImage>,
}

impl ImageCatalog {
    /// Parse and fully validate a catalog from disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let body = std::fs::read_to_string(path)
            .map_err(|err| format!("read image catalog {} failed: {err}", path.display()))?;
        Self::from_str_validated(body.as_str())
            .map_err(|err| format!("image catalog {} failed validation: {err}", path.display()))
    }

    /// String-input variant, for tests and in-memory callers.
    pub fn from_str_validated(body: &str) -> Result<Self, String> {
        let parsed: Self = serde_json::from_str(body)
            .map_err(|err| format!("malformed image-catalog JSON: {err}"))?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != SUPPORTED_CATALOG_VERSION {
            return Err(format!(
                "catalog schema: unsupported version {} (this binary understands {}). A \
                 newer catalog is refused rather than partially applied.",
                self.version, SUPPORTED_CATALOG_VERSION
            ));
        }
        if self.images.is_empty() {
            return Err(
                "catalog schema: images must not be empty — an empty catalog is \
                 indistinguishable from a truncated one, so it is refused rather than \
                 reported as healthy"
                    .to_owned(),
            );
        }
        if self.images.len() > MAX_CATALOG_IMAGES {
            return Err(format!(
                "catalog schema: {} images exceeds the {MAX_CATALOG_IMAGES} entry limit",
                self.images.len()
            ));
        }

        for image in &self.images {
            image.validate()?;
        }

        for (index, image) in self.images.iter().enumerate() {
            for other in self.images.iter().skip(index + 1) {
                // Names are compared case-insensitively: two entries differing
                // only by case are one name as far as an operator is concerned,
                // and letting both exist invites naming the wrong one.
                if image.name.eq_ignore_ascii_case(other.name.as_str()) {
                    return Err(format!(
                        "catalog schema: duplicate image name {:?} (names are compared \
                         case-insensitively)",
                        image.name
                    ));
                }
                if image.filename == other.filename {
                    // One pool filename is one file on disk. If two entries share
                    // it they must agree on everything that describes those bytes;
                    // otherwise naming one entry or the other yields a different
                    // verdict for the same file — including a different
                    // architecture, which would let the gate be dodged by choosing
                    // the convenient alias.
                    if image.sha256.eq_ignore_ascii_case(other.sha256.as_str())
                        && image.arch == other.arch
                        && image.kind == other.kind
                        && image.os == other.os
                        && image.os_version == other.os_version
                    {
                        continue;
                    }
                    return Err(format!(
                        "catalog schema: images {:?} and {:?} share filename {:?} but \
                         describe it differently (sha256/arch/kind/os must be identical \
                         — one pool filename is one file)",
                        image.name, other.name, image.filename
                    ));
                }
            }
        }
        Ok(())
    }

    /// Look up an entry by name, case-insensitively.
    ///
    /// A miss is an error, not `None`-as-permission: every caller of this is
    /// about to act on the result, and "the name you asked for is not in the
    /// catalog" must stop that.
    pub fn image(&self, name: &str) -> Result<&CatalogImage, String> {
        self.images
            .iter()
            .find(|image| image.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                let mut known: Vec<&str> = self
                    .images
                    .iter()
                    .map(|image| image.name.as_str())
                    .collect();
                known.sort_unstable();
                format!(
                    "fail-closed: no image named {name:?} in the catalog (known: {})",
                    known.join(", ")
                )
            })
    }
}

/// The gate. Refuses unless the image can run on this host.
///
/// Takes a validated [`CatalogImage`] and a [`ProbedHostArch`] rather than two
/// strings, so it cannot be reached with an unparsed architecture on either
/// side, and the entry it reports on is the entry that was checked.
///
/// An `arch_independent` entry is allowed on any host by construction — that is
/// what the declaration means, and [`CatalogImage::validate`] has already
/// confined it to ISOs and confirmed the artifact's naming does not contradict
/// it.
pub fn assert_image_runnable_on(
    image: &CatalogImage,
    host: &ProbedHostArch,
) -> Result<String, String> {
    let declared = image.image_arch()?;
    match declared {
        ImageArch::ArchIndependent => Ok(format!(
            "GATE: RAN — image {:?} is arch_independent (kind=iso); host {} arch {} \
             [{}] imposes no constraint",
            image.name,
            host.host_id,
            host.arch.as_str(),
            host.provenance()
        )),
        ImageArch::Fixed(image_arch) if image_arch == host.arch => Ok(format!(
            "GATE: RAN — PASS: image {:?} arch {} matches host {} arch {} [{}]",
            image.name,
            image_arch.as_str(),
            host.host_id,
            host.arch.as_str(),
            host.provenance()
        )),
        // The wording matters for the exit code: `classify_cli_error` maps
        // "fail-closed" to PolicyReject (78, "do not retry") and words like
        // "timeout"/"retry"/"transient" to TransientFailure (70, "CI may retry").
        // An architecture mismatch is a policy denial that retrying cannot fix, so
        // this message must not contain any transient-sounding word — the
        // classifier's branch order happens to favour PolicyReject today, but
        // depending on that order would make a reordering silently turn this into
        // a retryable error.
        ImageArch::Fixed(image_arch) => Err(format!(
            "GATE: RAN — fail-closed: image {:?} is built for {} but host {} is {} [{}]. \
             Provisioning would define a domain that never reaches userspace, surfacing \
             much later as an unreachable guest. Refusing.",
            image.name,
            image_arch.as_str(),
            host.host_id,
            host.arch.as_str(),
            host.provenance()
        )),
    }
}

/// Measure a lab host's architecture.
///
/// Fails closed on an unreachable host, a non-zero probe, empty output, or a
/// token outside the accept-list. There is deliberately no declared-value
/// fallback: a value that cannot be measured is unknown, and the gate is
/// worthless if "unknown" resolves to "probably fine".
pub fn probe_host_arch(
    host: &LabHost,
    ssh_identity_file: Option<&Path>,
    known_hosts_path: Option<&Path>,
    timeout: Duration,
) -> Result<ProbedHostArch, String> {
    let host_id = leak_host_id(host.host_id.as_str());
    match host.ssh_endpoint() {
        // No SSH endpoint means the record describes the machine this process is
        // running on, so the compiled-in target architecture IS the measurement.
        None => {
            let arch = parse_probed_arch(std::env::consts::ARCH).map_err(|err| {
                format!("host {host_id} is local and its architecture is unusable: {err}")
            })?;
            Ok(ProbedHostArch {
                arch,
                measured: true,
                host_id,
            })
        }
        Some(endpoint) => {
            if host.kind != LabHostKind::Libvirt {
                return Err(format!(
                    "fail-closed: host {host_id} is kind={} with an SSH endpoint; \
                     architecture probing is implemented for libvirt hosts and the local \
                     machine only",
                    host.kind.as_str()
                ));
            }
            let ssh_user = endpoint.split_once('@').map(|(user, _)| user.to_owned());
            let target = endpoint
                .split_once('@')
                .map(|(_, addr)| addr.to_owned())
                .unwrap_or_else(|| endpoint.clone());
            let output = run_guest_script(
                target.as_str(),
                ssh_user.as_deref(),
                "set -eu; uname -m\n",
                false,
                ssh_identity_file,
                known_hosts_path,
                timeout,
            )
            .map_err(|err| format!("fail-closed: probing host {host_id} architecture: {err}"))?;
            let token = output
                .lines()
                .map(str::trim)
                .rfind(|line| !line.is_empty())
                .ok_or_else(|| {
                    format!("fail-closed: host {host_id} returned no architecture from `uname -m`")
                })?;
            let arch = parse_probed_arch(token).map_err(|err| format!("host {host_id}: {err}"))?;
            Ok(ProbedHostArch {
                arch,
                measured: true,
                host_id,
            })
        }
    }
}

/// `ProbedHostArch` carries a `&'static str` host id so it stays `Copy` and can
/// be embedded in messages without lifetime plumbing through the CLI layer.
/// Host ids come from the inventory, are few, and live for the process, so
/// interning them is bounded — an unbounded leak would be a different matter.
fn leak_host_id(host_id: &str) -> &'static str {
    Box::leak(host_id.to_owned().into_boxed_str())
}

/// Config for `ops vm-lab-image-catalog`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VmLabImageCatalogConfig {
    pub catalog_path: Option<PathBuf>,
    pub inventory_path: Option<PathBuf>,
    /// Entry to inspect or gate. Required for both gate modes.
    pub name: Option<String>,
    /// Probe this host's architecture and gate `--name` against it.
    pub host_id: Option<String>,
    /// Gate `--name` against an operator-asserted architecture instead of a probe.
    pub assume_host_arch: Option<String>,
    /// Explicitly ask for the non-gating listing mode.
    pub list: bool,
    pub ssh_identity_file: Option<PathBuf>,
    pub known_hosts_path: Option<PathBuf>,
    pub timeout_secs: u64,
}

/// Validate the catalog, and optionally run the arch gate.
///
/// Mode is selected by an explicit flag, never by the absence of one. That is
/// not stylistic: the ops option parser turns a value-less `--foo` into a flag
/// and does not reject unknown options, so `--host-arch` (typo'd, or with its
/// value swallowed) would otherwise silently select a mode that exits 0 without
/// gating — making "gate not run" indistinguishable from "gate passed" in the
/// one command whose purpose is to be a gate. Every successful gating run prints
/// `GATE: RAN`; the listing mode prints `GATE: NOT RUN`.
pub fn execute_ops_vm_lab_image_catalog(config: VmLabImageCatalogConfig) -> Result<String, String> {
    let catalog_path = match config.catalog_path.as_deref() {
        Some(path) => resolve_path(path)?,
        None => default_image_catalog_path(),
    };
    let catalog = ImageCatalog::load(catalog_path.as_path())?;

    let gate_by_probe = config.host_id.is_some();
    let gate_by_assumption = config.assume_host_arch.is_some();
    if gate_by_probe && gate_by_assumption {
        return Err(
            "--host and --assume-host-arch are mutually exclusive: a measured \
             architecture and an asserted one cannot both be the gate's input"
                .to_owned(),
        );
    }
    if config.list && (gate_by_probe || gate_by_assumption) {
        return Err(
            "--list does not gate; drop it to gate with --host or --assume-host-arch".to_owned(),
        );
    }
    if !config.list && !gate_by_probe && !gate_by_assumption {
        return Err(
            "vm-lab-image-catalog requires an explicit mode: --list to validate and \
             list, or --name <image> with --host <host_id> (measured) or \
             --assume-host-arch <token> (asserted) to run the gate"
                .to_owned(),
        );
    }

    if config.list {
        let mut out = format!(
            "catalog {} — {} image(s), schema v{} VALID\nGATE: NOT RUN (listing mode; \
             pass --name with --host or --assume-host-arch to gate)\n",
            catalog_path.display(),
            catalog.images.len(),
            catalog.version
        );
        for image in &catalog.images {
            out.push_str(&format!(
                "  {:<28} {:<8} {:<18} {:<10} {} sha256:{}… [{}]\n",
                image.name,
                image.arch,
                format!("{} {}", image.os, image.os_version),
                match image.kind {
                    ImageKind::CloudImageQcow2 => "qcow2",
                    ImageKind::Iso => "iso",
                },
                image.filename,
                &image.sha256[..12.min(image.sha256.len())],
                image.digest_provenance.as_str(),
            ));
        }
        return Ok(out);
    }

    let name = config
        .name
        .as_deref()
        .ok_or_else(|| "vm-lab-image-catalog requires --name <image> when gating".to_owned())?;
    let image = catalog.image(name)?;

    let host_arch = if let Some(host_id) = config.host_id.as_deref() {
        let inventory_path = match config.inventory_path.as_deref() {
            Some(path) => resolve_path(path)?,
            None => super::default_inventory_path(),
        };
        let (_entries, hosts) = load_inventory_with_hosts(inventory_path.as_path())?;
        let host = hosts
            .iter()
            .find(|host| host.host_id == host_id)
            .ok_or_else(|| format!("unknown host_id: {host_id}"))?;
        probe_host_arch(
            host,
            config.ssh_identity_file.as_deref(),
            config.known_hosts_path.as_deref(),
            Duration::from_secs(if config.timeout_secs == 0 {
                60
            } else {
                config.timeout_secs
            }),
        )?
    } else {
        let token = config.assume_host_arch.as_deref().unwrap_or_default();
        ProbedHostArch::assumed_by_operator(parse_probed_arch(token)?)
    };

    let verdict = assert_image_runnable_on(image, &host_arch)?;
    let mut out = format!("{verdict}\n");
    if !host_arch.is_measured() {
        // A pass on an asserted architecture is only as good as the assertion. Say
        // so on the passing path too — a caution that appears only on failure is a
        // caution nobody reads.
        out.push_str(
            "NOTE: the host architecture was ASSERTED by the operator, not measured. \
             This verdict is only as trustworthy as that assertion — pass --host \
             <host_id> to probe the real host instead.\n",
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A catalog covering both architectures and both artifact kinds.
    fn catalog_json(entries: &str) -> String {
        format!("{{\"version\":1,\"images\":[{entries}]}}")
    }

    const ARM_ENTRY: &str = r#"{
        "name":"debian-13-arm64","os":"debian","os_version":"13","arch":"arm64",
        "kind":"cloud_image_qcow2","filename":"debian-13-generic-arm64.qcow2",
        "url":"https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2",
        "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "digest_provenance":"upstream_published"
    }"#;

    const AMD_ENTRY: &str = r#"{
        "name":"rocky-10-amd64","os":"rocky","os_version":"10","arch":"amd64",
        "kind":"cloud_image_qcow2","filename":"Rocky-10-GenericCloud.latest.x86_64.qcow2",
        "url":"https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud.latest.x86_64.qcow2",
        "sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "digest_provenance":"upstream_published"
    }"#;

    const ISO_ENTRY: &str = r#"{
        "name":"virtio-win","os":"windows","os_version":"any","arch":"arch_independent",
        "kind":"iso","filename":"virtio-win.iso",
        "url":"https://fedorapeople.org/groups/virt/virtio-win/virtio-win.iso",
        "sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "digest_provenance":"local_tofu"
    }"#;

    fn arm() -> CatalogImage {
        let catalog = ImageCatalog::from_str_validated(&catalog_json(ARM_ENTRY))
            .expect("fixture must be valid");
        catalog.images[0].clone()
    }

    // ---- default-deny / fail-closed on the arch primitives -----------------

    #[test]
    fn probed_arch_accepts_every_spelling_the_fleet_actually_produces() {
        for token in ["x86_64", "amd64", "AMD64", " x86_64 ", "X86_64"] {
            assert_eq!(parse_probed_arch(token), Ok(LabArch::Amd64), "{token:?}");
        }
        for token in ["aarch64", "arm64", "ARM64", " aarch64\n"] {
            assert_eq!(parse_probed_arch(token), Ok(LabArch::Arm64), "{token:?}");
        }
    }

    #[test]
    fn probed_arch_rejects_everything_else_rather_than_defaulting() {
        for token in [
            "", "   ", "i686", "i386", "x86", "arm", "armv7l", "armv8l", "riscv64", "unknown",
            "(none)", "x64", "amd", "64",
        ] {
            let err = parse_probed_arch(token).expect_err("must reject");
            assert!(err.contains("fail-closed"), "{token:?} -> {err}");
        }
    }

    /// Unicode case folding would map some non-ASCII lookalikes onto real
    /// tokens; ASCII folding must leave them unrecognised.
    #[test]
    fn probed_arch_rejects_non_ascii_lookalikes() {
        for token in ["ARM64\u{212A}", "aarch6\u{2074}", "\u{0430}rm64"] {
            assert!(parse_probed_arch(token).is_err(), "{token:?}");
        }
    }

    #[test]
    fn catalog_arch_requires_canonical_spelling() {
        assert_eq!(
            parse_catalog_arch("amd64"),
            Ok(ImageArch::Fixed(LabArch::Amd64))
        );
        assert_eq!(
            parse_catalog_arch("arm64"),
            Ok(ImageArch::Fixed(LabArch::Arm64))
        );
        assert_eq!(
            parse_catalog_arch("arch_independent"),
            Ok(ImageArch::ArchIndependent)
        );
        // Lenient spellings are fine from a live host but not in a tracked file.
        for token in ["AMD64", " amd64", "amd64 ", "x86_64", "aarch64", "any", ""] {
            assert!(parse_catalog_arch(token).is_err(), "{token:?}");
        }
    }

    // ---- the gate ----------------------------------------------------------

    #[test]
    fn gate_passes_only_on_a_real_match() {
        let arm_image = arm();
        let ok = assert_image_runnable_on(
            &arm_image,
            &ProbedHostArch::assumed_by_operator(LabArch::Arm64),
        )
        .expect("arm64 image on an arm64 host");
        assert!(ok.contains("GATE: RAN"));
        assert!(ok.contains("PASS"));

        let err = assert_image_runnable_on(
            &arm_image,
            &ProbedHostArch::assumed_by_operator(LabArch::Amd64),
        )
        .expect_err("arm64 image on an amd64 host must be refused");
        assert!(err.contains("GATE: RAN"), "{err}");
        assert!(err.contains("fail-closed"), "{err}");
        assert!(err.contains("arm64") && err.contains("amd64"), "{err}");
    }

    /// The mismatch message must classify as a policy rejection, not a
    /// transient failure — a CI wrapper must never retry an arch mismatch.
    #[test]
    fn gate_mismatch_message_has_no_transient_sounding_words() {
        let err =
            assert_image_runnable_on(&arm(), &ProbedHostArch::assumed_by_operator(LabArch::Amd64))
                .expect_err("must refuse");
        let lower = err.to_ascii_lowercase();
        assert!(lower.contains("fail-closed"), "{err}");
        for transient in [
            "connection refused",
            "temporarily unavailable",
            "retry",
            "transient",
        ] {
            assert!(!lower.contains(transient), "{transient:?} in {err}");
        }
        // "timeout"/"timed out" would also misclassify as transient. The message
        // explains the symptom without using either spelling.
        assert!(!lower.contains("timed out"), "{err}");
        assert!(!lower.contains("timeout"), "{err}");
    }

    #[test]
    fn arch_independent_iso_runs_anywhere_but_says_the_gate_ran() {
        let catalog = ImageCatalog::from_str_validated(&catalog_json(ISO_ENTRY)).expect("valid");
        for arch in [LabArch::Amd64, LabArch::Arm64] {
            let out = assert_image_runnable_on(
                &catalog.images[0],
                &ProbedHostArch::assumed_by_operator(arch),
            )
            .expect("arch_independent is allowed anywhere");
            assert!(out.contains("GATE: RAN"), "{out}");
            assert!(out.contains("arch_independent"), "{out}");
        }
    }

    /// A measured verdict and an asserted one must be distinguishable in output.
    #[test]
    fn gate_output_records_whether_the_host_arch_was_measured() {
        let assumed = ProbedHostArch::assumed_by_operator(LabArch::Arm64);
        assert!(!assumed.is_measured());
        let out = assert_image_runnable_on(&arm(), &assumed).expect("match");
        assert!(out.contains("assumed"), "{out}");
        assert!(out.contains("not measured"), "{out}");
    }

    // ---- catalog schema: every rule denies -------------------------------

    #[test]
    fn valid_catalog_loads() {
        let body = catalog_json(&format!("{ARM_ENTRY},{AMD_ENTRY},{ISO_ENTRY}"));
        let catalog = ImageCatalog::from_str_validated(&body).expect("must load");
        assert_eq!(catalog.images.len(), 3);
        assert_eq!(
            catalog.image("DEBIAN-13-ARM64").map(|i| i.name.as_str()),
            Ok("debian-13-arm64")
        );
    }

    #[test]
    fn lookup_miss_denies() {
        let catalog = ImageCatalog::from_str_validated(&catalog_json(ARM_ENTRY)).expect("valid");
        let err = catalog.image("nope").expect_err("a miss must deny");
        assert!(err.contains("fail-closed"), "{err}");
    }

    #[test]
    fn empty_catalog_is_refused_not_reported_healthy() {
        let err = ImageCatalog::from_str_validated("{\"version\":1,\"images\":[]}")
            .expect_err("empty must be refused");
        assert!(err.contains("must not be empty"), "{err}");
    }

    #[test]
    fn version_must_be_exactly_one() {
        for body in [
            "{\"images\":[]}",
            "{\"version\":\"1\",\"images\":[]}",
            "{\"version\":2,\"images\":[]}",
            "{\"version\":0,\"images\":[]}",
        ] {
            assert!(ImageCatalog::from_str_validated(body).is_err(), "{body}");
        }
    }

    #[test]
    fn non_object_root_is_refused() {
        for body in ["[]", "null", "\"catalog\"", "3"] {
            assert!(ImageCatalog::from_str_validated(body).is_err(), "{body}");
        }
    }

    #[test]
    fn unknown_keys_are_refused_at_both_levels() {
        let top = format!("{{\"version\":1,\"extra\":true,\"images\":[{ARM_ENTRY}]}}");
        assert!(ImageCatalog::from_str_validated(&top).is_err());
        let entry = ARM_ENTRY.replace("\"os\":", "\"achr\":\"arm64\",\"os\":");
        assert!(ImageCatalog::from_str_validated(&catalog_json(&entry)).is_err());
    }

    /// `serde_json` keeps the LAST duplicate key when walking a `Value`; the
    /// derive path rejects it. On a digest field that difference is the whole
    /// reason this module uses the derive path.
    #[test]
    fn duplicate_json_keys_are_refused() {
        let entry = ARM_ENTRY.replace(
            "\"digest_provenance\":\"upstream_published\"",
            "\"digest_provenance\":\"upstream_published\",\
             \"sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"",
        );
        let err = ImageCatalog::from_str_validated(&catalog_json(&entry))
            .expect_err("a duplicated sha256 must be refused, not silently last-wins");
        assert!(err.to_ascii_lowercase().contains("sha256"), "{err}");
    }

    #[test]
    fn every_required_field_is_required() {
        for field in [
            "\"name\"",
            "\"os\"",
            "\"os_version\"",
            "\"arch\"",
            "\"kind\"",
            "\"filename\"",
            "\"url\"",
            "\"sha256\"",
            "\"digest_provenance\"",
        ] {
            let entry = ARM_ENTRY.replace(field, "\"unused_key\"");
            assert!(
                ImageCatalog::from_str_validated(&catalog_json(&entry)).is_err(),
                "missing {field} must be refused"
            );
        }
    }

    #[test]
    fn whitespace_only_fields_are_treated_as_absent() {
        for (field, blank) in [("\"debian\"", "\"   \""), ("\"13\"", "\" \"")] {
            let entry = ARM_ENTRY.replace(field, blank);
            let err = ImageCatalog::from_str_validated(&catalog_json(&entry))
                .expect_err("whitespace-only must be refused");
            assert!(err.contains("must not be empty"), "{err}");
        }
    }

    #[test]
    fn url_must_be_https() {
        for bad in [
            "http://cloud.debian.org/x-arm64.qcow2",
            "ftp://cloud.debian.org/x-arm64.qcow2",
            "cloud.debian.org/x-arm64.qcow2",
            "https:/cloud.debian.org/x-arm64.qcow2",
        ] {
            let entry = ARM_ENTRY.replace(
                "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2",
                bad,
            );
            assert!(
                ImageCatalog::from_str_validated(&catalog_json(&entry)).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn sha256_shape_is_enforced_but_case_is_canonicalised() {
        let good = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let entry = ARM_ENTRY.replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            good,
        );
        assert!(
            ImageCatalog::from_str_validated(&catalog_json(&entry)).is_ok(),
            "an uppercase digest must be accepted — rejecting it pushes operators to \
             bypass the catalog"
        );
        for bad in [
            "aaaa",
            "",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            let entry = ARM_ENTRY.replace(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                bad,
            );
            assert!(
                ImageCatalog::from_str_validated(&catalog_json(&entry)).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn duplicate_names_are_refused_including_case_only_differences() {
        let dup = ARM_ENTRY.replace("debian-13-arm64\"", "DEBIAN-13-ARM64\"");
        let body = catalog_json(&format!("{ARM_ENTRY},{dup}"));
        let err = ImageCatalog::from_str_validated(&body).expect_err("must refuse");
        assert!(err.contains("duplicate image name"), "{err}");
    }

    #[test]
    fn one_pool_filename_must_describe_one_file() {
        // Same filename, different digest.
        let conflicting = ARM_ENTRY
            .replace("debian-13-arm64\"", "debian-13-arm64-alias\"")
            .replace(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            );
        let err =
            ImageCatalog::from_str_validated(&catalog_json(&format!("{ARM_ENTRY},{conflicting}")))
                .expect_err("must refuse");
        assert!(err.contains("share filename"), "{err}");
    }

    /// The gate-dodging alias: same file, same digest, contradictory arch.
    /// Rejecting only *differing digests* would leave this open, and a caller
    /// could then name whichever alias claimed the convenient architecture and
    /// get a different verdict for the same bytes.
    ///
    /// The fixture is architecture-neutral in both filename and URL so that the
    /// artifact-naming cross-check cannot fire first — this must prove the
    /// duplicate-filename rule is what catches it.
    #[test]
    fn same_filename_with_a_different_arch_is_refused() {
        const NEUTRAL_ARM: &str = r#"{
            "name":"neutral-arm","os":"debian","os_version":"13","arch":"arm64",
            "kind":"cloud_image_qcow2","filename":"debian-13-generic.qcow2",
            "url":"https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic.qcow2",
            "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "digest_provenance":"upstream_published"
        }"#;
        // Sanity: the neutral entry alone is valid, so the failure below is
        // attributable to the duplicate rule and nothing else.
        assert!(ImageCatalog::from_str_validated(&catalog_json(NEUTRAL_ARM)).is_ok());

        let lie = NEUTRAL_ARM
            .replace("\"neutral-arm\"", "\"neutral-arm-lie\"")
            .replace("\"arch\":\"arm64\"", "\"arch\":\"amd64\"");
        let err = ImageCatalog::from_str_validated(&catalog_json(&format!("{NEUTRAL_ARM},{lie}")))
            .expect_err("same filename + same digest + contradictory arch must be refused");
        assert!(err.contains("share filename"), "{err}");
    }

    // ---- the lying-arch-field hole ---------------------------------------

    #[test]
    fn declared_arch_must_match_the_filename() {
        let lie = ARM_ENTRY.replace("\"arch\":\"arm64\"", "\"arch\":\"amd64\"");
        let err = ImageCatalog::from_str_validated(&catalog_json(&lie))
            .expect_err("a declared arch the artifact contradicts must be refused");
        assert!(err.contains("contradicts"), "{err}");
    }

    #[test]
    fn declared_arch_must_match_the_url_basename() {
        let lie = AMD_ENTRY
            .replace("\"arch\":\"amd64\"", "\"arch\":\"arm64\"")
            .replace(
                "\"filename\":\"Rocky-10-GenericCloud.latest.x86_64.qcow2\"",
                "\"filename\":\"Rocky-10-GenericCloud.latest.qcow2\"",
            );
        let err = ImageCatalog::from_str_validated(&catalog_json(&lie))
            .expect_err("the url basename must be cross-checked too");
        assert!(err.contains("contradicts"), "{err}");
    }

    #[test]
    fn arch_independent_must_not_name_an_architecture() {
        let lie = ISO_ENTRY.replace("virtio-win.iso\"", "virtio-win-amd64.iso\"");
        let err = ImageCatalog::from_str_validated(&catalog_json(&lie))
            .expect_err("arch_independent contradicted by its own name must be refused");
        assert!(err.contains("arch_independent"), "{err}");
    }

    /// A mirror directory naming an unrelated architecture must not false-fail;
    /// only the URL's final segment is scanned.
    #[test]
    fn unrelated_architecture_in_a_mirror_path_does_not_false_fail() {
        let entry = ARM_ENTRY.replace(
            "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-arm64.qcow2",
            "https://mirror.example.org/x86_64-host/debian/debian-13-generic-arm64.qcow2",
        );
        assert!(ImageCatalog::from_str_validated(&catalog_json(&entry)).is_ok());
    }

    // ---- kind / provenance ------------------------------------------------

    #[test]
    fn arch_independent_is_iso_only() {
        let lie = ISO_ENTRY.replace("\"kind\":\"iso\"", "\"kind\":\"cloud_image_qcow2\"");
        let err = ImageCatalog::from_str_validated(&catalog_json(&lie))
            .expect_err("a cloud image always has an architecture");
        assert!(
            err.contains("only \\\npermitted") || err.contains("permitted for kind"),
            "{err}"
        );
    }

    #[test]
    fn kind_and_provenance_reject_unknown_variants() {
        let bad_kind = ARM_ENTRY.replace("\"cloud_image_qcow2\"", "\"raw\"");
        assert!(ImageCatalog::from_str_validated(&catalog_json(&bad_kind)).is_err());
        let bad_prov = ARM_ENTRY.replace("\"upstream_published\"", "\"trust_me\"");
        assert!(ImageCatalog::from_str_validated(&catalog_json(&bad_prov)).is_err());
    }

    /// A TOFU pin must stay distinguishable from a vendor-attested one. Losing
    /// that distinction is how TLS-only trust gets laundered into something that
    /// looks authoritative forever.
    #[test]
    fn tofu_provenance_is_representable_and_labelled() {
        let catalog = ImageCatalog::from_str_validated(&catalog_json(ISO_ENTRY)).expect("valid");
        assert_eq!(
            catalog.images[0].digest_provenance,
            DigestProvenance::LocalTofu
        );
        assert_eq!(
            DigestProvenance::LocalTofu.as_str(),
            "local_tofu",
            "the label must survive into output"
        );
    }

    // ---- filename shape ---------------------------------------------------

    #[test]
    fn filename_must_satisfy_the_consumer_validator() {
        for bad in [
            "../../etc/passwd",
            "/etc/passwd",
            "sub/dir.qcow2",
            "x'; id; '.qcow2",
            "a$b.qcow2",
            "a b.qcow2",
            "-rf.qcow2",
            "debıan-arm64.qcow2",
        ] {
            let entry = ARM_ENTRY.replace("debian-13-generic-arm64.qcow2\"", &format!("{bad}\""));
            assert!(
                ImageCatalog::from_str_validated(&catalog_json(&entry)).is_err(),
                "{bad:?}"
            );
        }
    }

    /// Every catalog-valid entry must also satisfy the validators the host
    /// scripts apply, or a validated row would be rejected downstream.
    #[test]
    fn catalog_valid_entries_pass_the_consumer_validators() {
        let body = catalog_json(&format!("{ARM_ENTRY},{AMD_ENTRY},{ISO_ENTRY}"));
        let catalog = ImageCatalog::from_str_validated(&body).expect("valid");
        for image in &catalog.images {
            assert!(
                ensure_provision_image_name(image.filename.as_str()).is_ok(),
                "{:?}",
                image.filename
            );
            assert!(ensure_script_safe_value("filename", image.filename.as_str()).is_ok());
            assert!(ensure_script_safe_value("url", image.url.as_str()).is_ok());
        }
    }

    #[test]
    fn catalog_name_shape_is_enforced() {
        for bad in [
            "-leading",
            ".leading",
            "has space",
            "has/slash",
            "has'quote",
        ] {
            let entry = ARM_ENTRY.replace("\"debian-13-arm64\"", &format!("\"{bad}\""));
            assert!(
                ImageCatalog::from_str_validated(&catalog_json(&entry)).is_err(),
                "{bad:?}"
            );
        }
    }

    /// The catalog that ships in the repo must satisfy every rule in this module.
    /// Without this, a hand-edit could land a catalog that no test ever parses and
    /// the first failure would be an operator running a live command.
    #[test]
    fn the_tracked_catalog_file_is_valid() {
        let path = default_image_catalog_path();
        let catalog = ImageCatalog::load(path.as_path())
            .unwrap_or_else(|err| panic!("tracked catalog {} is invalid: {err}", path.display()));
        assert!(!catalog.images.is_empty());
        // Every arch_independent entry must be an ISO, and vice-versa is NOT
        // implied — an ISO may legitimately be arch-specific installer media.
        for image in &catalog.images {
            if image.image_arch() == Ok(ImageArch::ArchIndependent) {
                assert_eq!(image.kind, ImageKind::Iso, "{}", image.name);
            }
        }
    }

    // ---- the verb's mode selection ---------------------------------------

    #[test]
    fn gating_requires_an_explicit_mode() {
        // No mode at all must not silently list-and-succeed.
        let err = execute_ops_vm_lab_image_catalog(VmLabImageCatalogConfig::default())
            .expect_err("absence of a mode must be an error, not the permissive branch");
        assert!(err.contains("requires an explicit mode"), "{err}");
    }

    #[test]
    fn probe_and_assumption_cannot_both_be_the_gate_input() {
        let config = VmLabImageCatalogConfig {
            name: Some("debian-13-arm64".to_owned()),
            host_id: Some("ubuntu-kvm-1".to_owned()),
            assume_host_arch: Some("x86_64".to_owned()),
            ..Default::default()
        };
        let err = execute_ops_vm_lab_image_catalog(config).expect_err("must refuse both");
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn list_does_not_gate_and_says_so() {
        let config = VmLabImageCatalogConfig {
            list: true,
            assume_host_arch: Some("x86_64".to_owned()),
            ..Default::default()
        };
        let err = execute_ops_vm_lab_image_catalog(config)
            .expect_err("--list combined with a gate input is a contradiction");
        assert!(err.contains("does not gate"), "{err}");
    }

    #[test]
    fn an_unparseable_assumed_arch_denies_rather_than_skipping_the_gate() {
        let config = VmLabImageCatalogConfig {
            name: Some("debian-13-arm64".to_owned()),
            assume_host_arch: Some(String::new()),
            ..Default::default()
        };
        let err = execute_ops_vm_lab_image_catalog(config).expect_err("must deny");
        assert!(
            err.contains("fail-closed") || err.contains("requires an explicit mode"),
            "{err}"
        );
    }
}
