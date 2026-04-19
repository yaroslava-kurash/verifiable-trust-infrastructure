use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use dialoguer::{Input, Select};
use ed25519_dalek::SigningKey;
use rand::Rng;
use vta_sdk::credentials::CredentialBundle;
use vta_sdk::prelude::*;

use crate::auth;
use crate::config::{PnmConfig, VtaConfig, save_config, slugify, vta_keyring_key};

/// Options for interactive setup from the CLI.
pub struct SetupOptions {
    /// Path to an armored sealed bundle (skip the interactive menu).
    pub credential_bundle: Option<PathBuf>,
    /// Expected SHA-256 digest of the sealed bundle.
    pub expect_digest: Option<String>,
    /// Skip out-of-band digest verification.
    pub no_verify_digest: bool,
}

/// Interactive setup for PNM.
///
/// Presents the user with a choice between connecting to an existing VTA
/// (with a sealed admin credential bundle) or preparing a new TEE deployment
/// (generating a did:key for the config).
pub async fn run_setup(
    opts: SetupOptions,
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    // If a bundle was passed on the CLI, skip the menu
    if let Some(path) = opts.credential_bundle {
        return setup_with_bundle(
            &path,
            opts.expect_digest.as_deref(),
            opts.no_verify_digest,
            config,
        )
        .await;
    }

    let choices = &[
        "Connect to an existing non-TEE VTA",
        "Set up a new VTA in a TEE  — generate admin identity for enclave deployment",
    ];

    let selection = Select::new()
        .with_prompt("What would you like to do?")
        .items(choices)
        .default(0)
        .interact()?;

    match selection {
        0 => connect_to_non_tee_vta(config).await,
        1 => setup_tee(config).await,
        _ => unreachable!(),
    }
}

/// "Connect to an existing non-TEE VTA" branch.
///
/// Splits into two sub-flows depending on whether the operator can reach the
/// VTA directly from this machine:
///
/// - **Online**: PNM generates a fresh did:key locally, stores the session,
///   and prints an `vta acl create ...` command the admin runs on the VTA
///   host. The private key never leaves this machine; no sealed transfer
///   is involved because there's nothing to transfer.
/// - **Offline**: The full sealed-transfer credential dance. PNM creates a
///   request file; admin mints and seals a credential; PNM opens it.
async fn connect_to_non_tee_vta(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    let reachable_options = &[
        "Online  — I can reach the VTA from this machine",
        "Offline — I can't reach the VTA directly; my admin will send me a credential",
    ];
    let reachable = Select::new()
        .with_prompt("Is the VTA reachable from here?")
        .items(reachable_options)
        .default(0)
        .interact()?;

    match reachable {
        0 => connect_online_non_tee(config).await,
        1 => connect_offline_non_tee(config).await,
        _ => unreachable!(),
    }
}

/// Online connection to a non-TEE VTA.
///
/// Generates a local did:key, stores a session pre-populated with the
/// operator-provided VTA URL + DID, and prints the `vta acl create`
/// command for the admin to run. The admin's action is authoritative —
/// until they add the did:key to the ACL, PNM will fail to authenticate.
async fn connect_online_non_tee(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    let url: String = Input::new()
        .with_prompt("VTA URL (e.g. https://vta.example.com)")
        .interact_text()?;
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err("VTA URL is required".into());
    }

    let vta_did: String = Input::new()
        .with_prompt("VTA DID (ask your admin, or see `vta config show`)")
        .interact_text()?;
    let vta_did = vta_did.trim().to_string();
    if !vta_did.starts_with("did:") {
        return Err("VTA DID must start with `did:` (e.g. did:webvh:... or did:key:...)".into());
    }

    let default_name = vta_did
        .rsplit(':')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("my-vta")
        .to_string();
    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default(default_name)
        .interact_text()?;

    let slug = slugify(&name);
    let keyring_key = vta_keyring_key(&slug);

    // Mint admin did:key locally — private key never leaves this host.
    let (bundle, did) =
        vta_cli_common::local_keygen::generate_admin_did_key(&vta_did, Some(url.clone()));

    // Store the session directly; PNM is ready to authenticate as soon as
    // the admin adds the did to the ACL.
    auth::store_session(
        &keyring_key,
        &did,
        &bundle.private_key_multibase,
        &vta_did,
        &url,
    )?;

    // Save config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: Some(url.clone()),
            vta_did: Some(vta_did.clone()),
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    eprintln!();
    eprintln!("\x1b[1;32mLocal admin identity created.\x1b[0m");
    eprintln!();
    eprintln!("  VTA:        {slug}  ({url})");
    eprintln!("  Client DID: {did}");
    eprintln!();
    eprintln!("Ask your VTA admin to grant this identity admin access. On the VTA host,");
    eprintln!("they should run:");
    eprintln!();
    eprintln!("  \x1b[1mvta acl create --did {did} --role admin\x1b[0m");
    eprintln!();
    eprintln!("Once that completes, verify with:");
    eprintln!("  pnm health");
    eprintln!();

    Ok(())
}

/// Offline connection to a non-TEE VTA — the full sealed-transfer dance.
///
/// 1. Either generate a `BootstrapRequest` inline (writes the secret to
///    `~/.config/pnm/bootstrap-secrets/` and the JSON to a file you pick),
///    or accept that the user already has a sealed bundle from the admin.
/// 2. In the generate case, show the request JSON + the hand-off
///    instructions so the operator can ship it to the admin without
///    jumping to another CLI.
/// 3. Prompt for the armored sealed bundle path + optional digest once the
///    admin has returned it.
/// 4. Open and install.
async fn connect_offline_non_tee(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    let have_bundle_options = &[
        "I need to request one — create a request file to send to my admin",
        "I already have a credential file from my admin",
    ];
    let have_bundle = Select::new()
        .with_prompt("Admin credential")
        .items(have_bundle_options)
        .default(0)
        .interact()?;

    if have_bundle == 0 {
        generate_and_show_connection_request()?;
    }

    eprintln!();
    let path: String = Input::new()
        .with_prompt(
            "Path to the credential file from your admin (leave empty to exit and resume later)",
        )
        .allow_empty(true)
        .interact_text()?;
    if path.trim().is_empty() {
        eprintln!();
        eprintln!("Exiting. When you receive the credential file, re-run:");
        eprintln!(
            "  pnm auth login --credential-bundle <file> --expect-digest <hex>    # to install",
        );
        eprintln!("or re-run `pnm setup` and choose \"I already have a credential file\".");
        return Ok(());
    }
    let digest: String = Input::new()
        .with_prompt("Expected SHA-256 digest from your admin (empty = skip verification)")
        .allow_empty(true)
        .interact_text()?;
    let (expect_digest, no_verify) = if digest.trim().is_empty() {
        (None, true)
    } else {
        (Some(digest.trim().to_string()), false)
    };
    setup_with_bundle(
        Path::new(path.trim()),
        expect_digest.as_deref(),
        no_verify,
        config,
    )
    .await
}

/// Generate a connection request (a [`BootstrapRequest`] under the hood),
/// persist its secret, write the JSON to a file the user picks, and print
/// the contents + hand-off instructions. Mirrors `pnm bootstrap request
/// --out` but inline so the user does not have to exit the wizard.
fn generate_and_show_connection_request() -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = crate::config::config_dir()?;

    let label: String = Input::new()
        .with_prompt("Label for this request (shown to your admin)")
        .default("pnm-setup".to_string())
        .interact_text()?;
    let label = label.trim().to_string();
    let label_opt = if label.is_empty() { None } else { Some(label) };

    let out_path: String = Input::new()
        .with_prompt("Write request to file")
        .default("request.json".to_string())
        .interact_text()?;
    let out_path = out_path.trim().to_string();

    let created =
        vta_cli_common::sealed_consumer::create_bootstrap_request(&config_dir, label_opt.clone())?;
    let json = serde_json::to_string_pretty(&created.request)?;
    std::fs::write(&out_path, json.as_bytes()).map_err(|e| format!("write {out_path}: {e}"))?;

    eprintln!();
    eprintln!("\x1b[1;32mConnection request generated.\x1b[0m");
    eprintln!();
    eprintln!("  Client pubkey: {}", created.request.client_pubkey);
    eprintln!("  Nonce (b64):   {}", created.request.nonce);
    if let Some(ref l) = label_opt {
        eprintln!("  Label:         {l}");
    }
    eprintln!("  Request file:  {out_path}");
    eprintln!();
    eprintln!("── Request file contents ──");
    eprintln!("{json}");
    eprintln!("──");
    eprintln!();
    eprintln!("Send the request file to your VTA admin. They will return a credential");
    eprintln!("file and a SHA-256 digest for you to verify.");
    eprintln!();
    Ok(())
}

/// Connect to an existing VTA using an armored sealed credential bundle.
async fn setup_with_bundle(
    path: &Path,
    expect_digest: Option<&str>,
    no_verify_digest: bool,
    config: &mut PnmConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = crate::config::config_dir()?;
    if no_verify_digest {
        eprintln!(
            "WARNING: --no-verify-digest disables out-of-band integrity verification.\n\
             You are trusting the producer pubkey embedded in the bundle without\n\
             any external anchor. Use only for testing."
        );
    }
    let opened = vta_cli_common::sealed_consumer::open_armored_bundle(
        path,
        &config_dir,
        expect_digest,
        no_verify_digest,
    )?;
    eprintln!(
        "Sealed bundle opened ({} — digest {}).",
        opened.bundle_id_hex, opened.digest
    );
    let bundle: CredentialBundle =
        vta_cli_common::sealed_consumer::extract_admin_credential(opened.payload)?;

    // Prompt for a name/slug
    let default_name = if bundle.vta_did.is_empty() {
        "My VTA".to_string()
    } else {
        // Use the last segment of the DID as a reasonable default
        bundle
            .vta_did
            .rsplit(':')
            .next()
            .unwrap_or("my-vta")
            .to_string()
    };

    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default(default_name)
        .interact_text()?;

    let slug = slugify(&name);
    let keyring_key = vta_keyring_key(&slug);

    // Resolve URL from DID
    let url = if let Some(ref url) = bundle.vta_url {
        url.clone()
    } else if !bundle.vta_did.is_empty() {
        eprintln!("Resolving VTA DID: {}", bundle.vta_did);
        vta_sdk::session::resolve_vta_url(&bundle.vta_did).await?
    } else {
        let url: String = Input::new().with_prompt("VTA URL").interact_text()?;
        url
    };
    let url = url.trim_end_matches('/').to_string();

    // Save to config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: Some(url.clone()),
            vta_did: if bundle.vta_did.is_empty() {
                None
            } else {
                Some(bundle.vta_did.clone())
            },
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    // Authenticate
    auth::login(&bundle, &url, &keyring_key).await?;

    let path = crate::config::config_path()?;
    eprintln!();
    eprintln!("VTA '{slug}' configured.");
    eprintln!("  Config: {}", path.display());
    if config.default_vta.as_deref() == Some(&slug) {
        eprintln!("  Default: yes");
    }

    Ok(())
}

/// Set up a new VTA for TEE deployment.
///
/// Single interactive session:
/// 1. Generate admin did:key (in memory)
/// 2. Print DID for config.toml
/// 3. Wait for operator to deploy + boot VTA
/// 4. Prompt for VTA DID
/// 5. Store credential in keyring, save config
async fn setup_tee(config: &mut PnmConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!();
    eprintln!("This will create an admin identity for a VTA running in a");
    eprintln!("Trusted Execution Environment. The private key stays on this");
    eprintln!("machine and never touches the TEE or the parent instance.");
    eprintln!();

    // 1. Prompt for name
    let name: String = Input::new()
        .with_prompt("Name for this VTA")
        .default("my-tee-vta".to_string())
        .interact_text()?;
    let slug = slugify(&name);

    // 2. Generate random Ed25519 keypair (in memory only)
    let mut seed = [0u8; 32];
    rand::rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let multibase_pubkey = ed25519_multibase_pubkey(&public_key);
    let did = format!("did:key:{multibase_pubkey}");
    let private_key_multibase = multibase::encode(multibase::Base::Base58Btc, seed);

    // 3. Print DID for config.toml
    eprintln!();
    eprintln!("Admin identity generated.");
    eprintln!();
    eprintln!("Add this to your VTA's deploy/nitro/config.toml under [tee.kms]:");
    eprintln!();
    println!("  admin_did = \"{did}\"");
    eprintln!();
    eprintln!("Then build the EIF and start the enclave.");

    // 4. Wait for VTA to be running
    eprintln!();
    eprint!("Press Enter once the VTA is running...");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;

    // 5. Prompt for VTA DID
    eprintln!();
    eprintln!("The VTA's DID is shown in its boot logs. You can also retrieve");
    eprintln!("it via: GET /attestation/did-log (if REST is enabled).");
    eprintln!();
    let vta_did: String = Input::new().with_prompt("VTA DID").interact_text()?;

    // 6. Prompt for mediator DID
    let mediator_did: String = Input::new().with_prompt("Mediator DID").interact_text()?;

    // 7. Store identity directly in the keyring. Bundle construction happens
    //    later, inside the TEE-first-boot flow, when the VTA is reachable.
    let keyring_key = vta_keyring_key(&slug);

    // Store session directly — the VTA may not be reachable for auth yet
    // (DIDComm connections need time to establish)
    auth::store_session(
        &keyring_key,
        &did,
        &private_key_multibase,
        &vta_did,
        "", // No REST URL in TEE mode
    )?;

    // 8. Save to config
    config.vtas.insert(
        slug.clone(),
        VtaConfig {
            name: name.clone(),
            url: None,
            vta_did: Some(vta_did.clone()),
        },
    );
    if config.default_vta.is_none() || config.vtas.len() == 1 {
        config.default_vta = Some(slug.clone());
    }
    save_config(config)?;

    eprintln!();
    eprintln!("VTA '{slug}' configured.");
    eprintln!("  Admin DID:    {did}");
    eprintln!("  VTA DID:      {vta_did}");
    eprintln!("  Mediator DID: {mediator_did}");
    eprintln!("  Credential stored in keyring (key: {keyring_key})");
    if config.default_vta.as_deref() == Some(&slug) {
        eprintln!("  Default: yes");
    }
    eprintln!();
    eprintln!("You can now run commands against this VTA:");
    eprintln!("  pnm health");
    eprintln!("  pnm keys list");

    Ok(())
}
