//! Manual integration check. Package/sign this executable with RV's profile
//! before running it. Uses a fresh temporary credential, never a saved VNC password.

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    std::thread::spawn(|| -> Result<(), rv_core::StoreError> {
        let id = rv_core::Connection::new("Keychain check", "localhost", 5900).id;
        let result: Result<(), rv_core::StoreError> = (|| {
            rv_core::save_password(id, "temporary test credential")?;
            // Also exercise updates of an existing access-controlled item.
            rv_core::save_password(id, "updated test credential")?;
            // A build the protected Keychain refuses falls back to the login
            // Keychain, so a passing round trip alone proves nothing. Fail if
            // the credential landed there instead.
            if in_login_keychain(id)? {
                return Err(rv_core::StoreError::Keyring(
                    "the credential went to the login Keychain: this build is not \
                     provisioned for the protected (Touch ID) Keychain"
                        .into(),
                ));
            }
            println!("Authenticate with Touch ID to read RV's temporary test credential.");
            let password = rv_core::load_password(id)?;
            if password.as_deref() != Some("updated test credential") {
                return Err(rv_core::StoreError::Keyring("round-trip mismatch".into()));
            }
            println!("Protected Keychain create, update, and authenticated read passed.");
            Ok(())
        })();
        let cleanup = rv_core::delete_password(id);
        result?;
        cleanup?;
        println!("Temporary credential removed.");
        Ok(())
    })
    .join()
    .expect("Keychain worker panicked")?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn in_login_keychain(id: rv_core::ConnectionId) -> Result<bool, rv_core::StoreError> {
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
    const ITEM_NOT_FOUND: i32 = -25300;
    let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
        .map_err(|error| rv_core::StoreError::Keyring(error.to_string()))?;
    match keychain.find_generic_password("rv", &rv_core::password_key(id)) {
        Ok(_) => Ok(true),
        Err(error) if error.code() == ITEM_NOT_FOUND => Ok(false),
        Err(error) => Err(rv_core::StoreError::Keyring(error.to_string())),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("This manual check is for macOS Touch ID Keychain access.");
}
