//! Keychain import through Security.framework.
//!
//! The partition list is not a high-level Security API. This follows
//! `keychain_set_partition_list` in Apple's SecurityTool: find signing keys,
//! rewrite the ACL whose tag is `CSSM_ACL_AUTHORIZATION_PARTITION_ID`, and
//! store it with `SecKeychainItemSetAccessWithPassword`.

use std::ffi::c_void;
use std::fs;
use std::path::PathBuf;
use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType, ToVoid};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::string::CFString;
use core_foundation_sys::array::{CFArrayGetTypeID, CFArrayRef};
use core_foundation_sys::base::{CFEqual, CFGetTypeID, CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::string::CFStringRef;
use security_framework::base::Error as SecurityError;
use security_framework::import_export::Pkcs12ImportOptions;
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use security_framework_sys::base::{SecAccessRef, SecKeychainItemRef};
use security_framework_sys::item::{
    kSecClass, kSecClassKey, kSecMatchLimit, kSecMatchLimitAll, kSecMatchSearchList, kSecReturnRef,
};
use security_framework_sys::keychain_item::SecItemCopyMatching;

use super::{partition_acl_description, InstallOutcome, SIGNING_PARTITIONS};
use apple_cert_manager_config::SyncConfig;
use apple_cert_manager_engine::SyncReport;
use apple_cert_manager_error::{Error, Result};
use apple_cert_manager_signing::profile_extension;
use apple_cert_manager_types::Platform;

const CSSM_ACL_AUTHORIZATION_PARTITION_ID: u32 = 0x0001_0002;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_PKCS12_VERIFY_FAILURE: i32 = -25264;
const ERR_SEC_NO_ACCESS_FOR_ITEM: i32 = -25243;

#[repr(C)]
struct PromptSelector {
    version: u16,
    flags: u16,
}

extern "C" {
    static kSecAttrCanSign: CFStringRef;

    fn SecKeychainItemCopyAccess(item: SecKeychainItemRef, access: *mut SecAccessRef) -> OSStatus;
    fn SecAccessCopyACLList(access: SecAccessRef, acl_list: *mut CFArrayRef) -> OSStatus;
    fn SecACLGetAuthorizations(acl: *mut c_void, tags: *mut u32, tag_count: *mut u32) -> OSStatus;
    fn SecACLCopySimpleContents(
        acl: *mut c_void,
        application_list: *mut CFArrayRef,
        description: *mut CFStringRef,
        prompt_selector: *mut PromptSelector,
    ) -> OSStatus;
    fn SecACLSetSimpleContents(
        acl: *mut c_void,
        application_list: CFArrayRef,
        description: CFStringRef,
        prompt_selector: *const PromptSelector,
    ) -> OSStatus;
    fn SecKeychainItemSetAccessWithPassword(
        item: SecKeychainItemRef,
        access: SecAccessRef,
        password_length: u32,
        password: *const u8,
    ) -> OSStatus;
    fn SecKeychainCopySearchList(search_list: *mut CFArrayRef) -> OSStatus;
    fn SecKeychainSetSearchList(search_list: CFArrayRef) -> OSStatus;
}

pub fn install(report: &SyncReport, sync: &SyncConfig) -> Result<InstallOutcome> {
    let profiles_installed = install_profiles(report)?;
    if report.certificates.is_empty() {
        return Ok(InstallOutcome {
            profiles_installed,
            identities_installed: 0,
            note: None,
        });
    }
    let password = sync.keychain_password.as_deref();
    let _interaction = if password.is_some() {
        Some(
            SecKeychain::disable_user_interaction()
                .map_err(|err| Error::msg(format!("cannot disable keychain prompts: {err}")))?,
        )
    } else {
        None
    };
    let keychain = open_keychain(&sync.keychain_name, password)?;
    ensure_search_list(&keychain)?;
    let identities_installed = import_identities(&keychain, report, &sync.p12_password)?;
    let note = match password {
        Some(password) => {
            set_partition_list(&keychain, password)?;
            None
        }
        None => Some(format!(
            "imported into {} without a partition list. Set MATCH_KEYCHAIN_PASSWORD so codesign can use the key without a prompt",
            sync.keychain_name
        )),
    };
    Ok(InstallOutcome {
        profiles_installed,
        identities_installed,
        note,
    })
}

fn install_profiles(report: &SyncReport) -> Result<usize> {
    let mut installed = 0;
    for profile in &report.profiles {
        let Some(directory) = xcode_profile_dir(profile.platform) else {
            continue;
        };
        fs::create_dir_all(&directory)?;
        let name = if profile.uuid.is_empty() {
            format!("apple-cert-manager-{}", installed)
        } else {
            profile.uuid.clone()
        };
        let path = directory.join(format!("{name}.{}", profile_extension(profile.platform)));
        fs::write(path, &profile.content)?;
        installed += 1;
    }
    Ok(installed)
}

fn xcode_profile_dir(platform: Platform) -> Option<PathBuf> {
    let home = home_dir()?;
    Some(match platform {
        Platform::Macos | Platform::Catalyst => {
            home.join("Library/Developer/Xcode/UserData/Provisioning Profiles")
        }
        Platform::Ios | Platform::Tvos => home.join("Library/MobileDevice/Provisioning Profiles"),
    })
}

fn open_keychain(name: &str, password: Option<&str>) -> Result<SecKeychain> {
    let path = keychain_path(name);
    let mut keychain = if path.exists() {
        SecKeychain::open(&path)
            .map_err(|err| Error::msg(format!("cannot open keychain {}: {err}", path.display())))?
    } else {
        let password = password.ok_or_else(|| {
            Error::msg(format!(
                "keychain {} does not exist. Set MATCH_KEYCHAIN_PASSWORD so apple-cert-manager can create it",
                path.display()
            ))
        })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut options = CreateOptions::new();
        options.password(password);
        options.create(&path).map_err(|err| {
            Error::msg(format!("cannot create keychain {}: {err}", path.display()))
        })?
    };
    keychain
        .unlock(password)
        .map_err(|err| Error::msg(format!("cannot unlock keychain {}: {err}", path.display())))?;
    Ok(keychain)
}

fn keychain_path(name: &str) -> PathBuf {
    let path = PathBuf::from(name);
    if path.is_absolute() || name.contains('/') {
        path
    } else {
        home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library/Keychains")
            .join(name)
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn import_identities(
    keychain: &SecKeychain,
    report: &SyncReport,
    p12_password: &str,
) -> Result<usize> {
    let mut seen = std::collections::HashSet::new();
    let mut installed = 0;
    for certificate in &report.certificates {
        if !seen.insert(certificate.id.clone()) || certificate.p12.is_empty() {
            continue;
        }
        let mut importer = Pkcs12ImportOptions::new();
        importer.passphrase(p12_password).keychain(keychain.clone());
        match importer.import(&certificate.p12) {
            Ok(items) => installed += items.len().max(1),
            Err(err) if err.code() == ERR_SEC_DUPLICATE_ITEM => installed += 1,
            // macOS 15 and later reject the MAC of an empty-password PKCS#12.
            // OpenSSL can still read it. Re-export with a temporary password
            // and 3DES, then import that copy.
            Err(err)
                if matches!(
                    err.code(),
                    ERR_SEC_AUTH_FAILED | ERR_SEC_PKCS12_VERIFY_FAILURE
                ) =>
            {
                installed += import_reprotected(keychain, &certificate.p12, p12_password)
                    .map_err(|fallback| {
                        Error::msg(format!(
                            "cannot import certificate {} into the keychain: {err}; reprotected import: {fallback}",
                            certificate.id
                        ))
                    })?;
            }
            Err(err) => {
                return Err(Error::msg(format!(
                    "cannot import certificate {} into the keychain: {err}",
                    certificate.id
                )));
            }
        }
    }
    Ok(installed)
}

fn import_reprotected(keychain: &SecKeychain, p12: &[u8], password: &str) -> Result<usize> {
    let (wrapped, wrapped_password) =
        apple_cert_manager_crypto::reprotect_p12_for_keychain(p12, password)?;
    let mut importer = Pkcs12ImportOptions::new();
    importer
        .passphrase(&wrapped_password)
        .keychain(keychain.clone());
    match importer.import(&wrapped) {
        Ok(items) => Ok(items.len().max(1)),
        Err(err) if err.code() == ERR_SEC_DUPLICATE_ITEM => Ok(1),
        Err(err) => Err(Error::msg(err.to_string())),
    }
}

fn ensure_search_list(keychain: &SecKeychain) -> Result<()> {
    unsafe {
        let mut raw = ptr::null();
        status(
            SecKeychainCopySearchList(&mut raw),
            "SecKeychainCopySearchList",
        )?;
        let existing: CFArray<CFType> = CFArray::wrap_under_create_rule(raw as *mut _);
        let ours = keychain.as_CFType();
        let present = existing
            .iter()
            .any(|item| CFEqual(item.as_CFTypeRef(), ours.as_CFTypeRef()) != 0);
        if present {
            return Ok(());
        }
        let mut items: Vec<CFType> = existing.iter().map(|item| item.as_CFType()).collect();
        items.push(ours);
        let updated = CFArray::from_CFTypes(&items);
        status(
            SecKeychainSetSearchList(updated.as_concrete_TypeRef()),
            "SecKeychainSetSearchList",
        )?;
    }
    Ok(())
}

fn set_partition_list(keychain: &SecKeychain, password: &str) -> Result<()> {
    let description = partition_acl_description(SIGNING_PARTITIONS)?;
    let description = CFString::new(&description);
    unsafe {
        let mut query = CFMutableDictionary::from_CFType_pairs(&[]);
        query.add(&kSecClass.to_void(), &kSecClassKey.to_void());
        query.add(&kSecMatchLimit.to_void(), &kSecMatchLimitAll.to_void());
        query.add(&kSecReturnRef.to_void(), &CFBoolean::true_value().to_void());
        query.add(
            &kSecAttrCanSign.to_void(),
            &CFBoolean::true_value().to_void(),
        );
        let search = CFArray::from_CFTypes(&[keychain.as_CFType()]);
        query.add(
            &kSecMatchSearchList.to_void(),
            &search.as_CFType().to_void(),
        );

        let mut raw: CFTypeRef = ptr::null();
        let found = SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw);
        if found == ERR_SEC_ITEM_NOT_FOUND {
            return Err(Error::msg(
                "the keychain has no signing key to receive the partition list",
            ));
        }
        status(found, "SecItemCopyMatching")?;
        let password_bytes = password.as_bytes();
        let description = description.as_concrete_TypeRef();
        visit_items(raw, |item| {
            apply_partition_list(item, description, password_bytes)
        })?;
    }
    Ok(())
}

/// `raw` is a create-rule reference. The item pointers are only used while
/// the owning array or type is still alive.
unsafe fn visit_items(
    raw: CFTypeRef,
    mut visit: impl FnMut(SecKeychainItemRef) -> Result<()>,
) -> Result<()> {
    if raw.is_null() {
        return Ok(());
    }
    if CFGetTypeID(raw) == CFArrayGetTypeID() {
        let array: CFArray<CFType> = CFArray::wrap_under_create_rule(raw as *mut _);
        for item in array.iter() {
            visit(item.as_CFTypeRef() as SecKeychainItemRef)?;
        }
    } else {
        let item = CFType::wrap_under_create_rule(raw);
        visit(item.as_CFTypeRef() as SecKeychainItemRef)?;
    }
    Ok(())
}

unsafe fn apply_partition_list(
    item: SecKeychainItemRef,
    description: CFStringRef,
    password: &[u8],
) -> Result<()> {
    let mut access: SecAccessRef = ptr::null_mut();
    let copied = SecKeychainItemCopyAccess(item, &mut access);
    if copied == ERR_SEC_NO_ACCESS_FOR_ITEM {
        return Ok(());
    }
    status(copied, "SecKeychainItemCopyAccess")?;
    let access_type = CFType::wrap_under_create_rule(access as CFTypeRef);

    let mut acl_raw: CFArrayRef = ptr::null();
    status(
        SecAccessCopyACLList(access, &mut acl_raw),
        "SecAccessCopyACLList",
    )?;
    let acls: CFArray<CFType> = CFArray::wrap_under_create_rule(acl_raw as *mut _);
    for acl in acls.iter() {
        let acl = acl.as_CFTypeRef() as *mut c_void;
        let mut tags = [0u32; 64];
        let mut tag_count = tags.len() as u32;
        status(
            SecACLGetAuthorizations(acl, tags.as_mut_ptr(), &mut tag_count),
            "SecACLGetAuthorizations",
        )?;
        let count = tag_count.min(tags.len() as u32) as usize;
        if !tags[..count].contains(&CSSM_ACL_AUTHORIZATION_PARTITION_ID) {
            continue;
        }
        let mut applications: CFArrayRef = ptr::null();
        let mut current: CFStringRef = ptr::null();
        let mut selector = PromptSelector {
            version: 0,
            flags: 0,
        };
        status(
            SecACLCopySimpleContents(acl, &mut applications, &mut current, &mut selector),
            "SecACLCopySimpleContents",
        )?;
        let updated = SecACLSetSimpleContents(acl, applications, description, &selector);
        release(applications as CFTypeRef);
        release(current as CFTypeRef);
        status(updated, "SecACLSetSimpleContents")?;
    }
    status(
        SecKeychainItemSetAccessWithPassword(
            item,
            access,
            password.len() as u32,
            password.as_ptr(),
        ),
        "SecKeychainItemSetAccessWithPassword",
    )?;
    drop(access_type);
    Ok(())
}

fn status(code: OSStatus, action: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        let message = SecurityError::from_code(code);
        Err(Error::msg(format!("{action}: {message} ({code})")))
    }
}

unsafe fn release(value: CFTypeRef) {
    if !value.is_null() {
        CFRelease(value);
    }
}
