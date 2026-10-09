use apple_cert_manager_types::{Platform, SigningType};

#[test]
fn signing_lanes_match_fastlane_paths() {
    assert_eq!(SigningType::AdHoc.cert_folder(), "distribution");
    assert_eq!(SigningType::AppStore.cert_folder(), "distribution");
    assert_eq!(
        SigningType::DeveloperId.cert_folder(),
        "developer_id_application"
    );
    assert_eq!(
        SigningType::DeveloperId.profile_folder(),
        Some("developer_id")
    );
    assert_eq!(SigningType::MacInstallerDistribution.profile_folder(), None);

    assert_eq!(
        SigningType::AppStore.profile_filename("com.example.app", Platform::Ios),
        "AppStore_com.example.app.mobileprovision"
    );
    assert_eq!(
        SigningType::Development.profile_filename("com.example.app", Platform::Macos),
        "Development_com.example.app.provisionprofile"
    );
    assert_eq!(
        SigningType::Development.profile_filename("com.example.app", Platform::Tvos),
        "Development_com.example.app_tvos.mobileprovision"
    );
    assert_eq!(
        SigningType::Development.portal_profile_name("com.example.app", Platform::Ios),
        "match Development com.example.app"
    );
    assert_eq!(
        SigningType::AppStore.portal_profile_name("com.example.app", Platform::Macos),
        "match AppStore com.example.app macos"
    );
    assert_eq!(
        SigningType::AdHoc.sigh_prefix("com.example.app", Platform::Ios),
        "sigh_com.example.app_adhoc"
    );
    assert_eq!(
        SigningType::AppStore.sigh_prefix("com.example.app", Platform::Macos),
        "sigh_com.example.app_appstore_macos"
    );
    assert_eq!(
        SigningType::Enterprise.apple_profile_type(Platform::Ios),
        Some("IOS_APP_INHOUSE")
    );
    assert_eq!(
        SigningType::DeveloperId.apple_profile_type(Platform::Macos),
        Some("MAC_APP_DIRECT")
    );
    assert_eq!(
        SigningType::AdHoc.preferred_certificate_type(Platform::Ios),
        Some("IOS_DISTRIBUTION")
    );
    assert!(SigningType::parse("app-store").is_ok());
    assert!(SigningType::parse("distribution").is_err());
}
