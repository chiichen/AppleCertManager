use apple_cert_manager::devices::{parse_devices, DeviceRecord};

#[test]
fn parses_fastlane_header_and_plain_rows() {
    let text = "\
Device ID\tDevice Name\tDevice Platform
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\tiPhone of Gov\tios
# a comment

00008030-001C25E40A68802E,\"iPad of Gov\",tvos
550e8400-e29b-41d4-a716-446655440000\tMac mini\tmac_os
";
    let devices = parse_devices(text).unwrap();
    assert_eq!(
        devices,
        vec![
            DeviceRecord {
                name: "iPhone of Gov".into(),
                udid: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".into(),
                platform: "IOS".into(),
            },
            DeviceRecord {
                name: "iPad of Gov".into(),
                udid: "00008030-001C25E40A68802E".into(),
                platform: "TVOS".into(),
            },
            DeviceRecord {
                name: "Mac mini".into(),
                udid: "550e8400-e29b-41d4-a716-446655440000".into(),
                platform: "MAC_OS".into(),
            },
        ]
    );
}

#[test]
fn name_first_rows_default_to_ios() {
    let devices = parse_devices("Front Desk    00008030-001C25E40A68802E\n").unwrap();
    assert_eq!(devices[0].name, "Front Desk");
    assert_eq!(devices[0].platform, "IOS");
}

#[test]
fn duplicate_udid_is_rejected() {
    let text = "\
Phone One\ta1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
Phone Two\tA1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2
";
    let error = parse_devices(text).unwrap_err();
    assert!(error.to_string().contains("repeats UDID"), "{error}");
}
