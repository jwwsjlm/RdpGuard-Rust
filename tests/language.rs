use rdpguard::language::Language;

#[test]
fn chinese_locales_map_to_chinese_and_other_locales_to_english() {
    assert_eq!(Language::from_locale_name("zh-CN"), Language::Chinese);
    assert_eq!(Language::from_locale_name("zh-Hant-TW"), Language::Chinese);
    assert_eq!(Language::from_locale_name("en-US"), Language::English);
    assert_eq!(Language::from_locale_name("ja-JP"), Language::English);
}

#[test]
fn cli_values_round_trip_and_toggle() {
    assert_eq!(Language::parse_cli("zh-CN").unwrap(), Language::Chinese);
    assert_eq!(Language::parse_cli("en-US").unwrap(), Language::English);
    assert_eq!(Language::Chinese.toggle(), Language::English);
    assert_eq!(Language::English.toggle(), Language::Chinese);
    assert!(Language::parse_cli("de-DE").is_err());
}
