"""The notification policy is the reader the Settings panel never had.

These pin the folding rules: no configured account keeps the old env-driven
behaviour, every switch off means silence, and each account's own address wins
over ALERT_EMAIL_TO.
"""
from app.services.alert_policy import merge_policy


def test_no_configured_accounts_keeps_env_behaviour() -> None:
    policy = merge_policy([], env_enabled=True, env_recipient="ops@example.com")

    assert policy.enabled is True
    assert policy.recipients == ("ops@example.com",)
    assert policy.notify_critical is True
    assert policy.notify_warning is False
    assert policy.notify_device_down is True
    assert policy.daily_digest is False


def test_saving_the_panel_with_email_off_means_silence() -> None:
    policy = merge_policy(
        [{"email_enabled": False, "alert_on_critical": True}],
        env_enabled=True,
        env_recipient="ops@example.com",
    )

    assert policy.enabled is False
    assert policy.recipients == ()
    assert policy.notify_critical is False


def test_addresses_and_switches_are_folded_across_enabled_accounts() -> None:
    rows = [
        {
            "email_enabled": True,
            "email_address": "a@example.com",
            "alert_on_critical": True,
            "alert_on_warning": False,
        },
        {
            "email_enabled": True,
            "email_address": "",
            "alert_on_device_down": True,
            "daily_digest": True,
        },
        {
            # Disabled accounts contribute neither recipients nor switches.
            "email_enabled": False,
            "email_address": "ignored@example.com",
            "alert_on_warning": True,
        },
    ]

    policy = merge_policy(rows, env_enabled=False, env_recipient="ops@example.com")

    assert policy.enabled is True
    assert policy.recipients == ("a@example.com", "ops@example.com")
    assert policy.notify_critical is True
    assert policy.notify_warning is False
    assert policy.notify_device_down is True
    assert policy.daily_digest is True


def test_enabled_account_without_any_address_cannot_send() -> None:
    policy = merge_policy(
        [{"email_enabled": True, "email_address": "", "alert_on_critical": True}],
        env_enabled=True,
        env_recipient="",
    )

    assert policy.enabled is False
    assert policy.recipients == ()
