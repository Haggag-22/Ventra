from collector.engine.azure_log_backend import (
    apply_azure_log_backend_iam,
    validate_azure_log_backend_dict,
)


def test_storage_mode_adds_blob_read() -> None:
    out = apply_azure_log_backend_iam({"Microsoft.Insights/eventtypes/values/read"}, {"mode": "storage"})
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" in out
    assert "Microsoft.Insights/DiagnosticSettings/read" in out


def test_monitor_api_mode_leaves_actions() -> None:
    wanted = {"Microsoft.Insights/eventtypes/values/read"}
    assert apply_azure_log_backend_iam(set(wanted), {"mode": "monitor_api"}) == wanted


def test_unknown_mode_is_rejected() -> None:
    try:
        validate_azure_log_backend_dict({"mode": "log_analytics"})
    except ValueError as exc:
        assert "log_analytics" in str(exc)
    else:
        raise AssertionError("expected ValueError")
