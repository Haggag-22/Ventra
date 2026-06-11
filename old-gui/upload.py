"""Accept evidence packages uploaded from the viewer GUI."""

import cgi
import os
import shutil
import tempfile
import zipfile

from .package import PackageReader
from .state import ViewerState


def _safe_relative_path(path):
    """Normalize an upload-relative path and reject traversal."""
    path = path.replace("\\", "/").lstrip("/")
    parts = [part for part in path.split("/") if part and part != "."]
    if ".." in parts:
        raise PermissionError(f"invalid upload path: {path}")
    return os.path.join(*parts) if parts else ""


def _parse_multipart(handler):
    content_type = handler.headers.get("Content-Type", "")
    if "multipart/form-data" not in content_type:
        raise ValueError("expected multipart/form-data upload")
    return cgi.FieldStorage(
        fp=handler.rfile,
        headers=handler.headers,
        environ={
            "REQUEST_METHOD": "POST",
            "CONTENT_TYPE": content_type,
            "CONTENT_LENGTH": handler.headers.get("Content-Length", "0"),
        },
    )


def _field_items(form, name):
    if name not in form:
        return []
    items = form[name]
    if not isinstance(items, list):
        items = [items]
    return items


def _materialize_zip(item):
    data = item.file.read()
    if not data:
        raise ValueError("empty ZIP upload")
    tmp = tempfile.mkdtemp(prefix="ir-viewer-upload-")
    zip_path = os.path.join(tmp, "upload.zip")
    with open(zip_path, "wb") as handle:
        handle.write(data)
    if not zipfile.is_zipfile(zip_path):
        shutil.rmtree(tmp, ignore_errors=True)
        raise ValueError("upload is not a valid ZIP file")
    label = os.path.basename(item.filename or "package.zip")
    package = PackageReader(zip_path)
    shutil.rmtree(tmp, ignore_errors=True)
    return package, label


def _materialize_folder(items):
    tmp = tempfile.mkdtemp(prefix="ir-viewer-upload-")
    label = None
    written = 0
    try:
        for item in items:
            if not item.filename:
                continue
            relative = _safe_relative_path(item.filename)
            if not relative:
                continue
            if label is None:
                label = relative.split(os.sep)[0]
            dest = os.path.join(tmp, relative)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as handle:
                shutil.copyfileobj(item.file, handle)
            written += 1
        if written == 0:
            raise ValueError("no files in folder upload")
        package = PackageReader(tmp)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return package, label or os.path.basename(tmp), tmp


def load_from_upload(handler, state):
    """Parse a multipart upload, build a PackageReader, and attach it to state."""
    form = _parse_multipart(handler)
    zip_items = _field_items(form, "package")
    folder_items = _field_items(form, "files")

    owned_path = None
    if zip_items:
        if folder_items:
            raise ValueError("upload either one ZIP or a folder, not both")
        package, label = _materialize_zip(zip_items[0])
    elif folder_items:
        package, label, owned_path = _materialize_folder(folder_items)
    else:
        raise ValueError("no package files found in upload")

    # Warm indexes before returning so the first UI view is responsive.
    events = len(package.cloudtrail_index)
    findings = len(package.findings_index)

    state.replace(package, label)
    if owned_path is not None:
        state.track_path(owned_path)

    scope = package.manifest.get("scope", {})
    return {
        "ok": True,
        "label": label,
        "account_id": scope.get("account_id"),
        "events": events,
        "findings": findings,
    }
