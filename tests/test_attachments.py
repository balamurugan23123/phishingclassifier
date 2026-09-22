"""Deep attachment (macro) analysis tests."""

import io
import zipfile
from email.message import EmailMessage

from phishingclassifier.attachments import analyze_bytes, analyze_eml


def _zip_with(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in members:
            zf.writestr(name, b"junk")
    return buf.getvalue()


def _eml_with_attachment(filename, data):
    msg = EmailMessage()
    msg["Subject"] = "Invoice"
    msg["From"] = "a@evil.test"
    msg["To"] = "victim@corp.test"
    msg.set_content("See attached.")
    msg.add_attachment(
        data,
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=filename,
    )
    return msg.as_bytes()


def test_ooxml_macro_in_macrofree_extension_is_concealed():
    data = _zip_with(["[Content_Types].xml", "word/document.xml", "word/vbaProject.bin"])
    ids = [x["id"] for x in analyze_bytes(data, "invoice.docx")]
    assert "attachment_concealed_macro" in ids


def test_ooxml_macro_declared_extension():
    data = _zip_with(["word/vbaProject.bin"])
    ids = [x["id"] for x in analyze_bytes(data, "invoice.docm")]
    assert ids == ["attachment_macro_document"]


def test_ooxml_without_macro_is_clean():
    data = _zip_with(["[Content_Types].xml", "word/document.xml"])
    assert analyze_bytes(data, "memo.docx") == []


def test_non_office_bytes_are_ignored():
    assert analyze_bytes(b"hello world, not an office file", "notes.txt") == []


def test_oversized_attachment_is_skipped(monkeypatch):
    import phishingclassifier.attachments as a

    monkeypatch.setattr(a, "MAX_SCAN_BYTES", 10)
    assert analyze_bytes(_zip_with(["word/vbaProject.bin"]) * 10, "big.docx") == []


def test_deep_scan_end_to_end_from_eml(tmp_path):
    eml = _eml_with_attachment("invoice.docx", _zip_with(["word/vbaProject.bin"]))
    path = tmp_path / "msg.eml"
    path.write_bytes(eml)
    ids = [x["id"] for x in analyze_eml(str(path))]
    assert "attachment_concealed_macro" in ids
