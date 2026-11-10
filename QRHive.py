import os
import sys
import re
import json
import time
import base64
import binascii
import hashlib
import gzip
import zlib
import bz2
import csv
import argparse
import webbrowser
from io import BytesIO
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote
import codecs

import numpy as np
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer, QRect
from PyQt5.QtGui import (
    QPixmap, QImage, QIcon, QPainter, QPen, QColor, QDragEnterEvent,
    QDropEvent, QMouseEvent, QFont, QBrush
)
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QAction, QToolBar, QSplitter,
    QVBoxLayout, QHBoxLayout, QFrame, QPlainTextEdit, QTabWidget, QTableWidget,
    QTableWidgetItem, QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QSizePolicy, QStatusBar, QCheckBox, QComboBox, QLineEdit, QPushButton,
    QDialog, QFormLayout, QSpinBox, QGroupBox, QScrollArea, QGridLayout,
    QHeaderView, QColorDialog
)

APP_NAME = "QRHive"
APP_VERSION = ""
APP_DESC = "二维码内容提取与威胁分析工具"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_PATH = os.path.join(BASE_DIR, "123.ico")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")
RULES_DIR = os.path.join(BASE_DIR, "rules")

try:
    import zxingcpp
    HAS_ZXINGCPP = True
except ImportError:
    HAS_ZXINGCPP = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from PIL import Image as PILImage
    from PIL.ExifTags import TAGS as EXIF_TAGS
    HAS_PYZBAR = True
    HAS_PIL = True
except ImportError:
    HAS_PYZBAR = False
    HAS_PIL = False

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    import pymupdf as fitz
    HAS_PYMUPDF = True
except ImportError:
    try:
        import fitz
        HAS_PYMUPDF = True
    except ImportError:
        HAS_PYMUPDF = False

try:
    import qrcode
    from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class DecodingLayer:
    method: str
    data: bytes
    text: str


@dataclass
class StructuredField:
    category: str
    fields: Dict[str, str]


@dataclass
class BarcodeHit:
    raw: bytes
    format: str
    engine: str
    bbox: Optional[Tuple[float, float, float, float]] = None


@dataclass
class DecodeResult:
    kind: str = "unknown"
    text: str = ""
    raw: bytes = b""
    format: str = ""
    engine: str = ""
    bbox: Optional[Tuple[float, float, float, float]] = None
    images: List[QImage] = field(default_factory=list)
    decodings: List[DecodingLayer] = field(default_factory=list)
    structured: List[StructuredField] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=dict)
    suspicion: int = 0
    suspicion_hits: List[str] = field(default_factory=list)
    dangers: List[str] = field(default_factory=list)
    exif: Dict[str, str] = field(default_factory=dict)
    file_type: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HistoryRecord:
    source_image: Optional[QImage]
    source_name: str
    result: DecodeResult
    timestamp: str


IMAGE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"RIFF", "webp"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
]


def detect_image_format(data: bytes) -> Optional[str]:
    for sig, fmt in IMAGE_SIGNATURES:
        if data.startswith(sig):
            if fmt == "webp":
                if len(data) >= 12 and data[8:12] == b"WEBP":
                    return fmt
                continue
            return fmt
    return None


def find_image_end(data: bytes, start: int, fmt: str) -> int:
    if fmt == "png":
        idx = data.find(b"IEND", start)
        return idx + 8 if idx != -1 else len(data)
    if fmt == "jpeg":
        idx = data.find(b"\xff\xd9", start)
        return idx + 2 if idx != -1 else len(data)
    if fmt == "gif":
        for j in range(len(data) - 1, start + 6, -1):
            if data[j] == 0x3B:
                return j + 1
        return len(data)
    if fmt == "bmp":
        if start + 6 <= len(data):
            size = int.from_bytes(data[start + 2:start + 6], "little")
            if 0 < size <= len(data) - start:
                return start + size
        return len(data)
    if fmt == "webp":
        if start + 8 <= len(data):
            size = int.from_bytes(data[start + 4:start + 8], "little") + 8
            if 0 < size <= len(data) - start:
                return start + size
        return len(data)
    return len(data)


def extract_images_from_bytes(raw: bytes) -> List[Tuple[bytes, str]]:
    results = []
    i = 0
    n = len(raw)
    while i < n:
        matched = None
        for sig, fmt in IMAGE_SIGNATURES:
            if raw.startswith(sig, i):
                if fmt in ("png", "jpeg", "gif", "bmp", "webp"):
                    if fmt == "webp":
                        if i + 12 <= n and raw[i + 8:i + 12] == b"WEBP":
                            matched = (sig, fmt)
                            break
                    else:
                        matched = (sig, fmt)
                        break
        if matched is None:
            i += 1
            continue
        sig, fmt = matched
        start = i
        end = find_image_end(raw, start, fmt)
        if end <= start:
            end = start + 1
        chunk = raw[start:end]
        if chunk:
            results.append((chunk, fmt))
        i = end
    return results


def qimage_from_bytes(data: bytes) -> Optional[QImage]:
    img = QImage()
    if img.loadFromData(data):
        return img
    return None


def qimage_to_numpy(qimage: QImage) -> np.ndarray:
    qimage = qimage.convertToFormat(QImage.Format_RGB888)
    w, h = qimage.width(), qimage.height()
    bpl = qimage.bytesPerLine()
    buf = qimage.constBits().asstring(qimage.byteCount())
    arr = np.frombuffer(buf, np.uint8).reshape((h, bpl))
    arr = arr[:, :w * 3].reshape((h, w, 3))
    return np.ascontiguousarray(arr)


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines)


def build_preprocess_variants(img_np: np.ndarray, options: List[str]) -> List[Tuple[str, np.ndarray]]:
    variants = [("原图", img_np)]
    if not options or not HAS_CV2:
        return variants
    gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
    if "灰度" in options:
        variants.append(("灰度", cv2.cvtColor(gray, cv2.COLOR_GRAY2RGB)))
    if "二值化" in options:
        _, binimg = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        variants.append(("二值化", cv2.cvtColor(binimg, cv2.COLOR_GRAY2RGB)))
    if "自适应阈值" in options:
        adap = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                                     cv2.THRESH_BINARY, 31, 10)
        variants.append(("自适应阈值", cv2.cvtColor(adap, cv2.COLOR_GRAY2RGB)))
    if "锐化" in options:
        kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
        sharp = cv2.filter2D(img_np, -1, kernel)
        variants.append(("锐化", sharp))
    if "去噪" in options:
        denoised = cv2.fastNlMeansDenoisingColored(img_np, None, 10, 10, 7, 21)
        variants.append(("去噪", denoised))
    if "反色" in options:
        variants.append(("反色", 255 - img_np))
    if "放大2x" in options:
        big = cv2.resize(img_np, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        variants.append(("放大2x", big))
    if "旋转90" in options:
        variants.append(("旋转90", cv2.rotate(img_np, cv2.ROTATE_90_CLOCKWISE)))
    if "旋转180" in options:
        variants.append(("旋转180", cv2.rotate(img_np, cv2.ROTATE_180)))
    if "旋转270" in options:
        variants.append(("旋转270", cv2.rotate(img_np, cv2.ROTATE_90_COUNTERCLOCKWISE)))
    return variants


def run_engine_zxing(img_np: np.ndarray) -> List[BarcodeHit]:
    hits = []
    try:
        results = zxingcpp.read_barcodes(img_np)
        for bc in results:
            raw = bytes(bc.bytes) if bc.bytes else (bc.text.encode("utf-8") if bc.text else b"")
            if not raw:
                continue
            bbox = None
            try:
                p = bc.position
                if p is not None:
                    bbox = (p.top_left.x, p.top_left.y, p.bottom_right.x, p.bottom_right.y)
            except Exception:
                pass
            hits.append(BarcodeHit(raw=raw, format=str(bc.format).split(".")[-1],
                                   engine="zxing-cpp", bbox=bbox))
    except Exception:
        pass
    return hits


def run_engine_pyzbar(img_np: np.ndarray) -> List[BarcodeHit]:
    hits = []
    try:
        pil_img = PILImage.fromarray(img_np)
        for obj in pyzbar_decode(pil_img):
            if not obj.data:
                continue
            bbox = None
            if obj.rect:
                r = obj.rect
                bbox = (r.left, r.top, r.left + r.width, r.top + r.height)
            hits.append(BarcodeHit(raw=obj.data, format=obj.type.upper(),
                                   engine="pyzbar", bbox=bbox))
    except Exception:
        pass
    return hits


def run_engine_opencv(img_np: np.ndarray) -> List[BarcodeHit]:
    hits = []
    try:
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(gray)
        if points is not None and data:
            bbox = None
            try:
                pts = points[0]
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                bbox = (min(xs), min(ys), max(xs), max(ys))
            except Exception:
                pass
            hits.append(BarcodeHit(raw=data.encode("utf-8"), format="QRCODE",
                                   engine="opencv", bbox=bbox))
    except Exception:
        pass
    return hits


def dedup_hits(hits: List[BarcodeHit]) -> List[BarcodeHit]:
    seen = set()
    out = []
    for h in hits:
        key = (h.raw, h.format.upper())
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def decode_image_all(qimage: QImage, preproc_options: List[str]) -> Tuple[List[BarcodeHit], str]:
    engines = []
    if HAS_ZXINGCPP:
        engines.append(("zxing-cpp", run_engine_zxing))
    if HAS_PYZBAR:
        engines.append(("pyzbar", run_engine_pyzbar))
    if HAS_CV2:
        engines.append(("opencv", run_engine_opencv))
    if not engines:
        return [], "none"

    img_np = qimage_to_numpy(qimage)
    variants = build_preprocess_variants(img_np, preproc_options)

    all_hits = []
    used_variant = ""
    for vname, var in variants:
        for ename, fn in engines:
            found = fn(var)
            if found:
                all_hits.extend(found)
                used_variant = vname
        if all_hits:
            break
    return dedup_hits(all_hits), used_variant or "原图"


def try_decode_base64(text: str) -> Optional[bytes]:
    s = re.sub(r"\s+", "", text)
    if len(s) < 8 or len(s) % 4 not in (0, 2, 3):
        return None
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def try_decode_hex(text: str) -> Optional[bytes]:
    s = re.sub(r"\s+", "", text)
    if len(s) < 8 or len(s) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def try_decode_url(text: str) -> Optional[bytes]:
    if "%" not in text:
        return None
    try:
        return unquote(text).encode("utf-8")
    except Exception:
        return None


def try_decode_rot13(text: str) -> Optional[bytes]:
    try:
        return codecs.decode(text, "rot_13").encode("utf-8")
    except Exception:
        return None


def try_decompress(data: bytes) -> Optional[Tuple[bytes, str]]:
    for name, fn in [("gzip", gzip.decompress), ("zlib", zlib.decompress),
                     ("bzip2", bz2.decompress)]:
        try:
            out = fn(data)
            if out:
                return out, name
        except Exception:
            pass
    return None


def detect_layers(raw: bytes, max_depth: int = 5) -> List[DecodingLayer]:
    layers = []
    current = raw
    seen = {hashlib.md5(current).hexdigest()}
    for depth in range(max_depth):
        text = None
        try:
            text = current.decode("utf-8")
        except UnicodeDecodeError:
            pass
        if text is None:
            break
        candidates = []
        b64 = try_decode_base64(text)
        if b64:
            candidates.append(("Base64", b64))
        hx = try_decode_hex(text)
        if hx:
            candidates.append(("Hex", hx))
        url = try_decode_url(text)
        if url and url != current:
            candidates.append(("URL编码", url))
        comp = try_decompress(current)
        if comp:
            candidates.append((comp[1], comp[0]))
        if not candidates:
            rot = try_decode_rot13(text)
            if rot and rot != current:
                try:
                    rot_text = rot.decode("utf-8")
                    if sum(c.isalpha() for c in rot_text) / max(len(rot_text), 1) > 0.7:
                        candidates.append(("ROT13", rot))
                except UnicodeDecodeError:
                    pass
        if not candidates:
            break
        method, decoded = candidates[0]
        h = hashlib.md5(decoded).hexdigest()
        if h in seen:
            break
        seen.add(h)
        try:
            new_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            new_text = decoded.decode("latin-1", errors="replace")
        layers.append(DecodingLayer(method=method, data=decoded, text=new_text))
        current = decoded
    return layers


URL_RE = re.compile(r"^(https?://|ftp://|www\.)[^\s]+$", re.IGNORECASE)


def classify_payload(raw: bytes) -> str:
    if not raw:
        return "unknown"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text:
        stripped = text.strip()
        if URL_RE.match(stripped):
            return "url"
        if "data:image/" in stripped and ";base64," in stripped:
            return "image"
        if detect_image_format(raw) in ("png", "jpeg", "gif", "bmp", "webp"):
            return "image"
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        if printable / max(len(text), 1) > 0.85:
            return "text"
    if detect_image_format(raw) in ("png", "jpeg", "gif", "bmp", "webp"):
        return "image"
    return "binary"


def parse_structured_payload(text: str) -> List[StructuredField]:
    fields_list = []
    t = text.strip()
    if t.startswith("WIFI:"):
        parts = dict(re.findall(r"([A-Z]):([^;]*);", t[5:]))
        fields_list.append(StructuredField("WiFi", parts))
    if t.startswith("BEGIN:VCARD"):
        fields = {}
        for line in t.splitlines():
            m = re.match(r"([A-Z]+)[^:]*:(.+)", line)
            if m:
                fields[m.group(1)] = m.group(2)
        fields_list.append(StructuredField("vCard", fields))
    if t.startswith("MECARD:"):
        parts = dict(re.findall(r"([A-Z]+):([^;]*);", t[7:]))
        fields_list.append(StructuredField("MECARD", parts))
    if t.startswith("mailto:"):
        parts = {"address": t[7:].split("?")[0]}
        q = t.split("?", 1)
        if len(q) > 1:
            for kv in q[1].split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    parts[k] = v
        fields_list.append(StructuredField("EMAIL", parts))
    if t.startswith("SMSTO:") or t.startswith("sms:"):
        body = t.split(":", 1)[1]
        parts = {}
        if ":" in body:
            num, msg = body.split(":", 1)
            parts = {"number": num, "message": msg}
        else:
            parts = {"number": body}
        fields_list.append(StructuredField("SMS", parts))
    if t.startswith("tel:"):
        fields_list.append(StructuredField("TEL", {"number": t[4:]}))
    if t.startswith("geo:"):
        coords = t[4:].split(",")
        if len(coords) >= 2:
            fields_list.append(StructuredField("GEO", {"lat": coords[0], "lon": coords[1]}))
    if t.startswith("otpauth://"):
        m = re.match(r"otpauth://([^/]+)/([^?]+)\?(.*)", t)
        if m:
            parts = {"type": m.group(1), "account": m.group(2)}
            for kv in m.group(3).split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    parts[k] = v
            fields_list.append(StructuredField("OTP", parts))
    if URL_RE.match(t):
        u = urlparse(t if t.startswith(("http", "ftp")) else "http://" + t)
        parts = {"scheme": u.scheme, "netloc": u.netloc, "path": u.path}
        if u.query:
            parts["query"] = u.query
            for k, v in parse_qs(u.query).items():
                parts[f"q.{k}"] = v[0] if len(v) == 1 else ",".join(v)
        if u.fragment:
            parts["fragment"] = u.fragment
        if u.port:
            parts["port"] = str(u.port)
        fields_list.append(StructuredField("URL", parts))
    return fields_list


IOC_PATTERNS = {
    "IPv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "IPv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    "域名": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
    "URL": re.compile(r"https?://[^\s\"'<>]+"),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "SHA1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "邮箱": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "CVE": re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE),
    "Windows路径": re.compile(r"[A-Za-z]:\\[^\s\"'<>|*?]+"),
    "注册表": re.compile(r"HKEY_[A-Z_]+\\[^\s\"']+", re.IGNORECASE),
}


def extract_iocs(text: str) -> Dict[str, List[str]]:
    out = {}
    for name, pat in IOC_PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            out[name] = sorted(set(matches))
    return out


DEFAULT_RULES = {
    "rules": [
        {"name": "IP直连URL", "score": 20, "regex": r"^https?://(?:\d{1,3}\.){3}\d{1,3}"},
        {"name": "IDN混淆域名", "score": 25, "regex": r"xn--[a-z0-9]+"},
        {"name": "javascript协议", "score": 30, "regex": r"^javascript:"},
        {"name": "data协议", "score": 30, "regex": r"^data:(?:text/html|application/)"},
        {"name": "vbscript协议", "score": 30, "regex": r"^vbscript:"},
        {"name": "file协议", "score": 15, "regex": r"^file://"},
        {"name": "PowerShell编码命令", "score": 35, "regex": r"(?i)(?:-EncodedCommand|-e\s+[A-Za-z0-9+/=]{20,})"},
        {"name": "PowerShell IEX", "score": 30, "regex": r"(?i)(?:IEX|Invoke-Expression|FromBase64String)"},
        {"name": "certutil下载", "score": 35, "regex": r"(?i)certutil\s+-urlcache"},
        {"name": "bitsadmin", "score": 35, "regex": r"(?i)bitsadmin"},
        {"name": "mshta执行", "score": 30, "regex": r"(?i)mshta\s+"},
        {"name": "长base64串", "score": 15, "regex": r"[A-Za-z0-9+/=]{200,}"},
        {"name": "非标准端口", "score": 10, "regex": r"^https?://[^\s/]+:(?!80\b|443\b)\d{2,5}"},
        {"name": "短链", "score": 10, "regex": r"^(?:https?://)?(?:bit\.ly|t\.cn|tinyurl\.com|goo\.gl|ow\.ly|is\.gd)"},
    ]
}


class HeuristicEngine:
    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict]:
        os.makedirs(RULES_DIR, exist_ok=True)
        rule_file = os.path.join(RULES_DIR, "heuristics.json")
        if os.path.exists(rule_file):
            try:
                with open(rule_file, "r", encoding="utf-8") as f:
                    return json.load(f).get("rules", DEFAULT_RULES["rules"])
            except Exception:
                pass
        try:
            with open(rule_file, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_RULES, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return DEFAULT_RULES["rules"]

    def score(self, text: str, raw: bytes) -> Tuple[int, List[str]]:
        total = 0
        hits = []
        nonprint = sum(1 for b in raw if not (32 <= b < 127) and b not in (9, 10, 13))
        if len(raw) > 0 and nonprint / len(raw) > 0.3:
            total += 10
            hits.append("大量非打印字符 (+10)")
        for rule in self.rules:
            try:
                if re.search(rule["regex"], text, re.MULTILINE):
                    total += rule["score"]
                    hits.append(f"{rule['name']} (+{rule['score']})")
            except re.error:
                continue
        return total, hits


DANGEROUS_PREFIXES = [
    ("javascript:", "JavaScript 伪协议"),
    ("data:text/html", "HTML data URI"),
    ("data:application/", "可执行 data URI"),
    ("vbscript:", "VBScript 伪协议"),
    ("file://", "本地文件访问"),
]


def detect_dangers(text: str) -> List[str]:
    out = []
    lower = text.lower()
    for prefix, desc in DANGEROUS_PREFIXES:
        if lower.startswith(prefix):
            out.append(desc)
    if re.search(r"<script[^>]*>", text, re.IGNORECASE):
        out.append("内嵌 script 标签")
    return out


def extract_exif(image_bytes: bytes) -> Dict[str, str]:
    if not HAS_PIL:
        return {}
    try:
        pil_img = PILImage.open(BytesIO(image_bytes))
        exif_data = pil_img.getexif()
        if not exif_data:
            return {}
        out = {}
        for tag_id, value in exif_data.items():
            tag = EXIF_TAGS.get(tag_id, str(tag_id))
            out[tag] = str(value)
        return out
    except Exception:
        return {}


def identify_file_type(data: bytes) -> str:
    if HAS_MAGIC:
        try:
            return magic.from_buffer(data[:4096], mime=True)
        except Exception:
            pass
    fmt = detect_image_format(data)
    if fmt:
        return f"image/{fmt}"
    if data.startswith(b"%PDF-"):
        return "application/pdf"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip"
    if data.startswith(b"MZ"):
        return "application/x-dosexec"
    if data.startswith(b"\x7fELF"):
        return "application/x-elf"
    return "application/octet-stream"


def analyze_raw(raw: bytes, engine: str, variant: str, fmt: str,
                bbox: Optional[Tuple]) -> DecodeResult:
    kind = classify_payload(raw)
    text = ""
    if kind in ("url", "text", "image"):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")

    layers = detect_layers(raw)
    if layers:
        text = layers[-1].text

    structured = parse_structured_payload(text) if text else []
    iocs = extract_iocs(text) if text else {}
    dangers = detect_dangers(text) if text else []

    he = HeuristicEngine()
    suspicion, hits = he.score(text, raw)

    images: List[QImage] = []
    exif: Dict[str, str] = {}
    if kind == "image":
        for data, f in extract_images_from_bytes(raw):
            qi = qimage_from_bytes(data)
            if qi:
                images.append(qi)
                if not exif:
                    exif = extract_exif(data)
        if not images:
            b64_match = re.search(r"base64,([A-Za-z0-9+/=\s]+)", text or "")
            if b64_match:
                try:
                    data = base64.b64decode(re.sub(r"\s+", "", b64_match.group(1)))
                    qi = qimage_from_bytes(data)
                    if qi:
                        images.append(qi)
                        exif = extract_exif(data)
                except Exception:
                    pass
    if not images:
        for data, f in extract_images_from_bytes(raw):
            qi = qimage_from_bytes(data)
            if qi:
                images.append(qi)

    file_type = identify_file_type(raw)

    return DecodeResult(
        kind=kind, text=text, raw=raw, format=fmt, engine=engine,
        bbox=bbox, images=images, decodings=layers, structured=structured,
        iocs=iocs, suspicion=suspicion, suspicion_hits=hits,
        dangers=dangers, exif=exif, file_type=file_type,
        meta={"variant": variant},
    )


class AnalysisThread(QThread):
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, image: QImage, preproc_options: List[str], parent=None):
        super().__init__(parent)
        self._image = image
        self._preproc = preproc_options

    def run(self):
        try:
            t0 = time.time()
            self.progress.emit("开始解析……")
            hits, variant = decode_image_all(self._image, self._preproc)
            if not hits:
                raise RuntimeError("未识别到任何条码。请检查图片，或勾选更多预处理选项。")
            self.progress.emit(f"识别到 {len(hits)} 个条码（预处理策略：{variant}）")
            results = []
            for h in hits:
                r = analyze_raw(h.raw, h.engine, variant, h.format, h.bbox)
                results.append(r)
                self.progress.emit(
                    f"  [{h.engine}] {h.format} -> {r.kind} "
                    f"可疑度 {r.suspicion} 图片 {len(r.images)} 张"
                )
            elapsed = int((time.time() - t0) * 1000)
            self.progress.emit(f"全部完成，总耗时 {elapsed} ms")
            self.succeeded.emit(results)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class ImageDropLabel(QLabel):
    fileDropped = pyqtSignal(str)
    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("dropArea")
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)
        self.setText("把二维码图片拖到这里\n或点击选择文件")
        self.setMinimumSize(320, 320)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCursor(Qt.PointingHandCursor)
        self.setProperty("hasImage", "false")
        self._pixmap: Optional[QPixmap] = None
        self._bboxes: List[Tuple[float, float, float, float]] = []

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls() or event.mimeData().hasImage():
            event.acceptProposedAction()
            self.setProperty("drag", "true")
            self._repolish()

    def dragLeaveEvent(self, event):
        self.setProperty("drag", "false")
        self._repolish()

    def dropEvent(self, event: QDropEvent):
        self.setProperty("drag", "false")
        self._repolish()
        mime = event.mimeData()
        if mime.hasUrls():
            path = mime.urls()[0].toLocalFile()
            if path:
                self.fileDropped.emit(path)
                return
        event.acceptProposedAction()

    def _repolish(self):
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event: QMouseEvent):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def set_image(self, pixmap: QPixmap):
        self._pixmap = pixmap
        self.setProperty("hasImage", "true")
        self._repolish()
        self.update()

    def set_bboxes(self, bboxes: List[Tuple[float, float, float, float]]):
        self._bboxes = bboxes
        self.update()

    def clear_image(self):
        self._pixmap = None
        self._bboxes = []
        self.setProperty("hasImage", "false")
        self._repolish()
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._pixmap is None or self._pixmap.isNull():
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)

        w = self.width() - 10
        h = self.height() - 10
        if w <= 0 or h <= 0:
            return

        scaled = self._pixmap.scaled(w, h, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        
        x = (self.width() - scaled.width()) // 2
        y = (self.height() - scaled.height()) // 2
        
        painter.drawPixmap(x, y, scaled)

        if self._bboxes and self._pixmap.width() > 0:
            ratio_x = scaled.width() / self._pixmap.width()
            ratio_y = scaled.height() / self._pixmap.height()
            
            pen = QPen(QColor(47, 128, 237), 3)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            
            for (x1, y1, x2, y2) in self._bboxes:
                rx = x + int(x1 * ratio_x)
                ry = y + int(y1 * ratio_y)
                rw = int((x2 - x1) * ratio_x)
                rh = int((y2 - y1) * ratio_y)
                painter.drawRect(rx, ry, rw, rh)
        painter.end()


class CameraDialog(QDialog):
    captured = pyqtSignal(QImage)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("摄像头实时扫描")
        self.resize(720, 600)
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))
        self._cap = None
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        lay = QVBoxLayout(self)
        self.preview = QLabel("正在启动摄像头……")
        self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumSize(640, 480)
        lay.addWidget(self.preview, 1)
        self.log_txt = QPlainTextEdit()
        self.log_txt.setReadOnly(True)
        self.log_txt.setMaximumHeight(100)
        lay.addWidget(self.log_txt)
        btns = QHBoxLayout()
        self.btn_start = QPushButton("开始")
        self.btn_stop = QPushButton("停止")
        self.btn_close = QPushButton("关闭")
        self.btn_start.clicked.connect(self._start)
        self.btn_stop.clicked.connect(self._stop)
        self.btn_close.clicked.connect(self.close)
        btns.addWidget(self.btn_start)
        btns.addWidget(self.btn_stop)
        btns.addWidget(self.btn_close)
        lay.addLayout(btns)
        if not HAS_CV2:
            self.log_txt.appendPlainText("未安装 opencv-python，无法使用摄像头。")
        else:
            self._start()

    def _start(self):
        if not HAS_CV2:
            return
        if self._cap is None:
            self._cap = cv2.VideoCapture(0)
        if not self._cap.isOpened():
            self.log_txt.appendPlainText("无法打开摄像头。")
            return
        self._timer.start(200)
        self.log_txt.appendPlainText("摄像头已启动，实时扫描中……")

    def _stop(self):
        self._timer.stop()
        if self._cap is not None:
            self._cap.release()
            self._cap = None
        self.log_txt.appendPlainText("摄像头已停止。")

    def _tick(self):
        if self._cap is None:
            return
        ret, frame = self._cap.read()
        if not ret:
            return
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        h, w, ch = rgb.shape
        qimg = QImage(rgb.data, w, h, ch * w, QImage.Format_RGB888).copy()
        scaled = qimg.scaled(self.preview.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.preview.setPixmap(QPixmap.fromImage(scaled))
        if HAS_ZXINGCPP:
            try:
                hits = zxingcpp.read_barcodes(rgb)
                for bc in hits:
                    raw = bytes(bc.bytes) if bc.bytes else (bc.text.encode("utf-8") if bc.text else b"")
                    if raw:
                        self.log_txt.appendPlainText(f"识别到：{raw[:120]!r}")
                        self.captured.emit(qimg.copy())
                        self._timer.stop()
                        return
            except Exception:
                pass

    def closeEvent(self, event):
        self._stop()
        super().closeEvent(event)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} —— {APP_DESC}")
        self.resize(1360, 880)
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))

        self.current_image: Optional[QImage] = None
        self.current_results: List[DecodeResult] = []
        self.worker: Optional[AnalysisThread] = None
        self.history: List[HistoryRecord] = []
        self.batch_records: List[Tuple[str, DecodeResult]] = []

        self._build_actions()
        self._build_ui()
        self._apply_style("light")
        self._report_engines()
        self.statusBar().showMessage("就绪")
        
        self.showMaximized()

    def _report_engines(self):
        engines = []
        if HAS_ZXINGCPP:
            engines.append("zxing-cpp")
        if HAS_PYZBAR:
            engines.append("pyzbar")
        if HAS_CV2:
            engines.append("opencv")
        extras = []
        if HAS_MAGIC:
            extras.append("python-magic")
        if HAS_PYMUPDF:
            extras.append("PyMuPDF")
        if HAS_QRCODE:
            extras.append("qrcode")
        if HAS_REQUESTS:
            extras.append("requests")
        msg = f"解码引擎：{', '.join(engines) if engines else '无'}"
        if extras:
            msg += f" | 扩展：{', '.join(extras)}"
        self._log(msg)
        if not engines:
            self._log("警告：未检测到解码库。请 pip install zxing-cpp pyzbar opencv-python")

    def _build_actions(self):
        def mk(text, shortcut, slot):
            a = QAction(text, self)
            if shortcut:
                a.setShortcut(shortcut)
            a.triggered.connect(slot)
            return a
        self.act_open = mk("打开图片", "Ctrl+O", self._on_open_file)
        self.act_paste = mk("从剪贴板", "Ctrl+V", self._on_paste)
        self.act_camera = mk("摄像头", None, self._on_camera)
        self.act_decode = mk("开始解析", "F5", self._start_decode)
        self.act_stop = mk("停止", "Esc", self._on_stop)
        self.act_copy = mk("复制全部", None, self._on_copy_all)
        self.act_save_text = mk("保存文本", "Ctrl+S", self._on_save_text)
        self.act_save_image = mk("保存图片", None, self._on_save_image)
        self.act_report = mk("导出报告", None, self._on_export_report)
        self.act_clear = mk("清空", "Ctrl+L", self._on_clear)
        self.act_stop.setEnabled(False)

    def _build_ui(self):
        tb = QToolBar("主工具栏", self)
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonTextOnly)
        for act in (self.act_open, self.act_paste, self.act_camera, None,
                    self.act_decode, self.act_stop, None,
                    self.act_copy, self.act_save_text, self.act_save_image,
                    self.act_report, None, self.act_clear):
            if act is None:
                tb.addSeparator()
            else:
                tb.addAction(act)
        btn = tb.widgetForAction(self.act_decode)
        if btn:
            btn.setObjectName("btnPrimary")
        btn = tb.widgetForAction(self.act_stop)
        if btn:
            btn.setObjectName("btnDanger")
        self.addToolBar(tb)

        self.tabs = QTabWidget()
        self.tabs.setUsesScrollButtons(True)
        self.tabs.addTab(self._build_analysis_tab(), "解析")
        self.tabs.addTab(self._build_batch_tab(), "批量")
        self.tabs.addTab(self._build_history_tab(), "历史")
        self.tabs.addTab(self._build_generate_tab(), "生成")
        self.tabs.addTab(self._build_range_tab(), "靶场")
        self.tabs.addTab(self._build_settings_tab(), "设置")
        self.setCentralWidget(self.tabs)

        sb = QStatusBar(self)
        self.lbl_session = QLabel("本会话：0 条")
        self.lbl_session.setObjectName("sessionLabel")
        sb.addPermanentWidget(self.lbl_session)
        self.setStatusBar(sb)

    def _build_analysis_tab(self) -> QWidget:
        w = QWidget()
        top = QSplitter(Qt.Horizontal)

        left_card = QFrame()
        left_card.setObjectName("card")
        ll = QVBoxLayout(left_card)
        ll.setContentsMargins(12, 10, 12, 12)
        t = QLabel("二维码源图")
        t.setObjectName("cardTitle")
        ll.addWidget(t)
        self.preview = ImageDropLabel()
        self.preview.fileDropped.connect(self._load_from_path)
        self.preview.clicked.connect(self._on_open_file)
        ll.addWidget(self.preview, 1)
        top.addWidget(left_card)

        right_card = QFrame()
        right_card.setObjectName("card")
        lr = QVBoxLayout(right_card)
        lr.setContentsMargins(12, 10, 12, 12)

        info = QHBoxLayout()
        self.lbl_kind = QLabel("类型: -")
        self.lbl_kind.setObjectName("pillKind")
        self.lbl_count = QLabel("识别: -")
        self.lbl_count.setObjectName("pillSource")
        self.lbl_susp = QLabel("可疑度: -")
        self.lbl_susp.setObjectName("pillSize")
        for x in (self.lbl_kind, self.lbl_count, self.lbl_susp):
            info.addWidget(x)
        info.addStretch(1)
        lr.addLayout(info)

        self.result_tabs = QTabWidget()
        self.result_tabs.setUsesScrollButtons(True)
        
        self.txt_content = QPlainTextEdit()
        self.txt_content.setReadOnly(True)
        self.txt_content.setPlaceholderText("文本内容")
        self.result_tabs.addTab(self.txt_content, "文本")
        
        self.list_images = QListWidget()
        self.list_images.setViewMode(QListWidget.IconMode)
        self.list_images.setIconSize(QSize(140, 140))
        self.list_images.setResizeMode(QListWidget.Adjust)
        self.list_images.setMovement(QListWidget.Static)
        self.list_images.setSpacing(8)
        self.result_tabs.addTab(self.list_images, "图片")
        
        self.txt_raw = QPlainTextEdit()
        self.txt_raw.setReadOnly(True)
        self.txt_raw.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.result_tabs.addTab(self.txt_raw, "原始字节")
        
        self.txt_layers = QPlainTextEdit()
        self.txt_layers.setReadOnly(True)
        self.result_tabs.addTab(self.txt_layers, "解码链")
        
        self.txt_structured = QPlainTextEdit()
        self.txt_structured.setReadOnly(True)
        self.result_tabs.addTab(self.txt_structured, "结构化")
        
        self.txt_ioc = QPlainTextEdit()
        self.txt_ioc.setReadOnly(True)
        self.result_tabs.addTab(self.txt_ioc, "IoC")
        
        self.txt_susp = QPlainTextEdit()
        self.txt_susp.setReadOnly(True)
        self.result_tabs.addTab(self.txt_susp, "可疑度")
        
        self.txt_exif = QPlainTextEdit()
        self.txt_exif.setReadOnly(True)
        self.result_tabs.addTab(self.txt_exif, "EXIF")
        
        lr.addWidget(self.result_tabs, 1)
        top.addWidget(right_card)
        
        top.setStretchFactor(0, 4)
        top.setStretchFactor(1, 6)
        top.setSizes([450, 750])

        log_card = QFrame()
        log_card.setObjectName("card")
        logl = QVBoxLayout(log_card)
        logl.setContentsMargins(12, 10, 12, 12)
        tlog = QLabel("运行日志")
        tlog.setObjectName("cardTitle")
        logl.addWidget(tlog)
        self.txt_log = QPlainTextEdit()
        self.txt_log.setObjectName("logView")
        self.txt_log.setReadOnly(True)
        self.txt_log.setMaximumBlockCount(2000)
        logl.addWidget(self.txt_log)

        split = QSplitter(Qt.Vertical)
        split.addWidget(top)
        split.addWidget(log_card)
        split.setStretchFactor(0, 7)
        split.setStretchFactor(1, 3)
        split.setSizes([650, 180])

        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.addWidget(split)
        return w

    def _build_batch_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        bar = QHBoxLayout()
        b1 = QPushButton("添加文件")
        b2 = QPushButton("添加文件夹")
        b3 = QPushButton("开始扫描")
        b4 = QPushButton("清空")
        b5 = QPushButton("导出 CSV")
        for b in (b1, b2, b3, b4, b5):
            bar.addWidget(b)
        bar.addStretch(1)
        lay.addLayout(bar)
        self.batch_table = QTableWidget(0, 8)
        self.batch_table.setHorizontalHeaderLabels(
            ["文件", "类型", "格式", "引擎", "可疑度", "图片数", "耗时(ms)", "错误"]
        )
        self.batch_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.batch_table, 1)
        b1.clicked.connect(self._batch_add_files)
        b2.clicked.connect(self._batch_add_folder)
        b3.clicked.connect(self._batch_start)
        b4.clicked.connect(self._batch_clear)
        b5.clicked.connect(self._batch_export)
        return w

    def _build_history_tab(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        left = QFrame()
        left.setObjectName("card")
        ll = QVBoxLayout(left)
        t = QLabel("历史会话")
        t.setObjectName("cardTitle")
        ll.addWidget(t)
        self.hist_list = QListWidget()
        ll.addWidget(self.hist_list, 1)
        btn_refresh = QPushButton("刷新")
        btn_refresh.clicked.connect(self._load_history)
        ll.addWidget(btn_refresh)
        lay.addWidget(left, 1)

        right = QFrame()
        right.setObjectName("card")
        lr = QVBoxLayout(right)
        t2 = QLabel("会话详情")
        t2.setObjectName("cardTitle")
        lr.addWidget(t2)
        self.hist_detail = QPlainTextEdit()
        self.hist_detail.setReadOnly(True)
        lr.addWidget(self.hist_detail, 1)
        lay.addWidget(right, 2)

        self.hist_list.itemClicked.connect(self._on_history_click)
        return w

    def _build_generate_tab(self) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        left = QFrame()
        left.setObjectName("card")
        ll = QVBoxLayout(left)
        t = QLabel("二维码生成器")
        t.setObjectName("cardTitle")
        ll.addWidget(t)
        form = QFormLayout()
        self.gen_text = QPlainTextEdit()
        self.gen_text.setPlaceholderText("输入要生成二维码的内容")
        self.gen_text.setMaximumHeight(120)
        form.addRow("内容：", self.gen_text)
        self.gen_ec = QComboBox()
        self.gen_ec.addItems(["L", "M", "Q", "H"])
        self.gen_ec.setCurrentText("M")
        form.addRow("纠错等级：", self.gen_ec)
        self.gen_box = QSpinBox()
        self.gen_box.setRange(1, 50)
        self.gen_box.setValue(10)
        form.addRow("边框：", self.gen_box)
        self.gen_fill = QLineEdit("#000000")
        self.gen_bg = QLineEdit("#FFFFFF")
        form.addRow("前景色：", self.gen_fill)
        form.addRow("背景色：", self.gen_bg)
        ll.addLayout(form)
        bb = QHBoxLayout()
        b_gen = QPushButton("生成")
        b_pick_fg = QPushButton("选前景色")
        b_pick_bg = QPushButton("选背景色")
        b_save = QPushButton("保存 PNG")
        for b in (b_gen, b_pick_fg, b_pick_bg, b_save):
            bb.addWidget(b)
        ll.addLayout(bb)
        lay.addWidget(left, 1)

        right = QFrame()
        right.setObjectName("card")
        lr = QVBoxLayout(right)
        t2 = QLabel("预览")
        t2.setObjectName("cardTitle")
        lr.addWidget(t2)
        self.gen_preview = QLabel("尚未生成")
        self.gen_preview.setAlignment(Qt.AlignCenter)
        self.gen_preview.setMinimumSize(400, 400)
        lr.addWidget(self.gen_preview, 1)
        lay.addWidget(right, 1)

        b_gen.clicked.connect(self._on_generate)
        b_pick_fg.clicked.connect(lambda: self._pick_color(self.gen_fill))
        b_pick_bg.clicked.connect(lambda: self._pick_color(self.gen_bg))
        b_save.clicked.connect(self._save_generated)
        return w

    def _build_range_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(12, 12, 12, 12)
        bar = QHBoxLayout()
        b_dir = QPushButton("选择样本目录")
        b_run = QPushButton("开始评估")
        bar.addWidget(b_dir)
        bar.addWidget(b_run)
        bar.addStretch(1)
        lay.addLayout(bar)
        self.range_label = QLabel("尚未选择样本目录")
        lay.addWidget(self.range_label)
        self.range_table = QTableWidget(0, 6)
        self.range_table.setHorizontalHeaderLabels(
            ["文件", "zxing-cpp", "pyzbar", "opencv", "结果", "备注"]
        )
        self.range_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        lay.addWidget(self.range_table, 1)
        b_dir.clicked.connect(self._range_pick_dir)
        b_run.clicked.connect(self._range_run)
        self._range_dir = ""
        return w

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        inner.setObjectName("settingsInner")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(20, 20, 20, 20)

        g_pre = QGroupBox("预处理策略（勾选后逐项尝试）")
        gpl = QGridLayout()
        self.preproc_checks = {}
        opts = ["灰度", "二值化", "自适应阈值", "锐化", "去噪",
                "反色", "放大2x", "旋转90", "旋转180", "旋转270"]
        for i, o in enumerate(opts):
            cb = QCheckBox(o)
            self.preproc_checks[o] = cb
            gpl.addWidget(cb, i // 5, i % 5)
        g_pre.setLayout(gpl)
        lay.addWidget(g_pre)

        g_theme = QGroupBox("主题")
        tl = QHBoxLayout()
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("浅色模式", "light")
        self.theme_combo.addItem("深色模式", "dark")
        b_apply = QPushButton("应用主题")
        tl.addWidget(QLabel("主题："))
        tl.addWidget(self.theme_combo)
        tl.addWidget(b_apply)
        tl.addStretch(1)
        g_theme.setLayout(tl)
        lay.addWidget(g_theme)

        g_rules = QGroupBox("可疑特征规则")
        rl = QVBoxLayout()
        b_edit = QPushButton("打开规则文件")
        b_reload = QPushButton("重新加载规则")
        b_edit.clicked.connect(self._open_rules_file)
        b_reload.clicked.connect(self._reload_rules)
        rl.addWidget(b_edit)
        rl.addWidget(b_reload)
        g_rules.setLayout(rl)
        lay.addWidget(g_rules)

        g_dep = QGroupBox("可选依赖状态")
        dl = QVBoxLayout()
        deps = [
            ("zxing-cpp", HAS_ZXINGCPP),
            ("pyzbar", HAS_PYZBAR),
            ("opencv-python", HAS_CV2),
            ("python-magic", HAS_MAGIC),
            ("PyMuPDF", HAS_PYMUPDF),
            ("qrcode", HAS_QRCODE),
            ("requests", HAS_REQUESTS),
        ]
        for name, ok in deps:
            dl.addWidget(QLabel(f"{'✓' if ok else '✗'} {name}"))
        g_dep.setLayout(dl)
        lay.addWidget(g_dep)

        lay.addStretch(1)
        scroll.setWidget(inner)
        wl = QVBoxLayout(w)
        wl.setContentsMargins(0, 0, 0, 0)
        wl.addWidget(scroll)
        b_apply.clicked.connect(lambda: self._apply_style(self.theme_combo.currentData()))
        return w

    def _apply_style(self, theme: str):
        self._theme = theme
        if theme == "dark":
            bg = "#1e1f22"
            card = "#2b2d31"
            border = "#3f4147"
            fg = "#e3e5e8"
            sub = "#949ba4"
            hover = "#35373c"
            input_bg = "#1e1f22"
            input_border = "#3f4147"
            tab_bg = "#2b2d31"
            tab_sel = "#4f8aed"
            tab_sel_bg = "#35373c"
            danger = "#ed4245"
            primary = "#4f8aed"
            primary_hover = "#3b74d6"
        else:
            bg = "#f5f6f8"
            card = "#ffffff"
            border = "#e4e6eb"
            fg = "#1f2328"
            sub = "#5f6368"
            hover = "#f0f2f5"
            input_bg = "#ffffff"
            input_border = "#e4e6eb"
            tab_bg = "#ffffff"
            tab_sel = "#2f80ed"
            tab_sel_bg = "#e8f0fe"
            danger = "#eb5757"
            primary = "#2f80ed"
            primary_hover = "#1a6dd4"

        self.setStyleSheet(f"""
            * {{ font-family: "Microsoft YaHei UI","PingFang SC","Segoe UI",sans-serif; }}
            QMainWindow {{ background: {bg}; }}
            QScrollArea, QScrollArea > QWidget > QWidget, QWidget#settingsInner {{ background: transparent; border: none; }}
            
            /* 工具栏 */
            QToolBar {{ background: {card}; border: none; border-bottom: 1px solid {border}; padding: 8px; spacing: 6px; }}
            QToolBar QToolButton {{ background: transparent; border-radius: 6px; padding: 6px 14px; color: {fg}; font-size: 13px; }}
            QToolBar QToolButton:hover {{ background: {hover}; }}
            QToolButton#btnPrimary {{ background: {primary}; color: #ffffff; font-weight: 600; border: none; }}
            QToolButton#btnPrimary:hover {{ background: {primary_hover}; }}
            QToolButton#btnDanger {{ background: {danger}; color: #ffffff; font-weight: 600; border: none; }}
            QToolButton#btnDanger:hover {{ background: #d64545; }}
            
            /* 卡片容器 */
            QFrame#card {{ background: {card}; border: 1px solid {border}; border-radius: 10px; }}
            QLabel#cardTitle {{ font-size: 13px; font-weight: 600; color: {fg}; }}
            
            /* 拖拽区 */
            #dropArea {{ border: 2px dashed {border}; border-radius: 8px; background: {input_bg}; color: {sub}; font-size: 14px; }}
            #dropArea[drag="true"] {{ border-color: {primary}; background: {hover}; }}
            #dropArea[hasImage="true"] {{ border: 1px solid {border}; background: {card}; }}
            
            /* 状态小药丸 */
            QLabel#pillKind {{ background: {primary}; color: #ffffff; border-radius: 10px; padding: 3px 12px; font-size: 12px; }}
            QLabel#pillSource {{ background: {hover}; color: {fg}; border-radius: 10px; padding: 3px 12px; font-size: 12px; }}
            QLabel#pillSize {{ background: #e6f4ea; color: #137333; border-radius: 10px; padding: 3px 12px; font-size: 12px; }}
            
            /* 页签 - 缩小 padding 防止被截断 */
            QTabWidget::pane {{ border: none; background: transparent; }}
            QTabBar::tab {{ background: transparent; border: none; padding: 6px 10px; color: {sub}; font-size: 13px; border-radius: 6px; margin-right: 1px; }}
            QTabBar::tab:selected {{ color: {tab_sel}; background: {tab_sel_bg}; font-weight: 600; }}
            QTabBar::tab:hover:!selected {{ color: {fg}; background: {hover}; }}
            
            /* 文本/输入框 */
            QPlainTextEdit, QTextEdit {{ background: {input_bg}; border: 1px solid {border}; border-radius: 6px; padding: 8px; font-size: 13px; color: {fg}; selection-background-color: {primary}; }}
            QPlainTextEdit#logView {{ font-family: Consolas,Menlo,monospace; font-size: 12px; }}
            
            /* 列表/表格 */
            QListWidget, QTableWidget {{ background: {input_bg}; border: 1px solid {border}; border-radius: 6px; padding: 4px; color: {fg}; outline: none; }}
            QListWidget::item {{ background: {hover}; border: 1px solid {border}; border-radius: 6px; padding: 6px; margin: 4px; color: {sub}; }}
            QListWidget::item:selected {{ background: {tab_sel_bg}; border-color: {primary}; color: {tab_sel}; }}
            QTableWidget {{ gridline-color: {border}; }}
            QHeaderView::section {{ background: {hover}; color: {fg}; border: none; border-bottom: 1px solid {border}; padding: 6px; font-weight: 600; }}
            
            /* 按钮/下拉框/输入行 */
            QPushButton {{ background: {hover}; border: 1px solid {border}; border-radius: 6px; padding: 6px 14px; color: {fg}; font-size: 13px; }}
            QPushButton:hover {{ background: {tab_sel_bg}; color: {primary}; border-color: {primary}; }}
            QComboBox, QLineEdit, QSpinBox {{ background: {input_bg}; border: 1px solid {input_border}; border-radius: 6px; padding: 4px 8px; color: {fg}; min-height: 20px; }}
            QComboBox QAbstractItemView {{ background: {card}; color: {fg}; border: 1px solid {border}; selection-background-color: {tab_sel_bg}; selection-color: {primary}; }}
            
            /* 分组框 - 修复深色模式底色 */
            QGroupBox {{ border: 1px solid {border}; border-radius: 6px; margin-top: 10px; padding-top: 15px; color: {fg}; font-weight: 600; background: {card}; }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {fg}; }}
            
            /* 复选框 */
            QCheckBox {{ color: {fg}; spacing: 6px; }}
            QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {border}; border-radius: 3px; background: {input_bg}; }}
            QCheckBox::indicator:checked {{ background: {primary}; border-color: {primary}; }}
            
            /* 滚动条 */
            QScrollBar:vertical {{ border: none; background: {bg}; width: 10px; margin: 0; }}
            QScrollBar::handle:vertical {{ background: {border}; min-height: 20px; border-radius: 5px; }}
            QScrollBar::handle:vertical:hover {{ background: {sub}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
            QScrollBar:horizontal {{ border: none; background: {bg}; height: 10px; margin: 0; }}
            QScrollBar::handle:horizontal {{ background: {border}; min-width: 20px; border-radius: 5px; }}
            QScrollBar::handle:horizontal:hover {{ background: {sub}; }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
            
            /* 其他 */
            QLabel {{ color: {fg}; background: transparent; }}
            QStatusBar {{ background: {card}; border-top: 1px solid {border}; color: {sub}; }}
            QLabel#sessionLabel {{ color: {primary}; font-weight: 600; padding: 0 8px; }}
        """)

    def _open_rules_file(self):
        rule_file = os.path.join(RULES_DIR, "heuristics.json")
        if not os.path.exists(rule_file):
            os.makedirs(RULES_DIR, exist_ok=True)
            with open(rule_file, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_RULES, f, ensure_ascii=False, indent=2)
        QMessageBox.information(self, "规则文件", f"规则文件位于：\n{rule_file}\n\n修改后点击“重新加载规则”。")

    def _reload_rules(self):
        HeuristicEngine()
        self._log("可疑特征规则已重新加载")

    def _on_open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择二维码图片", "",
            "图片/文档 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.pdf);;所有文件 (*)"
        )
        if path:
            self._load_from_path(path)

    def _load_from_path(self, path: str):
        if not path or not os.path.isfile(path):
            QMessageBox.warning(self, "提示", "文件不存在")
            return
        if path.lower().endswith(".pdf"):
            if not HAS_PYMUPDF:
                QMessageBox.warning(self, "提示", "需要安装 PyMuPDF：pip install PyMuPDF")
                return
            self._load_pdf(path)
            return
        pm = QPixmap(path)
        if pm.isNull():
            QMessageBox.warning(self, "提示", "无法解析该图片")
            return
        self._set_source(pm.toImage(), os.path.basename(path))

    def _load_pdf(self, path: str):
        try:
            doc = fitz.open(path)
            for pno in range(len(doc)):
                page = doc[pno]
                pix = page.get_pixmap(dpi=150)
                img = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format_RGB888).copy()
                self._set_source(img, f"{os.path.basename(path)} p{pno+1}")
                return
        except Exception as exc:
            QMessageBox.warning(self, "PDF 解析失败", str(exc))

    def _on_paste(self):
        cb = QApplication.clipboard()
        img = cb.image()
        if img.isNull():
            mime = cb.mimeData()
            if mime is not None and mime.hasUrls():
                self._load_from_path(mime.urls()[0].toLocalFile())
                return
            QMessageBox.information(self, "提示", "剪贴板里没有图片")
            return
        self._set_source(img, "剪贴板")

    def _on_camera(self):
        dlg = CameraDialog(self)
        dlg.captured.connect(lambda img: self._set_source(img, "摄像头"))
        dlg.exec_()

    def _set_source(self, image: QImage, source: str):
        self.current_image = image
        self.preview.set_image(QPixmap.fromImage(image))
        self.preview.set_bboxes([])
        self._log(f"载入：{source} ({image.width()}x{image.height()})")
        self._start_decode()

    def _start_decode(self):
        if self.current_image is None:
            QMessageBox.information(self, "提示", "请先载入二维码图片")
            return
        if self.worker is not None and self.worker.isRunning():
            return
        self._reset_results()
        opts = [k for k, cb in self.preproc_checks.items() if cb.isChecked()]
        self.worker = AnalysisThread(self.current_image, opts, self)
        self.worker.progress.connect(self._log)
        self.worker.succeeded.connect(self._on_analysis_done)
        self.worker.failed.connect(self._on_analysis_failed)
        self.worker.finished.connect(lambda: (self.act_decode.setEnabled(True),
                                              self.act_stop.setEnabled(False)))
        self.worker.start()
        self.act_decode.setEnabled(False)
        self.act_stop.setEnabled(True)

    def _on_stop(self):
        if self.worker is not None and self.worker.isRunning():
            self.worker.requestInterruption()
            self._log("已请求中断")

    def _on_analysis_done(self, results: List[DecodeResult]):
        self.current_results = results
        bboxes = [r.bbox for r in results if r.bbox]
        self.preview.set_bboxes(bboxes)

        if not results:
            return
        first = results[0]

        self.lbl_kind.setText(f"类型: {first.kind}")
        self.lbl_count.setText(f"识别: {len(results)} 个")
        self.lbl_susp.setText(f"可疑度: {first.suspicion}")

        self.txt_content.setPlainText(first.text or "（无文本）")

        self.list_images.clear()
        for r in results:
            for idx, img in enumerate(r.images):
                pm = QPixmap.fromImage(img)
                item = QListWidgetItem(QIcon(pm), f"{r.format}_{idx} {img.width()}x{img.height()}")
                self.list_images.addItem(item)

        self.txt_raw.setPlainText(hexdump(first.raw) if first.raw else "（空）")

        if first.decodings:
            lines = [f"原始：{first.raw[:120]!r}"]
            for i, layer in enumerate(first.decodings):
                lines.append(f"\n第 {i+1} 层 [{layer.method}]：")
                lines.append(layer.text[:500])
            self.txt_layers.setPlainText("\n".join(lines))
        else:
            self.txt_layers.setPlainText("（未检测到多层编码）")

        if first.structured:
            lines = []
            for sf in first.structured:
                lines.append(f"[{sf.category}]")
                for k, v in sf.fields.items():
                    lines.append(f"  {k}: {v}")
                lines.append("")
            self.txt_structured.setPlainText("\n".join(lines))
        else:
            self.txt_structured.setPlainText("（未识别出结构化格式）")

        if first.iocs:
            lines = []
            for k, v in first.iocs.items():
                lines.append(f"[{k}]")
                for item in v:
                    lines.append(f"  {item}")
                lines.append("")
            self.txt_ioc.setPlainText("\n".join(lines))
        else:
            self.txt_ioc.setPlainText("（无 IoC）")

        susp_lines = [f"可疑度评分：{first.suspicion}"]
        if first.dangers:
            susp_lines.append("\n危险内容：")
            for d in first.dangers:
                susp_lines.append(f"  ⚠ {d}")
        if first.suspicion_hits:
            susp_lines.append("\n命中规则：")
            for h in first.suspicion_hits:
                susp_lines.append(f"  • {h}")
        if first.suspicion == 0 and not first.dangers:
            susp_lines.append("\n未发现明显可疑特征")
        self.txt_susp.setPlainText("\n".join(susp_lines))

        if first.exif:
            self.txt_exif.setPlainText("\n".join(f"{k}: {v}" for k, v in first.exif.items()))
        else:
            self.txt_exif.setPlainText("（无 EXIF 数据）")

        for r in results:
            self.history.append(HistoryRecord(
                source_image=self.current_image.copy() if self.current_image else None,
                source_name=r.format,
                result=r,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ))
        self._update_session_label()

        self.statusBar().showMessage(
            f"解析完成：{len(results)} 个条码，可疑度 {first.suspicion}", 5000
        )

    def _on_analysis_failed(self, msg: str):
        self._log(f"[错误] {msg}")
        QMessageBox.warning(self, "解析失败", msg)

    def _reset_results(self):
        self.current_results = []
        self.lbl_kind.setText("类型: -")
        self.lbl_count.setText("识别: -")
        self.lbl_susp.setText("可疑度: -")
        for w in (self.txt_content, self.txt_raw, self.txt_layers,
                  self.txt_structured, self.txt_ioc, self.txt_susp, self.txt_exif):
            w.clear()
        self.list_images.clear()

    def _on_copy_all(self):
        if not self.current_results:
            return
        r = self.current_results[0]
        parts = [r.text]
        for k, v in r.iocs.items():
            parts.append(f"\n[{k}]")
            parts.extend(v)
        QApplication.clipboard().setText("\n".join(parts))
        self.statusBar().showMessage("已复制到剪贴板", 3000)

    def _on_save_text(self):
        if not self.current_results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存文本", "qr_result.txt", "文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for i, r in enumerate(self.current_results):
                    f.write(f"=== 结果 {i+1} [{r.format}/{r.engine}] ===\n")
                    f.write(r.text + "\n")
                    if r.iocs:
                        f.write("\nIoC:\n")
                        for k, v in r.iocs.items():
                            f.write(f"  [{k}]\n")
                            for item in v:
                                f.write(f"    {item}\n")
                    f.write("\n")
            self._log(f"文本已保存：{path}")
        except OSError as exc:
            QMessageBox.warning(self, "保存失败", str(exc))

    def _on_save_image(self):
        row = self.list_images.currentRow()
        if row < 0:
            QMessageBox.information(self, "提示", "请先选择一张图片")
            return
        item = self.list_images.item(row)
        icon = item.icon()
        pm = icon.pixmap(icon.actualSize(QSize(400, 400)))
        path, _ = QFileDialog.getSaveFileName(
            self, "保存图片", "img.png", "PNG (*.png);;JPEG (*.jpg)"
        )
        if path and pm.save(path):
            self._log(f"图片已保存：{path}")

    def _on_export_report(self):
        if not self.current_results:
            QMessageBox.information(self, "提示", "请先解析")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出报告", "report.html", "HTML (*.html)"
        )
        if not path:
            return
        try:
            self._write_html_report(self.current_results, path)
            self._log(f"报告已导出：{path}")
            if QMessageBox.question(self, "报告已导出", "是否立即打开？") == QMessageBox.Yes:
                webbrowser.open(path)
        except Exception as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    def _write_html_report(self, results: List[DecodeResult], path: str):
        rows = []
        for i, r in enumerate(results):
            ioc_html = ""
            for k, v in r.iocs.items():
                ioc_html += f"<tr><td><b>{k}</b></td><td><pre>{chr(10).join(v)}</pre></td></tr>"
            hits_html = "".join(f"<li>{h}</li>" for h in r.suspicion_hits)
            dangers_html = "".join(f"<li>⚠ {d}</li>" for d in r.dangers)
            rows.append(f"""
            <div class="record">
              <h3>结果 {i+1} · {r.format} · {r.engine} · 类型 {r.kind}</h3>
              <p class="susp">可疑度 {r.suspicion}</p>
              <h4>文本内容</h4><pre>{r.text}</pre>
              <h4>IoC</h4><table>{ioc_html or '<tr><td>（无）</td></tr>'}</table>
              <h4>可疑命中</h4><ul>{hits_html or '<li>无</li>'}</ul>
              <h4>危险内容</h4><ul>{dangers_html or '<li>无</li>'}</ul>
            </div>
            """)
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>QRHive 报告</title>
        <style>
        body {{ font-family: -apple-system,sans-serif; background: #f5f6f8; padding: 20px; color: #1f2328; }}
        h1 {{ color: #2f80ed; }}
        .record {{ background: #fff; border: 1px solid #e4e6eb; border-radius: 10px; padding: 20px; margin: 16px 0; }}
        .susp {{ color: #eb5757; font-weight: 600; }}
        pre {{ background: #fafbfc; border: 1px solid #e4e6eb; border-radius: 6px; padding: 12px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        td, th {{ border: 1px solid #e4e6eb; padding: 6px 10px; text-align: left; vertical-align: top; }}
        ul {{ padding-left: 20px; }}
        </style></head><body>
        <h1>QRHive 分析报告</h1>
        <p>导出时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>共 {len(results)} 条结果</p>
        {''.join(rows)}
        </body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _on_clear(self):
        self.current_image = None
        self._reset_results()
        self.preview.clear_image()
        self.txt_log.clear()
        self.statusBar().showMessage("已清空", 3000)

    def _batch_add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, "选择文件", "",
            "图片/文档 (*.png *.jpg *.jpeg *.bmp *.gif *.webp *.pdf);;所有文件 (*)"
        )
        for p in paths:
            self._batch_add_row(p)

    def _batch_add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if not d:
            return
        for root, _, files in os.walk(d):
            for f in files:
                if f.lower().split(".")[-1] in ("png", "jpg", "jpeg", "bmp", "gif", "webp", "pdf"):
                    self._batch_add_row(os.path.join(root, f))

    def _batch_add_row(self, path: str):
        row = self.batch_table.rowCount()
        self.batch_table.insertRow(row)
        self.batch_table.setItem(row, 0, QTableWidgetItem(os.path.basename(path)))
        self.batch_table.item(row, 0).setData(Qt.UserRole, path)
        for c in range(1, 8):
            self.batch_table.setItem(row, c, QTableWidgetItem(""))

    def _batch_start(self):
        rows = self.batch_table.rowCount()
        if rows == 0:
            return
        self._batch_records = []
        for row in range(rows):
            path = self.batch_table.item(row, 0).data(Qt.UserRole)
            if not path or not os.path.isfile(path):
                continue
            t0 = time.time()
            try:
                pm = QPixmap(path)
                if pm.isNull():
                    self.batch_table.setItem(row, 7, QTableWidgetItem("无法载入"))
                    continue
                img = pm.toImage()
                hits, variant = decode_image_all(img, [])
                elapsed = int((time.time() - t0) * 1000)
                if not hits:
                    self.batch_table.setItem(row, 7, QTableWidgetItem("未识别"))
                    continue
                r = analyze_raw(hits[0].raw, hits[0].engine, variant, hits[0].format, hits[0].bbox)
                self.batch_table.setItem(row, 1, QTableWidgetItem(r.kind))
                self.batch_table.setItem(row, 2, QTableWidgetItem(r.format))
                self.batch_table.setItem(row, 3, QTableWidgetItem(r.engine))
                self.batch_table.setItem(row, 4, QTableWidgetItem(str(r.suspicion)))
                self.batch_table.setItem(row, 5, QTableWidgetItem(str(len(r.images))))
                self.batch_table.setItem(row, 6, QTableWidgetItem(str(elapsed)))
                self.batch_records.append((path, r))
            except Exception as exc:
                self.batch_table.setItem(row, 7, QTableWidgetItem(str(exc)))
        self.statusBar().showMessage(f"批量扫描完成，成功 {len(self.batch_records)} 条", 5000)

    def _batch_clear(self):
        self.batch_table.setRowCount(0)
        self.batch_records = []

    def _batch_export(self):
        if not self.batch_records:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 CSV", "batch.csv", "CSV (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["文件", "类型", "格式", "引擎", "可疑度", "文本"])
                for fp, r in self.batch_records:
                    w.writerow([fp, r.kind, r.format, r.engine, r.suspicion, r.text])
            self._log(f"批量结果已导出：{path}")
        except Exception as exc:
            QMessageBox.warning(self, "导出失败", str(exc))

    def _load_history(self):
        self.hist_list.clear()
        if not os.path.isdir(SESSIONS_DIR):
            return
        for name in sorted(os.listdir(SESSIONS_DIR), reverse=True):
            d = os.path.join(SESSIONS_DIR, name)
            if os.path.isdir(d):
                self.hist_list.addItem(name)

    def _on_history_click(self, item: QListWidgetItem):
        name = item.text()
        path = os.path.join(SESSIONS_DIR, name, "manifest.json")
        if not os.path.isfile(path):
            self.hist_detail.setPlainText("无法读取该会话")
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            lines = [f"会话：{name}",
                     f"创建时间：{data.get('created', '?')}",
                     f"应用版本：{data.get('app', '?')} {data.get('version', '?')}",
                     f"记录数：{len(data.get('records', []))}", ""]
            for rec in data.get("records", []):
                lines.append(f"[{rec.get('index')}] {rec.get('timestamp')}")
                lines.append(f"  类型: {rec.get('kind')}")
                lines.append(f"  引擎: {rec.get('decoder')}")
                lines.append(f"  文本: {rec.get('text', '')[:200]}")
                lines.append(f"  图片: {len(rec.get('images', []))} 张")
                lines.append("")
            self.hist_detail.setPlainText("\n".join(lines))
        except Exception as exc:
            self.hist_detail.setPlainText(f"读取失败：{exc}")

    def _pick_color(self, line_edit: QLineEdit):
        c = QColorDialog.getColor()
        if c.isValid():
            line_edit.setText(c.name())

    def _on_generate(self):
        if not HAS_QRCODE:
            QMessageBox.warning(self, "提示", "需要安装 qrcode：pip install qrcode")
            return
        text = self.gen_text.toPlainText()
        if not text:
            QMessageBox.information(self, "提示", "请输入内容")
            return
        ec_map = {"L": ERROR_CORRECT_L, "M": ERROR_CORRECT_M,
                  "Q": ERROR_CORRECT_Q, "H": ERROR_CORRECT_H}
        try:
            qr = qrcode.QRCode(
                version=None,
                error_correction=ec_map[self.gen_ec.currentText()],
                box_size=self.gen_box.value(),
                border=4,
            )
            qr.add_data(text)
            qr.make(fit=True)
            img = qr.make_image(fill_color=self.gen_fill.text(),
                                back_color=self.gen_bg.text())
            buf = BytesIO()
            img.save(buf, format="PNG")
            qimg = QImage.fromData(buf.getvalue())
            pm = QPixmap.fromImage(qimg)
            self.gen_preview.setPixmap(pm.scaled(400, 400, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            self._gen_last_pm = pm
        except Exception as exc:
            QMessageBox.warning(self, "生成失败", str(exc))

    def _save_generated(self):
        pm = getattr(self, "_gen_last_pm", None)
        if pm is None:
            QMessageBox.information(self, "提示", "请先生成")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存二维码", "qrcode.png", "PNG (*.png)"
        )
        if path and pm.save(path):
            self._log(f"二维码已保存：{path}")

    def _range_pick_dir(self):
        d = QFileDialog.getExistingDirectory(self, "选择样本目录")
        if d:
            self._range_dir = d
            self.range_label.setText(f"样本目录：{d}")

    def _range_run(self):
        if not self._range_dir:
            QMessageBox.information(self, "提示", "请先选择样本目录")
            return
        files = []
        for root, _, fs in os.walk(self._range_dir):
            for f in fs:
                if f.lower().split(".")[-1] in ("png", "jpg", "jpeg", "bmp", "gif", "webp"):
                    files.append(os.path.join(root, f))
        self.range_table.setRowCount(0)
        for fp in files:
            pm = QPixmap(fp)
            if pm.isNull():
                continue
            img = pm.toImage()
            np_img = qimage_to_numpy(img)
            zx = bool(run_engine_zxing(np_img)) if HAS_ZXINGCPP else False
            py = bool(run_engine_pyzbar(np_img)) if HAS_PYZBAR else False
            cv = bool(run_engine_opencv(np_img)) if HAS_CV2 else False
            row = self.range_table.rowCount()
            self.range_table.insertRow(row)
            self.range_table.setItem(row, 0, QTableWidgetItem(os.path.basename(fp)))
            self.range_table.setItem(row, 1, QTableWidgetItem("✓" if zx else "✗"))
            self.range_table.setItem(row, 2, QTableWidgetItem("✓" if py else "✗"))
            self.range_table.setItem(row, 3, QTableWidgetItem("✓" if cv else "✗"))
            ok_count = sum([zx, py, cv])
            self.range_table.setItem(row, 4, QTableWidgetItem(f"{ok_count}/3"))
            note = ""
            if ok_count == 0:
                note = "全部引擎失败"
            elif ok_count == 3:
                note = "全部识别"
            self.range_table.setItem(row, 5, QTableWidgetItem(note))

    def _update_session_label(self):
        self.lbl_session.setText(f"本会话：{len(self.history)} 条")

    def _log(self, msg: str):
        self.txt_log.appendPlainText(msg)

    def _save_session(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        d = os.path.join(SESSIONS_DIR, f"session_{ts}")
        os.makedirs(d, exist_ok=True)
        manifest = {"created": datetime.now().isoformat(timespec="seconds"),
                    "app": APP_NAME, "version": APP_VERSION, "records": []}
        for i, rec in enumerate(self.history):
            entry = {"index": i, "timestamp": rec.timestamp,
                     "source_name": rec.source_name, "kind": rec.result.kind,
                     "format": rec.result.format, "engine": rec.result.engine,
                     "text": rec.result.text, "raw_length": len(rec.result.raw),
                     "suspicion": rec.result.suspicion,
                     "iocs": rec.result.iocs, "images": []}
            if rec.source_image and not rec.source_image.isNull():
                p = os.path.join(d, f"source_{i:02d}.png")
                if rec.source_image.save(p, "PNG"):
                    entry["source_image"] = os.path.basename(p)
            if rec.result.text:
                p = os.path.join(d, f"text_{i:02d}.txt")
                with open(p, "w", encoding="utf-8") as f:
                    f.write(rec.result.text)
                entry["text_file"] = os.path.basename(p)
            if rec.result.raw:
                p = os.path.join(d, f"raw_{i:02d}.bin")
                with open(p, "wb") as f:
                    f.write(rec.result.raw)
                entry["raw_file"] = os.path.basename(p)
            for j, img in enumerate(rec.result.images):
                p = os.path.join(d, f"image_{i:02d}_{j}.png")
                if img.save(p, "PNG"):
                    entry["images"].append(os.path.basename(p))
            manifest["records"].append(entry)
        with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        return d

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.worker.requestInterruption()
            self.worker.wait(3000)
        if self.history:
            try:
                d = self._save_session()
                QMessageBox.information(self, "会话已保存",
                    f"共 {len(self.history)} 条记录\n保存位置：\n{d}")
            except Exception as exc:
                QMessageBox.warning(self, "保存失败", str(exc))
        super().closeEvent(event)


def cli_main(args):
    if not os.path.isfile(args.scan):
        print(f"文件不存在：{args.scan}", file=sys.stderr)
        return 1
    pm = QPixmap(args.scan)
    if pm.isNull():
        print(f"无法载入图片：{args.scan}", file=sys.stderr)
        return 1
    img = pm.toImage()
    hits, variant = decode_image_all(img, [])
    if not hits:
        print("未识别到条码", file=sys.stderr)
        return 2
    outputs = []
    for h in hits:
        r = analyze_raw(h.raw, h.engine, variant, h.format, h.bbox)
        if args.json:
            outputs.append({
                "kind": r.kind, "format": r.format, "engine": r.engine,
                "text": r.text, "raw_hex": r.raw.hex(), "suspicion": r.suspicion,
                "iocs": r.iocs, "hits": r.suspicion_hits,
                "dangers": r.dangers, "images": len(r.images),
            })
        else:
            print(f"=== {r.format} / {r.engine} / {r.kind} ===")
            print(r.text)
            if r.iocs:
                print("IoC:")
                for k, v in r.iocs.items():
                    print(f"  [{k}]")
                    for item in v:
                        print(f"    {item}")
            if r.suspicion:
                print(f"可疑度：{r.suspicion}")
                for h2 in r.suspicion_hits:
                    print(f"  · {h2}")
            print()
    if args.json:
        print(json.dumps(outputs, ensure_ascii=False, indent=2))
    return 0


class QRHiveApp(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName(APP_NAME)
        self.setApplicationVersion(APP_VERSION)
        if os.path.exists(ICON_PATH):
            self.setWindowIcon(QIcon(ICON_PATH))


def main():
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--scan", help="扫描指定图片并输出结果（命令行模式）")
    parser.add_argument("--json", action="store_true", help="命令行模式输出 JSON")
    args = parser.parse_args()

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    if args.scan:
        app = QApplication(sys.argv)
        return cli_main(args)

    app = QRHiveApp(sys.argv)
    win = MainWindow()
    win.showMaximized() 
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())