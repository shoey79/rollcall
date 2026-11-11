"""Newer versions of installed Windows programs, from the winget catalogue.

The add-on downloads Microsoft's pre-built winget index (source2.msix, a zip holding a SQLite
database) about once a day, and matches each program an agent reports the way winget itself
does: first by the program's Uninstall key name (its MSI product code, or the key name winget
records for other installers), then by its normalised name and publisher. Nothing runs on the
servers, so this works on every Windows version, including Server 2016 and 2019.

The name normaliser is a port of winget's NameNormalization.cpp ("Initial" version), checked
against winget's own test data; the version comparison follows its Versions.cpp.
"""
from __future__ import annotations

import io
import sqlite3
import unicodedata
import zipfile

try:
    import regex as re  # \p{L} classes and variable-width look-behinds, as ICU has
except ImportError:  # pragma: no cover - the add-on image installs py3-regex
    re = None

INDEX_URL = "https://cdn.winget.microsoft.com/cache/source2.msix"

_F = 0 if re is None else re.IGNORECASE | re.V1


def _rx(p: str):
    return re.compile(p, _F) if re else None


ARCH_X32 = _rx(r"(?<=^|[^\p{L}\p{Nd}])(X32|X86)(?=\P{Nd}|$)(?:\sEDITION)?")
ARCH_X64 = _rx(r"(?<=^|[^\p{L}\p{Nd}])(X64|AMD64|X86([\p{Pd}\p{Pc}]64))(?=\P{Nd}|$)(?:\sEDITION)?")
ARCH_ARM64 = _rx(r"(?<=^|[^\p{L}\p{Nd}])(ARM64|AARCH64)(?=\P{Nd}|$)(?:\sEDITION)?")
ARCH_ARM = _rx(r"(?<=^|[^\p{L}\p{Nd}])(ARM32)(?=\P{Nd}|$)(?:\sEDITION)?")
ARCH_32BIT = _rx(r"(?<=^|[^\p{L}\p{Nd}])(32[\p{Pd}\p{Pc}\p{Z}]?BIT)S?(?:\sEDITION)?")
ARCH_64BIT = _rx(r"(?<=^|[^\p{L}\p{Nd}])(64[\p{Pd}\p{Pc}\p{Z}]?BIT)S?(?:\sEDITION)?")
ARCH_32OR64 = _rx(r"(?<=^|[^\p{L}\p{Nd}])((64[\\\/]32|32[\\\/]64)[\p{Pd}\p{Pc}\p{Z}]?BIT)S?(?:\sEDITION)?")
LOCALE = _rx(r"(?<![A-Z])((?:\p{Lu}{2,3}(-(CANS|CYRL|LATN|MONG))?-\p{Lu}{2})(?![A-Z])(?:-VALENCIA)?)")
SAP_PACKAGE = _rx(r"^(?:[\p{Lu}\p{Nd}]+[\._])+[\p{Lu}\p{Nd}]+(?:-(?:\p{Nd}+\.)+\p{Nd}+)(?:-(?:\p{Lu}{2}(?:_\p{Lu}{2})?|CORE))(?:-(?:\p{Lu}{2}|\p{Nd}{2}))$")
KB_NUMBERS = _rx(r"\((KB\d+)\)")
NON_LETTERS_AND_DIGITS = _rx(r"[^\p{L}\p{Nd}]")
URI_PROTOCOL = _rx(r"(?<!\p{L})(?:http[s]?|ftp):\/\/")
VERSION_DELIMITED = _rx(r"((?<!\p{L})(?:V|VER|VERSI(?:O|Ó)N|VERSÃO|VERSIE|WERSJA|BUILD|RELEASE|RC|SP)\P{L}?)?\p{Nd}+([\p{Po}\p{Pd}\p{Pc}]\p{Nd}?(RC|B|A|R|SP|K)?\p{Nd}+)+([\p{Po}\p{Pd}\p{Pc}]?[\p{L}\p{Nd}]+)*")
VERSION = _rx(r"(FOR\s)?(?<!\p{L})(?:P|V|R|VER|VERSI(?:O|Ó)N|VERSÃO|VERSIE|WERSJA|BUILD|RELEASE|RC|SP)(?:\P{L}|\P{L}\p{L})?(\p{Nd}|\.\p{Nd})+(?:RC|B|A|R|V|SP)?\p{Nd}?")
VERSION_LETTER = _rx(r"(?<!\p{L})(?:(?:V|VER|VERSI(?:O|Ó)N|VERSÃO|VERSIE|WERSJA|BUILD|RELEASE|RC|SP)\P{L})?\p{Lu}\p{Nd}+(?:[\p{Po}\p{Pd}\p{Pc}]\p{Nd}+)+")
NON_NESTED_BRACKET = _rx(r"\([^\(\)]*\)|\[[^\[\]]*\]")
BRACKET_ENCLOSED = _rx(r"(?:\p{Ps}.*\p{Pe}|\".*\")")
LEADING_SYMBOLS = _rx(r"^[^\p{L}\p{Nd}]+")
TRAILING_NON_LETTERS = _rx(r"\P{L}+$")
PREFIX_PARENS = _rx(r"^\(.*?\)")
EMPTY_PARENS = _rx(r"(\(\s*\)|\[\s*\]|\"\s*\")")
EN = _rx(r"\sEN\s*$")
TRAILING_SYMBOLS = _rx(r"[^\p{L}\p{Nd}]+$")
FILE_PATH = _rx(r"(((INSTALLED\sAT|IN)\s)?[CDEF]:\\(.+?\\)*[^\s]*\\?)")
FILE_PATH_GHS = _rx(r"\(CHANGE #\d{1,2} TO [CDEF]:\\(.+?\\)*[^\s]*\\?\)")
FILE_PATH_PARENS = _rx(r"\([CDEF]:\\(.+?\\)*[^\s]*\\?\)")
FILE_PATH_QUOTES = _rx(r"\"[CDEF]:\\(.+?\\)*[^\s]*\\?\"")
ROBLOX = _rx(r"(?<=^ROBLOX\s(PLAYER|STUDIO))(\sFOR\s.*)")
BOMGAR = _rx(r"(?<=^BOMGAR\s(JUMP CLIENT|(ACCESS|REPRESENTATIVE) CONSOLE|BUTTON)|^EMBEDDED CALLBACK)(\s.*)")
ACRONYM_SEPARATORS = _rx(r"(?:(?<=^\p{L})|(?<=\P{L}\p{L}))(\.|\/)(?=\p{L}(?:\P{L}|$))")
NON_LETTERS = _rx(r"(?<=^|\s)[^\p{L}]+(?=\s|$)")
PROGRAM_NAME_SPLIT = _rx(r"[^\p{L}\p{Nd}\+\&]")
PUBLISHER_NAME_SPLIT = _rx(r"[^\p{L}\p{Nd}]")

PROGRAM_NAME_REGEXES = [ROBLOX, BOMGAR, PREFIX_PARENS, EMPTY_PARENS, FILE_PATH_GHS, FILE_PATH_PARENS, FILE_PATH_QUOTES,
                        FILE_PATH, VERSION_LETTER, VERSION_DELIMITED, VERSION, EN, NON_NESTED_BRACKET, BRACKET_ENCLOSED,
                        URI_PROTOCOL, LEADING_SYMBOLS, TRAILING_SYMBOLS]
PUBLISHER_NAME_REGEXES = [VERSION_DELIMITED, VERSION, NON_NESTED_BRACKET, BRACKET_ENCLOSED, URI_PROTOCOL, NON_LETTERS,
                          TRAILING_NON_LETTERS, ACRONYM_SEPARATORS]

_LOCALES = """AF-ZA AM-ET AR-AE AR-BH AR-DZ AR-EG AR-IQ AR-JO AR-KW AR-LB AR-LY AR-MA ARN-CL AR-OM AR-QA AR-SA AR-SY AR-TN
AR-YE AS-IN BA-RU BE-BY BG-BG BN-BD BN-IN BO-CN BR-FR CA-ES CA-ES-VALENCIA CO-FR CS-CZ CY-GB DA-DK DE-AT DE-CH DE-DE DE-LI
DE-LU DSB-DE DV-MV EL-GR EN-AU EN-BZ EN-CA EN-GB EN-IE EN-IN EN-JM EN-MY EN-NZ EN-PH EN-SG EN-TT EN-US EN-ZA EN-ZW ES-AR
ES-BO ES-CL ES-CO ES-CR ES-DO ES-EC ES-ES ES-GT ES-HN ES-MX ES-NI ES-PA ES-PE ES-PR ES-PY ES-SV ES-US ES-UY ES-VE ET-EE
EU-ES FA-IR FI-FI FIL-PH FO-FO FR-BE FR-CA FR-CH FR-FR FR-LU FR-MC FY-NL GA-IE GD-DB GL-ES GSW-FR GU-IN HE-IL HI-IN HR-BA
HR-HR HSB-DE HU-HU HY-AM ID-ID IG-NG II-CN IS-IS IT-CH IT-IT JA-JP KA-GE KK-KZ KL-GL KM-KH KN-IN KOK-IN KO-KR KY-KG LB-LU
LO-LA LT-LT LV-LV MI-NZ MK-MK ML-IN MN-MN MOH-CA MR-IN MS-BN MS-MY MT-MT NB-NO NE-NP NL-BE NL-NL NN-NO NSO-ZA OC-FR OR-IN
PA-IN PL-PL PRS-AF PS-AF PT-BR PT-PT QUT-GT QUZ-BO QUZ-EC QUZ-PE RM-CH RO-RO RU-RU RW-RW SAH-RU SA-IN SE-FI SE-NO SE-SE
SI-LK SK-SK SL-SI SMA-NO SMA-SE SMJ-NO SMJ-SE SMN-FI SMS-FI SQ-AL SV-FI SV-SE SW-KE SYR-SY TA-IN TE-IN TH-TH TK-TM TN-ZA
TR-TR TT-RU UG-CN UK-UA UR-PK VI-VN WO-SN XH-ZA YO-NG ZH-CN ZH-HK ZH-MO ZH-SG ZH-TW ZU-ZA AZ-CYRL-AZ AZ-LATN-AZ BS-CYRL-BA
BS-LATN-BA HA-LATN-NG IU-CANS-CA IU-LATN-CA MN-MONG-CN SR-CYRL-BA SR-CYRL-CS SR-CYRL-ME SR-CYRL-RS SR-LATN-BA SR-LATN-CS
SR-LATN-ME SR-LATN-RS TG-CYRL-TJ TZM-LATN-DZ UZ-CYRL-UZ UZ-LATN-UZ"""
LOCALES = {x.casefold() for x in _LOCALES.split()}
LEGAL_SUFFIXES = {x.casefold() for x in """AB AD AG APS AS ASA BV CO CV DOO eV GES GESMBH GMBH INC KG KS PS LLC LP LTD LTDA MBH
NV PLC SL PTY PVT SA SARL SC SCA SL SP SPA SRL SRO COMPANY CORP CORPORATION HOLDING HOLDINGS INCORPORATED LIMITED
SUBSIDIARY""".split()}


def _prepare(value: str) -> str:
    v = unicodedata.normalize("NFKC", value or "").strip()
    at = v.find("@@", 3)
    return v[:at] if at != -1 else v


def _unwrap(v: str) -> tuple[str, bool]:
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "(" and v[-1] == ")")):
        return v[1:-1], True
    return v, False


def _remove(rx, v: str) -> tuple[str, bool]:
    out = rx.sub("", v)
    return out, out != v


def _remove_all(regexes, v: str) -> tuple[str, bool]:
    changed = False
    for rx in regexes:
        v, c = _remove(rx, v)
        changed = changed or c
    return v, changed


def _for_each(rx, v: str):
    """(is_match, text) pieces, like winget's Regex::Expression::ForEach."""
    pos = 0
    for m in rx.finditer(v):
        if m.start() > pos:
            yield False, v[pos:m.start()]
        yield True, m.group(0)
        pos = m.end()
    if len(v) > pos:
        yield False, v[pos:]


def _split(rx, v: str, stop_on_exclusion: bool = False) -> list[str]:
    out = []
    for _, text in _for_each(rx, v):
        if not text.strip():
            continue
        if out and text.casefold() in LEGAL_SUFFIXES:
            if stop_on_exclusion:
                break
            continue
        out.append(text)
    return out


def _remove_arch(v: str) -> str:
    for group in ((ARCH_32OR64,), (ARCH_X64, ARCH_64BIT), (ARCH_X32, ARCH_32BIT), (ARCH_ARM64,), (ARCH_ARM,)):
        for rx in group:
            v, hit = _remove(rx, v)
            if hit:
                return v
    return v


def _remove_locale(v: str) -> str:
    return "".join(text for is_match, text in _for_each(LOCALE, v) if not (is_match and text.casefold() in LOCALES))


def normalize_name(name: str) -> str:
    v = _prepare(name)
    while True:
        v, more = _unwrap(v)
        if not more:
            break
    if SAP_PACKAGE.search(v):
        return v
    v = _remove_locale(_remove_arch(v))
    v = KB_NUMBERS.sub(r"\1", v)
    while True:
        v, more = _remove_all(PROGRAM_NAME_REGEXES, v)
        if not more:
            break
    return NON_LETTERS_AND_DIGITS.sub("", "".join(_split(PROGRAM_NAME_SPLIT, v)))


def normalize_publisher(publisher: str) -> str:
    v = _prepare(publisher)
    while True:
        v, more = _unwrap(v)
        if not more:
            break
    while True:
        v, more = _remove_all(PUBLISHER_NAME_REGEXES, v)
        if not more:
            break
    return NON_LETTERS_AND_DIGITS.sub("", "".join(_split(PUBLISHER_NAME_SPLIT, v, True)))


# -- versions, as winget compares them ---------------------------------------------------------
def _parts(v: str) -> list[tuple[int, str]]:
    v = (v or "").strip()
    digit = next((i for i, c in enumerate(v) if c.isdigit() and c.isascii()), -1)
    dot = v.find(".")
    if digit != -1 and (dot == -1 or digit < dot):
        v = v[digit:]
    parts = []
    for p in v.split(".") if v else []:
        p = p.strip()
        n = 0
        i = 0
        while i < len(p) and p[i].isdigit() and p[i].isascii():
            i += 1
        if i:
            n = int(p[:i])
        parts.append((n, p[i:] if i < len(p) else ""))
    while parts and parts[-1] == (0, ""):
        parts.pop()
    return parts


def _part_lt(a: tuple[int, str], b: tuple[int, str]) -> bool:
    if a[0] != b[0]:
        return a[0] < b[0]
    if not a[1]:
        return False
    if not b[1]:
        return True
    return a[1].casefold() < b[1].casefold()


def version_lt(a: str, b: str) -> bool:
    """a is older than b, as winget sees it ("Unknown" sorts lowest, "Latest" highest)."""
    def special(v):
        f = (v or "").strip().casefold()
        return 2 if f == "latest" else 0 if f in ("", "unknown") else 1
    sa, sb = special(a), special(b)
    if sa != sb:
        return sa < sb
    if sa != 1:
        return False
    pa, pb = _parts(a), _parts(b)
    for i in range(max(len(pa), len(pb))):
        x, y = (pa[i] if i < len(pa) else (0, "")), (pb[i] if i < len(pb) else (0, ""))
        if _part_lt(x, y):
            return True
        if _part_lt(y, x):
            return False
    return False


# -- the index ------------------------------------------------------------------------------------
class Index:
    """The winget catalogue's packages, with lookups by product code and by normalised name + publisher."""

    def __init__(self, db_bytes: bytes):
        con = sqlite3.connect(":memory:")
        con.deserialize(db_bytes)
        self.packages = {}  # rowid -> (id, name, latest_version, arp_min, arp_max)
        for rid, pid, name, latest, amin, amax in con.execute(
                "SELECT rowid, id, name, latest_version, arp_min_version, arp_max_version FROM packages"):
            self.packages[rid] = (pid, name, latest, amin or "", amax or "")
        self.by_code = self._map(con, "productcodes2", "productcode")
        names = self._map(con, "norm_names2", "norm_name")
        pubs = self._map(con, "norm_publishers2", "norm_publisher")
        self.by_name_pub = {}
        pub_of = {}
        for p, rows in pubs.items():
            for r in rows:
                pub_of.setdefault(r, set()).add(p)
        for n, rows in names.items():
            for r in rows:
                for p in pub_of.get(r, ()):
                    self.by_name_pub.setdefault((n, p), set()).add(r)
        con.close()

    @staticmethod
    def _map(con, table: str, col: str) -> dict:
        out: dict = {}
        for value, pkg in con.execute(f"SELECT t.{col}, m.package FROM {table} t JOIN {table}_map m ON m.{col} = t.rowid"):
            out.setdefault(str(value).casefold(), set()).add(pkg)
        return out

    @classmethod
    def from_msix(cls, data: bytes) -> "Index":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            name = next((n for n in z.namelist() if n.lower().endswith("index.db")), None)
            if not name:
                raise ValueError("no index.db in the winget catalogue")
            return cls(z.read(name))

    def match(self, app: dict) -> tuple | None:
        """The catalogue package for an installed program, or None. Only a single, clear match counts."""
        code = str(app.get("code") or "").strip().casefold()
        rows = self.by_code.get(code) if code else None
        if not rows:
            n = normalize_name(str(app.get("name") or "").casefold())
            p = normalize_publisher(str(app.get("publisher") or "").casefold())
            rows = self.by_name_pub.get((n, p)) if n and p else None
        if not rows or len(rows) != 1:
            return None
        return self.packages.get(next(iter(rows)))

    def newer(self, app: dict) -> dict | None:
        """{"id", "version"} when the catalogue has a newer version than the one installed."""
        pkg = self.match(app)
        if not pkg:
            return None
        pid, _name, latest, _amin, amax = pkg
        have = str(app.get("version") or "")
        if not have or not latest:
            return None
        # The latest version's Apps & features version, when the catalogue knows it (e.g. 24.08 for 7-Zip "24.08").
        target = amax or latest
        if version_lt(have, target):
            return {"id": pid, "version": latest}
        return None
