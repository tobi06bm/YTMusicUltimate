#!/usr/bin/env python3
"""Inspicér HLS/DASH-manifester og hent ukrypterede spor.

Værktøjet viser hvilke video-, lyd- og undertekststreams et manifest peger på,
og markerer spor der er DRM-/krypterede. Det henter KUN ukrypterede spor
(typisk undertekster og evt. åbne streams). Det udtrækker ikke nøgler og
dekrypterer ikke noget.

Kommandoer:
  har       <fil.har>          list manifest-URL'er fundet i en HAR-fil
  inspect   <url|fil>          vis spor (video/lyd/undertekst) og DRM-status
  download  <url|fil>          hent ukrypterede spor

Kun standardbibliotek. Brug --header "Navn: værdi" til cookies/tokens fra din
egen session.
"""
import argparse
import json
import math
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

DRM_UUIDS = {
    "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed": "Widevine",
    "9a04f079-9840-4286-ab92-e65be0885f95": "PlayReady",
    "94ce86fb-07ff-4f43-adb8-93d2fa968ca2": "FairPlay",
    "e2719d58-a985-b3c9-781a-b030af78d30e": "ClearKey",
}


@dataclass
class Track:
    id: str
    kind: str  # video | audio | subtitle
    protocol: str  # dash | hls
    codecs: str = ""
    bandwidth: int = 0
    width: int = 0
    height: int = 0
    lang: str = ""
    mime: str = ""
    drm: list = field(default_factory=list)  # tom liste = ukrypteret
    init: str = ""
    segments: list = field(default_factory=list)

    @property
    def encrypted(self):
        return bool(self.drm)

    def describe(self):
        bits = [f"{self.kind:<8}", f"id={self.id}"]
        if self.width:
            bits.append(f"{self.width}x{self.height}")
        if self.codecs:
            bits.append(self.codecs)
        if self.bandwidth:
            bits.append(f"{self.bandwidth // 1000} kbps")
        if self.lang:
            bits.append(f"lang={self.lang}")
        bits.append("KRYPTERET(" + ",".join(self.drm) + ")" if self.drm else "ukrypteret")
        n = len(self.segments) + (1 if self.init else 0)
        if n:
            bits.append(f"{n} filer")
        return "  ".join(bits)


# ---------- netværk ----------

def fetch(src, headers=None):
    if not re.match(r"^https?://", src):
        with open(src, "rb") as f:
            return f.read()
    req = urllib.request.Request(src, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def join(base, ref):
    return urllib.parse.urljoin(base, ref) if re.match(r"^https?://", base) else ref


# ---------- DASH ----------

def _strip_ns(root):
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = el.tag.split("}")[-1]
    return root


def _iso_duration(s):
    m = re.match(r"^P(?:(\d+)D)?T?(?:(\d+)H)?(?:(\d+)M)?(?:([\d.]+)S)?$", s or "")
    if not m:
        return 0.0
    d, h, mi, sec = (float(x) if x else 0.0 for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + sec


def _drm_systems(el):
    out = []
    for cp in el.findall("ContentProtection"):
        uri = (cp.get("schemeIdUri") or "").lower()
        name = None
        for u, n in DRM_UUIDS.items():
            if u in uri:
                name = n
        if name is None and "mp4protection" in uri:
            name = "CENC"
        if name and name not in out:
            out.append(name)
    return out


def _tmpl(s, rep_id, bw, number=None, time=None):
    s = s.replace("$RepresentationID$", rep_id).replace("$Bandwidth$", str(bw))

    def sub(name, val):
        nonlocal s
        if val is None:
            return
        s = re.sub(r"\$%s(?:%%0(\d+)d)?\$" % name,
                   lambda m: str(val).zfill(int(m.group(1) or 0)), s)
    sub("Number", number)
    sub("Time", time)
    return s


def parse_dash(data, base):
    root = _strip_ns(ET.fromstring(data))
    total = _iso_duration(root.get("mediaPresentationDuration"))
    tracks = []
    root_base = (root.findtext("BaseURL") or "").strip()
    for period in root.findall("Period"):
        pdur = _iso_duration(period.get("duration")) or total
        pbase = join(join(base, root_base), (period.findtext("BaseURL") or "").strip())
        for aset in period.findall("AdaptationSet"):
            abase = join(pbase, (aset.findtext("BaseURL") or "").strip())
            a_drm = _drm_systems(aset)
            for rep in aset.findall("Representation"):
                mime = rep.get("mimeType") or aset.get("mimeType") or ""
                ctype = aset.get("contentType") or mime.split("/")[0]
                kind = {"video": "video", "audio": "audio"}.get(ctype, "subtitle")
                rid = rep.get("id") or str(len(tracks))
                bw = int(rep.get("bandwidth") or 0)
                t = Track(
                    id=rid, kind=kind, protocol="dash", mime=mime, bandwidth=bw,
                    codecs=rep.get("codecs") or aset.get("codecs") or "",
                    width=int(rep.get("width") or aset.get("width") or 0),
                    height=int(rep.get("height") or aset.get("height") or 0),
                    lang=aset.get("lang") or rep.get("lang") or "",
                    drm=_drm_systems(rep) or a_drm,
                )
                rbase = join(abase, (rep.findtext("BaseURL") or "").strip())
                st = rep.find("SegmentTemplate")
                if st is None:
                    st = aset.find("SegmentTemplate")
                sl = rep.find("SegmentList")
                if st is not None:
                    _dash_template(t, st, rbase, rid, bw, pdur)
                elif sl is not None:
                    ini = sl.find("Initialization")
                    if ini is not None:
                        t.init = join(rbase, ini.get("sourceURL", ""))
                    t.segments = [join(rbase, s.get("media", "")) for s in sl.findall("SegmentURL")]
                else:
                    t.segments = [rbase]  # enkelt fil via BaseURL
                tracks.append(t)
    return tracks


def _dash_template(t, st, base, rid, bw, period_dur):
    ts = int(st.get("timescale") or 1)
    start = int(st.get("startNumber") or 1)
    if st.get("initialization"):
        t.init = join(base, _tmpl(st.get("initialization"), rid, bw))
    media = st.get("media") or ""
    tl = st.find("SegmentTimeline")
    if tl is not None:
        number, time = start, 0
        for s in tl.findall("S"):
            time = int(s.get("t")) if s.get("t") else time
            d = int(s.get("d"))
            for _ in range(int(s.get("r") or 0) + 1):
                t.segments.append(join(base, _tmpl(media, rid, bw, number, time)))
                number += 1
                time += d
    else:
        d = int(st.get("duration") or 0)
        if d and period_dur:
            count = math.ceil(period_dur * ts / d)
            t.segments = [join(base, _tmpl(media, rid, bw, start + i, i * d)) for i in range(count)]


# ---------- HLS ----------

_ATTR = re.compile(r'([A-Z0-9-]+)=("[^"]*"|[^,]*)')


def _attrs(line):
    return {k: v.strip('"') for k, v in _ATTR.findall(line.split(":", 1)[1])}


def parse_hls(text, base, headers=None, deep=True):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not any(l.startswith("#EXT-X-STREAM-INF") or l.startswith("#EXT-X-MEDIA:") for l in lines):
        t = Track(id="0", kind="video", protocol="hls")
        _hls_media(t, text, base)
        return [t]
    tracks = []
    for i, l in enumerate(lines):
        if l.startswith("#EXT-X-MEDIA:"):
            a = _attrs(l)
            kind = {"AUDIO": "audio", "SUBTITLES": "subtitle"}.get(a.get("TYPE"))
            if not kind or not a.get("URI"):
                continue
            t = Track(id=a.get("GROUP-ID", "") + ":" + a.get("NAME", str(i)), kind=kind,
                      protocol="hls", lang=a.get("LANGUAGE", ""))
            _hls_load(t, join(base, a["URI"]), headers, deep)
            tracks.append(t)
        elif l.startswith("#EXT-X-STREAM-INF"):
            a = _attrs(l)
            w, _, h = a.get("RESOLUTION", "0x0").partition("x")
            t = Track(id=str(i), kind="video", protocol="hls", codecs=a.get("CODECS", ""),
                      bandwidth=int(a.get("BANDWIDTH", 0)), width=int(w), height=int(h or 0))
            _hls_load(t, join(base, lines[i + 1]), headers, deep)
            tracks.append(t)
    return tracks


def _hls_load(t, url, headers, deep):
    if not deep:
        return
    try:
        _hls_media(t, fetch(url, headers).decode("utf-8", "replace"), url)
    except Exception as e:  # netværk/parsing: spor vises stadig uden segmentliste
        print(f"  (kunne ikke hente {url}: {e})", file=sys.stderr)


def _hls_media(t, text, base):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for l in lines:
        if l.startswith("#EXT-X-KEY"):
            a = _attrs(l)
            if a.get("METHOD", "NONE") != "NONE":
                fmt = a.get("KEYFORMAT", "")
                name = next((n for u, n in DRM_UUIDS.items() if u in fmt.lower()), a["METHOD"])
                if name not in t.drm:
                    t.drm.append(name)
        elif l.startswith("#EXT-X-MAP"):
            t.init = join(base, _attrs(l)["URI"])
    t.segments = [join(base, l) for l in lines if not l.startswith("#")]


# ---------- fælles ----------

def load_tracks(src, headers, deep=True):
    data = fetch(src, headers)
    head = data[:2000].lstrip()
    if head.startswith(b"#EXTM3U"):
        return parse_hls(data.decode("utf-8", "replace"), src, headers, deep)
    if b"<MPD" in data[:4000]:
        return parse_dash(data, src)
    raise SystemExit("Ukendt format: hverken HLS (.m3u8) eller DASH (.mpd).")


def parse_headers(items):
    h = {}
    for it in items or []:
        k, _, v = it.partition(":")
        h[k.strip()] = v.strip()
    return h


def cmd_har(args):
    with open(args.file, encoding="utf-8") as f:
        har = json.load(f)
    seen = set()
    for e in har["log"]["entries"]:
        url = e["request"]["url"]
        if re.search(r"\.(m3u8|mpd)(\?|$)", url) and url not in seen:
            seen.add(url)
            print(url)
    if not seen:
        print("Ingen .m3u8/.mpd-URL'er fundet.", file=sys.stderr)


def cmd_inspect(args):
    tracks = load_tracks(args.source, parse_headers(args.header))
    if args.json:
        print(json.dumps([t.__dict__ for t in tracks], indent=2, ensure_ascii=False))
        return
    for t in tracks:
        print(t.describe())
    enc = sum(t.encrypted for t in tracks)
    print(f"\n{len(tracks)} spor, {enc} krypterede (kan ikke hentes med dette værktøj).")


def _ext(t):
    if t.kind == "subtitle":
        return ".ttml" if "ttml" in t.mime or "xml" in t.mime else ".vtt" if t.protocol == "hls" or "vtt" in t.mime else ".sub"
    if t.init or "mp4" in t.mime:
        return ".m4a" if t.kind == "audio" else ".mp4"
    return ".ts"


def cmd_download(args):
    headers = parse_headers(args.header)
    tracks = load_tracks(args.source, headers)
    os.makedirs(args.out, exist_ok=True)
    wanted = set(args.track or [])
    for t in tracks:
        if wanted and t.id not in wanted:
            continue
        if args.kind and t.kind not in args.kind:
            continue
        if t.encrypted:
            print(f"Springer over {t.kind} {t.id}: krypteret ({', '.join(t.drm)})")
            continue
        parts = ([t.init] if t.init else []) + t.segments
        if not parts:
            print(f"Springer over {t.kind} {t.id}: ingen filer fundet")
            continue
        name = re.sub(r"[^\w.-]+", "_", f"{t.kind}_{t.id}_{t.lang}".strip("_")) + _ext(t)
        path = os.path.join(args.out, name)
        print(f"Henter {t.kind} {t.id} ({len(parts)} filer) -> {path}")
        with open(path, "wb") as out:
            for p in parts:
                out.write(fetch(p, headers))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("har"); s.add_argument("file"); s.set_defaults(fn=cmd_har)
    for name, fn in (("inspect", cmd_inspect), ("download", cmd_download)):
        s = sub.add_parser(name)
        s.add_argument("source", help="URL eller lokal manifest-fil")
        s.add_argument("--header", action="append", help='f.eks. "Cookie: ..." (gentagelig)')
        if name == "inspect":
            s.add_argument("--json", action="store_true")
        else:
            s.add_argument("--track", action="append", help="kun dette spor-id (gentagelig)")
            s.add_argument("--kind", action="append", choices=["video", "audio", "subtitle"])
            s.add_argument("--out", default="downloads")
        s.set_defaults(fn=fn)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
