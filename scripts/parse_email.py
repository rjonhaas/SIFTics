#!/usr/bin/env python3
"""
parse_email.py — SIFTics Phase 14 email artifact parser

Usage:
    python3 parse_email.py <mbox_dir> <machine> <username> <msg_csv> <att_csv> <attach_dir>

Parses all .mbox files produced by readpst, writing:
  - msg_csv   : one row per message (date, from/to/cc/subject, body preview, IOCs)
  - att_csv   : one row per attachment (saved to attach_dir, SHA-256 hashed)
"""

import sys
import os
import csv
import re
import hashlib
import base64
import mailbox
import glob
from email.header import decode_header as _decode_header
from email.utils import parsedate_to_datetime
from datetime import timezone

# IOC extraction patterns
URL_RE = re.compile(r'https?://[^\s<>"\')\]]+')
IP_RE  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
# DMS coordinates with common Unicode variants (°, ', ")
COORD_RE = re.compile(
    r'\d{1,3}\s*[°°]\s*\d{1,2}\s*[\'`‘’′]\s*'
    r'\d{1,2}(?:\.\d+)?\s*["“”″′’]?\s*[NSns]'
    r'[,\s]+'
    r'\d{1,3}\s*[°°]\s*\d{1,2}\s*[\'`‘’′]\s*'
    r'\d{1,2}(?:\.\d+)?\s*["“”″′’]?\s*[EWew]'
)
# Standalone base64 token: ≥20 chars of base64 alphabet, not embedded in URLs/paths
B64_TOKEN_RE = re.compile(
    r'(?<![A-Za-z0-9+/=@\-_.:/])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=@\-_.:/])'
)

_PRIVATE_IP_RE = re.compile(
    r'^(127\.|0\.|255\.|10\.|192\.168\.|'
    r'172\.(1[6-9]|2[0-9]|3[01])\.)'
)


def decode_hdr(h):
    if not h:
        return ''
    parts = _decode_header(h)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            decoded.append(str(part))
    return ' '.join(decoded).strip()


def clean_html(html):
    html = re.sub(r'<style[^>]*>.*?</style>', ' ', html,
                  flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<script[^>]*>.*?</script>', ' ', html,
                  flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<[^>]+>', ' ', html)
    html = (html.replace('&nbsp;', ' ').replace('&amp;', '&')
                .replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"'))
    return re.sub(r'\s+', ' ', html).strip()


def get_body(msg):
    plain = ''
    html  = ''
    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get('Content-Disposition', ''))
            if 'attachment' in disp:
                continue
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                cs   = part.get_content_charset() or 'utf-8'
                text = payload.decode(cs, errors='replace')
                if ct == 'text/plain' and not plain:
                    plain = text
                elif ct == 'text/html' and not html:
                    html = clean_html(text)
            except Exception:
                pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                cs   = msg.get_content_charset() or 'utf-8'
                text = payload.decode(cs, errors='replace')
                if msg.get_content_type() == 'text/html':
                    html = clean_html(text)
                else:
                    plain = text
        except Exception:
            pass
    body = plain.strip() if plain.strip() else html.strip()
    return body


def get_attachments(msg):
    attachments = []
    for part in msg.walk():
        disp = str(part.get('Content-Disposition', ''))
        if 'attachment' in disp:
            fn = decode_hdr(part.get_filename('') or '')
            if not fn:
                fn = f'attachment_{len(attachments)}'
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    attachments.append((fn, payload))
            except Exception:
                pass
    return attachments


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def parse_date_utc(msg):
    date_str = msg.get('Date', '')
    if not date_str:
        return ''
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        return date_str.strip()


def detect_base64_flags(body):
    tokens   = B64_TOKEN_RE.findall(body)
    findings = []
    seen     = set()
    for tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        try:
            padded  = tok + '=' * (-len(tok) % 4)
            decoded = base64.b64decode(padded)
            text    = decoded.decode('utf-8', errors='replace')
            if text.isprintable() and len(text) >= 6 and not text.isspace():
                findings.append(f'{tok}→{text[:50]}')
        except Exception:
            pass
        if len(findings) >= 5:
            break
    return ' | '.join(findings)


def extract_iocs(body):
    urls   = list(dict.fromkeys(URL_RE.findall(body)))[:10]
    ips    = [ip for ip in dict.fromkeys(IP_RE.findall(body))
              if not _PRIVATE_IP_RE.match(ip)][:5]
    coords = list(dict.fromkeys(COORD_RE.findall(body)))[:3]
    b64    = detect_base64_flags(body)
    return ';'.join(urls), ';'.join(ips), ';'.join(coords), b64


def main():
    if len(sys.argv) < 7:
        print(f'Usage: {sys.argv[0]} <mbox_dir> <machine> <username> '
              f'<msg_csv> <att_csv> <attach_dir>', file=sys.stderr)
        sys.exit(1)

    mbox_dir   = sys.argv[1]
    machine    = sys.argv[2]
    username   = sys.argv[3]
    msg_csv    = sys.argv[4]
    att_csv    = sys.argv[5]
    attach_dir = sys.argv[6]

    os.makedirs(attach_dir, exist_ok=True)

    msg_rows = 0
    att_rows = 0

    with open(msg_csv, 'w', newline='', encoding='utf-8') as msg_fh, \
         open(att_csv, 'w', newline='', encoding='utf-8') as att_fh:

        msg_writer = csv.writer(msg_fh)
        att_writer = csv.writer(att_fh)

        msg_writer.writerow([
            'Machine', 'Username', 'FolderName', 'MessageDate_UTC',
            'From', 'To', 'CC', 'Subject',
            'BodyPreview', 'AttachmentNames',
            'EmbeddedURLs', 'EmbeddedIPs', 'EmbeddedCoords', 'Base64Flags',
        ])
        att_writer.writerow([
            'Machine', 'Username', 'FolderName', 'MessageDate_UTC',
            'From', 'Subject', 'AttachmentName', 'SavedPath',
            'FileSizeBytes', 'SHA256',
        ])

        for mbox_path in sorted(glob.glob(os.path.join(mbox_dir, '*.mbox'))):
            folder_name = os.path.basename(mbox_path)[:-5]
            try:
                mbox = mailbox.mbox(mbox_path)
            except Exception as e:
                print(f'WARNING: could not open {mbox_path}: {e}', file=sys.stderr)
                continue

            for msg in mbox:
                date_utc = parse_date_utc(msg)
                frm      = decode_hdr(msg.get('From', ''))
                to       = decode_hdr(msg.get('To', ''))
                cc       = decode_hdr(msg.get('CC', '') or msg.get('Cc', ''))
                subject  = decode_hdr(msg.get('Subject', ''))
                body     = get_body(msg)
                preview  = body[:500]

                urls, ips, coords, b64 = extract_iocs(body)

                attachments = get_attachments(msg)
                att_names   = '; '.join(fn for fn, _ in attachments)

                msg_writer.writerow([
                    machine, username, folder_name, date_utc,
                    frm, to, cc, subject,
                    preview, att_names,
                    urls, ips, coords, b64,
                ])
                msg_rows += 1

                date_prefix = (date_utc.replace(':', '').replace('-', '')[:15]
                               if date_utc else 'unknown')
                for fn, data in attachments:
                    safe_fn   = re.sub(r'[^\w.\-]', '_', fn)
                    save_path = os.path.join(attach_dir, f'{date_prefix}_{safe_fn}')
                    counter   = 0
                    orig_path = save_path
                    while os.path.exists(save_path):
                        counter  += 1
                        base, ext = os.path.splitext(orig_path)
                        save_path = f'{base}_{counter}{ext}'
                    try:
                        with open(save_path, 'wb') as f:
                            f.write(data)
                        sha = sha256_bytes(data)
                    except Exception as e:
                        save_path = f'ERROR: {e}'
                        sha = ''

                    att_writer.writerow([
                        machine, username, folder_name, date_utc,
                        frm, subject, fn, save_path,
                        len(data), sha,
                    ])
                    att_rows += 1

    print(f'{msg_rows},{att_rows}')


if __name__ == '__main__':
    main()
