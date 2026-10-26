
import email
import html
import re
from email.header import decode_header
from urllib.parse import urlparse, urlunparse

import tiktoken
from bs4 import BeautifulSoup, Comment


class EmailProcessor:
    def __init__(self, token_limit=3500):
        self.token_limit = token_limit
        self.headers = ""
        self.bodies = []

    class ReportMessageException(Exception):
        pass

    def get_email_text(self):
        return self.headers + "".join([body for body, _ in self.bodies])

    def count_token(self, text):
        try:
            enc = tiktoken.encoding_for_model("gpt-4")
        except KeyError:
            enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))

    def _clean_header_value(self, value):
        decoded = decode_header(value)
        if decoded[0][1] == "unknown-8bit":
            try:
                value = decoded[0][0].decode("utf-8")
            except UnicodeDecodeError:
                value = decoded[0][0].decode("latin-1")
        elif decoded[0][1] is not None:
            value = decoded[0][0].decode(decoded[0][1], errors="replace")
        if isinstance(value, email.header.Header):
            return decode_header(value.encode())[0][0].decode("utf-8")
        return re.sub(r"[\r\n]+", "", value)

    def _process_header(self, msg):
        ignore = {"arc-seal", "arc-message-signature", "dkim-signature"}
        lines = []
        for key, value in msg.items():
            if key.lower() in ignore or key.lower().startswith("x"):
                continue
            cleaned = self._clean_header_value(value)
            cleaned = re.sub(r"\[SPAM\] ?", "", cleaned, flags=re.IGNORECASE)
            lines.append(f"{key}: {cleaned}")
        return "\n".join(lines)

    def _shorten_url(self, url, max_len=20):
        p = urlparse(url)
        path = p.path[:max_len]
        query = p.query[: max(0, max_len - len(path))]
        return urlunparse((p.scheme, p.netloc, path, p.params, query, p.fragment))

    def _clean_html(self, raw_html):
        soup = BeautifulSoup(raw_html, "html.parser")
        for tag in soup(["script", "style"]):
            tag.decompose()
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            c.extract()
        for tag in soup.find_all(True):
            if tag.name != "meta":
                for attr in list(tag.attrs):
                    if attr not in ["src", "href", "alt", "title", "name", "id", "class"]:
                        del tag[attr]
        for tag in soup.find_all():
            if tag.name not in ("meta", "img", "a", "input") and tag.text.strip() == "":
                tag.decompose()
        for name in ["font", "strong", "b"]:
            for tag in soup.find_all(name):
                tag.unwrap() if tag.text.strip() else tag.decompose()
        for br in soup.find_all("br"):
            br.decompose()
        for img in soup.find_all("img"):
            src = img.get("src", "")
            if src.startswith("data:image"):
                img["src"] = src[:10]
            elif len(src) > 30:
                img["src"] = self._shorten_url(src, 30)
        for a in soup.find_all("a"):
            href = a.get("href", "")
            if len(href) > 30:
                a["href"] = self._shorten_url(href, 30)
        return soup.prettify()

    def _remove_breaks(self, text):
        text = re.sub(r"\n+", "\n", text)
        text = re.sub(r"\t+", "\t", text)
        text = re.sub(r" +", " ", text)
        text = re.sub(r"[\r\n]+", "\n", text)
        text = re.sub(r"\n ", " ", text)
        text = re.sub(r"> <", "><", text)
        text = re.sub(r" <", "<", text)
        text = re.sub(r"> ", ">", text)
        text = re.sub(r"‌| ", "", text)
        text = re.sub(r" \n", "\n", text)
        return text

    def _process_body(self, part):
        content_type = part.get_content_type()
        charset = part.get_content_charset() or "utf-8"
        if charset == "windows-1252":
            charset = "cp1252"
        else:
            try:
                "".encode(charset)
            except LookupError:
                charset = "utf-8"

        if part.get("Content-Transfer-Encoding") is not None:
            raw = part.get_payload(decode=True)
            if raw is None:
                body = part.get_payload() or ""
                if isinstance(body, list):
                    body = ""
            else:
                try:
                    body = raw.decode(charset)
                except UnicodeDecodeError:
                    body = raw.decode("latin-1")
            body = html.unescape(body)
        else:
            body = part.get_payload()
            if isinstance(body, list):
                body = ""

        if content_type == "text/html" and self.count_token(body) > 1000:
            body = self._clean_html(body)
        elif content_type == "text/plain":
            body = re.sub(r"[ \t]+", " ", body)
            body = re.sub(r"\n{3,}", "\n\n", body)

        return self._remove_breaks(body), content_type

    def _shorten_html(self, html_text, idx):
        soup = BeautifulSoup(html_text, "html.parser")
        while self.token_limit > 0 and self.count_token(self.get_email_text()) > self.token_limit:
            elements = soup.find_all(lambda t: t.name != "a")
            if len(elements) <= 2:
                text = self._remove_breaks(soup.get_text())
                self.bodies[idx] = (text, self.bodies[idx][1])
                self._shorten_text(text, idx)
                return
            elements[len(elements) // 2].decompose()
            self.bodies[idx] = (self._remove_breaks(soup.prettify()), self.bodies[idx][1])

    def _shorten_text(self, text, idx):
        while self.token_limit > 0 and self.count_token(self.get_email_text()) > self.token_limit:
            lines = text.splitlines()
            if len(lines) <= 2:
                break
            del lines[len(lines) // 2]
            text = "\n".join(lines)
            self.bodies[idx] = (text, self.bodies[idx][1])
        return text

    def process_email(self, eml_path):
        with open(eml_path, "rb") as f:
            msg = email.message_from_bytes(f.read())

        self.headers = self._process_header(msg) + "\n"
        self.bodies = []

        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                if part.get_content_type() == "application/pgp-signature":
                    continue
                chunk = f"\n--{msg.get_boundary()}\nContent-Type: {part.get_content_type()}\n"
                if part.get_filename():
                    chunk += f"Content-Disposition: {part.get('Content-Disposition')}\nname: {part.get_filename()}\n"
                    self.bodies.append((chunk, part.get_content_type()))
                else:
                    body, ct = self._process_body(part)
                    self.bodies.append((chunk + body + "\n", ct))
        else:
            body, ct = self._process_body(msg)
            self.bodies.append(("\n" + body, ct))

        # Truncate if over token limit (skip if token_limit is 0)
        if self.token_limit > 0 and self.count_token(self.get_email_text()) > self.token_limit:
            content_types = [ct for _, ct in self.bodies]
            if "text/html" in content_types:
                self.bodies = [(b, ct) for b, ct in self.bodies if ct != "text/plain"]
            elif content_types.count("text/plain") > 1:
                self.bodies = [(b, ct) for b, ct in self.bodies if ct == "text/plain"][:1]

            for i, (body, ct) in enumerate(self.bodies):
                if ct == "text/html":
                    self._shorten_html(body, i)
                elif ct == "text/plain":
                    self._shorten_text(body, i)

        return self.headers, self.bodies
