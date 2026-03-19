"""Same-origin HTML crawler that extracts links and forms into request templates."""

from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from fuzzer.models import RequestTemplate
from fuzzer.utils import normalize_path, query_params_from_url, template_key


class WebCrawler:
    """Simple crawler for discovering request templates from a web app."""

    def __init__(self, session: requests.Session, timeout: float = 2.0) -> None:
        self.session = session
        self.timeout = timeout

    def crawl(
        self,
        base_url: str,
        start_path: str = "/",
        max_depth: int = 2,
        max_pages: int = 30,
    ) -> list[RequestTemplate]:
        parsed_base = urlparse(base_url)
        origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        queue: deque[tuple[str, int]] = deque([(urljoin(origin, start_path), 0)])
        visited_pages: set[str] = set()
        templates: list[RequestTemplate] = []
        seen_templates: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

        while queue and len(visited_pages) < max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited_pages or depth > max_depth:
                continue
            visited_pages.add(current_url)

            try:
                response = self.session.get(current_url, timeout=self.timeout)
            except requests.RequestException:
                continue

            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower() and "<html" not in response.text.lower():
                continue

            soup = BeautifulSoup(response.text, "lxml")

            current_qs = query_params_from_url(current_url)
            if current_qs:
                parsed_current = urlparse(current_url)
                template = RequestTemplate(
                    method="GET",
                    path=normalize_path(parsed_current.path),
                    params=current_qs,
                    source="link-query",
                    input_names=sorted(current_qs.keys()),
                )
                key = template_key(template.method, template.path, template.params)
                if key not in seen_templates:
                    seen_templates.add(key)
                    templates.append(template)

            for link in soup.find_all("a", href=True):
                href = link.get("href", "").strip()
                if not href:
                    continue
                absolute = urljoin(current_url, href)
                parsed_link = urlparse(absolute)
                if parsed_link.scheme not in {"http", "https"}:
                    continue
                if parsed_link.netloc != parsed_base.netloc:
                    continue

                normalized_url = f"{parsed_link.scheme}://{parsed_link.netloc}{normalize_path(parsed_link.path)}"
                if parsed_link.query:
                    qparams = query_params_from_url(absolute)
                    template = RequestTemplate(
                        method="GET",
                        path=normalize_path(parsed_link.path),
                        params=qparams,
                        source="link-query",
                        input_names=sorted(qparams.keys()),
                    )
                    key = template_key(template.method, template.path, template.params)
                    if key not in seen_templates:
                        seen_templates.add(key)
                        templates.append(template)
                queue.append((normalized_url, depth + 1))

            for form in soup.find_all("form"):
                method = form.get("method", "GET").upper()
                action = form.get("action", "")
                target = urljoin(current_url, action)
                parsed_target = urlparse(target)
                if parsed_target.netloc != parsed_base.netloc:
                    continue

                params: dict[str, str] = {}
                for field in form.find_all(["input", "textarea", "select"]):
                    name = field.get("name")
                    if not name:
                        continue
                    value = field.get("value", "")
                    params[name] = value

                template = RequestTemplate(
                    method="POST" if method == "POST" else "GET",
                    path=normalize_path(parsed_target.path),
                    params=params,
                    source="form",
                    input_names=sorted(params.keys()),
                )
                key = template_key(template.method, template.path, template.params)
                if key not in seen_templates:
                    seen_templates.add(key)
                    templates.append(template)

        return templates
