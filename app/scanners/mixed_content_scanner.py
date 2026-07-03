from collections import defaultdict

from app.scanners.base import BaseScanner


RESOURCE_SELECTORS = {
    "images": ("img", "src"),
    "scripts": ("script", "src"),
    "stylesheets": ("link", "href"),
    "iframes": ("iframe", "src"),
    "audio": ("audio", "src"),
    "video": ("video", "src"),
    "sources": ("source", "src"),
    "form actions": ("form", "action"),
}


class MixedContentScanner(BaseScanner):
    category = "Mixed Content"

    def scan(self):
        if not (self.context.final_url or self.context.original_url).startswith("https://"):
            return [self.finding(
                "Mixed content not applicable to HTTP page",
                "info",
                "info",
                "Mixed-content checks apply to HTTPS pages.",
                "Final URL is not HTTPS.",
                "Move the page to HTTPS before reviewing mixed content.",
            )]
        if not self.context.soup:
            return []
        grouped = defaultdict(list)
        for label, (tag_name, attr) in RESOURCE_SELECTORS.items():
            for tag in self.context.soup.find_all(tag_name):
                value = tag.get(attr)
                if value and value.strip().lower().startswith("http://"):
                    grouped[label].append(value.strip())
        if not grouped:
            return [self.finding(
                "No mixed-content references detected",
                "info",
                "passed",
                "The inspected HTML did not reference HTTP resources from common resource tags.",
                "No http:// resource references found.",
                "Keep all images, scripts, styles, media, iframes, and form actions on HTTPS.",
            )]
        findings = []
        for label, urls in grouped.items():
            sample = "; ".join(urls[:5])
            findings.append(self.finding(
                f"Mixed-content {label} detected",
                "medium" if label in {"scripts", "iframes", "form actions"} else "low",
                "warning",
                f"The HTTPS page references {label} over HTTP. Browsers may block active mixed content.",
                sample,
                "Update these references to HTTPS or remove them.",
            ))
        return findings
