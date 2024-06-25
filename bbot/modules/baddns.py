from baddns.base import get_all_modules
from baddns.lib.loader import load_signatures
from .base import BaseModule

import asyncio
import logging
from bbot.core.logger.logger import include_logger

include_logger(logging.getLogger("baddns"))


class baddns(BaseModule):
    watched_events = ["URL", "URL_UNVERIFIED", "DNS_NAME", "DNS_NAME_UNRESOLVED"]
    produced_events = ["FINDING", "VULNERABILITY"]
    flags = ["active", "safe", "web-basic", "baddns", "cloud-enum", "subdomain-hijack"]
    meta = {
        "description": "Check hosts for domain/subdomain takeovers",
        "created_date": "2024-01-18",
        "author": "@liquidsec",
    }
    options = {"custom_nameservers": [], "only_high_confidence": False}
    options_desc = {
        "custom_nameservers": "Force BadDNS to use a list of custom nameservers",
        "only_high_confidence": "Do not emit low-confidence or generic detections",
    }
    max_event_handlers = 8
    deps_pip = ["baddns~=1.1.789"]

    # We allow distance-1 events in at the module level so we can selectively block them in filter_event
    scope_distance_modifier = 1

    def _incoming_dedup_hash(self, event):
        # Dedupe on the host + first 3 characters of event. Example: whatever.foo.com|DNS. This opens things up for the custom filter_event(), which handles DNS vs URL.
        return hash(f"{event.host}|{event.type[0:3]}")

    def select_modules(self):
        selected_modules = []
        for m in get_all_modules():
            # We don't include the references module in the bbot version, since bbot is already recursively parsing links
            if m.name in ["CNAME", "NS", "MX", "TXT"]:
                selected_modules.append(m)
        return selected_modules

    async def setup(self):
        self.custom_nameservers = self.config.get("custom_nameservers", []) or None
        if self.custom_nameservers:
            self.custom_nameservers = self.helpers.chain_lists(self.custom_nameservers)
        self.only_high_confidence = self.config.get("only_high_confidence", False)
        self.signatures = load_signatures()
        return True

    async def handle_event(self, event):

        tasks = []
        for ModuleClass in self.select_modules():
            module_instance = ModuleClass(
                event.host,
                http_client_class=self.scan.helpers.web.AsyncClient,
                dns_client=self.scan.helpers.dns.resolver,
                custom_nameservers=self.custom_nameservers,
                signatures=self.signatures,
            )
            tasks.append((module_instance, asyncio.create_task(module_instance.dispatch())))

        for module_instance, task in tasks:
            if await task:
                results = module_instance.analyze()
                if results and len(results) > 0:
                    for r in results:
                        r_dict = r.to_dict()

                        if r_dict["confidence"] in ["CONFIRMED", "PROBABLE"]:
                            data = {
                                "severity": "MEDIUM",
                                "description": f"{r_dict['description']}. Confidence: [{r_dict['confidence']}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                                "host": str(event.host),
                            }
                            await self.emit_event(
                                data, "VULNERABILITY", event, tags=[f"baddns-{module_instance.name.lower()}"]
                            )

                        elif r_dict["confidence"] in ["UNLIKELY", "POSSIBLE"] and not self.only_high_confidence:
                            data = {
                                "description": f"{r_dict['description']} Confidence: [{r_dict['confidence']}] Signature: [{r_dict['signature']}] Indicator: [{r_dict['indicator']}] Trigger: [{r_dict['trigger']}] baddns Module: [{r_dict['module']}]",
                                "host": str(event.host),
                            }
                            await self.emit_event(
                                data, "FINDING", event, tags=[f"baddns-{module_instance.name.lower()}"]
                            )
                        else:
                            self.warning(f"Got unrecognized confidence level: {r['confidence']}")

                        found_domains = r_dict.get("found_domains", None)
                        if found_domains:
                            for found_domain in found_domains:
                                await self.emit_event(
                                    found_domain, "DNS_NAME", event, tags=[f"baddns-{module_instance.name.lower()}"]
                                )

    # instead of using the baddns references module, we just allow in js/css that comes from distance-1
    async def filter_event(self, event):
        if event.scope_distance == 1:
            # For distance-1, we only care about URL events, and further only those with certain extensions
            return event.type.startswith("URL") and ("extension-js" in event.tags or "extension-css" in event.tags)
        # If its not distance-0, we only care about DNS events
        return not event.type.startswith("URL")
