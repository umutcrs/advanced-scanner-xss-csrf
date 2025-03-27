"use strict";
Object.defineProperty(n, "__esModule", {
    value: !0
}),
n.COOKIE_ID_MARKETING_WHITELIST_ORIGINS = n.COOKIE_ID_MARKETING_WHITELIST = void 0;
const r = n.COOKIE_ID_MARKETING_WHITELIST = ["https://metamask.io", "https://learn.metamask.io", "https://mmi-support.zendesk.com", "https://community.metamask.io", "https://support.metamask.io"];
n.COOKIE_ID_MARKETING_WHITELIST_ORIGINS = r.map((e => new URL(e).origin))
