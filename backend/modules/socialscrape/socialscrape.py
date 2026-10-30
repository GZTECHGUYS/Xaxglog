"""Xaxglog socialscrape — broad, public social-media discovery and scraping.

Purpose
-------
Search a name, handle, hashtag, keyword or public post URL across a large
international platform catalog and the keyless public search engines. The
module also scrapes *public* profile/post pages for OpenGraph, Twitter-card,
schema.org and media metadata, and can attach the normalized result to a case
as hashed evidence.

What it does
------------
  * 180+ platform catalog (global + CN/RU/JP/KR/SEA/VN/TH/ID/NG/LATAM/...)
  * search-link matrix for platforms that only expose a web search UI
  * federated discovery through DuckDuckGo, SearXNG and Mojeek
  * regional public engines: Baidu, Yandex, Weibo, Telegram public preview
  * keyless public APIs: Reddit search, Bluesky search, Lemmy search
  * public-page scraper: title, author, timestamp, hashtags, mentions,
    outbound links, image/video URLs, OpenGraph/Twitter/JSON-LD
  * optional oEmbed for TikTok, X/Twitter, YouTube, Vimeo, SoundCloud, Spotify
  * case evidence attachment (SHA-256 chain of custody)

Lawful use
----------
Public pages and public APIs only. No login walls, no private groups, no
credential attacks, no captcha solving, no anti-bot evasion. A login wall,
captcha, rate limit or private channel is reported as ``blocked`` — never
bypassed. Respect each platform's Terms of Service, robots.txt and rate
limits. Profile/post matches are leads, not identity proof.
"""
import html as _html
import ipaddress
import json
import re
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

import db
from modules.deep_search import social as SOCIAL

UA = {"User-Agent": "Xaxglog-OSINT/2.0 (+public-source research)"}
T = 12
MAX_HTML = 512 * 1024
MAX_REDIRECTS = 4
MAX_IMAGES = 40
MAX_VIDEOS = 20
MAX_LINKS = 80
MAX_TEXT = 50000

_BLOCK_MARKERS = (
    "captcha", "unusual traffic", "verifying your browser", "are you a robot",
    "just a moment", "cf-chl", "challenge-platform", "access denied",
    "request blocked", "client challenge", "enable javascript and cookies",
    "checking your browser", "log in to continue", "sign in to continue",
    "login required", "please log in", "rate limit", "too many requests",
)
_MISSING_MARKERS = (
    "page not found", "profile not found", "user not found",
    "account not found", "this account doesn't exist",
    "this account does not exist", "this page isn't available",
    "this page is not available", "this page doesn't exist",
    "no such user", "couldn't find that page", "couldn't find this account",
)

# ------------------------------------------------------------------ catalog
# Search URLs for the platforms already in deep_search.social.PLATFORMS.
# These are link-outs only: the analyst opens the platform's own search UI.
SEARCH_TEMPLATES = {
    "X/Twitter": "https://x.com/search?q={q}",
    "Instagram": "https://www.instagram.com/web/search/topsearch/?query={q}",
    "Facebook": "https://www.facebook.com/search/top?q={q}",
    "Threads": "https://www.threads.net/search?q={q}",
    "Bluesky": "https://bsky.app/search?q={q}",
    "Mastodon": "https://mastodon.social/search?q={q}",
    "TikTok": "https://www.tiktok.com/search?q={q}",
    "Snapchat": "https://www.snapchat.com/explore/{q}",
    "Pinterest": "https://www.pinterest.com/search/pins/?q={q}",
    "Tumblr": "https://www.tumblr.com/search/{q}",
    "Reddit": "https://www.reddit.com/search/?q={q}",
    "Quora": "https://www.quora.com/search?q={q}",
    "Medium": "https://medium.com/search?q={q}",
    "Substack": "https://substack.com/search/{q}",
    "About.me": "https://about.me/search?q={q}",
    "Keybase": "https://keybase.io/search?q={q}",
    "Telegram": "https://t.me/s/{q}",
    "Gab": "https://gab.com/search?q={q}",
    "Gettr": "https://gettr.com/search?q={q}",
    "Truth Social": "https://truthsocial.com/search?q={q}",
    "VK": "https://vk.com/search?c[q]={q}&c[section]=people",
    "OK.ru": "https://ok.ru/search?st.query={q}",
    "Weibo": "https://s.weibo.com/weibo?q={q}",
    "Douyin": "https://www.douyin.com/search/{q}",
    "Zhihu": "https://www.zhihu.com/search?type=content&q={q}",
    "Douban": "https://www.douban.com/search?q={q}",
    "Bilibili": "https://search.bilibili.com/all?keyword={q}",
    "LinkedIn": "https://www.linkedin.com/search/results/people/?keywords={q}",
    "Fiverr": "https://www.fiverr.com/search/gigs?query={q}",
    "Freelancer": "https://www.freelancer.com/search/users?q={q}",
    "GitHub": "https://github.com/search?q={q}&type=users",
    "GitLab": "https://gitlab.com/search?search={q}",
    "Codeberg": "https://codeberg.org/explore/repos?q={q}",
    "DockerHub": "https://hub.docker.com/search?q={q}",
    "NPM": "https://www.npmjs.com/search?q={q}",
    "PyPI": "https://pypi.org/search/?q={q}",
    "Crates.io": "https://crates.io/search?q={q}",
    "HuggingFace": "https://huggingface.co/search/full-text?q={q}",
    "Replit": "https://replit.com/search?q={q}",
    "Codepen": "https://codepen.io/search/pens?q={q}",
    "Kaggle": "https://www.kaggle.com/search?q={q}",
    "Dev.to": "https://dev.to/search?q={q}",
    "HackerNews": "https://hn.algolia.com/?q={q}",
    "LeetCode": "https://leetcode.com/search/?q={q}",
    "HackerOne": "https://hackerone.com/hacktivity?querystring={q}",
    "Bugcrowd": "https://bugcrowd.com/programs?search={q}",
    "TryHackMe": "https://tryhackme.com/search?q={q}",
    "Exercism": "https://exercism.org/search?q={q}",
    "FreeCodeCamp": "https://www.freecodecamp.org/news/search/?query={q}",
    "Behance": "https://www.behance.net/search/projects?search={q}",
    "Dribbble": "https://dribbble.com/search/{q}",
    "Flickr": "https://www.flickr.com/search/?text={q}",
    "500px": "https://500px.com/search?q={q}",
    "ArtStation": "https://www.artstation.com/search?q={q}",
    "DeviantArt": "https://www.deviantart.com/search?q={q}",
    "Unsplash": "https://unsplash.com/s/photos/{q}",
    "VSCO": "https://vsco.co/search/{q}",
    "Wattpad": "https://www.wattpad.com/search/{q}",
    "AO3": "https://archiveofourown.org/works/search?work_search%5Bquery%5D={q}",
    "WordPress": "https://wordpress.com/read/search?q={q}",
    "YouTube": "https://www.youtube.com/results?search_query={q}",
    "Vimeo": "https://vimeo.com/search?q={q}",
    "Dailymotion": "https://www.dailymotion.com/search/{q}",
    "Twitch": "https://www.twitch.tv/search?term={q}",
    "Rumble": "https://rumble.com/search/video?q={q}",
    "Odysee": "https://odysee.com/$/search?q={q}",
    "Spotify": "https://open.spotify.com/search/{q}",
    "SoundCloud": "https://soundcloud.com/search?q={q}",
    "Last.fm": "https://www.last.fm/search?q={q}",
    "Bandcamp": "https://bandcamp.com/search?q={q}",
    "Steam": "https://steamcommunity.com/search/users/#text={q}",
    "Roblox": "https://www.roblox.com/search/users?keyword={q}",
    "Patreon": "https://www.patreon.com/search?q={q}",
    "Etsy": "https://www.etsy.com/search?q={q}",
    "eBay": "https://www.ebay.com/sch/i.html?_nkw={q}",
    "ResearchGate": "https://www.researchgate.net/search?q={q}",
    "Academia.edu": "https://www.academia.edu/search?q={q}",
    "Goodreads": "https://www.goodreads.com/search?q={q}",
    "Letterboxd": "https://letterboxd.com/search/{q}/",
    "Duolingo": "https://www.duolingo.com/search?q={q}",
    "MyFitnessPal": "https://www.myfitnesspal.com/search?q={q}",
    "Untappd": "https://untappd.com/search?q={q}",
    "Ravelry": "https://www.ravelry.com/people/search?q={q}",
}

# Additional international platforms. profile/search are templates; {u} is a
# handle, {q} is a URL-encoded query. Empty strings mean the platform has no
# stable public profile or search URL.
EXTRAS = [
    # China
    {"name": "Xiaohongshu", "profile": "https://www.xiaohongshu.com/user/profile/{u}",
     "search": "https://www.xiaohongshu.com/search_result?keyword={q}",
     "category": "social", "region": "CN", "domains": ["xiaohongshu.com"]},
    {"name": "Baidu Tieba", "profile": "https://tieba.baidu.com/home/main?un={u}",
     "search": "https://tieba.baidu.com/f/search/res?qw={q}",
     "category": "forum", "region": "CN", "domains": ["tieba.baidu.com"]},
    {"name": "WeChat (Sogou)", "profile": "",
     "search": "https://weixin.sogou.com/weixin?type=2&query={q}",
     "category": "messaging", "region": "CN", "domains": ["weixin.sogou.com"]},
    # Japan / Korea
    {"name": "LINE", "profile": "https://line.me/ti/p/~{u}",
     "search": "https://search.line.me/?q={q}", "category": "messaging",
     "region": "JP", "domains": ["line.me"]},
    {"name": "Naver Blog", "profile": "https://blog.naver.com/{u}",
     "search": "https://search.naver.com/search.naver?where=blog&query={q}",
     "category": "social", "region": "KR", "domains": ["blog.naver.com", "naver.com"]},
    {"name": "Daum Cafe", "profile": "https://cafe.daum.net/{u}",
     "search": "https://search.daum.net/search?w=tot&q={q}",
     "category": "forum", "region": "KR", "domains": ["cafe.daum.net", "daum.net"]},
    {"name": "Kakao Story", "profile": "https://story.kakao.com/{u}",
     "search": "https://search.daum.net/search?w=tot&q={q}",
     "category": "social", "region": "KR", "domains": ["story.kakao.com"]},
    {"name": "Tistory", "profile": "https://{u}.tistory.com",
     "search": "https://www.tistory.com/search?keyword={q}",
     "category": "social", "region": "KR", "domains": ["tistory.com"]},
    {"name": "AfreecaTV", "profile": "https://bj.afreecatv.com/{u}",
     "search": "https://www.afreecatv.com/?szSearchWord={q}",
     "category": "video", "region": "KR", "domains": ["afreecatv.com"]},
    {"name": "Pixiv", "profile": "https://www.pixiv.net/users/{u}",
     "search": "https://www.pixiv.net/search.php?s_mode=s_tag&word={q}",
     "category": "creative", "region": "JP", "domains": ["pixiv.net"]},
    {"name": "Niconico", "profile": "https://www.nicovideo.jp/user/{u}",
     "search": "https://www.nicovideo.jp/search/{q}",
     "category": "video", "region": "JP", "domains": ["nicovideo.jp"]},
    {"name": "Ameba", "profile": "https://ameblo.jp/{u}",
     "search": "https://search.ameba.jp/search?q={q}",
     "category": "social", "region": "JP", "domains": ["ameblo.jp", "ameba.jp"]},
    {"name": "Mixi", "profile": "https://mixi.jp/show_profile.pl?id={u}",
     "search": "https://mixi.jp/search?q={q}", "category": "social",
     "region": "JP", "domains": ["mixi.jp"]},
    {"name": "Hatena", "profile": "https://profile.hatena.ne.jp/{u}/",
     "search": "https://b.hatena.ne.jp/search/text?q={q}",
     "category": "social", "region": "JP", "domains": ["hatena.ne.jp"]},
    {"name": "FC2", "profile": "https://{u}.blog.fc2.com",
     "search": "https://search.fc2.com/search?q={q}", "category": "social",
     "region": "JP", "domains": ["fc2.com"]},
    {"name": "5ch", "profile": "", "search": "https://find.5ch.net/search?q={q}",
     "category": "forum", "region": "JP", "domains": ["5ch.net"]},
    {"name": "Yahoo Japan", "profile": "",
     "search": "https://search.yahoo.co.jp/search?p={q}",
     "category": "search", "region": "JP", "domains": ["yahoo.co.jp"]},
    {"name": "Rakuten", "profile": "", "search": "https://search.rakuten.co.jp/search/mall/{q}/",
     "category": "shopping", "region": "JP", "domains": ["rakuten.co.jp"]},
    {"name": "Mercari", "profile": "https://www.mercari.com/jp/u/{u}/",
     "search": "https://www.mercari.com/jp/search/?keyword={q}",
     "category": "shopping", "region": "JP", "domains": ["mercari.com"]},
    # Southeast Asia
    {"name": "Zalo", "profile": "https://zalo.me/{u}",
     "search": "https://zalo.me/search?q={q}", "category": "messaging",
     "region": "VN", "domains": ["zalo.me"]},
    {"name": "Tinhte", "profile": "https://tinhte.vn/members/{u}.1/",
     "search": "https://tinhte.vn/search/?q={q}", "category": "forum",
     "region": "VN", "domains": ["tinhte.vn"]},
    {"name": "Voz", "profile": "https://voz.vn/u/{u}/",
     "search": "https://voz.vn/search/?q={q}", "category": "forum",
     "region": "VN", "domains": ["voz.vn"]},
    {"name": "Pantip", "profile": "https://pantip.com/profile/{u}",
     "search": "https://pantip.com/search?q={q}", "category": "forum",
     "region": "TH", "domains": ["pantip.com"]},
    {"name": "Kaskus", "profile": "https://www.kaskus.co.id/@{u}",
     "search": "https://www.kaskus.co.id/search?q={q}", "category": "forum",
     "region": "ID", "domains": ["kaskus.co.id"]},
    {"name": "Tokopedia", "profile": "https://www.tokopedia.com/{u}",
     "search": "https://www.tokopedia.com/search?q={q}", "category": "shopping",
     "region": "ID", "domains": ["tokopedia.com"]},
    {"name": "Bukalapak", "profile": "https://www.bukalapak.com/u/{u}",
     "search": "https://www.bukalapak.com/products?search%5Bkeywords%5D={q}",
     "category": "shopping", "region": "ID", "domains": ["bukalapak.com"]},
    {"name": "Shopee", "profile": "https://shopee.com/{u}",
     "search": "https://shopee.com/search?keyword={q}", "category": "shopping",
     "region": "SEA", "domains": ["shopee.com", "shopee.sg", "shopee.co.id"]},
    {"name": "Lazada", "profile": "https://www.lazada.com/shop/{u}",
     "search": "https://www.lazada.com/catalog/?q={q}", "category": "shopping",
     "region": "SEA", "domains": ["lazada.com", "lazada.sg"]},
    {"name": "Carousell", "profile": "https://www.carousell.com/u/{u}",
     "search": "https://www.carousell.com/search/{q}", "category": "shopping",
     "region": "SEA", "domains": ["carousell.com", "carousell.sg"]},
    # Africa / Russia / global community
    {"name": "Nairaland", "profile": "https://www.nairaland.com/{u}",
     "search": "https://www.nairaland.com/search?q={q}", "category": "forum",
     "region": "NG", "domains": ["nairaland.com"]},
    {"name": "Rutube", "profile": "https://rutube.ru/channel/{u}/",
     "search": "https://rutube.ru/search/?query={q}", "category": "video",
     "region": "RU", "domains": ["rutube.ru"]},
    {"name": "Dzen", "profile": "https://dzen.ru/{u}",
     "search": "https://dzen.ru/search?query={q}", "category": "social",
     "region": "RU", "domains": ["dzen.ru"]},
    {"name": "LiveJournal", "profile": "https://{u}.livejournal.com",
     "search": "https://www.livejournal.com/rsearch/?q={q}",
     "category": "social", "region": "RU", "domains": ["livejournal.com"]},
    {"name": "Discord", "profile": "", "search": "https://discord.com/servers?query={q}",
     "category": "community", "region": "global", "domains": ["discord.com"]},
    {"name": "Lemmy", "profile": "https://lemmy.world/u/{u}",
     "search": "https://lemmy.world/search?q={q}&type=All",
     "category": "community", "region": "global", "domains": ["lemmy.world"]},
    {"name": "Matrix", "profile": "https://matrix.to/#/@{u}:matrix.org",
     "search": "", "category": "messaging", "region": "global",
     "domains": ["matrix.to"]},
    # Europe / professional / community
    {"name": "Xing", "profile": "https://www.xing.com/profile/{u}",
     "search": "https://www.xing.com/search/members?q={q}",
     "category": "professional", "region": "EU", "domains": ["xing.com"]},
    {"name": "Viadeo", "profile": "https://www.viadeo.com/p/{u}",
     "search": "https://www.viadeo.com/search?q={q}",
     "category": "professional", "region": "EU", "domains": ["viadeo.com"]},
    {"name": "Wykop", "profile": "https://wykop.pl/ludzie/{u}",
     "search": "https://wykop.pl/szukaj?q={q}", "category": "social",
     "region": "PL", "domains": ["wykop.pl"]},
    {"name": "NK.pl", "profile": "https://nk.pl/profile/{u}",
     "search": "https://nk.pl/szukaj?q={q}", "category": "social",
     "region": "PL", "domains": ["nk.pl"]},
    {"name": "Fotka", "profile": "https://www.fotka.pl/profil/{u}",
     "search": "https://www.fotka.pl/szukaj?q={q}", "category": "social",
     "region": "PL", "domains": ["fotka.pl"]},
    {"name": "Skyrock", "profile": "https://{u}.skyrock.com",
     "search": "https://www.skyrock.com/search?q={q}", "category": "social",
     "region": "FR", "domains": ["skyrock.com"]},
    {"name": "Copains d'avant",
     "profile": "https://copainsdavant.linternaute.com/p/{u}",
     "search": "https://copainsdavant.linternaute.com/s/?q={q}",
     "category": "social", "region": "FR", "domains": ["linternaute.com"]},
    {"name": "Nextdoor", "profile": "https://nextdoor.com/profile/{u}/",
     "search": "https://nextdoor.com/search/?query={q}",
     "category": "community", "region": "US", "domains": ["nextdoor.com"]},
    {"name": "Meetup", "profile": "https://www.meetup.com/members/{u}/",
     "search": "https://www.meetup.com/find/?keywords={q}",
     "category": "community", "region": "global", "domains": ["meetup.com"]},
    {"name": "Badoo", "profile": "https://badoo.com/profile/{u}",
     "search": "https://badoo.com/search?q={q}", "category": "social",
     "region": "global", "domains": ["badoo.com"]},
    {"name": "Tagged", "profile": "https://www.tagged.com/profile.html?uid={u}",
     "search": "https://www.tagged.com/search?q={q}", "category": "social",
     "region": "global", "domains": ["tagged.com"]},
    {"name": "MySpace", "profile": "https://myspace.com/{u}",
     "search": "https://myspace.com/search?q={q}", "category": "social",
     "region": "global", "domains": ["myspace.com"]},
    {"name": "Bebo", "profile": "https://bebo.com/{u}",
     "search": "https://bebo.com/search?q={q}", "category": "social",
     "region": "global", "domains": ["bebo.com"]},
    {"name": "Minds", "profile": "https://www.minds.com/{u}",
     "search": "https://www.minds.com/search?q={q}", "category": "social",
     "region": "global", "domains": ["minds.com"]},
    {"name": "MeWe", "profile": "https://mewe.com/i/{u}",
     "search": "https://mewe.com/search?q={q}", "category": "social",
     "region": "global", "domains": ["mewe.com"]},
    {"name": "Parler", "profile": "https://parler.com/{u}",
     "search": "https://parler.com/search?q={q}", "category": "social",
     "region": "US", "domains": ["parler.com"]},
    {"name": "BitChute", "profile": "https://www.bitchute.com/channel/{u}/",
     "search": "https://www.bitchute.com/search/?q={q}", "category": "video",
     "region": "global", "domains": ["bitchute.com"]},
    {"name": "Vingle", "profile": "https://www.vingle.net/{u}",
     "search": "https://www.vingle.net/search?q={q}", "category": "social",
     "region": "global", "domains": ["vingle.net"]},
    # India / South Asia
    {"name": "ShareChat", "profile": "https://sharechat.com/profile/{u}",
     "search": "https://sharechat.com/search?q={q}", "category": "social",
     "region": "IN", "domains": ["sharechat.com"]},
    {"name": "Moj", "profile": "https://mojapp.in/@{u}",
     "search": "https://mojapp.in/search?q={q}", "category": "video",
     "region": "IN", "domains": ["mojapp.in"]},
    {"name": "Dailyhunt", "profile": "https://dailyhunt.in/profile/{u}",
     "search": "https://dailyhunt.in/search?q={q}", "category": "social",
     "region": "IN", "domains": ["dailyhunt.in"]},
    {"name": "Josh", "profile": "https://joshapp.in/@{u}",
     "search": "https://joshapp.in/search?q={q}", "category": "video",
     "region": "IN", "domains": ["joshapp.in"]},
    {"name": "Koo", "profile": "https://www.kooapp.com/profile/{u}",
     "search": "https://www.kooapp.com/search?q={q}", "category": "social",
     "region": "IN", "domains": ["kooapp.com"]},
    # Latin America / MENA / Africa / Oceania marketplaces & forums
    {"name": "Taringa", "profile": "https://www.taringa.net/{u}",
     "search": "https://www.taringa.net/buscar?q={q}", "category": "social",
     "region": "LATAM", "domains": ["taringa.net"]},
    {"name": "MercadoLibre", "profile": "https://www.mercadolibre.com/{u}",
     "search": "https://listado.mercadolibre.com/{q}", "category": "shopping",
     "region": "LATAM", "domains": ["mercadolibre.com"]},
    {"name": "OLX", "profile": "https://www.olx.com/{u}",
     "search": "https://www.olx.com/items/q-{q}", "category": "shopping",
     "region": "global", "domains": ["olx.com"]},
    {"name": "Gumtree", "profile": "",
     "search": "https://www.gumtree.com/search?q={q}", "category": "shopping",
     "region": "UK", "domains": ["gumtree.com"]},
    {"name": "Trade Me", "profile": "",
     "search": "https://www.trademe.co.nz/a/search?search_string={q}",
     "category": "shopping", "region": "NZ", "domains": ["trademe.co.nz"]},
    {"name": "Dubizzle", "profile": "",
     "search": "https://www.dubizzle.com/search/?q={q}", "category": "shopping",
     "region": "MENA", "domains": ["dubizzle.com"]},
    {"name": "OpenSooq", "profile": "",
     "search": "https://www.opensooq.com/en/search?q={q}", "category": "shopping",
     "region": "MENA", "domains": ["opensooq.com"]},
    {"name": "Haraj", "profile": "",
     "search": "https://haraj.com.sa/search?q={q}", "category": "shopping",
     "region": "SA", "domains": ["haraj.com.sa"]},
    {"name": "GhanaWeb", "profile": "https://www.ghanaweb.com/GhanaHomePage/people/person.php?ID={u}",
     "search": "https://www.ghanaweb.com/search.php?q={q}", "category": "forum",
     "region": "GH", "domains": ["ghanaweb.com"]},
    {"name": "KenyaTalk", "profile": "https://kenyatalk.com/index.php?members/{u}/",
     "search": "https://kenyatalk.com/index.php?search/search&q={q}",
     "category": "forum", "region": "KE", "domains": ["kenyatalk.com"]},
    {"name": "Something Awful", "profile": "",
     "search": "https://forums.somethingawful.com/search.php?query={q}",
     "category": "forum", "region": "US", "domains": ["somethingawful.com"]},
    {"name": "NeoGAF", "profile": "",
     "search": "https://www.neogaf.com/search/?q={q}", "category": "forum",
     "region": "global", "domains": ["neogaf.com"]},
    {"name": "ResetEra", "profile": "",
     "search": "https://www.resetera.com/search/?q={q}", "category": "forum",
     "region": "global", "domains": ["resetera.com"]},
    {"name": "SpaceBattles", "profile": "",
     "search": "https://forums.spacebattles.com/search/?q={q}",
     "category": "forum", "region": "global", "domains": ["spacebattles.com"]},
    {"name": "Sufficient Velocity", "profile": "",
     "search": "https://forums.sufficientvelocity.com/search/?q={q}",
     "category": "forum", "region": "global", "domains": ["sufficientvelocity.com"]},
    {"name": "Craigslist", "profile": "",
     "search": "https://craigslist.org/search/sss?query={q}",
     "category": "shopping", "region": "US", "domains": ["craigslist.org"]},
]

# NEW_SOURCES — extended international catalog (2026 additions). Same shape as
# EXTRAS: `profile` is the stable public profile URL ({u} = handle), `search`
# is the platform's native search UI ({q} = query) or "" when there is none.
NEW_SOURCES = [
    # Streaming / short video / creator platforms
    {"name": "Kick", "profile": "https://kick.com/{u}",
     "search": "https://kick.com/search?query={q}", "category": "video",
     "region": "global", "domains": ["kick.com"]},
    {"name": "Trovo", "profile": "https://trovo.live/s/{u}",
     "search": "https://trovo.live/search?keyword={q}", "category": "video",
     "region": "global", "domains": ["trovo.live"]},
    {"name": "Likee", "profile": "https://likee.video/@{u}",
     "search": "", "category": "video", "region": "SEA",
     "domains": ["likee.video"]},
    {"name": "Triller", "profile": "https://triller.co/@{u}",
     "search": "", "category": "video", "region": "global",
     "domains": ["triller.co"]},
    {"name": "Roposo", "profile": "https://www.roposo.com/@{u}",
     "search": "https://www.roposo.com/search?q={q}", "category": "video",
     "region": "IN", "domains": ["roposo.com"]},
    {"name": "Kuaishou", "profile": "https://www.kuaishou.com/profile/{u}",
     "search": "", "category": "video", "region": "CN",
     "domains": ["kuaishou.com"]},
    {"name": "VK Video", "profile": "https://vkvideo.ru/@{u}",
     "search": "https://vkvideo.ru/search?q={q}", "category": "video",
     "region": "RU", "domains": ["vkvideo.ru"]},
    # Music / audio
    {"name": "Mixcloud", "profile": "https://www.mixcloud.com/{u}/",
     "search": "https://www.mixcloud.com/search/?q={q}", "category": "music",
     "region": "global", "domains": ["mixcloud.com"]},
    {"name": "Audiomack", "profile": "https://audiomack.com/{u}",
     "search": "https://audiomack.com/search?q={q}", "category": "music",
     "region": "global", "domains": ["audiomack.com"]},
    # Media / communities / forums
    {"name": "Imgur", "profile": "https://imgur.com/user/{u}",
     "search": "https://imgur.com/search?q={q}", "category": "creative",
     "region": "global", "domains": ["imgur.com"]},
    {"name": "Farcaster", "profile": "https://warpcast.com/{u}",
     "search": "", "category": "community", "region": "global",
     "domains": ["warpcast.com"]},
    {"name": "Tildes", "profile": "https://tildes.net/user/{u}",
     "search": "https://tildes.net/search?q={q}", "category": "forum",
     "region": "global", "domains": ["tildes.net"]},
    {"name": "Dreamwidth", "profile": "https://{u}.dreamwidth.org",
     "search": "", "category": "blog", "region": "global",
     "domains": ["dreamwidth.org"]},
    {"name": "Plurk", "profile": "https://www.plurk.com/{u}",
     "search": "https://www.plurk.com/search?q={q}", "category": "social",
     "region": "SEA", "domains": ["plurk.com"]},
    {"name": "Baidu Zhidao", "profile": "",
     "search": "https://zhidao.baidu.com/search?word={q}", "category": "forum",
     "region": "CN", "domains": ["zhidao.baidu.com"]},
    # Code / writing / funding
    {"name": "Hashnode", "profile": "https://hashnode.com/@{u}",
     "search": "https://hashnode.com/search?q={q}", "category": "code",
     "region": "global", "domains": ["hashnode.com"]},
    {"name": "Subscribestar", "profile": "https://www.subscribestar.com/{u}",
     "search": "", "category": "shopping", "region": "global",
     "domains": ["subscribestar.com"]},
    # Gaming
    {"name": "Chess.com", "profile": "https://www.chess.com/member/{u}",
     "search": "", "category": "gaming", "region": "global",
     "domains": ["chess.com"]},
    {"name": "Lichess", "profile": "https://lichess.org/@/{u}",
     "search": "", "category": "gaming", "region": "global",
     "domains": ["lichess.org"]},
]

# oEmbed endpoints (public, keyless). The provider returns JSON metadata.
OEMBED = {
    "TikTok": "https://www.tiktok.com/oembed?url={url}",
    "X/Twitter": "https://publish.twitter.com/oembed?url={url}",
    "YouTube": "https://www.youtube.com/oembed?url={url}&format=json",
    "Vimeo": "https://vimeo.com/api/oembed.json?url={url}",
    "SoundCloud": "https://soundcloud.com/oembed?format=json&url={url}",
    "Spotify": "https://open.spotify.com/oembed?url={url}",
    "Reddit": "https://www.reddit.com/oembed?url={url}",
    "Dailymotion": "https://www.dailymotion.com/services/oembed?url={url}",
    "Tumblr": "https://www.tumblr.com/oembed/1.0?url={url}",
    "Mixcloud": "https://app.mixcloud.com/oembed/?url={url}",
    "Flickr": "https://www.flickr.com/services/oembed?url={url}",
}


def _base_domain(host):
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} \
            and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _domain_from_template(tmpl):
    if not tmpl:
        return ""
    try:
        raw = tmpl.replace("{u}", "placeholder")
        host = (urllib.parse.urlsplit(raw).hostname or "").lower().strip(".")
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    if host.startswith("placeholder."):
        return _base_domain(host[len("placeholder."):])
    return host


def _build_catalog():
    rows, seen = [], {}
    for name, tmpl, cat, region in SOCIAL.PLATFORMS:
        rec = {
            "name": name, "profile_template": tmpl, "category": cat,
            "region": region, "search_template": SEARCH_TEMPLATES.get(name, ""),
            "domains": [_domain_from_template(tmpl)], "adapter": "public_html",
            "notes": "",
        }
        rows.append(rec)
        seen[name.lower()] = rec
    for extra in EXTRAS:
        key = extra["name"].lower()
        rec = seen.get(key)
        if rec is None:
            rec = {
                "name": extra["name"], "profile_template": extra.get("profile", ""),
                "category": extra.get("category", "social"),
                "region": extra.get("region", "global"),
                "search_template": extra.get("search", ""),
                "domains": list(extra.get("domains") or []),
                "adapter": extra.get("adapter", "public_html"),
                "notes": extra.get("notes", ""),
            }
            rows.append(rec)
            seen[key] = rec
        else:
            if extra.get("profile"):
                rec["profile_template"] = extra["profile"]
            if extra.get("search"):
                rec["search_template"] = extra["search"]
            if extra.get("domains"):
                rec["domains"] = list(extra["domains"])
            rec["category"] = extra.get("category", rec["category"])
            rec["region"] = extra.get("region", rec["region"])
            rec["adapter"] = extra.get("adapter", rec["adapter"])
            rec["notes"] = extra.get("notes", rec.get("notes", ""))
    for extra in NEW_SOURCES:
        key = extra["name"].lower()
        if key in seen:
            continue
        rec = {
            "name": extra["name"], "profile_template": extra.get("profile", ""),
            "category": extra.get("category", "social"),
            "region": extra.get("region", "global"),
            "search_template": extra.get("search", ""),
            "domains": list(extra.get("domains") or []),
            "adapter": extra.get("adapter", "public_html"),
            "notes": extra.get("notes", ""),
        }
        rows.append(rec)
        seen[key] = rec
    for rec in rows:
        rec["domains"] = [d for d in rec.get("domains") or [] if d]
        rec["searchable"] = bool(rec.get("search_template"))
        rec["profile_url"] = bool(rec.get("profile_template"))
    rows.sort(key=lambda r: (r["region"], r["category"], r["name"].lower()))
    return rows


PLATFORMS = _build_catalog()
_PLATFORM_BY_NAME = {p["name"].lower(): p for p in PLATFORMS}
_HOST_INDEX = {}
for _p in PLATFORMS:
    for _d in _p["domains"]:
        _HOST_INDEX[_d] = _p["name"]

REGIONS = sorted({p["region"] for p in PLATFORMS})
CATEGORIES = sorted({p["category"] for p in PLATFORMS})

# High-signal global platforms are placed first when building a site-dork so a
# default "all regions" search does not spend its 24-domain budget on small
# regional catalogs before reaching X/Reddit/GitHub/etc.
MAJOR_PRIORITY = [
    "X/Twitter", "Instagram", "Facebook", "TikTok", "Reddit", "YouTube",
    "LinkedIn", "Telegram", "GitHub", "Bluesky", "Mastodon", "Threads",
    "Pinterest", "Medium", "VK", "Weibo", "Douyin", "Zhihu", "Bilibili",
    "Pixiv", "Naver Blog", "LINE", "Tumblr", "Snapchat", "Quora",
    "Substack", "Twitch", "SoundCloud", "GitLab", "Codeberg", "HackerNews",
    "Stack Overflow", "Behance", "Dribbble", "Flickr", "DeviantArt",
    "ArtStation", "Spotify", "Steam", "Roblox", "Patreon", "Etsy", "eBay",
    "ResearchGate", "Academia.edu", "Goodreads", "Letterboxd", "Xing",
    "Nextdoor", "Meetup", "ShareChat", "Taringa", "MercadoLibre", "OLX",
]
MAJOR_PLATFORMS = set(MAJOR_PRIORITY)

def _ordered_platforms(selected, region="all"):
    reg = (region or "all").strip()
    by_name = {p["name"]: p for p in selected}
    regional = []
    if reg.lower() not in ("all", "*", "global"):
        regional = [p for p in selected if p["region"] == reg]
    regional_names = {p["name"] for p in regional}
    major = [by_name[n] for n in MAJOR_PRIORITY if n in by_name]
    major_names = {p["name"] for p in major}
    rest = [p for p in selected if p["name"] not in regional_names
            and p["name"] not in major_names]
    return regional + major + rest


def catalog():
    """Describe the platform/engine coverage for the UI and source catalog."""
    by_region, by_category = {}, {}
    for p in PLATFORMS:
        by_region[p["region"]] = by_region.get(p["region"], 0) + 1
        by_category[p["category"]] = by_category.get(p["category"], 0) + 1
    return {
        "platforms": len(PLATFORMS),
        "searchable_platforms": sum(1 for p in PLATFORMS if p["searchable"]),
        "profile_platforms": sum(1 for p in PLATFORMS if p["profile_url"]),
        "by_region": by_region,
        "by_category": by_category,
        "regions": REGIONS,
        "categories": CATEGORIES,
        "engines": ["ddg", "searx", "mojeek", "baidu", "yandex", "weibo",
                    "telegram", "reddit", "bluesky", "lemmy", "hn", "mastodon"],
        "adapters": ["public_html", "opengraph", "twitter_card", "jsonld",
                     "oembed", "reddit_json", "bluesky_api", "lemmy_api",
                     "hn_algolia", "mastodon_tag"],
        "platform_list": PLATFORMS,
        "limits": {"max_html_bytes": MAX_HTML, "redirects": MAX_REDIRECTS,
                   "max_images": MAX_IMAGES, "max_links": MAX_LINKS,
                   "public_ip_only": True, "no_login": True},
        "caveat": ("Public pages and public APIs only. Login walls, captchas "
                   "and private content are reported as blocked, never bypassed. "
                   "Platform search URLs are best-effort and may change. "
                   "Profile/post matches are leads, not identity proof."),
    }


def platform_for_url(url):
    """Map a URL host to a platform name (known social hosts first)."""
    p = SOCIAL.platform_for_url(url)
    if p:
        return p
    try:
        host = (urllib.parse.urlsplit(url or "").hostname or "").lower().strip(".")
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    for d, name in _HOST_INDEX.items():
        if host == d or host.endswith("." + d):
            return name
    return ""


def _select_platforms(platforms=None, region="all", category="all"):
    if isinstance(platforms, str):
        platforms = [x.strip() for x in platforms.split(",") if x.strip()]
    selected = list(PLATFORMS)
    if platforms:
        wanted = {str(x).strip().lower() for x in platforms}
        selected = [p for p in selected if p["name"].lower() in wanted
                    or any(d in wanted for d in p["domains"])]
        # Explicit platform names/domains win over a broad region/category
        # filter; otherwise "Pixiv + region=US" would silently return nothing.
        return selected
    reg = (region or "all").strip()
    if reg and reg.lower() not in ("all", "*"):
        if reg.lower() == "global":
            selected = [p for p in selected if p["region"] == "global"]
        else:
            selected = [p for p in selected if p["region"] == reg
                        or p["region"] == "global"]
    cat = (category or "all").strip()
    if cat and cat.lower() != "all":
        selected = [p for p in selected if p["category"] == cat]
    return selected


def search_links(query, platforms=None, region="all", category="all", limit=250):
    """Build platform-native search links for a query."""
    q = (query or "").strip()
    if not q:
        return []
    selected = _ordered_platforms(_select_platforms(platforms, region, category), region)
    out = []
    for p in selected:
        tmpl = p.get("search_template") or ""
        if not tmpl:
            continue
        out.append({
            "platform": p["name"], "region": p["region"],
            "category": p["category"], "mode": "link_out",
            "url": tmpl.format(q=urllib.parse.quote_plus(q)),
        })
        if len(out) >= limit:
            break
    return out


def detect_query_type(query):
    q = (query or "").strip()
    if not q:
        return "empty"
    if re.match(r"^https?://", q, re.I):
        return "url"
    if q.startswith("#"):
        return "hashtag"
    if q.startswith("@"):
        return "handle"
    if "@" in q and "." in q.split("@")[-1] and " " not in q:
        return "email"
    if re.match(r"^\+?[0-9][0-9\s().-]{5,}$", q):
        return "phone"
    if re.match(r"^[A-Za-z0-9_.-]{2,39}$", q) and " " not in q:
        return "handle"
    if SOCIAL.NAME_RE.fullmatch(q):
        return "name"
    return "keyword"


# ------------------------------------------------------------------ helpers
def _clean(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    s = _html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def _norm_url(url):
    try:
        p = urllib.parse.urlsplit(url or "")
        if p.scheme not in ("http", "https"):
            return url or ""
        q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)
             if not k.lower().startswith(("utm_", "fbclid", "gclid", "mc_", "ref_"))]
        path = p.path.rstrip("/") or "/"
        return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path,
                                        urllib.parse.urlencode(q), ""))
    except Exception:
        return url or ""


def _iso(ts):
    if not ts:
        return ""
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        s = str(ts).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return str(ts)[:80]


def _validate_public_url(url):
    """SSRF guard: public http(s) URL, no credentials, global IP only."""
    return SOCIAL._validate_public_url(url)


def _fetch_public(url, max_bytes=MAX_HTML):
    """Fetch a public HTML page, validating every redirect hop."""
    current = url
    r = None
    for _hop in range(MAX_REDIRECTS + 1):
        ok, why = _validate_public_url(current)
        if not ok:
            return {"status": "error", "error": why, "url": current}
        try:
            r = requests.get(current, headers={**UA, "Accept": "text/html,application/xhtml+xml"},
                             timeout=T, allow_redirects=False, stream=True)
        except Exception as e:
            return {"status": "error", "error": str(e)[:150], "url": current}
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location") or ""
            try:
                r.close()
            except Exception:
                pass
            if not loc:
                return {"status": "error", "error": "redirect without Location",
                        "url": current}
            current = urllib.parse.urljoin(current, loc)
            continue
        break
    else:
        return {"status": "error", "error": "too many redirects", "url": current}
    try:
        ctype = (r.headers.get("Content-Type") or "").lower()
        if ctype and "html" not in ctype and "xhtml" not in ctype:
            return {"status": "error", "error": "not an HTML page (%s)" % ctype,
                    "url": current}
        chunks, total = [], 0
        for chunk in r.iter_content(chunk_size=16384):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= max_bytes:
                break
        raw = b"".join(chunks)[:max_bytes]
        enc = r.encoding or "utf-8"
        try:
            page = raw.decode(enc, "replace")
        except Exception:
            page = raw.decode("utf-8", "replace")
        final_url = getattr(r, "url", current) or current
        low = page[:8000].lower()
        if any(m in low for m in _BLOCK_MARKERS):
            return {"status": "blocked", "mode": "anti_bot",
                    "url": current, "final_url": final_url,
                    "error": "page looks like a login/captcha/anti-bot wall"}
        return {"status": "ok", "page": page, "final_url": final_url,
                "bytes": len(page.encode("utf-8", "replace"))}
    except Exception as e:
        return {"status": "error", "error": str(e)[:150], "url": current}
    finally:
        try:
            r.close()
        except Exception:
            pass


def _jsonld_items(page):
    items = []
    for m in re.finditer(r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                         page or "", re.S | re.I):
        try:
            obj = json.loads(m.group(1).strip())
        except Exception:
            continue
        stack = obj if isinstance(obj, list) else [obj]
        while stack:
            item = stack.pop(0)
            if isinstance(item, dict):
                items.append(item)
                if isinstance(item.get("@graph"), list):
                    stack.extend(item["@graph"])
            elif isinstance(item, list):
                stack.extend(item)
    return items


def _first(*values):
    for v in values:
        if isinstance(v, str) and v.strip():
            return v.strip()
        if isinstance(v, (int, float)):
            return str(v)
    return ""


def _jsonld_value(item, key):
    v = item.get(key)
    if isinstance(v, dict):
        return _first(v.get("name"), v.get("url"), v.get("@id"))
    if isinstance(v, list):
        for x in v:
            got = _jsonld_value({"v": x}, "v")
            if got:
                return got
    return _first(v)


def _abs_url(base, value):
    if not value:
        return ""
    value = _html.unescape(str(value)).strip()
    if not value or value.startswith(("data:", "blob:", "javascript:")):
        return ""
    if value.startswith("//"):
        value = "https:" + value
    try:
        absolute = urllib.parse.urljoin(base, value)
        p = urllib.parse.urlsplit(absolute)
        if p.scheme not in ("http", "https") or not p.hostname:
            return ""
        return absolute
    except Exception:
        return ""


def _srcset_first(value):
    for part in (value or "").split(","):
        url = part.strip().split(" ")[0]
        if url:
            return url
    return ""


def _extract_media(page, base_url):
    images, videos, seen_i, seen_v = [], [], set(), set()

    def add_image(u):
        absolute = _abs_url(base_url, u)
        key = _norm_url(absolute)
        if absolute and key not in seen_i and len(images) < MAX_IMAGES:
            seen_i.add(key)
            images.append(absolute)

    def add_video(u):
        absolute = _abs_url(base_url, u)
        key = _norm_url(absolute)
        if absolute and key not in seen_v and len(videos) < MAX_VIDEOS:
            seen_v.add(key)
            videos.append(absolute)

    for m in re.finditer(r"<meta\b[^>]*>", page or "", re.I):
        raw = m.group(0)
        attrs = {}
        for am in re.finditer(r"""([\w:-]+)\s*=\s*["']([^"']*)["']""", raw):
            attrs[am.group(1).lower()] = _html.unescape(am.group(2))
        key = (attrs.get("property") or attrs.get("name") or "").lower()
        content = attrs.get("content") or ""
        if key in ("og:image", "og:image:url", "og:image:secure_url",
                   "twitter:image", "twitter:image:src", "image"):
            add_image(content)
        elif key in ("og:video", "og:video:url", "og:video:secure_url",
                     "twitter:player:stream", "twitter:player"):
            add_video(content)
        elif key in ("og:video:image", "twitter:player:image"):
            add_image(content)

    for m in re.finditer(r"<link\b[^>]*>", page or "", re.I):
        raw = m.group(0)
        if re.search(r"""\brel\s*=\s*["'](?:image_src|apple-touch-icon)["']""", raw, re.I):
            hm = re.search(r"""\bhref\s*=\s*["']([^"']+)["']""", raw, re.I)
            if hm:
                add_image(hm.group(1))

    for m in re.finditer(r"<img\b([^>]*)>", page or "", re.I):
        attrs = m.group(1)
        for name in ("data-src", "data-original", "data-lazy-src", "data-url", "src"):
            am = re.search(r"""\b%s\s*=\s*["']([^"']+)["']""" % name, attrs, re.I)
            if am:
                add_image(am.group(1))
                break
        sm = re.search(r"""\bsrcset\s*=\s*["']([^"']+)["']""", attrs, re.I)
        if sm:
            add_image(_srcset_first(sm.group(1)))

    for m in re.finditer(r"<video\b([^>]*)>(.*?)</video>", page or "", re.I | re.S):
        attrs, body = m.group(1), m.group(2)
        pm = re.search(r"""\bposter\s*=\s*["']([^"']+)["']""", attrs, re.I)
        if pm:
            add_image(pm.group(1))
        for sm in re.finditer(r"""<source\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", body, re.I):
            add_video(sm.group(1))

    for item in _jsonld_items(page):
        for key in ("image", "thumbnailUrl", "contentUrl", "url"):
            v = item.get(key)
            if isinstance(v, str):
                (add_video if key == "contentUrl" else add_image)(v)
            elif isinstance(v, dict):
                (add_video if key == "contentUrl" else add_image)(
                    _first(v.get("url"), v.get("contentUrl")))
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, str):
                        (add_video if key == "contentUrl" else add_image)(x)
                    elif isinstance(x, dict):
                        (add_video if key == "contentUrl" else add_image)(
                            _first(x.get("url"), x.get("contentUrl")))
    return images, videos


def _extract_links(page, base_url):
    links, social_links, seen = [], [], set()
    try:
        page_host = (urllib.parse.urlsplit(base_url).hostname or "").lower()
        if page_host.startswith("www."):
            page_host = page_host[4:]
    except Exception:
        page_host = ""
    for m in re.finditer(r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
                         page or "", re.S | re.I):
        href = _html.unescape(m.group(1)).strip()
        if not href or href.startswith(("#", "javascript:", "data:")):
            continue
        absolute = _abs_url(base_url, href)
        if not absolute:
            continue
        key = _norm_url(absolute)
        if key in seen:
            continue
        seen.add(key)
        rec = {"url": absolute, "text": _clean(m.group(2))[:160],
               "platform": platform_for_url(absolute)}
        if len(links) < MAX_LINKS:
            links.append(rec)
        try:
            host = (urllib.parse.urlsplit(absolute).hostname or "").lower()
            if host.startswith("www."):
                host = host[4:]
        except Exception:
            host = ""
        if rec["platform"] and host != page_host and rec not in social_links:
            social_links.append(rec)
    return links, social_links[:40]


def _visible_text(page, limit=MAX_TEXT):
    page = re.sub(r"<script\b.*?</script>", " ", page or "", flags=re.S | re.I)
    page = re.sub(r"<style\b.*?</style>", " ", page, flags=re.S | re.I)
    page = re.sub(r"<[^>]+>", " ", page)
    page = _html.unescape(page)
    return re.sub(r"\s+", " ", page).strip()[:limit]


def _hashtags(text):
    out = []
    for m in re.finditer(r"(?<!\w)#([\w\u0080-\uffff]{1,60})", text or "", re.UNICODE):
        tag = m.group(1)
        if tag not in out:
            out.append(tag)
    return out[:50]


def _mentions(text):
    out = []
    for m in re.finditer(r"(?<!\w)@([A-Za-z0-9_.-]{2,60})", text or ""):
        handle = m.group(1).strip(".")
        if handle and handle not in out:
            out.append(handle)
    return out[:50]


def _post_type(url, platform, meta, jsonld):
    try:
        path = urllib.parse.urlsplit(url or "").path.lower()
    except Exception:
        path = ""
    markers = ("/status/", "/p/", "/reel/", "/video/", "/post/", "/pin/",
               "/photos/", "/watch", "/shorts/", "/t/", "/notes/")
    if any(m in path for m in markers):
        return "post"
    if meta.get("article:published_time") or meta.get("og:type") in ("article", "video"):
        return "post"
    for item in jsonld:
        typ = item.get("@type")
        types = typ if isinstance(typ, list) else [typ]
        if any(str(t).lower() in ("socialmediaposting", "article", "videoobject",
                                  "imageobject", "blogposting") for t in types if t):
            return "post"
    return "profile" if platform else "page"


def _handle_from_url(url, platform):
    try:
        parts = [p for p in urllib.parse.urlsplit(url or "").path.split("/") if p]
    except Exception:
        return ""
    if not parts:
        return ""
    if platform in ("X/Twitter", "Instagram", "Threads", "TikTok", "Bluesky",
                    "Mastodon", "Reddit", "GitHub", "GitLab", "Codeberg"):
        return parts[0].lstrip("@")
    if platform == "Telegram":
        return parts[0]
    return ""


def _parse_public_page(page, base_url):
    meta = SOCIAL._meta_tags(page)
    title_m = re.search(r"<title[^>]*>(.*?)</title>", page or "", re.S | re.I)
    title = _clean(title_m.group(1)) if title_m else ""
    canonical = ""
    for m in re.finditer(r"<link\b[^>]*>", page or "", re.I):
        raw = m.group(0)
        if re.search(r"""\brel\s*=\s*["']canonical["']""", raw, re.I):
            hm = re.search(r"""\bhref\s*=\s*["']([^"']+)["']""", raw, re.I)
            if hm:
                canonical = _html.unescape(hm.group(1))
                break
    jsonld = _jsonld_items(page)
    jsonld_person = []
    for item in jsonld:
        typ = item.get("@type")
        types = typ if isinstance(typ, list) else [typ]
        if any(str(t).lower() in ("person", "profilepage", "organization") for t in types if t):
            jsonld_person.append({k: item.get(k) for k in
                                  ("@type", "name", "alternateName", "description",
                                   "image", "sameAs", "jobTitle", "worksFor",
                                   "address", "alumniOf", "url") if item.get(k) is not None})
    author = _first(meta.get("author"), meta.get("article:author"),
                    meta.get("og:article:author"), meta.get("profile:username"),
                    meta.get("twitter:creator"))
    if not author:
        for item in jsonld:
            if item.get("author"):
                author = _jsonld_value(item, "author")
                if author:
                    break
    published = _first(meta.get("article:published_time"), meta.get("og:published_time"),
                       meta.get("date"), meta.get("datepublished"))
    if not published:
        for item in jsonld:
            if item.get("datePublished"):
                published = _jsonld_value(item, "datePublished")
                if published:
                    break
    if not published:
        tm = re.search(r"""<time\b[^>]*\bdatetime\s*=\s*["']([^"']+)["']""", page or "", re.I)
        if tm:
            published = tm.group(1)
    description = _first(meta.get("og:description"), meta.get("description"),
                         meta.get("twitter:description"))
    if not description:
        for item in jsonld:
            if item.get("description"):
                description = _jsonld_value(item, "description")
                if description:
                    break
    images, videos = _extract_media(page, base_url)
    links, social_links = _extract_links(page, base_url)
    text = _visible_text(page)
    tags = _hashtags(" ".join([title, description, text]))
    mentions = _mentions(" ".join([title, description, text]))
    platform = platform_for_url(base_url)
    return {
        "title": _first(meta.get("og:title"), meta.get("twitter:title"), title),
        "description": description,
        "site_name": _first(meta.get("og:site_name"), meta.get("application-name")),
        "author": author,
        "published": _iso(published) if published else "",
        "language": _first(meta.get("og:locale"), meta.get("language")),
        "canonical": _abs_url(base_url, canonical) if canonical else "",
        "og": {k: v for k, v in meta.items() if k.startswith("og:")},
        "twitter": {k: v for k, v in meta.items() if k.startswith("twitter:")},
        "jsonld": jsonld_person or jsonld[:8],
        "images": images,
        "videos": videos,
        "links": links,
        "social_links": social_links,
        "hashtags": tags,
        "mentions": mentions,
        "platform": platform,
        "post_type": _post_type(base_url, platform, meta, jsonld),
        "handle": _handle_from_url(base_url, platform),
        "name": _first(meta.get("og:title"), title),
    }


def oembed(url):
    """Public oEmbed lookup for platforms that expose it."""
    platform = platform_for_url(url)
    tmpl = OEMBED.get(platform)
    if not tmpl:
        return {"status": "not_supported", "platform": platform,
                "note": "no public oEmbed endpoint for this platform"}
    lookup_url = url
    # publish.twitter.com expects twitter.com URLs, not the x.com alias.
    if platform == "X/Twitter" and "//x.com/" in lookup_url:
        lookup_url = lookup_url.replace("//x.com/", "//twitter.com/", 1)
    endpoint = tmpl.format(url=urllib.parse.quote(lookup_url, safe=""))
    try:
        r = requests.get(endpoint, headers=UA, timeout=T)
    except Exception as e:
        return {"status": "error", "platform": platform, "error": str(e)[:150]}
    if r.status_code in (401, 403, 429):
        return {"status": "blocked", "platform": platform, "http": r.status_code}
    if r.status_code == 404:
        return {"status": "not_found", "platform": platform, "http": 404}
    if r.status_code != 200:
        return {"status": "error", "platform": platform, "http": r.status_code}
    try:
        j = r.json()
    except Exception:
        return {"status": "error", "platform": platform, "error": "non-JSON oEmbed response"}
    return {
        "status": "ok", "platform": platform, "provider": j.get("provider_name"),
        "title": j.get("title") or "", "author_name": j.get("author_name") or "",
        "author_url": j.get("author_url") or "", "type": j.get("type") or "",
        "thumbnail_url": j.get("thumbnail_url") or "",
        "html": (j.get("html") or "")[:4000], "url": url,
    }


def scrape_public_page(url, include_images=True, include_oembed=True):
    """Scrape one public profile/post URL. No login or JS execution."""
    url = (url or "").strip()
    if not url:
        return {"status": "error", "error": "url required"}
    if "://" not in url:
        url = "https://" + url
    fetched = _fetch_public(url)
    if fetched.get("status") != "ok":
        return {"status": fetched.get("status", "error"),
                "url": url, "error": fetched.get("error", "fetch failed"),
                "final_url": fetched.get("final_url", url)}
    page = fetched["page"]
    final_url = fetched["final_url"]
    parsed = _parse_public_page(page, final_url)
    out = {"status": "ok", "url": url, "final_url": final_url,
           "fetched_bytes": fetched.get("bytes", 0), **parsed}
    if not include_images:
        out["images"], out["videos"] = [], []
    if include_oembed:
        oe = oembed(final_url)
        if oe.get("status") == "ok":
            out["oembed"] = oe
            out["title"] = out.get("title") or oe.get("title", "")
            out["author"] = out.get("author") or oe.get("author_name", "")
            if not out.get("images") and oe.get("thumbnail_url"):
                out["images"] = [oe["thumbnail_url"]]
        elif oe.get("status") not in ("not_supported",):
            out["oembed"] = oe
    low = (page[:12000] or "").lower()
    if any(m in low for m in _MISSING_MARKERS):
        out["note"] = "page contains a missing-profile marker; verify manually"
    return out


# ------------------------------------------------------------------ public APIs
def _json_get(url, params=None):
    try:
        r = requests.get(url, params=params, headers={**UA, "Accept": "application/json"},
                         timeout=T)
    except Exception as e:
        return {"status": "error", "error": str(e)[:150]}
    if r.status_code in (401, 403, 429):
        return {"status": "blocked", "http": r.status_code,
                "error": "public API rate-limited or blocked"}
    if r.status_code == 404:
        return {"status": "not_found", "http": 404}
    if r.status_code != 200:
        return {"status": "error", "http": r.status_code}
    try:
        return {"status": "ok", "data": r.json()}
    except Exception as e:
        return {"status": "error", "error": "non-JSON response: %s" % str(e)[:80]}


def reddit_search(query, limit=25):
    """Reddit public search JSON (keyless)."""
    res = _json_get("https://www.reddit.com/search.json",
                    {"q": query, "limit": max(1, min(int(limit or 25), 100)),
                     "sort": "relevance", "type": "link"})
    if res.get("status") != "ok":
        return {"engine": "reddit", "status": res.get("status", "error"),
                "results": [], "error": res.get("error", ""), "http": res.get("http")}
    rows = []
    for child in ((res.get("data") or {}).get("data") or {}).get("children") or []:
        d = child.get("data") or {}
        if not d.get("permalink"):
            continue
        rows.append({
            "title": d.get("title") or "",
            "url": "https://www.reddit.com" + d["permalink"],
            "snippet": _clean(d.get("selftext") or "")[:400],
            "author": d.get("author") or "",
            "published": _iso(d.get("created_utc")),
            "platform": "Reddit", "source": "reddit_api",
        })
    return {"engine": "reddit", "status": "ok", "results": rows,
            "count": len(rows)}


def bluesky_search(query, limit=25):
    """Bluesky public search API (keyless)."""
    res = _json_get("https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts",
                    {"q": query, "limit": max(1, min(int(limit or 25), 100))})
    if res.get("status") != "ok":
        return {"engine": "bluesky", "status": res.get("status", "error"),
                "results": [], "error": res.get("error", ""), "http": res.get("http")}
    rows = []
    for post in (res.get("data") or {}).get("posts") or []:
        author = (post.get("author") or {}).get("handle") or ""
        uri = post.get("uri") or ""
        rkey = uri.rsplit("/", 1)[-1] if uri else ""
        text = post.get("record", {}).get("text") or ""
        if not author or not rkey:
            continue
        rows.append({
            "title": text[:120] or "Bluesky post",
            "url": "https://bsky.app/profile/%s/post/%s" % (author, rkey),
            "snippet": text[:400], "author": author,
            "published": _iso(post.get("indexedAt")),
            "platform": "Bluesky", "source": "bluesky_api",
        })
    return {"engine": "bluesky", "status": "ok", "results": rows,
            "count": len(rows)}


def lemmy_search(query, limit=25):
    """Lemmy public search API (keyless, one large instance)."""
    res = _json_get("https://lemmy.world/api/v3/search",
                    {"q": query, "type_": "All",
                     "limit": max(1, min(int(limit or 25), 50))})
    if res.get("status") != "ok":
        return {"engine": "lemmy", "status": res.get("status", "error"),
                "results": [], "error": res.get("error", ""), "http": res.get("http")}
    rows = []
    for item in (res.get("data") or {}).get("posts") or []:
        post = item.get("post") or {}
        creator = item.get("creator") or {}
        if not post:
            continue
        url = post.get("url") or ("https://lemmy.world/post/%s" % post.get("id", ""))
        rows.append({
            "title": post.get("name") or "",
            "url": url, "snippet": _clean(post.get("body") or "")[:400],
            "author": creator.get("name") or "",
            "published": _iso(post.get("published")),
            "platform": "Lemmy", "source": "lemmy_api",
        })
    return {"engine": "lemmy", "status": "ok", "results": rows,
            "count": len(rows)}


def hn_search(query, limit=25):
    """Hacker News stories + comments via the keyless Algolia API."""
    res = _json_get("https://hn.algolia.com/api/v1/search",
                    {"query": query, "hitsPerPage": max(1, min(int(limit or 25), 50))})
    if res.get("status") != "ok":
        return {"engine": "hn", "status": res.get("status", "error"),
                "results": [], "error": res.get("error", ""), "http": res.get("http")}
    rows = []
    for h in (res.get("data") or {}).get("hits") or []:
        oid = h.get("objectID") or ""
        if not oid:
            continue
        is_comment = bool(h.get("comment_text"))
        url = h.get("url") or ""
        if is_comment:
            url = "https://news.ycombinator.com/item?id=%s" % oid
        title = h.get("title") or _clean(h.get("story_title") or "") \
            or (h.get("comment_text") or "")[:120] or "HN item"
        text = h.get("story_text") or h.get("comment_text") or ""
        rows.append({
            "title": title,
            "url": url or "https://news.ycombinator.com/item?id=%s" % oid,
            "snippet": _clean(text)[:400],
            "author": h.get("author") or "",
            "published": _iso(h.get("created_at")),
            "platform": "HackerNews", "source": "hn_algolia",
            "meta": {"points": h.get("points"), "comments": h.get("num_comments"),
                     "kind": "comment" if is_comment else "story"},
        })
    return {"engine": "hn", "status": "ok", "results": rows, "count": len(rows)}


def mastodon_tag_search(hashtag, limit=25):
    """Public hashtag timeline on mastodon.social (keyless).

    Only meaningful for ``#tag`` queries; returns ``not_supported`` otherwise.
    """
    tag = (hashtag or "").strip().lstrip("#")
    if not tag or " " in tag:
        return {"engine": "mastodon", "status": "not_supported",
                "results": [], "error": "mastodon tag search needs a single #hashtag"}
    res = _json_get("https://mastodon.social/api/v1/timelines/tag/%s"
                    % urllib.parse.quote(tag, safe=""),
                    {"limit": max(1, min(int(limit or 25), 40))})
    if res.get("status") != "ok":
        return {"engine": "mastodon", "status": res.get("status", "error"),
                "results": [], "error": res.get("error", ""), "http": res.get("http")}
    rows = []
    for st in res.get("data") or []:
        if not isinstance(st, dict):
            continue
        acct = (st.get("account") or {}).get("acct") or ""
        url = st.get("url") or ""
        if not url:
            continue
        rows.append({
            "title": _clean(st.get("content") or "")[:120] or ("Mastodon post by @%s" % acct),
            "url": url,
            "snippet": _clean(st.get("content") or "")[:400],
            "author": "@" + acct if acct else "",
            "published": _iso(st.get("created_at")),
            "platform": "Mastodon", "source": "mastodon_tag",
            "meta": {"boosts": st.get("reblogs_count"), "favourites": st.get("favourites_count")},
        })
    return {"engine": "mastodon", "status": "ok", "results": rows, "count": len(rows)}


def _run_engines(query, dork, selected, engines=None, region="all"):
    """Run federated + regional + keyless API engines concurrently."""
    out = {}
    try:
        from modules.searchx import searchx as SEARCHX
    except Exception as e:
        SEARCHX = None
        out["searchx"] = {"status": "error", "results": [],
                          "error": "searchx unavailable: %s" % str(e)[:100]}
    if SEARCHX is not None:
        try:
            fed = SEARCHX.federated(dork, engines=engines or ["ddg", "searx", "mojeek"])
            out.update(fed.get("engines") or {})
        except Exception as e:
            out["searchx"] = {"status": "error", "results": [],
                              "error": str(e)[:120]}
    try:
        from modules.regional import regional as REG
    except Exception:
        REG = None
    tasks = {}
    if REG is not None:
        tasks["baidu"] = lambda: REG.baidu_search(query)
        tasks["yandex"] = lambda: REG.yandex_search(query)
        tasks["weibo"] = lambda: REG.weibo_search(query)
        if re.match(r"^[A-Za-z0-9_]{4,32}$", (query or "").lstrip("@")):
            tasks["telegram"] = lambda: REG.telegram_channel(query)
    names = {p["name"] for p in selected}
    if not names or "Reddit" in names:
        tasks["reddit"] = lambda: reddit_search(query)
    if not names or "Bluesky" in names:
        tasks["bluesky"] = lambda: bluesky_search(query)
    if not names or "Lemmy" in names:
        tasks["lemmy"] = lambda: lemmy_search(query)
    if not names or "HackerNews" in names:
        tasks["hn"] = lambda: hn_search(query)
    if q.lstrip("@").startswith("#"):
        tasks["mastodon"] = lambda: mastodon_tag_search(query)
    if tasks:
        with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as ex:
            futs = {ex.submit(fn): name for name, fn in tasks.items()}
            for f in as_completed(futs):
                name = futs[f]
                try:
                    out[name] = f.result()
                except Exception as e:
                    out[name] = {"status": "error", "results": [],
                                 "error": str(e)[:120]}
    return out


def _normalize_engine_results(engines):
    by_url, rows = {}, []
    for engine, res in (engines or {}).items():
        if not isinstance(res, dict):
            continue
        items = res.get("results")
        if items is None and isinstance(res.get("posts"), list):
            items = res["posts"]
        for item in items or []:
            if not isinstance(item, dict):
                continue
            url = item.get("url") or item.get("link") or ""
            title = item.get("title") or item.get("text") or item.get("nickname") or ""
            snippet = item.get("snippet") or item.get("text") or ""
            platform = item.get("platform") or platform_for_url(url)
            if not platform:
                platform = {"weibo": "Weibo", "telegram": "Telegram"}.get(engine, "")
            if not url and platform == "Weibo":
                url = "https://s.weibo.com/weibo?q=" + urllib.parse.quote_plus(
                    item.get("text") or "")
            rec = {
                "url": url, "title": _clean(title)[:240],
                "snippet": _clean(snippet)[:600],
                "platform": platform, "author": item.get("author") or "",
                "published": _iso(item.get("published") or item.get("ts") or ""),
                "source": item.get("source") or engine,
                "engines": [engine], "is_social": bool(platform),
            }
            if isinstance(item.get("meta"), dict):
                rec["meta"] = item["meta"]
            key = _norm_url(url) or ("%s|%s" % (platform, title))
            if key in by_url:
                old = by_url[key]
                if engine not in old["engines"]:
                    old["engines"].append(engine)
                if not old.get("snippet") and rec.get("snippet"):
                    old["snippet"] = rec["snippet"]
                continue
            by_url[key] = rec
            rows.append(rec)
    rows.sort(key=lambda r: (0 if r.get("is_social") else 1,
                             -len(r.get("engines") or []),
                             0 if r.get("url") else 1))
    return rows


def _attach(case_id, payload, user, action, target):
    try:
        db.audit(user, action, (target or "")[:120],
                 "results=%s" % len(payload.get("results") or []))
        if case_id:
            payload["artifact"] = db.store_artifact(
                case_id, None, "social_scrape", "socialscrape:search",
                payload, user)
    except Exception as e:
        payload["artifact_error"] = str(e)[:150]
    return payload


def search(query, platforms=None, region="all", category="all", language=None,
           limit=30, scrape=False, probe=False, case_id=None, user="system",
           engines=None):
    """Broad public social-media search.

    ``platforms`` may be a comma string or list of platform names/domains.
    ``region`` filters the catalog (global platforms are always included).
    ``scrape`` fetches up to five public social result pages.
    ``probe`` also checks the handle across the exact public profile matrix.
    """
    q = (query or "").strip()
    if not q:
        return {"status": "error", "error": "empty query", "results": [],
                "search_links": [], "engines": {}}
    qtype = detect_query_type(q)
    selected = _ordered_platforms(_select_platforms(platforms, region, category), region)
    out = {
        "status": "ok", "query": q, "query_type": qtype,
        "region": region or "all", "category": category or "all",
        "language": language or "",
        "platforms_selected": len(selected),
        "platform_names": [p["name"] for p in selected],
        "coverage": {
            "platforms_selected": len(selected),
            "searchable_selected": sum(1 for p in selected if p["searchable"]),
            "catalog_platforms": len(PLATFORMS),
            "searchable_catalog": sum(1 for p in PLATFORMS if p["searchable"]),
        },
        "engines": {}, "results": [], "search_links": [],
        "profiles": [], "scraped_pages": [],
        "hashtags": [], "mentions": [],
    }
    if not selected:
        out["status"] = "error"
        out["error"] = "no platform matched the selected region/category/platforms"
        return out
    if qtype == "url":
        page = scrape_public_page(q)
        out["page"] = page
        if page.get("status") == "ok":
            out["results"] = [{
                "url": page.get("final_url") or page.get("url"),
                "title": page.get("title") or "",
                "snippet": page.get("description") or "",
                "platform": page.get("platform") or platform_for_url(q),
                "author": page.get("author") or "",
                "published": page.get("published") or "",
                "source": "public_page", "engines": ["public_page"],
                "is_social": bool(page.get("platform")),
                "post_type": page.get("post_type"),
                "images": page.get("images") or [],
            }]
            out["status"] = "ok"
            out["hashtags"] = page.get("hashtags") or []
            out["mentions"] = page.get("mentions") or []
        else:
            out["status"] = page.get("status", "error")
            out["error"] = page.get("error", "page scrape failed")
        out["search_links"] = search_links(q, platforms, region, category)
        out["summary"] = {
            "results": len(out["results"]),
            "search_links": len(out["search_links"]),
            "engines_ok": 0, "engines_blocked": 0,
            "platforms_selected": len(selected),
            "profiles": 0, "scraped_pages": 1 if out.get("results") else 0,
        }
        out["caveat"] = ("Public-page metadata only. A matching profile/post is "
                         "a lead, not identity proof. No login wall or captcha "
                         "bypass.")
        return _attach(case_id, out, user, "socialscrape.page", q)

    domains = []
    for p in selected:
        for d in p["domains"]:
            if d and d not in domains:
                domains.append(d)
    dork_domains = domains[:24]
    site_expr = " OR ".join("site:" + d for d in dork_domains)
    dork = '"%s" (%s)' % (q.replace('"', ""), site_expr) if site_expr else q
    out["dork"] = dork
    out["domains_used"] = dork_domains
    eng = _run_engines(q, dork, selected, engines=engines, region=region)
    out["engines"] = eng
    rows = _normalize_engine_results(eng)
    allowed = {p["name"] for p in selected}
    if platforms:
        rows = [r for r in rows if not r.get("platform") or r["platform"] in allowed]
    out["results"] = rows[:max(1, int(limit or 30))]
    out["search_links"] = search_links(q, platforms, region, category)

    if qtype == "handle" and probe:
        handle = q.lstrip("@")
        if SOCIAL.SAFE_USER_RE.match(handle):
            prof = SOCIAL.check_username(handle)
            out["profiles"] = prof.get("hits") or []
            out["profile_checked"] = prof.get("checked")
            out["profile_coverage"] = prof.get("coverage")
    if qtype == "name":
        out["handle_candidates"] = SOCIAL.handle_candidates(q)
        out["name_variants"] = SOCIAL.name_variants(q)
    if scrape:
        scraped = []
        for row in rows[:5]:
            if row.get("is_social") and row.get("url"):
                scraped.append(scrape_public_page(row["url"]))
        out["scraped_pages"] = scraped

    tags, mentions = [], []
    for row in rows:
        for t in _hashtags(" ".join([row.get("title", ""), row.get("snippet", "")])):
            if t not in tags:
                tags.append(t)
        for m in _mentions(" ".join([row.get("title", ""), row.get("snippet", "")])):
            if m not in mentions:
                mentions.append(m)
    out["hashtags"] = tags[:50]
    out["mentions"] = mentions[:50]

    statuses = [v.get("status") for v in eng.values() if isinstance(v, dict)]
    ok_engines = statuses.count("ok")
    blocked = sum(1 for s in statuses if s == "blocked")
    if out["results"]:
        out["status"] = "ok" if ok_engines else "partial"
    elif ok_engines:
        out["status"] = "empty"
        out["note"] = "engines returned no public results"
    elif blocked:
        out["status"] = "blocked"
        out["note"] = ("all tested engines were login/anti-bot/rate-limit blocked; "
                       "use the platform search links or an exact public profile URL")
    else:
        out["status"] = "error"
        out["note"] = "engines unavailable or returned no parsable results"
    out["summary"] = {
        "results": len(out["results"]),
        "search_links": len(out["search_links"]),
        "engines_ok": ok_engines,
        "engines_blocked": blocked,
        "platforms_selected": len(selected),
        "profiles": len(out["profiles"]),
        "scraped_pages": len(out["scraped_pages"]),
    }
    out["caveat"] = ("Public-source social discovery only. A matching profile or "
                     "post is a lead, not identity proof. No login walls, private "
                     "groups or captcha bypass.")
    return _attach(case_id, out, user, "socialscrape.search", q)
