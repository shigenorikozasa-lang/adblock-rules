#!/usr/bin/env python3
"""
ADBlock Rules Auto-Generator
毎週自動実行され、最新の日本のオープンソース広告リストを収集・最適化し、
Safari Content Blocker 形式の blockerList.json を生成します。
"""

import urllib.request
import re
import json
import os
import sys

print("=== Starting ADBlock Rule Generation ===")

# 信頼できる公開フィルターリスト（EasyList Japan / AdGuard Japanese 等）
UPSTREAM_URLS = [
    "https://raw.githubusercontent.com/k2jp/abp-japanese-filters/master/abp_jp.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt"
]

domains = set()
css_selectors = set()

# 国内で絶対に外せない主要アドネットワーク・DSP・SSP
GUARANTEED_DOMAINS = [
    # Google
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "2mdn.net",
    "adservice.google.com", "pagead2.googlesyndication.com", "securepubads.g.doubleclick.net",
    "ad.doubleclick.net", "static.doubleclick.net", "stats.g.doubleclick.net",
    
    # Yahoo
    "yads.c.yimg.jp", "b92.yahoo.co.jp", "yads.yahoo.co.jp", "ads.yahoo.com",
    "advertising.yahoo.com", "s.yimg.jp/images/listing/tool/yads", "ov.yahoo.co.jp",
    
    # 日本国内ASP・SSP
    "microad.jp", "microad.net", "send.microad.jp", "j.microad.net", "i-mobile.co.jp",
    "spdeliver.i-mobile.co.jp", "spad.i-mobile.co.jp", "nend.net", "output.nend.net",
    "geniee.jp", "geniee.net", "cpt.geniee.jp", "gssprt.jp", "gsspat.jp", "fluct.jp",
    "sh.adingo.jp", "an.adingo.jp", "adingo.jp", "zucks.net", "j.zucks.net.zimg.jp",
    "zucks.net.zimg.jp", "amoad.com", "j.amoad.com", "ad-stir.com", "js.ad-stir.com",
    "so-netmedia.jp", "uncn.jp", "as.uncn.jp", "enhance.co.jp", "rise.enhance.co.jp",
    "gmossp-sp.jp", "adtown.jp", "fout.jp", "js.fout.jp", "cnt.fout.jp", "mediba.jp",
    "socdm.com", "popin.cc", "api.popin.cc", "logly.co.jp", "uzou.me", "adcolony.com",
    "ad-v.jp", "untd.jp", "im-apps.net", "cirqua.jp", "bypass.ad-stir.com",
    "ad-matrix.jp", "bypass.jp", "smart-c.jp", "appdriver.jp", "accesstrade.net",
    "a8.net", "valuecommerce.com", "rentracks.jp", "felmat.net", "link-a.net",
    
    # 海外主要アドネットワーク
    # 海外主要アドネットワーク & ポップアップ/ポップアンダー/リダイレクト広告
    "criteo.com", "criteo.net", "static.criteo.net", "outbrain.com", "taboola.com",
    "adnxs.com", "rubiconproject.com", "pubmatic.com", "openx.net", "smartadserver.com",
    "amazon-adsystem.com", "aax.amazon-adsystem.com", "adform.net", "adroll.com",
    "bidswitch.net", "indexexchange.com", "media.net", "infolinks.com", "sovrn.com",
    "revcontent.com", "mgid.com", "popads.net", "popcash.net", "exoclick.com", "exosrv.com",
    "trafficjunky.com", "adsterra.com", "propellerads.com", "juicyads.com", "clickadu.com",
    "hilltopads.com", "monetag.com", "admaven.com", "ad-maven.com", "richpush.co",
    "rollerads.com", "trafficfactory.biz", "adcash.com", "ad-cash.com", "yllix.com",
    "zeroredirect.com", "onclickalgo.com", "onclickperformance.com", "smartclick.net",
    "inmobi.com", "unityads.unity3d.com", "ironsrc.com", "vungle.com", "chartboost.com",
    "tapjoy.com", "applovin.com", "applvn.com", "mintegral.com", "pangle.io",
    
    # トラッカー
    "scorecardresearch.com", "quantserve.com", "chartbeat.com", "clarity.ms",
    "hotjar.com", "mixpanel.com", "segment.io", "amplitude.com", "userlocal.jp",
    "ptengine.jp", "privacymanager.io", "ats-wrapper.privacymanager.io", "flux-cdn.com",
    "html-load.com",
    
    # 汎用アンチ・アドブロック検知サービス (予防遮断)
    "getadmiral.com", "admiral.com", "adrecover.com", "blockadblock.com",
    "antiadblock.org", "antiblock.org", "detectadblock.com", "adblockdetector.com",
    "adunlock.com", "instartlogic.com", "pagefair.com", "pagefair.net",
    "adblockanalytics.com", "adblock-checker.com", "antiadblocksystems.com"
]

for d in GUARANTEED_DOMAINS:
    domains.add(d)

for url in UPSTREAM_URLS:
    try:
        print(f"Fetching from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("!") or line.startswith("["):
                    continue
                
                # ドメインブロックルール (||example.com^)
                m = re.match(r"^\|\|([a-zA-Z0-9\.\-\_]+)\^", line)
                if m:
                    domain = m.group(1).lower()
                    if "." in domain and not domain.endswith(".jp") and len(domain) > 4:
                        domains.add(domain)
                    elif domain.endswith(".jp") or domain.endswith(".com") or domain.endswith(".net"):
                        domains.add(domain)
                
                # CSS 非表示ルール (##selector)
                if line.startswith("##"):
                    sel = line[2:].strip()
                    # 検索窓や通常UIを巻き込まない安全フィルター
                    if any(bad in sel for bad in ["*=", ":has", ":not", "body", "html", "main", "header", "nav", "article", "div"]):
                        continue
                    if len(sel) > 3 and (sel.startswith(".") or sel.startswith("#")):
                        if any(k in sel for k in ["ad", "banner", "sponsor", "pr", "yads", "dfp", "advert"]):
                            css_selectors.add(sel)
    except Exception as e:
        print(f"Warning: Failed to fetch {url}: {e}")

# 誤爆防止済みの安全な基本CSSルール
BASE_CSS = [
    "ins.adsbygoogle", "div.adsbygoogle", "[data-ad-client]", "[data-ad-slot]",
    "[data-ad-unit]", "[data-google-query-id]", "iframe[id^=\"google_ads_\"]",
    "iframe[name^=\"google_ads_\"]", "div[id^=\"google_ads_\"]", "div[id^=\"dfp-ad-\"]",
    "div[id^=\"div-gpt-ad-\"]", "[class^=\"ad-\"]", "[class^=\"ad_\"]",
    "[class$=\"-ad\"]", "[class$=\"_ad\"]", "[class~=\"ad\"]", "[class~=\"ads\"]",
    "[id^=\"ad-\"]", "[id^=\"ad_\"]", "[id$=\"-ad\"]", "[id$=\"_ad\"]",
    "[class*=\"advert\"]", "[id*=\"advert\"]", "[class*=\"sponsored\"]", "[id*=\"sponsored\"]",
    "[class*=\"promotion\"]", "[id*=\"promotion\"]", "[class*=\"banner-ad\"]", "[id*=\"banner-ad\"]",
    "[class*=\"ad-banner\"]", "[id*=\"ad-banner\"]", "[class*=\"ad-container\"]", "[id*=\"ad-container\"]",
    "[class*=\"ad-wrapper\"]", "[id*=\"ad-wrapper\"]", "[class*=\"ad-content\"]", "[id*=\"ad-content\"]",
    "[class*=\"ad-space\"]", "[id*=\"ad-space\"]", "[class*=\"ad-slot\"]", "[id*=\"ad-slot\"]",
    "[class*=\"ad-unit\"]", "[id*=\"ad-unit\"]", "[class*=\"ad-area\"]", "[id*=\"ad-area\"]",
    "[class*=\"ad-box\"]", "[id*=\"ad-box\"]", "[class*=\"ad-ranking\"]",
    "[class*=\"sticky-ad\"]", "[id*=\"sticky-ad\"]", "[class*=\"floating-ad\"]", "[id*=\"floating-ad\"]",
    "[class*=\"interstitial-ad\"]", "[id*=\"interstitial-ad\"]", "[class*=\"popup-ad\"]", "[id*=\"popup-ad\"]",
    "[class^=\"pr-box\"]", "[class*=\"pr-area\"]", "[class*=\"pr_area\"]", "[class*=\"pr-item\"]",
    "[class*=\"sponsor-link\"]", "[class*=\"sponsored-link\"]", "#yads", ".yads",
    "[id^=\"yads\"]", "[class^=\"yads\"]", "div[id*=\"yahoo_ad\"]", "div[class*=\"yahoo_ad\"]",
    ".c-sp-leaderboard-ad", ".c-sp-leaderboard-ad-overlay", ".ad-sp-header",
    ".walkthrough-ad-ranking-game", "._native_ad_item", ".dfp-ad-ranking", ".js-gwad",
    "#adinhead", "#addesktopinside", "#admobiletopinside", "#admobilefootinside",
    "#adstripe", "#videotextbanner", "#EPimLayerOuter", "#ifadmiddle", "#ifdeskadmiddle",
    "#adPlayerIfr", "#adPlayerIfrMob", "#adnative-1x1-iframe", "#pbwuvpad", ".homeadiframe",
    
    # 汎用アンチ・アドブロック警告・全画面オーバーレイ非表示 (予防処置)
    "[class*=\"adblock-modal\"]", "[id*=\"adblock-modal\"]",
    "[class*=\"adblock-overlay\"]", "[id*=\"adblock-overlay\"]",
    "[class*=\"adblock-warning\"]", "[id*=\"adblock-warning\"]",
    "[class*=\"adblock-notice\"]", "[id*=\"adblock-notice\"]",
    "[class*=\"adblock-popup\"]", "[id*=\"adblock-popup\"]",
    "[class*=\"adblock-message\"]", "[id*=\"adblock-message\"]",
    ".ab-message", ".ab-modal", ".ab-overlay", "#ab-modal", "#ab-overlay",
    ".advertisement-blocker-warning", ".ad-blocker-notice", ".sp-ab-banner", ".ab-banner",
    ".visitors-agreement-modal", "#agreement-root",
    
    # 動画プレイヤー上・クリックジャック透明レイヤー・フッター追従動画広告の除去
    "[class*=\"player-overlay-ad\"]", "[id*=\"player-overlay-ad\"]",
    "[class*=\"click-trap\"]", "[id*=\"click-trap\"]",
    "[class*=\"overlay-click-ad\"]", "[id*=\"overlay-click-ad\"]",
    "[class*=\"video-ad-overlay\"]", "[id*=\"video-ad-overlay\"]",
    "[class*=\"vjs-overlay-ad\"]", "[class*=\"jw-overlay-ad\"]",
    "div[id^=\"player_overlay_ad\"]", "div[class^=\"player_overlay_ad\"]",
    "div[id^=\"ads-ADU-\"]", "div[id^=\"ad-ADU-\"]",
    "div[class*=\"floating-video\"]", "div[id*=\"floating-video\"]",
    "div[class*=\"sp-footer-ad\"]", "div[id*=\"sp-footer-ad\"]",
    "div[class*=\"footer-ad\"]", "div[id*=\"footer-ad\"]",
    "div[class*=\"sticky-footer-ad\"]", "div[id*=\"sticky-footer-ad\"]",
    "#admobileoutstream", "#ifadoutstream",
    
    # GameWith トップページ・フッター固定PRバナー・ジャック広告・おすすめPR
    ".gdb-ad-footer-creative", ".gwt-ad-footer-creative",
    ".gwt-ad-ranking-recommend", ".gdb-ranking-slider.is-pr",
    ".js-jack-ad", ".gwt-jack-ad", ".gdb-feature_tile-item.is-pr",
    "div[class*=\"gdb-ad-footer\"]", "div[class*=\"gwt-ad-footer\"]",
    "a[class*=\"gdb-ad-footer\"]", "a[class*=\"gwt-ad-footer\"]",
    "img[src*=\"/ad/gamedboverlay/\"]",
    "img[src*=\"/ad/rankingrecommend/\"]",
    "img[src*=\"/gamedb/autopanel/\"]",
    "a[href*=\"onelink.me\"]",
    "[gtm-ga4-module-type*=\"オーバーレイ\"]",
    "[gtm-ga4-module-type*=\"ランキング広告\"]",
    "[gtm-ga4-module-type*=\"ジャックパネル\"]",
    "[gtm-action-name*=\"オーバーレイ\"]",
    "[gtm-action-name*=\"ランキング広告\"]"
]

all_css = sorted(list(set(BASE_CSS + list(css_selectors)[:200])))

final_rules = []

# 1. CSS 非表示ルール
for sel in all_css:
    final_rules.append({
        "action": {"type": "css-display-none", "selector": sel},
        "trigger": {"url-filter": ".*"}
    })

# 2. ネットワーク遮断ルール（上位3,000ドメイン）
sorted_domains = sorted(list(domains), key=lambda x: (x not in GUARANTEED_DOMAINS, len(x)))
for d in sorted_domains[:3000]:
    escaped = re.escape(d)
    final_rules.append({
        "action": {"type": "block"},
        "trigger": {
            "url-filter": f"^https?://+([^:/]+\\.)?{escaped}[:/]",
            "load-type": ["third-party"]
        }
    })

# 3. 特定サイトの広告初期化スクリプトおよびアンチアドブロック妨害の完全遮断 (ファーストパーティ含む)
custom_blocked_urls = [
    # GameWith 自社広告配信スクリプト (フッター追従・動画広告初期化)
    r"^https?://+([^:/]+\\.)?assets\\.gamewith\\.jp/js/dist/jp/gamewith/ad/.*",
    r"^https?://+([^:/]+\\.)?rise\\.enhance\\.co\\.jp/.*",
    r"^https?://+([^:/]+\\.)?flux-cdn\\.com/.*",
    
    # EPORNER アンチアドブロック妨害
    r"^https?://+([^:/]+\\.)?eporner\\.com/getadb/.*",
    r"^https?://+([^:/]+\\.)?eporner\\.com/getadb.*",
    r"^https?://+([^:/]+\\.)?eporner\\.com/dot/.*",
    r"^https?://+([^:/]+\\.)?eporner\\.com/adCounter/.*"
]

for url_pat in custom_blocked_urls:
    final_rules.append({
        "action": {"type": "block"},
        "trigger": {
            "url-filter": url_pat
        }
    })

# 4. トラッキングCookie遮断
final_rules.append({
    "action": {"type": "block-cookies"},
    "trigger": {
        "url-filter": ".*",
        "load-type": ["third-party"]
    }
})

# 出力先パスの決定（リポジトリルートとExtensionフォルダ両方に出力）
script_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.dirname(script_dir)

output_paths = [
    os.path.join(repo_root, "blockerList.json"),
    os.path.join(repo_root, "ADBlock", "ContentBlockerExtension", "blockerList.json")
]

for out_path in output_paths:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(final_rules, f, indent=2, ensure_ascii=False)
    print(f"Saved: {out_path}")

print(f"=== Successfully Generated {len(final_rules)} Rules! ===")
