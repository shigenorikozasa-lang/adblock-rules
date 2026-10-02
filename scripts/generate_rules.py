#!/usr/bin/env python3
"""
ADBlock Rules Auto-Generator v2.0 — 完全自律メンテナンス対応版

毎週自動実行され、複数の上流フィルタリストから最新ルールを収集・差分追跡し、
誤検知防止バリデーションを通過したルールのみ Safari Content Blocker 形式で出力します。

機能:
  1. 上流フィルタリスト差分追跡 (.last_upstream_hashes.json)
  2. 複数の信頼できる上流ソースからの自動収集
  3. セーフリストによる誤検知防止
  4. ルール品質検証（正規表現・CSS・上限チェック）
  5. CHANGELOG.md への変更ログ出力
"""

import urllib.request
import re
import json
import os
import sys
import hashlib
from datetime import datetime, timezone, timedelta

print("=== ADBlock Rule Generation v2.0 開始 ===")

# ────────────────────────────────────────────
# パス設定
# ────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
HASH_FILE = os.path.join(SCRIPT_DIR, ".last_upstream_hashes.json")
CHANGELOG_PATH = os.path.join(REPO_ROOT, "CHANGELOG.md")
OUTPUT_REPO = os.path.join(REPO_ROOT, "blockerList.json")
# ローカル開発時のみ使う Extension パス（GitHub Actions では無視）
OUTPUT_EXT = "/Volumes/BUFFALO SSD/AD block/ADBlock/ContentBlockerExtension/blockerList.json"

# Safari Content Blocker のルール上限
MAX_RULES = 50000

# ────────────────────────────────────────────
# 上流フィルタリスト URL
# ────────────────────────────────────────────
UPSTREAM_URLS = {
    "ABP Japanese Filters": "https://raw.githubusercontent.com/k2jp/abp-japanese-filters/master/abp_jp.txt",
    "AdGuard Japanese": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
    "EasyList": "https://easylist.to/easylist/easylist.txt",
    "EasyPrivacy": "https://easylist.to/easylist/easyprivacy.txt",
    "AdGuard Base": "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "AdGuard Tracking": "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "Peter Lowe's List": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0",
}

# ────────────────────────────────────────────
# 誤検知防止: 絶対にブロックしてはいけないセーフドメイン
# ────────────────────────────────────────────
SAFE_DOMAINS = {
    # 日本の主要サービス
    "google.co.jp", "google.com", "yahoo.co.jp", "amazon.co.jp", "amazon.com",
    "rakuten.co.jp", "rakuten.com", "mercari.com", "zozo.jp", "line.me",
    "gamewith.jp", "nicovideo.jp", "niconico.jp", "dmm.com", "dmm.co.jp",
    "cookpad.com", "tabelog.com", "kakaku.com", "livedoor.com", "fc2.com",
    "naver.jp", "ameblo.jp", "hatena.ne.jp", "note.com", "qiita.com",
    "zenn.dev", "github.com", "github.io", "apple.com", "microsoft.com",
    "nintendo.co.jp", "sony.co.jp", "nhk.or.jp", "weather.yahoo.co.jp",
    # CDN / インフラ
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com",
    "ajax.googleapis.com", "unpkg.com", "stackpath.bootstrapcdn.com",
    "cloudflare.com", "akamai.net", "akamaized.net", "fastly.net",
    "googleapis.com", "gstatic.com",
    # SNS
    "twitter.com", "x.com", "facebook.com", "instagram.com", "youtube.com",
    "tiktok.com", "reddit.com", "linkedin.com", "pinterest.com",
    "threads.net", "bsky.app",
    # メール / 通信
    "gmail.com", "outlook.com", "icloud.com",
    # 決済
    "stripe.com", "paypal.com", "pay.jp",
}

# ────────────────────────────────────────────
# 国内で絶対に外せない主要アドネットワーク
# ────────────────────────────────────────────
GUARANTEED_DOMAINS = [
    # Google 広告
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "2mdn.net",
    "adservice.google.com", "pagead2.googlesyndication.com", "securepubads.g.doubleclick.net",
    "ad.doubleclick.net", "static.doubleclick.net", "stats.g.doubleclick.net",
    # Yahoo 広告
    "yads.c.yimg.jp", "b92.yahoo.co.jp", "yads.yahoo.co.jp", "ads.yahoo.com",
    "advertising.yahoo.com", "ov.yahoo.co.jp",
    # 日本国内 ASP・SSP
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
    # 海外主要アドネットワーク & ポップアップ/リダイレクト広告
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
    "html-load.com", "onelink.me",
    # アンチ・アドブロック検知サービス
    "getadmiral.com", "admiral.com", "adrecover.com", "blockadblock.com",
    "antiadblock.org", "antiblock.org", "detectadblock.com", "adblockdetector.com",
    "adunlock.com", "instartlogic.com", "pagefair.com", "pagefair.net",
    "adblockanalytics.com", "adblock-checker.com", "antiadblocksystems.com", "ad-shield.io",
]

# ────────────────────────────────────────────
# 誤爆防止済みの安全な基本CSSルール
# ────────────────────────────────────────────
BASE_CSS = [
    "ins.adsbygoogle", "div.adsbygoogle", "[data-ad-client]", "[data-ad-slot]",
    "[data-ad-unit]", "[data-google-query-id]", 'iframe[id^="google_ads_"]',
    'iframe[name^="google_ads_"]', 'div[id^="google_ads_"]', 'div[id^="dfp-ad-"]',
    'div[id^="div-gpt-ad-"]', '[class^="ad-"]', '[class^="ad_"]',
    '[class$="-ad"]', '[class$="_ad"]', '[class~="ad"]', '[class~="ads"]',
    '[id^="ad-"]', '[id^="ad_"]', '[id$="-ad"]', '[id$="_ad"]',
    '[class*="advert"]', '[id*="advert"]', '[class*="sponsored"]', '[id*="sponsored"]',
    '[class*="promotion"]', '[id*="promotion"]', '[class*="banner-ad"]', '[id*="banner-ad"]',
    '[class*="ad-banner"]', '[id*="ad-banner"]', '[class*="ad-container"]', '[id*="ad-container"]',
    '[class*="ad-wrapper"]', '[id*="ad-wrapper"]', '[class*="ad-content"]', '[id*="ad-content"]',
    '[class*="ad-space"]', '[id*="ad-space"]', '[class*="ad-slot"]', '[id*="ad-slot"]',
    '[class*="ad-unit"]', '[id*="ad-unit"]', '[class*="ad-area"]', '[id*="ad-area"]',
    '[class*="ad-box"]', '[id*="ad-box"]', '[class*="ad-ranking"]',
    '[class*="sticky-ad"]', '[id*="sticky-ad"]', '[class*="floating-ad"]', '[id*="floating-ad"]',
    '[class*="interstitial-ad"]', '[id*="interstitial-ad"]', '[class*="popup-ad"]', '[id*="popup-ad"]',
    '[class^="pr-box"]', '[class*="pr-area"]', '[class*="pr_area"]', '[class*="pr-item"]',
    '[class*="sponsor-link"]', '[class*="sponsored-link"]', "#yads", ".yads",
    '[id^="yads"]', '[class^="yads"]', 'div[id*="yahoo_ad"]', 'div[class*="yahoo_ad"]',
    ".c-sp-leaderboard-ad", ".c-sp-leaderboard-ad-overlay", ".ad-sp-header",
    ".walkthrough-ad-ranking-game", "._native_ad_item", ".dfp-ad-ranking", ".js-gwad",
    "#adinhead", "#addesktopinside", "#admobiletopinside", "#admobilefootinside",
    "#adstripe", "#videotextbanner", "#EPimLayerOuter", "#ifadmiddle", "#ifdeskadmiddle",
    "#adPlayerIfr", "#adPlayerIfrMob", "#adnative-1x1-iframe", "#pbwuvpad", ".homeadiframe",
    # アンチ・アドブロック警告・オーバーレイ非表示
    '[class*="adblock-modal"]', '[id*="adblock-modal"]',
    '[class*="adblock-overlay"]', '[id*="adblock-overlay"]',
    '[class*="adblock-warning"]', '[id*="adblock-warning"]',
    '[class*="adblock-notice"]', '[id*="adblock-notice"]',
    '[class*="adblock-popup"]', '[id*="adblock-popup"]',
    '[class*="adblock-message"]', '[id*="adblock-message"]',
    ".ab-message", ".ab-modal", ".ab-overlay", "#ab-modal", "#ab-overlay",
    ".advertisement-blocker-warning", ".ad-blocker-notice", ".sp-ab-banner", ".ab-banner",
    ".visitors-agreement-modal", "#agreement-root",
    # 動画プレイヤー上・クリックジャック・フッター追従広告
    '[class*="player-overlay-ad"]', '[id*="player-overlay-ad"]',
    '[class*="click-trap"]', '[id*="click-trap"]',
    '[class*="overlay-click-ad"]', '[id*="overlay-click-ad"]',
    '[class*="video-ad-overlay"]', '[id*="video-ad-overlay"]',
    '[class*="vjs-overlay-ad"]', '[class*="jw-overlay-ad"]',
    'div[id^="player_overlay_ad"]', 'div[class^="player_overlay_ad"]',
    'div[id^="ads-ADU-"]', 'div[id^="ad-ADU-"]',
    'div[class*="floating-video"]', 'div[id*="floating-video"]',
    'div[class*="sp-footer-ad"]', 'div[id*="sp-footer-ad"]',
    'div[class*="footer-ad"]', 'div[id*="footer-ad"]',
    'div[class*="sticky-footer-ad"]', 'div[id*="sticky-footer-ad"]',
    "#admobileoutstream", "#ifadoutstream",
    # GameWith 固有
    ".gdb-ad-footer-creative", ".gwt-ad-footer-creative",
    ".gwt-ad-ranking-recommend", ".gdb-ranking-slider.is-pr",
    ".js-jack-ad", ".gwt-jack-ad", ".gdb-feature_tile-item.is-pr",
    'div[class*="gdb-ad-footer"]', 'div[class*="gwt-ad-footer"]',
    'a[class*="gdb-ad-footer"]', 'a[class*="gwt-ad-footer"]',
    ".c-floating-ad", ".c-floating-ad-overlay",
    'img[src*="/ad/gamedboverlay/"]',
    'img[src*="/ad/rankingrecommend/"]',
    'a[href*="onelink.me"]',
    'a[href*="eggryptox"]',
    "div._rank.is-pr",
    '[gtm-ga4-module-type*="オーバーレイ"]',
    '[gtm-ga4-module-type*="人気ランキング広告"]',
    '[gtm-ga4-module-type*="ジャックパネル"]',
    '[gtm-action-name*="オーバーレイ"]',
    '[gtm-action-name*="ランキング広告"]',
    "#skyflag_link",
]

# ────────────────────────────────────────────
# ユーティリティ関数
# ────────────────────────────────────────────

def is_safe_domain(domain):
    """セーフリストに含まれるドメインまたはそのサブドメインかどうかチェック"""
    for safe in SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return True
    return False


def is_valid_domain(domain):
    """ドメインが妥当かチェック（短すぎ・セーフリスト・形式異常を排除）"""
    if not domain or len(domain) < 5:
        return False
    if is_safe_domain(domain):
        return False
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+\.[a-zA-Z]{2,}$', domain):
        return False
    # TLD 前のラベルが2文字未満は危険（誤爆リスク高）
    parts = domain.split(".")
    if len(parts) >= 2 and len(parts[-2]) < 2:
        return False
    return True


def validate_regex(pattern):
    """url-filter の正規表現が有効かチェック"""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def is_safe_css_selector(sel):
    """CSSセレクタが安全か（ページ破壊リスクがないか）チェック"""
    dangerous = ["*=", ":not", "body", "html", "main", "header", "nav",
                 "article", "div >", "section", "footer > ", ":first-child",
                 ":nth-child", "autopanel"]
    for d in dangerous:
        if d in sel:
            return False
    if len(sel) < 3:
        return False
    return True


def load_previous_hashes():
    """前回の上流ハッシュを読み込み"""
    if os.path.exists(HASH_FILE):
        try:
            with open(HASH_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_current_hashes(hashes):
    """今回の上流ハッシュを保存"""
    os.makedirs(os.path.dirname(HASH_FILE), exist_ok=True)
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=2, ensure_ascii=False)


def load_previous_rule_count():
    """前回の blockerList.json のルール数を取得"""
    if os.path.exists(OUTPUT_REPO):
        try:
            with open(OUTPUT_REPO, "r") as f:
                data = json.load(f)
                return len(data)
        except (json.JSONDecodeError, IOError):
            pass
    return 0


def fetch_url(url, name):
    """URLからコンテンツを取得"""
    try:
        print(f"  取得中: {name} ({url[:60]}...)")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 ADBlock/2.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"  ⚠ 取得失敗: {name}: {e}")
        return None


# ────────────────────────────────────────────
# メイン処理
# ────────────────────────────────────────────

# 前回のハッシュと比較用データ
prev_hashes = load_previous_hashes()
prev_rule_count = load_previous_rule_count()
current_hashes = {}
fetch_results = {}  # ソース名 → "成功" / "失敗"

domains = set()
css_selectors = set()

# 保証ドメインを追加
for d in GUARANTEED_DOMAINS:
    domains.add(d)

# 上流フィルタリストからルール収集
print("\n[1/5] 上流フィルタリストを取得...")
new_domains_from_upstream = set()

for name, url in UPSTREAM_URLS.items():
    content = fetch_url(url, name)
    if content is None:
        fetch_results[name] = "❌ 失敗"
        continue

    fetch_results[name] = "✅ 成功"
    content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
    current_hashes[name] = content_hash

    is_updated = prev_hashes.get(name) != content_hash
    if is_updated:
        print(f"  📦 {name}: 更新あり (ハッシュ変化)")
    else:
        print(f"  ✓ {name}: 変更なし")

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("[") or line.startswith("#"):
            continue

        # ドメインブロックルール (||example.com^)
        m = re.match(r"^\|\|([a-zA-Z0-9\.\-\_]+)\^", line)
        if m:
            domain = m.group(1).lower()
            if is_valid_domain(domain):
                if domain not in domains and is_updated:
                    new_domains_from_upstream.add(domain)
                domains.add(domain)

        # ホストファイル形式 (0.0.0.0 example.com / 127.0.0.1 example.com)
        m2 = re.match(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9\.\-\_]+)", line)
        if m2:
            domain = m2.group(1).lower()
            if is_valid_domain(domain):
                if domain not in domains and is_updated:
                    new_domains_from_upstream.add(domain)
                domains.add(domain)

        # CSS 非表示ルール (##selector)
        if line.startswith("##"):
            sel = line[2:].strip()
            if is_safe_css_selector(sel):
                if len(sel) > 3 and (sel.startswith(".") or sel.startswith("#") or sel.startswith("[") or sel.startswith("ins")):
                    if any(k in sel.lower() for k in ["ad", "banner", "sponsor", "pr", "yads", "dfp", "advert", "jack", "ranking"]):
                        css_selectors.add(sel)

# ハッシュ保存
save_current_hashes(current_hashes)

# ────────────────────────────────────────────
# ルール組み立て
# ────────────────────────────────────────────
print(f"\n[2/5] ルール組み立て中...")
print(f"  収集ドメイン数: {len(domains)}")
print(f"  収集CSSセレクタ数: {len(css_selectors)}")

all_css = sorted(list(set(BASE_CSS + list(css_selectors)[:500])))
final_rules = []
invalid_count = 0

# 1. CSS 非表示ルール
for sel in all_css:
    final_rules.append({
        "action": {"type": "css-display-none", "selector": sel},
        "trigger": {"url-filter": ".*"}
    })

# 2. ネットワーク遮断ルール
sorted_domains = sorted(list(domains), key=lambda x: (x not in GUARANTEED_DOMAINS, len(x)))
for d in sorted_domains[:5000]:
    escaped = re.escape(d)
    url_filter = f"^https?://+([^:/]+\\.)?{escaped}[:/]"
    if validate_regex(url_filter):
        final_rules.append({
            "action": {"type": "block"},
            "trigger": {
                "url-filter": url_filter,
                "load-type": ["third-party"]
            }
        })
    else:
        invalid_count += 1

# 3. カスタムブロック URL パターン（ファーストパーティ含む）
custom_blocked_urls = [
    r"^https?://+([^:/]+\.)?assets\.gamewith\.jp/js/dist/jp/gamewith/ad/.*",
    r"^https?://+([^:/]+\.)?img\.gamewith\.jp/ad/.*",
    r"^https?://+([^:/]+\.)?rise\.enhance\.co\.jp/.*",
    r"^https?://+([^:/]+\.)?flux-cdn\.com/.*",
    r"^https?://+([^:/]+\.)?ats-wrapper\.privacymanager\.io/.*",
    r"^https?://+([^:/]+\.)?.*\.onelink\.me/.*",
    r"^https?://+([^:/]+\.)?eporner\.com/getadb/.*",
    r"^https?://+([^:/]+\.)?eporner\.com/getadb.*",
    r"^https?://+([^:/]+\.)?eporner\.com/dot/.*",
    r"^https?://+([^:/]+\.)?eporner\.com/adCounter/.*",
]

for url_pat in custom_blocked_urls:
    if validate_regex(url_pat):
        final_rules.append({
            "action": {"type": "block"},
            "trigger": {"url-filter": url_pat}
        })

# 4. サードパーティCookie遮断
final_rules.append({
    "action": {"type": "block-cookies"},
    "trigger": {
        "url-filter": ".*",
        "load-type": ["third-party"]
    }
})

# ────────────────────────────────────────────
# ルール品質検証
# ────────────────────────────────────────────
print(f"\n[3/5] ルール品質検証...")

# 重複排除
seen = set()
deduped_rules = []
for rule in final_rules:
    key = json.dumps(rule, sort_keys=True, ensure_ascii=False)
    if key not in seen:
        seen.add(key)
        deduped_rules.append(rule)
final_rules = deduped_rules

# 上限チェック
if len(final_rules) > MAX_RULES:
    print(f"  ⚠ ルール数が上限超過 ({len(final_rules)} > {MAX_RULES})、切り詰めます")
    final_rules = final_rules[:MAX_RULES]

# 前回比での急激な減少チェック（50%以上減少 → 異常の可能性）
if prev_rule_count > 0:
    decrease_ratio = (prev_rule_count - len(final_rules)) / prev_rule_count
    if decrease_ratio > 0.5:
        print(f"  🚨 警告: ルール数が前回 ({prev_rule_count}) から 50% 以上減少 ({len(final_rules)})")
        print(f"  上流ソースの障害の可能性があります。処理は継続しますがログに記録します。")

print(f"  ✅ 最終ルール数: {len(final_rules)} (重複排除済み, 無効パターン: {invalid_count}件除外)")

# ────────────────────────────────────────────
# ファイル出力
# ────────────────────────────────────────────
print(f"\n[4/5] ファイル出力...")

# リポジトリルートに出力
os.makedirs(os.path.dirname(OUTPUT_REPO), exist_ok=True)
with open(OUTPUT_REPO, "w", encoding="utf-8") as f:
    json.dump(final_rules, f, indent=2, ensure_ascii=False)
print(f"  保存: {OUTPUT_REPO}")

# ローカル Extension パスに出力（存在する場合のみ）
ext_dir = os.path.dirname(OUTPUT_EXT)
if os.path.isdir(ext_dir):
    with open(OUTPUT_EXT, "w", encoding="utf-8") as f:
        json.dump(final_rules, f, indent=2, ensure_ascii=False)
    print(f"  保存: {OUTPUT_EXT}")
else:
    print(f"  スキップ: Extension パスが存在しません（GitHub Actions環境）")

# ────────────────────────────────────────────
# CHANGELOG.md 生成
# ────────────────────────────────────────────
print(f"\n[5/5] CHANGELOG.md 生成...")

jst = timezone(timedelta(hours=9))
now = datetime.now(jst).strftime("%Y-%m-%d %H:%M JST")

new_count = len(final_rules) - prev_rule_count if prev_rule_count > 0 else 0
upstream_summary = "\n".join([f"  - {name}: {status}" for name, status in fetch_results.items()])
new_domains_list = sorted(list(new_domains_from_upstream))[:50]  # 上位50件のみ表示
new_domains_text = "\n".join([f"  - `{d}`" for d in new_domains_list]) if new_domains_list else "  - なし"

changelog_entry = f"""# ADBlock ルール更新ログ

## 最終更新: {now}

### 📊 統計
| 項目 | 値 |
|---|---|
| 総ルール数 | {len(final_rules)} |
| 前回からの増減 | {'+' if new_count >= 0 else ''}{new_count} |
| 収集ドメイン数 | {len(domains)} |
| CSSセレクタ数 | {len(all_css)} |
| 無効パターン除外数 | {invalid_count} |

### 🌐 上流ソース取得結果
{upstream_summary}

### 🆕 新規検出ドメイン（上位50件）
{new_domains_text}

### ℹ️ 備考
- セーフリスト: {len(SAFE_DOMAINS)} ドメインを誤検知防止のため保護
- 保証ドメイン: {len(GUARANTEED_DOMAINS)} ドメインを常時ブロック
- Safari Content Blocker 上限: {MAX_RULES} ルール
"""

with open(CHANGELOG_PATH, "w", encoding="utf-8") as f:
    f.write(changelog_entry)
print(f"  保存: {CHANGELOG_PATH}")

print(f"\n=== ルール生成完了！ 合計 {len(final_rules)} ルール ===")
