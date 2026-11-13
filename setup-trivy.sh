#!/usr/bin/env bash
# VM 用 Trivy 定期スキャン + Discord 通知のセットアップスクリプト（Ubuntu 専用）
#
# 使い方:
#   curl -fsSL https://raw.githubusercontent.com/mitunaga870/tois-trivy/main/setup-trivy.sh | sudo bash
#     → 実行中に Discord Webhook URL を入力する（コマンド履歴に残らない）
#
#   引数で渡す:   ... | sudo bash -s -- 'https://discord.com/api/webhooks/...'
#   環境変数で渡す: ... | sudo TRIVY_WEBHOOK_URL='https://...' bash   （Ansible 向け）
#
# 再実行すると Trivy・スクリプト・systemd 設定を上書き更新する。
# Webhook URL を指定しなければ、既存の設定を引き継ぐ。
set -euo pipefail

# 導入する Trivy のバージョンと .deb の SHA256（2026年3月のサプライチェーン攻撃を受けて中身ごと固定する）
# 更新時は、新しいリリースの checksums.txt を cosign で署名検証してから両方を書き換える
TRIVY_VERSION="0.76.1"
TRIVY_DEB_SHA256="3350f4fac96ed099590c4a353bddb226f86311a0a2e7a8c626c162790d947f10"

CONF_DIR=/etc/trivy-scan
ENV_FILE=$CONF_DIR/env
SCAN_BIN=/usr/local/bin/trivy-scan.sh
UNIT_DIR=/etc/systemd/system
DEB_NAME=trivy_${TRIVY_VERSION}_Linux-64bit.deb
DEB_URL=https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${DEB_NAME}

# root 権限の確認
if [[ $EUID -ne 0 ]]; then
  echo "root で実行してください（sudo bash ...）" >&2
  exit 1
fi

# Ubuntu 以外は対象外
if ! grep -qi '^ID=ubuntu' /etc/os-release; then
  echo "このスクリプトは Ubuntu 専用です" >&2
  exit 1
fi

# ハッシュを固定しているのは amd64 の .deb のみ
if [[ $(dpkg --print-architecture) != amd64 ]]; then
  echo "amd64 以外には対応していません" >&2
  exit 1
fi

# Webhook URL の取得（引数 → 環境変数 → 既存設定 → 対話入力の順）
WEBHOOK_URL="${1:-${TRIVY_WEBHOOK_URL:-}}"
if [[ -z $WEBHOOK_URL && -f $ENV_FILE ]]; then
  WEBHOOK_URL=$(sed -n 's/^WEBHOOK_URL=//p' "$ENV_FILE")
fi
if [[ -z $WEBHOOK_URL ]]; then
  # curl | bash では標準入力がスクリプト本体なので、端末から直接読む
  read -rsp "Discord Webhook URL: " WEBHOOK_URL </dev/tty
  echo
fi

# Webhook URL の形式確認
if [[ ! $WEBHOOK_URL =~ ^https://(discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+$ ]]; then
  echo "Discord Webhook URL の形式ではありません" >&2
  exit 1
fi

# 必要なパッケージの導入
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl jq ca-certificates >/dev/null

# GitHub Releases から .deb を取得
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL -o "$TMP_DIR/$DEB_NAME" "$DEB_URL"

# SHA256 が一致しなければ中止（配布元が改ざんされていても入れない）
if ! echo "$TRIVY_DEB_SHA256  $TMP_DIR/$DEB_NAME" | sha256sum -c --quiet -; then
  echo "SHA256 が一致しません。改ざんの可能性があるため中止します" >&2
  exit 1
fi

# Trivy を導入し、apt で勝手に上がらないよう固定する
apt-mark unhold trivy >/dev/null 2>&1 || true
dpkg -i "$TMP_DIR/$DEB_NAME" >/dev/null
apt-mark hold trivy >/dev/null
echo "trivy $(trivy --version | sed -n 's/^Version: //p') を導入しました"

# Webhook URL の保存（root のみ読める）
install -d -m 700 "$CONF_DIR"
umask 077
printf 'WEBHOOK_URL=%s\n' "$WEBHOOK_URL" >"$ENV_FILE"
chmod 600 "$ENV_FILE"
umask 022

# スキャン本体の配置
cat >"$SCAN_BIN" <<'SCAN'
#!/usr/bin/env bash
# Trivy でホストと稼働中のコンテナイメージをスキャンし、Discord に要約を送る
set -uo pipefail

ENV_FILE=/etc/trivy-scan/env
DATA_DIR=/var/lib/trivy-scan
CACHE_DIR=/var/cache/trivy
RETENTION_DAYS=14
# Discord の添付上限（10MB）より少し小さくしておく
MAX_ATTACH_BYTES=$((9 * 1024 * 1024))

# Webhook URL の読み込み
WEBHOOK_URL=$(sed -n 's/^WEBHOOK_URL=//p' "$ENV_FILE")
if [[ -z $WEBHOOK_URL ]]; then
  echo "Webhook URL が設定されていません: $ENV_FILE" >&2
  exit 1
fi

HOST=$(hostname)
STAMP=$(date +%Y%m%d-%H%M%S)
RUN_DIR=$DATA_DIR/$STAMP
mkdir -p "$RUN_DIR" "$CACHE_DIR"

results=()
errors=()

# 共通オプション（脆弱性のみ。シークレット検出は結果に秘密情報が載るので使わない）
common=(--cache-dir "$CACHE_DIR" --scanners vuln --severity "CRITICAL,HIGH"
        --format json --quiet --timeout 30m)

# ホストのファイルシステムをスキャン（DB もここで更新する）
if trivy rootfs "${common[@]}" \
    --skip-dirs /proc,/sys,/dev,/run,/var/lib/docker,/var/lib/containerd,/snap,"$DATA_DIR","$CACHE_DIR" \
    --output "$RUN_DIR/host.json" /; then
  results+=("$RUN_DIR/host.json")
else
  errors+=("ホスト")
fi

# 稼働中のコンテナイメージをスキャン（Docker が動いている VM のみ）
if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
  i=0
  while IFS=$'\t' read -r image cname; do
    [[ -z $image ]] && continue
    i=$((i + 1))
    out=$RUN_DIR/image-$i.json

    # タグが外れて ID だけになったイメージは、コンテナ名を添えて見分けられるようにする
    label=$image
    if [[ $image =~ ^(sha256:)?[0-9a-f]{12,}$ ]]; then
      label="${image#sha256:}"
      label="${label:0:12}（$cname）"
    fi

    if trivy image "${common[@]}" --skip-db-update --output "$out" "$image"; then
      jq --arg l "$label" '. + {Label: $l}' "$out" >"$out.tmp" && mv "$out.tmp" "$out"
      results+=("$out")
    else
      errors+=("$label")
    fi
  done < <(docker ps --format '{{.Image}}\t{{.Names}}' | sort -u -t $'\t' -k1,1)
fi

# Discord 用の要約を作成
if ((${#results[@]} > 0)); then
  msg=$(jq -rs --arg host "$HOST" --arg date "$(date '+%Y-%m-%d %H:%M')" '
    # 検出場所をプロジェクト単位にまとめる（OS パッケージは 1 つに集約）
    def loc($class; $target):
      if $class == "os-pkgs" then "OSパッケージ"
      else
        ("/" + ((.PkgPath // $target // "") | ltrimstr("/"))) as $p
        | ([$p | splits("/(node_modules|site-packages|dist-packages|vendor|\\.?venv)/")][0]) as $c
        | (if $c != $p then $c else ($p | sub("/[^/]*$"; "")) end) as $d
        | ($d | split("/")) as $s
        | if $s[1] == "home" then
            (if (($s[3] // "") | startswith(".")) then $s[0:4] else $s[0:5] end | join("/"))
          elif $s[1] == "root" then
            (if (($s[2] // "") | startswith(".")) then $s[0:3] else $s[0:4] end | join("/"))
          elif $d == "" then "場所不明（\($target)）"
          else $d end
      end;
    def count($v): "CRITICAL \([$v[] | select(.Severity == "CRITICAL")] | length) / HIGH \([$v[] | select(.Severity == "HIGH")] | length)";

    # 全脆弱性を「対象・場所」付きで平らにし、重複を除く
    . as $in
    | [ $in[]
      | (if .ArtifactType == "container_image" then (.Label // .ArtifactName) else "ホスト" end) as $t
      | .Results[]? | .Class as $cl | .Target as $tg
      | .Vulnerabilities[]?
      | {target: $t, loc: loc($cl; $tg), id: .VulnerabilityID, pkg: .PkgName, ver: .InstalledVersion, Severity}
    ] | unique_by([.target, .loc, .id, .pkg, .ver]) as $all

    # 対象ごとの件数（ホストは常に先頭。イメージは件数の多い 10 件まで、残りと 0 件はまとめる）
    | ([ $in[] | select(.ArtifactType == "container_image") | (.Label // .ArtifactName) ] | unique
        | map(. as $n | [$all[] | select(.target == $n)] as $v
              | {n: $n, c: ([$v[] | select(.Severity == "CRITICAL")] | length), h: ([$v[] | select(.Severity == "HIGH")] | length)})
      ) as $imgs
    | ([$imgs[] | select(.c + .h > 0)] | sort_by([-.c, -.h, .n])) as $bad
    | ([$imgs[] | select(.c + .h == 0)] | length) as $clean
    | ($bad[10:]) as $rest
    | (["・`ホスト`: " + count([$all[] | select(.target == "ホスト")])]
       + ($bad[:10] | map("・`\(.n)`: CRITICAL \(.c) / HIGH \(.h)"))
       + (if ($rest | length) > 0
          then ["（ほか \($rest | length) イメージ: CRITICAL \([$rest[].c] | add) / HIGH \([$rest[].h] | add)）"] else [] end)
       + (if $clean > 0 then ["（問題なし: \($clean) イメージ）"] else [] end)
      | join("\n")) as $counts

    # ホストで件数が多い場所の上位 10
    | ([ $all[] | select(.target == "ホスト") ] | group_by(.loc)
        | map({loc: .[0].loc, c: ([.[] | select(.Severity == "CRITICAL")] | length), h: ([.[] | select(.Severity == "HIGH")] | length)})
        | sort_by([-.c, -.h])) as $locs
    | ($locs[:10] | map("・`\(.loc)`: CRITICAL \(.c) / HIGH \(.h)") | join("\n")) as $top

    | "**Trivyスキャン: \($host)**（\($date)）\n\($counts)"
      + (if ($all | length) == 0 then "\n\nCRITICAL / HIGH の脆弱性はありません"
         elif ($locs | length) == 0 then ""
         else "\n\n**件数が多い場所（ホスト）**\n\($top)"
              + (if ($locs | length) > 10 then "\n（ほか \(($locs | length) - 10) か所）" else "" end)
         end)
  ' "${results[@]}")
else
  msg="**Trivyスキャン: $HOST**（$(date '+%Y-%m-%d %H:%M')）"
fi

# 失敗した対象を追記
if ((${#errors[@]} > 0)); then
  msg+=$'\n\n'"⚠ スキャン失敗: ${errors[*]}"
fi

# 詳細 JSON をまとめて圧縮
tarball=$RUN_DIR/trivy-$HOST-$STAMP.tar.gz
attach=()
if ((${#results[@]} > 0)); then
  tar -czf "$tarball" -C "$RUN_DIR" "${results[@]##*/}"
  if (($(stat -c %s "$tarball") <= MAX_ATTACH_BYTES)); then
    attach=(-F "files[0]=@$tarball")
  else
    msg+=$'\n'"（詳細 JSON は大きすぎるため未添付: $tarball）"
  fi
fi

# Discord の本文上限（2000文字）に収める
if ((${#msg} > 1900)); then
  msg="${msg:0:1900}"$'\n…（省略）'
fi

# Discord へ送信（メンションは無効化）
payload=$(jq -n --arg c "$msg" '{content: $c, allowed_mentions: {parse: []}}')
if ! curl -fsS -o /dev/null -F "payload_json=$payload" "${attach[@]}" "$WEBHOOK_URL"; then
  echo "Discord への送信に失敗しました" >&2
fi

# 古い結果の削除
find "$DATA_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +"$RETENTION_DAYS" -exec rm -rf {} +

# スキャン失敗があれば異常終了として記録する
((${#errors[@]} == 0))
SCAN
chmod 755 "$SCAN_BIN"

# systemd service の配置
cat >"$UNIT_DIR/trivy-scan.service" <<EOF
[Unit]
Description=Trivy vulnerability scan with Discord notification
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
Environment=LANG=C.UTF-8
ExecStart=$SCAN_BIN
Nice=10
IOSchedulingClass=idle
EOF

# systemd timer の配置（毎日 4:00〜5:00 の間で VM ごとにずらす）
cat >"$UNIT_DIR/trivy-scan.timer" <<'EOF'
[Unit]
Description=Daily Trivy vulnerability scan

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=1h
FixedRandomDelay=true
Persistent=true

[Install]
WantedBy=timers.target
EOF

# timer の有効化
systemctl daemon-reload
systemctl enable --now trivy-scan.timer >/dev/null

echo "セットアップが完了しました"
echo "次回実行: $(systemctl show trivy-scan.timer -p NextElapseUSecRealtime --value)"
echo "今すぐ試す: sudo systemctl start trivy-scan.service && journalctl -u trivy-scan.service -f"
