# ddns-cf

Cloudflare DDNS + network watchdog for Debian / Ubuntu VPS. Pure Python 3 standard library, no pip.

## 功能

- **DDNS**：定期检测公网 IPv4 / IPv6，更新 Cloudflare 的 A / AAAA 记录（记录不存在可自动创建；没有 IPv6 时自动跳过）。
- **凭据放在 `.env`**：安装后位于 `/opt/ddns-cf/.env`，权限 `600 root`。
- **PPPoE 优先（pppd / `pon`）**：`/etc/ppp/peers/dsl-provider` 存在时自动启用（`PPP_ENABLE`）。
  - ppp0 在线时，把系统 IPv4 默认路由强制指向 ppp0；原来的 DHCP 默认路由改成更高 metric 留作备份。
  - ppp0 掉线：先 `poff` + `pon` 重拨；拨不起来就回落到物理网卡的 DHCP，同时**每 60 秒重拨一次**（`PPP_RETRY_INTERVAL`），ppp0 一回来就切回去，并立即同步 DDNS。
  - 只保留 ppp0：发现 ppp1 等其他 ppp 接口，直接结束它对应的 pppd；拨号时带 `unit 0` 让 pppd 优先拿 ppp0。
  - 只管 IPv4 默认路由，IPv6 路由仍由系统 / RA 决定。
- **掉线自动恢复**：每 `CHECK_INTERVAL` 秒 ping `CHECK_TARGETS`，连续 `FAIL_THRESHOLD` 次失败后按系统自动识别逐级恢复：
  0. PPP 重拨（启用 PPP 时）；ppp0 拨上了但还是不通，就挂断它，让 DHCP 路由接管
  1. DHCP 续租：`networkctl renew` / `nmcli device reapply` / `dhclient -r && dhclient`（ifupdown 下只对 `inet dhcp` 接口执行，不会动静态 IP）
  2. 重启网络：`netplan apply` / `systemctl restart systemd-networkd` / `NetworkManager` / `systemctl restart networking`（失败时 `ifdown && ifup`）
  3. 可选：多轮失败后重启 VPS（`REBOOT_ON_FAILURE=true`，默认关闭）
  恢复成功后立即强制跑一次 DDNS。
- **systemd 服务 + 开机自启**：`ddns-cf.service`，崩溃自动重启，日志进 journald。

## 安装

```bash
scp -r DDNS_CF root@your-vps:/root/
ssh root@your-vps
cd /root/DDNS_CF
cp .env.example .env && nano .env      # 填 CF_API_TOKEN、CF_RECORDS
sudo bash install.sh
```

Cloudflare Token 权限：`Zone → DNS → Edit`（如果不填 `CF_ZONE_ID`，还需要 `Zone → Zone → Read`）。

## 常用命令

```bash
ddns-cf check                 # 检查配置、Token、PPP / 路由状态、网络栈识别、公网 IP
ddns-cf ddns                  # 立即更新一次 DNS
sudo ddns-cf dial             # 手动重拨一次 PPP 并把默认路由指向 ppp0
sudo ddns-cf recover          # 手动演练一次恢复流程（会真的重启网络）
systemctl status ddns-cf
journalctl -u ddns-cf -f
sudo systemctl restart ddns-cf   # 改了 .env 之后
sudo bash uninstall.sh [--purge]
```

## 配置项

见 `.env.example`，每项都有注释。时间单位都是秒。
