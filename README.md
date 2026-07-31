# zapret-for-mac

**A complete macOS port of [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) — DPI bypass for Discord and YouTube, rewritten from scratch in Go for Apple Silicon.**

> **Полный порт [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) на macOS** — обход DPI для Discord и YouTube, переписанный с нуля на Go под Apple Silicon.

[![macOS](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)](#requirements)
[![Apple Silicon](https://img.shields.io/badge/Apple%20Silicon-arm64-black?logo=apple)](#requirements)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

All 21 upstream strategies are here, converted automatically from the original `.bat` files with their exact parameters preserved — `seqovl` offsets, split positions, fooling modes, repeat counts and the binary fake payloads from `bin/*.bin`. No hand-tuning, no guesswork: the converter reads upstream and fails loudly on any flag it does not understand.

> Здесь все 21 стратегия из upstream, сконвертированные автоматически из оригинальных `.bat` с сохранением точных параметров — смещений `seqovl`, позиций split, режимов fooling, числа повторов и бинарных fake-пейлоадов из `bin/*.bin`. Никакой ручной подгонки: конвертер читает upstream и падает с ошибкой на любом неизвестном флаге.

---

## Quick start / Быстрый старт

### Homebrew

```bash
brew tap naladwepo/zapret
brew install --cask zapret-for-mac

sudo zapret-probe                # what does this machine support? (reverts itself)
sudo /opt/homebrew/libexec/zapretd install-daemon \
  --plist /Library/LaunchDaemons/io.zapretmac.zapretd.plist \
  --data /opt/homebrew/var/zapret-mac

sudo zaprctl vpn stop            # a full-tunnel VPN makes desync pointless
sudo zaprctl start --transport divert
zaprctl autopick && zaprctl test
```

> **Через Homebrew.** `brew tap naladwepo/zapret` и `brew install --cask zapret-for-mac` ставят готовые arm64-бинарники и данные (стратегии, списки, fake-пейлоады) — компилятор не нужен. Дальше: `sudo zapret-probe` выясняет, что умеет ваша машина, и откатывает всё за собой; команда `install-daemon` регистрирует демон в launchd; `sudo zaprctl vpn stop` выключает полнотуннельный VPN, при котором обход бессмыслен; `autopick` перебирает стратегии и оставляет рабочую.

### From source / Из исходников

```bash
git clone https://github.com/naladwepo/zapret-for-mac.git
cd zapret-for-mac
make build

# 1. Find out what your machine can actually do (reverts everything it touches)
sudo ./bin/zapret-probe

# 2. Install the daemon
make install

# 3. Turn off any full-tunnel VPN, then start the packet datapath
sudo zaprctl vpn stop
sudo zaprctl start --transport divert

# 4. Let it find the strategy that works on your ISP
zaprctl autopick
zaprctl test
```

> **Быстрый старт.** Склонируйте репозиторий и соберите (`make build`). Затем: `sudo ./bin/zapret-probe` — выясняет, что умеет именно ваша машина, и откатывает всё, что создал. `make install` — ставит демон. `sudo zaprctl vpn stop` — корректно выключает полнотуннельный VPN, если он есть (при активном VPN обход бесполезен). `sudo zaprctl start --transport divert` — поднимает пакетный датапас. `zaprctl autopick` — перебирает стратегии и оставляет рабочую, `zaprctl test` — проверяет результат.

**Requirements:** macOS on Apple Silicon, Go 1.26+, root to run. **Not** required: disabling SIP, kernel extensions, NetworkExtension entitlements, a paid Apple Developer account, a reboot, or notarization.

> **Требования:** macOS на Apple Silicon, Go 1.26+, root для запуска. **Не** требуется: отключать SIP, kext, NetworkExtension, платный Apple Developer, перезагрузка, нотаризация.

---

## Why this is not a straight port / Почему это не портирование «в лоб»

`winws` (Windows) and `nfqws` (Linux) work the same way: the kernel hands a packet to userspace, the program edits or drops it and injects its own — WinDivert on Windows, NFQUEUE on Linux, divert sockets on FreeBSD. **macOS has none of that.** `ipfw` and `ipdivert` were removed in OS X 10.10, and Apple's `pf` has no `divert-to` and no `divert-packet` — verified on a live machine: `man 5 pf.conf` lists only `route-to`, `reply-to`, `dup-to`, `rdr`, `nat` and `dummynet`, and the kernel exports no `div_*` symbol at all. bol-van says it himself in `docs/bsd.en.md` ("*dvtws does compile but is useless*"), and `zapret2` declares macOS unsupported outright.

> `winws` (Windows) и `nfqws` (Linux) устроены одинаково: ядро отдаёт пакет в userspace, программа его правит или дропает и инжектит свои — WinDivert на Windows, NFQUEUE на Linux, divert-сокеты на FreeBSD. **На macOS ничего этого нет.** `ipfw` вместе с `ipdivert` вырезаны ещё в OS X 10.10, а в pf от Apple нет ни `divert-to`, ни `divert-packet` — проверено на живой машине: в `man 5 pf.conf` есть только `route-to`, `reply-to`, `dup-to`, `rdr`, `nat` и `dummynet`, а ядро не экспортирует ни одного символа `div_*`. Сам bol-van пишет об этом в `docs/bsd.en.md` («*dvtws does compile but is useless*»), а в `zapret2` macOS объявлен неподдерживаемым.

So the interception core had to be rebuilt on primitives macOS does have.

> Поэтому ядро перехвата пришлось собрать заново — на тех примитивах, которые в macOS есть.

---

## How it works / Как это устроено

```
                    ┌──────────────────────────────────────────────┐
   application  ──► │ pf: pass out quick route-to (utun9 …) no state│ ──► our utun fd
                    └──────────────────────────────────────────────┘      (interception
                                                                           + drop verdict)
                                          │
                            desync engine │ split / fake / seqovl / ttl / ip-id
                                          ▼
                    ┌──────────────────────────────────────────────┐
                    │ BPF Ethernet write on en0 (bypasses pf)      │ ──► the wire
                    └──────────────────────────────────────────────┘

   server replies ──► en0 ──► straight into the application's own socket
                              (inbound is never steered: no userspace TCP stack)
```

**`divert` — the packet datapath.** A pf rule steers the strategy's port window into a utun the daemon owns: reading a packet from that descriptor **is** the interception, and not re-emitting it **is** the drop verdict. Packets go back out as raw Ethernet frames written to `/dev/bpfN`, which bypasses pf entirely — so there is no loop, and every byte is ours: TCP sequence numbers (so `seqovl` works), per-packet TTL, `ip.id`, deliberately bad checksums, TCP options. Inbound traffic is never intercepted, so no userspace TCP stack is needed and the application's real 4-tuple is preserved.

> **`divert` — пакетный датапас.** Правило pf заворачивает окно портов стратегии в utun, которым владеет демон: чтение пакета из этого дескриптора **и есть** перехват, а решение не переслать его — **и есть** дроп. Обратно пакеты уходят сырыми Ethernet-кадрами в `/dev/bpfN`, минуя pf — поэтому нет петли, и каждый байт наш: номера последовательности TCP (значит работает `seqovl`), TTL на каждый пакет, `ip.id`, намеренно битые контрольные суммы, TCP-опции. Входящий трафик не перехватывается вообще, поэтому не нужен userspace TCP-стек и сохраняется настоящий 4-tuple приложения.

**`proxy` — the fallback.** `pf rdr` to a local listener plus `ioctl(DIOCNATLOOK)` to recover the original destination — the way zapret's `tpws` works on macOS. TCP only, byte-level tricks only: `send()` boundaries, `tlsrec`, `tamper`, disorder via TTL 1. No `fake`, no `seqovl`, no UDP.

> **`proxy` — резервный режим.** `pf rdr` на локальный порт плюс `ioctl(DIOCNATLOOK)` для восстановления настоящего адресата — так работает `tpws` из zapret на macOS. Только TCP и только байтовые трюки: границы `send()`, `tlsrec`, `tamper`, disorder через TTL 1. Ни `fake`, ни `seqovl`, ни UDP.

**No edit to `/etc/pf.conf`.** A stock file already declares `anchor "com.apple/*"`, and a trailing `/*` makes pf evaluate every nested sub-anchor — which is created simply by loading rules into it. So rules go into `com.apple/zapret-mac` and become live with no system file touched, exactly the way Apple's own services inject theirs at runtime.

> **`/etc/pf.conf` не правится.** Стоковый файл уже объявляет `anchor "com.apple/*"`, а суффикс `/*` заставляет pf вычислять все вложенные под-анкоры — а под-анкор создаётся самим фактом загрузки в него правил. Поэтому правила уходят в `com.apple/zapret-mac` и становятся активными без единой правки системного файла — ровно так же свои правила в рантайме добавляют сервисы самой Apple.

---

## Verified on real hardware / Проверено на живом железе

`zapret-probe` answers, on your machine, whether the packet datapath is possible at all — and it reverts every change it makes. On the development machine (macOS 26.5.1, Apple Silicon, SIP enabled) all ten stages pass:

> `zapret-probe` отвечает на вопрос, возможен ли пакетный датапас именно на вашей машине, и откатывает все свои изменения. На машине разработки (macOS 26.5.1, Apple Silicon, SIP включён) проходят все десять стадий:

| Property | Evidence |
|---|---|
| `route-to` delivers an outbound segment to our utun | SYN read off `utun9` with the `{0,0,0,2}` prefix |
| Packets need no checksum repair | IPv4 and TCP checksums already correct on arrival |
| A BPF write reaches the NIC and completes the flow | frame seen by a second reader, the TCP dial **completed** |
| `--ip-id=zero` survives on the BPF path | `egress_frame_ip_id: 0x0000` |
| `--ip-id=zero` is impossible via `SOCK_RAW` | kernel rewrote `ip_id 0` → `0xf7a0` |
| `DIOCNATLOOK` recovers the original destination | returned the exact target address and port |
| `/etc/pf.conf` untouched | same SHA-256 and mtime before and after |

---

## What works, and what cannot / Что работает, а что нет

| winws feature | `divert` | `proxy` |
|---|---|---|
| `multisplit` / `multidisorder`, all split-position markers | full | approximate |
| `--dpi-desync-split-seqovl` (**15 of 21 upstream strategies**) | full | **no** |
| `fake`, `fakedsplit`, `fakeddisorder`, `hostfakesplit`, `syndata`, `rst` | full | **no** |
| `--dpi-desync-fooling` (badsum, badseq, md5sig, ts, datanoack) | full | **no** |
| `--ip-id=zero`/`seq`, `ipfrag`, IPv6 ext headers | full | **no** |
| per-packet TTL / `--dpi-desync-autottl` | full | **no** |
| `udplen`, QUIC / Discord / STUN fakes | full | **no** |
| `tamper`, `tlsrec`, hostlists, ipset, `--new` chain, cutoff | full | full |
| `--oob` / `--disoob` | **no** | **no** |

The CLI never hides this: `zaprctl list` marks, per strategy, exactly which ops the active transport cannot honour, and `zaprctl use` refuses to silently activate a strategy whose core technique would be skipped. Full table with reasons: [docs/limits.md](docs/limits.md).

> CLI это не скрывает: `zaprctl list` для каждой стратегии помечает, какие именно техники активный транспорт выполнить не может, а `zaprctl use` не даёт молча включить стратегию, у которой отключится ключевая техника. Полная таблица с причинами — в [docs/limits.md](docs/limits.md).

**Discord voice (UDP 19294–19344, 50000–50100):** mechanically reproduced in `divert` only — the fake datagrams are injected with a chosen TTL **from the client's own source port** before the 74-byte IP-Discovery packet, exactly as winws does. Whether that defeats a given DPI box is an empirical question no local test can answer. In `proxy` voice does not work at all.

> **Discord voice (UDP 19294–19344, 50000–50100):** механика воспроизведена только в `divert` — фейковые датаграммы инжектируются с заданным TTL **с настоящего исходного порта клиента** перед 74-байтным пакетом IP Discovery, ровно как это делает winws. Пробьёт ли это конкретный ТСПУ — вопрос эмпирический, локальным тестом не проверяется. В `proxy` голос не работает никак.

---

## Commands / Команды

```bash
zaprctl status                  # transport, strategy, counters, pf state, warnings
zaprctl list                    # strategies + what the transport cannot honour
zaprctl explain general         # compiled profiles: filters, ops, real parameters
sudo zaprctl use general-alt3   # switch strategy
zaprctl autopick                # measure every strategy, keep the best
zaprctl test                    # connectivity self-test through the datapath
zaprctl doctor [--repair]       # diagnostics; fixes what is safely ours
sudo zaprctl vpn stop|start     # the VPN that blocks the packet datapath
sudo zaprctl hosts apply        # /etc/hosts pinning for Discord voice
sudo zaprctl ipset any          # upstream's tri-state ipset switch
zaprctl logs -f
```

> Те же команды по-русски: `status` — транспорт, стратегия, счётчики, состояние pf и предупреждения; `list` — стратегии и что из них не потянет активный транспорт; `explain` — скомпилированные профили с реальными параметрами (замена чтению `.bat`); `use` — сменить стратегию; `autopick` — перебрать все и оставить рабочую; `test` — проверка связности через датапас; `doctor` — диагностика и починка своего мусора; `vpn stop/start` — корректно остановить и вернуть VPN; `hosts apply` — пины IP для Discord voice; `ipset` — tri-state переключатель из upstream; `logs` — журнал демона.

---

## If something breaks / Если что-то сломалось

One command always restores normal networking — it empties only our own pf anchor:

```bash
sudo pfctl -a zapret-mac -F all
```

A `launchd` guard does this automatically every 5 seconds whenever no daemon owns the anchor, so a `kill -9` cannot leave pf dropping your traffic.

> Одна команда всегда возвращает сеть в норму — она очищает только наш собственный pf-анкор: `sudo pfctl -a zapret-mac -F all`. Раз в 5 секунд то же самое делает автоматически launchd-страж, если анкором никто не владеет, поэтому `kill -9` не может оставить pf дропающим ваш трафик.

Full uninstall: `make uninstall` — removes the binaries, both launchd jobs and the `/etc/hosts` block if it was applied.

> Полное удаление: `make uninstall` — снимает бинари, обе launchd-задачи и блок в `/etc/hosts`, если он применялся.

---

## Known limitations / Известные ограничения

* Traffic from **root-owned** processes is not bypassed — the `user { > root }` rule is the loop breaker for our own injected packets. `tpws` on macOS has the same limitation.
* Internet Sharing is not supported.
* A full-tunnel VPN makes the whole thing pointless; the daemon refuses to start the packet datapath while one holds the default route (`--allow-vpn` overrides).
* Apple documents pf as "not API" ([TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)) and there is no arbitration between tools. The daemon watches its anchor for drift and reloads, but a conflict with something else running `pfctl -f /etc/pf.conf` is possible by design.
* Strategies decay: `seqovl=681` works only while the DPI reassembles naively. `cmd/batconv` re-imports upstream at any time.

> * Трафик процессов, запущенных от **root**, не обходится — правило `user { > root }` разрывает петлю для наших же инжектированных пакетов; ровно то же ограничение у `tpws` на macOS.
> * Internet Sharing не поддерживается.
> * При полнотуннельном VPN всё это бессмысленно: демон отказывается поднимать пакетный датапас, пока VPN держит маршрут по умолчанию (обходится флагом `--allow-vpn`).
> * Apple документирует pf как «не API» ([TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)), арбитража между инструментами не существует. Демон следит за дрейфом своего анкора и восстанавливает его, но конфликт с чем-то, что делает `pfctl -f /etc/pf.conf`, возможен принципиально.
> * Стратегии деградируют: `seqovl=681` работает, пока DPI собирает поток наивно. `cmd/batconv` в любой момент перечитывает upstream.

Everything that is unverified, approximated or deliberately unimplemented is written down without hedging in [docs/known-issues.md](docs/known-issues.md).

> Всё, что не проверено, аппроксимировано или сознательно не реализовано, выписано без смягчений в [docs/known-issues.md](docs/known-issues.md).

---

## Layout / Структура

```
cmd/zapretd            root daemon: launchd, supervisor, journal-based rollback
cmd/zaprctl            CLI over the unix socket /var/run/zapret-mac.sock
cmd/zapret-probe       standalone capability probe (needs root, reverts itself)
cmd/batconv            converter: upstream .bat strategies → TOML
internal/proto         IPv4/IPv6/TCP/UDP, checksums, fragmentation, TLS ClientHello,
                       split-position markers, QUIC Initial decryption → SNI,
                       STUN / Discord IP-Discovery / WireGuard / DHT
internal/desync        techniques: multisplit, multidisorder, fakedsplit, fakeddisorder,
                       hostfakesplit, fake, rst, syndata, udplen, ipfrag, hopbyhop,
                       tamper, tlsrec, wssize, ip_id, block
internal/engine        profile selection, flow state, cutoff/start, autottl, Caps gating
internal/strategy      TOML strategy loader and compiler
internal/lists         hostlists (suffix matching) and ipsets (32k CIDRs)
internal/transport     divert (utun + BPF) and proxy (pf rdr + DIOCNATLOOK)
internal/netcfg        pf: token, wildcard sub-anchor, tables, rollback journal
internal/vpn           detect and cleanly stop VPN software holding the default route
internal/diag          capability detection, doctor, self-test, strategy autopick
strategies/*.toml      21 strategies converted from upstream
lists/, fakes/         domain/CIDR lists and fake payloads from upstream
```

---

## Credits / Благодарности

* [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) — the strategies, lists and fake payloads this port reproduces.
* [bol-van/zapret](https://github.com/bol-van/zapret) — the desync engine whose packet-level semantics were ported.

> Стратегии, списки и fake-пейлоады происходят из [Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube); семантика desync-техник портирована из [bol-van/zapret](https://github.com/bol-van/zapret).

## License / Лицензия

MIT — see [LICENSE](LICENSE). Upstream strategies, lists and payloads remain under their original MIT terms.

> MIT — см. [LICENSE](LICENSE). Стратегии, списки и пейлоады из upstream остаются под своей исходной лицензией MIT.
