# <picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg"><img alt="" src="docs/assets/logo-light.svg" width="40" height="40" align="absmiddle"></picture> Ping Brutter

Ping Brutter работает на роутере с OpenWrt и выпускает трафик Counter-Strike и
Valorant через самый быстрый UDP-порт.

[![OpenWrt 22.03+](https://img.shields.io/badge/OpenWrt-22.03%2B-00B5E2?logo=openwrt&logoColor=white)](https://openwrt.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[English version](README.md)

<picture>
  <source media="(prefers-color-scheme: light)" srcset="docs/screenshots/dashboard-light.png">
  <img src="docs/screenshots/dashboard-dark.png" alt="Панель Ping Brutter: закреплённый порт Counter-Strike и матч Valorant на более быстром порту" width="860">
</picture>

## Зачем это

Провайдеры часто раскладывают UDP по параллельным каналам по номеру порта. Игра
может попасть на медленный путь, хотя с другого порта до того же сервера на
10–20 мс быстрее. Brutter меряет десятки портов с роутера и переводит игру на
самый быстрый. Если провайдер гонит все порты одинаково, Brutter не найдёт
выигрыша и оставит соединение как есть.

## Что умеет

- **Counter-Strike** (CS2 и CS:GO, community-серверы). На новом сервере Brutter
  меряет время ответа A2S с 20 портов и закрепляет самый быстрый.
  Переподключаешься, и дальше игра ходит на этот сервер с этого порта. Второй
  закреплённый порт нужен для быстрых переподключений.
- **Valorant.** В начале матча Brutter проверяет 50 портов рукопожатием самой
  игры и переносит живое соединение на самый быстрый. Потом меряет порт, с
  которым ты зашёл, и возвращает тебя на него, если тот был быстрее.
- **Несколько устройств.** Выбери в панели ПК (а может, и консоли), на которых
  играешь.
- **Правило 2 мс.** Brutter переключает порт, только если выигрыш не меньше 2 мс.
  Force берёт самый быстрый порт в любом случае.
- **Flow offload.** UDP выбранных устройств Brutter держит вне ускорения, их TCP
  остаётся ускоренным.
- **Лёгкий.** Один статический бинарник: около 3 МБ на флеше и 15 МБ памяти.

Число проверяемых портов (от 5 до 100) для каждой игры меняется в панели.

<img src="docs/screenshots/servers-dark.png" alt="Сохранённые серверы Counter-Strike с закреплёнными портами" width="860">

## Установка

На роутере от root:

```sh
sh -c "$(wget -qO- https://raw.githubusercontent.com/demyaha/openwrt-brutter/main/scripts/install.sh)"
```

Установщик скачивает сборку под твой процессор и проверяет её SHA256. Если нет
`kmod-nf-conntrack-netlink` или выключен учёт conntrack, он это исправит, потом
запустит службу `brutter` и напишет адрес панели, например
`http://192.168.1.1:1337/`. Открой её и выбери устройства в **Devices**.

Та же команда обновляет Brutter. Чтобы поставить конкретный релиз:

```sh
BRUTTER_VERSION=v0.1.0 sh -c "$(wget -qO- https://raw.githubusercontent.com/demyaha/openwrt-brutter/main/scripts/install.sh)"
```

Нужен OpenWrt 22.03 или новее с firewall4, около 4 МБ свободного флеша и один
из процессоров: arm64, armv7, armv5, mips, mipsel, x86-64, x86. Проверено на
OpenWrt 25.12.

## Настройки

Brutter работает с настройками по умолчанию. Они лежат в
`/etc/ping-brutter.json`:

| Ключ | По умолчанию | |
|---|---|---|
| `clients` | `[]` | Игровые устройства. Панель заполняет сама. Закрепи их адреса в DHCP. |
| `listen` | адрес LAN | Адрес панели. |
| `port` | `1337` | Порт панели. |
| `lan_interface` | `br-lan` | LAN-мост. |
| `wan_interface` | маршрут по умолчанию | WAN-устройство, например `pppoe-wan` или `wan`. |
| `state_dir` | `/root` | Настройки и сохранённые серверы. |
| `ram_dir` | `/tmp` | Рабочие файлы. |

После правки перезапусти службу: `/etc/init.d/brutter restart`. Лог:
`logread -e brutter`.

## Удаление

```sh
sh -c "$(wget -qO- https://raw.githubusercontent.com/demyaha/openwrt-brutter/main/scripts/uninstall.sh)"
```

Настройки и сохранённые серверы остаются. С `--purge` удалятся и они:

```sh
sh -c "$(wget -qO- https://raw.githubusercontent.com/demyaha/openwrt-brutter/main/scripts/uninstall.sh)" uninstall --purge
```

## Вопросы

**Пинг станет ниже?** Только если провайдер выбирает маршрут по порту. Панель
показывает время ответа каждого проверенного порта, так что разброс видно
сразу. В игре цифра может немного отличаться: игра добавляет своё время
обработки.

**Официальный матчмейкинг Valve?** Нет. Premier и другие матчи Valve идут через
Steam Datagram Relay: ПК подключается к ретранслятору Valve, а он не отвечает
на запросы, которыми меряет Brutter. Community-серверы с прямым адресом
работают.

**CGNAT, второй роутер, VPN?** Brutter должен стоять на роутере с последним
твоим NAT. NAT после него может снова поменять порт, а VPN или прокси ведут игру
своим маршрутом.

**Панель защищена?** Нет, её может открыть любое устройство в твоей сети.
Brutter слушает только адрес LAN, не пробрасывай его порт наружу.

## Что Brutter меняет на роутере

Ставит `/usr/bin/brutter`, `/etc/init.d/brutter` и `/etc/ping-brutter.json`,
хранит настройки и сохранённые серверы в `/root/ping-brutter-*.json`. Во время
работы создаёт таблицы nftables `brutter_*` и убирает их при остановке. Пока
выбраны устройства, ведёт `/etc/nftables.d/20-brutter.nft` и перезагружает
firewall4 при смене списка, после того как `fw4 check` принял правила. Скрипт
удаления убирает всё это.

## Сборка

```sh
go test -race ./...
scripts/build.sh 0.1.0    # все платформы и SHA256SUMS в dist/
```

Пуш тега `v*` собирает релиз на GitHub.

## Благодарности

- [Dawnline](https://github.com/tickcount/luci-app-dawnline): панель
  позаимствовала его дизайн.
- [Claude Code](https://claude.com/claude-code)
