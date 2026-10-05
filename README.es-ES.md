

Una reescritura completa en Rust de [fail2ban](https://github.com/fail2ban/fail2ban) — **coincidencias 50x más rápidas · inicio 9x más rápido · binario único de ~5 MB**

Usado en producción en [tell.rs](https://tell.rs) para proteger los puntos finales de la aplicación.

fail2ban es una base de código en Python de 20 años que funciona, pero requiere un runtime de Python en cada servidor de producción, serializa todas las operaciones del firewall detrás de un bloqueo global de hilos y ejecuta comandos de shell a través de `subprocess.Popen(shell=True)`.

fail2ban-rs es un único binario estático:

- **Coincidencias 50x más rápidas** — 158 ns por línea de registro frente a 8.123 ns de fail2ban, con el mismo registro y los mismos patrones
- **Inicio 9x más rápido** — 4 ms frente a 38 ms
- **Binario de ~5 MB, ~9 MB de memoria en reposo** — sin Python, sin runtime, sin intérprete
- **Nada que mantener** — los bloqueos persisten en un registro de escritura anticipada integrado y sobreviven a reinicios y caídas; sin base de datos SQLite creciendo en disco
- **Sin shell para los firewalls nativos** — los comandos de nftables, iptables e ipset se ejecutan directamente vía argv

Todo lo demás que esperarías: backends nftables/iptables/ipset/script, escalación del tiempo de bloqueo, superposición de configuración, recarga en caliente vía SIGHUP, 88 filtros integrados, soporte para systemd journal.

## Instalación

Requiere Linux y systemd. Instala el binario, el servicio de systemd y la configuración predeterminada.

```bash
curl -sSfL https://raw.githubusercontent.com/aejimmi/fail2ban-rs/main/scripts/install.sh | bash
```

O instala solo el binario desde crates.io:

```bash
cargo install fail2ban-rs
```

```bash
vi /etc/fail2ban-rs/config.toml       # editar config
systemctl enable fail2ban-rs          # iniciar en el arranque
systemctl start fail2ban-rs           # iniciar
fail2ban-rs status                    # verificar estado
journalctl -u fail2ban-rs -f          # registros
```

## Configuración

Consulta [`config/default.toml`](config/default.toml) para ver todas las opciones. Cárcel mínima:

```toml
[jail.sshd]
enabled = true
log_path = "/var/log/auth.log"
date_format = "syslog"
filter = [
    'sshd\[\d+\]: Failed password for .* from <HOST>',
    'sshd\[\d+\]: Invalid user .* from <HOST>',
]
port = ["22"]
protocol = "tcp"
max_retry = 5
find_time = "10m"
ban_time = "1h"
backend = "nftables"

# Escalación del tiempo de bloqueo para reincidencias
bantime_increment = true
bantime_multipliers = [1, 2, 4, 8, 16, 32, 64]
bantime_maxtime = "1w"

# IPs/CIDRs que nunca se bloquearán
ignoreip = ["127.0.0.1/8", "::1/128"]
ignoreself = true
```

Las duraciones aceptan sufijos `s`, `m`, `h`, `d`, `w` (p. ej., `"10m"`, `"1h"`, `"7d"`). También funcionan los segundos en crudo.

### Decaimiento de la escalación

Con `bantime_increment`, cada bloqueo repetido de una IP incrementa su tiempo de bloqueo. El contador de escalación por IP se reinicia tras un período de tranquilidad para que una IP que haya cambiado su comportamiento comience desde cero y el mapa de contadores no crezca sin límite:

```toml
[global]
ban_count_decay = "30d"   # reiniciar el conteo de escalación después de 30 días sin incidentes (predeterminado); "0" desactiva
```

Una IP sin un nuevo bloqueo dentro de `ban_count_decay` ve reducido su conteo de escalación en el siguiente ciclo, por lo que su siguiente infracción escalará desde cero nuevamente — replicando el concepto de decaimiento de tiempo de bloqueo de fail2ban.

### Backends de firewall

**nftables** (predeterminado): Crea la tabla `inet fail2ban-rs`, cadena y conjuntos por cárcel. Desmontaje al cerrar.

**iptables**: Cadenas por cárcel con coincidencia multiport. Gestiona tanto `iptables` como `ip6tables`.

**script**: Comandos personalizados con los marcadores `<IP>` y `<JAIL>`:

```toml
[jail.custom.backend.script]
ban_cmd = "/usr/local/bin/ban.sh <IP> <JAIL>"
unban_cmd = "/usr/local/bin/unban.sh <IP> <JAIL>"
```

**ipset**: Para listas de bloqueo grandes. Cada bloqueo se convierte en una búsqueda hash del núcleo en O(1), en lugar de recorrer una cadena entera, y no hay nada que preparar a mano:

```toml
[jail.sshd]
backend = "ipset"
```

El demonio crea y destruye los conjuntos y las reglas por sí mismo. Cada bloqueo lleva un temporizador en el núcleo, así que se limpia solo aunque el demonio muera. Dos ajustes opcionales:

```toml
[jail.sshd.backend.ipset]
maxelem = 200000       # entradas máximas por conjunto (predeterminado 65536)
chain = "DOCKER-USER"  # cadena de la regla (predeterminado INPUT); necesaria para puertos publicados de Docker
```

Requiere la herramienta `ipset` y los módulos del núcleo `ip_set`, `ip_set_hash_ip` y `xt_set`, junto con `iptables`/`ip6tables`. Los nombres de cárcel tienen un máximo de 26 caracteres, y un conjunto lleno rechaza nuevos bloqueos, así que sube `maxelem` en cárceles con mucho tráfico. Deja `reban_on_restart` en su valor predeterminado `true`.

Todos los backends comparten estas garantías:

- **Bloqueos duraderos** — un bloqueo se escribe en disco antes de llegar al firewall, y un desbloqueo conserva su registro hasta que el firewall confirma la eliminación, con reintento a los 60 segundos si falla.
- **Sin comandos colgados** — todo comando de firewall se mata a los 30 segundos, incluidos los procesos en segundo plano que deje un script de bloqueo.
- **Autorreparación** — cada 5 minutos se comprueban hasta 1.000 bloqueos activos contra el firewall y se vuelven a aplicar los que falten. El backend de script no se puede verificar y se omite.

### Webhooks

Establece `webhook` en una cárcel para enviar un POST con una carga JSON (IP, cárcel, tiempo de bloqueo, marca de tiempo) en cada bloqueo:

```toml
[jail.sshd]
webhook = "https://example.com/hooks/ban"
```

La entrega está acotada: como máximo 8 peticiones en vuelo, una cola de 64, un tiempo límite de 15 segundos por petición, y el cuerpo de la respuesta se descarta. Un endpoint lento pierde notificaciones; nunca frena los bloqueos.

> **Nota:** los webhooks delegan en `curl` presente en `PATH` — la única dependencia más allá de las herramientas de firewall que la instalación de binario único no incluye. Las cárceles sin un `webhook` nunca lo invocan.

### Superposiciones de configuración

Los archivos `.toml` adicionales en `config.d/` junto a tu configuración principal se fusionan alfabéticamente.

Las claves desconocidas se rechazan al cargar, por lo que un error tipográfico falla rápidamente en lugar de ignorarse silenciosamente.

## Filtros integrados

`fail2ban-rs gen-config <name>` genera una configuración de cárcel para cualquiera de los **88 servicios integrados**, incluyendo:

`sshd` `nginx-auth` `nginx-botsearch` `postfix` `dovecot` `vsftpd` `asterisk` `mysqld` `apache-auth` `apache-botsearch` `vaultwarden` `bitwarden` `proxmox` `gitlab` `grafana` `haproxy` `drupal` `traefik` `openvpn`

Ejecuta `fail2ban-rs list-filters` para ver la lista completa.

## CLI

```bash
fail2ban-rs status                              # mostrar todas las cárceles y bloqueos
fail2ban-rs list-bans                           # tabla ordenada de bloqueos activos (--json para JSONL)
fail2ban-rs stats                               # estadísticas del demonio
fail2ban-rs ban 1.2.3.4 --jail sshd             # bloquear manualmente una IP
fail2ban-rs unban 1.2.3.4 --jail sshd           # desbloquear manualmente
fail2ban-rs dry-run /var/log/auth.log -j sshd   # analizar un registro sin bloquear
fail2ban-rs regex --pattern '...' --line '...'  # probar un patrón
fail2ban-rs gen-config sshd                     # generar configuración de cárcel
fail2ban-rs list-filters                        # listar los 88 filtros integrados
fail2ban-rs reload                              # recarga en caliente vía socket de control
systemctl reload fail2ban-rs                    # recarga en caliente vía SIGHUP
```

`ban` y `unban` responden solo después de que el firewall aplicó el cambio. Una recarga cuenta exactamente una vez cada fallo escrito mientras ocurre, e informa del éxito solo cuando la nueva configuración está aplicada. `regex` y `dry-run` nunca tocan el firewall, así que los patrones se pueden probar contra registros reales sin riesgo.

## Rendimiento

Medido contra fail2ban 1.1.0 en la misma máquina (MacBook M4 Pro), con el mismo registro, los mismos patrones y el mismo número de coincidencias:

| | fail2ban-rs | fail2ban | |
|---|---|---|---|
| Coincidencias, por línea de registro | 158 ns | 8.123 ns | **50x** |
| Inicio | 4 ms | 38 ms | **9x** |

Las coincidencias se miden sobre 200.000 líneas de [openssh_2k.log](sample/openssh_2k.log) de [logpai/loghub](https://github.com/logpai/loghub), restando el tiempo de inicio. El inicio es `--version` de cada herramienta. Reprodúcelo:

```bash
fail2ban-rs dry-run auth.log --jail sshd              # fail2ban-rs
fail2ban-regex --no-check-all auth.log filter.conf    # fail2ban
cargo bench --bench matching                          # microbenchmarks por etapa
```

## Compilación desde el código fuente

```bash
cargo build --release
cargo test
```

## Migración desde fail2ban

fail2ban-rs no lee directamente los archivos INI de fail2ban. Crea una tabla
TOML `[jail.<nombre>]` por cada cárcel habilitada de fail2ban. Los archivos
`config.d/*.toml`, fusionados alfabéticamente tras la configuración principal,
son el equivalente más cercano a los overrides `jail.d/*.local`.

| fail2ban | fail2ban-rs | Notas |
|---|---|---|
| `/etc/fail2ban/jail.conf`, `jail.local` | `/etc/fail2ban-rs/config.toml` | Usa `[jail.sshd]`, no `[sshd]`. |
| `jail.d/*.local` | `/etc/fail2ban-rs/config.d/*.toml` | Los archivos posteriores sobrescriben valores anteriores. |
| `enabled = true` | `enabled = true` | En una cárcel TOML, habilitada por defecto. |
| `logpath = /var/log/auth.log` | `log_path = "/var/log/auth.log"` | Un archivo por cárcel; los `logpath` con glob o múltiples archivos requieren cárceles separadas. |
| `backend = systemd` | `log_backend = "systemd"` | Omite `log_path` y añade `journalmatch = ["_SYSTEMD_UNIT=sshd.service"]` según necesites. La vigilancia de archivos es `log_backend = "file"`. |
| `journalmatch = ...` | `journalmatch = ["..."]` | Una expresión de coincidencia de campo del journal por entrada del array. |
| `datepattern = ...` | `date_format = "syslog"` | Elige un preset: `syslog`, `iso8601`, `epoch` o `common`; las expresiones `datepattern` arbitrarias de fail2ban no están soportadas. |
| `filter = sshd` / `failregex = ...` | `filter = ['... <HOST> ...']` | Copia los patrones reales, con exactamente un `<HOST>` por patrón. Usa `gen-config` para partir de una plantilla integrada. |
| `ignoreregex = ...` | `ignoreregex = ['...']` | Cada línea que coincida se suprime aunque coincida con `filter`. Son expresiones regulares de Rust; `<HOST>` no se expande aquí. |
| `maxretry = 5` | `max_retry = 5` | |
| `findtime = 10m` | `find_time = "10m"` | También funcionan segundos numéricos. |
| `bantime = 1h` | `ban_time = "1h"` | Usa `-1` para un bloqueo permanente. |
| `bantime.increment = true` | `bantime_increment = true` | |
| `bantime.factor = 1` | `bantime_factor = 1.0` | |
| `bantime.multipliers = 1 2 4 8` | `bantime_multipliers = [1, 2, 4, 8]` | |
| `bantime.maxtime = 1w` | `bantime_maxtime = "1w"` | |
| `ignoreip = 127.0.0.1/8 ::1` | `ignoreip = ["127.0.0.1/8", "::1"]` | Solo direcciones IP y CIDR; no se resuelven nombres DNS. |
| `ignoreself = true` | `ignoreself = true` | |
| `port = 22`, `protocol = tcp` | `port = ["22"]`, `protocol = "tcp"` | Los puertos deben ser numéricos; traduce primero nombres de servicio, rangos y expresiones multipuerto. |
| `action = iptables[...]` / `banaction = ...` | `backend = "iptables"`, `"nftables"` o `"ipset"` | `nftables` es el predeterminado. Usa el backend `script` para comandos de bloqueo/desbloqueo personalizados. |
| `banaction = iptables-ipset-proto6[...]` | `backend = "ipset"` | Nativo — los sets y las reglas de coincidencia se crean automáticamente, sin sección `[Init]`. Deja `reban_on_restart` en su valor predeterminado `true`. |
| lista de bloqueos externa persistente | `reban_on_restart = false` | Solo para backends `script` cuyo almacén externo conserva los bloqueos por sí mismo; el backend ipset nativo rebloquea desde su estado. |
| `fail2ban-client status` | `fail2ban-rs status` | |
| `fail2ban-client set sshd banip 1.2.3.4` | `fail2ban-rs ban 1.2.3.4 --jail sshd` | |

Las siguientes características de fail2ban aún no tienen equivalente directo de
configuración: etiquetas de filtro personalizadas e interpolación (`%(...)s`),
`prefregex`, `maxlines`, `datepattern` arbitrario, `ignoreip`/`usedns` basados
en DNS, `ignorecommand`, `bantime.rndtime`, `bantime.formula`,
`bantime.overalljails`, puertos con nombre o por rangos, múltiples rutas de log
o con glob, y las definiciones de acciones de fail2ban (correo, Cloudflare,
informes y acciones múltiples). Una cárcel que las use necesita un
filtro/configuración simplificado, cárceles separadas o un backend `script`.

## Hoja de ruta

- Recidiva — los reincidentes escalan automáticamente a bloqueos más largos y en todos los puertos entre cárceles
- Acciones de bloqueo — ganchos post-bloqueo integrables para AbuseIPDB, bloqueo en el borde de Cloudflare y notificaciones
- Enriquecimiento de IP — whois, DNS inverso e informes de abuso X-ARF en eventos de bloqueo
- Firewalls BSD — backends pf e ipfw para OpenBSD/FreeBSD
- Bloqueo de feeds de amenazas — importar listas de bloqueo para bloquear proactivamente a atacantes conocidos
- Compartición de bloqueos entre servidores — el bloqueo de un nodo se propaga en todo el clúster
- Paquetes de distribución — apt, RPM, Homebrew, AUR

[El patrocinio](https://github.com/sponsors/aejimmi) ayuda a priorizarlos.

## Licencia

MIT
