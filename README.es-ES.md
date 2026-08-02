

Una reescritura completa en Rust de [fail2ban](https://github.com/fail2ban/fail2ban) — **5x más rápido en coincidencias · 6.6x más rápido en inicio · binario único · cero base de datos · cero bloqueos**

Usado en producción en [tell.rs](https://tell.rs) para proteger los puntos finales de la aplicación.

fail2ban es una base de código en Python de 20 años que funciona, pero requiere un runtime de Python en cada servidor de producción, serializa todas las operaciones del firewall detrás de un bloqueo global de hilos y ejecuta comandos de shell a través de `subprocess.Popen(shell=True)`.

fail2ban-rs elimina todo eso:

- **Binario único de ~3 MB** — sin Python, sin runtime, sin sobrecarga de inicio del intérprete
- **~6 MB RSS en producción** — memoria constante independientemente del volumen de registros
- **Cero bloqueos** — pipeline asíncrono de tres capas conectado por canales, estado de propietario único (fail2ban en Python usa más de 9 bloqueos de hilos)
- **5x más rápido en coincidencias por línea** — prefiltro Aho-Corasick + selección de expresiones regulares guiada por AC
- **Sin ejecución de shell** — los backends de nftables/iptables ejecutan directamente vía argv, sin `shell=True` (el backend de script usa `sh -c` pero solo sustituye valores `IpAddr` validados)
- **6.6x más rápido en inicio** — 3.7ms vs 25.8ms (medido con hyperfine, 50 ejecuciones)
- **Estado de tamaño constante** — instantánea binaria plana solo de los bloqueos activos. Sin base de datos SQLite creciendo en disco durante años
- **~1 MB con 10K bloqueos activos** — los búferes en anillo almacenan 5 marcas de tiempo por IP, no las líneas de registro coincidentes

Todo lo demás que esperarías: backends nftables/iptables/script, escalación del tiempo de bloqueo, superposición de configuración, recarga en caliente vía SIGHUP, 88 filtros integrados, soporte para systemd journal.

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

**ipset**: Para listas de bloqueo grandes, [ipset](https://ipset.netfilter.org/) proporciona búsquedas a nivel de núcleo en O(1) mediante conjuntos hash. Usa el backend de script con `reban_on_restart = false` ya que ipset persiste entre reinicios del servicio:

```toml
[jail.sshd]
reban_on_restart = false

[jail.sshd.backend.script]
ban_cmd = "ipset add fail2ban-sshd <IP>"
unban_cmd = "ipset del fail2ban-sshd <IP>"
```

Crea el conjunto y la regla de firewall previamente:

```bash
ipset create fail2ban-sshd hash:ip
iptables -I INPUT -m set --match-set fail2ban-sshd src -j DROP
```

> **Nota:** ipset reside en la memoria del núcleo — sobrevive a los reinicios del servicio pero no a los reinicios del sistema. Para persistencia entre reinicios, usa `ipset save` / `ipset restore` en una unidad de systemd o establece `reban_on_restart = true`.

### Webhooks

Establece `webhook` en una cárcel para enviar un POST con una carga JSON (IP, cárcel, tiempo de bloqueo, marca de tiempo) en cada bloqueo:

```toml
[jail.sshd]
webhook = "https://example.com/hooks/ban"
```

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
fail2ban-rs ban 1.2.3.4 sshd                    # bloquear manualmente una IP
fail2ban-rs unban 1.2.3.4 sshd                  # desbloquear manualmente
fail2ban-rs dry-run /var/log/auth.log -j sshd   # analizar un registro sin bloquear
fail2ban-rs regex --pattern '...' --line '...'  # probar un patrón
fail2ban-rs gen-config sshd                     # generar configuración de cárcel
fail2ban-rs list-filters                        # listar los 88 filtros integrados
fail2ban-rs reload                              # recarga en caliente vía socket de control
systemctl reload fail2ban-rs                    # recarga en caliente vía SIGHUP
```

## Pruebas

Prueba patrones y simulaciones contra registros reales — sin modificar ningún firewall.

```bash
# verificar que un patrón extrae la IP correcta de una línea de registro
fail2ban-rs regex --pattern 'sshd\[\d+\]: Failed password for .* from <HOST>' \
  --line 'sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2'

# simulación contra un archivo de registro real — muestra qué IPs serían bloqueadas
fail2ban-rs dry-run /var/log/auth.log --jail sshd
```

## Rendimiento

Benchmarks del pipeline de coincidencias por línea (MacBook M4 Pro, criterion), comparado con el motor de expresiones regulares equivalente de fail2ban en Python. Mezcla de líneas basada en [openssh_2k.log](sample/openssh_2k.log) de [logpai/loghub](https://github.com/logpai/loghub) (~30% aciertos, ~70% fallos cercanos):

| Etapa | Rust | Python | Aceleración |
|---|---|---|---|
| Pipeline completo (mezcla openssh_2k) | ~147 ns/línea | ~740 ns/línea | **5x** |
| Coincidencia de patrón — acierto | 291-353 ns | 457-730 ns | 1.6-2.1x |
| Coincidencia de patrón — fallo (rechazo AC) | 20-56 ns | 342-574 ns | 6-29x |
| Análisis de fecha (ISO 8601) | 7.6 ns | 165 ns | 22x |

Ejecuta los benchmarks tú mismo:
```bash
cargo bench --bench matching                 # Rust (criterion)
python3 benches/bench_matching_fail2ban.py   # Python (timeit)
```

## Compilación desde el código fuente

```bash
cargo build --release
cargo test
```

## Migración desde fail2ban

| fail2ban | fail2ban-rs |
|---|---|
| `/etc/fail2ban/jail.conf` | `/etc/fail2ban-rs/config.toml` |
| `failregex = ...` | `filter = ['...']` |
| `maxretry = 5` | `max_retry = 5` |
| `findtime = 10m` | `find_time = "10m"` |
| `bantime = 1h` | `ban_time = "1h"` |
| `bantime.increment = true` | `bantime_increment = true` |
| `bantime.multipliers = 1 2 4 8` | `bantime_multipliers = [1, 2, 4, 8]` |
| `action = iptables[...]` | `backend = "iptables"` |
| `ignoreip = 127.0.0.1/8` | `ignoreip = ["127.0.0.1/8"]` |
| `fail2ban-client status` | `fail2ban-rs status` |
| `fail2ban-client set sshd banip 1.2.3.4` | `fail2ban-rs ban 1.2.3.4 sshd` |

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
