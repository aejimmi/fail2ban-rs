

Una reescritura completa en Rust de [fail2ban](https://github.com/fail2ban/fail2ban) — **binario único · pipeline asíncrono · persistencia integrada**

Usado en producción en [tell.rs](https://tell.rs) para proteger los puntos finales de la aplicación.

fail2ban es una base de código en Python de 20 años que funciona, pero requiere un runtime de Python en cada servidor de producción, serializa todas las operaciones del firewall detrás de un bloqueo global de hilos y ejecuta comandos de shell a través de `subprocess.Popen(shell=True)`.

fail2ban-rs elimina todo eso:

- **Binario único de ~5 MB** — sin Python, sin runtime, sin sobrecarga de arranque del intérprete
- **~9 MB de RSS en reposo en una prueba local** — 8,7 MiB con una cárcel de archivo y los hilos predeterminados del runtime; el RSS depende de la configuración, las IP registradas y los bloqueos activos
- **Estado del tracker con propietario único** — canales acotados conectan detección, seguimiento y aplicación; la persistencia y algunos backends siguen usando bloqueos, y los comandos de firewall pasan por un único ejecutor ordenado
- **Coincidencias rápidas por línea** — prefiltro Aho-Corasick y selección de expresiones regulares guiada por AC; consulta los benchmarks acotados más abajo
- **Ejecución directa de comandos de firewall nativos** — nftables/iptables/ipset usan argv; el backend de script usa `sh -c` con sustituciones validadas de IP y cárcel
- **Inicio rápido** — el tiempo depende del comando, la configuración, el estado persistido y el backend; el lanzamiento de la CLI y la disponibilidad del demonio son mediciones diferentes
- **Estado integrado con EtchDB** — el WAL y las instantáneas compactadas almacenan bloqueos activos, contadores de escalación y metadatos sin SQLite; el espacio en disco crece con el estado retenido
- **40 bytes de marcas de tiempo por IP/cárcel registrada por defecto** — cinco marcas de 8 bytes, en lugar de líneas de registro; estos datos ocupan `8 × max_retry` bytes y excluyen las estructuras de los búferes, claves de los mapas, sobrecarga del asignador, bloqueos activos y persistencia (el RSS total es mayor)

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

**ipset**: Para listas de bloqueo grandes, [ipset](https://ipset.netfilter.org/) convierte cada bloqueo en una búsqueda hash del núcleo en O(1), en lugar de recorrer una cadena entera. No hay nada que preparar a mano:

```toml
[jail.sshd]
backend = "ipset"
```

Esa es toda la configuración. La cárcel obtiene dos conjuntos `hash:ip` — `f2b-sshd` para IPv4 y `f2b-sshd6` para IPv6 — más una regla `-m set --match-set ... -j DROP` por familia en `INPUT`, acotada al `port`/`protocol` de la cárcel cuando están definidos. Cada bloqueo lleva un temporizador en el núcleo, así que se limpia solo aunque el demonio muera. El desmontaje elimina las reglas y luego vacía y destruye los conjuntos.

Dos ajustes opcionales:

```toml
[jail.sshd.backend.ipset]
maxelem = 200000       # entradas máximas por conjunto (predeterminado 65536)
chain = "DOCKER-USER"  # cadena donde se inserta la regla (predeterminado INPUT)
```

`chain` es clave en hosts con Docker: el tráfico hacia puertos publicados de contenedores evita `INPUT`, así que la regla DROP debe estar en `DOCKER-USER` para llegar a verlo.

Requiere la herramienta `ipset` y los módulos del núcleo `ip_set`, `ip_set_hash_ip` y `xt_set`, junto con `iptables`/`ip6tables`.

> **Nota:** deja `reban_on_restart` en su valor predeterminado `true`. fail2ban-rs es dueño de estos conjuntos y los destruye al cerrar limpiamente, así que los bloqueos vuelven desde el WAL al arrancar — y añadir una entrada que ya existe no hace nada, por lo que rebloquear no cuesta nada si el conjunto sí sobrevivió.

Dos límites que conviene conocer: una cárcel con este backend necesita un nombre de 26 caracteres como máximo, ya que `f2b-<jail>6` debe caber en el tope de 31 caracteres de ipset, y `maxelem` acota la lista de bloqueos. Un conjunto lleno rechaza nuevos bloqueos — fallan de forma visible y la IP se reintenta en vez de registrarse como bloqueada — así que sube `maxelem` en cárceles con mucho tráfico, a costa de memoria del núcleo.

**Persistencia y reintentos del firewall.** Un bloqueo se escribe en el WAL antes de llegar al firewall, y un desbloqueo conserva su registro hasta que el firewall confirma la eliminación — un desbloqueo fallido se reintenta a los 60 segundos en lugar de dejar la dirección bloqueada. Todo comando de firewall se mata a los 30 segundos, incluidos los procesos en segundo plano que deje un script de bloqueo. iptables espera el candado de xtables en vez de fallar cuando otra herramienta lo tiene. Cada 5 minutos el demonio programa un lote de reconciliación de hasta 1.000 bloqueos activos. Los backends nativos consultan el estado del firewall por cárcel y vuelven a aplicar los bloqueos que falten; recorrer listas mayores requiere varios lotes. El backend de script no puede verificar el estado externo del firewall y omite esta comprobación.

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
fail2ban-rs ban 1.2.3.4 --jail sshd              # bloquear manualmente una IP
fail2ban-rs unban 1.2.3.4 --jail sshd            # desbloquear manualmente
fail2ban-rs dry-run /var/log/auth.log -j sshd   # analizar un registro sin bloquear
fail2ban-rs regex --pattern '...' --line '...'  # probar un patrón
fail2ban-rs gen-config sshd                     # generar configuración de cárcel
fail2ban-rs list-filters                        # listar los 88 filtros integrados
fail2ban-rs reload                              # recarga en caliente vía socket de control
systemctl reload fail2ban-rs                    # recarga en caliente vía SIGHUP
```

`ban` y `unban` responden solo después de que el firewall aplicó el cambio; un error del firewall vuelve como error, no como un falso éxito. La recarga entrega la posición de lectura de cada observador de registros a su reemplazo y vacía primero los fallos en cola, así que un fallo escrito durante la recarga se cuenta exactamente una vez. Los cambios de puerto o protocolo reconstruyen las reglas de la cárcel, una configuración de firewall fallida restaura la anterior, y el éxito se informa solo cuando el demonio ha aplicado la nueva configuración.

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

Microbenchmarks históricos de coincidencias (MacBook M4 Pro, Criterion para Rust y `timeit` para `re` de Python, no el motor de filtros de fail2ban). Mezcla sintética de diez líneas basada en [openssh_2k.log](sample/openssh_2k.log) de [logpai/loghub](https://github.com/logpai/loghub) (~30% aciertos, ~70% fallos cercanos):

| Etapa | Rust | Python | Aceleración |
|---|---|---|---|
| Fecha + coincidencias (mezcla sintética) | ~147 ns/línea | ~740 ns/línea | **5x** |
| Coincidencia de patrón — acierto | 291-353 ns | 457-730 ns | 1.6-2.1x |
| Coincidencia de patrón — fallo (rechazo AC) | 20-56 ns | 342-574 ns | 6-29x |
| Análisis de fecha (ISO 8601) | 7.6 ns | 165 ns | No comparable |

Los tiempos dependen de la carga y del equipo y excluyen la lectura del demonio, el seguimiento, la persistencia y la ejecución del firewall. El benchmark de fechas de Python solo busca una regex; Rust convierte a una marca de tiempo, por lo que esos tiempos no son comparables.

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
