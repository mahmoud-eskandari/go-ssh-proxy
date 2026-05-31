# go-ssh-proxy

An SSH-to-SOCKS5 tunnel server written in Go. It creates an SSH server that forwards all traffic through an upstream SOCKS5 proxy. Clients connect using `ssh -D` to get a local SOCKS5 proxy that routes through the upstream proxy.

## How It Works

```
Client (ssh -D 8080) → SSH Server (this tool) → SOCKS5 Proxy → Internet
```

1. The client connects via SSH with dynamic port forwarding (`-D`).
2. The server authenticates the client with username/password.
3. All `direct-tcpip` channels are forwarded through the configured upstream SOCKS5 proxy.
4. An ephemeral ECDSA host key is generated on each run (no key files needed).

## Installation

```bash
go build -o go-ssh-proxy .
```

## Usage

### Command-line flags

```bash
./go-ssh-proxy -port 2222 -proxy 192.168.10.10:1080 -user myuser -password secret
```

### Config file

```bash
./go-ssh-proxy -config config.yaml
```

**config.yaml:**

```yaml
listen_port: 2222
# ECDSA host key let it empty then run app to generate a new random key
# to prevent next run key changes copy below the ECDSA key from output to prevent key changes
host_key:
# single SOCKS5 proxy (deprecated - use 'socks_list' instead)
# socks5_address: 192.168.10.10:1080

# Multiple SOCKS5 proxy configurations with round-robin and circuit breaker
socks_list:
  - address: 192.168.10.201:7000
    username:
    password:
  - address: 127.0.0.1:7000
    username:
    password:


# single user config (use 'users' list instead)
# username: user0
# password: pass0

# Multiple user configurations
users:
  - user: user1
    password: pass1
  - user: user2
    password: pass2
```

### Client connection

```bash
ssh myuser@yourserver -N -p 2222 -D 8080
```

Then configure your browser or application to use `localhost:8080` as a SOCKS5 proxy.

## Flags

| Flag | Description |
|------|-------------|
| `-port` | SSH server listen port |
| `-proxy` | Upstream SOCKS5 proxy address (`host:port`) |
| `-user` | SSH username |
| `-password` | SSH password |
| `-config` | Path to YAML config file |

---

<div dir="rtl">

# go-ssh-proxy

یک سرور تونل SSH به SOCKS5 که با زبان Go نوشته شده است. این ابزار یک سرور SSH ایجاد می‌کند که تمام ترافیک را از طریق یک پروکسی SOCKS5 بالادستی هدایت می‌کند. کلاینت‌ها با استفاده از `ssh -D` متصل می‌شوند و یک پروکسی SOCKS5 محلی دریافت می‌کنند.

## نحوه کار

</div>

```
کلاینت (ssh -D 8080) ← سرور SSH (این ابزار) ← پروکسی SOCKS5 ← اینترنت
```

<div dir="rtl">

1. کلاینت از طریق SSH با پورت‌فوروارد داینامیک (`D-`) متصل می‌شود.
2. سرور، کلاینت را با نام کاربری و رمز عبور احراز هویت می‌کند.
3. تمام کانال‌های `direct-tcpip` از طریق پروکسی SOCKS5 بالادستی هدایت می‌شوند.
4. در هر اجرا یک کلید میزبان ECDSA موقت تولید می‌شود (نیازی به فایل کلید نیست).

## نصب

</div>

```bash
go build -o go-ssh-proxy .
```

<div dir="rtl">

## استفاده

### پرچم‌های خط فرمان

</div>

```bash
./go-ssh-proxy -port 2222 -proxy 192.168.10.10:1080 -user myuser -password secret
```

<div dir="rtl">

### فایل تنظیمات

</div>

```bash
./go-ssh-proxy -config config.yaml
```

<div dir="rtl">

**config.yaml:**

</div>

```yaml
listen_port: 2222
socks5_address: 192.168.10.10:1080
username: myuser
password: secret
```

<div dir="rtl">

### اتصال کلاینت

</div>

```bash
ssh myuser@yourserver -N -p 2222 -D 8080
```

<div dir="rtl">

سپس مرورگر یا برنامه خود را طوری تنظیم کنید که از `localhost:8080` به عنوان پروکسی SOCKS5 استفاده کند.

## پرچم‌ها

| پرچم | توضیحات |
|------|---------|
| `port-` | پورت گوش‌دادن سرور SSH |
| `proxy-` | آدرس پروکسی SOCKS5 بالادستی (`host:port`) |
| `user-` | نام کاربری SSH |
| `password-` | رمز عبور SSH |
| `config-` | مسیر فایل تنظیمات YAML |

</div>
