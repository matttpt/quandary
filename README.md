# Quandary

Quandary is an authoritative DNS server. Its goal is to provide a DNS
implementation that is

1. correct,
2. well documented, and
3. efficient.

It is written in Rust and licensed under the Apache License 2.0.

## Getting started

These instructions assume some familiarity with DNS concepts like zones,
zone files, and classes. (A more comprehensive manual—including an
introduction for those without much DNS knowledge—is under development.)

### Building and installing from Git

```shell
git clone https://github.com/matttpt/quandary
cd quandary
```

After cloning, the `quandaryd` binary can be built with standard Cargo
commands. Alternatively, you may wish to build and run `quandaryd` with
Docker.

#### With Cargo

```shell
cargo build --release
```

This will generate a (mostly) static binary at
`target/release/quandaryd`. Quandary doesn’t rely on hardwired paths, so
you may copy and run the binary from wherever you’d like. For
test-driving the server, installation with `cargo install --path .`,
running with `cargo run --release`, or simply executing
`target/release/quandaryd` are all fine options.

#### With Docker on Linux

```shell
docker build -t quandary .
```

The provided `Dockerfile` compiles Quandary using the official Rust
Docker image and then copies the resulting binary to a production image
based on Google’s [distroless] images.

The working directory of the final image is `/etc/quandary`, and the
default command is `quandaryd run --config /etc/quandary/config.toml`.
Quandary runs as a non-root user, but is given the
`CAP_NET_BIND_SERVICE` capability to bind privileged ports (like 53).

### Running with command line arguments

If you’re running a public DNS server, you should consider using a
configuration file and configuring rate-limiting (see below). However,
for quick testing or lightweight use, the server can be configured from
the command line.

If you don’t have a DNS zone file handy, try using the following for the
`quandary.test.` zone:

```dns-zone
; Try writing this to a file called quandary.test.zone:
$ORIGIN quandary.test.
$TTL 3600
@  IN SOA  ns admin 1 3600 900 86400 60
   IN NS   ns
   IN TXT  "It works!"
ns IN AAAA ::1
```

Here are a few ways to run the server. (Note that you will probably need
root privileges to bind to port 53.)

```shell
# Serves the Internet (class IN) zone quandary.test., loading it from
# the zone file quandary.test.zone.
#
# Quandary binds to ::1 (IPv6 localhost) on port 53 by default.
quandaryd run --zones quandary.test.:quandary.test.zone

# For paths ending in .zone, Quandary will assume that the file name
# specifies the zone name if no zone name is explicitly provided. The
# following has the same effect the previous command.
quandaryd run --zones quandary.test.zone

# You can serve more than one zone, too! The following are equivalent.
quandaryd run --zones quandary.test.zone another.test.zone
quandaryd run --zones quandary.test.zone,another.test.zone
quandaryd run --zones quandary.test.zone --zones another.test.zone

# The --bind option changes the bind address and port.
quandaryd run --zones quandary.test.zone --bind '[::]:53'         # Any IPv6 address, port 53
quandaryd run --zones quandary.test.zone --bind '127.0.0.1:5353'  # IPv4 localhost, port 5353

# The --ip and --port options can also be used.
quandaryd run --zones quandary.test.zone --ip 2001:db8::1  # Port defaults to 53
quandaryd run --zones quandary.test.zone --port 5353       # IP defaults to ::1
```

#### Testing it out with `host` or `dig`

If you have BIND’s `host` or `dig` utilities installed, you can check
that the server is working. Assuming that you are loading the above zone
file and are using the default IP address and port:

```shell
# Try:
host -rt txt quandary.test. ::1
# or:
dig @::1 +short +norec quandary.test. TXT
# Hopefully you'll see the "It works!" TXT record.
```

#### Limitations

Only some `quandaryd` options can be configured on the command line.
Furthermore, it assumes that all zones are of class `IN` (though this is
almost always what you want).

### Running with a configuration file

Quandary supports a TOML configuration file that exposes all options.
There is no hardwired configuration search path; instead, you must run
`quandaryd` with the `--config` parameter, e.g.:

```shell
quandaryd run --config /etc/quandary/config.toml
```

The following shows current configuration file parameters and defaults.

```toml
bind = "[::1]:53"  # Required.

# If present, configures the I/O subsystem.
[io]
provider          = "blocking"  # The only available provider for now.
tcp_base_workers  = 4
tcp_worker_linger = 15          # In seconds.
udp_workers       = 2

# If present, configures server options.
[server]
edns_udp_payload_size = 1232

# If present, response rate-limiting (RRL) is enabled. If you're running
# on the public Internet, you should consider enabling this!
[server.rrl]
noerror_rate    = 100  # Required if RRL is enabled.
nxdomain_rate   = 100  # Required if RRL is enabled.
error_rate      = 10   # Required if RRL is enabled.
window          = 15   # Required if RRL is enabled.
slip            = 2
ipv4_prefix_len = 24
ipv6_prefix_len = 56
size            = 65537

# The zones array lists all zones to be served.
[[zones]]
name        = "quandary.test."      # Required.
class       = "IN"
glue_policy = "narrow"              # See draft-koch-dns-glue-clarifications-05.
path        = "quandary.test.zone"  # Required. Relative paths are
                                    # interpreted relative to the
                                    # configuration file.

# The tsig_keys array configures TSIG keys recognized by the server.
[[tsig_keys]]
name      = "domain.name.of.tsig.key."  # Required.
algorithm = "hmac-sha256"               # Required; supports hmac-sha1 and hmac-sha256.
secret    = "EncodedInBase64="          # Required.
```

### Reloading

The Quandary daemon reloads its data (zones and TSIG keys) when it
receives SIGHUP. When configured with a configuration file, the
configuration file is first reread to update the list of zones to serve
and the TSIG keys to recognize; zones and keys are then loaded,
reloaded, and dropped as required. When configured from the command
line, the configured zones are reloaded, but the list of zones to serve
cannot be changed without a full restart. (TSIG keys cannot be
configured from the command line.)

On systems that support it, Quandary checks the modification time of the
configured zone files and does not reload them if they have not changed.

Note that SIGHUP triggers only a data reload. Changes to the
configuration file outside of the `zones` and `tsig_keys` arrays are not
applied without a full restart.

### Logging

Logging in Quandary is based on the `log` and `env_logger` Rust crates.
By default, `quandaryd` emits errors and warnings to `stderr`. The log
level can be changed by setting the environment variable
`RUST_LOG=<level>`, where `level` is one of `trace`, `debug`, `info`,
`warn`, and `error`. See the [`env_logger` documentation][env_logger]
for additional logging parameters.

## Why the name?

If you’re facing a quandary, you might also say that you’re in a
[bind][BIND].

[BIND]: https://www.isc.org/bind/
[distroless]: https://github.com/GoogleContainerTools/distroless
[env_logger]: https://docs.rs/env_logger/latest/env_logger/
