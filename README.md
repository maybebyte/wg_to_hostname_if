# wg_to_hostname_if

`wg_to_hostname_if` translates WireGuard configuration files to
OpenBSD's hostname.if(5) format. Specifically, it deals with client
configuration files. It also performs some validation to ensure that
each option in each section is set to a reasonable value.

This tool is still under development. It's usable as is, but consider
the API unstable. When it's ready for public consumption, I'll
create a release.

## Example usage

There is a file named `test.ini` in the tests directory. Here are
its contents.

```shell
$ cat tests/test.ini
[Interface]
PrivateKey = yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=
Address = 192.168.1.23/32,fd12:3456:789a:1::1/128

[Peer]
PublicKey = YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg=
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = 73.60.105.217:11507
```

These are the contents of that file translated to hostname.if format.

```shell
$ ./wg_to_hostname_if.py tests/test.ini
wgkey yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=
wgpeer YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg= \
	wgendpoint 73.60.105.217 11507 \
	wgaip 0.0.0.0/0 \
	wgaip ::/0
inet 192.168.1.23/32
inet6 fd12:3456:789a:1::1/128
```

## TODOs

- Documentation:
  - README.md
- Packaging (I'm considering flit due to its relative simplicity
  compared to other solutions).
