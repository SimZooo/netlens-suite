# Netlens suite
Netlens suite is a set of lightweight tools for penetration testing, written in rust.
### v0.1.0
**nlnetwork** - network scanner

    Usage: nlnetwork [OPTIONS] <NETWORK>

    Arguments:
    <NETWORK>

    Options:
    -t, --threads <THREADS>
    -h, --help               Print help
    -V, --version            Print version
**nlscan** - port scanner
Currently only supports SYN scans
The different possible scans: SYN, ACK, TWH
These can be specified like: `-sS`, `-s S`, `-s SYN`

    Usage: nlscan [OPTIONS] --host <HOST>
    Options:
        --host <HOST>
    -i, --interface <INTERFACE>
    -t, --threads <THREADS>
    -s, --scan <SCAN>
    -p, --ports <PORTS>
    -g, --source-port <SOURCE_PORT>
    -m, --mac <MAC>
    -h, --help                       Print help
    -V, --version                    Print version
