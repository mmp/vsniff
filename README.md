vsniff
======

`vsniff` is a simple network sniffer that records traffic on a single
connection to a specified remote server. For example,
```bash
$ vsniff -local :5000 -remote example.com:1234
```
waits for a connection on the local port 5000. When one arrives, it
connects to `example.com:1234` and records the traffic on the connection,
saving it to a file in the current directory.

The proximate use for `vsniff` is to record VATSIM network traffic for the
[vice](https://github.com/mmp/vice) client.  For this one can just run:
```bash
$ vsniff
```
In this case, `vsniff` listens to the local port 6809, ready for a proper
VATSIM client (e.g., VRC) to connect, at which point it completes the
connection to VATSIM for VRC.  The recorded session file can later be
played back by [vice](https://github.com/mmp/vice) using its built-in
"replay" functionality.

To build `vsniff` from source, run `go install
github.com/mmp/vsniff@latest`. Alternatively, binaries for Windows and OSX
can be downloaded from the [releases
page](https://github.com/mmp/vsniff/releases/latest).


