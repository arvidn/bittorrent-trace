bittorrent-trace
----------------

``tracebt`` is a tool that reconstructs BitTorrent peer protocol streams (TCP
and uTP) from a packet capture, parse the protocol and prints it to human
readable form to files on disk. The packet capture is expected to be a libpcap
compatible file, either ``.pcap`` or ``.pcapng``, suitable captured with
wireshark or tcpdump.

For the reconstruction to work reliably, the full packets need to be included in
the capture, not just packet headers. This is because at the bittorrent protocol
level, messages are not aligned to packets, and may end up at the end of a full
MTU segment.

usage::

	./tracebt <capture-file>

Files are saved to current working directory, in a subdirectory called ``bt/<info-hash>``.
Each TCP or uTP connection is dumped to a file in that directory.

dependencies
~~~~~~~~~~~~

Bittorrent trace depends on ``libpcap`` and `boost.system`.

build
~~~~~

Building is most conveniently done with ``boost-build``. Run::

	b2

In the root directory.
