/*

Copyright (c) 2020, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

#include <iostream>
#include <iomanip>
#include <fstream>
#include <map>
#include <vector>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <boost/asio/ip/address_v4.hpp>

#include "utp_state.hpp"
#include "pcap.hpp"
#include "str.hpp"
#include "bittorrent.hpp"

using libtorrent::span;
using boost::asio::ip::address_v4;
using boost::asio::ip::make_address_v4;

template <typename Handler>
struct processor
{

static void handler_wrapper(u_char *user_data, pcap_pkthdr const* pkthdr, u_char const* packet)
{
	auto* self = reinterpret_cast<processor<Handler>*>(user_data);
	if (pkthdr->len != pkthdr->caplen) {
		std::cout << " ERROR: missing data in capture! packet: " << pkthdr->len << " B captured: " << pkthdr->caplen << "B\n";
	}
	span<unsigned char const> pkt(packet, pkthdr->len);
	self->process(pkthdr->ts, pkt);
}

void process(timeval const& ts, span<unsigned char const> pkt)
{
// TODO: ensure this is an ethernet frame, and maybe even support other physical links

	if (!quiet_)
		std::cout << "\x1b[0m";

	auto const& eth_header = cast<ether_header const>(pkt);
	pkt = pkt.subspan(sizeof(ether_header));

	// we're only interested in IP packets
	if (ntohs(eth_header.ether_type) != ETHERTYPE_IP) {
		if (!quiet_ && !connid_filter_)
			std::cout << "[not ethernet]\n";
		return;
	}

	auto const& ip_header = cast<ip const>(pkt);
	// read the header length to skip over IP option headers too
	int const ip_header_len = int(ip_header.ip_hl) * 4;
	pkt = pkt.subspan(ip_header_len, ntohs(ip_header.ip_len) - ip_header_len);

	if (ip_header.ip_hl < 5) {
		// invalid packet
		if (!quiet_)
			std::cout << "ignoring IP packet with header length: " << ip_header.ip_hl << "\n";
		return;
	}

	// we only support IPv4
	if (ip_header.ip_v != 4) {
		if (!quiet_)
			std::cout << "[not IPv4: " << ip_header.ip_v << "]\n";
		return;
	}

	if (ip_header.ip_p != IPPROTO_UDP) {
		return;
	}

	address_v4 const src(ntohl(ip_header.ip_src.s_addr));
	address_v4 const dst(ntohl(ip_header.ip_dst.s_addr));

	char const* header = "";
	std::string indent;
	if (!quiet_ && home_addr_)
	{
		if (*home_addr_ == src) {
			header = "\x1b[32m=>\n";
			indent = "\x1b[32m";
		}
		else if (*home_addr_ == dst) {
			header = "\x1b[33m<=\n";
			indent = "\x1b[33m          ";
		}
	}

	int const fragment_offset = ntohs(ip_header.ip_off) & IP_OFFMASK;
	int const fragment_id = ntohs(ip_header.ip_id);

	if (fragment_offset == 0) {
		if (pkt.size() < std::ptrdiff_t(sizeof(utphdr) + sizeof(udphdr))) {
			if (!quiet_ && !connid_filter_)
				std::cout << indent << "not uTP " << pkt.size() << " [packet too small]\n";
			return;
		}

		auto const& udp_header = cast<udphdr const>(pkt);
		pkt = pkt.subspan(sizeof(udphdr));

		auto const& utp_header = cast<utphdr const>(pkt);

		stream_key const k{
			src, dst, ntohs(udp_header.source), ntohs(udp_header.dest)
		};

		packet_count_[std::uint16_t(utp_header.connection_id)] += 1;

		if (quiet_) return;

		if (connid_filter_
			&& *connid_filter_ != utp_header.connection_id
			&& *connid_filter_ != ((utp_header.connection_id + 1) & 0xffff)
			&& *connid_filter_ != ((utp_header.connection_id - 1) & 0xffff))
		{
			return;
		}

		std::cout << header;

		if (k.src_port == 443 || k.dst_port == 443) {
			std::cout << indent << "  not uTP " << k << " [https port]\n";
			return;
		}

		std::cout << indent << "uTP " << k << " pkt-size: " << ntohs(ip_header.ip_len);

		if (ip_header.ip_off != 0 || (ntohs(ip_header.ip_off) & IP_MF)) {
			std::cout << indent << " [ fragment-offset: " << (fragment_offset * 8) << " fragment-id: " << fragment_id << " flags:";
			if (ntohs(ip_header.ip_off) & IP_DF)
				std::cout << " DF";
			if (ntohs(ip_header.ip_off) & IP_MF)
				std::cout << " MF";
			std::cout << " ]";
			last_printed_fragment_id_ = fragment_id;
		}
		else {
			last_printed_fragment_id_ = -1;
		}

		std::cout << '\n';

		// make sure this is in fact a uTP packet
		if (utp_header.get_version() != 1) {
			std::cout << indent << "  not uTP " << k << " [invalid version]\n";
			return;
		}
		if (utp_header.get_type() >= NUM_TYPES) {
			std::cout << indent << "  not uTP " << k << " [invalid type]\n";
			return;
		}
		if (utp_header.extension >= 3) {
			std::cout << indent << "  not uTP " << k << " [invalid extension]\n";
			return;
		}

		// we need to parse utp header options to know how large the header is
		pkt = pkt.subspan(sizeof(utphdr));
		std::uint8_t extension = utp_header.extension;
		while (extension != 0) {
			if (pkt.size() < 2) {
				// this is most likely not a uTP packet
				std::cout << indent << "  invalid uTP header options in " << k << '\n';
				return;
			}

			std::cout << indent << "  extension_header: " << int(extension) << " len: " << int(pkt[1]) << "\n";

			std::uint8_t len = pkt[1];

			if (pkt.size() < len + 2) {
				// this is most likely not a uTP packet
				std::cout << indent << "  invalid uTP header options in " << k << '\n';
				return;
			}
			if (extension == 1) {
				std::cout << indent << "    SACK: ";
				for (int i = 0; i < len; ++i) {
					std::uint8_t const bitfield = std::uint8_t(pkt[i + 2]);
					std::uint8_t mask = 1;
					// for each bit
					for (int i = 0; i < 8; ++i)
					{
						std::cout << ((mask & bitfield) ? "1" : "0");
						mask <<= 1;
					}
				}
				std::cout << '\n';
			}
			// next extension header
			extension = pkt[0];
			pkt = pkt.subspan(2 + len);
		}

		if (utp_header.get_type() == ST_SYN) {
			std::cout << indent << "  uTP SYN\n";
		}

		if (utp_header.get_type() == ST_FIN) {
			std::cout << indent << "  uTP FIN\n";
		}

		if (utp_header.get_type() == ST_RESET) {
			std::cout << indent << "  uTP RESET\n";
		}

		std::cout << indent << "  type: " << (utp_header.type_ver >> 4)
			<< " ver: " << (utp_header.type_ver & 0x3)
			<< " ext: " << int(utp_header.extension)
			<< " id: " << std::uint16_t(utp_header.connection_id)
			<< " wnd: " << int(utp_header.wnd_size)
			<< " seq: " << int(utp_header.seq_nr)
			<< " ack: " << int(utp_header.ack_nr)
			<< '\n';
	}
	else {
		if (quiet_) return;

		if (fragment_id != last_printed_fragment_id_) return;

		std::cout << "\x1b[31m";
		std::cout << indent << "[packet fragment] pkt-size: " << ntohs(ip_header.ip_len) << '\n';

		if (ip_header.ip_off != 0) {
			std::cout << indent << "  fragment-offset: " << (fragment_offset * 8) << " id: " << fragment_id;
			if (ntohs(ip_header.ip_off) & IP_DF)
				std::cout << " dont-fragment";
			if (ntohs(ip_header.ip_off) & IP_MF)
				std::cout << " more-fragments";
			std::cout << '\n';
		}
	}

	std::cout << indent << "  uTP payload: " << pkt.size() << '\n';
}

// count number of packets per connection ID
std::unordered_map<std::uint16_t, int> packet_count_;

// when set, only print packets with this connection ID
std::optional<std::uint16_t> connid_filter_;

// the "local" address, to determin what's incoming and outgoing
std::optional<address_v4> home_addr_;

// we use this to remember the IP header ID field we last *printed*. If there's
// any filter in affect, we only want to print fragments whose first packet were
// not fitlered
int last_printed_fragment_id_ = -1;

// don't print any packets (just count stats)
bool quiet_ = false;
};

int print_usage()
{
	std::cout << R"(analyze_utp [OPTIONS] pcap-file

OPTIONS:
--help              print this message
--focus-id <id>     Only print uTP messages with this connection ID, or a
                    connection ID one off this ID (to include both directions)
--home-ip <ip>      Consider the specified IP as local, and indent and mark
                    messages being sent FROM this address as outgoing, and
                    messages sent TO this address as incoming
--stats             Don't print any packets, just collect and print counters
                    for connection IDs.
)";
	return 1;
}

int main(int argc, char const* argv[]) try
{
	if (argc == 1) {
		return print_usage();
	}

	++argv;
	--argc;

	using namespace std::literals::string_literals;

	processor<parse_bittorrent> p;

	while (argc > 1) {
		if (argv[0] == "--help"s) {
			print_usage();
			return 0;
		}
		if (argv[0] == "--stats"s) {
			p.quiet_ = true;
		}
		else if (argv[0] == "--focus-id"s && argc > 2) {
			p.connid_filter_ = atoi(argv[1]);
			++argv;
			--argc;
		}
		else if (argv[0] == "--home-ip"s && argc > 2) {
			p.home_addr_ = make_address_v4(argv[1]);
			++argv;
			--argc;
		}
		else {
			std::cerr << "unknown option: " << argv[0] << '\n';
			return 1;
		}

		++argv;
		--argc;
	}

	pcap_handle h = pcap_open(argv[0]);

	// start packet processing loop, just like live capture
	if (pcap_loop(h, 0, p.handler_wrapper, reinterpret_cast<unsigned char*>(&p)) < 0) {
		std::cerr << "pcap_loop() failed: " << pcap_geterr(h);
		return 1;
	}

	if (!p.quiet_) {
		std::cout << "\x1b[0m\n\n";
	}
	else
	{
		std::cout << "packet counters by connection ID:\n";
		for (auto const& [id, n] : p.packet_count_) {
			std::cout << std::setw(5) << id << ": " << n << '\n';
		}
	}

	return 0;
}
catch (std::exception const& e)
{
	std::cerr << "failed: " << e.what() << '\n';
}


