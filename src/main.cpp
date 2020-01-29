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

#include "tcp_state.hpp"
#include "utp_state.hpp"
#include "pcap.hpp"
#include "str.hpp"
#include "bittorrent.hpp"

using libtorrent::span;
using boost::asio::ip::address_v4;

struct logger
{
	logger(stream_key const& key)
	{
		log[0].open(str("tcp/", key.src, ":", key.src_port, "-", key.dst, ":", key.dst_port, "-", this, "-in"));
		log[1].open(str("tcp/", key.src, ":", key.src_port, "-", key.dst, ":", key.dst_port, "-", this, "-out"));
	}

	void data(span<unsigned char const> buf, dir_t d)
	{
//		std::cout << "incoming " << buf.size() << " bytes\n";
		log[std::uint8_t(d)].write((char const*)buf.data(), buf.size());
	}

private:
	std::ofstream log[2];
};

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

std::pair<typename std::map<utp_stream_key, utp_state<Handler>>::iterator, dir_t>
find_utp_stream(utp_stream_key const s)
{
	auto it = utp_streams_.find(s);
	dir_t d = dir_t::out;
	if (it == utp_streams_.end()) {
		it = utp_streams_.find(swap(s, 0));
		d = dir_t::in;
		if (it == utp_streams_.end()) {
			it = utp_streams_.find(swap(s, 1));
			if (it == utp_streams_.end()) {
				it = utp_streams_.find(swap(s, -1));
				if (it == utp_streams_.end()) {
					return {utp_streams_.end(), dir_t::out};
				}
			}
		}
	}
	return {it, d};
}

void process(timeval const& ts, span<unsigned char const> pkt)
{
// TODO: ensure this is an ethernet frame, and maybe even support other physical links

	auto const& eth_header = cast<ether_header const>(pkt);
	pkt = pkt.subspan(sizeof(ether_header));

	// we're only interested in IP packets
	if (ntohs(eth_header.ether_type) != ETHERTYPE_IP) return;

	auto const& ip_header = cast<ip const>(pkt);
	// read the header length to skip over IP option headers too
	int const ip_header_len = int(ip_header.ip_hl) * 4;
	pkt = pkt.subspan(ip_header_len, ntohs(ip_header.ip_len) - ip_header_len);

	if (ip_header.ip_hl < 5) {
		// invalid packet
		std::cout << "ignoring IP packet with header length: " << ip_header.ip_hl << "\n";
		return;
	}

	// we only support IPv4
	if (ip_header.ip_v != 4) return;

	if (ip_header.ip_p == IPPROTO_TCP) {
		auto const& tcp_header = cast<tcphdr const>(pkt);
		// read the data offset header to skip over TCP options
		pkt = pkt.subspan(int(tcp_header.th_off) * 4);

		if (tcp_header.th_off < 5) {
			// invalid packet
			std::cout << "ignoring TCP packet with header length: " << tcp_header.th_off << "\n";
			return;
		}

		stream_key const s{
			address_v4(ntohl(ip_header.ip_src.s_addr)),
			address_v4(ntohl(ip_header.ip_dst.s_addr)),
			ntohs(tcp_header.source),
			ntohs(tcp_header.dest)
		};

//		std::cout << "TCP " << s << '\n';

		if ((ip_header.ip_off & IP_OFFMASK) != 0
			&& (ip_header.ip_off & IP_MF) != 0)
		{
			std::cout << "TCP " << s << '\n';
			std::cout << "ignoring fragmented IP packet\n";
			return;
		}

		if (tcp_header.syn && tcp_header.ack) {
			// this is a response, so the stream is already open
			// in the "other direction".
			auto const it = tcp_streams_.find(swap(s));
			if (it == tcp_streams_.end()) {
//				std::cout << "ignoring TCP SYN+ACK " << s << '\n';
				return;
			}
//			std::cout << "TCP SYN+ACK " << s << '\n';
			it->second.syn(tcp_header, dir_t::in);
			if (pkt.size() > 0) std::cout << "SYN+ACK with payload!\n";
			return;
		}

		if (tcp_header.syn) {
			// this is initiating a new stream.
			auto it = tcp_streams_.find(s);
			if (it != tcp_streams_.end()) {
//				std::cout << "ignoring TCP SYN " << s << '\n';
				return;
			}
//			std::cout << "TCP SYN " << s << '\n';
			it = tcp_streams_.emplace(s, tcp_state<Handler>{s}).first;
			it->second.syn(tcp_header, dir_t::out);
			if (pkt.size() > 0) std::cout << "SYN with payload!\n";
			return;
		}

		auto it = tcp_streams_.find(s);
		if (it != tcp_streams_.end()) {
			if (tcp_header.fin) {
//				std::cout << "TCP FIN " << s << '\n';
				if (it->second.fin(ts, dir_t::out)) tcp_streams_.erase(it);
			}
			else if (tcp_header.rst) {
//				std::cout << "TCP RST " << s << '\n';
				it->second.rst(ts, dir_t::out);
				tcp_streams_.erase(it);
			}
			else {
//				std::cout << "TCP " << s << '\n';
				it->second.packet(ts, tcp_header, pkt, dir_t::out);
			}
			return;
		}

		it = tcp_streams_.find(swap(s));
		if (it != tcp_streams_.end()) {
			if (tcp_header.fin) {
//				std::cout << "TCP FIN " << s << '\n';
				if (it->second.fin(ts, dir_t::in)) tcp_streams_.erase(it);
			}
			else if (tcp_header.rst) {
//				std::cout << "TCP RST " << s << '\n';
				it->second.rst(ts, dir_t::in);
				tcp_streams_.erase(it);
			}
			else {
//				std::cout << "TCP " << s << '\n';
				it->second.packet(ts, tcp_header, pkt, dir_t::in);
			}
			return;
		}

//		std::cout << "ignoring TCP segment " << s << '\n';
	}
	else if (ip_header.ip_p == IPPROTO_UDP && pkt.size() >= std::ptrdiff_t(sizeof(utphdr) + sizeof(udphdr))) {

		auto const& udp_header = cast<udphdr const>(pkt);
		pkt = pkt.subspan(sizeof(udphdr));

		auto const& utp_header = cast<utphdr const>(pkt);

		stream_key const k{
			address_v4(ntohl(ip_header.ip_src.s_addr)),
			address_v4(ntohl(ip_header.ip_dst.s_addr)),
			ntohs(udp_header.source),
			ntohs(udp_header.dest)
		};

		// make sure this is in fact a uTP packet
		if (utp_header.get_version() != 1) return;
		if (utp_header.get_type() >= NUM_TYPES) return;
		if (utp_header.extension >= 3) return;
		if (k.src_port == 443) return;
		if (k.dst_port == 443) return;

		// we need to parse utp header options to know how large the header is
		pkt = pkt.subspan(sizeof(utphdr));
		std::uint8_t extension = utp_header.extension;
		while (extension != 0) {
			if (pkt.size() < 2) {
				// this is most likely not a uTP packet
//				std::cout << "ERROR: invalid uTP header options in " << k << '\n';
				return;
			}

			extension = pkt[0];
			std::uint8_t len = pkt[1];

			if (pkt.size() < len + 2) {
				// this is most likely not a uTP packet
//				std::cout << "ERROR: invalid uTP header options in " << k << '\n';
				return;
			}
			pkt = pkt.subspan(2 + len);
		}

//		std::cout << "uTP " << k << '\n';

		if ((ip_header.ip_off & IP_OFFMASK) != 0
			&& (ip_header.ip_off & IP_MF) != 0)
		{
			std::cout << "uTP " << k << '\n';
			std::cout << "ignoring fragmented IP packet\n";
			return;
		}

		utp_stream_key const s{k, std::uint16_t(utp_header.connection_id) };

		auto [it, d] = find_utp_stream(s);

		if (utp_header.get_type() == ST_SYN) {
			if (it != utp_streams_.end()) {
				it->second.syn(utp_header, d);
//				if (d == dir_t::out)
//					std::cout << "uTP SYN " << s << '\n';
//				else
//					std::cout << "uTP SYN+ACK " << s << '\n';
				return;
			}
			it = utp_streams_.emplace(inc_connid(s, 1), utp_state<Handler>{s}).first;
			it->second.syn(utp_header, dir_t::out);
//			std::cout << "uTP SYN " << s << '\n';
			return;
		}

		if (it == utp_streams_.end()) {
// this may not actually be a utp packet.
//			std::cout << "ignoring uTP segment " << s << '\n';
			return;
		}

		if (utp_header.get_type() == ST_FIN) {
			if (it->second.fin(ts, d)) {
				utp_streams_.erase(it);
			}
			return;
		}

		if (utp_header.get_type() == ST_RESET) {
			it->second.rst(ts, d);
			utp_streams_.erase(it);
			return;
		}

//		std::cout << "uTP " << s << '\n';
		it->second.packet(ts, utp_header, pkt, d);

	}
}

private:
	std::map<stream_key, tcp_state<Handler>> tcp_streams_;
	std::map<utp_stream_key, utp_state<Handler>> utp_streams_;
};

int main(int const argc, char const* argv[]) try
{
	pcap_handle h = pcap_open(argv[1]);

//	processor<logger> p;
	processor<parse_bittorrent> p;

	// start packet processing loop, just like live capture
	if (pcap_loop(h, 0, p.handler_wrapper, reinterpret_cast<unsigned char*>(&p)) < 0) {
		std::cerr << "pcap_loop() failed: " << pcap_geterr(h);
		return 1;
	}

	return 0;
}
catch (std::exception const& e)
{
	std::cerr << "failed: " << e.what() << '\n';
}


