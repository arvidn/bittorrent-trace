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

#pragma once

#include <boost/asio/ip/address_v4.hpp>

#include "stream_key.hpp"
#include "tcp_state.hpp"
#include "span.hpp"
#include "array.hpp"
#include "utphdr.hpp"

using libtorrent::span;
using boost::asio::ip::address_v4;

struct utp_side_state
{
	bool closed = false;
	bool connected = false;
	std::uint16_t seqnr = 0;
	std::uint16_t connid = 0;
	// store out of order segments here
	std::map<std::uint16_t, std::vector<unsigned char>> ooo_;
};

template <typename Handler>
struct utp_state
{
	utp_state(utp_stream_key const& k)
		: key(k)
		, handler(k.ip)
	{}

	void syn(utphdr const& hdr, dir_t const d)
	{
		auto& s = state_[d];
		s.connected = true;
		s.seqnr = hdr.seq_nr + 1;
		s.connid = hdr.connection_id;
	}

	bool fin(timeval const& ts, dir_t const d)
	{
		auto& s = state_[d];
		s.closed = true;
		handler.event(ts, socket_event_t::fin, d);
		return state_[(d == dir_t::out) ? dir_t::in : dir_t::out].closed;
	}

	void rst(timeval const& ts, dir_t const d)
	{
		handler.event(ts, socket_event_t::reset, d);
	}

	// returns false if this packet is a duplicate and should be ignored. For now
	// re-packetized messages are not supported. i.e. no overlapping byte ranges
	void packet(timeval const& ts, utphdr const& hdr, span<unsigned char const> buf, dir_t const d)
	{
		auto& s = state_[d];
		if (!s.connected) {
			s.seqnr = hdr.seq_nr;
			s.connected = true;
			s.connid = hdr.connection_id;
		}

		if (buf.size() == 0) return;

		if (hdr.seq_nr != s.seqnr) {
			// if hdr.seq is higher than what we expect, it's an out of order
			// message. Store it in s.ooo_.
			if (std::uint16_t(hdr.seq_nr - s.seqnr) < std::numeric_limits<std::uint16_t>::max() / 2) {
				s.ooo_.emplace(hdr.seq_nr, std::vector<unsigned char>(buf.begin(), buf.end()));
//				std::cout << "uTP " << key << " out of order " << s.ooo_.size() << '\n';
				return;
			}

//			std::cout << "uTP " << key << " resent (" << std::uint16_t(hdr.seq_nr)
//				<< ") next: " << s.seqnr
//				<< " diff: " << std::uint16_t(hdr.seq_nr) - s.seqnr  << "\n";
		}
		else {
			++s.seqnr;
			handler.data(ts, buf, d);
			auto it = s.ooo_.find(s.seqnr);
			while (it != s.ooo_.end()) {
				++s.seqnr;
//				std::cout << "uTP " << key << " replaying from out of order buffer: " << s.ooo_.size() << "\n";
				handler.data(ts, it->second, d);
				s.ooo_.erase(it);
				it = s.ooo_.find(s.seqnr);
			}
		}
	}

private:

	utp_stream_key key;

	// incoming and outgoing are relative the node that sent the first SYN.
	// That's the outgoing direction. The SYN+ACK is then incoming.
	array<utp_side_state, 2, dir_t> state_;

	Handler handler;
};


