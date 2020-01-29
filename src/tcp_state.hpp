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
#include "span.hpp"
#include "array.hpp"

using libtorrent::span;
using boost::asio::ip::address_v4;

enum class dir_t : std::uint8_t { in, out };

inline std::ostream& operator<<(std::ostream& os, dir_t const d)
{
	switch (d) {
		case dir_t::in: return os << "\x1b[34m<<";
		case dir_t::out: return os << "\x1b[33m>>";
	};
	return os << "??";
}

enum socket_event_t : std::uint8_t
{
	reset, fin, seqnr_mismatch
};

inline std::ostream& operator<<(std::ostream& os, socket_event_t const e)
{
	using se = socket_event_t;
	switch (e) {
		case se::reset: return os << "RESET";
		case se::fin: return os << "FIN";
		case se::seqnr_mismatch: return os << "(transport layer: mismatching sequence numbers)";
	};
	return os << "EVENT: ??";
}


struct tcp_side_state
{
	bool closed = false;
	std::uint32_t seqnr = 0;
	// store out of order segments here
	std::map<std::uint32_t, std::vector<unsigned char>> ooo_;
};

template <typename Handler>
struct tcp_state
{
	tcp_state(stream_key const& k)
		: key(k)
		, handler(k)
	{}

	void syn(tcphdr const& hdr, dir_t const d)
	{
		state_[d].seqnr = ntohl(hdr.seq) + 1;
	}

	bool fin(timeval const& ts, dir_t const d)
	{
		state_[d].closed = true;
		handler.event(ts, socket_event_t::fin, d);
		return state_[(d == dir_t::out) ? dir_t::in : dir_t::out].closed;
	}

	void rst(timeval const& ts, dir_t const d)
	{
		handler.event(ts, socket_event_t::reset, d);
	}

	// returns false if this packet is a duplicate and should be ignored. For now
	// re-packetized messages are not supported. i.e. no overlapping byte ranges
	void packet(timeval const& ts, tcphdr const& hdr, span<unsigned char const> buf, dir_t const d)
	{
		if (buf.size() == 0) return;
		auto& s = state_[d];
		std::uint32_t const incoming_seqnr = ntohl(hdr.seq);
		if (incoming_seqnr != s.seqnr) {
			// if hdr.seq is higher than what we expect, it's an out of order
			// message. Store it in s.ooo_.
			if (std::uint32_t(incoming_seqnr - s.seqnr) < std::numeric_limits<std::uint32_t>::max() / 2) {
				s.ooo_.emplace(incoming_seqnr, std::vector<unsigned char>(buf.begin(), buf.end()));
//				std::cout << "TCP " << key << " out of order " << s.ooo_.size() << '\n';
				return;
			}
			// if it's a clean retransmit of a segment, don't bother logging
			if (incoming_seqnr + buf.size() != state_[d].seqnr) {
//				std::cout << "TCP " << key << '\n';
//				std::cout << "  mismatch seqnr: " << state_[d].seqnr
//					<< (d == dir_t::in ? " incoming: " : "outgoing: ") << incoming_seqnr
//					<< " size: " << buf.size()
//					<< " diff: " << std::int32_t(state_[d].seqnr - incoming_seqnr) << '\n';
				handler.event(ts, socket_event_t::seqnr_mismatch, d);
			}
		}
		else {
			s.seqnr += buf.size();
			handler.data(ts, buf, d);
			auto it = s.ooo_.find(s.seqnr);
			while (it != s.ooo_.end()) {
				s.seqnr += it->second.size();
//				std::cout << "TCP " << key << " replaying from out of order buffer: " << s.ooo_.size() << "\n";
				handler.data(ts, it->second, d);
				s.ooo_.erase(it);
				it = s.ooo_.find(s.seqnr);
			}
		}
	}

private:

	stream_key key;

	// incoming and outgoing are relative the node that sent the first SYN.
	// That's the outgoing direction. The SYN+ACK is then incoming.
	array<tcp_side_state, 2, dir_t> state_;

	Handler handler;
};

