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

#include "tcp_state.hpp"
#include "bdecode.hpp"

#include <bitset>

using boost::system::error_code;
using libtorrent::bdecode;
using libtorrent::bdecode_node;

inline std::ostream& operator<<(std::ostream& os, timeval const& ts)
{
	return os << ts.tv_sec << '.' << std::setfill('0') << std::setw(3) << ts.tv_usec / 1000;
}

enum class state_t : std::uint8_t {
	protocol,
	reserved,
	info_hash,
	peer_id,
	length,
	msg,
	have,
	dht_port,
	allowed_fast,
	request,
	piece,
	cancel,
	suggest,
	reject,
	bitfield,
	extension,
	extension_handshake,
	skip
};

struct bittorrent_side_state
{
	std::uint32_t skip_ = 0;
	std::uint64_t offset_ = 0;
	state_t state_ = state_t::protocol;
	std::vector<unsigned char> buffer_;
	std::vector<unsigned char> reserved_;

	std::map<int, std::string> extensions_;

	// make sure our internal buffer has at least "bytes" bytes in it
	span<unsigned char const> ensure_buffer(span<unsigned char const> buf, int const bytes)
	{
		if (buffer_.size() >= static_cast<std::size_t>(bytes)) return buf;
		int const overlap = std::min(buf.size(), std::ptrdiff_t(bytes - buffer_.size()));
		buffer_.insert(buffer_.end(), buf.data(), buf.data() + overlap);
		return buf.subspan(overlap);
	}
};

std::string msg_type_name(int const msg)
{
	std::array<char const*, 21> message_name = {{"choke", "unchoke", "interested", "not_interested"
		, "have", "bitfield", "request", "piece", "cancel", "dht_port", "??", "??", "??"
		, "suggest_piece", "have_all", "have_none", "reject_request", "allowed_fast", "??", "??", "extension-msg"}};

	if (msg >= 0 && static_cast<std::size_t>(msg) < message_name.size()) {
		return message_name[msg];
	}
	return "?? (" + std::to_string(msg) + ")";
}

std::uint32_t read_u32(span<unsigned char const> buf)
{
	if (buf.size() < 4) throw std::runtime_error("internal inconsistency");
	return (std::uint32_t(buf[0]) << 24)
		| (std::uint32_t(buf[1]) << 16)
		| (std::uint32_t(buf[2]) << 8)
		| std::uint32_t(buf[3]);
}

std::uint16_t read_u16(span<unsigned char const> buf)
{
	if (buf.size() < 2) throw std::runtime_error("internal inconsistency");
	return (std::uint16_t(buf[0]) << 8)
		| std::uint16_t(buf[1]);
}

dir_t opposite(dir_t const d)
{
	return d == dir_t::in ? dir_t::out : dir_t::in;
}

std::string printable(span<unsigned char const> bytes)
{
	std::string ret;
	for (auto const c : bytes) {
		if (c >= ' ' && c < 127) ret += c;
		else ret += '.';
	}
	return ret;
}

struct parse_bittorrent
{
	parse_bittorrent(stream_key const& key)
		: key_(key)
	{
	}

	void event(timeval const& ts, socket_event_t e, dir_t d)
	{
		log_ << d << ' ' << ts << ' ' << e << '\n';
	}

	void check_zero(bittorrent_side_state& s, dir_t const d)
	{
		if (s.skip_ == 0) s.state_ = state_t::length;
		else {
			log_ << d << " ERROR: unexpected bytes after message: " << s.skip_ << '\n';
			s.state_ = state_t::skip;
		}
	}

	void data(timeval const& ts, span<unsigned char const> buf, dir_t d)
	{
		// we're not following this stream
		if (disabled_) return;
		if (buf.empty()) {
			if (log_.is_open()) log_ << d << ' ' << ts << " ACK\n";
			return;
		}

		auto& s = state_[d];
		if (s.state_ == state_t::protocol) {
			buf = s.ensure_buffer(buf, 20);
			if (s.buffer_.size() < 20) return;

			char const handshake[] = "\x13" "BitTorrent protocol";
			if (memcmp(s.buffer_.data(), handshake, sizeof(handshake) - 1) != 0) {
				disabled_ = true;
				return;
			}
			s.buffer_.clear();
			s.offset_ += 20;
			if (log_.is_open()) log_ << d << ' ' << ts << " HANDSHAKE\n";
			s.state_ = state_t::reserved;
		}

		if (s.state_ == state_t::reserved) {
			buf = s.ensure_buffer(buf, 8);
			if (s.buffer_.size() < 8) return;

			if (log_.is_open()) {
				log_ << d << ' ' << ts << " RESERVED " << std::hex;
				for (auto const c : s.buffer_) log_ << std::setw(2) << std::setfill('0') << int(c);
				log_ << std::dec << '\n';
			}
			else {
				s.reserved_ = std::move(s.buffer_);
			}
			s.buffer_.clear();
			s.offset_ += 8;
			s.state_ = state_t::info_hash;
		}

		if (s.state_ == state_t::info_hash) {
			buf = s.ensure_buffer(buf, 20);
			if (s.buffer_.size() < 20) return;

			std::stringstream ih;
			ih << std::hex;
			for (auto const c : s.buffer_) ih << std::setw(2) << std::setfill('0') << int(c);

			if (!log_.is_open()) {
				mkdir("bt", 0755);
				mkdir(("bt/" + ih.str()).c_str(), 0755);
				static int stream_cnt = 0;
				log_.open(str("bt/", ih.str(), "/", key_.src, ".", key_.src_port, "_", key_.dst, ".", key_.dst_port, "_", stream_cnt));
				++stream_cnt;
				log_ << d << ' ' << ts << " HANDSHAKE\n";
				log_ << d << ' ' << ts << " RESERVED " << std::hex;
				for (auto const c : s.reserved_) log_ << std::setw(2) << std::setfill('0') << int(c);
				log_ << std::dec << '\n';
			}
			log_ << d << ' ' << ts << " INFO-HASH " << std::hex;
			for (auto const c : s.buffer_) log_ << std::setw(2) << std::setfill('0') << int(c);
			log_ << std::dec << '\n';
			s.buffer_.clear();
			s.offset_ += 20;
			s.state_ = state_t::peer_id;
		}

		if (s.state_ == state_t::peer_id) {
			buf = s.ensure_buffer(buf, 20);
			if (s.buffer_.size() < 20) return;

			log_ << d << ' ' << ts << " PEER-ID " << std::hex;
			for (auto const c : s.buffer_) log_ << std::setw(2) << std::setfill('0') << int(c);
			log_ << std::dec << " [" << printable(s.buffer_) << "]\n";
			s.buffer_.clear();
			s.offset_ += 20;
			s.state_ = state_t::length;
		}

		while (buf.size() > 0) {

			if (s.state_ == state_t::length) {
				buf = s.ensure_buffer(buf, 4);
				if (s.buffer_.size() < 4) return;

				std::uint32_t const length = read_u32(s.buffer_);
				if (length > 0x100000) {
					log_ << d << ' ' << ts << " ERROR: message too large! " << length << " (" << std::hex << length << ")" << std::dec << '\n';
				}

				s.offset_ += 4;
				s.buffer_.clear();

				if (length == 0) {
					// if skip is 0, this was a keep-alive message. The next state
					// should be to read another length prefix
					log_ << d << ' ' << ts << " KEEP-ALIVE\n";
				}
				else {
					s.skip_ = length;
					s.state_ = state_t::msg;

//					log_ << d << ' ' << ts << " length-prefix: " << length << "\n";
				}
			}

			if (s.state_ == state_t::msg) {
				buf = s.ensure_buffer(buf, 1);
				if (s.buffer_.size() < 1) return;

				int const msg = s.buffer_[0];

				s.offset_ += 1;
				s.buffer_.clear();
				s.skip_ -= 1;
				switch (msg) {
					case 0: log_ << d << ' ' << ts << " CHOKE\n"; check_zero(s, d); break;
					case 1: log_ << d << ' ' << ts << " UNCHOKE\n"; check_zero(s, d); break;
					case 2: log_ << d << ' ' << ts << " INTERESTED\n"; check_zero(s, d); break;
					case 3: log_ << d << ' ' << ts << " NOT-INTERESTED\n"; check_zero(s, d); break;
					case 4: s.state_ = state_t::have; break;
					case 5: s.state_ = state_t::bitfield; break;
					case 6: s.state_ = state_t::request; break;
					case 7: s.state_ = state_t::piece; break;
					case 8: s.state_ = state_t::cancel; break;
					case 9: s.state_ = state_t::dht_port; break;
					case 13: s.state_ = state_t::suggest; break;
					case 14: log_ << d << ' ' << ts << " HAVE-ALL\n"; check_zero(s, d); break;
					case 15: log_ << d << ' ' << ts << " HAVE-NONE\n"; check_zero(s, d); break;
					case 16: s.state_ = state_t::reject; break;
					case 17: s.state_ = state_t::allowed_fast; break;
					case 20: s.state_ = state_t::extension; break;
					default:
						log_ << d << ' ' << ts << " msg: " << msg_type_name(msg) << '\n';
						s.state_ = state_t::skip;
						break;
				}
			}

			if (s.state_ == state_t::have
				|| s.state_ == state_t::allowed_fast
				|| s.state_ == state_t::suggest)
			{
				buf = s.ensure_buffer(buf, 4);
				if (s.buffer_.size() < 4) return;

				std::uint32_t const piece = read_u32(s.buffer_);
				switch (s.state_) {
					case state_t::have: log_ << d << ' ' << ts << " HAVE " << piece <<"\n"; break;
					case state_t::suggest: log_ << d << ' ' << ts << " SUGGEST " << piece <<"\n"; break;
					case state_t::allowed_fast: log_ << d << ' ' << ts << " ALLOWED-FAST " << piece <<"\n"; break;
					default: assert(false);
				}

				s.offset_ += 4;
				s.buffer_.clear();
				s.skip_ -= 4;
				check_zero(s, d);
			}

			if (s.state_ == state_t::extension) {
				buf = s.ensure_buffer(buf, 1);
				if (s.buffer_.size() < 1) return;

				std::uint32_t const extension_msg = s.buffer_[0];

				s.offset_ += 1;
				s.buffer_.clear();
				s.skip_ -= 1;

				// this is the extension handshake. It's a bencoded structure, load
				// it all and parse it
				if (extension_msg == 0) {
					s.state_ = state_t::extension_handshake;
				}
				else {

					auto& other = state_[opposite(d)];
					auto it = other.extensions_.find(extension_msg);
					if (it == other.extensions_.end()) {
						log_ << d << ' ' << ts << " EXTENSION-MSG: ?? (" << extension_msg << ")\n";
					}
					else {
						log_ << d << ' ' << ts << " EXTENSION-MSG: " << it->second <<"\n";
					}
					s.state_ = state_t::skip;
				}
			}

			if (s.state_ == state_t::extension_handshake) {
				buf = s.ensure_buffer(buf, s.skip_);
				if (s.buffer_.size() < s.skip_) return;

				error_code ec;
				auto e = bdecode({reinterpret_cast<char const*>(s.buffer_.data())
					, std::ptrdiff_t(s.buffer_.size())}, ec);
				if (ec) {
					log_ << d << ' ' << ts << " EXTENSION-HANDSHAKE " << ec.message() << "\n";
				}
				else {
					log_ << d << ' ' << ts << " EXTENSION-HANDSHAKE " << print_entry(e) << "\n";
					auto const m = e.dict_find_dict("m");
					if (m) {
						for (int i = 0; i < m.dict_size(); ++i) {
							string_view name;
							bdecode_node val;
							std::tie(name, val) = m.dict_at(i);
							if (val.type() == bdecode_node::int_t)
								s.extensions_[val.int_value()] = std::string(name);
						}
					}
				}

				s.offset_ += s.skip_;
				s.buffer_.clear();
				s.skip_ = 0;
				s.state_ = state_t::length;
			}

			if (s.state_ == state_t::request
				|| s.state_ == state_t::reject
				|| s.state_ == state_t::cancel)
			{
				buf = s.ensure_buffer(buf, 12);
				if (s.buffer_.size() < 12) return;

				std::uint32_t const piece = read_u32(s.buffer_);
				s.buffer_.erase(s.buffer_.begin(), s.buffer_.begin() + 4);
				std::uint32_t const start = read_u32(s.buffer_);
				s.buffer_.erase(s.buffer_.begin(), s.buffer_.begin() + 4);
				std::uint32_t const length = read_u32(s.buffer_);

				log_ << d << ' ' << ts;
				switch (s.state_) {
					case state_t::request: log_ << " REQUEST "; break;
					case state_t::cancel: log_ << " CANCEL "; break;
					case state_t::reject: log_ << " REJECT "; break;
					default: assert(false);
				}
				log_ << piece << ' ' << start << ' ' << length << '\n';

				s.offset_ += 12;
				s.buffer_.clear();
				s.skip_ -= 12;
				check_zero(s, d);
			}

			if (s.state_ == state_t::piece) {
				buf = s.ensure_buffer(buf, 8);
				if (s.buffer_.size() < 8) return;

				std::uint32_t const piece = read_u32(s.buffer_);
				s.buffer_.erase(s.buffer_.begin(), s.buffer_.begin() + 4);
				std::uint32_t const start = read_u32(s.buffer_);

				log_ << d << ' ' << ts << " PIECE " << piece << ' ' << start << '\n';

				s.offset_ += 8;
				s.buffer_.clear();
				s.skip_ -= 8;
				s.state_ = state_t::skip;
			}

			if (s.state_ == state_t::dht_port) {
				buf = s.ensure_buffer(buf, 2);
				if (s.buffer_.size() < 2) return;

				std::uint16_t const port = read_u16(s.buffer_);
				log_ << d << ' ' << ts << " DHT-PORT " << port <<"\n";

				s.offset_ += 2;
				s.buffer_.clear();
				s.skip_ -= 2;
				check_zero(s, d);
			}

			if (s.state_ == state_t::bitfield) {
				buf = s.ensure_buffer(buf, s.skip_);
				if (s.buffer_.size() < s.skip_) return;

				log_ << d << ' ' << ts << " BITFIELD ";
				for (auto const c : s.buffer_) {
					log_ << std::bitset<8>(c);
				}
				log_ << '\n';

				s.offset_ += s.skip_;
				s.buffer_.clear();
				s.skip_ = 0;
				s.state_ = state_t::length;
			}

			if (buf.size() == 0) break;
			if (s.state_ == state_t::skip) {
				int const overlap = std::min(std::uint32_t(buf.size()), s.skip_);
				s.skip_ -= overlap;
				buf = buf.subspan(overlap);
				s.offset_ += overlap;

				log_ << d << ' ' << ts << "   - payload: " << overlap << " (left: " << s.skip_ << ")\n";

				if (s.skip_ == 0) {
					// once we've skipped all the payload, go back to reading a
					// length prefix
					s.state_ = state_t::length;
				}
			}
		}

//		std::cout << "incoming " << buf.size() << " bytes\n";
	}

private:
	stream_key key_;
	std::ofstream log_;
	array<bittorrent_side_state, 2, dir_t> state_;
	bool disabled_ = false;
};

