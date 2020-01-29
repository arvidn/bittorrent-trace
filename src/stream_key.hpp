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

using boost::asio::ip::address_v4;

struct stream_key
{
	address_v4 src;
	address_v4 dst;
	std::uint16_t src_port;
	std::uint16_t dst_port;

	friend bool operator!=(stream_key const& lhs, stream_key const& rhs)
	{
		return lhs.src != rhs.src
			|| lhs.dst != rhs.dst
			|| lhs.src_port != rhs.src_port
			|| lhs.dst_port != rhs.dst_port;
	}

	friend bool operator<(stream_key const& lhs, stream_key const& rhs)
	{
		if (lhs.src != rhs.src) return lhs.src < rhs.src;
		if (lhs.dst != rhs.dst) return lhs.dst < rhs.dst;
		if (lhs.src_port != rhs.src_port) return lhs.src_port < rhs.src_port;
		return lhs.dst_port < rhs.dst_port;
	}

	friend std::ostream& operator<<(std::ostream& os, stream_key const& st)
	{
		return os << st.src << ":" << st.src_port
			<< " -> " << st.dst << ":" << st.dst_port;
	}
};

inline stream_key swap(stream_key const& k)
{
	return stream_key{k.dst, k.src, k.dst_port, k.src_port};
}

struct utp_stream_key
{
	stream_key ip;
	std::uint16_t connid;

	friend bool operator<(utp_stream_key const& lhs, utp_stream_key const& rhs)
	{
		if (lhs.ip != rhs.ip) return lhs.ip < rhs.ip;
		return lhs.connid < rhs.connid;
	}

	friend std::ostream& operator<<(std::ostream& os, utp_stream_key const& st)
	{
		return os << st.ip << " [" << st.connid << "]";
	}
};

inline utp_stream_key swap(utp_stream_key const& k, int const offset)
{
	return utp_stream_key{swap(k.ip), std::uint16_t(k.connid + offset)};
}

inline utp_stream_key inc_connid(utp_stream_key const& k, int const offset)
{
	return utp_stream_key{k.ip, std::uint16_t(k.connid + offset)};
}
