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

#include <array>
#include <type_traits>

template <typename T, typename IndexType, typename Base>
struct container_wrapper : Base
{
	using underlying_index = typename std::underlying_type<IndexType>::type;

	// pull in constructors from Base class
	using Base::Base;
	container_wrapper() = default;

	explicit container_wrapper(IndexType const s)
		: Base(static_cast<std::size_t>(static_cast<underlying_index>(s))) {}

	decltype(auto) operator[](IndexType idx) const
	{
		assert(idx >= IndexType(0));
		assert(idx < end_index());
		return this->Base::operator[](std::size_t(static_cast<underlying_index>(idx)));
	}

	decltype(auto) operator[](IndexType idx)
	{
		assert(idx >= IndexType(0));
		assert(idx < end_index());
		return this->Base::operator[](std::size_t(static_cast<underlying_index>(idx)));
	}

	IndexType end_index() const
	{
		assert(this->size() <= std::size_t((std::numeric_limits<underlying_index>::max)()));
		return IndexType(static_cast<underlying_index>(this->size()));
	}
};
template <typename T, std::size_t Size, typename IndexType = std::ptrdiff_t>
using array = container_wrapper<T, IndexType, std::array<T, Size>>;

