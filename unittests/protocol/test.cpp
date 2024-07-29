#define BOOST_TEST_MAIN

#ifdef USE_MIMALLOC

#ifdef MI_OVERRIDE
#	include <mimalloc.h>
#else
#	include <mimalloc-new-delete.h>
#endif

#ifdef _WIN32
#	include <mimalloc-new-delete.h>
#endif

#endif // USE_MIMALLOC

#include <boost/test/included/unit_test.hpp>
#include <cstdlib>
#include <ctime>

#include "utils/misc.hpp"
#include "utils/crypto.hpp"
#include "avpn/protocol.hpp"

namespace
{
	// Returns the highest byte of `val` in a uint8_t.
	uint8_t HighestByte(uint64_t val)
	{
		return static_cast<uint8_t>(val >> 56);
	}

	// Returns the result of writing partial data from `source`, of
	// `source_bit_count` size in the highest bits, to `target` at
	// `target_bit_offset` from the highest bit.
	uint8_t WritePartialByte(uint8_t source, size_t source_bit_count, uint8_t target, size_t target_bit_offset)
	{
		// RTC_DCHECK(target_bit_offset < 8);
		// RTC_DCHECK(source_bit_count < 9);
		// RTC_DCHECK(source_bit_count <= (8 - target_bit_offset));
		// Generate a mask for just the bits we're going to overwrite, so:
		uint8_t mask =
			// The number of bits we want, in the most significant bits...
			static_cast<uint8_t>(0xFF << (8 - source_bit_count))
			// ...shifted over to the target offset from the most signficant bit.
			>> target_bit_offset;
		// We want the target, with the bits we'll overwrite masked off, or'ed with
		// the bits from the source we want.
		return (target & ~mask) | (source >> target_bit_offset);
	}
} // namespace

class BitBufferWriter
{
public:
	// Constructs a bit buffer for the writable buffer of `bytes`.
	BitBufferWriter(uint8_t* bytes, size_t byte_count)
		: writable_bytes_(bytes)
		, byte_count_(byte_count)
		, byte_offset_()
		, bit_offset_()
	{
		BOOST_ASSERT(static_cast<uint64_t>(byte_count_) <= std::numeric_limits<uint32_t>::max());
	}

	BitBufferWriter(const BitBufferWriter&)			   = delete;
	BitBufferWriter& operator=(const BitBufferWriter&) = delete;

	// Gets the current offset, in bytes/bits, from the start of the buffer. The
	// bit offset is the offset into the current byte, in the range [0,7].
	void GetCurrentOffset(size_t* out_byte_offset, size_t* out_bit_offset)
	{
		BOOST_ASSERT(out_byte_offset != nullptr);
		BOOST_ASSERT(out_bit_offset != nullptr);

		*out_byte_offset = byte_offset_;
		*out_bit_offset	 = bit_offset_;
	}

	// The remaining bits in the byte buffer.
	uint64_t RemainingBitCount() const
	{
		return (static_cast<uint64_t>(byte_count_) - byte_offset_) * 8 - bit_offset_;
	}

	// Moves current position `byte_count` bytes forward. Returns false if
	// there aren't enough bytes left in the buffer.
	bool ConsumeBytes(size_t byte_count)
	{
		return ConsumeBits(byte_count * 8);
	}

	// Moves current position `bit_count` bits forward. Returns false if
	// there aren't enough bits left in the buffer.
	bool ConsumeBits(size_t bit_count)
	{
		if (bit_count > RemainingBitCount())
			return false;

		byte_offset_ += (bit_offset_ + bit_count) / 8;
		bit_offset_ = (bit_offset_ + bit_count) % 8;

		return true;
	}

	// Sets the current offset to the provied byte/bit offsets. The bit
	// offset is from the given byte, in the range [0,7].
	bool Seek(size_t byte_offset, size_t bit_offset)
	{
		if (byte_offset > byte_count_ || bit_offset > 7 || (byte_offset == byte_count_ && bit_offset > 0))
			return false;

		byte_offset_ = byte_offset;
		bit_offset_	 = bit_offset;

		return true;
	}


	// Writes byte-sized values from the buffer. Returns false if there isn't
	// enough data left for the specified type.
	bool WriteUInt8(uint8_t val)
	{
		return WriteBits(val, sizeof(uint8_t) * 8);
	}

	bool WriteUInt16(uint16_t val)
	{
		return WriteBits(val, sizeof(uint16_t) * 8);
	}

	bool WriteUInt32(uint32_t val)
	{
		return WriteBits(val, sizeof(uint32_t) * 8);
	}

	// Writes bit-sized values to the buffer. Returns false if there isn't enough
	// room left for the specified number of bits.
	bool WriteBits(uint64_t val, size_t bit_count)
	{
		if (bit_count > RemainingBitCount())
			return false;

		size_t total_bits = bit_count;

		// For simplicity, push the bits we want to read from val to the highest bits.
		val <<= (sizeof(uint64_t) * 8 - bit_count);
		uint8_t* bytes = writable_bytes_ + byte_offset_;

		// The first byte is relatively special; the bit offset to write to may put us
		// in the middle of the byte, and the total bit count to write may require we
		// save the bits at the end of the byte.
		size_t remaining_bits_in_current_byte = 8 - bit_offset_;
		size_t bits_in_first_byte			  = std::min(bit_count, remaining_bits_in_current_byte);
		*bytes = WritePartialByte(HighestByte(val), bits_in_first_byte, *bytes, bit_offset_);
		if (bit_count <= remaining_bits_in_current_byte)
		{
			// Nothing left to write, so quit early.
			return ConsumeBits(total_bits);
		}

		// Subtract what we've written from the bit count, shift it off the value, and
		// write the remaining full bytes.
		val <<= bits_in_first_byte;
		bytes++;
		bit_count -= bits_in_first_byte;
		while (bit_count >= 8)
		{
			*bytes++ = HighestByte(val);
			val <<= 8;
			bit_count -= 8;
		}

		// Last byte may also be partial, so write the remaining bits from the top of
		// val.
		if (bit_count > 0)
		{
			*bytes = WritePartialByte(HighestByte(val), bit_count, *bytes, 0);
		}

		// All done! Consume the bits we've written.
		return ConsumeBits(total_bits);
	}

	// Writes value in range [0, num_values - 1]
	// See ReadNonSymmetric documentation for the format,
	// Call SizeNonSymmetricBits to get number of bits needed to store the value.
	// Returns false if there isn't enough room left for the value.
	bool WriteNonSymmetric(uint32_t val, uint32_t num_values)
	{
		// RTC_DCHECK_LT(val, num_values);
		// RTC_DCHECK_LE(num_values, uint32_t{ 1 } << 31);

		if (num_values == 1)
		{
			// When there is only one possible value, it requires zero bits to store it.
			// But WriteBits doesn't support writing zero bits.
			return true;
		}

		size_t count_bits			 = std::bit_width(num_values);
		uint32_t num_min_bits_values = (uint32_t{ 1 } << count_bits) - num_values;

		return val < num_min_bits_values ? WriteBits(val, count_bits - 1)
										 : WriteBits(val + num_min_bits_values, count_bits);
	}

	// Returns number of bits required to store `val` with NonSymmetric encoding.
	static size_t SizeNonSymmetricBits(uint32_t val, uint32_t num_values)
	{
		// RTC_DCHECK_LT(val, num_values);
		// RTC_DCHECK_LE(num_values, uint32_t{ 1 } << 31);

		size_t count_bits			 = std::bit_width(num_values);
		uint32_t num_min_bits_values = (uint32_t{ 1 } << count_bits) - num_values;

		return val < num_min_bits_values ? (count_bits - 1) : count_bits;
	}

	// Writes the exponential golomb encoded version of the supplied value.
	// Returns false if there isn't enough room left for the value.
	bool WriteExponentialGolomb(uint32_t val)
	{
		// We don't support reading UINT32_MAX, because it doesn't fit in a uint32_t
		// when encoded, so don't support writing it either.
		if (val == std::numeric_limits<uint32_t>::max())
			return false;

		uint64_t val_to_encode = static_cast<uint64_t>(val) + 1;

		// We need to write bit_width(val+1) 0s and then val+1. Since val (as a
		// uint64_t) has leading zeros, we can just write the total golomb encoded
		// size worth of bits, knowing the value will appear last.
		return WriteBits(val_to_encode, std::bit_width(val_to_encode) * 2 - 1);
	}

	// Writes the signed exponential golomb version of the supplied value.
	// Signed exponential golomb values are just the unsigned values mapped to the
	// sequence 0, 1, -1, 2, -2, etc. in order.
	bool WriteSignedExponentialGolomb(int32_t val)
	{
		if (val == 0)
			return WriteExponentialGolomb(0);

		if (val > 0)
		{
			uint32_t signed_val = val;
			return WriteExponentialGolomb((signed_val * 2) - 1);
		}

		if (val == std::numeric_limits<int32_t>::min())
			return false; // Not supported, would cause overflow.

		uint32_t signed_val = -val;
		return WriteExponentialGolomb(signed_val * 2);
	}

	// Writes the Leb128 encoded value.
	bool WriteLeb128(uint64_t val)
	{
		bool success = true;
		do
		{
			uint8_t byte = static_cast<uint8_t>(val & 0x7f);
			val >>= 7;
			if (val > 0)
				byte |= 0x80;
			success &= WriteUInt8(byte);
		} while (val > 0);

		return success;
	}

	// Writes the string as bytes of data.
	bool WriteString(std::string_view data)
	{
		bool success = true;

		for (char c : data)
			success &= WriteUInt8(c);

		return success;
	}

private:
	// The buffer, as a writable array.
	uint8_t* const writable_bytes_;
	// The total size of `bytes_`.
	const size_t byte_count_;
	// The current offset, in bytes, from the start of `bytes_`.
	size_t byte_offset_;
	// The current offset, in bits, into the current byte.
	size_t bit_offset_;
};


BOOST_AUTO_TEST_CASE(test_handshake)
{
	const std::string privateKey = "ICBmoiZBqo7pyHZVK+vM2I3LF9PePa18DVjkcbLl/XM=";
	crypto_util::keyexchange ke(privateKey);

	const std::string const_id = gen_unique_string(32);
	const std::string const_pubkey = std::string(ke.StaticPublicKey());

	std::string id = const_id;
	std::string pubkey = const_pubkey;
	uint32_t src = 167772225;
	auto pkt = avpn::make_handshake(src, id, pubkey, 8, 4);

	src = 0;
	id.resize(0);
	pubkey.resize(0);
	uint8_t ds, ps;
	auto bytes = avpn::unwrap_handshake(pkt, src, id, pubkey, ds, ps);

	BOOST_TEST(src == (uint32_t)167772225);
	BOOST_TEST(id == const_id);
	BOOST_TEST(pubkey == const_pubkey);
	BOOST_TEST(ds == 8);
	BOOST_TEST(ps == 4);

	int len = (int)pubkey.size() + 1 + (int)id.size() + 1;
	len += (1 + 4);
	len += 2;
	len += 2;
	BOOST_TEST(len == bytes);
}

#if 0
BOOST_AUTO_TEST_CASE(test_transfer)
{
	uint32_t src = 167772225;
	uint32_t gid = 12;
	uint8_t pid = 23;
	std::string data = "hello";

	auto pkt = avpn::make_transfer(src, gid, pid, data);

	src = 0;
	gid = 0;
	pid = 0;

	auto bytes = avpn::unwrap_transfer(pkt, src, gid, pid);
	(void)bytes;

	BOOST_TEST(bytes == 19);
	BOOST_TEST(src == (uint32_t)167772225);
	BOOST_TEST(gid == (uint32_t)12);
	BOOST_TEST(pid == (uint8_t)23);

	std::string_view sv((char*)pkt.payload(), pkt.payload_size());
	BOOST_TEST(sv == data);

	auto d1 = pkt.data();

	std::shared_ptr<avpn::vpn_packet> sp =
		std::make_shared<avpn::vpn_packet>(std::move(pkt));

	auto d2 = sp->data();

	BOOST_TEST(d1 == d2);
}
#endif