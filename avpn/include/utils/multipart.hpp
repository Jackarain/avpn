//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <regex>
#include <utility>
#include <list>
#include <vector>
#include <string>
#include <string_view>

#ifdef _MSC_VER
#if !defined(_CPPUNWIND) && !defined(_NO_EXCEPTIONS)
#	define _NO_EXCEPTIONS
#endif
#elif __GNUC__
#if !defined(__EXCEPTIONS) && !defined(_NO_EXCEPTIONS)
#	define _NO_EXCEPTIONS
#endif
#elif __clang__
#if !__has_feature(cxx_exceptions) && !defined(_NO_EXCEPTIONS)
#	define _NO_EXCEPTIONS
#endif
#endif // WIN32


namespace util {
	namespace detail {
		template<int v1, int v2>
		struct max { enum { value = v1 > v2 ? v1 : v2 }; };

		inline bool is_print(char c)
		{
			return (c >= 32 && c < 127) || c == '\r' || c == '\n';
		}

		static const char hex_chars[] = "0123456789abcdef";

		inline std::string to_hex(std::string const& s)
		{
			std::string ret;
			for (std::string::const_iterator i = s.begin(); i != s.end(); ++i)
			{
				ret += hex_chars[((unsigned char)*i) >> 4];
				ret += hex_chars[((unsigned char)*i) & 0xf];
			}
			return ret;
		}
	}

	namespace {
		template <class T>
		void call_destructor(T* o)
		{
			assert(o && "o is nullptr");
			o->~T();
		}
	}

#ifndef _NO_EXCEPTIONS
	inline void throw_type_error(std::string str = "")
	{
		throw std::runtime_error(str.c_str());
	}
#endif

	struct lazy_part
	{
	public:
		enum class data_type
		{
			content_t,
			list_t,
			undefined_t,
		};

		using list_type = std::list<lazy_part>;
		using content_type = std::string_view;
		using string_type = std::string_view;
		using keyvalue_type = std::pair<string_type, string_type>;
		using prototype_type = std::vector<keyvalue_type>;

		lazy_part(content_type const& v, prototype_type const& p = {})
		{
			new(data_) content_type(v);
			prototype_ = p;
			type_ = data_type::content_t;
		}

		lazy_part(list_type const& v, prototype_type const& p = {})
		{
			new(data_) list_type(v);
			prototype_ = p;
			type_ = data_type::list_t;
		}

		lazy_part(data_type t)
		{
			construct(t);
		}

		lazy_part(lazy_part const& e)
		{
			copy(e);
		}

		lazy_part() = default;
		~lazy_part() { destruct(); }

		void operator=(lazy_part const& e)
		{
			destruct();
			copy(e);
		}

		void operator=(content_type const& v)
		{
			destruct();
			new(data_) content_type(v);
			type_ = data_type::content_t;
		}

		void operator=(list_type const& v)
		{
			destruct();
			new(data_) list_type(v);
			type_ = data_type::list_t;
		}

		data_type type() const noexcept
		{
			return type_;
		}

		content_type& content()
		{
			if (type_ == data_type::undefined_t) construct(data_type::content_t);
			assert(type_ == data_type::content_t);
			return *reinterpret_cast<content_type*>(data_);
		}

		list_type& list()
		{
			if (type_ == data_type::undefined_t) construct(data_type::list_t);
			assert(type_ == data_type::list_t);
			return *reinterpret_cast<list_type*>(data_);
		}

		const content_type& content() const
		{
#ifndef _NO_EXCEPTIONS
			if (type_ != data_type::content_t) throw_type_error();
#endif
			assert(type_ == data_type::content_t);
			return *reinterpret_cast<const content_type*>(data_);
		}

		const list_type& list() const
		{
#ifndef _NO_EXCEPTIONS
			if (type_ != data_type::list_t) throw_type_error();
#endif
			assert(type_ == data_type::list_t);
			return *reinterpret_cast<const list_type*>(data_);
		}

		prototype_type& prototype()
		{
			return prototype_;
		}

		const prototype_type& prototype() const
		{
			return prototype_;
		}

		std::string& boundary()
		{
			return boundary_;
		}

		const std::string& boundary() const
		{
			return boundary_;
		}

#if defined(_DEBUG) || defined(DEBUG)
		void print(std::ostream& os, int indent = 0) const
		{
			assert(indent >= 0);
			os << " " << boundary();
			for (int i = 0; i < indent; ++i) os << " ";
			switch (type_)
			{
			case data_type::content_t:
			{
				for (const auto& r : prototype_) {
					os << std::string(r.first) << ": " << std::string(r.second) << "\n";
					for (int i = 0; i < indent; ++i) os << " ";
				}
				bool binary_string = false;
				for (auto i = content().begin(); i != content().end(); ++i)
				{
					if (!detail::is_print(static_cast<unsigned char>(*i)))
					{
						binary_string = true;
						break;
					}
				}
				if (binary_string) os << detail::to_hex(std::string(content())) << "\n\n";
				else os << std::string(content()) << "\n\n";
			} break;
			case data_type::list_t:
			{
				os << "list\n";
				for (const auto& r : prototype_) {
					for (int i = 0; i < indent; ++i) os << " ";
					os << std::string(r.first) << ": " << std::string(r.second) << "\n";
				}
				for (list_type::const_iterator i = list().begin(); i != list().end(); ++i) {
					i->print(os, indent + 1);
				}
			} break;
			default:
				os << "<uninitialized>\n\n";
			}
		}
#endif

	protected:
		void construct(data_type t)
		{
			switch (t)
			{
			case data_type::content_t:
				new(data_) content_type;
				break;
			case data_type::list_t:
				new(data_) list_type;
				break;
			default:
				assert(t == data_type::undefined_t);
			}
			type_ = t;
		}

		void copy(const lazy_part& e)
		{
			switch (e.type())
			{
			case data_type::content_t:
				new(data_) content_type(e.content());
				break;
			case data_type::list_t:
				new(data_) list_type(e.list());
				break;
			default:
				assert(e.type() == data_type::undefined_t);
			}
			type_ = e.type();
			prototype_ = e.prototype();
			boundary_ = e.boundary();
		}

		void destruct()
		{
			switch (type_)
			{
			case data_type::content_t:
				call_destructor(reinterpret_cast<content_type*>(data_));
				break;
			case data_type::list_t:
				call_destructor(reinterpret_cast<list_type*>(data_));
				break;
			default:
				assert(type_ == data_type::undefined_t);
				break;
			}
			type_ = data_type::undefined_t;
			prototype_.clear();
		}

		enum {
			union_size = detail::max<sizeof(list_type), sizeof(content_type)>::value
		};

		std::string boundary_;
		data_type type_ = data_type::undefined_t;
		prototype_type prototype_;
		size_t data_[(union_size + sizeof(size_t) - 1) / sizeof(size_t)] = { 0 };
	};

	struct part
	{
	public:
		enum class data_type
		{
			content_t,
			list_t,
			undefined_t,
		};

		using list_type = std::list<part>;
		using content_type = std::string;
		using string_type = std::string;
		using keyvalue_type = std::pair<string_type, string_type>;
		using prototype_type = std::vector<keyvalue_type>;

		part(content_type const& v, prototype_type const& p = {})
		{
			new(data_) content_type(v);
			prototype_ = p;
			type_ = data_type::content_t;
		}

		part(list_type const& v, prototype_type const& p = {})
		{
			new(data_) list_type(v);
			prototype_ = p;
			type_ = data_type::list_t;
		}

		part(data_type t)
		{
			construct(t);
		}

		part(part const& e)
		{
			copy(e);
		}

		part() = default;
		~part() { destruct(); }

		void operator=(part const& e)
		{
			destruct();
			copy(e);
		}

		void operator=(content_type const& v)
		{
			destruct();
			new(data_) content_type(v);
			type_ = data_type::content_t;
		}

		void operator=(list_type const& v)
		{
			destruct();
			new(data_) list_type(v);
			type_ = data_type::list_t;
		}

		data_type type() const noexcept
		{
			return type_;
		}

		content_type& content()
		{
			if (type_ == data_type::undefined_t) construct(data_type::content_t);
			assert(type_ == data_type::content_t);
			return *reinterpret_cast<content_type*>(data_);
		}

		list_type& list()
		{
			if (type_ == data_type::undefined_t) construct(data_type::list_t);
			assert(type_ == data_type::list_t);
			return *reinterpret_cast<list_type*>(data_);
		}

		const content_type& content() const
		{
#ifndef _NO_EXCEPTIONS
			if (type_ != data_type::content_t) throw_type_error();
#endif
			assert(type_ == data_type::content_t);
			return *reinterpret_cast<const content_type*>(data_);
		}

		const list_type& list() const
		{
#ifndef _NO_EXCEPTIONS
			if (type_ != data_type::list_t) throw_type_error();
#endif
			assert(type_ == data_type::list_t);
			return *reinterpret_cast<const list_type*>(data_);
		}

		prototype_type& prototype()
		{
			return prototype_;
		}

		const prototype_type& prototype() const
		{
			return prototype_;
		}

		std::string& boundary()
		{
			return boundary_;
		}

		const std::string& boundary() const
		{
			return boundary_;
		}

#if defined(_DEBUG) || defined(DEBUG)
		void print(std::ostream& os, int indent = 0) const
		{
			assert(indent >= 0);
			os << " " << boundary();
			for (int i = 0; i < indent; ++i) os << " ";
			switch (type_)
			{
			case data_type::content_t:
			{
				for (const auto& r : prototype_) {
					os << std::string(r.first) << ": " << std::string(r.second) << "\n";
					for (int i = 0; i < indent; ++i) os << " ";
				}
				bool binary_string = false;
				for (auto i = content().begin(); i != content().end(); ++i)
				{
					if (!detail::is_print(static_cast<unsigned char>(*i)))
					{
						binary_string = true;
						break;
					}
				}
				if (binary_string) os << detail::to_hex(std::string(content())) << "\n\n";
				else os << std::string(content()) << "\n\n";
			} break;
			case data_type::list_t:
			{
				os << "list\n";
				for (const auto& r : prototype_) {
					for (int i = 0; i < indent; ++i) os << " ";
					os << std::string(r.first) << ": " << std::string(r.second) << "\n";
				}
				for (list_type::const_iterator i = list().begin(); i != list().end(); ++i) {
					i->print(os, indent + 1);
				}
			} break;
			default:
				os << "<uninitialized>\n\n";
			}
		}
#endif

	protected:
		void construct(data_type t)
		{
			switch (t)
			{
			case data_type::content_t:
				new(data_) content_type;
				break;
			case data_type::list_t:
				new(data_) list_type;
				break;
			default:
				assert(t == data_type::undefined_t);
			}
			type_ = t;
		}

		void copy(const part& e)
		{
			switch (e.type())
			{
			case data_type::content_t:
				new(data_) content_type(e.content());
				break;
			case data_type::list_t:
				new(data_) list_type(e.list());
				break;
			default:
				assert(e.type() == data_type::undefined_t);
			}
			type_ = e.type();
			prototype_ = e.prototype();
			boundary_ = e.boundary();
		}

		void destruct()
		{
			switch (type_)
			{
			case data_type::content_t:
				call_destructor(reinterpret_cast<content_type*>(data_));
				break;
			case data_type::list_t:
				call_destructor(reinterpret_cast<list_type*>(data_));
				break;
			default:
				assert(type_ == data_type::undefined_t);
				break;
			}
			type_ = data_type::undefined_t;
			prototype_.clear();
		}

		enum {
			union_size = detail::max<sizeof(list_type), sizeof(content_type)>::value
		};

		std::string boundary_;
		data_type type_ = data_type::undefined_t;
		prototype_type prototype_;
		size_t data_[(union_size + sizeof(size_t) - 1) / sizeof(size_t)] = { 0 };
	};

	using callback_func = std::function<int(const std::string_view&)>;
	struct event_cb
	{
		callback_func boundary_;
		callback_func header_field_;
		callback_func header_value_;
		callback_func part_data_;
	};

	namespace detail {

		enum {
			s_start,
			s_start_boundary,
			s_header_field,
			s_header_value,
			s_part_data
		};

		enum {
			max_recursive_depth = 100
		};

		template<typename InIt, typename Entry>
		int64_t decode_recursive(InIt in, InIt end, Entry& ret, bool& err, int depth, event_cb ecb)
		{
			InIt sp = in;

			if (depth >= max_recursive_depth) {
				err = true;
				return std::distance(sp, in);
			}

			if (in == end) {
				err = true;
				return std::distance(sp, in);
			}

			int state = s_start;
			std::string boundary;
			using data_type = typename Entry::data_type;
			using string_type = typename Entry::string_type;
			using prototype_type = typename Entry::prototype_type;
			string_type key;
			string_type value;
			InIt cbegin = in, cend = in;
			prototype_type prototype{};
			Entry tmp;

			while (in != end)
			{
				auto c = *in++;

				switch (state)
				{
				case s_start:
					if (c != '-') {
						err = true; return std::distance(sp, in);
					}
					if (in == end) {
						err = true; return std::distance(sp, in);
					}
					c = *in++;
					if (c != '-') {
						err = true; return std::distance(sp, in);
					}
					state = s_start_boundary;
					boundary.push_back(c);
					[[fallthrough]];
				case s_start_boundary:
					if (c == '\r') {
						if (in == end) {
							err = true; return std::distance(sp, in);
						}
						c = *in++;
						if (c == '\n') {
							cbegin = cend = in;
							state = s_header_field;
							if (ecb.boundary_)
								ecb.boundary_(boundary);
							continue;
						}
					}
					boundary.push_back(c);
					continue;
				case s_header_field:
					if (c == '\r' || c == '\n') {
						err = true; return std::distance(sp, in);
					}
					if (c == ':') {
						auto sbegin = reinterpret_cast<const char*>(&*cbegin);
						key = string_type(sbegin, std::distance(cbegin, cend));
						cbegin = cend = in;
						if (ecb.header_field_)
							ecb.header_field_(key);
						state = s_header_value;
						continue;
					}
					cend = in;
					continue;
				case s_header_value:
					if (cbegin + 1 == in && c == ' ') { // skip space
						cbegin = cend = in;
						continue;
					}
					if (c != '\r') {
						cend = in; continue;
					}
					value = string_type(reinterpret_cast<const char*>(&*cbegin), std::distance(cbegin, cend));
					prototype.push_back({ key, value });
					if (in == end) {
						err = true; return std::distance(sp, in);
					}
					c = *in++; // skip \n
					if (c != '\n') {
						err = true; return std::distance(sp, in);
					}
					if (in == end) {
						err = true; return std::distance(sp, in);
					}
					c = *in;
					if (c != '\r')
					{
						cbegin = cend = in;
						if (ecb.header_value_)
							ecb.header_value_(value);
						state = s_header_field;
						continue;
					}
					// double \r\n\r\n
					if (in == end) {
						err = true; return std::distance(sp, in);
					}
					in++; // skip \r
					if (*in != '\n') {
						err = true; return std::distance(sp, in);
					}
					in++; // skip \n
					{
						if (ecb.header_value_)
							ecb.header_value_(value);
						// check recursive.
						std::match_results<decltype(value.begin())> what;
						if (key == "Content-Type" &&
							std::regex_match(value.begin(), value.end(),
								what, std::regex{ "^\\s*multipart\\/(\\S+) boundary=(.*)$" })) {
							bool error = false;
							auto pos = decode_recursive(in, end, tmp, error, depth + 1, ecb);
							if (error) {
								err = true; return std::distance(sp, in);
							}
							in += pos;
							cbegin = cend = in;
							state = s_part_data;
							continue;
						}
					}
					cbegin = cend = in;
					state = s_part_data;
					continue;
				case s_part_data:
					if (c == '\r') {
						if (in == end) {
							err = true; return std::distance(sp, in);
						}
						if (*in != '\n') {
							cend = in;
							continue;
						}
						auto p = in;
						std::advance(p, 1);
						// check boundary.
						int64_t size = std::distance(p, end);
						if (size < (int64_t)boundary.size() + 2) {
							err = true; return std::distance(sp, p);
						}
						auto e = p;
						std::advance(e, boundary.size() + 2);
						std::string next{ p, e };
						if (boundary + "--" == next) {
							if (tmp.type() == data_type::undefined_t) {
								auto sbegin = reinterpret_cast<const char*>(&*cbegin);
								string_type sv(sbegin, std::distance(cbegin, cend));
								if (ecb.part_data_)
									ecb.part_data_(sv);
								tmp.content() = sv;
							}
							tmp.boundary() = boundary;
							if (!prototype.empty()) {
								tmp.prototype() = prototype;
							}
							if (ret.type() == data_type::list_t)
								ret.list().push_back(tmp);
							else
								ret = tmp;
							tmp = Entry();

							std::advance(p, boundary.size() + 2);
							return std::distance(sp, p);
						}
						next.resize(boundary.size());
						if (boundary == next) {
							if (tmp.type() == data_type::undefined_t) {
								auto sbegin = reinterpret_cast<const char*>(&*cbegin);
								string_type sv(sbegin, std::distance(cbegin, cend));
								if (ecb.part_data_)
									ecb.part_data_(sv);
								tmp.content() = sv;
							}
							tmp.boundary() = boundary;
							if (!prototype.empty()) {
								tmp.prototype() = prototype;
							}

							prototype.clear();

							ret.list().push_back(tmp);

							tmp = Entry();
							std::advance(p, boundary.size() + 2);
							in = p;
							cbegin = cend = in;
							state = s_header_field;
							continue;
						}
					}
					cend = in;
					continue;
				}
			}

			return std::distance(sp, in);
		}

		template <class OutIt>
		int write_string(OutIt& out, const std::string& val)
		{
			for (std::string::const_iterator i = val.begin()
				, end(val.end()); i != end; ++i)
				*out++ = *i;
			return (int)val.length();
		}

		template<class OutIt>
		int encode_recursive(OutIt& out, const part& e, bool w = false, int depth = 0)
		{
			int ret = 0;

			std::string boundary;
			bool writed = false;

			switch (e.type())
			{
			case part::data_type::content_t:
				ret += write_string(out, e.boundary() + "\r\n");
				for (const auto& p : e.prototype()) {
					ret += write_string(out, p.first);
					ret += write_string(out, ": ");
					ret += write_string(out, p.second);
					ret += write_string(out, "\r\n");
				}
				ret += write_string(out, "\r\n");
				ret += write_string(out, e.content() + "\r\n");
				boundary = e.boundary();
				if (depth == 0)
					w = true;
				break;
			case part::data_type::list_t:
				if (!e.boundary().empty()) {
					ret += write_string(out, e.boundary() + "\r\n");
				}
				for (const auto& p : e.prototype()) {
					ret += write_string(out, p.first);
					ret += write_string(out, ": ");
					ret += write_string(out, p.second);
					ret += write_string(out, "\r\n");
				}
				if (!e.boundary().empty()) {
					ret += write_string(out, "\r\n");
				}
				for (const auto& p : e.list()) {
					if (boundary.empty()) {
						boundary = p.boundary();
					} else if (boundary != p.boundary()) {
						ret += write_string(out, boundary + "--\r\n");
						boundary = p.boundary();
						writed = true;
					}
					ret += encode_recursive(out, p, false, depth + 1);
				}
				if (!writed) {
					ret += write_string(out, boundary + "--\r\n");
				}
				break;
			case part::data_type::undefined_t:
				[[fallthrough]];
			default:
				return ret;
			}

			if (w) {
				ret += write_string(out, boundary + "--\r\n");
			}

			return ret;
		}
	}

	template<typename Entry, typename InIt>
	Entry decode(InIt start, InIt end, event_cb ecb = {})
	{
		Entry e;
		bool err = false;
		detail::decode_recursive(start, end, e, err, 0, ecb);
		if (err) return Entry();
		return e;
	}

	template<class OutIt>
	int encode(OutIt out, const part& e)
	{
		return detail::encode_recursive(out, e, false);
	}
}
