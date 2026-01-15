#ifndef BIGNUM_BIGNUM_H
#define BIGNUM_BIGNUM_H

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <vector>

namespace apa::details {

#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
using u128 = __uint128_t;
#elif defined(_MSC_VER)
using u128 = umul128;
#else
#error "Unsupported compiler"
#endif

#if INTPTR_MAX == INT64_MAX
using usize = std::uint64_t;
using overflow_type = u128;
constexpr auto arch_bits = 64;
#elif INTPTR_MAX == INT32_MAX
using usize = std::uint32_t;
using overflow_type = std::uint64_t;
constexpr auto arch_bits = 32;
#else
#error "Unsupported architecture"
#endif

struct bignum_impl {
  using data_type = usize;

  constexpr static auto SBO_SIZE = 4;

  std::uint32_t m_size;
  std::uint32_t m_capacity;
  union {
    data_type m_sbo_data[SBO_SIZE];
    data_type *m_heap_data;
  };
};

} // namespace apa::details

namespace apa {

using bignum = details::bignum_impl;

} // namespace apa

#endif
