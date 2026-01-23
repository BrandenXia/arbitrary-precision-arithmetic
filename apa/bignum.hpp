#ifndef BIGNUM_BIGNUM_H
#define BIGNUM_BIGNUM_H

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#include <x86intrin.h>
#endif

namespace apa::details {

#if INTPTR_MAX == INT64_MAX
#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
using u128 = __uint128_t;
#elif defined(_MSC_VER)
using u128 = umul128;
#else
#error "Unsupported compiler"
#endif
using usize = std::uint64_t;
using overflow_type = u128;
constexpr auto arch_bits = 64;
#elif INTPTR_MAX == INT32_MAX
using usize = std::uint32_t;
using overflow_type = std::uint64_t;
constexpr auto arch_bits = 32;
#else
#error "Unsupported arch"
#endif

#if defined(_MSC_VER)
#define FORCE_INLINE __forceinline
#else
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif

// helper macros
#define BIGNUM_TEMPLATE_DECL                                                   \
  template <std::unsigned_integral DataType, short SBO_SIZE, typename Alloc>

#define BIGNUM_TEMPLATE_CLSNAME bignum_impl<DataType, SBO_SIZE, Alloc>

template <std::unsigned_integral DataType = usize, short SBO_SIZE = 4,
          typename Alloc = std::allocator<DataType>>
struct bignum_impl;

// type traits
namespace traits {

struct is_bignum {
  template <typename T>
  static constexpr bool value = false;

  BIGNUM_TEMPLATE_DECL
  static constexpr bool value<bignum_impl<DataType, SBO_SIZE, Alloc>> = true;
};

template <typename T>
constexpr bool is_bignum_v = is_bignum::value<T>;

template <typename T>
concept bignum_concept = is_bignum_v<T>;

} // namespace traits

BIGNUM_TEMPLATE_DECL
struct bignum_impl {
private:
  using data_type = DataType;
  using allocator_type = Alloc;
  using allocator_traits = std::allocator_traits<allocator_type>;

  constexpr static auto sbo_size = SBO_SIZE;

  [[no_unique_address]] allocator_type m_alloc;
  std::uint32_t m_size;
  std::uint32_t m_cap;
  bool is_negative;
  union {
    data_type m_sbo_data[sbo_size];
    data_type *m_heap_data;
  };

public:
  explicit constexpr bignum_impl(const allocator_type &) noexcept;
  ~bignum_impl();

  bignum_impl(const bignum_impl &);
  bignum_impl(bignum_impl &&) noexcept;
  auto operator=(const bignum_impl &) -> bignum_impl &;
  auto operator=(bignum_impl &&) noexcept -> bignum_impl &;

  inline auto is_large() const noexcept -> bool { return m_cap > sbo_size; }
  // clang-format off
  inline auto data() noexcept -> data_type * { return is_large() ? m_heap_data : m_sbo_data; }
  inline auto data() const noexcept -> const data_type * { return is_large() ? m_heap_data : m_sbo_data; }
  // clang-format on
  inline auto size() const noexcept -> std::size_t { return m_size; }

  auto reserve(std::size_t) -> void;
  auto resize(std::size_t new_size) -> void;
  auto resize(std::size_t new_size, data_type value) -> void;
  auto push_back(data_type) -> void;
  // clang-format off
  auto pop_back() -> void { if (m_size > 0) --m_size; }
  // clang-format on

  auto operator+=(bignum_impl const &) -> bignum_impl &;
  auto operator-=(bignum_impl const &) -> bignum_impl &;
  auto operator*=(bignum_impl const &) -> bignum_impl &;
  auto operator/=(bignum_impl const &) -> bignum_impl &;

  auto cmp_abs(const bignum_impl &) -> std::strong_ordering;
  auto operator<=>(const bignum_impl &) -> std::strong_ordering;
  auto operator==(const bignum_impl &other) -> bool;

  auto swap(bignum_impl &) noexcept(
      allocator_traits::propagate_on_container_swap::value ||
      allocator_traits::is_always_equal::value) -> void;
};

// implementations
BIGNUM_TEMPLATE_DECL
constexpr BIGNUM_TEMPLATE_CLSNAME::bignum_impl(
    const allocator_type &alloc) noexcept
    : m_alloc(alloc), m_size(0), m_cap(sbo_size) {
  std::uninitialized_value_construct_n(m_sbo_data, sbo_size);
}

BIGNUM_TEMPLATE_DECL
BIGNUM_TEMPLATE_CLSNAME::~bignum_impl() {
  if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
}

BIGNUM_TEMPLATE_DECL
BIGNUM_TEMPLATE_CLSNAME::bignum_impl(const bignum_impl &other)
    : m_alloc(allocator_traits::select_on_container_copy_construction(
          other.m_alloc)),
      m_size(other.m_size), m_cap(other.m_cap), is_negative(other.is_negative) {
  if (other.is_large()) {
    m_heap_data = allocator_traits::allocate(m_alloc, m_cap);
    std::copy_n(other.data(), m_size, m_heap_data);
  } else
    std::copy_n(other.m_sbo_data, m_size, m_sbo_data);
}

BIGNUM_TEMPLATE_DECL
BIGNUM_TEMPLATE_CLSNAME::bignum_impl(bignum_impl &&other) noexcept
    : m_alloc(std::move(other.m_alloc)), m_size(other.m_size),
      m_cap(other.m_cap), is_negative(other.is_negative) {
  if (other.is_large()) {
    m_heap_data = other.m_heap_data;
    other.m_heap_data = nullptr;
    other.m_size = 0;
    other.m_cap = sbo_size;
  } else {
    std::copy_n(other.m_sbo_data, m_size, m_sbo_data);
    other.m_size = 0;
  }
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator=(const bignum_impl &other)
    -> bignum_impl & {
  if (this == &other) return *this;

  if (allocator_traits::propagate_on_container_copy_assignment::value &&
      m_alloc != other.m_alloc) {
    if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
    m_alloc = other.m_alloc;
    m_cap = sbo_size;
  }

  m_size = other.m_size;
  is_negative = other.is_negative;

  if (other.is_large()) {
    if (m_cap < other.m_cap) {
      if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
      m_heap_data = allocator_traits::allocate(m_alloc, other.m_cap);
      m_cap = other.m_cap;
    }
    std::copy_n(other.data(), m_size, m_heap_data);
  } else {
    if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
    m_cap = sbo_size;
    std::copy_n(other.m_sbo_data, m_size, m_sbo_data);
  }

  return *this;
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator=(bignum_impl &&other) noexcept
    -> bignum_impl & {
  if (this == &other) return *this;

  if (allocator_traits::propagate_on_container_move_assignment::value) {
    if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
    m_alloc = std::move(other.m_alloc);
    m_cap = sbo_size;
  }

  m_size = other.m_size;
  is_negative = other.is_negative;

  if (other.is_large()) {
    if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
    m_heap_data = other.m_heap_data;
    m_cap = other.m_cap;
    other.m_heap_data = nullptr;
    other.m_size = 0;
    other.m_cap = sbo_size;
  } else {
    if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);
    m_cap = sbo_size;
    std::copy_n(other.m_sbo_data, m_size, m_sbo_data);
    other.m_size = 0;
  }

  return *this;
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::reserve(std::size_t new_cap) -> void {
  if (new_cap <= m_cap) return;

  data_type *ptr = allocator_traits::allocate(m_alloc, new_cap);
  if (m_size > 0) std::copy_n(data(), m_size, ptr);

  if (is_large()) allocator_traits::deallocate(m_alloc, m_heap_data, m_cap);

  m_heap_data = ptr;
  m_cap = static_cast<std::uint32_t>(new_cap);
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::resize(std::size_t new_size) -> void {
  if (new_size > m_cap) reserve(new_size);
  if (new_size > m_size)
    std::uninitialized_value_construct_n(data() + m_size, new_size - m_size);
  m_size = static_cast<std::uint32_t>(new_size);
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::resize(std::size_t new_size, data_type value)
    -> void {
  if (new_size > m_cap) reserve(new_size);
  if (new_size > m_size)
    std::uninitialized_fill_n(data() + m_size, new_size - m_size, value);
  m_size = static_cast<std::uint32_t>(new_size);
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::push_back(data_type data) -> void {
  static constexpr auto CAPACITY_SCALE = 2;

  if (m_size == m_cap) {
    std::size_t new_cap = (m_cap == 0) ? sbo_size : m_cap * CAPACITY_SCALE;
    if (new_cap <= sbo_size) new_cap = sbo_size * 2;
    reserve(new_cap);
  }
  data()[m_size++] = data;
};

FORCE_INLINE auto add_usize_carry(usize a, usize b, unsigned char carry_in,
                                  usize *out) -> unsigned char {
#if defined(_MSC_VER) && defined(_M_X64)
  return _addcarry_u64(carry_in, a, b, out);
#elif defined(__x86_64__) && defined(__ADX__)
  return _addcarry_u64(carry_in, a, b, (unsigned long long *)out);
#elif defined(__GNUC__) || defined(__clang__)
  usize res1;
  usize res2;

  bool c1 = __builtin_uaddll_overflow(a, b, &res1);
  bool c2 = __builtin_uaddll_overflow(res1, carry_in, &res2);

  *out = (usize)res2;
  return c1 | c2;
#else
  usize res = a + b + carry_in;
  bool overflow = carry_in ? (res <= a) : (res < a);
  *out = res;
  return overflow ? 1 : 0;
#endif
}

template <traits::bignum_concept T>
auto add_bignum(T &a, const T &b) {
  auto a_size = a.size(), b_size = b.size();

  if (a_size < b_size) {
    a.resize(b_size, 0);
    a_size = b_size;
  }

  auto a_ptr = a.data();
  const auto b_ptr = b.data();
  unsigned char carry = 0;
  std::size_t i = 0;

  for (; i < b_size; ++i)
    carry = add_usize_carry(a_ptr[i], b_ptr[i], carry, &a_ptr[i]);
  for (; i < a_size && carry; ++i)
    carry = add_usize_carry(a_ptr[i], 0, carry, &a_ptr[i]);

  if (carry) a.push_back(1);
}

FORCE_INLINE auto sub_usize_borrow(usize a, usize b, unsigned char borrow_in,
                                   usize *out) -> unsigned char {
#if defined(_MSC_VER) && defined(_M_X64)
  return _subborrow_u64(borrow_in, a, b, out);
#elif defined(__x86_64__) && defined(__ADX__)
  return _subborrow_u64(borrow_in, a, b, (unsigned long long *)out);
#else
  usize res = a - b - borrow_in;
  bool borrow_out = (borrow_in ? (a <= b) : (a < b));
  *out = res;
  return borrow_out ? 1 : 0;
#endif
}

template <traits::bignum_concept T>
auto sub_bignum(T &a, const T &b) {
  auto a_size = a.size(), b_size = b.size();

  auto a_ptr = a.data();
  const auto b_ptr = b.data();
  unsigned char borrow = 0;
  std::size_t i = 0;

  for (; i < b_size; ++i)
    borrow = sub_usize_borrow(a_ptr[i], b_ptr[i], borrow, &a_ptr[i]);

  for (; i < a_size && borrow; ++i)
    borrow = sub_usize_borrow(a_ptr[i], 0, borrow, &a_ptr[i]);

  while (a_size > 0 && a_ptr[a_size - 1] == 0)
    --a_size;
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator+=(bignum_impl const &other)
    -> bignum_impl & {
  if (is_negative == other.is_negative) add_bignum(*this, other);
  else if (cmp_abs(other) != std::strong_ordering::less)
    sub_bignum(*this, other);
  else {
    bignum_impl temp = other;
    sub_bignum(temp, *this);
    *this = std::move(temp);
  }
  return *this;
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator-=(bignum_impl const &other)
    -> bignum_impl & {
  if (is_negative != other.is_negative) add_bignum(*this, other);
  else if (cmp_abs(other) != std::strong_ordering::less)
    sub_bignum(*this, other);
  else {
    bignum_impl temp = other;
    sub_bignum(temp, *this);
    *this = std::move(temp);
    is_negative = !is_negative;
  }
  return *this;
}

FORCE_INLINE auto mul_widen(usize a, usize b, usize *lo, usize *hi) {
#if defined(_MSC_VER) && defined(_M_X64)
  *lo = _umul128(a, b, hi);
#elif defined(__x86_64__) && defined(__BMI2__)
  *lo = _mulx_u64(a, b, (unsigned long long *)hi);
#elif defined(__GNUC__) || defined(__clang__)
  overflow_type res = (overflow_type)a * b;
  *lo = (usize)res;
  *hi = (usize)(res >> 64);
#else
#error "Unsupported arch"
#endif
}

inline auto mul_add_row(usize *res, const usize *a, std::size_t n, usize b_limb)
    -> usize {
  usize carry = 0;
  usize *__restrict r_ptr = res;
  const usize *__restrict a_ptr = a;

  for (std::size_t i = 0; i < n; ++i) {
    usize p_lo, p_hi;
    mul_widen(a_ptr[i], b_limb, &p_lo, &p_hi);
#if defined(__GNUC__) || defined(__clang__)
    u128 sum = (u128)p_lo + r_ptr[i] + carry;
    r_ptr[i] = (usize)sum;
    carry = p_hi + (usize)(sum >> 64);
#else
    unsigned char c1 = _addcarry_u64(0, p_lo, r_ptr[i], &r_ptr[i]);
    unsigned char c2 = _addcarry_u64(c1, r_ptr[i], carry, &r_ptr[i]);
    carry = p_hi;
    if (c2) carry++;
#endif
  }
  return carry;
}

inline auto base_mul(usize *res, const usize *a, std::size_t n, const usize *b,
                     std::size_t m) {
  for (std::size_t j = 0; j < m; ++j) {
    if (b[j] == 0) continue;
    auto carry = mul_add_row(res + j, a, n, b[j]);
    res[j + n] = carry;
  }
}

template <traits::bignum_concept T>
auto mul_bignum(T &a, const T &b) {
  static constexpr auto KARATSUBA_CUTOFF = 32;
  static constexpr auto FFT_CUTOFF = 256;

  auto a_size = a.size(), b_size = b.size();

  if (a_size < KARATSUBA_CUTOFF || b_size < KARATSUBA_CUTOFF) {
    T result;
    result.resize(a.size() + b.size(), 0);

    base_mul(result.data(), a.data(), a.size(), b.data(), b.size());

    while (result.size() > 0 && result.data()[result.size() - 1] == 0)
      result.pop_back();

    a = std::move(result);
  } else if (a_size < FFT_CUTOFF && b_size < FFT_CUTOFF) {
    // TODO: implement karatsuba
  } else {
    // TODO: implement FFT multiplication
  }
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator*=(bignum_impl const &other)
    -> bignum_impl & {}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator/=(bignum_impl const &other)
    -> bignum_impl & {}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::cmp_abs(const bignum_impl &other)
    -> std::strong_ordering {
  if (m_size != other.m_size) return m_size <=> other.m_size;

  for (std::size_t i = m_size; i-- > 0;)
    if (data()[i] != other.data()[i]) return data()[i] <=> other.data()[i];

  return std::strong_ordering::equal;
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator<=>(const bignum_impl &other)
    -> std::strong_ordering {
  if (is_negative != other.is_negative)
    return is_negative ? std::strong_ordering::less
                       : std::strong_ordering::greater;

  std::strong_ordering abs_cmp = cmp_abs(other);
  return is_negative ? (0 <=> abs_cmp) : abs_cmp;
}

BIGNUM_TEMPLATE_DECL
auto BIGNUM_TEMPLATE_CLSNAME::operator==(const bignum_impl &other) -> bool {
  if (is_negative != other.is_negative) return false;
  if (m_size != other.m_size) return false;

  for (std::size_t i = 0; i < m_size; ++i)
    if (data()[i] != other.data()[i]) return false;

  return true;
}

#undef BIGNUM_TEMPLATE_DECL
#undef BIGNUM_TEMPLATE_CLSNAME

#undef FORCE_INLINE

} // namespace apa::details

namespace apa {

using bignum = details::bignum_impl<>;

using namespace details::traits;

} // namespace apa

#endif
