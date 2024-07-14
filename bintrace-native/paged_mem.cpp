#include <assert.h>
#include <algorithm>
#include <iostream>
#include "paged_mem.hpp"


Page::Page()
  : m_base_addr(0), m_page_size(0)
{

}

Page::Page(uint64_t base_addr, uint32_t page_size)
  : m_base_addr(base_addr), m_page_size(page_size)
{

}

Page::Page(const Page & page)
  : m_base_addr(page.m_base_addr), m_page_size(page.m_page_size)
{
  m_bitmap = page.m_bitmap;
  m_content = page.m_content;
}

bool Page::contains(uint64_t off) const
{
  if (off >= 0 && off < m_content.size()) {
    return this->is_bit_set(off);
  }
  return false;
}

void Page::setbit(uint64_t off)
{
  uint64_t byte_idx = off / 8, bit_off = off % 8;
  if (byte_idx >= m_bitmap.size()) {
    m_bitmap.resize(byte_idx + 1);
  }
  uint8_t b = m_bitmap.at(byte_idx);
  b |= (1 << bit_off);
  m_bitmap[byte_idx] = b;
}

bool Page::is_bit_set(uint64_t off) const
{
  uint64_t byte_idx = off / 8, bit_off = off % 8;
  if (byte_idx >= m_bitmap.size()) {
    // the byte does not exist. the bit is missing
    return false;
  }
  uint8_t b = m_bitmap.at(byte_idx);
  if (((b >> bit_off) & 1) == 1) {
    return true;
  }
  return false;
}

std::vector<uint64_t> Page::offsets() const
{
  std::vector<uint64_t> offs;
  // traverse the bitmap
  for (uint64_t i = 0; i < m_bitmap.size(); ++i) {
    uint8_t b = m_bitmap.at(i);
    if (b != 0) {
      for (uint64_t o = 0; o < 8; ++o) {
        if ((b & 1) == 1) {
          offs.push_back(i * 8 + o);
        }
        b >>= 1;
      }
    }
  }
  return offs;
}

uint8_t Page::operator [](uint64_t off) const
{
  assert(this->contains(off));

  return m_content[off];
}

uint8_t & Page::operator [](uint64_t off)
{
  assert(off >= 0 && off < m_page_size);
  if (off >= m_content.size()) {
    m_content.resize(off + 1);
  }
  setbit(off);
  return m_content[off];
}

std::vector<std::pair<uint64_t, uint64_t>> Page::get_contiguous_ranges() const
{
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  // traverse the bitmap to determine ranges
  std::pair<uint64_t, uint64_t> prev_range = std::make_pair(0, 0);
  for (size_t i = 0; i < m_bitmap.size(); ++i) {
    uint32_t byte_base = i * 8;
    uint8_t b = m_bitmap[i];

    // fast path: b == 0xff
    if (b == 0xff) {
      if (prev_range.second > 0) {
        // previous range exists
        if (prev_range.first + prev_range.second == byte_base) {
          // update prev_range by incrementing the size by 8
          // continuous
          prev_range = std::make_pair(prev_range.first, prev_range.second + 8);
        } else {
          // not continuous
          // insert prev_range
          ranges.push_back(prev_range);
          // update prev_range
          prev_range = std::make_pair(byte_base, 8);
        }
      } else {
        // prev_range does not exist
        // update prev_range
        prev_range = std::make_pair(byte_base, 8);
      }
      continue;
    }
    // fast path: b == 0
    if (b == 0) {
      if (prev_range.second > 0) {
        // insert prev_range
        ranges.push_back(prev_range);
        prev_range = std::make_pair(0, 0);
      }
      continue;
    }

    for (int bitoff = 0; bitoff < 8; ++bitoff) {
      if ((b & 1) == 1) {
        if (prev_range.second > 0) {
          if (prev_range.first + prev_range.second == byte_base + bitoff) {
            prev_range = std::make_pair(prev_range.first, prev_range.second + 1);
            continue;
          } else {
            // insert prev_range
            ranges.push_back(prev_range);
            prev_range = std::make_pair(0, 0);
          }
        }
        // update prev_range
        prev_range = std::make_pair(byte_base + bitoff, 1);
      }
      b >>= 1;
    }
  }
  if (prev_range.second > 0) {
    // insert the last prev_range
    ranges.push_back(prev_range);
  }
  return ranges;
}

PagedMemory::PagedMemory()
  : m_page_size(4096)
{

}

PagedMemory::PagedMemory(uint32_t page_size)
  : m_page_size(page_size)
{

}

PagedMemory::PagedMemory(const PagedMemory &mem)
  : m_page_size(mem.m_page_size), m_pages(mem.m_pages)
{

}

bool PagedMemory::contains(uint64_t addr) const
{
  uint64_t page_id = get_page_id(addr);
  auto iter = m_pages.find(page_id);
  if (iter == m_pages.end()) {
    return false;
  }
  Page page = iter->second;
  uint32_t off = get_page_offset(addr);
  return page.contains(off);
}

uint8_t PagedMemory::operator [](uint64_t addr) const
{
  assert(this->contains(addr));
  uint64_t page_id = get_page_id(addr), off = get_page_offset(addr);
  Page page = m_pages.find(page_id)->second;
  return page[off];
}

uint8_t PagedMemory::at(uint64_t addr) const
{
  assert(this->contains(addr));
  uint64_t page_id = get_page_id(addr), off = get_page_offset(addr);
  Page page = m_pages.find(page_id)->second;
  return page[off];
}

uint8_t & PagedMemory::operator [](uint64_t addr)
{
  uint64_t page_id = get_page_id(addr), off = get_page_offset(addr);
  auto iter = m_pages.find(page_id);
  if (iter == m_pages.end()) {
    m_pages[page_id] = Page(page_id * m_page_size, m_page_size);
    return m_pages[page_id][off];
  }
  return iter->second[off];
}

std::vector<uint64_t> PagedMemory::sorted_addresses() const
{
  uint64_t zeros = 0, total = 0;

  std::vector<uint64_t> addrs;
  std::vector<uint64_t> sorted_page_idx;
  for (
    auto iter = m_pages.begin();
    iter != m_pages.end();
    ++iter
  ) {
    sorted_page_idx.push_back(iter->first);
  }
  // sort
  std::sort(sorted_page_idx.begin(), sorted_page_idx.end());
  for (
    auto iter = sorted_page_idx.begin();
    iter != sorted_page_idx.end();
    ++iter
  ) {
    uint64_t page_addr = *iter * m_page_size;
    const Page & p = m_pages.at(*iter);
    std::vector<uint64_t> page_offs = p.offsets();
    for (uint64_t i = 0; i < page_offs.size(); ++i) {
      addrs.push_back(page_addr + page_offs.at(i));
      total += 1;
      if (p[page_offs.at(i)] == 0) {
        zeros += 1;
      }
    }
  }
  std::cerr << "Got " << total << " addresses with " << zeros << " zeros." << std::endl;
  return addrs;
}

std::vector<std::pair<uint64_t, uint64_t>> PagedMemory::get_contiguous_ranges() const
{
  std::vector<std::pair<uint64_t, uint64_t>> ranges;
  std::vector<uint64_t> sorted_page_idx;
  for (
    auto iter = m_pages.begin();
    iter != m_pages.end();
    ++iter
  ) {
    sorted_page_idx.push_back(iter->first);
  }
  // sort
  std::sort(sorted_page_idx.begin(), sorted_page_idx.end());

  std::pair<uint64_t, uint64_t> prev_range = std::make_pair(0, 0);

  for (size_t i = 0; i < sorted_page_idx.size(); ++i) {
    uint64_t page_id = sorted_page_idx[i];
    uint64_t page_base = page_id * m_page_size;

    const Page & page = m_pages.at(page_id);
    std::vector<std::pair<uint64_t, uint64_t>> page_ranges = page.get_contiguous_ranges();
    for (size_t j = 0; j < page_ranges.size(); ++j) {
      std::pair<uint64_t, uint64_t> r = page_ranges.at(j);
      // check if we consolidate with the previous range
      if(prev_range.second != 0) {
        if (prev_range.first + prev_range.second == page_base + r.first) {
          // update prev_range
          prev_range = std::make_pair(
            prev_range.first,
            prev_range.second + r.second
          );
          continue;
        } else {
          // insert prev_range and clear it
          ranges.push_back(prev_range);
          prev_range = std::make_pair(0, 0);
        }
      }
      // now prev_range does not exist - update it
      prev_range = std::make_pair(page_base + r.first, r.second);
    }
  }
  if (prev_range.second > 0) {
    // insert the very last range
    ranges.push_back(prev_range);
  }
  return ranges;
}
