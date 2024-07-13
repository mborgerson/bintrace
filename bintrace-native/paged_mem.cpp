#include <assert.h>
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
  m_content = page.m_content;
}

bool Page::contains(uint64_t off) const
{
  if (off >= 0 && off < m_content.size()) {
    return true;
  }
  return false;
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
  return m_content[off];
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
