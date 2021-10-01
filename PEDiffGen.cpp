// PEDiffGen - A PE file subtraction tool
// Copyright (C) 2021  namazso <admin@namazso.eu>
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#include <Windows.h>
#include <winternl.h>
#include <fstream>
#include <vector>
#include <array>
#include <algorithm>
#include <cassert>

std::vector<uint8_t> read_all(const char* path)
{
  std::ifstream is(path, std::ios::binary);
  if (!is.good() || !is.is_open())
    return {};
  is.seekg(0, std::ifstream::end);
  std::vector<uint8_t> data;
  data.resize((size_t)is.tellg());
  is.seekg(0, std::ifstream::beg);
  is.read(reinterpret_cast<char*>(data.data()), (std::streamsize)data.size());
  return data;
}

void write_all(const char* path, const void* data, size_t size)
{
  std::ofstream os(path, std::ios::binary);
  os.write((const char*)data, size);
  os.close();
}

template <bool Is64>
int main2(const uint8_t* pe1, const uint8_t* pe2, const char* out_filename)
{
  using NT_HEADERS = std::conditional_t<Is64, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32>;

  const auto dosh1 = (const IMAGE_DOS_HEADER*)pe1;
  const auto dosh2 = (const IMAGE_DOS_HEADER*)pe2;
  const auto peh1 = (const NT_HEADERS*)(pe1 + dosh1->e_lfanew);
  const auto peh2 = (const NT_HEADERS*)(pe2 + dosh2->e_lfanew);

  if (peh1->OptionalHeader.SizeOfHeaders != peh2->OptionalHeader.SizeOfHeaders)
  {
    fprintf(stderr, "Header size mismatch!!\n");
    return -7;
  }

  std::vector<uint8_t> out_file;
  const auto do_compare = [&out_file](const uint8_t* it1, const uint8_t* it2, size_t size, uint32_t offset)
  {
    if (out_file.size() < offset + size)
      out_file.resize(offset + size);
    std::transform(it1, it1 + size, it2, out_file.begin() + offset, [](uint8_t a, uint8_t b)
      {
        return (uint8_t)(a - b);
      });
  };

  do_compare(pe1, pe2, peh1->OptionalHeader.SizeOfHeaders, 0);

  if (peh1->FileHeader.NumberOfSections != peh2->FileHeader.NumberOfSections)
  {
    fprintf(stderr, "Section count mismatch!!\n");
    return -8;
  }

  const auto section_count = peh1->FileHeader.NumberOfSections;
  const auto sections1 = (const IMAGE_SECTION_HEADER*)(peh1 + 1);
  const auto sections2 = (const IMAGE_SECTION_HEADER*)(peh2 + 1);

  for (size_t i = 0; i < section_count; ++i)
  {
    const auto& section1 = sections1[i];
    const auto& section2 = sections2[i];

    if (section1.VirtualAddress != section2.VirtualAddress)
    {
      fprintf(stderr, "Section VA mismatch!!\n");
      return -9;
    }

    const auto virtual_address = section1.VirtualAddress;

    if (section1.Misc.VirtualSize != section2.Misc.VirtualSize)
    {
      fprintf(stderr, "Section virtual size mismatch!!\n");
      return -10;
    }

    const auto virtual_size = section2.Misc.VirtualSize;

    if (!section1.SizeOfRawData && !section2.SizeOfRawData)
      continue;

    std::vector<uint8_t> section1_copy{ pe1 + section1.PointerToRawData, pe1 + section1.PointerToRawData + section1.SizeOfRawData };
    std::vector<uint8_t> section2_copy{ pe2 + section2.PointerToRawData, pe2 + section2.PointerToRawData + section2.SizeOfRawData };

    section1_copy.resize(virtual_size);
    section2_copy.resize(virtual_size);

    do_compare(section1_copy.data(), section2_copy.data(), virtual_size, virtual_address);
  }

  const auto last_nonzero = std::find_if(out_file.rbegin(), out_file.rend(), [](uint8_t v) { return v != 0; });
  if (last_nonzero == out_file.rend())
  {
    fprintf(stderr, "Warning: no differences!!\n");
    out_file.clear();
  }
  else if (last_nonzero != out_file.rbegin())
  {
    out_file.erase(last_nonzero.base(), out_file.end());
  }
  
  write_all(out_filename, out_file.data(), out_file.size());

  return 0;
}

int main(int argc, char** argv)
{
  if (argc != 4)
  {
    fprintf(stderr, "Usage: %s <pe1> <pe2> <output (pe1 - pe2)>\n", argv[0]);
    return -1;
  }

  const auto pe1 = read_all(argv[1]);
  const auto pe2 = read_all(argv[2]);

  if (pe1.size() < sizeof(IMAGE_DOS_HEADER) || pe2.size() < sizeof(IMAGE_DOS_HEADER))
  {
    fprintf(stderr, "Not a PE file!!\n");
    return -2;
  }

  const auto dosh1 = (const IMAGE_DOS_HEADER*)pe1.data();
  const auto dosh2 = (const IMAGE_DOS_HEADER*)pe2.data();

  if (dosh1->e_magic != IMAGE_DOS_SIGNATURE || dosh2->e_magic != IMAGE_DOS_SIGNATURE)
  {
    fprintf(stderr, "Not a PE file!!\n");
    return -3;
  }

  const auto peh1 = (const IMAGE_NT_HEADERS*)(pe1.data() + dosh1->e_lfanew);
  const auto peh2 = (const IMAGE_NT_HEADERS*)(pe2.data() + dosh2->e_lfanew);

  if (peh1->Signature != IMAGE_NT_SIGNATURE || peh2->Signature != IMAGE_NT_SIGNATURE)
  {
    fprintf(stderr, "Not a PE file!!\n");
    return -4;
  }

  if (peh1->OptionalHeader.Magic != peh2->OptionalHeader.Magic)
  {
    fprintf(stderr, "Bitness mismatch!!\n");
    return -5;
  }

  if (peh1->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return main2<true>(pe1.data(), pe2.data(), argv[3]);
  if (peh1->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    return main2<false>(pe1.data(), pe2.data(), argv[3]);

  fprintf(stderr, "Unsupported PE!!\n");
  return -6;
}
