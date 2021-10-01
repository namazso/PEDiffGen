# PEDiffGen

A simple PE subtraction utility.

```
PEDiffGen.exe <pe1> <pe2> <output>
```

The above command generates the result of pe1 - pe2 in memory (as in, matching up with virtual addresses). This can be applied onto an in-memory image easily:

```cpp
  for (size_t i = 0; i < diff_size; i += 0x1000)
  {
    const auto curr = diff + i;
    const auto chunk_size = std::min((size_t)(diff_size - i), (size_t)0x1000);
    if (std::all_of(curr, curr + chunk_size, [](uint8_t c) { return !!c; }))
      continue;
    uint8_t page[0x1000];
    std::transform(curr, curr + chunk_size, dll_base + i, page, [](uint8_t a, uint8_t b) { return a + b; });
    unprotect_memcpy(dll_base + i, page, chunk_size);
  }
```

It is recommended that you compress the subtraction result as most of it is zeros. After compression, this should produce one of the smallest possible footprints compared to other diffing methods.

## License

    PEDiffGen - A PE file subtraction tool
    Copyright (C) 2021  namazso <admin@namazso.eu>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
