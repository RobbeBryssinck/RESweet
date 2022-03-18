#include "loader.h"

#include <capstone/capstone.h>
#include <bfd.h>

static bfd* open_bfd(std::string& fname)
{
  static int bfd_inited = 0;
  bfd* bfd_h;

  if (!bfd_inited)
  {
    bfd_init();
    bfd_inited = 1;
  }

  bfd_h = bfd_openr(fname.c_str(), NULL);
  if (!bfd_h)
  {
    fprintf(stderr, "failed to open binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return nullptr;
  }

  if (!bfd_check_format(bfd_h, bfd_object))
  {
    fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return nullptr;
  }

  bfd_set_error(bfd_error_no_error);

  if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
  {
    fprintf(stderr, "unrecognized format for binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return nullptr;
  }

  return bfd_h;
}

static bool load_symbols_bfd(bfd* bfd_h, Binary* bin)
{
  long upperBound = bfd_get_symtab_upper_bound(bfd_h);
  if (upperBound < 0)
  {
    fprintf(stderr, "failed to read symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    return false;
  }
  else if (upperBound)
  {
    asymbol** bfd_symtab = static_cast<asymbol**>(malloc(upperBound));
    if (!bfd_symtab)
    {
      fprintf(stderr, "out of memory\n");
      return false;
    }

    long nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if (nsyms < 0)
    {
      fprintf(stderr, "failed to read symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      return false;
    }

    for (long i = 0; i < nsyms; i++)
    {
      if (bfd_symtab[i]->flags & BSF_FUNCTION)
      {
        bin->symbols.push_back(Symbol());
        Symbol& symbol = bin->symbols.back();

        symbol.type = Symbol::Type::FUNC;
        symbol.name = bfd_symtab[i]->name;
        symbol.addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }

    free(bfd_symtab);
  }

  return true;
}

static bool load_dynsym_bfd(bfd* bfd_h, Binary* bin)
{
  long upperBound = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if (upperBound < 0)
  {
    fprintf(stderr, "failed to read dynamic symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    return false;
  }
  else if (upperBound)
  {
    asymbol** bfd_symtab = static_cast<asymbol**>(malloc(upperBound));
    if (!bfd_symtab)
    {
      fprintf(stderr, "out of memory\n");
      return false;
    }

    long nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_symtab);
    if (nsyms < 0)
    {
      fprintf(stderr, "failed to read dynamic symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      return false;
    }

    for (long i = 0; i < nsyms; i++)
    {
      if (bfd_symtab[i]->flags & BSF_FUNCTION)
      {
        bin->symbols.push_back(Symbol());
        Symbol& symbol = bin->symbols.back();
        symbol.type = Symbol::Type::FUNC;
        symbol.name = bfd_symtab[i]->name;
        symbol.addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }

    free(bfd_symtab);
  }

  return true;
}

static bool load_sections_bfd(bfd* bfd_h, Binary* bin)
{
  for (asection* bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next)
  {
    int bfd_flags = bfd_section_flags(bfd_sec);

    Section::Type sectype = Section::Type::NONE;
    if (bfd_flags & SEC_CODE)
      sectype = Section::Type::CODE;
    else if (bfd_flags & SEC_DATA)
      sectype = Section::Type::DATA;
    else
      continue;

    const char* secname = bfd_section_name(bfd_sec);

    bin->sections.push_back(Section());
    Section& section = bin->sections.back();

    section.binary = bin;
    section.name = secname ? secname : "<unnamed>";
    section.type = sectype;
    section.vma = bfd_section_vma(bfd_sec);
    section.size = bfd_section_size(bfd_sec);
    section.bytes = static_cast<uint8_t*>(malloc(section.size));

    if (!section.bytes)
    {
      fprintf(stderr, "out of memory\n");
      return false;
    }

    if (!bfd_get_section_contents(bfd_h, bfd_sec, section.bytes, 0, section.size))
    {
      fprintf(stderr, "failed to read section '%s' (%s)\n",
              section.name.c_str(), bfd_errmsg(bfd_get_error()));
      return false;
    }
  }

  return true;
}

static bool load_binary_bfd(std::string& fname, Binary* bin, Binary::Type type)
{
  const bfd_arch_info_type* bfd_info;

  bfd* bfd_h = nullptr;
  bfd_h = open_bfd(fname);
  if (!bfd_h)
    return false;
  
  bin->filename = fname;
  bin->entry = bfd_get_start_address(bfd_h);
  bin->type_str = bfd_h->xvec->name;

  switch (bfd_h->xvec->flavour)
  {
    case bfd_target_elf_flavour:
      bin->type = Binary::Type::ELF;
      break;
    case bfd_target_coff_flavour:
      bin->type = Binary::Type::PE;
      break;
    case bfd_target_unknown_flavour:
    default:
      fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
      return false;
  }

  bfd_info = bfd_get_arch_info(bfd_h);
  bin->arch_str = bfd_info->printable_name;

  switch (bfd_info->mach)
  {
    case bfd_mach_i386_i386:
      bin->arch = Binary::Arch::X86;
      bin->bits = 32;
      break;
    case bfd_mach_x86_64:
      bin->arch = Binary::Arch::X86;
      bin->bits = 64;
      break;
    default:
      fprintf(stderr, "unsupported architecture (%s)\n", bfd_info->printable_name);
      return false;
  }

  load_symbols_bfd(bfd_h, bin);
  load_dynsym_bfd(bfd_h, bin);

  if (load_sections_bfd(bfd_h, bin) < 0)
    return false;

  if (bfd_h)
    bfd_close(bfd_h);

  return true;
}

bool LoadBinary(std::string& fname, Binary* bin, Binary::Type type)
{
  return load_binary_bfd(fname, bin, type);
}

void UnloadBinary(Binary* bin)
{
  for (Section& section : bin->sections)
  {
    if (section.bytes)
      free(section.bytes);
  }
}
