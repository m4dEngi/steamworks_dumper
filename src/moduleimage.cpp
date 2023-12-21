#include <cstring>
#include "moduleimage.h"

ModuleImage::ModuleImage(std::string_view t_path):
    m_modulePath(t_path),
    m_loaded(false),
    m_moduleFileSize(0),
    m_sections(nullptr),
    m_sectStrTab(nullptr),
    m_image(nullptr),
    m_imageSize(0)
{
    std::memset(&m_hdr, 0, sizeof(Elf32_Ehdr));
}

ModuleImage::~ModuleImage()
{
    // you're damn right, i have no idea how to use smart pointers
    if(m_sections != nullptr)
    {
        delete [] m_sections;
    }

    if(m_sectStrTab != nullptr)
    {
        delete [] m_sectStrTab;
    }

    if(m_image != nullptr)
    {
        delete [] m_image;
    }
}

bool ModuleImage::IsValid()
{
    if(std::memcmp(m_hdr.e_ident, ELFMAG, SELFMAG))
    {
        return false;
    }

    if(m_hdr.e_type != ET_DYN)
    {
        return false;
    }

    if(m_hdr.e_machine != EM_386)
    {
        return false;
    }

    return true;
}

size_t ModuleImage::GetFileSize()
{
    if(m_moduleFileSize == 0)
    {
        if(m_moduleStream.good())
        {
            size_t posNow = m_moduleStream.tellg();
            m_moduleStream.seekg(0, std::ios_base::end);
            m_moduleFileSize = m_moduleStream.tellg();
            m_moduleStream.seekg(posNow, std::ios_base::beg);
        }
    }

    return m_moduleFileSize;
}

const char *ModuleImage::GetImage()
{
    return m_image;
}

size_t ModuleImage::GetImageSize()
{
    return m_imageSize;
}

Elf32_Sym *ModuleImage::GetSymbolAtOffset(size_t t_offset)
{
    const Elf32_Shdr* dynSymShdr = GetSectionHeader(".dynsym");

    if(dynSymShdr == nullptr || t_offset == 0)
    {
        return nullptr;
    }

    Elf32_Sym* symtab = (Elf32_Sym*)(m_image + dynSymShdr->sh_addr);

    int numSym = dynSymShdr->sh_size / sizeof(Elf32_Sym);
    for(int i = 0; i < numSym; ++i)
    {
        if(symtab[i].st_value == t_offset)
        {
            return &symtab[i];
        }
    }

    return nullptr;
}

bool ModuleImage::ReadSectionHeaders()
{
    if( m_hdr.e_shnum == 0 ||
        m_hdr.e_shstrndx == SHN_UNDEF ||
        m_hdr.e_shstrndx >= SHN_LORESERVE
      )
    {
        return false;
    }

    m_sections = new Elf32_Shdr[m_hdr.e_shnum];
    m_moduleStream.seekg(m_hdr.e_shoff, std::ios::beg);
    m_moduleStream.read((char*)m_sections, m_hdr.e_shentsize * m_hdr.e_shnum);

    m_sectStrTab = new char[m_sections[m_hdr.e_shstrndx].sh_size];
    m_moduleStream.seekg(m_sections[m_hdr.e_shstrndx].sh_offset, std::ios::beg);
    m_moduleStream.read(m_sectStrTab, m_sections[m_hdr.e_shstrndx].sh_size);

    return true;
}

void ModuleImage::LoadModuleImage()
{
    // not gonna load anything for real, obviously
    // just read image into memory

    Elf32_Phdr* pHdrs = new Elf32_Phdr[m_hdr.e_phnum];
    m_moduleStream.seekg(m_hdr.e_phoff, std::ios::beg);
    m_moduleStream.read((char*)pHdrs, m_hdr.e_phnum * m_hdr.e_phentsize);

    for(int i = 0; i < m_hdr.e_phnum; ++i)
    {
        if(pHdrs[i].p_type == PT_LOAD)
        {
            size_t memReq = pHdrs[i].p_vaddr + pHdrs[i].p_memsz;
            if(memReq > m_imageSize)
            {
                m_imageSize = memReq;
            }
        }
    }

    m_image = new char[m_imageSize]{0};

    for(int i = 0; i < m_hdr.e_phnum; ++i)
    {
        if(pHdrs[i].p_type == PT_LOAD)
        {
            m_moduleStream.seekg(pHdrs[i].p_offset, std::ios::beg);
            m_moduleStream.read(m_image + pHdrs[i].p_vaddr, pHdrs[i].p_filesz);
        }
    }

    delete [] pHdrs;
}

bool ModuleImage::ProcessRelocations()
{
    const Elf32_Shdr* dynRelo = GetSectionHeader(".rel.dyn");
    if(dynRelo == nullptr)
    {
        return false;
    }

    const Elf32_Shdr* dynsymSect = GetSectionHeader(".dynsym");
    if(dynsymSect == nullptr)
    {
        return false;
    }

    const Elf32_Shdr* pltRelo = GetSectionHeader(".rel.plt");
    if(pltRelo == nullptr)
    {
        return false;
    }

    Elf32_Rel* relocs = (Elf32_Rel*)(m_image + dynRelo->sh_addr);
    int relocCount = dynRelo->sh_size / sizeof(Elf32_Rel);

    Elf32_Sym* symtab = (Elf32_Sym*)(m_image + dynsymSect->sh_addr);

    for(int i = 0; i < relocCount; ++i)
    {
        if(ELF32_R_TYPE(relocs[i].r_info) == R_386_32)
        {
           *(uint32_t*)(m_image + relocs[i].r_offset) = symtab[ELF32_R_SYM(relocs[i].r_info)].st_value;
        }
    }

    Elf32_Rel* pltRelocs = (Elf32_Rel*)(m_image + pltRelo->sh_addr);
    int pltRelocCount = pltRelo->sh_size / sizeof(Elf32_Rel);

    for(int i = 0; i < pltRelocCount; ++i)
    {
        if(ELF32_R_TYPE(pltRelocs[i].r_info) == R_386_JMP_SLOT)
        {
            *(uint32_t*)(m_image + pltRelocs[i].r_offset) = symtab[ELF32_R_SYM(pltRelocs[i].r_info)].st_value;
        }
    }

    return true;
}

bool ModuleImage::ProcessDynSymtab()
{
    // assign some 'address' outside of image scope for external symbols
    uint32_t oneMadeUpAddress = GetImageSize() + 4096;
    const Elf32_Shdr* dynsymSect = GetSectionHeader(".dynsym");
    if(dynsymSect == nullptr)
    {
        return false;
    }

    Elf32_Sym* symtab = (Elf32_Sym*)(m_image + dynsymSect->sh_addr);
    int numSym = dynsymSect->sh_size / sizeof(Elf32_Sym);

    for(int i = 1; i < numSym; ++i)
    {
        if(symtab[i].st_value == 0 &&
                ( ELF32_ST_BIND(symtab[i].st_info) == STB_GLOBAL ||  ELF32_ST_BIND(symtab[i].st_info) == STB_WEAK)
          )
        {
            symtab[i].st_value = oneMadeUpAddress;
            oneMadeUpAddress += 4; // could be just ++ (?) we're not gonna use it anyway
                                   // we just need a unique "address" outside of image
                                   // but sizeof(void*) for 32bit is 4
        }
    }

    return true;
}

void ModuleImage::UpdatePltSymbols()
{
    const Elf32_Shdr* gotPltSect = GetSectionHeader(".got");
    const Elf32_Shdr* pltSect = GetSectionHeader(".plt");
    const char* gotPlt = m_image + gotPltSect->sh_addr;

    // 16 byte aligned jmp slot where 1st 6 bytes are relative short jmp to GOT offset
    const char* jmpSlot = m_image + pltSect->sh_addr;
    const char* jmpTblEnd = jmpSlot + pltSect->sh_size;

    while(jmpSlot < jmpTblEnd)
    {
        jmpSlot += 16;
        size_t jmpSlotGotOffset = *(int*)(jmpSlot + 2);
        Elf32_Sym* pltSym = GetSymbolAtOffset(*((int*)(gotPlt + jmpSlotGotOffset)));
        if(pltSym)
        {
            pltSym->st_value = jmpSlot - m_image;
        }
    }
}

const Elf32_Shdr *ModuleImage::GetSectionHeader(std::string_view t_section)
{
    for(int i = 0; i < m_hdr.e_shnum; ++i)
    {
        if(t_section == m_sectStrTab + m_sections[i].sh_name)
        {
            return &m_sections[i];
        }
    }

    return nullptr;
}


bool ModuleImage::Load()
{
    if(m_loaded)
    {
        return true;
    }

    m_moduleStream.open(m_modulePath, std::ios::in | std::ios::binary);
    if(!m_moduleStream.good())
    {
        return false;
    }

    if(GetFileSize() < sizeof(Elf32_Ehdr))
    {
        return false;
    }

    m_moduleStream.read((char*)&m_hdr, sizeof(Elf32_Ehdr));

    if(!IsValid())
    {
        return false;
    }

    if(!ReadSectionHeaders())
    {
        return false;
    }

    LoadModuleImage();
    ProcessDynSymtab();
    ProcessRelocations();
    UpdatePltSymbols();

    return m_loaded = true;
}
