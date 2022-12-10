#include <cstring>
#include "clientmodule.h"

ClientModule::ClientModule(std::string_view t_path):
    m_image(t_path),
    m_imageData(nullptr),
    m_extSyms(nullptr),
    m_extStrTab(nullptr),
    m_numExtSyms(0)
{
}

ClientModule::~ClientModule()
{
}

const Elf32_Sym* ClientModule::GetSymbol(std::string_view t_name)
{
    if(t_name.size() == 0)
    {
        return nullptr;
    }

    for(int i = 0; i < m_numExtSyms; ++i)
    {
        if(std::string_view(m_extStrTab + m_extSyms[i].st_name) == t_name)
        {
            return &m_extSyms[i];
        }
    }

    return nullptr;
}

const size_t ClientModule::FindSymbols(std::string_view t_name, std::vector<const Elf32_Sym *>* t_out)
{
    if(t_name.empty())
    {
        return 0;
    }

    for(int i = 0; i < m_numExtSyms; ++i)
    {
        if(std::string_view(m_extStrTab + m_extSyms[i].st_name).rfind(t_name) != std::string::npos)
        {
            t_out->push_back(&m_extSyms[i]);
        }
    }

    return t_out->size();
}

const Elf32_Shdr* ClientModule::GetSectionHeader(std::string_view t_name)
{
    return m_image.GetSectionHeader(t_name);
}

const char* ClientModule::GetImageBytes()
{
    return m_imageData;
}

const std::map<size_t, std::vector<size_t>>* ClientModule::GetFunctions()
{
    return &m_functions;
}

const std::map<size_t,std::vector<size_t>>* ClientModule::GetConstants()
{
    return &m_suspectConstants;
}

const std::vector<size_t>* ClientModule::GetRefsToSymbol(size_t t_offset)
{
    if(m_extRefs.find(t_offset) != m_extRefs.cend())
    {
        return &m_extRefs[t_offset];
    }

    return nullptr;
}

size_t ClientModule::GetVTTypes(std::vector<size_t> *t_out)
{
    std::vector<const Elf32_Sym*> tis;
    if(FindSymbols("_class_type_infoE", &tis) != 0)
    {
        for(auto it = tis.begin(); it != tis.end(); ++it)
        {
            auto refs = GetRefsToSymbol((*it)->st_value);
            t_out->insert(t_out->end(), refs->cbegin(), refs->cend());
        }
    }

    return t_out->size();
}

size_t ClientModule::GetFunctionSize(size_t t_offset)
{
    auto it = m_functions.find(t_offset);
    if(it == m_functions.cend())
    {
        return -1;
    }

    return std::next(it)->first - it->first;
}

const std::vector<size_t>* ClientModule::GetRefsToConstOffset(size_t t_offset)
{
    if(m_suspectConstants.find(t_offset) != m_suspectConstants.cend())
    {
        return &m_suspectConstants[t_offset];
    }

    return nullptr;
}

const std::vector<size_t>* ClientModule::GetRefsToFuncOffset(size_t t_offset)
{
    if(m_functions.find(t_offset) != m_functions.cend())
    {
        return &m_functions[t_offset];
    }

    return nullptr;
}

bool ClientModule::Load()
{
    bool loaded = m_image.Load();

    if(loaded)
    {
        const Elf32_Shdr* data = m_image.GetSectionHeader(".data");
        if(data)
        {
            m_dataSections[data->sh_addr] = data->sh_addr + data->sh_size;
        }
        const Elf32_Shdr* roData = m_image.GetSectionHeader(".rodata");
        if(roData)
        {
            m_dataSections[roData->sh_addr] = roData->sh_addr + roData->sh_size;
        }
        const Elf32_Shdr* relData = m_image.GetSectionHeader(".data.rel.ro");
        if(relData)
        {
            m_dataSections[relData->sh_addr] = relData->sh_addr + relData->sh_size;
        }
        const Elf32_Shdr* relLocalData = m_image.GetSectionHeader(".data.rel.ro.local");
        if(relLocalData)
        {
            m_dataSections[relLocalData->sh_addr] = relLocalData->sh_addr + relLocalData->sh_size;
        }
    }

    m_imageData = m_image.GetImage();

    const Elf32_Shdr* dynSymShdr = GetSectionHeader(".dynsym");
    if(dynSymShdr)
    {
        m_extSyms = (Elf32_Sym*)(m_imageData + dynSymShdr->sh_addr);
        m_numExtSyms = dynSymShdr->sh_size / sizeof(Elf32_Sym);

        const Elf32_Shdr* dynStrShdr = GetSectionHeader(".dynstr");
        m_extStrTab = (char*)(m_imageData + dynStrShdr->sh_addr);
    }
    else
    {
        loaded = false;
    }

    return loaded;
}

bool ClientModule::IsDataOffset(size_t t_offset)
{
    for(auto it = m_dataSections.cbegin(); it != m_dataSections.cend(); ++it)
    {
        if(it->first <= t_offset && t_offset < it->second)
        {
            return true;
        }
    }

    return false;
}

void ClientModule::FindExtSymRefs()
{
    const Elf32_Shdr* dynRelocsShdr = GetSectionHeader(".rel.dyn");

    if(dynRelocsShdr == nullptr)
    {
        return;
    }

    const Elf32_Rel* relocs = (Elf32_Rel*)(m_imageData + dynRelocsShdr->sh_addr);
    int relocCnt = dynRelocsShdr->sh_size / sizeof(Elf32_Rel);
    for(int i = 0; i < relocCnt; ++i)
    {
        if(ELF32_R_TYPE(relocs[i].r_info) == R_386_32)
        {
            m_extRefs[m_extSyms[ELF32_R_SYM(relocs[i].r_info)].st_value].push_back(relocs[i].r_offset);
        }
    }
}

// huge and ugly function
bool ClientModule::Parse()
{
    csh csHandle;
    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) != CS_ERR_OK)
    {
        return false;
    }

    cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
    // details are irrelevant with skipdata option on
    // but somehow quite useful and relevant at the same time ¯\_(ツ)_/¯
    cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

    const Elf32_Shdr* codeSect = m_image.GetSectionHeader(".text");
    const uint8_t* code = (uint8_t*)(m_imageData + codeSect->sh_addr);
    size_t codeSize = codeSect->sh_size;
    uint64_t address = codeSect->sh_addr;
    cs_insn* insn = cs_malloc(csHandle);

    const Elf32_Shdr* gotPlt = m_image.GetSectionHeader(".got.plt");

    while(cs_disasm_iter(csHandle, &code, &codeSize, &address, insn))
    {
        cs_x86* x86 = &(insn->detail->x86);

        switch(insn->id)
        {
            case X86_INS_MOV:
            case X86_INS_LEA:
            case X86_INS_CMP:
            {
                // every time we see something like
                //
                // lea eax, [ebx - 0xFFFFFFFF]
                //
                // it's probably calculating relative offset to constant using .got.plt offset
                // previously stored in a reg as base
                // so we'll store that offset to use later for const size hint
                //
                // probably not the best way to guess const offsets, but good enough for our needs
                for(int i = 0; i < x86->op_count; ++i)
                {
                    if( x86->operands[i].type == X86_OP_MEM
                        && x86->operands[i].mem.base != X86_REG_INVALID
                      )
                    {
                        size_t constOffset = gotPlt->sh_addr + x86->disp;
                        if(IsDataOffset(constOffset))
                        {
                            m_suspectConstants[constOffset].push_back(insn->address);
                        }
                        break;
                    }
                }
                break;
            }
            case X86_INS_CALL:
            {
                if(x86->operands[0].type == X86_OP_IMM)
                {
                    m_functions[x86->operands[0].imm].push_back(insn->address);
                }
                break;
            }

            // Turns out using PUSH EBP/ESP as a marker for function prologue
            // isn't a good idea
            //
            // TODO: Figure out a better way to find functions prologue
            case X86_INS_PUSH:
            {
                if(x86->operands[0].type == X86_OP_REG
                   && x86->operands[0].reg == X86_REG_EBP
                  )
                {
                    m_functions[insn->address].push_back(insn->address);
                }
                break;
            }
        }
    }

    cs_free(insn, 1);
    cs_close(&csHandle);

    FindExtSymRefs();

    return true;
}

size_t ClientModule::FindSignature(const char* t_sign, const char* t_mask, size_t t_searchBaseOffset)
{
    size_t signLen = std::strlen(t_mask);
    if(signLen == 0)
    {
        return -1;
    }

    const Elf32_Shdr* text = m_image.GetSectionHeader(".text");
    const char* searchBase = m_imageData + text->sh_addr;
    if(t_searchBaseOffset != -1)
    {
        searchBase = m_imageData + t_searchBaseOffset;
    }
    const char* searchEnd = searchBase + text->sh_size - signLen;

    while(searchBase < searchEnd)
    {
        int i;
        for(i = 0; i < signLen; ++i)
        {
            if(t_mask[i] != '?' && t_sign[i] != searchBase[i])
            {
                break;
            }
        }

        if(i == signLen)
        {
            return (size_t)(searchBase - m_imageData);
        }

        ++searchBase;
    }

    return -1;
}

bool ClientModule::FindRefOrigin(size_t t_offset, size_t* t_funcOffset, size_t* t_funcSize)
{
    auto it = m_functions.lower_bound(t_offset);
    if(it != m_functions.cend() && it != m_functions.cbegin())
    {
        if(t_funcSize)
        {
            *t_funcSize = it->first - std::prev(it)->first;
        }

        if(t_funcOffset)
        {
            *t_funcOffset = std::prev(it)->first;
        }

        return true;
    }

    return false;
}

size_t ClientModule::FindStringLiteral(const std::string_view t_string)
{
    const char* image = m_image.GetImage();
    for(auto it = m_suspectConstants.cbegin(); it != m_suspectConstants.cend(); ++it)
    {
        std::string_view strValue(image + it->first);
        if(strValue == t_string)
        {
            return it->first;
        }
    }

    return -1;
}



