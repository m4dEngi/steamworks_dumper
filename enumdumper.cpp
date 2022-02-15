#include <vector>
#include <iostream>
#include <set>
#include "enumdumper.h"

EnumDumper::EnumDumper(ClientModule *t_module):
    DumperBase(t_module),
    m_searchHint(-1),
    m_relData(nullptr)
{
    m_searchHint = m_module->FindStringLiteral("/data/src/common/enum_names.cpp");
    if(m_searchHint == -1)
    {
        std::cout << "Enum search hint not found" << std::endl;
    }

    m_relData = m_module->GetSectionHeader(".data.rel.ro.local");
}

EnumDumper::~EnumDumper()
{

}

std::string EnumDumper::SanitizeEnumStr(const std::string_view t_enumStr)
{
    static std::string allowed("ABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321_abcdefghijklmnopqrstuvwxyz");
    std::string out;

    for(auto it = t_enumStr.begin(); it != t_enumStr.end(); ++it)
    {
        if(allowed.find(*it) != std::string::npos)
        {
            if(it == t_enumStr.begin() || ' ' == *std::prev(it))
            {
                out += std::toupper(*it);
            }
            else
            {
                out += *it;
            }
        }
    }
    return out;
}

bool EnumDumper::GetEnumOffsetsByRef(size_t t_ref, size_t* t_name, size_t* t_value)
{
    size_t funcSize, funcOffset = 0;
    if(!m_module->FindRefOrigin(t_ref, &funcOffset, &funcSize))
    {
        return false;
    }

    csh csHandle;
    cs_insn *ins;
    size_t count;

    std::vector<size_t> possibleAssertArgs;
    std::set<size_t> suspectEnumOffsets;
    size_t enumNameOffset = -1;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) == CS_ERR_OK)
    {
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(csHandle, (uint8_t*)(m_image + funcOffset), funcSize, funcOffset, 0, &ins);
        if(count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                if(ins[i].id == X86_INS_LEA || ins[i].id == X86_INS_MOV)
                {
                    cs_x86* x86 = &ins[i].detail->x86;
                    if( x86->operands[1].type == X86_OP_MEM
                        && x86->operands[1].mem.base == X86_REG_EBX
                      )
                    {
                       size_t memOffset = x86->disp + m_constBase;
                       if(m_relData->sh_addr <= memOffset && memOffset < m_relData->sh_addr + m_relData->sh_size)
                       {
                           suspectEnumOffsets.insert(memOffset);
                       }
                       else
                       {
                           possibleAssertArgs.push_back(memOffset);
                       }


                       if(memOffset == m_searchHint)
                       {
                            // found enum search hint, now to get it's name and offset in .data.rel
                           if(possibleAssertArgs.size() < 3)
                           {
                               // something went wrong and no possible args were found
                               continue;
                           }

                           enumNameOffset = *(possibleAssertArgs.cend() - 3);
                       }
                    }
                }
            }

            cs_free(ins, count);
        }
    }
    cs_close(&csHandle);

    if(enumNameOffset != -1 && suspectEnumOffsets.size() != 0)
    {
        *t_name = enumNameOffset;
        *t_value = *suspectEnumOffsets.rbegin();

        return true;
    }

    return false;
}

void EnumDumper::ReadEnum(size_t t_nameOffset, size_t t_offset)
{
    size_t enumRealOffset = t_offset - 4;

    auto constants = m_module->GetConstants();

    size_t enumValueEnd = m_relData->sh_addr + m_relData->sh_size;
    auto constEntry = constants->find(t_offset);
    if(constEntry != constants->cend())
    {
        enumValueEnd = (++constEntry)->first;
        if(enumValueEnd - enumRealOffset == sizeof(EnumPair))
        {
            // single value enum? This can't be true...
            // it's either broken offset or not worth dumping
            enumValueEnd = (++constEntry)->first;
        }
    }

    while(enumRealOffset + 4 < enumValueEnd)
    {
        EnumPair* enumValue = (EnumPair*)(m_image + enumRealOffset);

        if(enumValue->nameOffset <= 0)
        {
            break;
        }

        m_enums[m_image+t_nameOffset].insert(
                    std::make_pair(enumValue->value,
                    SanitizeEnumStr(m_image + enumValue->nameOffset))
        );

        enumRealOffset += sizeof(EnumPair);
    }
}

size_t EnumDumper::FindEnums()
{
    if(m_searchHint == -1)
    {
        return 0;
    }

    auto stringRefs = m_module->GetRefsToConstOffset(m_searchHint);
    if(!stringRefs->size())
    {
        return 0;
    }

    for(auto it = stringRefs->cbegin(); it != stringRefs->cend(); ++it)
    {
        size_t enumNameOff, enumValueOff = 0;
        if(GetEnumOffsetsByRef(*it, &enumNameOff, &enumValueOff))
        {
            ReadEnum(enumNameOff, enumValueOff);
        }
        else
        {
            continue;
        }
    }

    return m_enums.size();
}

const std::map<std::string, std::map<int32_t, std::string>> *EnumDumper::GetEnums()
{
    return &m_enums;
}

