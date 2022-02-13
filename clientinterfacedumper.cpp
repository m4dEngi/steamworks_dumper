#include "clientinterfacedumper.h"
#include <iostream>
#include <set>

ClientInterfaceDumper::ClientInterfaceDumper(ClientModule *t_module):
    DumperBase(t_module)
{
    m_relRoShdr = t_module->GetSectionHeader(".data.rel.ro");
    m_txtShdr = t_module->GetSectionHeader(".text");
    m_sendSerializedFnOffset = t_module->FindSignature(
                "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x81\xEC\x00\x00\x00\x00\x65\x8B\x15\x00\x00\x00\x00\x89\x94\x24\x00\x00\x00\x00\x31\xD2\x8B\xB4\x24\x00\x00\x00\x00",
                "xxxxx????xx????xx????xxx????xxx????xxxxx????"
    );
    m_roShdr = t_module->GetSectionHeader(".rodata");
}

ClientInterfaceDumper::~ClientInterfaceDumper()
{

}

bool ClientInterfaceDumper::GetSerializedFuncInfo(std::string t_iname, size_t t_offset, size_t* t_argc, std::string* t_name)
{
    size_t funcSize = m_module->GetFunctionSize(t_offset);
    if(funcSize == -1)
    {
        return false;
    }

    csh csHandle;
    cs_insn *ins;
    size_t count;
    size_t stackAdj = 0;
    std::set<int32_t> args;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) == CS_ERR_OK)
    {
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

        std::vector<size_t> possibleSerializeArgs;

        count = cs_disasm(csHandle, (uint8_t*)(m_image + t_offset), funcSize, t_offset, 0, &ins);
        if(count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                cs_x86* x86 = &ins[i].detail->x86;

                if(ins[i].id == X86_INS_SUB)
                {
                    if(x86->operands[0].reg == X86_REG_ESP)
                    {
                        stackAdj = x86->operands[1].imm;
                    }
                }

                if(ins[i].id == X86_INS_LEA
                   || ins[i].id == X86_INS_MOV
                  )
                {
                    if(x86->operands[1].type == X86_OP_MEM)
                    {
                        if(x86->operands[1].mem.base == X86_REG_EBX)
                        {
                            size_t argOffset = m_constBase + x86->disp;
                            if(m_roShdr->sh_addr < argOffset
                               && argOffset < m_relRoShdr->sh_addr + m_roShdr->sh_size
                              )
                            {
                                possibleSerializeArgs.push_back(argOffset);
                            }
                        }
                        else if( x86->operands[1].mem.base == X86_REG_ESP
                                 && x86->disp > stackAdj
                        )
                        {
                            // no idea how many times args could be addressed
                            // so just store stack offsets above stack
                            // reserve for local vars from function prologue in a set
                            // that should give us approximate count of function args
                            args.insert(x86->disp);
                        }
                    }
                }

                if(ins[i].id == X86_INS_CALL)
                {
                    if(x86->operands[0].imm == m_sendSerializedFnOffset)
                    {
                        if(possibleSerializeArgs.size() == 2)
                        {
                            if(t_iname.find(m_image + possibleSerializeArgs[0]) != std::string_view::npos)
                            {
                                *t_name = (const char*)(m_image + possibleSerializeArgs[1]);
                            }
                            else
                            {
                                *t_name = (const char*)(m_image + possibleSerializeArgs[0]);
                            }
                        }
                    }
                    else
                    {
                        possibleSerializeArgs.clear();
                    }
                }
            }
            cs_free(ins, count);
        }
    }
    cs_close(&csHandle);

    *t_argc = args.size();

    return true;
}

void ClientInterfaceDumper::ParseVTable(std::string t_typeName, size_t t_vtoffset)
{
    int32_t* vtFuncs = (int32_t*)(m_image + t_vtoffset);
    int vmIdx = 0;
    while(vtFuncs[vmIdx] != 0
          && vtFuncs[vmIdx] <= m_txtShdr->sh_addr + m_txtShdr->sh_size
          && vtFuncs[vmIdx] > m_txtShdr->sh_addr
         )
    {
        std::string fName;
        size_t fArgc = 0;
        InterfaceFunction func;

        if(!GetSerializedFuncInfo(t_typeName, vtFuncs[vmIdx], &fArgc, &fName))
        {
            fName = "Unknown_" + std::to_string(vtFuncs[vmIdx]);
        }

        func.m_addr = vtFuncs[vmIdx];
        func.m_argc = fArgc;
        func.m_name = fName;
        m_interfaces[t_typeName].m_functions.push_back(func);

        ++vmIdx;
    }
}

size_t ClientInterfaceDumper::FindClientInterfaces()
{
    std::vector<size_t> vtInfos;
    if(!m_module->GetVTTypes(&vtInfos))
    {
        return -1;
    }

    if(!m_relRoShdr)
    {
        return -1;
    }

    if(m_sendSerializedFnOffset == -1)
    {
        return -1;
    }

    auto consts = m_module->GetConstants();
    auto relConstBegin = consts->lower_bound(m_relRoShdr->sh_addr);
    auto relConstEnd = consts->upper_bound(m_relRoShdr->sh_addr + m_relRoShdr->sh_size);

    for(auto it = vtInfos.cbegin(); it != vtInfos.cend(); ++it)
    {
        size_t strOffset = *(int32_t*)(m_image + *it + 4);
        std::string_view vtName(m_image + strOffset);
        if( vtName.find("IClient") != std::string_view::npos
            && vtName.find("Map") != std::string_view::npos
            && vtName.find("Base") == std::string_view::npos
          )
        {
            for(auto cit = relConstBegin; cit != relConstEnd; ++cit)
            {
                if(*(int32_t*)(m_image + cit->first - 4) == *it)
                {
                    std::string iname(vtName.substr(vtName.find("IClient")));
                    m_interfaces[iname].m_foundAt = cit->first;

                    ParseVTable(iname, cit->first);
                }
            }
        }
    }

    return m_interfaces.size();
}

const std::map<std::string, ClientInterface>* ClientInterfaceDumper::GetInterfaces()
{
    return &m_interfaces;
}
