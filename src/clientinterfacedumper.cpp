#include "clientinterfacedumper.h"
#include "randomstack.h"
#include <iostream>
#include <set>

ClientInterfaceDumper::ClientInterfaceDumper(ClientModule *t_module):
    DumperBase(t_module),
    m_relRoShdr(nullptr),
    m_txtShdr(nullptr),
    m_roShdr(nullptr),
    m_sendSerializedFnOffset(-1)
{
    m_relRoShdr = t_module->GetSectionHeader(".data.rel.ro");
    m_relRoLocalShdr = t_module->GetSectionHeader(".data.rel.ro.local");
    m_roShdr = t_module->GetSectionHeader(".rodata");
    m_txtShdr = t_module->GetSectionHeader(".text");

    m_sendSerializedFnOffset = t_module->FindSignature(
        "\x55\x89\xE5\x57\x56\xE8\x00\x00\x00\x00\x81\xC6\x00\x00\x00\x00\x53\x81\xEC\x00\x00\x00\x00\x8B\x45\x08\x89\x85\x00\x00\x00\x00\x8B\x45\x10\x8B\xBE\x00\x00\x00\x00\x89\x85\x00\x00\x00\x00",
        "xxxxxx????xx????xxx????xxxxx????xxxxx????xx????"
    );

    if(m_sendSerializedFnOffset == -1)
    {
        std::cout << "Could not find SendSerializedFunction offset!" << std::endl;
    }
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
    std::set<int32_t> args;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) == CS_ERR_OK)
    {
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

        RandomAccessStack ras;

        count = cs_disasm(csHandle, (uint8_t*)(m_image + t_offset), funcSize, t_offset, 0, &ins);
        if(count > 0)
        {
            for (size_t i = 0; i < count; i++)
            {
                cs_x86* x86 = &ins[i].detail->x86;

                ras.Update(&ins[i]);

                switch(ins[i].id)
                {
                    case X86_INS_PUSH:
                    case X86_INS_FLD:
                    {
                        if( x86->operands[0].mem.base == X86_REG_EBP
                            && x86->disp > 0
                        )
                        {
                            args.insert(x86->disp);
                        }
                        break;
                    }
                    case X86_INS_LEA:
                    case X86_INS_MOV:
                    {
                        if(x86->operands[1].type == X86_OP_MEM)
                        {
                            if( x86->operands[1].mem.base == X86_REG_EBP
                                     && x86->disp > 0
                            )
                            {
                                // no idea how many times args could be addressed
                                // so just store stack offsets above stack
                                // reserve for local vars from function prologue in a set
                                // that should give us approximate count of function args
                                args.insert(x86->disp);
                            }
                        }
                        break;
                    }
                    case X86_INS_CALL:
                    {
                        if(x86->operands[0].imm == m_sendSerializedFnOffset)
                        {
                            if(ras.Size() > 4)
                            {
                                int32_t stackOffset = ras.GetOffset();
                                size_t nameOffset = m_constBase + ras[stackOffset - 16]->disp;
                                if(m_module->IsDataOffset(nameOffset))
                                {
                                    *t_name = (const char*)(m_image + nameOffset);
                                }
                            }
                        }

                        break;
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
    while(   vtFuncs[vmIdx] != 0
          && vtFuncs[vmIdx] <= m_txtShdr->sh_addr + m_txtShdr->sh_size
          && vtFuncs[vmIdx] > m_txtShdr->sh_addr
         )
    {
        std::string fName;
        size_t fArgc = 0;
        InterfaceFunction func;

        if(!GetSerializedFuncInfo(t_typeName, vtFuncs[vmIdx], &fArgc, &fName) || fName.empty())
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
    if(    !m_module->GetVTTypes(&vtInfos)
        || !m_relRoShdr
        || m_sendSerializedFnOffset == -1
      )
    {
        return 0;
    }

    auto consts = m_module->GetConstants();

    for(auto it = vtInfos.cbegin(); it != vtInfos.cend(); ++it)
    {
        size_t strOffset = *(int32_t*)(m_image + *it + 4);
        std::string_view vtName(m_image + strOffset);
        if(    vtName.find("IClient") != std::string_view::npos
            && vtName.find("Map") != std::string_view::npos
            && vtName.find("Base") == std::string_view::npos
          )
        {
            for(auto cit = consts->cbegin(); cit != consts->cend(); ++cit)
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
