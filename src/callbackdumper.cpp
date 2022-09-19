#include "callbackdumper.h"
#include <iostream>

CallbackDumper::CallbackDumper(ClientModule* t_module):
    DumperBase(t_module),
    m_postCallbackToAll(-1),
    m_postCallbackToUI(-1),
    m_postCallbackToPipe(-1),
    m_postCallbackToApp(-1)
{
    // ( bool? )( this*, int32_t cbID, char* cbuf, int32_t szBuf )
    m_postCallbackToAll = m_module->FindSignature(
                "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x2C\x8B\x7C\x24\x44\xC7\x44\x24\x00\x00\x00\x00\x00\x8B\x6C\x24\x48",
                "xxxxx????xx????xxxxxxxxxx?????xxxx"
    );
    if(m_postCallbackToAll == -1)
    {
        std::cout << "Could not find PostCallbackToAll offset" << std::endl;
    }

    // ( bool? )( this*, int32_t cbID, char* cbuf, int32_t szBuf )
    m_postCallbackToUI = m_module->FindSignature(
                "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x2C\x8B\x7C\x24\x44\xC7\x44\x24\x00\x00\x00\x00\x00\x8B\x6C\x24\x48",
                "xxxxx????xx????xxxxxxxxxx?????xxxx",
                m_postCallbackToAll + 1
    );
    if(m_postCallbackToUI == -1)
    {
        std::cout << "Could not find PostCallbackToUI offset" << std::endl;
    }
    // ( bool? )( this*, int32_t pipe(?), int32_t cbID, char* cbuf, int32_t szBuf )
    m_postCallbackToPipe = m_module->FindSignature(
                "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x2C\x8B\x6C\x24\x44\x8B\x74\x24\x48\x8B\x83\x00\x00\x00\x00",
                "xxxxx????xx????xxxxxxxxxxxxx????"
    );
    if(m_postCallbackToPipe == -1)
    {
        std::cout << "Could not find PostCallbackToPipe offset" << std::endl;
    }
    // ( bool? )( this*, int32_t appid/pid(?), int32_t cbID, char* cbuf, int32_t szBuf )
    m_postCallbackToApp = m_module->FindSignature(
                "\x55\x57\x56\x53\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x2C\x83\x7C\x24\x00\x00\x0F\x84\x00\x00\x00\x00",
                "xxxxx????xx????xxxxxx??xx????"
    );
    if(m_postCallbackToApp == -1)
    {
        std::cout << "Could not find PostCallbackToApp offset" << std::endl;
    }

    m_logCallback = m_module->FindSignature(
                "\x53\x31\xC0\xE8\x00\x00\x00\x00\x81\xC3\x00\x00\x00\x00\x83\xEC\x18\x8B\x54\x24\x24\x39\x93\x00\x00\x00\x00",
                "xxxx????xx????xxxxxxxxx????"
    );
    if(m_logCallback == -1)
    {
        std::cout << "Could not find LogCallback offset" << std::endl;
    }
}

size_t CallbackDumper::GetCBRefs(size_t t_offset, std::vector<size_t> *t_out)
{
    auto refs = m_module->GetRefsToFuncOffset(t_offset);
    if(refs)
    {
        t_out->insert(t_out->end(), refs->cbegin(), refs->cend());
        return refs->size();
    }
    return 0;
}

// one ugly function
bool CallbackDumper::GetCallbackInfoFromRef(size_t t_ref, size_t* t_cbID, size_t* t_cbSize)
{
    size_t funcSize, funcOffset = 0;
    if(!m_module->FindRefOrigin(t_ref, &funcOffset, &funcSize))
    {
        return false;
    }

    csh csHandle;
    cs_insn *ins;
    size_t count;

    bool result = false;

    if(cs_open(CS_ARCH_X86, CS_MODE_32, &csHandle) == CS_ERR_OK)
    {
        cs_option(csHandle, CS_OPT_SKIPDATA, CS_OPT_ON);
        cs_option(csHandle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(csHandle, (uint8_t*)(m_image + funcOffset), funcSize, funcOffset, 0, &ins);
        if(count > 0)
        {
            std::map<size_t,  cs_x86*> possibleArgs;
            std::map<x86_reg, cs_x86*> possibleRegConsts;

            size_t annoyance = m_module->FindStringLiteral("- callback definition not available\n");

            for(size_t i = 0; i < count; ++i)
            {
                cs_x86* x86 = &ins[i].detail->x86;

                if(ins[i].id == X86_INS_MOV                  &&
                   x86->operands[0].type == X86_OP_MEM       &&
                   x86->operands[0].mem.base == X86_REG_ESP
                )
                {
                    possibleArgs[x86->operands[0].mem.disp] = x86;
                }
                else if(ins[i].id == X86_INS_LEA &&
                        m_module->IsDataOffset(x86->operands[1].mem.disp + m_constBase)
                )
                {
                    // just not interested in this particular const
                    if(x86->operands[1].mem.disp + m_constBase != annoyance)
                    {
                        possibleRegConsts[x86->operands[0].reg] = x86;
                    }
                }
                else if(ins[i].id == X86_INS_CALL)
                {
                    if( x86->operands[0].type == X86_OP_IMM )
                    {
                        if(ins[i].address == t_ref)
                        {
                            if( ( x86->operands[0].imm == m_postCallbackToAll   ||
                                  x86->operands[0].imm == m_postCallbackToUI )  &&
                                  possibleArgs.size() > 3  // both have 4 args on the stack & same prototype
                            )
                            {
                                *t_cbID = possibleArgs[4]->operands[1].imm;
                                *t_cbSize = possibleArgs[12]->operands[1].imm;
                                result = true;
                            }
                            else if( ( x86->operands[0].imm == m_postCallbackToPipe   ||
                                       x86->operands[0].imm == m_postCallbackToApp )  &&
                                       possibleArgs.size() > 4  // both have 5 args on the stack & similar args layout
                            )
                            {
                                *t_cbID = possibleArgs[8]->operands[1].imm;
                                *t_cbSize = possibleArgs[16]->operands[1].imm;
                                result = true;
                            }
                            break;
                        }

                        if( x86->operands[0].imm == m_logCallback && possibleArgs.size() > 1 )
                        {
                            // looks like we found a wild LogCallback function
                            // it has 2 args: 1st is callback name offset passed by reg
                            //                2nd is callbackid

                            if(possibleArgs[0]->operands[1].type == X86_OP_REG )
                            {
                                x86_reg constReg = possibleArgs[0]->operands[1].reg;
                                int64_t cbid = possibleArgs[4]->operands[1].imm;

                                if( possibleRegConsts.find(constReg) != possibleRegConsts.cend() &&
                                    m_callbackNames.find(cbid) == m_callbackNames.cend() &&
                                    possibleRegConsts[constReg] != nullptr
                                )
                                {
                                    m_callbackNames[cbid] = m_constBase + possibleRegConsts[constReg]->operands[1].mem.disp;
                                }
                            }
                        }
                    }
                    possibleArgs.clear();
                    possibleRegConsts.clear();
                }
            }
            cs_free(ins, count);
        }
    }
    cs_close(&csHandle);

    return result;
}

CallbackDumper::~CallbackDumper()
{

}

size_t CallbackDumper::FindCallbacks()
{
    std::vector<size_t> refs;
    GetCBRefs(m_postCallbackToAll, &refs);
    GetCBRefs(m_postCallbackToApp, &refs);
    GetCBRefs(m_postCallbackToPipe, &refs);
    GetCBRefs(m_postCallbackToUI, &refs);

    if(!refs.size())
    {
        return 0;
    }

    for(auto it = refs.cbegin(); it != refs.cend(); ++it)
    {
        size_t cbID, cbSize = 0;
        if(GetCallbackInfoFromRef(*it, &cbID, &cbSize))
        {
            if(m_callbackNames.find(cbID) != m_callbackNames.cend())
            {
                m_callbacks[cbID].m_name = m_image + m_callbackNames[cbID];
            }
            else
            {
                m_callbacks[cbID].m_name = "Unknown";
            }

            m_callbacks[cbID].m_callbackID = cbID;
            m_callbacks[cbID].m_callbackSize = cbSize;
            m_callbacks[cbID].m_postedAt.push_back(*it);
        }
    }

    return m_callbacks.size();
}

std::map<int64_t, CallbackInfo> *CallbackDumper::GetCallbacks()
{
    return &m_callbacks;
}
