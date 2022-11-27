#include <iostream>
#include "emsgdumper.h"

EMsgDumper::EMsgDumper(ClientModule* t_module):
    DumperBase(t_module),
    m_emsgListOffset(-1)
{
    size_t emsgHint = m_module->FindSignature("\x8D\x90\x00\x00\x00\x00\x8B\x44\x24\x04\x89\x10\x8B\x44\x24\x08\xC7\x00\x00\x00\x00\x00",
                                           "xx????xxxxxxxxxxxx????");

    if(emsgHint == -1)
    {
        std::cout << "Could not find EMsgInfo offset!" << std::endl;
    }
    else
    {
        m_emsgListOffset = m_constBase + *(int*)(m_image + emsgHint + 2);
    }
}

EMsgDumper::~EMsgDumper()
{

}

size_t EMsgDumper::FindEMsgInfos()
{
    if(m_emsgListOffset == -1)
    {
        return 0;
    }

    auto consts = m_module->GetConstants();
    auto constEntry = consts->find(m_emsgListOffset);
    if(constEntry == consts->cend())
    {
        return 0;
    }

    size_t msgListEndOffset = std::next(constEntry)->first;
    size_t emsgOffset = m_emsgListOffset;

    const Elf32_Shdr* hData = m_module->GetSectionHeader(".rodata");

    while(emsgOffset < msgListEndOffset)
    {
        EMsgInfo* emsg = (EMsgInfo*)(m_image + emsgOffset);

        if( emsg->m_descriptorOffset < hData->sh_addr
            || (hData->sh_addr + hData->sh_size) < emsg->m_descriptorOffset
          )
        {
            break;
        }

        m_emsgList[emsg->m_emsg].m_descriptor = m_image + emsg->m_descriptorOffset;
        m_emsgList[emsg->m_emsg].m_emsg = emsg->m_emsg;
        m_emsgList[emsg->m_emsg].m_flags = emsg->m_flags;
        m_emsgList[emsg->m_emsg].m_serverType = emsg->m_serverType;

        emsgOffset += sizeof(EMsgInfo);
    }

    return m_emsgList.size();
}

std::map<int32_t, EMsg>* EMsgDumper::GetEMsgList()
{
    return &m_emsgList;
}
