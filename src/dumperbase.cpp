#include "dumperbase.h"

DumperBase::DumperBase(ClientModule *t_module):
    m_module(t_module)
{
    const Elf32_Shdr* pltGot = t_module->GetSectionHeader(".got.plt");
    if(pltGot)
    {
        m_constBase = pltGot->sh_addr;
    }

    m_image = t_module->GetImageBytes();
}

DumperBase::~DumperBase()
{

}
