#include "dumperbase.h"

DumperBase::DumperBase(ClientModule *t_module):
    m_module(t_module)
{
    const Elf32_Shdr* pltGot = t_module->GetSectionHeader(".got");
    if(pltGot)
    {
        m_constBase = pltGot->sh_addr;
    }

    m_image = t_module->GetImageBytes();
}

DumperBase::~DumperBase()
{

}

// just a little helper function that only makes sense for
// immediate function args passed on stack
bool DumperBase::GetImmStackValue(cs_x86 *t_ins, int64_t *t_out)
{
    if(t_ins->op_count == 1)                        // for PUSH IMM
    {
        if(t_ins->operands[0].type == X86_OP_IMM)
        {
            *t_out = t_ins->operands[0].imm;
            return true;
        }
    }
    else if(t_ins->op_count == 2)
    {
        if(t_ins->operands[1].type == X86_OP_IMM)  // for MOV [ESP+DISP], IMM shenanigans
        {
            *t_out = t_ins->operands[1].imm;
            return true;
        }
    }

    return false;
}

