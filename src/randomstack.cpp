#include "randomstack.h"

RandomAccessStack::RandomAccessStack(int32_t t_offset)
{
    m_offset       = t_offset;
    m_offsetBackup = t_offset; // assuming that EBP is used as intended
}

RandomAccessStack::~RandomAccessStack()
{
}

int32_t RandomAccessStack::GetOffset()
{
    return m_offset;
}

size_t RandomAccessStack::Size()
{
    return std::distance(m_stack.begin(), m_stack.upper_bound(m_offset));
}

void RandomAccessStack::Push(cs_x86 *t_value)
{
    m_offset += 4;
    m_stack[m_offset] = t_value;
}

cs_x86 *&RandomAccessStack::Pop()
{
    int32_t tOffset = m_offset;
    m_offset -= 4;
    return m_stack[tOffset];
}

void RandomAccessStack::Add(int32_t t_disp)
{
    m_offset += t_disp;
}

void RandomAccessStack::Sub(int32_t t_disp)
{
    m_offset -= t_disp;
}

cs_x86 *&RandomAccessStack::operator[](int32_t t_offset)
{
    return m_stack[t_offset];
}


//
//  lots of assumptions and misconceptions here
//
// 1st we assume that EBP holds the stack frame snapshot
//      which is recommended, but not guaranteed
//  2nd just a limited and inaccurate stack tracking is done,
//      not taking into account all possible ways to modify stack
//  3rd branching is ignored
//  4th and the most important factor is that
//      author of this code is uneducated idiot, so keep that in mind
//      if you decide to reuse it anywhere
//
void RandomAccessStack::Update(cs_insn* t_op)
{
    if(t_op->detail == nullptr)
    {
        return;
    }

    cs_x86* x86 = &t_op->detail->x86;

    // cache registry 'state'
    if(    x86->op_count > 1
        && x86->operands[0].type == X86_OP_REG
        && x86->operands[0].reg  != X86_REG_ESP
      )
    {
        m_regMod[x86->operands[0].reg] = x86;
    }

    switch (t_op->id)
    {
        case X86_INS_PUSH:
        {
            // if we have cached registry state
            // push it on 'stack' instead
            if(    x86->operands[0].type == X86_OP_REG
                && m_regMod.find(x86->operands[0].reg) != m_regMod.cend()
              )
            {
                Push(m_regMod[x86->operands[0].reg]);
            }
            else
            {
                Push(x86);
            }
            break;
        }
        case X86_INS_SUB:
        {
            if(x86->operands[0].reg != X86_REG_ESP)
            {
                break;
            }
            Sub(x86->operands[1].imm);
            break;
        }
        case X86_INS_ADD:
        {
            if(x86->operands[0].reg != X86_REG_ESP)
            {
                break;
            }
            Add(x86->operands[1].imm);
            break;
        }
        case X86_INS_POP:
        {
            Pop();
            break;
        }
        case X86_INS_MOV:
        {
            if(   x86->operands[0].type == X86_OP_MEM
               && (    x86->operands[0].mem.base == X86_REG_ESP
                    || x86->operands[0].mem.base == X86_REG_EBP
                  )
              )
            {
                int32_t dispBase = m_offset;
                if (x86->operands[0].mem.base == X86_REG_EBP)
                {
                    dispBase = m_offsetBackup;
                }
                if(    x86->operands[1].type == X86_OP_REG
                    && m_regMod.find(x86->operands[1].reg) != m_regMod.cend()
                  )
                {
                    m_stack[dispBase + x86->operands[0].mem.disp] = m_regMod[x86->operands[1].reg];
                }
                else
                {
                    m_stack[dispBase + x86->operands[0].mem.disp] = x86;
                }
            }
            break;
        }
    }
}
