#ifndef RANDOMSTACK_H
#define RANDOMSTACK_H

#include <map>
#include <capstone/capstone.h>

// inaccurate function local stack tracker
// only somewhat suitable for approximating local stack state
// for cdecl style functions
class RandomAccessStack
{
public:
    RandomAccessStack(int32_t t_offset = 0);
    ~RandomAccessStack();

    /**
     * @brief Updates the stack based on instruction passed as t_op
     * @param t_op current cs_insn
     */
    void Update(cs_insn* t_op);

    int32_t GetOffset();

    /**
     * @brief Gets the size of stack
     * @return Size of stack, from bottom to top(m_offset), not counting whatever is above
     */
    size_t Size();

    void Push(cs_x86* t_value);
    cs_x86*& Pop();

    void Add(int32_t t_disp);
    void Sub(int32_t t_disp);

    cs_x86*& operator[](int32_t t_offset);

private:
    int32_t m_offset;
    int32_t m_offsetBackup;
    std::map<int32_t, cs_x86*> m_stack;
    std::map<x86_reg, cs_x86*> m_regMod;
};

#endif // RANDOMSTACK_H
