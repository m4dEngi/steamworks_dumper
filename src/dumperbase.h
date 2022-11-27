#ifndef DUMPERBASE_H
#define DUMPERBASE_H
#include "clientmodule.h"

class DumperBase
{
public:
    DumperBase(ClientModule* t_module);
    virtual ~DumperBase();

protected:
    ClientModule* m_module;
    size_t m_constBase;
    const char* m_image;

    bool GetImmStackValue(cs_x86 *t_ins, int64_t *t_out);

private:
    DumperBase();

};

#endif // DUMPERBASE_H
