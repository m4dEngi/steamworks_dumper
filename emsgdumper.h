#ifndef EMSGDUMPER_H
#define EMSGDUMPER_H

#include "dumperbase.h"

#pragma pack(push,1)
struct EMsgInfo
{
    int32_t  m_emsg;
    uint32_t m_flags;
    int32_t  m_serverType;
    int32_t  m_unk1;
    int32_t  m_descriptorOffset;
    int32_t  m_unk2;
};
#pragma pack(pop)

struct EMsg
{
    int32_t  m_emsg;
    int32_t  m_serverType;
    uint32_t m_flags;
    std::string m_descriptor;
};

class EMsgDumper : public DumperBase
{
public:
    EMsgDumper(ClientModule* t_module);
    ~EMsgDumper();

    size_t FindEMsgInfos();
    std::map<int32_t, EMsg>* GetEMsgList();

private:
    EMsgDumper();

    size_t m_emsgListOffset;
    std::map<int32_t, EMsg> m_emsgList;
};

#endif // EMSGDUMPER_H
