#ifndef ENUMDUMPER_H
#define ENUMDUMPER_H
#include <map>
#include "dumperbase.h"

#pragma pack(push,1)
struct EnumPair
{
    int32_t value;
    int32_t nameOffset;
};
#pragma pack(pop)


class EnumDumper: public DumperBase
{
public:
    EnumDumper(ClientModule* t_module);
    ~EnumDumper();

    size_t FindEnums();
    const std::map<std::string,
                   std::map<int32_t, std::string>
                  >*  GetEnums();

private:
    EnumDumper();

    size_t m_searchHint;
    const Elf32_Shdr* m_relData;

    //ClientModule* m_module;
    void ReadEnum(size_t t_nameOffset, size_t t_offset);
    std::string SanitizeEnumStr(const std::string_view t_enumStr);
    bool GetEnumOffsetsByRef(size_t t_ref, size_t* t_name, size_t* t_value);

    std::map<std::string, std::map<int32_t, std::string>> m_enums;
};

#endif // ENUMDUMPER_H
