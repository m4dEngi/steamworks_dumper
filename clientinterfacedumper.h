#ifndef CLIENTINTERFACEDUMPER_H
#define CLIENTINTERFACEDUMPER_H
#include "dumperbase.h"

struct InterfaceFunction
{
    std::string m_name;
    int m_argc;
    size_t m_addr;
};

struct ClientInterface
{
    size_t m_foundAt;
    std::vector<InterfaceFunction> m_functions;
};

class ClientInterfaceDumper: public DumperBase
{
public:
    ClientInterfaceDumper(ClientModule* t_module);
    ~ClientInterfaceDumper();

    size_t FindClientInterfaces();
    const std::map<std::string, ClientInterface>* GetInterfaces();

private:
    ClientInterfaceDumper();

    void ParseVTable(std::string t_typeName, size_t t_vtoffset);
    bool GetSerializedFuncInfo(std::string t_iname, size_t t_offset, size_t* t_argc, std::string* t_name);

    const Elf32_Shdr* m_relRoShdr;
    const Elf32_Shdr* m_txtShdr;
    const Elf32_Shdr* m_roShdr;

    size_t m_sendSerializedFnOffset;

    std::map<std::string, ClientInterface> m_interfaces;
};

#endif // CLIENTINTERFACEDUMPER_H
