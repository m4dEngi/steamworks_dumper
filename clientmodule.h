#ifndef CLIENTMODULE_H
#define CLIENTMODULE_H

#include <capstone/capstone.h>
#include <map>
#include <vector>
#include "moduleimage.h"

class ClientModule
{
public:
    ClientModule(std::string_view t_path);
    ~ClientModule();

    bool Load();
    bool Parse();

    const char* GetImageBytes();
    const Elf32_Sym* GetSymbol(std::string_view t_name);
    const size_t FindSymbols(std::string_view t_name, std::vector<const Elf32_Sym*>* t_out);
    const Elf32_Shdr* GetSectionHeader(std::string_view t_name);
    const std::map<size_t, std::vector<size_t>>* GetFunctions();
    const std::map<size_t, std::vector<size_t>>* GetConstants();

    const std::vector<size_t>* GetRefsToConstOffset(size_t t_offset);
    const std::vector<size_t>* GetRefsToFuncOffset(size_t t_offset);
    const std::vector<size_t>* GetRefsToSymbol(size_t t_offset);
    size_t GetVTTypes(std::vector<size_t>* t_out);

    size_t GetFunctionSize(size_t t_offset);
    size_t FindSignature(const char* t_sign, const char* t_mask, size_t t_searchBaseOffset = -1);
    size_t FindStringLiteral(std::string_view t_string);;
    bool FindRefOrigin(size_t t_offset, size_t* t_funcOffset, size_t* t_funcSize);

private:
    ClientModule();
    ClientModule(const ClientModule&);
    ClientModule& operator=(const ClientModule&);

    ModuleImage m_image;
    const char* m_imageData;

    std::map<size_t, size_t> m_dataSections;
    bool IsDataOffset(size_t t_offset);
    void FindExtSymRefs();

    Elf32_Sym* m_extSyms;
    size_t m_numExtSyms;
    const char* m_extStrTab;

    // map of local function offsets
    std::map<size_t, std::vector<size_t>> m_functions;
    // a helper set of image offsets of possible constants
    std::map<size_t, std::vector<size_t>> m_suspectConstants;
    // imports refs
    std::map<size_t, std::vector<size_t>> m_extRefs;
};

#endif // CLIENTMODULE_H
