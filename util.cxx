#include <string>
#include <cxxabi.h>
#include "util.h"

std::string escape_str(std::string& in)
{
    static std::string allowed("ABCDEFGHIJKLMNOPQRSTUVWXYZ0987654321_abcdefghijklmnopqrstuvwxyz");
    std::string out;

    for(std::string::iterator it = in.begin();
                              it != in.end();
                            ++it
    )
    {
        if(allowed.find(*it) != std::string::npos)
        {
            out += *it;
        }
        else
        {
            if(it+1 != in.end() && *it == ' ')
            {
                *(it+1) = toupper(*(it+1));
            }
        }
    }
    return out;
}

std::string demangle(const char* t_name)
{
    int status = -4;

    char* ret = abi::__cxa_demangle(t_name, NULL, NULL, &status);
    const char* demangled = (status == 0) ? ret : t_name;
    std::string out(demangled);
    std::free(ret);

    return out;
}
