#ifndef UTIL_H
#define UTIL_H

std::string escape_str(std::string& in);
std::string demangle(const char* t_name);

template<typename T>
T int_byte_swap(T num)
{
    return  (num & 0xff000000) >> 24 |
            (num & 0x00ff0000) >> 8  |
            (num & 0x0000ff00) << 8  |
            (num & 0x000000ff) << 24 ;
}

template<typename T>
void swap_uint32_struct(T* header)
{
    uint32_t* headarr = (uint32_t*)header;

    for(int i = 0; i < sizeof(T) / sizeof(uint32_t); ++i)
    {
        headarr[i] = int_byte_swap<uint32_t>(headarr[i]);
    }
}


#endif // UTIL_H
