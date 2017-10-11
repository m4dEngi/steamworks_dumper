#ifndef MACHFILE_H
#define MACHFILE_H

#include <vector>
#include <map>

#include "stuff.h"

class symbol
{
public:
	symbol(nlist* t_nlvalue, char* t_strvalue)
	{
		nvalue = t_nlvalue;
		strval = t_strvalue;
	}
	
	nlist* nvalue;
	char* strval;
};

// just a helper class to make reading memory easier
class mach_image
{
public:
	mach_image();
	mach_image(unsigned char* t_image, size_t t_image_size);

	~mach_image();

	template<typename T>
	T* ptr_to_struct()
	{
		T* mapped = (T*)(m_image_bytes + m_offset);
		m_offset += sizeof(T);
		return mapped;
	}
	
	template<typename T>
	T* ptr_to_struct(size_t t_struct_size)
	{
		T* mapped = (T*)(m_image_bytes + m_offset);
		m_offset += t_struct_size;
		return mapped;
	}
	
	template<typename T>
	T* ptr_peek_struct()
	{
		T* mapped = (T*)(m_image_bytes + m_offset);
		return mapped;
	}
	
	template<typename T>
	T* ptr_peek_struct(size_t t_offset)
	{
		T* mapped = (T*)(m_image_bytes + t_offset);
		return mapped;
	}
	
	void load_from_fstream(std::ifstream& in, size_t t_image_size);
	void seek(size_t t_offset);
	void seek(size_t t_offset, std::ios_base::seekdir t_dir);
	size_t tellg();
	symbol* get_symbol_at_offset(size_t offset);
	section* get_section_by_name(const char* t_segment_name, const char* t_section_name);
	bool is_valid_string_const(size_t t_cscaddr);
	bool is_valid_function_address(size_t t_funcaddr);
	void find_symbols_by_name(const char* t_name_part, std::vector<symbol*>& t_matches_out);

private:
	void reset();
	void parse_image();
	
	std::vector<segment_command*> m_segments;
	std::vector<section*> m_sections;
	std::map<uint32_t, symbol*> m_symbols;
	char* m_strings;
		
	unsigned char* m_image_bytes;
	size_t m_offset;
	size_t m_image_size;
};

#endif // MACHFILE_H
