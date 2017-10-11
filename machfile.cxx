#include <fstream>
#include <cstring>

#include "machfile.h"


// just a helper class to make reading memory easier
mach_image::mach_image()
{
	m_image_bytes = nullptr;
	m_image_size = 0;
}

mach_image::mach_image(unsigned char* t_image, size_t t_image_size)
{
	m_image_bytes = t_image;
	m_image_size = t_image_size;
	
	parse_image();
}

mach_image::~mach_image()
{
	this->reset();
}

void mach_image::load_from_fstream(std::ifstream& in, size_t t_image_size)
{
	this->reset();
	
	m_image_bytes = new unsigned char[t_image_size];
	in.read((char*)m_image_bytes, t_image_size);
	m_image_size = t_image_size;
	m_offset = 0;
	
	parse_image();
}
	
void mach_image::seek(size_t t_offset)
{
	if(t_offset < m_image_size)
	{
		m_offset = t_offset;
	}
}
	
void mach_image::seek(size_t t_offset, std::ios_base::seekdir t_dir)
{
	switch(t_dir)
	{
		case std::ios_base::beg:
			{
				if(t_offset < m_image_size)
				{
					m_offset = t_offset;
				}
				break;
			}
		case std::ios_base::cur:
			{
				if((m_image_size - m_offset) > t_offset)
				{
					m_offset += t_offset;
				}
				break;
			}
		case std::ios_base::end:
			{
				if(t_offset < m_image_size)
				{
					m_offset = m_image_size - t_offset;
				}
				break;
			}
		default:
			break;
	}
}
	
size_t mach_image::tellg()
{
	return m_offset;
}
	
symbol* mach_image::get_symbol_at_offset(size_t offset)
{
	auto nl = m_symbols.find(offset);
	if(nl != m_symbols.end())
	{
		return (*nl).second;
	}
	return nullptr;
}
	
section* mach_image::get_section_by_name(const char* t_segment_name, const char* t_section_name)
{
	for(auto it = m_sections.begin(); it != m_sections.end(); ++it)
	{
		if(strcmp((*it)->segname, t_segment_name) == 0)
		{
			if(strcmp((*it)->sectname, t_section_name) == 0)
			{
				return *it;
			}
		}
	}
	return nullptr;
}
	
bool mach_image::is_valid_string_const(size_t t_cscaddr)
{
	static section* cssection = get_section_by_name("__TEXT", "__cstring");
	static size_t section_end_offset = cssection->offset + cssection->size;

	if(t_cscaddr > cssection->offset && t_cscaddr < section_end_offset && t_cscaddr > 0)
	{
		return true;
	}
	
	return false;
}
	
bool mach_image::is_valid_function_address(size_t t_funcaddr)
{
	static section* code_section = get_section_by_name("__TEXT", "__text");
	static size_t section_end_offset = code_section->offset + code_section->size;

	if(t_funcaddr > code_section->offset && t_funcaddr < section_end_offset && t_funcaddr > 0)
	{
		return true;
	}

	return false;
}
	
void mach_image::find_symbols_by_name(const char* t_name_part, std::vector<symbol*>& t_matches_out)
{
	for(auto it = m_symbols.begin(); it != m_symbols.end(); ++it)
	{
		if(strstr((*it).second->strval, t_name_part) != nullptr)
		{
			t_matches_out.push_back((*it).second);
		}
	}
}

void mach_image::reset()
{
	if(m_image_bytes != nullptr)
	{
		m_offset = 0;
		m_image_size = 0;
		delete [] m_image_bytes;
	}
		
	m_sections.clear();
	m_segments.clear();
	m_strings = nullptr;
	
	for(auto it=m_symbols.begin(); it!=m_symbols.end(); ++it)
	{
		delete it->second;
	}
	m_symbols.clear();
}
	
void mach_image::parse_image()
{
	mach_header* header = ptr_to_struct<mach_header>();
	
	for(int i=0; i<header->ncmds; ++i)
	{
		load_command* lcmd = ptr_peek_struct<load_command>();
		
		switch(lcmd->cmd)
		{
			case LC_SEGMENT:
				{
					segment_command* seg = ptr_to_struct<segment_command>();
					m_segments.push_back(seg);
						
					for(int i=0; i<seg->nsects; ++i)
					{
						section* sect = ptr_to_struct<section>();
						m_sections.push_back(sect);
					}
					break;
				}
			case LC_SYMTAB:
				{
					// TODO:
					// change m_symbols to multimap
					//
					symtab_command* sym = ptr_to_struct<symtab_command>();
					m_strings = ptr_peek_struct<char>(sym->stroff);
					nlist* syms = ptr_peek_struct<nlist>(sym->symoff);

					for(int i=0; i<sym->nsyms; ++i)
					{
						if(syms[i].n_value != 0 && syms[i].n_un.n_strx != 0 && !(syms[i].n_type & N_GSYM))
						{
							symbol* symb = new symbol(&syms[i], m_strings+syms[i].n_un.n_strx );
							auto inres = m_symbols.insert(std::pair<uint32_t,symbol*>(syms[i].n_value, symb));
							if(inres.second == false)
							{
								delete symb;
							}
								
						}
					}
					
					seek(sym->cmdsize - sizeof(symtab_command), std::ios_base::cur);
					break;
				}
			default:
				seek(lcmd->cmdsize, std::ios_base::cur);
				break;
		}
		
	}
		
	seek(0);		
}
