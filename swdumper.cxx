#include <iostream>
#include <fstream>
#include <stdio.h>
#include <map>
#include <cstring>
#include <vector>

#include "stuff.h"
#include "util.h"
#include "machfile.h"


mach_image image;
size_t binary_size;

struct steam_enum_pair
{
	int32_t value;
	int32_t descriptor_offset;
};

void save_vtable(const char* t_out_path, const char* t_vtname, std::vector<symbol*>& t_vtfuncs)
{
	size_t path_len = strlen(t_out_path)+strlen(t_vtname)+16;
	char* file_path_out = new char[path_len];
	snprintf(file_path_out, path_len, "%s/%s.h", t_out_path, t_vtname);
	
	std::ofstream ofs(file_path_out, std::ios_base::out);
	
	ofs << "class " << t_vtname << std::endl << "{" << std::endl << "public:" << std::endl;
	
	int unknowncount = 0;
	
	for(auto it=t_vtfuncs.begin(); it!=t_vtfuncs.end(); ++it)
	{
		if((*it) != nullptr) 
		{
			std::string demangled = demangle((*it)->strval+1); 
			ofs << "    virtual unknown_ret " << demangled.substr(demangled.find("::")+2) << " = 0;" << std::endl;
		}
		else
		{
			ofs << "    virtual unknown_ret unknownwnFunction" << unknowncount << "() = 0;" << std::endl;
			++unknowncount;
		}
	}
	
	ofs << "};" << std::endl;
	
	delete [] file_path_out;
}

void save_enum(const char* t_out_path, const char* t_enum_name, std::map<int32_t,char*> t_enum)
{
	size_t path_len = strlen(t_out_path)+strlen(t_enum_name)+16;
	char* file_path_out = new char[path_len];
	snprintf(file_path_out, path_len, "%s/%s.h", t_out_path, t_enum_name);
	
	std::ofstream ofs(file_path_out, std::ios_base::out);
	int32_t prev_value = 0;
	
	ofs << "typedef enum " << t_enum_name << std::endl << "{" << std::endl;
	
	for(auto it=t_enum.begin(); it!=t_enum.end(); ++it)
	{
		std::string name_escaped((*it).second);
		name_escaped = escape_str(name_escaped);
		name_escaped[0] = toupper(name_escaped[0]);
		ofs << "    ";
		if(name_escaped.find("k_E") == std::string::npos)
		{
			ofs << "k_" << t_enum_name;
		}
		ofs << name_escaped;
		
		if((*it).first - prev_value != 1 || it == t_enum.begin())
		{
			ofs << " = " << (*it).first;
		}
		
		ofs << ", // " << (*it).second << std::endl;
		
		prev_value = (*it).first;
	}
	
	ofs << "} " << t_enum_name << ";" << std::endl;
	
	delete [] file_path_out;
}

void save_steam_vtables(mach_image& t_image, const char* out_path)
{
	std::vector<symbol*> vtables;
	t_image.find_symbols_by_name("__ZTV", vtables);
	std::cout << vtables.size() << " vtables found" << std::endl;
	for(auto it=vtables.begin(); it!=vtables.end(); ++it)
	{
		if(strstr((*it)->strval, "IClient") || strstr((*it)->strval, "CAdapterSteam") || strstr((*it)->strval, "CSteam"))
		{
			int* func_ptrs = t_image.ptr_peek_struct<int>((*it)->nvalue->n_value);
			int vtf_index = 2; // start with 2, because first is reserved for obj pointer, second contains type info pointer
			std::vector<symbol*> vtable;
			while(image.is_valid_function_address(func_ptrs[vtf_index]))
			{
				vtable.push_back(t_image.get_symbol_at_offset(func_ptrs[vtf_index]));
				++vtf_index;
			}
			std::string vtname(demangle((*it)->strval+1));
			if(vtname.find("::") == std::string::npos && vtname.find("<") == std::string::npos && vtable.size() > 0)
			{
				vtname = vtname.substr(11);
				if(vtname.find("Map") != std::string::npos)
				{
					vtname = vtname.substr(0, vtname.length()-3);
				}

				// will just renaming few adapters to match their steamworks names
				size_t capos = vtname.find("CAdapterSteam");
				if(capos == 0)
				{
					vtname.replace(0, 8, "I");
				}
				
				size_t csuv = vtname.find("CSteamUserV");
				if(csuv == 0)
				{
					vtname.replace(0, 11, "ISteamUser");
				}
				
				size_t cscl = vtname.find("CSteamClient");
				if(cscl == 0)
				{
					vtname.replace(0, 12,"IClientEngine");
				}
				
				size_t cshtml = vtname.find("CSteamHTMLSurface");
				if(cshtml == 0)
				{
					vtname.replace(0, 17,"IClientHTMLSurface");
				}				
				
				//size_t csctrl = vtname.find("CSteamController");
				if(vtname == "CSteamController")
				{
					vtname.replace(0, 16,"IClientController");
				}				
				
				//CSteamController
				
				// now just save any vtable which name starts with 'I'
				// because i'm too lazy 
				// and at this point all public steam interfaces just named 
				// ISteam* or IClient*
				if(vtname[0] == 'I')
				{
					save_vtable(out_path, vtname.c_str(), vtable);
				}
			}
		}
	}	
}

void save_steam_enums(mach_image& t_image, const char* out_path)
{
	std::vector<symbol*> enums;
	t_image.find_symbols_by_name("__ZL", enums);
	std::cout << enums.size() << " enums found" << std::endl;
	for(auto it=enums.begin(); it!=enums.end(); ++it)
	{
		if(strstr((*it)->strval, "s_E"))
		{
			steam_enum_pair* sep = t_image.ptr_peek_struct<steam_enum_pair>((*it)->nvalue->n_value);
			size_t enum_offset = (*it)->nvalue->n_value;
			int idx = 0;
			std::map<int32_t,char*> enum_val;
			do
			{
				enum_val[sep[idx].value] = t_image.ptr_peek_struct<char>(sep[idx].descriptor_offset);
				enum_offset += sizeof(steam_enum_pair);
				++idx;
			} while(t_image.is_valid_string_const(sep[idx].descriptor_offset) && t_image.get_symbol_at_offset(enum_offset) == nullptr);
			save_enum(out_path, demangle((*it)->strval+1).substr(2).c_str(), enum_val);
		}
	}
}

int find_image_offset(std::ifstream& t_universal_bin, cpu_type_t t_cputype, size_t& image_size)
{
	uint32_t nfat_arches;
	t_universal_bin.read((char*)&nfat_arches, sizeof(uint32_t));
	nfat_arches = int_byte_swap<uint32_t>(nfat_arches);
	
	for(uint32_t i=0; i<nfat_arches; ++i)
	{
		fat_arch arch;
		t_universal_bin.read((char*)&arch, sizeof(fat_arch));
		swap_uint32_struct<fat_arch>(&arch);
			
		if(arch.cputype == t_cputype)
		{
			image_size = arch.size;
			return arch.offset;
		}
	}	
	
	return -1;
}

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		std::cout << "Usage " << argv[0] << " <in_dylib> <out_path>" << std::endl;
		return -1;
	}
	
	const char* in_file = argv[1];
	const char* out_path = argv[2];
	
	std::ifstream binary;
	binary.open(in_file, std::fstream::binary | std::fstream::in);
	
	if(!binary.is_open())
	{
		std::cout << "Could not open file" << std::endl;
		return -1;
	}
	
	binary.seekg(0, binary.end);
	binary_size = binary.tellg();
	binary.seekg(0, binary.beg);
	
	if(binary_size < 16)
	{
		std::cout << "There's something seriously wrong with this file... aborted." << std::endl;
		return -1;
	}
	
	uint32_t magic;
	binary.read((char*)&magic, sizeof(magic));
	
	std::cout << "File size: " << binary_size << " bytes" << std::endl;
	std::cout << "Magic: 0x"<< std::hex << magic << std::dec << std::endl;
	std::cout << "File type: ";
	
	switch(magic)
	{
		case FAT_CIGAM:
			{
				std::cout << "Universal binary" << std::endl;
				std::cout << "Looking for I386 image..." << std::endl;
				size_t arch_size = 0;
				int i386_image_offset = find_image_offset(binary, CPU_TYPE_I386, arch_size);
				if(i386_image_offset == -1)
				{
					std::cout << "Supported arch not found!" << std::endl;
					return -1;
				}
				std::cout << "Image found..." << std::endl;
				binary.seekg(i386_image_offset);
				image.load_from_fstream(binary, arch_size);
				break;
			}
		case MH_CIGAM:
			{
				std::cout << "Mach32" << std::endl;
				binary.seekg(0, binary.beg);
				image.load_from_fstream(binary, binary_size);
				break;
			}
		case MH_MAGIC:
		case MH_MAGIC_64:
		case FAT_MAGIC:
		default:
			{
				std::cout << "Unsupported binary format!" << std::endl;
				return -1;
			}
			break;
	}
	

	save_steam_enums(image, out_path);
	save_steam_vtables(image, out_path);
	
	return 0;
}
