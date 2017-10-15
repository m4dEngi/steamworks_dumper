#include <iostream>
#include <fstream>
#include <stdio.h>
#include <map>
#include <cstring>
#include <vector>
#include <list>

#include "stuff.h"
#include "util.h"
#include "machfile.h"
#include "include/hde/hde32.h"

mach_image image;
size_t binary_size;

struct callback_desc
{
	size_t size;
	char* posted_in;
};

#pragma pack(push, 1)
// steam public enums string lookup
struct steam_enum_pair
{
	int32_t value;
	int32_t descriptor_offset;
};

// msginfo 
struct steam_emsg 
{
	int32_t emsg;
	int32_t descriptor_offset;
	uint32_t flags;
	int32_t server_type;
	
	uint64_t unk1;
	uint64_t unk2;
	uint64_t unk3;
	uint32_t unk4;
};
#pragma pack(pop)

void write_vtable(const char* t_out_path, const char* t_vtname, std::vector<symbol*>& t_vtfuncs)
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
			// just in case... we shouldn't get here
			ofs << "    virtual unknown_ret unknownwnFunction" << unknowncount << "() = 0;" << std::endl;
			++unknowncount;
		}
	}
	
	ofs << "};" << std::endl;
	
	delete [] file_path_out;
}

void write_enum(const char* t_out_path, const char* t_enum_name, std::map<int32_t,char*> t_enum)
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
		
		if(((*it).first - prev_value != 1 && it != t_enum.begin()) || (it == t_enum.begin() && (*it).first != 0))
		{
			ofs << " = " << (*it).first;
		}
		
		ofs << ", // " << (*it).second << std::endl;
		
		prev_value = (*it).first;
	}
	
	ofs << "} " << t_enum_name << ";" << std::endl;
	
	delete [] file_path_out;
}

void write_callbackid_dump(const char* t_out_path, std::map<int32_t, callback_desc> &t_callbacks)
{
	std::string file_path_out(t_out_path);
	std::ofstream ofs(file_path_out + "/callbacks.json", std::ios_base::out);	
	
	ofs << "[" << std::endl;
	
	for(auto it = t_callbacks.begin(); it != t_callbacks.end(); ++it)
	{
		ofs << "    {" << std::endl;
		ofs << "        \"id\": " << (*it).first << "," << std::endl;
		ofs << "        \"size\": " <<  (*it).second.size << "," << std::endl;
		ofs << "        \"posted_in\": \"" <<  demangle((*it).second.posted_in + 1) << "\"" << std::endl;
		ofs << "    }";
		
		auto it_next = it;
		++it_next;
		
		if(it_next != t_callbacks.end())
		{
			ofs << ",";
		}
		ofs << std::endl;
	}
	
	ofs << "]" << std::endl;
}

void write_emsgs_dump(const char* t_out_path, std::map<int32_t, steam_emsg*> &t_emsg_list, mach_image& t_image)
{
	std::string file_path_out(t_out_path);
	std::ofstream ofs(file_path_out + "/emsg_list.json", std::ios_base::out);	
	
	ofs << "[" << std::endl;
	
	for(auto it = t_emsg_list.begin(); it != t_emsg_list.end(); ++it)
	{
		ofs << "    {" << std::endl;
		ofs << "        \"emsg\": " << (*it).first << "," << std::endl;
		ofs << "        \"name\": \"" <<  t_image.ptr_peek_struct<char>((*it).second->descriptor_offset) << "\"," << std::endl;
		ofs << "        \"flags\": " <<  (*it).second->flags << "," << std::endl;
		ofs << "        \"server_type\": " << (*it).second->server_type << std::endl;
		ofs << "    }";
				
		auto it_next = it;
		++it_next;
		
		if(it_next != t_emsg_list.end())
		{
			ofs << ",";
		}
		ofs << std::endl;
	}
	
	
	ofs << "]" << std::endl;
}

void dump_vtables(mach_image& t_image, const char* out_path)
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
			// skipping all "weird" templated classes and empty vtables
			if(vtname.find("::") == std::string::npos && vtname.find("<") == std::string::npos && vtable.size() > 0)
			{
				vtname = vtname.substr(11);
				if(vtname.find("Map") != std::string::npos)
				{
					vtname = vtname.substr(0, vtname.length()-3);
				}

				// just renaming few adapters to match their steamworks names
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
				
				if(vtname == "CSteamController")
				{
					vtname.replace(0, 16,"IClientController");
				}				
				
				// At this point public and private client interfaces should be named 
				// ISteam* or IClient*
				// So we'll save any vtable which name starts with I
				// cheap and dirty
				if(vtname[0] == 'I')
				{
					write_vtable(out_path, vtname.c_str(), vtable);
				}
			}
		}
	}	
}

void dump_enums(mach_image& t_image, const char* out_path)
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
			write_enum(out_path, demangle((*it)->strval+1).substr(2).c_str(), enum_val);
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


uint32_t get_argument(unsigned char* t_image_bytes, std::list<size_t> &t_instruction_bt, uint8_t t_arg_num)
{
	uint8_t arg_soff = t_arg_num * 4;
	for(auto it = t_instruction_bt.end(); it != t_instruction_bt.begin(); --it)
	{
		hde32s hds_bt;
		hde32_disasm(t_image_bytes + *it, &hds_bt);
		if(hds_bt.opcode == 0xc7 && hds_bt.disp8 == arg_soff) // only interested in mov imm32 screw the rest
		{
			return hds_bt.imm32;
		}
	}
	
	return -1;
}


void dump_callback_ids(mach_image& t_image, const char* out_path)
{
	symbol* post_callback_to_ui = t_image.find_symbol_by_name("__ZN9CBaseUser16PostCallbackToUIEiPhi");
	if(post_callback_to_ui == nullptr)
	{
		return;
	}
	
	symbol* post_callback_to_all = t_image.find_symbol_by_name("__ZN9CBaseUser17PostCallbackToAllEiPhi");
	if(post_callback_to_all == nullptr)
	{
		return;
	}
	
	symbol* post_callback_to_app = t_image.find_symbol_by_name("__ZN9CBaseUser17PostCallbackToAppEjiPhi");
	if(post_callback_to_app == nullptr)
	{
		return;
	}

	symbol* post_callback_to_pipe = t_image.find_symbol_by_name("__ZN9CBaseUser18PostCallbackToPipeEiiPhi");
	if(post_callback_to_pipe == nullptr)
	{
		return;
	}	

	symbol* post_api_result = t_image.find_symbol_by_name("__ZN12CSteamEngine13PostAPIResultEP9CBaseUseryiPvi");
	if(post_callback_to_pipe == nullptr)
	{
		return;
	}	
	
	section* text_section = t_image.get_section_by_name("__TEXT", "__text");
	t_image.seek(text_section->offset , std::ios_base::beg);
	size_t current_pos = text_section->offset;
	size_t section_end = text_section->offset + text_section->size;
	
	unsigned char* image_bytes = t_image.get_image_bytes();
	
	hde32s hds;
	size_t func_start_offset = 0;
	std::list<size_t> instruction_bt;
	std::map<int32_t, callback_desc> callbacks;
	while(current_pos < section_end)
	{
		hde32_disasm(image_bytes + current_pos, &hds);

		if(hds.opcode == 0x55) // push ebp
		{
			func_start_offset = current_pos;
		}
		
		if(hds.opcode == 0xe8) // call rel offset
		{
			size_t func_absolute_offset = (int)hds.rel32 + current_pos + 5;
			uint32_t cbid = -1;
			uint32_t cbsize = 0;
		
			if( func_absolute_offset == post_callback_to_ui->nvalue->n_value  ||
				func_absolute_offset == post_callback_to_all->nvalue->n_value 
			)
			{
				cbid = get_argument(image_bytes, instruction_bt, 1);
				cbsize = get_argument(image_bytes, instruction_bt, 3);
			}
			else if( func_absolute_offset == post_callback_to_app->nvalue->n_value  ||
					 func_absolute_offset == post_callback_to_pipe->nvalue->n_value 
			)
			{
				cbsize = get_argument(image_bytes, instruction_bt, 4);
				cbid = get_argument(image_bytes, instruction_bt, 2);
			}
			else if( func_absolute_offset == post_api_result->nvalue->n_value )
			{
				cbsize = get_argument(image_bytes, instruction_bt, 6);
				cbid = get_argument(image_bytes, instruction_bt, 7);
			}
			else { }
			
			if(cbid != -1) 
			{
				callbacks.insert(std::pair<int32_t, callback_desc>((int32_t)cbid, {cbsize, t_image.get_symbol_at_offset(func_start_offset)->strval}));
			}
		}
		
		instruction_bt.push_back(current_pos);
		
		if(instruction_bt.size() > 10)
		{
			instruction_bt.pop_front();
		}		
		
		current_pos += hds.len;
	}
	
	std::cout << callbacks.size() << " callbacks found" << std::endl;
	
	write_callbackid_dump(out_path, callbacks);
}

void dump_emsgs(mach_image& t_image, const char* out_path)
{
	symbol* emsglist = t_image.find_symbol_by_name("__ZL9g_MsgInf");
	if(emsglist == nullptr)
	{
		return;
	}
	
	steam_emsg* msgs_info = t_image.ptr_peek_struct<steam_emsg>(emsglist->nvalue->n_value);
	
	int32_t idx = 0;
	size_t emsg_offset = emsglist->nvalue->n_value;
	std::map<int32_t, steam_emsg*> msglist;
	do
	{
		msglist.insert(std::pair<int32_t, steam_emsg*>(msgs_info[idx].emsg, &msgs_info[idx]));
		emsg_offset += sizeof(steam_emsg);
		++idx;
	} while(msgs_info[idx].emsg != 0 && t_image.get_symbol_at_offset(emsg_offset) == nullptr);

	write_emsgs_dump(out_path, msglist, t_image);
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
	

	dump_enums(image, out_path);
	dump_vtables(image, out_path);
	dump_callback_ids(image, out_path);
	dump_emsgs(image, out_path);
	
	return 0;
}
