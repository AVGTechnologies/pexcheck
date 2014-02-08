#include <atlbase.h>
#include <dia2.h>
#include <string>
#include <set>
#include <map>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iostream>
#include <iomanip>

struct hrchecker
{
	hrchecker(char const * file, int line, bool sok)
		: file(file), line(line), sok(sok)
	{
	}

	void operator%(HRESULT hr) const
	{
		if ((sok && hr != S_OK) || FAILED(hr))
		{
			std::ostringstream oss;
			oss << file << "(" << line << "): error: hresult 0x" << std::hex << std::setprecision(8) << hr;
			throw std::runtime_error(oss.str());
		}
	}

	char const * file;
	int line;
	bool sok;
};

#define hrchk hrchecker(__FILE__, __LINE__, false) %
#define hrsok hrchecker(__FILE__, __LINE__, true) %

static std::string to_utf8(wchar_t const * src)
{
	char tmp[16 * 1024];
	size_t len;
	wcstombs_s(&len, tmp, src, sizeof tmp);
	return std::string(tmp);
}

static std::wstring to_utf16(std::string const & s)
{
	int len = MultiByteToWideChar(CP_ACP, 0, s.data(), s.size(), 0, 0);

	std::vector<wchar_t> res;
	res.resize(len);
	len = MultiByteToWideChar(CP_ACP, 0, s.data(), s.size(), res.data(), res.size());

	return std::wstring(res.data(), len);
}

class type_formatter
{
public:
	explicit type_formatter(std::set<std::string> const & exported_fn_names, int ptr_size)
		: m_exported_fn_names(exported_fn_names), m_ptr_size(ptr_size)
	{
	}

	std::string format_type(CComPtr<IDiaSymbol> const & type)
	{
		DWORD tag;
		hrsok type->get_symTag(&tag);

		std::string res;
		switch (tag)
		{
		case SymTagFunctionType:
			{
				CComPtr<IDiaSymbol> result_type;
				hrsok type->get_type(&result_type);
				res = format_type(result_type);
				res.append("(");

				CComPtr<IDiaEnumSymbols> args;
				hrchk type->findChildren(SymTagNull, 0, 0, &args);

				bool first = true;

				CComPtr<IDiaSymbol> class_parent;
				if (type->get_classParent(&class_parent) == S_OK)
				{
					res.append(format_type(class_parent));
					res.append("*");
					first = false;
				}

				ULONG celt;
				CComPtr<IDiaSymbol> arg;
				while (SUCCEEDED(args->Next(1, &arg, &celt)) && celt == 1)
				{
					CComPtr<IDiaSymbol> arg_type;
					hrsok arg->get_type(&arg_type);

					if (!first)
						res.append(",");
					first = false;

					res.append(format_type(arg_type));
					arg.Release();
				}

				res.append(")");
			}
			break;

		case SymTagPointerType:
			{
				CComPtr<IDiaSymbol> nested_type;
				hrsok type->get_type(&nested_type);

				res = format_type(nested_type);
				res.append("*");
			}
			break;

		case SymTagTypedef:
			{
				CComPtr<IDiaSymbol> nested_type;
				hrsok type->get_type(&nested_type);
				res = format_type(nested_type);
			}
			break;

		case SymTagEnum:
			{
				CComBSTR name;
				hrsok type->get_name(&name);
				res = "enum(";
				res.append(to_utf8(name.m_str));
				res.append(")");
			}
			break;

		case SymTagUDT:
			{
				CComBSTR name;
				hrsok type->get_name(&name);
				res = to_utf8(name.m_str);
				this->add_udt(type);
			}
			break;

		case SymTagArrayType:
			{
				DWORD len;
				hrsok type->get_count(&len);

				CComPtr<IDiaSymbol> nested_type;
				hrsok type->get_type(&nested_type);

				res = format_type(nested_type);
				char tmp[32];
				sprintf_s(tmp, "[%d]", len);

				res.append(tmp);
			}
			break;

		case SymTagBaseType:
			{
				DWORD baseType;
				hrsok type->get_baseType(&baseType);

				switch (baseType)
				{
				case btVoid:
					res = "void";
					break;
				case btChar:
					res = "char";
					break;
				case btWChar:
					res = "wchar_t";
					break;
				case btInt:
					res = "int";
					break;
				case btUInt:
					res = "uint";
					break;
				case btFloat:
					res = "float";
					break;
				case btBCD:
					res = "bcd";
					break;
				case btBool:
					res = "bool";
					break;
				case btLong:
					res = "long";
					break;
				case btULong:
					res = "ulong";
					break;
				case btCurrency:
					res = "currency";
					break;
				case btDate:
					res = "date";
					break;
				case btVariant:
					res = "variant";
					break;
				case btComplex:
					res = "complex";
					break;
				case btBit:
					res = "bit";
					break;
				case btBSTR:
					res = "bstr";
					break;
				case btHresult:
					res = "hresult";
					break;
				default:
					res = "<unkbase>";
				}
			}
			break;

		default:
			res = "<unknown>";
		}

		return res;
	}

	void add_function(CComPtr<IDiaSymbol> const & fn)
	{
		CComBSTR fn_name;
		hrsok fn->get_name(&fn_name);

		CComPtr<IDiaSymbol> fn_type;
		hrsok fn->get_type(&fn_type);

		CComBSTR demangled_name;
		hrsok fn->get_undecoratedNameEx(0, &demangled_name);

		std::string tmp;
		if (m_exported_fn_names.find(to_utf8(demangled_name)) != m_exported_fn_names.end())
			tmp.append("exp ");
		else
			tmp.append("fn ");

		tmp.append(to_utf8(fn_name.m_str));
		tmp.append(" ");
		tmp.append(this->format_type(fn_type));

		m_lines.insert(tmp);
	}

	void add_udt(CComPtr<IDiaSymbol> const & sym)
	{
		DWORD type_id;
		hrsok sym->get_symIndexId(&type_id);

		if (m_udts.find(type_id) != m_udts.end())
			return;

		m_udts.insert(type_id);

		std::ostringstream oss;
		oss << "type ";

		CComBSTR name;
		hrsok sym->get_name(&name);
		oss << to_utf8(name);

		ULONG celt;

		DWORD vtableBaseLen = 0;

		{
			CComPtr<IDiaEnumSymbols> children;
			hrchk sym->findChildren(SymTagBaseClass, 0, 0, &children);

			std::vector<std::string> bases;

			CComPtr<IDiaSymbol> child;
			for (; SUCCEEDED(children->Next(1, &child, &celt)) && celt == 1; child.Release())
			{
				BOOL virt;
				hrsok child->get_virtualBaseClass(&virt);

				CComBSTR name;
				hrsok child->get_name(&name);

				CComPtr<IDiaSymbol> base_type;
				hrsok child->get_type(&base_type);

				this->add_udt(base_type);

				if (!virt)
				{
					LONG ofs;
					hrsok child->get_offset(&ofs);

					if (ofs == 0)
					{
						CComPtr<IDiaSymbol> vtableShape;
						if (child->get_virtualTableShape(&vtableShape) == S_OK)
						{
							DWORD len;
							vtableShape->get_count(&len);
							vtableBaseLen = len;
						}
					}

					std::ostringstream lss;
					lss << ofs << ":base:" << to_utf8(name);
					bases.push_back(lss.str());
				}
				else
				{
					std::ostringstream lss;
					lss << "virt:base:" << to_utf8(name);
					bases.push_back(lss.str());
				}
			}

			for (auto it = bases.begin(); it != bases.end(); ++it)
				oss << " " << *it;
		}

		{
			CComPtr<IDiaEnumSymbols> children;
			hrchk sym->findChildren(SymTagFunction, 0, 0, &children);

			std::map<LONG, std::string> vfns;

			CComPtr<IDiaSymbol> child;
			for (; SUCCEEDED(children->Next(1, &child, &celt)) && celt == 1; child.Release())
			{
				BOOL virt;
				hrsok child->get_virtual(&virt);
				if (!virt)
					continue;

				hrsok child->get_compilerGenerated(&virt);
				if (virt)
					continue;

				DWORD ofs;
				if (child->get_virtualBaseOffset(&ofs) != S_OK)
					continue;

				if (ofs / m_ptr_size < vtableBaseLen)
					continue;

				CComBSTR fn_name;
				hrsok child->get_name(&fn_name);

				CComPtr<IDiaSymbol> fn_type;
				hrsok child->get_type(&fn_type);

				std::ostringstream lss;
				lss << ofs / m_ptr_size << ":fn:" << to_utf8(fn_name) << "(" << this->format_type(fn_type) << ")";
				vfns[ofs / m_ptr_size] = lss.str();
			}

			for (auto it = vfns.begin(); it != vfns.end(); ++it)
				oss << " " << it->second;
		}

		{
			CComPtr<IDiaEnumSymbols> children;
			hrchk sym->findChildren(SymTagData, 0, 0, &children);

			std::map<LONG, std::string> data;

			CComPtr<IDiaSymbol> child;
			for (; SUCCEEDED(children->Next(1, &child, &celt)) && celt == 1; child.Release())
			{
				DWORD dk;
				hrsok child->get_dataKind(&dk);
				if (dk == DataIsStaticMember)
					continue;

				LONG ofs;
				hrsok child->get_offset(&ofs);

				CComPtr<IDiaSymbol> data_type;
				hrsok child->get_type(&data_type);

				std::ostringstream lss;
				lss << ofs << ":var:" << this->format_type(data_type);
				data[ofs] = lss.str();
			}

			for (auto it = data.begin(); it != data.end(); ++it)
				oss << " " << it->second;
		}

		m_lines.insert(oss.str());
	}

	void emit(std::ostream & fout)
	{
		for (std::set<std::string>::const_iterator it = m_lines.begin(); it != m_lines.end(); ++it)
			fout << *it << "\n";
	}

	std::set<std::string> get_removed_lines(std::set<std::string> const & templ)
	{
		std::set<std::string> res;
		std::set_difference(templ.begin(), templ.end(), m_lines.begin(), m_lines.end(), std::inserter(res, res.begin()));
		return res;
	}

	void add_unknowns(std::set<std::string> const & handled_exports)
	{
		std::set<std::string> unhandled_exports;
		std::set_difference(m_exported_fn_names.begin(), m_exported_fn_names.end(), handled_exports.begin(), handled_exports.end(), std::inserter(unhandled_exports, unhandled_exports.begin()));
		for (std::string const & s : unhandled_exports)
			m_lines.insert("unk " + s);
	}

private:
	std::set<DWORD> m_udts;
	std::set<std::string> m_lines;
	std::set<std::string> m_exported_fn_names;
	int m_ptr_size;
};

class pe_section_table
{
public:
	pe_section_table(std::istream & fin, size_t section_count)
		: m_sections(section_count)
	{
		fin.read((char *)m_sections.data(), m_sections.size() * sizeof(IMAGE_SECTION_HEADER));
	}

	size_t rva_to_offset(size_t rva)
	{
		for (size_t i = 0; i < m_sections.size(); ++i)
		{
			if (m_sections[i].VirtualAddress <= rva && rva < m_sections[i].VirtualAddress + m_sections[i].Misc.VirtualSize)
				return m_sections[i].PointerToRawData + (rva - m_sections[i].VirtualAddress);
		}

		throw std::runtime_error("translation failure");
	}

private:
	std::vector<IMAGE_SECTION_HEADER> m_sections;
};

std::set<std::string> get_exported_addresses(std::string const & fname, int & ptr_size)
{
	std::ifstream fin(fname.c_str(), std::ios::binary);

	IMAGE_DOS_HEADER header;
	fin.read((char *)&header, sizeof header);

	fin.seekg(header.e_lfanew);

	DWORD sig;
	fin.read((char *)&sig, sizeof sig);

	IMAGE_FILE_HEADER ifh;
	fin.read((char *)&ifh, sizeof ifh);

	uint64_t opt_header_pos = header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	fin.seekg(opt_header_pos + ifh.SizeOfOptionalHeader);

	pe_section_table section_table(fin, ifh.NumberOfSections);

	IMAGE_DATA_DIRECTORY export_dir;
	fin.seekg(opt_header_pos);
	if (ifh.Machine == IMAGE_FILE_MACHINE_I386)
	{
		IMAGE_OPTIONAL_HEADER32 ioh;
		fin.read((char *)&ioh, sizeof ioh);
		export_dir = ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		ptr_size = 4;
	}
	else
	{
		IMAGE_OPTIONAL_HEADER64 ioh;
		fin.read((char *)&ioh, sizeof ioh);
		export_dir = ioh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		ptr_size = 8;
	}

	size_t offs = section_table.rva_to_offset(export_dir.VirtualAddress);
	fin.seekg(offs);

	std::vector<uint8_t> export_section(export_dir.Size);
	fin.read((char *)export_section.data(), export_section.size());

	fin.seekg(offs);
	IMAGE_EXPORT_DIRECTORY export_dir_table;
	fin.read((char *)&export_dir_table, sizeof export_dir_table);

	size_t export_fn_offs = section_table.rva_to_offset(export_dir_table.AddressOfFunctions);
	std::vector<DWORD> export_address_entries(export_dir_table.NumberOfFunctions);

	fin.seekg(export_fn_offs);
	fin.read((char *)export_address_entries.data(), export_address_entries.size() * sizeof(DWORD));

	std::set<uint64_t> res;
	for (size_t i = 0; i < export_address_entries.size(); ++i)
	{
		if (export_address_entries[i] >= export_dir.VirtualAddress && export_address_entries[i] < export_dir.VirtualAddress + export_dir.Size)
			continue;

		res.insert(export_address_entries[i]);
	}

	std::vector<DWORD> export_name_entries(export_dir_table.NumberOfNames);
	fin.seekg(section_table.rva_to_offset(export_dir_table.AddressOfNames));
	fin.read((char *)export_name_entries.data(), export_name_entries.size() * sizeof(DWORD));

	std::set<std::string> exported_names;
	for (size_t i = 0; i < export_dir_table.NumberOfNames; ++i)
	{
		size_t idx = export_name_entries[i] - export_dir.VirtualAddress;
		char const * name = (char const *)(export_section.data() + idx);
		exported_names.insert(name);
	}

	return exported_names;
}

static void print_help(char const * argv0)
{
	size_t l = strlen(argv0);
	while (l != 0 && argv0[l - 1] != '/' && argv0[l - 1] != '\\')
		--l;

	if (argv0[l] == '/' || argv0[l] == '\\')
		++l;

	std::cout << "Usage: " << argv0 + l << " [--warning] [--no-dia-fail] [--no-unks] [-y SYMPATH] [-c CHECKFILE] [-o OUTPUTFILE] PEFILE" << std::endl;
}

int _main(int argc, char *argv[])
{
	std::string exepath;
	std::string sympath;
	std::string chkpath;
	std::string outputpath;
	bool succeed = false;
	bool no_dia_fail = false;
	bool no_unks = false;
	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
		{
			print_help(argv[0]);
			return 0;
		}
		else if (strcmp(argv[i], "--warning") == 0)
		{
			succeed = true;
		}
		else if (strcmp(argv[i], "--no-unks") == 0)
		{
			no_unks = true;
		}
		else if (strcmp(argv[i], "--no-dia-fail") == 0)
		{
			no_dia_fail = true;
		}
		else if (strcmp(argv[i], "-c") == 0)
		{
			if (++i >= argc)
			{
				print_help(argv[0]);
				return 2;
			}
			chkpath = argv[i];
		}
		else if (strcmp(argv[i], "-y") == 0)
		{
			if (++i >= argc)
			{
				print_help(argv[0]);
				return 2;
			}
			sympath = argv[i];
		}
		else if (strcmp(argv[i], "-o") == 0)
		{
			if (++i >= argc)
			{
				print_help(argv[0]);
				return 2;
			}
			outputpath = argv[i];
		}
		else
		{
			if (!exepath.empty())
			{
				print_help(argv[0]);
				return 2;
			}
			exepath = argv[i];
		}
	}

	if (exepath.empty())
	{
		print_help(argv[0]);
		return 1;
	}

	bool add_exports = true;
	std::set<std::string> fn_patterns, type_patterns, check_lines;
	std::vector<std::string> config_lines;

	if (!chkpath.empty())
	{
		add_exports = false;

		std::ifstream fin(chkpath);
		if (!fin.is_open())
		{
			std::cerr << "error: couldn't open " << chkpath << std::endl;
			return 3;
		}

		std::string line;
		while (std::getline(fin, line))
		{
			config_lines.push_back(line);

			if (line.empty())
			{
				config_lines.pop_back();
				break;
			}
			if (line == "%exported_functions")
			{
				add_exports = true;
			}
			else if (line.substr(0, 5) == "type ")
			{
				type_patterns.insert(line.substr(5));
			}
			else if (line.substr(0, 3) == "fn ")
			{
				fn_patterns.insert(line.substr(3));
			}
			else
			{
				type_patterns.insert(line);
				fn_patterns.insert(line);
			}
		}

		while (std::getline(fin, line))
			check_lines.insert(line);

		if (fin.bad() || fin.fail())
		{
			std::cerr << "error: failure while reading " << chkpath << std::endl;
			return 3;
		}
	}
	else
	{
		config_lines.push_back("%exported_functions");
	}

	if (check_lines.empty() && outputpath.empty())
		outputpath = "-";

	int ptr_size;
	std::set<std::string> exported_names = get_exported_addresses(exepath, ptr_size);

	hrchk CoInitialize(0);

	CComPtr<IDiaDataSource> source;
	{
		HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&source);
		if (no_dia_fail && hr != S_OK)
		{
			std::cerr << "warning: DIA SDK initialization failed\n";
			return 0;
		}

		hrchk hr;
	}

	{
		HRESULT hr = source->loadDataForExe(to_utf16(exepath).c_str(), sympath.empty()? 0: to_utf16(sympath).c_str(), 0);
		if (hr == E_PDB_NOT_FOUND)
		{
			std::cerr << "error: failed to open file or its associated PDB: " << exepath << std::endl;
			return 3;
		}
		hrchk hr;
	}

	CComPtr<IDiaSession> session;
	hrchk source->openSession(&session);

	CComPtr<IDiaSymbol> global;
	hrchk session->get_globalScope(&global);

	std::set<std::string> demangled_exports;

	{
		CComPtr<IDiaEnumSymbols> syms;
		hrchk global->findChildren(SymTagPublicSymbol, 0, 0, &syms);

		ULONG celt;
		CComPtr<IDiaSymbol> sym;
		for (; SUCCEEDED(syms->Next(1, &sym, &celt)) && celt == 1; sym.Release())
		{
			CComBSTR mangled_name;
			hrchk sym->get_name(&mangled_name);

			if (exported_names.find(to_utf8(mangled_name)) == exported_names.end())
				continue;

			CComBSTR name;
			hrchk sym->get_undecoratedNameEx(0, &name);
			demangled_exports.insert(to_utf8(name));
		}
	}

	type_formatter fmt(demangled_exports, ptr_size);
	std::set<std::string> handled_exports;

	{
		CComPtr<IDiaEnumSymbols> globalFunctions;
		hrchk global->findChildren(SymTagFunction, 0, 0, &globalFunctions);

		ULONG celt;
		CComPtr<IDiaSymbol> globalFunction;
		for (; SUCCEEDED(globalFunctions->Next(1, &globalFunction, &celt)) && celt == 1; globalFunction.Release())
		{
			bool do_add = false;

			if (add_exports)
			{
				CComBSTR demangled_name;
				hrchk globalFunction->get_undecoratedNameEx(0, &demangled_name);

				if (demangled_name)
				{
					std::string name8 = to_utf8(demangled_name);
					if (demangled_exports.find(name8) != demangled_exports.end())
					{
						do_add = true;
						handled_exports.insert(name8);
					}
				}
			}

			if (!do_add)
			{
				CComBSTR name;
				globalFunction->get_name(&name);

				if (fn_patterns.find(to_utf8(name.m_str)) != fn_patterns.end())
					do_add = true;
			}

			if (do_add)
				fmt.add_function(globalFunction);
		}

		CComPtr<IDiaEnumSymbols> globalTypes;
		hrchk global->findChildren(SymTagUDT, 0, 0, &globalTypes);

		CComPtr<IDiaSymbol> globalType;
		for (; SUCCEEDED(globalTypes->Next(1, &globalType, &celt)) && celt == 1; globalType.Release())
		{
			CComBSTR name;
			hrchk globalType->get_name(&name);

			if (type_patterns.find(to_utf8(name.m_str)) != type_patterns.end())
				fmt.add_udt(globalType);
		}
	}

	if (add_exports && !no_unks)
		fmt.add_unknowns(handled_exports);

	if (!outputpath.empty())
	{
		std::ofstream fout;
		std::ostream * out;
		if (outputpath == "-")
		{
			out = &std::cout;
		}
		else
		{
			fout.open(outputpath);
			if (!fout.is_open())
			{
				std::cerr << "error: couldn't open " << outputpath << std::endl;
				return 3;
			}
			out = &fout;
		}

		for (size_t i = 0; i < config_lines.size(); ++i)
			*out << config_lines[i] << '\n';
		*out << '\n';
		fmt.emit(*out);
	}

	if (!check_lines.empty())
	{
		std::set<std::string> removed_lines = fmt.get_removed_lines(check_lines);
		if (!removed_lines.empty())
		{
			if (!succeed)
				std::cout << chkpath << "(1): error: cross-module check failed\n";
			else
				std::cout << chkpath << "(1): warning: cross-module check failed\n";

			for (std::set<std::string>::const_iterator it = removed_lines.begin(); it != removed_lines.end(); ++it)
				std::cout << '-' << *it << '\n';

			if (!succeed)
				return 1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	try
	{
		return _main(argc, argv);
	}
	catch (std::exception const & e)
	{
		std::cerr << e.what() << std::endl;
		return 2;
	}
}
