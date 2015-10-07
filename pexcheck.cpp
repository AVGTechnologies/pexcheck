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
#include <regex>

static uint32_t const crc32c_table[] =
{
	0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4,
	0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
	0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b,
	0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
	0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b,
	0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
	0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54,
	0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
	0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a,
	0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
	0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5,
	0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
	0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45,
	0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
	0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
	0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
	0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48,
	0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
	0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687,
	0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
	0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927,
	0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
	0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8,
	0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
	0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096,
	0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
	0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859,
	0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
	0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9,
	0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
	0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36,
	0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
	0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c,
	0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
	0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043,
	0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
	0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3,
	0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
	0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c,
	0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
	0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652,
	0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
	0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d,
	0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
	0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
	0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
	0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2,
	0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
	0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530,
	0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
	0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff,
	0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
	0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f,
	0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
	0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90,
	0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
	0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee,
	0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
	0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321,
	0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
	0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81,
	0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
	0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e,
	0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351,
};

template <typename InputIterator>
uint32_t crc32c(InputIterator first, InputIterator last, uint32_t seed = 0)
{
	uint32_t res = ~seed;
	while (first != last)
		res = crc32c_table[(uint8_t)(res ^ (uint8_t)(*first++))] ^ (res >> 8);
	return ~res;
}

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

struct version_t
{
	version_t() : major(0), minor(0), build(0), revision(0)
	{
	}

	explicit version_t(const std::string & version_string) : version_t()
	{
		std::stringstream version_stream(version_string);
		char dot;
		version_stream >> major >> dot >> minor >> dot >> build >> dot >> revision;
	}

	bool operator<(const version_t & other) const
	{
		return std::tie(major, minor, build, revision)
			< std::tie(other.major, other.minor, other.build, other.revision);
	}

	bool operator==(const version_t & other) const
	{
		return std::tie(major, minor, build, revision)
			== std::tie(other.major, other.minor, other.build, other.revision);
	}

private:
	uint16_t major;
	uint16_t minor;
	uint16_t build;
	uint16_t revision;
};

struct follow_t
{
	std::regex templ;
	std::vector<std::string> repls;
};

class type_formatter
{
public:
	explicit type_formatter(std::set<std::string> const & exported_fn_names, std::vector<follow_t> const & follows, std::set<std::string> & follow_matches, int ptr_size, version_t pex_version)
		: m_exported_fn_names(exported_fn_names), m_ptr_size(ptr_size), m_follows(follows), m_follow_matches(follow_matches), m_pex_version(pex_version)
	{
	}

	std::string format_type(CComPtr<IDiaSymbol> const & type, bool simple_unnamed)
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
				res = format_type(result_type, simple_unnamed);
				res.append("(");

				CComPtr<IDiaEnumSymbols> args;
				hrchk type->findChildren(SymTagNull, 0, 0, &args);

				bool first = true;

				if (m_pex_version < version_t("1.0.0.5"))
				{
					CComPtr<IDiaSymbol> class_parent;
					if (type->get_classParent(&class_parent) == S_OK)
					{
						res.append(format_type(class_parent, simple_unnamed));
						res.append("*");
						first = false;
					}
				}
				else
				{
					CComPtr<IDiaSymbol> objectPointerType;
					hrchk type->get_objectPointerType(&objectPointerType);
					if (objectPointerType)
					{
						res.append(format_type(objectPointerType, simple_unnamed));
						first = false;
					}
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

					res.append(format_type(arg_type, simple_unnamed));
					arg.Release();
				}

				res.append(")");
			}
			break;

		case SymTagPointerType:
			{
				CComPtr<IDiaSymbol> nested_type;
				hrsok type->get_type(&nested_type);

				res = format_type(nested_type, simple_unnamed);
				res.append("*");
			}
			break;

		case SymTagTypedef:
			{
				CComPtr<IDiaSymbol> nested_type;
				hrsok type->get_type(&nested_type);
				res = format_type(nested_type, simple_unnamed);
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
			if (simple_unnamed)
				res = this->get_udt_name(type, /*simple_unnamed=*/true);
			else
				res = this->add_udt(type);
			break;

		case SymTagArrayType:
			{
				DWORD len;
				hrsok type->get_count(&len);

				CComPtr<IDiaSymbol> nested_type;
				hrsok type->get_type(&nested_type);

				res = format_type(nested_type, simple_unnamed);
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
		tmp.append(this->format_type(fn_type, /*simple_unnamed=*/false));

		this->add_line(tmp);
	}

	std::string get_udt_name(CComPtr<IDiaSymbol> const & sym, bool simple_unnamed)
	{
		DWORD type_id;
		hrsok sym->get_symIndexId(&type_id);

		auto it = m_udts.find(type_id);
		if (it != m_udts.end())
			return it->second;

		CComBSTR name;
		hrsok sym->get_name(&name);
		std::string name8 = to_utf8(name);

		if (name8.find("<unnamed") != std::string::npos)
		{
			if (simple_unnamed)
			{
				name8 = "~unnamed";
			}
			else
			{
				std::string contents = this->get_udt_contents(sym, /*simple_unnamed=*/true);
				uint32_t hash = crc32c(contents.begin(), contents.end());

				std::ostringstream oss;
				oss << "~unnamed_" << std::hex << std::setw(8) << std::setfill('0') << hash;
				name8 = oss.str();
			}
		}

		return name8;
	}

	std::string get_udt_contents(CComPtr<IDiaSymbol> const & sym, bool simple_unnamed, std::string const & udt_name = std::string())
	{
		std::ostringstream oss;
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

				if (!simple_unnamed)
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

		if (!simple_unnamed)
		{
			CComPtr<IDiaEnumSymbols> children;
			hrchk sym->findChildren(SymTagFunction, 0, 0, &children);

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
				lss << "vfn " << udt_name << " " << ofs / m_ptr_size << ":" << to_utf8(fn_name) << "(" << this->format_type(fn_type, simple_unnamed) << ")";
				this->add_line(lss.str());
			}
		}

		{
			CComPtr<IDiaEnumSymbols> children;
			hrchk sym->findChildren(SymTagData, 0, 0, &children);

			std::vector<std::pair<LONG, std::string> > data;

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
				lss << ofs << ":var:" << this->format_type(data_type, simple_unnamed);
				data.push_back(std::make_pair(ofs, lss.str()));
			}

			std::sort(data.begin(), data.end());
			for (auto it = data.begin(); it != data.end(); ++it)
				oss << " " << it->second;
		}

		return oss.str();
	}

	std::string add_udt(CComPtr<IDiaSymbol> const & sym)
	{
		DWORD type_id;
		hrsok sym->get_symIndexId(&type_id);

		{
			auto it = m_udts.find(type_id);
			if (it != m_udts.end())
				return it->second;
		}

		std::string name8 = this->get_udt_name(sym, /*simple_unnamed=*/false);
		m_udts.insert(std::make_pair(type_id, name8));

		std::ostringstream oss;
		oss << "type " << name8 << this->get_udt_contents(sym, /*simple_unnamed=*/false, name8);
		this->add_line(oss.str());
		return name8;
	}

	void emit(std::ostream & fout)
	{
		for (std::set<std::string>::const_iterator it = m_lines.begin(); it != m_lines.end(); ++it)
			fout << *it << "\n";
	}

	std::set<std::string> get_removed_lines(std::set<std::string> const & templ, bool remove_unks)
	{
		std::set<std::string> res;
		std::set_difference(templ.begin(), templ.end(), m_lines.begin(), m_lines.end(), std::inserter(res, res.begin()));

		if (remove_unks)
			res.erase(res.lower_bound("unk "), res.lower_bound("unk!"));

		return res;
	}

	void add_unknowns(std::set<std::string> const & handled_exports)
	{
		std::set<std::string> unhandled_exports;
		std::set_difference(m_exported_fn_names.begin(), m_exported_fn_names.end(), handled_exports.begin(), handled_exports.end(), std::inserter(unhandled_exports, unhandled_exports.begin()));
		for (std::string const & s : unhandled_exports)
			this->add_line("unk " + s);
	}

private:
	void add_line(std::string const & line)
	{
		m_lines.insert(line);
		for (auto && follow : m_follows)
		{
			std::match_results<std::string::const_iterator> mrs;
			if (std::regex_search(line, mrs, follow.templ))
			{
				for (auto && fmt: follow.repls)
					m_follow_matches.insert(mrs.format(fmt));
			}
		}
	}

	std::map<DWORD, std::string> m_udts;
	std::set<std::string> m_lines;
	std::set<std::string> m_exported_fn_names;
	std::vector<follow_t> const & m_follows;
	std::set<std::string> & m_follow_matches;
	int m_ptr_size;
	version_t m_pex_version;
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

		throw std::runtime_error("error: failed to translate rva to file offset");
	}

private:
	std::vector<IMAGE_SECTION_HEADER> m_sections;
};

std::set<std::string> get_exported_addresses(std::string const & fname, int & ptr_size)
{
	std::ifstream fin(fname.c_str(), std::ios::binary);
	if (!fin.is_open())
		throw std::runtime_error("error: failed to open file: " + fname);

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

	std::set<std::string> exported_names;
	if (!export_dir.VirtualAddress)
		return exported_names;

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

	std::cout << "Usage: " << argv0 + l << " [--warning] [--do-fail] [--no-dia-fail] [--no-unks] [--diff DIFFFILE] [--diff-unks] [-y SYMPATH] [-c CHECKFILE] [-o OUTPUTFILE] PEFILE" << std::endl;
}

int _main(int argc, char *argv[])
{
	std::string exepath;
	std::string sympath;
	std::string chkpath;
	std::string outputpath;
	std::string diffpath = "-";
	bool succeed = false;
	bool no_dia_fail = false;
	bool no_unks = false;
	bool do_fail = false;
	bool diff_unks = false;
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
		else if (strcmp(argv[i], "--do-fail") == 0)
		{
			do_fail = true;
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
		else if (strcmp(argv[i], "--diff") == 0)
		{
			if (++i >= argc)
			{
				print_help(argv[0]);
				return 2;
			}
			diffpath = argv[i];
		}
		else if (strcmp(argv[i], "--diff-unks") == 0)
		{
			diff_unks = true;
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

	hrchk CoInitialize(0);

	CComPtr<IDiaDataSource> source;
	{
		HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void **)&source);
		if (no_dia_fail && hr != S_OK)
		{
			std::cerr << "warning: DIA SDK initialization failed\n";
			return 0;
		}

		if (hr == REGDB_E_CLASSNOTREG)
		{
			std::cerr << "error: DIA SDK is not installed\n";
			return 1;
		}

		hrchk hr;
	}

	if (exepath.empty())
	{
		print_help(argv[0]);
		return 1;
	}

	bool add_exports = true;
	std::map<std::string, std::regex> fn_patterns, type_patterns;
	std::set<std::string> check_lines;
	std::vector<follow_t> follow_exprs;
	std::vector<std::string> config_lines, ignored_checks;
	version_t version;

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

			size_t hashpos = line.find('#');
			if (hashpos != std::string::npos)
				line = line.substr(0, hashpos);

			if (line.empty())
			{
			}
			else if (line.substr(0, 13) == "%pex_version ")
			{
				version = version_t(line.substr(13));
			}
			else if (line == "%exported_functions")
			{
				add_exports = true;
			}
			else if (line.substr(0, 5) == "type ")
			{
				line = line.substr(5);
				type_patterns[line] = std::regex(line);
			}
			else if (line.substr(0, 3) == "fn ")
			{
				line = line.substr(3);
				fn_patterns[line] = std::regex(line);
			}
			else if (line.substr(0, 8) == "follow /")
			{
				follow_t f;

				size_t first_pos = 7;
				size_t last_pos = line.find('/', first_pos + 1);
				while (last_pos != std::string::npos)
				{
					f.repls.push_back(line.substr(first_pos + 1, last_pos - first_pos - 1));
					first_pos = last_pos;
					last_pos = line.find('/', first_pos + 1);
				}

				if (!f.repls.empty())
				{
					f.templ.assign(f.repls[0]);
					f.repls.erase(f.repls.begin());

					if (f.repls.empty())
					{
						for (size_t i = 0; i < f.templ.mark_count(); ++i)
						{
							char buf[32];
							sprintf(buf, "$%d", i + 1);
							f.repls.push_back(buf);
						}
					}

					follow_exprs.push_back(f);
				}
			}
			else if (line[0] == '~')
			{
				ignored_checks.push_back(line.substr(1));
			}
			else
			{
				type_patterns[line] = std::regex(line);
				fn_patterns[line] = std::regex(line);
			}
		}

		while (std::getline(fin, line))
		{
			bool ignore = false;
			for (std::string const & ig : ignored_checks)
			{
				if (line.size() >= ig.size() && line.substr(0, ig.size()) == ig)
				{
					ignore = true;
					break;
				}
			}

			if (!ignore)
				check_lines.insert(line);
		}

		if (fin.bad())
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

	std::set<std::string> follow_matches;
	type_formatter fmt(demangled_exports, follow_exprs, follow_matches, ptr_size, version);
	std::set<std::string> handled_exports;

	size_t last_follow_matches_size = 0;

	for (;;)
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

				std::string name8 = to_utf8(name.m_str);
				for (auto && kv : fn_patterns)
				{
					if (std::regex_match(name8, kv.second))
					{
						do_add = true;
						break;
					}
				}
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

			std::string name8 = to_utf8(name.m_str);
			for (auto && kv : type_patterns)
			{
				if (std::regex_match(name8, kv.second))
				{
					fmt.add_udt(globalType);
					break;
				}
			}
		}

		if (last_follow_matches_size == follow_matches.size())
			break;

		for (auto && fm : follow_matches)
			type_patterns[fm] = fn_patterns[fm] = std::regex(fm);

		last_follow_matches_size = follow_matches.size();
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
		std::ofstream fout;
		std::ostream * out;
		if (diffpath == "-")
		{
			out = &std::cout;
		}
		else
		{
			fout.open(diffpath);
			if (!fout.is_open())
			{
				std::cerr << "error: couldn't open " << diffpath << std::endl;
				return 3;
			}
			out = &fout;
		}

		std::set<std::string> removed_lines = fmt.get_removed_lines(check_lines, /*remove_unks=*/!diff_unks);
		if (!removed_lines.empty())
		{
			std::cout << (diffpath == "-"? chkpath: diffpath) << "(1): " << (succeed? "warning": "error") << ": cross-module compatibility check failed\n";
			if (!chkpath.empty() && diffpath != "-")
				std::cout << chkpath << "(1): note: using this pexcheck template\n";

			for (std::set<std::string>::const_iterator it = removed_lines.begin(); it != removed_lines.end(); ++it)
				*out << '-' << *it << '\n';

			if (!succeed || do_fail)
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
