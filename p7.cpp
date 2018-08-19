#include <list>
#include <errno.h>
#include <string>
#include <stddef.h>
#include <limits.h>
#include <vector>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
typedef short SHORT;
typedef int INT;
typedef unsigned char UINT8, UCHAR, BYTE;
typedef unsigned short UINT16, USHORT, WORD;
typedef unsigned UINT32, DWORD, UINT;
typedef unsigned long long UINT64, ULONGLONG;
typedef long long INT64, LONGLONG;
#endif
typedef unsigned char uchar, byte;
typedef unsigned short ushort;
typedef unsigned uint;
typedef uint64_t uint64;

struct image_format_invalid_t { };
struct host_address_t { };
struct target_address_t { };
struct read_size_mismatch_t { };
struct file_too_large_t { };
struct file_too_small_t { };
struct file_zero_size_t { };

struct mmap_t
{
	void * base = 0;
	size_t len = 0;
	~mmap_t()
	{
		if (!base) return;
#ifdef _WIN32
		UnmapViewOfFile(base);
#else
		munmap(base, len);
#endif
		base = 0;
	}
};

#ifdef _WIN32
void throw_last_error()
{
	throw GetLastError();
}
#endif

void throw_errno()
{
	throw errno;
}

struct file_t
{
	union {
		int fd;
		void* h;
		ptrdiff_t pd;
	};

	file_t()
	{
		pd = -1; // invalid in either scheme
	}

	void openr(const std::string& path)
	{
		cleanup();
#ifdef _WIN32
		fd = (ptrdiff_t)CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
			0, OPEN_EXISTING, 0, 0);
		if (fd == -1)
			throw GetLastError();
#else
		fd = open(path.c_str(), O_RDONLY);
		if (fd < 0)
			throw_errno();
#endif
	}

	void openw(const std::string& path)
	{
		cleanup();
#ifdef _WIN32
		fd = (ptrdiff_t)CreateFile(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE, 0, OPEN_ALWAYS, 0, 0);
		if (fd == -1)
			throw_last_error();
#else
		fd = open(path.c_str(), O_RDWR);
		if (fd < 0)
			throw_errno();
#endif
	}

	int64_t size()
	{
#ifdef _WIN32
		LARGE_INTEGER a = { 0 };
		if (!GetFileSizeEx(h, &a))
			throw_last_error();
		return a.QuadPart;
#else
		struct stat s = { 0 };
		if (fstat(fd, &s) == -1)
			throw_errno();
		return s.st_size;
#endif
	}

	~file_t()
	{
		cleanup();
	}
	void cleanup()
	{
#ifdef _WIN32
		if (fd == 0 || fd == -1)
			return;
		CloseHandle((void*)fd);
#else
		if (fd < 0)
			return;
		::close(fd);
#endif
		fd = -1;
	}
};

struct pecoff_file_header_packed_t
{
	char Machine[2];
	char NumberOfSections[2];
	char TimeDateStamp[4];
	char PointerToSymbolTable[4];
	char NumberOfSymbols[4];
	char SizeOfOptionalHeader[]2;
	char Characteristics[4];
};

void unpack(UINT& a, char (&b)[2])
{
	a = (UINT)(UCHAR)b[0] | (((UINT)(UCHAR)b[0]) << 8);
}

void unpack(UINT& a, char (&b)[4])
{
	a = (UINT)(UCHAR)b[0] | (((UINT)(UCHAR)b[0]) << 8);
}

struct pecoff_file_header_t
{
	void unpack(const pecoff_file_header_packed_t& packed)
	{
	}
	ushort Machine;
	ushort NumberOfSections;
	uint TimeDateStamp;
	uint PointerToSymbolTable;
	uint NumberOfSymbols;
	ushort SizeOfOptionalHeader;
	uint Characteristics;
};

uint read8 (void **a)
{
	uchar* b = (u*)*a;
	*a = b + 1;
	return *b;
}

uint read16le (void **a)
{
	uint b = read8(a);
	return b | (read8(a) << 8);
}

uint read32le (void **a)
{
	uint b = read16le(a);
	return b | (read16le(a) << 16);
}

uint64 read64le (void **a)
{
	uint b = read32le(a);
	return b | ((uint64)read32le(a) << 32);
}

struct pe_section_header_t
{
	char Name[8];
	uint VirtualAddress;
	uint SizeOfRawData;
	uint PointerToRawData;
	uint PointerToRelocations;
	uint PointerToLinenumbers;
	uint NumberOfRelocations;
	uint NumberOfLinenumbers;
	uint Characteristics;

	void unpack (const void *a)
	{
		memcpy(Name, a, 8);
		a = (char*)a + 8;
		VirtualAddress = read32le (&a);
		SizeOfRawData = read32le (&a);
		PointerToRawData = read32le (&a);
		PointerToRelocations = read32le (&a);
		PointerToLinenumbers = read32le (&a);
		NumberOfRelocations = read16le (&a);
		NumberOfLinenumbers = read16le (&a);
		Characteristics = read32le (&a);
	}
};

struct pe_file_header_t
{
	uint Machine;
	uint NumberOfSections;
	uint TimeDateStamp;
	uint PointerToSymbolTable;
	uint NumberOfSymbols;
	uint SizeOfOptionalHeader;
	uint Characteristics;

	void unpack (const void *a)
	{
		Machine = read16le (&a);
		NumberOfSections = read16le (&a);
		TimeDateStamp = read32le (&a);
		PointerToSymbolTable = read32le (&a);
		NumberOfSymbols = read32le (&a);
		SizeOfOptionalHeader = read16le (&a);
		Characteristics = read16le (&a);
	}
};

struct module_t
{
// TODO boost intrusive list
	bool pinned = false;
	int refcount = 0;
	std::string host_path;
	std::string target_path;
	std::vector<byte> data;
	std::vector<module_t*> dependents;
	pe_file_header_t file_header;

	int machine;
	std::vector<section_t*> sections;

	void load(std::string host_path)
	{
		file_t fd;
		fd.openr(host_path);
		std::vector<byte> data;
		int64_t size = fd.size();
		if (size >= UINT_MAX)
			throw file_too_large_t();
		if  (size == 0)
			throw file_zero_size_t();
		if  (size <= 64)
			throw file_too_small_t();
		data.resize((size_t)size);
#ifdef _WIN32
		DWORD r = 0;
		if (!ReadFile(fd.h, &data[0], (DWORD)size, 0)
			throw_last_error();
#else
		ssize_t r = ::read(fd.fd, &data[0], size);
		if (r == -1)
			throw_errno();
#endif
		if (r != size)
			throw read_size_mismatch_t();
		if (data[0] != 'M' || data[1] != 'Z')
			throw image_format_invalid_t();
		size_t offset_to_pe = read32le (&data[60]);
		if ((offset_to_pe + 4) >= data.size())
			throw image_format_invalid_t();
		if (data[offset_to_pe] != 'P' || data[offset_to_pe + 1] != 'E'
			|| data[offset_to_pe + 2] || data[offset_to_pe + 3])
			throw image_format_invalid_t();
	}
};

struct loader_t
{
	std::list<module_t> modules;
};

struct stringi_t
{
};

struct envvars_t
{
};

struct system_t // aka process
{
};

int main(int argc, char **argv)
{
	if (!*argv[1])
		exit(1);

	module_t m;
	m.load(argv[1]);
}