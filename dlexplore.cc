#include <iostream>
#include <iomanip>
#include <cassert>
#include <string>
#include <vector>

// References
// [1] man 5 elf
// [2] https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html
// [3] http://refspecs.linuxbase.org/elf/elf.pdf

//#define __USE_GNU
// __USE_GNU -- enable gnu extensions in link.h
//   struct dl_phdr_info
//   int dl_iterate_phdr(...)
#include <link.h>

struct link_map* get_my_link_map () {
    // Loop over dynamic tags using _DYNAMIC[] pointer.
    // Retrieve our link_map by searching for the DT_DEBUG tag,
    // containing debugger meta infos.
    struct r_debug* r_debug = 0;
    for (ElfW(Dyn)* dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_DEBUG) {
            r_debug = (struct r_debug *) dyn->d_un.d_ptr;
            break;
        }
    }

    assert(r_debug);
    //printf("got DT_DEBUG @%p\n", r_debug);
    return r_debug->r_map;
}

struct link_map* get_my_link_map2 () {
    // Retrieve our link_map by using dladdr1(3) with RTLD_DL_LINKMAP query.
    Dl_info info;
    struct link_map* lmap = 0;
    int ret = dladdr1((void*)get_my_link_map2, &info, (void**)&lmap, RTLD_DL_LINKMAP);
    assert(ret != 0);
    assert(lmap != 0);
    return lmap;
}


struct DynamicSymbolInfo {
    void parse(struct link_map& lm);
    void dump() const;
    bool hasSymbol(const char* symbol) const;
    const std::string& name() const { return mLinkMapName; }

    private:
    struct ElfHashTable {
        uint32_t mNumBucket;
        uint32_t mNumChain;
        const uint32_t* mBucket;
        const uint32_t* mChain;
    };
    ElfHashTable mHashTable;

    static uint32_t elfHash(const uint8_t* sym_name) {
        uint32_t h = 0, g;
        while (*sym_name) {
            h = (h << 4) + *sym_name++;
            if ((g = h & 0xf0000000)) {
                h ^= g >> 24;
            }
            h &= ~g;
        }
        return h;
    }

    const ElfW(Sym)* mSymbolTable;
    ElfW(Word) mSymbolTableEntrySize;

    const char* mStringTable;
    ElfW(Word) mStringTableSize;

    std::string mLinkMapName;
};

void DynamicSymbolInfo::parse(struct link_map& lm) {
    mLinkMapName.assign(!std::string(lm.l_name).empty() ? lm.l_name : "<no_name>");

    for (ElfW(Dyn)* dyn = lm.l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        assert(dyn);

        switch (dyn->d_tag) {
            case DT_HASH: // d_ptr -- addr of symbol hash table

                /// Table entries are 32bit object for Elf32 & Elf64
                ///            +--------------------+
                /// d_ptr ---> | nbucket            |
                ///            +--------------------+
                ///            | nchain             |
                ///            +--------------------+
                ///            | bucket [0]         |
                ///            | ...                |
                ///            | bucket [nbucket-1] |
                ///            +--------------------+
                ///            | chain [0]          |
                ///            | ...                |
                ///            | chain [nchain-1]   |
                ///            +--------------------+

                {
                    const uint32_t* data = (uint32_t*)dyn->d_un.d_ptr;
                    mHashTable.mNumBucket = data[0];
                    mHashTable.mNumChain = data[1];
                    mHashTable.mBucket = &data[2];
                    mHashTable.mChain = &data[mHashTable.mNumBucket];
                }
                break;
            case DT_SYMENT: // d_val -- size in bytes of a symbol table entry
                mSymbolTableEntrySize = dyn->d_un.d_val;
                break;
            case DT_SYMTAB: // d_ptr -- address of symbol table

                ///            +--------------+
                /// d_ptr ---> | ElfW(Sym)[0] |
                ///            +--------------+  -
                ///            | ElfW(Sym)[1] |  | DT_SYMENT denotes size of symtable entry
                ///            +--------------+  -
                ///            | ...          |
                ///            +--------------+
                ///            | ElfW(Sym)[n] | <--- d_ptr + n * DT_SYMENT
                ///            +--------------+
                ///
                /// Symobl Table entry 0 is the undefined symbol `STN_UNDEF`

                mSymbolTable = (const ElfW(Sym)*)dyn->d_un.d_ptr;
                break;
            case DT_STRSZ: // d_val -- size in bytes of string table
                mStringTableSize = dyn->d_un.d_val;
                break;
            case DT_STRTAB: // d_ptr -- address of string table

                ///            +------+
                /// d_ptr ---> | '\0' |
                ///            +------+  -
                ///            | 'a ' |  | 1 char
                ///            +------+  -
                ///            | ...  |
                ///            +------+
                ///            | '\0' | <--- d_ptr + DT_STRSZ-1
                ///            +------+
                ///

                mStringTable = (const char*)dyn->d_un.d_ptr;
                break;
            default:
                break;
        }
    }
}

void DynamicSymbolInfo::dump() const {
    assert(mSymbolTable);
    assert(mStringTable);

    std::cout << "+----------------------------------------------------------+\n";
    std::cout << "| HashTable for " << std::left << std::setw(42)
                                    << (!mLinkMapName.empty() ? mLinkMapName : "<no_name>")
                                    << " |\n";
    std::cout << "+----------------------------------------------------------+\n";
    std::cout << "| NumBuckets: " << std::setw(4) << mHashTable.mNumBucket
                                  << " NumChains: "
                                  << std::setw(4) << mHashTable.mNumChain
                                  << std::setw(24) << ' '
                                  << " |\n";
    std::cout << "+----------------------------------------------------------+\n";

    for (uint32_t i=0; i<mHashTable.mNumBucket; ++i) {
        if (mHashTable.mBucket[i] != STN_UNDEF) {
            for (uint32_t j=mHashTable.mBucket[i]; j!=STN_UNDEF; j=mHashTable.mChain[j]) {
                const ElfW(Sym)* elf_symbol = (const ElfW(Sym)*)((const char*)mSymbolTable + (mSymbolTableEntrySize * j));
                if (elf_symbol->st_name < mStringTableSize) {
                    const char* symstr = &mStringTable[elf_symbol->st_name];
                    if (symstr) {
                        std::cout << "| " << std::setw(56) << symstr << " |\n";
                    }
                }
            }
            std::cout << "+----------------------------------------------------------+\n";
        }
    }
}

bool DynamicSymbolInfo::hasSymbol(const char* symbol_name) const {
    assert(mSymbolTable);
    assert(mStringTable);
    assert(symbol_name);

    if (mHashTable.mNumBucket == 0) {
        return false;
    }

    /// Symbol lookup via HashTable
    ///
    /// idx = elfHash(symbol) % numBuckets
    ///
    ///      HashTable
    ///      +---------------+
    /// idx  | bucket[0] : 3 |
    ///  |   | bucket[1] : 6 |
    ///  +-> | bucket[2] : 2 | ---+     // reference symbolTable[2]
    ///      +---------------+    |
    ///      | chain[0] : 2  |    |
    ///      | ...           |    |
    ///  +-- | chain[2] : 5  | <--+     // reference symbolTable[5]
    ///  |   | ...           |
    ///  +-> | chain[5] : 0  |          // terminate chain: STN_UNDEF
    ///      +---------------+

    uint32_t hash = elfHash(reinterpret_cast<const unsigned char*>(symbol_name));
    for (uint32_t idx=mHashTable.mBucket[hash % mHashTable.mNumBucket]; idx!=STN_UNDEF; idx=mHashTable.mChain[idx]) {
        const ElfW(Sym)* elf_symbol = (const ElfW(Sym)*)((const char*)mSymbolTable + (mSymbolTableEntrySize * idx));
        if (elf_symbol->st_name < mStringTableSize) {
            const char* symstr = &mStringTable[elf_symbol->st_name];
            if (symstr && std::string(symstr).compare(symbol_name) == 0) {
                return true;
            }
        }
    }
    return false;
}

int main () {
    struct link_map* my_lmap = get_my_link_map();
    // our link_map is the first list entry
    assert(my_lmap && my_lmap->l_prev==0);

    std::vector<DynamicSymbolInfo> dyn_sym_infos;
    for (struct link_map* lm = my_lmap; lm!=0; lm=lm->l_next) {
        if (std::string(lm->l_name).find("linux-vdso.so") != std::string::npos) {
            std::cout << "Skip walking dynamic tags for linux-vdso" << std::endl;
            continue;
        }

        dyn_sym_infos.emplace_back();
        dyn_sym_infos.back().parse(*lm);
    }

    for (const DynamicSymbolInfo& dsi : dyn_sym_infos) {
        std::cout << "Found " << dsi.name() << std::endl;
        const char* sym = "recv";
        std::cout << "\thas symbol=" << sym << " ? " << (dsi.hasSymbol(sym) ? "found" : "not found") << std::endl;
    }

///#ifdef __USE_GNU
///    printf("---- dl_iterate_phdr ----\n");
///    int handle_phdr_item(struct dl_phdr_info* info, size_t size, void* data) {
///        printf("+ %p (%s)\n", info->dlpi_addr, info->dlpi_name);
///        printf("\tphdr=%p phnum=%d\n", info->dlpi_phdr, info->dlpi_phnum);
///        return 0; // return != 0 stops iter
///    }
///    int ret = dl_iterate_phdr(handle_phdr_item, 0);
///    assert(ret == 0);
///#endif

    return 0;
}

