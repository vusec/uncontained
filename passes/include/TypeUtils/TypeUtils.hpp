#ifndef _TypeUtils_
#define _TypeUtils_

#include <llvm/IR/DerivedTypes.h>

#include <set>
#include <map>
#include <functional>
#include <string>
#include <sstream>
#include <vector>

static std::vector<std::string> string_split(const std::string &s, char delim) {
  std::stringstream ss(s);
  std::string item;
  std::vector<std::string> elems;
  while (std::getline(ss, item, delim)) {
    // elems.push_back(item);
    elems.push_back(std::move(item));
  }
  return elems;
}

static std::string GetTypeName(llvm::Type* T) {
    switch (T->getTypeID())
    {
        case llvm::Type::IntegerTyID:
            return "i" + std::to_string(llvm::cast<llvm::IntegerType>(T)->getBitWidth());

        case llvm::Type::VoidTyID:
            return "v";
        case llvm::Type::FloatTyID:
            return "f";
        case llvm::Type::DoubleTyID:
            return "d";
        case llvm::Type::X86_FP80TyID:
            return "f80";
        case llvm::Type::FP128TyID:
            return "f128";
        case llvm::Type::PPC_FP128TyID:
            return "f2x64";

        case llvm::Type::PointerTyID:
        {
            return GetTypeName(llvm::cast<llvm::PointerType>(T)->getPointerElementType()) + "*";
        }

        case llvm::Type::StructTyID:
        {
            // get the actual Struct name but strip away llvm suffixes
            auto ST = llvm::cast<llvm::StructType>(T);

            // if the structure has no name, or is an anonymous structure, visit the fields
            if (!ST->hasName() || ST->getName().str() == "" || ST->getName().contains(".anon.")) {
                std::string struct_repr = "struct(";
                // insert each type recursively in the struct
                for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i)
                {
                    // NOTICE:
                    // The recursive call here should be guaranteed to terminate, as
                    // there should not be pointers to the same anon struct (otherwise
                    // it could not be anonymous), thus anon types should have no
                    // loops
                    struct_repr += GetTypeName(ST->getElementType(i));
                    if (i < e-1) struct_repr += ", ";
                }

                struct_repr += ")";
                return struct_repr;
            }

            std::string struct_name = string_split(ST->getName().str(), '.').at(1);

            return struct_name;
        }

        case llvm::Type::FunctionTyID:
        {
            auto FT = llvm::cast<llvm::FunctionType>(T);

            std::string func_repr = "func(";
            func_repr += GetTypeName(FT->getReturnType());
            func_repr += ",";

            for (unsigned i = 0, e = FT->getNumParams(); i != e; ++i)
            {
                func_repr += GetTypeName(FT->getParamType(i));
                if (i < e-1) func_repr += ", ";
            }

            if (FT->isVarArg()) func_repr += ", ...)";
            else func_repr += ")";

            return func_repr;
        }

        case llvm::Type::ArrayTyID:
        {
            auto AT = llvm::cast<llvm::ArrayType>(T);
            return "arr(" + std::to_string(AT->getNumElements()) + ", " + GetTypeName(AT->getElementType()) + ")";
        }

        case llvm::Type::FixedVectorTyID:
        {
            auto FVT = llvm::cast<llvm::FixedVectorType>(T);
            return "fvec(" + std::to_string(FVT->getNumElements()) + ", " + GetTypeName(FVT->getElementType()) + ")";
        }

        default:
        {
            llvm::errs() << "UNABLE TO GENERATE NAME:";
            T->print(llvm::errs());
            return "unknown";
        }
    }
}

// Return a string representation of the type T, that represents its structure
static std::string __TypeToString(llvm::Type* T, int depth) {

    switch (T->getTypeID())
    {
        case llvm::Type::IntegerTyID:
            return "i" + std::to_string(llvm::cast<llvm::IntegerType>(T)->getBitWidth());

        case llvm::Type::VoidTyID:
            return "v";
        case llvm::Type::FloatTyID:
            return "f";
        case llvm::Type::DoubleTyID:
            return "d";
        case llvm::Type::X86_FP80TyID:
            return "f80";
        case llvm::Type::FP128TyID:
            return "f128";
        case llvm::Type::PPC_FP128TyID:
            return "f2x64";

        case llvm::Type::PointerTyID:
        {
            // if the pointer points to a struct we do not explore the structure to avoid recursive type visits
            // we originally solved the problem giving IDs to structs based on the StructType, but this does not work
            // when a struct has two variations of the same type, and a topologically equivalent struct has only one variation
            // e.g.
            // struct s1.0 {int a; struct p1.0* p; struct p1.0* p}
            // struct s1.1 {int a; struct p1.1* p; struct p1.2* p}
            // with p1.0, p1.1 and p1.1 being structurally equivalent.
            // While these two structs should be equivalent, they would be evaluated as different
            if (llvm::isa<llvm::StructType>(llvm::cast<llvm::PointerType>(T)->getPointerElementType())) {
                return "p(struct)";
            }
            return "p(" + __TypeToString(llvm::cast<llvm::PointerType>(T)->getPointerElementType(), depth+1) + ")";
        }

        case llvm::Type::StructTyID:
        {
            auto ST = llvm::cast<llvm::StructType>(T);

            std::string struct_repr = "struct(";

            // insert each type recursively in the struct
            for (unsigned i = 0, e = ST->getNumElements(); i != e; ++i)
            {
                struct_repr += __TypeToString(ST->getElementType(i), depth+1);
                if (i < e-1) struct_repr += ", ";
            }

            struct_repr += ")";

            return struct_repr;
        }

        case llvm::Type::FunctionTyID:
        {
            auto FT = llvm::cast<llvm::FunctionType>(T);

            std::string func_repr = "func(";
            func_repr += __TypeToString(FT->getReturnType(), depth+1);
            func_repr += ",";

            for (unsigned i = 0, e = FT->getNumParams(); i != e; ++i)
            {
                func_repr += __TypeToString(FT->getParamType(i), depth+1);
                if (i < e-1) func_repr += ", ";
            }

            if (FT->isVarArg()) func_repr += ", ...)";
            else func_repr += ")";

            return func_repr;
        }

        case llvm::Type::ArrayTyID:
        {
            auto AT = llvm::cast<llvm::ArrayType>(T);
            return "arr(" + std::to_string(AT->getNumElements()) + ", " + __TypeToString(AT->getElementType(), depth+1) + ")";
        }

        default:
        {
            llvm::errs() << "UNABLE TO DUMP:";
            T->print(llvm::errs());
            return "unknown";
        }
    }
}

static std::string TypeToString(llvm::Type* T) {
    return __TypeToString(T, 0);
}

static size_t TypeToNameHash(llvm::Type* T) {
    static thread_local std::map<llvm::Type*, size_t> HashCache;
    if (HashCache.find(T) != HashCache.end()) {
        return HashCache[T];
    }
    size_t type_hash = std::hash<std::string>{}(GetTypeName(T));
    HashCache[T] = type_hash;
    return type_hash;
}

static size_t TypeToTopologyHash(llvm::Type* T) {
    static thread_local std::map<llvm::Type*, size_t> HashCache;
    if (HashCache.find(T) != HashCache.end()) {
        return HashCache[T];
    }
    // yes this is super lazy
    size_t type_hash = std::hash<std::string>{}(__TypeToString(T, 0));
    HashCache[T] = type_hash;
    return type_hash;
}

#endif	/* _TypeUtils_ */
