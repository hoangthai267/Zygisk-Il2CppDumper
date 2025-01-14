//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"
#include <map>
// #include <il2cpp-api.h>
#include <iostream>
#include <fstream>
#include <locale>
#include <codecvt>

#define DO_API(r, n, p) r(*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

static uint64_t il2cpp_base = 0;

void init_il2cpp_api(void *handle)
{
#define DO_API(r, n, p)                           \
    {                                             \
        n = (r(*) p)xdl_sym(handle, #n, nullptr); \
        if (!n)                                   \
        {                                         \
            LOGW("api not found %s", #n);         \
        }                                         \
    }

#include "il2cpp-api-functions.h"

#undef DO_API
}
namespace fs = std::filesystem;

void CopyArrayToVector(Il2CppArray *byteArray, std::vector<uint8_t> &result)
{
    if (!byteArray)
    {
        return;
    }

    // Get array length
    size_t length = il2cpp_array_length(byteArray);

    // Get raw data pointer
    uint8_t *data = reinterpret_cast<uint8_t *>(byteArray->vector);

    // Copy data into std::vector
    result.assign(data, data + length);
}

void LogArray(std::vector<uint8_t> &result, const char *name)
{
    std::stringstream byteOutput;

    if (!result.empty())
    {
        LOGD("Retrieved %s: ", name);
        for (auto byte : result)
        {
            byteOutput << std::hex << static_cast<int>(byte) << " ";
        }
    }
    else
    {
        LOGD("Failed to retrieve %s.", name);
    }

    LOGD("Retrieved %s: %s ", name, byteOutput.str().c_str());
}

std::string convertToString(Il2CppString *str)
{
    if (str == nullptr)
    {
        return "";
    }
    const Il2CppChar *il2cppChars = il2cpp_string_chars(str);
    size_t length = il2cpp_string_length(str);
    std::wstring wstr(il2cppChars, il2cppChars + length);

    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

template <typename T>
T convertResult(Il2CppObject *result)
{
    if (!result)
    {
        std::cout << "[Error] Null result.";
    }

    if constexpr (std::is_same_v<T, std::string>)
    {
        // Convert Il2CppString to std::string
        Il2CppString *il2cppString = reinterpret_cast<Il2CppString *>(result);
        return convertToString(il2cppString);
    }
    else if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>)
    {
        // Unbox primitive types or enums
        return *(T *)il2cpp_object_unbox(result);
    }
    else
    {
        // Return the result as a raw pointer for other types
        return reinterpret_cast<T>(result);
    }
}

template <typename T>
T getStaticProperty(Il2CppClass *klass, const std::string &propertyName)
{
    if (!klass)
    {
        return nullptr;
    }

    std::string getterName = "get_" + propertyName;
    const MethodInfo *getterMethod = il2cpp_class_get_method_from_name(klass, getterName.c_str(),
                                                                       0);
    if (!getterMethod)
    {
        std::cout << "[Error] Getter method not found: " + propertyName;
    }

    // Invoke the getter method to retrieve the property value
    Il2CppObject *result = il2cpp_runtime_invoke(getterMethod, nullptr, nullptr, nullptr);
    return convertResult<T>(result);
}

template <typename T>
T getInstanceProperty(Il2CppObject *instance, const std::string &propertyName)
{
    if (!instance)
    {
        std::cout << "[Error] Instance is null.";
    }

    Il2CppClass *klass = il2cpp_object_get_class(instance);
    if (!klass)
    {
        std::cout << "[Error] Class not found.";
    }

    std::string getterName = "get_" + propertyName;
    const MethodInfo *getterMethod = il2cpp_class_get_method_from_name(klass, getterName.c_str(),
                                                                       0);
    if (!getterMethod)
    {
        std::cout << "[Error] Getter method not found: " + propertyName;
    }

    // Invoke the getter method to retrieve the property value
    Il2CppObject *result = il2cpp_runtime_invoke(getterMethod, instance, nullptr, nullptr);
    return convertResult<T>(result);
}

class TSCrypto
{
private:
    Il2CppClass *kClass;

public:
    TSCrypto(Il2CppClass *kClass)
    {
        this->kClass = kClass;
    }

    void dumpToFile(const char *outDir, std::string outFile, std::string imageOutput)
    {
        auto outPath = std::string(outDir).append(outFile);
        LOGI("Dump file %s", outPath.c_str());
        std::ofstream outStream(outPath);
        outStream << imageOutput.c_str();
        outStream.close();
        LOGI("Dump done!");
    }

    std::string decryptData(const std::string &base64Encrypted, bool isUseLocalKey)
    {
        if (!kClass)
        {
            LOGD("Class TSCrypto not found.");
            return "";
        }

        // Get the method (DecryptData, 2 parameters)
        const MethodInfo *method = il2cpp_class_get_method_from_name(kClass, "DecryptData", 2);
        if (!method)
        {
            LOGD("Method DecryptData not found.\n");
            return "";
        }

        // Prepare parameters
        void *args[2];
        args[0] = il2cpp_string_new(base64Encrypted.c_str()); // First argument (string)
        args[1] = &isUseLocalKey;                             // Second argument (bool)

        // Call the static method
        Il2CppException *exception = nullptr;
        Il2CppObject *result = il2cpp_runtime_invoke(method, nullptr, args, &exception);

        if (exception)
        {
            return "";
        }

        // Convert Il2CppString* to std::string
        Il2CppString *resultString = reinterpret_cast<Il2CppString *>(result);
        if (resultString)
        {
            auto string = convertToString(resultString);
            return string;
        }

        return "";
    }

    void startDecryptData(const char *outDir)
    {
        auto outPath = std::string(outDir).append("/files/TextAsset/");
        LOGI("Reading file %s", outPath.c_str());
        for (const auto &entry : fs::directory_iterator(outPath))
        {
            LOGI("Reading file %s", entry.path().c_str());
            auto filePath = entry.path();
            if (fs::exists(filePath))
            {
                LOGI("Reading file %s", filePath.c_str());
                std::ifstream inFile(filePath);
                if (inFile)
                {
                    std::ostringstream buffer;
                    buffer << inFile.rdbuf();
                    auto result = decryptData(buffer.str(), true);
                    auto resultPath = std::string("/files/JsonAsset/").append(entry.path().filename());
                    dumpToFile(outDir, resultPath, result);
                }
                else
                {
                    LOGI("Failed to open file %s", filePath.c_str());
                }
            }
            else
            {
                LOGI("File does not exist: %s", filePath.c_str());
            }
        }
    }

    std::string encryptData(const std::string &dataText, bool isUseLocalKey)
    {
        if (!kClass)
        {
            LOGD("Class TSCrypto not found.");
            return "";
        }

        // Get the method (EncryptData, 2 parameters)
        // public static String EncryptData(String dataText, Boolean isUseLocalKey) { }
        const MethodInfo *method = il2cpp_class_get_method_from_name(kClass, "EncryptData", 2);
        if (!method)
        {
            LOGD("Method EncryptData not found.\n");
            return "";
        }

        // Prepare parameters
        void *args[2];
        args[0] = il2cpp_string_new(dataText.c_str()); // First argument (string)
        args[1] = &isUseLocalKey;                      // Second argument (bool)

        // Call the static method
        Il2CppException *exception = nullptr;
        Il2CppObject *result = il2cpp_runtime_invoke(method, nullptr, args, &exception);

        if (exception)
        {
            return "";
        }

        // Convert Il2CppString* to std::string
        Il2CppString *resultString = reinterpret_cast<Il2CppString *>(result);
        if (resultString)
        {
            auto string = convertToString(resultString);
            return string;
        }

        return "";
    }

    void startEncryptData(const char *outDir)
    {
        auto outPath = std::string(outDir).append("/files/TestAsset/");
        LOGI("Reading file %s", outPath.c_str());
        for (const auto &entry : fs::directory_iterator(outPath))
        {
            LOGI("Reading file %s", entry.path().c_str());
            auto filePath = entry.path();
            if (fs::exists(filePath))
            {
                LOGI("Reading file %s", filePath.c_str());
                std::ifstream inFile(filePath);
                if (inFile)
                {
                    std::ostringstream buffer;
                    buffer << inFile.rdbuf();
                    auto result = encryptData(buffer.str(), true);
                    auto resultPath = std::string("/files/EncryptAsset/").append(entry.path().filename());
                    dumpToFile(outDir, resultPath, result);
                }
                else
                {
                    LOGI("Failed to open file %s", filePath.c_str());
                }
            }
            else
            {
                LOGI("File does not exist: %s", filePath.c_str());
            }
        }
    }

    void logKey()
    {
        auto byteArray = getStaticProperty<Il2CppArray *>(this->kClass, "Key");
        // Get array length
        size_t length = il2cpp_array_length(byteArray);
        LOGD("Retrieved Byte array of length: %zu\n", length);
        std::vector<uint8_t> result;
        CopyArrayToVector(byteArray, result);
        LogArray(result, "Key");
    }

    void logIV()
    {
        auto byteArray = getStaticProperty<Il2CppArray *>(this->kClass, "IV");
        // Get array length
        size_t length = il2cpp_array_length(byteArray);
        LOGD("Retrieved Byte array of length: %zu\n", length);
        std::vector<uint8_t> result;
        CopyArrayToVector(byteArray, result);
        LogArray(result, "IV");
    }
};

class NetworkManager
{
private:
    Il2CppClass *kClass;

public:
    NetworkManager(Il2CppClass *kClass)
    {
        this->kClass = kClass;
    }

    void logResourceVersion()
    {
        auto byteArray = getStaticProperty<Il2CppString *>(this->kClass, "ResourceVersion");
        auto result = convertToString(byteArray);

        LOGD("Retrieved logResourceVersion: %s", result.c_str());
    }
    void logCDN_URL()
    {
        auto byteArray = getStaticProperty<Il2CppString *>(this->kClass, "CDN_URL");
        auto result = convertToString(byteArray);

        LOGD("Retrieved CDN_URL: %s", result.c_str());
    }
    void logLocaleManifestFilePath()
    {
        auto byteArray = getStaticProperty<Il2CppString *>(this->kClass, "LocaleManifestFilePath");
        auto result = convertToString(byteArray);

        LOGD("Retrieved LocaleManifestFilePath: %s", result.c_str());
    }

    void logVersionTvs()
    {
        const MethodInfo *method = il2cpp_class_get_method_from_name(kClass, "GetVersionTvs", 0);
        if (!method)
        {
            LOGD("Method GetVersionTvs not found.\n");
            return;
        }

        // Prepare parameters
        // void *args[2];
        // args[0] = il2cpp_string_new(base64Encrypted.c_str()); // First argument (string)
        // args[1] = &isUseLocalKey;                             // Second argument (bool)

        // Call the static method
        Il2CppException *exception = nullptr;
        Il2CppObject *result = il2cpp_runtime_invoke(method, nullptr, nullptr, &exception);

        if (exception)
        {
            LOGD("Method GetVersionTvs exception. \n");
            return;
        }

        // Convert Il2CppString* to std::string
        Il2CppString *resultString = reinterpret_cast<Il2CppString *>(result);
        if (resultString)
        {
            auto string = convertToString(resultString);
            LOGD("Retrieved VersionTvs: %s", string.c_str());
            // return string;
        }

        // return "";
    }
    void logServerTvs()
    {
        const MethodInfo *method = il2cpp_class_get_method_from_name(kClass, "GetServerTvs", 0);
        if (!method)
        {
            LOGD("Method GetServerTvs not found.\n");
            return;
        }

        // Prepare parameters
        // void *args[2];
        // args[0] = il2cpp_string_new(base64Encrypted.c_str()); // First argument (string)
        // args[1] = &isUseLocalKey;                             // Second argument (bool)

        // Call the static method
        Il2CppException *exception = nullptr;
        Il2CppObject *result = il2cpp_runtime_invoke(method, nullptr, nullptr, &exception);

        if (exception)
        {
            LOGD("Method GetServerTvs exception. \n");
            return;
        }

        // Convert Il2CppString* to std::string
        Il2CppString *resultString = reinterpret_cast<Il2CppString *>(result);
        if (resultString)
        {
            auto string = convertToString(resultString);
            LOGD("Retrieved GetServerTvs: %s", string.c_str());
            // return string;
        }

        // return "";
    }

    void logAll()
    {
        logResourceVersion();
        logCDN_URL();
        logLocaleManifestFilePath();
        logVersionTvs();
        logServerTvs();
    }
};

class UserManager
{
private:
    /* data */
    Il2CppClass *kClass;
    Il2CppObject *kInstance;

public:
    UserManager(Il2CppClass *kClass)
    {
        this->kClass = kClass;
        this->kInstance = getStaticProperty<Il2CppObject *>(this->kClass, "Instance");
    }

    void logStringStaticProperty(const std::string &propertyName)
    {
        auto byteArray = getStaticProperty<Il2CppString *>(this->kClass, propertyName);
        auto result = convertToString(byteArray);

        LOGD("Retrieved %s: %s", propertyName.c_str(), result.c_str());
    }

    void logAll()
    {
        logStringStaticProperty("UserName");
        logStringStaticProperty("DeviceId");
        logStringStaticProperty("UserToken");
        logStringStaticProperty("PlayerId");
    }
};

std::string
get_method_modifier(uint32_t flags)
{
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access)
    {
    case METHOD_ATTRIBUTE_PRIVATE:
        outPut << "private ";
        break;
    case METHOD_ATTRIBUTE_PUBLIC:
        outPut << "public ";
        break;
    case METHOD_ATTRIBUTE_FAMILY:
        outPut << "protected ";
        break;
    case METHOD_ATTRIBUTE_ASSEM:
    case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
        outPut << "internal ";
        break;
    case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
        outPut << "protected internal ";
        break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC)
    {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT)
    {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
        {
            outPut << "override ";
        }
    }
    else if (flags & METHOD_ATTRIBUTE_FINAL)
    {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
        {
            outPut << "sealed override ";
        }
    }
    else if (flags & METHOD_ATTRIBUTE_VIRTUAL)
    {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
        {
            outPut << "virtual ";
        }
        else
        {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL)
    {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type)
{
    auto byref = type->byref;
    if (il2cpp_type_is_byref)
    {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass)
{
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter))
    {
        // TODO attribute
        if (method->methodPointer)
        {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t)method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t)method->methodPointer;
        }
        else
        {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        /*if (method->slot != 65535) {
            outPut << " Slot: " << std::dec << method->slot;
        }*/
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        // TODO genericContainerIndex
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type))
        {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i)
        {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param))
            {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN))
                {
                    outPut << "out ";
                }
                else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT))
                {
                    outPut << "in ";
                }
                else
                {
                    outPut << "ref ";
                }
            }
            else
            {
                if (attrs & PARAM_ATTRIBUTE_IN)
                {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT)
                {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0)
        {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
        // TODO GenericInstMethod
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass)
{
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter))
    {
        // TODO attribute
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get)
        {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        }
        else if (set)
        {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class)
        {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get)
            {
                outPut << "get; ";
            }
            if (set)
            {
                outPut << "set; ";
            }
            outPut << "}\n";
        }
        else
        {
            if (prop_name)
            {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass)
{
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter))
    {
        // TODO attribute
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access)
        {
        case FIELD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case FIELD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case FIELD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case FIELD_ATTRIBUTE_ASSEMBLY:
        case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL)
        {
            outPut << "const ";
        }
        else
        {
            if (attrs & FIELD_ATTRIBUTE_STATIC)
            {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY)
            {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        // TODO 获取构造函数初始化后的字段值
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum)
        {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type)
{
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE)
    {
        outPut << "[Serializable]\n";
    }
    // TODO attribute
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility)
    {
    case TYPE_ATTRIBUTE_PUBLIC:
    case TYPE_ATTRIBUTE_NESTED_PUBLIC:
        outPut << "public ";
        break;
    case TYPE_ATTRIBUTE_NOT_PUBLIC:
    case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
    case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
        outPut << "internal ";
        break;
    case TYPE_ATTRIBUTE_NESTED_PRIVATE:
        outPut << "private ";
        break;
    case TYPE_ATTRIBUTE_NESTED_FAMILY:
        outPut << "protected ";
        break;
    case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
        outPut << "protected internal ";
        break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED)
    {
        outPut << "static ";
    }
    else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT)
    {
        outPut << "abstract ";
    }
    else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED)
    {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE)
    {
        outPut << "interface ";
    }
    else if (is_enum)
    {
        outPut << "enum ";
    }
    else if (is_valuetype)
    {
        outPut << "struct ";
    }
    else
    {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass); // TODO genericContainerIndex
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent)
    {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT)
        {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter))
    {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty())
    {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i)
        {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    // TODO EventInfo
    outPut << "}\n";
    return outPut.str();
}

void il2cpp_api_init(void *handle)
{
    LOGI("il2cpp_handle: %p", handle);
    init_il2cpp_api(handle);
    if (il2cpp_domain_get_assemblies)
    {
        Dl_info dlInfo;
        if (dladdr((void *)il2cpp_domain_get_assemblies, &dlInfo))
        {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        }
        LOGI("il2cpp_base: %" PRIx64 "", il2cpp_base);
    }
    else
    {
        LOGE("Failed to initialize il2cpp api.");
        return;
    }
    while (!il2cpp_is_vm_thread(nullptr))
    {
        LOGI("Waiting for il2cpp_init...");
        sleep(1);
    }
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

std::string Il2CppStringToStdString(Il2CppString *str)
{
    if (str == nullptr)
    {
        return "";
    }

    // Get Il2CppChar* (UTF-16)
    const Il2CppChar *il2cppChars = il2cpp_string_chars(str);
    size_t length = il2cpp_string_length(str);

    // Convert to std::wstring
    std::wstring wstr(il2cppChars, il2cppChars + length);

    // Convert wide string to UTF-8 string
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

// Retrieve the value of a constant field
int32_t GetConstantValue(const char *outDir, Il2CppClass *klass, const char *fieldName)
{
    if (!klass)
    {
        return -1;
    }

    // Get the field info
    auto field = il2cpp_class_get_field_from_name(klass, fieldName);
    if (!field)
    {
        return -1;
    }

    // Check if the field is a constant
    if (!il2cpp_field_is_literal(field))
    {
        LOGD("Field '%s' is not a constant.\n", fieldName);
        return -1;
    }

    // Retrieve the constant value
    void *constantValue = nullptr;
    il2cpp_field_get_value(nullptr, field,
                           &constantValue); // For constants, the instance is ignored (nullptr)

    // Cast to int32_t (assuming Int32 type)
    int32_t result = *reinterpret_cast<int32_t *>(&constantValue);
    LOGD("Constant value of '%s' is: %d\n", fieldName, result);

    return result;
}

float GetSingleConstantValue(const char *outDir, Il2CppClass *klass, const char *fieldName)
{
    if (!klass)
    {
        return -1.0f;
    }

    // Get the field info
    auto field = il2cpp_class_get_field_from_name(klass, fieldName);
    if (!field)
    {
        return -1.0f;
    }

    // Check if the field is a constant
    if (!il2cpp_field_is_literal(field))
    {
        LOGD("Field '%s' is not a constant.\n", fieldName);
        return -1.0f;
    }

    // Retrieve the constant value
    void *constantValue = nullptr;
    il2cpp_field_get_value(nullptr, field, &constantValue); // Constants don't require an instance.

    // Cast to float (Single)
    float result = *reinterpret_cast<float *>(&constantValue);
    LOGD("Constant value of '%s' is: %f\n", fieldName, result);

    return result;
}

// Retrieve the value of a constant field of type `String`
std::string GetStringConstantValue(const char *outDir, Il2CppClass *klass, const char *fieldName)
{
    if (!klass)
    {
        return "";
    }

    // Get the field info
    auto field = il2cpp_class_get_field_from_name(klass, fieldName);
    if (!field)
    {
        return "";
    }

    // Check if the field is a constant
    if (!il2cpp_field_is_literal(field))
    {
        LOGD("Field '%s' is not a constant.\n", fieldName);
        return "";
    }

    // Retrieve the constant value
    void *constantValue = nullptr;
    il2cpp_field_get_value(nullptr, field, &constantValue); // Constants don't require an instance.

    // Convert Il2CppString* to std::string
    std::string result = Il2CppStringToStdString(reinterpret_cast<Il2CppString *>(constantValue));
    LOGD("Constant value of '%s' is: %s\n", fieldName, result.c_str());

    return result;
}

void il2cpp_dump(const char *outDir)
{
    LOGI("dumping...");
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    std::stringstream imageOutput;

    for (int i = 0; i < size; ++i)
    {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }

    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class)
    {
        LOGI("Version greater than 2018.3");
        // 使用il2cpp_image_get_class
        for (int i = 0; i < size; ++i)
        {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j)
            {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                auto name = il2cpp_type_get_name(type);

                if (strcmp(name, "Tikitaka.NetworkManager") == 0)
                {
                    auto kClass2 = il2cpp_class_from_name(image, "Tikitaka", "NetworkManager");

                    NetworkManager networkManager(kClass2);
                    networkManager.logAll();
                }

                if (strcmp(name, "UserManager") == 0)
                {
                    // LOGD("UserManager");
                    auto kClass2 = il2cpp_class_from_name(image, "", "UserManager");
                    UserManager userManager(kClass2);
                    userManager.logAll();
                }

                if (strcmp(name, "Tikitaka.TSCrypto") == 0)
                {
                    // LOGD("type name : %s 2", il2cpp_type_get_name(type));
                    // Get the class from the image (namespace and class name)
                    auto kClass2 = il2cpp_class_from_name(image, "Tikitaka", "TSCrypto");
                    if (!kClass2)
                    {
                        LOGD("Class not found");
                    }

                    TSCrypto tsCrypto(kClass2);
                    // tsCrypto.startDecryptData(outDir);
                    // tsCrypto.startEncryptData(outDir);
                    tsCrypto.logIV();
                    tsCrypto.logKey();
                }

                // if (strcmp(name, "Alch_Constants_JM") == 0)
                // {
                //     auto klass2 = il2cpp_class_from_name(image, "", "Alch_Constants_JM");
                //     GetConstantValue(outDir, klass2, "DreamDg_GradeStart");
                //     GetConstantValue(outDir, klass2, "DreamDg_GradeRatio");
                //     GetConstantValue(outDir, klass2, "DreamDg_StageCalibrate");

                //     GetSingleConstantValue(outDir, klass2, "DreamDg_MainItemDropRate_Start");
                //     GetSingleConstantValue(outDir, klass2, "DreamDg_MainItemDropRate_Increase");
                //     GetSingleConstantValue(outDir, klass2, "DreamDg_MainItemDropRate_MAX");

                //     //                    GetStringConstantValue(outDir, klass2, "DreamDg_Boss_CommonDrop");

                //     GetSingleConstantValue(outDir, klass2, "DreamDg_Boss_DropCount_Start");
                //     GetSingleConstantValue(outDir, klass2, "DreamDg_Boss_DropCount_Increase");
                //     GetSingleConstantValue(outDir, klass2, "DreamDg_Boss_DropCount_Multiple_Easy");
                //     GetSingleConstantValue(outDir, klass2,
                //                            "DreamDg_Boss_DropCount_Multiple_Normal");
                //     GetSingleConstantValue(outDir, klass2, "DreamDg_Boss_DropCount_Multiple_Hard");
                // }

                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    }
    else
    {
        LOGI("Version less than 2018.3");
        // 使用反射
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (assemblyLoad && assemblyLoad->methodPointer)
        {
            LOGI("Assembly::Load: %p", assemblyLoad->methodPointer);
        }
        else
        {
            LOGI("miss Assembly::Load");
            return;
        }
        if (assemblyGetTypes && assemblyGetTypes->methodPointer)
        {
            LOGI("Assembly::GetTypes: %p", assemblyGetTypes->methodPointer);
        }
        else
        {
            LOGI("miss Assembly::GetTypes");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i)
        {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            // LOGD("image name : %s", image->name);
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn)assemblyLoad->methodPointer)(nullptr,
                                                                                       assemblyFileName,
                                                                                       nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn)assemblyGetTypes->methodPointer)(
                reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j)
            {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *)items[j]);
                auto type = il2cpp_class_get_type(klass);
                // LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type);
                outPuts.push_back(outPut);
            }
        }
    }
    LOGI("write dump file");
    auto outPath = std::string(outDir).append("/files/dump.cs");
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i)
    {
        outStream << outPuts[i];
    }
    outStream.close();
    LOGI("dump done!");
}