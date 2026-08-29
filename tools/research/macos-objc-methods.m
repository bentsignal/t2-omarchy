#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc < 3) {
            fprintf(stderr, "usage: %s FRAMEWORK CLASS [FILTER]\n", argv[0]);
            return 2;
        }
        if (!dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL)) {
            fprintf(stderr, "dlopen: %s\n", dlerror());
            return 1;
        }
        if (!strcmp(argv[2], "*")) {
            int count = objc_getClassList(NULL, 0);
            Class *classes = (Class *)calloc((size_t)count, sizeof(*classes));
            count = objc_getClassList(classes, count);
            const char *leaf = strrchr(argv[1], '/');
            leaf = leaf ? leaf + 1 : argv[1];
            for (int i = 0; i < count; i++) {
                const char *image = class_getImageName(classes[i]);
                if (image && strstr(image, leaf)) puts(class_getName(classes[i]));
            }
            free(classes);
            return 0;
        }
        Class cls = objc_getClass(argv[2]);
        if (!cls) {
            fprintf(stderr, "class not found: %s\n", argv[2]);
            return 1;
        }
        const char *filter = argc > 3 ? argv[3] : NULL;
        for (int classMethod = 0; classMethod < 2; classMethod++) {
            Class target = classMethod ? object_getClass(cls) : cls;
            unsigned int count = 0;
            Method *methods = class_copyMethodList(target, &count);
            for (unsigned int i = 0; i < count; i++) {
                const char *name = sel_getName(method_getName(methods[i]));
                if (filter && !strcasestr(name, filter)) continue;
                IMP imp = method_getImplementation(methods[i]);
                Dl_info info = {0};
                dladdr((const void *)imp, &info);
                printf("%c %s %s %p +0x%llx\n",
                       classMethod ? '+' : '-', name,
                       method_getTypeEncoding(methods[i]), imp,
                       (unsigned long long)((uintptr_t)imp - (uintptr_t)info.dli_fbase));
                const char *dump = getenv("MACOS_OBJC_DUMP_METHOD");
                if (dump && !strcmp(dump, name)) {
                    FILE *fp = fopen("/tmp/macos-objc-method.bin", "wb");
                    if (!fp || fwrite((const void *)imp, 1, 4096, fp) != 4096) {
                        fprintf(stderr, "could not dump method code\n");
                        if (fp) fclose(fp);
                        free(methods);
                        return 1;
                    }
                    fclose(fp);
                }
                const char *selectors = getenv("MACOS_OBJC_PRINT_SELECTORS");
                if (selectors && !strcmp(selectors, name)) {
                    const unsigned char *code = (const unsigned char *)imp;
                    for (size_t off = 0; off + 7 < 4096; off++) {
                        if (code[off] != 0x48 || code[off + 1] != 0x8b ||
                            code[off + 2] != 0x35) continue;
                        int32_t displacement = 0;
                        memcpy(&displacement, code + off + 3, sizeof(displacement));
                        SEL *reference = (SEL *)(code + off + 7 + displacement);
                        SEL selector = *reference;
                        if (selector) printf("  +0x%zx selector %s\n", off, sel_getName(selector));
                    }
                }
                const char *constants = getenv("MACOS_OBJC_PRINT_CONSTANTS");
                if (constants && !strcmp(constants, name)) {
                    const unsigned char *code = (const unsigned char *)imp;
                    for (size_t off = 0; off + 7 < 1024; off++) {
                        if (code[off] != 0x4c || code[off + 1] != 0x8d ||
                            code[off + 2] != 0x25) continue;
                        int32_t displacement = 0;
                        memcpy(&displacement, code + off + 3, sizeof(displacement));
                        const void *address = code + off + 7 + displacement;
                        id object = (__bridge id)address;
                        if ([object isKindOfClass:[NSString class]])
                            printf("  +0x%zx string %s\n", off, [object UTF8String]);
                    }
                }
            }
            free(methods);
        }
    }
    return 0;
}
