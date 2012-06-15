



struct foobar {
    unsigned int gni;
    (...)
};

void foo()
{
    struct foobar foo;
    struct info   *info;

    if (copyin(&foo, sizeof(foo)))
        return EIO;

    info = malloc(sizeof(struct info) * foo.gni, M_TEMP);
    if (info)
        return ENOMEM;

    for (i = 0; i < foo.gni && kernelinfo; i++, kernelinfo++, info++)
        memcpy(info, kernelinfo, sizeof(struct info));

    (...)
}
