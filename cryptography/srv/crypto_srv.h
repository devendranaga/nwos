#ifndef CRYPTOGRAPHY_SRV_H
#define CRYPTOGRAPHY_SRV_H

namespace netos {

class cryptography_srv {
    public:
        explicit cryptography_srv();
        ~cryptography_srv();

        void run(int argc, char **argv);
    private:
};

}

#endif
