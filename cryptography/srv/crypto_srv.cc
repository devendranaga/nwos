#include <iostream>
#include <thread>

#include "crypto_srv.h"

namespace netos {

cryptography_srv::cryptography_srv()
{

}

cryptography_srv::~cryptography_srv()
{

}

void cryptography_srv::run(int argc, char **argv)
{
    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

}

int main(int argc, char **argv)
{
    netos::cryptography_srv csrv;

    csrv.run(argc, argv);
}

