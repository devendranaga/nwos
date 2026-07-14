name: clang build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Install System Packages
      run: |
        sudo apt update
        sudo apt install -y liblzma-dev libicu-dev libwolfssl-dev libncurses-dev
    - name: Compile
      run: |
        cmake .. -DCOMPILER_CLANG=on -DDEBUG=on -DWITH_WOLFSSL=on; make -j;
    - name: Upload build artifact to Github Actions
      uses: actions/upload-artifact@v4
      with:
        name: release-${{ github.ref_name }}
        path: netos_release*.tar.gz
        retention-days: 7
