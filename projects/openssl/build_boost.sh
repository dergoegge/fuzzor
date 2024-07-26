# Install Boost headers
tar jxf boost_1_84_0.tar.bz2
pushd boost_1_84_0/
CFLAGS="" CXXFLAGS="" ./bootstrap.sh
CFLAGS="" CXXFLAGS="" ./b2 headers
cp -R boost/ /usr/include/
popd
